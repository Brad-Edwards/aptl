const jwt = require('jsonwebtoken');

function createResponseLogger(telemetryService) {
  return function responseLogger(req, res, next) {
    // Capture response data
    const originalSend = res.send;
    const originalJson = res.json;
    
    let responseBody = null;
    let responseSize = 0;

    // Override res.send to capture response data
    res.send = function(body) {
      responseBody = body;
      responseSize = Buffer.byteLength(body || '', 'utf8');
      return originalSend.call(this, body);
    };

    // Override res.json to capture JSON responses  
    res.json = function(obj) {
      responseBody = obj;
      const jsonString = JSON.stringify(obj);
      responseSize = Buffer.byteLength(jsonString, 'utf8');
      return originalJson.call(this, obj);
    };

    // Log response when finished
    res.on('finish', () => {
      const endTime = Date.now();
      const duration = endTime - (req.startTime || endTime);
      
      // Extract user context from token if present
      const userContext = extractUserContext(req);
      
      const responseLog = {
        timestamp: new Date().toISOString(),
        event_type: 'api_response_outbound',
        method: req.method,
        url: req.originalUrl, 
        path: req.path,
        status_code: res.statusCode,
        status_text: getStatusText(res.statusCode),
        response_time_ms: duration,
        response_size_bytes: responseSize,
        ip: req.ip || req.connection.remoteAddress,
        user_agent: req.get('User-Agent'),
        
        // User context
        user_id: userContext.userId,
        username: userContext.username,
        is_authenticated: userContext.isAuthenticated,
        session_id: userContext.sessionId,
        
        // Response analysis
        is_error: res.statusCode >= 400,
        is_success: res.statusCode < 300,
        is_redirect: res.statusCode >= 300 && res.statusCode < 400,
        
        // Security context
        auth_failure: res.statusCode === 401,
        rate_limited: res.statusCode === 429,
        forbidden: res.statusCode === 403,
        not_found: res.statusCode === 404,
        
        // Response headers that matter for security
        content_type: res.get('content-type'),
        cache_control: res.get('cache-control'),
        set_cookie_count: (res.get('set-cookie') || []).length
      };

      // Add sanitized response body for certain conditions
      if (shouldLogResponseBody(req, res, responseBody)) {
        responseLog.response_body = sanitizeResponseBody(responseBody, req.path);
      }

      // Add error context for failed responses
      if (res.statusCode >= 400) {
        responseLog.error_context = {
          endpoint: req.path,
          method: req.method,
          client_ip: req.ip,
          user_agent: req.get('User-Agent')
        };
      }

      telemetryService.logger.info('API Response Outbound', responseLog);
    });

    next();
  };
}

function extractUserContext(req) {
  const context = {
    userId: null,
    username: null,
    isAuthenticated: false,
    sessionId: null
  };

  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    try {
      const token = authHeader.substring(7);
      // Note: In production, use proper JWT secret
      const decoded = jwt.decode(token); // Just decode, don't verify for logging
      
      if (decoded) {
        context.userId = decoded.id;
        context.username = decoded.username;
        context.isAuthenticated = true;
        context.sessionId = `user_${decoded.id}_session`;
      }
    } catch (err) {
      // Invalid token, keep defaults
    }
  }

  return context;
}

function getStatusText(statusCode) {
  const statusTexts = {
    200: 'OK',
    201: 'Created', 
    400: 'Bad Request',
    401: 'Unauthorized',
    403: 'Forbidden',
    404: 'Not Found',
    429: 'Too Many Requests',
    500: 'Internal Server Error'
  };
  
  return statusTexts[statusCode] || 'Unknown';
}

function shouldLogResponseBody(req, res, responseBody) {
  // Log response bodies for errors and certain endpoints
  if (res.statusCode >= 400) {
    return true; // Always log error responses
  }
  
  // Log successful auth responses (but sanitize tokens)
  if (req.path.includes('/auth/') && res.statusCode < 300) {
    return true;
  }
  
  // Log other important endpoints
  const logResponseEndpoints = [
    '/api/player/dashboard',
    '/api/player/profile',
    '/health'
  ];
  
  return logResponseEndpoints.some(endpoint => req.path.startsWith(endpoint));
}

function sanitizeResponseBody(body, path) {
  if (!body || typeof body !== 'object') {
    return body;
  }

  const sanitized = { ...body };
  
  // Sanitize JWT tokens and sensitive data
  if (sanitized.token) {
    sanitized.token = '[REDACTED_JWT_TOKEN]';
  }
  if (sanitized.session_id) {
    sanitized.session_id = sanitized.session_id.substring(0, 8) + '[TRUNCATED]';
  }
  if (sanitized.user && sanitized.user.password_hash) {
    delete sanitized.user.password_hash;
  }
  
  return sanitized;
}

module.exports = createResponseLogger;