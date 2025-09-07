const ClientInfoExtractor = require('../utils/ClientInfoExtractor');

function createRequestLogger(telemetryService) {
  return function requestLogger(req, res, next) {
    const startTime = Date.now();
    const clientInfo = ClientInfoExtractor.extract(req);
    
    // Log inbound request
    const requestLog = {
      timestamp: new Date().toISOString(),
      event_type: 'api_request_inbound',
      method: req.method,
      url: req.originalUrl,
      path: req.path,
      query: req.query,
      ip: clientInfo.ip,
      user_agent: clientInfo.userAgent,
      headers: sanitizeHeaders(req.headers),
      body_size: req.headers['content-length'] || 0,
      content_type: req.headers['content-type'],
      auth_header_present: !!req.headers.authorization,
      referer: req.headers.referer,
      x_forwarded_for: req.headers['x-forwarded-for'],
      device_fingerprint: clientInfo.deviceFingerprint,
      geo_location: clientInfo.geoLocation
    };

    // Add sanitized body for specific endpoints (avoid logging passwords)
    if (shouldLogRequestBody(req)) {
      requestLog.body = sanitizeRequestBody(req.body, req.path);
    }

    telemetryService.logger.info('API Request Inbound', requestLog);

    // Store start time for response logging
    req.startTime = startTime;
    req.requestLog = requestLog;
    
    next();
  };
}

function sanitizeHeaders(headers) {
  const sanitized = { ...headers };
  
  // Remove sensitive headers
  delete sanitized.authorization;
  delete sanitized.cookie;
  delete sanitized['x-api-key'];
  delete sanitized['x-auth-token'];
  
  return sanitized;
}

function sanitizeRequestBody(body, path) {
  if (!body || typeof body !== 'object') {
    return body;
  }

  const sanitized = { ...body };
  
  // Remove passwords and sensitive data
  if (sanitized.password) {
    sanitized.password = '[REDACTED]';
  }
  if (sanitized.current_password) {
    sanitized.current_password = '[REDACTED]';  
  }
  if (sanitized.new_password) {
    sanitized.new_password = '[REDACTED]';
  }
  if (sanitized.token) {
    sanitized.token = '[REDACTED]';
  }
  
  return sanitized;
}

function shouldLogRequestBody(req) {
  // Log request body for most endpoints, but be selective
  const logBodyEndpoints = [
    '/api/auth/login',
    '/api/auth/register', 
    '/api/player/character',
    '/api/trade/initiate',
    '/api/marketplace/list',
    '/api/chat/send'
  ];
  
  return logBodyEndpoints.some(endpoint => req.path.startsWith(endpoint)) ||
         req.method === 'POST' || 
         req.method === 'PUT' || 
         req.method === 'PATCH';
}

module.exports = createRequestLogger;