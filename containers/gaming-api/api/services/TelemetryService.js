const winston = require('winston');
require('winston-syslog').Syslog;

class TelemetryService {
  constructor(logger) {
    this.logger = logger;
    this.setupSyslogTransport();
  }

  setupSyslogTransport() {
    try {
      // Add syslog transport for forwarding to Wazuh via rsyslog
      // Use UDP protocol to localhost syslog daemon
      this.logger.add(new winston.transports.Syslog({
        host: 'localhost',
        port: 514,
        protocol: 'udp4',
        facility: 'local0',
        app_name: 'gaming-api',
        localhost: 'gaming-api-host',
        type: '5424' // RFC 5424 format
      }));
      
      console.log('Syslog transport configured successfully');
    } catch (error) {
      console.error('Failed to configure syslog transport:', error.message);
      // Continue without syslog - logs will still go to console/files
    }
  }

  logAuthEvent(username, result, clientInfo, user = null, failureReason = null) {
    const logData = {
      timestamp: new Date().toISOString(),
      event_type: 'auth_attempt',
      result: result,
      username: username,
      source_ip: clientInfo.ip,
      user_agent: clientInfo.userAgent,
      session_id: result === 'success' ? this._generateSessionId() : null,
      account_value: user?.account_value || null,
      is_premium: user?.is_premium || false,
      account_age_days: user ? this._calculateAccountAge(user.created_at) : null,
      geo_location: clientInfo.geoLocation,
      geo_anomaly: false, // TODO: implement geo checking
      device_fingerprint: clientInfo.deviceFingerprint,
      consecutive_failures: 0, // TODO: implement failure tracking
      time_since_last_login: user ? this._calculateTimeSinceLastLogin(user.last_login) : null,
      failure_reason: failureReason
    };

    this.logger.info('Authentication Event', logData);
  }

  logApiCall(req, res, duration, sessionInfo = {}) {
    const logData = {
      timestamp: new Date().toISOString(),
      event_type: 'api_call',
      method: req.method,
      endpoint: req.path,
      user_agent: req.get('User-Agent'),
      source_ip: req.ip,
      status_code: res.statusCode,
      response_time_ms: duration,
      session_id: sessionInfo.sessionId || 'anonymous',
      username: sessionInfo.username || null,
      character_id: sessionInfo.characterId || null,
      session_duration_seconds: sessionInfo.sessionDuration || 0,
      api_calls_this_session: sessionInfo.apiCallsCount || 0,
      unique_endpoints_accessed: sessionInfo.uniqueEndpoints || 0
    };

    this.logger.info('API Call', logData);
  }

  _generateSessionId() {
    return 'sess_' + Math.random().toString(36).substr(2, 9) + Date.now().toString(36);
  }

  _calculateAccountAge(createdAt) {
    if (!createdAt) return null;
    const created = new Date(createdAt);
    const now = new Date();
    return Math.floor((now - created) / (1000 * 60 * 60 * 24));
  }

  _calculateTimeSinceLastLogin(lastLogin) {
    if (!lastLogin) return null;
    const last = new Date(lastLogin);
    const now = new Date();
    const hours = Math.floor((now - last) / (1000 * 60 * 60));
    return hours > 24 ? `${Math.floor(hours/24)} days` : `${hours} hours`;
  }
}

module.exports = TelemetryService;