const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

class AuthService {
  constructor(databaseService, logger, jwtSecret = 'gaming-api-secret', jwtExpiresIn = '24h') {
    this.db = databaseService;
    this.logger = logger;
    this.jwtSecret = jwtSecret;
    this.jwtExpiresIn = jwtExpiresIn;
  }

  async login(username, password, clientInfo) {
    if (!username || !password) {
      throw new Error('Username and password required');
    }

    const user = await this.db.get('SELECT * FROM users WHERE username = ?', [username]);
    
    if (!user) {
      await this._logFailedLogin(null, username, 'user_not_found', clientInfo);
      throw new Error('Invalid credentials');
    }

    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    
    if (!passwordMatch) {
      await this._logFailedLogin(user.id, username, 'invalid_password', clientInfo);
      throw new Error('Invalid credentials');
    }

    // Successful login
    const token = this._generateToken(user);
    const sessionId = this._generateSessionId();

    await this._updateLastLogin(user.id);
    await this._logSuccessfulLogin(user.id, clientInfo);
    await this._createSession(user.id, sessionId, clientInfo);

    return {
      token,
      sessionId,
      user: this._sanitizeUser(user)
    };
  }

  async logout(token) {
    if (!token) return;

    try {
      const decoded = jwt.verify(token, this.jwtSecret);
      await this._endSession(decoded.id);
      this.logger.info('User logout', { user_id: decoded.id, username: decoded.username });
    } catch (err) {
      this.logger.warn('Logout with invalid token', { error: err.message });
    }
  }

  async refreshToken(token) {
    const decoded = jwt.verify(token, this.jwtSecret);
    const user = await this.db.get('SELECT id, username, is_premium, account_value FROM users WHERE id = ?', [decoded.id]);
    
    if (!user) {
      throw new Error('Invalid token');
    }

    const newToken = this._generateToken(user);
    this.logger.info('Token refresh', { user_id: user.id, username: user.username });

    return {
      token: newToken,
      user: this._sanitizeUser(user)
    };
  }

  _generateToken(user) {
    return jwt.sign(
      { 
        id: user.id, 
        username: user.username,
        is_premium: user.is_premium 
      },
      this.jwtSecret,
      { expiresIn: this.jwtExpiresIn }
    );
  }

  _generateSessionId() {
    return 'sess_' + Math.random().toString(36).substr(2, 9) + Date.now().toString(36);
  }

  _sanitizeUser(user) {
    return {
      id: user.id,
      username: user.username,
      is_premium: user.is_premium,
      account_value: user.account_value,
      created_at: user.created_at
    };
  }

  async _updateLastLogin(userId) {
    await this.db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [userId]);
  }

  async _createSession(userId, sessionId, clientInfo) {
    await this.db.run(
      'INSERT INTO player_sessions (user_id, session_id, ip_address, user_agent) VALUES (?, ?, ?, ?)',
      [userId, sessionId, clientInfo.ip, clientInfo.userAgent]
    );
  }

  async _endSession(userId) {
    await this.db.run(
      'UPDATE player_sessions SET logout_time = CURRENT_TIMESTAMP WHERE user_id = ? AND logout_time IS NULL',
      [userId]
    );
  }

  async _logSuccessfulLogin(userId, clientInfo) {
    await this.db.run(
      'INSERT INTO login_history (user_id, ip_address, user_agent, success, geo_location, device_fingerprint) VALUES (?, ?, ?, ?, ?, ?)',
      [userId, clientInfo.ip, clientInfo.userAgent, 1, clientInfo.geoLocation, clientInfo.deviceFingerprint]
    );
  }

  async _logFailedLogin(userId, username, reason, clientInfo) {
    await this.db.run(
      'INSERT INTO login_history (user_id, username, ip_address, user_agent, success, failure_reason, geo_location, device_fingerprint) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [userId, username, clientInfo.ip, clientInfo.userAgent, 0, reason, clientInfo.geoLocation, clientInfo.deviceFingerprint]
    );
  }
}

module.exports = AuthService;