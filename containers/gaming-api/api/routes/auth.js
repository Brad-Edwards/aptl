const express = require('express');
const ClientInfoExtractor = require('../utils/ClientInfoExtractor');

function createAuthRoutes(authService, telemetryService, rateLimiter) {
  const router = express.Router();

  // POST /api/auth/login
  router.post('/login', async (req, res) => {
    try {
      await rateLimiter.consume(req.ip);
      
      const { username, password } = req.body;
      const clientInfo = ClientInfoExtractor.extract(req);

      const result = await authService.login(username, password, clientInfo);
      
      telemetryService.logAuthEvent(username, 'success', clientInfo, result.user);

      res.json({
        message: 'Login successful',
        token: result.token,
        session_id: result.sessionId,
        user: result.user
      });

    } catch (error) {
      const clientInfo = ClientInfoExtractor.extract(req);
      telemetryService.logAuthEvent(req.body.username, 'failure', clientInfo, null, error.message);

      if (error.message === 'Username and password required') {
        return res.status(400).json({ error: error.message });
      }
      
      res.status(401).json({ error: 'Invalid credentials' });
    }
  });

  // POST /api/auth/logout
  router.post('/logout', async (req, res) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    await authService.logout(token);
    res.json({ message: 'Logout successful' });
  });

  // GET /api/auth/refresh
  router.get('/refresh', async (req, res) => {
    try {
      const token = req.headers.authorization?.replace('Bearer ', '');
      
      if (!token) {
        return res.status(401).json({ error: 'No token provided' });
      }

      const result = await authService.refreshToken(token);
      
      res.json({
        message: 'Token refreshed',
        token: result.token,
        user: result.user
      });

    } catch (error) {
      res.status(401).json({ error: 'Invalid token' });
    }
  });

  return router;
}

module.exports = createAuthRoutes;