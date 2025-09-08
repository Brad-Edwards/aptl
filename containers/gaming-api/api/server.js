const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { RateLimiterMemory } = require('rate-limiter-flexible');
const winston = require('winston');

// Services
const DatabaseService = require('./services/DatabaseService');
const AuthService = require('./services/AuthService');
const TelemetryService = require('./services/TelemetryService');

// Routes
const createAuthRoutes = require('./routes/auth');

// Middleware
const createRequestLogger = require('./middleware/requestLogger');
const createResponseLogger = require('./middleware/responseLogger');

// Configuration
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const JWT_SECRET = process.env.JWT_SECRET || 'gaming-api-secret-change-in-production';

class GamingApiServer {
  constructor() {
    this.app = express();
    this.setupLogger();
    this.setupRateLimiters();
    this.setupServices();
  }

  setupLogger() {
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
      ),
      defaultMeta: { 
        service: 'gaming-api',
        environment: NODE_ENV,
        container: 'aptl-gaming-api'
      },
      transports: [
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
          )
        })
      ]
    });

    // Add file transports in production
    if (NODE_ENV === 'production') {
      this.logger.add(new winston.transports.File({ 
        filename: '/var/log/gaming-api-error.log', 
        level: 'error' 
      }));
      this.logger.add(new winston.transports.File({ 
        filename: '/var/log/gaming-api-combined.log' 
      }));
    }
  }

  setupRateLimiters() {
    this.rateLimiter = new RateLimiterMemory({
      points: 100,
      duration: 60,
    });

    this.authRateLimiter = new RateLimiterMemory({
      points: 5,
      duration: 900,
    });
  }

  async setupServices() {
    this.databaseService = new DatabaseService(this.logger);
    await this.databaseService.connect();
    await this.databaseService.initializeSchema();

    this.authService = new AuthService(this.databaseService, this.logger, JWT_SECRET);
    this.telemetryService = new TelemetryService(this.logger);
  }

  setupMiddleware() {
    this.app.use(helmet());
    this.app.use(cors());
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true }));

    // Comprehensive request/response logging
    this.app.use(createRequestLogger(this.telemetryService));
    this.app.use(createResponseLogger(this.telemetryService));

    // Global rate limiting
    this.app.use(async (req, res, next) => {
      try {
        await this.rateLimiter.consume(req.ip);
        next();
      } catch (rejRes) {
        const secs = Math.round(rejRes.msBeforeNext / 1000) || 1;
        res.set('Retry-After', String(secs));
        this.logger.warn('Rate limit exceeded', { ip: req.ip, endpoint: req.path });
        res.status(429).json({ error: 'Too Many Requests' });
      }
    });
  }

  setupRoutes() {
    // Health check
    this.app.get('/health', (req, res) => {
      res.json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        environment: NODE_ENV,
        version: '1.0.0'
      });
    });

    // API Routes with dependency injection
    this.app.use('/api/auth', createAuthRoutes(this.authService, this.telemetryService, this.authRateLimiter));

    // TODO: Add other routes
    // this.app.use('/api/player', createPlayerRoutes(...));
    // this.app.use('/api/game', createGameRoutes(...));
    // etc.

    // 404 handler
    this.app.use((req, res) => {
      this.logger.warn('404 Not Found', { method: req.method, path: req.originalUrl, ip: req.ip });
      res.status(404).json({ error: 'Endpoint not found' });
    });

    // Error handler
    this.app.use((err, req, res, next) => {
      this.logger.error('Unhandled error', {
        error: err.message,
        stack: err.stack,
        method: req.method,
        path: req.path,
        ip: req.ip
      });
      
      res.status(500).json({ 
        error: NODE_ENV === 'development' ? err.message : 'Internal server error' 
      });
    });
  }

  async start() {
    await this.setupServices();
    this.setupMiddleware();
    this.setupRoutes();
    this.setupGracefulShutdown();

    this.app.listen(PORT, '0.0.0.0', () => {
      this.logger.info('Gaming API Server started', {
        port: PORT,
        environment: NODE_ENV,
        timestamp: new Date().toISOString()
      });
    });
  }

  setupGracefulShutdown() {
    process.on('SIGTERM', async () => {
      this.logger.info('SIGTERM received, shutting down gracefully');
      await this.databaseService.close();
      process.exit(0);
    });
  }
}

// Start the server
if (require.main === module) {
  const server = new GamingApiServer();
  server.start().catch(error => {
    console.error('Failed to start server:', error);
    process.exit(1);
  });
}

module.exports = GamingApiServer;