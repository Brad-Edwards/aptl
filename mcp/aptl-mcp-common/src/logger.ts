/**
 * Structured logging for APTL MCP servers
 * 
 * Provides ECS-compliant JSON logging similar to the Python implementation.
 * Uses lightweight structured logging with configurable log levels.
 */

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

interface LogEntry {
  '@timestamp': string;
  'log.level': string;
  'log.logger': string;
  message: string;
  'service.name': string;
  'ecs.version': string;
  'error.type'?: string;
  'error.message'?: string;
  'error.stack_trace'?: string;
  [key: string]: any;
}

const ECS_VERSION = '8.11.0';
const SERVICE_NAME = 'aptl-mcp';

/**
 * Logger class for structured logging with ECS-compliant JSON output
 */
export class Logger {
  private loggerName: string;
  private minLevel: LogLevel;
  private useJson: boolean;

  private static levelPriority: Record<LogLevel, number> = {
    debug: 0,
    info: 1,
    warn: 2,
    error: 3,
  };

  constructor(name: string, minLevel: LogLevel = 'info', useJson: boolean = false) {
    this.loggerName = name;
    this.minLevel = minLevel;
    this.useJson = useJson;
  }

  /**
   * Check if a log level should be emitted based on minimum level
   */
  private shouldLog(level: LogLevel): boolean {
    return Logger.levelPriority[level] >= Logger.levelPriority[this.minLevel];
  }

  /**
   * Format and emit a log entry
   */
  private log(level: LogLevel, message: string, error?: Error, extra?: Record<string, any>): void {
    if (!this.shouldLog(level)) {
      return;
    }

    if (this.useJson) {
      const entry: LogEntry = {
        '@timestamp': new Date().toISOString(),
        'log.level': level.toUpperCase(),
        'log.logger': this.loggerName,
        message,
        'service.name': SERVICE_NAME,
        'ecs.version': ECS_VERSION,
        ...extra,
      };

      if (error) {
        entry['error.type'] = error.name;
        entry['error.message'] = error.message;
        entry['error.stack_trace'] = error.stack || '';
      }

      console.error(JSON.stringify(entry));
    } else {
      // Plain text format similar to Python
      const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
      const levelStr = level.toUpperCase().padEnd(5);
      let logMessage = `${timestamp} [${levelStr}] ${this.loggerName}: ${message}`;
      
      if (extra && Object.keys(extra).length > 0) {
        logMessage += ` ${JSON.stringify(extra)}`;
      }
      
      console.error(logMessage);
      
      if (error && error.stack) {
        console.error(error.stack);
      }
    }
  }

  /**
   * Log a debug message
   */
  debug(message: string, extra?: Record<string, any>): void {
    this.log('debug', message, undefined, extra);
  }

  /**
   * Log an info message
   */
  info(message: string, extra?: Record<string, any>): void {
    this.log('info', message, undefined, extra);
  }

  /**
   * Log a warning message
   */
  warn(message: string, extra?: Record<string, any>): void {
    this.log('warn', message, undefined, extra);
  }

  /**
   * Log an error message
   */
  error(message: string, error?: Error, extra?: Record<string, any>): void {
    this.log('error', message, error, extra);
  }
}

/**
 * Get or create a logger instance for a specific module
 */
const loggers = new Map<string, Logger>();

export function getLogger(name: string): Logger {
  // Check for log level from environment
  const envLevel = process.env.APTL_LOG_LEVEL?.toLowerCase();
  const validLevels: LogLevel[] = ['debug', 'info', 'warn', 'error'];
  const logLevel = (validLevels.includes(envLevel as LogLevel) ? envLevel : 'info') as LogLevel;
  const useJson = process.env.APTL_LOG_FORMAT?.toLowerCase() === 'json';
  
  const key = `${name}:${logLevel}:${useJson}`;
  let logger = loggers.get(key);
  
  if (!logger) {
    logger = new Logger(name, logLevel, useJson);
    loggers.set(key, logger);
  }
  
  return logger;
}
