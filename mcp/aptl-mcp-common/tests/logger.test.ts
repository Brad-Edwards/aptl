import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { getLogger, Logger } from '../src/logger.js';

describe('Logger', () => {
  let consoleErrorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    // Reset environment variables
    delete process.env.APTL_LOG_LEVEL;
    delete process.env.APTL_LOG_FORMAT;
  });

  afterEach(() => {
    consoleErrorSpy.mockRestore();
  });

  describe('Plain text logging', () => {
    it('should log info messages in plain text format', () => {
      const logger = new Logger('test.module', 'info', false);
      logger.info('Test message');

      expect(consoleErrorSpy).toHaveBeenCalledOnce();
      const output = consoleErrorSpy.mock.calls[0][0];
      expect(output).toContain('[INFO ]');
      expect(output).toContain('test.module');
      expect(output).toContain('Test message');
    });

    it('should include extra fields in plain text format', () => {
      const logger = new Logger('test.module', 'info', false);
      logger.info('Test message', { key: 'value' });

      const output = consoleErrorSpy.mock.calls[0][0];
      expect(output).toContain('Test message');
      expect(output).toContain('"key":"value"');
    });

    it('should log error messages with stack trace', () => {
      const logger = new Logger('test.module', 'info', false);
      const error = new Error('Test error');
      logger.error('Error occurred', error);

      expect(consoleErrorSpy).toHaveBeenCalledTimes(2);
      const message = consoleErrorSpy.mock.calls[0][0];
      const stack = consoleErrorSpy.mock.calls[1][0];
      
      expect(message).toContain('[ERROR]');
      expect(message).toContain('Error occurred');
      expect(stack).toContain('Error: Test error');
    });
  });

  describe('JSON logging', () => {
    it('should log info messages in JSON format', () => {
      const logger = new Logger('test.module', 'info', true);
      logger.info('Test message');

      expect(consoleErrorSpy).toHaveBeenCalledOnce();
      const output = JSON.parse(consoleErrorSpy.mock.calls[0][0]);
      
      expect(output['@timestamp']).toBeDefined();
      expect(output['log.level']).toBe('INFO');
      expect(output['log.logger']).toBe('test.module');
      expect(output['message']).toBe('Test message');
      expect(output['service.name']).toBe('aptl-mcp');
      expect(output['ecs.version']).toBe('8.11.0');
    });

    it('should include extra fields in JSON format', () => {
      const logger = new Logger('test.module', 'info', true);
      logger.info('Test message', { key: 'value', count: 42 });

      const output = JSON.parse(consoleErrorSpy.mock.calls[0][0]);
      expect(output['key']).toBe('value');
      expect(output['count']).toBe(42);
    });

    it('should log error messages with error fields', () => {
      const logger = new Logger('test.module', 'info', true);
      const error = new Error('Test error');
      logger.error('Error occurred', error);

      expect(consoleErrorSpy).toHaveBeenCalledOnce();
      const output = JSON.parse(consoleErrorSpy.mock.calls[0][0]);
      
      expect(output['log.level']).toBe('ERROR');
      expect(output['message']).toBe('Error occurred');
      expect(output['error.type']).toBe('Error');
      expect(output['error.message']).toBe('Test error');
      expect(output['error.stack_trace']).toContain('Error: Test error');
    });

    it('should use ISO 8601 timestamp format', () => {
      const logger = new Logger('test.module', 'info', true);
      logger.info('Test message');

      const output = JSON.parse(consoleErrorSpy.mock.calls[0][0]);
      const timestamp = output['@timestamp'];
      
      // Verify ISO 8601 format with regex
      expect(timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    });
  });

  describe('Log levels', () => {
    it('should respect minimum log level', () => {
      const logger = new Logger('test.module', 'warn', false);
      
      logger.debug('Debug message');
      logger.info('Info message');
      logger.warn('Warning message');
      logger.error('Error message');

      // Only warn and error should be logged
      expect(consoleErrorSpy).toHaveBeenCalledTimes(2);
      expect(consoleErrorSpy.mock.calls[0][0]).toContain('Warning message');
      expect(consoleErrorSpy.mock.calls[1][0]).toContain('Error message');
    });

    it('should log all levels when set to debug', () => {
      const logger = new Logger('test.module', 'debug', false);
      
      logger.debug('Debug message');
      logger.info('Info message');
      logger.warn('Warning message');
      logger.error('Error message');

      expect(consoleErrorSpy).toHaveBeenCalledTimes(4);
    });
  });

  describe('getLogger', () => {
    it('should return a logger with default settings', () => {
      const logger = getLogger('test.module');
      logger.info('Test message');

      expect(consoleErrorSpy).toHaveBeenCalledOnce();
      const output = consoleErrorSpy.mock.calls[0][0];
      expect(output).toContain('test.module');
      expect(output).toContain('Test message');
    });

    it('should respect APTL_LOG_LEVEL environment variable', () => {
      process.env.APTL_LOG_LEVEL = 'error';
      const logger = getLogger('test.module');
      
      logger.info('Info message');
      logger.error('Error message');

      // Only error should be logged
      expect(consoleErrorSpy).toHaveBeenCalledOnce();
      expect(consoleErrorSpy.mock.calls[0][0]).toContain('Error message');
    });

    it('should respect APTL_LOG_FORMAT environment variable', () => {
      process.env.APTL_LOG_FORMAT = 'json';
      const logger = getLogger('test.module');
      
      logger.info('Test message');

      const output = JSON.parse(consoleErrorSpy.mock.calls[0][0]);
      expect(output['@timestamp']).toBeDefined();
      expect(output['log.level']).toBe('INFO');
    });

    it('should handle invalid log level gracefully', () => {
      process.env.APTL_LOG_LEVEL = 'invalid';
      const logger = getLogger('test.module');
      
      // Should default to 'info'
      logger.debug('Debug message');
      logger.info('Info message');

      // Debug should not be logged, info should be
      expect(consoleErrorSpy).toHaveBeenCalledOnce();
      expect(consoleErrorSpy.mock.calls[0][0]).toContain('Info message');
    });
  });
});
