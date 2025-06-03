import winston from 'winston';

// Logger instance
export const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ level, message, timestamp }) => {
            return `${timestamp} [${level.toUpperCase()}]: ${message}`;
        })
    ),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'kali-ctf-server.log' })
    ]
});

// Setup logger with custom configuration
export function setupLogger(options?: {
    level?: string;
    logToFile?: boolean;
    filename?: string;
}): void {
    // Set log level
    if (options?.level) {
        logger.level = options.level;
    }

    // Configure transports
    const transports: winston.transport[] = [new winston.transports.Console()];
    
    // Add file transport if enabled
    if (options?.logToFile !== false) {
        transports.push(
            new winston.transports.File({
                filename: options?.filename || 'kali-ctf-server.log'
            })
        );
    }

    // Update logger configuration
    logger.configure({
        transports
    });

    logger.info('Logger initialized');
}
