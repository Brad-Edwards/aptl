import { v4 as uuidv4 } from 'uuid';
import { spawn, ChildProcess } from 'child_process';
import { logger } from './logger.js';
import { DockerManager } from './docker-manager.js';

export interface Session {
    id: string;
    containerId: string;
    process: ChildProcess;
    created: Date;
    lastActivity: Date;
    name?: string;
    buffer: string;
    bufferPosition: number;
}

export interface CreateSessionOptions {
    name?: string;
    workingDir?: string;
    env?: Record<string, string>;
    timeout?: number;
    shell?: string;
    initialCommand?: string;
}

export interface SendInputOptions {
    endWithNewline?: boolean;
}

export interface GetOutputOptions {
    since?: Date;
    maxBytes?: number;
    wait?: boolean;
    timeout?: number;
}

export class SessionManager {
    private sessions: Map<string, Session> = new Map();
    private dockerManager: DockerManager;

    constructor(dockerManager: DockerManager) {
        this.dockerManager = dockerManager;

        // Set up cleanup interval for idle sessions
        setInterval(() => this.cleanupIdleSessions(), 60000); // Check every minute
    }

    /**
     * Create a new terminal session
     */
    async createSession(options: CreateSessionOptions = {}): Promise<Session> {
        try {
            // Ensure Docker container is running
            await this.dockerManager.initialize();

            // Generate a unique session ID
            const sessionId = uuidv4();
            
            // Get container ID
            const containerId = await this.dockerManager.getContainerId();
            
            if (!containerId) {
                throw new Error('Failed to get container ID');
            }

            // Set up environment variables
            const env = {
                TERM: 'xterm-256color',
                ...options.env
            };

            // Determine shell to use
            const shell = options.shell || 'bash';
            
            // Spawn docker exec process
            const process = spawn('docker', [
                'exec',
                '-i',
                '-w', options.workingDir || '/ctf',
                '-e', `TERM=${env.TERM}`,
                ...Object.entries(env).filter(([key]) => key !== 'TERM').map(([key, value]) => ['-e', `${key}=${value}`]).flat(),
                containerId,
                shell
            ]);

            // Create session object
            const session: Session = {
                id: sessionId,
                containerId,
                process,
                created: new Date(),
                lastActivity: new Date(),
                name: options.name,
                buffer: '',
                bufferPosition: 0
            };

            // Set up event handlers
            process.stdout.on('data', (data) => {
                session.buffer += data.toString();
                session.lastActivity = new Date();
                logger.debug(`Session ${sessionId} received output: ${data.toString().length} bytes`);
            });

            process.stderr.on('data', (data) => {
                session.buffer += data.toString();
                session.lastActivity = new Date();
                logger.debug(`Session ${sessionId} received stderr: ${data.toString().length} bytes`);
            });

            process.on('close', (code) => {
                logger.info(`Session ${sessionId} closed with code ${code}`);
                this.sessions.delete(sessionId);
            });

            process.on('error', (error) => {
                logger.error(`Session ${sessionId} error: ${error.message}`);
                this.sessions.delete(sessionId);
            });

            // Store the session
            this.sessions.set(sessionId, session);

            // Run initial command if provided
            if (options.initialCommand) {
                await this.sendInput(sessionId, options.initialCommand);
            }

            logger.info(`Created new session ${sessionId} for container ${containerId}`);
            return session;
        } catch (error) {
            logger.error('Failed to create session:', error);
            throw new Error(`Session creation failed: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * Send input to a session
     */
    async sendInput(sessionId: string, input: string, options: SendInputOptions = {}): Promise<void> {
        const session = this.sessions.get(sessionId);
        if (!session) {
            throw new Error(`Session ${sessionId} not found`);
        }

        try {
            // Update last activity timestamp
            session.lastActivity = new Date();
            
            // Add newline if requested (default: true)
            const inputToSend = options.endWithNewline !== false && !input.endsWith('\n') 
                ? input + '\n' 
                : input;
            
            // Send input to the process
            if (session.process.stdin) {
                session.process.stdin.write(inputToSend);
            } else {
                throw new Error('Process stdin is not available');
            }
            
            logger.debug(`Sent input to session ${sessionId}: ${input.length} bytes`);
        } catch (error) {
            logger.error(`Failed to send input to session ${sessionId}:`, error);
            throw new Error(`Failed to send input: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * Get output from a session
     */
    async getOutput(sessionId: string, options: GetOutputOptions = {}): Promise<string> {
        const session = this.sessions.get(sessionId);
        if (!session) {
            throw new Error(`Session ${sessionId} not found`);
        }

        try {
            // If there's no new output and wait is true, wait for output
            if (session.bufferPosition >= session.buffer.length && options.wait) {
                const timeout = options.timeout || 5000; // Default: 5 seconds
                
                await new Promise<void>((resolve, reject) => {
                    const timeoutId = setTimeout(() => {
                        resolve(); // Resolve on timeout, we'll return whatever we have
                    }, timeout);
                    
                    const dataHandler = () => {
                        clearTimeout(timeoutId);
                        resolve();
                    };
                    
                    // Set up one-time handlers for new data
                    if (session.process.stdout) {
                        session.process.stdout.once('data', dataHandler);
                    }
                    if (session.process.stderr) {
                        session.process.stderr.once('data', dataHandler);
                    }
                    
                    // Also resolve if the process ends
                    session.process.once('close', () => {
                        clearTimeout(timeoutId);
                        resolve();
                    });
                });
            }
            
            // Get new output
            const output = session.buffer.substring(session.bufferPosition);
            
            // Update buffer position
            session.bufferPosition = session.buffer.length;
            
            // Update last activity timestamp
            session.lastActivity = new Date();
            
            logger.debug(`Retrieved output from session ${sessionId}: ${output.length} bytes`);
            
            return output;
        } catch (error) {
            logger.error(`Failed to get output from session ${sessionId}:`, error);
            throw new Error(`Failed to get output: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * List all active sessions
     */
    listSessions(): Session[] {
        return Array.from(this.sessions.values()).map(session => ({
            ...session,
            // Don't include the full buffer in the listing
            buffer: `${session.buffer.length} bytes`,
            // Don't include the process object
            process: undefined as any
        }));
    }

    /**
     * Terminate a session
     */
    async terminateSession(sessionId: string): Promise<void> {
        const session = this.sessions.get(sessionId);
        if (!session) {
            throw new Error(`Session ${sessionId} not found`);
        }

        try {
            // Send exit command
            if (session.process.stdin) {
                session.process.stdin.write('exit\n');
            }
            
            // Kill the process after a short delay if it doesn't exit
            setTimeout(() => {
                if (this.sessions.has(sessionId)) {
                    session.process.kill();
                    this.sessions.delete(sessionId);
                }
            }, 1000);
            
            logger.info(`Terminated session ${sessionId}`);
        } catch (error) {
            logger.error(`Failed to terminate session ${sessionId}:`, error);
            
            // Force kill if normal termination fails
            session.process.kill('SIGKILL');
            this.sessions.delete(sessionId);
            
            throw new Error(`Failed to terminate session: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * Clean up idle sessions
     */
    private cleanupIdleSessions(): void {
        const now = new Date();
        const maxIdleTime = 30 * 60 * 1000; // 30 minutes
        
        for (const [sessionId, session] of this.sessions.entries()) {
            const idleTime = now.getTime() - session.lastActivity.getTime();
            
            if (idleTime > maxIdleTime) {
                logger.info(`Cleaning up idle session ${sessionId} (idle for ${Math.round(idleTime / 1000 / 60)} minutes)`);
                this.terminateSession(sessionId).catch(error => {
                    logger.error(`Failed to clean up idle session ${sessionId}:`, error);
                });
            }
        }
    }
}
