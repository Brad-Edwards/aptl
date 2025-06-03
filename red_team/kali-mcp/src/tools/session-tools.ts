import { logger } from '../utils/logger.js';
import { SessionManager, CreateSessionOptions, SendInputOptions, GetOutputOptions } from '../utils/session-manager.js';

interface CreateSessionArgs {
    name?: string;
    workingDir?: string;
    env?: Record<string, string>;
    timeout?: number;
    shell?: string;
    initialCommand?: string;
}

interface SendInputArgs {
    sessionId: string;
    input: string;
    endWithNewline?: boolean;
}

interface GetOutputArgs {
    sessionId: string;
    wait?: boolean;
    timeout?: number;
}

interface TerminateSessionArgs {
    sessionId: string;
}

/**
 * Create a new terminal session
 */
export async function createSession(sessionManager: SessionManager, args: any) {
    // Validate arguments
    if (!args) {
        return {
            content: [
                {
                    type: 'text',
                    text: 'Invalid arguments. Please provide session options.',
                },
            ],
            isError: true,
        };
    }

    try {
        logger.info(`Creating new session with options: ${JSON.stringify(args)}`);
        
        // Create the session
        const options: CreateSessionOptions = {
            name: args.name,
            workingDir: args.workingDir,
            env: args.env,
            timeout: args.timeout,
            shell: args.shell,
            initialCommand: args.initialCommand,
        };
        
        const session = await sessionManager.createSession(options);
        
        // Get initial output
        const output = await sessionManager.getOutput(session.id);
        
        return {
            content: [
                {
                    type: 'text',
                    text: `Session created with ID: ${session.id}\n\nInitial output:\n${output}`,
                },
            ],
            metadata: {
                sessionId: session.id,
            },
        };
    } catch (error) {
        logger.error('Session creation failed:', error);
        
        return {
            content: [
                {
                    type: 'text',
                    text: `Session creation failed: ${error instanceof Error ? error.message : String(error)}`,
                },
            ],
            isError: true,
        };
    }
}

/**
 * Send input to a terminal session
 */
export async function sendInput(sessionManager: SessionManager, args: any) {
    // Validate arguments
    if (!args || typeof args.sessionId !== 'string' || typeof args.input !== 'string') {
        return {
            content: [
                {
                    type: 'text',
                    text: 'Invalid arguments. Please provide sessionId and input.',
                },
            ],
            isError: true,
        };
    }

    const { sessionId, input, endWithNewline } = args as SendInputArgs;

    try {
        logger.info(`Sending input to session ${sessionId}: ${input.length} bytes`);
        
        // Send input to the session
        const options: SendInputOptions = {
            endWithNewline,
        };
        
        await sessionManager.sendInput(sessionId, input, options);
        
        // Get output after sending input
        const output = await sessionManager.getOutput(sessionId, { wait: true, timeout: 1000 });
        
        return {
            content: [
                {
                    type: 'text',
                    text: output || '(No output received)',
                },
            ],
            metadata: {
                sessionId,
            },
        };
    } catch (error) {
        logger.error(`Failed to send input to session ${sessionId}:`, error);
        
        return {
            content: [
                {
                    type: 'text',
                    text: `Failed to send input: ${error instanceof Error ? error.message : String(error)}`,
                },
            ],
            isError: true,
        };
    }
}

/**
 * Get output from a terminal session
 */
export async function getOutput(sessionManager: SessionManager, args: any) {
    // Validate arguments
    if (!args || typeof args.sessionId !== 'string') {
        return {
            content: [
                {
                    type: 'text',
                    text: 'Invalid arguments. Please provide sessionId.',
                },
            ],
            isError: true,
        };
    }

    const { sessionId, wait, timeout } = args as GetOutputArgs;

    try {
        logger.info(`Getting output from session ${sessionId}`);
        
        // Get output from the session
        const options: GetOutputOptions = {
            wait,
            timeout,
        };
        
        const output = await sessionManager.getOutput(sessionId, options);
        
        return {
            content: [
                {
                    type: 'text',
                    text: output || '(No output available)',
                },
            ],
            metadata: {
                sessionId,
            },
        };
    } catch (error) {
        logger.error(`Failed to get output from session ${sessionId}:`, error);
        
        return {
            content: [
                {
                    type: 'text',
                    text: `Failed to get output: ${error instanceof Error ? error.message : String(error)}`,
                },
            ],
            isError: true,
        };
    }
}

/**
 * List all active terminal sessions
 */
export async function listSessions(sessionManager: SessionManager) {
    try {
        logger.info('Listing active sessions');
        
        // Get all active sessions
        const sessions = sessionManager.listSessions();
        
        if (sessions.length === 0) {
            return {
                content: [
                    {
                        type: 'text',
                        text: 'No active sessions found.',
                    },
                ],
            };
        }
        
        // Format session information
        const sessionInfo = sessions.map(session => ({
            id: session.id,
            name: session.name || 'unnamed',
            created: session.created.toISOString(),
            lastActivity: session.lastActivity.toISOString(),
            bufferSize: session.buffer,
        }));
        
        return {
            content: [
                {
                    type: 'text',
                    text: `Active sessions (${sessions.length}):\n\n${JSON.stringify(sessionInfo, null, 2)}`,
                },
            ],
        };
    } catch (error) {
        logger.error('Failed to list sessions:', error);
        
        return {
            content: [
                {
                    type: 'text',
                    text: `Failed to list sessions: ${error instanceof Error ? error.message : String(error)}`,
                },
            ],
            isError: true,
        };
    }
}

/**
 * Terminate a terminal session
 */
export async function terminateSession(sessionManager: SessionManager, args: any) {
    // Validate arguments
    if (!args || typeof args.sessionId !== 'string') {
        return {
            content: [
                {
                    type: 'text',
                    text: 'Invalid arguments. Please provide sessionId.',
                },
            ],
            isError: true,
        };
    }

    const { sessionId } = args as TerminateSessionArgs;

    try {
        logger.info(`Terminating session ${sessionId}`);
        
        // Terminate the session
        await sessionManager.terminateSession(sessionId);
        
        return {
            content: [
                {
                    type: 'text',
                    text: `Session ${sessionId} terminated successfully.`,
                },
            ],
        };
    } catch (error) {
        logger.error(`Failed to terminate session ${sessionId}:`, error);
        
        return {
            content: [
                {
                    type: 'text',
                    text: `Failed to terminate session: ${error instanceof Error ? error.message : String(error)}`,
                },
            ],
            isError: true,
        };
    }
}
