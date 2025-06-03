import { DockerManager } from '../utils/docker-manager.js';
import { logger } from '../utils/logger.js';

interface ExecuteCommandArgs {
    command: string;
}

/**
 * Execute a command in the Kali Linux container
 */
export async function executeCommand(dockerManager: DockerManager, args: any) {
    // Validate arguments
    if (!args || typeof args.command !== 'string') {
        return {
            content: [
                {
                    type: 'text',
                    text: 'Invalid arguments. Please provide a command string.',
                },
            ],
            isError: true,
        };
    }

    const { command } = args as ExecuteCommandArgs;

    try {
        logger.info(`Executing command: ${command}`);
        const output = await dockerManager.executeCommand(command);

        return {
            content: [
                {
                    type: 'text',
                    text: output || '(Command executed successfully with no output)',
                },
            ],
        };
    } catch (error) {
        logger.error(`Command execution failed: ${command}`, error);
        
        return {
            content: [
                {
                    type: 'text',
                    text: `Command execution failed: ${error instanceof Error ? error.message : String(error)}`,
                },
            ],
            isError: true,
        };
    }
}
