import { DockerManager } from '../utils/docker-manager.js';
import { logger } from '../utils/logger.js';

interface ReadFileArgs {
    path: string;
}

interface WriteFileArgs {
    path: string;
    content: string;
}

/**
 * Read a file from the Kali Linux container
 */
export async function readFile(dockerManager: DockerManager, args: any) {
    // Validate arguments
    if (!args || typeof args.path !== 'string') {
        return {
            content: [
                {
                    type: 'text',
                    text: 'Invalid arguments. Please provide a file path.',
                },
            ],
            isError: true,
        };
    }

    const { path } = args as ReadFileArgs;

    try {
        logger.info(`Reading file: ${path}`);
        const content = await dockerManager.readFile(path);

        return {
            content: [
                {
                    type: 'text',
                    text: content,
                },
            ],
        };
    } catch (error) {
        logger.error(`Failed to read file: ${path}`, error);
        
        return {
            content: [
                {
                    type: 'text',
                    text: `Failed to read file: ${error instanceof Error ? error.message : String(error)}`,
                },
            ],
            isError: true,
        };
    }
}

/**
 * Write content to a file in the Kali Linux container
 */
export async function writeFile(dockerManager: DockerManager, args: any) {
    // Validate arguments
    if (!args || typeof args.path !== 'string' || typeof args.content !== 'string') {
        return {
            content: [
                {
                    type: 'text',
                    text: 'Invalid arguments. Please provide a file path and content.',
                },
            ],
            isError: true,
        };
    }

    const { path, content } = args as WriteFileArgs;

    try {
        logger.info(`Writing to file: ${path}`);
        await dockerManager.writeFile(path, content);

        return {
            content: [
                {
                    type: 'text',
                    text: `File written successfully: ${path}`,
                },
            ],
        };
    } catch (error) {
        logger.error(`Failed to write file: ${path}`, error);
        
        return {
            content: [
                {
                    type: 'text',
                    text: `Failed to write file: ${error instanceof Error ? error.message : String(error)}`,
                },
            ],
            isError: true,
        };
    }
}
