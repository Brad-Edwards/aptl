import Dockerode from 'dockerode';
import { logger } from './logger.js';

export class DockerManager {
    private docker: Dockerode;
    private containerName: string;
    private container: Dockerode.Container | null = null;

    constructor(containerName: string) {
        this.docker = new Dockerode();
        this.containerName = containerName;
    }

    /**
     * Get the ID of the container
     */
    async getContainerId(): Promise<string | null> {
        if (!this.container) {
            await this.initialize();
        }
        
        if (!this.container) {
            return null;
        }
        
        const containerInfo = await this.container.inspect();
        return containerInfo.Id;
    }

    /**
     * Initialize the Docker manager and ensure the container is running
     */
    async initialize(): Promise<void> {
        try {
            // Check if container exists
            const containers = await this.docker.listContainers({ all: true });
            const containerInfo = containers.find(
                (container) => container.Names.includes(`/${this.containerName}`)
            );

            if (containerInfo) {
                // Container exists, get reference to it
                this.container = this.docker.getContainer(containerInfo.Id);
                
                // Check if container is running
                if (containerInfo.State !== 'running') {
                    logger.info(`Starting existing container: ${this.containerName}`);
                    await this.container.start();
                } else {
                    logger.info(`Container already running: ${this.containerName}`);
                }
            } else {
                // Container doesn't exist, create and start it
                logger.info(`Creating and starting new container: ${this.containerName}`);
                await this.createContainer();
            }
        } catch (error) {
            logger.error('Failed to initialize Docker manager:', error);
            throw new Error(`Docker initialization failed: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * Create and start the Kali Linux container
     */
    private async createContainer(): Promise<void> {
        try {
            // Pull the Kali Linux image if needed
            logger.info('Pulling Kali Linux image...');
            await new Promise<void>((resolve, reject) => {
                this.docker.pull('kalilinux/kali-rolling', (err: any, stream: any) => {
                    if (err) {
                        reject(err);
                        return;
                    }

                    this.docker.modem.followProgress(stream, (err: any) => {
                        if (err) {
                            reject(err);
                            return;
                        }
                        resolve();
                    });
                });
            });

            // Create the container
            logger.info('Creating Kali Linux container...');
            const container = await this.docker.createContainer({
                Image: 'kalilinux/kali-rolling',
                name: this.containerName,
                Tty: true,
                Cmd: ['/bin/bash'],
                WorkingDir: '/ctf',
                HostConfig: {
                    Binds: [
                        `${this.containerName}-shared:/shared`
                    ]
                }
            });

            // Start the container
            logger.info('Starting Kali Linux container...');
            await container.start();
            this.container = container;

            // Install basic tools
            logger.info('Installing basic tools...');
            await this.executeCommand('apt-get update && apt-get install -y curl wget git python3 python3-pip vim nano tmux netcat-traditional iputils-ping net-tools whois dnsutils');
            
            // Create working directories
            logger.info('Setting up working directories...');
            await this.executeCommand('mkdir -p /ctf /shared');
        } catch (error) {
            logger.error('Failed to create container:', error);
            throw new Error(`Container creation failed: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * Execute a command in the container
     */
    async executeCommand(command: string): Promise<string> {
        if (!this.container) {
            throw new Error('Container not initialized');
        }

        try {
            logger.debug(`Executing command: ${command}`);
            
            const exec = await this.container.exec({
                Cmd: ['bash', '-c', command],
                AttachStdout: true,
                AttachStderr: true
            });

            const stream = await exec.start({});
            
            return new Promise<string>((resolve, reject) => {
                let output = '';
                
                stream.on('data', (chunk: Buffer) => {
                    output += chunk.toString();
                });
                
                stream.on('end', () => {
                    resolve(output);
                });
                
                stream.on('error', (err: Error) => {
                    reject(err);
                });
            });
        } catch (error) {
            logger.error(`Command execution failed: ${command}`, error);
            throw new Error(`Command execution failed: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * Read a file from the container
     */
    async readFile(path: string): Promise<string> {
        try {
            return await this.executeCommand(`cat ${path}`);
        } catch (error) {
            logger.error(`Failed to read file: ${path}`, error);
            throw new Error(`Failed to read file: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * Write content to a file in the container
     */
    async writeFile(path: string, content: string): Promise<void> {
        try {
            // Create temporary file with content
            const tempFile = `/tmp/file-${Date.now()}`;
            await this.executeCommand(`echo '${content.replace(/'/g, "'\\''")}' > ${tempFile}`);
            
            // Create directory if it doesn't exist
            await this.executeCommand(`mkdir -p $(dirname ${path})`);
            
            // Move file to destination
            await this.executeCommand(`mv ${tempFile} ${path}`);
        } catch (error) {
            logger.error(`Failed to write file: ${path}`, error);
            throw new Error(`Failed to write file: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * Stop and remove the container
     */
    async cleanup(): Promise<void> {
        if (!this.container) {
            return;
        }

        try {
            logger.info(`Stopping container: ${this.containerName}`);
            await this.container.stop();
            
            logger.info(`Removing container: ${this.containerName}`);
            await this.container.remove();
            
            this.container = null;
        } catch (error) {
            logger.error('Failed to cleanup container:', error);
            throw new Error(`Container cleanup failed: ${error instanceof Error ? error.message : String(error)}`);
        }
    }
}
