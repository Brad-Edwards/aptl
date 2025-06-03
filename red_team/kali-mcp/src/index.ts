#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
    CallToolRequestSchema,
    ErrorCode,
    ListResourcesRequestSchema,
    ListResourceTemplatesRequestSchema,
    ListToolsRequestSchema,
    McpError,
    ReadResourceRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { setupLogger, logger } from './utils/logger.js';
import { DockerManager } from './utils/docker-manager.js';
import { SessionManager } from './utils/session-manager.js';
import { executeCommand } from './tools/execute-command.js';
import { readFile, writeFile } from './tools/file-access.js';
import { 
    createSession, 
    sendInput, 
    getOutput, 
    listSessions, 
    terminateSession 
} from './tools/session-tools.js';

// Setup logger
setupLogger();

// Container name for the Kali Linux container
const CONTAINER_NAME = process.env.CONTAINER_NAME || 'kali-ctf';

class KaliCTFServer {
    private server: Server;
    private dockerManager: DockerManager;
    private sessionManager: SessionManager;

    constructor() {
        this.server = new Server(
            {
                name: 'kali-ctf-server',
                version: '0.2.0',
            },
            {
                capabilities: {
                    resources: {},
                    tools: {},
                },
            }
        );

        this.dockerManager = new DockerManager(CONTAINER_NAME);
        this.sessionManager = new SessionManager(this.dockerManager);

        this.setupResourceHandlers();
        this.setupToolHandlers();
        
        // Error handling
        this.server.onerror = (error) => logger.error('[MCP Error]', error);
        process.on('SIGINT', async () => {
            await this.server.close();
            process.exit(0);
        });
    }

    private setupResourceHandlers() {
        // List available resources
        this.server.setRequestHandler(ListResourcesRequestSchema, async () => ({
            resources: [
                {
                    uri: `kali://files/readme`,
                    name: `Kali CTF README`,
                    mimeType: 'text/plain',
                    description: 'Information about the Kali CTF environment',
                },
            ],
        }));

        // List resource templates
        this.server.setRequestHandler(
            ListResourceTemplatesRequestSchema,
            async () => ({
                resourceTemplates: [
                    {
                        uriTemplate: 'kali://files/{path}',
                        name: 'File in Kali environment',
                        mimeType: 'application/octet-stream',
                        description: 'Access files in the Kali Linux environment',
                    },
                ],
            })
        );

        // Read resources
        this.server.setRequestHandler(
            ReadResourceRequestSchema,
            async (request) => {
                const fileMatch = request.params.uri.match(/^kali:\/\/files\/(.+)$/);
                
                if (fileMatch) {
                    const filePath = fileMatch[1];
                    try {
                        const content = await this.dockerManager.readFile(filePath);
                        return {
                            contents: [
                                {
                                    uri: request.params.uri,
                                    mimeType: 'text/plain',
                                    text: content,
                                },
                            ],
                        };
                    } catch (error) {
                        throw new McpError(
                            ErrorCode.InternalError,
                            `Failed to read file: ${error instanceof Error ? error.message : String(error)}`
                        );
                    }
                }

                // Handle readme resource
                if (request.params.uri === 'kali://files/readme') {
                    return {
                        contents: [
                            {
                                uri: request.params.uri,
                                mimeType: 'text/plain',
                                text: `# Kali CTF Environment

This is a Kali Linux environment for CTF challenges.

## Available Tools

- Web exploitation: burpsuite, sqlmap, dirb, nikto
- Network tools: nmap, wireshark, tcpdump
- Password cracking: hydra, john, hashcat
- Forensics: binwalk, foremost, exiftool
- Reverse engineering: gdb, radare2
- Cryptography: openssl
- Exploitation: metasploit-framework

## Usage

### Non-Interactive Commands

You can execute commands in this environment using the 'execute_command' tool:
- 'execute_command': Execute a command and get the output

You can access files using the file access tools:
- 'read_file': Read a file from the environment
- 'write_file': Write a file to the environment

### Interactive Sessions

For interactive tools like Metasploit, you can use the session management tools:
- 'create_session': Create a new interactive terminal session
- 'send_input': Send input to an interactive session
- 'get_output': Get output from an interactive session
- 'list_sessions': List all active interactive sessions
- 'terminate_session': Terminate an interactive session

## Working Directory

The working directory is /ctf
Shared files are stored in /shared
`,
                            },
                        ],
                    };
                }

                throw new McpError(
                    ErrorCode.InvalidRequest,
                    `Invalid URI format: ${request.params.uri}`
                );
            }
        );
    }

    private setupToolHandlers() {
        // List available tools
        this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
            tools: [
                // Command execution tools
                {
                    name: 'execute_command',
                    description: 'Execute a command in the Kali Linux environment',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            command: {
                                type: 'string',
                                description: 'Command to execute',
                            },
                        },
                        required: ['command'],
                    },
                },
                
                // File access tools
                {
                    name: 'read_file',
                    description: 'Read a file from the Kali Linux environment',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            path: {
                                type: 'string',
                                description: 'Path to the file',
                            },
                        },
                        required: ['path'],
                    },
                },
                {
                    name: 'write_file',
                    description: 'Write a file to the Kali Linux environment',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            path: {
                                type: 'string',
                                description: 'Path to the file',
                            },
                            content: {
                                type: 'string',
                                description: 'Content to write to the file',
                            },
                        },
                        required: ['path', 'content'],
                    },
                },
                
                // Session management tools
                {
                    name: 'create_session',
                    description: 'Create a new interactive terminal session',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            name: {
                                type: 'string',
                                description: 'Name for the session (optional)',
                            },
                            workingDir: {
                                type: 'string',
                                description: 'Working directory for the session (default: /ctf)',
                            },
                            env: {
                                type: 'object',
                                description: 'Environment variables for the session',
                            },
                            shell: {
                                type: 'string',
                                description: 'Shell to use (default: bash)',
                            },
                            initialCommand: {
                                type: 'string',
                                description: 'Command to run when the session starts',
                            },
                        },
                    },
                },
                {
                    name: 'send_input',
                    description: 'Send input to an interactive terminal session',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            sessionId: {
                                type: 'string',
                                description: 'ID of the session',
                            },
                            input: {
                                type: 'string',
                                description: 'Input to send to the session',
                            },
                            endWithNewline: {
                                type: 'boolean',
                                description: 'Whether to append a newline to the input (default: true)',
                            },
                        },
                        required: ['sessionId', 'input'],
                    },
                },
                {
                    name: 'get_output',
                    description: 'Get output from an interactive terminal session',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            sessionId: {
                                type: 'string',
                                description: 'ID of the session',
                            },
                            wait: {
                                type: 'boolean',
                                description: 'Whether to wait for output if none is available (default: false)',
                            },
                            timeout: {
                                type: 'number',
                                description: 'Timeout in milliseconds when waiting for output (default: 5000)',
                            },
                        },
                        required: ['sessionId'],
                    },
                },
                {
                    name: 'list_sessions',
                    description: 'List all active interactive terminal sessions',
                    inputSchema: {
                        type: 'object',
                        properties: {},
                    },
                },
                {
                    name: 'terminate_session',
                    description: 'Terminate an interactive terminal session',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            sessionId: {
                                type: 'string',
                                description: 'ID of the session to terminate',
                            },
                        },
                        required: ['sessionId'],
                    },
                },
            ],
        }));

        // Handle tool calls
        this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
            switch (request.params.name) {
                // Command execution tools
                case 'execute_command':
                    return executeCommand(this.dockerManager, request.params.arguments);
                
                // File access tools
                case 'read_file':
                    return readFile(this.dockerManager, request.params.arguments);
                case 'write_file':
                    return writeFile(this.dockerManager, request.params.arguments);
                
                // Session management tools
                case 'create_session':
                    return createSession(this.sessionManager, request.params.arguments);
                case 'send_input':
                    return sendInput(this.sessionManager, request.params.arguments);
                case 'get_output':
                    return getOutput(this.sessionManager, request.params.arguments);
                case 'list_sessions':
                    return listSessions(this.sessionManager);
                case 'terminate_session':
                    return terminateSession(this.sessionManager, request.params.arguments);
                
                default:
                    throw new McpError(
                        ErrorCode.MethodNotFound,
                        `Unknown tool: ${request.params.name}`
                    );
            }
        });
    }

    async run() {
        try {
            // Initialize Docker manager
            await this.dockerManager.initialize();
            
            // Connect to the MCP transport
            const transport = new StdioServerTransport();
            await this.server.connect(transport);
            
            logger.info('Kali CTF MCP server running on stdio');
        } catch (error) {
            logger.error('Failed to start server:', error);
            process.exit(1);
        }
    }
}

// Start the server
const server = new KaliCTFServer();
server.run().catch(console.error);
