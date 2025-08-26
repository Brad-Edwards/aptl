
import { Client, ClientChannel } from 'ssh2';
import { readFileSync } from 'fs';
import { EventEmitter } from 'events';

export interface CommandResult {
  stdout: string;
  stderr: string;
  code: number | null;
  signal: string | null;
}

export class SSHError extends Error {
  constructor(message: string, cause?: Error) {
    super(message);
    this.name = 'SSHError';
    this.cause = cause;
  }
}

export type SessionType = 'interactive' | 'background';

export interface SessionMetadata {
  sessionId: string;
  target: string;
  username: string;
  type: SessionType;
  createdAt: Date;
  lastActivity: Date;
  port: number;
  workingDirectory: string;
  environmentVars: Map<string, string>;
  isActive: boolean;
  commandHistory: string[];
}

export interface CommandRequest {
  id: string;
  command: string;
  resolve: (result: CommandResult) => void;
  reject: (error: Error) => void;
  timeout?: number;
}

interface ConnectionInfo {
  client: Client;
  connected: boolean;
}

/**
 * Manages a persistent SSH shell session with command queuing and output buffering.
 * 
 * Features:
 * - Maintains a persistent shell connection for stateful operations
 * - Queues commands to ensure sequential execution
 * - Buffers output for background sessions
 * - Implements keep-alive and session timeout mechanisms
 * - Parses command output using delimiters to separate command results
 * 
 * @extends EventEmitter
 * @fires PersistentSession#closed - When the session is closed
 * @fires PersistentSession#error - When an error occurs
 * @fires PersistentSession#timeout - When the session times out
 * 
 * @example
 * const session = new PersistentSession('session-1', '192.168.1.100', 'user', 'interactive', sshClient);
 * await session.initialize();
 * const result = await session.executeCommand('ls -la');
 * console.log(result.stdout);
 */
export class PersistentSession extends EventEmitter {
  private shell: ClientChannel | null = null;
  private outputBuffer: string[] = [];
  private commandQueue: CommandRequest[] = [];
  private currentCommand: CommandRequest | null = null;
  private sessionInfo: SessionMetadata;
  private client: Client;
  private commandDelimiter: string;
  private keepAliveInterval: NodeJS.Timeout | null = null;
  private sessionTimeout: NodeJS.Timeout | null = null;
  private isInitialized = false;
  private outputData = '';

  /**
   * Creates a new persistent SSH session.
   * 
   * @param sessionId - Unique identifier for this session
   * @param target - Target host IP or hostname
   * @param username - SSH username
   * @param type - Session type: 'interactive' for stateful operations, 'background' for long-running processes
   * @param client - Established SSH2 client connection
   * @param port - SSH port number (default: 22)
   */
  constructor(
    sessionId: string,
    target: string,
    username: string,
    type: SessionType,
    client: Client,
    port: number = 22
  ) {
    super();
    this.client = client;
    this.commandDelimiter = `___CMD_${Date.now()}_${Math.random().toString(36).substring(2, 11)}___`;
    
    this.sessionInfo = {
      sessionId,
      target,
      username,
      type,
      createdAt: new Date(),
      lastActivity: new Date(),
      port,
      workingDirectory: '~',
      environmentVars: new Map(),
      isActive: false,
      commandHistory: []
    };
  }

  /**
   * Initializes the shell session and sets up event handlers.
   * Must be called before executing commands.
   * 
   * @returns Promise that resolves when the shell is ready
   * @throws {SSHError} If shell creation fails
   */
  async initialize(): Promise<void> {
    if (this.isInitialized) return;

    return new Promise((resolve, reject) => {
      this.client.shell((err, stream) => {
        if (err) {
          reject(new SSHError(`Failed to create shell: ${err.message}`, err));
          return;
        }

        this.shell = stream;
        this.sessionInfo.isActive = true;
        this.isInitialized = true;

        stream.on('data', (data: Buffer) => {
          this.handleShellOutput(data.toString());
        });

        stream.stderr.on('data', (data: Buffer) => {
          this.handleShellOutput(data.toString());
        });

        stream.on('close', () => {
          this.sessionInfo.isActive = false;
          this.emit('closed');
          this.cleanup();
        });

        stream.on('error', (error: Error) => {
          this.emit('error', new SSHError(`Shell error: ${error.message}`, error));
        });

        this.startKeepAlive();
        this.resetSessionTimeout();

        setTimeout(() => {
          resolve();
        }, 1000);
      });
    });
  }

  /**
   * Executes a command in the persistent shell session.
   * Commands are queued and executed sequentially.
   * 
   * @param command - The command to execute
   * @param timeout - Command timeout in milliseconds (default: 30000)
   * @returns Promise resolving to command result with stdout, stderr, exit code
   * @throws {SSHError} If session is not initialized or inactive
   */
  async executeCommand(command: string, timeout: number = 30000): Promise<CommandResult> {
    if (!this.isInitialized || !this.shell || !this.sessionInfo.isActive) {
      throw new SSHError('Session not initialized or inactive');
    }

    return new Promise((resolve, reject) => {
      const commandId = `${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;
      const request: CommandRequest = {
        id: commandId,
        command,
        resolve,
        reject,
        timeout
      };

      this.commandQueue.push(request);
      this.sessionInfo.commandHistory.push(command);
      this.sessionInfo.lastActivity = new Date();
      this.resetSessionTimeout();

      if (!this.currentCommand) {
        this.processNextCommand();
      }
    });
  }

  private processNextCommand(): void {
    if (this.commandQueue.length === 0 || !this.shell) return;

    this.currentCommand = this.commandQueue.shift()!;
    this.outputData = '';

    const startDelimiter = `${this.commandDelimiter}_START_${this.currentCommand.id}`;
    const endDelimiter = `${this.commandDelimiter}_END_${this.currentCommand.id}`;
    
    const wrappedCommand = `echo "${startDelimiter}"; ${this.currentCommand.command}; echo "${endDelimiter}:$?"`;
    
    this.shell.write(wrappedCommand + '\n');

    if (this.currentCommand.timeout) {
      const commandId = this.currentCommand.id;
      setTimeout(() => {
        if (this.currentCommand?.id === commandId) {
          this.currentCommand!.reject(new SSHError(`Command timeout: ${this.currentCommand!.command}`));
          this.currentCommand = null;
          this.processNextCommand();
        }
      }, this.currentCommand.timeout);
    }
  }

  private handleShellOutput(data: string): void {
    if (this.sessionInfo.type === 'background') {
      this.outputBuffer.push(data);
      if (this.outputBuffer.length > 10000) {
        this.outputBuffer = this.outputBuffer.slice(-5000);
      }
    }

    if (this.currentCommand) {
      this.outputData += data;
      this.parseCommandOutput();
    }
  }

  /**
   * Parses accumulated output data to extract command results.
   * Uses delimiter patterns to identify command boundaries and exit codes.
   * Resolves the current command promise when complete output is detected.
   * 
   * @private
   */
  private parseCommandOutput(): void {
    if (!this.currentCommand) return;

    const endPattern = `${this.commandDelimiter}_END_${this.currentCommand.id}:(\\d+)`;
    const endMatch = this.outputData.match(new RegExp(endPattern));
    
    if (endMatch) {
      const exitCode = parseInt(endMatch[1], 10);
      const startPattern = `${this.commandDelimiter}_START_${this.currentCommand.id}`;
      const startIndex = this.outputData.indexOf(startPattern);
      const endIndex = this.outputData.indexOf(endMatch[0]);
      
      if (startIndex !== -1 && endIndex !== -1) {
        const output = this.outputData.substring(
          startIndex + startPattern.length,
          endIndex
        ).trim();

        const lines = output.split('\n');
        if (lines[0] === '') lines.shift();
        if (lines[lines.length - 1] === '') lines.pop();
        
        const cleanOutput = lines.join('\n');

        this.currentCommand.resolve({
          stdout: cleanOutput,
          stderr: '',
          code: exitCode,
          signal: null
        });
        
        this.currentCommand = null;
        this.processNextCommand();
      }
    }
  }

  getSessionInfo(): SessionMetadata {
    return { ...this.sessionInfo };
  }

  getBufferedOutput(lines?: number, clear: boolean = false): string[] {
    const result = lines ? this.outputBuffer.slice(-lines) : [...this.outputBuffer];
    if (clear) {
      this.outputBuffer = [];
    }
    return result;
  }

  private startKeepAlive(): void {
    this.keepAliveInterval = setInterval(() => {
      if (this.shell && this.sessionInfo.isActive && this.commandQueue.length === 0 && !this.currentCommand) {
        this.shell.write('\n');
      }
    }, 30000);
  }

  private resetSessionTimeout(): void {
    if (this.sessionTimeout) {
      clearTimeout(this.sessionTimeout);
    }
    
    this.sessionTimeout = setTimeout(() => {
      this.emit('timeout');
      this.close();
    }, 300000); // 5 minutes timeout
  }

  close(): void {
    this.cleanup();
    if (this.shell) {
      this.shell.end();
    }
  }

  private cleanup(): void {
    if (this.keepAliveInterval) {
      clearInterval(this.keepAliveInterval);
      this.keepAliveInterval = null;
    }
    
    if (this.sessionTimeout) {
      clearTimeout(this.sessionTimeout);
      this.sessionTimeout = null;
    }
    
    this.sessionInfo.isActive = false;
    this.currentCommand = null;
    this.commandQueue = [];
  }
}

/**
 * Manages SSH connections and persistent sessions.
 * 
 * Features:
 * - Connection pooling and reuse
 * - Multiple persistent session management
 * - Automatic connection cleanup
 * - Session lifecycle management
 * 
 * @example
 * const manager = new SSHConnectionManager();
 * const result = await manager.executeCommand('192.168.1.100', 'user', '/path/to/key', 'ls -la');
 * 
 * // Or with persistent sessions
 * const session = await manager.createSession('session-1', '192.168.1.100', 'user', 'interactive', '/path/to/key');
 * const result = await manager.executeInSession('session-1', 'cd /tmp && pwd');
 */
export class SSHConnectionManager {
  private connections: Map<string, ConnectionInfo> = new Map();
  private sessions: Map<string, PersistentSession> = new Map();

  /**
   * Execute a single command on a target host via SSH.
   * Creates a temporary connection if needed, reuses existing connections when possible.
   * 
   * @param host - Target host IP or hostname
   * @param username - SSH username
   * @param privateKeyPath - Path to SSH private key
   * @param command - Command to execute
   * @param port - SSH port (default: 22)
   * @param timeout - Command timeout in milliseconds (default: 30000)
   * @returns Command execution result
   * @throws {SSHError} On connection or execution failure
   */
  public async executeCommand(
    host: string,
    username: string,
    privateKeyPath: string,
    command: string,
    port: number = 22,
    timeout: number = 30000
  ): Promise<CommandResult> {
    const client = await this.getConnection(host, username, privateKeyPath, port);
    
    return new Promise((resolve, reject) => {
      let stdout = '';
      let stderr = '';
      let hasTimedOut = false;

      const timeoutId = setTimeout(() => {
        hasTimedOut = true;
        reject(new SSHError(`Command timeout after ${timeout}ms: ${command}`));
      }, timeout);

      client.exec(command, (err, stream) => {
        if (err) {
          clearTimeout(timeoutId);
          reject(new SSHError(`Failed to execute command: ${err.message}`, err));
          return;
        }

        stream.on('close', (code: number | null, signal: string | null) => {
          clearTimeout(timeoutId);
          if (!hasTimedOut) {
            resolve({ stdout, stderr, code, signal });
          }
        });

        stream.on('data', (data: Buffer) => {
          stdout += data.toString();
        });

        stream.stderr.on('data', (data: Buffer) => {
          stderr += data.toString();
        });

        stream.on('error', (error: Error) => {
          clearTimeout(timeoutId);
          if (!hasTimedOut) {
            reject(new SSHError(`Stream error: ${error.message}`, error));
          }
        });
      });
    });
  }

  /**
   * Get or create an SSH connection to a host
   */
  private async getConnection(
    host: string,
    username: string,
    privateKeyPath: string,
    port: number = 22
  ): Promise<Client> {
    const connectionKey = `${username}@${host}:${port}`;
    
    if (this.connections.has(connectionKey)) {
      const connInfo = this.connections.get(connectionKey)!;
      if (connInfo.connected) {
        return connInfo.client;
      }
      // Connection is dead, remove it
      this.connections.delete(connectionKey);
    }

    // Create new connection
    const client = await this.createConnection(host, username, privateKeyPath, port);
    this.connections.set(connectionKey, { client, connected: true });
    
    return client;
  }

  /**
   * Create a new SSH connection
   */
  private async createConnection(
    host: string,
    username: string,
    privateKeyPath: string,
    port: number = 22
  ): Promise<Client> {
    let privateKey: Buffer;
    try {
      privateKey = readFileSync(privateKeyPath);
    } catch (error) {
      throw new SSHError(
        `Failed to read SSH private key from ${privateKeyPath}: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }

    const client = new Client();

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new SSHError('Connection timeout'));
      }, 30000);

      client.on('ready', () => {
        clearTimeout(timeout);
        resolve(client);
      });

      client.on('error', (err) => {
        clearTimeout(timeout);
        reject(new SSHError(`Connection failed to ${host}:${port}: ${err.message}`, err));
      });

      client.on('close', () => {
        // Mark connection as disconnected
        const connectionKey = `${username}@${host}:${port}`;
        const connInfo = this.connections.get(connectionKey);
        if (connInfo) {
          connInfo.connected = false;
        }
      });

      client.connect({
        host,
        port,
        username,
        privateKey,
        timeout: 30000,
        readyTimeout: 30000,
        keepaliveInterval: 30000,
        keepaliveCountMax: 3,
      });
    });
  }

  /**
   * Create a new persistent SSH session for stateful operations.
   * Sessions maintain shell state between commands and can run in interactive or background mode.
   * 
   * @param sessionId - Unique session identifier
   * @param target - Target host IP or hostname
   * @param username - SSH username
   * @param type - 'interactive' for stateful ops, 'background' for long-running processes
   * @param privateKeyPath - Path to SSH private key
   * @param port - SSH port (default: 22)
   * @returns Initialized PersistentSession instance
   * @throws {SSHError} If session ID already exists or connection fails
   */
  public async createSession(
    sessionId: string,
    target: string,
    username: string,
    type: SessionType,
    privateKeyPath: string,
    port: number = 22
  ): Promise<PersistentSession> {
    if (this.sessions.has(sessionId)) {
      throw new SSHError(`Session with ID '${sessionId}' already exists`);
    }

    const client = await this.getConnection(target, username, privateKeyPath, port);
    const session = new PersistentSession(sessionId, target, username, type, client, port);
    
    await session.initialize();
    this.sessions.set(sessionId, session);

    session.on('closed', () => {
      this.sessions.delete(sessionId);
    });

    session.on('error', (error) => {
      console.error(`[SSH] Session ${sessionId} error:`, error);
      this.sessions.delete(sessionId);
    });

    session.on('timeout', () => {
      console.error(`[SSH] Session ${sessionId} timed out`);
      this.sessions.delete(sessionId);
    });

    return session;
  }

  /**
   * Get an existing session by ID.
   * 
   * @param sessionId - Session identifier to look up
   * @returns PersistentSession if found, undefined otherwise
   */
  public getSession(sessionId: string): PersistentSession | undefined {
    return this.sessions.get(sessionId);
  }

  /**
   * List all active sessions.
   * 
   * @returns Array of session metadata for all active sessions
   */
  public listSessions(): SessionMetadata[] {
    return Array.from(this.sessions.values()).map(session => session.getSessionInfo());
  }

  /**
   * Close a specific session.
   * 
   * @param sessionId - Session identifier to close
   * @returns true if session was found and closed, false if not found
   */
  public async closeSession(sessionId: string): Promise<boolean> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      return false;
    }

    return new Promise<boolean>((resolve) => {
      const timeout = setTimeout(() => {
        // Force cleanup even if 'closed' event doesn't fire
        this.sessions.delete(sessionId);
        resolve(true);
      }, 3000); // 3 second timeout
      
      // Use once() instead of on() to avoid multiple event listeners
      session.once('closed', () => {
        clearTimeout(timeout);
        this.sessions.delete(sessionId);
        resolve(true);
      });
      
      session.close();
    });
  }

  /**
   * Execute a command in a specific session.
   * Maintains session state between commands.
   * 
   * @param sessionId - Session identifier
   * @param command - Command to execute
   * @param timeout - Command timeout in milliseconds
   * @returns Command execution result
   * @throws {SSHError} If session not found
   */
  public async executeInSession(
    sessionId: string,
    command: string,
    timeout?: number
  ): Promise<CommandResult> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new SSHError(`Session '${sessionId}' not found`);
    }

    return session.executeCommand(command, timeout);
  }

  /**
   * Get buffered output from a background session.
   * Useful for monitoring long-running processes.
   * 
   * @param sessionId - Session identifier
   * @param lines - Number of recent lines to retrieve (optional)
   * @param clear - Whether to clear the buffer after reading
   * @returns Array of output lines
   * @throws {SSHError} If session not found
   */
  public getSessionOutput(sessionId: string, lines?: number, clear?: boolean): string[] {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new SSHError(`Session '${sessionId}' not found`);
    }

    return session.getBufferedOutput(lines, clear);
  }

  /**
   * Close all connections and sessions.
   * Gracefully shuts down all SSH connections and cleans up resources.
   * 
   * @returns Promise that resolves when all connections are closed
   */
  public async disconnectAll(): Promise<void> {
    const sessionPromises = Array.from(this.sessions.values()).map(session => {
      return new Promise<void>((resolve) => {
        const timeout = setTimeout(() => {
          resolve(); // Resolve even if 'closed' event doesn't fire
        }, 5000); // 5 second timeout
        
        // Use once() instead of on() to avoid multiple event listeners
        session.once('closed', () => {
          clearTimeout(timeout);
          resolve();
        });
        
        session.close();
      });
    });

    const connectionPromises = Array.from(this.connections.values()).map(connInfo => {
      return new Promise<void>((resolve) => {
        if (connInfo.connected) {
          const timeout = setTimeout(() => {
            resolve(); // Resolve even if 'close' event doesn't fire
          }, 5000); // 5 second timeout
          
          // Use once() instead of on() to avoid multiple event listeners
          connInfo.client.once('close', () => {
            clearTimeout(timeout);
            resolve();
          });
          
          connInfo.client.end();
        } else {
          resolve();
        }
      });
    });

    try {
      await Promise.all([...sessionPromises, ...connectionPromises]);
    } catch (error) {
      console.error('[SSH] Error during disconnectAll:', error);
    } finally {
      this.sessions.clear();
      this.connections.clear();
    }
  }
} 