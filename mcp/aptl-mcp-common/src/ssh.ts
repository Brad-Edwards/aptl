
import { Client, ClientChannel } from 'ssh2';
import { readFile } from 'fs/promises';
import { EventEmitter } from 'events';
import { ShellFormatter, ShellType, createShellFormatter } from './shells.js';

// Constants for timeouts and limits
const TIMEOUTS = {
  DEFAULT_COMMAND: 30000,
  DEFAULT_SESSION: 600000,
  CONNECTION: 30000,
  KEEP_ALIVE_INTERVAL: 30000,
  FORCE_CLOSE: 3000,
  SESSION_CLOSE: 5000,
} as const;

const BUFFER_LIMITS = {
  MAX_SIZE: 10000,
  TRIM_TO: 5000,
} as const;

const SSH_CONFIG = {
  READY_TIMEOUT: 30000,
  KEEPALIVE_INTERVAL: 30000,
  KEEPALIVE_COUNT_MAX: 3,
} as const;

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
export type SessionMode = 'normal' | 'raw';

export interface SessionMetadata {
  sessionId: string;
  target: string;
  username: string;
  type: SessionType;
  mode: SessionMode;
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
  raw?: boolean;
}

interface ConnectionInfo {
  client: Client;
  connected: boolean;
}

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
  private shellFormatter: ShellFormatter;

  private sessionTimeoutMs: number;

  constructor(
    sessionId: string,
    target: string,
    username: string,
    type: SessionType,
    client: Client,
    port: number = 22,
    mode: SessionMode = 'normal',
    timeoutMs: number = TIMEOUTS.DEFAULT_SESSION,
    shellType: ShellType = 'bash'
  ) {
    super();
    this.client = client;
    this.sessionTimeoutMs = timeoutMs;
    this.commandDelimiter = `___CMD_${Date.now()}_${Math.random().toString(36).substring(2, 11)}___`;
    this.shellFormatter = createShellFormatter(shellType);
    
    this.sessionInfo = {
      sessionId,
      target,
      username,
      type,
      mode,
      createdAt: new Date(),
      lastActivity: new Date(),
      port,
      workingDirectory: '~',
      environmentVars: new Map(),
      isActive: false,
      commandHistory: []
    };
  }

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
        }, 1000); // Shell startup delay
      });
    });
  }

  async executeCommand(command: string, timeout: number = TIMEOUTS.DEFAULT_COMMAND, raw?: boolean): Promise<CommandResult> {
    if (!this.isInitialized || !this.shell || !this.sessionInfo.isActive) {
      throw new SSHError('Session not initialized or inactive');
    }

    // Background sessions should return immediately after queuing
    if (this.sessionInfo.type === 'background') {
      const commandId = `${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;
      const request: CommandRequest = {
        id: commandId,
        command,
        resolve: () => {}, // No-op resolve for background
        reject: () => {}, // No-op reject for background  
        timeout,
        raw: raw !== undefined ? raw : this.sessionInfo.mode === 'raw'
      };

      this.commandQueue.push(request);
      this.sessionInfo.commandHistory.push(command);
      this.sessionInfo.lastActivity = new Date();
      this.resetSessionTimeout();

      if (!this.currentCommand) {
        this.processNextCommand();
      }

      // Return immediately for background sessions
      return {
        stdout: `Command '${command}' queued in background session '${this.sessionInfo.sessionId}'`,
        stderr: '',
        code: 0,
        signal: null
      };
    }

    // Interactive sessions wait for completion
    return new Promise((resolve, reject) => {
      const commandId = `${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;
      const request: CommandRequest = {
        id: commandId,
        command,
        resolve,
        reject,
        timeout,
        raw: raw !== undefined ? raw : this.sessionInfo.mode === 'raw'
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

    if (this.currentCommand.raw) {
      // Raw mode: send command directly without wrapping
      this.shell.write(this.currentCommand.command + '\n');
      
      // For raw mode, we'll use a simpler timeout-based approach
      if (this.currentCommand.timeout) {
        const commandId = this.currentCommand.id;
        const timeoutDuration = this.currentCommand.timeout;
        setTimeout(() => {
          if (this.currentCommand?.id === commandId) {
            // In raw mode, resolve with whatever output we've collected
            const output = this.outputData;
            this.currentCommand!.resolve({
              stdout: output,
              stderr: '',
              code: 0, // Unknown in raw mode
              signal: null
            });
            this.currentCommand = null;
            this.processNextCommand();
          }
        }, timeoutDuration);
      }
    } else {
      // Normal mode: use delimiter wrapping
      const startDelimiter = `${this.commandDelimiter}_START_${this.currentCommand.id}`;
      const endDelimiter = `${this.commandDelimiter}_END_${this.currentCommand.id}`;
      
      const wrappedCommand = this.shellFormatter.formatCommandWithDelimiters(
        this.currentCommand.command,
        startDelimiter,
        endDelimiter
      );
      
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
  }

  private handleShellOutput(data: string): void {
    if (this.sessionInfo.type === 'background') {
      this.outputBuffer.push(data);
      if (this.outputBuffer.length > BUFFER_LIMITS.MAX_SIZE) {
        this.outputBuffer = this.outputBuffer.slice(-BUFFER_LIMITS.TRIM_TO);
      }
    }

    if (this.currentCommand) {
      this.outputData += data;
      this.parseCommandOutput();
    }
  }

  private parseCommandOutput(): void {
    if (!this.currentCommand) return;

    // Skip parsing for raw mode commands
    if (this.currentCommand.raw) {
      // Raw mode output is handled by timeout in processNextCommand
      return;
    }

    const endDelimiter = `${this.commandDelimiter}_END_${this.currentCommand.id}`;
    const exitCode = this.shellFormatter.parseExitCode(this.outputData, endDelimiter);
    
    if (exitCode !== null) {
      const startPattern = `${this.commandDelimiter}_START_${this.currentCommand.id}`;
      const startIndex = this.outputData.indexOf(startPattern);
      const endPattern = `${endDelimiter}:${exitCode}`;
      const endIndex = this.outputData.indexOf(endPattern);
      
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
    return { 
      ...this.sessionInfo,
      commandHistory: [...this.sessionInfo.commandHistory],
      environmentVars: new Map(this.sessionInfo.environmentVars)
    };
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
        this.shell.write(this.shellFormatter.getKeepAliveCommand());
      }
    }, TIMEOUTS.KEEP_ALIVE_INTERVAL);
  }

  private resetSessionTimeout(): void {
    if (this.sessionTimeout) {
      clearTimeout(this.sessionTimeout);
    }
    
    this.sessionTimeout = setTimeout(() => {
      this.emit('timeout');
      this.close();
    }, this.sessionTimeoutMs);
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

export class SSHConnectionManager {
  private connections: Map<string, ConnectionInfo> = new Map();
  private sessions: Map<string, PersistentSession> = new Map();

  /**
   * Execute a command on a target host via SSH
   */
  public async executeCommand(
    host: string,
    username: string,
    privateKeyPath: string,
    command: string,
    port: number = 22,
    timeout: number = TIMEOUTS.DEFAULT_COMMAND
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
    console.error(`[SSH-CLIENT] getConnection called with key: ${connectionKey}`);
    
    if (this.connections.has(connectionKey)) {
      const connInfo = this.connections.get(connectionKey)!;
      if (connInfo.connected) {
        console.error(`[SSH-CLIENT] Reusing existing connection for: ${connectionKey}`);
        return connInfo.client;
      }
      // Connection is dead, remove it
      console.error(`[SSH-CLIENT] Removing dead connection for: ${connectionKey}`);
      this.connections.delete(connectionKey);
    }

    // Create new connection
    console.error(`[SSH-CLIENT] Creating new connection for: ${connectionKey}`);
    const client = await this.createConnection(host, username, privateKeyPath, port);
    this.connections.set(connectionKey, { client, connected: true });
    console.error(`[SSH-CLIENT] Connection cache now has ${this.connections.size} connections`);
    
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
      privateKey = await readFile(privateKeyPath);
    } catch (error) {
      throw new SSHError(
        `Failed to read SSH private key from ${privateKeyPath}: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }

    const client = new Client();

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new SSHError('Connection timeout'));
      }, TIMEOUTS.KEEP_ALIVE_INTERVAL);

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
        timeout: SSH_CONFIG.READY_TIMEOUT,
        readyTimeout: SSH_CONFIG.READY_TIMEOUT,
        keepaliveInterval: SSH_CONFIG.KEEPALIVE_INTERVAL,
        keepaliveCountMax: SSH_CONFIG.KEEPALIVE_COUNT_MAX,
      });
    });
  }

  /**
   * Create a new persistent session
   */
  public async createSession(
    sessionId: string,
    target: string,
    username: string,
    type: SessionType,
    privateKeyPath: string,
    port: number = 22,
    mode: SessionMode = 'normal',
    timeoutMs: number = TIMEOUTS.DEFAULT_SESSION,
    shellType: ShellType = 'bash'
  ): Promise<PersistentSession> {
    if (this.sessions.has(sessionId)) {
      throw new SSHError(`Session with ID '${sessionId}' already exists`);
    }

    const client = await this.getConnection(target, username, privateKeyPath, port);
    const session = new PersistentSession(sessionId, target, username, type, client, port, mode, timeoutMs, shellType);
    
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
   * Get an existing session by ID
   */
  public getSession(sessionId: string): PersistentSession | undefined {
    return this.sessions.get(sessionId);
  }

  /**
   * List all active sessions
   */
  public listSessions(): SessionMetadata[] {
    return Array.from(this.sessions.values()).map(session => session.getSessionInfo());
  }

  /**
   * Close a specific session
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
      }, TIMEOUTS.FORCE_CLOSE);
      
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
   * Execute a command in a specific session
   */
  public async executeInSession(
    sessionId: string,
    command: string,
    timeout?: number,
    raw?: boolean
  ): Promise<CommandResult> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new SSHError(`Session '${sessionId}' not found`);
    }

    return session.executeCommand(command, timeout, raw);
  }

  /**
   * Get buffered output from a background session
   */
  public getSessionOutput(sessionId: string, lines?: number, clear?: boolean): string[] {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new SSHError(`Session '${sessionId}' not found`);
    }

    return session.getBufferedOutput(lines, clear);
  }

  /**
   * Close all connections and sessions
   */
  public async disconnectAll(): Promise<void> {
    const sessionPromises = Array.from(this.sessions.values()).map(session => {
      return new Promise<void>((resolve) => {
        const timeout = setTimeout(() => {
          resolve(); // Resolve even if 'closed' event doesn't fire
        }, TIMEOUTS.SESSION_CLOSE);
        
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
          }, TIMEOUTS.SESSION_CLOSE);
          
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