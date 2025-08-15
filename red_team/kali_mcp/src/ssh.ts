// SPDX-License-Identifier: BUSL-1.1

import { Client } from 'ssh2';
import { readFileSync } from 'fs';

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

interface ConnectionInfo {
  client: Client;
  connected: boolean;
}

export class SSHConnectionManager {
  private connections: Map<string, ConnectionInfo> = new Map();

  /**
   * Execute a command on a target host via SSH
   */
  public async executeCommand(
    host: string,
    username: string,
    privateKeyPath: string,
    command: string,
    timeout: number = 30000
  ): Promise<CommandResult> {
    const client = await this.getConnection(host, username, privateKeyPath);
    
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
    privateKeyPath: string
  ): Promise<Client> {
    const connectionKey = `${username}@${host}`;
    
    if (this.connections.has(connectionKey)) {
      const connInfo = this.connections.get(connectionKey)!;
      if (connInfo.connected) {
        return connInfo.client;
      }
      // Connection is dead, remove it
      this.connections.delete(connectionKey);
    }

    // Create new connection
    const client = await this.createConnection(host, username, privateKeyPath);
    this.connections.set(connectionKey, { client, connected: true });
    
    return client;
  }

  /**
   * Create a new SSH connection
   */
  private async createConnection(
    host: string,
    username: string,
    privateKeyPath: string
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
        reject(new SSHError(`Connection failed to ${host}: ${err.message}`, err));
      });

      client.on('close', () => {
        // Mark connection as disconnected
        const connectionKey = `${username}@${host}`;
        const connInfo = this.connections.get(connectionKey);
        if (connInfo) {
          connInfo.connected = false;
        }
      });

      client.connect({
        host,
        port: 22,
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
   * Close all connections
   */
  public async disconnectAll(): Promise<void> {
    const promises = Array.from(this.connections.values()).map(connInfo => {
      return new Promise<void>((resolve) => {
        if (connInfo.connected) {
          connInfo.client.on('close', () => resolve());
          connInfo.client.end();
        } else {
          resolve();
        }
      });
    });

    await Promise.all(promises);
    this.connections.clear();
  }
} 