// SPDX-License-Identifier: BUSL-1.1

import { Client } from 'ssh2';
import { readFileSync } from 'fs';
import { resolve as resolvePath } from 'path';
import ConfigManager, { type KaliConfig } from './config.js';

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

export class KaliConnection {
  private client: Client;
  private connected: boolean = false;
  private config: KaliConfig;

  constructor(config: KaliConfig) {
    this.client = new Client();
    this.config = config;
  }

  public static fromConfig(): KaliConnection {
    const configManager = ConfigManager.getInstance();
    const kaliConfig = configManager.getKaliConfig();
    return new KaliConnection(kaliConfig);
  }

  public async connect(): Promise<void> {
    if (this.connected) {
      return;
    }

    // Prepare SSH key path outside Promise constructor
    const homeDir = process.env['HOME'];
    if (!homeDir) {
      throw new SSHError('HOME environment variable not set');
    }
    
    const keyPath = this.config.ssh_key.replace(/^~/, homeDir);
    const resolvedKeyPath = resolvePath(keyPath);
    
    let privateKey: Buffer;
    try {
      privateKey = readFileSync(resolvedKeyPath);
    } catch (error) {
      throw new SSHError(
        `Failed to read SSH private key from ${resolvedKeyPath}: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new SSHError('Connection timeout'));
      }, 30000);

      this.client.on('ready', () => {
        clearTimeout(timeout);
        this.connected = true;
        resolve();
      });

      this.client.on('error', (err) => {
        clearTimeout(timeout);
        this.connected = false;
        reject(new SSHError(`Connection failed: ${err.message}`, err));
      });

      this.client.on('close', () => {
        this.connected = false;
      });

      this.client.connect({
        host: this.config.public_ip,
        port: this.config.ports.ssh,
        username: this.config.ssh_user,
        privateKey,
        timeout: 30000,
        readyTimeout: 30000,
        keepaliveInterval: 30000,
        keepaliveCountMax: 3,
      });
    });
  }

  public async executeCommand(command: string, timeout: number = 30000): Promise<CommandResult> {
    if (!this.connected) {
      await this.connect();
    }

    return new Promise((resolve, reject) => {
      let stdout = '';
      let stderr = '';
      let hasTimedOut = false;

      const timeoutId = setTimeout(() => {
        hasTimedOut = true;
        reject(new SSHError(`Command timeout after ${timeout}ms: ${command}`));
      }, timeout);

      this.client.exec(command, (err, stream) => {
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

  public async disconnect(): Promise<void> {
    if (!this.connected) {
      return;
    }

    return new Promise((resolve) => {
      this.client.on('close', () => {
        this.connected = false;
        resolve();
      });
      this.client.end();
    });
  }

  public isConnected(): boolean {
    return this.connected;
  }
} 