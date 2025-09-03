

import { existsSync } from 'fs';
import { resolve } from 'path';
import { expandTilde } from './utils.js';

// Lab configuration matching actual docker-lab-config.json structure
export interface LabConfig {
  version: string;
  server: {
    name: string;
    version: string;
    description: string;
    toolPrefix: string;
    targetName: string;
    configKey: string;
  };
  lab: {
    name: string;
    network_subnet: string;
  };
  containers?: {
    [key: string]: {
      container_name: string;
      container_ip: string;
      ssh_key: string;
      ssh_user: string;
      ssh_port: number;
      enabled: boolean;
      shell?: 'bash' | 'sh' | 'powershell' | 'cmd';
    };
  };
  api?: {
    baseUrl: string;
    auth: {
      type: 'basic' | 'bearer' | 'apikey' | 'custom';
      username?: string;
      password?: string;
      token?: string;
      apiKey?: string;
      header?: string;
    };
    timeout?: number;
    verify_ssl?: boolean;
    default_headers?: Record<string, string>;
  };
  queries?: {
    [queryName: string]: {
      url: string;
      method: 'GET' | 'POST' | 'PUT' | 'DELETE';
      auth?: {
        type: 'basic' | 'bearer' | 'apikey' | 'custom';
        username?: string;
        password?: string;
        token?: string;
        apiKey?: string;
        header?: string;
      };
      params?: Record<string, any>;
      body?: any;
      description: string;
      response_type?: 'json' | 'text';
      verify_ssl?: boolean;
    };
  };
  mcp: {
    server_name: string;
    allowed_networks: string[];
    max_session_time: number;
    audit_enabled: boolean;
    log_level: string;
  };
}

/**
 * Load Docker lab configuration from JSON file
 */
async function loadDockerLabConfig(configPath: string): Promise<LabConfig> {
  console.error(`[MCP] Looking for Docker config at: ${configPath}`);
  
  if (!existsSync(configPath)) {
    throw new Error(`Docker lab configuration not found at: ${configPath}`);
  }

  const fs = await import('fs/promises');
  const configContent = await fs.readFile(configPath, 'utf8');
  const config = JSON.parse(configContent) as LabConfig;
  
  // Validate required configuration sections exist
  if (!config.server) {
    throw new Error('Server configuration is required in docker-lab-config.json');
  }
  
  // Validate that at least one capability is configured
  if (!config.containers && !config.api) {
    throw new Error('Either containers (SSH) or api (HTTP) configuration is required');
  }
  
  // If SSH is configured, validate container exists
  if (config.containers && config.server.configKey && !config.containers[config.server.configKey]) {
    throw new Error(`Container '${config.server.configKey}' not found in configuration`);
  }
  
  console.error(`[MCP] Loaded Docker lab config for: ${config.lab.name}`);
  return config;
}

/**
 * Load lab configuration from Docker setup
 */
export async function loadLabConfig(configPath: string): Promise<LabConfig> {
  const config = await loadDockerLabConfig(configPath);
  
  // Expand tilde paths for SSH keys if containers are configured
  if (config.containers && config.server.configKey) {
    const configKey = config.server.configKey;
    const container = config.containers[configKey];
    if (container && container.ssh_key.startsWith('~')) {
      container.ssh_key = expandTilde(container.ssh_key);
    }
  }
  
  return config;
}



/**
 * Get target instance SSH credentials
 */
export function getTargetCredentials(config: LabConfig): { sshKey: string; username: string; port: number; target: string } {
  if (!config.containers) {
    throw new Error('SSH containers not configured - use API tools instead');
  }
  
  const configKey = config.server.configKey;
  const container = config.containers[configKey];
  
  if (!container) {
    throw new Error(`Container '${configKey}' not found in configuration`);
  }
  
  if (!container.enabled) {
    throw new Error(`${config.server.targetName} instance is not enabled`);
  }
  
  return {
    sshKey: container.ssh_key,
    username: container.ssh_user,
    port: container.ssh_port,
    target: container.container_ip
  };
} 