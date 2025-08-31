

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
  containers: {
    [key: string]: {
      container_name: string;
      container_ip: string;
      ssh_key: string;
      ssh_user: string;
      ssh_port: number;
      enabled: boolean;
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
  if (!config.containers) {
    throw new Error('Containers configuration is required in docker-lab-config.json');
  }
  if (!config.containers[config.server.configKey]) {
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
  
  // Expand tilde paths for SSH keys
  const configKey = config.server.configKey;
  if (config.containers[configKey].ssh_key.startsWith('~')) {
    config.containers[configKey].ssh_key = expandTilde(config.containers[configKey].ssh_key);
  }
  
  return config;
}



/**
 * Get target instance SSH credentials
 */
export function getTargetCredentials(config: LabConfig): { sshKey: string; username: string; port: number; target: string } {
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