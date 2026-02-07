

import { existsSync, readFileSync } from 'fs';
import { resolve, dirname } from 'path';
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
}

/**
 * Substitute ${VAR} patterns in a string with environment variable values.
 * Values are JSON-escaped so the result is safe to pass to JSON.parse().
 * Returns the substituted string and a list of any unresolved variable names.
 */
export function substituteEnvVars(
  content: string,
  env: Record<string, string | undefined> = process.env
): { result: string; missing: string[] } {
  const missing: string[] = [];
  const result = content.replace(/\$\{(\w+)\}/g, (_match, varName) => {
    const value = env[varName];
    if (value === undefined) {
      missing.push(varName);
      return _match;
    }
    // Escape characters that would break a JSON string
    return value
      .replace(/\\/g, '\\\\')
      .replace(/"/g, '\\"')
      .replace(/\n/g, '\\n')
      .replace(/\r/g, '\\r')
      .replace(/\t/g, '\\t');
  });
  return { result, missing };
}

/**
 * Parse a .env file into a key-value map.
 * Handles KEY=VALUE, KEY="VALUE", KEY='VALUE', comments, and blank lines.
 */
export function parseDotEnv(content: string): Record<string, string> {
  const vars: Record<string, string> = {};
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIndex = trimmed.indexOf('=');
    if (eqIndex === -1) continue;
    const key = trimmed.slice(0, eqIndex).trim();
    let val = trimmed.slice(eqIndex + 1).trim();
    // Strip matching quotes
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    vars[key] = val;
  }
  return vars;
}

/**
 * Find and load .env from the config file's directory or ancestors.
 * Returns merged env: .env values as defaults, process.env as overrides.
 */
function loadEnvForConfig(configPath: string): Record<string, string | undefined> {
  let dir = dirname(resolve(configPath));
  // Walk up at most 5 levels looking for .env
  for (let i = 0; i < 5; i++) {
    const envPath = resolve(dir, '.env');
    if (existsSync(envPath)) {
      try {
        const dotEnv = parseDotEnv(readFileSync(envPath, 'utf8'));
        console.error(`[MCP] Loaded .env from: ${envPath}`);
        // process.env overrides .env (explicit env vars take priority)
        return { ...dotEnv, ...process.env };
      } catch {
        break;
      }
    }
    const parent = dirname(dir);
    if (parent === dir) break; // reached filesystem root
    dir = parent;
  }
  return process.env;
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
  const rawContent = await fs.readFile(configPath, 'utf8');

  const env = loadEnvForConfig(configPath);
  const { result: configContent, missing } = substituteEnvVars(rawContent, env);
  if (missing.length > 0) {
    console.error(`[MCP] Warning: unresolved environment variables: ${missing.join(', ')}`);
  }

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