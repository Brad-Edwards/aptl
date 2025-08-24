

import { z } from 'zod';
import { execSync } from 'child_process';
import { existsSync } from 'fs';
import { dirname, resolve } from 'path';
// @ts-ignore: TypeScript can't find declaration but module exists and builds correctly
import { expandTilde } from './utils.js';

// Schema for Kali instance configuration
export const KaliInstanceSchema = z.object({
  public_ip: z.string(),
  private_ip: z.string(),
  ssh_key: z.string(),
  ssh_user: z.string(),
  ssh_port: z.number().optional().default(22),
  enabled: z.boolean().optional().default(true)
});


// Schema for network configuration
const NetworkSchema = z.object({
  vpc_cidr: z.string(),
  subnet_cidr: z.string(),
  allowed_ip: z.string()
});

// Schema for MCP server configuration
const MCPConfigSchema = z.object({
  server_name: z.string(),
  allowed_targets: z.array(z.string()),
  max_session_time: z.number(),
  audit_enabled: z.boolean(),
  log_level: z.string()
});

// Main lab configuration schema - Kali only
const LabConfigSchema = z.object({
  version: z.string(),
  generated: z.string(),
  lab: z.object({
    name: z.string(),
    vpc_cidr: z.string(),
    project: z.string().optional(),
    environment: z.string().optional()
  }),
  kali: KaliInstanceSchema,
  network: NetworkSchema,
  mcp: MCPConfigSchema
});

export type LabConfig = z.infer<typeof LabConfigSchema>;
export type KaliInstance = z.infer<typeof KaliInstanceSchema>;

/**
 * Load simple Docker lab configuration from JSON file
 */
async function loadDockerLabConfig(): Promise<LabConfig> {
  const configPath = process.env.APTL_CONFIG_PATH || resolve(process.cwd(), 'docker-lab-config.json');
  console.error(`[MCP] Looking for Docker config at: ${configPath}`);
  
  if (!existsSync(configPath)) {
    throw new Error(`Docker lab configuration not found at: ${configPath}`);
  }

  try {
    const fs = await import('fs/promises');
    const configContent = await fs.readFile(configPath, 'utf8');
    const dockerConfig = JSON.parse(configContent);
    
    // Convert Docker config to LabConfig format - Kali only
    if (!dockerConfig.containers?.kali) {
      throw new Error('Kali container configuration is required');
    }
    
    const config: LabConfig = {
      version: dockerConfig.version || "1.0.0",
      generated: new Date().toISOString(),
      lab: {
        name: dockerConfig.lab?.name || "aptl-local",
        vpc_cidr: dockerConfig.lab?.network_subnet || "172.20.0.0/16",
        project: "aptl-local",
        environment: "local"
      },
      kali: {
        public_ip: dockerConfig.containers.kali.container_ip,
        private_ip: dockerConfig.containers.kali.container_ip,
        ssh_key: dockerConfig.containers.kali.ssh_key,
        ssh_user: dockerConfig.containers.kali.ssh_user,
        ssh_port: dockerConfig.containers.kali.ssh_port || 22,
        enabled: dockerConfig.containers.kali.enabled !== false
      },
      network: {
        vpc_cidr: dockerConfig.lab?.network_subnet || "172.20.0.0/16",
        subnet_cidr: dockerConfig.lab?.network_subnet || "172.20.0.0/16",
        allowed_ip: "0.0.0.0/0"
      },
      mcp: {
        server_name: dockerConfig.mcp?.server_name || "aptl-local-mcp",
        allowed_targets: dockerConfig.mcp?.allowed_networks || ["172.20.0.0/16"],
        max_session_time: dockerConfig.mcp?.max_session_time || 3600,
        audit_enabled: dockerConfig.mcp?.audit_enabled !== false,
        log_level: dockerConfig.mcp?.log_level || "info"
      }
    };
    
    console.error(`[MCP] Loaded Docker lab config for: ${config.lab.name}`);
    return config;
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Failed to load Docker lab configuration: ${error.message}`);
    }
    throw new Error('Unknown error loading Docker lab configuration');
  }
}

/**
 * Load lab configuration from Docker setup
 */
export async function loadLabConfig(): Promise<LabConfig> {
  const config = await loadDockerLabConfig();
  
  // Expand tilde paths for SSH keys - Kali only
  if (config.kali.ssh_key.startsWith('~')) {
    config.kali.ssh_key = expandTilde(config.kali.ssh_key);
  }
  
  return config;
}



/**
 * Get Kali SSH credentials - only target allowed
 */
export function getKaliCredentials(config: LabConfig): { sshKey: string; username: string; port: number; target: string } {
  if (!config.kali.enabled) {
    throw new Error('Kali instance is not enabled');
  }
  
  return {
    sshKey: config.kali.ssh_key,
    username: config.kali.ssh_user,
    port: config.kali.ssh_port || 22,
    target: config.kali.public_ip
  };
} 