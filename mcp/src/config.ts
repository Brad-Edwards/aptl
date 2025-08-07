// SPDX-License-Identifier: BUSL-1.1

import { z } from 'zod';
import { execSync } from 'child_process';
import { existsSync } from 'fs';
import { dirname, resolve } from 'path';
// @ts-ignore: TypeScript can't find declaration but module exists and builds correctly
import { expandTilde } from './utils.js';

// Schema for individual instance configuration
export const InstanceSchema = z.object({
  public_ip: z.string(),
  private_ip: z.string(),
  ssh_key: z.string(),
  ssh_user: z.string(),
  instance_type: z.string(),
  enabled: z.boolean().optional().default(true),
  ssh_port: z.number().optional().default(22),
  ports: z.record(z.number()).optional()
});

// Schema for disabled instance
export const DisabledInstanceSchema = z.object({
  enabled: z.literal(false)
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

// Main lab configuration schema
const LabConfigSchema = z.object({
  version: z.string(),
  generated: z.string(),
  lab: z.object({
    name: z.string(),
    vpc_cidr: z.string(),
    project: z.string().optional(),
    environment: z.string().optional()
  }),
  instances: z.object({
    siem: z.union([InstanceSchema, DisabledInstanceSchema]),
    victim: z.union([InstanceSchema, DisabledInstanceSchema]),
    kali: z.union([InstanceSchema, DisabledInstanceSchema])
  }),
  network: NetworkSchema,
  mcp: MCPConfigSchema
});

export type LabConfig = z.infer<typeof LabConfigSchema>;
export type Instance = z.infer<typeof InstanceSchema>;

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
    
    // Convert Docker config to LabConfig format
    const config: LabConfig = {
      version: dockerConfig.version || "1.0.0",
      generated: new Date().toISOString(),
      lab: {
        name: dockerConfig.lab?.name || "aptl-local",
        vpc_cidr: dockerConfig.lab?.network_subnet || "172.20.0.0/16",
        project: "aptl-local",
        environment: "local"
      },
      instances: {
        siem: dockerConfig.containers?.wazuh ? {
          public_ip: dockerConfig.containers.wazuh.container_ip,
          private_ip: dockerConfig.containers.wazuh.container_ip,
          ssh_key: dockerConfig.containers.wazuh.ssh_key,
          ssh_user: dockerConfig.containers.wazuh.ssh_user,
          instance_type: "docker-container",
          ssh_port: dockerConfig.containers.wazuh.ssh_port || 22,
          enabled: dockerConfig.containers.wazuh.enabled !== false
        } : { enabled: false },
        victim: dockerConfig.containers?.victim ? {
          public_ip: dockerConfig.containers.victim.container_ip,
          private_ip: dockerConfig.containers.victim.container_ip,
          ssh_key: dockerConfig.containers.victim.ssh_key,
          ssh_user: dockerConfig.containers.victim.ssh_user,
          instance_type: "docker-container",
          ssh_port: dockerConfig.containers.victim.ssh_port || 22,
          enabled: dockerConfig.containers.victim.enabled !== false
        } : { enabled: false },
        kali: dockerConfig.containers?.kali ? {
          public_ip: dockerConfig.containers.kali.container_ip,
          private_ip: dockerConfig.containers.kali.container_ip,
          ssh_key: dockerConfig.containers.kali.ssh_key,
          ssh_user: dockerConfig.containers.kali.ssh_user,
          instance_type: "docker-container",
          ssh_port: dockerConfig.containers.kali.ssh_port || 22,
          enabled: dockerConfig.containers.kali.enabled !== false
        } : { enabled: false }
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
  
  // Expand tilde paths for SSH keys
  if ('ssh_key' in config.instances.siem && config.instances.siem.ssh_key.startsWith('~')) {
    config.instances.siem.ssh_key = expandTilde(config.instances.siem.ssh_key);
  }
  if ('ssh_key' in config.instances.victim && config.instances.victim.ssh_key.startsWith('~')) {
    config.instances.victim.ssh_key = expandTilde(config.instances.victim.ssh_key);
  }
  if ('ssh_key' in config.instances.kali && config.instances.kali.ssh_key.startsWith('~')) {
    config.instances.kali.ssh_key = expandTilde(config.instances.kali.ssh_key);
  }
  
  return config;
}


/**
 * Check if target is in allowed CIDR ranges
 */
export function isTargetAllowed(target: string, allowedCidrs: string[]): boolean {
  // For now, implement basic CIDR checking
  // In production, you'd use a proper CIDR library
  for (const cidr of allowedCidrs) {
    if (isIpInCidr(target, cidr)) {
      return true;
    }
  }
  return false;
}

/**
 * Basic CIDR check (simplified implementation)
 */
function isIpInCidr(ip: string, cidr: string): boolean {
  const [network, prefixLength] = cidr.split('/');
  const prefix = parseInt(prefixLength, 10);
  
  const ipNum = ipToNumber(ip);
  const networkNum = ipToNumber(network);
  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  
  return (ipNum & mask) === (networkNum & mask);
}

/**
 * Convert IP address to number
 */
function ipToNumber(ip: string): number {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

/**
 * Select SSH credentials based on target IP and lab configuration
 */
export function selectCredentials(target: string, config: LabConfig, defaultUsername: string = 'kali'): { sshKey: string; username: string; port: number } {
  // Auto-detect instance and credentials
  if ('ssh_key' in config.instances.siem && 
      (config.instances.siem.public_ip === target || config.instances.siem.private_ip === target)) {
    return {
      sshKey: config.instances.siem.ssh_key,
      username: config.instances.siem.ssh_user,
      port: config.instances.siem.ssh_port || 22
    };
  } else if ('ssh_key' in config.instances.victim && 
             (config.instances.victim.public_ip === target || config.instances.victim.private_ip === target)) {
    return {
      sshKey: config.instances.victim.ssh_key,
      username: config.instances.victim.ssh_user,
      port: config.instances.victim.ssh_port || 22
    };
  } else if ('ssh_key' in config.instances.kali && 
             (config.instances.kali.public_ip === target || config.instances.kali.private_ip === target)) {
    return {
      sshKey: config.instances.kali.ssh_key,
      username: config.instances.kali.ssh_user,
      port: config.instances.kali.ssh_port || 22
    };
  } else {
    // Default to Kali credentials for unknown targets in allowed ranges
    if (!('ssh_key' in config.instances.kali)) {
      throw new Error('Kali instance not available for SSH operations');
    }
    return {
      sshKey: config.instances.kali.ssh_key,
      username: defaultUsername,
      port: config.instances.kali.ssh_port || 22
    };
  }
} 