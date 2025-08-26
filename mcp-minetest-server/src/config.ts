

import { z } from 'zod';
import { execSync } from 'child_process';
import { existsSync } from 'fs';
import { dirname, resolve } from 'path';
// @ts-ignore: TypeScript can't find declaration but module exists and builds correctly
import { expandTilde } from './utils.js';

// Schema for container configuration
export const ContainerInstanceSchema = z.object({
  container_name: z.string(),
  container_ip: z.string(),
  ssh_key: z.string(),
  ssh_user: z.string(),
  ssh_port: z.number().optional().default(22),
  enabled: z.boolean().optional().default(true)
});

// Schema for lab configuration
const LabSchema = z.object({
  name: z.string(),
  network_subnet: z.string()
});

// Schema for MCP server configuration
const MCPConfigSchema = z.object({
  server_name: z.string(),
  allowed_networks: z.array(z.string()),
  max_session_time: z.number(),
  audit_enabled: z.boolean(),
  log_level: z.string()
});

// Main lab configuration schema - Docker containers
const LabConfigSchema = z.object({
  version: z.string(),
  lab: LabSchema,
  containers: z.record(z.string(), ContainerInstanceSchema),
  mcp: MCPConfigSchema
});

export type LabConfig = z.infer<typeof LabConfigSchema>;
export type ContainerInstance = z.infer<typeof ContainerInstanceSchema>;

/**
 * Load simple Docker lab configuration from JSON file
 */
export async function loadDockerLabConfig(): Promise<LabConfig> {
  const configPath = process.env.APTL_MINETEST_SERVER_CONFIG_PATH || resolve(process.cwd(), 'docker-lab-config.json');
  console.error(`[MCP] Looking for Docker config at: ${configPath}`);
  
  if (!existsSync(configPath)) {
    throw new Error(`Docker lab configuration not found at: ${configPath}`);
  }

  try {
    const fs = await import('fs/promises');
    const configContent = await fs.readFile(configPath, 'utf8');
    const dockerConfig = JSON.parse(configContent);
    
    // Use Docker config directly
    if (!dockerConfig.containers) {
      throw new Error('Containers configuration is required');
    }
    
    const config: LabConfig = {
      version: dockerConfig.version || "1.0.0",
      lab: {
        name: dockerConfig.lab?.name || "aptl-local",
        network_subnet: dockerConfig.lab?.network_subnet || "172.20.0.0/16"
      },
      containers: dockerConfig.containers,
      mcp: {
        server_name: dockerConfig.mcp?.server_name || "aptl-local-mcp",
        allowed_networks: dockerConfig.mcp?.allowed_networks || ["172.20.0.0/16"],
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
  
  // Expand tilde paths for SSH keys - all containers
  Object.values(config.containers).forEach(container => {
    if (container.ssh_key.startsWith('~')) {
      container.ssh_key = expandTilde(container.ssh_key);
    }
  });
  
  return config;
} 