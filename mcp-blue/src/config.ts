

import { z } from 'zod';
import { existsSync } from 'fs';
import { resolve } from 'path';

// Schema for Wazuh Manager configuration
const WazuhManagerSchema = z.object({
  host: z.string(),
  api_port: z.number(),
  protocol: z.string(),
  api_username: z.string(),
  api_password: z.string(),
  verify_ssl: z.boolean()
});

// Schema for Wazuh Indexer configuration
const WazuhIndexerSchema = z.object({
  host: z.string(),
  port: z.number(),
  protocol: z.string(),
  username: z.string(),
  password: z.string(),
  verify_ssl: z.boolean()
});

// Schema for Wazuh Dashboard configuration
const WazuhDashboardSchema = z.object({
  host: z.string(),
  port: z.number(),
  protocol: z.string(),
  url: z.string()
});

// Schema for network configuration
const NetworkSchema = z.object({
  lab_subnet: z.string(),
  gateway: z.string()
});

// Schema for query limits
const QueryLimitsSchema = z.object({
  max_alerts_per_query: z.number(),
  max_time_range_days: z.number(),
  rate_limit_per_minute: z.number()
});

// Schema for MCP configuration
const MCPConfigSchema = z.object({
  server_name: z.string()
});

// Main Wazuh configuration schema
const WazuhConfigSchema = z.object({
  comment: z.string().optional(),
  wazuh: z.object({
    manager: WazuhManagerSchema,
    indexer: WazuhIndexerSchema,
    dashboard: WazuhDashboardSchema
  }),
  network: NetworkSchema,
  query_limits: QueryLimitsSchema,
  mcp: MCPConfigSchema
});

export type WazuhConfig = z.infer<typeof WazuhConfigSchema>;
export type WazuhManager = z.infer<typeof WazuhManagerSchema>;
export type WazuhIndexer = z.infer<typeof WazuhIndexerSchema>;

/**
 * Load Wazuh configuration from JSON file
 */
async function loadWazuhConfig(): Promise<WazuhConfig> {
  const configPath = process.env.WAZUH_API_CONFIG || resolve(process.cwd(), 'wazuh-api-config.json');
  console.error(`[MCP-Blue] Looking for Wazuh config at: ${configPath}`);
  
  if (!existsSync(configPath)) {
    throw new Error(`Wazuh configuration not found at: ${configPath}`);
  }

  try {
    const fs = await import('fs/promises');
    const configContent = await fs.readFile(configPath, 'utf8');
    const rawConfig = JSON.parse(configContent);
    
    // Validate configuration against schema
    const config = WazuhConfigSchema.parse(rawConfig);
    
    console.error(`[MCP-Blue] Loaded Wazuh config for: ${config.mcp.server_name}`);
    return config;
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Failed to load Wazuh configuration: ${error.message}`);
    }
    throw new Error('Unknown error loading Wazuh configuration');
  }
}

/**
 * Load and validate Wazuh configuration
 */
export async function loadConfig(): Promise<WazuhConfig> {
  const config = await loadWazuhConfig();
  
  // Validate network addresses are in lab subnet (allow localhost for Docker port forwarding)
  if (config.wazuh.manager.host !== 'localhost' && !isInLabNetwork(config.wazuh.manager.host, config.network.lab_subnet)) {
    throw new Error(`Wazuh Manager host ${config.wazuh.manager.host} is not in lab subnet ${config.network.lab_subnet}`);
  }
  
  if (config.wazuh.indexer.host !== 'localhost' && !isInLabNetwork(config.wazuh.indexer.host, config.network.lab_subnet)) {
    throw new Error(`Wazuh Indexer host ${config.wazuh.indexer.host} is not in lab subnet ${config.network.lab_subnet}`);
  }
  
  return config;
}


/**
 * Validate if host is in lab network
 */
export function isInLabNetwork(host: string, subnet: string): boolean {
  // Basic CIDR validation - in production you'd use a proper library
  const [network, prefixLength] = subnet.split('/');
  const prefix = parseInt(prefixLength, 10);
  
  const hostNum = ipToNumber(host);
  const networkNum = ipToNumber(network);
  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  
  return (hostNum & mask) === (networkNum & mask);
}

/**
 * Convert IP address to number
 */
function ipToNumber(ip: string): number {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

/**
 * Validate query parameters
 */
export function validateQueryParams(params: any, config: WazuhConfig): { valid: boolean; error?: string } {
  // Validate time range
  const validTimeRanges = ['15m', '1h', '6h', '24h', '7d'];
  if (params.time_range && !validTimeRanges.includes(params.time_range)) {
    return { valid: false, error: `Invalid time range. Must be one of: ${validTimeRanges.join(', ')}` };
  }
  
  // Validate alert level
  if (params.min_level && (params.min_level < 1 || params.min_level > 15)) {
    return { valid: false, error: 'Alert level must be between 1 and 15' };
  }
  
  // Validate query size
  if (params.size && params.size > config.query_limits.max_alerts_per_query) {
    return { valid: false, error: `Query size cannot exceed ${config.query_limits.max_alerts_per_query}` };
  }
  
  // Validate source IP is in lab network
  if (params.source_ip && !isInLabNetwork(params.source_ip, config.network.lab_subnet)) {
    return { valid: false, error: `Source IP ${params.source_ip} is not in lab network` };
  }
  
  return { valid: true };
}

/**
 * Validate rule XML content
 */
export function validateRuleXML(ruleXML: string): { valid: boolean; error?: string } {
  // Basic XML structure validation
  if (!ruleXML.includes('<rule') || !ruleXML.includes('</rule>')) {
    return { valid: false, error: 'Rule XML must contain <rule> and </rule> tags' };
  }
  
  return { valid: true };
}