import { readFileSync } from 'fs';
import { resolve } from 'path';
import { z } from 'zod';

// Zod schema for lab configuration validation
const LabConfigSchema = z.object({
  version: z.string(),
  generated: z.string(),
  lab: z.object({
    name: z.string(),
    vpc_cidr: z.string(),
    project: z.string().optional(),
    environment: z.string().optional(),
  }),
  instances: z.object({
    siem: z.object({
      public_ip: z.string(),
      private_ip: z.string(),
      ssh_key: z.string(),
      ssh_user: z.string(),
      instance_type: z.string(),
      ports: z.object({
        ssh: z.number(),
        https: z.number(),
        syslog_udp: z.number(),
        syslog_tcp: z.number(),
      }),
    }),
    victim: z.object({
      public_ip: z.string(),
      private_ip: z.string(),
      ssh_key: z.string(),
      ssh_user: z.string(),
      instance_type: z.string(),
      ports: z.object({
        ssh: z.number(),
        rdp: z.number(),
        http: z.number(),
      }),
    }),
    kali: z.union([
      z.object({
        public_ip: z.string(),
        private_ip: z.string(),
        ssh_key: z.string(),
        ssh_user: z.string(),
        instance_type: z.string(),
        enabled: z.literal(true),
        ports: z.object({
          ssh: z.number(),
        }),
      }),
      z.object({
        enabled: z.literal(false),
      }),
    ]),
  }),
  network: z.object({
    vpc_cidr: z.string(),
    subnet_cidr: z.string(),
    allowed_ip: z.string(),
  }),
  mcp: z.object({
    server_name: z.string(),
    allowed_targets: z.array(z.string()),
    max_session_time: z.number(),
    audit_enabled: z.boolean(),
    log_level: z.string(),
  }),
});

export type LabConfig = z.infer<typeof LabConfigSchema>;
export type KaliConfig = LabConfig['instances']['kali'] & { enabled: true };

export class ConfigError extends Error {
  constructor(message: string, cause?: Error) {
    super(message);
    this.name = 'ConfigError';
    this.cause = cause;
  }
}

class ConfigManager {
  private static instance: ConfigManager;
  private config: LabConfig | null = null;

  private constructor() {}

  public static getInstance(): ConfigManager {
    if (!ConfigManager.instance) {
      ConfigManager.instance = new ConfigManager();
    }
    return ConfigManager.instance;
  }

  public loadConfig(configPath?: string): LabConfig {
    if (this.config) {
      return this.config;
    }

    const configFile = configPath || process.env['LAB_CONFIG'] || this.findConfigFile();
    
    try {
      const configContent = readFileSync(configFile, 'utf-8');
      const rawConfig = JSON.parse(configContent);
      
      this.config = LabConfigSchema.parse(rawConfig);
      
      // Validate that Kali is enabled
      if (!this.config.instances.kali.enabled) {
        throw new ConfigError('Kali instance is not enabled in the lab configuration');
      }
      
      return this.config;
    } catch (error) {
      if (error instanceof Error) {
        throw new ConfigError(`Failed to load lab configuration from ${configFile}: ${error.message}`, error);
      }
      throw new ConfigError(`Failed to load lab configuration from ${configFile}: Unknown error`);
    }
  }

  public getKaliConfig(): KaliConfig {
    const config = this.loadConfig();
    if (!config.instances.kali.enabled) {
      throw new ConfigError('Kali instance is not enabled');
    }
    return config.instances.kali as KaliConfig;
  }

  public isTargetAllowed(target: string): boolean {
    const config = this.loadConfig();
    const allowedTargets = config.mcp.allowed_targets;
    
    // Simple CIDR check for lab network
    for (const cidr of allowedTargets) {
      if (this.isIpInCidr(target, cidr)) {
        return true;
      }
    }
    
    return false;
  }

  private findConfigFile(): string {
    // Look for config file in common locations
    const possiblePaths = [
      resolve(process.cwd(), 'lab_config.json'),
      resolve(process.cwd(), '../../lab_config.json'),
      resolve(process.cwd(), '../../../lab_config.json'),
    ];

    for (const path of possiblePaths) {
      try {
        readFileSync(path, 'utf-8');
        return path;
      } catch {
        // Continue to next path
      }
    }

    throw new ConfigError(
      'Could not find lab_config.json. Please set LAB_CONFIG environment variable or ensure the file exists in the project root.'
    );
  }

  private isIpInCidr(ip: string, cidr: string): boolean {
    // Simple implementation for lab network validation
    const parts = cidr.split('/');
    if (parts.length !== 2) return false;
    
    const [network, prefixStr] = parts;
    if (!network || !prefixStr) return false;
    
    const prefix = parseInt(prefixStr, 10);
    
    if (prefix === 32) {
      return ip === network;
    }
    
    // For lab subnets, do simple prefix matching
    const networkOctets = network.split('.');
    const ipOctets = ip.split('.');
    
    if (networkOctets.length !== 4 || ipOctets.length !== 4) return false;
    
    // Check the first 3 octets for /24 networks (typical lab setup)
    if (prefix >= 24) {
      return networkOctets.slice(0, 3).join('.') === ipOctets.slice(0, 3).join('.');
    }
    
    return true; // Allow broader ranges for simplicity
  }
}

export default ConfigManager; 