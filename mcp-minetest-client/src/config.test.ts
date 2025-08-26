import { describe, it, expect } from 'vitest';
import { loadLabConfig, getMinetestClientCredentials, MinetestClientInstanceSchema, type LabConfig } from './config.js';
import { writeFileSync, unlinkSync } from 'fs';
import { resolve } from 'path';

describe('MinetestClientInstanceSchema', () => {
  it('should validate a complete Minetest Client instance', () => {
    const validMinetestClient = {
      public_ip: '172.20.0.23',
      private_ip: '172.20.0.23',
      ssh_key: '/path/to/key',
      ssh_user: 'labadmin',
      ssh_port: 2025,
      enabled: true
    };

    expect(() => MinetestClientInstanceSchema.parse(validMinetestClient)).not.toThrow();
  });

  it('should default enabled to true', () => {
    const minetestClient = {
      public_ip: '172.20.0.23',
      private_ip: '172.20.0.23',
      ssh_key: '/path/to/key',
      ssh_user: 'labadmin'
    };

    const result = MinetestClientInstanceSchema.parse(minetestClient);
    expect(result.enabled).toBe(true);
  });

  it('should default ssh_port to 22', () => {
    const minetestClient = {
      public_ip: '172.20.0.23',
      private_ip: '172.20.0.23',
      ssh_key: '/path/to/key',
      ssh_user: 'labadmin'
    };

    const result = MinetestClientInstanceSchema.parse(minetestClient);
    expect(result.ssh_port).toBe(22);
  });

  it('should require all mandatory fields', () => {
    const incomplete = {
      public_ip: '172.20.0.23',
      ssh_key: '/path/to/key'
    };

    expect(() => MinetestClientInstanceSchema.parse(incomplete)).toThrow();
  });
});

describe('getMinetestClientCredentials', () => {
  const mockConfig: LabConfig = {
    version: '1.0.0',
    generated: '2024-01-01',
    lab: {
      name: 'aptl-minetest-client',
      vpc_cidr: '172.20.0.0/16'
    },
    minetestClient: {
      public_ip: '172.20.0.23',
      private_ip: '172.20.0.23',
      ssh_key: '/path/to/key',
      ssh_user: 'labadmin',
      ssh_port: 2025,
      enabled: true
    },
    network: {
      vpc_cidr: '172.20.0.0/16',
      subnet_cidr: '172.20.0.0/16',
      allowed_ip: '0.0.0.0/0'
    },
    mcp: {
      server_name: 'aptl-minetest-client-mcp',
      allowed_targets: ['172.20.0.0/16'],
      max_session_time: 3600,
      audit_enabled: true,
      log_level: 'info'
    }
  };

  it('should return correct credentials for enabled minetest client', () => {
    const result = getMinetestClientCredentials(mockConfig);

    expect(result).toEqual({
      sshKey: '/path/to/key',
      username: 'labadmin',
      port: 2025,
      target: '172.20.0.23'
    });
  });

  it('should default port to 22 when not specified', () => {
    const configWithDefaultPort = {
      ...mockConfig,
      minetestClient: {
        ...mockConfig.minetestClient,
        ssh_port: undefined as any
      }
    };

    const result = getMinetestClientCredentials(configWithDefaultPort);
    expect(result.port).toBe(22);
  });

  it('should throw error for disabled minetest client', () => {
    const configWithDisabledMinetestClient = {
      ...mockConfig,
      minetestClient: {
        ...mockConfig.minetestClient,
        enabled: false
      }
    };

    expect(() => getMinetestClientCredentials(configWithDisabledMinetestClient)).toThrow(
      'Minetest Client instance is not enabled'
    );
  });
});

describe('loadLabConfig', () => {
  const testConfigPath = resolve(process.cwd(), 'test-docker-lab-config.json');

  it('should load Docker lab configuration', async () => {
    const testConfig = {
      version: '1.0.0',
      lab: {
        name: 'aptl-minetest-client',
        network_subnet: '172.20.0.0/16'
      },
      containers: {
        'minetest-client': {
          container_name: 'aptl-minetest-client',
          container_ip: '172.20.0.23',
          ssh_key: '~/.ssh/aptl_lab_key',
          ssh_user: 'labadmin',
          ssh_port: 2025,
          enabled: true
        }
      },
      mcp: {
        server_name: 'aptl-minetest-client-mcp',
        allowed_networks: ['172.20.0.0/16'],
        max_session_time: 3600,
        audit_enabled: true,
        log_level: 'info'
      }
    };

    writeFileSync(testConfigPath, JSON.stringify(testConfig, null, 2));

    // Set environment variable to use test config
    process.env.APTL_CONFIG_PATH = testConfigPath;

    try {
      const config = await loadLabConfig();
      
      expect(config.lab.name).toBe('aptl-minetest-client');
      expect(config.minetestClient.ssh_user).toBe('labadmin');
      expect(config.minetestClient.ssh_port).toBe(2025);
      expect(config.minetestClient.public_ip).toBe('172.20.0.23');
    } finally {
      unlinkSync(testConfigPath);
      delete process.env.APTL_CONFIG_PATH;
    }
  });

  it('should throw error when minetest-client config is missing', async () => {
    const testConfig = {
      version: '1.0.0',
      lab: { name: 'test' },
      containers: {},
      mcp: {}
    };

    writeFileSync(testConfigPath, JSON.stringify(testConfig, null, 2));
    process.env.APTL_CONFIG_PATH = testConfigPath;

    try {
      await expect(loadLabConfig()).rejects.toThrow('Minetest Client container configuration is required');
    } finally {
      unlinkSync(testConfigPath);
      delete process.env.APTL_CONFIG_PATH;
    }
  });
});