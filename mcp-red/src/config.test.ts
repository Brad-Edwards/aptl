import { describe, it, expect } from 'vitest';
import { loadLabConfig, getKaliCredentials, KaliInstanceSchema, type LabConfig } from './config.js';
import { writeFileSync, unlinkSync } from 'fs';
import { resolve } from 'path';

describe('KaliInstanceSchema', () => {
  it('should validate a complete Kali instance', () => {
    const validKali = {
      public_ip: '172.20.0.30',
      private_ip: '172.20.0.30',
      ssh_key: '/path/to/key',
      ssh_user: 'kali',
      ssh_port: 2023,
      enabled: true
    };

    expect(() => KaliInstanceSchema.parse(validKali)).not.toThrow();
  });

  it('should default enabled to true', () => {
    const kali = {
      public_ip: '172.20.0.30',
      private_ip: '172.20.0.30',
      ssh_key: '/path/to/key',
      ssh_user: 'kali'
    };

    const result = KaliInstanceSchema.parse(kali);
    expect(result.enabled).toBe(true);
  });

  it('should default ssh_port to 22', () => {
    const kali = {
      public_ip: '172.20.0.30',
      private_ip: '172.20.0.30',
      ssh_key: '/path/to/key',
      ssh_user: 'kali'
    };

    const result = KaliInstanceSchema.parse(kali);
    expect(result.ssh_port).toBe(22);
  });

  it('should reject invalid IP addresses', () => {
    const invalidKali = {
      public_ip: 'not-an-ip',
      private_ip: '172.20.0.30',
      ssh_key: '/path/to/key',
      ssh_user: 'kali'
    };

    expect(() => KaliInstanceSchema.parse(invalidKali)).toThrow();
  });
});

describe('getKaliCredentials', () => {
  const mockConfig: LabConfig = {
    version: '1.0',
    generated: '2024-01-01T00:00:00Z',
    lab: {
      name: 'Test Lab',
      vpc_cidr: '172.20.0.0/16'
    },
    kali: {
      public_ip: '172.20.0.30',
      private_ip: '172.20.0.30',
      ssh_key: '/path/to/kali-key',
      ssh_user: 'kali',
      ssh_port: 2023,
      enabled: true
    },
    network: {
      vpc_cidr: '172.20.0.0/16',
      subnet_cidr: '172.20.0.0/16',
      allowed_ip: '0.0.0.0/0'
    },
    mcp: {
      server_name: 'test-server',
      allowed_targets: ['172.20.0.0/16'],
      max_session_time: 3600,
      audit_enabled: true,
      log_level: 'info'
    }
  };

  it('should return Kali credentials when enabled', () => {
    const result = getKaliCredentials(mockConfig);
    expect(result).toEqual({
      sshKey: '/path/to/kali-key',
      username: 'kali',
      port: 2023,
      target: '172.20.0.30'
    });
  });

  it('should use default port when not specified', () => {
    const configWithDefaultPort: LabConfig = {
      ...mockConfig,
      kali: {
        ...mockConfig.kali,
        ssh_port: 22
      }
    };

    const result = getKaliCredentials(configWithDefaultPort);
    expect(result.port).toBe(22);
  });

  it('should throw error when Kali instance is disabled', () => {
    const configWithDisabledKali: LabConfig = {
      ...mockConfig,
      kali: {
        ...mockConfig.kali,
        enabled: false
      }
    };

    expect(() => getKaliCredentials(configWithDisabledKali)).toThrow(
      'Kali instance is not enabled'
    );
  });
}); 