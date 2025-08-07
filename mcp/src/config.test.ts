// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import { isTargetAllowed, selectCredentials, type LabConfig } from './config.js';

describe('isTargetAllowed', () => {
  it('should allow IPs within CIDR range', () => {
    expect(isTargetAllowed('10.0.1.100', ['10.0.1.0/24'])).toBe(true);
    expect(isTargetAllowed('192.168.1.50', ['192.168.1.0/24'])).toBe(true);
  });

  it('should reject IPs outside CIDR range', () => {
    expect(isTargetAllowed('10.0.2.100', ['10.0.1.0/24'])).toBe(false);
    expect(isTargetAllowed('192.168.2.50', ['192.168.1.0/24'])).toBe(false);
  });

  it('should handle /32 networks', () => {
    expect(isTargetAllowed('10.0.1.100', ['10.0.1.100/32'])).toBe(true);
    expect(isTargetAllowed('10.0.1.101', ['10.0.1.100/32'])).toBe(false);
  });

  it('should handle multiple CIDR ranges', () => {
    const ranges = ['10.0.1.0/24', '192.168.1.0/24'];
    expect(isTargetAllowed('10.0.1.50', ranges)).toBe(true);
    expect(isTargetAllowed('192.168.1.50', ranges)).toBe(true);
    expect(isTargetAllowed('172.16.1.50', ranges)).toBe(false);
  });
});

describe('selectCredentials', () => {
  const mockConfig: LabConfig = {
    version: '1.0',
    generated: '2024-01-01T00:00:00Z',
    lab: {
      name: 'Test Lab',
      vpc_cidr: '10.0.0.0/16'
    },
    instances: {
      siem: {
        public_ip: '1.2.3.4',
        private_ip: '10.0.1.10',
        ssh_key: '/path/to/siem-key',
        ssh_user: 'ec2-user',
        instance_type: 't3.large',
        ssh_port: 22,
        enabled: true
      },
      victim: {
        public_ip: '1.2.3.5',
        private_ip: '10.0.1.20',
        ssh_key: '/path/to/victim-key',
        ssh_user: 'ec2-user',
        instance_type: 't3.medium',
        ssh_port: 22,
        enabled: true
      },
      kali: {
        public_ip: '1.2.3.6',
        private_ip: '10.0.1.30',
        ssh_key: '/path/to/kali-key',
        ssh_user: 'kali',
        instance_type: 't3.medium',
        ssh_port: 22,
        enabled: true
      }
    },
    network: {
      vpc_cidr: '10.0.0.0/16',
      subnet_cidr: '10.0.1.0/24',
      allowed_ip: '192.168.1.100/32'
    },
    mcp: {
      server_name: 'test-server',
      allowed_targets: ['10.0.1.0/24'],
      max_session_time: 3600,
      audit_enabled: true,
      log_level: 'info'
    }
  };

  it('should select SIEM credentials for SIEM IPs', () => {
    const result = selectCredentials('1.2.3.4', mockConfig);
    expect(result).toEqual({
      sshKey: '/path/to/siem-key',
      username: 'ec2-user',
      port: 22
    });

    const resultPrivate = selectCredentials('10.0.1.10', mockConfig);
    expect(resultPrivate).toEqual({
      sshKey: '/path/to/siem-key',
      username: 'ec2-user',
      port: 22
    });
  });

  it('should select victim credentials for victim IPs', () => {
    const result = selectCredentials('1.2.3.5', mockConfig);
    expect(result).toEqual({
      sshKey: '/path/to/victim-key',
      username: 'ec2-user',
      port: 22
    });
  });

  it('should select Kali credentials for Kali IPs', () => {
    const result = selectCredentials('1.2.3.6', mockConfig);
    expect(result).toEqual({
      sshKey: '/path/to/kali-key',
      username: 'kali',
      port: 22
    });
  });

  it('should default to Kali credentials for unknown IPs', () => {
    const result = selectCredentials('10.0.1.99', mockConfig, 'testuser');
    expect(result).toEqual({
      sshKey: '/path/to/kali-key',
      username: 'testuser',
      port: 22
    });
  });

  it('should throw error when Kali instance is disabled', () => {
    const configWithoutKali: LabConfig = {
      ...mockConfig,
      instances: {
        ...mockConfig.instances,
        kali: { enabled: false }
      }
    };

    expect(() => selectCredentials('10.0.1.99', configWithoutKali)).toThrow(
      'Kali instance not available for SSH operations'
    );
  });

  it('should handle disabled SIEM instance', () => {
    const configWithoutSiem: LabConfig = {
      ...mockConfig,
      instances: {
        ...mockConfig.instances,
        siem: { enabled: false }
      }
    };

    // Should fall back to Kali for unknown IP
    const result = selectCredentials('1.2.3.4', configWithoutSiem);
    expect(result).toEqual({
      sshKey: '/path/to/kali-key',
      username: 'kali',
      port: 22
    });
  });
}); 