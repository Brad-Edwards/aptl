import { describe, it, expect } from 'vitest';
import { getTargetCredentials } from '../src/config.js';

describe('getTargetCredentials', () => {
  it('returns credentials for enabled container', () => {
    const config = {
      server: {
        configKey: 'test-container',
        targetName: 'Test Container'
      },
      containers: {
        'test-container': {
          ssh_key: '/path/to/key',
          ssh_user: 'testuser',
          ssh_port: 2022,
          container_ip: '172.20.0.50',
          enabled: true
        }
      }
    } as any;

    const creds = getTargetCredentials(config);
    
    expect(creds.sshKey).toBe('/path/to/key');
    expect(creds.username).toBe('testuser');
    expect(creds.port).toBe(2022);
    expect(creds.target).toBe('172.20.0.50');
  });

  it('throws error when container disabled', () => {
    const config = {
      server: {
        configKey: 'test-container',
        targetName: 'Test Container'
      },
      containers: {
        'test-container': {
          enabled: false
        }
      }
    } as any;

    expect(() => getTargetCredentials(config)).toThrow('Test Container instance is not enabled');
  });

  it('works with different container configs', () => {
    const config = {
      server: {
        configKey: 'kali',
        targetName: 'Kali Linux'
      },
      containers: {
        'kali': {
          ssh_key: '/kali/key',
          ssh_user: 'kali',
          ssh_port: 22,
          container_ip: '172.20.0.30',
          enabled: true
        }
      }
    } as any;

    const creds = getTargetCredentials(config);
    
    expect(creds.target).toBe('172.20.0.30');
    expect(creds.username).toBe('kali');
    expect(creds.sshKey).toBe('/kali/key');
    expect(creds.port).toBe(22);
  });

  it('uses correct configKey to find container', () => {
    const config = {
      server: {
        configKey: 'victim',
        targetName: 'Victim Container'
      },
      containers: {
        'victim': {
          ssh_key: '/victim/key',
          ssh_user: 'labadmin',
          ssh_port: 2022,
          container_ip: '172.20.0.20',
          enabled: true
        },
        'kali': {
          ssh_key: '/kali/key',
          ssh_user: 'kali',
          ssh_port: 22,
          container_ip: '172.20.0.30',
          enabled: true
        }
      }
    } as any;

    const creds = getTargetCredentials(config);
    
    expect(creds.target).toBe('172.20.0.20');
    expect(creds.username).toBe('labadmin');
  });
});