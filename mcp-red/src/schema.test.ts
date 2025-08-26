import { describe, it, expect } from 'vitest';
import { z } from 'zod';
import { KaliInstanceSchema } from './config.js';

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

  it('should require all mandatory fields', () => {
    const incompleteKali = {
      public_ip: '172.20.0.30'
      // Missing required fields
    };

    expect(() => KaliInstanceSchema.parse(incompleteKali)).toThrow();
  });

  it('should accept custom ssh_port', () => {
    const kaliWithCustomPort = {
      public_ip: '172.20.0.30',
      private_ip: '172.20.0.30',
      ssh_key: '/path/to/key',
      ssh_user: 'kali',
      ssh_port: 2023
    };

    const result = KaliInstanceSchema.parse(kaliWithCustomPort);
    expect(result.ssh_port).toBe(2023);
  });
});

describe('Schema Error Handling', () => {
  it('should provide meaningful error messages for invalid data', () => {
    const invalidKali = {
      public_ip: 'invalid-ip',
      private_ip: '172.20.0.30',
      ssh_key: '',
      ssh_user: 123 // Should be string
    };

    expect(() => KaliInstanceSchema.parse(invalidKali)).toThrow();
  });

  it('should handle missing required fields', () => {
    const emptyObject = {};
    expect(() => KaliInstanceSchema.parse(emptyObject)).toThrow();
  });
});