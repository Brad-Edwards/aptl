// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import { z } from 'zod';
import { InstanceSchema, DisabledInstanceSchema } from './config.js';

describe('Schema Validation', () => {
  describe('InstanceSchema', () => {
    it('should validate a complete instance', () => {
      const validInstance = {
        public_ip: '1.2.3.4',
        private_ip: '10.0.1.10',
        ssh_key: '/path/to/key',
        ssh_user: 'ec2-user',
        instance_type: 't3.large',
        enabled: true,
        ports: { ssh: 22, https: 443 }
      };

      expect(() => InstanceSchema.parse(validInstance)).not.toThrow();
    });

    it('should default enabled to true', () => {
      const instance = {
        public_ip: '1.2.3.4',
        private_ip: '10.0.1.10',
        ssh_key: '/path/to/key',
        ssh_user: 'ec2-user',
        instance_type: 't3.large'
      };

      const result = InstanceSchema.parse(instance);
      expect(result.enabled).toBe(true);
    });

    it('should reject invalid IP addresses', () => {
      const invalidInstance = {
        public_ip: 'not-an-ip',
        private_ip: '10.0.1.10',
        ssh_key: '/path/to/key',
        ssh_user: 'ec2-user',
        instance_type: 't3.large'
      };

      expect(() => InstanceSchema.parse(invalidInstance)).toThrow();
    });

    it('should allow missing optional ports', () => {
      const instance = {
        public_ip: '1.2.3.4',
        private_ip: '10.0.1.10',
        ssh_key: '/path/to/key',
        ssh_user: 'ec2-user',
        instance_type: 't3.large'
      };

      expect(() => InstanceSchema.parse(instance)).not.toThrow();
    });
  });

  describe('DisabledInstanceSchema', () => {
    it('should validate disabled instance', () => {
      const disabledInstance = { enabled: false };
      expect(() => DisabledInstanceSchema.parse(disabledInstance)).not.toThrow();
    });

    it('should reject enabled instance', () => {
      const enabledInstance = { enabled: true };
      expect(() => DisabledInstanceSchema.parse(enabledInstance)).toThrow();
    });
  });

  describe('Union Schema', () => {
    const UnionSchema = z.union([InstanceSchema, DisabledInstanceSchema]);

    it('should accept either enabled or disabled instance', () => {
      const enabledInstance = {
        public_ip: '1.2.3.4',
        private_ip: '10.0.1.10',
        ssh_key: '/path/to/key',
        ssh_user: 'ec2-user',
        instance_type: 't3.large'
      };

      const disabledInstance = { enabled: false };

      expect(() => UnionSchema.parse(enabledInstance)).not.toThrow();
      expect(() => UnionSchema.parse(disabledInstance)).not.toThrow();
    });
  });
}); 