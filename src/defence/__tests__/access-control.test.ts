/**
 * Access Control Tests
 */

import { describe, it, expect } from '@jest/globals';
import { checkAccess, type AccessCheckMemory } from '../trust/access-control.js';
import type { DefenceSource } from '../types.js';

describe('Access Control', () => {
  const highTrustSource: DefenceSource = { type: 'cli', identifier: 'mcp' }; // 0.9
  const mediumTrustSource: DefenceSource = { type: 'agent', identifier: 'user-spawned>task-1' }; // 0.63
  const lowTrustSource: DefenceSource = { type: 'agent', identifier: 'agent-spawned>deep>chain' }; // 0.3 * 0.7^2 = 0.147

  const publicMemory: AccessCheckMemory = {
    id: 1,
    source: 'cli:mcp',
    sensitivity_level: 'PUBLIC',
  };

  const restrictedMemory: AccessCheckMemory = {
    id: 2,
    source: 'user:direct',
    sensitivity_level: 'RESTRICTED',
  };

  const ownedMemory: AccessCheckMemory = {
    id: 3,
    source: 'agent:user-spawned>task-1',
    sensitivity_level: 'INTERNAL',
  };

  describe('read access', () => {
    it('should allow high-trust to read all memories', () => {
      const policy = checkAccess(publicMemory, highTrustSource, 'read');
      expect(policy.canRead).toBe(true);
    });

    it('should allow high-trust to read RESTRICTED', () => {
      const policy = checkAccess(restrictedMemory, highTrustSource, 'read');
      expect(policy.canRead).toBe(true);
    });

    it('should block medium-trust from RESTRICTED (credential isolation)', () => {
      const policy = checkAccess(restrictedMemory, mediumTrustSource, 'read');
      expect(policy.canRead).toBe(false);
      expect(policy.reason).toContain('Credential isolation');
    });

    it('should allow medium-trust to read non-restricted', () => {
      const policy = checkAccess(publicMemory, mediumTrustSource, 'read');
      expect(policy.canRead).toBe(true);
    });

    it('should block low-trust from shared memories', () => {
      const policy = checkAccess(publicMemory, lowTrustSource, 'read');
      expect(policy.canRead).toBe(false);
    });

    it('should allow owner to read own memory regardless of trust', () => {
      const policy = checkAccess(ownedMemory, mediumTrustSource, 'read');
      expect(policy.canRead).toBe(true);
      expect(policy.reason).toContain('Owner');
    });
  });

  describe('write access', () => {
    it('should allow direct write for high-trust', () => {
      const policy = checkAccess(publicMemory, highTrustSource, 'write');
      expect(policy.canWrite).toBe(true);
      expect(policy.writeRequiresQuarantine).toBe(false);
    });

    it('should require quarantine for medium-trust', () => {
      const policy = checkAccess(publicMemory, mediumTrustSource, 'write');
      expect(policy.canWrite).toBe(false);
      expect(policy.writeRequiresQuarantine).toBe(true);
    });

    it('should require quarantine for low-trust', () => {
      const policy = checkAccess(publicMemory, lowTrustSource, 'write');
      expect(policy.writeRequiresQuarantine).toBe(true);
    });
  });

  describe('delete access', () => {
    it('should allow owner to delete own memory', () => {
      const policy = checkAccess(ownedMemory, mediumTrustSource, 'delete');
      expect(policy.canDelete).toBe(true);
    });

    it('should block non-owner deletion', () => {
      const policy = checkAccess(publicMemory, mediumTrustSource, 'delete');
      expect(policy.canDelete).toBe(false);
    });

    it('should block low-trust deletion even of own', () => {
      const lowOwnedMemory: AccessCheckMemory = {
        id: 4,
        source: 'agent:agent-spawned>deep>chain',
        sensitivity_level: 'INTERNAL',
      };
      const policy = checkAccess(lowOwnedMemory, lowTrustSource, 'delete');
      expect(policy.canDelete).toBe(false); // trust < 0.5
    });
  });
});
