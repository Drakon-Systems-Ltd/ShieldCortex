/**
 * Tests for v4.0.0 type additions
 */

import { describe, it, expect } from '@jest/globals';

describe('Memory Type Taxonomy (v4.0.0)', () => {
  it('should validate valid memory purposes', async () => {
    const { isValidMemoryPurpose, VALID_MEMORY_PURPOSES } = await import('../memory/types.js');
    for (const purpose of VALID_MEMORY_PURPOSES) {
      expect(isValidMemoryPurpose(purpose)).toBe(true);
    }
  });

  it('should reject invalid memory purposes', async () => {
    const { isValidMemoryPurpose } = await import('../memory/types.js');
    expect(isValidMemoryPurpose('invalid')).toBe(false);
    expect(isValidMemoryPurpose(null)).toBe(false);
    expect(isValidMemoryPurpose(42)).toBe(false);
  });

  it('should validate valid memory scopes', async () => {
    const { isValidMemoryScope, VALID_MEMORY_SCOPES } = await import('../memory/types.js');
    for (const scope of VALID_MEMORY_SCOPES) {
      expect(isValidMemoryScope(scope)).toBe(true);
    }
  });

  it('should reject invalid memory scopes', async () => {
    const { isValidMemoryScope } = await import('../memory/types.js');
    expect(isValidMemoryScope('global')).toBe(false);
    expect(isValidMemoryScope('')).toBe(false);
  });

  it('should have 4 memory purposes', async () => {
    const { VALID_MEMORY_PURPOSES } = await import('../memory/types.js');
    expect(VALID_MEMORY_PURPOSES).toHaveLength(4);
    expect(VALID_MEMORY_PURPOSES).toContain('user');
    expect(VALID_MEMORY_PURPOSES).toContain('feedback');
    expect(VALID_MEMORY_PURPOSES).toContain('project');
    expect(VALID_MEMORY_PURPOSES).toContain('reference');
  });

  it('should have 2 memory scopes', async () => {
    const { VALID_MEMORY_SCOPES } = await import('../memory/types.js');
    expect(VALID_MEMORY_SCOPES).toHaveLength(2);
    expect(VALID_MEMORY_SCOPES).toContain('private');
    expect(VALID_MEMORY_SCOPES).toContain('team');
  });
});
