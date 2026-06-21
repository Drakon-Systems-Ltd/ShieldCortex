/**
 * checkAccess('revoke') — the trust-hierarchy delete used by revoke-by-source.
 * A caller may revoke a source's memories if it OWNS that source, OR it is
 * high-trust (>=0.7) AND strictly outranks the target source's trust. Equal/
 * higher-trust targets and sub-0.7 callers are denied. Single-row delete stays
 * own-only (operation 'delete') — unchanged.
 */

import { describe, it, expect } from '@jest/globals';
import { checkAccess } from '../trust/access-control.js';
import type { DefenceSource } from '../types.js';

const HIGH: DefenceSource = { type: 'cli', identifier: 'mcp' };          // ~0.9
const MID: DefenceSource = { type: 'file', identifier: 'import' };       // ~0.4
const LOW: DefenceSource = { type: 'agent', identifier: 'agent-spawned' }; // ~0.3
const USER: DefenceSource = { type: 'user', identifier: 'direct' };      // 1.0

describe("checkAccess('revoke')", () => {
  it('owner can revoke their own source', () => {
    expect(checkAccess({ id: 1, source: 'cli:mcp' }, HIGH, 'revoke').canDelete).toBe(true);
  });

  it('high-trust caller can revoke a strictly lower-trust source (outrank)', () => {
    expect(checkAccess({ id: 1, source: 'agent:agent-spawned' }, HIGH, 'revoke').canDelete).toBe(true);
  });

  it('high-trust caller CANNOT revoke an equal/higher-trust source', () => {
    // cli:mcp (0.9) vs user:direct (1.0): 0.9 is not > 1.0 → denied
    expect(checkAccess({ id: 1, source: 'user:direct' }, HIGH, 'revoke').canDelete).toBe(false);
  });

  it('sub-0.7 caller cannot revoke even a lower-trust source', () => {
    // file:import (0.4) revoking web:unattributed (0.3): trust < 0.7 → denied
    expect(checkAccess({ id: 1, source: 'web:unattributed' }, MID, 'revoke').canDelete).toBe(false);
  });

  it('low-trust caller cannot revoke a higher-trust source', () => {
    expect(checkAccess({ id: 1, source: 'user:direct' }, LOW, 'revoke').canDelete).toBe(false);
  });

  it("single-row 'delete' stays own-only (no outrank) — unchanged", () => {
    // HIGH does not own agent:agent-spawned → a plain delete is still denied
    expect(checkAccess({ id: 1, source: 'agent:agent-spawned' }, HIGH, 'delete').canDelete).toBe(false);
  });
});
