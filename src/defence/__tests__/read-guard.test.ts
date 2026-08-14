/**
 * Tests for the MCP read-path access guard. The .mjs prompt hooks already filter
 * recalled rows; the MCP read tools (get_memory / get_related / get_context, and
 * belt-and-braces recall) did not. guardReadMemories applies the existing
 * access-control engine consistently: quarantined rows are always dropped, and
 * when a caller source is present, rows the caller cannot read are dropped
 * (RESTRICTED isolation below trust 0.7, own-only for low trust). Owner /
 * high-trust callers pass through in full (the chosen policy).
 */

import { describe, it, expect } from '@jest/globals';
import { guardReadMemories, guardReadMemory, guardReadRows, guardReadBySensitivity } from '../trust/read-guard.js';
import type { Memory } from '../../memory/types.js';
import type { DefenceSource } from '../types.js';

const mem = (p: Partial<Memory> & { id: number }): Memory =>
  ({ trustScore: 1, sensitivityLevel: 'INTERNAL', source: null, content: 'secret-or-not', ...p } as unknown as Memory);

const HIGH: DefenceSource = { type: 'user', identifier: 'direct' };      // ~1.0
const LOW: DefenceSource = { type: 'web', identifier: 'unattributed' };  // ~0.3
const MED: DefenceSource = { type: 'api', identifier: 'dashboard' };     // ~0.7

describe('guardReadMemories', () => {
  it('always drops quarantined rows (trustScore 0), even for a high-trust caller', () => {
    const rows = [mem({ id: 1, trustScore: 0 }), mem({ id: 2, trustScore: 1 })];
    expect(guardReadMemories(rows, HIGH).map((m) => m.id)).toEqual([2]);
  });

  it('drops RESTRICTED rows for a low-trust caller (credential isolation)', () => {
    const rows = [mem({ id: 1, sensitivityLevel: 'RESTRICTED' })];
    expect(guardReadMemories(rows, LOW)).toHaveLength(0);
  });

  it('keeps RESTRICTED rows for a high-trust caller (owner/high-trust full per policy)', () => {
    const rows = [mem({ id: 1, sensitivityLevel: 'RESTRICTED' })];
    expect(guardReadMemories(rows, HIGH).map((m) => m.id)).toEqual([1]);
  });

  it("drops other-source rows for a low-trust non-owner caller (own-only tier)", () => {
    const rows = [mem({ id: 1, source: 'user:someoneelse' })];
    expect(guardReadMemories(rows, LOW)).toHaveLength(0);
  });

  it('keeps own rows for a low-trust OWNER caller', () => {
    const rows = [mem({ id: 1, source: 'web:unattributed' })]; // matches LOW caller key
    expect(guardReadMemories(rows, LOW).map((m) => m.id)).toEqual([1]);
  });

  it('keeps non-restricted shared rows for a medium-trust (>=0.7) caller', () => {
    const rows = [mem({ id: 1, source: 'user:someoneelse' })];
    expect(guardReadMemories(rows, MED).map((m) => m.id)).toEqual([1]);
  });

  it('with no caller source, keeps everything except quarantined', () => {
    const rows = [mem({ id: 1, sensitivityLevel: 'RESTRICTED' }), mem({ id: 2, trustScore: 0 })];
    expect(guardReadMemories(rows, undefined).map((m) => m.id)).toEqual([1]);
  });
});

describe('guardReadRows (raw snake_case rows, e.g. export)', () => {
  const row = (p: Record<string, unknown> & { id: number }) =>
    ({ trust_score: 1, sensitivity_level: 'INTERNAL', source: null, ...p });

  it('drops own RESTRICTED raw rows for a low-trust caller, keeps own non-restricted', () => {
    // Both owned by the LOW caller (web:unattributed). RESTRICTED is still denied
    // below trust 0.7 even to the owner (credential isolation); the normal own
    // row survives.
    const rows = [
      row({ id: 1, sensitivity_level: 'RESTRICTED', source: 'web:unattributed' }),
      row({ id: 2, source: 'web:unattributed' }),
    ];
    expect(guardReadRows(rows, LOW).map((r) => r.id)).toEqual([2]);
  });

  it('keeps RESTRICTED raw rows for a high-trust caller', () => {
    const rows = [row({ id: 1, sensitivity_level: 'RESTRICTED' })];
    expect(guardReadRows(rows, HIGH).map((r) => r.id)).toEqual([1]);
  });

  it('always drops quarantined raw rows (trust_score 0)', () => {
    const rows = [row({ id: 1, trust_score: 0 }), row({ id: 2 })];
    expect(guardReadRows(rows, HIGH).map((r) => r.id)).toEqual([2]);
    expect(guardReadRows(rows, undefined).map((r) => r.id)).toEqual([2]);
  });
});

describe('guardReadBySensitivity (shared-context bootstrap surfaces)', () => {
  it('drops RESTRICTED and quarantined regardless of caller (even high-trust/owner)', () => {
    const rows = [
      mem({ id: 1, sensitivityLevel: 'RESTRICTED' }),
      mem({ id: 2, trustScore: 0 }),
      mem({ id: 3, sensitivityLevel: 'INTERNAL' }),
    ];
    // Source is irrelevant — sensitivity-only.
    expect(guardReadBySensitivity(rows).map((m) => m.id)).toEqual([3]);
  });

  it('KEEPS INTERNAL/CONFIDENTIAL shared context for everyone (no own-only blackout)', () => {
    // The key difference from full checkAccess: a low-trust subagent still sees
    // INTERNAL project context from other sources — it is not a leak.
    const rows = [
      mem({ id: 1, sensitivityLevel: 'INTERNAL', source: 'user:direct' }),
      mem({ id: 2, sensitivityLevel: 'CONFIDENTIAL', source: 'user:direct' }),
    ];
    expect(guardReadBySensitivity(rows).map((m) => m.id)).toEqual([1, 2]);
  });

  it('drops web/email inbound rows so a capture cannot bootstrap another agent', () => {
    const rows = [
      mem({ id: 1, source: 'web:evil.example', sensitivityLevel: 'PUBLIC' }),
      mem({ id: 2, source: 'email:inbox', sensitivityLevel: 'INTERNAL' }),
      mem({ id: 3, source: 'cli:openclaw-jarvis', sensitivityLevel: 'INTERNAL' }),
    ];
    expect(guardReadBySensitivity(rows).map((m) => m.id)).toEqual([3]);
  });
});

describe('guardReadMemory', () => {
  it('returns null when access is denied', () => {
    expect(guardReadMemory(mem({ id: 1, sensitivityLevel: 'RESTRICTED' }), LOW)).toBeNull();
  });

  it('returns the memory when allowed', () => {
    expect(guardReadMemory(mem({ id: 1 }), HIGH)?.id).toBe(1);
  });

  it('returns null for null/undefined input', () => {
    expect(guardReadMemory(null, HIGH)).toBeNull();
    expect(guardReadMemory(undefined, HIGH)).toBeNull();
  });
});
