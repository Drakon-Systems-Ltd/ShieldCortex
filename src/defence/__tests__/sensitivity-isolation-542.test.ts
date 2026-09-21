/**
 * #542 — a row labelled SECRET (or any label outside the defined ladder) must
 * be isolated exactly like RESTRICTED by every reader-side gate. Before the fix
 * each gate tested `=== 'RESTRICTED'`, so SECRET — which the merge ladder ranks
 * ABOVE RESTRICTED and refuses to lower — fell through to the shared branch and
 * read like CONFIDENTIAL: a peer high-trust agent could read it, the dashboard
 * displayed its content, recall returned it unredacted and start packs injected
 * it into a prompt.
 *
 * Every assertion below fails on the pre-fix code and passes after it.
 */

import { describe, it, expect } from '@jest/globals';
import Database from 'better-sqlite3';
import {
  SHARED_SENSITIVITY_LEVELS,
  isIsolatedSensitivity,
  normaliseSensitivityLabel,
  sharedSensitivitySqlPredicate,
} from '../sensitivity/isolation.js';
import { checkAccess, type AccessCheckMemory } from '../trust/access-control.js';
import {
  deepRedactRestrictedContent,
  guardReadBySensitivity,
  guardReadMemories,
  redactRestrictedForDisplay,
} from '../trust/read-guard.js';
import { filterByTrust } from '../trust/recall-filter.js';
import { isInjectEligible, NATIVE_INJECT_CONTRACT } from '../../../scripts/lib/inject-pack.mjs';
import type { Memory } from '../../memory/types.js';
import type { DefenceSource } from '../types.js';

// Labels that must be isolated: the two ranked tiers plus everything unknown.
const ISOLATED_LABELS = ['RESTRICTED', 'SECRET', 'secret', ' Secret ', 'restricted', 'TOP-SECRET', 'PRIVATE', 'LEVEL9', '[object]'];
// Labels a peer may read: the shared tiers in any case, and an absent label.
const SHARED_LABELS: Array<string | null | undefined> = ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'internal', ' confidential ', null, undefined, '', '   '];

const PEER: DefenceSource = { type: 'cli', identifier: 'mcp' };                // 0.9, not the owner, not the operator
const OPERATOR: DefenceSource = { type: 'user', identifier: 'direct' };        // human operator
const MEDIUM: DefenceSource = { type: 'agent', identifier: 'user-spawned>task-1' }; // ~0.63

const row = (sensitivity_level: string | null | undefined, source = 'user:direct'): AccessCheckMemory =>
  ({ id: 42, source, sensitivity_level });

const mem = (p: Partial<Memory> & { id: number }): Memory =>
  ({ trustScore: 1, sensitivityLevel: 'INTERNAL', source: null, title: 'label', content: 'the stored text', ...p } as unknown as Memory);

describe('#542 isIsolatedSensitivity', () => {
  it('isolates RESTRICTED, SECRET and every label outside the ladder, ignoring case and whitespace', () => {
    for (const label of ISOLATED_LABELS) expect([label, isIsolatedSensitivity(label)]).toEqual([label, true]);
  });

  it('does not isolate the shared tiers or an absent label (unlabelled rows are INTERNAL by convention)', () => {
    for (const label of SHARED_LABELS) expect([label, isIsolatedSensitivity(label)]).toEqual([label, false]);
  });

  it('fails closed on non-string labels rather than reading them as a shared tier', () => {
    expect(isIsolatedSensitivity({ level: 'INTERNAL' })).toBe(true);
    expect(isIsolatedSensitivity(3)).toBe(true);
    expect(isIsolatedSensitivity(true)).toBe(true);
  });

  it('normalises labels and never exposes RESTRICTED or SECRET as a shared tier', () => {
    expect(normaliseSensitivityLabel(' secret ')).toBe('SECRET');
    expect(normaliseSensitivityLabel('')).toBeNull();
    expect(SHARED_SENSITIVITY_LEVELS.has('RESTRICTED')).toBe(false);
    expect(SHARED_SENSITIVITY_LEVELS.has('SECRET')).toBe(false);
  });
});

describe('#542 checkAccess read: SECRET and unknown labels are isolated like RESTRICTED', () => {
  it('denies a peer high-trust agent every isolated label (the reported hole: SECRET read true)', () => {
    for (const label of ISOLATED_LABELS) {
      const policy = checkAccess(row(label), PEER, 'read');
      expect([label, policy.canRead]).toEqual([label, false]);
      expect(policy.reason).toContain('isolated across agents');
    }
  });

  it('still lets the peer read the shared tiers and unlabelled rows', () => {
    for (const label of SHARED_LABELS) expect([label, checkAccess(row(label), PEER, 'read').canRead]).toEqual([label, true]);
  });

  it('denies medium trust every isolated label with the credential-isolation reason', () => {
    for (const label of ISOLATED_LABELS) {
      const policy = checkAccess(row(label), MEDIUM, 'read');
      expect(policy.canRead).toBe(false);
      expect(policy.reason).toContain('Credential isolation');
    }
  });

  it('keeps the RESTRICTED exemptions for SECRET: the operator and the owner may read', () => {
    expect(checkAccess(row('SECRET'), OPERATOR, 'read')).toMatchObject({ canRead: true, reason: 'Operator credential access' });
    expect(checkAccess(row('SECRET', 'cli:mcp'), PEER, 'read')).toMatchObject({ canRead: true, reason: 'Owner access' });
  });
});

describe('#542 read-guard: SECRET is withheld and redacted like RESTRICTED', () => {
  it('guardReadBySensitivity drops SECRET and unknown-label rows from shared context', () => {
    const rows = [
      mem({ id: 1, sensitivityLevel: 'INTERNAL' }),
      mem({ id: 2, sensitivityLevel: 'RESTRICTED' }),
      mem({ id: 3, sensitivityLevel: 'SECRET' }),
      mem({ id: 4, sensitivityLevel: 'secret' }),
      mem({ id: 5, sensitivityLevel: 'TOP-SECRET' }),
    ];
    expect(guardReadBySensitivity(rows).map((m) => m.id)).toEqual([1]);
  });

  it('guardReadMemories drops a SECRET row for a peer caller (same as RESTRICTED) and keeps it for the operator', () => {
    const rows = [mem({ id: 1, sensitivityLevel: 'SECRET', source: 'user:direct' })];
    expect(guardReadMemories(rows, PEER)).toHaveLength(0);
    expect(guardReadMemories(rows, OPERATOR).map((m) => m.id)).toEqual([1]);
  });

  it('redactRestrictedForDisplay withholds SECRET content exactly as it withholds RESTRICTED content', () => {
    const [restricted, secret, unknown, internal] = redactRestrictedForDisplay([
      mem({ id: 1, sensitivityLevel: 'RESTRICTED', content: 'restricted-body' }),
      mem({ id: 2, sensitivityLevel: 'SECRET', content: 'secret-body' }),
      mem({ id: 3, sensitivityLevel: 'PRIVATE', content: 'unknown-body' }),
      mem({ id: 4, sensitivityLevel: 'INTERNAL', content: 'internal-body' }),
    ]);
    expect(secret.content).toBe(restricted.content);
    expect(secret.content).not.toContain('secret-body');
    expect(unknown.content).toBe(restricted.content);
    expect(internal.content).toBe('internal-body');
  });

  it('deepRedactRestrictedContent scrubs SECRET rows inside an arbitrary HTTP payload (camelCase and snake_case)', () => {
    const payload = {
      memories: [
        { id: 1, sensitivityLevel: 'SECRET', content: 'secret-body' },
        { id: 2, sensitivity_level: 'secret', content: 'secret-body-2' },
        { id: 3, sensitivity_level: 'INTERNAL', content: 'internal-body' },
      ],
    };
    const out = JSON.stringify(deepRedactRestrictedContent(payload));
    expect(out).not.toContain('secret-body');
    expect(out).toContain('internal-body');
  });
});

describe('#542 recall filter: SECRET content is redacted like RESTRICTED', () => {
  it('replaces the content of SECRET and unknown-label rows and leaves shared rows alone', () => {
    const out = filterByTrust(
      [
        { id: 1, trust_score: 1, sensitivity_level: 'RESTRICTED', content: 'restricted-body' },
        { id: 2, trust_score: 1, sensitivity_level: 'SECRET', content: 'secret-body' },
        { id: 3, trust_score: 1, sensitivity_level: 'Secret', content: 'secret-body-2' },
        { id: 4, trust_score: 1, sensitivity_level: 'INTERNAL', content: 'internal-body' },
      ],
      0.5,
    );
    expect(out.map((r) => r.content)).toEqual([
      '[REDACTED - RESTRICTED]',
      '[REDACTED - RESTRICTED]',
      '[REDACTED - RESTRICTED]',
      'internal-body',
    ]);
  });
});

describe('#542 inject pack: SECRET and unknown labels are never injectable', () => {
  // Same eligible-row shape as inject-two-key-402.test.ts: only the label changes below.
  const scope = { hostId: 'tars', agentId: 'hermes', project: 'ShieldCortex' };
  const base = {
    id: 1,
    title: 'Fact',
    content: 'Open Day is Fri 25 Sep.',
    salience: 0.8,
    trust_score: 0.9,
    status: 'active',
    host_id: 'tars',
    agent_id: 'hermes',
    project: 'ShieldCortex',
    source: 'agent:openclaw',
    pinned: false,
    content_form: 'fact',
  };

  it('a row that is injectable at INTERNAL becomes ineligible at SECRET, any case, and at an unknown label', () => {
    expect(isInjectEligible({ ...base, sensitivity_level: 'INTERNAL' }, scope)).toBe(true);
    expect(isInjectEligible({ ...base, sensitivity_level: 'RESTRICTED' }, scope)).toBe(false);
    expect(isInjectEligible({ ...base, sensitivity_level: 'SECRET' }, scope)).toBe(false);
    expect(isInjectEligible({ ...base, sensitivity_level: 'secret' }, scope)).toBe(false);
    expect(isInjectEligible({ ...base, sensitivity_level: 'TOP-SECRET' }, scope)).toBe(false);
    expect(isInjectEligible({ ...base, sensitivity: 'SECRET' }, scope)).toBe(false);
  });

  it('keeps the unlabelled-row convention (missing/blank label reads as INTERNAL)', () => {
    expect(isInjectEligible({ ...base, sensitivity_level: null }, scope)).toBe(true);
    expect(isInjectEligible({ ...base, sensitivity_level: '  ' }, scope)).toBe(true);
    expect(NATIVE_INJECT_CONTRACT.SC_ONLY).toBeDefined();
  });
});

describe('#542 doctor counting predicate mirrors the TypeScript helper', () => {
  it('counts only shared-tier and unlabelled rows as admitted; SECRET and unknown labels are excluded', () => {
    const db = new Database(':memory:');
    db.exec('CREATE TABLE memories (id INTEGER PRIMARY KEY, sensitivity_level TEXT)');
    const insert = db.prepare('INSERT INTO memories (sensitivity_level) VALUES (?)');
    const labels: Array<string | null> = ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', ' confidential ', null, '', '  ', 'RESTRICTED', 'SECRET', 'secret', 'TOP-SECRET'];
    for (const label of labels) insert.run(label);
    const admitted = db.prepare(`SELECT COUNT(*) AS c FROM memories WHERE ${sharedSensitivitySqlPredicate()}`).get() as { c: number };
    expect(admitted.c).toBe(7);
    const excluded = db
      .prepare(`SELECT sensitivity_level AS l FROM memories WHERE NOT (${sharedSensitivitySqlPredicate()}) ORDER BY id`)
      .all() as Array<{ l: string }>;
    expect(excluded.map((r) => r.l)).toEqual(['RESTRICTED', 'SECRET', 'secret', 'TOP-SECRET']);
    // The SQL predicate and the TypeScript helper agree on every label.
    for (const label of labels) expect([label, isIsolatedSensitivity(label)]).toEqual([label, !['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', ' confidential ', null, '', '  '].includes(label)]);
    db.close();
  });
});
