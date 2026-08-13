/**
 * Phase B step 1 — attestation plumbing (design doc: "Phase B implementation
 * notes" §1-2).
 *
 * The pre-B audit established that attestation does not exist in the ledger:
 * resolveToolSource computes the env-inference metadata and discards it, and
 * strictSourceMode is defined but consumed nowhere. This suite pins:
 *
 *  - deriveAttested semantics: an identity is attested when it is
 *    SYSTEM-derived (no declaration; clamped to the env ceiling; or declared
 *    identical to what the environment infers) or when the deployment runs
 *    strictSourceMode (the operator's opt-in to enforcement consequences —
 *    strict mode does not verify identities, it accepts the stakes).
 *  - attested is NOT a field on DefenceSource (caller-suppliable) — it rides
 *    resolveToolSource's return value and a pipeline option only.
 *  - the ledger carries it: defence_audit.source_attested (nullable — NULL on
 *    legacy rows and unplumbed paths), written by the pipeline's audit stage.
 *  - risk_modifier column exists alongside it (written by a later B step).
 */

import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { closeDatabase, getDatabase, initDatabase } from '../database/init.js';
import { deriveAttested, resolveToolSource } from '../defence/trust/resolve-tool-source.js';
import { runDefencePipeline } from '../defence/pipeline.js';
import type { DefenceSource } from '../defence/types.js';

beforeEach(() => {
  initDatabase(':memory:');
});

afterEach(() => {
  closeDatabase();
});

describe('defence_audit schema', () => {
  it('has nullable source_attested and risk_modifier columns', () => {
    const cols = getDatabase().pragma('table_info(defence_audit)') as Array<{ name: string; notnull: number }>;
    const names = new Set(cols.map(c => c.name));
    expect(names.has('source_attested')).toBe(true);
    expect(names.has('risk_modifier')).toBe(true);
    expect(cols.find(c => c.name === 'source_attested')?.notnull).toBe(0);
  });
});

describe('deriveAttested', () => {
  const declared: DefenceSource = { type: 'agent', identifier: 'jarvis' };
  const inferred: DefenceSource = { type: 'unknown', identifier: 'undetected' };

  it('no declaration → attested (identity is system-derived)', () => {
    expect(deriveAttested({ declared: undefined, resolved: inferred, clamped: false, strict: false })).toBe(true);
  });

  it('declared and clamped → attested (the claim was rejected; env identity won)', () => {
    expect(deriveAttested({ declared, resolved: inferred, clamped: true, strict: false })).toBe(true);
  });

  it('declared, unclamped, differs from resolution basis → NOT attested', () => {
    expect(deriveAttested({ declared, resolved: declared, clamped: false, strict: false })).toBe(false);
  });

  it('declared identical to the env inference → attested (environment confirms it)', () => {
    expect(
      deriveAttested({ declared: inferred, resolved: inferred, clamped: false, strict: false, envInferred: inferred }),
    ).toBe(true);
  });

  it('strictSourceMode attests everything (operator opt-in to consequences)', () => {
    expect(deriveAttested({ declared, resolved: declared, clamped: false, strict: true })).toBe(true);
  });
});

describe('resolveToolSource return shape', () => {
  it('returns { source, attested } with attested=true when nothing was declared', () => {
    const resolved = resolveToolSource(undefined, { toolName: 'remember', project: null });
    expect(resolved.source).toBeDefined();
    expect(resolved.attested).toBe(true);
  });

  it('a self-declared low-trust identity resolves unattested (strict off)', () => {
    const resolved = resolveToolSource(
      { type: 'file', identifier: 'import' },
      { toolName: 'remember', project: null, strict: false },
    );
    // Whatever the clamp decides, an accepted self-declaration is not attested…
    if (!resolved.clamped) {
      expect(resolved.attested).toBe(false);
    } else {
      // …and a rejected one is (env identity won).
      expect(resolved.attested).toBe(true);
    }
  });

  it('strict override attests a declared identity', () => {
    const resolved = resolveToolSource(
      { type: 'file', identifier: 'import' },
      { toolName: 'remember', project: null, strict: true },
    );
    expect(resolved.attested).toBe(true);
  });
});

describe('pipeline → ledger plumbing', () => {
  const source: DefenceSource = { type: 'user', identifier: 'direct' };

  function lastAuditRow(): { source_attested: number | null } {
    return getDatabase()
      .prepare('SELECT source_attested FROM defence_audit ORDER BY id DESC LIMIT 1')
      .get() as { source_attested: number | null };
  }

  it('records source_attested=1 when the pipeline is told the source is attested', () => {
    runDefencePipeline('harmless note content', 'note', source, undefined, 'test', { sourceAttested: true });
    expect(lastAuditRow().source_attested).toBe(1);
  });

  it('records source_attested=0 when explicitly unattested', () => {
    runDefencePipeline('harmless note content', 'note', source, undefined, 'test', { sourceAttested: false });
    expect(lastAuditRow().source_attested).toBe(0);
  });

  it('records NULL when the caller did not plumb attestation (legacy paths)', () => {
    runDefencePipeline('harmless note content', 'note', source, undefined, 'test');
    expect(lastAuditRow().source_attested).toBeNull();
  });
});
