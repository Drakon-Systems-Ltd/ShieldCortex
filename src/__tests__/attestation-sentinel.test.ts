import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { closeDatabase, getDatabase, initDatabase } from '../database/init.js';
import { runDefencePipeline } from '../defence/pipeline.js';
import { scoreSource } from '../defence/trust/source-scorer.js';
import { runProjectorWithLease } from '../threat-graph/projector.js';
import { checkAttestationCoverage } from '../cli/doctor.js';
import type { DefenceSource } from '../defence/types.js';

const __dirname = path.join(fileURLToPath(import.meta.url), '..');
const repoRoot = path.join(__dirname, '..', '..');

/**
 * Phase 5 of the attestation gap: the DONE-criteria.
 *
 * The sentinel is the one test that walks the whole chain the previous four
 * phases built, through the PRODUCTION tick path: an attested BLOCK lands in
 * the ledger → the lease runner projects and sweeps → source_risk carries
 * {risk>0, attested=1} → the very next scan for that source records a non-zero
 * risk_modifier (computed-not-applied in advisory; subtracted in enforce).
 * If any link regresses — a writer stops attesting, the accrual gate breaks,
 * the sweep stops deriving, the hot-path read drifts — this fails.
 */
describe('phase 5 — end-to-end attestation sentinel', () => {
  const attacker: DefenceSource = { type: 'agent', identifier: 'sentinel-attacker' };
  // Deterministic BLOCK: a cleartext test credential trips the credential-leak
  // detector regardless of trust (same fixture class as memory-file-scanner).
  const hostile = 'Temporary test fixture token: sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

  beforeEach(() => {
    initDatabase(':memory:');
  });

  afterEach(() => {
    closeDatabase();
  });

  it('attested BLOCK → lease tick → risk accrues → next scan records the modifier', async () => {
    // 1. The attested BLOCK (as the resolver-vouched write path produces).
    const blocked = runDefencePipeline(hostile, 'note', attacker, undefined, 'test', { sourceAttested: true });
    expect(blocked.firewall.result).toBe('BLOCK');

    // 2. One PRODUCTION worker tick (lease acquisition, projection, sweep).
    const tick = await runProjectorWithLease({ now: Date.now() });
    expect(tick.ran).toBe(true);

    // 3. The risk model saw it.
    const risk = getDatabase()
      .prepare("SELECT risk, attested FROM source_risk WHERE source_key = 'agent:sentinel-attacker'")
      .get() as { risk: number; attested: number } | undefined;
    expect(risk).toBeDefined();
    expect(risk!.risk).toBeGreaterThan(0);
    expect(risk!.attested).toBe(1);

    // 4a. Advisory (the shipped default): the modifier is RECORDED on the next
    // scan's audit row but NOT applied — trust unchanged.
    const base = scoreSource(attacker).score;
    const advisory = runDefencePipeline('a perfectly benign follow-up note', 'note', attacker, undefined, 'test', {
      trustModifierMode: 'advisory',
    });
    expect(advisory.trust.score).toBe(base);
    const advisoryRow = getDatabase()
      .prepare('SELECT risk_modifier FROM defence_audit ORDER BY id DESC LIMIT 1')
      .get() as { risk_modifier: number | null };
    expect(advisoryRow.risk_modifier).toBeGreaterThan(0);

    // 4b. Enforce: the same modifier is SUBTRACTED (additive-tightening only).
    const enforce = runDefencePipeline('a perfectly benign follow-up note', 'note', attacker, undefined, 'test', {
      trustModifierMode: 'enforce',
    });
    expect(enforce.trust.score).toBeLessThan(base);
    expect(enforce.trust.score).toBeCloseTo(base - advisoryRow.risk_modifier!, 5);
  });

  it('the sentinel chain stays dead for an UNATTESTED block (the gate is the point)', async () => {
    runDefencePipeline(hostile, 'note', attacker, undefined, 'test'); // NULL attestation
    await runProjectorWithLease({ now: Date.now() });

    const risk = getDatabase()
      .prepare("SELECT risk, attested FROM source_risk WHERE source_key = 'agent:sentinel-attacker'")
      .get() as { risk: number; attested: number } | undefined;
    if (risk) {
      expect(risk.risk).toBe(0);
      expect(risk.attested).not.toBe(1);
    }
    const next = runDefencePipeline('benign', 'note', attacker, undefined, 'test', { trustModifierMode: 'enforce' });
    expect(next.trust.score).toBe(scoreSource(attacker).score);
  });
});

describe('phase 5 — doctor attestation-coverage metric', () => {
  const NOW = Date.parse('2026-08-16T12:00:00.000Z');

  beforeEach(() => {
    initDatabase(':memory:');
  });

  afterEach(() => {
    closeDatabase();
  });

  function seedRow(daysAgo: number, attested: number | null): void {
    getDatabase().prepare(`
      INSERT INTO defence_audit (
        memory_id, project, timestamp, source_type, source_identifier,
        trust_score, sensitivity_level, firewall_result,
        anomaly_score, threat_indicators, blocked_patterns,
        reason, fragmentation_score, pipeline_duration_ms, source_attested
      ) VALUES (NULL, 'test', ?, 'cli', 'seed', 0.9, 'PUBLIC', 'ALLOW', 0, '[]', '[]', NULL, NULL, 0, ?)
    `).run(new Date(NOW - daysAgo * 86_400_000).toISOString(), attested);
  }

  it('reports the window percentage with the attested/unattested/unplumbed split', async () => {
    seedRow(1, 1);
    seedRow(2, 1);
    seedRow(3, 0);
    seedRow(4, null);
    seedRow(40, null); // outside the 28-day window — excluded
    const result = await checkAttestationCoverage({ nowMs: NOW });
    expect(result.status).toBe('pass');
    expect(result.message).toContain('75%'); // 3 of 4 in-window rows non-NULL
    expect(result.message).toContain('2 attested');
    expect(result.message).toContain('1 explicitly unattested');
    expect(result.message).toContain('1 unplumbed');
  });

  it('warns when a busy install has ZERO attested rows (stale long-running processes)', async () => {
    for (let i = 0; i < 60; i++) seedRow(1, null);
    const result = await checkAttestationCoverage({ nowMs: NOW });
    expect(result.status).toBe('warn');
    expect(result.message.toLowerCase()).toContain('no audit row');
    expect(result.fix ?? '').toMatch(/restart/i);
  });

  it('a quiet window is informational, not a fault', async () => {
    const result = await checkAttestationCoverage({ nowMs: NOW });
    expect(result.status).toBe('info');
  });

  it('is wired into the doctor run registry (source pin)', () => {
    const src = fs.readFileSync(path.join(repoRoot, 'src', 'cli', 'doctor.ts'), 'utf8');
    const registry = src.slice(src.indexOf('checkDefenceCanary,'));
    expect(registry).toContain('checkAttestationCoverage,');
  });
});

describe('phase 5 — the no-backfill decision is recorded and enforced', () => {
  it('no migration ever writes source_attested values (source pin)', () => {
    // NULL→1 on historic rows is a trust-elevation hole; NULL→0 is a
    // behavioural no-op that only adds mute-lever surface. The consumption
    // side reads NULL conservatively, so history stays NULL, forever. This
    // pin stops a future session from "tidying" the NULL backlog.
    const src = fs.readFileSync(
      path.join(fileURLToPath(import.meta.url), '..', '..', 'database', 'migrations.ts'), 'utf8');
    expect(src).not.toMatch(/UPDATE\s+defence_audit\s+SET\s+source_attested/i);
    // And the decision is documented at the column's migration site.
    expect(src).toMatch(/never backfill/i);
  });
});
