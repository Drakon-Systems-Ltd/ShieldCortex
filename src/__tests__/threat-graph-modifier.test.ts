/**
 * Phase B step 3 — the advisory trust modifier (design doc Loop 2).
 *
 * effective_trust = base_trust - min(risk × RISK_TRUST_SCALE, RISK_TRUST_CAP).
 * Subtraction only (additive-tightening). The read is the ONE hot-path touch:
 * O(1) by primary key, guarded, fail-to-zero, and gated on attestation so a
 * spoofed victim identity can only turn enforcement OFF, never on. Default
 * mode is 'advisory' — computed and recorded on the audit row, not applied.
 */

import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { closeDatabase, getDatabase, initDatabase } from '../database/init.js';
import { computeRiskModifier, RISK_TRUST_CAP, RISK_TRUST_SCALE } from '../threat-graph/risk.js';
import { runDefencePipeline } from '../defence/pipeline.js';
import type { DefenceSource } from '../defence/types.js';

const SRC: DefenceSource = { type: 'agent', identifier: 'jarvis' };

function seedRisk(risk: number, attested: 0 | 1, key = 'agent:jarvis'): void {
  getDatabase().prepare(`
    INSERT INTO source_risk (source_key, risk, attested, updated_at)
    VALUES (?, ?, ?, '2026-08-11T00:00:00.000Z')
    ON CONFLICT(source_key) DO UPDATE SET risk = excluded.risk, attested = excluded.attested
  `).run(key, risk, attested);
}

beforeEach(() => initDatabase(':memory:'));
afterEach(() => closeDatabase());

describe('computeRiskModifier', () => {
  it('is 0 when no source_risk row exists', () => {
    expect(computeRiskModifier(SRC, 'advisory').modifier).toBe(0);
  });

  it('is 0 for an unattested source even at high risk (spoof-safe)', () => {
    seedRisk(1.0, 0);
    const r = computeRiskModifier(SRC, 'enforce');
    expect(r.modifier).toBe(0);
    expect(r.applied).toBe(false);
  });

  it('scales attested risk and caps it', () => {
    seedRisk(0.5, 1);
    expect(computeRiskModifier(SRC, 'enforce').modifier).toBeCloseTo(0.5 * RISK_TRUST_SCALE, 6);
    seedRisk(1.0, 1);
    expect(computeRiskModifier(SRC, 'enforce').modifier).toBeCloseTo(RISK_TRUST_CAP, 6);
  });

  it('mode off → modifier 0 even for attested high risk', () => {
    seedRisk(1.0, 1);
    expect(computeRiskModifier(SRC, 'off').modifier).toBe(0);
  });

  it('advisory computes the modifier but marks it not applied', () => {
    seedRisk(1.0, 1);
    const r = computeRiskModifier(SRC, 'advisory');
    expect(r.modifier).toBeCloseTo(RISK_TRUST_CAP, 6);
    expect(r.applied).toBe(false);
  });

  it('enforce marks it applied', () => {
    seedRisk(1.0, 1);
    expect(computeRiskModifier(SRC, 'enforce').applied).toBe(true);
  });

  it('normalises the lookup key like the projector (long identifiers still match)', () => {
    const longId = 'x'.repeat(500);
    seedRisk(1.0, 1, `agent:${'x'.repeat(200)}`);
    const r = computeRiskModifier({ type: 'agent', identifier: longId }, 'enforce');
    expect(r.modifier).toBeCloseTo(RISK_TRUST_CAP, 6);
  });

  it('#307 overflowed attested source uses overflow risk, not silent 0', () => {
    seedRisk(0.8, 1, 'overflow');
    getDatabase().prepare(`
      INSERT INTO defence_audit (
        memory_id, project, timestamp, source_type, source_identifier,
        trust_score, sensitivity_level, firewall_result,
        anomaly_score, threat_indicators, blocked_patterns,
        reason, fragmentation_score, pipeline_duration_ms, source_attested
      ) VALUES (NULL, 'test', '2026-08-16T00:00:00.000Z', 'agent', 'overflowed-attacker',
        0.1, 'PUBLIC', 'BLOCK', 0, '[]', '[]', NULL, NULL, 0, 1)
    `).run();
    const r = computeRiskModifier({ type: 'agent', identifier: 'overflowed-attacker' }, 'enforce');
    expect(r.modifier).toBeGreaterThan(0);
    expect(r.applied).toBe(true);
  });

  it('#307 overflowed unattested source stays 0', () => {
    seedRisk(0.8, 1, 'overflow');
    const r = computeRiskModifier({ type: 'agent', identifier: 'overflowed-unattested' }, 'enforce');
    expect(r.modifier).toBe(0);
    expect(r.applied).toBe(false);
  });
});

describe('pipeline integration', () => {
  function lastRow(): { risk_modifier: number | null; trust_score: number } {
    return getDatabase()
      .prepare('SELECT risk_modifier, trust_score FROM defence_audit ORDER BY id DESC LIMIT 1')
      .get() as { risk_modifier: number | null; trust_score: number };
  }

  it('advisory records the modifier but leaves the recorded trust at its base', () => {
    // Base trust for this source, with the modifier off.
    runDefencePipeline('a harmless note', 'note', SRC, undefined, 'test', { trustModifierMode: 'off' });
    const base = lastRow().trust_score;

    seedRisk(1.0, 1);
    runDefencePipeline('a harmless note', 'note', SRC, undefined, 'test', { trustModifierMode: 'advisory' });
    const row = lastRow();
    expect(row.risk_modifier).toBeCloseTo(RISK_TRUST_CAP, 6);
    expect(row.trust_score).toBeCloseTo(base, 6); // advisory does not apply
  });

  it('enforce subtracts the modifier from the recorded trust', () => {
    runDefencePipeline('a harmless note', 'note', SRC, undefined, 'test', { trustModifierMode: 'off' });
    const base = lastRow().trust_score;

    seedRisk(1.0, 1);
    runDefencePipeline('a harmless note', 'note', SRC, undefined, 'test', { trustModifierMode: 'enforce' });
    const row = lastRow();
    expect(row.risk_modifier).toBeCloseTo(RISK_TRUST_CAP, 6);
    expect(row.trust_score).toBeCloseTo(Math.max(0, base - RISK_TRUST_CAP), 6);
  });

  it('a DB read failure never breaks the scan (fail-to-zero, not fail-closed)', () => {
    // No source_risk row + a valid source → modifier 0, scan proceeds normally.
    const result = runDefencePipeline('a harmless note', 'note', SRC, undefined, 'test', { trustModifierMode: 'enforce' });
    expect(result.allowed).toBe(true);
    expect(lastRow().risk_modifier).toBe(0);
  });
});
