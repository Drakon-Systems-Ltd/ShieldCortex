/**
 * Phase B step 2 — the risk model (design doc Loop 1).
 *
 * risk(t) = 1 - exp( -Σᵢ wᵢ · 2^(-(t - tᵢ)/H) ), weights BLOCK 1.0 /
 * QUARANTINE 0.5 / high-anomaly ALLOW 0.1 / pipeline_error 0.0, half-life H.
 *
 * Split by the determinism contract:
 *  - the raw exponent SUM + its ledger-time reference live in the source
 *    node's attrs (pure function of ledger rows — covered by canonicalDump);
 *  - the DECAYED risk (wall-clock relative) lives in source_risk, recomputed
 *    every sweep, and is deliberately outside the determinism contract.
 *
 * Accrual is rate-capped per source (≤ RATE_CAP weight per rolling window) so
 * one identity — including an attacker burning a victim's name — cannot
 * saturate risk in a burst.
 */

import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import {
  DEFAULT_HALF_LIFE_MS,
  RATE_CAP,
  decayedRisk,
  eventWeight,
  foldEvent,
} from '../threat-graph/risk.js';
import { closeDatabase, getDatabase, initDatabase } from '../database/init.js';
import { projectToCompletion } from '../threat-graph/projector.js';
import { runRiskSweep } from '../threat-graph/risk.js';

const DAY = 24 * 60 * 60 * 1000;

describe('eventWeight', () => {
  const T = 0.7;
  it('weights verdicts per the model', () => {
    expect(eventWeight({ verdict: 'BLOCK', anomaly: 0, pipelineError: false, anomalyThreshold: T })).toBe(1.0);
    expect(eventWeight({ verdict: 'QUARANTINE', anomaly: 0, pipelineError: false, anomalyThreshold: T })).toBe(0.5);
    expect(eventWeight({ verdict: 'ALLOW', anomaly: 0.85, pipelineError: false, anomalyThreshold: T })).toBe(0.1);
    expect(eventWeight({ verdict: 'ALLOW', anomaly: 0.2, pipelineError: false, anomalyThreshold: T })).toBe(0);
  });

  it('zero-weights pipeline_error rows even when they are BLOCK', () => {
    expect(eventWeight({ verdict: 'BLOCK', anomaly: 1, pipelineError: true, anomalyThreshold: T })).toBe(0);
  });
});

describe('foldEvent + decayedRisk', () => {
  const opts = { halfLifeMs: DEFAULT_HALF_LIFE_MS, rateCap: RATE_CAP, rateWindowMs: DAY };

  it('a single BLOCK folds to sum 1 at its own timestamp', () => {
    const s = foldEvent(null, 1_000_000, 1.0, opts);
    expect(s.sum).toBeCloseTo(1.0, 10);
    expect(s.refTs).toBe(1_000_000);
    // Risk right at the event ≈ 1 - e^-1
    expect(decayedRisk(s.sum, s.refTs, 1_000_000, DEFAULT_HALF_LIFE_MS)).toBeCloseTo(1 - Math.exp(-1), 6);
  });

  it('decays by half over one half-life (sum halves; risk drops accordingly)', () => {
    const s = foldEvent(null, 0, 1.0, opts);
    const now = DEFAULT_HALF_LIFE_MS;
    // sum decays to 0.5 → risk = 1 - e^-0.5
    expect(decayedRisk(s.sum, s.refTs, now, DEFAULT_HALF_LIFE_MS)).toBeCloseTo(1 - Math.exp(-0.5), 6);
  });

  it('is rebase-invariant: folding order/reference does not change the risk at a fixed now', () => {
    // Two BLOCKs a half-life apart, folded in order.
    let s = foldEvent(null, 0, 1.0, opts);
    s = foldEvent(s, DEFAULT_HALF_LIFE_MS, 1.0, opts);
    const now = 2 * DEFAULT_HALF_LIFE_MS;
    // Direct: term1 at t=0 → 2^-2 = 0.25; term2 at t=H → 2^-1 = 0.5; sum 0.75
    const direct = 1 - Math.exp(-0.75);
    expect(decayedRisk(s.sum, s.refTs, now, DEFAULT_HALF_LIFE_MS)).toBeCloseTo(direct, 6);
  });

  it('saturates: many BLOCKs cannot push risk to or past 1', () => {
    let s = foldEvent(null, 0, 1.0, opts);
    for (let i = 1; i < 50; i++) s = foldEvent(s, i * 2 * DAY, 1.0, opts);
    const risk = decayedRisk(s.sum, s.refTs, 50 * 2 * DAY, DEFAULT_HALF_LIFE_MS);
    expect(risk).toBeLessThan(1);
    expect(risk).toBeGreaterThan(0.5);
  });

  it('rate-caps accrual within the window: a burst beyond RATE_CAP is clipped', () => {
    // Ten BLOCKs in the same instant — only RATE_CAP worth accrues.
    let s = foldEvent(null, 5_000, 1.0, opts);
    for (let i = 0; i < 9; i++) s = foldEvent(s, 5_000, 1.0, opts);
    expect(s.sum).toBeCloseTo(RATE_CAP, 6);
  });

  it('reopens the rate window after it elapses', () => {
    let s = foldEvent(null, 0, 1.0, opts);
    for (let i = 0; i < 9; i++) s = foldEvent(s, 0, 1.0, opts); // capped at 2.0
    s = foldEvent(s, DAY + 1, 1.0, opts); // new window → accrues again
    // sum ≈ 2.0 decayed over a day + 1.0
    const decayedOld = RATE_CAP * Math.pow(2, -(DAY + 1) / DEFAULT_HALF_LIFE_MS);
    expect(s.sum).toBeCloseTo(decayedOld + 1.0, 6);
  });
});

describe('runRiskSweep (DB)', () => {
  beforeEach(() => initDatabase(':memory:'));
  afterEach(() => closeDatabase());

  function insertAudit(seed: {
    verdict?: 'ALLOW' | 'BLOCK' | 'QUARANTINE';
    identifier?: string;
    ts: string;
    attested?: 0 | 1 | null;
    anomaly?: number;
  }): void {
    getDatabase().prepare(`
      INSERT INTO defence_audit (
        project, timestamp, source_type, source_identifier, trust_score,
        sensitivity_level, firewall_result, anomaly_score, threat_indicators,
        blocked_patterns, source_attested
      ) VALUES ('test', @ts, 'agent', @identifier, 0.8, 'INTERNAL', @verdict,
        @anomaly, '[]', '[]', @attested)
    `).run({
      ts: seed.ts,
      identifier: seed.identifier ?? 'jarvis',
      verdict: seed.verdict ?? 'ALLOW',
      anomaly: seed.anomaly ?? 0,
      attested: seed.attested === undefined ? 1 : seed.attested,
    });
  }

  it('populates source_risk with decayed risk + 28-day counters from the projected graph', () => {
    insertAudit({ verdict: 'BLOCK', ts: '2026-08-01T00:00:00.000Z' });
    insertAudit({ verdict: 'QUARANTINE', ts: '2026-08-02T00:00:00.000Z' });
    insertAudit({ verdict: 'ALLOW', ts: '2026-08-03T00:00:00.000Z' });
    projectToCompletion();

    const now = Date.parse('2026-08-03T00:00:00.000Z');
    runRiskSweep({ nowMs: now });

    const row = getDatabase().prepare("SELECT * FROM source_risk WHERE source_key = 'agent:jarvis'")
      .get() as any;
    expect(row).toBeDefined();
    expect(row.risk).toBeGreaterThan(0);
    expect(row.risk).toBeLessThan(1);
    expect(row.block_count_28d).toBe(1);
    expect(row.quarantine_count_28d).toBe(1);
    expect(row.scan_count_28d).toBe(3);
  });

  it('sets attested from the source’s latest audit row (spoofing turns enforcement off, never wrongly on)', () => {
    insertAudit({ verdict: 'BLOCK', ts: '2026-08-01T00:00:00.000Z', attested: 1 });
    // A later declared (unattested) row — an attacker writing under this name.
    insertAudit({ verdict: 'ALLOW', ts: '2026-08-05T00:00:00.000Z', attested: 0 });
    projectToCompletion();
    runRiskSweep({ nowMs: Date.parse('2026-08-05T00:00:00.000Z') });

    const row = getDatabase().prepare("SELECT attested FROM source_risk WHERE source_key = 'agent:jarvis'")
      .get() as { attested: number };
    expect(row.attested).toBe(0);
  });

  it('is idempotent and refreshes decay for idle sources (risk falls as now advances)', () => {
    insertAudit({ verdict: 'BLOCK', ts: '2026-08-01T00:00:00.000Z' });
    projectToCompletion();

    runRiskSweep({ nowMs: Date.parse('2026-08-01T00:00:00.000Z') });
    const early = (getDatabase().prepare("SELECT risk FROM source_risk WHERE source_key = 'agent:jarvis'")
      .get() as { risk: number }).risk;

    // No new events — just time passing. The idle sweep must lower risk.
    runRiskSweep({ nowMs: Date.parse('2026-08-01T00:00:00.000Z') + 28 * DAY });
    const later = (getDatabase().prepare("SELECT risk FROM source_risk WHERE source_key = 'agent:jarvis'")
      .get() as { risk: number }).risk;

    expect(later).toBeLessThan(early);
  });

  it('rebuild after a ledger purge does not lower a surviving source’s risk (no amnesty)', async () => {
    const { rebuildThreatGraph } = await import('../threat-graph/projector.js');
    const db = getDatabase();

    // Two BLOCKs build risk; project them.
    insertAudit({ verdict: 'BLOCK', ts: '2026-08-01T00:00:00.000Z' });
    insertAudit({ verdict: 'BLOCK', ts: '2026-08-02T00:00:00.000Z' });
    projectToCompletion();
    const before = (db.prepare(
      "SELECT json_extract(attrs,'$.risk_sum') AS s FROM threat_nodes WHERE key = 'agent:jarvis'"
    ).get() as { s: number }).s;

    // Retention purges the older row out from under the graph, but the source
    // still has a surviving row.
    db.prepare("DELETE FROM defence_audit WHERE timestamp = '2026-08-01T00:00:00.000Z'").run();

    rebuildThreatGraph();
    const after = (db.prepare(
      "SELECT json_extract(attrs,'$.risk_sum') AS s FROM threat_nodes WHERE key = 'agent:jarvis'"
    ).get() as { s: number }).s;

    // A naive replay of the truncated ledger would give ~half; re-seed keeps
    // the pre-purge sum.
    expect(after).toBeCloseTo(before, 6);
  });

  it('does not accrue risk for pipeline_error BLOCK rows', () => {
    getDatabase().prepare(`
      INSERT INTO defence_audit (project, timestamp, source_type, source_identifier,
        trust_score, sensitivity_level, firewall_result, anomaly_score,
        threat_indicators, blocked_patterns, source_attested)
      VALUES ('test', '2026-08-01T00:00:00.000Z', 'agent', 'wedged', 0, 'RESTRICTED',
        'BLOCK', 1.0, '["pipeline_error"]', '[]', 1)
    `).run();
    projectToCompletion();
    runRiskSweep({ nowMs: Date.parse('2026-08-01T00:00:00.000Z') });

    const row = getDatabase().prepare("SELECT risk FROM source_risk WHERE source_key = 'agent:wedged'")
      .get() as { risk: number } | undefined;
    // Either no row, or a row with zero risk — never risk from a self-inflicted block.
    expect(row?.risk ?? 0).toBe(0);
  });
});
