/**
 * Phase B step 4 — operator dispute (reset-source) + doctor sweep-age.
 *
 * reset-source is invariant 3's only loosening: human-authored, single-source,
 * expiring-by-nature (risk re-accrues if the source keeps misbehaving), and
 * recorded as an operation='review' audit row so a rebuild reproduces it. It
 * zeroes the source's stored risk sum and its source_risk row.
 *
 * The doctor gains a sweep-age signal: source_risk that has not been
 * refreshed within the staleness budget means the idle sweep (hence the
 * modifier's freshness) has stalled.
 */

import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { closeDatabase, getDatabase, initDatabase } from '../database/init.js';
import { projectToCompletion } from '../threat-graph/projector.js';
import { runRiskSweep } from '../threat-graph/risk.js';
import { resetSourceRisk } from '../threat-graph/risk.js';
import { checkThreatGraph } from '../cli/doctor.js';

function insertBlock(identifier = 'jarvis', ts = '2026-08-01T00:00:00.000Z'): void {
  getDatabase().prepare(`
    INSERT INTO defence_audit (project, timestamp, source_type, source_identifier,
      trust_score, sensitivity_level, firewall_result, anomaly_score,
      threat_indicators, blocked_patterns, source_attested)
    VALUES ('test', ?, 'agent', ?, 0.8, 'INTERNAL', 'BLOCK', 0, '[]', '[]', 1)
  `).run(ts, identifier);
}

beforeEach(() => initDatabase(':memory:'));
afterEach(() => closeDatabase());

describe('resetSourceRisk', () => {
  it('zeroes the source risk sum + source_risk row and writes an operation=review audit row', () => {
    const db = getDatabase();
    insertBlock();
    projectToCompletion();
    runRiskSweep({ nowMs: Date.parse('2026-08-01T00:00:00.000Z') });

    const before = (db.prepare("SELECT risk FROM source_risk WHERE source_key = 'agent:jarvis'")
      .get() as { risk: number }).risk;
    expect(before).toBeGreaterThan(0);

    const result = resetSourceRisk('agent:jarvis', { reviewedBy: 'michael' });
    expect(result.found).toBe(true);

    // source_risk zeroed, node sum cleared.
    const after = db.prepare("SELECT risk FROM source_risk WHERE source_key = 'agent:jarvis'")
      .get() as { risk: number } | undefined;
    expect(after?.risk ?? 0).toBe(0);
    const node = db.prepare("SELECT json_extract(attrs,'$.risk_sum') AS s FROM threat_nodes WHERE key = 'agent:jarvis'")
      .get() as { s: number | null };
    expect(node.s ?? 0).toBe(0);

    // Recorded as an operator review event with a host-derived identity (#305):
    // the caller-supplied reviewedBy string is annotation, never a user: row.
    const audit = db.prepare(
      "SELECT operation, source_type, source_identifier, reason FROM defence_audit WHERE operation = 'review' ORDER BY id DESC LIMIT 1"
    ).get() as { operation: string; source_type: string; source_identifier: string; reason: string };
    expect(audit.operation).toBe('review');
    expect(audit.source_type).not.toBe('user');
    expect(audit.source_identifier).not.toBe('michael');
    expect(audit.reason).toContain('agent:jarvis');
    expect((JSON.parse(audit.reason) as { reviewed_by?: string }).reviewed_by).toBe('michael');
  });

  it('reports not-found for an unknown source without writing risk state', () => {
    const result = resetSourceRisk('agent:nobody', { reviewedBy: 'michael' });
    expect(result.found).toBe(false);
  });

  it('survives a rebuild — the disputed risk does not silently re-accrue', async () => {
    const { rebuildThreatGraph } = await import('../threat-graph/projector.js');
    const db = getDatabase();

    // A block builds risk, the operator resets it.
    insertBlock('jarvis', '2026-08-01T00:00:00.000Z');
    projectToCompletion();
    resetSourceRisk('agent:jarvis', { reviewedBy: 'michael' });
    const afterReset = (db.prepare(
      "SELECT json_extract(attrs,'$.risk_sum') AS s FROM threat_nodes WHERE key = 'agent:jarvis'"
    ).get() as { s: number | null } | undefined)?.s ?? 0;
    expect(afterReset).toBe(0);

    // A full rebuild replays the ledger — including the block. Without the
    // projector consuming the risk_reset review row, risk would re-accrue.
    rebuildThreatGraph();
    const afterRebuild = (db.prepare(
      "SELECT json_extract(attrs,'$.risk_sum') AS s FROM threat_nodes WHERE key = 'agent:jarvis'"
    ).get() as { s: number | null } | undefined)?.s ?? 0;
    expect(afterRebuild ?? 0).toBe(0);
  });

  it('review rows do not accrue risk when projected', () => {
    insertBlock();
    projectToCompletion();
    resetSourceRisk('agent:jarvis', { reviewedBy: 'michael' });
    // Project the new review row.
    projectToCompletion();
    runRiskSweep({ nowMs: Date.parse('2026-08-02T00:00:00.000Z') });

    // The operator (source_identifier='michael') must not become a risky agent.
    const operatorRow = getDatabase()
      .prepare("SELECT risk FROM source_risk WHERE source_key = 'agent:michael' OR source_key LIKE '%michael%'")
      .get() as { risk: number } | undefined;
    expect(operatorRow?.risk ?? 0).toBe(0);
  });
});

describe('doctor sweep-age', () => {
  it('warns when source_risk is stale beyond the budget', async () => {
    insertBlock();
    projectToCompletion();
    runRiskSweep({ nowMs: Date.parse('2026-08-01T00:00:00.000Z') });

    // now is far ahead of the last sweep → stale.
    const result = await checkThreatGraph({
      nowMs: Date.parse('2026-08-01T00:00:00.000Z') + 3 * 24 * 60 * 60 * 1000,
      sweepStaleMs: 24 * 60 * 60 * 1000,
    });
    expect(result.status).toBe('warn');
    expect(result.message).toMatch(/sweep|stale|risk/i);
  });

  it('passes when the sweep is fresh', async () => {
    insertBlock();
    projectToCompletion();
    const now = Date.parse('2026-08-01T00:00:00.000Z');
    runRiskSweep({ nowMs: now });
    const result = await checkThreatGraph({ nowMs: now, sweepStaleMs: 24 * 60 * 60 * 1000 });
    expect(result.status).toBe('pass');
  });
});
