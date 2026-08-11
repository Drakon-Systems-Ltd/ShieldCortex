/**
 * Threat Graph projector — Phase A core (docs/design/2026-08-11-threat-graph.md).
 *
 * The projector is a deterministic projection of the defence_audit ledger into
 * threat_nodes / threat_edges, advanced by an atomic claim-and-advance cursor
 * in threat_graph_state. Contract pinned here:
 *
 *  - Two-tier volume control: ALLOW rows update source counters + aggregate
 *    `triggered` edges only; event nodes are minted solely for notable rows
 *    (BLOCK/QUARANTINE, high-anomaly ALLOW).
 *  - pipeline_error BLOCK rows (the fail-closed handler's own audit rows) are
 *    flagged on their event node so Phase B's risk model can zero-weight them.
 *  - All graph timestamps derive from ledger-row timestamps, never wall clock.
 *  - Logical determinism: incremental projection and a from-zero rebuild yield
 *    identical canonical dumps.
 *  - Bounded everything: source cap routes overflow to a bucket node; evidence
 *    arrays are FIFO-capped.
 *
 * Harness: fresh in-memory DB per test; audit rows inserted directly so
 * timestamps and verdicts are exact.
 */

import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import type Database from 'better-sqlite3';
import { closeDatabase, getDatabase, initDatabase } from '../database/init.js';
import {
  canonicalDump,
  projectAuditLedger,
  projectToCompletion,
  rebuildThreatGraph,
} from '../threat-graph/projector.js';

interface AuditSeed {
  timestamp?: string;
  source_type?: string;
  source_identifier?: string;
  firewall_result?: 'ALLOW' | 'BLOCK' | 'QUARANTINE';
  anomaly_score?: number;
  blocked_patterns?: string[];
  threat_indicators?: string[];
  project?: string;
}

function insertAuditRow(seed: AuditSeed = {}): number {
  const db = getDatabase();
  const r = db.prepare(`
    INSERT INTO defence_audit (
      memory_id, project, timestamp, source_type, source_identifier,
      trust_score, sensitivity_level, firewall_result,
      anomaly_score, threat_indicators, blocked_patterns,
      reason, fragmentation_score, pipeline_duration_ms
    ) VALUES (
      NULL, @project, @timestamp, @source_type, @source_identifier,
      0.8, 'INTERNAL', @firewall_result,
      @anomaly_score, @threat_indicators, @blocked_patterns,
      NULL, NULL, 1
    )
  `).run({
    project: seed.project ?? 'test',
    timestamp: seed.timestamp ?? '2026-08-01T10:00:00.000Z',
    source_type: seed.source_type ?? 'agent',
    source_identifier: seed.source_identifier ?? 'jarvis',
    firewall_result: seed.firewall_result ?? 'ALLOW',
    anomaly_score: seed.anomaly_score ?? 0,
    threat_indicators: JSON.stringify(seed.threat_indicators ?? []),
    blocked_patterns: JSON.stringify(seed.blocked_patterns ?? []),
  });
  return Number(r.lastInsertRowid);
}

function getNode(db: Database.Database, kind: string, key: string): any {
  return db.prepare('SELECT * FROM threat_nodes WHERE kind = ? AND key = ?').get(kind, key);
}

function getEdge(db: Database.Database, srcId: number, predicate: string, dstId: number): any {
  return db.prepare('SELECT * FROM threat_edges WHERE src = ? AND predicate = ? AND dst = ?')
    .get(srcId, predicate, dstId);
}

beforeEach(() => {
  initDatabase(':memory:');
});

afterEach(() => {
  closeDatabase();
});

describe('schema', () => {
  it('creates the threat-graph tables on init', () => {
    const db = getDatabase();
    const tables = db.prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('threat_nodes','threat_edges','threat_graph_state','source_risk')"
    ).all() as Array<{ name: string }>;
    expect(tables.map(t => t.name).sort()).toEqual(
      ['source_risk', 'threat_edges', 'threat_graph_state', 'threat_nodes'],
    );
  });
});

describe('aggregate tier (ALLOW rows)', () => {
  it('mints source + pattern nodes and a counted triggered edge, but no event node', () => {
    insertAuditRow({ blocked_patterns: ['instruction_injection'] });
    const result = projectAuditLedger();
    expect(result.processed).toBe(1);

    const db = getDatabase();
    const source = getNode(db, 'source', 'agent:jarvis');
    const pattern = getNode(db, 'pattern', 'instruction_injection');
    expect(source).toBeDefined();
    expect(pattern).toBeDefined();

    const edge = getEdge(db, source.id, 'triggered', pattern.id);
    expect(edge).toBeDefined();
    expect(edge.count).toBe(1);
    expect(edge.writer).toBe('projector');

    expect(db.prepare("SELECT COUNT(*) as c FROM threat_nodes WHERE kind = 'event'").get()).toEqual({ c: 0 });
  });

  it('increments the same edge on repeat firings and updates last_seen from row timestamps', () => {
    insertAuditRow({ blocked_patterns: ['instruction_injection'], timestamp: '2026-08-01T10:00:00.000Z' });
    insertAuditRow({ blocked_patterns: ['instruction_injection'], timestamp: '2026-08-02T11:00:00.000Z' });
    projectToCompletion();

    const db = getDatabase();
    const source = getNode(db, 'source', 'agent:jarvis');
    const pattern = getNode(db, 'pattern', 'instruction_injection');
    const edge = getEdge(db, source.id, 'triggered', pattern.id);
    expect(edge.count).toBe(2);
    expect(edge.first_seen).toBe('2026-08-01T10:00:00.000Z');
    expect(edge.last_seen).toBe('2026-08-02T11:00:00.000Z');

    const attrs = JSON.parse(source.attrs);
    expect(attrs.scan_count).toBe(2);
    expect(attrs.allow_count).toBe(2);
  });

  it('an ALLOW row with no patterns updates counters only — no pattern node, no edge', () => {
    insertAuditRow();
    projectAuditLedger();
    const db = getDatabase();
    expect(getNode(db, 'source', 'agent:jarvis')).toBeDefined();
    expect(db.prepare('SELECT COUNT(*) as c FROM threat_edges').get()).toEqual({ c: 0 });
    expect(db.prepare("SELECT COUNT(*) as c FROM threat_nodes WHERE kind = 'pattern'").get()).toEqual({ c: 0 });
  });
});

describe('event tier (notable rows)', () => {
  it('mints an event node with from_source and matched edges for a BLOCK', () => {
    const auditId = insertAuditRow({
      firewall_result: 'BLOCK',
      blocked_patterns: ['credential_exfil'],
      anomaly_score: 0.4,
      project: 'alpha',
    });
    projectAuditLedger();

    const db = getDatabase();
    const event = getNode(db, 'event', `audit:${auditId}`);
    expect(event).toBeDefined();
    const attrs = JSON.parse(event.attrs);
    expect(attrs.verdict).toBe('BLOCK');
    expect(attrs.project).toBe('alpha');

    const source = getNode(db, 'source', 'agent:jarvis');
    const pattern = getNode(db, 'pattern', 'credential_exfil');
    expect(getEdge(db, event.id, 'from_source', source.id)).toBeDefined();
    expect(getEdge(db, event.id, 'matched', pattern.id)).toBeDefined();

    expect(JSON.parse(source.attrs).block_count).toBe(1);
  });

  it('mints an event node for a high-anomaly ALLOW', () => {
    const auditId = insertAuditRow({ firewall_result: 'ALLOW', anomaly_score: 0.85 });
    projectAuditLedger();
    expect(getNode(getDatabase(), 'event', `audit:${auditId}`)).toBeDefined();
  });

  it('does not mint an event node for an ordinary ALLOW', () => {
    insertAuditRow({ firewall_result: 'ALLOW', anomaly_score: 0.3 });
    projectAuditLedger();
    const db = getDatabase();
    expect(db.prepare("SELECT COUNT(*) as c FROM threat_nodes WHERE kind = 'event'").get()).toEqual({ c: 0 });
  });

  it('flags pipeline_error BLOCK rows on their event node', () => {
    const auditId = insertAuditRow({
      firewall_result: 'BLOCK',
      threat_indicators: ['pipeline_error'],
    });
    projectAuditLedger();
    const event = getNode(getDatabase(), 'event', `audit:${auditId}`);
    expect(JSON.parse(event.attrs).pipeline_error).toBe(true);
  });
});

describe('cursor (claim-and-advance)', () => {
  it('advances in batches and is idempotent once dry', () => {
    for (let i = 0; i < 5; i++) insertAuditRow();
    const first = projectAuditLedger({ batchSize: 2 });
    expect(first.processed).toBe(2);
    const second = projectAuditLedger({ batchSize: 2 });
    expect(second.processed).toBe(2);
    const third = projectAuditLedger({ batchSize: 2 });
    expect(third.processed).toBe(1);
    const dry = projectAuditLedger({ batchSize: 2 });
    expect(dry.processed).toBe(0);

    const db = getDatabase();
    const source = getNode(db, 'source', 'agent:jarvis');
    expect(JSON.parse(source.attrs).scan_count).toBe(5);
  });
});

describe('determinism', () => {
  it('incremental projection and from-zero rebuild produce identical canonical dumps', () => {
    insertAuditRow({ blocked_patterns: ['instruction_injection'], timestamp: '2026-08-01T09:00:00.000Z' });
    insertAuditRow({
      firewall_result: 'QUARANTINE',
      blocked_patterns: ['credential_exfil', 'instruction_injection'],
      source_identifier: 'researcher',
      timestamp: '2026-08-01T10:00:00.000Z',
    });
    insertAuditRow({ firewall_result: 'BLOCK', timestamp: '2026-08-02T08:00:00.000Z' });

    // Incremental: three separate single-row batches.
    projectAuditLedger({ batchSize: 1 });
    projectAuditLedger({ batchSize: 1 });
    projectAuditLedger({ batchSize: 1 });
    const incremental = canonicalDump();

    // From-zero rebuild over the same ledger.
    rebuildThreatGraph();
    const rebuilt = canonicalDump();

    expect(rebuilt).toBe(incremental);
    expect(rebuilt.length).toBeGreaterThan(0);
  });
});

describe('bounds', () => {
  it('routes sources beyond the cap to the overflow bucket', () => {
    for (let i = 0; i < 4; i++) {
      insertAuditRow({ source_identifier: `agent-${i}` });
    }
    projectToCompletion({ maxSources: 3 });

    const db = getDatabase();
    const distinct = db.prepare(
      "SELECT COUNT(*) as c FROM threat_nodes WHERE kind = 'source' AND key != 'overflow'"
    ).get() as { c: number };
    expect(distinct.c).toBe(3);
    const overflow = getNode(db, 'source', 'overflow');
    expect(overflow).toBeDefined();
    expect(JSON.parse(overflow.attrs).scan_count).toBe(1);
  });

  it('caps evidence arrays FIFO, keeping the newest', () => {
    const ids: number[] = [];
    for (let i = 0; i < 4; i++) {
      ids.push(insertAuditRow({ blocked_patterns: ['instruction_injection'] }));
    }
    projectToCompletion({ evidenceCap: 2 });

    const db = getDatabase();
    const source = getNode(db, 'source', 'agent:jarvis');
    const pattern = getNode(db, 'pattern', 'instruction_injection');
    const edge = getEdge(db, source.id, 'triggered', pattern.id);
    const evidence = JSON.parse(edge.evidence) as number[];
    expect(evidence).toEqual(ids.slice(-2));
  });
});
