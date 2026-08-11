/**
 * Threat Graph — Phase A.2: single-writer lease, realtime JSONL second ledger,
 * and brain-worker hosting (docs/design/2026-08-11-threat-graph.md).
 *
 *  - Lease: nothing enforces a worker singleton (MCP servers, dashboard,
 *    `shieldcortex worker` all construct one), so exactly-once projection
 *    comes from an atomic compare-and-set on threat_graph_state.lease_expires_at.
 *    A held lease no-ops; completion releases it.
 *  - JSONL: conversation scans in the OpenClaw gateway never reach
 *    defence_audit (the plugin is deliberately DB-free) — their realtime
 *    JSONL is a second append-only ledger, tailed with a '<file>:<line>'
 *    cursor. Only `type:"threat"` rows project; `reason` is free text and is
 *    stored capped in attrs, never as node identity (invariant 5).
 *  - Worker: hosted in the LIGHT tick on BOTH profiles — the medium tick is
 *    full-profile-only, and mcp-only installs are exactly the deployments
 *    that only scan (the audit-retention precedent, brain-worker.ts).
 */

import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { closeDatabase, getDatabase, initDatabase } from '../database/init.js';
import { runProjectorWithLease } from '../threat-graph/projector.js';
import { projectRealtimeLedger } from '../threat-graph/realtime-ledger.js';
import { BrainWorker } from '../worker/brain-worker.js';

const T0 = Date.parse('2026-08-11T12:00:00.000Z');

function insertAuditRow(): void {
  getDatabase().prepare(`
    INSERT INTO defence_audit (
      project, timestamp, source_type, source_identifier, trust_score,
      sensitivity_level, firewall_result, anomaly_score, threat_indicators, blocked_patterns
    ) VALUES ('test', '2026-08-01T10:00:00.000Z', 'agent', 'jarvis', 0.8,
      'INTERNAL', 'ALLOW', 0, '[]', '[]')
  `).run();
}

function makeRealtimeDir(files: Record<string, object[]>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-rt-'));
  for (const [name, rows] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, name), rows.map(r => JSON.stringify(r)).join('\n') + '\n');
  }
  return dir;
}

const THREAT_ROW = {
  type: 'threat', hook: 'llm_input', sessionId: 'sess-abc', model: 'claude-x',
  reason: 'instruction_injection: override attempt', chars: 512,
  contentSha256: 'deadbeefdeadbeef', ts: '2026-08-11T09:00:00.000Z',
};

beforeEach(() => {
  initDatabase(':memory:');
});

afterEach(() => {
  closeDatabase();
});

describe('single-writer lease', () => {
  it('processes under an acquired lease and releases on completion', async () => {
    insertAuditRow();
    const first = await runProjectorWithLease({ now: T0 });
    expect(first.ran).toBe(true);
    expect(first.audit?.processed).toBe(1);

    // Released: an immediate second run may acquire again (new rows process).
    insertAuditRow();
    const second = await runProjectorWithLease({ now: T0 + 1000 });
    expect(second.ran).toBe(true);
    expect(second.audit?.processed).toBe(1);
  });

  it('no-ops while a foreign lease is unexpired, and recovers after expiry', async () => {
    insertAuditRow();
    const db = getDatabase();
    db.prepare('INSERT OR IGNORE INTO threat_graph_state (id) VALUES (1)').run();
    // Simulate another process holding the lease.
    db.prepare('UPDATE threat_graph_state SET lease_expires_at = ? WHERE id = 1')
      .run(new Date(T0 + 60_000).toISOString());

    const blocked = await runProjectorWithLease({ now: T0 });
    expect(blocked.ran).toBe(false);

    // A crashed holder's stale lease is not permanent: past expiry, we acquire.
    const recovered = await runProjectorWithLease({ now: T0 + 61_000 });
    expect(recovered.ran).toBe(true);
    expect(recovered.audit?.processed).toBe(1);
  });
});

describe('realtime JSONL ledger', () => {
  it('projects threat rows into event + source + session nodes with edges', () => {
    const dir = makeRealtimeDir({
      'realtime-2026-08-11.jsonl': [
        { type: 'memory', hook: 'llm_output', count: 2 },     // non-threat: skipped
        THREAT_ROW,
      ],
    });
    const result = projectRealtimeLedger({ dir });
    expect(result.eventNodes).toBe(1);

    const db = getDatabase();
    const event = db.prepare(
      "SELECT * FROM threat_nodes WHERE kind = 'event' AND key = 'rt:realtime-2026-08-11.jsonl:2'"
    ).get() as any;
    expect(event).toBeDefined();
    expect(event.first_seen).toBe('2026-08-11T09:00:00.000Z');
    const attrs = JSON.parse(event.attrs);
    expect(attrs.hook).toBe('llm_input');
    expect(attrs.reason).toContain('instruction_injection');

    const source = db.prepare(
      "SELECT * FROM threat_nodes WHERE kind = 'source' AND key = 'conversation:llm_input'"
    ).get() as any;
    const session = db.prepare(
      "SELECT * FROM threat_nodes WHERE kind = 'session' AND key = 'sess-abc'"
    ).get() as any;
    expect(source).toBeDefined();
    expect(session).toBeDefined();

    const edges = db.prepare(
      'SELECT predicate FROM threat_edges WHERE src = ? ORDER BY predicate'
    ).all(event.id) as Array<{ predicate: string }>;
    expect(edges.map(e => e.predicate)).toEqual(['from_source', 'in_session']);
  });

  it('resumes from the cursor: appended lines project, replays do not duplicate', () => {
    const dir = makeRealtimeDir({ 'realtime-2026-08-11.jsonl': [THREAT_ROW] });
    expect(projectRealtimeLedger({ dir }).eventNodes).toBe(1);
    expect(projectRealtimeLedger({ dir }).eventNodes).toBe(0); // dry

    fs.appendFileSync(
      path.join(dir, 'realtime-2026-08-11.jsonl'),
      JSON.stringify({ ...THREAT_ROW, sessionId: 'sess-def' }) + '\n',
    );
    const resumed = projectRealtimeLedger({ dir });
    expect(resumed.eventNodes).toBe(1);

    const db = getDatabase();
    expect(db.prepare("SELECT COUNT(*) as c FROM threat_nodes WHERE kind = 'event'").get()).toEqual({ c: 2 });
    expect(db.prepare("SELECT COUNT(*) as c FROM threat_nodes WHERE kind = 'session'").get()).toEqual({ c: 2 });
  });

  it('advances across day files in name order', () => {
    const dir = makeRealtimeDir({
      'realtime-2026-08-10.jsonl': [{ ...THREAT_ROW, ts: '2026-08-10T09:00:00.000Z' }],
      'realtime-2026-08-11.jsonl': [THREAT_ROW],
    });
    const result = projectRealtimeLedger({ dir });
    expect(result.eventNodes).toBe(2);
    expect(result.cursor).toBe('realtime-2026-08-11.jsonl:1');
  });

  it('skips malformed lines without wedging the cursor', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-rt-'));
    fs.writeFileSync(
      path.join(dir, 'realtime-2026-08-11.jsonl'),
      'not json at all\n' + JSON.stringify(THREAT_ROW) + '\n',
    );
    const result = projectRealtimeLedger({ dir });
    expect(result.eventNodes).toBe(1);
    expect(result.errors.length).toBe(1);
    expect(projectRealtimeLedger({ dir }).eventNodes).toBe(0); // cursor past both lines
  });

  it('returns zeros when the directory does not exist', () => {
    const result = projectRealtimeLedger({ dir: '/nonexistent/sc-rt-none' });
    expect(result.eventNodes).toBe(0);
    expect(result.errors).toEqual([]);
  });

  it('never consumes an unterminated final line (concurrent-append tail race)', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-rt-'));
    const file = path.join(dir, 'realtime-2026-08-11.jsonl');
    const full = JSON.stringify(THREAT_ROW);
    // Gateway mid-append: line bytes present, trailing newline not yet written.
    fs.writeFileSync(file, full.slice(0, 40));
    const partial = projectRealtimeLedger({ dir });
    expect(partial.processed).toBe(0);
    expect(partial.errors).toEqual([]);

    // Append completes: the full line + newline is now consumable.
    fs.writeFileSync(file, full + '\n');
    const complete = projectRealtimeLedger({ dir });
    expect(complete.eventNodes).toBe(1);
  });

  it('normalises source identity: unknown hook names collapse to conversation:unknown', () => {
    const dir = makeRealtimeDir({
      'realtime-2026-08-11.jsonl': [{ ...THREAT_ROW, hook: 'totally-made-up-hook' }],
    });
    projectRealtimeLedger({ dir });
    const db = getDatabase();
    expect(db.prepare("SELECT id FROM threat_nodes WHERE kind = 'source' AND key = 'conversation:unknown'").get()).toBeDefined();
    expect(db.prepare("SELECT COUNT(*) as c FROM threat_nodes WHERE kind = 'source' AND key LIKE '%made-up%'").get()).toEqual({ c: 0 });
  });

  it('skips oversized files without stalling the cursor', () => {
    const dir = makeRealtimeDir({
      'realtime-2026-08-10.jsonl': [THREAT_ROW],
      'realtime-2026-08-11.jsonl': [{ ...THREAT_ROW, sessionId: 'sess-later' }],
    });
    const first = projectRealtimeLedger({ dir, maxFileBytes: 10 }); // both files exceed 10 bytes
    expect(first.eventNodes).toBe(0);
    expect(first.errors.length).toBe(2);

    // Cursor moved past the oversized files — a later normal file still projects.
    fs.writeFileSync(
      path.join(dir, 'realtime-2026-08-12.jsonl'),
      JSON.stringify({ ...THREAT_ROW, sessionId: 'sess-fresh' }) + '\n',
    );
    const second = projectRealtimeLedger({ dir });
    expect(second.eventNodes).toBe(1);
  });
});

describe('projector version upgrades', () => {
  it('a stored version older than the code forces a from-zero rebuild on the next lease run', async () => {
    insertAuditRow();
    await runProjectorWithLease({ now: T0 });
    const db = getDatabase();
    // Plant a stale-version marker plus a junk node a rebuild must clear.
    db.prepare('UPDATE threat_graph_state SET projector_version = 0 WHERE id = 1').run();
    db.prepare("INSERT INTO threat_nodes (kind, key, attrs, first_seen, last_seen) VALUES ('campaign', 'stale-junk', '{}', 'x', 'x')").run();

    const run = await runProjectorWithLease({ now: T0 + 1000 });
    expect(run.ran).toBe(true);
    expect(db.prepare("SELECT id FROM threat_nodes WHERE key = 'stale-junk'").get()).toBeUndefined();
    // Real projection replayed and version stamped current.
    expect(db.prepare("SELECT COUNT(*) as c FROM threat_nodes WHERE kind = 'source'").get()).toEqual({ c: 1 });
    const state = db.prepare('SELECT projector_version FROM threat_graph_state WHERE id = 1').get() as { projector_version: number };
    expect(state.projector_version).toBeGreaterThan(0);
  });
});

describe('error visibility', () => {
  it('persists realtime errors into last_error on a successful run, and clears them once healthy', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-rt-'));
    fs.writeFileSync(path.join(dir, 'realtime-2026-08-11.jsonl'), 'garbage line\n');
    await runProjectorWithLease({ now: T0, realtimeDir: dir });

    const db = getDatabase();
    let state = db.prepare('SELECT last_error FROM threat_graph_state WHERE id = 1').get() as { last_error: string | null };
    expect(state.last_error).toContain('malformed');

    // Next run with nothing wrong clears the stale error.
    await runProjectorWithLease({ now: T0 + 1000, realtimeDir: dir });
    state = db.prepare('SELECT last_error FROM threat_graph_state WHERE id = 1').get() as { last_error: string | null };
    expect(state.last_error).toBeNull();
  });
});

describe('brain-worker hosting (light tick, both profiles)', () => {
  it('the mcp-profile light tick runs the projector', async () => {
    insertAuditRow();
    const emptyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-rt-'));
    const worker = new BrainWorker({ profile: 'mcp', threatGraphRealtimeDir: emptyDir });

    await worker.lightTick();

    const state = getDatabase()
      .prepare('SELECT last_audit_id FROM threat_graph_state WHERE id = 1')
      .get() as { last_audit_id: number };
    expect(state.last_audit_id).toBeGreaterThan(0);
  });
});
