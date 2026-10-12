/**
 * #579 Slice 1A — strict realtime cursor classification and report-and-halt.
 *
 * A malformed stored cursor used to stall silently (file part sorting after
 * every realtime file) or replay from the first file (re-incrementing edge
 * counts). It now halts realtime projection with one fixed error, before the
 * directory is listed, leaving the graph and cursor unchanged. Recovery is an
 * operator action; nothing here heals the cursor.
 *
 * Absence claims are backed by operation observers (a recording fs seam, a
 * spy on the connection's transaction(), SQLite total_changes()), not only by
 * row equality. The ensure-row INSERT OR IGNORE still executes; these tests
 * do not claim zero SQL statements.
 */

import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { closeDatabase, getDatabase, initDatabase } from '../database/init.js';
import { runProjectorWithLease } from '../threat-graph/projector.js';
import {
  MALFORMED_CURSOR_ERROR,
  projectRealtimeLedger,
  projectRealtimeLedgerWithSeams,
} from '../threat-graph/realtime-ledger.js';
import {
  FILE_CONSUMED_LINE,
  nodeRealtimePlaneFs,
  parseRealtimeCursor,
  type RealtimePlaneFs,
} from '../threat-graph/realtime-plane.js';

const T0 = Date.parse('2026-08-11T12:00:00.000Z');
const DAY = 'realtime-2026-08-11.jsonl';

const THREAT_ROW = {
  type: 'threat', hook: 'llm_input', sessionId: 'sess-abc', model: 'claude-x',
  reason: 'instruction_injection: override attempt', chars: 512,
  contentSha256: 'deadbeefdeadbeef', ts: '2026-08-11T09:00:00.000Z',
};

const scratch: string[] = [];

function scratchDir(): string {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-579-cursor-')));
  scratch.push(dir);
  return dir;
}

function line(row: object): string {
  return JSON.stringify(row) + '\n';
}

function recordingFs(): { ops: RealtimePlaneFs; calls: string[] } {
  const calls: string[] = [];
  const ops: RealtimePlaneFs = {
    readdir: (d) => { calls.push(`readdir ${d}`); return nodeRealtimePlaneFs.readdir(d); },
    stat: (p) => { calls.push(`stat ${p}`); return nodeRealtimePlaneFs.stat(p); },
    readFile: (p) => { calls.push(`read ${p}`); return nodeRealtimePlaneFs.readFile(p); },
  };
  return { ops, calls };
}

function storedCursor(): string {
  return (getDatabase().prepare('SELECT last_rt_cursor FROM threat_graph_state WHERE id = 1')
    .get() as { last_rt_cursor: string }).last_rt_cursor;
}

function setCursor(cursor: string): void {
  getDatabase().prepare('UPDATE threat_graph_state SET last_rt_cursor = ? WHERE id = 1').run(cursor);
}

function graphSnapshot(): unknown {
  const db = getDatabase();
  return {
    nodes: db.prepare('SELECT id, kind, key, attrs, first_seen, last_seen FROM threat_nodes ORDER BY id').all(),
    edges: db.prepare('SELECT * FROM threat_edges ORDER BY 1').all(),
    cursor: storedCursor(),
  };
}

/**
 * Projection-owned state only. Lease runs also run the risk sweep, which
 * rewrites source-node risk attrs from wall-clock `now`; that is not
 * realtime projection, so lease-level comparisons exclude it.
 */
function projectionSnapshot(): unknown {
  const db = getDatabase();
  return {
    events: db.prepare("SELECT id, key, attrs, first_seen, last_seen FROM threat_nodes WHERE kind = 'event' ORDER BY id").all(),
    nodeKeys: db.prepare('SELECT id, kind, key FROM threat_nodes ORDER BY id').all(),
    edges: db.prepare('SELECT id, src, predicate, dst, count, first_seen, last_seen FROM threat_edges ORDER BY id').all(),
    cursor: storedCursor(),
  };
}

function totalChanges(): number {
  return (getDatabase().prepare('SELECT total_changes() AS c').get() as { c: number }).c;
}

beforeEach(() => {
  initDatabase(':memory:');
});

afterEach(() => {
  jest.restoreAllMocks();
  closeDatabase();
  for (const dir of scratch.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

describe('T3a parseRealtimeCursor', () => {
  it('classifies empty and canonical cursors', () => {
    expect(parseRealtimeCursor('')).toEqual({ kind: 'empty' });
    expect(parseRealtimeCursor(`${DAY}:5`)).toEqual({ kind: 'valid', file: DAY, line: 5 });
    expect(parseRealtimeCursor(`${DAY}:0`)).toEqual({ kind: 'valid', file: DAY, line: 0 });
    expect(parseRealtimeCursor(`${DAY}:${FILE_CONSUMED_LINE}`))
      .toEqual({ kind: 'valid', file: DAY, line: FILE_CONSUMED_LINE });
  });

  it.each([
    'x:1',
    `${DAY}:1e3`,
    `${DAY}: 5`,
    `${DAY}:01`,
    `${DAY}:1.5`,
    `${DAY}:`,
    `${DAY}:-1`,
    `${DAY}:abc`,
    `${DAY}:5 `,
    `${DAY}:10000000000`,
    `${DAY}:99999999999`,
    ':5',
    'nocolon',
    DAY,
    `realtime-2026-08-11.jsonl.gz:5`,
    `sub/${DAY}:5`,
  ])('classifies %j as malformed', (raw) => {
    expect(parseRealtimeCursor(raw)).toEqual({ kind: 'malformed' });
  });
});

const MALFORMED_SAMPLES = ['x:1', `${DAY}:1e3`, `${DAY}:01`, `${DAY}:-1`, `${DAY}:abc`, ':5', 'nocolon', `${DAY}:10000000000`];

describe('T3b malformed cursor halts on a populated graph', () => {
  it.each(MALFORMED_SAMPLES)('cursor %j: fixed error, graph rows, edge counts and cursor unchanged', (bad) => {
    const dir = scratchDir();
    fs.writeFileSync(path.join(dir, DAY), line(THREAT_ROW));
    expect(projectRealtimeLedger({ dir }).eventNodes).toBe(1);
    // New pending content that a non-halting ledger would project or replay.
    fs.appendFileSync(path.join(dir, DAY), line({ ...THREAT_ROW, sessionId: 'sess-new' }));
    setCursor(bad);

    const before = graphSnapshot();
    const edgeCounts = getDatabase().prepare('SELECT count FROM threat_edges ORDER BY 1').all();
    const db = getDatabase();
    const txSpy = jest.spyOn(db, 'transaction');
    const rec = recordingFs();
    const changesBefore = totalChanges();

    const result = projectRealtimeLedgerWithSeams({ dir }, { fs: rec.ops });

    expect(result).toEqual({ processed: 0, cursor: bad, eventNodes: 0, errors: [MALFORMED_CURSOR_ERROR] });
    expect(result.errors[0]).not.toContain(bad);
    expect(rec.calls).toEqual([]);
    expect(txSpy).not.toHaveBeenCalled();
    expect(totalChanges()).toBe(changesBefore);
    expect(graphSnapshot()).toEqual(before);
    expect(getDatabase().prepare('SELECT count FROM threat_edges ORDER BY 1').all()).toEqual(edgeCounts);
    expect(storedCursor()).toBe(bad);
  });
});

describe('T3c malformed cursor halts identically for every directory state', () => {
  const states: Array<[string, (dir: string) => string]> = [
    ['empty directory', (dir) => dir],
    ['missing directory', (dir) => path.join(dir, 'does-not-exist')],
    ['unterminated tail only', (dir) => { fs.writeFileSync(path.join(dir, DAY), JSON.stringify(THREAT_ROW)); return dir; }],
    ['first listed file unavailable', (dir) => { fs.mkdirSync(path.join(dir, 'realtime-2026-08-01.jsonl')); fs.writeFileSync(path.join(dir, DAY), line(THREAT_ROW)); return dir; }],
    ['oversize only', (dir) => { fs.writeFileSync(path.join(dir, DAY), line(THREAT_ROW).repeat(4)); return dir; }],
  ];

  it.each(states)('%s', (_label, setup) => {
    const dir = setup(scratchDir());
    getDatabase().prepare('INSERT OR IGNORE INTO threat_graph_state (id) VALUES (1)').run();
    setCursor('x:1');
    const before = graphSnapshot();
    const db = getDatabase();
    const txSpy = jest.spyOn(db, 'transaction');
    const rec = recordingFs();
    const changesBefore = totalChanges();

    const result = projectRealtimeLedgerWithSeams({ dir, maxFileBytes: 64 }, { fs: rec.ops });

    expect(result).toEqual({ processed: 0, cursor: 'x:1', eventNodes: 0, errors: [MALFORMED_CURSOR_ERROR] });
    expect(rec.calls).toEqual([]);
    expect(txSpy).not.toHaveBeenCalled();
    expect(totalChanges()).toBe(changesBefore);
    expect(graphSnapshot()).toEqual(before);
  });
});

describe('T3d malformed cursor through the lease runner', () => {
  it('persists the fixed error on every run; a manual canonical restore resumes normally', async () => {
    const dir = scratchDir();
    fs.writeFileSync(path.join(dir, DAY), line(THREAT_ROW));
    // Establish the current projector version first so later runs do not
    // take the version-bump clearGraph path.
    await runProjectorWithLease({ now: T0, realtimeDir: dir });
    expect(storedCursor()).toBe(`${DAY}:1`);

    fs.appendFileSync(path.join(dir, DAY), line({ ...THREAT_ROW, sessionId: 'sess-new' }));
    setCursor(`${DAY}:01`);
    const before = projectionSnapshot();

    const first = await runProjectorWithLease({ now: T0 + 1000, realtimeDir: dir });
    expect(first.ran).toBe(true);
    expect(first.realtime?.errors).toEqual([MALFORMED_CURSOR_ERROR]);
    const db = getDatabase();
    const lastError = () => (db.prepare('SELECT last_error FROM threat_graph_state WHERE id = 1')
      .get() as { last_error: string | null }).last_error;
    expect(lastError()).toContain(MALFORMED_CURSOR_ERROR);
    expect(projectionSnapshot()).toEqual(before);

    await runProjectorWithLease({ now: T0 + 2000, realtimeDir: dir });
    expect(lastError()).toContain(MALFORMED_CURSOR_ERROR);
    expect(storedCursor()).toBe(`${DAY}:01`);
    expect(projectionSnapshot()).toEqual(before);

    // Operator restores a canonical cursor: projection resumes at line 2 only.
    setCursor(`${DAY}:1`);
    const resumed = await runProjectorWithLease({ now: T0 + 3000, realtimeDir: dir });
    expect(resumed.realtime?.processed).toBe(1);
    expect(storedCursor()).toBe(`${DAY}:2`);
    expect(lastError()).toBeNull();
    const fromSource = db.prepare(`
      SELECT e.count FROM threat_edges e JOIN threat_nodes n ON n.id = e.src
      WHERE n.kind = 'event' AND n.key = ? AND e.predicate = 'from_source'
    `).get(`rt:${DAY}:1`) as { count: number };
    expect(fromSource.count).toBe(1);
  });
});

describe('T3e empty and canonical cursors are unchanged', () => {
  it('empty cursor projects from the first file; a valid cursor resumes after its line', () => {
    const dir = scratchDir();
    fs.writeFileSync(path.join(dir, DAY), line(THREAT_ROW) + line({ ...THREAT_ROW, sessionId: 's2' }));
    const first = projectRealtimeLedger({ dir, batchSize: 1 });
    expect(first).toEqual({ processed: 1, cursor: `${DAY}:1`, eventNodes: 1, errors: [] });
    const second = projectRealtimeLedger({ dir });
    expect(second).toEqual({ processed: 1, cursor: `${DAY}:2`, eventNodes: 1, errors: [] });
    const idle = projectRealtimeLedger({ dir });
    expect(idle).toEqual({ processed: 0, cursor: `${DAY}:2`, eventNodes: 0, errors: [] });
  });

  it('a sentinel cursor skips its whole file', () => {
    const dir = scratchDir();
    fs.writeFileSync(path.join(dir, DAY), line(THREAT_ROW));
    getDatabase().prepare('INSERT OR IGNORE INTO threat_graph_state (id) VALUES (1)').run();
    setCursor(`${DAY}:${FILE_CONSUMED_LINE}`);
    expect(projectRealtimeLedger({ dir })).toEqual({
      processed: 0, cursor: `${DAY}:${FILE_CONSUMED_LINE}`, eventNodes: 0, errors: [],
    });
  });
});
