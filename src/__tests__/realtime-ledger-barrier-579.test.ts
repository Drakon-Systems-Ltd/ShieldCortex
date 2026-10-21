/**
 * #579 Slice 1A — listed-pending-file barrier, plus characterization of the
 * gaps 1A deliberately does NOT close.
 *
 * A listed realtime file whose stat or read fails used to be skipped
 * silently, and the cursor then advanced past it. It now holds projection at
 * that file: lines and oversize floors from EARLIER files may commit, but
 * nothing of the held file or any later file does, and later files are not
 * even stat'd. A start cursor already inside the held file stays exactly
 * unchanged with no apply transaction. The barrier is stateless: it is
 * re-evaluated on every run, and repair resumes projection.
 *
 * T4/T4b document current behaviour that 1A leaves unchanged: files absent
 * before listing, days before the cursor and rebuild-with-absent-day are
 * NOT detected or recovered.
 *
 * Operation observers (recording fs seam, transaction() spy, SQLite
 * total_changes()) back every absence claim alongside row equality.
 */

import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { closeDatabase, getDatabase, initDatabase } from '../database/init.js';
import { rebuildThreatGraph, runProjectorWithLease } from '../threat-graph/projector.js';
import {
  projectRealtimeLedger,
  projectRealtimeLedgerWithSeams,
} from '../threat-graph/realtime-ledger.js';
import { FILE_CONSUMED_LINE, nodeRealtimePlaneFs, type RealtimePlaneFs } from '../threat-graph/realtime-plane.js';

const T0 = Date.parse('2026-08-11T12:00:00.000Z');
const D_PREV = 'realtime-2026-08-09.jsonl';
const D = 'realtime-2026-08-10.jsonl';
const D_NEXT = 'realtime-2026-08-11.jsonl';

const THREAT_ROW = {
  type: 'threat', hook: 'llm_input', sessionId: 'sess-abc', model: 'claude-x',
  reason: 'instruction_injection: override attempt', chars: 512,
  contentSha256: 'deadbeefdeadbeef', ts: '2026-08-11T09:00:00.000Z',
};

const HELD = /realtime projection held at this file/;
const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;

const scratch: string[] = [];
const chmodRestore: string[] = [];

function scratchDir(): string {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-579-barrier-')));
  scratch.push(dir);
  return dir;
}

function rows(n: number, tag: string): string {
  let out = '';
  for (let i = 0; i < n; i++) out += JSON.stringify({ ...THREAT_ROW, sessionId: `${tag}-${i}` }) + '\n';
  return out;
}

type Op = 'readdir' | 'stat' | 'read';

function injectedError(code: string): Error {
  return Object.assign(new Error(`injected ${code}`), { code });
}

/** Recording fs seam over the real filesystem, with optional injected failures. */
function recordingFs(fail?: (op: Op, p: string) => string | undefined): { ops: RealtimePlaneFs; calls: string[] } {
  const calls: string[] = [];
  const check = (op: Op, p: string) => {
    calls.push(`${op} ${path.basename(p)}`);
    const code = fail?.(op, p);
    if (code) throw injectedError(code);
  };
  const ops: RealtimePlaneFs = {
    readdir: (d) => { check('readdir', d); return nodeRealtimePlaneFs.readdir(d); },
    stat: (p) => { check('stat', p); return nodeRealtimePlaneFs.stat(p); },
    readFile: (p) => { check('read', p); return nodeRealtimePlaneFs.readFile(p); },
  };
  return { ops, calls };
}

function touched(calls: string[], name: string): string[] {
  return calls.filter(c => c.endsWith(` ${name}`));
}

function storedCursor(): string {
  return (getDatabase().prepare('SELECT last_rt_cursor FROM threat_graph_state WHERE id = 1')
    .get() as { last_rt_cursor: string }).last_rt_cursor;
}

function setCursor(cursor: string): void {
  getDatabase().prepare('INSERT OR IGNORE INTO threat_graph_state (id) VALUES (1)').run();
  getDatabase().prepare('UPDATE threat_graph_state SET last_rt_cursor = ? WHERE id = 1').run(cursor);
}

function lastError(): string | null {
  return (getDatabase().prepare('SELECT last_error FROM threat_graph_state WHERE id = 1')
    .get() as { last_error: string | null }).last_error;
}

function rtNodes(file: string): number {
  return (getDatabase().prepare("SELECT COUNT(*) AS c FROM threat_nodes WHERE kind = 'event' AND key LIKE ?")
    .get(`rt:${file}:%`) as { c: number }).c;
}

function graphSnapshot(): unknown {
  const db = getDatabase();
  return {
    nodes: db.prepare('SELECT id, kind, key, attrs, first_seen, last_seen FROM threat_nodes ORDER BY id').all(),
    edges: db.prepare('SELECT * FROM threat_edges ORDER BY id').all(),
    cursor: storedCursor(),
  };
}

function totalChanges(): number {
  return (getDatabase().prepare('SELECT total_changes() AS c').get() as { c: number }).c;
}

function noHoldError(errors: string[]): void {
  for (const e of errors) expect(e).not.toMatch(HELD);
}

beforeEach(() => {
  initDatabase(':memory:');
});

afterEach(() => {
  jest.restoreAllMocks();
  closeDatabase();
  for (const p of chmodRestore.splice(0)) {
    try { fs.chmodSync(p, 0o644); } catch { /* already removed */ }
  }
  for (const dir of scratch.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

describe('T4 characterization: issue fixture 1 (unchanged by 1A)', () => {
  it('a day moved away before listing, then restored, is neither held nor replayed; rebuild drops it when absent', () => {
    const dir = scratchDir();
    const aside = scratchDir();
    fs.writeFileSync(path.join(dir, D), rows(1, 'd'));
    fs.writeFileSync(path.join(dir, D_NEXT), rows(1, 'n'));
    expect(projectRealtimeLedger({ dir }).processed).toBe(2);
    expect(storedCursor()).toBe(`${D_NEXT}:1`);

    fs.renameSync(path.join(dir, D), path.join(aside, D));
    const moved = projectRealtimeLedger({ dir });
    expect(moved).toEqual({ processed: 0, cursor: `${D_NEXT}:1`, eventNodes: 0, errors: [] });

    fs.renameSync(path.join(aside, D), path.join(dir, D));
    const restored = projectRealtimeLedger({ dir });
    expect(restored).toEqual({ processed: 0, cursor: `${D_NEXT}:1`, eventNodes: 0, errors: [] });
    expect(rtNodes(D)).toBe(1);

    const present = rebuildThreatGraph({ realtimeDir: dir });
    noHoldError(present.errors);
    expect(rtNodes(D)).toBe(1);

    fs.renameSync(path.join(dir, D), path.join(aside, D));
    const absent = rebuildThreatGraph({ realtimeDir: dir });
    noHoldError(absent.errors);
    expect(rtNodes(D)).toBe(0); // the R2 T4 hazard: rebuild replays only files present
    expect(rtNodes(D_NEXT)).toBe(1);
  });
});

describe('T4b characterization: a day absent before listing is passed undetected', () => {
  it('D absent while the cursor ends D-1; D+1 consumed; a later restore of D is skipped', () => {
    const dir = scratchDir();
    fs.writeFileSync(path.join(dir, D_PREV), rows(1, 'p'));
    expect(projectRealtimeLedger({ dir }).processed).toBe(1);
    expect(storedCursor()).toBe(`${D_PREV}:1`);

    fs.writeFileSync(path.join(dir, D_NEXT), rows(1, 'n'));
    const passed = projectRealtimeLedger({ dir });
    expect(passed.processed).toBe(1);
    noHoldError(passed.errors);
    expect(storedCursor()).toBe(`${D_NEXT}:1`);

    fs.writeFileSync(path.join(dir, D), rows(1, 'd'));
    const late = projectRealtimeLedger({ dir });
    expect(late).toEqual({ processed: 0, cursor: `${D_NEXT}:1`, eventNodes: 0, errors: [] });
    expect(rtNodes(D)).toBe(0);
  });
});

describe('T6a later-file hold: D-1 readable, D unavailable, D+1 readable', () => {
  interface Variant {
    label: string;
    skip?: boolean;
    /** Make D unavailable; returns an fs-failure injector if the variant needs one. */
    breakD(dir: string): ((op: Op, p: string) => string | undefined) | undefined;
    repairD(dir: string): void;
    expectStage: RegExp;
  }

  const variants: Variant[] = [
    {
      label: '(a) directory named like a day file (read EISDIR)',
      breakD: (dir) => { fs.mkdirSync(path.join(dir, D)); return undefined; },
      repairD: (dir) => { fs.rmdirSync(path.join(dir, D)); fs.writeFileSync(path.join(dir, D), rows(2, 'd')); },
      expectStage: /unavailable \(read [A-Z0-9_]+\)/,
    },
    {
      label: '(b) chmod 000 (read EACCES)',
      skip: isRoot,
      breakD: (dir) => {
        const p = path.join(dir, D);
        fs.writeFileSync(p, rows(2, 'd'));
        fs.chmodSync(p, 0o000);
        chmodRestore.push(p);
        return undefined;
      },
      repairD: (dir) => { fs.chmodSync(path.join(dir, D), 0o644); },
      expectStage: /unavailable \(read EACCES\)/,
    },
    {
      label: '(c) injected ENOENT at stat',
      breakD: (dir) => {
        fs.writeFileSync(path.join(dir, D), rows(2, 'd'));
        return (op, p) => (op === 'stat' && path.basename(p) === D ? 'ENOENT' : undefined);
      },
      repairD: () => { /* drop the injector */ },
      expectStage: /unavailable \(stat ENOENT\)/,
    },
  ];

  for (const v of variants) {
    (v.skip ? it.skip : it)(v.label, () => {
      const dir = scratchDir();
      fs.writeFileSync(path.join(dir, D_PREV), rows(2, 'p'));
      fs.writeFileSync(path.join(dir, D_NEXT), rows(1, 'n'));
      const fail = v.breakD(dir);

      const rec1 = recordingFs(fail);
      const first = projectRealtimeLedgerWithSeams({ dir }, { fs: rec1.ops });
      expect(first.processed).toBe(2);
      expect(first.cursor).toBe(`${D_PREV}:2`);
      expect(storedCursor()).toBe(`${D_PREV}:2`);
      expect(first.errors).toHaveLength(1);
      expect(first.errors[0]).toMatch(new RegExp(`^${D.replace(/\./g, '\\.')}: `));
      expect(first.errors[0]).toMatch(v.expectStage);
      expect(first.errors[0]).toMatch(HELD);
      expect(touched(rec1.calls, D_NEXT)).toEqual([]);
      expect(rtNodes(D)).toBe(0);
      expect(rtNodes(D_NEXT)).toBe(0);

      // Repeats on the next run: cursor unchanged, no apply transaction.
      const before = graphSnapshot();
      const db = getDatabase();
      const txSpy = jest.spyOn(db, 'transaction');
      const rec2 = recordingFs(fail);
      const again = projectRealtimeLedgerWithSeams({ dir }, { fs: rec2.ops });
      expect(again.processed).toBe(0);
      expect(again.cursor).toBe(`${D_PREV}:2`);
      expect(again.errors).toHaveLength(1);
      expect(again.errors[0]).toMatch(HELD);
      expect(txSpy).not.toHaveBeenCalled();
      expect(touched(rec2.calls, D_NEXT)).toEqual([]);
      expect(graphSnapshot()).toEqual(before);
      txSpy.mockRestore();

      // After repair, D then D+1 project.
      v.repairD(dir);
      const repaired = projectRealtimeLedger({ dir });
      expect(repaired.errors).toEqual([]);
      expect(repaired.processed).toBe(3);
      expect(storedCursor()).toBe(`${D_NEXT}:1`);
      expect(rtNodes(D)).toBe(2);
      expect(rtNodes(D_NEXT)).toBe(1);
    });
  }

  it('the lease runner persists the hold into last_error on every run', async () => {
    const dir = scratchDir();
    await runProjectorWithLease({ now: T0 }); // establish the projector version
    fs.writeFileSync(path.join(dir, D_PREV), rows(1, 'p'));
    fs.mkdirSync(path.join(dir, D));
    fs.writeFileSync(path.join(dir, D_NEXT), rows(1, 'n'));

    const first = await runProjectorWithLease({ now: T0 + 1000, realtimeDir: dir });
    expect(first.realtime?.processed).toBe(1);
    expect(lastError()).toMatch(HELD);
    expect(lastError()).toContain(D);
    expect(storedCursor()).toBe(`${D_PREV}:1`);

    const second = await runProjectorWithLease({ now: T0 + 2000, realtimeDir: dir });
    expect(second.realtime?.processed).toBe(0);
    expect(lastError()).toMatch(HELD);
    expect(storedCursor()).toBe(`${D_PREV}:1`);
    expect(rtNodes(D_NEXT)).toBe(0);
  });
});

describe('T6b current-file hold: start cursor already inside D', () => {
  it.each([
    ['stat', 'ENOENT'],
    ['read', 'EIO'],
  ] as Array<[Op, string]>)('D fails at %s: cursor exactly D:k, no transaction, D+1 untouched', (stage, code) => {
    const dir = scratchDir();
    fs.writeFileSync(path.join(dir, D), rows(2, 'd'));
    expect(projectRealtimeLedger({ dir }).processed).toBe(2);
    fs.appendFileSync(path.join(dir, D), rows(1, 'd-late'));
    fs.writeFileSync(path.join(dir, D_NEXT), rows(1, 'n'));
    expect(storedCursor()).toBe(`${D}:2`);

    const fail = (op: Op, p: string) => (op === stage && path.basename(p) === D ? code : undefined);
    const before = graphSnapshot();
    const db = getDatabase();
    const txSpy = jest.spyOn(db, 'transaction');
    const changesBefore = totalChanges();

    for (let run = 0; run < 2; run++) {
      const rec = recordingFs(fail);
      const held = projectRealtimeLedgerWithSeams({ dir }, { fs: rec.ops });
      expect(held).toEqual({
        processed: 0,
        cursor: `${D}:2`,
        eventNodes: 0,
        errors: [`${D}: unavailable (${stage} ${code}); realtime projection held at this file`],
      });
      expect(touched(rec.calls, D_NEXT)).toEqual([]);
    }
    expect(txSpy).not.toHaveBeenCalled();
    expect(totalChanges()).toBe(changesBefore);
    expect(graphSnapshot()).toEqual(before);
    txSpy.mockRestore();

    // Repair: resumes at line k+1 of D, then D+1; earlier rows not replayed.
    const resumed = projectRealtimeLedger({ dir });
    expect(resumed.processed).toBe(2);
    expect(storedCursor()).toBe(`${D_NEXT}:1`);
    expect(rtNodes(D)).toBe(3);
    const counts = getDatabase().prepare(`
      SELECT e.count FROM threat_edges e JOIN threat_nodes n ON n.id = e.src
      WHERE n.kind = 'event' AND n.key = ?
    `).all(`rt:${D}:1`) as Array<{ count: number }>;
    expect(counts.map(c => c.count)).toEqual([1, 1]);
  });

  it('native stat (dangling symlink) and read (directory) holds persist through the lease runner and recover', async () => {
    const dir = scratchDir();
    await runProjectorWithLease({ now: T0 }); // establish the projector version
    const dPath = path.join(dir, D);
    fs.writeFileSync(dPath, rows(2, 'd'));
    await runProjectorWithLease({ now: T0 + 1000, realtimeDir: dir });
    expect(storedCursor()).toBe(`${D}:2`);
    fs.writeFileSync(path.join(dir, D_NEXT), rows(1, 'n'));
    const kept = fs.readFileSync(dPath, 'utf-8');

    // Stat failure: the listed name is a dangling symlink (stat follows it).
    fs.rmSync(dPath);
    fs.symlinkSync(path.join(dir, 'missing-target'), dPath);
    const statHeld = await runProjectorWithLease({ now: T0 + 2000, realtimeDir: dir });
    expect(statHeld.realtime?.errors).toEqual([`${D}: unavailable (stat ENOENT); realtime projection held at this file`]);
    expect(lastError()).toMatch(HELD);
    expect(storedCursor()).toBe(`${D}:2`);

    // Read failure: the listed name is a directory.
    fs.rmSync(dPath);
    fs.mkdirSync(dPath);
    const readHeld = await runProjectorWithLease({ now: T0 + 3000, realtimeDir: dir });
    expect(readHeld.realtime?.processed).toBe(0);
    expect(readHeld.realtime?.errors[0]).toMatch(/unavailable \(read [A-Z0-9_]+\)/);
    expect(lastError()).toMatch(HELD);
    expect(storedCursor()).toBe(`${D}:2`);
    expect(rtNodes(D_NEXT)).toBe(0);

    // Repair with one appended line: resumes at line 3, then D+1.
    fs.rmdirSync(dPath);
    fs.writeFileSync(dPath, kept + rows(1, 'd-late'));
    const recovered = await runProjectorWithLease({ now: T0 + 4000, realtimeDir: dir });
    expect(recovered.realtime?.processed).toBe(2);
    expect(storedCursor()).toBe(`${D_NEXT}:1`);
    expect(lastError()).toBeNull();
    expect(rtNodes(D)).toBe(3);
  });
});

describe('T6c earlier oversize floor, then a held file', () => {
  it('the floor for E commits; nothing of D or D+1 is read or committed', () => {
    const dir = scratchDir();
    fs.writeFileSync(path.join(dir, D_PREV), rows(4, 'big'));
    fs.writeFileSync(path.join(dir, D), rows(1, 'd'));
    fs.writeFileSync(path.join(dir, D_NEXT), rows(1, 'n'));
    const maxFileBytes = Buffer.byteLength(rows(1, 'd')) + 10; // E exceeds, D would fit

    const rec = recordingFs((op, p) => (op === 'stat' && path.basename(p) === D ? 'ENOENT' : undefined));
    const result = projectRealtimeLedgerWithSeams({ dir, maxFileBytes }, { fs: rec.ops });
    expect(result.processed).toBe(0);
    expect(result.cursor).toBe(`${D_PREV}:${FILE_CONSUMED_LINE}`);
    expect(storedCursor()).toBe(`${D_PREV}:${FILE_CONSUMED_LINE}`);
    expect(result.errors).toHaveLength(2);
    expect(result.errors[0]).toMatch(/exceeds the \d+-byte file cap — skipped/);
    expect(result.errors[1]).toBe(`${D}: unavailable (stat ENOENT); realtime projection held at this file`);
    expect(touched(rec.calls, D)).toEqual([`stat ${D}`]);
    expect(touched(rec.calls, D_NEXT)).toEqual([]);
    expect(rtNodes(D)).toBe(0);
    expect(rtNodes(D_NEXT)).toBe(0);
  });
});

describe('T6d stale claim-and-advance (raw cursor CAS)', () => {
  const cases: Array<[string, string]> = [
    ['another holder advanced the cursor', `${D_NEXT}:1`],
    ['clearGraph reset the cursor to empty', ''],
  ];

  it.each(cases)('%s: no node/edge/cursor write after the competing change', (_label, competing) => {
    const dir = scratchDir();
    fs.writeFileSync(path.join(dir, D_PREV), rows(1, 'p'));
    expect(projectRealtimeLedger({ dir }).processed).toBe(1);
    fs.writeFileSync(path.join(dir, D), rows(2, 'd'));

    let afterCompeting: { snapshot: unknown; changes: number } | undefined;
    const db = getDatabase();
    const txSpy = jest.spyOn(db, 'transaction');
    const result = projectRealtimeLedgerWithSeams({ dir }, {
      beforeApply: () => {
        setCursor(competing);
        afterCompeting = { snapshot: graphSnapshot(), changes: totalChanges() };
      },
    });

    expect(afterCompeting).toBeDefined();
    expect(txSpy).toHaveBeenCalledTimes(1); // beginning the stale transaction is allowed
    expect(result.processed).toBe(0);
    expect(totalChanges()).toBe(afterCompeting!.changes);
    expect(graphSnapshot()).toEqual(afterCompeting!.snapshot);
    expect(storedCursor()).toBe(competing);
    expect(rtNodes(D)).toBe(0);
  });

  it('a hold-run with earlier lines commits nothing when the cursor moved meanwhile', () => {
    const dir = scratchDir();
    fs.writeFileSync(path.join(dir, D_PREV), rows(2, 'p'));
    fs.mkdirSync(path.join(dir, D));
    let changes = -1;
    const result = projectRealtimeLedgerWithSeams({ dir }, {
      beforeApply: () => { setCursor(`${D_PREV}:1`); changes = totalChanges(); },
    });
    expect(result.processed).toBe(0);
    expect(result.errors[0]).toMatch(HELD);
    expect(totalChanges()).toBe(changes);
    expect(storedCursor()).toBe(`${D_PREV}:1`);
    expect(rtNodes(D_PREV)).toBe(0);

    // Next run re-collects from the moved cursor and holds again at D.
    const next = projectRealtimeLedger({ dir });
    expect(next.processed).toBe(1);
    expect(storedCursor()).toBe(`${D_PREV}:2`);
    expect(next.errors[0]).toMatch(HELD);
  });
});

describe('T7 rebuildThreatGraph with a held file', () => {
  it('returns without throwing, terminates, leaves the cursor below D and records the hold', () => {
    const dir = scratchDir();
    fs.writeFileSync(path.join(dir, D_PREV), rows(3, 'p'));
    fs.mkdirSync(path.join(dir, D));
    fs.writeFileSync(path.join(dir, D_NEXT), rows(1, 'n'));

    const result = rebuildThreatGraph({ realtimeDir: dir });
    expect(result.errors.some(e => HELD.test(e))).toBe(true);
    expect(storedCursor()).toBe(`${D_PREV}:3`);
    expect(storedCursor().slice(0, storedCursor().lastIndexOf(':')) < D).toBe(true);
    expect(lastError()).toMatch(HELD);
    expect(rtNodes(D_PREV)).toBe(3);
    expect(rtNodes(D_NEXT)).toBe(0);
  });
});
