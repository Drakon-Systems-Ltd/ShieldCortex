/**
 * #579 Slice 1A follow-up — direct coverage of the typed plain-file reader's
 * error-code sanitisation, and the parser's non-string guard.
 *
 * readPlainRealtimeFile reports a stat/read failure as
 * `{ kind: 'unavailable', stage, code }`, where `code` is the thrown error's
 * `code` only when it is a string of 1-32 uppercase letters, digits or
 * underscores, and `OTHER` otherwise. The native message and path are never
 * carried into the outcome or the ledger's hold diagnostic.
 *
 * Failures are synthetic errors thrown through the existing per-call
 * filesystem seam (the reader's `fsOps` argument and the ledger's `fs`
 * seam); nothing here touches a live audit directory or changes production
 * behaviour.
 */

import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { closeDatabase, getDatabase, initDatabase } from '../database/init.js';
import { projectRealtimeLedgerWithSeams } from '../threat-graph/realtime-ledger.js';
import {
  nodeRealtimePlaneFs,
  parseRealtimeCursor,
  readPlainRealtimeFile,
  type RealtimePlaneFs,
} from '../threat-graph/realtime-plane.js';

const D = 'realtime-2026-08-10.jsonl';
const D_PREV = 'realtime-2026-08-09.jsonl';

/** Appears in every synthetic message and path; must never be reported. */
const SENTINEL = 'sc579-raw-sentinel';
const RAW_MESSAGE = `EACCES: permission denied, open '/home/${SENTINEL}/.shieldcortex/audit/${D}'`;

const THREAT_ROW = {
  type: 'threat', hook: 'llm_input', sessionId: 'sess-abc', model: 'claude-x',
  reason: 'instruction_injection: override attempt', chars: 512,
  contentSha256: 'deadbeefdeadbeef', ts: '2026-08-11T09:00:00.000Z',
};

type Stage = 'stat' | 'read';

/** Code shapes that must collapse to OTHER. `undefined` = no `code` property. */
const OTHER_CODES: Array<[string, unknown]> = [
  ['missing', undefined],
  ['number', 13],
  ['object', { errno: -13 }],
  ['null', null],
  ['empty string', ''],
  ['overlong (33 chars)', `E${'A'.repeat(32)}`],
  ['lowercase', 'eacces'],
  ['free text with path', `${SENTINEL} /home/${SENTINEL}/${D}`],
  ['message-shaped', RAW_MESSAGE],
  ['trailing space', 'EACCES '],
  ['hyphenated', 'ERR-ACCESS'],
];

function syntheticError(code: unknown): Error {
  const e = new Error(RAW_MESSAGE);
  if (code !== undefined) Object.assign(e, { code });
  return e;
}

/** Synthetic seam: no real filesystem; fails at one stage with one error. */
function failingFs(stage: Stage, thrown: unknown): RealtimePlaneFs {
  return {
    readdir: () => { throw new Error('readdir is not used by the reader'); },
    stat: () => {
      if (stage === 'stat') throw thrown;
      return { size: 10 };
    },
    readFile: () => {
      if (stage === 'read') throw thrown;
      return 'unreachable';
    },
  };
}

function expectNoRaw(reported: unknown, dir: string): void {
  const text = JSON.stringify(reported);
  expect(text).not.toContain(SENTINEL);
  expect(text).not.toContain('permission denied');
  expect(text).not.toContain(dir);
}

describe('readPlainRealtimeFile error-code sanitisation (direct)', () => {
  const dir = `/tmp/${SENTINEL}-dir`;

  for (const stage of ['stat', 'read'] as Stage[]) {
    it.each(OTHER_CODES)(`${stage} failure with a %s code reports ${stage} OTHER`, (_label, code) => {
      const out = readPlainRealtimeFile(dir, D, 1024, failingFs(stage, syntheticError(code)));
      expect(out).toEqual({ kind: 'unavailable', stage, code: 'OTHER' });
      expectNoRaw(out, dir);
    });

    it(`${stage} failure with a non-Error throw reports ${stage} OTHER`, () => {
      for (const thrown of [RAW_MESSAGE, null, undefined, 42]) {
        const out = readPlainRealtimeFile(dir, D, 1024, failingFs(stage, thrown));
        expect(out).toEqual({ kind: 'unavailable', stage, code: 'OTHER' });
        expectNoRaw(out, dir);
      }
    });

    it(`${stage} failure keeps a bounded code exactly, still without the raw message`, () => {
      for (const code of ['EACCES', 'ERR_FS_EISDIR', 'E2BIG', 'A'.repeat(32)]) {
        const out = readPlainRealtimeFile(dir, D, 1024, failingFs(stage, syntheticError(code)));
        expect(out).toEqual({ kind: 'unavailable', stage, code });
        expect(JSON.stringify(out)).not.toContain(SENTINEL);
      }
    });
  }

  it('a stat failure never reaches readFile', () => {
    let reads = 0;
    const ops: RealtimePlaneFs = {
      ...failingFs('stat', syntheticError('free text')),
      readFile: () => { reads++; return ''; },
    };
    expect(readPlainRealtimeFile(dir, D, 1024, ops)).toEqual({ kind: 'unavailable', stage: 'stat', code: 'OTHER' });
    expect(reads).toBe(0);
  });
});

describe('ledger hold diagnostic carries only the sanitised code', () => {
  const scratch: string[] = [];

  beforeEach(() => {
    initDatabase(':memory:');
  });

  afterEach(() => {
    closeDatabase();
    for (const d of scratch.splice(0)) fs.rmSync(d, { recursive: true, force: true });
  });

  function scratchDir(): string {
    const d = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-579-reader-')));
    scratch.push(d);
    return d;
  }

  function storedCursor(): string {
    return (getDatabase().prepare('SELECT last_rt_cursor FROM threat_graph_state WHERE id = 1')
      .get() as { last_rt_cursor: string }).last_rt_cursor;
  }

  /** Real filesystem, except stat/read of D throws the given error. */
  function failAtD(stage: Stage, thrown: unknown): RealtimePlaneFs {
    const hit = (op: Stage, p: string) => {
      if (op === stage && path.basename(p) === D) throw thrown;
    };
    return {
      readdir: (d) => nodeRealtimePlaneFs.readdir(d),
      stat: (p) => { hit('stat', p); return nodeRealtimePlaneFs.stat(p); },
      readFile: (p) => { hit('read', p); return nodeRealtimePlaneFs.readFile(p); },
    };
  }

  for (const stage of ['stat', 'read'] as Stage[]) {
    it.each(OTHER_CODES)(`${stage} failure at D with a %s code holds with "${stage} OTHER"`, (_label, code) => {
      const dir = scratchDir();
      fs.writeFileSync(path.join(dir, D_PREV), JSON.stringify(THREAT_ROW) + '\n');
      fs.writeFileSync(path.join(dir, D), JSON.stringify(THREAT_ROW) + '\n');

      const result = projectRealtimeLedgerWithSeams({ dir }, { fs: failAtD(stage, syntheticError(code)) });
      expect(result.processed).toBe(1);
      expect(result.errors).toEqual([`${D}: unavailable (${stage} OTHER); realtime projection held at this file`]);
      expectNoRaw(result.errors, dir);
      expect(storedCursor()).toBe(`${D_PREV}:1`);
    });
  }
});

describe('parseRealtimeCursor non-string input', () => {
  it.each([
    ['Buffer (SQLite BLOB)', Buffer.from('realtime-2026-08-10.jsonl:1')],
    ['number', 1],
    ['null', null],
    ['undefined', undefined],
    ['object', { toString: () => 'realtime-2026-08-10.jsonl:1' }],
  ] as Array<[string, unknown]>)('classifies a %s as malformed', (_label, raw) => {
    expect(parseRealtimeCursor(raw as unknown as string)).toEqual({ kind: 'malformed' });
  });
});
