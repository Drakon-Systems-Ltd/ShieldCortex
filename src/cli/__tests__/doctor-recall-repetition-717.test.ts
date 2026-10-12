/**
 * #717 — doctor WARN when the newest interactive prompt-recall runs all
 * returned the same non-empty top-k candidate set (the envelope-dominated
 * query signature from the issue: four unrelated prompts, same six rows).
 *
 * Every case drives the real reader (recall-repetition.ts) and the real doctor
 * row (checkRecallRepetition) against a fixture home under os.tmpdir(); none
 * reads or falls back to the live HOME. Fixtures follow the payload
 * scripts/lib/recall-log.mjs writes, and one case writes them with that real
 * writer.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import {
  checkRecallRepetition,
  RECALL_REPETITION_LABEL,
  recallRepetitionResult,
} from '../doctor.js';
import { formatDoctorReport } from '../doctor-report.js';
import {
  evaluateRecallRepetition,
  RECALL_LOG_MAX_ENTRY_BYTES,
  RECALL_LOG_MAX_TOTAL_BYTES,
  recallLogDirFor,
  REPEAT_MIN_SET_SIZE,
  REPEAT_SAMPLE_RUNS,
  type RecallRepetitionFs,
} from '../recall-repetition.js';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

const SENTINEL_PROMPT = 'SENTINEL-PROMPT-c0ffee owner private question';
const SENTINEL_TITLE = 'SENTINEL-TITLE-beef private memory title';
const SENTINEL_HASH = 'feedfacecafe0717';
const SENTINEL_IDS = [987654321, 987654322, 987654323, 987654324, 987654325];

let root: string;
let home: string;
let logDir: string;

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-recall-rep-717-'));
  // The fixture home's own name is a sentinel too: no path may reach output.
  home = path.join(root, 'SENTINEL-HOME-dir');
  logDir = recallLogDirFor(home);
  fs.mkdirSync(logDir, { recursive: true });
});

afterEach(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

interface RunSpec {
  lane?: unknown;
  ids?: number[];
  /** Candidates below the hook's top-N cut; never part of the compared set. */
  outside?: number[];
  promptHash?: string | null;
  prompt?: string;
  pad?: number;
}

function entry(spec: RunSpec): Record<string, unknown> {
  const ids = spec.ids ?? SENTINEL_IDS;
  const candidates = [
    ...ids.map((id, i) => ({
      id,
      title: `${SENTINEL_TITLE} ${i}`,
      category: 'context',
      source: 'fts',
      ftsRank: -1 - i,
      injected: i === 0,
      dropReason: i === 0 ? null : 'dedupe',
    })),
    ...(spec.outside ?? []).map((id) => ({ id, title: SENTINEL_TITLE, injected: false, dropReason: 'outside_top_n' })),
  ];
  const e: Record<string, unknown> = {
    ranAt: '2026-10-10T09:00:00.000Z',
    prompt: spec.prompt ?? SENTINEL_PROMPT,
    promptHash: spec.promptHash === undefined ? SENTINEL_HASH : spec.promptHash,
    sessionId: 'sess-SENTINEL',
    project: 'SENTINEL-project',
    minSalience: 0.2,
    candidates,
    injectedCount: 1,
    finalContextChars: 100,
    vectorPlane: 'disabled:default-off',
    laneSignal: 'default',
  };
  if (spec.lane !== undefined) e.lane = spec.lane;
  if (spec.pad) e.padding = 'x'.repeat(spec.pad);
  return e;
}

function writeSlot(slot: number, body: unknown): void {
  fs.writeFileSync(path.join(logDir, `${slot}.json`), typeof body === 'string' ? body : JSON.stringify(body, null, 2));
}

/** Interactive runs with distinct prompt hashes, newest first from slot 0. */
function writeInteractive(sets: number[][], startSlot = 0): void {
  sets.forEach((ids, i) => writeSlot(startSlot + i, entry({ lane: 'interactive', ids, promptHash: `${SENTINEL_HASH}${i}` })));
}

/** Shallow snapshot of everything under root: names, sizes, mtimes, bytes. */
function snapshot(): string {
  const out: string[] = [];
  const walk = (dir: string): void => {
    for (const name of fs.readdirSync(dir).sort()) {
      const p = path.join(dir, name);
      const st = fs.lstatSync(p);
      out.push(`${path.relative(root, p)}|${st.mode}|${st.size}|${st.mtimeMs}`);
      if (st.isDirectory()) walk(p);
      else if (st.isFile()) out.push(fs.readFileSync(p, 'base64'));
    }
  };
  walk(root);
  return out.join('\n');
}

const repeat = (n: number, ids: number[]) => Array.from({ length: n }, () => ids);

describe('#717 recall repetition — verdicts', () => {
  it('WARNs when the last interactive runs return the same non-empty top-k set', async () => {
    writeInteractive(repeat(REPEAT_SAMPLE_RUNS, SENTINEL_IDS));

    expect(evaluateRecallRepetition({ homeDir: home })).toEqual({
      kind: 'repeated', runs: REPEAT_SAMPLE_RUNS, setSize: SENTINEL_IDS.length, distinctPromptHashes: REPEAT_SAMPLE_RUNS,
    });

    const row = await checkRecallRepetition({ homeDir: home });
    expect(row.label).toBe(RECALL_REPETITION_LABEL);
    expect(row.status).toBe('warn');
    expect(row.message).toContain(`same ${SENTINEL_IDS.length}-candidate top-k set`);
    expect(row.message).toContain(`${REPEAT_SAMPLE_RUNS} distinct prompt hashes`);
    expect(row.message).toContain('repetition evidence, not a proven root cause');
    expect(row.message).toContain('asking about the same topic repeatedly');
  });

  it('the WARN prescribes nothing: no command, vector, Guard, scanning or repair', async () => {
    writeInteractive(repeat(REPEAT_SAMPLE_RUNS, SENTINEL_IDS));
    const row = await checkRecallRepetition({ homeDir: home });
    expect(row.status).toBe('warn');
    expect(row.fix).toBeUndefined();
    expect(row.message).not.toMatch(/vector|guard|scan|repair|shieldcortex|setup|`|\$ /i);
  });

  it('candidate order, duplicates and below-cut rows do not change equality', () => {
    const [a, b, c, d, e] = SENTINEL_IDS;
    writeSlot(0, entry({ lane: 'interactive', ids: [a, b, c, d, e], promptHash: 'h0' }));
    writeSlot(1, entry({ lane: 'interactive', ids: [e, d, c, b, a], promptHash: 'h1', outside: [11, 12] }));
    writeSlot(2, entry({ lane: 'interactive', ids: [c, a, e, b, d, a], promptHash: 'h2', outside: [13] }));
    writeSlot(3, entry({ lane: 'interactive', ids: [b, e, a, d, c], promptHash: 'h3' }));
    expect(evaluateRecallRepetition({ homeDir: home })).toMatchObject({ kind: 'repeated', setSize: 5 });
  });

  it('a changed set in any sampled run is not a repeated-set warning', async () => {
    const changed = [...SENTINEL_IDS.slice(0, 4), 42];
    writeInteractive([SENTINEL_IDS, SENTINEL_IDS, changed, SENTINEL_IDS]);
    expect(evaluateRecallRepetition({ homeDir: home })).toEqual({ kind: 'varied', runs: REPEAT_SAMPLE_RUNS });
    const row = await checkRecallRepetition({ homeDir: home });
    expect(row.status).toBe('pass');
  });

  it('empty candidate sets never warn', async () => {
    writeInteractive(repeat(REPEAT_SAMPLE_RUNS, []));
    expect(evaluateRecallRepetition({ homeDir: home }).kind).toBe('varied');
    expect((await checkRecallRepetition({ homeDir: home })).status).not.toBe('warn');
  });

  it('only rows below the top-N cut count as outside the set — all-outside is empty', () => {
    for (let i = 0; i < REPEAT_SAMPLE_RUNS; i++) {
      writeSlot(i, entry({ lane: 'interactive', ids: [], outside: SENTINEL_IDS, promptHash: `h${i}` }));
    }
    expect(evaluateRecallRepetition({ homeDir: home }).kind).toBe('varied');
  });

  it('fewer interactive runs than the sample is INFO, never PASS', async () => {
    writeInteractive(repeat(REPEAT_SAMPLE_RUNS - 1, SENTINEL_IDS));
    expect(evaluateRecallRepetition({ homeDir: home })).toEqual({
      kind: 'insufficient', interactiveRuns: REPEAT_SAMPLE_RUNS - 1, otherLaneRuns: 0, unknownLaneRuns: 0,
    });
    expect((await checkRecallRepetition({ homeDir: home })).status).toBe('info');
  });

  it('identical cron / automation / subagent runs are not interactive evidence', async () => {
    const lanes = ['cron', 'automation', 'subagent', 'cron', 'automation', 'subagent', 'cron', 'cron', 'cron', 'cron'];
    lanes.forEach((lane, i) => writeSlot(i, entry({ lane, promptHash: `h${i}` })));
    expect(evaluateRecallRepetition({ homeDir: home })).toEqual({
      kind: 'insufficient', interactiveRuns: 0, otherLaneRuns: 10, unknownLaneRuns: 0,
    });
    const row = await checkRecallRepetition({ homeDir: home });
    expect(row.status).toBe('info');
    expect(row.message).toContain('10 cron/automation/subagent or unlabelled runs skipped');
  });

  it('runs with no lane, a null lane or an unknown lane are skipped, not counted as interactive', () => {
    const lanes: unknown[] = [undefined, null, 'Interactive', 'watchdog', 7, undefined, null, 'interactive '];
    lanes.forEach((lane, i) => writeSlot(i, entry({ lane, promptHash: `h${i}` })));
    expect(evaluateRecallRepetition({ homeDir: home })).toEqual({
      kind: 'insufficient', interactiveRuns: 0, otherLaneRuns: 0, unknownLaneRuns: lanes.length,
    });
  });

  it('interactive runs interleaved with automated ones are compared on their own', () => {
    writeSlot(0, entry({ lane: 'interactive', promptHash: 'h0' }));
    writeSlot(1, entry({ lane: 'cron', ids: [1, 2, 3], promptHash: 'c' }));
    writeSlot(2, entry({ lane: 'interactive', promptHash: 'h1' }));
    writeSlot(3, entry({ lane: null, ids: [4, 5, 6], promptHash: 'u' }));
    writeSlot(4, entry({ lane: 'interactive', promptHash: 'h2' }));
    writeSlot(5, entry({ lane: 'subagent', promptHash: 's' }));
    writeSlot(6, entry({ lane: 'interactive', promptHash: 'h3' }));
    expect(evaluateRecallRepetition({ homeDir: home })).toMatchObject({ kind: 'repeated', runs: 4, setSize: 5 });
  });

  it('the same prompt hash on every run explains the repetition: INFO, no WARN', async () => {
    for (let i = 0; i < REPEAT_SAMPLE_RUNS; i++) writeSlot(i, entry({ lane: 'interactive', promptHash: SENTINEL_HASH }));
    expect(evaluateRecallRepetition({ homeDir: home }).kind).toBe('same-prompt');
    const row = await checkRecallRepetition({ homeDir: home });
    expect(row.status).toBe('info');
    expect(row.message).toContain('same prompt repeated');
  });

  it('a run without a prompt hash does not become a "different prompts" claim', async () => {
    writeSlot(0, entry({ lane: 'interactive', promptHash: null }));
    for (let i = 1; i < REPEAT_SAMPLE_RUNS; i++) writeSlot(i, entry({ lane: 'interactive', promptHash: SENTINEL_HASH }));
    expect(evaluateRecallRepetition({ homeDir: home })).toMatchObject({ kind: 'repeated', distinctPromptHashes: null });
    const row = await checkRecallRepetition({ homeDir: home });
    expect(row.status).toBe('warn');
    expect(row.message).toContain('prompt identity not recorded for every run');
    expect(row.message).not.toMatch(/distinct prompt hashes|different prompts/);
  });

  it('a shared set smaller than the floor is INFO', async () => {
    writeInteractive(repeat(REPEAT_SAMPLE_RUNS, SENTINEL_IDS.slice(0, REPEAT_MIN_SET_SIZE - 1)));
    expect(evaluateRecallRepetition({ homeDir: home })).toMatchObject({ kind: 'below-floor', setSize: REPEAT_MIN_SET_SIZE - 1 });
    expect((await checkRecallRepetition({ homeDir: home })).status).toBe('info');
  });

  it('only the newest sample is compared — an older differing run does not hide a current repeat', () => {
    writeInteractive([...repeat(REPEAT_SAMPLE_RUNS, SENTINEL_IDS), [1, 2, 3, 4]]);
    expect(evaluateRecallRepetition({ homeDir: home }).kind).toBe('repeated');
  });
});

describe('#717 recall repetition — unavailable evidence is never healthy', () => {
  it('no recall-log directory is INFO "not checked"', async () => {
    const bare = path.join(root, 'bare-home');
    fs.mkdirSync(bare);
    expect(evaluateRecallRepetition({ homeDir: bare })).toEqual({ kind: 'absent' });
    const row = await checkRecallRepetition({ homeDir: bare });
    expect(row.status).toBe('info');
    expect(row.message).toContain('not checked');
  });

  it('an empty recall-log directory is insufficient, not healthy', async () => {
    expect(evaluateRecallRepetition({ homeDir: home }).kind).toBe('insufficient');
    expect((await checkRecallRepetition({ homeDir: home })).status).toBe('info');
  });

  it('corrupt JSON inside the sample stops the evaluation', async () => {
    writeInteractive([SENTINEL_IDS]);
    writeSlot(1, '{"lane":"interactive","candidates":[');
    writeInteractive(repeat(REPEAT_SAMPLE_RUNS, [1, 2, 3, 4]), 2);
    expect(evaluateRecallRepetition({ homeDir: home })).toEqual({
      kind: 'incomplete', problems: { corrupt: 1 }, interactiveRuns: 1,
    });
    const row = await checkRecallRepetition({ homeDir: home });
    expect(row.status).toBe('info');
    expect(row.message).toContain('not valid JSON');
  });

  it('a corrupt slot after a complete sample is never read', () => {
    writeInteractive(repeat(REPEAT_SAMPLE_RUNS, SENTINEL_IDS));
    writeSlot(REPEAT_SAMPLE_RUNS, 'not json');
    expect(evaluateRecallRepetition({ homeDir: home }).kind).toBe('repeated');
  });

  it('a malformed interactive run (non-integer id, bad dropReason, non-array) is incomplete', () => {
    const bad: Array<Record<string, unknown>> = [
      { ...entry({ lane: 'interactive' }), candidates: [{ id: '987654321', dropReason: null }] },
      { ...entry({ lane: 'interactive' }), candidates: [{ id: 1, dropReason: 3 }] },
      { ...entry({ lane: 'interactive' }), candidates: [{ dropReason: null }] },
      { ...entry({ lane: 'interactive' }), candidates: 'nope' },
      { ...entry({ lane: 'interactive' }), candidates: Array.from({ length: 65 }, (_, i) => ({ id: i, dropReason: null })) },
    ];
    for (const b of bad) {
      writeSlot(0, b);
      expect(evaluateRecallRepetition({ homeDir: home })).toEqual({
        kind: 'incomplete', problems: { malformed: 1 }, interactiveRuns: 0,
      });
    }
    writeSlot(0, '[1,2,3]');
    expect(evaluateRecallRepetition({ homeDir: home })).toMatchObject({ kind: 'incomplete', problems: { malformed: 1 } });
  });

  it('an oversized slot is refused, not parsed', () => {
    writeSlot(0, entry({ lane: 'interactive', pad: RECALL_LOG_MAX_ENTRY_BYTES }));
    expect(evaluateRecallRepetition({ homeDir: home })).toEqual({
      kind: 'incomplete', problems: { oversized: 1 }, interactiveRuns: 0,
    });
  });

  it('the total read budget is enforced and reported, not silently truncated', async () => {
    const per = RECALL_LOG_MAX_ENTRY_BYTES - 2048;
    const fit = Math.floor(RECALL_LOG_MAX_TOTAL_BYTES / RECALL_LOG_MAX_ENTRY_BYTES);
    for (let i = 0; i <= fit; i++) writeSlot(i, entry({ lane: 'cron', pad: per }));
    const v = evaluateRecallRepetition({ homeDir: home });
    expect(v).toEqual({ kind: 'incomplete', problems: { budget: 1 }, interactiveRuns: 0 });
    expect((await checkRecallRepetition({ homeDir: home })).message).toContain('over the read budget');
  });

  const posixOnly = process.platform === 'win32' ? it.skip : it;

  posixOnly('a symlinked slot is not followed', () => {
    const outside = path.join(root, 'outside.json');
    fs.writeFileSync(outside, JSON.stringify(entry({ lane: 'interactive' })));
    fs.symlinkSync(outside, path.join(logDir, '0.json'));
    expect(evaluateRecallRepetition({ homeDir: home })).toEqual({
      kind: 'incomplete', problems: { unsafe: 1 }, interactiveRuns: 0,
    });
  });

  it('a directory at a slot name is not a regular file', () => {
    fs.mkdirSync(path.join(logDir, '0.json'));
    expect(evaluateRecallRepetition({ homeDir: home })).toEqual({
      kind: 'incomplete', problems: { unsafe: 1 }, interactiveRuns: 0,
    });
  });

  posixOnly('a symlinked recall-log directory is not read', async () => {
    const elsewhere = path.join(root, 'elsewhere');
    fs.mkdirSync(elsewhere);
    const h2 = path.join(root, 'home2');
    fs.mkdirSync(path.join(h2, '.shieldcortex'), { recursive: true });
    fs.symlinkSync(elsewhere, recallLogDirFor(h2));
    expect(evaluateRecallRepetition({ homeDir: h2 })).toEqual({ kind: 'unavailable', reason: 'unsafe' });
    expect((await checkRecallRepetition({ homeDir: h2 })).status).toBe('info');
  });

  it('a recall-log path that is a file is unavailable', () => {
    const h2 = path.join(root, 'home3');
    fs.mkdirSync(path.join(h2, '.shieldcortex'), { recursive: true });
    fs.writeFileSync(recallLogDirFor(h2), 'x');
    expect(evaluateRecallRepetition({ homeDir: h2 })).toEqual({ kind: 'unavailable', reason: 'unsafe' });
  });

  it('read errors (EACCES) are unreadable, never a pass', async () => {
    writeInteractive(repeat(REPEAT_SAMPLE_RUNS, SENTINEL_IDS));
    const denying: RecallRepetitionFs = {
      lstatSync: (p) => fs.lstatSync(p),
      openSync: () => { throw Object.assign(new Error('EACCES: SENTINEL-HOME-dir'), { code: 'EACCES' }); },
      fstatSync: (fd) => fs.fstatSync(fd),
      readSync: (fd, b, o, l, pos) => fs.readSync(fd, b, o, l, pos),
      closeSync: (fd) => fs.closeSync(fd),
    };
    expect(evaluateRecallRepetition({ homeDir: home, fs: denying })).toEqual({
      kind: 'incomplete', problems: { unreadable: 1 }, interactiveRuns: 0,
    });
    const lstatDenied: RecallRepetitionFs = {
      ...denying,
      lstatSync: () => { throw Object.assign(new Error('EACCES'), { code: 'EACCES' }); },
    };
    expect(evaluateRecallRepetition({ homeDir: home, fs: lstatDenied })).toEqual({ kind: 'unavailable', reason: 'unreadable' });
    const row = await checkRecallRepetition({ homeDir: home, fs: denying });
    expect(row.status).toBe('info');
    expect(row.message).not.toContain('SENTINEL');
  });

  it('a reader that throws unexpectedly yields fixed-text INFO, not a crash or pass', async () => {
    const exploding: RecallRepetitionFs = {
      lstatSync: () => ({ isDirectory: () => true, isSymbolicLink: () => false }),
      openSync: () => 3,
      fstatSync: () => { throw new Error('boom SENTINEL-HOME-dir'); },
      readSync: () => 0,
      closeSync: () => { throw new Error('close SENTINEL-HOME-dir'); },
    };
    const row = await checkRecallRepetition({ homeDir: home, fs: exploding });
    expect(row.status).toBe('info');
    expect(row.message).not.toContain('SENTINEL');
  });

  it('every non-WARN, non-varied verdict maps to INFO', () => {
    const verdicts = [
      { kind: 'absent' },
      { kind: 'unavailable', reason: 'unsafe' },
      { kind: 'unavailable', reason: 'unreadable' },
      { kind: 'incomplete', problems: { budget: 1 }, interactiveRuns: 2 },
      { kind: 'insufficient', interactiveRuns: 1, otherLaneRuns: 0, unknownLaneRuns: 0 },
      { kind: 'below-floor', runs: 4, setSize: 1 },
      { kind: 'same-prompt', runs: 4, setSize: 6 },
    ] as const;
    for (const v of verdicts) expect(recallRepetitionResult(v).status).toBe('info');
  });
});

describe('#717 recall repetition — privacy and read-only', () => {
  it('no prompt, title, hash, id, session, project or path reaches the doctor report', async () => {
    writeInteractive(repeat(REPEAT_SAMPLE_RUNS, SENTINEL_IDS));
    const row = await checkRecallRepetition({ homeDir: home });
    expect(row.status).toBe('warn');
    const rendered = [
      ...formatDoctorReport([row], { verbose: true, width: 200 }),
      ...formatDoctorReport([row], { verbose: false, width: 40 }),
    ];
    expect(rendered.join(' ').replace(/\s+/g, ' ')).toContain('not a proven root cause');
    const report = [...rendered, JSON.stringify(row)].join('\n');
    for (const s of ['SENTINEL', SENTINEL_HASH, 'c0ffee', 'beef', root, home, ...SENTINEL_IDS.map(String)]) {
      expect(report).not.toContain(s);
    }
  });

  it('reads only fixed slot names inside the injected home and writes nothing', async () => {
    writeInteractive(repeat(REPEAT_SAMPLE_RUNS, SENTINEL_IDS));
    writeSlot(REPEAT_SAMPLE_RUNS, entry({ lane: 'cron' }));
    const before = snapshot();
    const touched: string[] = [];
    const recording: RecallRepetitionFs = {
      lstatSync: (p) => { touched.push(p); return fs.lstatSync(p); },
      openSync: (p, flags) => {
        touched.push(p);
        // Read-only open: no write, create, truncate or append bit.
        expect(flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR | fs.constants.O_CREAT
          | fs.constants.O_TRUNC | fs.constants.O_APPEND)).toBe(0);
        return fs.openSync(p, flags);
      },
      fstatSync: (fd) => fs.fstatSync(fd),
      readSync: (fd, b, o, l, pos) => fs.readSync(fd, b, o, l, pos),
      closeSync: (fd) => fs.closeSync(fd),
    };
    const writeSpy = jest.spyOn(fs, 'writeFileSync');
    try {
      const row = await checkRecallRepetition({ homeDir: home, fs: recording });
      expect(row.status).toBe('warn');
      expect(writeSpy).not.toHaveBeenCalled();
    } finally {
      writeSpy.mockRestore();
    }
    expect(snapshot()).toBe(before);
    expect(touched[0]).toBe(logDir);
    for (const p of touched.slice(1)) expect(p).toMatch(new RegExp(`^${logDir.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/[0-9]\\.json$`));
    // Stops once the sample is complete: slot 4 onward is never opened.
    expect(touched).toHaveLength(1 + REPEAT_SAMPLE_RUNS);
  });

  it('an absent log is not created by the check', async () => {
    const bare = path.join(root, 'bare');
    fs.mkdirSync(bare);
    await checkRecallRepetition({ homeDir: bare });
    expect(fs.readdirSync(bare)).toEqual([]);
  });
});

describe('#717 recall repetition — matches the real recall-log writer', () => {
  let origHome: string | undefined;

  beforeEach(() => {
    origHome = process.env.HOME;
    // recall-log.mjs resolves HOME per call; point it at the fixture only.
    process.env.HOME = home;
    jest.resetModules();
  });

  afterEach(() => {
    if (origHome === undefined) delete process.env.HOME;
    else process.env.HOME = origHome;
  });

  it('runs written by writeRecallLog are read back and compared', async () => {
    const { writeRecallLog, getRecallLogDir } = await import('../../../scripts/lib/recall-log.mjs');
    expect(getRecallLogDir()).toBe(logDir);
    for (let i = 0; i < REPEAT_SAMPLE_RUNS; i++) {
      const ids = i % 2 === 0 ? SENTINEL_IDS : [...SENTINEL_IDS].reverse();
      writeRecallLog({
        prompt: `${SENTINEL_PROMPT} ${i}`,
        promptHash: `${SENTINEL_HASH}${i}`,
        candidates: [
          ...ids.map((id) => ({ id, title: SENTINEL_TITLE, source: 'fts' as const, injected: false, dropReason: 'dedupe' })),
          { id: 1000 + i, title: SENTINEL_TITLE, source: 'fts' as const, injected: false, dropReason: 'outside_top_n' },
        ],
        lane: 'interactive',
        laneSignal: 'default',
      });
    }
    // A newer automated run on top must not disturb the interactive sample.
    writeRecallLog({ prompt: 'cron', candidates: [], lane: 'cron', laneSignal: 'marker' });
    expect(evaluateRecallRepetition({ homeDir: home })).toEqual({
      kind: 'repeated', runs: REPEAT_SAMPLE_RUNS, setSize: SENTINEL_IDS.length, distinctPromptHashes: REPEAT_SAMPLE_RUNS,
    });
  });
});

describe('#717 recall repetition — wiring', () => {
  it('runDoctor registers the row with the live home only in production', () => {
    const src = fs.readFileSync(path.join(REPO, 'src', 'cli', 'doctor.ts'), 'utf8');
    const list = src.slice(src.indexOf('const checks: Array<'), src.indexOf('for (const check of checks)'));
    expect(list).toContain('async () => checkRecallRepetition()');
  });
});

describe('#717 recall repetition — docs', () => {
  it('UPDATING qualifies the WARN and prescribes no command for it', () => {
    const guide = fs.readFileSync(path.join(REPO, 'docs', 'UPDATING.md'), 'utf8');
    const start = guide.indexOf('#### Doctor: Recall repetition');
    expect(start).toBeGreaterThan(-1);
    const section = guide.slice(start, guide.indexOf('\n#### ', start + 1));
    expect(section).toContain('repetition evidence, not a proven root cause');
    expect(section).toContain('asking about the same topic repeatedly');
    expect(section).toContain('never a pass');
    expect(section).not.toContain('```');
    expect(section).not.toMatch(/recallVector|SHIELDCORTEX_RECALL_VECTOR|repair|guard enable/i);
  });

  it('CHANGELOG Unreleased carries the entry without dropping the existing ones', () => {
    const log = fs.readFileSync(path.join(REPO, 'CHANGELOG.md'), 'utf8');
    const unreleased = log.slice(log.indexOf('## [Unreleased]'), log.indexOf('## [5.7.0]'));
    expect(unreleased).toContain('**Doctor: Recall repetition row (#717).**');
    expect(unreleased).toContain('#678 Action Guard surface');
    expect(unreleased).toContain('the #717 vector plane is off by default');
  });
});
