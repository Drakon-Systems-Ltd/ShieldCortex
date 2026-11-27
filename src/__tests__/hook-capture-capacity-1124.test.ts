/**
 * #1124: the capture hooks judge fullness against the RESOLVED memory caps.
 *
 * pre-compact, session-end and stop choose how selective extraction is from
 * (stored STM + LTM) / (STM cap + LTM cap). Until #1124 the caps were hardcoded
 * 100 / 1000, so after a signed `config --memory-cap` raise the hooks still
 * divided by 1100 and called a roomy store "full". The fix reads the caps
 * through the compiled resolver (dist/memory/config.js `resolveMemoryConfig`),
 * which owns the #1125/#1132 integrity rules — this suite pins that the hooks
 * see what that resolver says, including its clamp, and fall back to 100 / 1000
 * without skipping extraction when it cannot be reached.
 *
 * Every case runs a REAL hook file as its own Node process inside a hermetic
 * package built here (the same package-layout substitution as
 * ./hook-package-fixture.ts — no environment switch exists in shipped code):
 *
 *     <pkg>/package.json                          { "type": "module" }
 *     <pkg>/node_modules -> repo node_modules     (better-sqlite3 resolves)
 *     <pkg>/scripts/{stop,pre-compact,session-end}-hook.mjs   copies of the real hooks
 *     <pkg>/scripts/lib/**                        copy of the real scripts/lib
 *     <pkg>/scripts/lib/extract-memorable-segments.mjs
 *                                                 recorder: logs the threshold
 *                                                 each hook passes, then calls
 *                                                 the real module unchanged
 *     <pkg>/dist/memory/config.js                 the REAL build (symlink), a
 *                                                 failing fixture, or absent
 *
 * The recorder is how the stop hook is observed at all: it prints no fullness
 * line, and every stop-mode extractor scores at least 0.50 salience — above
 * every combined threshold its category table allows — so which band it picks
 * never shows up in what it saves.
 *
 * Nothing else of dist/ is in the package. The memory writer therefore cannot
 * load the defence pipeline and drops every candidate fail-closed (its
 * documented no-build behaviour): no row is written, no model is loaded and
 * nothing reaches the network. Each run gets its own HOME and config dir under
 * a fresh temp directory and a minimal environment.
 */
import { spawnSync } from 'node:child_process';
import { createHmac, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from '@jest/globals';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(__dirname, '..', '..');
const SCHEMA = path.join(REPO, 'src', 'database', 'schema.sql');
const BUILT_RESOLVER = path.join(REPO, 'dist', 'memory', 'config.js');

const HOOK_FILES = ['stop-hook.mjs', 'pre-compact-hook.mjs', 'session-end-hook.mjs'] as const;
type HookFile = (typeof HOOK_FILES)[number];

/** Child budget strictly below the case budget, so a wedged hook reports its own output. */
const CHILD_MS = 30_000;
const CASE_MS = 2 * CHILD_MS;

const INTEGRITY_KEY = 'e'.repeat(64);
const DEFAULT_CAPS = { maxShortTermMemories: 100, maxLongTermMemories: 1000 };

/** Enough of `autoMemory` to reach the selectivity call site in all three hooks. */
const AUTO_MEMORY = {
  enableStop: true,
  enableSessionEnd: true,
  stopHookSamplingTurns: 1,
  captureMode: 'regex',
};

type DistMode = 'real' | 'none' | 'throws' | 'unusable' | 'no-export';

/** Test-owned stand-ins for dist/memory/config.js. */
const FIXTURE_RESOLVERS: Record<Exclude<DistMode, 'real' | 'none'>, string> = {
  throws: "export function resolveMemoryConfig() { throw new Error('fixture: config read failed'); }\n",
  unusable: 'export function resolveMemoryConfig() { return { maxShortTermMemories: 0, maxLongTermMemories: Number.NaN }; }\n',
  'no-export': 'export const notTheResolver = true;\n',
};

const FIXTURE_HEADER = '// Fixture module — written by src/__tests__/hook-capture-capacity-1124.test.ts, never shipped.\n';

function recorderJs(logPath: string): string {
  return `${FIXTURE_HEADER}
import { appendFileSync } from 'fs';
import { processSegments as realProcessSegments } from './extract-memorable-segments.real.mjs';
export * from './extract-memorable-segments.real.mjs';

const LOG = ${JSON.stringify(logPath)};

export function processSegments(segments, dynamicThreshold, opts) {
  appendFileSync(LOG, JSON.stringify({ dynamicThreshold }) + '\\n');
  return realProcessSegments(segments, dynamicThreshold, opts);
}
`;
}

const PROBE_JS = `${FIXTURE_HEADER}
import { resolveCaptureMemoryCaps } from './scripts/lib/memory-caps.mjs';
process.stdout.write(JSON.stringify(await resolveCaptureMemoryCaps()));
`;

interface HookPackage {
  root: string;
  pkg: string;
  thresholdLog: string;
}

function createPackage(dist: DistMode): HookPackage {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1124-pkg-'));
  const pkg = path.join(root, 'pkg');
  const scripts = path.join(pkg, 'scripts');
  const lib = path.join(scripts, 'lib');
  fs.mkdirSync(scripts, { recursive: true });
  fs.writeFileSync(path.join(pkg, 'package.json'), JSON.stringify({ type: 'module' }));
  fs.symlinkSync(path.join(REPO, 'node_modules'), path.join(pkg, 'node_modules'), 'dir');
  for (const file of HOOK_FILES) fs.copyFileSync(path.join(REPO, 'scripts', file), path.join(scripts, file));
  fs.cpSync(path.join(REPO, 'scripts', 'lib'), lib, { recursive: true });

  const thresholdLog = path.join(root, 'thresholds.jsonl');
  fs.renameSync(path.join(lib, 'extract-memorable-segments.mjs'), path.join(lib, 'extract-memorable-segments.real.mjs'));
  fs.writeFileSync(path.join(lib, 'extract-memorable-segments.mjs'), recorderJs(thresholdLog));
  fs.writeFileSync(path.join(pkg, 'probe.mjs'), PROBE_JS);

  if (dist !== 'none') {
    const memoryDir = path.join(pkg, 'dist', 'memory');
    fs.mkdirSync(memoryDir, { recursive: true });
    if (dist === 'real') {
      // A link, not a copy: ESM resolves it to its real path, so the resolver's
      // own imports (cloud/config, capacity, types) are the current build's.
      fs.symlinkSync(BUILT_RESOLVER, path.join(memoryDir, 'config.js'));
    } else {
      fs.writeFileSync(path.join(memoryDir, 'config.js'), FIXTURE_HEADER + FIXTURE_RESOLVERS[dist]);
    }
  }
  return { root, pkg, thresholdLog };
}

interface Home {
  dir: string;
  configDir: string;
  dbPath: string;
  transcript: string;
  tmp: string;
}

function createHome(): Home {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1124-home-'));
  const configDir = path.join(dir, '.shieldcortex');
  const tmp = path.join(dir, 'tmp');
  fs.mkdirSync(configDir, { mode: 0o700 });
  fs.mkdirSync(tmp, { mode: 0o700 });
  const transcript = path.join(dir, 'transcript.jsonl');
  fs.writeFileSync(transcript, [
    { type: 'user', message: { role: 'user', content: 'What did you find out about the bakery hours for the team breakfast on Friday?' } },
    { type: 'assistant', message: { role: 'assistant', content: 'Turns out the bakery on the corner opens at seven on weekdays, so the Friday pickup works.' } },
  ].map((line) => JSON.stringify(line)).join('\n') + '\n');
  return { dir, configDir, dbPath: path.join(configDir, 'memories.db'), transcript, tmp };
}

function configFile(home: Home): string {
  return path.join(home.configDir, 'config.json');
}

/** No signature of any kind: the resolver treats any stored cap as unverified. */
function writeUnsigned(home: Home, memory?: Record<string, unknown>): void {
  const data = memory ? { autoMemory: AUTO_MEMORY, memory } : { autoMemory: AUTO_MEMORY };
  fs.writeFileSync(configFile(home), JSON.stringify(data, null, 2) + '\n');
}

/** Current shape: embedded `_sig` over the canonical body, verified with `.integrity-key`. */
function writeSigned(home: Home, memory: Record<string, unknown>): void {
  const data = { autoMemory: AUTO_MEMORY, memory };
  const sig = createHmac('sha256', INTEGRITY_KEY).update(JSON.stringify(data, null, 2)).digest('hex');
  fs.writeFileSync(path.join(home.configDir, '.integrity-key'), INTEGRITY_KEY);
  fs.writeFileSync(configFile(home), JSON.stringify({ ...data, _sig: sig }, null, 2) + '\n');
}

function seedDb(home: Home, counts: { shortTerm: number; longTerm: number }): void {
  const db = new Database(home.dbPath);
  try {
    db.exec(fs.readFileSync(SCHEMA, 'utf8'));
    const insert = db.prepare("INSERT INTO memories (uuid, type, category, title, content) VALUES (?, ?, 'note', ?, 'seeded row')");
    db.transaction(() => {
      for (let i = 0; i < counts.shortTerm; i++) insert.run(randomUUID(), 'short_term', `seed short ${i}`);
      for (let i = 0; i < counts.longTerm; i++) insert.run(randomUUID(), 'long_term', `seed long ${i}`);
    })();
  } finally {
    db.close();
  }
}

function rowCount(home: Home): number {
  const db = new Database(home.dbPath, { readonly: true });
  try {
    return (db.prepare('SELECT COUNT(*) AS n FROM memories').get() as { n: number }).n;
  } finally {
    db.close();
  }
}

function childEnv(home: Home): NodeJS.ProcessEnv {
  return {
    HOME: home.dir,
    USERPROFILE: home.dir,
    SHIELDCORTEX_CONFIG_DIR: home.configDir,
    TMPDIR: home.tmp,
    PATH: process.env.PATH ?? '/usr/bin:/bin',
  };
}

function payloadFor(file: HookFile, home: Home): Record<string, unknown> {
  switch (file) {
    case 'stop-hook.mjs': return { transcript_path: home.transcript, cwd: home.dir };
    case 'pre-compact-hook.mjs': return { trigger: 'manual', transcript_path: home.transcript, cwd: home.dir };
    case 'session-end-hook.mjs': return { reason: 'other', transcript_path: home.transcript, cwd: home.dir };
  }
}

function describeRun(res: ReturnType<typeof spawnSync>): string {
  return `status=${res.status} signal=${res.signal}\n--- stdout ---\n${res.stdout}\n--- stderr ---\n${res.stderr}`;
}

function runHook(pkg: HookPackage, home: Home, file: HookFile) {
  fs.rmSync(pkg.thresholdLog, { force: true });
  const res = spawnSync(process.execPath, [path.join(pkg.pkg, 'scripts', file)], {
    input: JSON.stringify(payloadFor(file, home)),
    encoding: 'utf8',
    timeout: CHILD_MS,
    cwd: home.dir,
    env: childEnv(home),
  });
  const thresholds = fs.existsSync(pkg.thresholdLog)
    ? fs.readFileSync(pkg.thresholdLog, 'utf8').trim().split('\n').filter(Boolean)
      .map((line) => (JSON.parse(line) as { dynamicThreshold: number }).dynamicThreshold)
    : [];
  return { res, thresholds, detail: describeRun(res) };
}

function probe(pkg: HookPackage, home: Home): unknown {
  const res = spawnSync(process.execPath, [path.join(pkg.pkg, 'probe.mjs')], {
    encoding: 'utf8',
    timeout: CHILD_MS,
    cwd: home.dir,
    env: childEnv(home),
  });
  if (res.status !== 0) throw new Error(`probe failed\n${describeRun(res)}`);
  return JSON.parse(res.stdout);
}

/** The config dir's names and config.json bytes — the cap read must change neither. */
function configSnapshot(home: Home): { names: string[]; bytes: string | null } {
  const file = configFile(home);
  return {
    names: fs.readdirSync(home.configDir).sort(),
    bytes: fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : null,
  };
}

const packages = new Map<DistMode, HookPackage>();
let home: Home;

beforeAll(() => {
  if (!fs.existsSync(BUILT_RESOLVER)) {
    throw new Error(`${BUILT_RESOLVER} is missing — run \`npm run build:ts\` first`);
  }
  for (const mode of ['real', 'none', 'throws', 'unusable', 'no-export'] as const) packages.set(mode, createPackage(mode));
});

afterAll(() => {
  for (const { root } of packages.values()) fs.rmSync(root, { recursive: true, force: true });
});

beforeEach(() => {
  home = createHome();
});

afterEach(() => {
  fs.rmSync(home.dir, { recursive: true, force: true });
});

function pkgFor(mode: DistMode): HookPackage {
  const pkg = packages.get(mode);
  if (!pkg) throw new Error(`no package for ${mode}`);
  return pkg;
}

describe('#1124 resolveCaptureMemoryCaps — caps come from the built resolver', () => {
  const cases: Array<{ name: string; write: (h: Home) => void; expected: typeof DEFAULT_CAPS }> = [
    { name: 'no config.json → built-in defaults', write: () => {}, expected: DEFAULT_CAPS },
    { name: 'config without a memory block → built-in defaults', write: (h) => writeUnsigned(h), expected: DEFAULT_CAPS },
    {
      name: 'malformed config.json → built-in defaults',
      write: (h) => fs.writeFileSync(configFile(h), '{ "memory": { "maxLongTermMemories": 5000 '),
      expected: DEFAULT_CAPS,
    },
    {
      name: 'a non-number cap is refused by the resolver → built-in default',
      write: (h) => writeSigned(h, { maxShortTermMemories: '250', maxLongTermMemories: '5000' }),
      expected: DEFAULT_CAPS,
    },
    {
      name: 'signed raise STM 250 / LTM 5000 is honoured',
      write: (h) => writeSigned(h, { maxShortTermMemories: 250, maxLongTermMemories: 5000 }),
      expected: { maxShortTermMemories: 250, maxLongTermMemories: 5000 },
    },
    {
      name: 'signed LOWER caps are a legitimate resolved value and are honoured',
      write: (h) => writeSigned(h, { maxShortTermMemories: 10, maxLongTermMemories: 100 }),
      expected: { maxShortTermMemories: 10, maxLongTermMemories: 100 },
    },
    {
      name: 'unverified caps below the default never shrink the denominator (#1125)',
      write: (h) => writeUnsigned(h, { maxShortTermMemories: 10, maxLongTermMemories: 100 }),
      expected: DEFAULT_CAPS,
    },
    {
      name: 'an unverified raise within the setter maximum is kept (#1132)',
      write: (h) => writeUnsigned(h, { maxShortTermMemories: 250, maxLongTermMemories: 5000 }),
      expected: { maxShortTermMemories: 250, maxLongTermMemories: 5000 },
    },
    {
      name: 'an unverified raise above the setter maximum is clamped to it (#1132)',
      write: (h) => writeUnsigned(h, { maxShortTermMemories: 50_000, maxLongTermMemories: 500_000 }),
      expected: { maxShortTermMemories: 10_000, maxLongTermMemories: 100_000 },
    },
  ];

  for (const c of cases) {
    it(c.name, () => {
      c.write(home);
      const before = configSnapshot(home);

      expect(probe(pkgFor('real'), home)).toEqual(c.expected);
      // A side-effect-free read: no adoption signature, no minted key, no rewrite.
      expect(configSnapshot(home)).toEqual(before);
    }, CASE_MS);
  }

  const failures: Array<{ mode: Exclude<DistMode, 'real'>; why: string }> = [
    { mode: 'none', why: 'no dist build at all' },
    { mode: 'throws', why: 'the resolver throws' },
    { mode: 'unusable', why: 'the resolver answers with unusable caps' },
    { mode: 'no-export', why: 'the build has no resolveMemoryConfig export' },
  ];

  for (const f of failures) {
    it(`falls back to 100 / 1000 when ${f.why}, even with a signed raise on disk`, () => {
      writeSigned(home, { maxShortTermMemories: 250, maxLongTermMemories: 5000 });
      expect(probe(pkgFor(f.mode), home)).toEqual(DEFAULT_CAPS);
    }, CASE_MS);
  }
});

const STATUS_PREFIX: Record<HookFile, string | null> = {
  // The stop hook prints no fullness line; #1124 does not add one.
  'stop-hook.mjs': null,
  'pre-compact-hook.mjs': '[auto-extract] Memory status:',
  'session-end-hook.mjs': '[session-end] Memory status:',
};

/** The written ring-buffer entry `shieldcortex inspect last-precompact` displays. */
function latestPrecompactEntry(h: Home): { thresholdUsed: number; contextFullnessPct: number | null; totalMemories: number } {
  return JSON.parse(fs.readFileSync(path.join(h.dir, '.shieldcortex', 'precompact-log', '0.json'), 'utf8'));
}

describe.each(HOOK_FILES)('#1124 %s — fullness denominator is the resolved cap sum', (file) => {
  function expectRun(
    run: ReturnType<typeof runHook>,
    expected: { stored: number; denominator: number; pct: number; threshold: number },
  ): void {
    expect({ status: run.res.status, detail: run.detail }).toEqual({ status: 0, detail: run.detail });
    // Extraction ran exactly once, at the band the resolved denominator selects.
    expect(run.thresholds).toEqual([expected.threshold]);
    // ...and its candidate reached the writer (which drops it fail-closed here:
    // the package carries no defence build, so nothing is stored).
    expect(run.res.stderr).toContain('dropped (defence pipeline unavailable)');

    const prefix = STATUS_PREFIX[file];
    if (prefix) {
      expect(run.res.stderr).toContain(`${prefix} ${expected.stored}/${expected.denominator} (${expected.pct}% full)`);
    } else {
      expect(run.res.stderr).not.toContain('Memory status:');
    }
    if (file === 'pre-compact-hook.mjs') {
      const entry = latestPrecompactEntry(home);
      expect(entry.totalMemories).toBe(expected.stored);
      expect(entry.contextFullnessPct).toBe(expected.pct);
      expect(entry.thresholdUsed).toBe(expected.threshold);
    }
  }

  it('defaults: 200 STM + 800 LTM over 100 + 1000 is 91% full → 0.50 band', () => {
    writeUnsigned(home);
    seedDb(home, { shortTerm: 200, longTerm: 800 });

    expectRun(runHook(pkgFor('real'), home, file), { stored: 1000, denominator: 1100, pct: 91, threshold: 0.5 });
    expect(rowCount(home)).toBe(1000);
  }, CASE_MS);

  it('signed raise: the same 1000 rows over 250 + 5000 is 19% full → 0.25 band', () => {
    writeSigned(home, { maxShortTermMemories: 250, maxLongTermMemories: 5000 });
    seedDb(home, { shortTerm: 200, longTerm: 800 });

    expectRun(runHook(pkgFor('real'), home, file), { stored: 1000, denominator: 5250, pct: 19, threshold: 0.25 });
    expect(rowCount(home)).toBe(1000);
  }, CASE_MS);

  it('unverified lower caps are clamped: 300 rows stay over 1100 (27%, 0.30), not 110', () => {
    writeUnsigned(home, { maxShortTermMemories: 10, maxLongTermMemories: 100 });
    seedDb(home, { shortTerm: 0, longTerm: 300 });

    expectRun(runHook(pkgFor('real'), home, file), { stored: 300, denominator: 1100, pct: 27, threshold: 0.3 });
    expect(rowCount(home)).toBe(300);
  }, CASE_MS);

  for (const mode of ['none', 'throws'] as const) {
    it(`a failed cap read (${mode === 'none' ? 'no dist build' : 'resolver throws'}) keeps 100 + 1000 and still extracts`, () => {
      writeSigned(home, { maxShortTermMemories: 250, maxLongTermMemories: 5000 });
      seedDb(home, { shortTerm: 200, longTerm: 800 });

      expectRun(runHook(pkgFor(mode), home, file), { stored: 1000, denominator: 1100, pct: 91, threshold: 0.5 });
      // Nothing was evicted or deleted on the fallback path.
      expect(rowCount(home)).toBe(1000);
    }, CASE_MS);
  }
});
