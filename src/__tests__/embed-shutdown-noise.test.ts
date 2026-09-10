/**
 * Shutdown cancels queued embedding jobs on purpose — that is the disposal
 * doing its job, not a failure.
 *
 * Round 2 made that cancellation SETTLE. Before it, queued embeds never
 * resolved before `process.exit(0)` and printed nothing; now every one of them
 * reaches its caller's catch, and with no allowlist entry each prints
 *   [shieldcortex] Failed to generate embedding: Error: Embedding worker disposed
 * once per queued job. The text is honest, the label is not — on exactly the
 * axis the disposal work exists to fix — and it scales with queue depth.
 *
 * Both embedding-job callers are pinned here, with no ONNX anywhere:
 *
 * - `store.ts` runs in-process against a stubbed `../embeddings/index.js`;
 * - `scripts/lib/save-memory.mjs` runs as a REAL hook process inside a hermetic
 *   package (see `./hook-package-fixture.js`) whose `dist/embeddings/*` modules
 *   are the fixture's and whose defence, database and disposal classifier are
 *   the real build's.
 *
 * The writer itself is unmodified and carries no test seam: it finds the
 * fixture's embedder the same way it finds the real one, by relative package
 * layout, and the last case below proves the retired injection variables now
 * do nothing even in a genuine jest runtime.
 *
 * Each hook process also runs on its own home, config dir and audit dir, all
 * pinned AFTER the caller's environment. The isolation case below is where that
 * is measured, and the two halves of it are not equally strong:
 *
 * - config isolation is proven non-vacuously, by the healed local twin. The
 *   child really did read a config, stamp an identity into it and sign it —
 *   into this run's directory, while the inherited and supplied canaries came
 *   back byte-identical;
 * - the audit-dir pin is belt-and-braces. This path writes its audit rows into
 *   SQLite (`defence_audit`), not into a directory, so an untouched audit
 *   canary says the pin held, NOT that a filesystem audit write was diverted.
 *   No such write executes here, and the case does not claim one.
 *
 * The match is EXACT. A timeout, a timeout kill, a crash, an invalid vector, a
 * database error, or any message that merely mentions disposal stays loud.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { pathToFileURL } from 'url';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { WORKER_DISPOSED_MSG, isWorkerDisposedError } from '../embeddings/generator.js';
import {
  DB_UPDATE_REJECTED_MSG,
  FIXTURE_VECTOR_BYTES,
  FIXTURE_VECTOR_HEAD,
  HOOK_CASE_MS,
  HOOK_CHILD_MS,
  HOOK_NO_PROXY,
  HOOK_PROXY_CONTROL_KEY,
  createHookPackage,
  destinationRefusal,
  repoRoot,
  runHook,
} from './hook-package-fixture.js';

// From the producer, not a second copy of it. The one literal pin lives at the
// producer end (`worker-dispose-honesty.test.ts` asserts the string a real
// disposal settles with), so a change to the contract fails there, once,
// instead of quietly agreeing with itself here.
const DISPOSED = WORKER_DISPOSED_MSG;

/** Messages that must NEVER be swallowed, each a near miss in its own way. */
const STILL_LOUD = [
  'embed timed out after 30000ms',                     // the timeout itself
  'Embedding worker terminated after a timed-out request', // collateral of one
  'Worker exited with code 3',                         // a real crash
  'Worker crashed: fake worker boom',
  'Embedding worker disposed while writing the vector', // merely starts the same
  'the worker was disposed',                            // merely mentions it
];

/**
 * Every line the writer prints starts with this.
 *
 * A quiet case asserts the absence of it rather than an empty stderr: the
 * subject is what the WRITER said, and a future Node deprecation notice on the
 * child's stderr is not that. Nothing about the axis under test is weakened —
 * the writer has no other way to speak.
 */
const WRITER_PREFIX = '[shieldcortex save-memory]';
/** Building a package copies the whole build; only ever done once per suite. */
const PACKAGE_BUILD_MS = 120_000;

/**
 * A config the child must never read, and its isolated twin.
 *
 * Both are unsigned and carry no device identity, which is the shape a hook
 * process CHANGES: reading one rewrites it in place with a `deviceId`, this
 * machine's `deviceName` and an HMAC `_sig`, and drops an `.integrity-key`
 * beside it. So a canary that comes back byte-identical is evidence the child
 * never read it — not merely that it never wrote to it — and the twin that DID
 * get healed says where the child's config work went instead.
 *
 * Cloud is on in both, because config work only happens when it is, and the
 * only endpoint either names is the discard port on loopback: an isolation
 * failure could still not reach a live endpoint with the key beside it. Every
 * other run in this file leaves its isolated config empty, which is the
 * cloud-disabled default and names no endpoint at all.
 */
function canaryShapedConfig(marker: string): string {
  return `${JSON.stringify({
    cloudEnabled: true,
    cloudApiKey: marker,
    cloudBaseUrl: 'http://127.0.0.1:9/shieldcortex-canary',
  }, null, 2)}\n`;
}
const CANARY_KEY = 'canary-key-must-never-be-read';
const ISOLATED_KEY = 'isolated-twin-key';
const CANARY_CONFIG = canaryShapedConfig(CANARY_KEY);
const ISOLATED_CONFIG = canaryShapedConfig(ISOLATED_KEY);
const CANARY_AUDIT_LINE = '{"canary":"an operator\'s real forensics"}\n';

/**
 * Every path under `dir`, with file bytes, so an added file or an edit both show.
 *
 * Walked explicitly rather than with `readdirSync({ recursive: true })`, which
 * only tells a caller where an entry came from through `Dirent.parentPath`
 * (Node 20.12) or its predecessor `Dirent.path` (20.1) — neither of which
 * exists on the 20.0 this package declares support for, where the recursive
 * option itself does not exist either. One `readdirSync` per directory is the
 * whole of what this needs and has been there since long before that floor.
 */
function snapshot(dir: string): Record<string, string> {
  const out: Record<string, string> = {};
  const walk = (current: string, prefix: string): void => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      const rel = prefix ? path.join(prefix, entry.name) : entry.name;
      if (entry.isDirectory()) {
        out[rel] = '<dir>';
        walk(full, rel);
      } else {
        out[rel] = fs.readFileSync(full, 'utf-8');
      }
    }
  };
  walk(dir, '');
  return out;
}

/** Regex-safe form of a literal, so an interpolated constant matches itself. */
function escapeRegExp(literal: string): string {
  return literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Owner-only, where that means something.
 *
 * 0700 is a POSIX bit pattern; Windows reports its ACLs through a fabricated
 * mode that no permission assertion can read, so the platform check is the
 * honest form of this assertion rather than a way of skipping it.
 */
function expectOwnerOnly(dir: string): void {
  const stat = fs.statSync(dir);
  expect(stat.isDirectory()).toBe(true);
  if (process.platform === 'win32') return;
  expect(stat.mode & 0o777).toBe(0o700);
}

// --- store.ts seam: the embedder is a stub, never the real worker ----------
let embedFailure: Error | null = null;
let embedResult: unknown = new Float32Array(384);
let embedCalls = 0;

const generateEmbedding = jest.fn(async (_text: string): Promise<Float32Array> => {
  embedCalls += 1;
  if (embedFailure) throw embedFailure;
  return embedResult as Float32Array;
});

jest.unstable_mockModule('../embeddings/index.js', () => ({
  generateEmbedding,
  cosineSimilarity: () => 0,
  isModelLoaded: () => false,
  preloadModel: async () => {},
  disposeModel: async () => {},
}));

const { initDatabase, closeDatabase, getDatabase } = await import('../database/init.js');
const { addMemory, updateMemory, awaitPendingEmbeddings } = await import('../memory/store.js');

const PROJECT = 'embed-shutdown-noise';

let errors: string[] = [];
let warns: string[] = [];
let realError: typeof console.error;
let realWarn: typeof console.warn;

function captureConsole(): void {
  errors = [];
  warns = [];
  realError = console.error;
  realWarn = console.warn;
  console.error = (...args: unknown[]) => { errors.push(args.map(String).join(' ')); };
  console.warn = (...args: unknown[]) => { warns.push(args.map(String).join(' ')); };
}

function restoreConsole(): void {
  console.error = realError;
  console.warn = realWarn;
}

/** The refresh path is fire-and-forget — let its catch run. */
const flush = (): Promise<void> => new Promise((r) => setTimeout(r, 30));

describe('store.ts embedding jobs — shutdown cancellation is not a failure', () => {
  beforeEach(() => {
    closeDatabase();
    initDatabase(':memory:');
    embedFailure = null;
    embedResult = new Float32Array(384);
    embedCalls = 0;
    captureConsole();
  });

  afterEach(() => {
    restoreConsole();
    closeDatabase();
  });

  function add(title: string): { id: number } {
    return addMemory({
      title,
      content: `Body for ${title} — ordinary project note, nothing adversarial.`,
      category: 'note',
      project: PROJECT,
      type: 'long_term',
    });
  }

  async function addAndEmbed(title: string): Promise<void> {
    add(title);
    await awaitPendingEmbeddings();
  }

  it('says nothing when a queued job is cancelled by disposal', async () => {
    embedFailure = new Error(DISPOSED);

    await addAndEmbed('disposal is quiet');

    expect(embedCalls).toBe(1); // the job really ran — silence is not vacuum
    expect(errors).toEqual([]);
  });

  it('stays silent for every job a shutdown cancels, not just the first', async () => {
    embedFailure = new Error(DISPOSED);

    for (let i = 0; i < 5; i++) await addAndEmbed(`queued job ${i}`);

    expect(embedCalls).toBe(5);
    expect(errors).toEqual([]);
  });

  it.each(STILL_LOUD)('still reports %s', async (message) => {
    embedFailure = new Error(message);

    await addAndEmbed(`loud: ${message.slice(0, 20)}`);

    expect(errors.join('\n')).toMatch(/Failed to generate embedding/);
    expect(errors.join('\n')).toContain(message);
  });

  it('still reports a vector it cannot use', async () => {
    embedResult = null;

    await addAndEmbed('invalid vector');

    expect(warns.join('\n')).toMatch(/returned invalid result/);
  });

  it('still reports a database failure on the write', async () => {
    add('write fails');
    // The row is already in; only the vector write is blocked, and the message
    // is not the connection-closed one the store path deliberately ignores.
    getDatabase().pragma('query_only = true');

    await awaitPendingEmbeddings();
    getDatabase().pragma('query_only = false');

    expect(errors.join('\n')).toMatch(/Failed to store embedding/);
  });

  it('classifies the update-refresh path the same way', async () => {
    const created = addMemory({
      title: 'refresh path',
      content: 'Original content for the refresh path.',
      category: 'note',
      project: PROJECT,
      type: 'long_term',
    });
    await awaitPendingEmbeddings();
    errors = [];

    embedFailure = new Error(DISPOSED);
    updateMemory(created.id, { content: 'Rewritten content, first pass.' });
    await flush();
    expect(embedCalls).toBe(2); // the refresh really ran — silence is not vacuum
    expect(errors).toEqual([]);

    embedFailure = new Error('embed timed out after 30000ms');
    updateMemory(created.id, { content: 'Rewritten content, second pass.' });
    await flush();
    expect(embedCalls).toBe(3);
    expect(errors.join('\n')).toMatch(/Failed to regenerate embedding/);
  });
});

/**
 * The canary comparison in the isolation case below is only as strong as what
 * `snapshot` sees. A walker that reported nothing would make "byte-identical"
 * true of every directory, including one the child had just rewritten — so the
 * walk itself is pinned here, on a tree that has something at the bottom of it.
 */
describe('snapshot — the canary comparison is only as good as the walk', () => {
  it('reports every file and directory under the root, at every depth', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-embed-snapshot-'));
    const leaf = path.join('nested', 'deeper', 'leaf.jsonl');
    try {
      fs.mkdirSync(path.join(dir, 'nested', 'deeper'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'top.json'), '{"top":true}');
      fs.writeFileSync(path.join(dir, leaf), '{"leaf":true}\n');

      expect(snapshot(dir)).toEqual({
        'top.json': '{"top":true}',
        nested: '<dir>',
        [path.join('nested', 'deeper')]: '<dir>',
        [leaf]: '{"leaf":true}\n',
      });

      // And an edit at the bottom of it moves the answer: this is a comparison
      // of bytes, not a listing of names.
      fs.writeFileSync(path.join(dir, leaf), '{"leaf":false}\n');
      expect(snapshot(dir)[leaf]).toBe('{"leaf":false}\n');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

/**
 * The hook writer, as a real process.
 *
 * Every case below runs `scripts/lib/save-memory.mjs` unmodified inside a
 * hermetic package, and every one asserts on what the process SAID and what it
 * STORED. `events` is the non-vacuity control: it is what the fixture embedder
 * recorded, so a writer that stopped embedding altogether fails the quiet cases
 * instead of passing them by saying nothing.
 */
describe('hook writer (real process, hermetic package) — same classification', () => {
  let root: string;
  let pkg: string;

  beforeAll(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-embed-noise-'));
    pkg = createHookPackage(path.join(root, 'pkg'));
  }, PACKAGE_BUILD_MS);

  afterAll(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  it('says nothing when the shutdown disposal cancels the embed', () => {
    const run = runHook({
      dir: root,
      pkgRoot: pkg,
      plan: { mode: 'fail', message: DISPOSED },
      title: 'HOOK disposal is quiet',
    });

    expect(run.events).toEqual(['generateEmbedding']); // it really ran
    expect(run.stderr).not.toContain(WRITER_PREFIX); // the writer said nothing at all
    expect(run.stderr).not.toContain(DISPOSED);
    expect(run.len).toBeNull(); // the vector is lost; the memory is not
  }, HOOK_CASE_MS);

  it.each(STILL_LOUD)('still reports %s', (message) => {
    const run = runHook({
      dir: root,
      pkgRoot: pkg,
      plan: { mode: 'fail', message },
      title: `HOOK loud ${message.slice(0, 20)}`,
    });

    expect(run.stderr).toMatch(/embedding failed for memory/);
    expect(run.stderr).toContain(message);
  }, HOOK_CASE_MS);

  it('reports a real timeout, and disposes the model it timed out on', () => {
    const run = runHook({
      dir: root,
      pkgRoot: pkg,
      plan: { mode: 'hang' },
      env: { SHIELDCORTEX_HOOK_EMBED_TIMEOUT_MS: '250' },
      title: 'HOOK real timeout',
    });

    // Not an injected message: the embed never settles, so this is the writer's
    // own Promise.race firing, and the disposal it triggers is the real call.
    expect(run.stderr).toContain('embedding failed for memory');
    expect(run.stderr).toContain('embedding timed out after 250ms');
    expect(run.events).toEqual(['generateEmbedding', 'disposeModel']);
    expect(run.len).toBeNull();
  }, HOOK_CASE_MS);

  it('says its one line when the worker is unavailable, and calls it that', () => {
    const run = runHook({
      dir: root,
      pkgRoot: pkg,
      plan: { mode: 'fail', message: 'Embedding worker unavailable. Run `npm run build` so dist/embeddings/worker.js exists.' },
      title: 'HOOK unavailable',
    });

    expect(run.stderr).toContain('embeddings unavailable');
    expect(run.stderr).toContain('Embedding worker unavailable');
    expect(run.stderr).not.toContain('embedding failed for memory'); // configuration, not failure
  }, HOOK_CASE_MS);

  it('still reports a vector it cannot use', () => {
    const run = runHook({
      dir: root,
      pkgRoot: pkg,
      plan: { mode: 'null' },
      title: 'HOOK no vector',
    });

    expect(run.stderr).toContain('embedding returned no vector');
    expect(run.len).toBeNull();
  }, HOOK_CASE_MS);

  it('still reports a vector whose buffer cannot be read', () => {
    // Raised by the `!embedding.buffer` validity check, before any SQL runs —
    // the case below is the one that fails inside the UPDATE itself.
    const run = runHook({
      dir: root,
      pkgRoot: pkg,
      plan: { mode: 'unusable', message: 'vector buffer detached' },
      title: 'HOOK buffer unreadable',
    });

    expect(run.stderr).toContain('embedding failed for memory');
    expect(run.stderr).toContain('vector buffer detached');
    expect(run.len).toBeNull();
  }, HOOK_CASE_MS);

  it('still reports a database failure raised by the embedding UPDATE itself', () => {
    // A real vector, a committed row, and SQLite refusing `UPDATE memories SET
    // embedding = ?` — the probe's own BEFORE UPDATE trigger raises it, so the
    // error comes back through better-sqlite3 from inside the statement rather
    // than from anything the fixture handed the writer.
    const run = runHook({
      dir: root,
      pkgRoot: pkg,
      plan: { mode: 'vector' },
      dbFailure: 'embedding-update',
      title: 'HOOK db rejects update',
    });

    expect(run.events).toEqual(['generateEmbedding']); // the embed itself succeeded
    // The whole composed line, so a mangled trigger that failed for some other
    // SQLite reason (a quoting slip turns RAISE's argument into a column
    // reference) cannot pass by merely containing the right words.
    // Escaped, so the constant matches ITSELF: a future message carrying `(` or
    // `.` would otherwise quietly change what this pattern accepts.
    expect(run.stderr).toMatch(
      new RegExp(`embedding failed for memory \\d+: ${escapeRegExp(DB_UPDATE_REJECTED_MSG)}`),
    );
    // Loud, and the memory still survives its lost vector: runHook fails the
    // case outright if the row is missing, so NULL here is the whole damage.
    expect(run.len).toBeNull();
  }, HOOK_CASE_MS);

  it('kills a wedged child on its own budget, and says what it was doing', () => {
    // The embedder never settles, and the writer's own embed timeout is PINNED
    // here rather than assumed: its default is 10s, but it reads
    // SHIELDCORTEX_HOOK_EMBED_TIMEOUT_MS, so an operator shell exporting a
    // short one would end the run by timing out — a green pass for the wrong
    // mechanism. At 30s against a 1.5s budget, the only thing that can end this
    // run is spawnSync's kill: the mechanism that must fire before jest's case
    // budget for every other subprocess case in this file.
    expect(() => runHook({
      dir: root,
      pkgRoot: pkg,
      plan: { mode: 'hang' },
      env: { SHIELDCORTEX_HOOK_EMBED_TIMEOUT_MS: '30000' },
      timeoutMs: 1_500,
      title: 'HOOK wedged',
    })).toThrow(/hook probe did not finish within its 1500ms child budget \(killed with SIGTERM\)/);
  }, HOOK_CASE_MS);

  it('gives every child a strictly smaller budget than the case running it', () => {
    // An invariant, not a behaviour: HOOK_CHILD_MS is runHook's default, so a
    // wedged child under jest gets the kill above — with the child's stdout and
    // stderr attached — instead of the case expiring first and reporting only
    // that it took too long.
    expect(HOOK_CHILD_MS).toBeLessThan(HOOK_CASE_MS);
  });

  it('refuses a child budget its own case could not outlive', () => {
    // The constant invariant above holds for the DEFAULT budget only. A case
    // passing its own `timeoutMs` at or beyond the jest budget would get the
    // bare "exceeded timeout" the whole arrangement exists to avoid, so runHook
    // rejects it at the boundary instead of spawning something it cannot report
    // on. Nothing is written before the refusal.
    const before = fs.readdirSync(root);
    for (const timeoutMs of [HOOK_CASE_MS, HOOK_CASE_MS + 1, 0, -1]) {
      expect(() => runHook({ dir: root, pkgRoot: pkg, timeoutMs, title: 'HOOK bad budget' }))
        .toThrow(/child budget/);
    }
    expect(fs.readdirSync(root)).toEqual(before);
  });

  it('generates a probe whose imports are file: URLs, not filesystem paths', () => {
    // The probe is generated ESM, and an ESM specifier is a URL — not a path.
    // A JSON-quoted `C:\...` is rejected by Node's loader as an unsupported
    // scheme, so a probe written that way cannot run on Windows at all, and the
    // Windows pins in this file (homedir, HOMEDRIVE, the proxy casing) would be
    // pinning a platform the harness itself cannot reach.
    //
    // Its own scratch directory, so the single probe left in it is this case's.
    const dir = fs.mkdtempSync(path.join(root, 'probe-source-'));
    const run = runHook({ dir, pkgRoot: pkg, plan: { mode: 'vector' }, title: 'HOOK probe source' });
    expect(run.len).toBe(FIXTURE_VECTOR_BYTES); // it really ran

    const probes = fs.readdirSync(dir).filter((name) => /^probe-.*\.mjs$/.test(name));
    expect(probes).toHaveLength(1);
    const source = fs.readFileSync(path.join(dir, probes[0]), 'utf-8');
    const specifiers = [...source.matchAll(/\bfrom (["'])([^"']+)\1/g)].map((m) => m[2]);
    // Every specifier that names a location rather than a builtin. Both of them
    // — the driver and the writer — and nothing else.
    const located = specifiers.filter((specifier) => /[/\\]/.test(specifier));
    expect(located).toHaveLength(2);
    expect(located).toContain(pathToFileURL(path.join(pkg, 'scripts', 'lib', 'save-memory.mjs')).href);
    for (const specifier of located) {
      expect(specifier.startsWith('file://')).toBe(true);
    }
  }, HOOK_CASE_MS);

  it('awaits the vector and stores it before the process exits', () => {
    const run = runHook({ dir: root, pkgRoot: pkg, plan: { mode: 'vector' }, title: 'HOOK stores it' });

    // The fixture embedder settles across a setImmediate, so a writer that
    // scheduled this instead of awaiting it would exit with a NULL column.
    expect(run.events).toEqual(['generateEmbedding']);
    expect(run.len).toBe(FIXTURE_VECTOR_BYTES);
    expect(run.head).toBe(FIXTURE_VECTOR_HEAD);
    expect(run.stderr).not.toContain(WRITER_PREFIX);
    // An empty isolated config is the authority for every ordinary run: no key,
    // no endpoint, nothing to sync — so the child wrote no config here at all.
    // What the whole directory holds is the isolation case's subject, not this
    // one's: asserting it here would fail this case for an unrelated change.
    expect(fs.existsSync(path.join(run.configDir, 'config.json'))).toBe(false);
  }, HOOK_CASE_MS);

  it('embeds nothing at all when embeddings are disabled', () => {
    const run = runHook({
      dir: root,
      pkgRoot: pkg,
      env: { SHIELDCORTEX_SKIP_EMBEDDINGS: '1' },
      title: 'HOOK disabled',
    });

    expect(run.events).toEqual([]); // the gate is before the embedder, not after
    expect(run.len).toBeNull();
    expect(run.stderr).not.toContain(WRITER_PREFIX);
  }, HOOK_CASE_MS);

  it('never reads or signs a config directory it inherited from outside', () => {
    // The hook process reads the live defence config on every scan. Whatever the
    // machine, the operator or the enclosing test runner has exported for
    // SHIELDCORTEX_CONFIG_DIR / SHIELDCORTEX_AUDIT_DIR, this child must read and
    // write its own — so an operator's config is neither consulted nor signed.
    const ext = fs.mkdtempSync(path.join(root, 'ext-'));
    const inheritedConfig = path.join(ext, 'inherited-config');
    const inheritedAudit = path.join(ext, 'inherited-audit');
    const suppliedConfig = path.join(ext, 'supplied-config');
    const suppliedAudit = path.join(ext, 'supplied-audit');
    for (const d of [inheritedConfig, suppliedConfig]) {
      fs.mkdirSync(d, { recursive: true });
      fs.writeFileSync(path.join(d, 'config.json'), CANARY_CONFIG);
    }
    for (const d of [inheritedAudit, suppliedAudit]) {
      fs.mkdirSync(d, { recursive: true });
      fs.writeFileSync(path.join(d, 'realtime-canary.jsonl'), CANARY_AUDIT_LINE);
    }
    const before = [inheritedConfig, inheritedAudit, suppliedConfig, suppliedAudit].map(snapshot);

    const priorConfig = process.env.SHIELDCORTEX_CONFIG_DIR;
    const priorAudit = process.env.SHIELDCORTEX_AUDIT_DIR;
    try {
      // Both channels at once: inherited from this process, and handed to
      // runHook by the caller. Neither may win over the run's own isolation.
      process.env.SHIELDCORTEX_CONFIG_DIR = inheritedConfig;
      process.env.SHIELDCORTEX_AUDIT_DIR = inheritedAudit;
      const run = runHook({
        dir: root,
        pkgRoot: pkg,
        plan: { mode: 'vector' },
        env: { SHIELDCORTEX_CONFIG_DIR: suppliedConfig, SHIELDCORTEX_AUDIT_DIR: suppliedAudit },
        seedConfig: ISOLATED_CONFIG,
        title: 'HOOK external canary',
      });

      // The run did the whole job — this is not a case that passed by not running.
      expect(run.events).toEqual(['generateEmbedding']);
      expect(run.len).toBe(FIXTURE_VECTOR_BYTES);

      // ...and the config work the canaries must not receive happened HERE: the
      // child read its own config, healed it with a device identity and an HMAC,
      // and dropped the integrity key beside it. That is what makes this case
      // non-vacuous — a real read-and-sign, landing inside this run's directory.
      const healed = fs.readFileSync(path.join(run.configDir, 'config.json'), 'utf-8');
      expect(healed).toContain(ISOLATED_KEY); // the twin, not one of the canaries
      expect(healed).toContain('"deviceId"'); // identity stamped...
      expect(healed).toContain('"_sig"');     // ...and signed, which no canary is
      // The whole directory, here rather than in the storing case above: this is
      // the case whose subject is where the child's own paths are and what may
      // appear in them. Nothing beyond the heal, the key it signs with, and the
      // audit dir the fixture made.
      expect(fs.readdirSync(run.configDir).sort()).toEqual(['.integrity-key', 'audit', 'config.json']);
      expect(run.configDir.startsWith(`${root}${path.sep}`)).toBe(true);
      expect(run.auditDir.startsWith(`${run.configDir}${path.sep}`)).toBe(true);
      for (const isolated of [run.home, run.configDir, run.auditDir]) {
        expectOwnerOnly(isolated);
      }
      // The child answered from the pinned paths, not from anything the caller
      // or this process exported.
      expect(run.child.configDirIsIsolated).toBe(true);
      expect(run.child.auditDirIsIsolated).toBe(true);
      expect(run.child.homedirIsIsolated).toBe(true);
      // The seeded config is the one cloud-enabled run in this file, so it is
      // also the one that must not be able to leave the machine. What holds
      // that is the endpoint: a loopback discard port. The empty proxy list is
      // belt-and-braces beside it — nothing here honours those variables today
      // — and it is pinned so the day something does, this run is still local.
      expect(run.child.proxyKeysPresent).toEqual([]);
      expect(run.child.noProxyIsLoopback).toBe(true);
      // Belt-and-braces, and labelled as such: NOTHING on this path appends to
      // an audit DIRECTORY — the writer's audit trail is the `defence_audit`
      // table — so the empty isolated audit dir says the pin held, not that a
      // filesystem audit write was diverted into it. The pin is still worth
      // having: the directory an append WOULD use is chosen before anyone knows
      // whether an append happens.
      expect(fs.readdirSync(run.auditDir)).toEqual([]);
    } finally {
      if (priorConfig === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
      else process.env.SHIELDCORTEX_CONFIG_DIR = priorConfig;
      if (priorAudit === undefined) delete process.env.SHIELDCORTEX_AUDIT_DIR;
      else process.env.SHIELDCORTEX_AUDIT_DIR = priorAudit;
    }

    // Not one byte, and not one new file, in any of the four. For the two config
    // canaries that is the load-bearing half — reading one would have signed it.
    expect([inheritedConfig, inheritedAudit, suppliedConfig, suppliedAudit].map(snapshot)).toEqual(before);
  }, HOOK_CASE_MS);

  it('pins its own home, whatever the caller and the environment say', () => {
    // HOME is not the whole of it: on Windows `os.homedir()` ignores HOME and
    // reads USERPROFILE, so a child pinned on HOME alone would still resolve an
    // operator's real home — and the model-cache root, which is derived from
    // homedir(), with it. Both channels are exercised at once, inherited from
    // this process and handed to runHook, exactly as the config case does.
    const ext = fs.mkdtempSync(path.join(root, 'ext-home-'));
    const prior = { HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE };
    try {
      process.env.HOME = ext;
      process.env.USERPROFILE = ext;
      const run = runHook({
        dir: root,
        pkgRoot: pkg,
        plan: { mode: 'vector' },
        env: { HOME: ext, USERPROFILE: ext },
        title: 'HOOK home pinned',
      });

      // The run did the whole job — not a case that passed by not running.
      expect(run.events).toEqual(['generateEmbedding']);
      expect(run.len).toBe(FIXTURE_VECTOR_BYTES);

      // What the child actually resolved, reported by the probe as booleans
      // against the paths this run pinned.
      expect(run.child.homeEnvIsIsolated).toBe(true);
      expect(run.child.userProfileIsIsolated).toBe(true);
      expect(run.child.homedirIsIsolated).toBe(true);
      expect(run.home.startsWith(`${root}${path.sep}`)).toBe(true);
      expectOwnerOnly(run.home);
    } finally {
      for (const [key, value] of Object.entries(prior)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
    }

    // ...and the home it was TOLD to use, twice, stayed empty.
    expect(fs.readdirSync(ext)).toEqual([]);
  }, HOOK_CASE_MS);

  it('strips every proxy variable, in any casing, and points NO_PROXY at loopback', () => {
    // A hook child inherits an operator's shell, and a proxy there is one more
    // thing this run did not choose. Belt-and-braces rather than a sandbox: no
    // call site in this codebase honours these variables — every cloud request
    // goes through global `fetch`, which ignores them, and nothing installs a
    // dispatcher that would not — so the scrub removes an egress that WOULD
    // exist the day a proxy-aware client is added, not one that exists today.
    //
    // Casing is the part that has to be right for it to mean anything on
    // Windows: `process.env` there is case-insensitive, so a shell's
    // `Http_Proxy` IS HTTP_PROXY to the child, while the plain object this
    // fixture copies it into is case-SENSITIVE and keeps the two apart. A
    // delete by exact name would leave the alias behind, still pointing the
    // child at the proxy. Both channels carry both spellings and an alias.
    const prior = {
      HTTP_PROXY: process.env.HTTP_PROXY,
      https_proxy: process.env.https_proxy,
      Https_Proxy: process.env.Https_Proxy,
    };
    try {
      process.env.HTTP_PROXY = 'http://proxy.invalid:3128';
      process.env.https_proxy = 'http://proxy.invalid:3128';
      process.env.Https_Proxy = 'http://proxy.invalid:3128';
      const run = runHook({
        dir: root,
        pkgRoot: pkg,
        plan: { mode: 'vector' },
        env: {
          HTTPS_PROXY: 'http://proxy.invalid:3128',
          all_proxy: 'socks5://proxy.invalid:1080',
          Http_Proxy: 'http://proxy.invalid:3128',
          ALL_Proxy: 'socks5://proxy.invalid:1080',
          // Proxy-SHAPED, and deliberately not one of the stripped keys: the
          // probe reports it, which is how an empty list for the real family is
          // known to be a scrub rather than a probe that never looked.
          [HOOK_PROXY_CONTROL_KEY]: 'http://127.0.0.1:9',
        },
        title: 'HOOK proxies stripped',
      });

      expect(run.events).toEqual(['generateEmbedding']); // it really ran
      // Names only. The probe never reports a proxy VALUE, so a failure here
      // cannot print an operator's credentialed proxy URL into a CI log.
      expect(run.child.proxyKeysPresent).toEqual([HOOK_PROXY_CONTROL_KEY]);
      expect(run.child.noProxyIsLoopback).toBe(true);
    } finally {
      for (const [key, value] of Object.entries(prior)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
    }

    // And what the child was told to bypass is loopback, nothing else.
    expect(HOOK_NO_PROXY.split(',')).toEqual(['localhost', '127.0.0.1', '::1']);
  }, HOOK_CASE_MS);

  it('embeds nothing at all when the model cache is not ready', () => {
    const run = runHook({
      dir: root,
      pkgRoot: pkg,
      plan: { cacheReady: false },
      title: 'HOOK cold cache',
    });

    // #460: never download at session close. The health gate is what stands
    // between a hook and a HuggingFace fetch, and nothing may skip it.
    expect(run.events).toEqual([]);
    expect(run.len).toBeNull();
    expect(run.stderr).not.toContain(WRITER_PREFIX);
  }, HOOK_CASE_MS);
});

/**
 * The writer is a plain .mjs that cannot import the TypeScript contract, so it
 * borrows the compiled classifier out of `dist/embeddings/`. That is not a
 * fallback risk: without a build the defence pipeline is unavailable and this
 * writer drops the memory long before it embeds anything, so any embed that
 * could produce a disposal has the build loaded already. If the borrow fails
 * anyway, nothing is suppressed — a disposal prints one line, exactly the
 * pre-fix behaviour, which is the safe direction to fail in.
 *
 * That is also what makes "borrowed" testable rather than asserted: the same
 * writer, in a package whose build predates the contract, goes loud again. A
 * copy of the literal could not tell the two packages apart.
 */
describe('hook writer — the disposal contract is borrowed from the build', () => {
  let root: string;
  let stale: string;

  beforeAll(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-embed-contract-'));
    stale = createHookPackage(path.join(root, 'stale'), { classifier: 'missing' });
  }, PACKAGE_BUILD_MS);

  afterAll(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  it('suppresses nothing when the build exports no classifier', () => {
    const run = runHook({
      dir: root,
      pkgRoot: stale,
      plan: { mode: 'fail', message: DISPOSED },
      title: 'HOOK stale build',
    });

    // Loud, and specifically loud about the disposal: proof that the quiet case
    // in the suite above came from the build's classifier, and not from a local
    // copy of the string that no missing export could ever disturb.
    expect(run.events).toEqual(['generateEmbedding']);
    expect(run.stderr).toContain('embedding failed for memory');
    expect(run.stderr).toContain(DISPOSED);
  }, HOOK_CASE_MS);
});

/**
 * `SHIELDCORTEX_TEST_SEAM`, `SHIELDCORTEX_HOOK_EMBED_FAKE` and
 * `SHIELDCORTEX_HOOK_EMBED_FAIL` used to be read by the writer itself, so a
 * hook whose environment happened to carry them — a shell profile, an agent
 * spawned by a test run — embedded whatever a test would have wanted, skipping
 * the SKIP_EMBEDDINGS and cache-health gates the rest of the path respects.
 * Fencing them behind more inherited variables only moved the boundary; they
 * are gone instead, and substitution now happens in the package a test builds.
 *
 * These two cases are what "gone" means, measured rather than asserted: with
 * every retired key set, and with the jest runtime markers those keys were
 * once fenced behind present too, the hook embeds exactly what its package
 * gives it and says exactly what the outcome was.
 */
describe('hook writer — no test seam survives into production', () => {
  const RETIRED_SEAM_ENV = {
    SHIELDCORTEX_TEST_SEAM: '1',
    SHIELDCORTEX_HOOK_EMBED_FAKE: '1',
    SHIELDCORTEX_HOOK_EMBED_FAIL: 'Worker exited with code 3',
    NODE_ENV: 'test',
    JEST_WORKER_ID: '1',
  };

  let root: string;
  let pkg: string;

  beforeAll(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-embed-noseam-'));
    pkg = createHookPackage(path.join(root, 'pkg'));
  }, PACKAGE_BUILD_MS);

  afterAll(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  it('ignores every retired injection variable, inside a real test runtime', () => {
    const run = runHook({
      dir: root,
      pkgRoot: pkg,
      plan: { mode: 'vector' },
      env: RETIRED_SEAM_ENV,
      title: 'HOOK retired keys',
    });

    // The package's embedder ran, so the vector carries the fixture's marker
    // rather than the deleted seam's 0.42, and no injected failure appears.
    expect(run.events).toEqual(['generateEmbedding']);
    expect(run.head).toBe(FIXTURE_VECTOR_HEAD);
    expect(run.len).toBe(FIXTURE_VECTOR_BYTES);
    expect(run.stderr).not.toContain('Worker exited with code 3');
  }, HOOK_CASE_MS);

  it('cannot be made to fake a vector in the real package layout', () => {
    // The repository itself this time: the real dist, the real model-cache gate,
    // and a HOME with no model in it. The only way a vector could appear here
    // is a seam, and there is none.
    const run = runHook({
      dir: root,
      pkgRoot: repoRoot,
      env: RETIRED_SEAM_ENV,
      title: 'HOOK real layout',
    });

    // No `events` assertion here on purpose: the real build has no recorder, so
    // an empty log is a property of the package rather than of the writer, and
    // would read like the non-vacuity control the fixture cases genuinely have.
    // What carries this case is the NULL column — a seam is the only thing that
    // could have filled it.
    expect(run.len).toBeNull();
    expect(run.stderr).not.toContain('Worker exited with code 3');
    expect(run.stderr).not.toContain('embedding failed for memory');
  }, HOOK_CASE_MS);
});

/**
 * The fixture builds packages by renaming and overwriting files under a
 * destination it is handed. Every caller passes an `mkdtemp` path — but the one
 * call that does not must not be carried out, because the repository is a
 * destination this builder would damage: it overwrites `package.json` first,
 * then renames `dist/embeddings/generator.js` out from under the build.
 *
 * Which is precisely why the repository is never handed to the builder, not
 * even to watch it refuse. A test written that way IS the accident on the day
 * the guard regresses — it destroys the working tree it runs in, and only then
 * reports that the guard is gone. So the real path is put to
 * `destinationRefusal`, which reads and returns rather than writes and throws,
 * and the builder's agreement with it is pinned on disposable twins below.
 */
describe('hook package fixture — never builds inside the repository', () => {
  it('classifies the repository root and everything under it as refused', () => {
    const packageJson = path.join(repoRoot, 'package.json');
    const generator = path.join(repoRoot, 'dist', 'embeddings', 'generator.js');
    const before = fs.readFileSync(packageJson);
    const strayPackage = path.join(repoRoot, 'stray-fixture-package');

    for (const dest of [
      repoRoot,
      `${repoRoot}${path.sep}`,
      path.join(repoRoot, 'dist'),
      path.join(repoRoot, 'src', '__tests__', 'nested'),
      strayPackage,
    ]) {
      expect(destinationRefusal(dest)).toMatch(/refuses to build inside the repository/);
    }

    // Non-vacuity: the classifier can say yes. A fresh path under a temporary
    // directory is the shape every caller in this file passes and the shape
    // `createHookPackage` actually builds at, so "refused" is not simply its
    // answer to everything.
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-embed-outside-'));
    try {
      expect(destinationRefusal(path.join(outside, 'pkg'))).toBeNull();
    } finally {
      fs.rmSync(outside, { recursive: true, force: true });
    }

    // And asking cost the working tree nothing: no write, no rename, no stray
    // package — this is a read-only question about a real checkout.
    expect(fs.readFileSync(packageJson)).toEqual(before);
    expect(fs.existsSync(generator)).toBe(true);
    expect(fs.existsSync(path.join(repoRoot, 'dist', 'embeddings', 'generator.real.js'))).toBe(false);
    expect(fs.existsSync(strayPackage)).toBe(false);
  });
});

/**
 * The same refusal, generalised — because `repoRoot` is only ONE checkout.
 *
 * This repository is worked in worktrees: a dozen sibling checkouts and a main
 * clone sit beside the one these tests run from, each with a `package.json` and
 * a `dist/embeddings/generator.js` this builder would overwrite and rename
 * exactly as it would here. `repoRoot` names none of them, so the guard is
 * written against what a checkout IS — a directory holding a `.git` entry,
 * a directory in a clone and a file in a worktree — and the destination itself
 * must not exist at all, since the builder writes THROUGH a link.
 *
 * Every case below uses disposable twins under a temporary directory. A real
 * sibling checkout is never passed to the builder, not even to be refused.
 */
describe('hook package fixture — a destination must be fresh, and outside every checkout', () => {
  const TWIN_PACKAGE_JSON = `${JSON.stringify({ name: 'a-real-checkouts-package-json' }, null, 2)}\n`;
  const TWIN_GENERATOR_JS = '// a real checkout\'s built generator\nexport const notOurs = true;\n';
  let root: string;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-embed-dest-'));
  });

  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  /**
   * A disposable stand-in for a checkout, carrying the two things the builder
   * damages: a `package.json` it overwrites, and a `dist/embeddings/generator.js`
   * it renames aside. Under a `.git` entry of the shape the real thing has — a
   * directory in a clone, a file in a worktree.
   */
  function makeCheckoutTwin(name: string, git: 'clone' | 'worktree'): string {
    const twin = path.join(root, name);
    fs.mkdirSync(path.join(twin, 'dist', 'embeddings'), { recursive: true });
    fs.writeFileSync(path.join(twin, 'package.json'), TWIN_PACKAGE_JSON);
    fs.writeFileSync(path.join(twin, 'dist', 'embeddings', 'generator.js'), TWIN_GENERATOR_JS);
    if (git === 'clone') fs.mkdirSync(path.join(twin, '.git', 'objects'), { recursive: true });
    else fs.writeFileSync(path.join(twin, '.git'), 'gitdir: /nowhere/.git/worktrees/twin\n');
    return twin;
  }

  /** Byte-for-byte what the twin was built with, with nothing added anywhere. */
  function expectTwinIntact(twin: string): void {
    expect(fs.readFileSync(path.join(twin, 'package.json'), 'utf-8')).toBe(TWIN_PACKAGE_JSON);
    const embeddings = path.join(twin, 'dist', 'embeddings');
    expect(fs.readFileSync(path.join(embeddings, 'generator.js'), 'utf-8')).toBe(TWIN_GENERATOR_JS);
    // The rename is the destructive half, and it would leave a trace of its
    // own: a `generator.real.js` beside a generator.js the fixture wrote.
    expect(fs.readdirSync(embeddings)).toEqual(['generator.js']);
    // No package built at the root, and none dropped underneath it either.
    expect(fs.readdirSync(twin).sort()).toEqual(['.git', 'dist', 'package.json']);
  }

  it('rejects a destination that already exists, whatever it is', () => {
    const existingDir = path.join(root, 'existing-dir');
    fs.mkdirSync(path.join(existingDir, 'keep'), { recursive: true });
    const existingFile = path.join(root, 'existing-file');
    fs.writeFileSync(existingFile, 'not a package');
    const linkTarget = path.join(root, 'link-target');
    fs.mkdirSync(linkTarget);
    const liveLink = path.join(root, 'live-link');
    fs.symlinkSync(linkTarget, liveLink, 'dir');
    // The one `fs.existsSync` cannot see, and the one that matters most: a
    // dangling link is a path the builder's own mkdir would CREATE, through the
    // link, wherever it points.
    const danglingLink = path.join(root, 'dangling-link');
    fs.symlinkSync(path.join(root, 'not-there'), danglingLink, 'dir');

    for (const dest of [existingDir, existingFile, liveLink, danglingLink]) {
      expect(() => createHookPackage(dest)).toThrow(/refuses to build at an existing path/);
    }

    // Nothing was written into, through or beside any of them.
    expect(fs.readFileSync(existingFile, 'utf-8')).toBe('not a package');
    expect(fs.readdirSync(existingDir)).toEqual(['keep']);
    expect(fs.readdirSync(linkTarget)).toEqual([]);
    expect(fs.existsSync(path.join(root, 'not-there'))).toBe(false);
  });

  it('rejects a destination inside another checkout, clone or worktree alike', () => {
    const clone = makeCheckoutTwin('clone-twin', 'clone');
    const worktree = makeCheckoutTwin('worktree-twin', 'worktree');

    for (const dest of [
      // The checkout root itself, and the two ways a path names it — the shapes
      // the repository case can only ask the classifier about.
      clone,
      `${clone}${path.sep}`,
      path.join(clone, 'dist'),
      // And underneath it, where the damage is a package dropped in somebody's
      // working tree rather than an overwrite of theirs.
      path.join(clone, 'pkg'),
      path.join(worktree, 'pkg'),
      // Ancestors that do not exist yet: the walk starts at the deepest one
      // that does, so depth cannot get a destination past the guard.
      path.join(worktree, 'nested', 'deeper', 'pkg'),
      path.join(worktree, 'stray-fixture-package'),
    ]) {
      // The builder refuses with exactly what the classifier says. That
      // agreement is what carries the repository case: it pins the same
      // function, on a path no builder may be pointed at.
      const refusal = destinationRefusal(dest);
      expect(refusal).toMatch(/refuses to build inside a checkout/);
      expect(() => createHookPackage(dest)).toThrow(String(refusal));
    }

    // Neither twin lost its package.json or its built generator, and neither
    // gained a package, a dist/ copy or a node_modules link.
    expectTwinIntact(clone);
    expectTwinIntact(worktree);
  });

  it('follows a link into a checkout before deciding', () => {
    // The destination's PARENT is an ordinary temporary directory; only its
    // resolved location is inside a checkout. A guard that reasoned about the
    // literal path would build here.
    const twin = makeCheckoutTwin('linked-twin', 'clone');
    const doorway = path.join(root, 'doorway');
    fs.symlinkSync(twin, doorway, 'dir');

    expect(() => createHookPackage(path.join(doorway, 'pkg')))
      .toThrow(/refuses to build inside a checkout/);
    expectTwinIntact(twin);
  });
});

/**
 * Negative controls for the boundary every caller now shares.
 *
 * Whole-message equality on an `Error` is the whole contract, so the two ways a
 * near miss could still carry the exact text — a bare string, and something
 * that merely has a `message` property — must both be rejected. Neither can be
 * produced by `intentionalMessage()`, and if one day the classifier were
 * loosened to `err.message === MSG` without the `instanceof` guard, an
 * arbitrary object thrown by any layer could go quiet.
 */
describe('isWorkerDisposedError — negative controls', () => {
  it('accepts only a real Error carrying the exact message', () => {
    expect(isWorkerDisposedError(new Error(DISPOSED))).toBe(true);
  });

  it('rejects the exact sentinel as a plain string', () => {
    expect(isWorkerDisposedError(DISPOSED)).toBe(false);
  });

  it('rejects a message-shaped object that is not an Error', () => {
    expect(isWorkerDisposedError({ message: DISPOSED })).toBe(false);
    expect(isWorkerDisposedError({ message: DISPOSED, name: 'Error', stack: 'fake' })).toBe(false);
  });

  it('rejects an Error whose message merely contains the sentinel', () => {
    expect(isWorkerDisposedError(new Error(`${DISPOSED} while writing the vector`))).toBe(false);
    expect(isWorkerDisposedError(new Error(`worker: ${DISPOSED}`))).toBe(false);
  });

  it('rejects the empty and absent cases', () => {
    expect(isWorkerDisposedError(null)).toBe(false);
    expect(isWorkerDisposedError(undefined)).toBe(false);
    expect(isWorkerDisposedError(new Error(''))).toBe(false);
  });
});
