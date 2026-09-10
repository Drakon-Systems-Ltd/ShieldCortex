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
 * Both embedding-job callers are pinned here, with no ONNX anywhere: store.ts
 * gets a stubbed `../embeddings/index.js` that fails with whatever message the
 * case needs, and `scripts/lib/save-memory.mjs` takes the same messages through
 * its own SHIELDCORTEX_TEST_SEAM failure injection.
 *
 * The match is EXACT. A timeout, a timeout kill, a crash, an invalid vector, a
 * database error, or any message that merely mentions disposal stays loud.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawnSync } from 'child_process';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import Database from 'better-sqlite3';
import { WORKER_DISPOSED_MSG } from '../embeddings/generator.js';

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
// @ts-expect-error -- importing a .mjs hook util
const { saveAutoExtractedMemory } = await import('../../scripts/lib/save-memory.mjs');

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

describe('hook writer (scripts/lib/save-memory.mjs) — same classification', () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
  const schemaPath = path.join(repoRoot, 'src', 'database', 'schema.sql');

  let tempDir: string;
  let db: Database.Database;
  let written: string[];
  let realWrite: typeof process.stderr.write;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-embed-noise-'));
    db = new Database(path.join(tempDir, 'memories.db'));
    db.exec(fs.readFileSync(schemaPath, 'utf-8'));
    process.env.SHIELDCORTEX_TEST_SEAM = '1';
    written = [];
    realWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = ((chunk: string | Uint8Array) => {
      written.push(String(chunk));
      return true;
    }) as typeof process.stderr.write;
  });

  afterEach(() => {
    process.stderr.write = realWrite;
    delete process.env.SHIELDCORTEX_TEST_SEAM;
    delete process.env.SHIELDCORTEX_HOOK_EMBED_FAIL;
    db.close();
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  /** Drive one hook write whose embed fails with `message`; return its stderr. */
  async function hookWrite(message: string, tag: string): Promise<string> {
    process.env.SHIELDCORTEX_HOOK_EMBED_FAIL = message;
    await saveAutoExtractedMemory(
      db,
      {
        title: `Decision: hook embed case ${tag}`,
        content: `We settled on approach ${tag} for the ingest queue after comparing three options.`,
        category: 'architecture',
        salience: 0.45,
        tags: ['auto-extracted'],
      },
      PROJECT,
    );
    const rows = (db.prepare('SELECT COUNT(*) AS c FROM memories').get() as { c: number }).c;
    expect(rows).toBeGreaterThan(0); // the row really was written and embedded
    return written.join('');
  }

  it('says nothing when the shutdown disposal cancels the embed', async () => {
    expect(await hookWrite(DISPOSED, 'quiet')).toBe('');
  });

  it.each(STILL_LOUD)('still reports %s', async (message) => {
    const stderr = await hookWrite(message, message.slice(0, 12));

    expect(stderr).toMatch(/embedding failed for memory/);
    expect(stderr).toContain(message);
  });
});

// --- Out-of-process hook probes -------------------------------------------
//
// Everything below is about what a REAL hook process does: which environment
// opens its test seams, and where it gets the disposal contract from. Neither
// question can be answered by an in-process stub, because both are decided by
// the process's own environment and module resolution.

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const schemaPath = path.join(repoRoot, 'src', 'database', 'schema.sql');
const betterSqlite = path.join(repoRoot, 'node_modules', 'better-sqlite3', 'lib', 'index.js');

interface HookProbe {
  /** Where the probe writes its scratch files. */
  dir: string;
  /** Which copy of the hook writer to import — the repo's, or a built tree. */
  libRoot?: string;
  /** Extra environment for the hook process. */
  env?: Record<string, string>;
  /** Strip the evidence jest leaves behind, i.e. look like a production hook. */
  productionRuntime?: boolean;
}

interface HookResult {
  len: number | null;
  head: string | null;
  stderr: string;
}

/** Run one real hook process and report what it stored and what it said. */
function runHook({ dir, libRoot, env = {}, productionRuntime = false }: HookProbe): HookResult {
  const lib = libRoot ?? path.join(repoRoot, 'scripts', 'lib');
  const tag = Math.random().toString(36).slice(2);
  const probe = path.join(dir, `probe-${tag}.mjs`);
  const dbPath = path.join(dir, `probe-${tag}.db`);
  fs.writeFileSync(probe, `
    import Database from ${JSON.stringify(betterSqlite)};
    import { readFileSync } from 'fs';
    import { saveAutoExtractedMemory } from ${JSON.stringify(path.join(lib, 'save-memory.mjs'))};

    const db = new Database(${JSON.stringify(dbPath)});
    db.exec(readFileSync(${JSON.stringify(schemaPath)}, 'utf-8'));
    await saveAutoExtractedMemory(
      db,
      {
        title: 'SEAM probe',
        content: 'We compared three queue designs and settled on the batched writer for ingest.',
        category: 'architecture',
        salience: 0.45,
        tags: ['auto-extracted'],
      },
      'seam-probe',
      { source: 'stop-hook' },
    );
    const row = db.prepare("SELECT length(embedding) AS len, hex(substr(embedding,1,4)) AS head FROM memories WHERE title = ?").get('SEAM probe');
    process.stdout.write(JSON.stringify(row ?? null));
    // Exactly what stop-hook.mjs does — nothing gets a chance to drain here.
    process.exit(0);
  `);

  // An isolated HOME means no model cache, so nothing here can reach a real
  // ONNX load: whatever the row ends up holding came from a seam.
  const home = path.join(dir, `home-${tag}`);
  fs.mkdirSync(home, { recursive: true });
  const childEnv: Record<string, string | undefined> = { ...process.env, HOME: home, ...env };
  delete childEnv.SHIELDCORTEX_SKIP_EMBEDDINGS; // the jest runner sets this to 1 globally
  if (productionRuntime) {
    delete childEnv.NODE_ENV;
    delete childEnv.JEST_WORKER_ID;
  }

  const proc = spawnSync(process.execPath, [probe], {
    env: childEnv as NodeJS.ProcessEnv,
    encoding: 'utf-8',
    timeout: 60_000,
  });
  expect(proc.status).toBe(0);
  const row = JSON.parse(proc.stdout) as HookResult | null;
  expect(row).not.toBeNull(); // the memory itself is never lost
  return { len: row!.len, head: row!.head, stderr: proc.stderr };
}

/**
 * The hook writer's test seams are env-triggered, and a hook is a process the
 * host starts with whatever environment it happens to have. `TEST_SEAM=1` left
 * behind in a shell profile — or inherited from a test run that spawned an
 * agent — was on its own enough to make a real hook honour an injected
 * embedding failure or write a fake vector, skipping the SKIP_EMBEDDINGS and
 * cache-health gates the rest of the path respects.
 *
 * So the seams now also want evidence of a test RUNTIME: jest sets NODE_ENV=test
 * (jest-cli/bin) and JEST_WORKER_ID (jest-runner sets it even with
 * --runInBand), and every honest probe inherits both from the worker that
 * spawns it. Two leaked env keys alone no longer open anything.
 */
describe('hook writer seams — inert without test-runtime evidence', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-embed-seam-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('ignores an injected failure in a production hook runtime', () => {
    const run = runHook({
      dir: tempDir,
      productionRuntime: true,
      env: { SHIELDCORTEX_TEST_SEAM: '1', SHIELDCORTEX_HOOK_EMBED_FAIL: 'Worker exited with code 3' },
    });

    expect(run.stderr).not.toContain('embedding failed for memory');
    expect(run.stderr).not.toContain('Worker exited with code 3');
    expect(run.len).toBeNull(); // no model cache under this HOME — nothing to embed with
  });

  it('ignores an injected fake vector in a production hook runtime', () => {
    const run = runHook({
      dir: tempDir,
      productionRuntime: true,
      env: { SHIELDCORTEX_TEST_SEAM: '1', SHIELDCORTEX_HOOK_EMBED_FAKE: '1' },
    });

    expect(run.len).toBeNull();
  });

  // Positive controls: the seams must still be usable BY A TEST, or the two
  // assertions above would pass just as well on seams that were deleted.
  it('still injects the failure when a test runtime is genuinely present', () => {
    const run = runHook({
      dir: tempDir,
      env: { SHIELDCORTEX_TEST_SEAM: '1', SHIELDCORTEX_HOOK_EMBED_FAIL: 'Worker exited with code 3' },
    });

    expect(run.stderr).toContain('embedding failed for memory');
    expect(run.stderr).toContain('Worker exited with code 3');
  });

  it('still writes the fake vector when a test runtime is genuinely present', () => {
    const run = runHook({
      dir: tempDir,
      env: { SHIELDCORTEX_TEST_SEAM: '1', SHIELDCORTEX_HOOK_EMBED_FAKE: '1' },
    });

    expect(run.len).toBe(384 * 4);
    expect(run.head).toBe('3D0AD73E'); // 0.42f little-endian — the seam's marker
  });
});

/**
 * The writer is a plain .mjs that cannot import the TypeScript contract, so it
 * borrows the compiled classifier out of `dist/embeddings/`. That is not a
 * fallback risk: without a build the defence pipeline is unavailable and this
 * writer drops the memory long before it embeds anything, so any embed that
 * could produce a disposal has the build loaded already. If the import fails
 * anyway, nothing is suppressed — a disposal prints one line, exactly the
 * pre-fix behaviour, which is the safe direction to fail in.
 *
 * That is also what makes "borrowed" testable rather than asserted: the same
 * hook writer, run against a tree whose `dist/embeddings/generator.js` is
 * missing, goes loud again. A copy of the literal could not tell the two trees
 * apart.
 */
describe('hook writer — the disposal contract is borrowed from the build', () => {
  let root: string;
  let intact: string;
  let degraded: string;

  /**
   * A self-contained tree the hook writer can run from: its own `scripts/lib`
   * and `dist`, plus a node_modules symlink so the copied build can still
   * resolve its dependencies.
   */
  function buildTree(name: string): string {
    const tree = path.join(root, name);
    fs.mkdirSync(path.join(tree, 'scripts'), { recursive: true });
    fs.cpSync(path.join(repoRoot, 'scripts', 'lib'), path.join(tree, 'scripts', 'lib'), { recursive: true });
    fs.cpSync(path.join(repoRoot, 'dist'), path.join(tree, 'dist'), { recursive: true });
    fs.symlinkSync(path.join(repoRoot, 'node_modules'), path.join(tree, 'node_modules'), 'dir');
    return tree;
  }

  beforeAll(() => {
    // Needs a build: the writer cannot reach its embed step without one.
    expect(fs.existsSync(path.join(repoRoot, 'dist', 'embeddings', 'generator.js'))).toBe(true);
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-embed-contract-'));
    intact = buildTree('intact');
    degraded = buildTree('degraded');
    fs.rmSync(path.join(degraded, 'dist', 'embeddings', 'generator.js'));
  });

  afterAll(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  it('says nothing about a disposal when the build is complete', () => {
    const run = runHook({
      dir: intact,
      libRoot: path.join(intact, 'scripts', 'lib'),
      env: { SHIELDCORTEX_TEST_SEAM: '1', SHIELDCORTEX_HOOK_EMBED_FAIL: DISPOSED },
    });

    expect(run.stderr).toBe('');
  });

  it('reports a genuine failure when the build is complete', () => {
    const run = runHook({
      dir: intact,
      libRoot: path.join(intact, 'scripts', 'lib'),
      env: { SHIELDCORTEX_TEST_SEAM: '1', SHIELDCORTEX_HOOK_EMBED_FAIL: 'Worker exited with code 3' },
    });

    expect(run.stderr).toContain('embedding failed for memory');
    expect(run.stderr).toContain('Worker exited with code 3');
  });

  it('suppresses nothing when the compiled contract is missing', () => {
    const run = runHook({
      dir: degraded,
      libRoot: path.join(degraded, 'scripts', 'lib'),
      env: { SHIELDCORTEX_TEST_SEAM: '1', SHIELDCORTEX_HOOK_EMBED_FAIL: DISPOSED },
    });

    // Loud, and specifically loud about the disposal: proof the quiet case
    // above came from the build's classifier and not from a local copy of the
    // string that no missing file could ever disturb.
    expect(run.stderr).toContain('embedding failed for memory');
    expect(run.stderr).toContain(DISPOSED);
  });
});
