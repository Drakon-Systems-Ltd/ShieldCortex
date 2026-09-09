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
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import Database from 'better-sqlite3';

const DISPOSED = 'Embedding worker disposed';

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
