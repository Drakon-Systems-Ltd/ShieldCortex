/**
 * A hermetic package the REAL hook writer runs inside.
 *
 * `scripts/lib/save-memory.mjs` is a plain .mjs that a hook host starts as its
 * own process. Everything interesting about its embed step — which module it
 * embeds with, whether it awaits the vector before `process.exit(0)`, where it
 * gets the disposal contract from — is decided by that process's own module
 * resolution, so none of it can be observed from an in-process stub.
 *
 * It used to be observed instead through env-gated seams compiled into the
 * writer itself (`SHIELDCORTEX_TEST_SEAM`, `SHIELDCORTEX_HOOK_EMBED_FAKE`,
 * `SHIELDCORTEX_HOOK_EMBED_FAIL`). Those are gone: production code carries no
 * test behaviour at all, and the substitution happens here instead, entirely in
 * test-owned files.
 *
 * The trick is that the writer resolves its dependencies by RELATIVE PACKAGE
 * LAYOUT — `dist/` two directories up from `scripts/lib/` — so a package built
 * out of a copy of the actual writer and a `dist/` whose embedding modules are
 * ours makes the real writer, unmodified, embed with a module the test wrote:
 *
 *     <pkg>/package.json                       { "type": "module" }
 *     <pkg>/node_modules -> repo node_modules  (symlink; native deps resolve)
 *     <pkg>/scripts/lib/**                     copy of the ACTUAL hook writer
 *     <pkg>/dist/**                            copy of the real build, except
 *     <pkg>/dist/embeddings/index.js           fixture embedder (plan-driven)
 *     <pkg>/dist/embeddings/model-cache.js     fixture cache-health gate
 *     <pkg>/dist/embeddings/generator.js       fixture surface, REAL classifier
 *
 * Defence, database and every other `dist/` module is the real current build,
 * so a row still has to survive the real pipeline to be stored. The disposal
 * classifier is the real compiled one too, re-exported from the build copy this
 * package was made from — an exact-sentinel result here is the shipped
 * function's result, not a second opinion about it.
 *
 * Nothing in the package can reach ONNX: the fixture embedder never touches the
 * real generator, and the fixture `generator.js` throws if its embedder surface
 * is called at all.
 */
import fs from 'fs';
import path from 'path';
import { spawnSync } from 'child_process';
import { fileURLToPath } from 'url';

/** Bytes a stored fixture vector occupies: 384 float32s. */
export const FIXTURE_VECTOR_BYTES = 384 * 4;
/** 0.75f little-endian — the first four bytes of a vector this fixture made. */
export const FIXTURE_VECTOR_HEAD = '0000403F';

export const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const schemaPath = path.join(repoRoot, 'src', 'database', 'schema.sql');
const betterSqlitePath = path.join(repoRoot, 'node_modules', 'better-sqlite3', 'lib', 'index.js');

/** How the fixture embedder answers the writer's one `generateEmbedding()` call. */
export type EmbedMode =
  /** Resolve a usable 384-float vector carrying the fixture marker. */
  | 'vector'
  /** Reject with `message` — the whole point of the classification cases. */
  | 'fail'
  /** Never settle, so the writer's own timeout is the thing under test. */
  | 'hang'
  /** Resolve something that is not a vector at all. */
  | 'null'
  /** Resolve a vector whose buffer throws when the write step reaches for it. */
  | 'unusable';

export interface EmbedPlan {
  mode?: EmbedMode;
  /** Rejection message for 'fail', buffer-failure message for 'unusable'. */
  message?: string;
  /** What the fixture cache-health gate reports. Defaults to ready. */
  cacheReady?: boolean;
}

export interface HookPackageOptions {
  /**
   * 'real'    — `dist/embeddings/generator.js` re-exports the real classifier.
   * 'missing' — it does not export one at all, i.e. a build too old to have it.
   *             The writer must then suppress nothing.
   */
  classifier?: 'real' | 'missing';
}

const FIXTURE_PLAN_JS = `
// Fixture module — written by src/__tests__/hook-package-fixture.ts, never shipped.
import { appendFileSync, readFileSync } from 'fs';

let cached;

export function readPlan() {
  if (cached === undefined) {
    const file = process.env.SC_HOOK_FIXTURE_PLAN;
    cached = file ? JSON.parse(readFileSync(file, 'utf8')) : {};
  }
  return cached;
}

/** Append one line of evidence that the writer really reached this module. */
export function record(event) {
  const { eventsPath } = readPlan();
  if (eventsPath) appendFileSync(eventsPath, event + '\\n');
}
`;

const FIXTURE_INDEX_JS = `
// Fixture module — written by src/__tests__/hook-package-fixture.ts, never shipped.
//
// This is what the hook writer embeds with inside the fixture package. It keeps
// the real barrel's export surface (the model-cache half is re-exported from
// the fixture cache module, which stars the real one) so any other dist module
// that imports the barrel still links.
import { readPlan, record } from './fixture-plan.js';

export * from './model-cache.js';

export async function generateEmbedding(text) {
  const plan = readPlan();
  record('generateEmbedding');
  // A real async boundary, on purpose: a writer that SCHEDULES this instead of
  // awaiting it exits with the column still NULL, exactly as production did
  // before #458 — which is the defect the 'vector' mode exists to catch.
  await new Promise((resolve) => setImmediate(resolve));
  switch (plan.mode) {
    case 'fail':
      throw new Error(plan.message);
    case 'hang':
      return new Promise(() => {});
    case 'null':
      return null;
    case 'unusable':
      return { get buffer() { throw new Error(plan.message || 'vector buffer detached'); } };
    default: {
      const vector = new Float32Array(384);
      // Deliberately NOT the 0.42 the deleted production FAKE seam wrote: a row
      // carrying that marker would mean the seam is back, and the difference is
      // visible in the stored column rather than only in the event log.
      vector[0] = 0.75;
      return vector;
    }
  }
}

export async function disposeModel() { record('disposeModel'); }
export async function preloadModel() { record('preloadModel'); }
export function isModelLoaded() { return false; }
export function cosineSimilarity() { return 0; }
`;

const FIXTURE_MODEL_CACHE_JS = `
// Fixture module — written by src/__tests__/hook-package-fixture.ts, never shipped.
//
// Everything except the hook-readiness gate is the real model-cache module: the
// gate is the one thing a package with no 90MB ONNX file on disk cannot answer
// honestly, and the one thing a test needs to control to reach the embed step.
import { readPlan } from './fixture-plan.js';

export * from './model-cache.real.js';

export async function inspectEmbeddingHookReady() {
  const plan = readPlan();
  return { ready: plan.cacheReady !== false, reason: 'hook package fixture' };
}
`;

function fixtureGeneratorJs(classifier: 'real' | 'missing'): string {
  const contract = classifier === 'real'
    ? "export { WORKER_DISPOSED_MSG, isWorkerDisposedError } from './generator.real.js';"
    : [
      "export { WORKER_DISPOSED_MSG } from './generator.real.js';",
      '// isWorkerDisposedError deliberately absent: a build older than the contract.',
    ].join('\n');

  return `
// Fixture module — written by src/__tests__/hook-package-fixture.ts, never shipped.
//
// The disposal contract is the REAL compiled one, re-exported from the copy of
// the build this package was made from. The embedder surface is not: nothing in
// the fixture may start an ONNX worker, so calling it is a fixture bug and says
// so instead of loading a model.
${contract}

function offLimits(name) {
  throw new Error('hook package fixture: generator.' + name + '() must never run');
}

export async function generateEmbedding() { offLimits('generateEmbedding'); }
export async function preloadModel() { offLimits('preloadModel'); }
export async function disposeModel() { offLimits('disposeModel'); }
export function isModelLoaded() { return false; }
export function cosineSimilarity() { return 0; }
`;
}

/**
 * Build one hermetic package at `dest` and return its root.
 *
 * Needs a build: the copied `dist/` is where the real defence pipeline, the
 * real database layer and the real disposal classifier come from — which is
 * also true of a production hook, whose writer drops the memory outright when
 * the defence pipeline is unavailable.
 */
export function createHookPackage(dest: string, { classifier = 'real' }: HookPackageOptions = {}): string {
  const builtGenerator = path.join(repoRoot, 'dist', 'embeddings', 'generator.js');
  if (!fs.existsSync(builtGenerator)) {
    throw new Error(`hook package fixture needs a build: ${builtGenerator} is missing — run \`npm run build:ts\``);
  }

  fs.mkdirSync(path.join(dest, 'scripts'), { recursive: true });
  fs.writeFileSync(
    path.join(dest, 'package.json'),
    `${JSON.stringify({ name: 'sc-hook-package-fixture', private: true, version: '0.0.0', type: 'module' }, null, 2)}\n`,
  );
  fs.cpSync(path.join(repoRoot, 'scripts', 'lib'), path.join(dest, 'scripts', 'lib'), { recursive: true });
  fs.cpSync(path.join(repoRoot, 'dist'), path.join(dest, 'dist'), { recursive: true });
  fs.symlinkSync(path.join(repoRoot, 'node_modules'), path.join(dest, 'node_modules'), 'dir');

  const embeddings = path.join(dest, 'dist', 'embeddings');
  fs.renameSync(path.join(embeddings, 'generator.js'), path.join(embeddings, 'generator.real.js'));
  fs.renameSync(path.join(embeddings, 'model-cache.js'), path.join(embeddings, 'model-cache.real.js'));
  fs.writeFileSync(path.join(embeddings, 'fixture-plan.js'), FIXTURE_PLAN_JS);
  fs.writeFileSync(path.join(embeddings, 'index.js'), FIXTURE_INDEX_JS);
  fs.writeFileSync(path.join(embeddings, 'model-cache.js'), FIXTURE_MODEL_CACHE_JS);
  fs.writeFileSync(path.join(embeddings, 'generator.js'), fixtureGeneratorJs(classifier));

  return dest;
}

export interface HookRunOptions {
  /** Scratch directory for this run's probe, database, plan and event log. */
  dir: string;
  /**
   * The package the writer runs from. A fixture package substitutes the
   * embedding modules; `repoRoot` — the default — substitutes nothing at all,
   * which is how a run can prove that no environment variable injects anything
   * into the writer as shipped.
   */
  pkgRoot?: string;
  /** Only the fixture package reads this; the real build ignores it. */
  plan?: EmbedPlan;
  /** Extra environment for the hook process (overrides the defaults below). */
  env?: Record<string, string>;
  /** Child wall-clock budget. Distinct from the per-test jest timeout. */
  timeoutMs?: number;
  /** Title the probe writes, so a run's row is identifiable. */
  title?: string;
}

export interface HookRunResult {
  /** Bytes in the stored `embedding` column, or null when it stayed empty. */
  len: number | null;
  /** First four bytes, hex — {@link FIXTURE_VECTOR_HEAD} when the fixture embedded. */
  head: string | null;
  stderr: string;
  /** What the fixture embedder recorded, in order. Empty for a real build. */
  events: string[];
}

/**
 * Run one real hook process and report what it stored and what it said.
 *
 * `process.exit(0)` at the end of the probe is exactly what `stop-hook.mjs`
 * does: nothing pending gets a chance to drain, so an embed the writer failed
 * to await is a NULL column rather than a race that usually passes.
 */
export function runHook({
  dir,
  pkgRoot = repoRoot,
  plan,
  env = {},
  timeoutMs = 60_000,
  title = 'HOOK probe',
}: HookRunOptions): HookRunResult {
  const tag = Math.random().toString(36).slice(2);
  const probePath = path.join(dir, `probe-${tag}.mjs`);
  const dbPath = path.join(dir, `probe-${tag}.db`);
  const eventsPath = path.join(dir, `events-${tag}.log`);
  const planPath = path.join(dir, `plan-${tag}.json`);
  const writer = path.join(pkgRoot, 'scripts', 'lib', 'save-memory.mjs');

  fs.writeFileSync(planPath, JSON.stringify({ mode: 'vector', ...plan, eventsPath }));
  fs.writeFileSync(probePath, `
    import Database from ${JSON.stringify(betterSqlitePath)};
    import { readFileSync } from 'fs';
    import { saveAutoExtractedMemory } from ${JSON.stringify(writer)};

    const db = new Database(${JSON.stringify(dbPath)});
    db.exec(readFileSync(${JSON.stringify(schemaPath)}, 'utf-8'));
    await saveAutoExtractedMemory(
      db,
      {
        title: ${JSON.stringify(title)},
        content: 'We compared three queue designs and settled on the batched writer for ingest.',
        category: 'architecture',
        salience: 0.45,
        tags: ['auto-extracted'],
      },
      'hook-package-fixture',
      { source: 'stop-hook' },
    );
    const row = db.prepare("SELECT length(embedding) AS len, hex(substr(embedding,1,4)) AS head FROM memories WHERE title = ?").get(${JSON.stringify(title)});
    process.stdout.write(JSON.stringify(row ?? null));
    // Exactly what stop-hook.mjs does — nothing gets a chance to drain here.
    process.exit(0);
  `);

  // An isolated HOME means no model cache and no host config: whatever the row
  // ends up holding was put there by this package, not by the machine.
  const home = path.join(dir, `home-${tag}`);
  fs.mkdirSync(home, { recursive: true });
  const childEnv: Record<string, string | undefined> = {
    ...process.env,
    HOME: home,
    SC_HOOK_FIXTURE_PLAN: planPath,
    ...env,
  };
  // The jest runner sets this to 1 for the whole suite; a hook process that
  // inherited it would skip the embed step entirely. Tests that want the gate
  // pass it back in through `env`.
  if (!('SHIELDCORTEX_SKIP_EMBEDDINGS' in env)) delete childEnv.SHIELDCORTEX_SKIP_EMBEDDINGS;

  const proc = spawnSync(process.execPath, [probePath], {
    cwd: pkgRoot,
    env: childEnv as NodeJS.ProcessEnv,
    encoding: 'utf-8',
    timeout: timeoutMs,
  });

  if (proc.status !== 0) {
    throw new Error(`hook probe exited ${proc.status} (signal ${proc.signal})\n--- stdout ---\n${proc.stdout}\n--- stderr ---\n${proc.stderr}`);
  }

  let row: { len: number | null; head: string | null } | null;
  try {
    row = JSON.parse(proc.stdout) as { len: number | null; head: string | null } | null;
  } catch {
    throw new Error(`hook probe printed no row\n--- stdout ---\n${proc.stdout}\n--- stderr ---\n${proc.stderr}`);
  }
  if (row === null) {
    throw new Error(`the hook lost the memory itself, not just its vector\n--- stderr ---\n${proc.stderr}`);
  }

  const events = fs.existsSync(eventsPath)
    ? fs.readFileSync(eventsPath, 'utf-8').split('\n').filter(Boolean)
    : [];

  return { len: row.len, head: row.head, stderr: proc.stderr, events };
}
