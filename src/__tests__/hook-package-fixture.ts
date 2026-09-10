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
 *
 * And nothing in a run reaches the machine it runs on, or the network it is on.
 * Each child gets its own home, config dir and audit dir inside that run's
 * scratch directory, owner-only and not overridable by the caller; it carries no
 * proxy variable (belt-and-braces: see {@link HOOK_PROXY_KEYS}); and it loads a
 * fail-closed `globalThis.fetch` before it loads anything else, so the real
 * cloud-sync path in the real pipeline is intercepted locally and recorded
 * rather than sent (see {@link fetchGuardJs}). The three directories are not
 * equally load-bearing either:
 *
 * - the config dir is: a hook process reads the defence config on every scan
 *   and SIGNS what it reads, rewriting it in place;
 * - the home is: `os.homedir()` is where the model cache is looked for, and it
 *   answers from HOME or USERPROFILE depending on the platform, so both are
 *   pinned;
 * - the audit dir is belt-and-braces. This path writes its audit rows into
 *   SQLite (`defence_audit`), not into a directory, so pinning it diverts no
 *   write that actually executes here — it just makes sure the directory an
 *   append WOULD choose is this run's, whoever adds one later.
 *
 * See `runHook` below. Building a package is guarded too: a destination must be
 * fresh, and outside every checkout on the machine — not merely outside this one.
 */
import fs from 'fs';
import path from 'path';
import { spawnSync } from 'child_process';
import { fileURLToPath, pathToFileURL } from 'url';
import {
  WORKER_DISPOSED_BRAND_KEY,
  WORKER_DISPOSED_CODE,
  WORKER_DISPOSED_MSG,
} from '../embeddings/generator.js';

/**
 * Distinct memories a multi-row run stores, in order.
 *
 * Distinct on purpose, and not merely cosmetically: `insertMemoryRow()` drops an
 * exact-title repeat outright and runs a near-duplicate scan over same-project,
 * same-category rows on top of that, so N copies of one note would be stored
 * once and the run would be measuring a single row while claiming to measure N.
 * Different subjects, not reworded ones.
 *
 * The first entry is what every single-row case in this suite has always
 * stored, so those runs are byte-identical to what they were.
 */
const ROW_CONTENTS = [
  'We compared three queue designs and settled on the batched writer for ingest.',
  'The nightly compaction job now runs before the index rebuild, not after it.',
  'Retry budgets moved out of the transport layer into the scheduler that owns them.',
  'Cache eviction switched to a segmented LRU once the hit rate stalled at 61 percent.',
  'Session identifiers are minted by the writer, so a replayed request cannot reuse one.',
  'The audit row is written inside the transaction that writes the row it describes.',
];

/** Bytes a stored fixture vector occupies: 384 float32s. */
export const FIXTURE_VECTOR_BYTES = 384 * 4;
/** 0.75f little-endian — the first four bytes of a vector this fixture made. */
export const FIXTURE_VECTOR_HEAD = '0000403F';

/**
 * Wall-clock budget for one child hook process.
 *
 * Strictly below {@link HOOK_CASE_MS}, and that ordering is the point: a wedged
 * child is killed by `spawnSync` while jest is still waiting, so the failure a
 * developer reads is this fixture's diagnostic — which carries the child's
 * stdout and stderr — rather than a bare "exceeded timeout of 60000 ms" that
 * says nothing about what the hook process was doing.
 */
export const HOOK_CHILD_MS = 30_000;

/**
 * Per-test budget for a case that spawns a child hook process.
 *
 * The repo default is 10s, which is right for an in-process test and wrong for
 * a case whose subject is a whole Node process doing a real defence scan. Twice
 * {@link HOOK_CHILD_MS}, so the child's own budget always fires first.
 */
export const HOOK_CASE_MS = 2 * HOOK_CHILD_MS;

/** What the probe's rejecting trigger raises from inside SQLite's UPDATE. */
export const DB_UPDATE_REJECTED_MSG = 'hook package fixture: embedding UPDATE rejected';

/**
 * Proxy variables a child must not inherit, in both spellings anything reads.
 *
 * Belt-and-braces, and worth stating as such rather than as a network sandbox.
 * Nothing in this codebase honours these variables today: every cloud call site
 * goes through global `fetch`, whose undici implementation ignores them, and no
 * module installs a dispatcher that would not. So the scrub removes an egress
 * that WOULD exist the day a proxy-aware client is added — not one that exists
 * now, and not one that would survive being wrong about `fetch`.
 *
 * It is still the right default: a hook process inherits an operator's shell,
 * and what actually holds a run local is the isolation and the fail-closed
 * `fetch` guard below — not this list.
 *
 * Removed in {@link runHook}, after the caller's env and without regard to
 * case — see {@link deleteEnvKeys}.
 */
export const HOOK_PROXY_KEYS = [
  'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY',
  'http_proxy', 'https_proxy', 'all_proxy',
] as const;

/** What a child is told to reach directly: loopback, and nothing else. */
export const HOOK_NO_PROXY = 'localhost,127.0.0.1,::1';

/**
 * A proxy-SHAPED variable the fixture deliberately does NOT strip.
 *
 * The probe reports which of the keys it scans are present, so a test that sets
 * this one can tell an empty result for {@link HOOK_PROXY_KEYS} apart from a
 * probe that never looked.
 */
export const HOOK_PROXY_CONTROL_KEY = 'SC_HOOK_FIXTURE_PROXY_CONTROL';

/**
 * The fail-closed network guard every hook probe loads before anything else.
 *
 * The proxy scrub above is belt-and-braces; THIS is the sandbox. A hook process
 * runs the real defence pipeline, and with cloud enabled that pipeline calls
 * `syncToCloud()`, which POSTs the run's device id, device name and platform to
 * whatever `cloudBaseUrl` says. A test must not make that request — not to a
 * remote host, and not to loopback either, where "a port nobody is listening
 * on" is a convention rather than a guarantee and an unrelated local listener
 * would receive generated host metadata.
 *
 * Global `fetch` is the whole of this codebase's egress: every cloud call site
 * goes through it, and no module installs an undici dispatcher or opens a
 * socket of its own. Replacing it before the first dist module is loaded is
 * therefore a real boundary rather than a partial one — and the endpoints this
 * suite names are reserved-invalid anyway (RFC 2606 `.invalid`, which no
 * resolver may answer), so even a path that somehow escaped this could reach
 * nothing.
 *
 * Attempts are recorded to a file, so a run can PROVE the interception happened
 * locally instead of asserting an absence.
 */
function fetchGuardJs(logPath: string): string {
  return `
// Fixture module — written by src/__tests__/hook-package-fixture.ts, never shipped.
//
// Imported FIRST by the generated probe. An ESM graph is evaluated in import
// order, so nothing the writer or the real pipeline loads can have captured the
// original global before this replaces it.
import { appendFileSync } from 'fs';

const LOG = ${JSON.stringify(logPath)};

function targetOf(input) {
  if (typeof input === 'string') return input;
  if (input && typeof input.url === 'string') return input.url;
  try { return String(input); } catch { return '<unprintable request>'; }
}

globalThis.fetch = async (input, init) => {
  const url = targetOf(input);
  const method = String((init && init.method) || (input && input.method) || 'GET');
  try {
    appendFileSync(LOG, JSON.stringify({ method, url }) + '\\n');
  } catch { /* the run's scratch directory may already be gone */ }
  // Rejected, not thrown synchronously: every cloud call site either awaits
  // this or attaches .catch(), and a synchronous throw would take a path none
  // of them handle — turning a blocked request into a pipeline failure.
  throw new Error('hook package fixture: network is fail-closed — intercepted ' + method + ' ' + url);
};
`;
}

/**
 * Quote a string as SQL — single quotes, doubled inside.
 *
 * `JSON.stringify` is not this: SQLite reads a double-quoted token as an
 * IDENTIFIER, so a JSON-quoted RAISE argument becomes a column reference and
 * the trigger fails with `no such column` instead of the message it was given.
 */
function sqlString(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

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
  /**
   * Raise a GENUINE disposal instead of an error carrying `message`.
   *
   * A disposal is a branded `WorkerDisposedError` from the package's own build
   * — the exact message, the code and the registry brand — so it is the one
   * thing the writer's classifier accepts, not an imitation of it. Applies to
   * whichever error `mode` raises: the rejection of 'fail', and the buffer
   * getter of 'unusable'.
   *
   * That difference is the whole subject of the narrowing cases: a disposal out
   * of `generateEmbedding()` is a cancellation and quiet, while the SAME error
   * raised while validating or storing the vector is a failure and loud.
   */
  branded?: boolean;
  /** What the fixture cache-health gate reports. Defaults to ready. */
  cacheReady?: boolean;
  /**
   * Hold the answer for this many ms before the mode below decides it.
   *
   * The default is one `setImmediate`, which is faster than the shortest timer
   * a run can arm — so a run whose deadline was silently coerced to 1ms still
   * gets its vector, and "the deadline was honoured" and "the deadline was
   * rejected" look identical. A delay an order of magnitude above that makes
   * the two outcomes different: an instant deadline times the embed out, and a
   * deadline that fell back to its documented default does not.
   *
   * Wall clock, so keep it small — it is spent by every row in the run.
   */
  delayMs?: number;
  /**
   * Make `disposeModel()` never settle.
   *
   * The wedge the hook's post-timeout cleanup has to survive: `disposeModel()`
   * resolves when the worker thread is actually gone, and if the native work
   * that hung the embed is what `terminate()` has to interrupt, that is exactly
   * the call that does not come back.
   */
  disposeHangs?: boolean;
}

export interface HookPackageOptions {
  /**
   * 'real'    — `dist/embeddings/generator.js` re-exports the real classifier.
   * 'missing' — it does not export one at all, i.e. a build too old to have it.
   *             The writer must then suppress nothing.
   *
   * The disposal CLASS is re-exported either way: a stale package still has to
   * be able to raise a genuine branded disposal, or the case that proves the
   * classifier is borrowed would be passing on an unbranded near miss that any
   * build goes loud about.
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
// The package's OWN compiled disposal class, so a branded plan raises the
// thing the writer's classifier accepts rather than a copy that looks like it.
import { WorkerDisposedError } from './generator.js';

export * from './model-cache.js';

/** What this plan raises: a real disposal, or an ordinary error with a message. */
function plannedError(plan) {
  if (plan.branded) return new WorkerDisposedError();
  return new Error(plan.message);
}

export async function generateEmbedding(text) {
  const plan = readPlan();
  record('generateEmbedding');
  // A real async boundary, on purpose: a writer that SCHEDULES this instead of
  // awaiting it exits with the column still NULL, exactly as production did
  // before #458 — which is the defect the 'vector' mode exists to catch.
  await new Promise((resolve) => setImmediate(resolve));
  // ...and, when a plan asks for it, a real WAIT on top of that boundary, long
  // enough that a deadline of 1ms would beat it. See EmbedPlan.delayMs.
  if (plan.delayMs > 0) await new Promise((resolve) => setTimeout(resolve, plan.delayMs));
  switch (plan.mode) {
    case 'fail':
      throw plannedError(plan);
    case 'hang':
      return new Promise(() => {});
    case 'null':
      return null;
    case 'unusable':
      return {
        get buffer() {
          throw plan.branded
            ? new WorkerDisposedError()
            : new Error(plan.message || 'vector buffer detached');
        },
      };
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

export async function disposeModel() {
  record('disposeModel');
  // The wedge: a terminate() that never lands. Recorded FIRST, so a run proves
  // the writer really called it and then gave up on it.
  if (readPlan().disposeHangs) return new Promise(() => {});
}
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
    ? "export { WORKER_DISPOSED_MSG, WorkerDisposedError, isWorkerDisposedError } from './generator.real.js';"
    : [
      "export { WORKER_DISPOSED_MSG, WorkerDisposedError } from './generator.real.js';",
      '// isWorkerDisposedError deliberately absent: a build older than the contract.',
      '// The CLASS stays, so this package can still raise a genuine disposal —',
      '// otherwise the case that proves the classifier is borrowed would be',
      '// asserting on a near miss every build reports loudly.',
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
 * Resolve `p` through symlinked ancestors, so a destination that only *reaches*
 * the repository through a link is still recognised as being inside it.
 */
function resolveThroughLinks(p: string): string {
  const target = path.resolve(p);
  const tail: string[] = [];
  let existing = target;
  while (!fs.existsSync(existing)) {
    const parent = path.dirname(existing);
    if (parent === existing) return target;
    tail.unshift(path.basename(existing));
    existing = parent;
  }
  return path.join(fs.realpathSync(existing), ...tail);
}

/**
 * Delete every key of `env` whose NAME matches one of `names`, in any casing.
 *
 * A Windows environment block is case-INSENSITIVE and case-PRESERVING: a shell
 * that exported `Http_Proxy` hands a child a variable that IS HTTP_PROXY. The
 * plain JavaScript object this fixture copies the environment into is neither,
 * so deleting by exact name there removes the spelling this file knows and
 * leaves the operator's — a proxy that survives the scrub, or an alias sitting
 * beside a path this run pinned and shadowing it in the child.
 */
function deleteEnvKeys(env: Record<string, string | undefined>, names: readonly string[]): void {
  const unwanted = new Set(names.map((name) => name.toLowerCase()));
  for (const key of Object.keys(env)) {
    if (unwanted.has(key.toLowerCase())) delete env[key];
  }
}

/** `lstat`, or null — never follows a link, and never throws for a missing path. */
function lstatOrNull(p: string): fs.Stats | null {
  try {
    return fs.lstatSync(p);
  } catch {
    return null;
  }
}

/**
 * Refuse a destination that already exists — anything at all, of any type.
 *
 * The builder writes `package.json`, copies `dist/` and renames files inside
 * it, all through whatever the destination turns out to be. A directory would
 * be merged into, a file replaced, and a SYMLINK followed: `fs.mkdirSync` on a
 * link creates the target, so a link into somewhere valuable is a destination
 * that damages that place while looking like a fresh path here.
 *
 * `fs.existsSync` cannot see the worst of those — it is false for a dangling
 * link, the one case where the builder's own mkdir would bring the target into
 * existence — so this uses `lstat`, which reports the link itself.
 */
function freshnessRefusal(dest: string): string | null {
  const stat = lstatOrNull(dest);
  if (!stat) return null;
  const kind = stat.isSymbolicLink()
    ? (fs.existsSync(dest) ? 'a symlink' : 'a dangling symlink')
    : stat.isDirectory() ? 'a directory' : stat.isFile() ? 'a file' : 'an existing entry';
  return (
    `hook package fixture refuses to build at an existing path: ${dest} is already ${kind}. `
    + 'This builder overwrites package.json, copies dist/ and renames files inside it, and it '
    + 'writes THROUGH a link. Pass a fresh path that does not exist yet (inside fs.mkdtempSync).'
  );
}

/**
 * Refuse a destination inside ANY checkout, not just this one.
 *
 * `repoRoot` is one worktree. This repository is worked in a dozen of them plus
 * a main clone, each with a `package.json` and a `dist/embeddings/generator.js`
 * that this builder would overwrite and rename exactly as it would here, and
 * none of which `repoRoot` names. So the rule is written against what a
 * checkout IS: a directory holding a `.git` entry — a directory in a clone, a
 * file in a worktree.
 *
 * The walk starts at the deepest ancestor that exists (the destination itself
 * must not, but the freshness check is what says so) and runs to the filesystem
 * root, through resolved links, so neither depth nor a doorway symlink gets a
 * destination past it.
 */
function anyCheckoutRefusal(dest: string): string | null {
  let dir = resolveThroughLinks(dest);
  while (!lstatOrNull(dir)) {
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
  for (;;) {
    if (lstatOrNull(path.join(dir, '.git'))) {
      return (
        `hook package fixture refuses to build inside a checkout: ${dir} holds a .git entry, `
        + `so ${dest} is inside a clone or worktree whose package.json and dist/ this builder `
        + 'would overwrite. Pass a fresh temporary directory (fs.mkdtempSync) instead.'
      );
    }
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

/**
 * Refuse to build a package inside the repository, before anything is written.
 *
 * Building at `repoRoot` overwrites the real `package.json` and then renames
 * `dist/embeddings/generator.js` out from under the build; building at a
 * subdirectory of it silently drops a copy of `dist/` and a `node_modules`
 * symlink into the working tree. Every caller passes an `mkdtemp` path, so this
 * only ever fires on a mistake — which is exactly when a mistake must not be
 * carried out. The check runs first: no mkdir, no write, no copy, no rename
 * happens before it.
 */
function repoRefusal(dest: string): string | null {
  const target = resolveThroughLinks(dest);
  const repo = resolveThroughLinks(repoRoot);
  if (target !== repo && !target.startsWith(repo + path.sep)) return null;
  return (
    `hook package fixture refuses to build inside the repository: ${target} is `
    + `${target === repo ? 'the repository root' : `under ${repo}`}. `
    + 'Pass a fresh temporary directory (fs.mkdtempSync) instead.'
  );
}

/**
 * Why a build at `dest` would be refused, or null if it would go ahead.
 *
 * Read-only, and that is the point of it existing separately: `lstat` and
 * `realpath`, no mkdir and no write on any path, so a REAL location can be
 * classified without being handed to a builder that would damage it if a guard
 * ever regressed. The repository these tests run in is exactly such a location,
 * and pinning its classification is otherwise a test that overwrites its own
 * `package.json` the day the guard breaks.
 *
 * {@link createHookPackage} asks this and nothing else, so what a test pins
 * here is what the builder does — not a second opinion that could drift from it.
 *
 * Repository first, so a destination inside THIS checkout keeps its specific
 * diagnostic rather than the general one; freshness last, so a destination that
 * is both inside a checkout and already exists is reported as the worse of the
 * two.
 */
export function destinationRefusal(dest: string): string | null {
  return repoRefusal(dest) ?? anyCheckoutRefusal(dest) ?? freshnessRefusal(dest);
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
  // Every refusal runs before anything is created, written, copied or renamed —
  // and it is the same classification a test can ask for on its own, so the
  // guard a test pins is the guard that runs here.
  const refusal = destinationRefusal(dest);
  if (refusal) throw new Error(refusal);

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
  /**
   * Extra environment for the hook process.
   *
   * Overrides anything inherited — except the keys this run pins, which are
   * applied last and cannot be opened up from here:
   *
   *   HOME, USERPROFILE        this run's isolated home, in both spellings
   *                            `os.homedir()` reads
   *   HOMEDRIVE, HOMEPATH      derived from that home when it is drive-rooted,
   *                            and removed outright when it is not
   *   SHIELDCORTEX_CONFIG_DIR  this run's config dir
   *   SHIELDCORTEX_AUDIT_DIR   this run's audit dir
   *   SC_HOOK_FIXTURE_PLAN     this run's plan file — the fixture package's own
   *                            channel, so a caller cannot repoint it either
   *   NO_PROXY, no_proxy       {@link HOOK_NO_PROXY}: loopback, nothing else
   *   {@link HOOK_PROXY_KEYS}  deleted, in any casing
   *
   * Each of those names is deleted from the inherited-and-caller environment
   * before the pin is written, so a Windows-cased alias cannot shadow it.
   *
   * `SHIELDCORTEX_SKIP_EMBEDDINGS` is the one inherited key handled the other
   * way round: the jest runner sets it for the whole suite, so it is dropped
   * unless a case names it here.
   *
   * A test that wants to prove the isolation holds passes external directories
   * in and finds them untouched.
   */
  env?: Record<string, string>;
  /**
   * Child wall-clock budget. Distinct from — and strictly below — the per-test
   * jest budget: see {@link HOOK_CHILD_MS}.
   */
  timeoutMs?: number;
  /** Title the probe writes, so a run's row is identifiable. */
  title?: string;
  /**
   * How many memories this one hook process stores, in sequence.
   *
   * Defaults to 1, which is what every classification case wants. More than
   * one is how a run measures what a hook COSTS: `saveAutoExtractedMemory()`
   * embeds inline per call, so a bound that is really per-row shows up here as
   * N deadlines and N give-up lines rather than one of each.
   *
   * Capped by {@link ROW_CONTENTS}: each row needs its own subject to survive
   * the writer's exact-title and near-duplicate gates.
   */
  rows?: number;
  /**
   * Config JSON to place in this run's ISOLATED config dir before the child
   * starts. Omitted by default: an empty config dir is the authority, and it
   * yields cloud-disabled defaults, so nothing in the child has an endpoint or a
   * key to reach. Used by the isolation cases, which need a config the child
   * will actually self-heal in order to show where the healing landed.
   */
  seedConfig?: string;
  /**
   * Make the row's embedding UPDATE fail.
   *
   * 'embedding-update' — a `BEFORE UPDATE OF embedding` trigger in the probe's
   * own database raises {@link DB_UPDATE_REJECTED_MSG}, so the writer's `UPDATE
   * memories SET embedding = ?` genuinely fails at the database, after the
   * INSERT committed and with a real vector in hand.
   *
   * 'embedding-update-disposal' — the same statement instead throws a GENUINE
   * branded disposal: exact message, code and registry brand, the thing the
   * writer's classifier accepts. This is the narrowing case. A catch that still
   * covered the database write would read a lost vector as a clean shutdown and
   * say nothing at all; the row would keep its NULL column with no diagnostic.
   * The error is minted structurally in the probe rather than imported, which
   * is also what pins the brand as cross-module rather than class identity.
   *
   * Test-owned, in the generated probe: the writer and the package are untouched.
   */
  dbFailure?: 'embedding-update' | 'embedding-update-disposal';
}

/**
 * What the child process resolved for itself, measured inside it.
 *
 * Booleans and variable NAMES only, never values: a failure here is printed
 * into a CI log, and an operator's credentialed proxy URL or real home path is
 * not something a test diagnostic should carry. Each flag compares against the
 * exact path this run pinned, so `true` means the child agreed with the fixture
 * rather than merely landing somewhere plausible.
 */
export interface HookChildFacts {
  /** `os.homedir()` — the model-cache root is derived from this. */
  homedirIsIsolated: boolean;
  /** `process.env.HOME` — what homedir() reads on POSIX. */
  homeEnvIsIsolated: boolean;
  /** `process.env.USERPROFILE` — what homedir() reads on Windows. */
  userProfileIsIsolated: boolean;
  configDirIsIsolated: boolean;
  auditDirIsIsolated: boolean;
  /**
   * Which of {@link HOOK_PROXY_KEYS} — plus {@link HOOK_PROXY_CONTROL_KEY} —
   * the child could see, matched by name WITHOUT regard to case: on Windows an
   * operator's `Http_Proxy` is the same variable as HTTP_PROXY, so an
   * exact-name scan would report a surviving alias as absent.
   *
   * Names as the child spells them, sorted. Never a value.
   */
  proxyKeysPresent: string[];
  /** Both spellings of NO_PROXY carry exactly {@link HOOK_NO_PROXY}. */
  noProxyIsLoopback: boolean;
}

export interface HookRunResult {
  /**
   * Every request the child's `fetch` was asked to make, in order.
   *
   * Empty is the ordinary answer — a cloud-disabled config has no endpoint to
   * reach. A cloud-ENABLED run does attempt an upload, and this is where that
   * attempt shows up: recorded locally by {@link fetchGuardJs} and rejected,
   * never sent. Method and URL only, which is all the guard is handed.
   */
  fetchAttempts: Array<{ method: string; url: string }>;
  /**
   * Wall-clock ms the child process took, start to exit.
   *
   * The subject of the bounded-shutdown case: a hook that cannot give up on a
   * wedged `disposeModel()` runs until something kills it, and "it eventually
   * came back" is not the same claim as "it came back on its own budget".
   */
  durationMs: number;
  /** Bytes in the FIRST row's `embedding` column, or null when it stayed empty. */
  len: number | null;
  /** First four bytes, hex — {@link FIXTURE_VECTOR_HEAD} when the fixture embedded. */
  head: string | null;
  /**
   * Every row this run stored, in the order it stored them.
   *
   * One entry per requested row, always — a run that lost a memory throws
   * rather than reporting a short array, so a case reading `rows[2]` is reading
   * a row that exists.
   */
  rows: Array<{ len: number | null; head: string | null }>;
  stderr: string;
  /** What the fixture embedder recorded, in order. Empty for a real build. */
  events: string[];
  /** This run's isolated HOME. Nothing the child wrote can be outside it. */
  home: string;
  /** This run's isolated config dir — where a self-heal or signature lands. */
  configDir: string;
  /** This run's isolated audit dir — where an audit append would land. */
  auditDir: string;
  /** What the child resolved for home, config, audit and proxies. */
  child: HookChildFacts;
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
  timeoutMs = HOOK_CHILD_MS,
  title = 'HOOK probe',
  seedConfig,
  dbFailure,
  rows = 1,
}: HookRunOptions): HookRunResult {
  if (!Number.isInteger(rows) || rows < 1 || rows > ROW_CONTENTS.length) {
    throw new Error(
      `hook probe row count must be an integer between 1 and ${ROW_CONTENTS.length} — each row needs `
      + `its own subject to survive the writer's duplicate gates; got ${rows}.`,
    );
  }
  // Before anything is written. HOOK_CHILD_MS < HOOK_CASE_MS holds for the
  // default, but a case passing its own budget can break the ordering the whole
  // arrangement rests on: a child that outlives its case is killed by jest, and
  // the failure then says only that the case took too long — never what the
  // hook process was doing. `spawnSync` also reads 0 as "no timeout at all".
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs >= HOOK_CASE_MS) {
    throw new Error(
      `hook probe child budget must be a positive number of ms below the ${HOOK_CASE_MS}ms case `
      + `budget, so this fixture kills a wedged child first and reports what it said; got ${timeoutMs}ms.`,
    );
  }

  const tag = Math.random().toString(36).slice(2);
  const probePath = path.join(dir, `probe-${tag}.mjs`);
  const guardPath = path.join(dir, `netguard-${tag}.mjs`);
  const fetchLogPath = path.join(dir, `fetch-${tag}.log`);
  const dbPath = path.join(dir, `probe-${tag}.db`);
  const eventsPath = path.join(dir, `events-${tag}.log`);
  const planPath = path.join(dir, `plan-${tag}.json`);
  const writer = path.join(pkgRoot, 'scripts', 'lib', 'save-memory.mjs');

  // Isolation, not a default.
  //
  // An isolated HOME means no model cache and no host config: whatever the row
  // ends up holding was put there by this package, not by the machine. But HOME
  // alone is not isolation — `getConfigDir()` and `defaultRealtimeAuditDir()`
  // prefer SHIELDCORTEX_CONFIG_DIR / SHIELDCORTEX_AUDIT_DIR over `~`, and the
  // hook reads the defence config on every scan. Inherited from an operator's
  // shell or handed in by a caller, those two point a child that SIGNS what it
  // reads at somebody's real config: it rewrites config.json in place, adding a
  // device identity and an HMAC, and drops an .integrity-key beside it.
  //
  // So the run pins all three inside its own directory, owner-only, applied
  // AFTER the caller's `env` — a caller can add variables, never open a path out.
  // The config dir starts empty (unless a case seeds it), which means
  // cloud-disabled defaults: no key, no endpoint, nothing to upload to.
  //
  // The audit dir is the weakest of the three, and worth saying so: the writer's
  // audit trail on this path is the `defence_audit` TABLE, so pinning the
  // directory diverts no write that actually runs here. It is pinned anyway,
  // because the directory an append would choose is decided before anyone knows
  // whether an append happens.
  const home = path.join(dir, `home-${tag}`);
  const configDir = path.join(home, '.shieldcortex');
  const auditDir = path.join(configDir, 'audit');
  for (const isolated of [home, configDir, auditDir]) {
    fs.mkdirSync(isolated, { recursive: true, mode: 0o700 });
    fs.chmodSync(isolated, 0o700);
  }
  if (seedConfig !== undefined) {
    fs.writeFileSync(path.join(configDir, 'config.json'), seedConfig, { mode: 0o600 });
  }

  fs.writeFileSync(planPath, JSON.stringify({ mode: 'vector', ...plan, eventsPath }));
  // A separate module rather than a statement at the top of the probe: an ESM
  // graph evaluates its imports before ANY of the importer's own body runs, so
  // a `globalThis.fetch = ...` written inline would land after the writer and
  // the whole real pipeline had already been loaded. Importing this first is
  // what makes "before the real pipeline" a property of the module graph
  // instead of a hope about evaluation order.
  fs.writeFileSync(guardPath, fetchGuardJs(fetchLogPath));
  // An ESM specifier is a URL, not a path. On POSIX an absolute path happens to
  // read as one; on Windows `C:\...` is a scheme Node's loader rejects outright,
  // so a probe written with quoted paths could not run there at all — and every
  // Windows pin in this fixture would be describing a platform it cannot reach.
  // `pathToFileURL` is also what escapes a `#` or a space in a scratch path.
  fs.writeFileSync(probePath, `
    // First, and deliberately before every other specifier in this file.
    import ${JSON.stringify(pathToFileURL(guardPath).href)};
    import Database from ${JSON.stringify(pathToFileURL(betterSqlitePath).href)};
    import os from 'os';
    import { readFileSync } from 'fs';
    import { saveAutoExtractedMemory } from ${JSON.stringify(pathToFileURL(writer).href)};

    const db = new Database(${JSON.stringify(dbPath)});
    db.exec(readFileSync(${JSON.stringify(schemaPath)}, 'utf-8'));
    ${dbFailure === 'embedding-update' ? `db.exec(\`
      CREATE TRIGGER sc_fixture_reject_embedding_update
      BEFORE UPDATE OF embedding ON memories
      BEGIN SELECT RAISE(ABORT, ${sqlString(DB_UPDATE_REJECTED_MSG)}); END;
    \`);` : ''}
    ${dbFailure === 'embedding-update-disposal' ? `
    // The embedding UPDATE throws a GENUINE disposal — exact message, code and
    // registry brand — from the database layer, where a disposal cannot
    // truthfully come from. Minted here with no import: \`Symbol.for\` resolves
    // through the cross-realm registry, so this IS the writer's brand without
    // this probe sharing a class with anything.
    const scFixtureDisposal = () => Object.assign(
      new Error(${JSON.stringify(WORKER_DISPOSED_MSG)}),
      {
        name: 'WorkerDisposedError',
        code: ${JSON.stringify(WORKER_DISPOSED_CODE)},
        [Symbol.for(${JSON.stringify(WORKER_DISPOSED_BRAND_KEY)})]: true,
      },
    );
    const scFixturePrepare = db.prepare.bind(db);
    db.prepare = (sql) => (/UPDATE\\s+memories\\s+SET\\s+embedding/i.test(sql)
      ? { run() { throw scFixtureDisposal(); } }
      : scFixturePrepare(sql));
    ` : ''}
    // One call per memory — exactly how a hook with N extractions behaves. A
    // single-row run is the same single call it always was.
    const specs = ${JSON.stringify(
      Array.from({ length: rows }, (_, i) => ({
        title: rows === 1 ? title : `${title} ${i + 1}`,
        content: ROW_CONTENTS[i],
      })),
    )};
    for (const spec of specs) {
      await saveAutoExtractedMemory(
        db,
        {
          title: spec.title,
          content: spec.content,
          category: 'architecture',
          salience: 0.45,
          tags: ['auto-extracted'],
        },
        'hook-package-fixture',
        { source: 'stop-hook' },
      );
    }
    const readRow = db.prepare("SELECT length(embedding) AS len, hex(substr(embedding,1,4)) AS head FROM memories WHERE title = ?");
    const storedRows = specs.map((spec) => readRow.get(spec.title) ?? null);
    // What this process resolved, compared HERE against the paths the fixture
    // pinned. Booleans and key names only — never a value: this is printed into
    // failures, and an inherited proxy URL or a real home path is not a
    // diagnostic worth leaking.
    const child = {
      homedirIsIsolated: os.homedir() === ${JSON.stringify(home)},
      homeEnvIsIsolated: process.env.HOME === ${JSON.stringify(home)},
      userProfileIsIsolated: process.env.USERPROFILE === ${JSON.stringify(home)},
      configDirIsIsolated: process.env.SHIELDCORTEX_CONFIG_DIR === ${JSON.stringify(configDir)},
      auditDirIsIsolated: process.env.SHIELDCORTEX_AUDIT_DIR === ${JSON.stringify(auditDir)},
      // Every environment key whose NAME belongs to the proxy family, matched
      // without regard to case: Windows keeps an operator's own casing, so a
      // surviving \`Http_Proxy\` is HTTP_PROXY to this child and has to be
      // reported as present rather than missed by an exact-name scan.
      proxyKeysPresent: Object.keys(process.env)
        .filter((key) => ${JSON.stringify(
          [...HOOK_PROXY_KEYS, HOOK_PROXY_CONTROL_KEY].map((key) => key.toLowerCase()),
        )}.includes(key.toLowerCase()))
        .sort(),
      noProxyIsLoopback: process.env.NO_PROXY === ${JSON.stringify(HOOK_NO_PROXY)}
        && process.env.no_proxy === ${JSON.stringify(HOOK_NO_PROXY)},
    };
    process.stdout.write(JSON.stringify({ rows: storedRows, child }));
    // Exactly what stop-hook.mjs does — nothing gets a chance to drain here.
    process.exit(0);
  `);

  // What this run decides for itself, whatever anyone else says.
  //
  // `os.homedir()` reads HOME on POSIX and USERPROFILE on Windows, so HOME
  // alone would leave a Windows child resolving an operator's real home — and
  // looking for the model cache in it. NO_PROXY is written in both spellings
  // because both are read; on Windows they are one variable and the second
  // assignment is simply the same pin again.
  const pinned: Record<string, string> = {
    HOME: home,
    USERPROFILE: home,
    SHIELDCORTEX_CONFIG_DIR: configDir,
    SHIELDCORTEX_AUDIT_DIR: auditDir,
    SC_HOOK_FIXTURE_PLAN: planPath,
    NO_PROXY: HOOK_NO_PROXY,
    no_proxy: HOOK_NO_PROXY,
  };
  const childEnv: Record<string, string | undefined> = { ...process.env, ...env };
  // Removed first — every proxy variable, and every name this run is about to
  // pin — and only then pinned, so a caller adds variables but never opens a
  // path out. An operator's shell, the enclosing runner and the caller are
  // three channels for one variable, and on Windows a fourth: a spelling this
  // fixture does not use. HOMEDRIVE/HOMEPATH go too, and come back below only
  // if they can be given a meaningful value.
  deleteEnvKeys(childEnv, [...Object.keys(pinned), ...HOOK_PROXY_KEYS, 'HOMEDRIVE', 'HOMEPATH']);
  Object.assign(childEnv, pinned);
  // HOMEDRIVE/HOMEPATH are a Windows pair, and only a drive-rooted path can
  // give them a valid value. Inventing `C:` for a `/tmp/...` home would hand the
  // child syntax that means nothing, so a home with no drive letter leaves the
  // pair deleted: half of somebody else's home is worse than none.
  const driveRoot = /^([A-Za-z]:)[\\/]$/.exec(path.parse(home).root);
  if (driveRoot) {
    childEnv.HOMEDRIVE = driveRoot[1];
    childEnv.HOMEPATH = home.slice(driveRoot[1].length);
  }
  // The jest runner sets this to 1 for the whole suite; a hook process that
  // inherited it would skip the embed step entirely. Tests that want the gate
  // pass it back in through `env`, in this exact spelling.
  if (!('SHIELDCORTEX_SKIP_EMBEDDINGS' in env)) deleteEnvKeys(childEnv, ['SHIELDCORTEX_SKIP_EMBEDDINGS']);

  const startedAt = Date.now();
  const proc = spawnSync(process.execPath, [probePath], {
    cwd: pkgRoot,
    env: childEnv as NodeJS.ProcessEnv,
    encoding: 'utf-8',
    timeout: timeoutMs,
  });
  const durationMs = Date.now() - startedAt;

  if (proc.error || proc.status !== 0) {
    // Naming the budget matters: this fires while jest is still waiting, so the
    // failure a developer reads says which timeout ran out and what the child
    // had said before it was killed.
    const why = (proc.error as NodeJS.ErrnoException | undefined)?.code === 'ETIMEDOUT'
      ? `hook probe did not finish within its ${timeoutMs}ms child budget (killed with ${proc.signal})`
      : proc.error
        ? `hook probe could not run: ${proc.error.message}`
        : `hook probe exited ${proc.status} (signal ${proc.signal})`;
    throw new Error(`${why}\n--- stdout ---\n${proc.stdout}\n--- stderr ---\n${proc.stderr}`);
  }

  type StoredRow = { len: number | null; head: string | null };
  let printed: { rows: Array<StoredRow | null>; child: HookChildFacts };
  try {
    printed = JSON.parse(proc.stdout) as typeof printed;
  } catch {
    throw new Error(`hook probe printed no row\n--- stdout ---\n${proc.stdout}\n--- stderr ---\n${proc.stderr}`);
  }
  // `!printed` as well as the row checks: a probe that printed a bare `null`
  // parses fine and would otherwise be read as a result. A missing row means a
  // memory was DROPPED — by the defence pipeline or a duplicate gate — which is
  // a different failure from a lost vector and must never read as one.
  if (!printed || !Array.isArray(printed.rows) || printed.rows.length !== rows
    || printed.rows.some((row) => !row)) {
    throw new Error(
      `the hook lost a memory itself, not just its vector: expected ${rows} row(s), got `
      + `${JSON.stringify(printed?.rows)}\n--- stderr ---\n${proc.stderr}`,
    );
  }
  const storedRows = printed.rows as StoredRow[];

  const events = fs.existsSync(eventsPath)
    ? fs.readFileSync(eventsPath, 'utf-8').split('\n').filter(Boolean)
    : [];
  const fetchAttempts = (fs.existsSync(fetchLogPath)
    ? fs.readFileSync(fetchLogPath, 'utf-8').split('\n').filter(Boolean)
    : []
  ).map((line) => JSON.parse(line) as { method: string; url: string });

  return {
    fetchAttempts,
    durationMs,
    len: storedRows[0].len,
    head: storedRows[0].head,
    rows: storedRows,
    stderr: proc.stderr,
    events,
    home,
    configDir,
    auditDir,
    child: printed.child,
  };
}
