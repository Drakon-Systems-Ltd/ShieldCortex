/**
 * ADR-002 measurement harness, Half B — the guard-evaluator adapter.
 *
 * This is the ONE seam between the fixture runner and the classifier under
 * test. Two implementations, one interface `{ evaluate(command, files) }`:
 *
 *   - `builtEvaluatorAdapter()` — the real thing. Imports `evaluateToolCall`
 *     from the BUILT `dist/` (per ADR-002's "run against the built guard
 *     evaluator", #556), and calls it in-process. Requires `npx tsc -p
 *     tsconfig.build.json` to have run first; throws a clear error otherwise.
 *     This is what `run.mjs` uses.
 *
 *   - `stubEvaluatorAdapter(table)` — a deterministic stand-in that returns a
 *     canned verdict per fixture id. It exists so the witness + corpus + runner
 *     wiring can be unit-tested WITHOUT a dist build, and so a reviewer can see
 *     the runner's logic exercised against known verdicts. It is NEVER the
 *     measurement; the PR reports numbers from the built adapter only.
 *
 * The interface is deliberately tiny: given the command text the guard would
 * see and an optional { path: contents } map of files a substitution/fold would
 * read, return `{ decision, severity, signals }`. `files` becomes the guard's
 * `resolveScriptSource`, so a `$(cat payload.sh)` fixture is judged on the
 * payload exactly as the live hook would judge it.
 */
import { createRequire } from 'node:module';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join, relative, resolve } from 'node:path';
import { createHash } from 'node:crypto';

const HERE = dirname(fileURLToPath(import.meta.url));
const DIST_GUARD_DIR = resolve(HERE, '../../dist/defence/iron-dome');
const DIST_GUARD = join(DIST_GUARD_DIR, 'tool-action-guard.js');

/** Scope label recorded next to every digest so a reader knows what was hashed. */
export const EVALUATOR_DIGEST_SCOPE = 'dist/defence/iron-dome/**/*.js';

/**
 * Digest of the BUILT evaluator (#570 item 1). sha256 over every `.js` file
 * under `dir`, in sorted relative-path order, each contributing
 * `<relative path>\0<bytes>\0`, so a byte change in any imported guard module,
 * a renamed file or an added file changes the value. Directory mtimes, file
 * mtimes and non-`.js` files (maps, d.ts) are NOT part of the digest: the
 * digest binds what Node loads, not how it was written to disk.
 *
 * This binds the run to the ARTEFACT BYTES, not to a source revision: two
 * builds of the same source give the same digest; a run cannot tell you which
 * commit was built, only which bytes evaluated the fixtures. Pair the digest
 * with the PR head in the report comment.
 * @param {string} dir
 * @returns {{ algorithm: 'sha256', scope: string, files: number, value: string }}
 */
export function evaluatorDigest(dir, scope = EVALUATOR_DIGEST_SCOPE) {
  const files = [];
  const walk = (d) => {
    for (const name of readdirSync(d).sort()) {
      const abs = join(d, name);
      const st = statSync(abs);
      if (st.isDirectory()) walk(abs);
      else if (st.isFile() && name.endsWith('.js')) files.push(abs);
    }
  };
  walk(dir);
  files.sort((a, b) => (relative(dir, a) < relative(dir, b) ? -1 : 1));
  const h = createHash('sha256');
  for (const abs of files) {
    h.update(relative(dir, abs)); h.update('\0');
    h.update(readFileSync(abs)); h.update('\0');
  }
  return { algorithm: 'sha256', scope, files: files.length, value: h.digest('hex') };
}

/**
 * The real adapter, bound to the built evaluator. Async because it dynamically
 * imports dist. `digest` is computed BEFORE the import so it describes the
 * bytes that were on disk when they were loaded.
 * @returns {Promise<{ id: string, digest: ReturnType<typeof evaluatorDigest>, evaluate: (command: string, files?: Record<string,string>) => {decision:string,severity:string,signals:string[]} }>}
 */
export async function builtEvaluatorAdapter() {
  if (!existsSync(DIST_GUARD)) {
    throw new Error(
      `built evaluator not found at ${DIST_GUARD}\n` +
      `Build it first with:  npx tsc -p tsconfig.build.json   (no dist delete)\n` +
      `This runner deliberately measures the BUILT artefact, per ADR-002 (#556).`,
    );
  }
  const digest = evaluatorDigest(DIST_GUARD_DIR);
  const mod = await import(pathToFileURL(DIST_GUARD).href);
  if (typeof mod.evaluateToolCall !== 'function') {
    throw new Error(`dist guard has no evaluateToolCall export (found: ${Object.keys(mod).join(', ')})`);
  }
  return {
    id: 'built-dist-evaluateToolCall',
    digest,
    evaluate(command, files) {
      const options = files
        ? { resolveScriptSource: (p) => (Object.prototype.hasOwnProperty.call(files, p) ? files[p] : null) }
        : undefined;
      const v = mod.evaluateToolCall('Bash', { command }, undefined, options);
      return { decision: v.decision, severity: v.severity, signals: [...(v.signals ?? [])] };
    },
  };
}

/**
 * A deterministic stub. `table` maps fixture id → { decision, severity, signals }.
 * A fixture id with no entry returns a benign allow, so a partial table is a
 * valid "everything not listed is allowed" fixture. A stub is NOT a build, so
 * its `digest` is `null` and any report it produces says the run is unbound.
 * @param {Record<string, {decision?:string,severity?:string,signals?:string[]}>} table
 */
export function stubEvaluatorAdapter(table = {}) {
  return {
    id: 'stub',
    digest: null,
    evaluate(_command, _files, fixtureId) {
      const e = fixtureId != null ? table[fixtureId] : undefined;
      return {
        decision: e?.decision ?? 'allow',
        severity: e?.severity ?? 'benign',
        signals: [...(e?.signals ?? [])],
      };
    },
  };
}

// Kept for callers that resolve the guard through CJS; unused by the runner but
// documents that the dist artefact is plain ESM and requires dynamic import.
export const require = createRequire(import.meta.url);
