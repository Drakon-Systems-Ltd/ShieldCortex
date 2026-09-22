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
import { existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const DIST_GUARD = resolve(HERE, '../../dist/defence/iron-dome/tool-action-guard.js');

/**
 * The real adapter, bound to the built evaluator. Async because it dynamically
 * imports dist.
 * @returns {Promise<{ id: string, evaluate: (command: string, files?: Record<string,string>) => {decision:string,severity:string,signals:string[]} }>}
 */
export async function builtEvaluatorAdapter() {
  if (!existsSync(DIST_GUARD)) {
    throw new Error(
      `built evaluator not found at ${DIST_GUARD}\n` +
      `Build it first with:  npx tsc -p tsconfig.build.json   (no dist delete)\n` +
      `This runner deliberately measures the BUILT artefact, per ADR-002 (#556).`,
    );
  }
  const mod = await import(pathToFileURL(DIST_GUARD).href);
  if (typeof mod.evaluateToolCall !== 'function') {
    throw new Error(`dist guard has no evaluateToolCall export (found: ${Object.keys(mod).join(', ')})`);
  }
  return {
    id: 'built-dist-evaluateToolCall',
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
 * valid "everything not listed is allowed" fixture.
 * @param {Record<string, {decision?:string,severity?:string,signals?:string[]}>} table
 */
export function stubEvaluatorAdapter(table = {}) {
  return {
    id: 'stub',
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
