/**
 * #501 — one build, one lock, for every suite that drives the BUILT artefacts.
 *
 * Two suites assert against `dist/` and `plugins/openclaw/dist/`
 * (`policy-lock-dist-regression-501`, `policy-lock-chain-e2e-501`). Both must
 * measure a FRESH build rather than merely a present one — a dist left over
 * from before a fix exists, so a probe-for-existence would drive the old build
 * and report green about code that is not under review.
 *
 * What this file deliberately does NOT do any more is build. It did, once, from
 * inside `beforeAll`, and the #501 review's BLOCK-3 is what that cost:
 * `npm run build:ts` begins by DELETING both dist trees, Jest runs suites in
 * parallel workers, and ~10 other suites read `dist/` from those workers. The
 * cross-process lock serialised the two #501 suites against each other and did
 * nothing for anybody else, so an ordinary `npm test` after any edit
 * reproducibly failed 45 tests in `embed-shutdown-noise` — a suite with no
 * relation to the code under test.
 *
 * So freshness is now ASSERTED here and BUILT once, serially, before any worker
 * starts, in `scripts/run-jest.mjs`. That is the convention the rest of the
 * repo already follows (`main-entry-native-import-graph.test.ts`,
 * `guard-precision-planes.test.ts`): a suite that needs a build says so and
 * fails with the command to run.
 *
 * Not a `.test.ts` file, so Jest does not collect it (same convention as
 * `hook-package-fixture.ts`).
 */
import { existsSync, statSync } from 'node:fs';
import { relative } from 'node:path';

export interface BuiltArtefactSpec {
  repoRoot: string;
  /** Sources whose behaviour the suite asserts THROUGH the built output. */
  sources: string[];
  /** Built files that must exist and be no older than every source above. */
  artefacts: string[];
}

/** Why the build is not usable, or null when it is. */
export function staleArtefactReason({ repoRoot, sources, artefacts }: BuiltArtefactSpec): string | null {
  const rel = (p: string) => relative(repoRoot, p) || p;
  const missing = artefacts.filter((p) => !existsSync(p));
  if (missing.length > 0) return `missing built artefact(s): ${missing.map(rel).join(', ')}`;

  let newest = { path: sources[0] ?? repoRoot, mtimeMs: -Infinity };
  for (const p of sources) {
    const mtimeMs = statSync(p).mtimeMs;
    if (mtimeMs > newest.mtimeMs) newest = { path: p, mtimeMs };
  }
  const stale = artefacts.filter((p) => statSync(p).mtimeMs < newest.mtimeMs);
  if (stale.length > 0) {
    return `${stale.map(rel).join(', ')} ${stale.length === 1 ? 'is' : 'are'} older than ${rel(newest.path)}`;
  }
  return null;
}

/**
 * Assert the build this suite measures is the build the sources describe.
 *
 * Throws with the command to run. It does NOT run that command: see the header
 * — building from inside a worker deletes `dist/` out from under every sibling
 * worker, and `npm test` already builds once before Jest starts.
 */
export function requireFreshBuiltArtefacts(spec: BuiltArtefactSpec): void {
  const reason = staleArtefactReason(spec);
  if (reason === null) return;
  throw new Error(
    `#501: this suite measures the BUILT artefacts and the build is not current — ${reason}. ` +
    'Run `npm run build:ts` first. (`npm test` does this for you; a bare `jest` invocation does not.)',
  );
}
