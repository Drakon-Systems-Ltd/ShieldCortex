/**
 * #501 — one build, one lock, for every suite that drives the BUILT artefacts.
 *
 * Two suites now assert against `dist/` and `plugins/openclaw/dist/`
 * (`policy-lock-dist-regression-501`, `policy-lock-chain-e2e-501`). Both must
 * rebuild a STALE build rather than merely a missing one — a dist left over
 * from before the fix exists, so a probe-for-existence would drive the old
 * build and report green about code that is not under review.
 *
 * But `npm run build:ts` begins by DELETING both dist trees. Jest runs suites
 * in parallel workers, so two suites each deciding to rebuild means one of them
 * spawns child processes against a dist the other just removed — a flake with
 * no relation to the code under test. Hence the cross-process lock: the
 * filesystem's own `mkdir` is the mutex, because it is atomic across processes
 * and needs nothing the worker does not already have.
 *
 * Not a `.test.ts` file, so Jest does not collect it (same convention as
 * `hook-package-fixture.ts`).
 */
import { execSync } from 'node:child_process';
import { existsSync, mkdirSync, rmSync, statSync } from 'node:fs';
import { join } from 'node:path';

/** A lock older than this belonged to a worker that died mid-build. */
const STALE_LOCK_MS = 15 * 60_000;
const POLL_MS = 250;
const ACQUIRE_TIMEOUT_MS = 10 * 60_000;

export interface BuiltArtefactSpec {
  repoRoot: string;
  /** Sources whose behaviour the suite asserts THROUGH the built output. */
  sources: string[];
  /** Built files that must exist and be no older than every source above. */
  artefacts: string[];
}

/** Blocking sleep — `beforeAll` here is synchronous and so is `execSync`. */
function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

export function artefactsAreStale({ sources, artefacts }: Omit<BuiltArtefactSpec, 'repoRoot'>): boolean {
  if (!artefacts.every((p) => existsSync(p))) return true;
  const newestSource = Math.max(...sources.map((p) => statSync(p).mtimeMs));
  return artefacts.some((p) => statSync(p).mtimeMs < newestSource);
}

/**
 * Build if — and only if — the artefacts are stale, at most once across all
 * workers. A waiter blocks on the LOCK rather than on freshness: `tsc` writes
 * its output file by file, so an individual artefact can look fresh while the
 * build that will overwrite its siblings is still running.
 */
export function ensureFreshBuiltArtefacts(spec: BuiltArtefactSpec): void {
  if (!artefactsAreStale(spec)) return;

  const lock = join(spec.repoRoot, '.jest-build-lock');
  const deadline = Date.now() + ACQUIRE_TIMEOUT_MS;
  for (;;) {
    try {
      mkdirSync(lock);
      break;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err;
      try {
        if (Date.now() - statSync(lock).mtimeMs > STALE_LOCK_MS) {
          rmSync(lock, { recursive: true, force: true });
          continue;
        }
      } catch { /* the holder released it between the mkdir and the stat */ }
      if (Date.now() > deadline) {
        throw new Error(`#501: timed out waiting ${ACQUIRE_TIMEOUT_MS}ms for the build lock at ${lock}`);
      }
      sleepSync(POLL_MS);
    }
  }

  try {
    // Re-checked under the lock: the worker we queued behind may have been
    // building exactly what we wanted, in which case there is nothing to do.
    if (artefactsAreStale(spec)) execSync('npm run build:ts', { cwd: spec.repoRoot, stdio: 'ignore' });
  } finally {
    rmSync(lock, { recursive: true, force: true });
  }
}
