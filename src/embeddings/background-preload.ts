/**
 * Fire-and-forget model preload for the MCP server.
 *
 * Extracted from `src/index.ts` so the one judgement it makes — what counts as
 * a preload failure worth an operator instruction — can be driven directly by
 * a test. The server entry starts a real MCP server on import, so a catch
 * inline there is only reachable by running the whole server, which is how it
 * came to keep calling a clean shutdown a failure.
 */
import { preloadModel, isWorkerDisposedError } from './generator.js';

/**
 * Start loading the model in the background so the first tool call doesn't
 * hang. Never rejects: a preload failure is fine, searchMemories falls back to
 * FTS-only. Returns the promise so callers (and tests) can await the settle;
 * the server deliberately does not.
 */
export function startBackgroundPreload(): Promise<void> {
  // Host has switched embeddings off — nothing to preload, and nothing to say.
  if (process.env.SHIELDCORTEX_SKIP_EMBEDDINGS === '1') return Promise.resolve();

  return preloadModel().catch(err => {
    // Shutdown disposed the model while this preload was still loading — the
    // disposal doing its job, not a failure, and on a cold cache that window is
    // as wide as the model-load timeout. Sending an operator to `doctor` over a
    // clean shutdown is exactly the false alarm this work exists to remove.
    // Matched whole by the generator's classifier: the load timeout, the
    // timeout kill, a crash, or anything that merely mentions disposal is a
    // genuine failure and keeps the guidance below.
    if (isWorkerDisposedError(err)) return;
    // #383: worker quarantines a corrupt on-disk weight and retries once.
    // If we still land here, the heal did not recover — operator should run doctor.
    console.error(
      '[shieldcortex] Model preload failed (worker heals a corrupt cache at most once per process; run `shieldcortex doctor` if this repeats):',
      err instanceof Error ? err.message : err,
    );
  });
}
