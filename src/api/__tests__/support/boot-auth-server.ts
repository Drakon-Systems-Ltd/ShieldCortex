/**
 * Test-only entry point: boot the REAL API server in a child process (#474).
 *
 * `startVisualizationServer()` returns `void` — it owns the http server, a
 * WebSocket server, two BrainWorker interval timers and process-level SIGTERM
 * handlers, and calls `process.exit` on a listen error. There is no handle to
 * close, so it cannot be booted inside a Jest worker without leaking all of
 * that into the worker for the rest of the run. A child process is the honest
 * way to exercise the real middleware stack: the parent picks a free port,
 * hands over an isolated HOME/config/db, probes over the wire, then kills it.
 *
 * Not compiled into the published build — `tsconfig.build.json` excludes every
 * `__tests__` directory under `src`. Run it with `tsx` so what boots is the
 * current source rather than whatever the last build left behind.
 *
 * argv[2] = database path. PORT / HOME / SHIELDCORTEX_CONFIG_DIR come from the
 * environment the parent hands over.
 */
import { startVisualizationServer } from '../../visualization-server.js';

const dbPath = process.argv[2];
if (!dbPath) {
  console.error('usage: boot-auth-server.ts <dbPath>');
  process.exit(64);
}

startVisualizationServer(dbPath);
