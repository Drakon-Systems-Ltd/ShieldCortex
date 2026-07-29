/**
 * Debug gate for internal diagnostic logging.
 *
 * Startup diagnostics (database runtime state, restore-point paths, …) are
 * invaluable when a support thread is open and pure noise the rest of the time.
 * Before v4.47.17 they were printed unconditionally, so the very first thing a
 * new user saw from `remember`/`scan` was a `[database] Startup runtime=…` line
 * and an internal `.pre-backfill-…` path — internal state leaking into user
 * output on a healthy install (#129).
 *
 * Everything routed through `debugLog()` is silent by default and restored by
 * either `SHIELDCORTEX_DEBUG` or a `--verbose` / `--debug` flag on the command
 * line. Output always goes to stderr, never stdout: the MCP stdio transport
 * owns stdout and a stray byte there closes the connection.
 */

const FALSY = /^(0|false|no|off)$/i;

/**
 * True when internal diagnostics should be printed.
 *
 * `--verbose` / `--debug` on the command line always wins — the documented
 * "show me everything" escape hatch must not be defeated by an inherited
 * `SHIELDCORTEX_DEBUG=0` in the environment.
 */
export function isDebugLoggingEnabled(
  env: NodeJS.ProcessEnv = process.env,
  argv: readonly string[] = process.argv,
): boolean {
  if (argv.includes('--verbose') || argv.includes('--debug')) return true;
  const raw = (env.SHIELDCORTEX_DEBUG ?? '').trim();
  if (raw === '') return false;
  return !FALSY.test(raw);
}

/**
 * Print an internal diagnostic line — stderr, and only when debug/verbose is on.
 */
export function debugLog(...args: unknown[]): void {
  if (!isDebugLoggingEnabled()) return;
  console.error(...args);
}
