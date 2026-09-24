/**
 * The `shieldcortex vacuum` / `compact` help gate (#577).
 *
 * The command itself stays inline in `main()` — it is a dozen lines of pragma +
 * VACUUM and moving it buys nothing. The gate does not stay there: it is the
 * only thing standing between `vacuum --help` and a full rewrite of the
 * operator's database file, so it has to be reachable from a test that can prove
 * it holds. A test of a gate buried in `main()` can only grep the source, which
 * cannot tell a live gate from a dead one.
 */
import { helpGate } from './help-gate.js';

/**
 * Every flag `vacuum` honours (#577). It parses none itself — but it calls
 * `initDatabase()`, and `debugLog()` under it reads `--verbose`/`--debug`
 * straight out of `process.argv`, so a parser that rejected them would reject a
 * working invocation.
 */
export const VACUUM_FLAGS = ['--verbose', '--debug'] as const;

export const VACUUM_HELP = `Usage: shieldcortex vacuum

Compact the memory database, reclaiming the free pages left behind by deletes
(consolidate / prune free rows; only VACUUM shrinks the file on disk).
Alias: shieldcortex compact.

Options:
      --verbose, --debug   Print internal startup diagnostics on stderr
  -h, --help               Show this help and exit (compacts nothing)

Environment:
  CLAUDE_MEMORY_DB   Database file to compact (default ~/.shieldcortex/memories.db)
  SHIELDCORTEX_DEBUG=1   Same as --debug.
`;

/**
 * True when the caller must stop: usage has been printed (`--help`, exit 0) or
 * the arguments were rejected (exit 2). VACUUM rewrites the whole database file,
 * and `initDatabase()` migrates and backfills on the way in, so this has to be
 * answered before either happens.
 */
export function vacuumHelpRequested(
  args: readonly string[],
  deps: { log?: (message: string) => void; error?: (message: string) => void } = {},
): boolean {
  const gate = helpGate(args, VACUUM_HELP, { known: VACUUM_FLAGS, log: deps.log, error: deps.error });
  if (gate === null) return false;
  process.exitCode = gate;
  return true;
}
