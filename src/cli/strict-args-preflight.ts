/**
 * Validate the strict-parser subcommands BEFORE anything else runs (#577).
 *
 * `main()` opens with `checkVersionStaleness()`, which shells out to
 * `npm ls -g`. npm's own update-notifier can then reach the registry and write
 * `~/.npm/_logs` — so `shieldcortex update --bogus` spawned a child process and
 * left files under the operator's HOME on its way to exit 2. "Invalid arguments
 * have no side effects" has to mean no side effects at all, not "none after the
 * preamble we happened to run first".
 *
 * The gate each command already owns is pure — it reads no files and opens no
 * sockets — so running it here costs a module import and nothing else. The
 * command modules stay lazily imported: only the one actually named is loaded.
 */
import { helpGate } from './help-gate.js';
import { isGatedCommand, type GatedCommand } from './wants-help.js';

/**
 * Commands whose arguments are an exhaustive allow-list.
 *
 * Keyed by `GatedCommand`, so a strict command that is not in the shared help
 * registry is a compile error rather than a gate that silently reaches its
 * verdict from an empty table (#577 round 3).
 */
const STRICT_COMMANDS: Partial<Record<GatedCommand, () => Promise<{ known: readonly string[]; help: string }>>> = {
  update: async () => {
    const m = await import('./update.js');
    return { known: m.UPDATE_FLAGS, help: m.UPDATE_HELP };
  },
  repair: async () => {
    const m = await import('./repair.js');
    return { known: m.REPAIR_FLAGS, help: m.REPAIR_HELP };
  },
  migrate: async () => {
    const m = await import('../setup/migrate.js');
    return { known: m.MIGRATE_FLAGS, help: m.MIGRATE_HELP };
  },
  uninstall: async () => {
    const m = await import('../setup/uninstall.js');
    return { known: m.UNINSTALL_FLAGS, help: m.UNINSTALL_HELP };
  },
  vacuum: async () => {
    const m = await import('./vacuum.js');
    return { known: m.VACUUM_FLAGS, help: m.VACUUM_HELP };
  },
  // #573: `logs prune --execute` deletes files, and its whole argument surface
  // is two tokens — so it belongs here rather than in the help-only group.
  // Without it, `logs prune --execute --exectue` exited 1 only AFTER the npm
  // staleness subprocess had written ~/.npm/_logs and update-notifier state.
  logs: async () => {
    const m = await import('./logs.js');
    return { known: m.LOGS_FLAGS, help: m.LOGS_HELP };
  },
};
STRICT_COMMANDS.compact = STRICT_COMMANDS.vacuum; // documented alias

/**
 * The exit code `main()` must stop on — 0 when usage was printed, 2 when an
 * argument was rejected — or `null` when this is not a strict command, or its
 * arguments are fine and dispatch should continue as normal.
 *
 * `argv` is `process.argv.slice(2)`: the subcommand word and everything after.
 * The dispatcher still runs each command's own gate afterwards; this is the
 * same verdict taken earlier, not a second, divergent one.
 */
export async function preflightStrictArgs(
  argv: readonly string[],
  deps: { log?: (message: string) => void; error?: (message: string) => void } = {},
): Promise<0 | 2 | null> {
  const command = argv[0] ?? '';
  if (!isGatedCommand(command)) return null;
  const load = STRICT_COMMANDS[command];
  if (!load) return null;
  const { known, help } = await load();
  return helpGate(argv.slice(1), help, { command, known, log: deps.log, error: deps.error });
}
