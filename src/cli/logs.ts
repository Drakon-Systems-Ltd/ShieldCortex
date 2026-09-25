/**
 * `shieldcortex logs` — on-disk log maintenance CLI (issue #573).
 *
 * The sibling of `sessions prune` and `memories prune` for the one file plane
 * that had no retention at all: `logs/project-key-repair-*.json`. Same
 * conventions as src/cli/sessions.ts — dry-run by default with a `[DRY RUN]`
 * banner and a matched/acted summary, `--execute` to actually touch the disk.
 *
 * Unlike its siblings this one needs no database handle, so the command stays
 * usable on a host whose DB is at the hard size block — exactly the host that
 * needs it.
 *
 * SCOPE. The realtime audit ledger under `~/.shieldcortex/audit/` is NOT
 * managed here and this command says so rather than implying otherwise: it is
 * an unread queue with concurrent writers, a projector cursor and stop-hook
 * recovery reading it, and bounding it safely is a separate piece of work
 * (#579).
 */

import path from 'path';
import { helpGate } from './help-gate.js';
import {
  DEFAULT_REPAIR_LOG_KEEP,
  defaultRepairLogDir,
  pruneRepairLogs,
  type RepairLogPruneResult,
} from '../logs/retention.js';

/** Cap on the itemised listing — a pre-fix host has thousands. */
const MAX_LISTED = 8;

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

export function renderRepairLogPrune(
  result: RepairLogPruneResult,
  log: (line: string) => void = console.log,
): void {
  const banner = result.dryRun ? '[DRY RUN] ' : '';
  log(`${banner}Repair-log retention — project-key-repair-*.json`);
  log(`  Directory: ${result.dir}`);

  if (result.refused !== null) {
    // Not merely a no-op: the plane was deliberately not examined. Saying
    // "would delete 0" here would read as "nothing to do".
    log(`  Refused — ${result.refused}`);
    log('  Nothing was read, written or removed.');
    for (const warning of result.warnings) log(`  ⚠ ${warning}`);
    return;
  }

  log(
    `  Matched: ${result.matched} file${result.matched === 1 ? '' : 's'} · ` +
    `${formatBytes(result.bytesBefore)} · ${result.databases} database${result.databases === 1 ? '' : 's'}`,
  );
  log(
    `  ${result.dryRun ? 'Would delete' : 'Deleted'}: ${result.deleted.length} · ` +
    `kept: ${result.kept} (newest ${result.keep} per database)`,
  );
  for (const deletion of result.deleted.slice(0, MAX_LISTED)) {
    log(
      `      ${result.dryRun ? 'would delete' : 'deleted'} ` +
      `${path.basename(deletion.path)} (${formatBytes(deletion.bytes)})`,
    );
  }
  if (result.deleted.length > MAX_LISTED) {
    log(`      … and ${result.deleted.length - MAX_LISTED} more`);
  }
  log(`  ${result.dryRun ? 'Would free' : 'Freed'}: ${formatBytes(result.freedBytes)}`);
  if (result.tooYoung > 0) {
    log(
      `  Kept ${result.tooYoung} past the bound for being under an hour old ` +
      '(a repair may still be writing one).',
    );
  }
  for (const warning of result.warnings) log(`  ⚠ ${warning}`);
  for (const err of result.errors) log(`  ✗ ${err}`);
  if (result.dryRun && result.deleted.length > 0) {
    log('  Re-run with --execute to apply.');
  }
}

export interface LogsPruneDeps {
  /** Defaults to `~/.shieldcortex/logs`. Injectable for tests. */
  dir?: string;
  env?: NodeJS.ProcessEnv;
  log?: (line: string) => void;
}

/** Run `logs prune [--execute]`. */
export async function runLogsPrune(
  args: string[],
  deps: LogsPruneDeps = {},
): Promise<RepairLogPruneResult> {
  const result = pruneRepairLogs({
    dir: deps.dir ?? defaultRepairLogDir(),
    execute: args.includes('--execute'),
    env: deps.env,
  });
  renderRepairLogPrune(result, deps.log);
  return result;
}

/** The help text, as lines, so it can be asserted without capturing stdout. */
export function logsUsageLines(): string[] {
  return [
    'Usage: shieldcortex logs <subcommand> [options]',
    '',
    'Subcommands:',
    '  prune [--execute]',
    '      Keep only the newest project-key-repair-*.json logs under',
    '        ~/.shieldcortex/logs/',
    '      DRY-RUN BY DEFAULT — prints exactly what --execute would do.',
    '',
    '      These are diagnostics written by `memories repair-project-keys`.',
    '      They have no reader and are not security evidence, so retention is',
    '      just "keep the newest N": an unlink of a regular file, with no',
    '      rewrite, no rename and no temporary file.',
    '',
    '      The bound is PER DATABASE — each record names the one it describes,',
    '      and a logs directory can hold records for several, because the log',
    '      is written beside the database it repaired. A record written in the',
    '      LAST HOUR is never deleted, whatever the keep count says, so a log a',
    '      repair is still writing is never a candidate; it becomes one on the',
    '      next run. Only the exact name a repair writes is ever touched, only',
    '      directly in the logs directory, only regular files with a single hard',
    '      link. The directory is fully resolved before anything is listed: a',
    '      symlinked logs path, or one resolving inside the realtime audit',
    '      ledger, refuses the whole pass and reports why.',
    '',
    '      NOT MANAGED YET: the realtime audit logs under',
    '      ~/.shieldcortex/audit/ have no retention. They are an unread queue',
    '      with concurrent writers, a projector cursor and stop-hook recovery',
    '      reading them, so bounding them safely is separate work — tracked in',
    '      #579. This command never reads, writes or removes an audit file.',
    '',
    'Environment:',
    `  SHIELDCORTEX_REPAIR_LOG_KEEP   newest repair logs kept PER DATABASE`,
    `                                 (default ${DEFAULT_REPAIR_LOG_KEEP}, whole number of at least 1;`,
    '                                 anything else is refused with a warning',
    '                                 and the default is used)',
  ];
}

/**
 * Everything `shieldcortex logs` accepts — the verb included, because the
 * shared gate checks whole tokens (#577). An exhaustive list is what lets the
 * strict preflight in `src/cli/strict-args-preflight.ts` reject `--exectue`
 * BEFORE `main()` shells out to `npm ls -g`.
 */
export const LOGS_FLAGS = ['prune', '--execute'] as const;

/**
 * The command's GRAMMAR, which token membership cannot express: exactly one
 * `prune`, then at most `--execute`.
 *
 * `logs prune prune --execute` passed the allow-list — every token is known —
 * so the second verb was silently ignored and the deletion ran under HOME
 * (round-2 blocker 5). An argument we do not understand must be a usage error,
 * not a token we drop on the floor on the way to unlinking files.
 *
 * Returns the error to print, or null when the line is valid.
 */
export function logsUsageError(args: readonly string[]): string | null {
  if (args.length === 0) return 'Missing subcommand.';
  if (args[0] !== 'prune') return `Unknown subcommand: ${args[0]}`;
  const rest = args.slice(1);
  if (rest.length > 1 || (rest.length === 1 && rest[0] !== '--execute')) {
    return `\`logs prune\` takes at most --execute; got: ${rest.join(' ')}`;
  }
  return null;
}

/** The same usage text, as one string, for the shared gate. */
export const LOGS_HELP = logsUsageLines().join('\n');

export async function handleLogsCommand(args: string[]): Promise<void> {
  // The shared #577 gate decides both questions: a help flag ANYWHERE prints
  // usage and exits 0 without running anything (`logs prune --execute --help`
  // must not delete), and an unknown token exits 2 with usage on stderr —
  // the same code and the same convention as `update --bogus`. The preflight
  // in main() has already reached this verdict on the same table; running it
  // again here is the same answer, not a second, divergent one.
  const gate = helpGate(args, LOGS_HELP, { command: 'logs', known: LOGS_FLAGS });
  if (gate !== null) {
    process.exitCode = gate;
    return;
  }
  const usage = logsUsageError(args);
  if (usage !== null) {
    process.stderr.write(`${usage}\n\n${LOGS_HELP}\n`);
    process.exitCode = 2;
    return;
  }
  try {
    const result = await runLogsPrune(args.slice(1));
    // A refusal examined nothing and a fault deleted less than it planned to;
    // either way the plane is not bounded and a script must be able to see
    // that. A rejected keep value is not in this set: the pass did its whole
    // job, at the default, and said so.
    if (result.refused !== null || result.errors.length > 0) process.exitCode = 1;
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
  }
}
