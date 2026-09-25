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
import { commandWantsHelp } from './wants-help.js';
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
    for (const err of result.errors) log(`  ⚠ ${err}`);
    return;
  }

  log(`  Matched: ${result.matched} file${result.matched === 1 ? '' : 's'} · ${formatBytes(result.bytesBefore)}`);
  log(
    `  ${result.dryRun ? 'Would delete' : 'Deleted'}: ${result.deleted.length} · ` +
    `kept: ${result.kept} (newest ${result.keep})`,
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
  for (const err of result.errors) log(`  ⚠ ${err}`);
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
    '      rewrite, no rename and no temporary file. Only that exact name is',
    '      ever touched, only directly in the logs directory, and a logs path',
    '      reachable through a symlink refuses the whole pass.',
    '',
    '      NOT MANAGED YET: the realtime audit logs under',
    '      ~/.shieldcortex/audit/ have no retention. They are an unread queue',
    '      with concurrent writers, a projector cursor and stop-hook recovery',
    '      reading them, so bounding them safely is separate work — tracked in',
    '      #579. This command never reads, writes or removes an audit file.',
    '',
    'Environment:',
    `  SHIELDCORTEX_REPAIR_LOG_KEEP   newest repair logs kept (default ${DEFAULT_REPAIR_LOG_KEEP},`,
    '                                 whole number of at least 1; anything else',
    '                                 is refused with a warning and the default',
    '                                 is used)',
  ];
}

export async function handleLogsCommand(args: string[]): Promise<void> {
  // A help request prints the usage and SUCCEEDS (#515): asking what a command
  // is going to do must never be answered with an error, and must never run
  // the command. Bare `logs` with no subcommand is still a usage error and
  // exits 1, exactly as `sessions` does.
  //
  // #577: the help flag counts ANYWHERE on the line, through the shared gate —
  // `logs prune --execute --help` must print usage, not delete logs.
  if (commandWantsHelp('logs', args)) {
    for (const line of logsUsageLines()) console.log(line);
    return;
  }
  if (args[0] === 'prune') {
    // #577: unknown flags are refused before anything touches the disk, so a
    // typo such as `--exectue` is an error, not a silent dry run, and a
    // misspelt `--help` is never mistaken for consent to delete.
    const unknown = args.slice(1).filter((a) => a !== '--execute');
    if (unknown.length > 0) {
      console.error(`Unknown option for 'logs prune': ${unknown.join(' ')}`);
      for (const line of logsUsageLines()) console.error(line);
      process.exit(1);
    }
    try {
      await runLogsPrune(args.slice(1));
    } catch (err) {
      console.error(err instanceof Error ? err.message : String(err));
      process.exit(1);
    }
    return;
  }
  for (const line of logsUsageLines()) console.log(line);
  process.exit(1);
}
