/**
 * `shieldcortex sessions` — session-capture maintenance CLI (issue #110).
 *
 * session_events is append-only turn capture (src/sessions/capture.ts) with,
 * until #110, no deletion path at all — live incident data showed it carrying
 * a DB to 79.6 MB with only 117 memories. `sessions prune` is the manual
 * valve alongside the brain worker's automatic retention: dry-run by default
 * (prints matched count + payload MB), `--execute` to delete. Follows the
 * `memories prune` conventions (src/cli/migrate-legacy.ts runPrune): same
 * flag parsing, same [DRY RUN] banner + Matched/Deleted output shape, same
 * initDatabase() startup (which owns the "[database] Another ShieldCortex
 * process ..." single-writer behaviour).
 */

function flagValue(args: string[], name: string): string | undefined {
  const idx = args.indexOf(name);
  if (idx === -1) return undefined;
  const v = args[idx + 1];
  if (!v || v.startsWith('--')) return undefined;
  return v;
}

/**
 * Run `sessions prune [--days N] [--execute]`.
 *
 * `dbPathOverride` is injectable for tests; production callers omit it and
 * initDatabase() resolves the standard ~/.shieldcortex/memories.db path.
 * Throws on invalid input (the command wrapper turns that into exit 1).
 */
export async function runSessionsPrune(args: string[], dbPathOverride?: string): Promise<void> {
  const { initDatabase } = await import('../database/init.js');
  const {
    resolveSessionRetentionDays,
    previewOldSessionEvents,
    purgeSessionEventsOlderThan,
  } = await import('../sessions/retention.js');

  initDatabase(dbPathOverride);

  const dryRun = !args.includes('--execute');
  const rawDays = flagValue(args, '--days');
  let days: number;
  if (rawDays === undefined) {
    days = resolveSessionRetentionDays();
  } else {
    days = Number(rawDays);
    // #114: `--days 0` is DELIBERATELY allowed here even though
    // resolveSessionRetentionDays()'s SHIELDCORTEX_SESSION_RETENTION_DAYS
    // floor is 1 (MIN_RETENTION_DAYS in retention.ts) — this is a manual,
    // operator-invoked escape hatch for "purge everything now" (e.g.
    // clearing a poisoned/oversized table), not an unattended background
    // knob. Dry-run-by-default is the mitigation: `--days 0 --execute` still
    // requires an explicit second flag to actually delete.
    if (!Number.isInteger(days) || days < 0) {
      throw new Error(`--days expects a non-negative integer, got '${rawDays}'`);
    }
  }

  const preview = previewOldSessionEvents(days);
  const payloadMb = preview.payloadBytes / (1024 * 1024);

  const banner = dryRun ? '[DRY RUN] ' : '';
  console.log(`${banner}Prune session_events older than ${days}d (ts < ${preview.cutoffIso})`);
  console.log(`  Matched: ${preview.matched} event${preview.matched === 1 ? '' : 's'} · ~${payloadMb.toFixed(1)} MB payload`);

  if (dryRun) {
    if (preview.matched > 0) {
      console.log('  Re-run with --execute to delete.');
    }
    return;
  }

  // Delete against the SAME cutoff the preview reported, so the printed
  // matched/deleted numbers can only differ by rows written in between.
  const deleted = purgeSessionEventsOlderThan(preview.cutoffIso);
  console.log(`  Deleted: ${deleted}`);
  if (deleted > 0) {
    console.log('  Freed rows leave free pages inside the DB file — run `shieldcortex vacuum` to shrink it on disk.');
  }
}

function printUsage(): void {
  console.log('Usage: shieldcortex sessions <subcommand> [options]');
  console.log('');
  console.log('Subcommands:');
  console.log('  prune [--days 30] [--execute]');
  console.log('      Delete session-capture events (session_events) older than N days.');
  console.log('      DRY-RUN BY DEFAULT — prints matched count + payload MB; pass');
  console.log('      --execute to actually delete, then run `shieldcortex vacuum` to');
  console.log('      reclaim the file space. Default window: 30 days, overridable via');
  console.log('      the SHIELDCORTEX_SESSION_RETENTION_DAYS env var (1-3650). --days 0 is');
  console.log('      allowed as a manual "purge everything now" escape hatch, even though');
  console.log('      the env var floor is 1 — dry-run-by-default is the guard rail.');
}

export async function handleSessionsCommand(args: string[]): Promise<void> {
  const sub = args[0];
  if (sub === 'prune') {
    try {
      await runSessionsPrune(args.slice(1));
    } catch (err) {
      console.error(err instanceof Error ? err.message : String(err));
      process.exit(1);
    }
    return;
  }
  printUsage();
  process.exit(1);
}
