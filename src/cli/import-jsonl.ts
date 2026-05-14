/**
 * CLI handler: `shieldcortex import-jsonl <path-or-glob>`
 *
 * Globs are expanded by Node's `fs.glob` (Node 22+) when the argument
 * contains wildcards. A literal path that doesn't contain `*` or `?`
 * is treated as a single file. Default glob if no argument is given:
 * `~/.claude/projects/&#42;&#42;/&#42;.jsonl` — the user's existing transcripts.
 *
 * Initialises the DB before importing so the call works from any cwd
 * (the importer relies on the singleton `getDatabase()`).
 */

import { homedir } from 'os';
import { join } from 'path';
import { existsSync } from 'fs';
import { expandGlob, isGlobPattern } from '../sessions/glob.js';

export async function handleImportJsonlCommand(args: readonly string[]): Promise<void> {
  if (args.includes('--help') || args.includes('-h')) {
    printHelp();
    return;
  }

  const argPath = args[0];
  const target = argPath ?? join(homedir(), '.claude', 'projects', '**', '*.jsonl');

  // Init DB first so the importer can use the singleton handle.
  const { initDatabase } = await import('../database/init.js');
  const dbPath =
    process.env.CLAUDE_MEMORY_DB ?? join(homedir(), '.shieldcortex', 'memories.db');
  initDatabase(dbPath);

  const { importJsonlTranscript } = await import('../sessions/import-jsonl.js');

  const files = await resolveFiles(target);
  if (files.length === 0) {
    console.error(`No JSONL files matched: ${target}`);
    process.exit(1);
  }

  console.log(`Importing ${files.length} JSONL file${files.length === 1 ? '' : 's'}…\n`);

  let totalEvents = 0;
  let totalSkipped = 0;
  let totalMalformed = 0;
  let imported = 0;
  let failed = 0;

  for (const file of files) {
    try {
      const result = importJsonlTranscript(file);
      totalEvents += result.eventCount;
      totalSkipped += result.skipped;
      totalMalformed += result.malformed;
      imported++;
      console.log(
        `  ✓ ${file}\n    session=${result.sessionId ?? '(unknown)'} events=${result.eventCount} skipped=${result.skipped}${result.malformed > 0 ? ` malformed=${result.malformed}` : ''}`,
      );
    } catch (err) {
      failed++;
      console.error(`  ✗ ${file}\n    ${(err as Error).message}`);
    }
  }

  console.log(
    `\nDone. ${imported}/${files.length} file${files.length === 1 ? '' : 's'} imported, ` +
      `${totalEvents} event${totalEvents === 1 ? '' : 's'} (${totalSkipped} skipped${totalMalformed > 0 ? `, ${totalMalformed} malformed` : ''})` +
      `${failed > 0 ? `, ${failed} failed` : ''}.`,
  );

  if (failed > 0 && imported === 0) process.exit(1);
}

function printHelp(): void {
  console.log(`Usage: shieldcortex import-jsonl [path-or-glob]

Import Claude Code session transcripts (JSONL) into session_events so they
become replayable in the dashboard. Idempotent: re-importing the same file
adds no duplicate rows.

Arguments:
  path-or-glob    File path or glob pattern. Defaults to
                  ~/.claude/projects/**/*.jsonl

Examples:
  shieldcortex import-jsonl                                 # all sessions
  shieldcortex import-jsonl ~/.claude/projects/my-proj/*.jsonl
  shieldcortex import-jsonl ./session.jsonl
`);
}

async function resolveFiles(target: string): Promise<string[]> {
  if (!isGlobPattern(target)) {
    if (!existsSync(target)) return [];
    return [target];
  }
  return expandGlob(target).sort();
}
