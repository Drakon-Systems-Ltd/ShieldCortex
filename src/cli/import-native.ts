import { closeDatabase, initDatabase } from '../database/init.js';
import { flushPendingCloudSync } from '../cloud/sync.js';
import { awaitPendingEmbeddings } from '../memory/store.js';
import {
  importNativeMemories,
  resolveConfiguredNativeImportScope,
  type NativeImportOptions,
  type NativeImportResult,
} from '../memory/import-native.js';

export interface ParsedNativeImportArgs {
  options: NativeImportOptions;
  json: boolean;
}

const VALUE_FLAGS = new Set(['--host-id', '--agent-id', '--project']);
const BOOLEAN_FLAGS = new Set(['--apply', '--json']);

export function parseNativeImportArgs(args: string[]): ParsedNativeImportArgs {
  const values = new Map<string, string>();
  const seen = new Set<string>();
  const paths: string[] = [];
  let apply = false;
  let json = false;
  let positionalOnly = false;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (positionalOnly || !arg.startsWith('-')) {
      paths.push(arg);
      continue;
    }
    if (arg === '--') {
      positionalOnly = true;
      continue;
    }
    if (VALUE_FLAGS.has(arg)) {
      if (seen.has(arg)) throw new Error(`ambiguous repeated flag: ${arg}`);
      const value = args[++i];
      if (!value || value.startsWith('-')) throw new Error(`missing value for ${arg}`);
      if (!value.trim()) throw new Error(`${arg} must be nonempty`);
      seen.add(arg);
      values.set(arg, value.trim());
      continue;
    }
    if (BOOLEAN_FLAGS.has(arg)) {
      if (seen.has(arg)) throw new Error(`ambiguous repeated flag: ${arg}`);
      seen.add(arg);
      if (arg === '--apply') apply = true;
      else json = true;
      continue;
    }
    throw new Error(`unknown flag: ${arg}`);
  }
  if (paths.length === 0) throw new Error('at least one Markdown path is required');

  const configured = resolveConfiguredNativeImportScope();
  return {
    options: {
      paths,
      apply,
      hostId: values.get('--host-id') ?? configured.hostId,
      agentId: values.get('--agent-id') ?? configured.agentId,
      project: values.get('--project'),
    },
    json,
  };
}

function printUsage(): void {
  console.error('Usage: shieldcortex memories import-native <path...> [--apply] [options]');
  console.error('');
  console.error('Options:');
  console.error('  --apply             Admit through full defence and archive sources');
  console.error('  --host-id <id>      Required host scope (or configured memory scope)');
  console.error('  --agent-id <id>     Required agent scope (or configured memory scope)');
  console.error('  --project <project> Optional project scope');
  console.error('  --json              Emit stable machine-readable dispositions');
  console.error('  --                  Treat all remaining arguments as paths');
  console.error('');
  console.error('Dry-run is the default. Directories, globs, symlinks, and non-Markdown files are rejected.');
  console.error('Archiving is a hard link, so every source must live on the same filesystem as the');
  console.error('archive root (~/.shieldcortex/native-import-archive by default); a cross-filesystem');
  console.error('apply fails EXDEV and rolls the whole batch back.');
  console.error('A dry-run is not a prediction: --apply re-runs the full defence pipeline WITH side');
  console.error('effects, so cross-chunk signals can deny a batch that dry-ran clean.');
}

function printHuman(result: NativeImportResult): void {
  console.log(`${result.dryRun ? '[DRY RUN] ' : ''}Native import batch ${result.batchId}`);
  console.log(`Scope: host=${result.hostId} agent=${result.agentId} project=${result.project ?? '(none)'}`);
  for (const row of result.rows) {
    const id = row.memoryId !== undefined
      ? ` memory=#${row.memoryId}`
      : row.preservedMemoryId !== undefined
        ? ` preserved=#${row.preservedMemoryId}`
        : '';
    console.log(`${row.disposition}/${row.admissionKind ?? '-'}\t${row.sourcePath}#${row.chunkIndex}\t${row.contentHash}\t${row.defenceVerdict ?? '-'}${id}\t${row.reason}`);
  }
  for (const file of result.files) {
    if (file.archivePath) console.log(`archived\t${file.sourcePath}\t${file.archivePath}`);
  }
  if (result.applyPossible === false && result.applyBlockedReason) {
    console.error(`apply-impossible\t${result.applyBlockedReason}`);
  }
  if (result.error) console.error(`Import failed: ${result.error}`);
  else if (result.dryRun) {
    console.log(
      'No files or database rows changed. Re-run with --apply to admit and archive: apply re-runs the '
      + 'full defence pipeline with side effects, so this dry-run does not guarantee admission, and '
      + 'archival can still fail (the batch then rolls back).',
    );
  }
}

/**
 * Usage/parse failures still owe `--json` callers a parseable envelope. Read the
 * flag straight off the raw argv (stopping at `--`, where it would be a path),
 * because the parser that would have told us never got to run.
 */
function rawArgsRequestJson(args: string[]): boolean {
  for (const arg of args) {
    if (arg === '--') return false;
    if (arg === '--json') return true;
  }
  return false;
}

function envelope(
  options: { apply?: boolean; hostId?: string | null; agentId?: string | null; project?: string; batchId?: string },
  error: string,
): NativeImportResult {
  return {
    success: false,
    applied: false,
    dryRun: options.apply !== true,
    batchId: options.batchId ?? '',
    hostId: options.hostId ?? '',
    agentId: options.agentId ?? '',
    project: options.project ?? null,
    files: [],
    rows: [],
    archived: [],
    error,
  };
}

export async function runNativeImportCli(args: string[]): Promise<number> {
  let parsed: ParsedNativeImportArgs;
  try {
    parsed = parseNativeImportArgs(args);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (rawArgsRequestJson(args)) {
      console.log(JSON.stringify(envelope({ apply: args.includes('--apply') }, message)));
      return 2;
    }
    console.error(message);
    printUsage();
    return 2;
  }

  // Scope is rejected before database initialisation or any defence scan.
  if (!parsed.options.hostId || !parsed.options.agentId) {
    const result = envelope(
      parsed.options,
      'native import requires --host-id and --agent-id (or configured memory scope)',
    );
    if (parsed.json) console.log(JSON.stringify(result));
    else printHuman(result);
    return 2;
  }

  let initialized = false;
  let result: NativeImportResult;
  try {
    initDatabase();
    initialized = true;
    result = importNativeMemories(parsed.options);
  } catch (error) {
    result = envelope(parsed.options, error instanceof Error ? error.message : String(error));
  }

  if (initialized) {
    try {
      await awaitPendingEmbeddings();
      await flushPendingCloudSync(8000);
    } catch (error) {
      result = {
        ...result,
        success: false,
        error: [result.error, `post-import drain failed: ${error instanceof Error ? error.message : String(error)}`]
          .filter(Boolean)
          .join('; '),
      };
    } finally {
      try {
        closeDatabase();
      } catch (error) {
        result = {
          ...result,
          success: false,
          error: [result.error, `database close failed: ${error instanceof Error ? error.message : String(error)}`]
            .filter(Boolean)
            .join('; '),
        };
      }
    }
  }

  if (parsed.json) console.log(JSON.stringify(result));
  else printHuman(result);
  return result.success ? 0 : 1;
}

export async function handleNativeImportCommand(args: string[]): Promise<void> {
  process.exit(await runNativeImportCli(args));
}
