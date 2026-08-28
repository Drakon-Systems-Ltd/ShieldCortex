import { closeDatabase, initDatabase } from '../database/init.js';
import os from 'os';
import fs from 'fs';
import path from 'path';
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

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (!arg.startsWith('-')) {
      paths.push(arg);
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
  console.error('');
  console.error('Dry-run is the default. Directories, globs, symlinks, and non-Markdown files are rejected.');
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
    console.log(`${row.disposition}\t${row.sourcePath}#${row.chunkIndex}\t${row.contentHash}\t${row.defenceVerdict ?? '-'}${id}\t${row.reason}`);
  }
  for (const file of result.files) {
    if (file.archivePath) console.log(`archived\t${file.sourcePath}\t${file.archivePath}`);
  }
  if (result.error) console.error(`Import failed: ${result.error}`);
  else if (result.dryRun) console.log('No sources archived and no memories admitted. Re-run with --apply to admit and archive.');
}

function configuredMemoriesDbPath(): string | null {
  if (!process.env.SHIELDCORTEX_CONFIG_DIR) return null;
  return path.join(path.resolve(process.env.SHIELDCORTEX_CONFIG_DIR), 'memories.db');
}

function liveMemoriesDbPath(): string | null {
  const configured = configuredMemoriesDbPath();
  if (configured) return fs.existsSync(configured) ? configured : null;
  const candidates = [
    path.join(os.homedir(), '.shieldcortex', 'memories.db'),
    path.join(os.homedir(), '.claude-memory', 'memories.db'),
  ];
  return candidates.find((candidate) => fs.existsSync(candidate)) ?? null;
}

export async function runNativeImportCli(args: string[]): Promise<number> {
  let parsed: ParsedNativeImportArgs;
  try {
    parsed = parseNativeImportArgs(args);
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    printUsage();
    return 2;
  }

  // Scope is rejected before database initialisation or any defence scan.
  if (!parsed.options.hostId || !parsed.options.agentId) {
    const result: NativeImportResult = {
      success: false,
      applied: false,
      dryRun: parsed.options.apply !== true,
      batchId: '',
      hostId: parsed.options.hostId ?? '',
      agentId: parsed.options.agentId ?? '',
      project: parsed.options.project ?? null,
      files: [],
      rows: [],
      archived: [],
      error: 'native import requires --host-id and --agent-id (or configured memory scope)',
    };
    if (parsed.json) console.log(JSON.stringify(result));
    else printHuman(result);
    return 2;
  }

  let previewDir: string | undefined;
  const configuredDb = configuredMemoriesDbPath();
  const liveDb = liveMemoriesDbPath();
  if (parsed.options.apply === true) {
    initDatabase(configuredDb ?? liveDb ?? undefined);
  } else if (liveDb) {
    initDatabase(liveDb);
  } else {
    previewDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-395-preview-'));
    initDatabase(path.join(previewDir, 'preview.db'));
  }
  try {
    const result = importNativeMemories(parsed.options);
    if (parsed.json) console.log(JSON.stringify(result));
    else printHuman(result);
    return result.success ? 0 : 1;
  } finally {
    closeDatabase();
    if (previewDir) fs.rmSync(previewDir, { recursive: true, force: true });
  }
}

export async function handleNativeImportCommand(args: string[]): Promise<void> {
  process.exit(await runNativeImportCli(args));
}
