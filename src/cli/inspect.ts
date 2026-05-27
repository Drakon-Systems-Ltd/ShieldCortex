/**
 * `shieldcortex inspect <subcommand>` (v4.25.0)
 *
 * Operator surface for the precompact ring buffer. Reads what the precompact
 * hook proposed during its last run(s), which proposals landed, and which
 * were dropped — useful when tuning thresholds or chasing weird auto-extract
 * behaviour.
 *
 * Subcommands:
 *   shieldcortex inspect last-precompact [--history N | --all]
 */

// ANSI colours — match doctor.ts conventions.
const bold = '\x1b[1m';
const reset = '\x1b[0m';
const green = '\x1b[32m';
const yellow = '\x1b[33m';
const red = '\x1b[31m';
const cyan = '\x1b[36m';
const dim = '\x1b[2m';

interface Candidate {
  extractorType?: string;
  category?: string;
  memoryPurpose?: string;
  title?: string;
  salience?: number;
  frequencyBoost?: number;
  saved?: boolean;
  error?: string | null;
}

interface PrecompactEntry {
  ranAt?: string;
  thresholdUsed?: number | null;
  contextFullnessPct?: number | null;
  totalMemories?: number | null;
  rawSegmentCount?: number;
  candidates?: Candidate[];
}

function parseFlag(args: string[], name: string): string | undefined {
  const idx = args.indexOf(name);
  if (idx === -1 || idx === args.length - 1) return undefined;
  return args[idx + 1];
}

function relativeTime(iso?: string): string {
  if (!iso) return '';
  const then = Date.parse(iso);
  if (!Number.isFinite(then)) return '';
  const deltaMs = Date.now() - then;
  const mins = Math.round(deltaMs / 60_000);
  if (mins < 1) return '(just now)';
  if (mins < 60) return `(${mins} min ago)`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `(${hours}h ago)`;
  const days = Math.round(hours / 24);
  return `(${days}d ago)`;
}

function printEntry(index: number, entry: PrecompactEntry) {
  const candidates = entry.candidates ?? [];
  const saved = candidates.filter((c) => c.saved);
  const dropped = candidates.filter((c) => !c.saved);

  console.log(`${bold}Slot ${index}: ${entry.ranAt ?? '(unknown time)'} ${dim}${relativeTime(entry.ranAt)}${reset}`);
  const thrLine = entry.thresholdUsed != null ? `threshold ${entry.thresholdUsed.toFixed(2)}` : 'threshold —';
  const fullLine = entry.contextFullnessPct != null
    ? `context ${entry.contextFullnessPct}% full`
    : 'context —';
  const memLine = entry.totalMemories != null ? `${entry.totalMemories} memories` : '';
  console.log(`  ${dim}${thrLine}, ${fullLine}${memLine ? ', ' + memLine : ''}${reset}`);
  console.log(`  Candidates: ${candidates.length} extracted${entry.rawSegmentCount != null ? ` (${entry.rawSegmentCount} raw segments)` : ''}, ${green}${saved.length} saved${reset}, ${dim}${dropped.length} dropped${reset}`);

  if (saved.length > 0) {
    console.log(`\n  ${green}SAVED${reset}`);
    for (const c of saved) {
      const sal = c.salience != null ? c.salience.toFixed(2) : '----';
      const boost = c.frequencyBoost && c.frequencyBoost > 0 ? ` ${dim}+${c.frequencyBoost.toFixed(2)}${reset}` : '';
      console.log(`    ${cyan}${(c.extractorType ?? '?').padEnd(15)}${reset} ${sal}${boost}  ${(c.title ?? '').slice(0, 70)}`);
      console.log(`    ${dim}  → category=${c.category ?? '?'}, purpose=${c.memoryPurpose ?? 'project'}${reset}`);
    }
  }

  if (dropped.length > 0) {
    console.log(`\n  ${red}DROPPED${reset}`);
    for (const c of dropped) {
      const sal = c.salience != null ? c.salience.toFixed(2) : '----';
      const err = c.error ? ` ${yellow}— ${c.error}${reset}` : '';
      console.log(`    ${dim}${(c.extractorType ?? '?').padEnd(15)} ${sal}${reset}  ${(c.title ?? '').slice(0, 70)}${err}`);
    }
  }
  console.log('');
}

async function cmdLastPrecompact(args: string[]): Promise<number> {
  const all = args.includes('--all');
  const historyArg = parseFlag(args, '--history');
  const historyIndex = historyArg !== undefined ? parseInt(historyArg, 10) : 0;

  const { readPrecompactLog, listPrecompactLogs, PRECOMPACT_RING_SIZE } =
    // @ts-expect-error — importing a .mjs hook util that has no .d.ts
    await import('../../scripts/lib/precompact-log.mjs');

  if (all) {
    const entries = listPrecompactLogs() as Array<{ index: number; entry: PrecompactEntry }>;
    if (entries.length === 0) {
      console.log(`${dim}No precompact runs logged yet. Trigger one via a /compact in Claude Code or wait for auto-compact.${reset}`);
      return 0;
    }
    console.log(`${bold}${entries.length} precompact run(s) in ring buffer${reset}\n`);
    for (const { index, entry } of entries) printEntry(index, entry);
    return 0;
  }

  if (!Number.isFinite(historyIndex) || historyIndex < 0 || historyIndex >= PRECOMPACT_RING_SIZE) {
    console.error(`--history must be 0..${PRECOMPACT_RING_SIZE - 1}. Got: ${historyArg ?? '<missing>'}`);
    return 2;
  }

  const entry = readPrecompactLog(historyIndex) as PrecompactEntry | null;
  if (!entry) {
    if (historyIndex === 0) {
      console.log(`${dim}No precompact runs logged yet. Trigger one via a /compact in Claude Code or wait for auto-compact.${reset}`);
    } else {
      console.log(`${dim}No precompact run at history slot ${historyIndex}.${reset}`);
    }
    return 0;
  }
  printEntry(historyIndex, entry);
  return 0;
}

function printHelp() {
  console.log('Usage: shieldcortex inspect <subcommand>');
  console.log('');
  console.log('Subcommands:');
  console.log('  last-precompact [--history N | --all]    Show extractor candidates from the last precompact run');
  console.log('                                           --history N (0=newest, up to 9) — show slot N');
  console.log('                                           --all — show every entry in the ring buffer (newest first)');
}

export async function handleInspectCommand(args: string[]): Promise<void> {
  const sub = args[0];
  let code = 0;
  switch (sub) {
    case 'last-precompact':
      code = await cmdLastPrecompact(args.slice(1));
      break;
    case undefined:
    case '--help':
    case '-h':
    case 'help':
      printHelp();
      break;
    default:
      console.error(`Unknown subcommand: inspect ${sub}`);
      printHelp();
      code = 2;
  }
  process.exit(code);
}
