/**
 * `shieldcortex remember "<title>" --content "<text>" [options]` (Phase 15c)
 *
 * A real, non-hanging CLI write command. The historical gotcha — "remember CLI
 * hangs, avoid until fixed" — was that no such subcommand existed; any lookalike
 * path blocked on a stdio/TTY transport. This command writes a memory directly
 * through the SAME store path the MCP `remember` tool uses (executeRemember), so
 * the defence pipeline + project scoping + dedupe all apply, then EXITS cleanly.
 *
 * Anti-hang contract: content comes from `--content`, else from PIPED stdin.
 * If neither is present (an interactive TTY with no flag), we print usage and
 * exit non-zero rather than blocking on a read that would never resolve.
 *
 * Layering:
 *   - `runRemember` is the pure core: takes resolved options, returns a
 *     structured result. No argv, no process.exit, no stdin — fully testable.
 *   - `resolveRememberContent` isolates the stdin/TTY decision so the anti-hang
 *     behaviour can be asserted without a real terminal.
 *   - `handleRememberCommand` is the thin CLI wrapper: parse argv, resolve
 *     content, run, print, drain cloud sync, close DB, exit.
 */

import { executeRemember, type RememberInput } from '../tools/remember.js';
import { closeDatabase, initDatabase } from '../database/init.js';

type Importance = 'low' | 'medium' | 'high';

export interface RememberOptions {
  title: string;
  content: string;
  category?: string;
  importance?: Importance;
  tags?: string[];
  project?: string;
  /** Flat source type — defaults to a `cli` source so interactive writes stay uncapped. */
  sourceType?: RememberInput['sourceType'];
  sourceIdentifier?: string;
}

export interface RememberResult {
  success: boolean;
  memory?: { id: number; title: string; salience: number; type: string; category: string };
  error?: string;
}

// CLI importance vocabulary → the MCP tool's importance scale. The CLI exposes
// the friendlier low/medium/high; the tool maps low:0.3, normal:0.5, high:0.8.
const IMPORTANCE_TO_TOOL: Record<Importance, NonNullable<RememberInput['importance']>> = {
  low: 'low',
  medium: 'normal',
  high: 'high',
};

/**
 * Pure write core. Delegates entirely to executeRemember so the defence
 * pipeline, project auto-scoping, dedupe and salience handling are reused
 * verbatim — there is no second implementation to drift.
 */
export async function runRemember(opts: RememberOptions): Promise<RememberResult> {
  const input: RememberInput = {
    title: opts.title,
    content: opts.content,
    category: opts.category as RememberInput['category'],
    importance: opts.importance ? IMPORTANCE_TO_TOOL[opts.importance] : undefined,
    tags: opts.tags,
    project: opts.project,
    // Default to a `cli` source. addMemory only runs the trust/defence pipeline
    // when a source is present, so passing one ensures malicious content is
    // actually scanned (and a `cli` source stays uncapped, unlike `hook`).
    sourceType: opts.sourceType ?? 'cli',
    sourceIdentifier: opts.sourceIdentifier ?? 'shieldcortex-remember-cli',
  };

  const result = await executeRemember(input);

  if (!result.success) {
    return { success: false, error: result.error };
  }

  const m = result.memory!;
  return {
    success: true,
    memory: { id: m.id, title: m.title, salience: m.salience, type: m.type, category: m.category },
  };
}

/**
 * Resolve the memory content from the flag or piped stdin WITHOUT ever blocking
 * on a TTY. `readStdin` is injected so this is unit-testable.
 *
 * Precedence: explicit --content > piped stdin > usage error.
 */
export async function resolveRememberContent(args: {
  contentFlag: string | undefined;
  isTTY: boolean;
  readStdin: () => Promise<string>;
}): Promise<{ ok: true; content: string } | { ok: false; usage: boolean }> {
  if (args.contentFlag !== undefined) {
    return { ok: true, content: args.contentFlag };
  }
  // No --content. Only read stdin if it is actually piped — never on a TTY,
  // which would hang waiting for input that never comes. THIS is the anti-hang.
  if (!args.isTTY) {
    const piped = await args.readStdin();
    return { ok: true, content: piped };
  }
  return { ok: false, usage: true };
}

/** Read all of process.stdin to EOF. Only called when stdin is piped. */
function readPipedStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf-8');
    process.stdin.on('data', (chunk) => {
      data += chunk;
    });
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
}

function parseFlag(args: string[], name: string): string | undefined {
  const idx = args.indexOf(name);
  if (idx === -1 || idx === args.length - 1) return undefined;
  return args[idx + 1];
}

function printUsage(): void {
  console.error('Usage: shieldcortex remember "<title>" --content "<text>" [options]');
  console.error('       echo "<text>" | shieldcortex remember "<title>"');
  console.error('');
  console.error('Options:');
  console.error('  --content <text>          Memory content (or pipe it via stdin)');
  console.error('  --category <category>     architecture|pattern|preference|error|context|');
  console.error('                            learning|todo|note|relationship|custom');
  console.error('  --importance <level>      low | medium | high');
  console.error('  --tags <a,b,c>            Comma-separated tags');
  console.error('  --project <name>          Project scope (auto-detected if omitted)');
  console.error('  --json                    Emit a structured JSON result');
}

/**
 * CLI entry point. Parses argv, resolves content (flag or piped stdin, never a
 * TTY block), runs the write, prints a concise human or --json result, drains
 * any in-flight cloud sync, closes the DB to release handles, and exits.
 */
export async function handleRememberCommand(args: string[]): Promise<void> {
  const json = args.includes('--json');

  // First positional (not a flag, not a flag value) is the title.
  let title: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith('--')) {
      // Skip the value of value-taking flags so it can't be misread as the title.
      if (['--content', '--category', '--importance', '--tags', '--project'].includes(a)) i++;
      continue;
    }
    title = a;
    break;
  }

  if (!title) {
    printUsage();
    process.exit(2);
  }

  const importanceRaw = parseFlag(args, '--importance');
  let importance: Importance | undefined;
  if (importanceRaw !== undefined) {
    if (importanceRaw === 'low' || importanceRaw === 'medium' || importanceRaw === 'high') {
      importance = importanceRaw;
    } else {
      console.error(`Invalid --importance "${importanceRaw}". Use: low | medium | high.`);
      process.exit(2);
    }
  }

  const resolved = await resolveRememberContent({
    contentFlag: parseFlag(args, '--content'),
    isTTY: Boolean(process.stdin.isTTY),
    readStdin: readPipedStdin,
  });

  if (!resolved.ok) {
    console.error('No content provided. Pass --content "<text>" or pipe text via stdin.');
    console.error('');
    printUsage();
    process.exit(2);
  }

  const tagsRaw = parseFlag(args, '--tags');
  const tags = tagsRaw
    ? tagsRaw.split(',').map((t) => t.trim()).filter(Boolean)
    : undefined;

  // Initialise the DB explicitly — executeRemember assumes an initialised store.
  initDatabase();

  let exitCode = 0;
  try {
    const result = await runRemember({
      title,
      content: resolved.content,
      category: parseFlag(args, '--category'),
      importance,
      tags,
      project: parseFlag(args, '--project'),
    });

    if (json) {
      console.log(JSON.stringify(result));
    } else if (result.success && result.memory) {
      const m = result.memory;
      console.log(`Remembered "${m.title}" (id ${m.id}, ${m.category}, salience ${(m.salience * 100).toFixed(0)}%).`);
    } else {
      console.error(`Not remembered: ${result.error ?? 'unknown error'}`);
    }

    exitCode = result.success ? 0 : 1;
  } finally {
    // Clean exit — release any open handles so the process does not linger.
    try {
      const { flushPendingCloudSync } = await import('../cloud/sync.js');
      await flushPendingCloudSync(8000);
    } catch {
      // Cloud sync drain is best-effort; never block exit on it.
    }
    closeDatabase();
  }

  process.exit(exitCode);
}
