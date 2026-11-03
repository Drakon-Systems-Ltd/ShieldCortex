/**
 * #777 — the top-level `shieldcortex --help` COMMANDS block lists every command
 * `main()` dispatches, and nothing it does not.
 *
 * Observed after #767: the block omitted 18 dispatched commands (update, repair,
 * env, xray, threat-graph, consolidate, deny, lease, freeze, stats, api, …),
 * `memories` listed only `import-native`, and `hook` was described as
 * "Manage hooks (start, stop, status)" although `hook <name>` runs one hook by
 * name.
 *
 * The expected entries are DERIVED from the dispatcher registry: every command
 * with a help spec in `COMMAND_HELP_SPECS` (which includes all of
 * `DISPATCH_HELP`), plus the commands whose handler owns its help gate, minus
 * the aliases. A tripwire pins that union to the command words `main()`
 * actually dispatches on (the same `process.argv[2] === '<word>'` derivation
 * the #767 suite uses), so a new command fails here until it is both gated and
 * listed in the top-level help.
 *
 * The block is read from src/index.ts, as the #708 vocabulary suite does; the
 * printed text is that template with colour codes substituted.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from '@jest/globals';
import { DISPATCH_HELP } from '../cli/dispatch-help.js';
import { COMMAND_HELP_SPECS } from '../cli/wants-help.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const indexSrc = fs.readFileSync(path.join(repoRoot, 'src', 'index.ts'), 'utf-8');

/** Dispatched commands that answer `--help` inside their own handler and have no registry spec. */
const HANDLER_ONLY: readonly string[] = [
  'doctor', 'setup', 'install', 'maintain', 'policy-evidence', 'import-jsonl', 'ledger', 'mcp',
];

/** Alias -> the command it shares a spec with. Aliases get no entry of their own. */
const ALIASES: Readonly<Record<string, string>> = {
  compact: 'vacuum',
  clawdbot: 'openclaw',
  licence: 'license',
};

function dispatchedFromIndex(): string[] {
  const words = new Set<string>(['api', 'dashboard', 'worker']);
  for (const m of indexSrc.matchAll(/process\.argv\[2\] === '([^']+)'/g)) {
    const word = m[1];
    if (word.startsWith('-') || word === 'help') continue;
    words.add(word);
  }
  return [...words].sort();
}

function commandsBlock(): string {
  const start = indexSrc.indexOf('${bold}COMMANDS${reset}');
  const end = indexSrc.indexOf('${bold}OPTIONS${reset}', start);
  if (start < 0 || end < 0) return '';
  return indexSrc.slice(start, end);
}

const BLOCK = commandsBlock();

/** The command word of every entry line: `  ${cyan}<word>${reset} ...`. */
function listedCommands(): string[] {
  return [...BLOCK.matchAll(/^ {2}\$\{cyan\}([^$]+)\$\{reset\}/gm)].map((m) => m[1]);
}

/** The full text of one entry: its line plus the indented continuation lines. */
function entryText(word: string, firstArg?: string): string {
  const lines = BLOCK.split('\n');
  const head = `  \${cyan}${word}\${reset}`;
  const i = lines.findIndex((l) => l.startsWith(head) && (firstArg === undefined || l.slice(head.length).trimStart().startsWith(firstArg)));
  if (i < 0) return '';
  const out = [lines[i]];
  for (let j = i + 1; j < lines.length && /^ {3,}\S/.test(lines[j]) && !lines[j].includes('${cyan}'); j++) out.push(lines[j]);
  return out.join('\n');
}

const registryCommands = (): string[] =>
  [...new Set([...Object.keys(COMMAND_HELP_SPECS), ...Object.keys(DISPATCH_HELP), ...HANDLER_ONLY])].sort();

const expectedEntries = (): string[] => registryCommands().filter((c) => !Object.hasOwn(ALIASES, c));

describe('#777 — the top-level COMMANDS block matches the dispatcher', () => {
  it('finds the COMMANDS block in src/index.ts', () => {
    expect(BLOCK.length).toBeGreaterThan(0);
    expect(listedCommands().length).toBeGreaterThan(30);
  });

  it('the registry plus the handler-gated list is exactly the set main() dispatches', () => {
    expect(registryCommands()).toEqual(dispatchedFromIndex());
  });

  it('every dispatched non-alias command has an entry', () => {
    const listed = new Set(listedCommands());
    expect(expectedEntries().filter((c) => !listed.has(c))).toEqual([]);
  });

  it('every entry is a dispatched command, and no alias has an entry of its own', () => {
    const expected = new Set(expectedEntries());
    expect([...new Set(listedCommands())].filter((c) => !expected.has(c)).sort()).toEqual([]);
    for (const [alias, target] of Object.entries(ALIASES)) {
      expect(Object.hasOwn(COMMAND_HELP_SPECS, alias)).toBe(true);
      expect(COMMAND_HELP_SPECS[alias as keyof typeof COMMAND_HELP_SPECS])
        .toBe(COMMAND_HELP_SPECS[target as keyof typeof COMMAND_HELP_SPECS]);
      expect(listedCommands()).toContain(target);
    }
  });

  it('includes the eleven commands #767 named', () => {
    const listed = new Set(listedCommands());
    for (const c of ['update', 'repair', 'env', 'xray', 'threat-graph', 'consolidate', 'deny', 'lease', 'freeze', 'stats', 'api']) {
      expect(listed.has(c)).toBe(true);
    }
  });

  it('describes hook as running one named hook, not as a start/stop/status verb', () => {
    const hook = entryText('hook');
    expect(hook).toMatch(/\$\{cyan\}hook\$\{reset\} <name>/);
    expect(hook).toMatch(/Run one hook by name/);
    expect(hook).not.toMatch(/start, stop, status/);
    expect(BLOCK).not.toMatch(/Manage hooks \(start, stop, status\)/);
  });

  it('describes memories as a subcommand group, not only import-native', () => {
    const memories = entryText('memories');
    expect(memories).toMatch(/\$\{cyan\}memories\$\{reset\} <subcommand>/);
    for (const sub of ['import-native', 'migrate-legacy', 'prune', 'embed-backfill', 'reclassify', 'dedupe', 'repair-project-keys', 'purge', 'recalc']) {
      expect(memories).toContain(sub);
    }
  });
});
