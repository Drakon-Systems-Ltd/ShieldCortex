/**
 * #577 round 3, blocker 2 — the value-flag inventory must be COMPLETE, and
 * provably so rather than by inspection.
 *
 * `ALLOWLIST_VALUE_FLAGS` was missing `--note`, which `allowlist add` consumes
 * the following token of (`allowlist add ./x.sh --note help`). Nothing failed
 * yet, only because `add` comes first and stops the verb scan — an accident of
 * word order, not a property of the code. The round-1 method for building these
 * lists was "read the handler and write down what you see", and this is what it
 * misses.
 *
 * So the lists are audited mechanically here. The analyser below reads each
 * command's handler sources, finds every place a token is consumed as a VALUE
 * (`args[i + 1]`, `args[indexOf(flag) + 1]`, `args[++i]`, a `flagValue(args,
 * '--x')` helper), resolves which flag each consumer belongs to, and asserts the
 * flag is in that command's registry row. A new value-taking option that nobody
 * adds to the row fails this test; so does a flag whose consumer the analyser
 * cannot attribute, which has to be named in EXEMPT with a reason.
 *
 * The analyser is text-level on purpose: a runtime check would have to execute
 * every verb of every command (which is what the gate exists to prevent), and a
 * type-level one cannot see an `indexOf(flag) + 1` at all.
 */
import { describe, expect, it } from '@jest/globals';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  COMMAND_HELP_SPECS,
  GLOBAL_VALUE_FLAGS,
  argvWantsHelp,
  commandWantsHelp,
  type GatedCommand,
} from '../wants-help.js';
import { runAllowlist } from '../allowlist.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

/**
 * Where each command's arguments are actually read — the handler and everything
 * it hands a slice of argv to. `global` is the pair of whole-argv gates in
 * `src/index.ts`, whose own inventory is `GLOBAL_VALUE_FLAGS`.
 */
const HANDLER_SOURCES: Record<GatedCommand | 'global', string[]> = {
  audit: ['src/cli/audit.ts'],
  allowlist: ['src/cli/allowlist.ts', 'src/cli/allowlist-scan.ts'],
  sessions: ['src/cli/sessions.ts'],
  memories: ['src/cli/migrate-legacy.ts', 'src/cli/import-native.ts', 'src/cli/embed-backfill.ts'],
  openclaw: ['src/setup/openclaw.ts'],
  clawdbot: ['src/setup/openclaw.ts'],
  hermes: ['src/setup/hermes.ts'],
  update: ['src/cli/update.ts'],
  repair: ['src/cli/repair.ts'],
  migrate: ['src/setup/migrate.ts'],
  uninstall: ['src/setup/uninstall.ts'],
  vacuum: ['src/cli/vacuum.ts'],
  compact: ['src/cli/vacuum.ts'],
  global: ['src/index.ts'],
};

/**
 * Value consumers the analyser cannot attribute to a flag literal, with the
 * reason each one is not an inventory question. Keyed by the enclosing
 * function, so the exemption survives the line moving.
 */
const EXEMPT = new Map<string, string>([
  [
    'src/setup/openclaw.ts:argsWithoutRejectedFlag',
    // Strips a flag (and its value) from an argv THIS CLI built, after the
    // OpenClaw child process said it does not recognise it. The flag name comes
    // from the child's stderr, never from the operator's command line, so it is
    // not a flag the help gate could ever have to skip.
    'removes a flag the child process rejected from a CLI-built argv',
  ],
]);

/** A token consumed as the value of the option before it. */
const VALUE_READ = /\[[^\]]*\+\s*1\s*\]|\[\s*\+\+\s*[A-Za-z_$][\w$]*\s*\]/;
/** …in an argv, not in some other array. */
const ARGV_ISH = /\b(arg|args|argv|extraArgs|process\.argv)\b/;
const FLAG_LITERAL = /'(--[a-z][a-z0-9-]*)'/g;
const DECLARATION = /^(?:export\s+)?(?:async\s+)?(?:function|const|class)\s+([A-Za-z_$][\w$]*)/;

/** Source with comments blanked — prose about a flag is not a consumer of it. */
function codeLines(rel: string): string[] {
  const raw = fs.readFileSync(path.join(repoRoot, rel), 'utf-8').split('\n');
  let inBlock = false;
  return raw.map((line) => {
    let s = line;
    if (inBlock) {
      if (/\*\//.test(s)) { inBlock = false; s = s.replace(/^.*\*\//, ''); } else return '';
    }
    s = s.replace(/\/\*.*?\*\//g, '');
    if (/\/\*/.test(s)) { inBlock = true; s = s.replace(/\/\*.*$/, ''); }
    return s.replace(/\/\/.*$/, '');
  });
}

function literalsOn(line: string): string[] {
  return [...line.matchAll(FLAG_LITERAL)].map((m) => m[1]);
}

/** Module-level flag collections (`const X = ['--a']`, `new Set([...])`). */
function flagCollections(lines: string[]): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (let i = 0; i < lines.length; i++) {
    const m = /^(?:export\s+)?const\s+([A-Z][A-Z0-9_]*)\s*=/.exec(lines[i]);
    if (!m) continue;
    let text = '';
    for (let j = i; j < Math.min(lines.length, i + 20); j++) {
      text += `${lines[j]}\n`;
      if (/;\s*$/.test(lines[j].trim())) break;
    }
    const lits = [...text.matchAll(FLAG_LITERAL)].map((x) => x[1]);
    if (lits.length) out.set(m[1], lits);
  }
  return out;
}

export interface Consumer {
  flag: string;
  site: string;
}

/** Every flag whose value one command consumes, with the site that consumes it. */
function analyse(files: string[]): { consumers: Consumer[]; unattributed: string[] } {
  const consumers: Consumer[] = [];
  const unattributed: string[] = [];
  for (const rel of files) {
    const lines = codeLines(rel);
    const collections = flagCollections(lines);
    const declarations: Array<{ name: string; line: number }> = [];
    lines.forEach((l, i) => {
      const m = DECLARATION.exec(l);
      if (m) declarations.push({ name: m[1], line: i });
    });
    const enclosing = (i: number) => declarations.filter((d) => d.line <= i).pop();

    for (let i = 0; i < lines.length; i++) {
      if (!VALUE_READ.test(lines[i]) || !ARGV_ISH.test(lines[i])) continue;
      const fn = enclosing(i);
      const site = `${rel}:${i + 1}`;
      if (fn && EXEMPT.has(`${rel}:${fn.name}`)) continue;

      // Walk up from the read to the top of its function, taking the first line
      // that names the flag — either literally, or through a flag collection.
      let flags: string[] | null = null;
      for (let j = i; j >= (fn?.line ?? 0) && !flags; j--) {
        const lits = literalsOn(lines[j]);
        if (lits.length) { flags = lits; break; }
        for (const [name, collected] of collections) {
          if (new RegExp(`\\b${name}\\b`).test(lines[j])) { flags = collected; break; }
        }
      }

      // A helper whose flag is a PARAMETER (`flagValue(args, name)`): the answer
      // is at its call sites, which are in this command's own sources.
      if (!flags && fn) {
        const fromCalls: string[] = [];
        for (const other of files) {
          for (const line of codeLines(other)) {
            if (new RegExp(`[^\\w.]${fn.name}\\s*\\(`).test(line)) fromCalls.push(...literalsOn(line));
          }
        }
        if (fromCalls.length) flags = [...new Set(fromCalls)];
      }

      if (!flags) { unattributed.push(`${site} in ${fn?.name ?? '<module>'}`); continue; }
      for (const flag of flags) consumers.push({ flag, site });
    }
  }
  return { consumers, unattributed };
}

function declaredFor(command: GatedCommand | 'global'): readonly string[] {
  return command === 'global' ? GLOBAL_VALUE_FLAGS : COMMAND_HELP_SPECS[command].valueFlags;
}

describe('#577 — every value-consuming flag is in its command\'s list', () => {
  const commands = Object.keys(HANDLER_SOURCES) as Array<GatedCommand | 'global'>;

  it('the analyser finds the consumers it is supposed to find', () => {
    // Guard the guard: an analyser that silently matched nothing would pass
    // every assertion below. These are the consumers the review named.
    const allowlist = analyse(HANDLER_SOURCES.allowlist).consumers.map((c) => c.flag);
    expect(allowlist).toContain('--note');           // src/cli/allowlist.ts add handler
    expect(allowlist).toContain('--openclaw-cron-db'); // allowlist-scan's parser
    expect(analyse(HANDLER_SOURCES.audit).consumers.map((c) => c.flag)).toEqual(['--deps-path']);
    expect(analyse(HANDLER_SOURCES.memories).consumers.map((c) => c.flag)).toContain('--source');
    expect(analyse(HANDLER_SOURCES.openclaw).consumers.map((c) => c.flag)).toContain('--agent');
  });

  it.each(commands)('%s consumes no value for a flag missing from its list', (command) => {
    const { consumers, unattributed } = analyse(HANDLER_SOURCES[command]);
    const declared = declaredFor(command);
    const missing = consumers
      .filter((c) => !declared.includes(c.flag))
      .map((c) => `${c.flag} (${c.site})`);
    expect({ command, missing }).toEqual({ command, missing: [] });
    // An unattributed consumer is not a pass: either the analyser learns to read
    // it, or it is named in EXEMPT with a reason.
    expect({ command, unattributed }).toEqual({ command, unattributed: [] });
  });

  it('prints the audit table (command → flags consumed → in list)', () => {
    const rows: string[] = [];
    for (const command of commands) {
      const { consumers } = analyse(HANDLER_SOURCES[command]);
      const flags = [...new Set(consumers.map((c) => c.flag))].sort();
      const declared = declaredFor(command);
      rows.push(
        `${command.padEnd(10)} ${flags.length ? flags.map((f) => `${f}${declared.includes(f) ? '' : ' ✗MISSING'}`).join(' ') : '(none)'}`,
      );
      // Every declared flag should be a real consumer too — a list that names a
      // flag nothing consumes is dead weight the next reader has to verify.
      const unused = declared.filter((f) => !flags.includes(f));
      expect({ command, unused }).toEqual({ command, unused: [] });
    }
    expect(rows.length).toBe(commands.length);
    // Printed, not just asserted: this table is the review artefact for "which
    // flag does each command consume a value for, and is it listed?".
    console.log(`#577 value-flag audit\n${rows.join('\n')}`);
  });

  it('`--note` is classified as a value, so its value is never the help verb', () => {
    expect(COMMAND_HELP_SPECS.allowlist.valueFlags).toContain('--note');
  });
});

describe('#577 — `allowlist add ./x.sh --note help` pins with the literal note "help"', () => {
  /** Any readable file works: `add` hashes the CONTENT it is vouching for. */
  const target = path.join(repoRoot, 'package.json');

  function pin(argv: string[]) {
    const written: Array<Array<Record<string, unknown>>> = [];
    const out: string[] = [];
    const err: string[] = [];
    const code = runAllowlist(argv, {
      now: 1_700_000_000_000,
      interactive: true,
      log: (m) => out.push(m),
      error: (m) => err.push(m),
      readEntries: () => [],
      writeEntries: (entries) => { written.push(entries); },
    });
    return { code, out, err, written };
  }

  it('classifies `--note help` as a value at both gates', () => {
    expect(commandWantsHelp('allowlist', ['--note', 'help'])).toBe(false);
    expect(argvWantsHelp(['allowlist', '--note', 'help'])).toBe(false);
    // A row that does NOT list `--note` reads the value as the verb — the defect
    // itself, pointed at another command so it stays visible.
    expect(commandWantsHelp('audit', ['--note', 'help'])).toBe(true);
    // An explicit help flag still wins over any note.
    expect(commandWantsHelp('allowlist', ['--note', 'help', '--help'])).toBe(true);
  });

  it('delivers the literal note to the handler instead of printing usage', () => {
    const r = pin(['add', target, '--note', 'help']);
    expect(r.err).toEqual([]);
    expect(r.code).toBe(0);
    expect(r.out.join('\n')).not.toContain('Usage: shieldcortex allowlist');
    expect(r.written).toHaveLength(1);
    expect(r.written[0]).toHaveLength(1);
    expect(r.written[0][0].note).toBe('help');
    expect(String(r.written[0][0].path)).toContain('package.json');
  });

  it('delivers it with the note before the path, too', () => {
    const r = pin(['add', '--note', 'help', target]);
    expect(r.err).toEqual([]);
    expect(r.code).toBe(0);
    expect(r.written).toHaveLength(1);
    expect(r.written[0][0].note).toBe('help');
  });

  it('`allowlist add ./x.sh --help` still prints usage and pins nothing', () => {
    const r = pin(['add', target, '--help']);
    expect(r.code).toBe(0);
    expect(r.out.join('\n')).toContain('Usage: shieldcortex allowlist');
    expect(r.written).toEqual([]);
  });
});
