/**
 * #577 round 3, blocker 2 — the value-flag inventory, audited mechanically
 * rather than by inspection.
 *
 * Scope, stated honestly (round-3 review nit): the analyser recognises the
 * consumer shapes listed below and attributes each to the nearest flag literal
 * in scope. It does NOT recognise every conceivable shape. For example, the
 * `--flag=value` form (`eq.slice(prefix.length)`, as in embed-backfill's
 * `readFlag`) is not a candidate; those flags are covered today only because the
 * same helper also has an `args[i + 1]` branch. Treat a green run as "no
 * recognised consumer is missing from its row", not as proof of completeness.
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
 *
 * #767 registered the dispatcher-gated commands and taught the analyser one
 * more shape: a read offset from an index VARIABLE (`args[idx + 1]`) is
 * attributed through that variable's `indexOf(...)` — directly when the
 * argument is a literal, through the innermost helper's call sites when it is
 * a parameter (`valueOf(flag)` ← `closed(flag, …)` ← `closed('--memory-plane',
 * …)`). Before, the read took the nearest literal above it, which for
 * `protect` was the boolean `--from-config` check on the line between.
 *
 * #767 round 3 (B4): a source may be scoped to ONE top-level function
 * (`src/index.ts#parseArgs`), because a file is the wrong unit for
 * `src/index.ts` — it hosts `parseArgs()`, which reads `--db` / `--mode` for
 * every command line, AND the `scan-skills` branch of `main()`, which reads
 * `--dir`. Attributing the whole file to every inline row let `api`,
 * `dashboard` and `worker` declare `--dir` as a value flag nothing of theirs
 * consumes, and `api --dir --help` reached server startup while this suite was
 * green. Each inline row now cites only the function(s) that read its argv, so
 * the "declared but unused" check catches that over-attribution.
 *
 * What this suite does NOT audit mechanically is the RULE on each flag — whether
 * the parser reads a `--`-leading token as the value or leaves it unread (#767
 * round 3, B3). Those were read out of each parser by hand and are pinned,
 * flag by flag, in src/__tests__/cli-help-gate-767.test.ts; this suite checks
 * that the derived `valueFlags` array agrees with the rules it was built from.
 */
import { describe, expect, it } from '@jest/globals';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  COMMAND_HELP_SPECS,
  GLOBAL_VALUES,
  GLOBAL_VALUE_FLAGS,
  argvWantsHelp,
  commandWantsHelp,
  type CommandHelpSpec,
  type GatedCommand,
  type ValueRule,
} from '../wants-help.js';
import { runAllowlist } from '../allowlist.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

/**
 * Where each command's arguments are actually read — the handler and everything
 * it hands a slice of argv to. `global` is the pair of whole-argv gates in
 * `src/index.ts`, whose own inventory is `GLOBAL_VALUE_FLAGS`. A `#name` suffix
 * narrows a file to the top-level function `name` (#767 round 3).
 */
const HANDLER_SOURCES: Record<GatedCommand | 'global', string[]> = {
  audit: ['src/cli/audit.ts'],
  allowlist: ['src/cli/allowlist.ts', 'src/cli/allowlist-scan.ts'],
  sessions: ['src/cli/sessions.ts'],
  memories: ['src/cli/migrate-legacy.ts', 'src/cli/import-native.ts', 'src/cli/embed-backfill.ts', 'src/cli/reclassify.ts'],
  openclaw: ['src/setup/openclaw.ts'],
  clawdbot: ['src/setup/openclaw.ts'],
  hermes: ['src/setup/hermes.ts'],
  update: ['src/cli/update.ts'],
  repair: ['src/cli/repair.ts'],
  migrate: ['src/setup/migrate.ts'],
  uninstall: ['src/setup/uninstall.ts'],
  vacuum: ['src/cli/vacuum.ts'],
  compact: ['src/cli/vacuum.ts'],
  logs: ['src/cli/logs.ts'],
  // ── #767: the rows the dispatcher's own gate reads (src/cli/dispatch-help.ts).
  // A command handled inline in src/index.ts, or a server mode, reads only what
  // `parseArgs()` reads — so its source is that function, not the file (B4).
  // `scan-skills` is the one inline command with an option of its own, read in
  // its branch of `main()`.
  hook: ['src/setup/hooks.ts'],
  protect: ['src/cli/protect.ts'],
  quickstart: ['src/setup/quickstart.ts'],
  copilot: ['src/setup/copilot.ts'],
  codex: ['src/setup/codex.ts'],
  service: ['src/service/install.ts'],
  config: ['src/cloud/cli.ts'],
  // `handleCloudCommand` reads two fixed tokens (`sync`, `--full`); every value
  // consumer in its module belongs to `config`, audited on that row.
  cloud: [],
  'review-copilot': ['src/cli/review-copilot.ts'],
  remember: ['src/cli/remember.ts'],
  approve: ['src/cli/approve.ts'],
  deny: ['src/cli/deny.ts'],
  freeze: ['src/cli/freeze.ts'],
  unfreeze: ['src/cli/freeze.ts'],
  lease: ['src/cli/freeze.ts'],
  status: ['src/setup/status.ts'],
  graph: ['src/index.ts#parseArgs'],
  'threat-graph': ['src/index.ts#parseArgs'],
  license: ['src/license/cli.ts'],
  licence: ['src/license/cli.ts'],
  stats: ['src/cli/stats-command.ts'],
  guard: ['src/cli/guard.ts'],
  memory: ['src/cli/memory.ts'],
  inspect: ['src/cli/inspect.ts'],
  'iron-dome': ['src/cli/iron-dome.ts'],
  scan: ['src/cli/scan-command.ts'],
  'scan-skill': ['src/index.ts#parseArgs'],
  env: ['src/index.ts#parseArgs'],
  'scan-skills': ['src/index.ts#parseArgs', 'src/index.ts#main'],
  consolidate: ['src/index.ts#parseArgs'],
  xray: ['src/xray/index.ts'],
  'xray-preinstall': ['src/xray/preinstall.ts'],
  cortex: ['src/cortex/cli.ts'],
  api: ['src/index.ts#parseArgs'],
  dashboard: ['src/index.ts#parseArgs'],
  worker: ['src/index.ts#parseArgs'],
  global: ['src/index.ts#parseArgs'],
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
  [
    'src/cortex/cli.ts:parseArgs',
    // A generic `--key value` parser: EVERY `--x` token consumes the one after
    // it, so there is no finite value-flag list to put in cortex's row (#767).
    // The rule is represented instead: the row declares
    // `everyLongFlagTakesValue`, and the gate steps over the token after any
    // `--key` exactly as this parser does (asserted below, #767 round 2). What
    // is exempt here is only the analyser's attribution, which needs a literal.
    'every --flag consumes the following token; the row carries the rule, not a list',
  ],
]);

/** A token consumed as the value of the option before it. */
const VALUE_READ = /\[[^\]]*\+\s*1\s*\]|\[\s*\+\+\s*[A-Za-z_$][\w$]*\s*\]/;
/** …in an argv, not in some other array. */
const ARGV_ISH = /\b(arg|args|argv|extraArgs|process\.argv)\b/;
const FLAG_LITERAL = /'(--[a-z][a-z0-9-]*)'/g;
const DECLARATION = /^(?:export\s+)?(?:async\s+)?(?:function|const|class)\s+([A-Za-z_$][\w$]*)/;

/**
 * Source with comments blanked — prose about a flag is not a consumer of it.
 * `file#name` keeps only the lines of the top-level declaration `name` (from
 * its line to the line before the next top-level declaration); every other
 * line is blanked so line numbers in sites stay those of the file.
 */
function codeLines(source: string): string[] {
  const [rel, only] = source.split('#');
  const raw = fs.readFileSync(path.join(repoRoot, rel), 'utf-8').split('\n');
  let inBlock = false;
  const lines = raw.map((line) => {
    let s = line;
    if (inBlock) {
      if (/\*\//.test(s)) { inBlock = false; s = s.replace(/^.*\*\//, ''); } else return '';
    }
    s = s.replace(/\/\*.*?\*\//g, '');
    if (/\/\*/.test(s)) { inBlock = true; s = s.replace(/\/\*.*$/, ''); }
    return s.replace(/\/\/.*$/, '');
  });
  if (!only) return lines;
  const start = lines.findIndex((l) => DECLARATION.exec(l)?.[1] === only);
  if (start === -1) throw new Error(`${source}: no top-level declaration named ${only}`);
  let end = lines.findIndex((l, i) => i > start && DECLARATION.test(l));
  if (end === -1) end = lines.length;
  return lines.map((l, i) => (i >= start && i < end ? l : ''));
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

/** `args[IDENT + 1]` → IDENT, or undefined when the offset is not a bare identifier. */
const INDEX_IDENT = /\[\s*([A-Za-z_$][\w$]*)\s*\+\s*1\s*\]/;

/**
 * Name of the nearest `function name(` or `const name = (` above `line` whose
 * parameter list names `param`; a parameter list may continue on later lines.
 */
function helperDeclaring(lines: string[], line: number, param: string): string | null {
  const open = /(?:function\s+([A-Za-z_$][\w$]*)\s*\(|(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\()(.*)$/;
  const names = new RegExp(`(?:^|[^\\w$])${param}(?=\\s*[:,)=])`);
  for (let j = line; j >= 0; j--) {
    const m = open.exec(lines[j]);
    if (!m) continue;
    let params = m[3];
    for (let k = j + 1; k < lines.length && !params.includes(')'); k++) params += lines[k];
    params = params.slice(0, params.indexOf(')'));
    if (names.test(params)) return m[1] ?? m[2];
  }
  return null;
}

/**
 * The literals passed for parameter `param` of the innermost helper declared
 * above `line` that takes it, across every call site in `files`. A call site
 * that forwards another identifier resolves through ITS enclosing helper, so
 * `closed(flag, …) { valueOf(flag) }` finds the literals passed to `closed`.
 */
function viaParameter(lines: string[], line: number, param: string, files: string[], depth: number): string[] | null {
  if (depth > 3) return null;
  const helper = helperDeclaring(lines, line, param);
  if (!helper) return null;
  const declaration = new RegExp(`(?:function|const|let)\\s+${helper}\\b`);
  const call = new RegExp(`[^\\w.]${helper}\\s*\\(`);
  const forwards = new RegExp(`[^\\w.]${helper}\\s*\\(\\s*([A-Za-z_$][\\w$]*)\\s*[,)]`);
  const out = new Set<string>();
  for (const other of files) {
    const otherLines = codeLines(other);
    otherLines.forEach((l, k) => {
      if (!call.test(l) || declaration.test(l)) return;
      for (const lit of literalsOn(l)) out.add(lit);
      const forwarded = forwards.exec(l)?.[1];
      if (forwarded) for (const lit of viaParameter(otherLines, k, forwarded, files, depth + 1) ?? []) out.add(lit);
    });
  }
  return out.size ? [...out] : null;
}

/**
 * The flag a read is offset from, through its index variable: `args[idx + 1]`
 * under `const idx = args.indexOf('--config')` names it directly, and under
 * `args.indexOf(flag)` names a parameter, answered at the call sites. Null when
 * the offset is not such a variable (a loop counter, say).
 */
function viaIndexVariable(lines: string[], read: number, top: number, files: string[]): string[] | null {
  const ident = INDEX_IDENT.exec(lines[read])?.[1];
  if (!ident) return null;
  const assign = new RegExp(`\\b${ident}\\s*=\\s*[^;]*\\.indexOf\\(`);
  for (let j = read - 1; j >= top; j--) {
    if (!assign.test(lines[j])) continue;
    const lits = literalsOn(lines[j]);
    if (lits.length) return lits;
    const param = /\.indexOf\(\s*([A-Za-z_$][\w$]*)\s*\)/.exec(lines[j])?.[1];
    return param ? viaParameter(lines, j, param, files, 0) : null;
  }
  return null;
}

/** Each flag whose value a recognised consumer shape reads, with the site that reads it. */
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

      // The index the read is offset from, when it is a variable: `args[idx + 1]`
      // under `const idx = args.indexOf('--config')` names the flag exactly,
      // where the nearest literal may be a boolean flag's `includes` check on
      // the line between (#767: protect, the config preflight closure).
      let flags: string[] | null = viaIndexVariable(lines, i, fn?.line ?? 0, files);
      // Otherwise walk up from the read to the top of its function, taking the
      // first line that names the flag — either literally, or through a flag
      // collection.
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

/** Every (flag → rule) a row applies, across its own table and its verb rows. */
function rulesOf(row: CommandHelpSpec): Map<string, Set<ValueRule>> {
  const out = new Map<string, Set<ValueRule>>();
  const add = (flag: string, rule: ValueRule) => {
    if (!out.has(flag)) out.set(flag, new Set());
    out.get(flag)!.add(rule);
  };
  for (const [flag, rule] of Object.entries(row.values)) add(flag, rule);
  for (const verb of Object.values(row.verbs ?? {})) {
    for (const [flag, rules] of rulesOf(verb)) for (const r of rules) add(flag, r);
  }
  return out;
}

function rulesFor(command: GatedCommand | 'global'): Map<string, Set<ValueRule>> {
  if (command === 'global') return new Map(Object.entries(GLOBAL_VALUES).map(([f, r]) => [f, new Set([r])]));
  return rulesOf(COMMAND_HELP_SPECS[command]);
}

describe('#577 — every recognised value-consuming flag is in its command\'s list', () => {
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
    // #767 round 3 (B4): the function scoping sees `--db`/`--mode` in
    // `parseArgs()` only, and `--dir` in `main()` only — so an inline row that
    // cites `parseArgs` and declares `--dir` fails the unused-flag check below.
    expect([...new Set(analyse(['src/index.ts#parseArgs']).consumers.map((c) => c.flag))].sort()).toEqual(['--db', '--mode']);
    expect([...new Set(analyse(['src/index.ts#main']).consumers.map((c) => c.flag))]).toEqual(['--dir']);
    expect(() => analyse(['src/index.ts#noSuchFunction'])).toThrow(/no top-level declaration/);
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

  it('prints the audit table (command → flags consumed → in list → rule)', () => {
    const rows: string[] = [];
    for (const command of commands) {
      const { consumers } = analyse(HANDLER_SOURCES[command]);
      const flags = [...new Set(consumers.map((c) => c.flag))].sort();
      const declared = declaredFor(command);
      const rules = rulesFor(command);
      const describe1 = (f: string) =>
        `${f}${declared.includes(f) ? `:${[...(rules.get(f) ?? [])].join('|')}` : ' ✗MISSING'}`;
      rows.push(`${command.padEnd(14)} ${flags.length ? flags.map(describe1).join(' ') : '(none)'}`);
      // Every declared flag should be a real consumer too — a list that names a
      // flag nothing consumes is dead weight the next reader has to verify.
      const unused = declared.filter((f) => !flags.includes(f));
      expect({ command, unused }).toEqual({ command, unused: [] });
    }
    expect(rows.length).toBe(commands.length);
    // Printed, not just asserted: this table is the review artefact for "which
    // flag does each command consume a value for, and is it listed?".
    console.log(`#577 value-flag audit (flag:rule — always | unless-double-dash | unless-dash)\n${rows.join('\n')}`);
  });

  it('every row\'s valueFlags is exactly the keys of its rules (own table ∪ verb rows)', () => {
    // `helpSpec()` derives the array; this pins that nothing bypasses it.
    for (const command of Object.keys(COMMAND_HELP_SPECS) as GatedCommand[]) {
      const row = COMMAND_HELP_SPECS[command];
      expect({ command, flags: [...row.valueFlags].sort() })
        .toEqual({ command, flags: [...rulesOf(row).keys()].sort() });
      for (const [verb, verbRow] of Object.entries(row.verbs ?? {})) {
        expect({ command, verb, flags: [...verbRow.valueFlags].sort() })
          .toEqual({ command, verb, flags: Object.keys(verbRow.values).sort() });
      }
    }
    expect([...GLOBAL_VALUE_FLAGS].sort()).toEqual(Object.keys(GLOBAL_VALUES).sort());
  });

  it('#767 round 3 (B4): `--dir` belongs to scan-skills alone; the inline/server rows are the global inventory', () => {
    const withDir = (Object.keys(COMMAND_HELP_SPECS) as GatedCommand[])
      .filter((c) => COMMAND_HELP_SPECS[c].valueFlags.includes('--dir'));
    expect(withDir).toEqual(['scan-skills']);
    expect([...COMMAND_HELP_SPECS['scan-skills'].valueFlags].sort()).toEqual([...GLOBAL_VALUE_FLAGS, '--dir'].sort());
    for (const c of ['api', 'dashboard', 'worker', 'graph', 'threat-graph', 'env', 'consolidate', 'scan-skill'] as const) {
      expect({ c, flags: [...COMMAND_HELP_SPECS[c].valueFlags].sort() }).toEqual({ c, flags: [...GLOBAL_VALUE_FLAGS].sort() });
    }
    expect(GLOBAL_VALUE_FLAGS).not.toContain('--dir');
  });

  it('`--note` is classified as a value, so its value is never the help verb', () => {
    expect(COMMAND_HELP_SPECS.allowlist.valueFlags).toContain('--note');
  });

  it('cortex: the exempted generic parser is represented as a rule on its row (#767 round 2)', () => {
    // The exemption above would otherwise leave cortex's values unprotected:
    // with an empty list and no rule, `--what --help` was a help request.
    expect(COMMAND_HELP_SPECS.cortex.valueFlags).toEqual([]);
    expect(COMMAND_HELP_SPECS.cortex.values).toEqual({});
    expect(COMMAND_HELP_SPECS.cortex.everyLongFlagTakesValue).toBe(true);
    expect(commandWantsHelp('cortex', ['capture', '--what', '--help', '--category', 'code'])).toBe(false);
    expect(commandWantsHelp('cortex', ['capture', '--what', 'x', '--help'])).toBe(true);
    expect(argvWantsHelp(['cortex', 'capture', '--what', '--help'])).toBe(false);
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
