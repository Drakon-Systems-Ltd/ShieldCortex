/**
 * Shared CLI help detection (#515, hardened in #577).
 *
 * `--help` / `-h` (and a bare `help` verb) must never execute an action.
 * Commands that previously ignored these flags ran the action anyway —
 * `audit --help` scanned the environment; `allowlist --help` was rejected
 * as an unknown subcommand.
 *
 * #577 put this function in front of every host-mutating subcommand, which
 * exposed the other half of the problem: it used to answer "does the word
 * `help` appear anywhere in argv?". That is not a question about the command
 * line, it is a substring search, and it swallowed perfectly valid VALUES —
 * `openclaw skill install --agent help`, `memories prune --project help` and
 * `memories migrate-legacy --source help` all printed usage and did nothing,
 * silently, while the downstream consumers accept those tokens as an agent id,
 * a project key and a source path. A help gate that eats real work is the same
 * defect as an action that eats a help flag, pointed the other way.
 *
 * The rule now: `--help` / `-h` count anywhere (they are never a value the CLI
 * asks for), and a bare `help` counts only in the verb position — the FIRST
 * positional, with the values of value-taking options skipped so they can never
 * be mistaken for one.
 *
 * Round 3 closed the last way that rule could still be applied WRONGLY: which
 * options take a value is a fact about one command, and the whole-argv gates in
 * `src/index.ts` were guessing at it instead of reading the command's own table.
 * `COMMAND_HELP_SPECS` below is that table, once, for every gate — see
 * `argvWantsHelp` and `commandWantsHelp`. `wantsHelp` itself stays the
 * table-free primitive both are built from.
 */

/** Options that consume the following token as their value, per command. */
export interface WantsHelpOptions {
  /**
   * The command's value-taking options (`--agent`, `--project`, `--days`, …).
   * A token immediately after one of these is that option's value and is never
   * read as a verb. Omit it only for commands whose options are all boolean.
   */
  valueFlags?: readonly string[];
  /**
   * How many leading positionals are verb slots. 1 for a command reading its
   * OWN arguments — `help` is the verb or it is an argument.
   *
   * Callers pass the command's own argv, so this is 1 everywhere today: the
   * whole-argv gates strip the command word themselves (`argvWantsHelp`) rather
   * than counting a slot deeper, because the token they have to skip past is the
   * command word and only the command's table describes what follows it.
   */
  verbDepth?: number;
}

export function wantsHelp(args: readonly string[], options: WantsHelpOptions = {}): boolean {
  // Explicit help flags win wherever they appear: no option in this CLI takes a
  // value spelled `--help`, so there is no ambiguity to resolve.
  if (args.some((a) => a === '--help' || a === '-h')) return true;

  const valueFlags = options.valueFlags ?? [];
  const verbDepth = options.verbDepth ?? 1;
  let positional = 0;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    // `--flag value` — skip the value; `--flag=value` is one token and falls
    // through to the option branch below.
    if (valueFlags.includes(a)) {
      i++;
      continue;
    }
    if (a.startsWith('-') && a !== '-') continue;
    positional += 1;
    if (a === 'help') return true;
    // Past the verb slots, `help` is an argument to a verb already chosen.
    if (positional >= verbDepth) return false;
  }
  return false;
}

/**
 * Value-taking options that can appear BEFORE the subcommand word, used to find
 * the command word itself (`shieldcortex --db /tmp/x.db audit help`).
 */
export const GLOBAL_VALUE_FLAGS = ['--db', '--mode', '--dir'] as const;

/** How one command's argv is read, for every gate that decides about it. */
export interface CommandHelpSpec {
  /**
   * The options whose FOLLOWING token the command consumes as a value. Every
   * `args[i + 1]` / `indexOf(flag) + 1` / `flagValue(args, flag)` consumer in
   * the command's own call graph must be represented here. The shapes the
   * analyser recognises are checked by `value-flag-inventory-577.test.ts`; see
   * its header for what it does not recognise.
   */
  valueFlags: readonly string[];
  /**
   * How many leading positionals of the command's OWN argv are verb slots.
   * 1 everywhere today: `help` is the command's verb, or it is an argument to a
   * verb already chosen. A command that ever grows a two-word verb declares 2
   * here and both gates follow.
   */
  verbDepth?: number;
  /**
   * The handler drops every bare `--` before reading its argv (`allowlist`).
   * Both gates must see the tokens the handler parses, so the gate applies the
   * same normalisation: `allowlist --note -- reviewed help` is the `help` verb
   * to the handler, and must be to the global gate too (#577 round 3).
   */
  stripDoubleDash?: boolean;
}

/** `audit`: `--deps-path help` is a path to scan (#577). */
const AUDIT_SPEC: CommandHelpSpec = { valueFlags: ['--deps-path'] };

/**
 * `allowlist`: `scan`'s path/glob options, and `add --note help` — a reviewer's
 * one-word reason. #577 round 3 found `--note` missing: the add handler consumes
 * the token after it, so the inventory was not complete.
 */
const ALLOWLIST_SPEC: CommandHelpSpec = {
  valueFlags: ['--glob', '--hermes-cron', '--openclaw-cron', '--openclaw-cron-db', '--note'],
  stripDoubleDash: true,
};

/** `sessions`: `--days help` is a value (rejected later, as a number). */
const SESSIONS_SPEC: CommandHelpSpec = { valueFlags: ['--days'] };

/**
 * `memories`: every value-taking option across its verbs — `prune`, `dedupe`,
 * `repair-project-keys`, `purge`, `recalc`, `import-native`, `embed-backfill`
 * and `migrate-legacy`. A project key or a source path may spell "help".
 */
const MEMORIES_SPEC: CommandHelpSpec = {
  valueFlags: [
    '--source',        // migrate-legacy
    '--project',       // prune, dedupe, repair-project-keys, import-native, embed-backfill
    '--salience-lte',  // prune
    '--older-than',    // prune
    '--limit',         // dedupe, embed-backfill
    '--db',            // repair-project-keys, purge, recalc
    '--backup-dir',    // repair-project-keys, purge, recalc
    '--map',           // repair-project-keys
    '--scan-paths',    // repair-project-keys
    '--host-id',       // import-native
    '--agent-id',      // import-native
  ],
};

/** `openclaw`: `skill install --agent help` installs for the agent "help". */
const OPENCLAW_SPEC: CommandHelpSpec = { valueFlags: ['--agent'] };

/** The strict-parser commands and `hermes` take no option values at all. */
const NO_VALUE_FLAGS: CommandHelpSpec = { valueFlags: [] };

/**
 * Every command that owns a help gate, and the one description of its argv that
 * all of its gates read (#577 round 3).
 *
 * The global gates in `src/index.ts` used to carry their own idea of the command
 * line — a flat `GLOBAL_VALUE_FLAGS` list and `verbDepth: 2` — and therefore
 * disagreed with the command they were gating for:
 * `shieldcortex audit --deps-path node_modules help` counted `node_modules` as
 * the verb, answered "not help", and ran the `npm ls -g` staleness preamble
 * before audit printed its usage. Two gates deciding the same question from two
 * tables will diverge again, so there is now one table and both read it.
 *
 * Aliases share the spec OBJECT, so `compact`/`clawdbot` cannot drift from
 * `vacuum`/`openclaw` either.
 */
export const COMMAND_HELP_SPECS = {
  audit: AUDIT_SPEC,
  allowlist: ALLOWLIST_SPEC,
  sessions: SESSIONS_SPEC,
  memories: MEMORIES_SPEC,
  openclaw: OPENCLAW_SPEC,
  clawdbot: OPENCLAW_SPEC,      // backward-compat alias
  hermes: NO_VALUE_FLAGS,
  update: NO_VALUE_FLAGS,
  repair: NO_VALUE_FLAGS,
  migrate: NO_VALUE_FLAGS,
  uninstall: NO_VALUE_FLAGS,
  vacuum: NO_VALUE_FLAGS,
  compact: NO_VALUE_FLAGS,      // documented alias of vacuum
} as const satisfies Record<string, CommandHelpSpec>;

/** A command word with an entry in `COMMAND_HELP_SPECS`. */
export type GatedCommand = keyof typeof COMMAND_HELP_SPECS;

export function isGatedCommand(word: string): word is GatedCommand {
  return Object.prototype.hasOwnProperty.call(COMMAND_HELP_SPECS, word);
}

/**
 * The gate a command applies to its OWN argv — everything after the command
 * word, exactly what `main()` hands the handler.
 *
 * Every per-command gate goes through here (directly or via `helpGate`), so the
 * command word is the only thing a caller chooses; the table supplies the rest.
 */
export function commandWantsHelp(command: GatedCommand, args: readonly string[]): boolean {
  const spec = COMMAND_HELP_SPECS[command];
  const tokens = spec.stripDoubleDash ? args.filter((a) => a !== '--') : args;
  return wantsHelp(tokens, { valueFlags: spec.valueFlags, verbDepth: spec.verbDepth });
}

/**
 * The gate for a WHOLE command line (`process.argv.slice(2)`) — the npm
 * staleness preamble and the stats banner in `src/index.ts`.
 *
 * It finds the command word and then asks that command's own question about the
 * rest, so its verdict is the destination handler's verdict by construction.
 * An unregistered command word keeps the old conservative reading: `help` in the
 * verb slot counts, no option values are skipped — those commands print no usage
 * for a bare `help` anyway, and a false positive here only skips a staleness
 * warning, while a false negative is the defect this function exists to close.
 */
export function argvWantsHelp(argv: readonly string[]): boolean {
  if (argv.some((a) => a === '--help' || a === '-h')) return true;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if ((GLOBAL_VALUE_FLAGS as readonly string[]).includes(a)) {
      i++;
      continue;
    }
    if (a.startsWith('-') && a !== '-') continue;
    // First positional: the command word.
    if (a === 'help') return true;
    const rest = argv.slice(i + 1);
    return isGatedCommand(a) ? commandWantsHelp(a, rest) : wantsHelp(rest);
  }
  return false;
}
