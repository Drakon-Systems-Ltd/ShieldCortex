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
 * The rule now: `--help` / `-h` count at any OPTION position, and a bare `help`
 * counts only in the verb position — the FIRST positional. The values of
 * value-taking options are stepped over before either check, so a value can
 * never be mistaken for a verb OR for a flag: `remember x --content --help`
 * stores the text "--help" (#767 round 2 — the first version checked the flags
 * against the whole argv before skipping values, and ate that content).
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
   * 0 for a command whose first positional is DATA, not a verb (#767): the text
   * `scan` analyses, the title `remember` stores, the file `scan-skill` reads,
   * the package `xray` inspects, the name `hook` runs. `shieldcortex scan help`
   * scans the word "help" and `hook help` runs a hook named "help"; only
   * `--help` / `-h` ask such a command for usage.
   *
   * Callers pass the command's own argv, so this is 1 (or 0) everywhere today:
   * the whole-argv gates strip the command word themselves (`argvWantsHelp`)
   * rather than counting a slot deeper, because the token they have to skip past
   * is the command word and only the command's table describes what follows it.
   */
  verbDepth?: number;
  /**
   * EVERY `--key` consumes the following token, whatever the key — the shape of
   * a generic `--key value` parser (`cortex`, src/cortex/cli.ts), for which no
   * finite `valueFlags` list exists. `cortex capture --what --help` is the
   * mistake "--help", not a help request; `--help` at an option position still
   * is one, because the help check runs before the consumption rule.
   */
  everyLongFlagTakesValue?: boolean;
}

export function wantsHelp(args: readonly string[], options: WantsHelpOptions = {}): boolean {
  const valueFlags = options.valueFlags ?? [];
  const verbDepth = options.verbDepth ?? 1;
  let positional = 0;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    // An explicit help flag counts at any OPTION position. A token in a VALUE
    // position never reaches this line — the branch below steps over it — so
    // `--content --help` is content spelled "--help", not a request for usage.
    if (a === '--help' || a === '-h') return true;
    // `--flag value` — skip the value; `--flag=value` is one token and falls
    // through to the option branch below.
    if (valueFlags.includes(a) || (options.everyLongFlagTakesValue && a.startsWith('--'))) {
      i++;
      continue;
    }
    if (a.startsWith('-') && a !== '-') continue;
    positional += 1;
    // A bare `help` is the help verb only in a verb slot. Past the verb slots it
    // is an argument to a verb already chosen — or, at depth 0, the command's
    // data — and the scan goes on, because a flag further along still counts.
    if (positional <= verbDepth && a === 'help') return true;
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
   * The handler drops every bare `--` before reading its argv (`allowlist`,
   * `approve`, `deny`). Both gates must see the tokens the handler parses, so
   * the gate applies the same normalisation: `allowlist --note -- reviewed help`
   * is the `help` verb to the handler, and must be to the global gate too (#577
   * round 3).
   */
  stripDoubleDash?: boolean;
  /**
   * The handler treats the first bare `--` as the end of its options and
   * everything after it as data (`scan -- --help` scans the text "--help").
   * The gate reads only the tokens before it, for the same reason as
   * `stripDoubleDash`: the verdict has to be about the argv the handler parses
   * (#767).
   */
  doubleDashEndsOptions?: boolean;
  /**
   * Options that consume EVERY following token as their value: `freeze <scope>
   * --reason <the rest of the line>`. The gate stops reading at the first one,
   * so a reason that happens to contain `--help` is still the reason (#767).
   */
  restFlags?: readonly string[];
  /**
   * The handler's parser consumes the token after EVERY `--key` (`cortex`), so
   * there is no finite `valueFlags` list to write down; the rule itself is the
   * row (#767 round 2). See `WantsHelpOptions.everyLongFlagTakesValue`.
   */
  everyLongFlagTakesValue?: boolean;
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
    '--project',       // prune, dedupe, repair-project-keys, import-native, embed-backfill, reclassify
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

/**
 * The strict-parser commands, `hermes`, and every command whose options are all
 * boolean or whose handler reads a fixed positional and nothing else
 * (`copilot <verb>`, `license <verb> [key]`, `lease`, `stats`, …).
 */
const NO_VALUE_FLAGS: CommandHelpSpec = { valueFlags: [] };

/**
 * Commands handled inline in `src/index.ts` (`consolidate`, `graph`, `env`, …)
 * and the three server modes (`api`, `dashboard`, `worker`). The only option
 * values `main()` ever consumes from their argv are the global ones —
 * `parseArgs()` reads `--db <path>` / `--mode <mode>` for every command, and
 * `scan-skills` reads `--dir <path>` — so their row IS the global inventory,
 * shared by identity (#767).
 */
const INDEX_SPEC: CommandHelpSpec = { valueFlags: GLOBAL_VALUE_FLAGS };

/** `scan-skill <path>`: inline like the above, but its first positional is a file. */
const SCAN_SKILL_SPEC: CommandHelpSpec = { valueFlags: GLOBAL_VALUE_FLAGS, verbDepth: 0 };

/** `protect`: `--config help` is a config path, `--agent-uid help` a (malformed) uid (#767). */
const PROTECT_SPEC: CommandHelpSpec = { valueFlags: ['--config', '--agent-uid'] };

/**
 * `config`: every option `handleCloudConfig` reads the following token of. The
 * values are enums, keys, URLs and numbers; a bare `help` after any of them is
 * that option's (invalid) value, and the handler is the one to refuse it.
 */
const CONFIG_SPEC: CommandHelpSpec = {
  valueFlags: [
    '--mode',
    '--cloud-api-key',
    '--cloud-url',
    '--verify-mode',
    '--verify-timeout',
    '--openclaw-auto-memory',
    '--ranker',
    '--proactive-recall',
    '--self-heal',
    '--action-guard-notify-webhook',
    '--memory-inject-contract',
    '--memory-plane',
    '--memory-host-posture',
    '--memory-host-runtime',
    '--auto-memory-sampling',
  ],
};

/** `review-copilot annotate --id <id> | --pending [--limit N]`. */
const REVIEW_COPILOT_SPEC: CommandHelpSpec = { valueFlags: ['--id', '--limit'] };

/**
 * `remember "<title>" --content <text> …`: the first positional is the memory's
 * title, so there is no verb slot — a memory titled "help" is a memory (#767).
 */
const REMEMBER_SPEC: CommandHelpSpec = {
  valueFlags: ['--content', '--category', '--importance', '--tags', '--project'],
  verbDepth: 0,
};

/** `approve [<hash>] [--ttl N] [--attempt <id>] …`; the handler drops bare `--`. */
const APPROVE_SPEC: CommandHelpSpec = { valueFlags: ['--ttl', '--attempt'], stripDoubleDash: true };

/** `deny [<hash>] [--attempt <id>]`; the handler drops bare `--`. */
const DENY_SPEC: CommandHelpSpec = { valueFlags: ['--attempt'], stripDoubleDash: true };

/** `freeze <scope> --reason <every following token>`. */
const FREEZE_SPEC: CommandHelpSpec = { valueFlags: [], restFlags: ['--reason'] };

/** `guard readiness|test-approval [--surface claude-code|openclaw]`. */
const GUARD_SPEC: CommandHelpSpec = { valueFlags: ['--surface'] };

/** `memory downvote <id> --reason <text>` / `memory list --purpose X --category X --limit N`. */
const MEMORY_SPEC: CommandHelpSpec = { valueFlags: ['--reason', '--purpose', '--category', '--limit'] };

/** `inspect last-precompact|last-recall [--history N]`. */
const INSPECT_SPEC: CommandHelpSpec = { valueFlags: ['--history'] };

/** `iron-dome activate --profile X`, `scan --text X | --file X`, `audit --search X`. */
const IRON_DOME_SPEC: CommandHelpSpec = { valueFlags: ['--profile', '--text', '--file', '--search'] };

/**
 * `scan "<text>" [--source=TYPE] [--identifier=ID]`: the text is data (no verb
 * slot) and `--` ends the options, so `scan -- --help` scans "--help" (#767).
 */
const SCAN_SPEC: CommandHelpSpec = {
  valueFlags: ['--source', '--identifier'],
  verbDepth: 0,
  doubleDashEndsOptions: true,
};

/** `xray <target> [--deep] [--json] …`: the target is a package, file or directory. */
const XRAY_SPEC: CommandHelpSpec = { valueFlags: [], verbDepth: 0 };

/**
 * `hook <name>`: the first argument is the name of a built-in or custom hook,
 * looked up without reserving any word — a custom hook may be named "help", and
 * `hook help` runs it (#767 round 2). The payload comes on stdin; only the flags
 * ask for usage.
 */
const HOOK_SPEC: CommandHelpSpec = { valueFlags: [], verbDepth: 0 };

/**
 * `cortex <verb> --key value …`: a generic parser (src/cortex/cli.ts) that
 * consumes the token after EVERY `--key`, so the row is the rule rather than a
 * list (#767 round 2). `cortex capture --what --help --category code …` captures
 * the mistake "--help"; `cortex capture --what x --help` asks for usage.
 */
const CORTEX_SPEC: CommandHelpSpec = { valueFlags: [], everyLongFlagTakesValue: true };

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
 * #767 registered the rest of the dispatched commands: the dispatcher's own gate
 * (`src/cli/dispatch-help.ts`) reads this table before any handler module is
 * imported, so `consolidate --help` no longer opens the database and
 * `api --help` no longer starts a server. Commands absent here are gated inside
 * their own handler (`doctor`, `setup`, `maintain`, `mcp`, `ledger`, …) and
 * `argvWantsHelp` keeps its conservative reading for them.
 *
 * Aliases share the spec OBJECT, so `compact`/`clawdbot`/`licence` cannot drift
 * from `vacuum`/`openclaw`/`license` either.
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
  logs: NO_VALUE_FLAGS,         // #573 `logs prune [--execute]` deletes files
  // ── #767: gated by the dispatcher, before the handler module is imported ──
  hook: HOOK_SPEC,              // `hook <name>`: the name is data, not a verb
  protect: PROTECT_SPEC,
  quickstart: NO_VALUE_FLAGS,   // `quickstart [target|--yes|--install-detected]`
  copilot: NO_VALUE_FLAGS,
  codex: NO_VALUE_FLAGS,
  service: NO_VALUE_FLAGS,      // `service <verb> [--dashboard|--api|--headless|--clean-logs]`
  config: CONFIG_SPEC,
  cloud: NO_VALUE_FLAGS,        // `cloud sync --full`
  'review-copilot': REVIEW_COPILOT_SPEC,
  remember: REMEMBER_SPEC,
  approve: APPROVE_SPEC,
  deny: DENY_SPEC,
  freeze: FREEZE_SPEC,
  unfreeze: NO_VALUE_FLAGS,
  lease: NO_VALUE_FLAGS,        // takes no arguments
  status: NO_VALUE_FLAGS,       // takes no arguments
  graph: INDEX_SPEC,            // `graph backfill [--force]`
  'threat-graph': INDEX_SPEC,
  license: NO_VALUE_FLAGS,
  licence: NO_VALUE_FLAGS,      // British-spelling alias
  stats: NO_VALUE_FLAGS,        // takes no arguments
  guard: GUARD_SPEC,
  memory: MEMORY_SPEC,
  inspect: INSPECT_SPEC,
  'iron-dome': IRON_DOME_SPEC,
  scan: SCAN_SPEC,
  'scan-skill': SCAN_SKILL_SPEC,
  env: INDEX_SPEC,              // `env scan <url> [--json|--markdown]`
  'scan-skills': INDEX_SPEC,    // `scan-skills [--dir <path>]`
  consolidate: INDEX_SPEC,      // takes no arguments
  xray: XRAY_SPEC,
  'xray-preinstall': NO_VALUE_FLAGS, // takes no arguments
  cortex: CORTEX_SPEC,          // generic `--k v` parser behind a verb: every `--key` takes a value
  api: INDEX_SPEC,              // server modes: `parseArgs()` reads --db / --mode
  dashboard: INDEX_SPEC,
  worker: INDEX_SPEC,
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
  let tokens: readonly string[] = args;
  // The tokens the handler never parses as options are not the gate's to read
  // either: everything after `--` for an end-of-options parser, everything
  // after a rest-consuming option.
  if (spec.doubleDashEndsOptions) {
    const end = tokens.indexOf('--');
    if (end !== -1) tokens = tokens.slice(0, end);
  } else if (spec.stripDoubleDash) {
    tokens = tokens.filter((a) => a !== '--');
  }
  if (spec.restFlags?.length) {
    const rest = tokens.findIndex((a) => spec.restFlags!.includes(a));
    if (rest !== -1) tokens = tokens.slice(0, rest);
  }
  return wantsHelp(tokens, {
    valueFlags: spec.valueFlags,
    verbDepth: spec.verbDepth,
    everyLongFlagTakesValue: spec.everyLongFlagTakesValue,
  });
}

/**
 * The gate for a WHOLE command line (`process.argv.slice(2)`) — the npm
 * staleness preamble and the stats banner in `src/index.ts`.
 *
 * It finds the command word and then asks that command's own question about the
 * rest, so its verdict is the destination handler's verdict by construction.
 * An explicit `--help` / `-h` BEFORE the command word is the top-level help
 * request; after it, the command's own table decides, so `scan -- --help` is
 * the scan of "--help" to both gates (#767). An unregistered command word keeps
 * the old conservative reading: `help` in the verb slot counts, no option values
 * are skipped — those commands print no usage for a bare `help` anyway, and a
 * false positive here only skips a staleness warning, while a false negative is
 * the defect this function exists to close.
 */
export function argvWantsHelp(argv: readonly string[]): boolean {
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') return true;
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
