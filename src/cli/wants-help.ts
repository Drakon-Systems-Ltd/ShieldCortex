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
 * Which tokens ARE values is a fact about each option's parser, not about the
 * gate (#767 round 3). Round 2 stepped over the token after every declared
 * value flag, which is what `remember`'s parser does and is NOT what
 * `sessions`' does: its `flagValue` returns "no value" for a token starting
 * with `--` and leaves it unread, so `sessions prune --days --help` was a help
 * request to the handler, a swallowed value to the gate, and a prune with the
 * default window to the operator. Every value-taking option therefore carries
 * its parser's rule (`ValueRule`), and a command whose verbs parse the same
 * option differently carries a row per verb (`CommandHelpSpec.verbs`).
 *
 * `COMMAND_HELP_SPECS` is that table, once, for every gate — see
 * `argvWantsHelp` and `commandWantsHelp`. `wantsHelp` itself stays the
 * table-free primitive both are built from.
 */

/**
 * How a value-taking option's parser reads the token after it (#767 round 3).
 *
 * The question the gate has to answer is "would the handler read the next
 * token as this option's value?", because a token the handler reads as a value
 * is never a flag to it, and a token it leaves unread is whatever it looks like
 * — a help flag, when it is spelled like one. The three answers the handlers
 * in this repository give:
 */
export type ValueRule =
  /**
   * The next token is the value whatever it is: a `parseFlag` / `args[i + 1]`
   * read with no shape check (`remember --content`, `memory --reason`,
   * `guard --surface`, `parseArgs` in src/index.ts, Cortex's `--key value`).
   * `--content --help` is content spelled "--help"; `--content -h` likewise.
   */
  | 'always'
  /**
   * A next token starting with `--` is "no value" and is left unread: the
   * `flagValue` helpers in sessions / migrate-legacy, audit `--deps-path`,
   * protect `--config`, config's enum flags. `--days --help` is a help request;
   * `--days -h` is the (invalid) value "-h", exactly as those parsers read it.
   */
  | 'unless-double-dash'
  /**
   * A next token starting with `-` is "no value" and is left unread (or refused
   * as a missing value): allowlist, import-native, reclassify, openclaw
   * `--agent`, scan `--source`. Both `--help` and `-h` after such an option are
   * help requests.
   */
  | 'unless-dash';

/** The value-taking options of one argv shape, each with its parser's rule. */
export type ValueRules = Readonly<Record<string, ValueRule>>;

/** Whether the parser behind `rule` reads `next` as the option's value. */
export function consumesAsValue(rule: ValueRule, next: string | undefined): boolean {
  switch (rule) {
    case 'always':
      return next !== undefined;
    case 'unless-double-dash':
      return !!next && !next.startsWith('--');
    case 'unless-dash':
      return !!next && !next.startsWith('-');
  }
}

function hasOwn(table: Readonly<Record<string, unknown>>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(table, key);
}

/** Options that consume the following token as their value, per command. */
export interface WantsHelpOptions {
  /**
   * The command's value-taking options (`--agent`, `--project`, `--days`, …),
   * each with the rule its parser applies to the following token. A token the
   * rule reads as the value is never a verb or a flag. Omit it only for
   * commands whose options are all boolean.
   */
  values?: ValueRules;
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
   * finite `values` table exists. `cortex capture --what --help` is the
   * mistake "--help", not a help request; `--help` at an option position still
   * is one, because the help check runs before the consumption rule.
   */
  everyLongFlagTakesValue?: boolean;
}

function ruleFor(token: string, values: ValueRules, everyLongFlagTakesValue: boolean | undefined): ValueRule | undefined {
  if (hasOwn(values, token)) return values[token];
  if (everyLongFlagTakesValue && token.startsWith('--')) return 'always';
  return undefined;
}

export function wantsHelp(args: readonly string[], options: WantsHelpOptions = {}): boolean {
  const values = options.values ?? {};
  const verbDepth = options.verbDepth ?? 1;
  let positional = 0;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    // An explicit help flag counts at any OPTION position. A token in a VALUE
    // position never reaches this line — the branch below steps over it — so
    // `--content --help` is content spelled "--help", not a request for usage.
    if (a === '--help' || a === '-h') return true;
    // `--flag value` — step over the value exactly when the parser would read
    // the token as one; a token the parser leaves unread is read here on its
    // own turn. `--flag=value` is one token and falls through to the option
    // branch below.
    const rule = ruleFor(a, values, options.everyLongFlagTakesValue);
    if (rule !== undefined) {
      if (consumesAsValue(rule, args[i + 1])) i++;
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
 * The option values `parseArgs()` in src/index.ts consumes from ANY command
 * line, before or after the command word: `--db <path>` and `--mode <mode>`,
 * each read unconditionally (`args[i + 1]` whenever it is truthy), so
 * `--db --help` is the database path "--help" to the parser and to the gates.
 * Used to find the command word itself (`shieldcortex --db /tmp/x.db audit
 * help`) and as the row of every command handled inline in `main()`.
 *
 * `--dir` is NOT here (#767 round 3): only `scan-skills` reads it, and it was
 * on this shared row, so `api --dir --help` was "--dir with the directory
 * --help" to the gates and reached server startup. `SCAN_SKILLS_SPEC` is the one
 * row that carries it.
 */
export const GLOBAL_VALUES: ValueRules = { '--db': 'always', '--mode': 'always' };

/** The flags of `GLOBAL_VALUES`, for the tests that enumerate the global inventory. */
export const GLOBAL_VALUE_FLAGS: readonly string[] = Object.keys(GLOBAL_VALUES);

/** How one command's argv is read, for every gate that decides about it. */
export interface CommandHelpSpec {
  /**
   * The options whose FOLLOWING token the command reads as a value, each with
   * the rule its parser applies (#767 round 3). Every `args[i + 1]` /
   * `indexOf(flag) + 1` / `flagValue(args, flag)` consumer in the command's own
   * call graph must be represented here or on one of its verb rows; the shapes
   * the analyser recognises are checked by `value-flag-inventory-577.test.ts`,
   * see its header for what it does not recognise. The rules themselves are
   * read out of each parser by hand and pinned in cli-help-gate-767.test.ts.
   */
  values: ValueRules;
  /**
   * Every value-taking option of the command: the keys of `values` and of each
   * verb row. DERIVED by `helpSpec()`, never written by hand, so the array the
   * handler modules re-export and the tests enumerate cannot disagree with the
   * rules the gate applies.
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
   * there is no finite `values` table to write down; the rule itself is the
   * row (#767 round 2). See `WantsHelpOptions.everyLongFlagTakesValue`.
   */
  everyLongFlagTakesValue?: boolean;
  /**
   * A row per verb, for a command whose verbs hand their arguments to DIFFERENT
   * parsers (#767 round 3). When the first token is one of these verbs, that
   * verb's row — not `values` — reads everything after it, with no verb slot
   * left (`memories prune help` is an argument to prune, as before).
   *
   * `memories` needs this: `prune --project` goes through a `flagValue` that
   * refuses a `--` value, `import-native --project` through a parser that
   * refuses any `-` value and honours `--`, and `embed-backfill --limit` through
   * a `readFlag` that reads the next token whatever it is. One flat row cannot
   * say all three, and saying the wrong one is this round's blocker.
   */
  verbs?: Readonly<Record<string, CommandHelpSpec>>;
}

type HelpSpecShape = Omit<CommandHelpSpec, 'values' | 'valueFlags'>;

/**
 * Build a row. `valueFlags` is derived from `values` and the verb rows here,
 * which is the only place it is ever written.
 */
export function helpSpec(values: ValueRules, shape: HelpSpecShape = {}): CommandHelpSpec {
  const flags = new Set(Object.keys(values));
  for (const row of Object.values(shape.verbs ?? {})) for (const f of row.valueFlags) flags.add(f);
  return { values, valueFlags: [...flags], ...shape };
}

/**
 * `audit --deps-path <path>`: `parseAuditArgs` reads the path only when it does
 * not start with `--` (src/cli/audit.ts). `--deps-path help` is a path to scan
 * (#577); `--deps-path --help` is a help request (#767 round 3).
 */
const AUDIT_SPEC = helpSpec({ '--deps-path': 'unless-double-dash' });

/**
 * `allowlist`: `scan`'s path/glob options and `add --note help` — a reviewer's
 * one-word reason. Both parsers refuse any `-`-leading value as missing
 * (src/cli/allowlist-scan.ts `runAllowlistScan`, src/cli/allowlist.ts `add`).
 * #577 round 3 found `--note` missing: the add handler consumes the token after
 * it, so the inventory was not complete.
 */
const ALLOWLIST_SPEC = helpSpec(
  {
    '--glob': 'unless-dash',
    '--hermes-cron': 'unless-dash',
    '--openclaw-cron': 'unless-dash',
    '--openclaw-cron-db': 'unless-dash',
    '--note': 'unless-dash',
  },
  { stripDoubleDash: true },
);

/**
 * `sessions prune --days N`: `flagValue` (src/cli/sessions.ts) returns "no
 * value" for a token starting with `--` and leaves it unread. `--days help` is a
 * value (rejected later, as a number); `--days --help` is the help request that
 * round 2 swallowed and ran a prune on (#767 round 3, B3).
 */
const SESSIONS_SPEC = helpSpec({ '--days': 'unless-double-dash' });

/**
 * `memories`: a row per verb, because the verbs parse the same options
 * differently (src/cli/migrate-legacy.ts unless noted):
 *   migrate-legacy  `--source`: `args[sourceIdx + 1]` whenever truthy.
 *   prune / dedupe / repair-project-keys / purge / recalc: `flagValue`, which
 *                   refuses a `--` value (`--map`: `args[i + 1]` whenever truthy).
 *   import-native   (src/cli/import-native.ts): `args[++i]`, refused when it
 *                   starts with `-`; a bare `--` ends the options.
 *   embed-backfill  (src/cli/embed-backfill.ts): `readFlag` reads `args[i + 1]`
 *                   whatever it is for `--limit`; `--project` is then refused
 *                   when it starts with `-` (`parseEmbedBackfillProject`).
 *   reclassify      (src/cli/reclassify.ts): `--project` refused when it starts
 *                   with `-`.
 * A project key or a source path may spell "help"; the command-level row is
 * empty because every option belongs to a verb, and `memories <not-a-verb> …`
 * prints usage in the handler.
 */
const MEMORIES_SPEC = helpSpec({}, {
  verbs: {
    'migrate-legacy': helpSpec({ '--source': 'always' }),
    prune: helpSpec({
      '--salience-lte': 'unless-double-dash',
      '--older-than': 'unless-double-dash',
      '--project': 'unless-double-dash',
    }),
    dedupe: helpSpec({ '--project': 'unless-double-dash', '--limit': 'unless-double-dash' }),
    'repair-project-keys': helpSpec({
      '--map': 'always',
      '--scan-paths': 'unless-double-dash',
      '--project': 'unless-double-dash',
      '--db': 'unless-double-dash',
    }),
    purge: helpSpec({ '--backup-dir': 'unless-double-dash' }),
    recalc: helpSpec({ '--backup-dir': 'unless-double-dash', '--db': 'unless-double-dash' }),
    'import-native': helpSpec(
      { '--host-id': 'unless-dash', '--agent-id': 'unless-dash', '--project': 'unless-dash' },
      { doubleDashEndsOptions: true },
    ),
    'embed-backfill': helpSpec({ '--limit': 'always', '--project': 'unless-dash' }),
    reclassify: helpSpec({ '--project': 'unless-dash' }),
  },
});

/**
 * `openclaw skill install|update --agent <id>`: `skill install --agent help`
 * installs for the agent "help"; an id starting with `-` is refused as missing
 * (src/setup/openclaw.ts), so `--agent --help` is a help request.
 */
const OPENCLAW_SPEC = helpSpec({ '--agent': 'unless-dash' });

/**
 * The strict-parser commands, `hermes`, and every command whose options are all
 * boolean or whose handler reads a fixed positional and nothing else
 * (`copilot <verb>`, `license <verb> [key]`, `lease`, `stats`, …).
 */
const NO_VALUE_FLAGS = helpSpec({});

/**
 * Commands handled inline in `src/index.ts` (`consolidate`, `graph`, `env`, …)
 * and the three server modes (`api`, `dashboard`, `worker`). The only option
 * values `main()` consumes from their argv are the global ones `parseArgs()`
 * reads for every command — `--db <path>` / `--mode <mode>` — so their row IS
 * the global inventory (#767). Nothing else: `api --dir --help` is an unknown
 * option and a help flag, not a directory (#767 round 3, B4).
 */
const INDEX_SPEC = helpSpec(GLOBAL_VALUES);

/**
 * `scan-skills [--dir <path>]`: the one inline command with an option of its
 * own. The directory is read as `process.argv[indexOf('--dir') + 1]`, whatever
 * it is, so `--dir --help` scans a directory named "--help" and `--dir x --help`
 * asks for usage.
 */
const SCAN_SKILLS_SPEC = helpSpec({ ...GLOBAL_VALUES, '--dir': 'always' });

/** `scan-skill <path>`: inline like the above, but its first positional is a file. */
const SCAN_SKILL_SPEC = helpSpec(GLOBAL_VALUES, { verbDepth: 0 });

/**
 * `protect`: `parseProtectArgs` (src/cli/protect.ts) reads `--config`'s path
 * only when it does not start with `--`, and `--agent-uid`'s token whatever it
 * is (a malformed uid is refused by name). `--config help` is a config path and
 * `--config --help` a help request; `--agent-uid --help` is the uid "--help"
 * (#767).
 */
const PROTECT_SPEC = helpSpec({ '--config': 'unless-double-dash', '--agent-uid': 'always' });

/**
 * `config`: every option `handleCloudConfig` (src/cloud/cli.ts) reads the
 * following token of. The values are enums, keys, URLs and numbers; a bare
 * `help` after any of them is that option's (invalid) value, and the handler is
 * the one to refuse it. Nine of them read `args[idx + 1]` whenever it is
 * truthy and refuse it as INVALID; the six signed-write and webhook options
 * refuse a `--`-leading token as MISSING without reading it.
 */
const CONFIG_SPEC = helpSpec({
  '--mode': 'always',
  '--cloud-api-key': 'always',
  '--cloud-url': 'always',
  '--verify-mode': 'always',
  '--verify-timeout': 'always',
  '--openclaw-auto-memory': 'always',
  '--ranker': 'always',
  '--proactive-recall': 'always',
  '--self-heal': 'always',
  '--action-guard-notify-webhook': 'unless-double-dash',
  '--memory-inject-contract': 'unless-double-dash',
  '--memory-plane': 'unless-double-dash',
  '--memory-host-posture': 'unless-double-dash',
  '--memory-host-runtime': 'unless-double-dash',
  '--auto-memory-sampling': 'unless-double-dash',
});

/** `review-copilot annotate --id <id> | --pending [--limit N]`: `Number(args[idx + 1])`. */
const REVIEW_COPILOT_SPEC = helpSpec({ '--id': 'always', '--limit': 'always' });

/**
 * `remember "<title>" --content <text> …`: the first positional is the memory's
 * title, so there is no verb slot — a memory titled "help" is a memory (#767).
 * `parseFlag` reads the next token whatever it is: `--content --help` is content.
 */
const REMEMBER_SPEC = helpSpec(
  { '--content': 'always', '--category': 'always', '--importance': 'always', '--tags': 'always', '--project': 'always' },
  { verbDepth: 0 },
);

/** `approve [<hash>] [--ttl N] [--attempt <id>] …`; the handler drops bare `--`. */
const APPROVE_SPEC = helpSpec({ '--ttl': 'always', '--attempt': 'always' }, { stripDoubleDash: true });

/** `deny [<hash>] [--attempt <id>]`; the handler drops bare `--`. */
const DENY_SPEC = helpSpec({ '--attempt': 'always' }, { stripDoubleDash: true });

/** `freeze <scope> --reason <every following token>`. */
const FREEZE_SPEC = helpSpec({}, { restFlags: ['--reason'] });

/** `guard readiness|test-approval [--surface claude-code|openclaw]`: `argv[surfaceAt + 1]`. */
const GUARD_SPEC = helpSpec({ '--surface': 'always' });

/** `memory downvote <id> --reason <text>` / `memory list --purpose X --category X --limit N`: `parseFlag`. */
const MEMORY_SPEC = helpSpec({ '--reason': 'always', '--purpose': 'always', '--category': 'always', '--limit': 'always' });

/** `inspect last-precompact|last-recall [--history N]`: `parseFlag`. */
const INSPECT_SPEC = helpSpec({ '--history': 'always' });

/** `iron-dome activate --profile X`, `scan --text X | --file X`, `audit --search X`: `args[idx + 1]`. */
const IRON_DOME_SPEC = helpSpec({ '--profile': 'always', '--text': 'always', '--file': 'always', '--search': 'always' });

/**
 * `scan "<text>" [--source=TYPE] [--identifier=ID]`: the text is data (no verb
 * slot) and `--` ends the options, so `scan -- --help` scans "--help" (#767).
 * `takeFlagValue` refuses a `-`-leading value, so `--source --help` is a help
 * request.
 */
const SCAN_SPEC = helpSpec(
  { '--source': 'unless-dash', '--identifier': 'unless-dash' },
  { verbDepth: 0, doubleDashEndsOptions: true },
);

/** `xray <target> [--deep] [--json] …`: the target is a package, file or directory. */
const XRAY_SPEC = helpSpec({}, { verbDepth: 0 });

/**
 * `hook <name>`: the first argument is the name of a built-in or custom hook,
 * looked up without reserving any word — a custom hook may be named "help", and
 * `hook help` runs it (#767 round 2). The payload comes on stdin; only the flags
 * ask for usage.
 */
const HOOK_SPEC = helpSpec({}, { verbDepth: 0 });

/**
 * `cortex <verb> --key value …`: a generic parser (src/cortex/cli.ts) that
 * consumes the token after EVERY `--key`, so the row is the rule rather than a
 * list (#767 round 2). `cortex capture --what --help --category code …` captures
 * the mistake "--help"; `cortex capture --what x --help` asks for usage.
 */
const CORTEX_SPEC = helpSpec({}, { everyLongFlagTakesValue: true });

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
  'scan-skills': SCAN_SKILLS_SPEC, // `scan-skills [--dir <path>]`: the only inline command with its own option
  consolidate: INDEX_SPEC,      // takes no arguments
  xray: XRAY_SPEC,
  'xray-preinstall': NO_VALUE_FLAGS, // takes no arguments
  cortex: CORTEX_SPEC,          // generic `--k v` parser behind a verb: every `--key` takes a value
  api: INDEX_SPEC,              // server modes: `parseArgs()` reads --db / --mode and nothing else
  dashboard: INDEX_SPEC,
  worker: INDEX_SPEC,
} as const satisfies Record<string, CommandHelpSpec>;

/** A command word with an entry in `COMMAND_HELP_SPECS`. */
export type GatedCommand = keyof typeof COMMAND_HELP_SPECS;

export function isGatedCommand(word: string): word is GatedCommand {
  return hasOwn(COMMAND_HELP_SPECS, word);
}

/**
 * The gate a command applies to its OWN argv — everything after the command
 * word, exactly what `main()` hands the handler.
 *
 * Every per-command gate goes through here (directly or via `helpGate`), so the
 * command word is the only thing a caller chooses; the table supplies the rest.
 */
export function commandWantsHelp(command: GatedCommand, args: readonly string[]): boolean {
  return rowWantsHelp(COMMAND_HELP_SPECS[command], args, COMMAND_HELP_SPECS[command].verbDepth ?? 1);
}

/**
 * One row applied to the argv it describes. A verb row is applied to the tokens
 * after its verb with no verb slot left: the verb has been chosen.
 */
function rowWantsHelp(row: CommandHelpSpec, args: readonly string[], verbDepth: number): boolean {
  if (row.verbs && args.length > 0 && hasOwn(row.verbs, args[0])) {
    return rowWantsHelp(row.verbs[args[0]], args.slice(1), 0);
  }
  let tokens: readonly string[] = args;
  // The tokens the handler never parses as options are not the gate's to read
  // either: everything after `--` for an end-of-options parser, everything
  // after a rest-consuming option.
  if (row.doubleDashEndsOptions) {
    const end = tokens.indexOf('--');
    if (end !== -1) tokens = tokens.slice(0, end);
  } else if (row.stripDoubleDash) {
    tokens = tokens.filter((a) => a !== '--');
  }
  if (row.restFlags?.length) {
    const rest = tokens.findIndex((a) => row.restFlags!.includes(a));
    if (rest !== -1) tokens = tokens.slice(0, rest);
  }
  return wantsHelp(tokens, {
    values: row.values,
    verbDepth,
    everyLongFlagTakesValue: row.everyLongFlagTakesValue,
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
    if (hasOwn(GLOBAL_VALUES, a)) {
      if (consumesAsValue(GLOBAL_VALUES[a], argv[i + 1])) i++;
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
