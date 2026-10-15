/**
 * The dispatcher's help gate (#767).
 *
 * `shieldcortex consolidate --help` ran memory maintenance and created the
 * database; `api --help` started the API server; `stats`, `deny`, `lease`,
 * `protect`, `scan-skill`, `graph backfill`, `service install` … all ignored
 * the flag and did the thing. `quickstart --help` fell through to a usage ERROR.
 * A help flag is the operator's one chance to read what a command does before
 * it does it, and the obvious thing for an agent to run when discovering a tool
 * — so an ungated help flag turns discovery into a write.
 *
 * `main()` in `src/index.ts` calls `dispatchHelp()` FIRST — before the `hook`
 * branch, the strict preflight, the npm staleness preamble, the stats banner
 * and every lazy `await import(...)` of a handler module. The gate is pure: it
 * reads this table and the shared registry in `wants-help.ts`, prints the
 * command's usage to stdout and returns. Nothing below it runs.
 *
 * Why the usage text lives HERE and not in each handler: the handler modules
 * are imported lazily precisely so that a CLI command pays only for what it
 * runs, and several of them pull in the database layer or the defence pipeline
 * on import. Printing usage must not load any of that. Handlers that print the
 * same usage on their own error paths import the constant from this module, so
 * there is one copy of each text; this module imports nothing but the registry
 * and the scan exit contract (both already on the CLI's startup graph).
 *
 * Commands NOT in this table are gated inside their own handler, before any
 * side effect: the #577 strict/help-gated set (`update`, `repair`, `migrate`,
 * `uninstall`, `vacuum`/`compact`, `logs`, `audit`, `allowlist`, `sessions`,
 * `memories`, `openclaw`/`clawdbot`, `hermes`), `setup`/`install`/`doctor`
 * (#707), `maintain`, `policy-evidence`, `import-jsonl`, `ledger`, `mcp`.
 */
import { SCAN_USAGE_LINES } from './scan-exit.js';
import { commandWantsHelp, isGatedCommand, type GatedCommand } from './wants-help.js';

const bold = '\x1b[1m';
const reset = '\x1b[0m';

/** `hook`: the built-in names must match `BUILT_IN_HOOKS` in src/setup/hooks.ts (pinned by test). */
export const HOOK_HELP = `Usage: shieldcortex hook <name>

Run one ShieldCortex hook; the host's hook payload is read from stdin.
Built-in hooks: pre-compact, session-start, session-end, stop, prompt-recall, pre-tool
Custom hooks: the customHooks entries in ~/.shieldcortex/config.json, by name.
  -h, --help   Show this help and exit (runs no hook)`;

/** `protect`: the flags `parseProtectArgs` in src/cli/protect.ts reads; this module never imports it. */
export const PROTECT_HELP = `Usage: shieldcortex protect [--dry-run] [--from-config] [--config <path>] [--agent-uid <uid>]

Pin the security-critical config to a root-owned policy lock the agent uid
cannot write (needs root). Without --from-config it pins the safe posture and
never reads config.json.

Options:
  --dry-run            Report what would be written; write nothing
  --from-config        Pin config.json's current values instead of the safe posture
  --config <path>      The config.json to read with --from-config
  --agent-uid <uid>    The uid the agent runs as, when the invoking shell gives
                       protect no other way to learn it (no SUDO_UID)
  -h, --help           Show this help and exit (writes nothing)`;

export const QUICKSTART_HELP = `Usage: shieldcortex quickstart [claude|openclaw|hermes|copilot|codex|security|--yes|--install-detected]

Older name for the guided setup path: the same as \`shieldcortex setup [target]\`
without the hook flags or uninstall. With no target it shows the host table and
asks before wiring each host; --yes / --install-detected wires every detected
host without asking.
  -h, --help   Show this help and exit (wires nothing)`;

export const COPILOT_HELP = `Usage: shieldcortex copilot <install|uninstall|status>

  install    Configure ShieldCortex MCP server for VS Code and Cursor
  uninstall  Remove ShieldCortex MCP server configuration
  status     Check current configuration`;

export const CODEX_HELP = `Usage: shieldcortex codex <install|uninstall|status>

Configures ShieldCortex in ~/.codex/config.toml for Codex CLI
and the Codex VS Code extension.`;

export const SERVICE_HELP = `Usage: shieldcortex service <install|repair|uninstall|status> [--dashboard|--api|--headless]

  install    Install the persistent ShieldCortex service (--headless is recommended for always-on servers)
  repair     Rebuild the service with the current install path
  uninstall  Remove the service (--clean-logs also removes its log files)
  status     Check service status`;

export const CONFIG_HELP = `Usage: shieldcortex config [options]

Options:
  --mode <mode>          Set defence mode (strict|balanced|permissive)
  --cloud-api-key <key>  Set cloud API key
  --cloud-url <url>      Set cloud base URL
  --cloud-enable         Enable cloud sync
  --cloud-disable        Disable cloud sync
  --cloud-include-sensitive  Sync CONFIDENTIAL+ memories (off by default since v4.27)
  --cloud-exclude-sensitive  Stop syncing CONFIDENTIAL+ memories (default)
  --cloud-status         Show current configuration
  --openclaw-auto-memory <true|false>  Extract memories from OpenClaw LLM output (off when unset)
  --proactive-recall <true|false>  Inject SC memory into prompts (off when unset — adds latency)
                            A fresh global npm install (not CI) with no ~/.shieldcortex/config.json
                            writes both as true. An existing config.json is never changed, so an
                            upgrade keeps your current values; a key it does not set stays off
  --ranker <rrf|legacy>  Hybrid retrieval engine (default: rrf; SHIELDCORTEX_RANKER env overrides)
  --self-heal <true|false>  Let the cortex-memory hook repair its own install at gateway bootstrap
                            (default: true; false = warn-only. SHIELDCORTEX_SKIP_SELF_HEAL=1 also opts out)
  --tool-firewall-enforce   Redact/withhold threatening tool output before the agent sees it
  --tool-firewall-advisory  Log tool-output threats but deliver intact (default)
  --tool-firewall-off / --tool-firewall-on  Disable / enable tool-output scanning
  --allow-revoke-by-source / --disallow-revoke-by-source  Enable/disable destructive forget --fromSource (default: disabled)
  --policy-status          Show the OS-owned policy lock: pinned keys, or why there is none
  --action-guard-enable    Turn Action Guard on, keeping the current enforce/advisory setting (default: off)
  --action-guard-disable   Turn Action Guard off entirely — tool calls are NOT gated (the default)
  --action-guard-enforce   Gate dangerous ops (approval/block) from now on; also enables the guard
  --action-guard-enforce-when-ready  Log ordinary dangerous ops (shadow) until two readiness proxies hold here
                           (≤ 2% would-stop, ≥ 98% of approvals answered by a human) AND reviewed
                           effectiveness evidence exists for this version — always required, none
                           published yet, so it stays in shadow today. Needs a webhook;
                           progress: shieldcortex guard readiness. Claude Code hook and OpenClaw
                           plugin, each measured on its own calls; Hermes ignores the gate and
                           enforces immediately. Also enables the guard
  --action-guard-advisory  Watch only — ordinary dangerous ops log but are not gated. Still held or
                           blocked, including catastrophic ops and calls the guard recognises as
                           changing its own state/config or disabling it. Hermes has its own
                           enforce setting (SHIELDCORTEX_ENFORCE), which this does not change
  --action-guard-notify-openclaw  Notify Action Guard denials via the native OpenClaw approval card
  --action-guard-notify-webhook <https-url>  Notify Action Guard denials to an https webhook
  --action-guard-notify-disable   Disable Action Guard denial notifications
  --memory-inject-contract <sc_only|disable_native_inject>  Set the memory-inject native contract (signed write)
  --memory-plane <dual_legacy|import_only|sc_canonical>  Set memory.plane (signed write; stamps planeSetAt)
  --memory-host-posture <mcp_sidecar_no_inject|bus_contract>  Honest sidecar (also turns inject off) or bus-contract posture (signed write)
  --memory-host-runtime <openclaw|claude_code|hermes>[,…]  Declare the bound host runtime(s) doctor must prove (signed write)
  --auto-memory-sampling <n>  Stop-hook sampling cadence in turns (1-20, ≤ 5 recommended; signed write)
  --restore-4.10-defaults  Restore pre-v4.11.0 defaults (recall on, strict interceptor, minimal preamble)

LLM Verification:
  --verify-enable        Enable LLM verification (requires cloud + verify scope)
  --verify-disable       Disable LLM verification
  --verify-mode <mode>   Set verify mode (advisory|enforce)
  --verify-timeout <ms>  Set verify timeout in ms (1000-30000)`;

export const CLOUD_HELP = `Usage: shieldcortex cloud sync --full

Backfill every local memory and the knowledge graph to ShieldCortex Cloud.
Needs cloud sync configured and enabled (shieldcortex config --cloud-api-key <key> --cloud-enable).`;

export const REVIEW_COPILOT_HELP = `Usage: shieldcortex review-copilot <enable|disable|status|download-model|annotate> [options]

Commands:
  enable [--accept-download]       Enable Local AI Explainer
  disable [--purge]                Disable Local AI Explainer; --purge removes cached model files
  status                           Show config and recent metadata-only telemetry
  download-model [--accept-download]  Download/preload the configured local model
  annotate --pending [--limit N]   Explain pending quarantine items
  annotate --id <id>               Explain one pending quarantine item`;

export const REMEMBER_HELP = `Usage: shieldcortex remember "<title>" --content "<text>" [options]
       echo "<text>" | shieldcortex remember "<title>"

Options:
  --content <text>          Memory content (or pipe it via stdin)
  --category <category>     architecture|pattern|preference|error|context|
                            learning|todo|note|relationship|custom
  --importance <level>      low | medium | high
  --tags <a,b,c>            Comma-separated tags
  --project <name>          Project scope (auto-detected if omitted)
  --json                    Emit a structured JSON result`;

export const APPROVE_HELP = `Usage: shieldcortex approve [<hash>] [--ttl <minutes>] [--attempt <id>]
       shieldcortex approve --denial [<actionId>] [--ttl <minutes>] [--reauth] [--any-origin] [--override-deny]

Grant a one-shot Action Guard approval. With no hash it lists what the guard has
refused recently. Granting needs a human at a real terminal (stdin and stdout
TTYs) with operator provenance; there is no env-var escape hatch.
  <hash>                 Approve that exact HELD call, once (default --ttl 10 minutes)
  --denial [<actionId>]  List headless denials, or authorise ONE retry of that
                         action, scoped to the cwd and tool it was refused in
  --ttl <minutes>        Spend window for the grant (positive number of minutes)
  --attempt <id>         The delivered attempt this answer is for (printed in the notification)
  --reauth               After a missed or expired card: TTY grant, same identity
  --any-origin           Unscoped retry grant (confirmed; dangerous)
  --override-deny        Retry despite your own earlier Deny
  -h, --help             Show this help and exit (grants nothing)`;

export const DENY_HELP = `Usage: shieldcortex deny [<hash>] [--attempt <id>]

Reject a pending Action Guard approval request; the exact command is refused
again if the agent retries it. With no hash it lists what the guard has refused
recently. Denying needs a human at a real terminal (stdin and stdout TTYs) with
operator provenance; there is no env-var escape hatch.
  --attempt <id>   The delivered attempt this answer is for (printed in the notification)
  -h, --help       Show this help and exit (denies nothing)`;

/** `freeze`: the scopes must match `SCOPE_KEYWORDS` in src/defence/iron-dome/session-lease.ts (pinned by test). */
export const FREEZE_HELP = `Usage: shieldcortex freeze <npm-publish|install|gateway-restart|security-config|fleet-broadcast> --reason "<why, and what lifts it>"

Record a FROZEN decision for that scope in this host's decisions ledger; every
token after --reason is the reason. Operator-only: needs a real terminal (TTY),
with no env-var escape hatch. Lift it with: shieldcortex unfreeze <scope>
  -h, --help   Show this help and exit (freezes nothing)`;

export const UNFREEZE_HELP = `Usage: shieldcortex unfreeze <npm-publish|install|gateway-restart|security-config|fleet-broadcast>

Lift a freeze recorded by \`shieldcortex freeze\`: the ledger record is rewritten
from FROZEN to LIFTED, never deleted. Operator-only: needs a real terminal (TTY).
  -h, --help   Show this help and exit (lifts nothing)`;

export const LEASE_HELP = `Usage: shieldcortex lease

Show this host's session action lease: recorded freezes, held leases and which
enforcement planes are bound here. Read-only; takes no arguments.`;

export const STATUS_HELP = `Usage: shieldcortex status

Show the memory database (path, size, memory counts, projects, last activity),
defence counters and whether the Claude Code hooks are configured. Takes no
arguments and creates nothing: with no database it says so and exits.`;

export const GRAPH_HELP = `Usage: shieldcortex graph backfill [--force]

Extract knowledge-graph entities and triples from new or updated memories
(--force: from ALL memories). Opens the memory database.
  -h, --help   Show this help and exit (opens nothing)`;

export const THREAT_GRAPH_HELP = `Usage: shieldcortex threat-graph <command>

Commands:
  rebuild                      Re-project the threat graph from both audit ledgers
  status                       Cursor, last run, node counts, allowances, campaigns, conflicts
  campaigns                    Run campaign detection over recent events and list campaigns
  conflicts                    List open relation-channel conflicts
  reset-source '<source-key>'  Reset a source's accumulated risk (recorded as an operator review)
  resolve-conflict '<conflict:SUBJECT_ID:predicate>' <keep-one|keep-both|reject-both> ['<object-to-keep>']
Every command opens the memory database.
  -h, --help   Show this help and exit (opens nothing)`;

export const LICENSE_HELP = `Usage: shieldcortex license <activate <key>|status|deactivate>

  activate <key>   Activate a licence key
  status           Show current licence tier and features
  deactivate       Remove licence

Alias: shieldcortex licence
Enterprise licences: sales@drakonsystems.com`;

export const STATS_HELP = `Usage: shieldcortex stats

Print the security report: lifetime, 24-hour and 7-day scan, block and
quarantine counts, memory quality and hook activity. Opens the memory database
(creating it if absent); takes no arguments.
  -h, --help   Show this help and exit (opens nothing)`;

export const GUARD_HELP = `Usage: shieldcortex guard readiness [--surface claude-code|openclaw] [--json]
                                  Show the enforce-when-ready readiness conditions, per surface (#509)
       shieldcortex guard test-approval [--surface claude-code|openclaw]
                                  Send a synthetic approval request through your channel`;

export const MEMORY_HELP = `Usage: shieldcortex memory <subcommand> [args]

Subcommands:
  show <id>                          Show a single memory with effective-salience breakdown
  downvote <id> [--reason <text>]    Mark a memory unhelpful (reduces effective salience at recall)
  list [--purpose X] [--category X] [--limit N]   Table view (default 20 rows)
  revert-backfill                    Undo the v4.29.0 salience-wall clamp (restores pre-clamp salience)`;

export const INSPECT_HELP = `Usage: shieldcortex inspect <subcommand>

Subcommands:
  last-precompact [--history N | --all]    Show extractor candidates from the last precompact run
                                           --history N (0=newest, up to 9) — show slot N
                                           --all — show every entry in the ring buffer (newest first)

  last-recall [--history N | --all]        Show recall candidates from the last prompt-recall run
                                           (requires proactiveRecall=true; logs prompt + per-candidate
                                           FTS rank + effective salience + drop reason).
                                           Note: prompts are stored locally at ~/.shieldcortex/recall-log/
                                           — same trust boundary as memories.db.`;

export const IRON_DOME_HELP = `
${bold}Iron Dome — Behaviour Protection Layer${reset}

${bold}Usage:${reset}
  shieldcortex iron-dome activate [--profile <profile>]
  shieldcortex iron-dome status
  shieldcortex iron-dome deactivate
  shieldcortex iron-dome scan --text "..." | --file <path>
  shieldcortex iron-dome audit [--tail] [--search <term>]
  shieldcortex iron-dome confirmation list
  shieldcortex iron-dome confirmation move <action> <red|amber|green>
  shieldcortex iron-dome confirmation add <action> <red|amber|green>
  shieldcortex iron-dome confirmation remove <action>

${bold}Profiles:${reset}
  school       GDPR strict, pupil data locked
  enterprise   Financial protection, compliance
  personal     Lighter touch for personal use
  paranoid     Everything requires approval

${bold}Trusted local channels:${reset}
  terminal, cli, dashboard
`;

export const SCAN_HELP = SCAN_USAGE_LINES.join('\n');

export const SCAN_SKILL_HELP = `Usage: shieldcortex scan-skill <path> [--accept | --clear | --forget]
  Scans an agent instruction file for threats.
  Supports: SKILL.md, HOOK.md, handler.js, .cursorrules,
  .windsurfrules, .clinerules, CLAUDE.md, copilot-instructions.md,
  .aider.conf.yml, .continue/config.json

  --accept / --clear   Mark this file (by content hash) as reviewed &
                       acceptable — suppresses re-flagging until it changes.
  --forget             Remove a previously recorded acceptance.`;

export const ENV_HELP = `Usage: shieldcortex env scan <url> [--json | --markdown]
  Fetches the URL, scores provenance, detects hidden instructions,
  runs injection patterns against visible + hidden content, and returns a taint label.`;

export const SCAN_SKILLS_HELP = `Usage: shieldcortex scan-skills [--dir <path>]

Scan every installed agent instruction file (Claude Code skills, OpenClaw hooks,
.cursorrules, CLAUDE.md and more) and regenerate SHIELDCORTEX_WARNINGS.md in the
current directory to match. --dir <path> scans a custom directory instead.
Exit 1 when any file has unaccepted threats.
  -h, --help   Show this help and exit (scans and writes nothing)`;

export const CONSOLIDATE_HELP = `Usage: shieldcortex consolidate

Run memory maintenance on the memory database — promote worthy short-term
memories, expire decayed ones, evict over the caps in both tiers, resolve
identical long-term pairs — then Dream Mode consolidation (near-duplicate merge,
archival candidates, contradictions). Opens the database, creating it if absent;
takes no arguments.
  -h, --help   Show this help and exit (opens and changes nothing)`;

export const XRAY_HELP = `Usage: shieldcortex xray <target> [--deep] [--json] [--markdown] [--watch]

  target:     npm package name, local file path, or directory path
  --deep      Deep scan with full analysis
  --json      Output JSON result
  --markdown  Output markdown report
  --sarif     Output SARIF 2.1.0 (GitHub Code Scanning)
  --ci        CI/CD mode: exit code 1 if risk >= threshold
  --threshold=LEVEL  Risk threshold for --ci (CRITICAL|HIGH|MEDIUM|LOW, default: HIGH)
  --watch     Watch directory for changes and scan incrementally

Examples:
  shieldcortex xray ./src/
  shieldcortex xray package.json
  shieldcortex xray lodash --deep
  shieldcortex xray ./src --watch`;

export const XRAY_PREINSTALL_HELP = `Usage: shieldcortex xray-preinstall

npm lifecycle pre-install check: scans the scripts in ./package.json for
suspicious patterns and records the result in the X-Ray activity log.
Exit 1 blocks the install (HIGH or worse findings); exit 0 allows it.
Takes no arguments.
  -h, --help   Show this help and exit (scans and records nothing)`;

export const CORTEX_HELP = `
  Usage: shieldcortex cortex <command> [options]

  Commands:
    capture     Log a mistake and extract a prevention rule
    preflight   Pre-task check against past mistakes
    review      Pattern analysis and weekly review
    graduate    Archive learned rules (30+ days, no recurrence)
    list        Browse mistake log
    stats       Summary counts and trends
    search      Full-text search across all entries
    confirm     Log a positive confirmation (what worked well)
    confirmations  List or search confirmations

  Examples:
    shieldcortex cortex capture --category code --what "Guessed URLs" --why "Didn't use API" --rule "Always fetch handles from API"
    shieldcortex cortex preflight --task "deploy to Fly.io"
    shieldcortex cortex review
    shieldcortex cortex confirm --category code --what "Used TypeScript strict mode" --why-worked "Caught type errors early" --when-repeat "Always on new TS projects"
    shieldcortex cortex stats
  `;

export const API_HELP = `Usage: shieldcortex api [--db <path>]

Start the visualization API server on http://localhost:3001 (the same as
\`shieldcortex --mode api\`). Runs until stopped; if an API is already listening
there it says so and exits.
  -h, --help   Show this help and exit (starts nothing)`;

export const DASHBOARD_HELP = `Usage: shieldcortex dashboard [--db <path>]

Start the API server and the local dashboard on http://localhost:3030 (the same
as \`shieldcortex --dashboard\`), reusing either if it is already running. Runs
until stopped.
  -h, --help   Show this help and exit (starts nothing)`;

export const WORKER_HELP = `Usage: shieldcortex worker [--db <path>]

Run the headless background brain worker (sync + heartbeat), the same as
\`shieldcortex --mode worker\`. Runs until stopped.
  -h, --help   Show this help and exit (starts nothing)`;

/**
 * Every command the dispatcher gates, and the usage it prints. The key type
 * admits only a registered command, so a usage cannot be wired to a command
 * whose argv shape the registry does not describe.
 */
export const DISPATCH_HELP = {
  hook: HOOK_HELP,
  protect: PROTECT_HELP,
  quickstart: QUICKSTART_HELP,
  copilot: COPILOT_HELP,
  codex: CODEX_HELP,
  service: SERVICE_HELP,
  config: CONFIG_HELP,
  cloud: CLOUD_HELP,
  'review-copilot': REVIEW_COPILOT_HELP,
  remember: REMEMBER_HELP,
  approve: APPROVE_HELP,
  deny: DENY_HELP,
  freeze: FREEZE_HELP,
  unfreeze: UNFREEZE_HELP,
  lease: LEASE_HELP,
  status: STATUS_HELP,
  graph: GRAPH_HELP,
  'threat-graph': THREAT_GRAPH_HELP,
  license: LICENSE_HELP,
  licence: LICENSE_HELP,
  stats: STATS_HELP,
  guard: GUARD_HELP,
  memory: MEMORY_HELP,
  inspect: INSPECT_HELP,
  'iron-dome': IRON_DOME_HELP,
  scan: SCAN_HELP,
  'scan-skill': SCAN_SKILL_HELP,
  env: ENV_HELP,
  'scan-skills': SCAN_SKILLS_HELP,
  consolidate: CONSOLIDATE_HELP,
  xray: XRAY_HELP,
  'xray-preinstall': XRAY_PREINSTALL_HELP,
  cortex: CORTEX_HELP,
  api: API_HELP,
  dashboard: DASHBOARD_HELP,
  worker: WORKER_HELP,
} as const satisfies Partial<Record<GatedCommand, string>>;

export type DispatchGatedCommand = keyof typeof DISPATCH_HELP;

export function isDispatchGated(word: string): word is DispatchGatedCommand {
  return Object.prototype.hasOwnProperty.call(DISPATCH_HELP, word);
}

/**
 * The gate `main()` runs first. `argv` is `process.argv.slice(2)`: the command
 * word and everything after it. Returns true when usage was printed — the caller
 * returns at once and the process exits 0 with nothing else having run.
 *
 * The verdict is the command's own (`commandWantsHelp`), so `scan -- --help`
 * scans, `remember help --content x` remembers, and `config --mode help` is an
 * invalid mode for the handler to refuse — exactly as the handler would read
 * them.
 */
export function dispatchHelp(
  argv: readonly string[],
  log: (message: string) => void = (m) => process.stdout.write(`${m}\n`),
): boolean {
  const word = argv[0];
  if (!word || !isGatedCommand(word) || !isDispatchGated(word)) return false;
  if (!commandWantsHelp(word, argv.slice(1))) return false;
  log(DISPATCH_HELP[word]);
  return true;
}
