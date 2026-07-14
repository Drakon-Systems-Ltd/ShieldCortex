/**
 * Iron Dome — Tool Action Guard
 *
 * Recognition layer that turns a live agent tool call (`toolName` + `arguments`)
 * into an Iron Dome action verdict. This is the piece that makes the headline
 * claim — "Iron Dome protects what the agent DOES" — true at runtime.
 *
 * Before this, the OpenClaw `before_tool_call` interceptor only inspected the
 * two memory-write tools (`WATCHED_TOOLS`), so an agent told to `rm -rf`,
 * `curl | sh`, or exfiltrate secrets passed completely ungated. This module
 * recognises destructive shell / file / network / git calls, hard-BLOCKs the
 * unambiguously catastrophic ones, and routes the rest through the existing
 * RED/AMBER/GREEN confirmation vocabulary.
 *
 * Design principle: POSITIVE RECOGNITION, not deny-all.
 *  - Unrecognised or read-only tools → `allow` (the guard never nags on benign
 *    work — generic `ls`, `git status`, `npm test`, web search all pass).
 *  - Recognised-dangerous (plain `rm <path>`, `sudo`, force-push, external
 *    egress) → `require_approval`.
 *  - Catastrophic (`rm -rf /`, fork bomb, `mkfs`, `dd of=/dev/sd*`, `curl | sh`,
 *    secret exfil) → `block`, and this can NEVER fail open, regardless of config.
 *
 * The danger detection is self-contained so the guard works out-of-the-box
 * (security on by default); an optional `IronDomeConfig` only relaxes via the
 * user's `autoApprove` list.
 */

import type { IronDomeConfig } from './config.js';

export type ToolGuardDecision = 'allow' | 'require_approval' | 'block';
export type ToolGuardSeverity = 'benign' | 'sensitive' | 'dangerous' | 'catastrophic';
export type ToolFamily =
  | 'read'
  | 'write'
  | 'delete'
  | 'exec'
  | 'network'
  | 'git'
  | 'memory'
  | 'unknown';

export interface ToolGuardVerdict {
  decision: ToolGuardDecision;
  severity: ToolGuardSeverity;
  family: ToolFamily;
  /** Canonical Iron Dome action string (e.g. `execute_command`, `delete_file`). */
  action: string;
  reason: string;
  /** Matched indicators, e.g. `['recursive-force-delete', 'root-path']`. */
  signals: string[];
}

// ── Tool-name recognition ───────────────────────────────────────────────────

/** Strip MCP / namespace prefixes and lowercase: `mcp__memory__remember` → `remember`. */
export function normaliseToolName(name: string): string {
  const raw = String(name || '').toLowerCase().trim();
  // Keep the most specific segment after mcp/namespace separators.
  const seg = raw.split(/__|\.|:|\//).filter(Boolean).pop() ?? raw;
  return seg;
}

const MEMORY_TOOLS = /^(remember|recall|forget|memory|get_context|graph)$/;
const READ_TOOLS = /^(read|read_file|cat|less|more|head|tail|view|open|get|glob|grep|search|find|ls|list|list_files|stat|pwd|which|web_search|websearch)$/;
const NETWORK_TOOLS = /(fetch|curl|wget|http|https|request|download|upload|web_fetch|webfetch|post|put|api_call|apicall|send|email|webhook)/;
const DELETE_TOOLS = /(delete|remove|rm|trash|unlink|destroy|drop|purge|rmdir)/;
const WRITE_TOOLS = /(write|edit|create|update|patch|append|save|mkdir|move|copy|cp|mv|rename|chmod|chown)/;
const EXEC_TOOLS = /(bash|shell|exec|run|run_command|runcommand|command|terminal|system|sh|zsh|powershell|cmd|spawn|process|eval|script)/;
const GIT_TOOLS = /(^git$|git_|_git|github)/;

export function classifyFamily(toolName: string): ToolFamily {
  const n = normaliseToolName(toolName);
  if (MEMORY_TOOLS.test(n)) return 'memory';
  // Exec is checked early: a "Bash" tool can do anything, so its args drive risk.
  if (EXEC_TOOLS.test(n)) return 'exec';
  if (GIT_TOOLS.test(n)) return 'git';
  if (READ_TOOLS.test(n)) return 'read';
  if (DELETE_TOOLS.test(n)) return 'delete';
  if (NETWORK_TOOLS.test(n)) return 'network';
  if (WRITE_TOOLS.test(n)) return 'write';
  return 'unknown';
}

// ── Argument extraction ──────────────────────────────────────────────────────

function pickString(args: Record<string, unknown>, keys: string[]): string {
  for (const k of keys) {
    const v = args?.[k];
    if (typeof v === 'string' && v.length > 0) return v;
  }
  return '';
}

export function extractCommand(args: Record<string, unknown>): string {
  return pickString(args, ['command', 'cmd', 'script', 'code', 'input', 'shell', 'run']);
}
export function extractPath(args: Record<string, unknown>): string {
  return pickString(args, ['path', 'file_path', 'filePath', 'file', 'target', 'destination', 'dir', 'directory']);
}
export function extractUrl(args: Record<string, unknown>): string {
  return pickString(args, ['url', 'uri', 'endpoint', 'href', 'host', 'to']);
}

// ── Danger detection ─────────────────────────────────────────────────────────

interface Pattern { re: RegExp; signal: string; }

/**
 * Unambiguously catastrophic, irreversible operations. Matching ANY of these is
 * a hard BLOCK that cannot be relaxed by config — there is no legitimate agent
 * reason to wipe a disk or fork-bomb a host mid-task.
 */
const CATASTROPHIC: Pattern[] = [
  // rm with both -r and -f (any flag order/cluster), e.g. rm -rf, rm -fr, rm -Rf, rm --recursive --force
  { re: /\brm\b[^|;&\n]*?(?:-\w*r\w*f\w*|-\w*f\w*r\w*|(?=[^|;&\n]*--recursive)(?=[^|;&\n]*--force))/i, signal: 'recursive-force-delete' },
  // rm targeting a root-ish / home / wildcard path
  { re: /\brm\b[^|;&\n]*\s(?:-\w+\s+)*(?:\/|~|\$HOME|\/\*|\*|\.\/\*)(?:\s|$)/i, signal: 'delete-root-or-home' },
  // fork bomb  :(){ :|:& };:
  { re: /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:?\s*&?\s*\}\s*;\s*:/, signal: 'fork-bomb' },
  // filesystem creation / raw disk writes
  { re: /\bmkfs(\.\w+)?\b/i, signal: 'format-filesystem' },
  { re: /\bdd\b[^|;&\n]*\bof=\/dev\/(sd|nvme|hd|disk|mmcblk|vd)/i, signal: 'raw-disk-write' },
  { re: /[>|]\s*\/dev\/(sd|nvme|hd|disk|mmcblk|vd)\w/i, signal: 'redirect-to-block-device' },
  { re: /\b(fdisk|parted|sgdisk|wipefs|blkdiscard)\b/i, signal: 'disk-partition-tool' },
  // pipe a download straight into an interpreter (remote code execution).
  // The danger is a BARE interpreter reading the fetched bytes as its PROGRAM
  // (`curl … | sh`, `curl … | python3`, `curl … | sh -s`). When the interpreter
  // is given its own program via an inline-script flag (`-c`/`-e`/`-m`), the
  // piped bytes are stdin DATA, not code — e.g. `curl … | python3 -c '<parse>'`
  // parses JSON and is not RCE (issue #73.6). The negative lookahead exempts an
  // interpreter whose next flag (allowing intervening short flags) is -c/-e/-m.
  { re: /\b(?:curl|wget|fetch)\b[^|\n]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|ksh|python\d?|perl|ruby|node)\b(?!(?:\s+-[a-z]+)*\s+-[cem]\b)/i, signal: 'pipe-download-to-shell' },
  // ANTI-BYPASS for the exemption above: an inline `-c`/`-e` program that itself
  // EXECUTES its stdin (`python3 -c "exec(sys.stdin.read())"`, `node -e
  // "eval(...readFileSync(0)...)"`, `bash -c 'source /dev/stdin'`) re-opens the
  // fetched bytes as code — still RCE, not data consumption. Single-line bounded;
  // `\b(exec|eval)\b` deliberately does not match `literal_eval` or
  // `json.load(sys.stdin)`, so the #73.6 data-parsing exemption stands.
  { re: /\b(?:curl|wget|fetch)\b[^|\n]*\|[^\n]*\b(?:bash|sh|zsh|ksh|python\d?|perl|ruby|node)\b[^\n]*(?:\b(?:exec|eval)\b|\bsource\s+\/dev\/stdin\b)/i, signal: 'pipe-download-stdin-exec' },
  // recursive permission/ownership change at the root
  { re: /\bch(?:mod|own)\b[^|;&\n]*(?:-\w*R\w*|--recursive)\b[^|;&\n]*\s\/(?:\s|$)/i, signal: 'recursive-perms-on-root' },
  // overwrite the whole disk with zeros/urandom. The [^|;&\n]* bridge keeps the
  // verb and the /dev/ target in ONE statement — mirroring recursive-force-delete
  // above — so `export PATH=/opt/wipe/bin; echo /dev/null` no longer collides two
  // unrelated statements into a false catastrophic block (issue #89).
  { re: /\b(?:shred|wipe)\b[^|;&\n]*\/dev\//i, signal: 'shred-device' },
];

/**
 * Recognised-dangerous operations: effectful and worth a human nod, but not
 * automatically catastrophic. These map to an Iron Dome action and escalate to
 * `require_approval`.
 */
const DANGEROUS: Pattern[] = [
  { re: /\brm\b|\bunlink\b|\brmdir\b|\bshred\b/i, signal: 'file-delete' },
  { re: /\bsudo\b|\bdoas\b|\bsu\s/i, signal: 'privilege-escalation' },
  { re: /\bgit\b[^|\n]*\bpush\b[^|\n]*(--force\b|-f\b|\+)/i, signal: 'git-force-push' },
  { re: /\bgit\b[^|\n]*\b(branch\s+-D|push\b[^|\n]*--delete|push\b[^|\n]*\s:)/i, signal: 'git-delete-branch' },
  { re: /\b(systemctl|service)\b[^|\n]*\b(stop|disable|mask)\b|\b(kill|pkill|killall)\b/i, signal: 'stop-process-or-service' },
  { re: /\b(iptables|ufw|nft|netplan|firewall-cmd)\b/i, signal: 'modify-network-firewall' },
  // Package installs split by blast radius (issue #73.3). System package managers
  // and language *global* installs mutate the host → approval. A workspace-local
  // `npm/yarn/pnpm/bun install` (no -g/--global) is routine operator-directed dev
  // work and is handled as a sensitive-but-allowed op (SENSITIVE.local-package-install
  // below) so it is never a hard gate.
  { re: /\b(?:apt|apt-get|yum|dnf|brew|pip|pip3|gem|cargo)\b[^|\n]*\b(?:install|add)\b/i, signal: 'install-package' },
  // A GLOBAL install mutates the host → approval. It must carry BOTH an install
  // verb (install/add/ci, or the `npm i` shorthand) AND a global flag in the SAME
  // statement. A read-only global QUERY — `npm ls -g`, `npm root -g`,
  // `npm outdated -g`, `npm list --global` — mutates nothing and is not gated
  // (issue #88). Order-independent (`npm install -g` and `npm -g install` both hit).
  { re: /\b(?:npm|yarn|pnpm|bun)\b(?=[^|;&\n]*(?:\s-g\b|--global\b|\bglobal\s+add\b))(?=[^|;&\n]*\b(?:install|add|ci)\b)|\b(?:npm|pnpm|bun)\s+i\b[^|;&\n]*(?:\s-g\b|--global\b)/i, signal: 'install-package-global' },
  // Scheduler MUTATION only: `crontab` in command position that edits/installs
  // (`-e`, `-r`, a file, or stdin `-`) — never the read-only `crontab -l`, and
  // never the bare word mentioned inside an echo/string (issue #89). Env-var and
  // sudo prefixes allowed. `/etc/cron*` writes and `at now` scheduling still gate.
  { re: /(?:^|[;&|(\n]|\$\()\s*(?:\w+=\S*\s+)*(?:sudo\s+)?crontab\b(?!\s+-l\b)|\/etc\/cron|\bat\s+now\b/i, signal: 'modify-scheduler' },
  { re: /\bhistory\s+-c\b|\.bash_history|truncate\b[^|\n]*\.log/i, signal: 'wipe-history-or-logs' },
  { re: /\/etc\/(passwd|shadow|sudoers)|~\/\.ssh|id_rsa|\.aws\/credentials|\.env\b/i, signal: 'touch-sensitive-path' },
];

/** Sensitive-but-routine writes/edits: announced, default-allow (interceptor may warn). */
const SENSITIVE: Pattern[] = [
  { re: /\bchmod\b|\bchown\b/i, signal: 'change-permissions' },
  { re: /\b(mv|move|rename|cp|copy)\b/i, signal: 'move-or-copy' },
  { re: /\bgit\b[^|\n]*\b(push|commit|reset|rebase|merge|checkout)\b/i, signal: 'git-mutate' },
  // Workspace-local package install (issue #73.3): operator-directed, into the
  // project (node_modules / vendor). Global installs matched install-package-global
  // in DANGEROUS above and are checked first, so this only tags the local case.
  { re: /\b(?:npm|yarn|pnpm|bun)\b[^|\n]*\b(?:install|add|ci|i)\b/i, signal: 'local-package-install' },
];

const SECRET_HINT = /(sk-[a-z0-9-]{12,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{12,}|xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|password\s*[=:]\s*\S{6,}|secret\s*[=:]\s*\S{6,})/i;
const EXTERNAL_EGRESS = /\b(curl|wget|fetch|nc|netcat|scp|rsync|http\.post|requests\.post|fetch\()/i;

// Outbound DATA on a network call (issue #73.2): a read-only GET carries nothing
// off-host, so a docs / releases fetch is not egress. Egress requires an actual
// payload — a non-GET method or a body/data/upload flag. This is what separates
// `web_fetch https://docs.openclaw.ai` (allow) from `curl -X POST … -d @dump`
// (approval). URL text is deliberately NOT scanned for the words post/put so a
// path like `/output` or `/put-item` cannot be mistaken for a write.
const OUTBOUND_DATA_FLAGS =
  /(?:-X|--request)\s*(?:POST|PUT|PATCH|DELETE)\b|(?:^|\s)-d\b|--data(?:-\w+)?\b|--json\b|--form\b|(?:^|\s)-F\b|--upload-file\b|(?:^|\s)-T\b|\bupload\s+to\b/i;

function hasOutboundData(args: Record<string, unknown>, execSurface: string): boolean {
  if (OUTBOUND_DATA_FLAGS.test(execSurface)) return true;
  const method = String((args?.method ?? args?.httpMethod ?? args?.verb) ?? '').toUpperCase();
  if (method && method !== 'GET' && method !== 'HEAD') return true;
  for (const k of ['body', 'data', 'json', 'form', 'payload', 'formData', 'files']) {
    const v = args?.[k];
    if (typeof v === 'string' && v.length > 0) return true;
    if (v && typeof v === 'object') return true;
  }
  return false;
}

function firstMatch(patterns: Pattern[], text: string): string | null {
  for (const p of patterns) if (p.re.test(text)) return p.signal;
  return null;
}
function allMatches(patterns: Pattern[], text: string): string[] {
  return patterns.filter(p => p.re.test(text)).map(p => p.signal);
}

/** Like allMatches, but also captures the matched span for actionable reason codes. */
function matchSpans(patterns: Pattern[], text: string): Array<{ signal: string; span: string }> {
  const out: Array<{ signal: string; span: string }> = [];
  for (const p of patterns) {
    const m = text.match(p.re);
    if (m) out.push({ signal: p.signal, span: m[0].trim().replace(/\s+/g, ' ').slice(0, 80) });
  }
  return out;
}

// Remediation hints keyed by signal — turn an opaque "failure policy: deny" into
// an actionable message that names the rule, the matched span, and the fix
// (issue #73 item 5).
const REMEDIATION: Record<string, string> = {
  'pipe-download-to-shell': 'download to a file and inspect it before running (curl -o get.sh URL; less get.sh; sh get.sh)',
  'pipe-download-stdin-exec': 'the inline program executes its stdin, so the fetched bytes still run as code — download to a file and inspect it first',
  'install-package-global': 'review the package + source, then install it explicitly if intended (a workspace-local install needs no global flag)',
  'install-package': 'review the package + source, then run the install yourself if intended',
  'privilege-escalation': 'run the specific privileged step yourself, or approve this exact command',
  'external-egress': 'confirm the destination and payload before data leaves the host',
  'git-force-push': 'confirm the branch and remote; a force-push can overwrite others’ work',
  'file-delete': 'confirm the target path before deleting',
};

/** Compose a reason string that names the rule, the matched span, and a fix hint. */
function buildReason(prefix: string, signals: string[], span?: string): string {
  const parts = [`rule: ${signals.join(', ')}`];
  if (span) parts.push(`matched: "${span}"`);
  const hint = REMEDIATION[signals[0]];
  if (hint) parts.push(`fix: ${hint}`);
  return `${prefix} [${parts.join('; ')}]`;
}

/** A path whose deletion is catastrophic: root, home, a top-level system dir, or a wildcard. */
export function isCriticalPath(path: string): boolean {
  const p = String(path || '').trim();
  if (!p) return false;
  if (/^(\/|~|\.|\*)$/.test(p)) return true;                    // /  ~  .  *
  if (/^(\/\*|~\/?\*|\.\/\*|\$HOME\/?\*?)$/.test(p)) return true; // /*  ~/*  ./*  $HOME
  if (/\*/.test(p) && p.length <= 3) return true;                // bare wildcard-ish
  if (/^\/(etc|usr|bin|sbin|boot|var|lib|lib64|sys|proc|root|dev|home|opt|srv)(\/?$|\/\*)/.test(p)) return true;
  if (/^~\/?$/.test(p) || /^\$HOME\/?$/.test(p)) return true;
  return false;
}

function looksExternal(url: string, text: string): boolean {
  const hay = `${url} ${text}`;
  // An external host that isn't localhost / private RFC1918.
  if (/\b(localhost|127\.0\.0\.1|0\.0\.0\.0|::1|10\.\d|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)\b/i.test(hay)) return false;
  return /https?:\/\/[a-z0-9.-]+\.[a-z]{2,}/i.test(hay) || /[a-z0-9.-]+\.[a-z]{2,}\b/i.test(url);
}

// ── Use/mention discipline for shell commands ────────────────────────────────
// A dangerous token inside a real shell command is only an *action* if it sits
// in command position. If it is merely printed (`echo "rm -rf /"`) or commented
// (`# rm -rf /`) it is inert. We recognise those two unambiguous inert forms and
// refuse to recognise anything that could re-activate text — operators,
// redirection, command substitution, `eval`, or variable expansion.
//
// We deliberately DON'T strip quoted spans wholesale: `"rm" -rf /` quotes the
// command name yet still executes, so blanket quote-removal would be a bypass.
// Fail-safe by construction — when in doubt, the original command text is scanned.
const SHELL_REACTIVATORS = /[;&|><`]|\$\(|\$\{|\$\w|\beval\b/;

/** A command whose sole effect is to print its arguments (cannot execute them). */
function isPurePrint(cmd: string): boolean {
  const c = cmd.trim();
  if (SHELL_REACTIVATORS.test(c)) return false;            // chaining / redirect / expansion → not pure
  const body = c.replace(/^(?:\w+=\S*\s+)*/, '').replace(/^sudo\s+/, '');
  return /^(?:echo|printf)\b/.test(body);
}

/** Strip `#` comments so a token mentioned only in a comment is not an action. */
function stripComments(cmd: string): string {
  return cmd.replace(/(^|\s)#[^\n]*/g, '$1 ');
}

// Interpreters that EXECUTE a heredoc body they read. If one of these introduces
// a heredoc, the body is code and must stay scanned (see stripQuotedHeredocs).
const HEREDOC_INTERPRETER = /\b(?:bash|sh|zsh|ksh|dash|python\d?|perl|ruby|node|php)\b/i;

/**
 * Neutralise the bodies of QUOTED heredocs (`<<'EOF'` / `<<"EOF"`).
 *
 * A quoted delimiter means the body is passed literally, unexpanded — it is a
 * data payload for its consumer (documentation for `gh issue create`, JSON for
 * `cat`/`jq`), never executed. Scanning that body for command patterns is a
 * mention-not-intent false positive: the jarvis `gh issue create` incident quoted
 * a `curl … | bash` example in the issue body via a heredoc (issue #71).
 *
 * Fail-safe by construction — the body stays scanned for the two re-activation
 * vectors, so this can never become a bypass:
 *   - an interpreter that itself reads the heredoc (`bash <<'EOF' … EOF`)
 *   - `eval` anywhere in the command (it can re-run captured heredoc text)
 */
function stripQuotedHeredocs(cmd: string): string {
  if (!/<<-?\s*['"]/.test(cmd)) return cmd;      // no quoted heredoc → nothing to do
  if (/\beval\b/.test(cmd)) return cmd;          // re-activation risk → keep the body
  return cmd.replace(
    /(<<-?\s*(['"])([A-Za-z_]\w*)\2[^\n]*\n)([\s\S]*?)(\n[ \t]*\3\b)/g,
    (match: string, opener: string, _q: string, _delim: string, _body: string, closer: string, offset: number, whole: string) => {
      const lineStart = whole.lastIndexOf('\n', offset) + 1;
      const introLine = whole.slice(lineStart, offset);
      if (HEREDOC_INTERPRETER.test(introLine)) return match; // interpreter consumes it → keep
      return opener + closer;                                 // drop the inert body
    },
  );
}

/**
 * The text of a shell command that is actually *executed*, for danger scanning.
 * Returns '' for a pure print; neutralises quoted-heredoc bodies and comments
 * otherwise; never trusts quote removal (see note above) so it cannot be evaded
 * by quoting a command name.
 */
export function commandScanText(cmd: string): string {
  if (!cmd) return '';
  if (isPurePrint(cmd)) return '';
  return stripComments(stripQuotedHeredocs(cmd));
}

// ── Main entry point ─────────────────────────────────────────────────────────

const ACTION_BY_FAMILY: Record<ToolFamily, string> = {
  read: 'read_file',
  write: 'edit_file',
  delete: 'delete_file',
  exec: 'execute_command',
  network: 'api_call',
  git: 'git_operation',
  memory: 'remember',
  unknown: 'unknown_action',
};

/**
 * Evaluate a single tool call and return a guard verdict.
 *
 * Pure and synchronous — no I/O. The interceptor decides how to ENFORCE the
 * verdict (block / prompt / warn) based on its own posture; this function only
 * RECOGNISES and recommends.
 */
export function evaluateToolCall(
  toolName: string,
  args: Record<string, unknown> = {},
  config?: IronDomeConfig,
): ToolGuardVerdict {
  const family = classifyFamily(toolName);
  const command = extractCommand(args);
  const path = extractPath(args);
  const url = extractUrl(args);

  // Memory tools are handled by the dedicated memory-defence pipeline elsewhere.
  if (family === 'memory') {
    return verdict('allow', 'benign', family, 'remember', 'memory tool — handled by memory defence pipeline', []);
  }
  // Read-only tools never execute their args — a search query or path that
  // merely *mentions* "rm -rf" is not an action. Short-circuit before scanning.
  if (family === 'read') {
    return verdict('allow', 'benign', family, 'read_file', 'read-only operation', []);
  }

  // Field discipline: danger patterns scan the EXECUTION SURFACE
  // (command/path/url) only — never content the agent produces
  // (a message body, file contents). See commandScanText for the
  // printed/commented-token suppression within a shell command.
  const execCommand = commandScanText(command);
  const execSurface = [execCommand, path, url].filter(Boolean).join('   ');

  // 1) Catastrophic — hard block, cannot fail open, ignores config.
  const catastrophicMatches = matchSpans(CATASTROPHIC, execSurface);
  if (catastrophicMatches.length > 0) {
    const catastrophicSignals = catastrophicMatches.map(m => m.signal);
    return verdict('block', 'catastrophic', family, ACTION_BY_FAMILY[family],
      buildReason('catastrophic operation blocked', catastrophicSignals, catastrophicMatches[0].span),
      catastrophicSignals);
  }

  // 1a) A structured delete tool carries its target as a path, not a command —
  // deleting a critical path (root, home, a system dir, a wildcard) is catastrophic.
  if (family === 'delete' && isCriticalPath(path)) {
    return verdict('block', 'catastrophic', family, 'delete_file',
      `catastrophic delete of a critical path (${path})`, ['delete-critical-path']);
  }

  // 1b) Secret exfiltration: external egress carrying a credential/secret.
  const egress = family === 'network' || EXTERNAL_EGRESS.test(execCommand) || EXTERNAL_EGRESS.test(url);
  if (egress && SECRET_HINT.test(`${execSurface}   ${rawStringArgs(args)}`) && looksExternal(url, execSurface)) {
    return verdict('block', 'catastrophic', family, 'data_exfiltration',
      'blocked likely secret exfiltration (credential bound for an external host)', ['secret-egress']);
  }

  // Config can auto-approve specific actions the operator has whitelisted.
  const canonical = ACTION_BY_FAMILY[family];
  if (config?.enabled && config.autoApprove?.some(a => canonical.includes(a.toLowerCase()) || a.toLowerCase().includes(family))) {
    // still fall through to catastrophic above; only downgrades the soft tiers.
  }

  // 2) Dangerous — recognised, effectful, worth a human nod → require approval.
  const dangerMatches = matchSpans(DANGEROUS, execSurface);
  const dangerSignals = dangerMatches.map(m => m.signal);
  let dangerSpan = dangerMatches[0]?.span;
  // External egress is a potential exfil vector — but only when the call carries
  // a payload OFF-host. A read-only GET (docs / releases fetch) leaves nothing
  // behind and is not egress (issue #73.2). Secret-bearing egress already hard
  // blocked at step 1b above regardless of method.
  if (egress && looksExternal(url, execSurface) && hasOutboundData(args, execSurface)) {
    dangerSignals.push('external-egress');
    dangerSpan = dangerSpan ?? (url || 'external host');
  }
  // A structured delete tool is inherently a delete, even with no "rm" in any arg.
  if (family === 'delete' && !dangerSignals.includes('file-delete')) dangerSignals.push('file-delete');
  if (dangerSignals.length > 0) {
    const action = dangerActionFor(dangerSignals, family);
    return verdict('require_approval', 'dangerous', family, action,
      buildReason('recognised dangerous operation requires approval', dangerSignals, dangerSpan),
      dangerSignals);
  }

  // 3) Sensitive-but-routine — allow, but tag so the interceptor can announce.
  const sensitiveSignal = firstMatch(SENSITIVE, execSurface);
  if (sensitiveSignal) {
    return verdict('allow', 'sensitive', family, canonical, `sensitive operation (${sensitiveSignal})`, [sensitiveSignal]);
  }

  // 4) A bare exec/network/write/git call with no dangerous signal is treated as
  // benign so the guard does not interrupt routine work (npm test, git status…).
  // (Read-only and memory tools already short-circuited to allow above.)
  return verdict('allow', 'benign', family, canonical, 'no dangerous signal detected', []);
}

function dangerActionFor(signals: string[], family: ToolFamily): string {
  if (signals.includes('git-force-push')) return 'force_push';
  if (signals.includes('git-delete-branch')) return 'delete_branch';
  if (signals.includes('file-delete')) return 'delete_file';
  if (signals.includes('privilege-escalation')) return 'sudo_command';
  if (signals.includes('stop-process-or-service')) return 'stop_service';
  if (signals.includes('modify-network-firewall')) return 'modify_firewall';
  if (signals.includes('install-package') || signals.includes('install-package-global')) return 'install_package';
  if (signals.includes('modify-scheduler')) return 'modify_cron';
  if (signals.includes('external-egress')) return 'network_egress';
  if (signals.includes('touch-sensitive-path')) return 'access_secret_path';
  if (signals.includes('wipe-history-or-logs')) return 'wipe_logs';
  return ACTION_BY_FAMILY[family];
}

/** Concatenate all top-level string argument values (bounded) for pattern scanning. */
function rawStringArgs(args: Record<string, unknown>): string {
  const parts: string[] = [];
  for (const v of Object.values(args ?? {})) {
    if (typeof v === 'string') parts.push(v);
    else if (Array.isArray(v)) parts.push(v.filter(x => typeof x === 'string').join(' '));
  }
  const joined = parts.join(' ');
  return joined.length > 20000 ? joined.slice(0, 20000) : joined;
}

function verdict(
  decision: ToolGuardDecision,
  severity: ToolGuardSeverity,
  family: ToolFamily,
  action: string,
  reason: string,
  signals: string[],
): ToolGuardVerdict {
  return { decision, severity, family, action, reason, signals };
}
