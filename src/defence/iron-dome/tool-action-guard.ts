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
  { re: /\bdd\b[^|\n]*\bof=\/dev\/(sd|nvme|hd|disk|mmcblk|vd)/i, signal: 'raw-disk-write' },
  { re: /[>|]\s*\/dev\/(sd|nvme|hd|disk|mmcblk|vd)\w/i, signal: 'redirect-to-block-device' },
  { re: /\b(fdisk|parted|sgdisk|wipefs|blkdiscard)\b/i, signal: 'disk-partition-tool' },
  // NOTE: pipe-download-to-shell is handled separately by pipeDownloadSignal()
  // below — a regex can't tell `curl … | bash` (RCE) from `curl … | python3 -c
  // '<local program>'` (JSON parsing) or a quoted documentation example (#71).
  // recursive permission/ownership change at the root
  { re: /\bch(?:mod|own)\b[^|;&\n]*(?:-\w*R\w*|--recursive)\b[^|;&\n]*\s\/(?:\s|$)/i, signal: 'recursive-perms-on-root' },
  // overwrite the whole disk with zeros/urandom
  { re: /\b(?:shred|wipe)\b[^|\n]*\/dev\//i, signal: 'shred-device' },
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
  { re: /\b(apt|apt-get|yum|dnf|brew|npm|pip|pip3|gem|cargo)\b[^|\n]*\b(install|add|i)\b/i, signal: 'install-package' },
  { re: /\bcrontab\b|\/etc\/cron|\bat\s+now\b/i, signal: 'modify-scheduler' },
  { re: /\bhistory\s+-c\b|\.bash_history|truncate\b[^|\n]*\.log/i, signal: 'wipe-history-or-logs' },
  { re: /\/etc\/(passwd|shadow|sudoers)|~\/\.ssh|id_rsa|\.aws\/credentials|\.env\b/i, signal: 'touch-sensitive-path' },
];

/** Sensitive-but-routine writes/edits: announced, default-allow (interceptor may warn). */
const SENSITIVE: Pattern[] = [
  { re: /\bchmod\b|\bchown\b/i, signal: 'change-permissions' },
  { re: /\b(mv|move|rename|cp|copy)\b/i, signal: 'move-or-copy' },
  { re: /\bgit\b[^|\n]*\b(push|commit|reset|rebase|merge|checkout)\b/i, signal: 'git-mutate' },
];

const SECRET_HINT = /(sk-[a-z0-9-]{12,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{12,}|xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|password\s*[=:]\s*\S{6,}|secret\s*[=:]\s*\S{6,})/i;
const EXTERNAL_EGRESS = /\b(curl|wget|fetch|nc|netcat|scp|rsync|http\.post|requests\.post|fetch\()/i;

function firstMatch(patterns: Pattern[], text: string): string | null {
  for (const p of patterns) if (p.re.test(text)) return p.signal;
  return null;
}
function allMatches(patterns: Pattern[], text: string): string[] {
  return patterns.filter(p => p.re.test(text)).map(p => p.signal);
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

/** Interpreters that treat their stdin (or a heredoc/substitution) as a program. */
const INTERP_TOKENS = 'bash|sh|zsh|ksh|dash|python\\d?|perl|ruby|node|php';
const INTERP_RE = new RegExp(`\\b(?:${INTERP_TOKENS})\\b`, 'i');

/**
 * Remove quoted-delimiter heredoc BODIES (`<<'X'`, `<<"X"`, `<<\X`) — literal
 * data blocks with no shell expansion — so a dangerous string that only appears
 * as documentation *inside* such a body (e.g. a `gh issue create` body that
 * quotes `curl | bash`, #71) is not scanned as an executable operation.
 *
 * ANTI-BYPASS: the body is kept (still scanned) when the command word
 * introducing the heredoc is an interpreter that would EXECUTE it as a script
 * (`bash <<'EOF' … EOF`), and expanding (unquoted-delimiter) heredocs are always
 * kept because they can re-activate content via `$(…)`.
 */
export function stripDataHeredocs(cmd: string): string {
  if (!/<<[-~]?\s*['"\\]?[A-Za-z_]/.test(cmd)) return cmd;
  const lines = cmd.split('\n');
  const out: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Opener: <<, optional -/~ (indent-strip), optional quote/backslash, delimiter word.
    const m = line.match(/<<[-~]?\s*(['"]?)(\\?)([A-Za-z_]\w*)\1/);
    if (!m) { out.push(line); continue; }
    const literal = m[1] !== '' || m[2] === '\\'; // quoted or backslash-escaped delimiter → no expansion
    const delim = m[3];
    const introSeg = line.slice(0, m.index ?? 0).split(/&&|\|\||[;&|]/).pop() ?? '';
    const fedToInterpreter = INTERP_RE.test(introSeg);

    out.push(line); // keep the opener line (the command itself is still scanned)
    let j = i + 1;
    const body: string[] = [];
    for (; j < lines.length; j++) {
      if (lines[j].trim() === delim) break;
      body.push(lines[j]);
    }
    // Drop only a literal, non-interpreter-fed body; otherwise keep it in scope.
    if (!(literal && !fedToInterpreter)) out.push(...body);
    if (j < lines.length) out.push(lines[j]); // keep the closing delimiter line
    i = j;
  }
  return out.join('\n');
}

/**
 * The text of a shell command that is actually *executed*, for danger scanning.
 * Returns '' for a pure print; strips `#` comments and literal data-heredoc
 * bodies otherwise; never trusts blanket quote removal (see note above) so it
 * cannot be evaded by quoting a command name.
 */
export function commandScanText(cmd: string): string {
  if (!cmd) return '';
  if (isPurePrint(cmd)) return '';
  return stripDataHeredocs(stripComments(cmd));
}

// ── pipe-download-to-shell (network-fetch → interpreter) ─────────────────────
// A remote-code-execution shape: a NETWORK FETCH whose bytes reach an
// interpreter as a PROGRAM — via a pipe (`curl … | bash`), or via a
// substitution whose output becomes code (`bash -c "$(curl …)"`, `eval "$(curl
// …)"`, `bash <(curl …)`). Local command substitution that does NOT feed an
// interpreter (`TOK=$(op item get …)`, `X=$(cat ~/.tok)`) is NOT this shape, and
// piping a fetch into a *data* consumer (`curl … | head`, `curl … | python3 -c
// '<local program>'` where stdin is only DATA) is not RCE either.
const FETCH_SRC = '(?:curl|wget|fetch|iwr|invoke-webrequest|aria2c)';

/** True when `text` contains a network-fetch feeding an interpreter as a program. */
export function pipeDownloadSignal(text: string): boolean {
  if (!text) return false;

  // Mechanism 1a — pipe into a shell: stdin is always executed as a script.
  if (new RegExp(`\\b${FETCH_SRC}\\b[^|\\n]*\\|\\s*(?:sudo\\s+)?(?:bash|sh|zsh|ksh|dash)\\b`, 'i').test(text)) {
    return true;
  }
  // Mechanism 1b — pipe into a script interpreter with NO explicit program
  // (`-c`/`-e`/`-m`/`--eval` or a script file): stdin becomes the program → RCE.
  // With an explicit program, stdin is only data (JSON parsing etc.) → allowed.
  const m = new RegExp(
    `\\b${FETCH_SRC}\\b[^|\\n]*\\|\\s*(?:sudo\\s+)?(python\\d?|perl|ruby|node|php)\\b([^|\\n;&]*)`,
    'i',
  ).exec(text);
  if (m) {
    const tail = m[2] ?? '';
    const hasProgram =
      /(^|\s)(?:-c|-e|-m|-p|--eval|--command)\b/i.test(tail) ||
      /\S+\.(?:py|js|mjs|cjs|ts|rb|pl|php)\b/i.test(tail);
    if (!hasProgram) return true;
  }
  // Mechanism 2 — a fetch whose OUTPUT becomes code:
  //   eval "$(curl …)"        interpreter -c/-e "$(curl …)"        interp <(curl …)
  if (new RegExp(`\\beval\\b[^\\n]*\\$\\([^)]*\\b${FETCH_SRC}\\b`, 'i').test(text)) return true;
  if (new RegExp(
    `\\b(?:${INTERP_TOKENS})\\b[^|\\n]*(?:-c|-e|--eval)\\b[^|\\n]*\\$\\([^)]*\\b${FETCH_SRC}\\b`, 'i',
  ).test(text)) return true;
  if (new RegExp(`\\b(?:${INTERP_TOKENS})\\b[^|\\n]*<\\(\\s*${FETCH_SRC}\\b`, 'i').test(text)) return true;

  return false;
}

/** A pure sudo capability probe (`sudo -n true`, `sudo -v`, `sudo -l`) — no side effect. */
export function isSudoCapabilityProbe(command: string): boolean {
  const c = String(command || '').trim();
  if (!/^sudo\b/i.test(c)) return false;
  if (SHELL_REACTIVATORS.test(c)) return false; // no chaining/redirect/substitution
  const rest = c.replace(/^sudo\b/i, '').trim();
  if (rest === '') return false; // bare `sudo` — leave as dangerous
  const allowed = new Set(['-n', '-k', '-v', '-l', '-s', '-a', '-nv', '-nl', 'true', ':']);
  return rest.split(/\s+/).every((t) => allowed.has(t.toLowerCase()));
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
  const catastrophicSignals = allMatches(CATASTROPHIC, execSurface);
  // pipe/substitution of a network download into an interpreter (RCE) — computed
  // here rather than as a regex so mention/data forms don't false-positive (#71).
  if (pipeDownloadSignal(execSurface)) catastrophicSignals.push('pipe-download-to-shell');
  if (catastrophicSignals.length > 0) {
    return verdict('block', 'catastrophic', family, ACTION_BY_FAMILY[family],
      `catastrophic operation blocked (${catastrophicSignals.join(', ')})`, catastrophicSignals);
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
  const dangerSignals = allMatches(DANGEROUS, execSurface);
  // External egress is only a potential exfil vector when data actually flows OUT
  // — a POST/PUT/upload or a request body. A plain GET (a docs fetch, a release
  // download) is not exfil, so it must not be gated (#73: docs/GitHub fetches
  // were denied, forcing a raw-curl fallback with a worse posture). Credentialed
  // egress is caught separately by the secret-exfil block above.
  if (egress && looksExternal(url, execSurface) && hasOutboundData(execSurface, args)) {
    dangerSignals.push('external-egress');
  }
  // A structured delete tool is inherently a delete, even with no "rm" in any arg.
  if (family === 'delete' && !dangerSignals.includes('file-delete')) dangerSignals.push('file-delete');
  // A pure sudo capability probe (`sudo -n true`, `sudo -v`) has no side effect —
  // it only checks whether privilege is available. Announce it, don't gate it
  // (#73: `sudo -n true` was hard-denied). Any real sudo'd command still gates.
  if (dangerSignals.length === 1 && dangerSignals[0] === 'privilege-escalation' && isSudoCapabilityProbe(command)) {
    return verdict('allow', 'sensitive', family, 'sudo_probe',
      'sudo capability probe (no side effect)', ['sudo-capability-probe']);
  }
  if (dangerSignals.length > 0) {
    const action = dangerActionFor(dangerSignals, family);
    return verdict('require_approval', 'dangerous', family, action,
      `recognised dangerous operation requires approval (${dangerSignals.join(', ')})`, dangerSignals);
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
  if (signals.includes('install-package')) return 'install_package';
  if (signals.includes('modify-scheduler')) return 'modify_cron';
  if (signals.includes('external-egress')) return 'network_egress';
  if (signals.includes('touch-sensitive-path')) return 'access_secret_path';
  if (signals.includes('wipe-history-or-logs')) return 'wipe_logs';
  return ACTION_BY_FAMILY[family];
}

/**
 * True when a request actually sends data OUT — a write verb, a curl data/upload
 * flag, or a non-empty request body. Distinguishes an exfil-capable POST/upload
 * from a benign GET (docs/release fetch), which must not be gated (#73).
 */
function hasOutboundData(execSurface: string, args: Record<string, unknown>): boolean {
  if (/\b(?:POST|PUT|PATCH)\b|--data\b|--data-[\w-]+\b|(?:^|\s)-d(?:\s|@|=)|--upload-file\b|(?:^|\s)-T\s|(?:^|\s)-F\s|\bupload\b/i.test(execSurface)) {
    return true;
  }
  const method = pickString(args, ['method', 'http_method', 'verb']).toUpperCase();
  if (method === 'POST' || method === 'PUT' || method === 'PATCH') return true;
  return pickString(args, ['body', 'data', 'payload', 'json', 'form']).length > 0;
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
