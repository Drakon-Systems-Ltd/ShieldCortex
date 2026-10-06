/**
 * ShieldCortex — plain-English approval cards (#648).
 *
 * An approval card is a DECISION request: the owner is asked, on a phone, to
 * allow or refuse one held tool call. Until #648 the card inherited the
 * surface built for after-the-fact alerts — `Bash: [redacted action surface;
 * command not persisted …] fields=command`, `Tripped: touch-sensitive-path
 * (dangerous)` — and an approval the approver cannot evaluate is not a
 * control: it is tapped through, or the guard gets switched off.
 *
 * This module builds the three lines a non-technical owner needs to answer in
 * a few seconds:
 *
 *   1. WHAT  — a plain sentence built from derived facts (a verb class plus the
 *              specific target: a path, host, process or package name). Never
 *              the raw command. A target that looks like a credential is shown
 *              as `(withheld: looks like a secret)`; when no target can be
 *              derived the line says so instead of guessing.
 *   2. WHY   — every guard signal id mapped to a short phrase in ONE table
 *              (`SIGNAL_PHRASES`); an unknown id falls back to the id itself.
 *   3. WHO   — the agent, the box and the session.
 *
 * Scope, and the constraint that does NOT move: this is the ask/card path
 * only. Notify webhooks and `denials.jsonl` stay values-free (#284/#369/#517 —
 * `safeActionGuardSurface` in operator-notify.ts). Nothing in this module is
 * read by those writers; the card summary rides on `OperatorNotification.card`,
 * which the webhook payload builder does not copy, and the hook attaches it
 * only for the card channel.
 */
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readlinkSync, statSync } from 'node:fs';
import { homedir, hostname as osHostname } from 'node:os';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { redactCredentials } from '../credential-leak/index.js';
import { classifyFamily, evaluateToolCall, extractCommand, extractPath, extractUrl, normaliseToolName } from './tool-action-guard.js';

/** What the card shows in place of a target that looks like a credential. */
export const WITHHELD_SECRET = '(withheld: looks like a secret)';
/** A candidate too long to check is withheld before any pattern runs on it. */
export const WITHHELD_TOO_LONG = '(withheld: too long to check safely)';
/** A candidate carrying control, separator, bidi or zero-width characters. */
export const WITHHELD_UNUSUAL = '(withheld: unusual characters)';
/** The honest line when nothing safe can be said about the action. */
export const UNSUMMARISABLE_SHELL = 'Run a shell command (details withheld: could not summarise safely)';
/** The honest line when the step that tripped the guard cannot be singled out. */
export const UNATTRIBUTED_SHELL = 'Run several commands (the risky part could not be summarised)';
/** Appended when the parse cap cut the command short. */
export const COMMAND_TOO_LONG = '(command too long to summarise fully)';

/** Longest candidate any pattern in this module is run on. */
const MAX_TARGET_CHARS = 256;
/**
 * Characters that never reach a card (#648 r2 S9): C0 and C1 controls (NEL
 * U+0085 included), the Unicode line/paragraph separators, bidi embeddings,
 * overrides and isolates, zero-width marks and the BOM. Any of them can break
 * a line or make a target read as something else.
 */
const UNUSUAL_CHARS = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2028\u2029\u2066-\u2069\ufeff]/u;
const UNUSUAL_CHARS_ALL = new RegExp(UNUSUAL_CHARS.source, 'gu');

/**
 * Every signal id the guard (and the planes around it) can put on a verdict,
 * in plain English. ONE table: both card planes read it, and a test pins that
 * every id the guard can emit has an entry. Phrases complete the sentence
 * "ShieldCortex stopped it because it …".
 */
export const SIGNAL_PHRASES: Readonly<Record<string, string>> = Object.freeze({
  // Sensitive files and the guard's own state.
  'touch-sensitive-path': 'touches a sensitive file (keys, passwords or credentials)',
  'credential-access': 'reads passwords or credentials',
  'touch-approval-store': "touches ShieldCortex's own approval records",
  'touch-decisions-ledger': 'touches the decisions ledger or action leases',
  'touch-guard-config': "changes ShieldCortex's own settings",
  'disable-action-guard': 'could switch off or weaken ShieldCortex',
  'modify-shell-startup': 'changes a file that runs every time a shell starts',
  // Data leaving the machine.
  'external-egress': 'sends data off this machine',
  'network-egress': 'sends data off this machine',
  'data-exfiltration': 'may copy data off this machine',
  'secret-egress': 'tries to send a secret or credential off this machine',
  'secret-egress-fold': 'tries to send a secret or credential off this machine',
  // Running programs and services.
  'stop-process-or-service': 'stops a running program',
  'service-restart': 'restarts a running service',
  'openclaw-process-mutate': 'controls a running command',
  'openclaw-process-inspect': 'looks inside a running command',
  'openclaw-process-unknown-action': "asks a running command to do something ShieldCortex doesn't recognise",
  'privilege-escalation': 'runs with administrator (root) rights',
  // Software installs.
  'install-package': 'installs software on this machine',
  'install-package-global': 'installs software for the whole machine',
  'local-package-install': 'installs packages into this project',
  'registry-code-exec': 'downloads a package and runs it straight away',
  // Deleting and overwriting.
  'recursive-force-delete': 'deletes files permanently',
  'delete-root-or-home': 'deletes a whole home folder or disk',
  'delete-critical-path': 'deletes something the system depends on',
  'file-delete': 'deletes files',
  'recursive-find-delete': 'searches for files and deletes what it finds',
  'filesystem-destructive': 'can destroy files',
  'destructive-filesystem': 'can destroy files',
  'truncate-to-zero': 'empties a file',
  // The rule also matches any mention of `.bash_history`, not only a wipe.
  'wipe-history-or-logs': 'touches shell history or log files',
  'dd-overwrite': 'overwrites data in place',
  'move-or-copy': 'moves or copies files',
  'change-permissions': 'changes who can read or run files',
  'recursive-perms-on-root': 'changes permissions across the whole system',
  'recursive-perms-system-dir': 'changes permissions on a system folder',
  // Disks.
  'format-filesystem': 'erases a disk by reformatting it',
  'raw-disk-write': 'writes straight onto a disk, which can destroy its data',
  'redirect-to-block-device': 'writes straight onto a disk, which can destroy its data',
  'disk-partition-tool': 'changes disk partitions, which can destroy data',
  'shred-device': 'wipes a disk beyond recovery',
  'fork-bomb': 'could freeze the machine with endless copies of itself',
  // Downloaded or hidden code.
  'pipe-download-to-shell': 'downloads code from the internet and runs it straight away',
  'pipe-download-stdin-exec': 'downloads code from the internet and runs it straight away',
  'pipe-download-module-exec': 'downloads code from the internet and runs it straight away',
  'decode-pipe-to-shell': 'runs hidden (encoded) code',
  'opaque-script-invocation': "runs a script ShieldCortex can't read",
  'opaque-script': "runs a script ShieldCortex can't read",
  'opaque-command-substitution': "builds part of the command as it runs, so ShieldCortex can't see all of it",
  'untrusted-script': 'runs a script nobody has reviewed',
  'reviewed-script': 'runs a script on the reviewed list',
  'shell-injection': 'looks like a shell-injection attempt',
  'dangerous-shell': 'runs a risky shell command',
  'command-exec': 'runs a command',
  'exec-like': 'runs a command',
  'oversized-command': 'is too long for ShieldCortex to check fully',
  'command-evidence-unscannable': 'is too large or complex for ShieldCortex to check fully',
  'write-content-catastrophic': 'writes a file containing a destructive command',
  'write-content-dangerous': 'writes a file containing a risky command',
  'write-content-scanned': 'writes a script file',
  // Git.
  // A force flag or `+refspec` on a push: it MAY overwrite history; the
  // branch need not be shared, and `--force-with-lease` may refuse.
  'git-force-push': 'pushes to a remote branch (may overwrite history)',
  'force-push': 'pushes to a remote branch (may overwrite history)',
  'force-push-invocation': 'pushes to a remote branch (may overwrite history)',
  'git-delete-branch': 'deletes a git branch',
  'git-mutate': 'changes the git repository',
  // Scheduling, network and persistence.
  'modify-scheduler': 'changes scheduled jobs',
  'persistence-risk': 'sets something up to run again later on its own',
  'modify-network-firewall': 'changes firewall or network rules',
  // Tool input ShieldCortex could not fully read.
  'invalid-tool-input': "uses a tool in a way ShieldCortex doesn't recognise",
  'unknown-keys': "passes settings ShieldCortex doesn't recognise",
  'not-object': 'sends tool input in an unexpected shape',
  'nested-invalid': 'sends tool input in an unexpected shape',
  'type-coercion': 'sends tool input in an unexpected shape',
  'missing-handle': 'is missing the id of what it acts on',
  // Plane-level and policy reasons.
  'session-lease': 'clashes with work another agent holds a lease on',
  // The lease refusal rides beside `session-lease` as its verdict word.
  frozen: 'is blocked by a freeze in the decisions ledger',
  held: 'needs a lease another session already holds',
  unknown: 'could not confirm who holds the action lease',
  'fallback-scan': "was flagged by ShieldCortex's backup check (the main check was unavailable)",
  'approval-required': 'needs your approval by policy',
  'redacted-signal': 'matched another safety rule',
  'readiness-demoted': 'is the first call since ShieldCortex went watch-only',
  'readiness-promoted': 'is the first call since ShieldCortex began enforcing',
  'readiness-started': 'is the first call since ShieldCortex began watching here',
  'approval-round-trip-test': 'is a test card (nothing will run)',
});

const SIGNAL_ID_SHAPE = /^[a-z][a-z0-9-]{0,47}$/;

/** One signal id in plain English; an unknown id falls back to the id itself
 *  (shape-checked — a verdict's signals are guard vocabulary, never input). */
export function describeSignal(id: string): string {
  const key = String(id ?? '').trim();
  if (Object.prototype.hasOwnProperty.call(SIGNAL_PHRASES, key)) return SIGNAL_PHRASES[key];
  return SIGNAL_ID_SHAPE.test(key) ? key : 'matched another safety rule';
}

/** The WHY line's body: the first phrase always, further distinct phrases
 *  only while they fit `maxLen` whole, then a count of the rest. The count is
 *  never dropped (#648 r2 S5): when the first phrase and the count do not fit
 *  together, the phrase is shortened instead. */
export function describeSignals(signals: readonly string[] | undefined, maxLen = 59): string {
  const phrases: string[] = [];
  for (const s of Array.isArray(signals) ? signals : []) {
    const p = describeSignal(s);
    if (!phrases.includes(p)) phrases.push(p);
  }
  if (phrases.length === 0) return 'matched a safety rule';
  const more = (n: number) => (n > 0 ? ` (+${n} more reason${n === 1 ? '' : 's'})` : '');
  let shown = phrases[0];
  let used = 1;
  for (; used < phrases.length; used += 1) {
    const next = `${shown}; ${phrases[used]}`;
    if (next.length + more(phrases.length - used - 1).length > maxLen) break;
    shown = next;
  }
  const count = more(phrases.length - used);
  if (shown.length + count.length <= maxLen) return `${shown}${count}`;
  const room = Math.max(8, maxLen - count.length);
  return `${shown.slice(0, room - 1).trimEnd()}…${count}`;
}

// ── Targets: shown only after the credential redactor has passed them ──────────

const HOME = (() => {
  try { return homedir(); } catch { return ''; }
})();

/** Names that make `KEY=value` or `--flag value` a credential. Plain literal
 *  alternations, tested one maximal word at a time — never wrapped in an
 *  unbounded `[\w.-]*` on both sides (#648 r2 S2: that shape backtracked
 *  cubically on `token-token-…`). */
const SECRET_KEY_NAME = /token|secret|passw(?:or)?d|passwd|api[_-]?key|auth|credential|bearer|session[_-]?id|private[_-]?key/i;
const SECRET_FLAG_NAME = /token|secret|passw(?:or)?d|passwd|api[_-]?key|credential|private[_-]?key/i;
const ASSIGNS_VALUE = /\s*[=:]\s*\S/y;
const FOLLOWED_BY_VALUE = /\s+\S/y;
const URL_USERINFO = /[^/\s@]+@/y;
const OPAQUE_RUN = /[A-Za-z0-9+_-]{32,}/;
const KEBAB_WORDS = /^[a-z]+(?:-[a-z]+)+$/;

/**
 * Generic credential shapes the vendor-pattern redactor does not own. Linear
 * in the input: one pass over maximal `[\w.-]` words with sticky look-aheads,
 * one `indexOf` walk for URL userinfo, and a split for long opaque runs.
 */
export function looksSecretish(text: string): boolean {
  const WORD = /[\w.-]+/g;
  for (let m = WORD.exec(text); m !== null; m = WORD.exec(text)) {
    const word = m[0];
    const end = m.index + word.length;
    // KEY=value / --token=value / KEY: value where the key names a secret.
    ASSIGNS_VALUE.lastIndex = end;
    if (SECRET_KEY_NAME.test(word) && ASSIGNS_VALUE.test(text)) return true;
    // The same names as a flag whose value is the next word: `--password <value>`.
    if (word.startsWith('-') && (m.index === 0 || /\s/.test(text[m.index - 1])) && SECRET_FLAG_NAME.test(word)) {
      FOLLOWED_BY_VALUE.lastIndex = end;
      if (FOLLOWED_BY_VALUE.test(text)) return true;
    }
  }
  // URL userinfo: scheme://user:pass@ or scheme://token@
  for (let at = text.indexOf('://'); at !== -1; at = text.indexOf('://', at + 3)) {
    if (at === 0 || !/[a-z0-9+.-]/i.test(text[at - 1])) continue;
    URL_USERINFO.lastIndex = at + 3;
    if (URL_USERINFO.test(text)) return true;
  }
  // A long opaque run in any one segment of a path, host or argument.
  for (const part of text.split(/[\/\\\s:@?&=#,;]+/)) {
    if (OPAQUE_RUN.test(part) && !KEBAB_WORDS.test(part)) return true;
  }
  return false;
}

function middleClip(text: string, max: number): string {
  if (text.length <= max) return text;
  const head = Math.ceil((max - 1) / 3);
  const tail = max - 1 - head;
  return `${text.slice(0, head)}…${text.slice(text.length - tail)}`;
}

/**
 * The ONE gate every target passes before it can reach a card. Order matters:
 * the length cap and the character check first, so no pattern ever runs on an
 * oversized or hostile candidate (#648 r2 S2, S9); then the credential redactor
 * (it owns the vendor shapes — AWS key ids, GitHub/Slack/Stripe tokens,
 * private-key blocks), then the generic shapes it does not own. Anything that
 * trips any of them is withheld whole; a target is never partially masked,
 * because a half-shown secret is still a disclosure.
 */
export function safeTarget(raw: unknown, maxLen = 60): string {
  if (typeof raw !== 'string') return WITHHELD_SECRET;
  if (raw.length > MAX_TARGET_CHARS * 2) return WITHHELD_TOO_LONG;
  const text = raw.trim();
  if (!text) return WITHHELD_SECRET;
  if (text.length > MAX_TARGET_CHARS) return WITHHELD_TOO_LONG;
  if (UNUSUAL_CHARS.test(text)) return WITHHELD_UNUSUAL;
  let redacted: string;
  try {
    redacted = redactCredentials(text);
  } catch {
    return WITHHELD_SECRET;
  }
  if (redacted !== text) return WITHHELD_SECRET;
  if (looksSecretish(text)) return WITHHELD_SECRET;
  let shown = text;
  if (HOME && HOME.length > 1 && (shown === HOME || shown.startsWith(`${HOME}/`))) shown = `~${shown.slice(HOME.length)}`;
  return middleClip(shown, maxLen);
}

const isWithheld = (shown: string) => shown.startsWith('(withheld');

/**
 * A target as the card prints it: through `safeTarget`, then in visible
 * quotes (#648 r2 S9), so a path that reads like prose — `notes. Why: routine`
 * — cannot pass for card text. A target with a quote of its own could close
 * the quotes early, so it is withheld instead.
 */
function quoted(raw: unknown, maxLen = 60): string {
  const shown = safeTarget(raw, maxLen);
  if (isWithheld(shown)) return shown;
  if (shown.includes('"')) return WITHHELD_UNUSUAL;
  return `"${shown}"`;
}

/** A host name from a URL, `user@host` or `user@host:path`, or null. */
function hostOf(text: string): string | null {
  const t = String(text ?? '').trim();
  if (!t || t.length > MAX_TARGET_CHARS) return null;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(t)) {
    try {
      const h = new URL(t).hostname.toLowerCase();
      return h || null;
    } catch {
      return null;
    }
  }
  const scp = /^(?:[^@\s/]+@)?([A-Za-z0-9.-]+\.[A-Za-z]{2,}|localhost|\d{1,3}(?:\.\d{1,3}){3}):/.exec(t);
  if (scp) return scp[1].toLowerCase();
  const at = /^[^@\s/]+@([A-Za-z0-9.-]+)$/.exec(t);
  if (at) return at[1].toLowerCase();
  return null;
}

/** The host only — never userinfo, path or query — after the target gate. A
 *  URL carrying credentials in its userinfo (`https://user:pass@…`,
 *  `https://<token>@…`) is withheld whole, host included. The path and query
 *  are never shown, so only the host itself goes through the redactor. */
function safeHost(text: string): string | null {
  const h = hostOf(text);
  if (!h || !/^[a-z0-9.-]{1,253}$/.test(h)) return null;
  if (/^[a-z][a-z0-9+.-]*:\/\/[^/\s@]+@/i.test(text) || /^[^@\s/]*:[^@\s/]*@/.test(text)) return WITHHELD_SECRET;
  return safeTarget(h);
}

const SENSITIVE_PATH_RE =
  /(?:^|[\/~])\.ssh(?:\/|$)|authorized_keys|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|\/etc\/(?:passwd|shadow|gshadow|sudoers)\b|\.aws\/|(?:^|\/)\.env(?:\.[\w.-]+)?$|\.gnupg|\.netrc|\.npmrc|\.pgpass|\.git-credentials|\.docker\/config\.json|\.kube\/config|\.shieldcortex(?:\/|$)/i;

/** Where a sensitive path lives, for the WHAT line ("… in your SSH folder"). */
function locationOf(path: string): string {
  if (/(?:^|[\/~])\.ssh(?:\/|$)|authorized_keys|\bid_(?:rsa|dsa|ecdsa|ed25519)\b/i.test(path)) return ' in your SSH folder';
  if (/\.aws\//i.test(path)) return ' in your AWS folder';
  if (/\.gnupg/i.test(path)) return ' in your GPG keyring';
  if (/\.shieldcortex(?:\/|$)/i.test(path)) return " in ShieldCortex's own folder";
  if (/\/etc\/(?:passwd|shadow|gshadow|sudoers)\b/i.test(path)) return ' holding system accounts or passwords';
  if (/(?:^|\/)\.env(?:\.[\w.-]+)?$/i.test(path)) return ' of secret settings';
  if (/\.netrc|\.npmrc|\.pgpass|\.git-credentials|\.docker\/config\.json|\.kube\/config/i.test(path)) return ' holding saved logins';
  return '';
}

// ── Shell parsing: just enough to find the verb and its target ──────────────

const MAX_COMMAND_CHARS = 8192;
/** A word longer than this keeps only its head and tail, so no pattern below
 *  ever runs on more than ~257 characters, and `safeTarget` withholds it. */
const MAX_WORD_CHARS = MAX_TARGET_CHARS;

interface Segment {
  words: string[];
  /** Files named by `>`/`>>` redirections in this segment. */
  writes: string[];
  opaque: boolean;
  /** The segment's own text, as typed — what the guard is re-run on. */
  raw: string;
  /** Index of the pipeline (`a | b`) this segment belongs to. */
  pipeline: number;
}

interface ParsedShell {
  segments: Segment[];
  /** Each pipeline's own text, indexed like `Segment.pipeline`. */
  pipelines: string[];
  /** The command was longer than the parse cap. */
  truncated: boolean;
}

const clipWord = (w: string) => (w.length > MAX_WORD_CHARS ? `${w.slice(0, 128)}…${w.slice(-128)}` : w);

/** Split a command line into simple commands (on unquoted `;`, `&`, `|`,
 *  newlines) of decoded words. Quotes are honoured; `$(…)` and backticks mark
 *  the segment opaque rather than being expanded. */
function parseShell(command: string): ParsedShell {
  const text = command.slice(0, MAX_COMMAND_CHARS);
  const segments: Segment[] = [];
  const pipelines: string[] = [];
  let words: string[] = [];
  let writes: string[] = [];
  let opaque = false;
  let word = '';
  let inWord = false;
  let pendingRedirect = false;
  let segStart = 0;
  let pipeStart = 0;
  let pipeline = 0;
  const endWord = () => {
    if (!inWord) return;
    if (pendingRedirect) {
      if (!word.startsWith('&')) writes.push(clipWord(word));
      pendingRedirect = false;
    } else {
      words.push(clipWord(word));
    }
    word = '';
    inWord = false;
  };
  const endSegment = (end: number) => {
    endWord();
    pendingRedirect = false;
    if (words.length > 0 || writes.length > 0) {
      segments.push({ words, writes, opaque, raw: text.slice(segStart, end).trim(), pipeline });
    }
    words = [];
    writes = [];
    opaque = false;
    segStart = end + 1;
  };
  const endPipeline = (end: number) => {
    endSegment(end);
    if (segments.some((s) => s.pipeline === pipeline)) {
      pipelines[pipeline] = text.slice(pipeStart, end).trim();
      pipeline += 1;
    }
    pipeStart = end + 1;
  };
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (ch === "'") {
      const close = text.indexOf("'", i + 1);
      const end = close === -1 ? text.length : close;
      word += text.slice(i + 1, end);
      inWord = true;
      i = end;
      continue;
    }
    if (ch === '"') {
      i += 1;
      while (i < text.length && text[i] !== '"') {
        if (text[i] === '\\' && i + 1 < text.length && '"\\$`'.includes(text[i + 1])) {
          word += text[i + 1];
          i += 2;
          continue;
        }
        if (text[i] === '`' || (text[i] === '$' && text[i + 1] === '(')) opaque = true;
        word += text[i];
        i += 1;
      }
      inWord = true;
      continue;
    }
    if (ch === '\\' && i + 1 < text.length) {
      if (text[i + 1] !== '\n') word += text[i + 1];
      inWord = true;
      i += 1;
      continue;
    }
    if (ch === '`' || (ch === '$' && text[i + 1] === '(')) opaque = true;
    if (/\s/.test(ch) && ch !== '\n') {
      endWord();
      continue;
    }
    if (ch === '\n' || ch === ';' || ch === '|' || ch === '&') {
      // `2>&1` / `>&2` keep their `&` inside the redirect target.
      if (ch === '&' && pendingRedirect && !inWord) {
        word += ch;
        inWord = true;
        continue;
      }
      // A single `|` joins a pipeline; `||`, `;`, `&`, `&&` and newlines end one.
      if (ch === '|' && text[i + 1] !== '|' && text[i - 1] !== '|') endSegment(i);
      else endPipeline(i);
      continue;
    }
    if (ch === '>' || ch === '<') {
      // A bare fd number before the operator (`2>`) is not a word.
      if (inWord && /^\d+$/.test(word)) {
        word = '';
        inWord = false;
      } else {
        endWord();
      }
      if (ch === '>') {
        if (text[i + 1] === '>') i += 1;
        pendingRedirect = true;
      } else {
        pendingRedirect = false;
      }
      continue;
    }
    word += ch;
    inWord = true;
  }
  endPipeline(text.length);
  return { segments, pipelines, truncated: command.length > MAX_COMMAND_CHARS };
}

/**
 * Folders whose programs are the system's own. A program named by a path
 * anywhere else (`./cat`, `/tmp/rm`, `~/bin/curl`) is NOT described by its
 * name (#648 r2 S4): a file called `cat` in /tmp can do anything.
 */
const SYSTEM_BIN_DIRS = new Set([
  '/bin', '/sbin', '/usr/bin', '/usr/sbin', '/usr/local/bin', '/usr/local/sbin',
  '/opt/homebrew/bin', '/opt/homebrew/sbin', '/snap/bin',
]);
const isTrustedProgram = (argv0: string) => !argv0.includes('/') || SYSTEM_BIN_DIRS.has(dirname(argv0));

const WRAPPERS = new Set(['sudo', 'doas', 'env', 'nohup', 'time', 'nice', 'ionice', 'timeout', 'stdbuf', 'setsid', 'command', 'exec', 'xargs', 'builtin']);
/** Wrapper flags that consume the next word. */
const WRAPPER_FLAG_ARGS: Record<string, RegExp> = {
  sudo: /^-[ugpCDhrtT]$/,
  doas: /^-[uC]$/,
  nice: /^-n$/,
  ionice: /^-[cnp]$/,
  timeout: /^-[sk]$/,
  xargs: /^-[IEdLnPsa]$/,
  env: /^-[uCS]$/,
};

/** Strip env assignments and wrappers; returns the program and its arguments. */
function unwrap(seg: Segment): { prog: string; argv0: string; args: string[]; sudo: boolean } {
  const w = [...seg.words];
  let sudo = false;
  let guard = 0;
  while (w.length > 0 && guard < 32) {
    guard += 1;
    const head = w[0];
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(head)) { w.shift(); continue; }
    const name = basename(head);
    if (!WRAPPERS.has(name) || !isTrustedProgram(head)) break;
    if (name === 'sudo' || name === 'doas') sudo = true;
    w.shift();
    while (w.length > 0 && (w[0].startsWith('-') || /^[A-Za-z_][A-Za-z0-9_]*=/.test(w[0]))) {
      const flag = w.shift() as string;
      if (WRAPPER_FLAG_ARGS[name]?.test(flag) && w.length > 0) w.shift();
    }
    if (name === 'timeout' && w.length > 0 && /^\d+(?:\.\d+)?[smhd]?$/.test(w[0])) w.shift();
  }
  const argv0 = w[0] ?? '';
  return { prog: argv0 ? basename(argv0) : '', argv0, args: w.slice(1), sudo };
}

const isFlag = (a: string) => a.startsWith('-') && a !== '-';

/**
 * Options whose VALUE is the next word, per program (#648 r2 S7): without
 * this, `head -n 5 f` names `5` and `curl -o FILE host` takes its host from
 * FILE. `--opt=value` is one word and needs no entry.
 */
const FLAG_VALUES: Record<string, RegExp> = {
  head: /^-[nc]$|^--(?:lines|bytes)$/,
  tail: /^-[ncs]$|^--(?:lines|bytes|sleep-interval|pid)$/,
  sort: /^-[ktoST]$|^--(?:key|field-separator|output|buffer-size|temporary-directory)$/,
  cut: /^-[dfbc]$|^--(?:delimiter|fields|bytes|characters|output-delimiter)$/,
  uniq: /^-[fsw]$|^--(?:skip-fields|skip-chars|check-chars)$/,
  nl: /^-[bvisw]$/,
  xxd: /^-[lscgo]$/,
  od: /^-[ANjtw]$/,
  hexdump: /^-[nsef]$/,
  base64: /^-w$|^--wrap$/,
  strings: /^-[nt]$/,
  jq: /^-[f]$|^--(?:arg|argjson|slurpfile|rawfile|indent|from-file)$/,
  yq: /^-[pIo]$/,
  diff: /^-[CUFIL]$|^--(?:label|ignore-matching-lines)$/,
  grep: /^-[efmABCd]$|^--(?:regexp|file|max-count|after-context|before-context|context|include|exclude|exclude-dir)$/,
  rg: /^-[efmABCgtTM]$|^--(?:regexp|file|max-count|after-context|before-context|context|glob|type|type-not|max-columns)$/,
  curl: /^-[odHuXAebcFTxKmwrEyYUQ]$|^--(?:output|data(?:-\w+)?|header|user|request|user-agent|referer|cookie|cookie-jar|form|form-string|upload-file|proxy|config|max-time|connect-timeout|write-out|range|cert|key|cacert|resolve|retry|json|url|oauth2-bearer)$/,
  wget: /^-[OoaPUeTtwlAR]$|^--(?:output-document|output-file|append-output|directory-prefix|header|post-data|post-file|user-agent|user|password|body-data|body-file|method|timeout|tries|wait|level)$/,
  pkill: /^-[sUuGgPtn]$|^--(?:signal|older-than|younger-than|ns|nslist)$/,
  killall: /^-[sUuoy]$|^--(?:signal|user|older-than|younger-than)$/,
  ssh: /^-[bcDEeFIiJLlmOopQRSWw]$/,
};
FLAG_VALUES.egrep = FLAG_VALUES.grep;
FLAG_VALUES.fgrep = FLAG_VALUES.grep;
FLAG_VALUES.ag = FLAG_VALUES.grep;
FLAG_VALUES.ack = FLAG_VALUES.grep;
FLAG_VALUES.mosh = FLAG_VALUES.ssh;

/** The operands of `prog`: arguments that are neither flags nor a flag's
 *  value. Everything after `--` is an operand. */
function operands(prog: string, args: string[]): string[] {
  const takesValue = FLAG_VALUES[prog];
  const out: string[] = [];
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i];
    if (a === '--') { out.push(...args.slice(i + 1)); break; }
    if (!isFlag(a)) { out.push(a); continue; }
    if (prog === 'jq' && /^--(?:arg|argjson|slurpfile|rawfile)$/.test(a)) { i += 2; continue; }
    if (takesValue?.test(a)) i += 1;
  }
  return out;
}

/** A program name fit to print: a bare, credential-free identifier. */
function safeProgram(prog: string): string | null {
  if (!/^[A-Za-z0-9][A-Za-z0-9._+-]{0,31}$/.test(prog)) return null;
  return safeTarget(prog, 32) === prog ? prog : null;
}

/**
 * The only subcommand words a card prints (#648 r2 S8). The first argument of
 * an unknown program is free-form — it can be a password (`tool <secret>`) —
 * so it is never shown; known tools show a word only from their own list.
 */
const SUBCOMMANDS: Record<string, ReadonlySet<string>> = (() => {
  const set = (...w: string[]) => new Set(w);
  const containers = set('run', 'exec', 'build', 'push', 'pull', 'rm', 'rmi', 'stop', 'kill', 'restart', 'start', 'compose', 'system', 'volume', 'image', 'network', 'container', 'login', 'logout', 'cp', 'logs', 'ps', 'images', 'tag', 'save', 'load', 'prune');
  const js = set('run', 'test', 'exec', 'publish', 'uninstall', 'remove', 'rm', 'update', 'upgrade', 'link', 'unlink', 'start', 'build', 'audit', 'version', 'pack', 'config', 'login', 'logout', 'cache', 'dlx', 'create', 'init');
  return {
    docker: containers,
    podman: containers,
    kubectl: set('apply', 'delete', 'exec', 'get', 'describe', 'logs', 'scale', 'rollout', 'edit', 'patch', 'create', 'run', 'cp', 'port-forward', 'drain', 'cordon', 'uncordon', 'label', 'annotate', 'set', 'replace', 'expose', 'config'),
    helm: set('install', 'upgrade', 'uninstall', 'delete', 'rollback', 'template', 'repo', 'list', 'status'),
    terraform: set('apply', 'destroy', 'plan', 'init', 'import', 'state', 'taint', 'untaint', 'refresh', 'output', 'workspace'),
    npm: js, pnpm: js, yarn: js, bun: js,
    gh: set('pr', 'issue', 'repo', 'release', 'api', 'auth', 'secret', 'workflow', 'run', 'gist', 'variable', 'label'),
    cargo: set('run', 'build', 'test', 'publish', 'clean', 'update', 'uninstall', 'add', 'remove'),
    pip: set('uninstall', 'download', 'freeze', 'list', 'show'),
    pip3: set('uninstall', 'download', 'freeze', 'list', 'show'),
    brew: set('uninstall', 'upgrade', 'update', 'services', 'tap', 'untap', 'link', 'unlink', 'cleanup'),
    openclaw: set('gateway', 'config', 'configure', 'plugins', 'channels', 'update', 'cron', 'status', 'agents', 'sessions', 'doctor', 'memory'),
    shieldcortex: set('approve', 'deny', 'allowlist', 'guard', 'config', 'doctor', 'uninstall', 'setup', 'status', 'audit'),
  };
})();
const GIT_SUBCOMMANDS = new Set([
  'add', 'commit', 'rebase', 'merge', 'checkout', 'switch', 'restore', 'stash', 'tag', 'cherry-pick', 'revert',
  'rm', 'mv', 'config', 'remote', 'submodule', 'worktree', 'gc', 'prune', 'reflog', 'filter-branch', 'filter-repo',
  'update-ref', 'notes', 'am', 'apply', 'bisect', 'status', 'log', 'diff', 'show', 'init', 'branch', 'reset', 'clean',
  'lfs', 'replace', 'symbolic-ref', 'update-index', 'sparse-checkout', 'maintenance',
]);
const SERVICE_VERBS = new Set(['start', 'enable', 'reenable', 'daemon-reload', 'status', 'edit', 'set-property', 'isolate', 'link', 'unmask', 'preset', 'revert', 'load', 'bootstrap', 'kickstart', 'set-default']);

type Category =
  | 'read' | 'write' | 'delete' | 'move' | 'perms' | 'stop' | 'network' | 'install'
  | 'git' | 'scheduler' | 'firewall' | 'disk' | 'script' | 'system' | 'other';

interface Described {
  category: Category;
  sentence: string;
}

interface ShellContext {
  signals: readonly string[];
  cwd?: string;
  agentPid?: number;
  procRoot?: string;
}

/**
 * How much a path matters, for picking which of several to name (#648 r2 S7):
 * a sensitive file, then the root or a home folder itself, then a system or
 * home path, then any other absolute or parent path, then a local one.
 */
function pathRank(p: string): number {
  if (SENSITIVE_PATH_RE.test(p)) return 5;
  if (/^(?:\/+|~\/?|\$HOME\/?|\$\{HOME\}\/?|\*|\.\.?\/?)$/.test(p)) return 4;
  if (/^(?:~|\$HOME|\$\{HOME\})\//.test(p) || /^\/(?:etc|usr|bin|sbin|lib|lib64|boot|var|opt|srv|root|home|Users|sys|proc|dev|System|Library|private)(?:\/|$)/.test(p)) return 3;
  if (isAbsolute(p) || p.startsWith('../')) return 2;
  return 1;
}

/** The path to name: the highest `pathRank`, the first on a tie. */
function mostSensitive(paths: string[]): string {
  let best = paths[0];
  for (const p of paths) if (pathRank(p) > pathRank(best)) best = p;
  return best;
}

const andMore = (n: number) => (n > 0 ? ` and ${n} more` : '');

function pathPhrase(verb: string, paths: string[], noun = 'a file'): string {
  const chosen = mostSensitive(paths);
  const loc = locationOf(chosen);
  const target = quoted(chosen);
  if (paths.length > 1) return `${verb} ${paths.length} files, including one${loc}: ${target}`;
  return `${verb} ${noun}${loc}: ${target}`;
}

/** `cat SRC > DST`: a copy, named by its (most sensitive) source. */
function copyPhrase(sources: string[], dest: string): string {
  const src = mostSensitive(sources);
  const from = locationOf(src).replace(/^ in /, ' from ');
  const what = sources.length > 1 ? `${sources.length} files, including one${from}` : `a file${from}`;
  return `Copy ${what} (${quoted(src)}) to ${quoted(dest)}`;
}

const READERS = new Set(['cat', 'less', 'more', 'head', 'tail', 'bat', 'batcat', 'view', 'strings', 'xxd', 'od', 'hexdump', 'base64', 'nl', 'wc', 'file', 'stat', 'jq', 'yq', 'md5sum', 'sha1sum', 'sha256sum', 'sort', 'uniq', 'cut', 'diff', 'cmp', 'source', '.']);
const SEARCHERS = new Set(['grep', 'egrep', 'fgrep', 'rg', 'ag', 'ack']);
const EDITORS = new Set(['vi', 'vim', 'nvim', 'nano', 'emacs', 'pico', 'ed', 'code']);
const INTERPRETERS = new Set(['bash', 'sh', 'zsh', 'dash', 'ksh', 'fish', 'python', 'python2', 'python3', 'node', 'deno', 'ruby', 'perl', 'php', 'tsx', 'ts-node', 'pwsh', 'osascript']);
const SYSTEM_PKG = new Set(['apt', 'apt-get', 'dnf', 'yum', 'apk', 'brew', 'pacman', 'snap']);
const PKG_MANAGERS: Record<string, { label: string; install: RegExp }> = {
  npm: { label: 'npm', install: /^(?:install|i|in|ins|inst|insta|instal|isnt|isntall|add|ci)$/ },
  pnpm: { label: 'pnpm', install: /^(?:install|i|add)$/ },
  yarn: { label: 'yarn', install: /^(?:install|add)$/ },
  bun: { label: 'bun', install: /^(?:install|i|add)$/ },
  pip: { label: 'pip', install: /^install$/ },
  pip3: { label: 'pip', install: /^install$/ },
  pipx: { label: 'pipx', install: /^install$/ },
  uv: { label: 'uv', install: /^(?:add|pip)$/ },
  gem: { label: 'gem', install: /^install$/ },
  cargo: { label: 'cargo', install: /^install$/ },
  go: { label: 'go', install: /^(?:install|get)$/ },
  apt: { label: 'apt', install: /^install$/ },
  'apt-get': { label: 'apt-get', install: /^install$/ },
  dnf: { label: 'dnf', install: /^install$/ },
  yum: { label: 'yum', install: /^install$/ },
  apk: { label: 'apk', install: /^add$/ },
  brew: { label: 'brew', install: /^install$/ },
  pacman: { label: 'pacman', install: /^-S\w*$/ },
  snap: { label: 'snap', install: /^install$/ },
};
const RUNNERS = new Set(['npx', 'bunx', 'pnpx', 'uvx']);
const DISK_SIGNAL_RE = /disk|block-device|format-filesystem|shred-device|dd-overwrite/;

function describeInstall(prog: string, args: string[]): Described | null {
  const pm = PKG_MANAGERS[prog];
  if (!pm) return null;
  const subIdx = args.findIndex((a) => !isFlag(a) || (prog === 'pacman' && /^-S/.test(a)));
  if (subIdx === -1 || !pm.install.test(args[subIdx])) return null;
  const rest = args.slice(subIdx + 1);
  const global = args.some((a) => /^(?:-g|--global|--location=global)$/.test(a));
  const label = `${pm.label}${global ? ', whole machine' : ''}`;
  const reqIdx = rest.findIndex((a) => a === '-r' || a === '--requirement');
  if (reqIdx !== -1 && rest[reqIdx + 1]) {
    return { category: 'install', sentence: `Install the packages listed in ${quoted(rest[reqIdx + 1])} (${label})` };
  }
  // Flags that take a value (`--registry <url>`, `-w <workspace>`) are not package names.
  const names = rest.filter((a, i) => !isFlag(a)
    && !(i > 0 && /^(?:--registry|--prefix|--cache|--tag|-w|--workspace|--index-url|-i|--extra-index-url|--target|-t|--root|--path|--source|-C|-c|--constraint)$/.test(rest[i - 1]))
    && !/^[a-z][a-z0-9+.-]*:\/\//i.test(a));
  if (names.length === 0) return { category: 'install', sentence: `Install this project's dependencies (${label})` };
  const shown = names.slice(0, 3).map((n) => quoted(n, 40));
  const noun = SYSTEM_PKG.has(prog) ? 'system software' : names.length === 1 ? 'a package' : `${names.length} packages`;
  return { category: 'install', sentence: `Install ${noun}: ${shown.join(', ')}${andMore(names.length - shown.length)} (${label})` };
}

/** Best-effort, bounded read of the remote URL a git command will talk to. */
function gitRemoteHost(cwd: string | undefined, remote: string): string | null {
  if (!cwd || !isAbsolute(cwd) || !/^[A-Za-z0-9._-]{1,64}$/.test(remote)) return null;
  try {
    let dir = cwd;
    for (let depth = 0; depth < 16; depth += 1) {
      const dotGit = join(dir, '.git');
      if (existsSync(dotGit)) {
        let gitDir = dotGit;
        if (statSync(dotGit).isFile()) {
          const m = /^gitdir:\s*(.+)$/m.exec(readFileSync(dotGit, 'utf8').slice(0, 4096));
          if (!m) return null;
          gitDir = resolve(dir, m[1].trim());
          const common = join(gitDir, 'commondir');
          if (existsSync(common)) gitDir = resolve(gitDir, readFileSync(common, 'utf8').slice(0, 4096).trim());
        }
        const config = readFileSync(join(gitDir, 'config'), 'utf8').slice(0, 65_536);
        let inRemote = false;
        for (const line of config.split('\n')) {
          const header = /^\s*\[(.+)\]\s*$/.exec(line);
          if (header) {
            inRemote = header[1].trim() === `remote "${remote}"`;
            continue;
          }
          const url = inRemote ? /^\s*url\s*=\s*(\S+)/.exec(line)?.[1] : undefined;
          if (url) return safeHost(url);
        }
        return null;
      }
      const parent = dirname(dir);
      if (parent === dir) return null;
      dir = parent;
    }
  } catch {
    return null;
  }
  return null;
}

const GIT_NETWORK = new Set(['push', 'fetch', 'pull', 'clone', 'ls-remote']);

function describeGit(args: string[], ctx: ShellContext): Described {
  // Skip global options (`-C dir`, `-c k=v`, `--git-dir=…`).
  let i = 0;
  while (i < args.length && isFlag(args[i])) {
    if (/^-[Cc]$/.test(args[i])) i += 1;
    i += 1;
  }
  const sub = args[i];
  const rest = args.slice(i + 1);
  if (sub && GIT_NETWORK.has(sub)) {
    const pos = operands('git', rest);
    const remoteArg = sub === 'clone' ? pos[0] : pos[0] ?? 'origin';
    const host = remoteArg ? (safeHost(remoteArg) ?? gitRemoteHost(ctx.cwd, remoteArg)) : null;
    const where = host ?? (remoteArg && /^[A-Za-z0-9._-]{1,32}$/.test(remoteArg) ? `the "${remoteArg}" remote` : 'a remote server');
    const force = sub === 'push' && rest.some((a) => /^(?:-f|--force|--force-with-lease(?:=.*)?|--mirror)$/.test(a) || /^\+/.test(a));
    const del = sub === 'push' && rest.some((a) => /^(?:-d|--delete)$/.test(a) || /^:/.test(a));
    const branch = sub === 'push' ? pos.slice(1).map((b) => b.replace(/^[+:]/, '')).find(Boolean) : undefined;
    const branchText = branch ? ` (branch ${quoted(branch, 40)})` : '';
    if (force) return { category: 'git', sentence: `Force-push to ${where}${branchText}, which may overwrite history (git push --force)` };
    if (del) return { category: 'git', sentence: `Delete a branch on ${where}${branchText} (git push --delete)` };
    return { category: 'network', sentence: `Send data to ${where} (git ${sub})` };
  }
  if (sub === 'branch' && rest.some((a) => /^(?:-D|-d|--delete)$/.test(a))) {
    const name = operands('git', rest)[0];
    return { category: 'git', sentence: name ? `Delete a git branch: ${quoted(name, 40)}` : 'Delete a git branch' };
  }
  if (sub === 'reset' && rest.includes('--hard')) return { category: 'git', sentence: 'Throw away uncommitted changes (git reset --hard)' };
  if (sub === 'clean') return { category: 'git', sentence: 'Delete untracked files in the repository (git clean)' };
  return { category: 'git', sentence: sub && GIT_SUBCOMMANDS.has(sub) ? `Change the git repository (git ${sub})` : 'Change the git repository' };
}

const HTTP_CLIENTS = new Set(['curl', 'wget', 'http', 'https', 'xh']);
const RAW_SOCKETS = new Set(['nc', 'ncat', 'netcat', 'telnet', 'socat']);
const COPY_REMOTE = new Set(['scp', 'sftp', 'rsync']);
/** HTTP client options that send a body (`-d@file`, `--data=x`, `-T f`). */
const SENDS_BODY = /^(?:-[dFT].*|--(?:data(?:-\w+)?|form(?:-string)?|upload-file|json|post-data|post-file|body-data|body-file)(?:=.*)?)$/;
const WRITE_METHOD = /^(?:POST|PUT|PATCH|DELETE)$/i;

function describeNetworkTool(prog: string, args: string[], ctx: ShellContext): Described | null {
  if (HTTP_CLIENTS.has(prog)) {
    const pos = operands(prog, args);
    const url = pos.find((a) => /^[a-z][a-z0-9+.-]*:\/\//i.test(a)) ?? pos.find((a) => /^[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:[/:]|$)/.test(a));
    const host = url ? safeHost(/^[a-z][a-z0-9+.-]*:\/\//i.test(url) ? url : `https://${url}`) : null;
    const sends = args.some((a) => SENDS_BODY.test(a))
      || args.some((a, i) => /^(?:-X|--request|--method)$/.test(a) && WRITE_METHOD.test(args[i + 1] ?? ''))
      || args.some((a) => /^(?:-X|--request=|--method=)(?:POST|PUT|PATCH|DELETE)$/i.test(a));
    const egress = ctx.signals.some((s) => /egress|exfil/.test(s));
    const verb = sends || egress ? 'Send data to' : 'Download from';
    return { category: 'network', sentence: host ? `${verb} ${host} (${prog})` : `${verb} a web address it could not show safely (${prog})` };
  }
  if (prog === 'ssh' || prog === 'mosh') {
    // ssh options that consume the next word (`-p 22`, `-i <key>`) are not the destination.
    const dest = operands(prog, args)[0];
    const host = dest ? safeHost(dest.includes('@') ? dest : `x@${dest}`) : null;
    return { category: 'network', sentence: host ? `Log in to ${host} over SSH` : 'Log in to another machine over SSH' };
  }
  if (COPY_REMOTE.has(prog)) {
    const pos = operands(prog, args);
    const remoteIdx = pos.findIndex((p) => hostOf(p) !== null && /:/.test(p) && !/^[a-z]+:\/\//i.test(p));
    if (remoteIdx === -1 && prog === 'rsync') return null;
    const host = remoteIdx !== -1 ? safeHost(pos[remoteIdx]) : null;
    const where = host ?? 'another machine';
    return { category: 'network', sentence: remoteIdx === pos.length - 1 ? `Copy files to ${where} (${prog})` : `Copy files from ${where} (${prog})` };
  }
  if (RAW_SOCKETS.has(prog)) {
    const host = operands(prog, args).map((a) => safeHost(`x@${a}`)).find((h) => h && !isWithheld(h));
    return { category: 'network', sentence: host ? `Open a raw network connection to ${host} (${prog})` : `Open a raw network connection (${prog})` };
  }
  if ((prog === 'npm' || prog === 'pnpm' || prog === 'yarn') && args[0] === 'publish') {
    return { category: 'network', sentence: `Publish a package to the ${prog} registry` };
  }
  return null;
}

function formatAge(seconds: number): string | null {
  if (!Number.isFinite(seconds) || seconds < 0) return null;
  const unit = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;
  if (seconds < 60) return unit(Math.round(seconds), 'second');
  if (seconds < 3600) return unit(Math.round(seconds / 60), 'minute');
  if (seconds < 86_400) return unit(Math.round(seconds / 3600), 'hour');
  return unit(Math.round(seconds / 86_400), 'day');
}

interface ProcFacts { name: string | null; age: string | null; cwd: string | null; startedByAgent: boolean }

/** Linux /proc facts about one PID. Every read is best-effort; nothing here
 *  ever throws, and every string passes `safeTarget` before it can be shown.
 *  `startedByAgent` is true only when the PID's ancestry reaches
 *  `ctx.agentPid` — the caller passes that only when the process is this
 *  agent's own session (Claude Code), never a shared gateway. */
function procFacts(pid: number, ctx: ShellContext): ProcFacts | null {
  const root = ctx.procRoot ?? (process.platform === 'linux' ? '/proc' : null);
  if (!root) return null;
  const read = (p: string) => {
    try { return readFileSync(join(root, p), 'utf8').slice(0, 4096); } catch { return null; }
  };
  const statOf = (id: number) => {
    const raw = read(`${id}/stat`);
    if (!raw) return null;
    const fields = raw.slice(raw.lastIndexOf(')') + 2).trim().split(/\s+/);
    return { ppid: Number(fields[1]), start: Number(fields[19]) };
  };
  const own = statOf(pid);
  const commRaw = read(`${pid}/comm`)?.trim() ?? null;
  if (!own && !commRaw) return null;
  const name = commRaw && /^[A-Za-z0-9._+:-]{1,32}$/.test(commRaw) && safeTarget(commRaw, 32) === commRaw ? commRaw : null;
  let age: string | null = null;
  const uptime = Number(read('uptime')?.split(/\s+/)[0]);
  // Linux reports start time in clock ticks; USER_HZ is 100 on every
  // mainstream build. An age off by a tick-rate is still "about N minutes".
  if (own && Number.isFinite(own.start) && Number.isFinite(uptime)) age = formatAge(uptime - own.start / 100);
  let cwd: string | null = null;
  try {
    const shown = quoted(readlinkSync(join(root, `${pid}/cwd`)), 32);
    if (!isWithheld(shown)) cwd = shown;
  } catch { /* not ours to read — the card just says less */ }
  let startedByAgent = false;
  if (own && ctx.agentPid && ctx.agentPid > 1) {
    let cur = own.ppid;
    for (let hop = 0; hop < 32 && Number.isFinite(cur) && cur > 1; hop += 1) {
      if (cur === ctx.agentPid) { startedByAgent = true; break; }
      cur = statOf(cur)?.ppid ?? 0;
    }
  }
  return { name, age, cwd, startedByAgent };
}

function describeKill(args: string[], ctx: ShellContext): Described {
  // The first dash word is the signal (`-9`, `-KILL`, `-s KILL`); after it, or
  // after `--`, a dash number is a process group, and `-1` is every process
  // the caller may signal.
  const targets: string[] = [];
  let signalSeen = false;
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i];
    if (a === '--') { targets.push(...args.slice(i + 1)); break; }
    if (/^(?:-s|-n|--signal)$/.test(a)) { i += 1; signalSeen = true; continue; }
    if (isFlag(a) && !signalSeen) { signalSeen = true; continue; }
    targets.push(a);
  }
  if (targets.includes('-1')) return { category: 'stop', sentence: 'Stop ALL your programs' };
  const groups = targets.filter((t) => /^-\d{1,9}$/.test(t));
  const pids = targets.filter((t) => /^\d{1,9}$/.test(t)).map(Number);
  if (groups.length > 0) {
    return { category: 'stop', sentence: `Stop a whole group of programs (group ${groups[0].slice(1)})${andMore(groups.length + pids.length - 1)}` };
  }
  if (pids.length === 0 && targets.some((t) => /^%\d*$/.test(t))) return { category: 'stop', sentence: 'Stop a background job in its own shell' };
  if (pids.length === 0) return { category: 'stop', sentence: 'Stop a running program' };
  if (pids.length > 1) return { category: 'stop', sentence: `Stop ${pids.length} running programs (PIDs ${pids.slice(0, 4).join(', ')}${pids.length > 4 ? ', …' : ''})` };
  const pid = pids[0];
  const facts = procFacts(pid, ctx);
  if (!facts) return { category: 'stop', sentence: `Stop a running program (PID ${pid})` };
  const detail = [facts.name ?? `PID ${pid}`, facts.cwd ? `in ${facts.cwd}` : null].filter(Boolean).join(', ');
  if (facts.startedByAgent && facts.age) return { category: 'stop', sentence: `Stop a program it started ${facts.age} ago (${detail})` };
  if (facts.startedByAgent) return { category: 'stop', sentence: `Stop a program it started (${detail})` };
  return { category: 'stop', sentence: `Stop a running program (${detail}${facts.name ? `, PID ${pid}` : ''}${facts.age ? `, running for ${facts.age}` : ''})` };
}

function describeStop(prog: string, args: string[], ctx: ShellContext): Described | null {
  if (prog === 'kill') return describeKill(args, ctx);
  if (prog === 'pkill' || prog === 'killall') {
    const full = args.some((a) => a === '-f' || a === '--full');
    const names = operands(prog, args);
    if (names.length === 0) return { category: 'stop', sentence: 'Stop running programs by name' };
    const shown = quoted(names[names.length - 1], 48);
    if (full) return { category: 'stop', sentence: `Stop every program whose command line matches: ${shown}` };
    return { category: 'stop', sentence: `Stop every program named ${shown}` };
  }
  if (prog === 'systemctl' || prog === 'service' || prog === 'launchctl') {
    const pos = operands(prog, args);
    const [verb, unit] = prog === 'service' ? [pos[1], pos[0]] : [pos[0], pos[1]];
    const name = unit ? quoted(unit, 48) : 'a service';
    switch (verb) {
      case 'stop': case 'kill': case 'unload': case 'bootout': return { category: 'stop', sentence: `Stop the service: ${name}` };
      case 'disable': return { category: 'stop', sentence: `Stop the service from starting at boot: ${name}` };
      case 'mask': return { category: 'stop', sentence: `Block the service from running at all: ${name}` };
      case 'restart': case 'reload': case 'try-restart': return { category: 'stop', sentence: `Restart the service: ${name}` };
      default: {
        const v = verb && SERVICE_VERBS.has(verb) ? verb : null;
        return { category: 'system', sentence: v ? `Change a system service: ${name} (${prog} ${v})` : `Change a system service (${prog})` };
      }
    }
  }
  return null;
}

function describeSegment(seg: Segment, ctx: ShellContext): (Described & { sudo: boolean; seg: Segment }) | null {
  const u = unwrap(seg);
  const base = describeProgram(u.prog, u.argv0, u.args, seg, ctx);
  if (!base) return null;
  return { ...base, sentence: u.sudo ? `${base.sentence}, as administrator (sudo)` : base.sentence, sudo: u.sudo, seg };
}

function describeProgram(prog: string, argv0: string, args: string[], seg: Segment, ctx: ShellContext): Described | null {
  if (!prog) {
    return seg.writes.length > 0 ? { category: 'write', sentence: pathPhrase('Write to', seg.writes) } : null;
  }
  if (!isTrustedProgram(argv0)) {
    // Not the system's own program, whatever it is called (#648 r2 S4).
    const dir = dirname(argv0);
    const where = dir === '.' ? 'this folder' : quoted(dir, 40);
    return { category: 'script', sentence: `Run a program from ${where}: ${quoted(argv0)}` };
  }
  const pos = operands(prog, args);
  if (READERS.has(prog)) {
    // `cat SRC > DST` copies SRC: the card names the source, not just the
    // harmless-looking destination (#648 r2 S3).
    if (seg.writes.length > 0 && pos.length > 0 && prog !== 'source' && prog !== '.') {
      return { category: 'move', sentence: copyPhrase(pos, seg.writes[seg.writes.length - 1]) };
    }
    if (seg.writes.length > 0) return { category: 'write', sentence: pathPhrase('Write to', seg.writes) };
    if (pos.length === 0) return { category: 'read', sentence: `Read input (${prog})` };
    return { category: 'read', sentence: pathPhrase(prog === 'source' || prog === '.' ? 'Load' : 'Read', pos) };
  }
  if (SEARCHERS.has(prog)) {
    // With `-e PATTERN` / `-f FILE` the pattern is not an operand.
    const patternByFlag = args.some((a) => /^(?:-[ef]|--regexp|--file)(?:=.*)?$/.test(a));
    const files = patternByFlag ? pos : pos.slice(1);
    return files.length === 0
      ? { category: 'read', sentence: `Search inside files (${prog})` }
      : { category: 'read', sentence: pathPhrase('Search inside', files) };
  }
  if (['rm', 'unlink', 'rmdir', 'shred', 'trash', 'srm'].includes(prog)) {
    const recursive = prog === 'rmdir' || args.some((a) => /^-[A-Za-z]*[rR][A-Za-z]*$/.test(a) || a === '--recursive');
    if (pos.length === 0) return { category: 'delete', sentence: 'Delete files' };
    const target = quoted(mostSensitive(pos));
    if (pos.length > 1) {
      return { category: 'delete', sentence: `${recursive ? 'Delete folders and everything in them' : 'Delete files'}: ${target}${andMore(pos.length - 1)}` };
    }
    return { category: 'delete', sentence: recursive ? `Delete a folder and everything in it: ${target}` : `Delete a file: ${target}` };
  }
  if (prog === 'find') {
    const deletes = args.includes('-delete')
      || args.some((a, i) => (a === '-exec' || a === '-execdir') && /^(?:rm|shred|unlink)$/.test(basename(args[i + 1] ?? '')));
    const root = pos[0] && !pos[0].startsWith('(') ? quoted(pos[0]) : null;
    if (deletes) return { category: 'delete', sentence: `Delete the files it finds under: ${root ?? 'the current folder'}` };
    return { category: 'read', sentence: root ? `Search for files under: ${root}` : 'Search for files' };
  }
  if (prog === 'mv' || prog === 'cp' || prog === 'install' || prog === 'ln') {
    if (pos.length === 0) return { category: 'move', sentence: `Move or copy files (${prog})` };
    const dst = pos.length > 1 ? pos[pos.length - 1] : null;
    const sources = dst ? pos.slice(0, -1) : pos;
    const src = mostSensitive(sources);
    const verb = prog === 'mv' ? 'Move' : prog === 'ln' ? 'Link' : 'Copy';
    const loc = locationOf(src);
    const what = sources.length > 1 ? `${sources.length} files, including one${loc}` : `a file${loc}`;
    return {
      category: 'move',
      sentence: dst ? `${verb} ${what}: ${quoted(src, 40)} → ${quoted(dst, 40)}` : `${verb} ${what}: ${quoted(src)}`,
    };
  }
  if (['chmod', 'chown', 'chgrp', 'setfacl', 'chattr'].includes(prog)) {
    const recursive = args.some((a) => /^-[A-Za-z]*R[A-Za-z]*$/.test(a) || a === '--recursive');
    const paths = pos.length > 1 ? pos.slice(1) : pos;
    if (paths.length === 0) return { category: 'perms', sentence: `Change file permissions (${prog})` };
    const target = mostSensitive(paths);
    const what = recursive ? 'a folder and everything in it' : 'a file';
    return { category: 'perms', sentence: `Change who can access ${what}${locationOf(target)}: ${quoted(target)}${andMore(paths.length - 1)}` };
  }
  const sedInPlace = prog === 'sed' && args.some((a) => /^-[A-Za-z]*i/.test(a) || a.startsWith('--in-place'));
  if (prog === 'tee' || prog === 'touch' || prog === 'truncate' || prog === 'mkdir' || EDITORS.has(prog) || sedInPlace) {
    const files = prog === 'sed' ? pos.slice(1) : pos;
    if (files.length === 0) return { category: 'write', sentence: `Change a file (${prog})` };
    if (prog === 'truncate') return { category: 'write', sentence: pathPhrase('Empty', files) };
    if (prog === 'mkdir') return { category: 'write', sentence: `Create a folder: ${quoted(files[0])}${andMore(files.length - 1)}` };
    return { category: 'write', sentence: pathPhrase(EDITORS.has(prog) ? 'Edit' : 'Change', files) };
  }
  if (seg.writes.length > 0 && (prog === 'echo' || prog === 'printf')) {
    return { category: 'write', sentence: pathPhrase('Write to', seg.writes) };
  }
  if (prog === 'git') return describeGit(args, ctx);
  const net = describeNetworkTool(prog, args, ctx);
  if (net) return net;
  const install = describeInstall(prog, args);
  if (install) return install;
  if (RUNNERS.has(prog)) {
    return { category: 'install', sentence: pos[0] ? `Download and run a package: ${quoted(pos[0], 40)} (${prog})` : `Download and run a package (${prog})` };
  }
  const stop = describeStop(prog, args, ctx);
  if (stop) return stop;
  if (prog === 'crontab') {
    return args.includes('-r')
      ? { category: 'scheduler', sentence: 'Remove all of its scheduled jobs (crontab -r)' }
      : { category: 'scheduler', sentence: 'Change scheduled jobs (crontab)' };
  }
  if (['at', 'batch', 'systemd-run', 'schtasks'].includes(prog)) {
    return { category: 'scheduler', sentence: `Schedule a job to run later (${prog})` };
  }
  if (['iptables', 'ip6tables', 'ufw', 'nft', 'firewall-cmd', 'netplan', 'pfctl'].includes(prog)) {
    return { category: 'firewall', sentence: `Change firewall or network rules (${prog})` };
  }
  // Disk tools are recognised by the guard's own disk signals plus the device
  // they name, rather than by a second list of program names here.
  const outFile = args.find((a) => a.startsWith('of='))?.slice(3);
  const device = pos.find((p) => p.startsWith('/dev/')) ?? (outFile?.startsWith('/dev/') ? outFile : undefined);
  if (device && ctx.signals.some((s) => DISK_SIGNAL_RE.test(s))) {
    const shownProg = safeProgram(prog);
    return { category: 'disk', sentence: `Change or erase a disk: ${quoted(device)}${shownProg ? ` (${shownProg})` : ''}` };
  }
  if (outFile) return { category: 'write', sentence: `Write raw data over: ${quoted(outFile)}` };
  if (['reboot', 'shutdown', 'halt', 'poweroff'].includes(prog)) {
    return { category: 'system', sentence: 'Restart or shut down this machine' };
  }
  if (prog === 'history' && args.includes('-c')) return { category: 'write', sentence: 'Clear the shell history' };
  if (INTERPRETERS.has(prog)) {
    if (args.some((a) => /^-[A-Za-z]*[ce]$/.test(a) || a === '--eval')) {
      return { category: 'script', sentence: `Run inline ${prog} code (details withheld: could not summarise safely)` };
    }
    if (args.includes('-m') && pos[0]) return { category: 'script', sentence: `Run the ${quoted(pos[0], 40)} module (${prog})` };
    const scriptArg = pos[0];
    return { category: 'script', sentence: scriptArg ? `Run a script: ${quoted(scriptArg)} (${prog})` : `Run ${prog} (details withheld: could not summarise safely)` };
  }
  const shown = safeProgram(prog);
  if (!shown) return null;
  // Only an allowlisted subcommand word of a known tool (#648 r2 S8): the
  // first argument of anything else is free-form and may be a secret.
  const sub = args[0] && SUBCOMMANDS[prog]?.has(args[0]) ? args[0] : null;
  return { category: 'other', sentence: `Run ${shown}${sub ? ` ${sub}` : ''} (other details not shown)` };
}

/** Which kind of step each signal is about: used only inside the one
 *  pipeline the guard itself pins a signal to (see `describeShell`). */
const SIGNAL_CATEGORIES: Array<[RegExp, Category[]]> = [
  [/^(?:touch-|credential-access|modify-shell-startup|disable-action-guard)/, ['read', 'write', 'delete', 'move', 'perms', 'script']],
  [/egress|exfil|pipe-download/, ['network']],
  [/^(?:stop-process|service-restart)/, ['stop']],
  [/install|registry-code-exec/, ['install']],
  [/^(?:git-|force-push)/, ['git', 'network']],
  [/delete|truncate|wipe-history/, ['delete', 'write']],
  [/perms|change-permissions/, ['perms']],
  [/scheduler|persistence/, ['scheduler']],
  [/firewall/, ['firewall']],
  [DISK_SIGNAL_RE, ['disk', 'write']],
  [/move-or-copy/, ['move']],
];

const SEVERITY_RANK: Record<string, number> = { benign: 0, sensitive: 1, dangerous: 2, catastrophic: 3 };
/** Steps (and pipelines) the guard is re-run on to find the risky one. */
const MAX_ATTRIBUTED = 32;

/** The guard's own verdict on one piece of the command. Pure and
 *  synchronous; any failure reads as "tripped nothing". */
function guardOn(text: string): { signals: readonly string[]; rank: number } {
  try {
    const v = evaluateToolCall('Bash', { command: text });
    return { signals: Array.isArray(v.signals) ? v.signals : [], rank: SEVERITY_RANK[v.severity] ?? 0 };
  } catch {
    return { signals: [], rank: 0 };
  }
}

/** The index of the piece the guard rates most dangerous among those that
 *  trip one of `wanted`, or -1. Ties go to more matched signals, then first. */
function riskiest(pieces: string[], wanted: ReadonlySet<string>): number {
  let best = -1;
  let bestRank = -1;
  let bestHits = 0;
  pieces.slice(0, MAX_ATTRIBUTED).forEach((text, i) => {
    const own = guardOn(text);
    const hits = own.signals.filter((s) => wanted.has(s)).length;
    if (hits === 0) return;
    if (own.rank > bestRank || (own.rank === bestRank && hits > bestHits)) {
      best = i;
      bestRank = own.rank;
      bestHits = hits;
    }
  });
  return best;
}

/**
 * Line 1 for a shell command. A multi-step command is described by the step
 * that tripped the guard, never simply the first one (#648 r2 S3): the guard
 * is re-run on each step, and the most dangerous step carrying one of the
 * verdict's signals is named. A signal that only a whole pipeline trips (a
 * download piped into an interpreter) is pinned to that pipeline, and the
 * step is chosen inside it. When nothing can be pinned, the card says so
 * instead of guessing.
 */
function describeShell(command: string, ctx: ShellContext): string {
  const { segments, pipelines, truncated } = parseShell(command);
  const tooLong = truncated ? ` ${COMMAND_TOO_LONG}` : '';
  if (segments.length === 0) return `${UNSUMMARISABLE_SHELL}${tooLong}`;
  let chosen: ReturnType<typeof describeSegment> = null;
  if (segments.length === 1) {
    chosen = describeSegment(segments[0], ctx);
  } else {
    const wanted = new Set(ctx.signals);
    const step = riskiest(segments.map((s) => s.raw), wanted);
    if (step !== -1) {
      chosen = describeSegment(segments[step], ctx);
    } else {
      const pipe = riskiest(pipelines, wanted);
      const inPipe = segments.filter((s) => s.pipeline === pipe).map((s) => describeSegment(s, ctx));
      for (const signal of ctx.signals) {
        const kinds = SIGNAL_CATEGORIES.find(([re]) => re.test(signal))?.[1];
        chosen = kinds ? inPipe.find((d) => d && kinds.includes(d.category)) ?? null : null;
        if (chosen) break;
      }
    }
    if (!chosen) return `${UNATTRIBUTED_SHELL}${tooLong}`;
  }
  if (!chosen) return `${UNSUMMARISABLE_SHELL}${tooLong}`;
  const others = segments.length - 1;
  const more = others > 0 ? ` (+${others} more step${others === 1 ? '' : 's'})` : '';
  const opaque = segments.some((s) => s.opaque) ? ' (part of it is built as it runs)' : '';
  return `${chosen.sentence}${more}${opaque}${tooLong}`;
}

// ── Non-shell tools ──────────────────────────────────────────────────────────

const NATIVE_PROCESS_ACTIONS: Record<string, string> = {
  list: 'See what commands are running',
  poll: 'Check a running command',
  log: "Read a running command's output",
  kill: 'Stop a running background command',
  write: 'Type into a running command',
  'send-keys': 'Press keys in a running command',
  submit: 'Submit input to a running command',
  paste: 'Paste text into a running command',
  clear: "Clear a running command's input",
  remove: "Remove a running command's session",
};

function safeToolLabel(tool: string): string {
  const t = String(tool ?? '').trim();
  return /^[A-Za-z][A-Za-z0-9_.:-]{0,47}$/.test(t) && safeTarget(t, 48) === t ? t : 'a tool';
}

export interface ApprovalCardActionInput {
  tool: string;
  input: unknown;
  signals: readonly string[];
  /** The tool call's working directory, for relative paths and git remotes. */
  cwd?: string;
  /** The agent's own process — a PID descended from it is one it started. */
  agentPid?: number;
  /** Tests only: a fake /proc. */
  procRoot?: string;
}

/** Line 1: what it wants to do, in plain English, naming the target. */
export function describeAction(a: ApprovalCardActionInput): string {
  const args = (a.input && typeof a.input === 'object' && !Array.isArray(a.input) ? a.input : {}) as Record<string, unknown>;
  const signals = Array.isArray(a.signals) ? a.signals.map(String) : [];
  const ctx: ShellContext = { signals, cwd: a.cwd, agentPid: a.agentPid, procRoot: a.procRoot };
  const raw = String(a.tool ?? '');
  try {
    const n = normaliseToolName(raw);
    if (/^(?:killshell|killbash|taskstop)$/.test(n)) return 'Stop a background command it started';
    if (raw.trim().toLowerCase() === 'process') {
      const verb = typeof args.action === 'string' ? args.action.trim().toLowerCase().replace(/_/g, '-') : '';
      return NATIVE_PROCESS_ACTIONS[verb] ?? 'Control a running command';
    }
    if (n === 'websearch' || n === 'web_search') return 'Search the web';
    if (n === 'task' || n === 'sessions_spawn' || n === 'agent') return 'Start a helper agent';
    if (n === 'apply_patch') return 'Apply a patch to files';
    const family = classifyFamily(raw);
    if (family === 'exec') {
      const command = extractCommand(args);
      return command ? describeShell(command, ctx) : UNSUMMARISABLE_SHELL;
    }
    const path = extractPath(args);
    if (family === 'read') {
      if (/^(?:glob|grep|search|find|ls|list|list_files)$/.test(n)) return path ? `Search files in: ${quoted(path)}` : 'Search files in the current folder';
      return path ? pathPhrase('Read', [path]) : `Read a file (${safeToolLabel(raw)})`;
    }
    if (family === 'write') {
      if (!path) return `Change files (${safeToolLabel(raw)})`;
      return pathPhrase(/^(?:write|create|write_file)$/.test(n) ? 'Write' : 'Change', [path]);
    }
    if (family === 'delete') return path ? pathPhrase('Delete', [path]) : `Delete something (${safeToolLabel(raw)})`;
    if (family === 'network') {
      const url = extractUrl(args, raw);
      const first = url.split(/[\s,]+/)[0] ?? '';
      const host = first ? (safeHost(first) ?? safeHost(`https://${first.replace(/^[^@]*@/, '')}`)) : null;
      if (/fetch|curl|wget|http|request|download/.test(n)) return host ? `Fetch a web page from ${host}` : 'Fetch a web page';
      return host ? `Send data to ${host} (${safeToolLabel(raw)})` : `Send data off this machine (${safeToolLabel(raw)})`;
    }
    if (family === 'git') return `Change the git repository (${safeToolLabel(raw)})`;
    if (family === 'memory') return "Change the agent's memory";
  } catch {
    /* fall through to the honest line */
  }
  return `Use ${safeToolLabel(raw)} (details withheld: could not summarise safely)`;
}

// ── Line 3: who is asking ────────────────────────────────────────────────────

const CHANNEL_LABELS: Record<string, string> = {
  telegram: 'Telegram chat', whatsapp: 'WhatsApp chat', discord: 'Discord chat', slack: 'Slack chat',
  signal: 'Signal chat', imessage: 'iMessage chat', webchat: 'web chat', tui: 'terminal', cron: 'scheduled job',
  subagent: 'sub-agent', hook: 'webhook', main: 'main chat', heartbeat: 'heartbeat',
};

export interface ApprovalCardWhoInput {
  plane: 'claude-code' | 'openclaw';
  agentId?: string;
  /** Defaults to this machine's hostname. */
  host?: string;
  sessionId?: string;
}

function safeHostname(h: string | undefined): string {
  let name = h;
  if (name === undefined) {
    try { name = osHostname(); } catch { name = ''; }
  }
  // The box's own label, not its FQDN: CI and cloud hosts carry long
  // generated names (`<id>.local`, `<id>.internal`), and a host that ate the
  // whole line would push the session off the card.
  const short = String(name ?? '').trim().split('.')[0];
  return /^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$/.test(short) ? middleClip(short, 20) : 'this machine';
}

/** Line 3: agent, box and session. An OpenClaw session key carries chat ids,
 *  so it is shown as its kind plus a short digest, never verbatim. */
export function describeWho(w: ApprovalCardWhoInput): string {
  const host = safeHostname(w.host);
  const session = String(w.sessionId ?? '').trim();
  if (w.plane === 'claude-code') {
    const s = /^sc-[0-9a-f]{16}$/.test(session) ? ` · session ${session}` : '';
    return `Claude Code on ${host}${s}`;
  }
  const parts = session.split(':');
  const fromKey = parts[0] === 'agent' ? parts[1] : undefined;
  const id = [w.agentId, fromKey].find((v) => typeof v === 'string' && /^[A-Za-z0-9_.-]{1,32}$/.test(v));
  const agent = id ? `OpenClaw agent "${id}"` : 'OpenClaw agent';
  if (!session) return `${agent} on ${host}`;
  const kind = parts[0] === 'agent' ? parts[2] : undefined;
  const label = (kind && CHANNEL_LABELS[kind.toLowerCase()]) ?? 'session';
  const tag = createHash('sha256').update(session).digest('hex').slice(0, 8);
  return `${agent} on ${host} · ${label} #${tag}`;
}

// ── The card ────────────────────────────────────────────────────────────────

/** What a decision card carries in place of the values-free alert surface. */
export interface ApprovalCardSummary {
  /** Line 1 — the action, plain English, with a redactor-passed target. */
  action: string;
  /** Line 2 body — the plain-English reason (no `Why:` prefix). */
  reason: string;
  /** Line 3 body — agent, host and session (no `Who:` prefix). */
  who: string;
}

export interface ApprovalCardInput extends ApprovalCardActionInput, ApprovalCardWhoInput {}

export function buildApprovalCard(input: ApprovalCardInput): ApprovalCardSummary {
  return {
    action: describeAction(input),
    reason: describeSignals(input.signals),
    who: describeWho(input),
  };
}

/** One card line: every line break becomes a space and every invisible
 *  format character is shown as `<U+XXXX>` (#648 r2 S9) — the fields may have
 *  crossed a process boundary since they were built. */
function flattenCardText(text: unknown): string {
  return String(text ?? '')
    .replace(UNUSUAL_CHARS_ALL, (c) => (/[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/u.test(c)
      ? `<U+${(c.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')}>`
      : ' '))
    .replace(/\s+/g, ' ')
    .trim();
}

/** Trailing markers a clipped line always keeps (#648 r2 S5, S6). */
const TAIL_MARKERS = /(?:, as administrator \(sudo\)| \(\+\d+ more (?:steps?|reasons?)\)| \(part of it is built as it runs\)| \(command too long to summarise fully\)| and \d+ more)+$/;

/**
 * Fit a card line into `max` characters by cutting its MIDDLE (#648 r2 S6):
 * the head (the verb) and the tail (a file name, the session id) stay, and the
 * trailing markers — the privilege marker, the step and reason counts — are
 * never cut. When the markers alone exceed the room they still survive and
 * the line runs over rather than drop them.
 */
export function clipCardLine(text: unknown, max: number): string {
  const one = flattenCardText(text);
  if (one.length <= max) return one;
  const tail = TAIL_MARKERS.exec(one)?.[0] ?? '';
  const body = one.slice(0, one.length - tail.length);
  const room = Math.max(12, max - tail.length);
  if (body.length <= room) return `${body}${tail}`;
  const head = Math.ceil((room - 1) / 2);
  return `${body.slice(0, head)}…${body.slice(body.length - (room - 1 - head))}${tail}`;
}

function clipLine(text: string, max: number): string {
  return clipCardLine(text, max);
}

function expiryText(ms: number): string {
  const minutes = Math.round(ms / 60_000);
  return minutes >= 1 ? `${minutes} min` : `${Math.max(1, Math.round(ms / 1000))} s`;
}

/**
 * The card body, bounded per line so the reason and the buttons' meaning are
 * never the part a length cap cuts off. WHY and WHO are clipped first; the
 * action gets whatever is left of `budget` (OpenClaw caps a card description
 * at 256), up to 120. Each field is re-flattened here because it may have
 * crossed a process boundary.
 */
export function formatApprovalCardLines(
  card: ApprovalCardSummary,
  opts: { expiresInMs: number; decisions?: string; budget?: number; separatorLength?: number; actionPrefix?: string },
): string[] {
  const why = clipLine(`Why: ${card.reason}`, 64);
  // 72: room for a 20-character host plus the session id (`describeWho`).
  const who = clipLine(`Who: ${card.who}`, 72);
  const footer = `${opts.decisions ?? 'Allow once or deny'} · expires in ${expiryText(opts.expiresInMs)}`;
  const prefix = opts.actionPrefix ?? '';
  const used = why.length + who.length + footer.length + 3 * (opts.separatorLength ?? 1) + prefix.length;
  const room = Math.max(40, Math.min(120, (opts.budget ?? 256) - used));
  return [`${prefix}${clipLine(card.action, room)}`, why, who, footer];
}
