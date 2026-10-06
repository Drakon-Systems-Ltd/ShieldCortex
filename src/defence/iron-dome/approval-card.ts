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
 * The characters that never reach a card, as character-class bodies. ONE
 * list for both card planes (#648 r3 R4): plugins/openclaw/interceptor.ts
 * carries the same strings, because the plugin is built with its own rootDir
 * and cannot import from src/ (TS6059); approval-card-648-r3-chars.test.ts
 * fails if the two copies differ by a single character.
 *
 * Line breaks (shown as a space): C0 and C1 controls, NEL U+0085 included,
 * and the Unicode line/paragraph separators (#648 r2 S9).
 */
export const CARD_LINE_BREAK_CLASS = '\\u0000-\\u001f\\u007f-\\u009f\\u2028\\u2029';
/**
 * Hidden and look-alike characters (shown as `<U+XXXX>`): soft hyphen, Arabic
 * letter mark, Hangul and Mongolian fillers, zero-width marks, bidi
 * embeddings, overrides and isolates, the U+2060-206F invisible operators,
 * variation selectors, tag characters, the BOM, and quotes that look like `"`
 * (#648 r2 S9, r3 R4).
 */
export const CARD_HIDDEN_CHAR_CLASS = [
  '\\u00ad', '\\u061c', '\\u115f', '\\u1160', '\\u17b4', '\\u17b5', '\\u180e', '\\u200b-\\u200f', '\\u202a-\\u202e', '\\u2060-\\u206f',
  '\\u3164', '\\ufe00-\\ufe0f', '\\ufeff', '\\uffa0', '\\u{e0000}-\\u{e007f}', '\\u{e0100}-\\u{e01ef}',
  '\\u201c-\\u201f', '\\u2033', '\\u301d-\\u301f', '\\uff02',
].join('');
const UNUSUAL_CHARS = new RegExp(`[${CARD_LINE_BREAK_CLASS}${CARD_HIDDEN_CHAR_CLASS}]`, 'u');
const CARD_LINE_BREAKS_ALL = new RegExp(`[${CARD_LINE_BREAK_CLASS}]`, 'gu');
const CARD_HIDDEN_ALL = new RegExp(`[${CARD_HIDDEN_CHAR_CLASS}]`, 'gu');
const codePointLabel = (c: string) => `<U+${(c.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')}>`;

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
/** A command of more steps than this is not summarised (#648 r3 R1). */
const MAX_STEPS = 64;

/**
 * The WHAT for any command outside the understood subset (#648 r3 R1). The
 * card is correct or generic, never confidently wrong: the WHY line still says
 * why the call was stopped, and the WHO line is unchanged.
 */
export const GENERIC_SHELL = "Run a complex shell command (couldn't summarise it safely)";

/** Every way a command can fall outside the understood subset. */
export type ShellDoubt =
  | 'ansi-c-quoting'
  | 'command-substitution'
  | 'process-substitution'
  | 'variable-expansion'
  | 'brace-expansion'
  | 'heredoc-or-herestring'
  | 'eval-or-source'
  | 'shell-syntax'
  | 'unsupported-redirect'
  | 'exec-wrapper'
  | 'inline-code'
  | 'env-prefix'
  | 'git-repo-option'
  | 'git-config-override'
  | 'remote-shell'
  | 'unknown-option'
  | 'unknown-writer'
  | 'hidden-write'
  | 'too-many-steps';

/**
 * #648 r3 R1 — what the shell summariser does NOT understand, as ONE list.
 *
 * A heuristic bash summariser is an arms race: every round of review found a
 * new way to make it name a harmless decoy. So instead of patching each one,
 * the summariser describes only a small understood subset, and anything on
 * this list makes the WHAT generic (`GENERIC_SHELL`). Git repository options
 * are the one exception: they can only falsify the remote's host, so they
 * drop the host and keep the rest. approval-card-648-r3-gate.test.ts holds a
 * sample for every id and fails if one is missing.
 */
export const OUTSIDE_UNDERSTOOD_SUBSET: Readonly<Record<ShellDoubt, { effect: 'generic' | 'drop-git-host'; what: string }>> = Object.freeze({
  'ansi-c-quoting': { effect: 'generic', what: "ANSI-C and locale quoting: $'…' and $\"…\"" },
  'command-substitution': { effect: 'generic', what: '$(…), $((…)) and backticks' },
  'process-substitution': { effect: 'generic', what: '<(…) and >(…)' },
  'variable-expansion': { effect: 'generic', what: '$VAR, ${…} and $1/$@/$! (only a leading $HOME is understood)' },
  'brace-expansion': { effect: 'generic', what: '{a,b} and {1..9}' },
  'heredoc-or-herestring': { effect: 'generic', what: '<<EOF heredocs and <<< here-strings' },
  'eval-or-source': { effect: 'generic', what: 'eval, source and ., and builtins that run stored code (alias, trap, hash, enable)' },
  'shell-syntax': { effect: 'generic', what: 'subshells, groups, functions, loops, conditionals, negation, unterminated quotes' },
  'unsupported-redirect': { effect: 'generic', what: 'a redirect with no target' },
  'exec-wrapper': {
    effect: 'generic',
    what: 'bash/sh -c, su -c, pkexec, env -S, xargs, find -exec/-execdir/-ok running anything but rm/shred/unlink, sudo -s/-i/-e, and other programs that run a command',
  },
  'inline-code': {
    effect: 'generic',
    what: 'an interpreter running inline code (-c, -e, -r, -p, -E, -Command, eval), reading code from stdin, or given an operand that is not a script path',
  },
  'env-prefix': { effect: 'generic', what: 'PATH, LD_*, DYLD_*, BASH_ENV, ENV, NODE_OPTIONS, PYTHONPATH, IFS and similar variables set for or before a command' },
  'git-repo-option': { effect: 'drop-git-host', what: 'git -C, --git-dir, --work-tree, GIT_DIR and the like, push --repo, or an earlier cd in the same command' },
  'git-config-override': { effect: 'generic', what: 'git -c, --config-env, --exec-path=, --upload-pack, --receive-pack, clone --config or --template' },
  'remote-shell': { effect: 'generic', what: "a command run elsewhere: ssh host 'cmd', nc -e, socat EXEC:, rsync -e, scp -S, systemctl -H" },
  'unknown-option': { effect: 'generic', what: 'an option the flag tables do not know (a long option may take a separate value)' },
  'unknown-writer': { effect: 'generic', what: 'a program that writes a file the card cannot name (time -o, find -fprint, sed w, less -o, curl -J)' },
  'hidden-write': { effect: 'generic', what: 'a write to a sensitive path that the summary does not name' },
  'too-many-steps': { effect: 'generic', what: `more than ${MAX_STEPS} steps` },
});

/** A table lookup that ignores the prototype (#648 r3 R5): `constructor`,
 *  `toString` and `__proto__` are words a command can contain. */
function own<T>(table: Readonly<Record<string, T>>, key: string): T | undefined {
  return Object.hasOwn(table, key) ? table[key] : undefined;
}

interface Segment {
  words: string[];
  /** Files named by `>`, `>>`, `>|`, `&>`, `<>` and `>& file` in this segment. */
  writes: string[];
  /** Files named by `<` in this segment. */
  reads: string[];
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
  /** Constructs met that the parser does not model (#648 r3 R1). */
  doubts: Set<ShellDoubt>;
}

const clipWord = (w: string) => (w.length > MAX_WORD_CHARS ? `${w.slice(0, 128)}…${w.slice(-128)}` : w);
const LEADING_HOME = /^(?:\$HOME|\$\{HOME\})(?![A-Za-z0-9_])/;

/**
 * Split a command line into simple commands (on unquoted `;`, `&`, `|`,
 * newlines) of decoded words, the way bash tokenises them: only space and tab
 * separate words, quotes are honoured, `#` starts a comment. Nothing is
 * expanded. Every construct the parser does not model is recorded as a doubt
 * AT THE POINT it is met — up to there the parse matches bash, and a single
 * doubt makes the card generic, so a desync after it cannot reach a card.
 */
function parseShell(command: string): ParsedShell {
  const text = command.slice(0, MAX_COMMAND_CHARS);
  const doubts = new Set<ShellDoubt>();
  const segments: Segment[] = [];
  const pipelines: string[] = [];
  let words: string[] = [];
  let writes: string[] = [];
  let reads: string[] = [];
  let word = '';
  // The word as typed with its quoted and escaped characters masked out:
  // brace expansion and fd numbers only count when they are unquoted.
  let mask = '';
  let inWord = false;
  let redirect: 'write' | 'read' | 'dup' | 'dup-in' | null = null;
  let segStart = 0;
  let pipeStart = 0;
  let pipeline = 0;
  const add = (s: string, quotedText: boolean) => {
    word += s;
    mask += quotedText ? '_'.repeat(s.length) : s;
    inWord = true;
  };
  const endWord = () => {
    if (!inWord) return;
    if (/\{[^{}]*(?:,|\.\.)[^{}]*\}/.test(mask)) doubts.add('brace-expansion');
    const w = clipWord(word);
    if (redirect === 'write') writes.push(w);
    else if (redirect === 'read') reads.push(w);
    else if (redirect === 'dup') { if (!/^(?:\d+-?|-)$/.test(word)) writes.push(w); }
    else if (redirect !== 'dup-in') words.push(w);
    redirect = null;
    word = '';
    mask = '';
    inWord = false;
  };
  const endSegment = (end: number) => {
    endWord();
    if (redirect) doubts.add('unsupported-redirect');
    redirect = null;
    if (words.length > 0 || writes.length > 0 || reads.length > 0) {
      segments.push({ words, writes, reads, raw: text.slice(segStart, end).trim(), pipeline });
    }
    words = [];
    writes = [];
    reads = [];
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
  /** `$` at `i`: what does it expand? Only a leading `$HOME` is understood. */
  const dollar = (i: number, inDouble: boolean, atWordStart: boolean) => {
    const next = text[i + 1] ?? '';
    if (next === '(') doubts.add('command-substitution');
    else if (!inDouble && (next === "'" || next === '"')) doubts.add('ansi-c-quoting');
    else if (next === '{' || /[A-Za-z0-9_@*#?$!-]/.test(next)) {
      if (!(atWordStart && LEADING_HOME.test(text.slice(i, i + 8)))) doubts.add('variable-expansion');
    }
  };
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (ch === "'") {
      const close = text.indexOf("'", i + 1);
      if (close === -1) doubts.add('shell-syntax');
      const end = close === -1 ? text.length : close;
      add(text.slice(i + 1, end), true);
      i = end;
      continue;
    }
    if (ch === '"') {
      let part = '';
      let j = i + 1;
      for (; j < text.length && text[j] !== '"'; j += 1) {
        const c = text[j];
        if (c === '\\' && j + 1 < text.length && '"\\$`\n'.includes(text[j + 1])) {
          if (text[j + 1] !== '\n') part += text[j + 1];
          j += 1;
          continue;
        }
        if (c === '`') doubts.add('command-substitution');
        if (c === '$') dollar(j, true, !inWord && part === '');
        part += c;
      }
      if (j >= text.length) doubts.add('shell-syntax');
      add(part, true);
      i = j;
      continue;
    }
    if (ch === '\\') {
      if (i + 1 < text.length && text[i + 1] !== '\n') add(text[i + 1], true);
      i += 1;
      continue;
    }
    if (ch === '`') {
      doubts.add('command-substitution');
      add(ch, false);
      continue;
    }
    if (ch === '$') {
      dollar(i, false, !inWord);
      add(ch, false);
      continue;
    }
    if (ch === '#' && !inWord) {
      const nl = text.indexOf('\n', i);
      i = (nl === -1 ? text.length : nl) - 1;
      continue;
    }
    if (ch === ' ' || ch === '\t') {
      endWord();
      continue;
    }
    if (ch === '(' || ch === ')') {
      doubts.add('shell-syntax');
      endWord();
      continue;
    }
    if (ch === '\n' || ch === ';' || ch === '|' || ch === '&') {
      if (ch === '&' && text[i + 1] === '>') {
        // `&>` / `&>>`: stdout and stderr to a file.
        endWord();
        if (redirect) doubts.add('unsupported-redirect');
        i += text[i + 2] === '>' ? 2 : 1;
        redirect = 'write';
        continue;
      }
      if (ch === '|' && text[i + 1] === '&') {
        // `|&` pipes stderr too: still one pipeline.
        endSegment(i);
        i += 1;
        continue;
      }
      // A single `|` joins a pipeline; `||`, `;`, `&`, `&&` and newlines end one.
      if (ch === '|' && text[i + 1] !== '|' && text[i - 1] !== '|') endSegment(i);
      else endPipeline(i);
      continue;
    }
    if (ch === '>' || ch === '<') {
      // A bare fd number (`2>`) or `{fd}` before the operator is not a word.
      if (inWord && /^(?:\d+|\{[A-Za-z_][A-Za-z0-9_]*\})$/.test(mask)) {
        word = '';
        mask = '';
        inWord = false;
      } else {
        endWord();
      }
      if (redirect) doubts.add('unsupported-redirect');
      const next = text[i + 1];
      if (next === '(') {
        doubts.add('process-substitution');
        redirect = null;
        continue;
      }
      if (ch === '<') {
        if (next === '<') {
          doubts.add('heredoc-or-herestring');
          i += text[i + 2] === '<' ? 2 : 1;
          redirect = 'read';
        } else if (next === '>') {
          i += 1;
          redirect = 'write';
        } else if (next === '&') {
          i += 1;
          redirect = 'dup-in';
        } else {
          redirect = 'read';
        }
        continue;
      }
      if (next === '>' || next === '|') {
        i += 1;
        redirect = 'write';
      } else if (next === '&') {
        i += 1;
        redirect = 'dup';
      } else {
        redirect = 'write';
      }
      continue;
    }
    add(ch, false);
  }
  endPipeline(text.length);
  return { segments, pipelines, truncated: command.length > MAX_COMMAND_CHARS, doubts };
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

const isFlag = (a: string) => a.startsWith('-') && a !== '-';
const sw = (s: string): readonly string[] => s.split(/\s+/).filter(Boolean);

/**
 * What a program's options are, so its operands can be told from option
 * values (#648 r2 S7) and an option it does not know can make the card
 * generic (#648 r3 R1). `value`: short letters that take a value (attached or
 * the next word). `valueLong`/`boolLong`: long options. `risky`: options that
 * put the call outside the understood subset, with the doubt they raise.
 */
interface ProgramOptions {
  value?: string;
  valueLong?: readonly string[];
  boolLong?: readonly string[];
  /** Long options that take TWO values (`jq --arg name value`). */
  pairLong?: readonly string[];
  /** Single-dash words that take a value (`xxd -cols 8`). */
  valueWords?: readonly string[];
  risky?: ReadonlyArray<readonly [RegExp, ShellDoubt]>;
}

/** Switches every GNU-style tool shares. */
const COMMON_SWITCHES = new Set(sw('help version verbose quiet silent force recursive dry-run interactive no-clobber debug null zero zero-terminated'));

const GREP_OPTIONS: ProgramOptions = {
  value: 'efmABCdD',
  valueLong: sw('regexp file max-count after-context before-context context include exclude exclude-dir exclude-from label binary-files devices directories group-separator'),
  boolLong: sw(`ignore-case no-ignore-case invert-match files-with-matches files-without-match count line-number recursive dereference-recursive
    fixed-strings extended-regexp perl-regexp basic-regexp word-regexp line-regexp with-filename no-filename only-matching no-messages text
    null-data byte-offset line-buffered color colour initial-tab no-group-separator`),
};
const CHMOD_OPTIONS: ProgramOptions = {
  valueLong: sw('reference from'),
  boolLong: sw('changes dereference no-dereference preserve-root no-preserve-root'),
};
const SUM_OPTIONS: ProgramOptions = { boolLong: sw('check binary text status strict tag ignore-missing warn') };
const SSH_OPTIONS: ProgramOptions = { value: 'BbcDEeFIiJLlmOopQRSWw' };
const NC_OPTIONS: ProgramOptions = {
  value: 'IiMmOPpqsTVWwXxdo',
  valueLong: sw('proxy proxy-type proxy-auth source-port source wait idle-timeout max-conns'),
  boolLong: sw('listen keep-open udp nodns ssl crlf recv-only send-only no-shutdown'),
};
const JS_INSTALL_OPTIONS: ProgramOptions = {
  value: 'w',
  valueLong: sw('registry prefix cache tag workspace omit include install-strategy filter'),
  boolLong: sw(`save save-dev save-exact save-optional save-peer save-prod no-save global legacy-peer-deps ignore-scripts no-audit no-fund
    production prefer-offline frozen-lockfile dev exact pure-lockfile no-package-lock strict-peer-deps workspaces include-workspace-root
    no-optional prefer-dedupe`),
};
const PY_INSTALL_OPTIONS: ProgramOptions = {
  value: 'ritce',
  valueLong: sw('index-url extra-index-url target root prefix constraint requirement editable find-links trusted-host python only-binary no-binary platform'),
  boolLong: sw('upgrade user break-system-packages no-deps no-cache-dir force-reinstall pre no-build-isolation require-hashes system no-index ignore-installed'),
};
const BAT_OPTIONS: ProgramOptions = {
  value: 'lHrm',
  valueLong: sw('language highlight-line line-range map-syntax style paging theme tabs wrap color decorations italic-text terminal-width file-name diff-context'),
  boolLong: sw('plain number show-all list-themes list-languages no-config diff'),
};
const COPY_OPTIONS: ProgramOptions = {
  value: 'St',
  valueLong: sw('suffix target-directory'),
  boolLong: sw(`archive update backup no-target-directory preserve no-preserve parents link symbolic-link dereference no-dereference one-file-system
    strip-trailing-slashes sparse reflink remove-destination attributes-only copy-contents exchange no-copy`),
};

const HTTP_OPTIONS: ProgramOptions = { value: 'oa', valueLong: sw('output auth auth-type print pretty style verify cert cert-key timeout proxy'), boolLong: sw('follow check-status ignore-stdin offline json form multipart headers body all'), risky: [[/^(?:-d|--download|--continue|--session|--session-read-only)$/, 'unknown-writer']] };
const NPX_OPTIONS: ProgramOptions = { value: 'p', valueLong: sw('package'), boolLong: sw('yes no ignore-existing'), risky: [[/^(?:-c|--call)$/, 'exec-wrapper']] };

const PROGRAM_OPTIONS: Readonly<Record<string, ProgramOptions>> = {
  cat: { boolLong: sw('number number-nonblank show-all show-ends show-tabs show-nonprinting squeeze-blank') },
  head: { value: 'nc', valueLong: sw('lines bytes') },
  tail: { value: 'ncs', valueLong: sw('lines bytes sleep-interval pid max-unchanged-stats'), boolLong: sw('follow retry') },
  less: {
    value: 'bhjkoOpPtTxyz',
    valueLong: sw('pattern tag tag-file tabs window shift max-back-scroll max-forw-scroll'),
    boolLong: sw('quit-if-one-screen RAW-CONTROL-CHARS raw-control-chars chop-long-lines LINE-NUMBERS line-numbers no-init ignore-case IGNORE-CASE squeeze-blank-lines follow-name'),
    risky: [[/^(?:-[oO]|--log-file|--LOG-FILE)$/, 'unknown-writer']],
  },
  bat: BAT_OPTIONS,
  batcat: BAT_OPTIONS,
  strings: { value: 'ntTe', valueLong: sw('bytes radix target encoding output-separator'), boolLong: sw('all print-file-name include-all-whitespace data') },
  xxd: { valueWords: sw('-l -len -s -seek -c -cols -g -groupsize -o -offset -n -name') },
  od: { value: 'ANjtwS', valueLong: sw('address-radix read-bytes skip-bytes format width strings endian'), boolLong: sw('output-duplicates traditional') },
  hexdump: { value: 'nsef', valueLong: sw('length skip format format-file') , boolLong: sw('canonical no-squeezing') },
  base64: {
    value: 'w',
    valueLong: sw('wrap'),
    boolLong: sw('decode ignore-garbage'),
    // macOS `-i FILE -o FILE` (GNU `-i` is a switch): which one runs is unknown.
    risky: [[/^(?:-[io]|--input|--output)$/, 'unknown-writer']],
  },
  nl: { value: 'bdfhilnsvw', valueLong: sw('body-numbering section-delimiter footer-numbering header-numbering line-increment join-blank-lines number-format number-separator starting-line-number number-width'), boolLong: sw('no-renumber') },
  wc: { valueLong: sw('files0-from'), boolLong: sw('lines words bytes chars max-line-length') },
  file: { value: 'mfeFP', valueLong: sw('magic-file files-from exclude separator parameter'), boolLong: sw('brief mime mime-type mime-encoding dereference no-dereference special-files uncompress keep-going no-pad print0 raw extension apple') },
  stat: { value: 'fc', valueLong: sw('format printf cached'), boolLong: sw('terse dereference file-system') },
  jq: {
    value: 'fL',
    valueLong: sw('from-file indent'),
    pairLong: sw('arg argjson slurpfile rawfile'),
    boolLong: sw('raw-output compact-output slurp null-input exit-status sort-keys tab join-output ascii-output raw-input seq stream color-output monochrome-output raw-output0 args jsonargs'),
  },
  yq: { value: 'pIo', valueLong: sw('input-format output-format indent expression from-file front-matter'), boolLong: sw('inplace null-input exit-status prettyPrint unwrapScalar no-doc colors no-colors') },
  md5sum: SUM_OPTIONS, sha1sum: SUM_OPTIONS, sha256sum: SUM_OPTIONS,
  sort: {
    value: 'ktoST',
    valueLong: sw('key field-separator output buffer-size temporary-directory parallel batch-size files0-from random-source sort'),
    boolLong: sw(`reverse numeric-sort unique human-numeric-sort general-numeric-sort version-sort random-sort ignore-case stable check merge
      dictionary-order ignore-leading-blanks month-sort ignore-nonprinting`),
    risky: [[/^--compress-program$/, 'exec-wrapper']],
  },
  uniq: { value: 'fsw', valueLong: sw('skip-fields skip-chars check-chars'), boolLong: sw('count repeated unique ignore-case all-repeated group') },
  cut: { value: 'dfbc', valueLong: sw('delimiter fields bytes characters output-delimiter'), boolLong: sw('complement only-delimited') },
  diff: {
    value: 'CUFILxXS',
    valueLong: sw('label ignore-matching-lines exclude exclude-from starting-file from-file to-file horizon-lines line-format tabsize width color palette'),
    boolLong: sw(`recursive brief new-file ignore-all-space ignore-space-change ignore-blank-lines ignore-case text side-by-side report-identical-files
      unified context expand-tabs initial-tab minimal suppress-common-lines strip-trailing-cr`),
  },
  cmp: { value: 'in', valueLong: sw('ignore-initial bytes'), boolLong: sw('print-bytes') },
  grep: GREP_OPTIONS, egrep: GREP_OPTIONS, fgrep: GREP_OPTIONS, ag: GREP_OPTIONS, ack: GREP_OPTIONS,
  rg: {
    value: 'efmABCgtTMjE',
    valueLong: sw(`regexp file max-count after-context before-context context glob iglob type type-not max-columns max-depth threads sort sortr
      encoding replace type-add type-clear colors color path-separator max-filesize ignore-file engine`),
    boolLong: sw(`hidden no-ignore follow files files-with-matches files-without-match count count-matches ignore-case smart-case case-sensitive
      fixed-strings word-regexp line-number no-line-number no-heading heading json vimgrep only-matching multiline pcre2 invert-match type-list
      search-zip no-messages text unrestricted no-ignore-vcs no-ignore-parent sort-files trim crlf passthru line-regexp with-filename no-filename
      column no-config stats`),
    risky: [[/^--pre$/, 'exec-wrapper']],
  },
  rm: { boolLong: sw('dir one-file-system no-preserve-root preserve-root') },
  shred: { value: 'ns', valueLong: sw('iterations size random-source'), boolLong: sw('remove exact zero') },
  rmdir: { boolLong: sw('parents ignore-fail-on-non-empty') },
  unlink: {},
  cp: COPY_OPTIONS,
  mv: COPY_OPTIONS,
  ln: { value: 'St', valueLong: sw('suffix target-directory'), boolLong: sw('backup symbolic logical physical relative no-dereference no-target-directory') },
  install: {
    value: 'gmoSt',
    valueLong: sw('group mode owner suffix target-directory'),
    boolLong: sw('backup directory compare preserve-timestamps strip no-target-directory preserve-context'),
    risky: [[/^--strip-program$/, 'exec-wrapper']],
  },
  chmod: CHMOD_OPTIONS, chown: CHMOD_OPTIONS, chgrp: CHMOD_OPTIONS,
  tee: { boolLong: sw('append ignore-interrupts output-error') },
  touch: { value: 'drt', valueLong: sw('date reference time'), boolLong: sw('no-create no-dereference') },
  truncate: { value: 'sro', valueLong: sw('size reference'), boolLong: sw('no-create io-blocks') },
  mkdir: { value: 'm', valueLong: sw('mode context'), boolLong: sw('parents') },
  sed: {
    value: 'efl',
    valueLong: sw('expression file line-length'),
    boolLong: sw('in-place regexp-extended separate null-data posix sandbox unbuffered follow-symlinks'),
  },
  curl: {
    value: 'ACDEFHKQTUXYbcdeiomrtuwxyz',
    valueLong: sw(`output data data-raw data-binary data-urlencode data-ascii json header user request user-agent referer cookie cookie-jar form
      form-string upload-file proxy proxy-user config max-time connect-timeout write-out range cert key cacert capath resolve retry retry-delay
      retry-max-time url oauth2-bearer dump-header trace trace-ascii stderr libcurl etag-save etag-compare hsts alt-svc output-dir continue-at
      limit-rate max-filesize interface local-port connect-to preproxy noproxy socks5 socks5-hostname socks4 socks4a time-cond variable
      aws-sigv4 ciphers cert-type key-type pass proto proto-redir dns-servers unix-socket abstract-unix-socket request-target url-query`),
    boolLong: sw(`location insecure show-error fail fail-with-body compressed head include progress-bar remote-name remote-name-all create-dirs
      globoff http1.0 http1.1 http2 http3 ipv4 ipv6 no-progress-meter get location-trusted tlsv1 tlsv1.2 tlsv1.3 ssl-reqd no-buffer raw
      path-as-is anyauth basic digest negotiate ntlm netrc netrc-optional retry-all-errors retry-connrefused fail-early no-keepalive
      tcp-nodelay disable styled-output no-styled-output show-headers`),
    // `-i` here is `--include`, a switch; it is listed with the value
    // letters only so the table stays one string — see `CURL_SWITCHES`.
    risky: [[/^(?:-[KJ]|--config|--remote-header-name|--output-dir)$/, 'unknown-writer']],
  },
  wget: {
    value: 'OoaPUeTtwlARDIXQi',
    valueLong: sw(`output-document output-file append-output directory-prefix header post-data post-file user-agent user password http-user
      http-password body-data body-file method timeout tries wait level accept reject domains include-directories exclude-directories quota
      limit-rate referer load-cookies save-cookies execute input-file base config`),
    boolLong: sw(`no-verbose continue no-check-certificate no-parent mirror timestamping spider server-response show-progress content-disposition
      convert-links page-requisites adjust-extension no-host-directories inet4-only inet6-only force-directories no-directories`),
    risky: [[/^(?:-[eiPx]|--execute|--input-file|--config|--directory-prefix|--force-directories|--save-cookies)$/, 'unknown-writer']],
  },
  http: HTTP_OPTIONS, https: HTTP_OPTIONS, xh: HTTP_OPTIONS,
  ssh: SSH_OPTIONS,
  mosh: SSH_OPTIONS,
  scp: { value: 'cFiloPSJD', risky: [[/^-[SF]$/, 'remote-shell']] },
  sftp: { value: 'BbcDFiloPRSs', risky: [[/^-[SFDs]$/, 'remote-shell']] },
  rsync: {
    value: 'efBTM',
    valueLong: sw(`rsh rsync-path remote-option exclude include exclude-from include-from files-from chmod info bwlimit timeout port backup-dir
      suffix filter temp-dir block-size compare-dest copy-dest link-dest`),
    boolLong: sw(`archive compress delete progress partial recursive human-readable checksum update times perms links hard-links stats
      itemize-changes remove-source-files delete-after delete-before delete-during delete-excluded inplace append sparse one-file-system
      numeric-ids owner group devices specials no-perms ignore-existing size-only backup mkpath copy-links safe-links relative no-motd`),
    risky: [[/^(?:-[eM]|--rsh|--rsync-path|--remote-option)$/, 'remote-shell']],
  },
  nc: NC_OPTIONS, netcat: NC_OPTIONS,
  ncat: { ...NC_OPTIONS, risky: [[/^(?:-[ox]|--output|--hex-dump|--append-output)$/, 'unknown-writer']] },
  pkill: {
    value: 'sUuGgPtnF',
    valueLong: sw('signal older-than younger-than ns nslist uid euid group pgroup parent session terminal pidfile'),
    boolLong: sw('full exact newest oldest inverse count echo ignore-case list-name list-full logpidfile'),
  },
  killall: { value: 'sUuoyn', valueLong: sw('signal user older-than younger-than ns context'), boolLong: sw('exact ignore-case process-group regexp wait') },
  systemctl: {
    value: 'tpsHMn',
    valueLong: sw('type state property signal kill-whom root host machine lines output job-mode'),
    boolLong: sw('user system global now no-block runtime no-pager all full wait no-reload no-ask-password show-types failed'),
    risky: [[/^(?:-[HM]|--host|--machine)$/, 'remote-shell']],
  },
  npm: JS_INSTALL_OPTIONS, pnpm: JS_INSTALL_OPTIONS, yarn: JS_INSTALL_OPTIONS, bun: JS_INSTALL_OPTIONS,
  pip: PY_INSTALL_OPTIONS, pip3: PY_INSTALL_OPTIONS, pipx: PY_INSTALL_OPTIONS, uv: PY_INSTALL_OPTIONS,
  gem: { value: 'vsin', valueLong: sw('version source install-dir bindir'), boolLong: sw('user-install no-document no-ri no-rdoc conservative pre') },
  cargo: { valueLong: sw('git branch tag rev path root version features registry index target'), boolLong: sw('locked frozen offline all-features no-default-features') },
  'apt-get': { value: 'ot', valueLong: sw('target-release option'), boolLong: sw('yes assume-yes no-install-recommends install-suggests reinstall fix-missing allow-downgrades only-upgrade fix-broken download-only') },
  apt: { value: 'ot', valueLong: sw('target-release option'), boolLong: sw('yes assume-yes no-install-recommends install-suggests reinstall fix-missing allow-downgrades only-upgrade fix-broken download-only') },
  dnf: { valueLong: sw('enablerepo disablerepo setopt releasever installroot'), boolLong: sw('assumeyes nogpgcheck refresh best allowerasing skip-broken') },
  yum: { valueLong: sw('enablerepo disablerepo setopt releasever installroot'), boolLong: sw('assumeyes nogpgcheck refresh best allowerasing skip-broken') },
  apk: { value: 'Xt', valueLong: sw('repository virtual'), boolLong: sw('no-cache update-cache allow-untrusted') },
  brew: { boolLong: sw('cask formula HEAD fetch-HEAD build-from-source') },
  pacman: { valueLong: sw('overwrite'), boolLong: sw('noconfirm needed refresh sysupgrade asdeps asexplicit') },
  snap: { valueLong: sw('channel revision'), boolLong: sw('classic devmode dangerous edge beta candidate stable') },
  npx: NPX_OPTIONS, bunx: NPX_OPTIONS, pnpx: NPX_OPTIONS,
};

/** curl's `-i` is `--include`, a switch, though the letter is shared above. */
const CURL_SWITCHES = 'i';

interface ParsedArgs {
  operands: string[];
  /** Every option met, with its value (`''` for a switch). */
  options: Array<[string, string]>;
  /** A long option the program's table does not know, without `=value`. */
  unknownLong: boolean;
}

/** Split `args` into operands and options by `prog`'s option table. Everything
 *  after `--` is an operand. */
function parseArgs(prog: string, args: string[], spec: ProgramOptions | undefined = own(PROGRAM_OPTIONS, prog)): ParsedArgs {
  const operands: string[] = [];
  const options: Array<[string, string]> = [];
  let unknownLong = false;
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i];
    if (a === '--') { operands.push(...args.slice(i + 1)); break; }
    if (!isFlag(a)) { operands.push(a); continue; }
    if (spec?.valueWords) {
      if (spec.valueWords.includes(a)) { options.push([a, args[i + 1] ?? '']); i += 1; } else options.push([a, '']);
      continue;
    }
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      const name = eq === -1 ? a.slice(2) : a.slice(2, eq);
      if (spec?.pairLong?.includes(name)) { options.push([`--${name}`, args[i + 1] ?? '']); i += 2; continue; }
      if (eq !== -1) { options.push([`--${name}`, a.slice(eq + 1)]); continue; }
      if (spec?.valueLong?.includes(name)) { options.push([`--${name}`, args[i + 1] ?? '']); i += 1; continue; }
      if (!spec?.boolLong?.includes(name) && !COMMON_SWITCHES.has(name)) unknownLong = true;
      options.push([`--${name}`, '']);
      continue;
    }
    for (let k = 1; k < a.length; k += 1) {
      const c = a[k];
      if (spec?.value?.includes(c) && !(prog === 'curl' && CURL_SWITCHES.includes(c))) {
        const attached = a.slice(k + 1);
        if (attached) options.push([`-${c}`, attached]);
        else { options.push([`-${c}`, args[i + 1] ?? '']); i += 1; }
        break;
      }
      options.push([`-${c}`, '']);
    }
  }
  return { operands, options, unknownLong };
}

/** The operands of `prog`: arguments that are neither options nor an option's value. */
const operands = (prog: string, args: string[]) => parseArgs(prog, args).operands;
/** The values given to any of `names` (`-o`, `--output`). */
const optionValues = (parsed: ParsedArgs, names: readonly string[]) => parsed.options.filter(([f]) => names.includes(f)).map(([, v]) => v);
const hasOption = (parsed: ParsedArgs, names: readonly string[]) => parsed.options.some(([f]) => names.includes(f));

// ── Wrappers: sudo, env, timeout … stripped to find the program they run ────

/** A wrapper's options (`ProgramOptions` shape, short and long), and which of
 *  them make the call one the card cannot follow. */
interface WrapperOptions {
  bool?: string;
  value?: string;
  /** Short letters that run a shell or editor, or otherwise leave the subset. */
  risky?: string;
  boolLong?: readonly string[];
  valueLong?: readonly string[];
  riskyLong?: readonly string[];
  riskyAs?: ShellDoubt;
  /** `nice -10`: a dash number is a switch. */
  numeric?: boolean;
}

const WRAPPERS: Readonly<Record<string, WrapperOptions>> = {
  sudo: {
    bool: 'AbEHkKnPSBNlvV',
    value: 'ugpCDhrtTUR',
    risky: 'sie',
    boolLong: sw('askpass background preserve-env set-home reset-timestamp remove-timestamp non-interactive preserve-groups stdin bell list validate'),
    valueLong: sw('user group prompt close-from chdir host role type command-timeout other-user chroot'),
    riskyLong: sw('shell login edit'),
  },
  doas: { bool: 'nL', value: 'uC', risky: 's' },
  env: { bool: 'i0v', value: 'uC', risky: 'S', boolLong: sw('ignore-environment null debug'), valueLong: sw('unset chdir'), riskyLong: sw('split-string') },
  nohup: {},
  time: { bool: 'pav', value: 'f', risky: 'o', riskyAs: 'unknown-writer', valueLong: sw('format'), boolLong: sw('portability append'), riskyLong: sw('output') },
  nice: { value: 'n', valueLong: sw('adjustment'), numeric: true },
  ionice: { bool: 't', value: 'cnpPu', boolLong: sw('ignore'), valueLong: sw('class classdata pid pgid uid') },
  timeout: { bool: 'v', value: 'sk', boolLong: sw('preserve-status foreground'), valueLong: sw('signal kill-after') },
  stdbuf: { value: 'ioe', valueLong: sw('input output error') },
  setsid: { bool: 'cfw', boolLong: sw('ctty fork wait') },
  command: { bool: 'pvV' },
  exec: { bool: 'cl', value: 'a' },
  builtin: {},
};

interface WrapperScan {
  end: number;
  values: Array<[string, string]>;
  doubts: ShellDoubt[];
}

/** Walk a wrapper's leading options, stopping at the first operand or after `--`. */
function scanWrapperOptions(args: string[], spec: WrapperOptions): WrapperScan {
  const values: Array<[string, string]> = [];
  const doubts: ShellDoubt[] = [];
  const risky = spec.riskyAs ?? 'exec-wrapper';
  let i = 0;
  for (; i < args.length; i += 1) {
    const a = args[i];
    if (a === '--') { i += 1; break; }
    if (!isFlag(a)) break;
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      const name = eq === -1 ? a.slice(2) : a.slice(2, eq);
      if (spec.riskyLong?.includes(name)) doubts.push(risky);
      if (spec.valueLong?.includes(name)) {
        if (eq === -1) { values.push([`--${name}`, args[i + 1] ?? '']); i += 1; } else values.push([`--${name}`, a.slice(eq + 1)]);
      } else if (!spec.boolLong?.includes(name) && !spec.riskyLong?.includes(name) && !['help', 'version'].includes(name)) {
        doubts.push('unknown-option');
      }
      continue;
    }
    if (spec.numeric && /^-\d+$/.test(a)) continue;
    for (let k = 1; k < a.length; k += 1) {
      const c = a[k];
      if (spec.risky?.includes(c)) doubts.push(risky);
      if (spec.value?.includes(c)) {
        const attached = a.slice(k + 1);
        if (attached) values.push([`-${c}`, attached]);
        else { values.push([`-${c}`, args[i + 1] ?? '']); i += 1; }
        break;
      }
      if (!spec.bool?.includes(c) && !spec.risky?.includes(c)) doubts.push('unknown-option');
    }
  }
  return { end: i, values, doubts };
}

const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*\+?=/;

interface Unwrapped {
  prog: string;
  argv0: string;
  args: string[];
  /** Run through sudo/doas: as root, or as another named user. */
  sudo: 'admin' | 'user' | null;
  /** `NAME=value` words set for (or, standing alone, before) the program. */
  assigns: string[];
  doubts: ShellDoubt[];
  /** A wrapper changed the working directory (`env -C`, `sudo -D`). */
  chdir: boolean;
}

/** Strip env assignments and wrappers; returns the program and its arguments. */
function unwrap(seg: Segment): Unwrapped {
  const w = [...seg.words];
  let sudo: Unwrapped['sudo'] = null;
  const assigns: string[] = [];
  const doubts: ShellDoubt[] = [];
  let chdir = false;
  for (let guard = 0; w.length > 0 && guard < 32; guard += 1) {
    const head = w[0];
    if (ASSIGNMENT.test(head)) { assigns.push(w.shift() as string); continue; }
    const name = basename(head);
    const spec = own(WRAPPERS, name);
    if (!spec || !isTrustedProgram(head)) break;
    w.shift();
    const scan = scanWrapperOptions(w, spec);
    doubts.push(...scan.doubts);
    w.splice(0, scan.end);
    if (name === 'sudo' || name === 'doas') {
      // `sudo --user root` and `sudo -u '#0'` are root; any other user is not.
      const user = scan.values.filter(([f]) => f === '-u' || f === '--user').map(([, v]) => v).pop();
      sudo = user === undefined || /^(?:root|#0)$/.test(user) ? 'admin' : 'user';
    }
    if (scan.values.some(([f]) => (name === 'env' && (f === '-C' || f === '--chdir')) || (name === 'sudo' && (f === '-D' || f === '--chdir')))) chdir = true;
    if (name === 'env') while (w.length > 0 && ASSIGNMENT.test(w[0])) assigns.push(w.shift() as string);
    if (name === 'timeout' && w.length > 0 && /^\d+(?:\.\d+)?[smhd]?$/.test(w[0])) w.shift();
  }
  const argv0 = w[0] ?? '';
  return { prog: argv0 ? basename(argv0) : '', argv0, args: w.slice(1), sudo, assigns, doubts, chdir };
}

// ── What puts a step outside the understood subset ──────────────────────────

/** Words bash reads as syntax, not as a program. */
const RESERVED_WORDS = new Set(['if', 'then', 'else', 'elif', 'fi', 'for', 'while', 'until', 'do', 'done', 'case', 'esac', 'select', 'function', 'coproc', '{', '}', '!', '[[', ']]']);
/** Builtins that run code stored elsewhere or change what a name runs. */
const EVAL_LIKE = new Set(['eval', 'source', '.', 'alias', 'trap', 'hash', 'enable']);
/** Programs whose job is to run another command. */
const EXEC_WRAPPERS = new Set([
  'xargs', 'parallel', 'pkexec', 'watch', 'flock', 'chroot', 'nsenter', 'unshare', 'setpriv', 'script', 'busybox', 'toybox', 'strace', 'ltrace',
  'sg', 'newgrp', 'sshpass', 'firejail', 'torsocks', 'proxychains', 'proxychains4', 'xvfb-run', 'dbus-run-session', 'systemd-inhibit',
  'caffeinate', 'chrt', 'taskset', 'numactl', 'cpulimit', 'prlimit', 'faketime', 'fakeroot', 'gosu', 'su-exec', 'tini', 'dumb-init', 'entr',
  'ssh-agent', 'runcon', 'catchsegv', 'valgrind', 'gdb',
]);
/** `su`/`runuser` options that hand it a command or a shell. */
const SU_COMMAND = /^(?:-[A-Za-z]*[cs][A-Za-z]*|--(?:command|session-command|shell)(?:=.*)?)$/;
/** Variables that change which program runs or what it loads (#648 r3 R1). */
const RISKY_ENV = new RegExp(`^(?:${[
  'PATH', 'LD_\\w*', 'DYLD_\\w*', 'BASH_ENV', 'ENV', 'NODE_OPTIONS', 'NODE_PATH', 'PYTHON\\w*', 'PERL5\\w*', 'PERLLIB', 'RUBY\\w*', 'GEM_\\w*',
  'IFS', 'HOME', 'ZDOTDIR', 'SHELLOPTS', 'BASHOPTS', 'BASH_FUNC_\\S*', 'PS4', 'PROMPT_COMMAND', 'CDPATH', 'GLOBIGNORE', 'XDG_CONFIG_HOME',
  'SSH_\\w*', 'GIT_\\w+', 'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'CLASSPATH', 'LUA_\\w*', 'NPM_CONFIG_\\w*', 'npm_config_\\w*', 'PIP_\\w*',
  'CURL_HOME', 'WGETRC', 'EDITOR', 'VISUAL', 'PAGER', 'LESSOPEN', 'LESSCLOSE', 'SUDO_ASKPASS', 'SSH_ASKPASS',
].join('|')})$`);
/** GIT_* variables that only move the repository: the host is dropped. */
const GIT_REPO_ENV = /^GIT_(?:DIR|WORK_TREE|COMMON_DIR|INDEX_FILE|NAMESPACE|CEILING_DIRECTORIES|DISCOVERY_ACROSS_FILESYSTEM|OBJECT_DIRECTORY|ALTERNATE_OBJECT_DIRECTORIES)$/;
const DECLARERS = new Set(['export', 'declare', 'typeset', 'local', 'readonly']);
/** ssh options that run a local command. */
const SSH_RISKY_OPTION = /^(?:proxycommand|localcommand|permitlocalcommand|knownhostscommand|match|include)\b/i;

function envDoubt(assignment: string): ShellDoubt | null {
  const name = assignment.slice(0, assignment.search(/\+?=/));
  if (GIT_REPO_ENV.test(name)) return 'git-repo-option';
  return RISKY_ENV.test(name) ? 'env-prefix' : null;
}

const SHELLS = new Set(['bash', 'sh', 'zsh', 'dash', 'ksh', 'mksh', 'ash', 'fish']);
const INTERPRETERS = new Set([...SHELLS, 'python', 'python2', 'python3', 'node', 'nodejs', 'deno', 'ruby', 'perl', 'php', 'tsx', 'ts-node', 'pwsh', 'powershell', 'osascript', 'lua', 'Rscript']);

const PYTHON_OPTIONS: WrapperOptions = { bool: 'BbdEhIiOqsSuvVxP', value: 'WXm', risky: 'c', riskyAs: 'inline-code' };
const SHELL_OPTIONS: WrapperOptions = {
  bool: 'abefhkmnptuvxBCEHPTilrs', value: 'oO', risky: 'c', riskyAs: 'exec-wrapper',
  boolLong: sw('norc noprofile login posix restricted noediting'), riskyLong: sw('rcfile init-file'),
};
/** Interpreter options. A risky option runs inline code (#648 r3 R1), and an
 *  option not listed here is unknown, so the card goes generic either way. */
const INTERPRETER_OPTIONS: Readonly<Record<string, WrapperOptions>> = {
  python: PYTHON_OPTIONS, python2: PYTHON_OPTIONS, python3: PYTHON_OPTIONS,
  node: {
    bool: 'hvi', value: 'C', risky: 'cerp', riskyAs: 'inline-code',
    boolLong: sw(`inspect inspect-brk trace-warnings no-warnings enable-source-maps watch test preserve-symlinks abort-on-uncaught-exception
      no-deprecation throw-deprecation trace-uncaught trace-deprecation pending-deprecation experimental-vm-modules experimental-strip-types
      experimental-transform-types no-experimental-strip-types harmony expose-gc frozen-intrinsics zero-fill-buffers no-addons`),
    valueLong: sw('title input-type stack-size conditions inspect-port unhandled-rejections max-old-space-size'),
    riskyLong: sw('eval print require import loader experimental-loader check env-file'),
  },
  ruby: { bool: 'wWvd', value: 'IC', risky: 'erpnaxlES', riskyAs: 'inline-code', boolLong: sw('disable-gems') },
  perl: { bool: 'wWTtvc', risky: 'eEnpiMmxlsaF0I', riskyAs: 'inline-code' },
  php: { bool: 'nqvh', value: 'f', risky: 'rRBEFdcza', riskyAs: 'inline-code' },
  osascript: { value: 'ls', risky: 'ei', riskyAs: 'inline-code' },
  lua: { bool: 'viEW', risky: 'el', riskyAs: 'inline-code' },
  Rscript: { boolLong: sw('vanilla no-save no-restore no-environ no-site-file no-init-file quiet slave'), risky: 'e', riskyAs: 'inline-code' },
  tsx: { risky: 'epr', riskyAs: 'inline-code', riskyLong: sw('eval print require import'), boolLong: sw('watch no-cache') },
  'ts-node': { bool: 'THv', risky: 'epr', riskyAs: 'inline-code', riskyLong: sw('eval print require'), boolLong: sw('transpile-only swc esm files') },
  fish: { bool: 'nilPN', risky: 'cC', riskyAs: 'exec-wrapper', boolLong: sw('no-execute interactive login private no-config'), riskyLong: sw('command init-command') },
};
for (const shell of SHELLS) if (!Object.hasOwn(INTERPRETER_OPTIONS, shell)) (INTERPRETER_OPTIONS as Record<string, WrapperOptions>)[shell] = SHELL_OPTIONS;
(INTERPRETER_OPTIONS as Record<string, WrapperOptions>).nodejs = INTERPRETER_OPTIONS.node;

/** A script operand the card may name: path characters only (#648 r3 R1 —
 *  a space, quote or parenthesis means it is code, not a file). */
const PATH_SHAPED = /^[A-Za-z0-9._/~+@%,:=-]+$/;
/** …and shown only when it looks like a file, so a bare word — which could be
 *  anything a caller typed — is never printed. */
const LOOKS_LIKE_FILE = /\/|\.[A-Za-z0-9]{1,10}$/;

interface InterpreterRun {
  /** The script, module or `-f` file named, if any. */
  script?: string;
  module?: string;
  /** Reads its program from stdin. */
  stdin: boolean;
  doubts: ShellDoubt[];
}

/** How an interpreter is being run. Anything but a script path or stdin is
 *  outside the understood subset, and its code is never printed. */
function interpreterRun(prog: string, args: string[]): InterpreterRun {
  const doubts: ShellDoubt[] = [];
  if (prog === 'pwsh' || prog === 'powershell') return powershellRun(prog, args);
  if (prog === 'deno') {
    if (args[0] !== 'run') return { stdin: false, doubts: ['inline-code'] };
    const rest = args.slice(1);
    const opts = rest.filter(isFlag);
    if (!opts.every((a) => /^(?:-A|-q|--quiet|--no-prompt|--watch|--check|--no-check|--(?:allow|deny)-[a-z-]+(?:=\S*)?|--unstable(?:-[a-z-]+)?)$/.test(a))) doubts.push('unknown-option');
    const script = rest.find((a) => !isFlag(a));
    return { script, stdin: script === undefined, doubts };
  }
  const spec = own(INTERPRETER_OPTIONS, prog) ?? {};
  const scan = scanWrapperOptions(args, spec);
  doubts.push(...scan.doubts);
  const rest = args.slice(scan.end);
  const module = scan.values.find(([f]) => f === '-m')?.[1];
  if (module !== undefined) return { module, stdin: false, doubts };
  const file = scan.values.find(([f]) => f === '-f')?.[1];
  if (prog === 'php' && file !== undefined) return { script: file, stdin: false, doubts };
  // `bash -s` reads its program from stdin; its operands are arguments.
  const stdinFlag = SHELLS.has(prog) && args.slice(0, scan.end).some((a) => /^-[A-Za-z]*s[A-Za-z]*$/.test(a));
  if (stdinFlag || rest.length === 0 || rest[0] === '-') return { stdin: true, doubts };
  return { script: rest[0], stdin: false, doubts };
}

function powershellRun(prog: string, args: string[]): InterpreterRun {
  const doubts: ShellDoubt[] = [];
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i];
    if (!/^[-/]/.test(a)) {
      // Windows PowerShell reads a bare operand as -Command; pwsh as -File.
      return prog === 'pwsh' ? { script: a, stdin: false, doubts } : { stdin: false, doubts: [...doubts, 'inline-code'] };
    }
    const name = a.replace(/^--?|^\//, '').toLowerCase();
    if (['file', 'f'].includes(name)) return { script: args[i + 1], stdin: false, doubts };
    if (['noprofile', 'nop', 'noninteractive', 'nonint', 'nologo', 'nol', 'sta', 'mta'].includes(name)) continue;
    if (['executionpolicy', 'ep', 'ex', 'inputformat', 'outputformat', 'of', 'if'].includes(name)) { i += 1; continue; }
    if (/^(?:c|command|e|ec|en|enc|encodedcommand|encodedarguments)$/.test(name) || name === '') return { stdin: false, doubts: [...doubts, 'inline-code'] };
    doubts.push('unknown-option');
  }
  return { stdin: true, doubts };
}

/** sed scripts that write (`w FILE`, the `s///w` flag) or run (`e`) — the
 *  match is loose on purpose: a false hit only makes the card generic. */
const SED_WRITES_OR_RUNS = /(?:^|[;{}\n])\s*(?:\d+|\$|\/[^/]*\/)?\s*[wWe](?:\s|$)|\/[gIpimM0-9]*[we](?:\s|$)/;

const READERS = new Set(['cat', 'less', 'more', 'head', 'tail', 'bat', 'batcat', 'view', 'strings', 'xxd', 'od', 'hexdump', 'base64', 'nl', 'wc', 'file', 'stat', 'jq', 'yq', 'md5sum', 'sha1sum', 'sha256sum', 'sort', 'uniq', 'cut', 'diff', 'cmp']);
const SEARCHERS = new Set(['grep', 'egrep', 'fgrep', 'rg', 'ag', 'ack']);
const EDITORS = new Set(['vi', 'vim', 'nvim', 'nano', 'emacs', 'pico', 'ed', 'code', 'view']);
const DELETERS = new Set(['rm', 'unlink', 'rmdir', 'shred', 'trash', 'srm']);
const HTTP_CLIENTS = new Set(['curl', 'wget', 'http', 'https', 'xh']);
const RAW_SOCKETS = new Set(['nc', 'ncat', 'netcat', 'telnet', 'socat']);
const COPY_REMOTE = new Set(['scp', 'sftp', 'rsync']);
const SYSTEM_PKG = new Set(['apt', 'apt-get', 'dnf', 'yum', 'apk', 'brew', 'pacman', 'snap']);
const PKG_MANAGERS: Readonly<Record<string, { label: string; install: RegExp }>> = {
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
/** Programs whose WHAT names a target taken from their operands: an option
 *  they do not know could hide which word is the target (#648 r3 R1). */
const TARGETED = new Set([
  ...READERS, ...SEARCHERS, ...DELETERS, 'cp', 'mv', 'install', 'ln', 'chmod', 'chown', 'chgrp', 'tee', 'touch', 'truncate', 'mkdir', 'sed',
  ...HTTP_CLIENTS, 'ssh', 'mosh', ...COPY_REMOTE, 'nc', 'ncat', 'netcat', 'pkill', 'killall', 'systemctl', ...RUNNERS,
]);

/**
 * Everything about ONE step that puts it outside the understood subset.
 * `afterCd`: an earlier step changed directory. `fedByDownload`: the step is
 * an interpreter reading stdin from a download earlier in its pipeline — the
 * one stdin form the card understands ("Download from X and run it").
 */
function stepDoubts(seg: Segment, u: Unwrapped, afterCd: boolean, fedByDownload: boolean): ShellDoubt[] {
  const doubts: ShellDoubt[] = [...u.doubts];
  const { prog, args } = u;
  if (RESERVED_WORDS.has(seg.words[0] ?? '') || RESERVED_WORDS.has(u.argv0)) doubts.push('shell-syntax');
  const assigns = [...u.assigns, ...(DECLARERS.has(prog) ? args.filter((a) => ASSIGNMENT.test(a)) : [])];
  for (const a of assigns) {
    const d = envDoubt(a);
    if (d) doubts.push(d);
  }
  if (!prog) return doubts;
  if (EVAL_LIKE.has(prog)) doubts.push('eval-or-source');
  if (EXEC_WRAPPERS.has(prog)) doubts.push('exec-wrapper');
  if ((prog === 'su' || prog === 'runuser') && args.some((a) => SU_COMMAND.test(a))) doubts.push('exec-wrapper');
  if (prog === 'find') {
    args.forEach((a, i) => {
      if (/^-(?:exec|execdir|ok|okdir)$/.test(a) && !/^(?:rm|shred|unlink)$/.test(basename(args[i + 1] ?? ''))) doubts.push('exec-wrapper');
      if (/^-(?:fprint|fprint0|fprintf|fls)$/.test(a)) doubts.push('unknown-writer');
    });
  }
  if (INTERPRETERS.has(prog)) {
    const run = interpreterRun(prog, args);
    doubts.push(...run.doubts);
    if (run.module !== undefined && !/^[A-Za-z_][\w.]*$/.test(run.module)) doubts.push('inline-code');
    if (run.script !== undefined && !PATH_SHAPED.test(run.script.replace(LEADING_HOME, '~'))) doubts.push('inline-code');
    if (run.stdin && !fedByDownload) doubts.push('inline-code');
  }
  if (EDITORS.has(prog) && args.some((a) => isFlag(a) || a.startsWith('+'))) doubts.push('unknown-option');
  if (prog === 'git') doubts.push(...gitDoubts(args, afterCd || u.chdir));
  const parsed = TARGETED.has(prog) || Object.hasOwn(PROGRAM_OPTIONS, prog) ? parseArgs(prog, args) : null;
  if (parsed) {
    if (parsed.unknownLong && (TARGETED.has(prog) || own(PKG_MANAGERS, prog)?.install.test(parsed.operands[0] ?? ''))) doubts.push('unknown-option');
    for (const [re, doubt] of own(PROGRAM_OPTIONS, prog)?.risky ?? []) {
      if (parsed.options.some(([f]) => re.test(f))) doubts.push(doubt);
    }
  }
  if (prog === 'ssh' || prog === 'mosh') {
    const p = parseArgs(prog, args);
    // Anything after the destination is a command for the remote shell.
    if (p.operands.length > 1 || hasOption(p, ['-F'])) doubts.push('remote-shell');
    if (optionValues(p, ['-o']).some((v) => SSH_RISKY_OPTION.test(v))) doubts.push('remote-shell');
  }
  if (prog === 'scp' || prog === 'sftp' || prog === 'rsync') {
    if (optionValues(parseArgs(prog, args), ['-o']).some((v) => SSH_RISKY_OPTION.test(v))) doubts.push('remote-shell');
  }
  if (RAW_SOCKETS.has(prog)) {
    if (args.some((a) => /^(?:-[A-Za-z]*[ec]|--(?:exec|sh-exec|lua-exec)(?:=.*)?)$/.test(a) && prog !== 'socat')) doubts.push('remote-shell');
    if (prog === 'socat' && args.some((a) => /(?:^|[,!])(?:EXEC|SYSTEM)[:,]/i.test(a))) doubts.push('remote-shell');
  }
  if (prog === 'sed') {
    const p = parseArgs(prog, args);
    const scripts = [...optionValues(p, ['-e', '--expression']), ...(hasOption(p, ['-e', '--expression', '-f', '--file']) ? [] : p.operands.slice(0, 1))];
    if (hasOption(p, ['-f', '--file']) || scripts.some((s) => SED_WRITES_OR_RUNS.test(s))) doubts.push('unknown-writer');
  }
  return doubts;
}

// ── Git: the remote's host, only when the command is sure to reach it ───────

const GIT_GLOBAL: ProgramOptions = {
  value: 'Cc',
  valueLong: sw('git-dir work-tree namespace config-env super-prefix'),
  boolLong: sw(`bare no-pager paginate no-replace-objects literal-pathspecs glob-pathspecs noglob-pathspecs icase-pathspecs no-optional-locks
    no-lazy-fetch no-advice exec-path html-path man-path info-path`),
};
const GIT_FETCH_LONG = sw('depth deepen shallow-since shallow-exclude jobs refmap negotiation-tip server-option filter upload-pack recurse-submodules submodule-prefix');
const GIT_FETCH_BOOL = sw(`all append atomic unshallow update-shallow dry-run keep multiple prune prune-tags no-tags tags progress no-progress ipv4 ipv6
  write-fetch-head no-write-fetch-head set-upstream update-head-ok show-forced-updates no-show-forced-updates auto-maintenance auto-gc refetch
  no-recurse-submodules`);
const GIT_SUB_OPTIONS: Readonly<Record<string, ProgramOptions>> = {
  push: {
    value: 'o',
    valueLong: sw('repo receive-pack exec push-option recurse-submodules'),
    boolLong: sw(`all mirror tags follow-tags atomic porcelain delete force-with-lease force-if-includes prune progress no-progress thin no-thin
      set-upstream no-verify verify ipv4 ipv6 no-signed signed no-recurse-submodules no-atomic no-force-with-lease no-follow-tags branches`),
  },
  fetch: { value: 'jo', valueLong: GIT_FETCH_LONG, boolLong: GIT_FETCH_BOOL },
  pull: {
    value: 'josX',
    valueLong: [...GIT_FETCH_LONG, ...sw('strategy strategy-option')],
    boolLong: [...GIT_FETCH_BOOL, ...sw(`rebase no-rebase ff no-ff ff-only squash no-squash commit no-commit edit no-edit stat no-stat autostash
      no-autostash verify no-verify allow-unrelated-histories signoff no-signoff`)],
  },
  clone: {
    value: 'bocju',
    valueLong: sw(`branch origin config jobs upload-pack depth reference reference-if-able separate-git-dir template filter shallow-since shallow-exclude
      server-option bundle-uri recurse-submodules`),
    boolLong: sw(`bare mirror recursive shallow-submodules no-checkout single-branch no-single-branch no-tags progress local no-hardlinks shared
      dissociate sparse remote-submodules no-remote-submodules also-filter-submodules no-reject-shallow reject-shallow`),
  },
  'ls-remote': { value: 'o', valueLong: sw('upload-pack sort server-option'), boolLong: sw('heads tags refs exit-code get-url symref branches') },
};
const GIT_NETWORK = new Set(Object.keys(GIT_SUB_OPTIONS));

/** Where a git command's options and environment put it (#648 r3 R1, R2). */
function gitDoubts(args: string[], dirChanged: boolean): ShellDoubt[] {
  const doubts: ShellDoubt[] = dirChanged ? ['git-repo-option'] : [];
  const { globals, sub, rest } = splitGit(args);
  for (const [flag, value] of globals.options) {
    if (/^(?:-C|--git-dir|--work-tree|--namespace)$/.test(flag)) doubts.push('git-repo-option');
    if (/^(?:-c|--config-env|--super-prefix)$/.test(flag) || (flag === '--exec-path' && value)) doubts.push('git-config-override');
  }
  if (globals.unknownLong) doubts.push('unknown-option');
  if (sub && GIT_NETWORK.has(sub)) {
    const p = parseArgs(`git ${sub}`, rest, own(GIT_SUB_OPTIONS, sub));
    if (p.unknownLong) doubts.push('unknown-option');
    for (const [flag] of p.options) {
      if (flag === '--repo') doubts.push('git-repo-option');
      if (/^(?:--receive-pack|--exec|--upload-pack|--template|--config)$/.test(flag) || (sub === 'clone' && /^-[cu]$/.test(flag))) doubts.push('git-config-override');
    }
  }
  return doubts;
}

/** git's global options, its subcommand, and the subcommand's arguments. */
function splitGit(args: string[]): { globals: ParsedArgs; sub: string | undefined; rest: string[] } {
  let i = 0;
  const head: string[] = [];
  while (i < args.length && isFlag(args[i])) {
    const a = args[i];
    head.push(a);
    if (/^-[Cc]$/.test(a) || (/^--(?:git-dir|work-tree|namespace|config-env|super-prefix)$/.test(a))) { head.push(args[i + 1] ?? ''); i += 1; }
    i += 1;
  }
  return { globals: parseArgs('git', head, GIT_GLOBAL), sub: args[i], rest: args.slice(i + 1) };
}

interface GitConfigEntry { section: string; sub: string | null; key: string; value: string }

/** One config value: quotes removed, a trailing comment cut. null when it
 *  continues on the next line or is otherwise beyond this reader. */
function gitConfigValue(raw: string): string | null {
  let out = '';
  let inQuote = false;
  for (let i = 0; i < raw.length; i += 1) {
    const c = raw[i];
    if (c === '\\') {
      const n = raw[i + 1];
      if (n === undefined) return null;
      out += n === 'n' ? '\n' : n === 't' ? '\t' : n;
      i += 1;
      continue;
    }
    if (c === '"') { inQuote = !inQuote; continue; }
    if (!inQuote && (c === '#' || c === ';')) break;
    out += c;
  }
  return inQuote ? null : out.trim();
}

/** A git config file as entries; null if any line is beyond this reader. */
function parseGitConfig(text: string): GitConfigEntry[] | null {
  const entries: GitConfigEntry[] = [];
  let section = '';
  let sub: string | null = null;
  for (const rawLine of text.split('\n')) {
    let line = rawLine.trim();
    if (line.startsWith('[')) {
      const h = /^\[\s*([A-Za-z0-9.-]+)(?:\s+"((?:[^"\\]|\\.)*)")?\s*\](.*)$/.exec(line);
      if (!h) return null;
      const name = h[1].toLowerCase();
      if (h[2] !== undefined) {
        section = name;
        sub = h[2].replace(/\\(.)/g, '$1');
      } else {
        const dot = name.indexOf('.');
        section = dot === -1 ? name : name.slice(0, dot);
        sub = dot === -1 ? null : name.slice(dot + 1);
      }
      line = h[3].trim();
    }
    if (!line || line.startsWith('#') || line.startsWith(';')) continue;
    const kv = /^([A-Za-z][A-Za-z0-9-]*)\s*(?:=(.*))?$/.exec(line);
    if (!kv) return null;
    const value = kv[2] === undefined ? 'true' : gitConfigValue(kv[2]);
    if (value === null) return null;
    entries.push({ section, sub, key: kv[1].toLowerCase(), value });
  }
  return entries;
}

/** The repository's git dir and common dir for `cwd`, or null. */
function findGitDirs(cwd: string): { gitDir: string; commonDir: string } | null {
  let dir = cwd;
  for (let depth = 0; depth < 16; depth += 1) {
    const dotGit = join(dir, '.git');
    if (existsSync(dotGit)) {
      if (!statSync(dotGit).isFile()) return { gitDir: dotGit, commonDir: dotGit };
      const m = /^gitdir:\s*(.+)$/m.exec(readFileSync(dotGit, 'utf8').slice(0, 4096));
      if (!m) return null;
      const gitDir = resolve(dir, m[1].trim());
      const common = join(gitDir, 'commondir');
      const commonDir = existsSync(common) ? resolve(gitDir, readFileSync(common, 'utf8').slice(0, 4096).trim()) : gitDir;
      return { gitDir, commonDir };
    }
    const parent = dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
  return null;
}

/** Environment that points git at config this reader cannot see. */
const GIT_CONFIG_ENV = /^GIT_(?:CONFIG|CONFIG_GLOBAL|CONFIG_SYSTEM|CONFIG_NOSYSTEM|CONFIG_COUNT|CONFIG_PARAMETERS|DIR|COMMON_DIR)$/;

/**
 * Every git config the command will read, in git's order (system, global,
 * repository), or null when any of it cannot be read and understood — the
 * caller then drops the host (#648 r3 R2). `repoKnown` is false when there
 * is no working directory to find the repository from.
 */
function loadGitConfig(ctx: ShellContext, wantRepo: boolean): { entries: GitConfigEntry[]; repoKnown: boolean } | null {
  if (Object.keys(process.env).some((k) => GIT_CONFIG_ENV.test(k))) return null;
  const home = process.env.HOME || HOME;
  const xdg = process.env.XDG_CONFIG_HOME || (home ? join(home, '.config') : '');
  const files = [
    ...(ctx.gitSystemConfig ?? ['/etc/gitconfig', '/usr/local/etc/gitconfig', '/opt/homebrew/etc/gitconfig']),
    ...(xdg ? [join(xdg, 'git', 'config')] : []),
    ...(home ? [join(home, '.gitconfig')] : []),
  ];
  let repoKnown = false;
  try {
    if (wantRepo && ctx.cwd && isAbsolute(ctx.cwd)) {
      const dirs = findGitDirs(ctx.cwd);
      if (dirs) {
        files.push(join(dirs.commonDir, 'config'), join(dirs.gitDir, 'config.worktree'));
        repoKnown = true;
      }
    }
    const entries: GitConfigEntry[] = [];
    for (const file of files) {
      if (!existsSync(file)) continue;
      const parsed = parseGitConfig(readFileSync(file, 'utf8').slice(0, 65_536));
      if (!parsed) return null;
      entries.push(...parsed);
    }
    // An include pulls in config this reader does not follow.
    if (entries.some((e) => e.section === 'include' || e.section === 'includeif')) return null;
    return { entries, repoKnown };
  } catch {
    return null;
  }
}

/**
 * The host a git network command will reach, only when it is certain (#648
 * r3 R2): `pushurl` before `url` for a push, every URL agreeing, no
 * `insteadOf`/`pushInsteadOf` rewriting anywhere in the config, and no
 * option or earlier `cd` that moves the repository. Otherwise null — the
 * card then names the remote, or "a remote server", never a host the
 * command may not reach.
 */
function gitRemoteHost(ctx: ShellContext, op: string, remoteArg: string | undefined): string | null {
  if (ctx.dropGitHost) return null;
  const config = loadGitConfig(ctx, op !== 'clone');
  if (!config) return null;
  const { entries, repoKnown } = config;
  if (entries.some((e) => e.section === 'url' && (e.key === 'insteadof' || e.key === 'pushinsteadof'))) return null;
  if (op === 'clone') return remoteArg ? safeHost(remoteArg) : null;
  if (remoteArg === undefined) {
    // No remote named: git picks one from pushDefault / branch.*.pushRemote /
    // branch.*.remote. Only an unambiguous `origin` is followed.
    const redirected = entries.some((e) => (e.section === 'remote' && e.sub === null && e.key === 'pushdefault')
      || (e.section === 'branch' && (e.key === 'pushremote' || (e.key === 'remote' && e.value !== 'origin'))));
    if (redirected) return null;
  }
  const name = remoteArg ?? 'origin';
  const remote = entries.filter((e) => e.section === 'remote' && e.sub === name);
  if (remote.length === 0) {
    // Not a configured remote: a URL, used as typed — if the repository's own
    // config (which may rewrite it) could be read.
    return repoKnown && /^[a-z][a-z0-9+.-]*:\/\/|^[^/\s]+:/i.test(name) ? safeHost(name) : null;
  }
  const urls = remote.filter((e) => e.key === 'url').map((e) => e.value);
  const pushUrls = remote.filter((e) => e.key === 'pushurl').map((e) => e.value);
  const targets = op === 'push' ? (pushUrls.length > 0 ? pushUrls : urls) : urls.slice(0, 1);
  const hosts = new Set(targets.map((u) => safeHost(u)));
  if (hosts.size !== 1) return null;
  return [...hosts][0];
}

/** How the card names a remote it will not put a host on. */
function remoteLabel(op: string, remoteArg: string | undefined, entries: boolean): string {
  if (op === 'clone' || !entries) return 'a remote server';
  const name = remoteArg ?? 'origin';
  return /^[A-Za-z0-9._-]{1,32}$/.test(name) ? `the "${name}" remote` : 'a remote server';
}

function describeGit(args: string[], ctx: ShellContext): Described {
  const { sub, rest } = splitGit(args);
  if (sub && GIT_NETWORK.has(sub)) {
    const pos = parseArgs(`git ${sub}`, rest, own(GIT_SUB_OPTIONS, sub)).operands;
    const remoteArg = pos[0];
    const host = gitRemoteHost(ctx, sub, remoteArg);
    // With no remote named and the default redirected, the remote is unknown.
    const where = host ?? remoteLabel(sub, remoteArg, !(remoteArg === undefined && (ctx.dropGitHost || gitDefaultRedirected(ctx))));
    const force = sub === 'push' && rest.some((a) => /^(?:-[A-Za-z]*f[A-Za-z]*|--force|--force-with-lease(?:=.*)?|--mirror)$/.test(a) || /^\+/.test(a));
    const del = sub === 'push' && rest.some((a) => /^(?:-d|--delete)$/.test(a) || /^:/.test(a));
    const branch = sub === 'push' ? pos.slice(1).map((b) => b.replace(/^[+:]/, '')).find(Boolean) : undefined;
    const branchText = branch ? ` (branch ${quoted(branch, 40)})` : '';
    // The WHY line carries "may overwrite history"; the WHAT stays short.
    if (force) return { category: 'git', sentence: `Force-push to ${where}${branchText} (git push --force)` };
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

/** The default remote is not plainly `origin` (or the config is unreadable). */
function gitDefaultRedirected(ctx: ShellContext): boolean {
  const config = loadGitConfig(ctx, true);
  if (!config) return true;
  return config.entries.some((e) => (e.section === 'remote' && e.sub === null && e.key === 'pushdefault')
    || (e.section === 'branch' && (e.key === 'pushremote' || (e.key === 'remote' && e.value !== 'origin'))));
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
const SUBCOMMANDS: Readonly<Record<string, ReadonlySet<string>>> = (() => {
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
  | 'read' | 'write' | 'delete' | 'move' | 'perms' | 'stop' | 'network' | 'fetch-run' | 'install'
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
  /** A repository option or earlier `cd` moved the repository (#648 r3 R2). */
  dropGitHost?: boolean;
  /** Tests only: the system-level git config files. */
  gitSystemConfig?: readonly string[];
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

/**
 * Writes the card must name whatever the program (#648 r3 R3): keys and
 * credentials, shell startup files, system config, schedulers, autostart,
 * git hooks and raw disks.
 */
const SENSITIVE_WRITE_RE =
  /(?:^|\/|~)\.(?:bashrc|bash_profile|bash_login|bash_logout|profile|zshrc|zprofile|zshenv|zlogin|kshrc|cshrc|tcshrc|inputrc|xprofile|xinitrc|xsessionrc|pam_environment)$|\.config\/(?:fish|autostart|systemd)\/|\.local\/share\/systemd\/|\/etc\/|^\/(?:boot|usr|bin|sbin|lib|lib64)\/|\/cron|Library\/Launch(?:Agents|Daemons)\/|\.git\/hooks\/|^\/dev\/(?!null$|stdout$|stderr$|tty$|fd\/)/;
const isSensitiveWrite = (p: string) => SENSITIVE_PATH_RE.test(p) || SENSITIVE_WRITE_RE.test(p);
/** Redirect targets that write nothing anyone keeps. */
const isBitBucket = (p: string) => /^\/dev\/(?:null|stdout|stderr|tty|fd\/\d+)$/.test(p);

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

/** The files a step writes, beyond its redirects (#648 r3 R3). */
function writerOutputs(prog: string, args: string[]): { inputs: string[]; outputs: string[] } | null {
  const p = parseArgs(prog, args);
  const pos = p.operands;
  switch (prog) {
    case 'sort': return { inputs: pos, outputs: optionValues(p, ['-o', '--output']) };
    case 'uniq': return { inputs: pos.slice(0, 1), outputs: pos.slice(1, 2) };
    case 'xxd': return { inputs: pos.slice(0, 1), outputs: pos.slice(1, 2) };
    case 'tee': return { inputs: [], outputs: pos };
    case 'curl': return { inputs: [], outputs: optionValues(p, ['-o', '--output', '-c', '--cookie-jar', '-D', '--dump-header', '--trace', '--trace-ascii', '--stderr', '--libcurl', '--etag-save', '--hsts', '--alt-svc']).filter((v) => v !== '-') };
    case 'wget': return { inputs: [], outputs: optionValues(p, ['-O', '--output-document', '-o', '--output-file', '-a', '--append-output']).filter((v) => v !== '-') };
    case 'http': case 'https': case 'xh': return { inputs: [], outputs: optionValues(p, ['-o', '--output']) };
    default: return null;
  }
}

function describeInstall(prog: string, args: string[]): Described | null {
  const pm = own(PKG_MANAGERS, prog);
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
  // Options that take a value (`--registry <url>`, `-w <workspace>`) are not package names.
  const names = parseArgs(prog, rest).operands.filter((a) => !/^[a-z][a-z0-9+.-]*:\/\//i.test(a));
  if (names.length === 0) return { category: 'install', sentence: `Install this project's dependencies (${label})` };
  const shown = names.slice(0, 3).map((n) => quoted(n, 40));
  const noun = SYSTEM_PKG.has(prog) ? 'system software' : names.length === 1 ? 'a package' : `${names.length} packages`;
  return { category: 'install', sentence: `Install ${noun}: ${shown.join(', ')}${andMore(names.length - shown.length)} (${label})` };
}

/** HTTP client options that send a body (`-d@file`, `--data=x`, `-T f`). */
const SENDS_BODY = /^(?:-[dFT].*|--(?:data(?:-\w+)?|form(?:-string)?|upload-file|json|post-data|post-file|body-data|body-file)(?:=.*)?)$/;
const WRITE_METHOD = /^(?:POST|PUT|PATCH|DELETE)$/i;

/** The host an HTTP client talks to, through the target gate, or null. */
function httpHost(prog: string, args: string[]): string | null {
  const pos = operands(prog, args);
  const url = pos.find((a) => /^[a-z][a-z0-9+.-]*:\/\//i.test(a)) ?? pos.find((a) => /^[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:[/:]|$)/.test(a));
  return url ? safeHost(/^[a-z][a-z0-9+.-]*:\/\//i.test(url) ? url : `https://${url}`) : null;
}

function describeNetworkTool(prog: string, args: string[], ctx: ShellContext, writes: string[]): Described | null {
  if (HTTP_CLIENTS.has(prog)) {
    const host = httpHost(prog, args);
    const sends = args.some((a) => SENDS_BODY.test(a))
      || args.some((a, i) => /^(?:-X|--request|--method)$/.test(a) && WRITE_METHOD.test(args[i + 1] ?? ''))
      || args.some((a) => /^(?:-X|--request=|--method=)(?:POST|PUT|PATCH|DELETE)$/i.test(a));
    const egress = ctx.signals.some((s) => /egress|exfil/.test(s));
    const verb = sends || egress ? 'Send data to' : 'Download from';
    // R3: where the download lands is part of WHAT it does.
    const outputs = [...(writerOutputs(prog, args)?.outputs ?? []), ...writes.filter((w) => !isBitBucket(w))];
    if (outputs.length > 0) {
      const dest = mostSensitive(outputs);
      return { category: 'network', sentence: `${verb} ${host ?? 'a web address it could not show safely'} and write to ${quoted(dest)}${andMore(outputs.length - 1)}` };
    }
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
    const host = operands(prog, args)
      .filter((a) => (/[A-Za-z]/.test(a) ? /^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/.test(a) : /^\d{1,3}(?:\.\d{1,3}){3}$/.test(a)))
      .map((a) => safeHost(`x@${a}`)).find((h) => h && !isWithheld(h));
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
  // PID 0 is the caller's own process group (#648 r3 R5).
  if (targets.some((t) => /^0+$/.test(t))) return { category: 'stop', sentence: 'Stop all programs in this group' };
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

const DISK_SIGNAL_RE = /disk|block-device|format-filesystem|shred-device|dd-overwrite/;

/** A step after its wrappers. `feed` is the download whose output an
 *  interpreter in the same pipeline runs (#648 r3 R5). */
interface Step {
  seg: Segment;
  u: Unwrapped;
  feed?: Step;
}

function describeProgram(step: Step, ctx: ShellContext): Described | null {
  const { seg } = step;
  const { prog, argv0, args } = step.u;
  if (!prog) {
    return seg.writes.length > 0 ? { category: 'write', sentence: pathPhrase('Write to', seg.writes) } : null;
  }
  if (!isTrustedProgram(argv0)) {
    // Not the system's own program, whatever it is called (#648 r2 S4).
    const dir = dirname(argv0);
    const where = dir === '.' ? 'this folder' : quoted(dir, 40);
    return { category: 'script', sentence: `Run a program from ${where}: ${quoted(argv0)}` };
  }
  const writes = seg.writes.filter((w) => !isBitBucket(w));
  const pos = operands(prog, args);
  if (READERS.has(prog)) {
    // `cat SRC > DST` copies SRC: the card names the source, not just the
    // harmless-looking destination (#648 r2 S3). `sort -o`, `uniq IN OUT`
    // and `xxd IN OUT` write as well (#648 r3 R3).
    const io = writerOutputs(prog, args);
    const inputs = io ? io.inputs : pos;
    const outputs = [...(io?.outputs ?? []), ...writes];
    if (outputs.length > 0) {
      const dest = mostSensitive(outputs);
      const more = andMore(outputs.length - 1);
      if (inputs.length > 0) return { category: 'move', sentence: `${copyPhrase(inputs, dest)}${more}` };
      return { category: 'write', sentence: `${pathPhrase('Write to', [dest])}${more}` };
    }
    if (prog === 'yq' && args.some((a) => /^(?:-i|--inplace)$/.test(a))) {
      const files = pos.slice(/^(?:e|eval|ea|eval-all)$/.test(pos[0] ?? '') ? 2 : 1);
      return files.length > 0 ? { category: 'write', sentence: pathPhrase('Change', files) } : null;
    }
    const inputsRead = inputs.length > 0 ? inputs : seg.reads;
    if (inputsRead.length === 0) return { category: 'read', sentence: `Read input (${prog})` };
    return { category: 'read', sentence: pathPhrase('Read', inputsRead) };
  }
  if (SEARCHERS.has(prog)) {
    // With `-e PATTERN` / `-f FILE` the pattern is not an operand.
    const patternByFlag = args.some((a) => /^(?:-[ef]|--regexp|--file)(?:=.*)?$/.test(a));
    const files = patternByFlag ? pos : pos.slice(1);
    return files.length === 0
      ? { category: 'read', sentence: `Search inside files (${prog})` }
      : { category: 'read', sentence: pathPhrase('Search inside', files) };
  }
  if (DELETERS.has(prog)) {
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
    const root = args[0] && !args[0].startsWith('-') && !args[0].startsWith('(') && args[0] !== '!' ? quoted(args[0]) : null;
    if (deletes) return { category: 'delete', sentence: `Delete the files it finds under: ${root ?? 'the current folder'}` };
    return { category: 'read', sentence: root ? `Search for files under: ${root}` : 'Search for files' };
  }
  if (prog === 'mv' || prog === 'cp' || prog === 'install' || prog === 'ln') {
    const p = parseArgs(prog, args);
    // `-t DIR` names the destination up front; every operand is a source (#648 r3 R3).
    const targetDir = optionValues(p, ['-t', '--target-directory']).pop();
    if (prog === 'install' && args.some((a) => /^(?:-[A-Za-z]*d[A-Za-z]*|--directory)$/.test(a))) {
      return pos.length > 0 ? { category: 'write', sentence: `Create a folder: ${quoted(mostSensitive(pos))}${andMore(pos.length - 1)}` } : null;
    }
    if (pos.length === 0) return { category: 'move', sentence: `Move or copy files (${prog})` };
    const dst = targetDir ?? (pos.length > 1 ? pos[pos.length - 1] : null);
    const sources = targetDir !== undefined || !dst ? pos : pos.slice(0, -1);
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
    const scriptByFlag = prog === 'sed' && args.some((a) => /^(?:-[ef]|--expression|--file)(?:=.*)?$/.test(a));
    const files = prog === 'sed' && !scriptByFlag ? pos.slice(1) : pos;
    if (files.length === 0) return { category: 'write', sentence: `Change a file (${prog})` };
    if (prog === 'truncate') return { category: 'write', sentence: pathPhrase('Empty', files) };
    if (prog === 'mkdir') return { category: 'write', sentence: `Create a folder: ${quoted(files[0])}${andMore(files.length - 1)}` };
    return { category: 'write', sentence: pathPhrase(EDITORS.has(prog) ? 'Edit' : 'Change', files) };
  }
  if (writes.length > 0 && (prog === 'echo' || prog === 'printf')) {
    return { category: 'write', sentence: pathPhrase('Write to', writes) };
  }
  if (prog === 'git') return describeGit(args, ctx);
  if (INTERPRETERS.has(prog)) {
    const run = interpreterRun(prog, args);
    if (run.stdin && step.feed) {
      // A download piped into an interpreter: one action, in the owner's words (#648 r3 R5).
      const host = httpHost(step.feed.u.prog, step.feed.u.args);
      return { category: 'fetch-run', sentence: `Download from ${host ?? 'a web address it could not show safely'} and run it` };
    }
    if (run.module !== undefined) return { category: 'script', sentence: `Run the ${quoted(run.module, 40)} module (${prog})` };
    if (run.script !== undefined) {
      const script = run.script;
      return LOOKS_LIKE_FILE.test(script)
        ? { category: 'script', sentence: `Run a script: ${quoted(script)} (${prog})` }
        : { category: 'script', sentence: `Run a ${prog} script (name not shown)` };
    }
    return null;
  }
  const net = describeNetworkTool(prog, args, ctx, writes);
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
  const shown = safeProgram(prog);
  if (!shown) return null;
  // Only an allowlisted subcommand word of a known tool (#648 r2 S8): the
  // first argument of anything else is free-form and may be a secret.
  const sub = args[0] && own(SUBCOMMANDS, prog)?.has(args[0]) ? args[0] : null;
  return { category: 'other', sentence: `Run ${shown}${sub ? ` ${sub}` : ''} (other details not shown)` };
}

/** Programs whose sentence already names where they write. */
const NAMES_OWN_WRITES = new Set([...READERS, ...HTTP_CLIENTS, 'echo', 'printf', 'tee']);

/** One step as a sentence: the program's, then where its redirects write
 *  (#648 r3 R3), then the privilege marker. */
function describeStep(step: Step, ctx: ShellContext): (Described & { step: Step }) | null {
  const base = describeProgram(step, ctx);
  if (!base) return null;
  let sentence = base.sentence;
  const writes = step.seg.writes.filter((w) => !isBitBucket(w));
  if (writes.length > 0 && step.u.prog && !NAMES_OWN_WRITES.has(step.u.prog)) {
    const dest = mostSensitive(writes);
    if (!sentence.includes(quoted(dest))) sentence = `${sentence} and write to ${quoted(dest)}${andMore(writes.length - 1)}`;
  }
  if (step.u.sudo === 'admin') sentence = `${sentence}, as administrator (sudo)`;
  if (step.u.sudo === 'user') sentence = `${sentence}, as another user (sudo)`;
  return { ...base, sentence, step };
}

/** Which kind of step each signal is about: used only inside the one
 *  pipeline the guard itself pins a signal to (see `describeShell`). Kinds
 *  are tried in order, so a download that is run outranks the download. */
const SIGNAL_CATEGORIES: Array<[RegExp, Category[]]> = [
  [/^(?:touch-|credential-access|modify-shell-startup|disable-action-guard)/, ['read', 'write', 'delete', 'move', 'perms', 'script']],
  [/pipe-download/, ['fetch-run', 'network']],
  [/egress|exfil/, ['network']],
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

const SEVERITY_RANK: Readonly<Record<string, number>> = { benign: 0, sensitive: 1, dangerous: 2, catastrophic: 3 };
/** Steps (and pipelines) the guard is re-run on to find the risky one. */
const MAX_ATTRIBUTED = 32;

/** The guard's own verdict on one piece of the command. Pure and
 *  synchronous; any failure reads as "tripped nothing". */
function guardOn(text: string): { signals: readonly string[]; rank: number } {
  try {
    const v = evaluateToolCall('Bash', { command: text });
    return { signals: Array.isArray(v.signals) ? v.signals : [], rank: own(SEVERITY_RANK, String(v.severity)) ?? 0 };
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
    const verdict = guardOn(text);
    const hits = verdict.signals.filter((s) => wanted.has(s)).length;
    if (hits === 0) return;
    if (verdict.rank > bestRank || (verdict.rank === bestRank && hits > bestHits)) {
      best = i;
      bestRank = verdict.rank;
      bestHits = hits;
    }
  });
  return best;
}

/** What `describeAction` / `describeShell` say, and how sure they are. */
export interface ActionDescription {
  /** Line 1, ready for the card. */
  text: string;
  /** False when the text is a generic or "could not summarise" line. */
  confident: boolean;
  /** Which entries of `OUTSIDE_UNDERSTOOD_SUBSET` the command met. */
  doubts: readonly ShellDoubt[];
}

/** The confidence gate's switch. Mutation checks only; nothing sets it off. */
const GATE = { enabled: true };
/** @internal Tests only: prove the gate is load-bearing by switching it off. */
export function __setConfidenceGateForTest(enabled: boolean): void {
  GATE.enabled = enabled;
}

/**
 * Line 1 for a shell command (#648 r3 R1: correct or generic, never
 * confidently wrong).
 *
 * Every step is checked against `OUTSIDE_UNDERSTOOD_SUBSET` first; one hit
 * anywhere makes the WHAT `GENERIC_SHELL`. Only then is a step described: a
 * multi-step command by the step that tripped the guard, never simply the
 * first one (#648 r2 S3) — the guard is re-run on each step, and the most
 * dangerous step carrying one of the verdict's signals is named. A signal
 * that only a whole pipeline trips (a download piped into an interpreter) is
 * pinned to that pipeline, and the step is chosen inside it. When nothing can
 * be pinned, the card says so instead of guessing. Last, every write to a
 * sensitive path must appear in the sentence, or it goes generic (R3).
 */
export function describeShell(command: string, ctxIn: ShellContext): ActionDescription {
  const ctx: ShellContext = { ...ctxIn };
  const { segments, pipelines, truncated, doubts } = parseShell(command);
  const tooLong = truncated ? ` ${COMMAND_TOO_LONG}` : '';
  const generic = (): ActionDescription => ({ text: `${GENERIC_SHELL}${tooLong}`, confident: false, doubts: [...doubts] });
  if (segments.length === 0) return { text: `${UNSUMMARISABLE_SHELL}${tooLong}`, confident: false, doubts: [...doubts] };
  if (segments.length > MAX_STEPS) doubts.add('too-many-steps');
  const steps: Step[] = [];
  let dirChanged = false;
  for (const seg of segments.slice(0, MAX_STEPS)) {
    const u = unwrap(seg);
    const step: Step = { seg, u };
    // An interpreter reading stdin from a download earlier in its pipeline.
    const feed = steps.find((s) => s.seg.pipeline === seg.pipeline && HTTP_CLIENTS.has(s.u.prog) && isTrustedProgram(s.u.argv0));
    if (feed && INTERPRETERS.has(u.prog) && isTrustedProgram(u.argv0) && interpreterRun(u.prog, u.args).stdin) step.feed = feed;
    for (const d of stepDoubts(seg, u, dirChanged, step.feed !== undefined)) doubts.add(d);
    if (['cd', 'pushd', 'popd'].includes(u.prog) || u.chdir) dirChanged = true;
    steps.push(step);
  }
  // A truncated command has an unseen tail: it cannot be "fully understood".
  const outside = truncated || [...doubts].some((d) => OUTSIDE_UNDERSTOOD_SUBSET[d].effect === 'generic');
  if (GATE.enabled && outside) return generic();
  ctx.dropGitHost = doubts.has('git-repo-option');
  let chosen: ReturnType<typeof describeStep> = null;
  if (steps.length === 1) {
    chosen = describeStep(steps[0], ctx);
  } else {
    const wanted = new Set(ctx.signals);
    const index = riskiest(steps.map((s) => s.seg.raw), wanted);
    if (index !== -1) {
      chosen = describeStep(steps[index], ctx);
    } else {
      const pipe = riskiest(pipelines, wanted);
      const inPipe = steps.filter((s) => s.seg.pipeline === pipe).map((s) => describeStep(s, ctx));
      for (const signal of ctx.signals) {
        const kinds = SIGNAL_CATEGORIES.find(([re]) => re.test(signal))?.[1] ?? [];
        for (const kind of kinds) {
          chosen = inPipe.find((d) => d?.category === kind) ?? null;
          if (chosen) break;
        }
        if (chosen) break;
      }
    }
    if (!chosen) return { text: `${UNATTRIBUTED_SHELL}${tooLong}`, confident: false, doubts: [...doubts] };
  }
  if (!chosen) return { text: `${UNSUMMARISABLE_SHELL}${tooLong}`, confident: false, doubts: [...doubts] };
  // A download that is run is one action with the step that runs it.
  const others = steps.length - 1 - (chosen.step.feed ? 1 : 0);
  const more = others > 0 ? ` (+${others} more step${others === 1 ? '' : 's'})` : '';
  const text = `${chosen.sentence}${more}${tooLong}`;
  // R3: a write to a sensitive path, anywhere in the command, is named — or
  // the WHAT goes generic rather than leave it out.
  const sensitiveWrites = steps.flatMap((s) => [...s.seg.writes, ...(writerOutputs(s.u.prog, s.u.args)?.outputs ?? [])]).filter(isSensitiveWrite);
  if (GATE.enabled && sensitiveWrites.some((w) => !text.includes(quoted(w)) && !text.includes(quoted(w, 40)))) {
    doubts.add('hidden-write');
    return generic();
  }
  return { text, confident: true, doubts: [...doubts] };
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
  /** Tests only: the system-level git config files (default: the real ones). */
  gitSystemConfig?: readonly string[];
}

/** Line 1: what it wants to do, in plain English, naming the target — and
 *  whether that line is a specific, fully understood summary (#648 r3 R1). */
export function describeAction(a: ApprovalCardActionInput): ActionDescription {
  const args = (a.input && typeof a.input === 'object' && !Array.isArray(a.input) ? a.input : {}) as Record<string, unknown>;
  const signals = Array.isArray(a.signals) ? a.signals.map(String) : [];
  const ctx: ShellContext = { signals, cwd: a.cwd, agentPid: a.agentPid, procRoot: a.procRoot, gitSystemConfig: a.gitSystemConfig };
  const raw = String(a.tool ?? '');
  const sure = (text: string): ActionDescription => ({ text, confident: true, doubts: [] });
  try {
    const n = normaliseToolName(raw);
    if (/^(?:killshell|killbash|taskstop)$/.test(n)) return sure('Stop a background command it started');
    if (raw.trim().toLowerCase() === 'process') {
      const verb = typeof args.action === 'string' ? args.action.trim().toLowerCase().replace(/_/g, '-') : '';
      return sure(own(NATIVE_PROCESS_ACTIONS, verb) ?? 'Control a running command');
    }
    if (n === 'websearch' || n === 'web_search') return sure('Search the web');
    if (n === 'task' || n === 'sessions_spawn' || n === 'agent') return sure('Start a helper agent');
    if (n === 'apply_patch') return sure('Apply a patch to files');
    const family = classifyFamily(raw);
    if (family === 'exec') {
      const command = extractCommand(args);
      return command ? describeShell(command, ctx) : { text: UNSUMMARISABLE_SHELL, confident: false, doubts: [] };
    }
    const path = extractPath(args);
    if (family === 'read') {
      if (/^(?:glob|grep|search|find|ls|list|list_files)$/.test(n)) return sure(path ? `Search files in: ${quoted(path)}` : 'Search files in the current folder');
      return sure(path ? pathPhrase('Read', [path]) : `Read a file (${safeToolLabel(raw)})`);
    }
    if (family === 'write') {
      if (!path) return sure(`Change files (${safeToolLabel(raw)})`);
      return sure(pathPhrase(/^(?:write|create|write_file)$/.test(n) ? 'Write' : 'Change', [path]));
    }
    if (family === 'delete') return sure(path ? pathPhrase('Delete', [path]) : `Delete something (${safeToolLabel(raw)})`);
    if (family === 'network') {
      const url = extractUrl(args, raw);
      const first = url.split(/[\s,]+/)[0] ?? '';
      const host = first ? (safeHost(first) ?? safeHost(`https://${first.replace(/^[^@]*@/, '')}`)) : null;
      if (/fetch|curl|wget|http|request|download/.test(n)) return sure(host ? `Fetch a web page from ${host}` : 'Fetch a web page');
      return sure(host ? `Send data to ${host} (${safeToolLabel(raw)})` : `Send data off this machine (${safeToolLabel(raw)})`);
    }
    if (family === 'git') return sure(`Change the git repository (${safeToolLabel(raw)})`);
    if (family === 'memory') return sure("Change the agent's memory");
  } catch {
    /* fall through to the honest line */
  }
  return { text: `Use ${safeToolLabel(raw)} (details withheld: could not summarise safely)`, confident: false, doubts: [] };
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
  const label = (kind && own(CHANNEL_LABELS, kind.toLowerCase())) ?? 'session';
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
    action: describeAction(input).text,
    reason: describeSignals(input.signals),
    who: describeWho(input),
  };
}

/** One card line: every line break becomes a space and every invisible
 *  format character is shown as `<U+XXXX>` (#648 r2 S9) — the fields may have
 *  crossed a process boundary since they were built. */
function flattenCardText(text: unknown): string {
  return String(text ?? '')
    .replace(CARD_HIDDEN_ALL, codePointLabel)
    .replace(CARD_LINE_BREAKS_ALL, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/** Trailing markers a clipped line always keeps (#648 r2 S5, S6). Shared
 *  with the plugin's card lines and pinned equal by test (#648 r3 R4). */
export const CARD_TAIL_MARKERS = /(?:, as (?:administrator|another user) \(sudo\)| \(\+\d+ more (?:steps?|reasons?)\)| \(part of it is built as it runs\)| \(command too long to summarise fully\)| and \d+ more)+$/;

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
  const tail = CARD_TAIL_MARKERS.exec(one)?.[0] ?? '';
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
