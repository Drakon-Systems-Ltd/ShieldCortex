/**
 * Iron Dome — Session Action Lease
 *
 * WHY THIS EXISTS (10 Aug 2026, and it is not hypothetical)
 * ---------------------------------------------------------
 * A single agent identity routinely runs as many concurrent processes: the
 * interactive session, ~20 isolated cron agents, sub-agents. They share a
 * filesystem and a name but cannot read each other's context. On 10 Aug that
 * cost one operator, in four hours:
 *
 *   - 11:14Z  a package published to the public npm registry, unauthorised and
 *             irreversible, by one session while another was still debating
 *             whether it could be installed internally
 *   - 11:29Z  a session announced to the fleet: nobody installs this until an
 *             independent review
 *   - 11:30Z  a DIFFERENT session installed it on two machines — 77 seconds
 *             after that freeze, having never seen it
 *
 * Nobody defied anything. The freeze lived in one context window, and a
 * commitment no other process can read binds nobody.
 *
 * The guard already answers "should this action proceed?" for content and
 * privilege. This adds the two questions a context window cannot answer:
 *
 *   1. Is a standing FREEZE in force for this class of action?
 *   2. Is another live session already holding it?
 *
 * DESIGN
 * ------
 * Pure decision, injected state. Nothing here touches disk: callers supply the
 * ledger text and the lease record, so every branch is testable and the same
 * logic serves both enforcement surfaces (the OpenClaw interceptor and the
 * Claude Code hook) without a shared runtime.
 *
 * FAILS CLOSED on an unreadable ledger. "I could not read the freezes" and
 * "nothing is frozen" must never produce the same behaviour — that equivalence
 * is precisely how a guard becomes decoration.
 */

/** Action classes worth serialising across sessions. Each is something that
 *  changed the world on 10 Aug without a second session knowing. */
export type LeaseScope =
  | 'npm-publish'
  | 'install'
  | 'gateway-restart'
  | 'security-config'
  | 'fleet-broadcast';

/**
 * Keywords that mean each scope, declared EXPLICITLY.
 *
 * An earlier stem-matching version let `install` sail past a freeze written
 * `installing` (guard silently off), then matched `instruction` to the same
 * freeze (guard fires on the wrong thing). Both failures are worse than a list
 * a human can read and audit, so the list is the design.
 */
export const SCOPE_KEYWORDS: Record<LeaseScope, readonly string[]> = {
  'npm-publish': ['publish', 'npm', 'registry'],
  install: ['install', 'upgrad'],
  'gateway-restart': ['gateway restart', 'restart the gateway', 'gateway restarts'],
  'security-config': ['security compon', 'trust key', 'guard posture', 'operatorpubkey'],
  'fleet-broadcast': ['broadcast', 'fleet directive'],
};

export interface LeaseRecord {
  holder: string;
  pid?: number | null;
  reason?: string;
  acquiredAtMs?: number;
  expiresAtMs?: number;
}

export interface LeaseCheckInput {
  scope: LeaseScope;
  /** Raw DECISIONS.md text, or null when it could not be read. */
  ledger: string | null;
  /** The lease currently on disk for this scope, or null when free. */
  held: LeaseRecord | null;
  /** Identity of the session asking — a holder may re-enter its own lease. */
  self: string;
  nowMs: number;
  /**
   * Injected liveness of `held.pid` (#438). Pure core does not probe the
   * process table. Store layer sets this after a same-host check.
   *
   *   - false: recorded PID is present and confirmed dead → treat as free
   *   - true / omitted: fail closed; a live or unconfirmed holder still binds
   *
   * A blank/missing PID is never a skeleton key even when this is false.
   */
  holderAlive?: boolean;
}

export type LeaseVerdict = 'allow' | 'frozen' | 'held' | 'unknown';

export interface LeaseDecision {
  verdict: LeaseVerdict;
  /** Operator-facing explanation. Never bare "denied": a refusal that does not
   *  say WHY, and who can lift it, is a refusal that gets routed around. */
  reason: string;
  /** The freeze record quoted verbatim, when one applies. */
  freeze?: string;
}

/**
 * Split DECISIONS.md into logical records.
 *
 * Records wrap across physical lines. A line-by-line version read only the
 * first fragment of every freeze and so never saw "gateway restarts", which sat
 * on a continuation line — the freeze was live, formatted innocently, and
 * silently unenforced. Blank lines separate records; everything else is joined.
 */
export function parseFreezeRecords(ledger: string): string[] {
  return ledger
    .split(/\n\s*\n/)
    .map((block) => block.split(/\s+/).join(' ').trim())
    .filter((record) => record.includes('| FROZEN |'));
}

/**
 * Default TTL applied when a lease record carries no explicit expiry — the
 * same 10-minute window the approvals store uses. A record with NO expiry and
 * NO acquisition time is malformed (our writer always stamps both) and is
 * treated as free: it cannot have been written by this subsystem, and treating
 * it as held-forever would hand a wedge-the-fleet primitive to anything that
 * can drop a JSON fragment in the store.
 */
export const DEFAULT_LEASE_TTL_MS = 10 * 60 * 1000;

/**
 * Strip control characters from ledger text before it is echoed into an
 * operator-facing reason. The ledger is operator-owned but its CONTENT is
 * still untrusted at echo time — a freeze record is quoted into terminal
 * output and audit rows, and ANSI escapes or bells in a quoted record would
 * let ledger text style or spoof the very message explaining it.
 */
function sanitiseLedgerText(text: string): string {
  // eslint-disable-next-line no-control-regex
  return text.replace(/[\u0000-\u001F\u007F]/g, ' ');
}

/** The first freeze record naming this scope, or null. */
export function findFreeze(ledger: string, scope: LeaseScope): string | null {
  const keywords = SCOPE_KEYWORDS[scope] ?? [];
  for (const record of parseFreezeRecords(ledger)) {
    const lowered = record.toLowerCase();
    if (keywords.some((k) => lowered.includes(k))) return record;
  }
  return null;
}

/**
 * Decide whether this session may take the action.
 *
 * Order matters: a FREEZE outranks lease availability. An unheld lease on a
 * frozen scope is still a refusal — otherwise the first session to arrive after
 * a freeze would sail through, which is exactly the 11:30 install.
 */
export function checkSessionLease(input: LeaseCheckInput): LeaseDecision {
  const { scope, ledger, held, self, nowMs } = input;

  // An unrecognised scope is a CONFIG error, not an absence of freezes. A
  // caller passing a scope this module has no keywords for would search the
  // ledger with an empty keyword list, find nothing, and allow — turning a
  // typo into a silent bypass. Refuse instead.
  if (!Object.prototype.hasOwnProperty.call(SCOPE_KEYWORDS, scope)) {
    return {
      verdict: 'unknown',
      reason:
        `"${String(scope).slice(0, 60)}" is not a recognised lease scope — refusing rather ` +
        `than treating a configuration error as "nothing is frozen"`,
    };
  }

  if (ledger == null) {
    return {
      verdict: 'unknown',
      reason:
        `cannot read the decisions ledger, so cannot know whether ${scope} is frozen — ` +
        `refusing rather than assuming it is clear`,
    };
  }

  const freeze = findFreeze(ledger, scope);
  if (freeze) {
    // Sanitised before echo: the quoted record travels into terminal output
    // and audit rows, and must not carry ANSI/control bytes from the ledger.
    const safeFreeze = sanitiseLedgerText(freeze);
    return {
      verdict: 'frozen',
      freeze: safeFreeze,
      reason:
        `${scope} is FROZEN by a standing decision: "${safeFreeze.slice(0, 180)}". ` +
        `A freeze is lifted by the operator editing DECISIONS.md — never by an agent ` +
        `deciding it does not apply to this case.`,
    };
  }

  if (held) {
    // An expired lease is not a held one; a crashed session must not wedge the
    // fleet forever, which is why every lease carries a TTL. A record WITHOUT
    // an explicit expiry gets one derived from its acquisition time + the
    // default TTL; a record with neither timestamp is malformed (our writer
    // always stamps both) and is treated as free — held-forever would be a
    // wedge-the-fleet primitive for anything able to drop a JSON fragment.
    const effectiveExpiry =
      held.expiresAtMs ??
      (held.acquiredAtMs != null ? held.acquiredAtMs + DEFAULT_LEASE_TTL_MS : null);
    const expired = effectiveExpiry == null || nowMs > effectiveExpiry;
    if (!expired) {
      // Re-entrancy: the holder may continue its own work. Without this a
      // multi-step action (acquire, then several tool calls) would deadlock
      // against itself and teach operators to disable the gate. A BLANK
      // identity never re-enters: two identity-less processes are not the
      // same session, and emptiness must not become a skeleton key.
      if (held.holder === self && self.trim() !== '') {
        return { verdict: 'allow', reason: `${scope} lease already held by this session` };
      }
      // #438: a crashed hook still wedges the scope for the full TTL unless
      // we reap a holder whose PID is present and confirmed dead. Missing /
      // non-positive / unconfirmed PIDs stay held — a blank pid must not
      // become a skeleton key, and "cannot know" must not behave like dead.
      const pid = held.pid;
      const pidPresent = typeof pid === 'number' && Number.isInteger(pid) && pid > 0;
      if (pidPresent && input.holderAlive === false) {
        return {
          verdict: 'allow',
          reason:
            `${scope} lease holder pid ${pid} is dead — treating the slot as free ` +
            `rather than waiting out the TTL`,
        };
      }
      const ageSec = held.acquiredAtMs != null ? Math.round((nowMs - held.acquiredAtMs) / 1000) : null;
      return {
        verdict: 'held',
        reason:
          `${scope} is held by another session (${held.holder}` +
          (held.pid != null ? `, pid ${held.pid}` : '') +
          (ageSec != null ? `, ${ageSec}s ago` : '') +
          `)${held.reason ? `: ${held.reason}` : ''}. Wait for it to finish or expire — do not force it.`,
      };
    }
  }

  return { verdict: 'allow', reason: `${scope} is neither frozen nor held` };
}

/** Whether a verdict permits the action. Single definition so no caller can
 *  invent its own idea of which verdicts are safe. */
export function leasePermits(decision: LeaseDecision): boolean {
  return decision.verdict === 'allow';
}

// ── Scope mapping — tool call → lease scope ─────────────────────────────────

/**
 * Command patterns per scope, judged on the COMMAND SURFACE the guard judges,
 * never the tool name (#183: gating on tool name missed the same action taken
 * through a different tool). Explicit and auditable, like SCOPE_KEYWORDS:
 * a human must be able to read this table and know exactly which commands a
 * freeze binds.
 *
 * Deliberately narrow. `npm install` with no -g is a routine dev action inside
 * a working tree; the 10 Aug incident was FLEET-HOST installs (global npm,
 * OpenClaw plugin installs). A mapper that taxes every dev action teaches
 * operators to lift freezes, which is worse than a narrow one.
 *
 * Anchored on a COMMAND BOUNDARY (start, or after a shell separator/env
 * prefix — the guard's own `(?:^|[;&|(\n]|\$\()` idiom), so a scope word that
 * merely appears inside a quoted argument (`echo "how to npm publish"`, `grep
 * "npm publish"`) does NOT match. The install check is order-independent: a
 * package manager on the surface + an install verb + a global marker anywhere,
 * because `npm --global install` and `npm --location=global install` are real
 * global installs that a fixed `npm install … -g` order silently missed.
 */
const CMD_BOUNDARY = '(?:^|[\\n;&|(]|\\$\\()\\s*(?:\\w+=\\S*\\s+)*(?:sudo\\s+)?';
const PKG_MGR = '(?:npm|pnpm|yarn|bun)';

const SCOPE_COMMAND_PATTERNS: ReadonlyArray<{ scope: LeaseScope; re: RegExp }> = [
  { scope: 'npm-publish', re: new RegExp(`${CMD_BOUNDARY}${PKG_MGR}\\s+publish\\b`, 'i') },
  { scope: 'npm-publish', re: new RegExp(`${CMD_BOUNDARY}git\\s+push\\b[^|;&\\n]*(?:--(?:tags|follow-tags)\\b|\\srefs\\/tags\\/|\\sv\\d+\\.\\d+\\.\\d+)`, 'i') },
  { scope: 'gateway-restart', re: new RegExp(`${CMD_BOUNDARY}(?:openclaw\\s+)?gateway\\s+(?:restart|stop|kickstart)\\b`, 'i') },
  { scope: 'gateway-restart', re: /\blaunchctl\s+(?:kickstart|bootout|bootstrap)\b[^|;&\n]*(?:openclaw|gateway)/i },
  { scope: 'gateway-restart', re: /\bsystemctl\s+(?:restart|stop|start)\b[^|;&\n]*gateway/i },
  // security-config is NOT a regex row: naming the file is not editing the
  // file. See securityConfigWriteShape (#550).
  { scope: 'fleet-broadcast', re: new RegExp(`${CMD_BOUNDARY}openclaw\\b[^|;&\\n]*\\b(?:broadcast|message\\s+send)\\b`, 'i') },
];

// ── security-config: a WRITE SHAPE onto a protected file, not a mention ─────
//
// #550: the three path rows used to fire on the path ANYWHERE in the command
// text — a heredoc string literal, a commit message, a grep pattern. Every
// other scope row anchors on a command boundary precisely so a scope word
// inside a quoted argument does not match; these three did not, so a session
// that mentioned the file in a commit message took (and then, through the
// second plane, was refused by) a security-config lease.
//
// The mapper below FAILS CLOSED (#552 review): a command that names a
// protected file on its executable surface takes the lease unless its shape
// is a positively proven read or mention — the file inside a quoted string,
// a comment or a heredoc body; a redirect elsewhere; a verb known to only
// read its operands; the source side of a copy. An unknown verb given the
// file (`curl -o`, `wget -O`, `patch`, `yq -i`, `awk -i inplace`, `git
// restore`) is a write until proven otherwise; a small verb table cannot be
// the thing that decides which writes escape a standing freeze.

/** The protected files, as they end a path token on a command surface. */
const SECURITY_CONFIG_FILE_TAIL_RE = /(?:\.shieldcortex[\\/]+config\.json|\.claude[\\/]+settings\.json|\.openclaw[\\/]+openclaw\.json)$/i;
/** Fast pre-check: the same three files anywhere. Most commands fail this. */
const SECURITY_CONFIG_FILE_ANY_RE = /(?:\.shieldcortex[\\/]+config\.json|\.claude[\\/]+settings\.json|\.openclaw[\\/]+openclaw\.json)/i;

/** Verbs that mutate EVERY path operand they are given (or the named one). */
const MUTATE_ANY_OPERAND_VERBS = new Set([
  'tee', 'rm', 'unlink', 'mv', 'truncate', 'chmod', 'chown', 'chgrp', 'touch', 'shred',
  'sponge', 'patch',
  // editors: opening the file in one is editing it
  'vi', 'vim', 'nvim', 'nano', 'pico', 'emacs', 'code', 'subl', 'gedit', 'ed', 'ex',
]);
/** Verbs whose LAST operand is the destination. A protected SOURCE is a read. */
const COPY_TO_LAST_OPERAND_VERBS = new Set(['cp', 'install', 'ln', 'rsync', 'scp']);
/** grep and friends: `-o` means only-matching, never an output file. */
const GREP_FAMILY_VERBS = new Set(['grep', 'egrep', 'fgrep', 'rg', 'ag', 'ack']);
/**
 * Filters whose optional SECOND operand is an output file (`uniq in out`,
 * `xxd -r in out`). Their option ARGUMENTS shift the operands (#552 r6):
 * `uniq -w 5 in out` has two operands, not three. Per verb: the options
 * that take a value (separate or glued, `-w 5` / `-w5` / `--skip-fields=1`)
 * and the options known to take none. An option in NEITHER set leaves the
 * operand count unproven, and an unproven protected operand fails closed.
 * uniq clusters short flags (`-cw 5`); xxd does not.
 */
const SECOND_OPERAND_OUTPUT_VERBS: Record<string, { valued: Set<string>; bare: Set<string>; clusters: boolean }> = {
  uniq: {
    valued: new Set(['-w', '-f', '-s', '--check-chars', '--skip-fields', '--skip-chars']),
    bare: new Set(['-c', '-d', '-D', '-i', '-u', '-z', '--count', '--repeated', '--all-repeated', '--ignore-case', '--unique', '--zero-terminated', '--group', '--help', '--version']),
    clusters: true,
  },
  xxd: {
    valued: new Set(['-c', '-l', '-s', '-g', '-o', '-R', '-cols', '-len', '-seek', '-groupsize', '-name']),
    bare: new Set(['-a', '-b', '-C', '-d', '-e', '-E', '-i', '-p', '-ps', '-r', '-u', '-v', '-h', '-autoskip', '-bits', '-capitalize', '-include', '-plain', '-postscript', '-revert', '-upper', '-version', '-help']),
    clusters: false,
  },
};

/**
 * The operands of a SECOND_OPERAND_OUTPUT_VERBS command with option values
 * removed, and whether every option was recognised. Fail closed on the
 * unrecognised: the caller treats an unproven protected operand as the output.
 */
function operandsAfterOptions(verb: string, rest: string[]): { operands: string[]; proven: boolean } {
  const spec = SECOND_OPERAND_OUTPUT_VERBS[verb]!;
  const operands: string[] = [];
  let proven = true;
  for (let i = 0; i < rest.length; i++) {
    const raw = rest[i]!;
    const t = unquote(raw);
    if (t === '--') {
      operands.push(...rest.slice(i + 1));
      break;
    }
    if (t === '-' || !t.startsWith('-')) {
      operands.push(raw);
      continue;
    }
    const eq = t.indexOf('=');
    const name = t.startsWith('--') && eq > 0 ? t.slice(0, eq) : t;
    if (spec.valued.has(name)) {
      if (name === t) i++; // separate value
      continue;
    }
    if (spec.bare.has(name)) continue;
    // Glued short value (`-w5`, `-c16`) or a cluster (`-cw5`, `-cw 5`).
    if (!t.startsWith('--')) {
      let consumed = false;
      for (let c = 1; c < t.length; c++) {
        const flag = `-${t[c]!}`;
        if (spec.valued.has(flag)) {
          if (c === t.length - 1) i++; // value is the next token
          consumed = true;
          break;
        }
        if (!spec.clusters || !spec.bare.has(flag)) break;
        if (c === t.length - 1) consumed = true;
      }
      if (consumed) continue;
    }
    proven = false;
  }
  return { operands, proven };
}
/**
 * Verbs that only READ the paths they are given. This is the proven-read
 * relief: a verb NOT listed here, given the file, fails closed.
 */
const READ_ONLY_VERBS = new Set([
  'cat', 'jq', 'diff', 'cmp', 'ls', 'stat', 'file', 'wc', 'head', 'tail', 'less', 'more', 'bat',
  'grep', 'egrep', 'fgrep', 'rg', 'ag', 'ack', 'md5sum', 'sha1sum', 'sha256sum', 'sha512sum',
  'cksum', 'sum', 'strings', 'od', 'hexdump', 'base64', 'cut', 'sort', 'nl',
  'column', 'du', 'df', 'readlink', 'realpath', 'basename', 'dirname', 'test', '[', '[[',
  'echo', 'printf', 'true', 'false', ':', 'type', 'which', 'whereis', 'lsattr', 'getfacl',
]);
/** git subcommands that do not write the working tree. Anything else fails closed. */
const GIT_READ_SUBCOMMANDS = new Set([
  'log', 'diff', 'show', 'status', 'blame', 'grep', 'ls-files', 'ls-tree', 'cat-file',
  'rev-parse', 'rev-list', 'describe', 'branch', 'tag', 'remote', 'add', 'commit', 'push',
  'fetch', 'shortlog', 'whatchanged', 'check-ignore', 'hash-object', 'name-rev', 'var', 'help',
]);
/**
 * Interpreters and shells. A program that is handed the file — inline
 * (`-c`, `-e`, a heredoc) or as an argument to a script — may write it, and
 * the mapper does not parse Python: fail closed on the mention, as the
 * guard's own path-target rules do ("path-target signals skip the
 * interpreter-source downgrade"). Disclosed cost: `node cli.js doctor
 * --config <file>` and `bash -c 'cat <file>'` take a lease they did not need.
 */
const INTERPRETER_VERBS = new Set([
  'python', 'python2', 'python3', 'node', 'nodejs', 'deno', 'bun', 'perl', 'ruby', 'php',
  'eval', 'sh', 'bash', 'zsh', 'dash', 'ksh', 'fish',
]);
/** Wrappers stripped from the front of a stage before the verb is read. */
const WRAPPER_VERBS = new Set([
  'sudo', 'doas', 'env', 'command', 'nohup', 'nice', 'ionice', 'time', 'timeout', 'stdbuf',
  'exec', 'busybox', 'xargs', 'chronic',
]);
/** Wrapper flags that take a SEPARATE argument (`sudo -u root`, `nice -n 10`). */
const WRAPPER_FLAGS_WITH_ARG: Record<string, Set<string>> = {
  sudo: new Set(['-u', '-g', '-U', '-C', '-p', '-h', '-r', '-t', '-T', '-D', '-R', '--user', '--group', '--other-user', '--close-from', '--prompt', '--host', '--role', '--type', '--command-timeout', '--chdir', '--chroot']),
  doas: new Set(['-u', '-C']),
  env: new Set(['-u', '-C', '-S', '--unset', '--chdir', '--split-string']),
  nice: new Set(['-n', '--adjustment']),
  ionice: new Set(['-c', '-n', '-p', '--class', '--classdata', '--pid']),
  timeout: new Set(['-k', '-s', '--kill-after', '--signal']),
  stdbuf: new Set(['-i', '-o', '-e', '--input', '--output', '--error']),
  xargs: new Set(['-I', '-n', '-P', '-d', '-L', '-s', '-a', '-E', '--replace', '--max-args', '--max-procs', '--delimiter', '--max-lines', '--max-chars', '--arg-file', '--eof']),
  exec: new Set(['-a']),
};
/** Wrapper positionals that precede the wrapped command (`timeout 5 cmd`). */
const WRAPPER_POSITIONALS: Record<string, number> = { timeout: 1 };
/** Shell reserved words that can sit where a verb would. */
const RESERVED_WORDS = new Set(['if', 'then', 'else', 'elif', 'do', 'while', 'until', '!', '{', '}', 'fi', 'done', 'esac']);
/** Options that name an OUTPUT whatever the verb (`git diff --output=f`, `curl -o f`, `wget -O f`). */
const OUTPUT_OPTION_RE = /^(?:-o|-O|--(?:output|out|outfile|out-file|output-file|output-document|dest|destination))(?:=(.*))?$/;
/** sed/awk in-place: a leading `-i`, a cluster holding one (`-ni`, `-Ei`, `-i.bak`), or the long form. */
const IN_PLACE_FLAG_RE = /^(?:-[a-zA-Z]*i\S*|--in-place(?:=.*)?|--inplace)$/;

/**
 * The quoting contexts of POSIX/bash text, as ONE state machine shared by
 * every lexer below — so `'` inside `"…"`, `\'` inside `'…'`, `$'…'`, and
 * the quote-less expanding heredoc body are handled as a class, not as a
 * table of spellings found one review at a time.
 *
 * Per character the machine says what the character IS to the shell:
 *  - `bare`      — unquoted, unescaped: operators (`;`, `|`, `#`, `<<`) act.
 *  - `expanding` — inside double quotes or an expanding heredoc body: `$(…)`
 *                  and `` `…` `` still EXECUTE; operators do not act.
 *  - `text`      — inside single quotes / `$'…'`, or escaped: nothing acts.
 *
 * Rules: single quotes end only at the next `'` (a backslash is literal, so
 * `'a\'` is CLOSED). Double quotes: `\` escapes the next character; `'` is
 * text. `$'…'`: `\` escapes, `'` closes. Bare: `\` escapes the next
 * character. Expanding heredoc body: there is no quoting at all — quotes are
 * text — and `\` escapes only `$`, `` ` ``, `\` and a newline.
 *
 * A backslash-newline is a LINE CONTINUATION wherever the backslash is an
 * escape (bare, double quotes, an expanding heredoc body): bash removes both
 * characters, so the next line belongs to the same statement. Single and
 * `$'…'` quotes keep it literal (see lineEnd).
 *
 * A COMMENT is a class of the same machine (#552 r6): in the bare context a
 * `#` at the start of a word (the first character, or after whitespace or
 * one of `;|&(`) opens a comment that runs to the newline. Every character
 * of it is `text` — a `'` or `"` in `# don't` opens nothing, a `)` closes no
 * substitution, a `<<` opens no heredoc, and a trailing `\` is NOT a
 * continuation (bash ends the comment at the newline regardless; verified
 * against bash 5.2 by the r6 probe). The newline that ends it is `bare`.
 * Inside double quotes `#` keeps expanding; `a#b` is one word. An expanding
 * heredoc body has no comments.
 */
type ShellQuote = 'none' | 'single' | 'double' | 'ansi';
type CharRole = 'bare' | 'expanding' | 'text';

class ShellLexer {
  quote: ShellQuote = 'none';
  /** Inside a `#` comment (bare context only), until the next newline. */
  comment = false;
  constructor(private readonly context: 'shell' | 'heredoc-body' = 'shell') {}

  /** Classify `text[i]`; returns the role and the index of the NEXT unread char. */
  step(text: string, i: number): { role: CharRole; next: number } {
    const c = text[i]!;
    if (this.context === 'heredoc-body') {
      if (c === '\\' && (text[i + 1] === '$' || text[i + 1] === '`' || text[i + 1] === '\\' || text[i + 1] === '\n')) {
        return { role: 'text', next: i + 2 };
      }
      return { role: 'expanding', next: i + 1 };
    }
    if (this.comment) {
      if (c === '\n') {
        this.comment = false;
        return { role: 'bare', next: i + 1 };
      }
      return { role: 'text', next: i + 1 };
    }
    switch (this.quote) {
      case 'single':
        if (c === "'") this.quote = 'none';
        return { role: 'text', next: i + 1 };
      case 'ansi':
        if (c === '\\') return { role: 'text', next: i + 2 };
        if (c === "'") this.quote = 'none';
        return { role: 'text', next: i + 1 };
      case 'double':
        if (c === '\\') return { role: 'text', next: i + 2 };
        if (c === '"') {
          this.quote = 'none';
          return { role: 'text', next: i + 1 };
        }
        return { role: 'expanding', next: i + 1 };
      default:
        if (c === '\\') return { role: 'text', next: i + 2 };
        if (c === "'") {
          this.quote = 'single';
          return { role: 'text', next: i + 1 };
        }
        if (c === '"') {
          this.quote = 'double';
          return { role: 'text', next: i + 1 };
        }
        if (c === '$' && text[i + 1] === "'") {
          this.quote = 'ansi';
          return { role: 'text', next: i + 2 };
        }
        if (c === '#' && (i === 0 || /[\s;|&(]/.test(text[i - 1]!))) {
          this.comment = true;
          return { role: 'text', next: i + 1 };
        }
        return { role: 'bare', next: i + 1 };
    }
  }
}

/**
 * How `text` ends, for the line joiner: the quote still open (`'` or `"`),
 * and whether the last character is an ESCAPING backslash — a line
 * continuation. Only the bare and double-quoted contexts continue: inside
 * `'…'` a backslash is literal, and inside `$'…'` bash keeps `\⏎` as text.
 */
function lineEnd(text: string): { quote: string | null; continues: boolean } {
  const lx = new ShellLexer();
  let continues = false;
  for (let i = 0; i < text.length; ) {
    const before = lx.quote;
    const { next } = lx.step(text, i);
    continues = i === text.length - 1 && text[i] === '\\' && next === i + 2 && (before === 'none' || before === 'double');
    i = next;
  }
  const quote = lx.quote === 'double' ? '"' : lx.quote === 'single' || lx.quote === 'ansi' ? "'" : null;
  return { quote, continues };
}

/** Cut a `#` comment off a line — where the lexer says one starts. */
function stripComment(line: string): string {
  const lx = new ShellLexer();
  for (let i = 0; i < line.length; ) {
    const { next } = lx.step(line, i);
    if (lx.comment) return line.slice(0, i);
    i = next;
  }
  return line;
}

const HEREDOC_WORD_END = /[\s;|&<>()]/;

/** A heredoc opened on a line: its delimiter, whether the body is literal, and `<<-`. */
interface HeredocOpen {
  tag: string;
  quoted: boolean;
  /** `<<-`: leading TABS are stripped from body and terminator lines. */
  dash: boolean;
}

/**
 * Read the delimiter WORD after `<<` / `<<-`. bash takes the whole word
 * (`E'O'F`, `"EO"F`, `\EOF` are all the delimiter `EOF`) and treats the body
 * as literal if ANY part of the word was quoted — a backslash counts. ANY
 * word is a delimiter (#552 r6): `<<1`, `<<!`, `<<$$`, `<<.`, `<<--` (that
 * is `<<-` with the delimiter `-`), `<<END-OF-FILE` — the word runs to the
 * next metacharacter. The only thing that keeps `<<` from opening a heredoc
 * is arithmetic (see findHeredocTags); `echo 1<<2` and `let x<<=2` DO open
 * one to bash (delimiters `2` and `=2`), so they open one here.
 */
function parseHeredocWord(text: string, at: number): { tag: string; quoted: boolean } | null {
  let i = at;
  while (i < text.length && (text[i] === ' ' || text[i] === '\t')) i++;
  let tag = '';
  let quoted = false;
  for (; i < text.length; ) {
    const c = text[i]!;
    // `$'…'` and `$"…"` are quotes of the same word; the `$` is not delimiter
    // text. (ANSI-C escapes inside `$'…'` are not expanded here.)
    if (c === '$' && (text[i + 1] === "'" || text[i + 1] === '"')) {
      i++;
      continue;
    }
    if (c === "'") {
      const close = text.indexOf("'", i + 1);
      if (close < 0) return null;
      tag += text.slice(i + 1, close);
      quoted = true;
      i = close + 1;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      for (; j < text.length && text[j] !== '"'; j++) {
        // Inside double quotes only `\$`, `` \` ``, `\"` and `\\` are escapes;
        // any other backslash is part of the word (`"E\OF"` ends on `E\OF`).
        if (text[j] === '\\' && j + 1 < text.length && '$`"\\'.includes(text[j + 1]!)) {
          tag += text[j + 1]!;
          j++;
        } else tag += text[j]!;
      }
      if (j >= text.length) return null;
      quoted = true;
      i = j + 1;
      continue;
    }
    if (c === '\\') {
      if (i + 1 >= text.length) return null;
      tag += text[i + 1]!;
      quoted = true;
      i += 2;
      continue;
    }
    if (HEREDOC_WORD_END.test(c)) break;
    tag += c;
    i++;
  }
  // A QUOTED empty word (`<<''`, `<<""`, `<<$''`) is a valid delimiter: the
  // body ends at the first EMPTY line (#552 r6 addendum). Only a bare empty
  // word is no heredoc (bash: syntax error).
  if (!tag && !quoted) return null;
  return { tag, quoted };
}

/**
 * Every heredoc OPENED on this line, in the order of its `<<` operators —
 * bash reads the bodies in that order, each beginning on the line after the
 * previous terminator (`cat <<A <<B`, `cat <<A; cat <<B`, `diff <(cat <<A)
 * <(cat <<B)`). Quote-, comment- and arithmetic-aware: `echo '<<EOF'`,
 * `# note: << EOF`, `$((1 << WIDTH))` and a bare `(( x = 1 << 2 ))` open
 * nothing — a phantom heredoc would swallow every following line as data.
 */
function findHeredocTags(line: string): HeredocOpen[] {
  const out: HeredocOpen[] = [];
  const lx = new ShellLexer();
  let arith = 0;
  for (let i = 0; i < line.length; ) {
    const { role, next } = lx.step(line, i);
    if (role !== 'bare') {
      i = next;
      continue;
    }
    if (line.startsWith('$((', i) || line.startsWith('((', i)) {
      arith++;
      i += line[i] === '$' ? 3 : 2;
      continue;
    }
    if (arith > 0 && line.startsWith('))', i)) {
      arith--;
      i += 2;
      continue;
    }
    if (arith === 0 && line[i] === '<' && line[i + 1] === '<' && line[i + 2] !== '<' && (i === 0 || line[i - 1] !== '<')) {
      const dash = line[i + 2] === '-';
      const found = parseHeredocWord(line, dash ? i + 3 : i + 2);
      if (found) out.push({ ...found, dash });
    }
    i = next;
  }
  return out;
}

/**
 * Attach heredoc bodies to the parts of a line that opened them: the Nth
 * body goes to the part holding the Nth `<<`. Bodies ride after a NUL each
 * (`header␀bodyA␀bodyB`) — the marker splitPipeline, tokenise and
 * stageWritesProtectedFile rely on. Bodies left over (a count mismatch)
 * go to the last part rather than being dropped.
 */
function attachHeredocBodies(parts: string[], bodies: string[]): string[] {
  if (parts.length === 0 || bodies.length === 0) return parts;
  const out = [...parts];
  let b = 0;
  for (let p = 0; p < out.length && b < bodies.length; p++) {
    const opens = findHeredocTags(out[p]!).length;
    for (let n = 0; n < opens && b < bodies.length; n++, b++) out[p] = `${out[p]!}\u0000${bodies[b]!}`;
  }
  for (; b < bodies.length; b++) out[out.length - 1] = `${out[out.length - 1]!}\u0000${bodies[b]!}`;
  return out;
}

/**
 * Quote-aware: a `;` or `|` inside `python3 -c "a; b"` is program text, not a
 * shell separator — splitting there would hide the file from the interpreter
 * rule and read `json.dump(` as a verb. Quote state comes from ShellLexer, so
 * `"a\"; b"` and `$'a\'; b'` are one string too.
 * Separators: `;`, `&&`, `||`, and a bare `&` (not `>&`, `|&`).
 */
function splitLineOnSeparators(line: string): string[] {
  const out: string[] = [];
  let cur = '';
  const lx = new ShellLexer();
  for (let i = 0; i < line.length; ) {
    const { role, next } = lx.step(line, i);
    if (role !== 'bare') {
      cur += line.slice(i, next);
      i = next;
      continue;
    }
    const c = line[i]!;
    const n = line[i + 1];
    if (c === ';' || ((c === '&' || c === '|') && n === c)) {
      if (cur.trim()) out.push(cur);
      cur = '';
      i += c === ';' ? 1 : 2;
      continue;
    }
    if (c === '&') {
      const prev = cur.length ? cur[cur.length - 1] : '';
      if (prev !== '>' && prev !== '|') {
        if (cur.trim()) out.push(cur);
        cur = '';
        i++;
        continue;
      }
    }
    cur += c;
    i = next;
  }
  if (cur.trim()) out.push(cur);
  return out;
}

/**
 * The bodies of every `$( … )` and backtick substitution in `text` — they
 * EXECUTE wherever the character is `bare` or `expanding` (double quotes,
 * an expanding heredoc body); only `text` (single quotes, `$'…'`, an escape)
 * keeps them literal. `$(( … ))` is arithmetic and holds no command. Nested
 * substitutions are found when the body is judged. A process substitution
 * `<( … )` / `>( … )` executes too, but only where it is `bare` — inside
 * double quotes it is text.
 *
 * `context` says what `text` is: shell surface (quotes act) or the body of
 * an unquoted heredoc (quotes are text; only `\$`, `` \` `` and `\\` escape).
 */
function commandSubstitutionBodies(text: string, context: 'shell' | 'heredoc-body' = 'shell'): string[] {
  const out: string[] = [];
  const lx = new ShellLexer(context);
  for (let i = 0; i < text.length; ) {
    const { role, next } = lx.step(text, i);
    if (role === 'text') {
      i = next;
      continue;
    }
    const c = text[i]!;
    const commandSub = c === '$' && text[i + 1] === '(' && text[i + 2] !== '(';
    const processSub = role === 'bare' && (c === '<' || c === '>') && text[i + 1] === '(';
    if (commandSub || processSub) {
      // The body is shell text of its own: track its quotes so a `)` inside
      // `'…'` or `"…"` does not close it, and balance bare parentheses.
      const inner = new ShellLexer();
      let depth = 1;
      let j = i + 2;
      while (j < text.length && depth > 0) {
        const st = inner.step(text, j);
        if (st.role === 'bare') {
          if (text[j] === '(') depth++;
          else if (text[j] === ')') depth--;
        }
        j = st.next;
      }
      const close = depth === 0 ? j - 1 : Math.min(j, text.length);
      out.push(text.slice(i + 2, close));
      i = Math.max(next, close + 1);
      continue;
    }
    if (c === '`') {
      // Inside backticks `\` escapes `` ` ``, `$` and `\` — bash STRIPS that
      // backslash before running the body, so `` `echo \$(cmd)` `` runs
      // `echo $(cmd)`. Any other backslash stays literal (`\>` is no
      // redirect). The first unescaped backtick closes.
      let j = i + 1;
      let body = '';
      while (j < text.length && text[j] !== '`') {
        if (text[j] === '\\' && j + 1 < text.length) {
          const n = text[j + 1]!;
          body += n === '$' || n === '`' || n === '\\' ? n : `\\${n}`;
          j += 2;
          continue;
        }
        body += text[j]!;
        j++;
      }
      out.push(body);
      i = Math.min(j, text.length) + 1;
      continue;
    }
    i = next;
  }
  return out.filter((b) => b.trim());
}

/**
 * Split a command into statements. A newline inside quotes continues the
 * statement (`python3 -c '⏎…⏎'` is one program); a comment is dropped; a
 * heredoc BODY stays attached to the stage that opened it (`cat > /tmp/x
 * <<'EOF' … EOF` is one statement whose verb is `cat` and whose redirect
 * target is `/tmp/x`; the body is data) and the statements after the
 * terminator are still read.
 */
function splitStatementsHeredocAware(command: string): string[] {
  const lines = command.split('\n');
  const out: string[] = [];
  let i = 0;
  while (i < lines.length) {
    const { code, bodies, next } = readLogicalLine(lines, i);
    // A substitution on the line executes whatever it holds: judge its body
    // as statements of its own (recursively — it may open heredocs and
    // substitutions of its own).
    for (const body of commandSubstitutionBodies(code)) out.push(...splitStatementsHeredocAware(body));
    // Each body rides on the segment of the header that opened it: `cat >
    // /tmp/x <<'EOF' && echo done` keeps the body with `cat`, not `echo`.
    out.push(...attachHeredocBodies(splitLineOnSeparators(code), bodies.map((b) => b.lines.join(' '))));
    // An UNQUOTED delimiter expands the body: a `$( … )` written in it runs.
    // A quoted delimiter (`<<'EOF'`) keeps the body literal.
    for (const b of bodies) {
      if (b.quoted) continue;
      for (const sub of commandSubstitutionBodies(b.lines.join('\n'), 'heredoc-body')) out.push(...splitStatementsHeredocAware(sub));
    }
    i = next;
  }
  return out;
}

/** One heredoc body as read from the lines after its header. */
interface HeredocBody {
  lines: string[];
  quoted: boolean;
}

/**
 * Read ONE logical line starting at `lines[at]`, exactly as bash does
 * (#552 r6, every rule verified against bash 5.2 by the differential probe):
 *
 *  1. Physical lines are joined while the line ends in a continuation or an
 *     open quote (lineEnd) — the HEADER, before any body is read.
 *  2. The comment is cut.
 *  3. The heredocs opened on the header are read in `<<` order, one body
 *     after another; each terminator is the line that EQUALS the delimiter
 *     (for `<<-`, after stripping leading tabs only). `EOF; cmd`, `EOF ` and
 *     ` EOF` are body lines, not terminators. For an UNQUOTED delimiter bash
 *     removes `\⏎` pairs while reading, so `EO\⏎F` joins to `EOF` and ends
 *     the body; a quoted delimiter keeps them literal.
 *  4. A header whose shell text ends in a bare `|`, `|&`, `&&` or `||`
 *     continues on the first line AFTER the bodies: that line is read the
 *     same way (it may open heredocs of its own) and joined to the header,
 *     so the pipeline is one statement (`cat <<EOF |⏎…⏎EOF⏎tee <file>`).
 *
 * Returns the joined shell text, the bodies in `<<` order and the index of
 * the first unread line.
 */
function readLogicalLine(lines: string[], at: number): { code: string; bodies: HeredocBody[]; next: number } {
  let logical = lines[at]!;
  let j = at;
  while (j + 1 < lines.length) {
    const end = lineEnd(logical);
    if (end.continues) {
      // Backslash-newline: bash drops both characters, so `tee \⏎<file>` is
      // one statement whose operand is on the second line.
      j++;
      logical = logical.slice(0, -1) + lines[j]!;
      continue;
    }
    if (end.quote === null) break;
    j++;
    logical += `\n${lines[j]!}`;
  }
  let code = stripComment(logical);
  const bodies: HeredocBody[] = [];
  let k = j + 1;
  for (const open of findHeredocTags(code)) {
    const body: string[] = [];
    for (; k < lines.length; k++) {
      let line = lines[k]!;
      if (!open.quoted) {
        // bash removes `\⏎` from an expanding body as it reads: an odd run
        // of trailing backslashes escapes the newline (`\\⏎` is `\` + end).
        while (k + 1 < lines.length && /(?:^|[^\\])(?:\\\\)*\\$/.test(line)) {
          k++;
          line = line.slice(0, -1) + lines[k]!;
        }
      }
      const candidate = open.dash ? line.replace(/^\t+/, '') : line;
      if (candidate === open.tag) break;
      body.push(line);
    }
    bodies.push({ lines: body, quoted: open.quoted });
    k++;
  }
  if (k < lines.length && endsWithPipelineOperator(code)) {
    const rest = readLogicalLine(lines, k);
    code = `${code} ${rest.code}`;
    bodies.push(...rest.bodies);
    k = rest.next;
  }
  return { code, bodies, next: k };
}

/** True when the bare shell text of `code` ends in `|`, `|&`, `&&` or `||`. */
function endsWithPipelineOperator(code: string): boolean {
  const lx = new ShellLexer();
  let tail = '';
  let inOperator = false;
  for (let i = 0; i < code.length; ) {
    const { role, next } = lx.step(code, i);
    const c = code[i]!;
    if (role === 'bare' && (c === '|' || c === '&')) {
      tail = inOperator ? tail + c : c;
      inOperator = true;
    } else if (role === 'bare' && /\s/.test(c)) {
      inOperator = false;
    } else {
      tail = '';
      inOperator = false;
    }
    i = next;
  }
  return /^(?:\||\|&|&&|\|\|)$/.test(tail);
}

/**
 * Split a statement on single `|` / `|&` outside quotes (`||` is already
 * split). A heredoc body (after the NUL the statement splitter inserted) is
 * data and is never split: a `|` written inside it is text, not a pipe. The
 * body rides on the stage that opened the heredoc (`python3 - <<'EOF' | tee
 * out` keeps the body with `python3`, where the interpreter rule reads it).
 */
function splitPipeline(statement: string): string[] {
  const nul = statement.indexOf('\u0000');
  if (nul >= 0) {
    const stages = splitPipeline(statement.slice(0, nul));
    if (stages.length === 0) return [];
    return attachHeredocBodies(stages, statement.slice(nul + 1).split('\u0000'));
  }
  const out: string[] = [];
  let cur = '';
  const lx = new ShellLexer();
  for (let i = 0; i < statement.length; ) {
    const { role, next } = lx.step(statement, i);
    if (role === 'bare' && statement[i] === '|') {
      if (cur.trim()) out.push(cur.trim());
      cur = '';
      i += statement[i + 1] === '&' ? 2 : 1;
      continue;
    }
    cur += statement.slice(i, next);
    i = next;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

/**
 * Whitespace tokens with quotes respected: `"a > b"` is ONE token, so a
 * redirect written inside a commit message or a string literal is not a
 * redirect. Quotes are kept on the token; callers strip them. An unquoted
 * `>` ends the word before it (`printf x>f` is `printf`, `x`, `>f` to the
 * shell); only an fd digit or `&` stays glued (`2>f`, `&>f`).
 */
function tokenise(stage: string): string[] {
  const toks: string[] = [];
  let cur = '';
  const lx = new ShellLexer();
  for (let i = 0; i < stage.length; ) {
    const { role, next } = lx.step(stage, i);
    if (role !== 'bare') {
      cur += stage.slice(i, next);
      i = next;
      continue;
    }
    const c = stage[i]!;
    if (/\s/.test(c) || c === '\u0000') {
      if (cur) toks.push(cur);
      cur = '';
      i = next;
      continue;
    }
    if (c === '>' && cur && !/^(?:\d|&|>)$/.test(cur)) {
      toks.push(cur);
      cur = '';
    }
    cur += c;
    i = next;
  }
  if (cur) toks.push(cur);
  return toks;
}

function unquote(token: string): string {
  return token.replace(/^[('"`]+|['")`]+$/g, '');
}

/** The token, with quotes off, names a protected file (and nothing after it). */
function isProtectedTarget(token: string): boolean {
  const bare = unquote(token);
  const afterEq = bare.includes('=') ? bare.slice(bare.lastIndexOf('=') + 1) : bare;
  return SECURITY_CONFIG_FILE_TAIL_RE.test(afterEq);
}

function baseName(token: string): string {
  return (unquote(token).split(/[\\/]/).pop() ?? '').toLowerCase();
}

/**
 * True when one pipeline stage writes a protected file. Fail closed: the
 * file named on the executable surface is a write unless the shape is a
 * proven read or mention.
 *
 * `pipedNamesFile`: an earlier stage of the same pipeline named the file, so
 * an `xargs` here receives it as an operand it cannot show.
 */
function stageWritesProtectedFile(stage: string, pipedNamesFile: boolean): boolean {
  // The heredoc body (after the NUL the splitter inserted) is data: a redirect
  // written inside it is text, not a redirect. Only the interpreter rule
  // reads it, through `namesFile` below.
  const header = stage.split('\u0000')[0]!;
  const toks = tokenise(header);
  if (toks.length === 0) return false;

  // Redirects: `> f`, `>> f`, `>| f`, `2> f`, `&> f`, glued or spaced. Fd dups
  // (`2>&1`, `>&2`) have a numeric "target" and never match a file. A target
  // computed by a substitution that names the file is the file.
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i]!;
    const m = /^(?:\d|&)?>{1,2}\|?(.*)$/.exec(t);
    if (!m) continue;
    const glued = m[1]!;
    if (glued.startsWith('&')) continue;
    const target = glued || toks[i + 1] || '';
    if (!target) continue;
    if (isProtectedTarget(target)) return true;
    if (/^(?:`|\$\()/.test(target) && SECURITY_CONFIG_FILE_ANY_RE.test(toks.slice(i + 1).join(' '))) return true;
  }

  // Strip reserved words, env assignments and wrappers (with their option
  // arguments) to find the verb.
  let k = 0;
  let viaXargs = false;
  while (k < toks.length) {
    const raw = unquote(toks[k]!);
    if (/^[A-Za-z_]\w*=/.test(raw)) {
      k++;
      continue;
    }
    const base = baseName(toks[k]!);
    if (RESERVED_WORDS.has(base) || base === '') {
      k++;
      continue;
    }
    if (!WRAPPER_VERBS.has(base)) break;
    if (base === 'xargs') viaXargs = true;
    k++;
    const argFlags = WRAPPER_FLAGS_WITH_ARG[base];
    let positionals = WRAPPER_POSITIONALS[base] ?? 0;
    while (k < toks.length) {
      const t = unquote(toks[k]!);
      if (t === '--') {
        k++;
        break;
      }
      if (t.startsWith('-') && t.length > 1) {
        k++;
        if (argFlags?.has(t)) k++;
        continue;
      }
      if (positionals > 0) {
        positionals--;
        k++;
        continue;
      }
      break;
    }
  }
  if (k >= toks.length) {
    // Only assignments and reserved words. An assignment whose VALUE is the
    // file is indirection (`T=<file>; echo x > "$T"`): the write that follows
    // cannot be seen, so the assignment itself takes the lease.
    return toks.some((t) => /^[A-Za-z_]\w*=/.test(unquote(t)) && isProtectedTarget(t));
  }
  const verb = baseName(toks[k]!);
  const rest = toks.slice(k + 1);
  // Flags are read with their quotes off: `sed "-i"` is `sed -i` to sed.
  const flags = rest.map(unquote);
  // A lone `-` is stdin, an operand: `xxd -r - <file>` writes its second.
  const operands = rest.filter((t) => unquote(t) === '-' || !unquote(t).startsWith('-'));
  /** The file anywhere on the stage, quoted or not, header or body. */
  const namesFile = SECURITY_CONFIG_FILE_ANY_RE.test(stage.replace(/\u0000/g, ' '));
  /** An operand or option value that IS the file, quotes off. */
  const namedOperand = rest.some(isProtectedTarget);

  // An output option names a destination whatever the verb.
  for (let i = 0; i < rest.length; i++) {
    const m = OUTPUT_OPTION_RE.exec(flags[i]!);
    if (!m) continue;
    // grep's `-o` is only-matching; the next token is the pattern.
    if (flags[i] === '-o' && GREP_FAMILY_VERBS.has(verb)) continue;
    const target = m[1] ?? rest[i + 1] ?? '';
    if (target && isProtectedTarget(target)) return true;
  }

  if (INTERPRETER_VERBS.has(verb)) return namesFile || (viaXargs && pipedNamesFile);
  if (MUTATE_ANY_OPERAND_VERBS.has(verb)) return namedOperand || (viaXargs && pipedNamesFile);
  if (verb === 'dd') return operands.some((t) => /^of=/i.test(unquote(t)) && isProtectedTarget(t));
  if (verb === 'sed' || verb === 'awk' || verb === 'gawk' || verb === 'mawk' || verb === 'nawk') {
    // In place, or a SCRIPT that names the file: sed's `w <file>` / `s///w
    // <file>` and awk's `print > "<file>"` write it without any flag. The
    // mapper does not parse sed or awk, so a script token naming the file
    // fails closed; a plain path operand is still the read it looks like.
    //
    // #552 r6: an awk ASSIGNMENT whose value is the file (`-v f=<file>`,
    // `-vf=<file>`, a bare `f=<file>` operand) is indirection — `print > f`
    // writes it — so it takes the lease like the env-assignment rule. And a
    // script read from a FILE (`-f prog`, `--file=prog`) is unseen: the
    // protected path anywhere on such a command line fails closed, whether
    // it is an operand under `-f` or the script file itself.
    const isAwk = verb !== 'sed';
    if (isAwk && rest.some((t) => /^(?:-v|--assign=)?[A-Za-z_]\w*=/.test(unquote(t)) && isProtectedTarget(t))) return true;
    const scriptFromFile = flags.some((t) => t.startsWith('--file') || (/^-[a-zA-Z]*f/.test(t) && !t.startsWith('--')));
    if (scriptFromFile && namedOperand) return true;
    const scriptNamesFile = rest.some((t) => {
      const bare = unquote(t);
      const m = SECURITY_CONFIG_FILE_ANY_RE.exec(bare);
      if (!m) return false;
      // A plain path operand has nothing but a ROOTED path prefix before the
      // file — `/`, `~/`, `./`, `../`, `$VAR/`, `${VAR}/`, `X:/` (optionally
      // after `--opt=`), then directory names — or nothing at all. Anything
      // else in front is script text naming it: `w ~/`, `s/a/b/w ~/`, `w~/`,
      // and (#552 r6 addendum) `w/home/x/` — a letter before the first slash
      // is sed's `w` command, not a relative directory called `w`.
      const before = bare.slice(0, m.index);
      return !/^(?:--?[\w-]+=)?(?:(?:[\\/]|~[\\/]|\.{1,2}[\\/]|\$\w+[\\/]|\$\{\w+\}[\\/]|[A-Za-z]:[\\/])(?:[\w.\-]+[\\/])*)?$/.test(before);
    });
    if (scriptNamesFile) return true;
    return flags.some((t) => IN_PLACE_FLAG_RE.test(t)) && (namedOperand || (viaXargs && pipedNamesFile));
  }
  if (Object.prototype.hasOwnProperty.call(SECOND_OPERAND_OUTPUT_VERBS, verb)) {
    // Option values are not operands (`uniq -w 5 in out`); an option the
    // table does not know leaves operand[0] unproven, so a protected operand
    // anywhere is then the output.
    const parsed = operandsAfterOptions(verb, rest);
    if (!parsed.proven) return parsed.operands.some(isProtectedTarget) || (viaXargs && pipedNamesFile);
    const out = parsed.operands[1];
    return (out != null && isProtectedTarget(out)) || (viaXargs && pipedNamesFile);
  }
  if (COPY_TO_LAST_OPERAND_VERBS.has(verb)) {
    const last = operands[operands.length - 1];
    return (last != null && isProtectedTarget(last)) || (viaXargs && pipedNamesFile);
  }
  if (verb === 'tar') {
    // `tar cf <archive> …` writes the archive; create/list otherwise only read
    // their operands; extract/append/update name members they will write.
    const mode = flags[0] ?? '';
    // An old-style mode word (`cf`, `xzf`) is not a path operand.
    const paths = mode && !mode.startsWith('-') ? operands.slice(1) : operands;
    if (/^-?[a-zA-Z]*f/.test(mode) && paths[0] != null && isProtectedTarget(paths[0])) return true;
    const reading = /^-?[a-zA-Z]*[ct]/.test(mode) || flags.some((f) => f === '--create' || f === '--list');
    return reading ? false : paths.some(isProtectedTarget);
  }
  if (verb === 'git') {
    let sub: string | undefined;
    for (let i = 0; i < rest.length; i++) {
      const prev = i > 0 ? flags[i - 1]! : '';
      if (flags[i]!.startsWith('-') || prev === '-C' || prev === '-c' || prev === '--git-dir' || prev === '--work-tree') continue;
      sub = flags[i]!.toLowerCase();
      break;
    }
    if (sub != null && GIT_READ_SUBCOMMANDS.has(sub)) return false;
    return namedOperand;
  }
  if (READ_ONLY_VERBS.has(verb)) return false;
  // Unknown verb: the file as an operand or an option value is a write until
  // proven otherwise — and so is a file handed over through xargs.
  return namedOperand || (viaXargs && pipedNamesFile);
}

/**
 * The security-config scope mapper for command surfaces (#550): a lease is
 * taken when some stage of the command WRITES a protected file — or names it
 * in a shape that is not a proven read — never for a mention. A commit
 * message, a heredoc string literal, a comment, a `grep` pattern, a
 * `cat`/`jq`/`diff` read or a `cp <file> <file>.bak` backup takes nothing.
 * Exported for tests; callers go through scopeForToolCall.
 */
export function securityConfigWriteShape(command: string): boolean {
  const text = String(command ?? '');
  if (!SECURITY_CONFIG_FILE_ANY_RE.test(text)) return false;
  for (const statement of splitStatementsHeredocAware(text)) {
    let pipedNamesFile = false;
    for (const stage of splitPipeline(statement)) {
      if (stageWritesProtectedFile(stage, pipedNamesFile)) return true;
      // Header OR heredoc body: `cat <<'EOF' | xargs rm⏎<file>⏎EOF` hands
      // the file to xargs through the body (#552 r6).
      if (SECURITY_CONFIG_FILE_ANY_RE.test(stage.replace(/\u0000/g, ' '))) pipedNamesFile = true;
    }
  }
  return false;
}

/**
 * A fleet-host install, evasion-resistant: a package manager (or `openclaw
 * plugins install`) invoked at a command boundary, with an install verb AND a
 * global marker present ANYWHERE on the surface — so flag order cannot defeat
 * it. Local `npm install`/`npm ci` (no global marker) is deliberately NOT an
 * install-scope action.
 */
function isGlobalInstall(command: string): boolean {
  if (new RegExp(`${CMD_BOUNDARY}openclaw\\s+plugins\\s+(?:install|add)\\b`, 'i').test(command)) return true;
  const pkgInvoked = new RegExp(`${CMD_BOUNDARY}${PKG_MGR}\\b`, 'i').test(command);
  if (!pkgInvoked) return false;
  const hasInstallVerb = /\b(?:install|i|add)\b/i.test(command);
  const hasGlobalMarker = /(?:\s-g\b|--global\b|--location[=\s]+global\b)/i.test(command);
  return hasInstallVerb && hasGlobalMarker;
}

/** File paths whose EDITS are security-config actions regardless of tool. */
const SECURITY_CONFIG_PATH_RE = /(?:\.shieldcortex[\\/]+config\.json|\.claude[\\/]+settings\.json|\.openclaw[\\/]+openclaw\.json|\.shieldcortex[\\/]+DECISIONS\.md|\.shieldcortex[\\/]+leases\b)/i;

const FILE_EDIT_TOOLS = new Set(['edit', 'write', 'notebookedit', 'multiedit', 'str_replace_editor']);

function extractCommand(args: Record<string, unknown> | null | undefined): string | null {
  if (!args || typeof args !== 'object') return null;
  for (const key of ['command', 'cmd', 'script']) {
    const v = (args as Record<string, unknown>)[key];
    if (typeof v === 'string' && v.length > 0) return v;
  }
  return null;
}

function extractFilePath(args: Record<string, unknown> | null | undefined): string | null {
  if (!args || typeof args !== 'object') return null;
  for (const key of ['file_path', 'path', 'filePath', 'notebook_path']) {
    const v = (args as Record<string, unknown>)[key];
    if (typeof v === 'string' && v.length > 0) return v;
  }
  return null;
}

/**
 * Map a tool call onto the lease scope it exercises, or null when it exercises
 * none. Null is the overwhelmingly common answer and the fast path: the lease
 * layer must not tax ordinary actions with state reads.
 *
 * Never throws — a mapper crash inside the guard flow would be a new way to
 * break the gate, which is exactly backwards.
 */
export function scopeForToolCall(
  toolName: string,
  args: Record<string, unknown> | null | undefined,
): LeaseScope | null {
  try {
    const command = extractCommand(args);
    if (command != null) {
      if (isGlobalInstall(command)) return 'install';
      for (const { scope, re } of SCOPE_COMMAND_PATTERNS) {
        if (re.test(command)) return scope;
      }
      if (securityConfigWriteShape(command)) return 'security-config';
      return null;
    }
    const tool = String(toolName ?? '').toLowerCase();
    if (FILE_EDIT_TOOLS.has(tool)) {
      const filePath = extractFilePath(args);
      if (filePath != null && SECURITY_CONFIG_PATH_RE.test(filePath)) return 'security-config';
    }
    return null;
  } catch {
    return null;
  }
}
