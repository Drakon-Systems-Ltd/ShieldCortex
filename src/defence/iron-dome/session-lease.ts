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
  /**
   * Injected (#550): `held.pid` is the live runtime process that SPAWNED the
   * checking harness — its parent, or its grandparent through one harness
   * process (gateway → claude → hook). Pure core does not walk the process
   * table; the store layer sets this after a same-host check.
   *
   * Two enforcement planes gate the same tool call under two identities: the
   * OpenClaw interceptor as the OpenClaw session id (pid = gateway), then the
   * Claude Code hook as the hashed Claude session id. The first plane allowed
   * and acquired; the second found a foreign holder and refused — naming the
   * caller's own session and "0s ago". The runtime that spawned this harness
   * already gated this very call under its own identity, so a record it holds
   * is this call's own lease, not a rival's.
   *
   *   - true: the holder is the spawning runtime → re-enter (allow, no acquire)
   *   - false / omitted: fail closed; a foreign live holder still binds
   *
   * A blank/missing PID is never a skeleton key even when this is true.
   */
  holderSpawnedSelf?: boolean;
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
      // #550: the holder is the runtime that spawned this harness (the OpenClaw
      // gateway gating a Claude Code child's tool call as the OpenClaw session,
      // while the hook gates the same call as the Claude session). That runtime
      // already applied session-level exclusion to this call before the child
      // ran it, so its record is this call's own lease under another name.
      // Re-enter without acquiring: the record stays the holder's, and a later
      // refusal in this plane has nothing of its own to release.
      if (pidPresent && input.holderSpawnedSelf === true) {
        return {
          verdict: 'allow',
          reason:
            `${scope} lease is held by the runtime that spawned this session ` +
            `(${held.holder}, pid ${pid}) — already gated there for this call`,
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
// second plane, was refused by) a security-config lease. The rows below take
// a lease only when the command's SHAPE writes the file.

/** The protected files, as they end a path token on a command surface. */
const SECURITY_CONFIG_FILE_TAIL_RE = /(?:\.shieldcortex[\\/]+config\.json|\.claude[\\/]+settings\.json|\.openclaw[\\/]+openclaw\.json)$/i;
/** Fast pre-check: the same three files anywhere. Most commands fail this. */
const SECURITY_CONFIG_FILE_ANY_RE = /(?:\.shieldcortex[\\/]+config\.json|\.claude[\\/]+settings\.json|\.openclaw[\\/]+openclaw\.json)/i;

/** Verbs that mutate EVERY path operand they are given (or the named one). */
const MUTATE_ANY_OPERAND_VERBS = new Set([
  'tee', 'rm', 'unlink', 'mv', 'truncate', 'chmod', 'chown', 'chgrp', 'touch', 'shred',
  'sponge', 'dd',
  // editors: opening the file in one is editing it
  'vi', 'vim', 'nvim', 'nano', 'pico', 'emacs', 'code', 'subl', 'gedit', 'ed', 'ex',
]);
/** Verbs whose LAST operand is the destination. A protected SOURCE is a read. */
const COPY_TO_LAST_OPERAND_VERBS = new Set(['cp', 'install', 'ln', 'rsync', 'scp']);
/**
 * Interpreters and shells. A program that is handed the file — inline
 * (`-c`, `-e`, a heredoc) or as an argument to a script — may write it, and
 * the mapper does not parse Python: fail closed on the mention, as the
 * guard's own path-target rules do ("path-target signals skip the
 * interpreter-source downgrade"). Disclosed cost: `node cli.js doctor
 * --config <file>` takes a (re-entrant, ten-minute) lease it did not need.
 */
const INTERPRETER_VERBS = new Set([
  'python', 'python2', 'python3', 'node', 'nodejs', 'deno', 'bun', 'perl', 'ruby', 'php',
  'eval', 'sh', 'bash', 'zsh', 'dash', 'ksh', 'fish',
]);
/** Wrappers stripped from the front of a stage before the verb is read. */
const WRAPPER_VERBS = new Set(['sudo', 'doas', 'env', 'command', 'nohup', 'nice', 'time', 'exec', 'busybox']);

/**
 * Split a command into statements, keeping a heredoc BODY attached to the
 * stage that opened it (`cat > /tmp/x <<'EOF' … EOF` is one statement whose
 * verb is `cat` and whose redirect target is `/tmp/x`; the body is data).
 * Separators: newline, `;`, `&&`, `||`, and a bare `&` (not `>&`, `|&`).
 */
/**
 * Quote-aware: a `;` or `|` inside `python3 -c "a; b"` is program text, not a
 * shell separator — splitting there would hide the file from the interpreter
 * rule and read `json.dump(` as a verb.
 */
function splitLineOnSeparators(line: string): string[] {
  const out: string[] = [];
  let cur = '';
  let quote: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i]!;
    const n = line[i + 1];
    if (quote) {
      cur += c;
      if (c === quote) quote = null;
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      cur += c;
      continue;
    }
    if (c === '\\' && n != null) {
      cur += c + n;
      i++;
      continue;
    }
    if (c === ';' || ((c === '&' || c === '|') && n === c)) {
      if (cur.trim()) out.push(cur);
      cur = '';
      if (c !== ';') i++;
      continue;
    }
    if (c === '&') {
      const prev = cur.length ? cur[cur.length - 1] : '';
      if (prev !== '>' && prev !== '|') {
        if (cur.trim()) out.push(cur);
        cur = '';
        continue;
      }
    }
    cur += c;
  }
  if (cur.trim()) out.push(cur);
  return out;
}

function splitStatementsHeredocAware(command: string): string[] {
  const lines = command.split('\n');
  const out: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const m = /<<-?\s*(?:'([^']+)'|"([^"]+)"|([A-Za-z_][\w-]*))/.exec(line.replace(/<<</g, '   '));
    if (!m) {
      out.push(...splitLineOnSeparators(line));
      continue;
    }
    const tag = (m[1] ?? m[2] ?? m[3])!;
    const body: string[] = [];
    let j = i + 1;
    let trailer = '';
    for (; j < lines.length; j++) {
      const candidate = lines[j]!.trim();
      // bash requires the delimiter alone on its line; a delimiter followed
      // by a separator is read as a terminator too, so the statements after
      // it are still evaluated rather than swallowed into the body.
      const term = new RegExp(`^${tag.replace(/[.*+?^${}()|[\]\\-]/g, '\\$&')}(?:\\s*(?:;|&&|\\|\\||[&|])(.*))?$`).exec(candidate);
      if (term) {
        trailer = term[1] ?? '';
        break;
      }
      body.push(lines[j]!);
    }
    // The body rides on the segment of the header that opened it: `cat >
    // /tmp/x <<'EOF' && echo done` keeps the body with `cat`, not `echo`.
    const segments = splitLineOnSeparators(line);
    const opener = Math.max(0, segments.findIndex((s) => /<<-?\s*['"]?[A-Za-z_]/.test(s.replace(/<<</g, '   '))));
    if (segments.length > 0) segments[opener] = `${segments[opener]!}\u0000${body.join(' ')}`;
    out.push(...segments);
    if (trailer.trim()) out.push(...splitLineOnSeparators(trailer));
    i = j;
  }
  return out;
}

/** Split a statement on single `|` / `|&` outside quotes (`||` is already split). */
function splitPipeline(statement: string): string[] {
  const out: string[] = [];
  let cur = '';
  let quote: string | null = null;
  for (let i = 0; i < statement.length; i++) {
    const c = statement[i]!;
    if (quote) {
      cur += c;
      if (c === quote) quote = null;
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      cur += c;
      continue;
    }
    if (c === '\\' && i + 1 < statement.length) {
      cur += c + statement[i + 1]!;
      i++;
      continue;
    }
    if (c === '|') {
      if (cur.trim()) out.push(cur.trim());
      cur = '';
      if (statement[i + 1] === '&') i++;
      continue;
    }
    cur += c;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

/**
 * Whitespace tokens with quotes respected: `"a > b"` is ONE token, so a
 * redirect written inside a commit message or a string literal is not a
 * redirect. Quotes are kept on the token; callers strip them.
 */
function tokenise(stage: string): string[] {
  const toks: string[] = [];
  let cur = '';
  let quote: string | null = null;
  for (let i = 0; i < stage.length; i++) {
    const c = stage[i]!;
    if (quote) {
      cur += c;
      if (c === quote) quote = null;
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      cur += c;
      continue;
    }
    if (c === '\\' && i + 1 < stage.length) {
      cur += c + stage[i + 1]!;
      i++;
      continue;
    }
    if (/\s/.test(c) || c === '\u0000') {
      if (cur) toks.push(cur);
      cur = '';
      continue;
    }
    // A redirect operator ends the word before it: `printf x>f` is `printf`,
    // `x`, `>f` to the shell. Only an fd digit or `&` stays glued (`2>f`, `&>f`).
    if (c === '>' && cur && !/^(?:\d|&|>)$/.test(cur)) {
      toks.push(cur);
      cur = '';
    }
    cur += c;
  }
  if (cur) toks.push(cur);
  return toks;
}

function unquote(token: string): string {
  return token.replace(/^[('"]+|['")]+$/g, '');
}

/** The token, with quotes off, names a protected file (and nothing after it). */
function isProtectedTarget(token: string): boolean {
  const bare = unquote(token);
  const afterEq = bare.includes('=') ? bare.slice(bare.lastIndexOf('=') + 1) : bare;
  return SECURITY_CONFIG_FILE_TAIL_RE.test(afterEq);
}

/**
 * True when one pipeline stage writes a protected file: a redirect onto it,
 * a mutating verb given it as an operand, a copy-like verb given it as the
 * destination, or an inline interpreter/shell program that names it.
 */
function stageWritesProtectedFile(stage: string): boolean {
  // The heredoc body (after the NUL the splitter inserted) is data: a redirect
  // written inside it is text, not a redirect. Only the interpreter rule
  // reads it, through `namesFile` below.
  const header = stage.split('\u0000')[0]!;
  const toks = tokenise(header);
  if (toks.length === 0) return false;

  // Redirects: `> f`, `>> f`, `>| f`, `2> f`, `&> f`, glued or spaced. Fd dups
  // (`2>&1`, `>&2`) have a numeric "target" and never match a file.
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i]!;
    const m = /^(?:\d|&)?>{1,2}\|?(.*)$/.exec(t);
    if (!m) continue;
    const glued = m[1]!;
    if (glued.startsWith('&')) continue;
    const target = glued || toks[i + 1] || '';
    if (target && isProtectedTarget(target)) return true;
  }

  // Strip wrappers and leading env assignments to find the verb.
  let k = 0;
  while (k < toks.length) {
    const t = toks[k]!;
    const base = (unquote(t).split(/[\\/]/).pop() ?? t).toLowerCase();
    if (/^[A-Za-z_]\w*=/.test(t) || (WRAPPER_VERBS.has(base)) || (k > 0 && t.startsWith('-') && WRAPPER_VERBS.has((unquote(toks[k - 1]!).split(/[\\/]/).pop() ?? '').toLowerCase()))) {
      k++;
      continue;
    }
    break;
  }
  if (k >= toks.length) return false;
  const verb = (unquote(toks[k]!).split(/[\\/]/).pop() ?? '').toLowerCase();
  const rest = toks.slice(k + 1);
  // Flags are read with their quotes off: `sed "-i"` is `sed -i` to sed.
  const flags = rest.map(unquote);
  const operands = rest.filter((t) => !unquote(t).startsWith('-'));
  const stageText = stage.replace(/\u0000/g, ' ');
  const namesFile = SECURITY_CONFIG_FILE_ANY_RE.test(stageText);

  // An output option names a destination whatever the verb: `git diff
  // --output=f`, `--output f`, `-o f`, `curl -o f`, `jq ... > f` is above.
  for (let i = 0; i < rest.length; i++) {
    const m = /^(?:-o|--(?:output|out|outfile|out-file|output-file|dest|destination))(?:=(.*))?$/.exec(flags[i]!);
    if (!m) continue;
    const target = m[1] ?? rest[i + 1] ?? '';
    if (target && isProtectedTarget(target)) return true;
  }

  if (MUTATE_ANY_OPERAND_VERBS.has(verb)) {
    return rest.some(isProtectedTarget);
  }
  // sed's in-place flag may sit in a cluster (`-ni`, `-Ei`, `-i.bak`) or be
  // spelled out (`--in-place[=suffix]`); perl's the same (`-pi`, `-i.bak`).
  if ((verb === 'sed' || verb === 'perl') && flags.some((t) => /^-[a-zA-Z]*i/.test(t) || /^--in-place(?:=|$)/.test(t))) {
    return operands.some(isProtectedTarget);
  }
  if (COPY_TO_LAST_OPERAND_VERBS.has(verb)) {
    const last = operands[operands.length - 1];
    return last != null && isProtectedTarget(last);
  }
  if (INTERPRETER_VERBS.has(verb)) {
    return namesFile;
  }
  return false;
}

/**
 * The security-config scope mapper for command surfaces (#550): a lease is
 * taken when some stage of the command WRITES a protected file, never for a
 * mention. A commit message, a heredoc string literal, a `grep` pattern, a
 * `cat`/`jq`/`diff` read or a `cp <file> <file>.bak` backup takes nothing.
 * Exported for tests; callers go through scopeForToolCall.
 */
export function securityConfigWriteShape(command: string): boolean {
  const text = String(command ?? '');
  if (!SECURITY_CONFIG_FILE_ANY_RE.test(text)) return false;
  for (const statement of splitStatementsHeredocAware(text)) {
    for (const stage of splitPipeline(statement)) {
      if (stageWritesProtectedFile(stage)) return true;
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
