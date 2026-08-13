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
  { scope: 'security-config', re: /\.shieldcortex[\\/]+config\.json\b/i },
  { scope: 'security-config', re: /\.claude[\\/]+settings\.json\b/i },
  { scope: 'security-config', re: /\.openclaw[\\/]+openclaw\.json\b/i },
  { scope: 'fleet-broadcast', re: new RegExp(`${CMD_BOUNDARY}openclaw\\b[^|;&\\n]*\\b(?:broadcast|message\\s+send)\\b`, 'i') },
];

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
