/**
 * ADR-002 measurement harness — the denial-log SCHEMA and the public-export
 * VOCABULARY for Half A (`scripts/guard-policy-replay.mjs`).
 *
 * Everything the replay prints about a log row is either a COUNT or a member
 * of one of the closed sets below. Nothing else from a row is ever copied into
 * JSON or Markdown output (round-2 finding 3). The sets are transcribed from
 * the code that WRITES the log, not guessed from log contents:
 *
 *   - `GUARD_SIGNAL_VOCABULARY` = the writer's signal allowlist
 *     (`SAFE_SIGNALS` in `scripts/pre-tool-hook.mjs`) plus the marker it
 *     substitutes for anything outside that allowlist (`redacted-signal`).
 *     A signal name is printable ONLY by membership here — never by matching a
 *     lexical pattern. A conforming-looking but unregistered name is NOT
 *     printable and is counted under a redacted bucket.
 *   - `EVENT_ENUM` / `OUTCOME_ENUM` = the `event` / `outcome` literals written
 *     by `scripts/pre-tool-hook.mjs` and `src/defence/iron-dome/dnp-retry-waiter.ts`.
 *   - `NOTIFY_STATUS_ENUM` = `classifyNotifyStatus` in the hook writer.
 *   - `DELIVERY_CHANNEL_ENUM` = channel names the notify path can report plus
 *     the writer's `redacted-channel` substitute.
 *   - `SEVERITY_ENUM` = `safeSeverity` in the hook writer.
 *   - `TOOL_ENUM` = `SAFE_TOOL_NAMES` in the hook writer plus its `tool` substitute.
 *
 * The harness test cross-checks `GUARD_SIGNAL_VOCABULARY` and `TOOL_ENUM`
 * against the writer's source text, and every `signal:` literal in
 * `src/defence/iron-dome/tool-action-guard.ts` against the vocabulary or the
 * never-logged list, so drift fails the suite rather than leaking a name.
 *
 * Node core only; no product import.
 */

/** Signal names the writer keeps verbatim (its allowlist), plus its redaction marker. */
export const GUARD_SIGNAL_VOCABULARY = Object.freeze([
  'approval-required', 'change-permissions', 'command-exec', 'credential-access',
  'dangerous-shell', 'data-exfiltration', 'dd-overwrite', 'decode-pipe-to-shell',
  'delete-critical-path', 'delete-root-or-home', 'destructive-filesystem',
  'disk-partition-tool', 'exec-like', 'external-egress', 'fallback-scan',
  'file-delete', 'filesystem-destructive', 'force-push', 'force-push-invocation',
  'fork-bomb', 'format-filesystem', 'git-delete-branch', 'git-force-push',
  'git-mutate', 'install-package', 'install-package-global', 'invalid-tool-input',
  'local-package-install', 'missing-handle', 'modify-network-firewall',
  'modify-scheduler', 'move-or-copy', 'nested-invalid', 'network-egress',
  'not-object', 'opaque-command-substitution', 'opaque-script',
  'opaque-script-invocation', 'oversized-command', 'persistence-risk',
  'pipe-download-module-exec', 'pipe-download-stdin-exec', 'pipe-download-to-shell',
  'privilege-escalation', 'raw-disk-write', 'recursive-find-delete',
  'recursive-force-delete', 'recursive-perms-on-root', 'recursive-perms-system-dir',
  'redirect-to-block-device', 'registry-code-exec', 'reviewed-script',
  'secret-egress', 'secret-egress-fold', 'service-restart', 'session-lease',
  'shell-injection', 'shred-device', 'stop-process-or-service',
  'touch-approval-store', 'touch-decisions-ledger', 'touch-sensitive-path',
  'truncate-to-zero', 'type-coercion', 'unknown-keys', 'untrusted-script',
  'wipe-history-or-logs', 'write-content-catastrophic', 'write-content-dangerous',
  // the writer's substitute for any signal outside its allowlist
  'redacted-signal',
]);
const SIGNAL_SET = new Set(GUARD_SIGNAL_VOCABULARY);

/** Record contracts. A row is a DENIAL only if BOTH its event and outcome say so. */
export const EVENT_ENUM = Object.freeze(['action_guard_denial', 'action_guard_warning']);
export const DENIAL_OUTCOMES = Object.freeze(['auto_denied', 'denied_no_prompt_surface', 'failure_denied']);
export const WARNING_OUTCOMES = Object.freeze(['warned', 'failure_allowed']);
export const RETRY_OUTCOMES = Object.freeze(['retry_granted', 'retry_denied', 'retry_grant_failed']);
export const OUTCOME_ENUM = Object.freeze([...DENIAL_OUTCOMES, ...WARNING_OUTCOMES, ...RETRY_OUTCOMES]);

export const NOTIFY_STATUS_ENUM = Object.freeze([
  'pending', 'delivered', 'coalesced', 'suppressed', 'not_configured', 'no_channel', 'error',
]);
/** Statuses that CLAIM a transport delivery; a claim without a channel is contradictory. */
export const DELIVERY_CLAIM_STATUSES = Object.freeze(['delivered']);

export const DELIVERY_CHANNEL_ENUM = Object.freeze([
  'webhook', 'openclaw-approval', 'operator-notify', 'tui', 'card', 'redacted-channel',
]);

export const SEVERITY_ENUM = Object.freeze(['critical', 'dangerous', 'high', 'medium', 'low', 'benign', 'unknown']);

export const TOOL_ENUM = Object.freeze([
  'Bash', 'Edit', 'MultiEdit', 'Write', 'Read', 'Glob', 'Grep', 'LS', 'Task',
  'TodoWrite', 'WebFetch', 'WebSearch', 'NotebookEdit', 'Workflow',
  'BashOutput', 'KillShell', 'KillBash', 'TaskOutput', 'TaskStop',
  // the writer's substitute for any tool outside its allowlist
  'tool',
]);

/** The one value every non-member of a closed set maps to in public output. */
export const OTHER = 'other';
/** The one label a non-vocabulary signal is printed under. */
export const REDACTED_SIGNAL_LABEL = '<signal-outside-vocabulary-redacted>';

const enumMapper = (list) => { const s = new Set(list); return (v) => (typeof v === 'string' && s.has(v) ? v : OTHER); };

/** Public projections: closed-set member or `other`. Pure. */
export const publicEvent = enumMapper(EVENT_ENUM);
export const publicOutcome = enumMapper(OUTCOME_ENUM);
export const publicNotifyStatus = enumMapper(NOTIFY_STATUS_ENUM);
export const publicChannel = enumMapper(DELIVERY_CHANNEL_ENUM);
export const publicSeverity = enumMapper(SEVERITY_ENUM);
export const publicTool = enumMapper(TOOL_ENUM);

/** Is `s` a signal name the writer can have produced? Membership only, no regex. */
export function isVocabularySignal(s) { return typeof s === 'string' && SIGNAL_SET.has(s); }

/** Public-safe signal name: vocabulary member verbatim, otherwise the one redaction label. */
export function publicSignalName(s) { return isVocabularySignal(s) ? s : REDACTED_SIGNAL_LABEL; }

/**
 * Validate the `notify` member of a row against the writer's schema.
 * @returns {{ ok: true, status: string|null, channel: string|null } | { ok: false, reason: string }}
 * `status: null` means the row carried no notify object at all (allowed: retry rows).
 * A whitespace-only channel is NOT a channel (finding 4).
 */
export function validateNotify(row) {
  if (row.notify === undefined || row.notify === null) return { ok: true, status: null, channel: null };
  const n = row.notify;
  if (typeof n !== 'object' || Array.isArray(n)) return { ok: false, reason: 'notify-not-object' };
  if (n.status !== undefined && typeof n.status !== 'string') return { ok: false, reason: 'notify-status-not-string' };
  if (n.deliveredVia !== undefined && n.deliveredVia !== null && typeof n.deliveredVia !== 'string') return { ok: false, reason: 'notify-channel-not-string' };
  const status = typeof n.status === 'string' ? n.status : null;
  const channel = typeof n.deliveredVia === 'string' && n.deliveredVia.trim() !== '' ? n.deliveredVia : null;
  return { ok: true, status, channel };
}
