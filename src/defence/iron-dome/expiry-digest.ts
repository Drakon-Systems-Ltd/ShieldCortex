/**
 * #673 — the session-end report of recorded OpenClaw approval timeouts.
 *
 * REPORTING ONLY, and explicitly partial against #673. This module is pure:
 * it renders the rows a bounded index read returned. It grants nothing, has
 * no approve/deny controls, does not touch request/decision paths, and does
 * not suppress the initial approval cards or any host "expired" notice.
 *
 * Honesty rules the text keeps:
 *  - counts are "recorded" (index evidence only), and "at least" when the
 *    read was partial;
 *  - "+K more" is "more recorded in this scan", never a total of attempts;
 *  - an affirmative blocked/skipped claim may appear ONLY in an entry line,
 *    and only when the caller's inspected-host set contains the projected
 *    host version. The header and the shared footer are host-neutral.
 *
 * Privacy: every rendered value is a closed-set projection
 * (`projectActionGuardFields`) or a regex-validated shape. `preview`, `args`,
 * matches, `reason`, broker fields, `actionKey`, nonces and hashes are never
 * read into the text.
 */
import { describeSignals } from './approval-card.js';
import { projectActionGuardFields } from './operator-notify.js';
import type { BoundedIndexRead } from './session-guard.js';

export const EXPIRY_DIGEST_MAX_CHARS = 4_000;
export const EXPIRY_DIGEST_MAX_ENTRIES = 10;

export const EXPIRY_DIGEST_FOOTER =
  'No approval was granted by this report and it has no approve/deny controls. '
  + 'Outcomes refer only to the listed calls; a later retry of the same action is a separate call and is not covered. '
  + 'Initial approval cards and any host "expired" messages are unchanged.';

const PINNED_CLAUSE = 'Approval timed out/unresolved; OpenClaw blocked this tool call (skipped).';
const neutralClause = (version: string) =>
  `Approval timed out/unresolved; ShieldCortex granted nothing. Whether this OpenClaw version (${version}) blocked the call has not been verified by ShieldCortex.`;
const REDACTED_SIGNAL_PHRASE = 'matched another safety rule';

const SESSION_KEY_RE = /^sc-[a-f0-9]{16}$/;
const NONCE_RE = /^[0-9a-f]{32}$/;
const ISO_TS_RE = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,3})?Z$/;
const HOST_VERSION_RE = /^\d{4}\.\d{1,2}\.\d{1,2}$/;

export interface ApprovalExpiryDigest {
  /** Distinct matching timeout entries in the scanned window. */
  observed: number;
  /** Entry lines actually rendered (≤ EXPIRY_DIGEST_MAX_ENTRIES). */
  rendered: number;
  /** The read was whole: not truncated, no corrupt or oversized line. */
  complete: boolean;
  /** A digest row (any phase) for this session is already in the window. */
  alreadyDigested: boolean;
  /** The full rendered message; '' when observed is 0. */
  text: string;
}

/** Exact membership on every field the issue's entry definition names. */
export function isApprovalTimeoutEntry(row: Record<string, unknown>, sessionKey: string): boolean {
  return (row.recordKind === 'guard' || row.type === 'intercept')
    && row.origin === 'openclaw-interceptor'
    && row.action === 'require_approval'
    && row.outcome === 'card_timeout'
    && row.sessionKey === sessionKey;
}

/** Render a host version only in its released shape; anything else is `unknown`. */
export function projectHostVersion(v: unknown): string {
  const text = typeof v === 'string' ? v.trim() : '';
  return HOST_VERSION_RE.test(text) ? text : 'unknown';
}

function safeClock(row: Record<string, unknown>): string | null {
  for (const v of [row.heldAtTs, row.ts]) {
    if (typeof v !== 'string' || !ISO_TS_RE.test(v) || !Number.isFinite(Date.parse(v))) continue;
    return `${v.slice(11, 19)}Z`;
  }
  return null;
}

function whyFor(row: Record<string, unknown>): string {
  const raw = Array.isArray(row.threats) ? row.threats : Array.isArray(row.signals) ? row.signals : [];
  const { signals } = projectActionGuardFields({ signals: raw });
  const known = signals.filter((s) => s !== 'redacted-signal');
  const redacted = known.length !== signals.length;
  // Every id reaching describeSignals is a closed-set member, so its raw-id
  // fallback can never echo caller-chosen text.
  if (known.length === 0) return redacted ? REDACTED_SIGNAL_PHRASE : describeSignals([]);
  const phrase = describeSignals(known);
  return redacted ? `${phrase}; ${REDACTED_SIGNAL_PHRASE}` : phrase;
}

function entryLine(row: Record<string, unknown>, clause: string): string {
  const { tool, severity } = projectActionGuardFields({ tool: row.tool, severity: row.severity });
  const clock = safeClock(row);
  return `• ${clock ? `${clock} ` : ''}${tool} (${severity}) — why: ${whyFor(row)}. ${clause}`;
}

export function buildApprovalExpiryDigest(
  read: Pick<BoundedIndexRead, 'rows' | 'truncated' | 'corrupt' | 'oversized'>,
  opts: { sessionKey: string; hostVersion?: unknown; blockingHosts?: ReadonlySet<string> },
): ApprovalExpiryDigest {
  const sessionKey = String(opts.sessionKey ?? '');
  const complete = read.truncated !== true && (read.corrupt ?? 0) === 0 && (read.oversized ?? 0) === 0;
  const empty: ApprovalExpiryDigest = { observed: 0, rendered: 0, complete, alreadyDigested: false, text: '' };
  if (!SESSION_KEY_RE.test(sessionKey)) return empty;
  const rows = Array.isArray(read.rows) ? read.rows : [];

  const alreadyDigested = rows.some((r) => r && r.recordKind === 'digest' && r.sessionKey === sessionKey);
  // Entry identity: the binding nonce when present (a repeated nonce is one
  // entry); otherwise the row's own line in this one file.
  const seen = new Set<string>();
  const entries: Array<Record<string, unknown>> = [];
  rows.forEach((row, line) => {
    if (!row || typeof row !== 'object' || !isApprovalTimeoutEntry(row, sessionKey)) return;
    const nonce = typeof row.nonce === 'string' && NONCE_RE.test(row.nonce) ? row.nonce : null;
    const key = nonce ? `n:${nonce}` : `l:${line}`;
    if (seen.has(key)) return;
    seen.add(key);
    entries.push(row);
  });
  const observed = entries.length;
  if (observed === 0) return { ...empty, alreadyDigested };

  const version = projectHostVersion(opts.hostVersion);
  const pinned = version !== 'unknown' && opts.blockingHosts?.has(version) === true;
  const clause = pinned ? PINNED_CLAUSE : neutralClause(version);

  const header = complete
    ? `ShieldCortex — ${observed} recorded approval timeout${observed === 1 ? '' : 's'} in OpenClaw session ${sessionKey} (report only)`
    : `ShieldCortex — at least ${observed} recorded approval timeout${observed === 1 ? '' : 's'} in OpenClaw session ${sessionKey} (report only). The local record was only partly readable; the true total is unknown.`;
  const moreLine = (k: number) => `+${k} more recorded in this scan`;

  // Reserve header, the WHOLE footer and the worst-case "+K more" first;
  // then add whole entry lines. Nothing is ever cut mid-line.
  const reserved = header.length + 2 + EXPIRY_DIGEST_FOOTER.length + 2 + moreLine(observed).length + 1;
  const lines: string[] = [];
  let used = reserved;
  for (const row of entries) {
    if (lines.length >= EXPIRY_DIGEST_MAX_ENTRIES) break;
    const line = entryLine(row, clause);
    if (used + line.length + 1 > EXPIRY_DIGEST_MAX_CHARS) break;
    lines.push(line);
    used += line.length + 1;
  }
  const rest = observed - lines.length;
  const parts = [header, '', ...lines];
  if (rest > 0) parts.push(moreLine(rest));
  parts.push('', EXPIRY_DIGEST_FOOTER);
  return { observed, rendered: lines.length, complete, alreadyDigested, text: parts.join('\n') };
}
