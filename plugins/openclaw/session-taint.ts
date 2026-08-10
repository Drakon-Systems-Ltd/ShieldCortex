/**
 * Session taint → Action Guard escalation (issue #233).
 *
 * The hole this closes: the conversation-scan path and the Action Guard share
 * NO state today. `scanLlmInput` detects a prompt injection, writes a log line
 * and a JSONL row that nothing reads back, and the tool call that injection is
 * steering — one turn later — is evaluated as if nothing had happened.
 *
 * The fix is deliberately NOT to block the turn. `before_agent_run` is
 * fail-closed with a 15s budget the host owns, so every ShieldCortex fault
 * (throw, timeout, a stray `null`) becomes a dead user turn, and a false
 * positive destroys the user's message irrecoverably. See
 * docs/design/2026-08-10-conversation-taint-escalation.md.
 *
 * Instead: a detection TAINTS the session, and the Action Guard — which
 * already gates actions, is already trusted, and is not a conversation hook —
 * reads that taint and tightens by one notch for a bounded window. The agent
 * keeps thinking; it just needs a human before it does anything consequential.
 *
 * Both the conversation scan and the interceptor run in the SAME gateway
 * process, so this store is in-memory by design. It is keyed per session
 * because one gateway serves many concurrent chats — a process-global flag
 * would leak one conversation's taint onto every other conversation's tools.
 */

export type TaintSeverity = 'low' | 'medium' | 'high' | 'critical' | 'unknown';

export interface TaintRecord {
  sessionId: string;
  severity: TaintSeverity;
  reason: string;
  /** Epoch ms when this taint stops applying. */
  expiresAtMs: number;
  markedAtMs: number;
}

/** How long a single detection keeps a session tainted. */
export const TAINT_TTL_MS = 15 * 60_000;

/** Hard cap on tracked sessions — a long-lived gateway must not grow forever. */
export const MAX_TAINTED_SESSIONS = 500;

export interface SessionTaintStore {
  mark(sessionId: string, input: { severity?: TaintSeverity; reason: string; nowMs?: number; ttlMs?: number }): void;
  /** The live taint for a session, or null when clean/expired. */
  get(sessionId: string, nowMs?: number): TaintRecord | null;
  clear(sessionId: string): void;
  reset(): void;
  size(): number;
}

export function createSessionTaintStore(): SessionTaintStore {
  const records = new Map<string, TaintRecord>();

  function prune(nowMs: number): void {
    for (const [id, rec] of records) {
      if (rec.expiresAtMs <= nowMs) records.delete(id);
    }
    // Still over cap after expiry (many live sessions): drop the oldest marks.
    // Evicting the OLDEST is the safe direction — the most recent detections
    // are the ones whose tool calls have not happened yet.
    if (records.size > MAX_TAINTED_SESSIONS) {
      const bySeniority = [...records.entries()].sort((a, b) => a[1].markedAtMs - b[1].markedAtMs);
      for (const [id] of bySeniority.slice(0, records.size - MAX_TAINTED_SESSIONS)) records.delete(id);
    }
  }

  return {
    mark(sessionId, input) {
      if (!sessionId) return;
      const nowMs = input.nowMs ?? Date.now();
      const ttl = input.ttlMs ?? TAINT_TTL_MS;
      const severity = input.severity ?? 'unknown';
      const existing = records.get(sessionId);

      // Re-marking EXTENDS the window and keeps the higher severity — a second
      // injection in the same session must never shorten the hold or downgrade
      // it to the newer, milder finding.
      const next: TaintRecord = {
        sessionId,
        severity: existing && rank(existing.severity) > rank(severity) ? existing.severity : severity,
        reason: input.reason,
        markedAtMs: nowMs,
        expiresAtMs: Math.max(nowMs + ttl, existing?.expiresAtMs ?? 0),
      };
      records.set(sessionId, next);
      prune(nowMs);
    },

    get(sessionId, nowMs = Date.now()) {
      if (!sessionId) return null;
      const rec = records.get(sessionId);
      if (!rec) return null;
      if (rec.expiresAtMs <= nowMs) {
        records.delete(sessionId);
        return null;
      }
      return rec;
    },

    clear(sessionId) {
      records.delete(sessionId);
    },

    reset() {
      records.clear();
    },

    size() {
      return records.size;
    },
  };
}

function rank(s: TaintSeverity): number {
  switch (s) {
    case 'critical': return 4;
    case 'high': return 3;
    case 'medium': return 2;
    case 'low': return 1;
    default: return 0;
  }
}

// ── Escalation policy ───────────────────────────────────────────────────────

export type GuardDecision = 'allow' | 'require_approval' | 'block';
export type GuardSeverity = 'benign' | 'sensitive' | 'dangerous' | 'catastrophic';

export interface EscalationInput {
  decision: GuardDecision;
  severity: GuardSeverity;
  tainted: boolean;
}

export interface EscalationResult {
  decision: GuardDecision;
  /** True when taint changed the answer — recorded on the verdict so an
   *  escalated deny is tellable from a natively-catastrophic one. */
  escalated: boolean;
}

/**
 * One notch tighter while tainted. Benign work is untouched on purpose: an
 * agent that cannot read a file is useless, and a taint response that stops
 * ordinary work is one operators will switch off.
 *
 *   benign        → unchanged (allow)
 *   sensitive     → require approval   (was allow)
 *   dangerous     → block              (was require approval)
 *   catastrophic  → unchanged (already blocked)
 *
 * Escalation NEVER downgrades: if the guard already decided something stricter
 * than the escalated value, the guard wins.
 */
export function escalateForTaint(input: EscalationInput): EscalationResult {
  const { decision, severity, tainted } = input;
  if (!tainted) return { decision, escalated: false };

  let target: GuardDecision = decision;
  if (severity === 'sensitive') target = 'require_approval';
  else if (severity === 'dangerous') target = 'block';

  // Only ever move toward caution.
  const next = strength(target) > strength(decision) ? target : decision;
  return { decision: next, escalated: next !== decision };
}

function strength(d: GuardDecision): number {
  switch (d) {
    case 'block': return 3;
    case 'require_approval': return 2;
    default: return 1;
  }
}
