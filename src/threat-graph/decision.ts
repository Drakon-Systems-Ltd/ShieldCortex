/**
 * Quarantine decision payloads — the ledger record the allowance derivation
 * (Loop 3) consumes. Each operator approve/reject of a QUARANTINE item writes
 * one operation='review' audit row carrying this JSON in `reason`, so a
 * rebuild reproduces every allowance from the ledger alone (invariant 1).
 */

import { createContentHash } from '../defence/audit/logger.js';
import { attestedFlag, logAudit } from '../defence/audit/logger.js';
import { getDatabase } from '../database/init.js';
import { inferSourceFromEnvironment } from '../defence/trust/env-detector.js';
import { scoreSource } from '../defence/trust/source-scorer.js';
import { sourceKey } from './keys.js';

export interface QuarantineDecision {
  kind: 'quarantine_decision';
  decision: 'approve' | 'reject';
  source_key: string;
  patterns: string[];
  content_hash: string;
  quarantine_id: number;
  /** true for by-source/batch approvals — never count toward an allowance. */
  bulk: boolean;
  /**
   * The reviewer's free-text note, carried as ANNOTATION only. It is
   * caller-supplied (over MCP it is the `notes` argument), so it must never be
   * read as an identity — the row's source_type/source_identifier carry the
   * env-derived reviewer. Absent on rows written before this field existed.
   */
  notes?: string;
}

const MAX_DECISION_PATTERNS = 32;
const MAX_DECISION_NOTES = 200;

/**
 * Cap + strip control characters from a caller-supplied note before it lands
 * in a ledger payload the projector parses. Empty notes are dropped entirely
 * rather than stored as ''.
 */
function annotation(raw: string): string | undefined {
  // eslint-disable-next-line no-control-regex
  const s = raw.replace(/[\u0000-\u001F\u007F]/g, ' ').trim().slice(0, MAX_DECISION_NOTES);
  return s.length > 0 ? s : undefined;
}

/**
 * The COMPLETE detection set for a firewall result — the union of
 * blocked_patterns and threat_indicators. Auto-release keys on this, not on
 * blocked_patterns alone: detectors like credential_exfil / credential_leak /
 * privilege_escalation / restricted_content surface ONLY in threat_indicators,
 * so checking blocked_patterns alone would let an item with an unlisted
 * detection slip through the "every detection is allowed" gate.
 */
export function detectionKeys(blockedPatterns: unknown[], threatIndicators: unknown[]): string[] {
  const set = new Set<string>();
  const add = (v: unknown) => {
    const s = typeof v === 'string'
      ? v
      : (v && typeof v === 'object' && 'pattern' in v ? String((v as { pattern?: unknown }).pattern) : '');
    if (s) set.add(s);
  };
  for (const p of blockedPatterns) add(p);
  for (const t of threatIndicators) add(t);
  return [...set].sort().slice(0, MAX_DECISION_PATTERNS);
}

/**
 * Exemplar hash for auto-release near-dup matching. Binds BOTH title and
 * content — the title is stored and FTS-indexed, so hashing content alone
 * would let an approved body carry an arbitrary, unreviewed attacker title
 * into memory. Distinct from createContentHash (content-only, used for the
 * audit tamper-evidence hash) by design.
 */
export function exemplarHash(title: string | null, content: string): string {
  // JSON-encode the pair so the title/content boundary is unambiguous — a
  // plain separator could let ('a','bc') and ('ab','c') collide.
  return createContentHash(JSON.stringify([title ?? '', content]));
}

export function parseQuarantineDecision(reason: string | null): QuarantineDecision | null {
  if (!reason || reason[0] !== '{') return null;
  try {
    const p = JSON.parse(reason) as Partial<QuarantineDecision>;
    if (
      p.kind === 'quarantine_decision' &&
      (p.decision === 'approve' || p.decision === 'reject') &&
      typeof p.source_key === 'string' &&
      Array.isArray(p.patterns) &&
      typeof p.content_hash === 'string' &&
      typeof p.quarantine_id === 'number'
    ) {
      return {
        kind: 'quarantine_decision',
        decision: p.decision,
        source_key: p.source_key,
        patterns: p.patterns.filter((x): x is string => typeof x === 'string').slice(0, MAX_DECISION_PATTERNS),
        content_hash: p.content_hash,
        quarantine_id: p.quarantine_id,
        bulk: p.bulk === true,
        // Optional: rows written before the annotation field existed have none.
        notes: typeof p.notes === 'string' ? annotation(p.notes) : undefined,
      };
    }
  } catch { /* not JSON */ }
  return null;
}

interface DecisionInput {
  quarantineId: number;
  decision: 'approve' | 'reject';
  sourceType: string | null;
  sourceIdentifier: string | null;
  title: string | null;
  content: string;
  reason: string | null;
  auditId: number | null;
  threatIndicators: string[];
  reviewedBy: string;
  bulk: boolean;
  project: string | null;
}

/**
 * The allowance's covered detections = the COMPLETE detection set of the
 * original scan (blocked_patterns ∪ threat_indicators), read from the linked
 * audit row when present, else from the quarantine row's threat_indicators.
 * This is the SAME derivation auto-release uses (detectionKeys), so the
 * identity spaces match and an earned allowance is always consumable.
 */
function resolvePatterns(auditId: number | null, quarantineIndicators: string[]): string[] {
  if (auditId !== null) {
    const row = getDatabase().prepare('SELECT blocked_patterns, threat_indicators FROM defence_audit WHERE id = ?').get(auditId) as
      { blocked_patterns: string | null; threat_indicators: string | null } | undefined;
    if (row) {
      const parse = (s: string | null): unknown[] => {
        if (!s) return [];
        try { const v = JSON.parse(s); return Array.isArray(v) ? v : []; } catch { return []; }
      };
      const keys = detectionKeys(parse(row.blocked_patterns), parse(row.threat_indicators));
      if (keys.length > 0) return keys;
    }
  }
  return detectionKeys([], quarantineIndicators);
}

/**
 * Ledger one operator decision. operation='review' so the projector skips it
 * for scan/risk purposes and consumes the payload for allowance derivation.
 * Best-effort: a logging failure must never break the review it records.
 */
export function recordQuarantineDecision(input: DecisionInput): void {
  const patterns = resolvePatterns(input.auditId, input.threatIndicators);
  // The reviewer identity is the RUNTIME one, derived from the environment the
  // same way `forget` derives its caller — never `input.reviewedBy`. That
  // string is caller-supplied (over MCP it is a free-text argument), so
  // stamping it would mint arbitrary `user:<anything>` ledger rows under the
  // one type the MCP surface deliberately refuses to accept. Env-derived
  // identity is attested by construction: nothing caller-suppliable shaped it.
  const reviewer = inferSourceFromEnvironment().source;
  const payload: QuarantineDecision = {
    kind: 'quarantine_decision',
    decision: input.decision,
    source_key: sourceKey(input.sourceType ?? 'unknown', input.sourceIdentifier ?? 'unknown'),
    patterns,
    content_hash: exemplarHash(input.title, input.content),
    quarantine_id: input.quarantineId,
    bulk: input.bulk,
    notes: annotation(input.reviewedBy),
  };
  try {
    logAudit({
      memory_id: null,
      project: input.project,
      timestamp: new Date().toISOString(),
      source_type: reviewer.type,
      source_identifier: reviewer.identifier,
      trust_score: scoreSource(reviewer).score,
      sensitivity_level: 'INTERNAL',
      firewall_result: 'ALLOW',
      operation: 'review',
      anomaly_score: 0,
      threat_indicators: '[]',
      blocked_patterns: '[]',
      reason: JSON.stringify(payload),
      fragmentation_score: null,
      pipeline_duration_ms: null,
      source_attested: attestedFlag(true),
    });
  } catch {
    // Recording the decision must never break the review action itself.
  }
}
