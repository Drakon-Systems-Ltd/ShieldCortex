/**
 * Trust source scorer — assigns trust levels based on memory source.
 */

import type { DefenceSource, TrustScore } from '../types.js';
import { scoreAgent, buildAgentHierarchy } from './agent-scorer.js';
import { stripUnattestedClaim } from './attestation.js';

const BASE_SCORES: Record<string, number> = {
  'user:direct': 1.0,
  'user:approved': 0.9,
  // Bulk import (restore from a backup/JSON). The generic `file` type is 0.6,
  // which sits inside the 0.5–0.7 auto-quarantine band and would quarantine
  // every imported row. Pin below the band so a benign restore succeeds while
  // imported file data stays scanned + low-trust until reviewed.
  'file:import': 0.4,
};

export const TYPE_SCORES: Record<DefenceSource['type'], number> = {
  user: 1.0,
  cli: 0.9,
  hook: 0.8,
  api: 0.7,
  file: 0.6,
  tool_response: 0.5,
  agent: 0.5,
  email: 0.4,
  web: 0.3,
};

/**
 * Shared-context bootstrap floor. A type scoring strictly below this is
 * untrusted inbound unless explicitly exempted.
 *
 * 0.6 is the generic `file` band: file:* stays available on get_context.
 * Identifier pins such as file:import (0.4) are write-path quarantine
 * adjustments, not a bootstrap denylist — this helper is type-level so a
 * restore still hydrates the session.
 *
 * `agent` scores 0.5, identical to `tool_response`. It is exempted on
 * purpose: guardReadBySensitivity promises INTERNAL project context to a
 * low-trust subagent (credential isolation without the availability
 * blackout). This function therefore does NOT implement "a capture written
 * by agent A must not bootstrap agent B" — that is checkAccess / own-only
 * on the per-caller fetch path.
 */
export const UNTRUSTED_INBOUND_FLOOR = 0.6;

export const UNTRUSTED_INBOUND_EXEMPT_TYPES: ReadonlySet<DefenceSource['type']> = new Set(['agent']);

export function isUntrustedInboundType(type: string): boolean {
  const normalised = type.toLowerCase();
  if ((UNTRUSTED_INBOUND_EXEMPT_TYPES as ReadonlySet<string>).has(normalised)) {
    return false;
  }
  return isUntrustedInboundTypeUnexempted(normalised);
}

/**
 * Score-only inbound classification, ignoring the exemption list.
 *
 * The `agent` exemption exists to keep INTERNAL project context available to a
 * REAL subagent. It is keyed on a type string, and a type string is
 * writer-chosen — so it must not apply to an identity the host never attested
 * (#283). The read guard calls this variant for stamped rows.
 */
export function isUntrustedInboundTypeUnexempted(type: string): boolean {
  const score = TYPE_SCORES[type.toLowerCase() as DefenceSource['type']];
  if (score === undefined) return true;
  return score < UNTRUSTED_INBOUND_FLOOR;
}

const HIERARCHY_DISPLAY = [
  'user:direct = 1.0',
  'user:approved = 0.9',
  'cli:* = 0.9',
  'hook:* = 0.8',
  'api:* = 0.7',
  'file:* = 0.6',
  'agent:* = hierarchy',
  'email:* = 0.4',
  'web:* = 0.3',
];

export function scoreSource(source: DefenceSource): TrustScore {
  // The unattested-claim stamp (#283) separates ACL KEYSPACE, never trust. Score
  // the underlying identity so the stamp can neither raise trust (`file:import`
  // 0.4 would fall back to the `file` type score 0.6; an `agent` identifier
  // would gain a decay level) nor lower it into a different policy band.
  const identifier = stripUnattestedClaim(source.identifier);
  const key = `${source.type}:${identifier}`;

  // Exact match overrides
  const baseScore = BASE_SCORES[key];
  if (baseScore !== undefined) {
    return { score: baseScore, source, hierarchy: [...HIERARCHY_DISPLAY, `>> ${key} = ${baseScore}`] };
  }

  // Agent hierarchy scoring
  if (source.type === 'agent') {
    const score = scoreAgent(identifier);
    return {
      score,
      source,
      hierarchy: [
        'Agent Hierarchy:',
        ...buildAgentHierarchy(identifier),
        `>> ${key} = ${score}`,
      ],
    };
  }

  // Type fallback
  const score = TYPE_SCORES[source.type] ?? 0;
  return { score, source, hierarchy: [...HIERARCHY_DISPLAY, `>> ${key} = ${score}`] };
}
