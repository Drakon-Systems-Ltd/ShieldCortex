/**
 * Trust source scorer — assigns trust levels based on memory source.
 */

import type { DefenceSource, TrustScore } from '../types.js';
import { scoreAgent, buildAgentHierarchy } from './agent-scorer.js';
import { stripUnattestedStamp } from './attestation-stamp.js';

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

/**
 * Claim stamps that mean "writer/env declared this, host did not".
 * Includes CASE ownership stamp (`unattested>`) and TARS env residual stamps.
 */
const CLAIM_STAMP_PREFIXES = ['env-override>', 'env-claim>', 'unattested>', 'unrecognised>'] as const;

export function isClaimStampedIdentifier(identifier: string): boolean {
  const id = identifier.toLowerCase();
  return CLAIM_STAMP_PREFIXES.some((prefix) => id.startsWith(prefix));
}

/**
 * True when a stored `type:identifier` (or bare type) is untrusted inbound for
 * shared-context bootstrap. Prefer this over {@link isUntrustedInboundType}
 * when the full source string is available — type-only cannot see #283 stamps.
 */
export function isUntrustedInboundSourceString(source: string | null | undefined): boolean {
  if (!source) return false;
  const sep = source.indexOf(':');
  const type = (sep === -1 ? source : source.slice(0, sep)).toLowerCase();
  const identifier = sep === -1 ? '' : source.slice(sep + 1);
  return isUntrustedInbound(type, identifier);
}

export function isUntrustedInbound(type: string, identifier = ''): boolean {
  const normalised = type.toLowerCase();
  const score = TYPE_SCORES[normalised as DefenceSource['type']];
  if (score === undefined) return true;
  // Agent is exempt ONLY when host-attested (no claim stamp). A stamped agent
  // row is a self-applied or integrator label — treat as inbound.
  if (normalised === 'agent') {
    return isClaimStampedIdentifier(identifier);
  }
  return score < UNTRUSTED_INBOUND_FLOOR;
}

/** @deprecated Prefer {@link isUntrustedInbound} with identifier when available. */
export function isUntrustedInboundType(type: string): boolean {
  // Type-only path: agent without identifier is treated as potentially
  // host-attested (legacy callers). New code must pass the identifier.
  return isUntrustedInbound(type, '');
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
  const key = `${source.type}:${source.identifier}`;
  // Score off the BARE identifier: the ownership stamp separates a self-declared
  // identity from the host-attested one of the same name, and must not move the
  // number in either direction. `agent` is the exception — see scoreAgent, where
  // a stamped identifier is barred from claiming a privileged origin.
  const bareKey = `${source.type}:${stripUnattestedStamp(source.identifier)}`;

  // A3 import-once assigns a per-chunk identifier so bulk imports do not share
  // one rate-limit bucket. Keep every such file at the same thin 0.4 trust as
  // file:import; the prefix can only lower generic file trust, never raise it.
  if (source.type === 'file' && stripUnattestedStamp(source.identifier).startsWith('native-import:')) {
    const score = BASE_SCORES['file:import'];
    return { score, source, hierarchy: [...HIERARCHY_DISPLAY, `>> ${key} = ${score}`] };
  }

  // Exact match overrides
  const baseScore = BASE_SCORES[bareKey];
  if (baseScore !== undefined) {
    return { score: baseScore, source, hierarchy: [...HIERARCHY_DISPLAY, `>> ${key} = ${baseScore}`] };
  }

  // Agent hierarchy scoring
  if (source.type === 'agent') {
    const score = scoreAgent(source.identifier);
    return {
      score,
      source,
      hierarchy: [
        'Agent Hierarchy:',
        ...buildAgentHierarchy(source.identifier),
        `>> ${key} = ${score}`,
      ],
    };
  }

  // Type fallback
  const score = TYPE_SCORES[source.type] ?? 0;
  return { score, source, hierarchy: [...HIERARCHY_DISPLAY, `>> ${key} = ${score}`] };
}
