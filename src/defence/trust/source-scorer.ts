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

/**
 * The exact internal native-import source identity (#395). Batch segment is the
 * validated batchId charset, bounded to 128; the file segment is the first 24
 * hex characters of the SHA-256 of the resolved source path.
 */
const NATIVE_IMPORT_SOURCE_SHAPE = /^native-import:[A-Za-z0-9._-]{1,128}:file:[0-9a-f]{24}$/;

export function scoreSource(source: DefenceSource): TrustScore {
  const key = `${source.type}:${source.identifier}`;
  // Score off the BARE identifier: the ownership stamp separates a self-declared
  // identity from the host-attested one of the same name, and must not move the
  // number in either direction. `agent` is the exception — see scoreAgent, where
  // a stamped identifier is barred from claiming a privileged origin.
  const bareKey = `${source.type}:${stripUnattestedStamp(source.identifier)}`;

  // A3 import-once assigns one stable identifier per source file so Class-B and
  // threat-graph accrual span every chunk. Its private bounded store seam owns
  // bulk rate handling, and the importer stamps thin `file:import` trust (0.4).
  //
  // Two conditions, and the second is the one that carries the security weight:
  //
  // 1. The FULL internal shape — `native-import:<batchId>:file:<24 hex>` exactly
  //    as import-native.ts mints it. A bare `native-import:` prefix would be a
  //    caller-spendable namespace on the MCP `source`/`sourceIdentifier` surface.
  // 2. The RAW, UNSTAMPED identifier must match. Exact syntax is a naming
  //    convention, not a capability: an MCP caller can type a well-formed
  //    `native-import:<batch>:file:<24 hex>` just as easily as a malformed one.
  //    What it cannot do is arrive unstamped — resolveToolSource stamps every
  //    identity the environment did not confirm (`unattested>`), and the env
  //    detector never mints this shape. The genuine importer never goes through
  //    that resolver: it calls createNativeImportAdmissionSession directly with
  //    the bare key it minted itself. So "unstamped AND exactly shaped" is
  //    internal provenance, whereas the stripped form is forgeable syntax.
  //
  // Scoring the stripped identifier here would hand a caller the sub-quarantine
  // band: 0.4 sits below SUBAGENT_QUARANTINE_MIN, so any agent could turn its
  // own held 0.6 `file:*` write into a stored one and forge native-import
  // provenance in `memories.source` / `defence_audit.source_identifier`.
  // A stamped, malformed, or otherwise caller-resolved identifier therefore
  // falls through to ordinary `file:*` trust and disposition.
  if (source.type === 'file' && NATIVE_IMPORT_SOURCE_SHAPE.test(source.identifier)) {
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
