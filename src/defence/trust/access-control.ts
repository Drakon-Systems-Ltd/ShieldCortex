/**
 * Memory access control — enforces read/write/delete policies based on trust.
 *
 * Access rules:
 *   Trust ≥ 0.7  → Read all non-RESTRICTED, write direct, delete own
 *   Trust 0.5–0.7 → Read own + non-restricted, write quarantine, delete own
 *   Trust < 0.5  → Read own only, write quarantine, delete none
 *
 * RESTRICTED is owner (trust ≥ 0.7) and attested, or `user` (human operator).
 * A peer high-trust cli/agent is not the operator — credential isolation holds
 * across agents (SCOPE P4).
 *
 * #283: ownership is decided by the host-attested identity key. An unattested
 * caller never matches a stored row as owner, even if the writer-chosen
 * type:identifier string collides. Callers that already went through
 * resolveToolSource have rewritten unattested keys; the `attested` option is
 * the second belt for any path that still holds a bare DefenceSource.
 */

import type { DefenceSource } from '../types.js';
import { scoreSource } from './source-scorer.js';

export interface AccessPolicy {
  canRead: boolean;
  canWrite: boolean;
  canDelete: boolean;
  writeRequiresQuarantine: boolean;
  reason: string;
}

/** Minimal memory shape needed for access checks */
export interface AccessCheckMemory {
  id: number;
  source?: string | null; // stored as "type:identifier"
  sensitivity_level?: string | null;
}

export interface AccessCheckOptions {
  /**
   * #283 — from ResolvedToolSource.attested. When false, the caller is not
   * host-attested and cannot be treated as owner of any stored row. Deliberately
   * NOT a field on DefenceSource (caller-suppliable). Default true preserves
   * legacy internal callers that already hold host-derived identities.
   */
  attested?: boolean;
}

/** Parse a stored "type:identifier" source string back into a DefenceSource. */
function parseStoredSource(stored: string): DefenceSource {
  const i = stored.indexOf(':');
  if (i === -1) return { type: 'agent', identifier: stored }; // unknown shape → low-trust agent
  return { type: stored.slice(0, i) as DefenceSource['type'], identifier: stored.slice(i + 1) };
}

/**
 * Check whether a source has access to a memory for a given operation.
 *
 * @param options.attested — pass ResolvedToolSource.attested from the resolve
 *   path. `false` denies ownership (read own / delete own / revoke own).
 */
export function checkAccess(
  memory: AccessCheckMemory,
  source: DefenceSource,
  operation: 'read' | 'write' | 'delete' | 'revoke',
  options?: AccessCheckOptions,
): AccessPolicy {
  const trust = scoreSource(source).score;
  const memorySource = memory.source || '__system:unattributed';
  const callerKey = `${source.type}:${source.identifier}`;
  // #283: unattested callers never own. Host-attested equality still required.
  const attested = options?.attested !== false;
  const isOwner = attested && memorySource === callerKey;
  const isRestricted = memory.sensitivity_level === 'RESTRICTED';

  if (operation === 'read') {
    // RESTRICTED: credential isolation holds ACROSS agents (SCOPE P4).
    // Owner (trust ≥ 0.7) and the human operator (`user`) may read.
    // A peer cli/agent at 0.9 is not the operator — that was the
    // contamination hole (Edith fetching Jarvis's secrets).
    if (isRestricted) {
      if (trust < 0.7 && source.type !== 'user') {
        return deny('Credential isolation: insufficient trust for RESTRICTED data');
      }
      if (isOwner) {
        return allow('Owner access');
      }
      if (source.type === 'user') {
        return allow('Operator credential access');
      }
      return deny('RESTRICTED is isolated across agents');
    }

    // Owner always reads own (attested identity only — #283)
    if (isOwner) {
      return allow('Owner access');
    }

    // High trust: read all non-RESTRICTED
    if (trust >= 0.7) {
      return allow('High-trust read access');
    }

    // Medium trust: read non-restricted
    if (trust >= 0.5) {
      return allow('Shared read access');
    }

    // Low trust: own only (already checked above). Unattested low-trust that
    // string-matched a host row used to fall through as owner — that door is shut.
    if (!attested && memorySource === callerKey) {
      return deny('Unattested identity cannot claim ownership');
    }
    return deny('Insufficient trust for shared memories (need ≥0.5)');
  }

  if (operation === 'write') {
    if (trust >= 0.7) {
      return allow('Direct write allowed (high trust)');
    }
    return quarantine(`Sub-agent write requires quarantine (trust=${trust.toFixed(3)})`);
  }

  if (operation === 'delete') {
    if (isOwner && trust >= 0.5) {
      return { canRead: true, canWrite: false, canDelete: true, writeRequiresQuarantine: false, reason: 'Owner deletion' };
    }
    return deny('Can only delete own memories (trust ≥0.5)');
  }

  if (operation === 'revoke') {
    // Trust-hierarchy revoke (revoke-by-source remediation): own cleanup, OR a
    // high-trust caller may purge a STRICTLY lower-trust source's memories.
    // Equal/higher-trust targets are protected, so a 0.9 agent can never revoke
    // user:direct (1.0). Single-row 'delete' stays own-only — this override is
    // reachable only through the explicit revoke path.
    if (isOwner && trust >= 0.5) {
      return { canRead: true, canWrite: false, canDelete: true, writeRequiresQuarantine: false, reason: 'Owner revoke' };
    }
    // Fail-safe: never mass-revoke unattributed / unclassifiable memories. They
    // have no clear owner to outrank, and a 0-trust target would be outranked by
    // any caller — so a high-trust caller must NOT be able to sweep null-source
    // rows by source.
    if (!memory.source || memorySource === '__system:unattributed') {
      return deny('Revoke denied: unattributed memories cannot be revoked by source');
    }
    const targetTrust = scoreSource(parseStoredSource(memorySource)).score;
    if (targetTrust > 0 && trust >= 0.7 && trust > targetTrust) {
      return {
        canRead: true, canWrite: false, canDelete: true, writeRequiresQuarantine: false,
        reason: `Trust-hierarchy revoke (caller ${trust.toFixed(2)} > target ${targetTrust.toFixed(2)})`,
      };
    }
    return deny('Revoke denied: must own the source or outrank it (trust ≥0.7 and strictly > a known target source trust)');
  }

  return deny('Unknown operation');
}

function allow(reason: string): AccessPolicy {
  return { canRead: true, canWrite: true, canDelete: false, writeRequiresQuarantine: false, reason };
}

function deny(reason: string): AccessPolicy {
  return { canRead: false, canWrite: false, canDelete: false, writeRequiresQuarantine: false, reason };
}

function quarantine(reason: string): AccessPolicy {
  return { canRead: true, canWrite: false, canDelete: false, writeRequiresQuarantine: true, reason };
}
