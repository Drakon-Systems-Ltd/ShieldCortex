/**
 * Memory access control — enforces read/write/delete policies based on trust.
 *
 * Access rules:
 *   Trust ≥ 0.7  → Read all, write direct, delete own
 *   Trust 0.5–0.7 → Read own + non-restricted, write quarantine, delete own
 *   Trust < 0.5  → Read own only, write quarantine, delete none
 *
 * RESTRICTED memories are always blocked below trust 0.7 (credential isolation).
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

/**
 * Check whether a source has access to a memory for a given operation.
 */
export function checkAccess(
  memory: AccessCheckMemory,
  source: DefenceSource,
  operation: 'read' | 'write' | 'delete',
): AccessPolicy {
  const trust = scoreSource(source).score;
  const memorySource = memory.source || '__system:unattributed';
  const callerKey = `${source.type}:${source.identifier}`;
  const isOwner = memorySource === callerKey;
  const isRestricted = memory.sensitivity_level === 'RESTRICTED';

  if (operation === 'read') {
    // RESTRICTED memories: credential isolation
    if (isRestricted && trust < 0.7) {
      return deny('Credential isolation: insufficient trust for RESTRICTED data');
    }

    // Owner always reads own
    if (isOwner) {
      return allow('Owner access');
    }

    // High trust: read all
    if (trust >= 0.7) {
      return allow('High-trust read access');
    }

    // Medium trust: read non-restricted
    if (trust >= 0.5) {
      return allow('Shared read access');
    }

    // Low trust: own only (already checked above)
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
