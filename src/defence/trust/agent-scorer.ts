/**
 * Agent trust scorer — hierarchical trust decay for sub-agents.
 *
 * Agents encode their lineage in the identifier using '>' separators:
 *   "user-spawned"                    → base trust 0.9
 *   "user-spawned>task-1"             → 0.9 × 0.7 = 0.63
 *   "user-spawned>task-1>subtask-2"   → 0.9 × 0.7² = 0.44
 *   "cron"                            → base trust 0.5
 *   "agent-spawned"                   → base trust 0.3
 *   "env-override>…"                  → pinned 0.5 (integrator env claim)
 *   "unattested>…"                    → self-declared; scores off the bare
 *                                       identifier but may not claim a
 *                                       privileged origin (see attestation-stamp)
 */

import {
  UNATTESTED_ORIGIN,
  isUnattestedIdentifier,
  stampUnattestedIdentifier,
  stripUnattestedStamp,
} from './attestation-stamp.js';

/** Base trust for an origin the environment did not confirm — the `?? 0.3` default. */
const UNPRIVILEGED_ORIGIN_SCORE = 0.3;

export interface AgentTrustConfig {
  /** Base trust scores by spawn origin (first segment of identifier) */
  originScores: Record<string, number>;
  /** Multiplier applied per hierarchy depth level */
  decayFactor: number;
  /** Maximum allowed depth — agents beyond this get score 0 */
  maxDepth: number;
}

export const DEFAULT_AGENT_CONFIG: AgentTrustConfig = {
  originScores: {
    'user-spawned': 0.9,
    'user-approved': 0.85,
    'cron': 0.5,
    'env-override': 0.5,
    'agent-spawned': 0.3,
    'web': 0.2,
  },
  decayFactor: 0.7,
  maxDepth: 5,
};

/**
 * Score an agent based on its hierarchy identifier.
 * Returns a trust score between 0.0 and 1.0.
 */
export function scoreAgent(
  identifier: string,
  config: AgentTrustConfig = DEFAULT_AGENT_CONFIG,
): number {
  // An identity the environment did not confirm scores off its BARE identifier,
  // so the stamp never changes the number — except that it may not claim a
  // privileged origin. `env-override`/`cron`/`user-spawned` all mean "the host
  // or the integrator's env said so"; a writer-chosen string saying it is one of
  // them is exactly the claim under audit, and gets the unprivileged default.
  const selfDeclared = isUnattestedIdentifier(identifier);
  const bare = stripUnattestedStamp(identifier);
  const parts = bare.split('>');
  const origin = parts[0];
  const depth = parts.length - 1;

  // Circuit breaker: block agents beyond max depth
  if (depth > config.maxDepth) return 0;

  // Integrator env claims may keep a unique identifier for ACL, but they
  // cannot ride parent-tier trust. Pin at the origin score (0.5) with no
  // further decay — the cap is a ceiling, not a forced downgrade below it.
  if (origin === 'env-override' && !selfDeclared) {
    return config.originScores['env-override'] ?? 0.5;
  }

  const baseScore = selfDeclared ? UNPRIVILEGED_ORIGIN_SCORE : (config.originScores[origin] ?? 0.3);
  return Math.round(baseScore * Math.pow(config.decayFactor, depth) * 1000) / 1000;
}

/**
 * Get the depth of an agent in its hierarchy (0 = parent).
 */
export function getAgentDepth(identifier: string): number {
  // The stamp is an attestation marker, not a hierarchy level — a stamped
  // identity must not read as one rung deeper than the name it declared.
  return stripUnattestedStamp(identifier).split('>').length - 1;
}

/**
 * Build a human-readable hierarchy showing trust at each level.
 */
export function buildAgentHierarchy(
  identifier: string,
  config: AgentTrustConfig = DEFAULT_AGENT_CONFIG,
): string[] {
  const selfDeclared = isUnattestedIdentifier(identifier);
  const parts = stripUnattestedStamp(identifier).split('>');
  const hierarchy: string[] = [];

  if (selfDeclared) {
    hierarchy.push(`${UNATTESTED_ORIGIN}> (self-declared — environment did not confirm)`);
  }
  for (let i = 0; i < parts.length; i++) {
    const path = parts.slice(0, i + 1).join('>');
    // Score each rung through the stamp so the displayed numbers are the ones
    // the ACL actually uses, not the unstamped identity's.
    const score = scoreAgent(selfDeclared ? stampUnattestedIdentifier(path) : path, config);
    hierarchy.push(`${'  '.repeat(i)}${parts[i]} (trust=${score.toFixed(3)})`);
  }

  return hierarchy;
}
