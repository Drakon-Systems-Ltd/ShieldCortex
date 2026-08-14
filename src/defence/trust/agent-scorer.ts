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
 */

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
    // Integrator / declaration stamps (#273 / #283). env-override is the
    // at-cap pin (0.5). Below-cap claims must NOT use that pin — it would
    // raise 0.3 → 0.5. env-claim / unattested stay at the low-trust floor.
    'env-override': 0.5,
    'env-claim': 0.3,
    'unattested': 0.3,
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
  const parts = identifier.split('>');
  const origin = parts[0];
  const depth = parts.length - 1;

  // Circuit breaker: block agents beyond max depth
  if (depth > config.maxDepth) return 0;

  // Claim stamps (#273 / #283) keep a unique identifier for ACL legibility
  // but cannot ride parent-tier trust or depth decay. Pin at the origin
  // score — the stamp is a ceiling/floor marker, not a hierarchy root.
  if (origin === 'env-override' || origin === 'env-claim' || origin === 'unattested') {
    return config.originScores[origin] ?? (origin === 'env-override' ? 0.5 : 0.3);
  }

  const baseScore = config.originScores[origin] ?? 0.3;
  return Math.round(baseScore * Math.pow(config.decayFactor, depth) * 1000) / 1000;
}

/**
 * Get the depth of an agent in its hierarchy (0 = parent).
 */
export function getAgentDepth(identifier: string): number {
  return identifier.split('>').length - 1;
}

/**
 * Build a human-readable hierarchy showing trust at each level.
 */
export function buildAgentHierarchy(
  identifier: string,
  config: AgentTrustConfig = DEFAULT_AGENT_CONFIG,
): string[] {
  const parts = identifier.split('>');
  const hierarchy: string[] = [];

  for (let i = 0; i < parts.length; i++) {
    const path = parts.slice(0, i + 1).join('>');
    const score = scoreAgent(path, config);
    hierarchy.push(`${'  '.repeat(i)}${parts[i]} (trust=${score.toFixed(3)})`);
  }

  return hierarchy;
}
