/**
 * Predictive Consolidation Module
 *
 * Phase 4 Organic Brain Feature
 *
 * Determines when to run consolidation early based on memory pressure
 * and activity patterns, rather than waiting for the 4-hour cycle.
 */

import { getDatabase } from '../database/init.js';
import { WorkerConfig, PredictiveDecision } from './types.js';
import { resolveMemoryConfig } from '../memory/config.js';
import { pendingConsolidationWork } from '../memory/consolidate.js';
import type { MemoryConfig } from '../memory/types.js';

/**
 * Memory statistics type (matches getMemoryStats return type)
 */
export interface MemoryStats {
  total: number;
  shortTerm: number;
  longTerm: number;
  episodic: number;
  byCategory: Record<string, number>;
  averageSalience: number;
}

/** The caps the trigger measures against: the same resolved caps consolidate() enforces. */
type Caps = Pick<MemoryConfig, 'maxShortTermMemories' | 'maxLongTermMemories'>;

/**
 * Determine if consolidation should run early
 * More intelligent than just waiting for the 4-hour cycle
 *
 * #1121: the trigger agrees with consolidate() on what it can change. A tier
 * strictly OVER its cap fires `critical` (consolidate evicts down to the cap —
 * the enforceMemoryLimitsByTier test). The fullness thresholds fire only when
 * consolidate would promote or decay-delete something; a store sitting at its
 * caps with nothing promotable used to fire "STM at 100% (critical)" every
 * tick while every run changed nothing.
 *
 * @param stats - Current memory statistics
 * @param config - Worker configuration
 * @param memoryConfig - Caps (and decay rules); defaults to the resolved, read-only config
 * @returns Decision object with shouldRun, reason, and urgency
 */
export function shouldTriggerPredictiveConsolidation(
  stats: MemoryStats,
  config: WorkerConfig,
  memoryConfig: MemoryConfig = resolveMemoryConfig(undefined, { readOnly: true }),
): PredictiveDecision {
  const maxShortTerm = memoryConfig.maxShortTermMemories;
  const maxLongTerm = memoryConfig.maxLongTermMemories;
  const stmFullness = stats.shortTerm / maxShortTerm;
  const totalFullness = stats.total / (maxShortTerm + maxLongTerm);

  // Over a cap: consolidate() evicts down to it.
  if (stats.shortTerm > maxShortTerm || stats.longTerm > maxLongTerm) {
    const over = stats.shortTerm > maxShortTerm
      ? `STM over its cap (${stats.shortTerm}/${maxShortTerm})`
      : `LTM over its cap (${stats.longTerm}/${maxLongTerm})`;
    return { shouldRun: true, reason: over, urgency: 'critical' };
  }

  // Below the caps, a fullness threshold only matters if a run would change
  // something. Computed lazily: most ticks never reach a threshold.
  let work: boolean | undefined;
  const hasWork = (): boolean => {
    if (work === undefined) {
      const pending = pendingConsolidationWork(memoryConfig);
      work = pending.overCap || pending.promotable > 0 || pending.expirable > 0;
    }
    return work;
  };

  // Critical: Over 85% STM capacity - consolidate immediately
  if (stmFullness > config.stmCriticalThreshold && hasWork()) {
    return {
      shouldRun: true,
      reason: `STM at ${(stmFullness * 100).toFixed(0)}% (critical threshold)`,
      urgency: 'critical',
    };
  }

  // High: Over 80% total capacity
  if (totalFullness > config.totalMemoryWarningThreshold && hasWork()) {
    return {
      shouldRun: true,
      reason: `Total memory at ${(totalFullness * 100).toFixed(0)}% capacity`,
      urgency: 'high',
    };
  }

  // Medium: Over 70% STM + high recent activity
  if (stmFullness > config.stmWarningThreshold && hasWork()) {
    const db = getDatabase();

    // Check recent activity (memories created in last 30 minutes)
    const recentActivity = db.prepare(`
      SELECT COUNT(*) as count FROM memories
      WHERE created_at > datetime('now', '-30 minutes')
    `).get() as { count: number };

    if (recentActivity.count >= config.highActivityThreshold) {
      return {
        shouldRun: true,
        reason: `STM at ${(stmFullness * 100).toFixed(0)}% with high activity (${recentActivity.count} recent memories)`,
        urgency: 'medium',
      };
    }

    // Check if many memories are below deletion threshold
    // These are candidates for cleanup
    const lowScoreCount = db.prepare(`
      SELECT COUNT(*) as count FROM memories
      WHERE type = 'short_term' AND decayed_score < 0.25
    `).get() as { count: number };

    if (lowScoreCount.count > 15) {
      return {
        shouldRun: true,
        reason: `${lowScoreCount.count} STM memories below salience threshold`,
        urgency: 'medium',
      };
    }
  }

  // No consolidation needed
  return {
    shouldRun: false,
    reason: 'No consolidation triggers met',
    urgency: 'low',
  };
}

/**
 * Get detailed memory pressure information
 * Useful for dashboard visualization and debugging
 *
 * @param stats - Current memory statistics
 * @param config - Worker configuration
 * @returns Object with detailed pressure metrics
 */
export function getMemoryPressure(
  stats: MemoryStats,
  config: WorkerConfig,
  caps: Caps = resolveMemoryConfig(undefined, { readOnly: true }),
): {
  stmFullness: number;
  totalFullness: number;
  ltmFullness: number;
  isWarning: boolean;
  isCritical: boolean;
  recommendation: string;
} {
  const stmFullness = stats.shortTerm / caps.maxShortTermMemories;
  const ltmFullness = stats.longTerm / caps.maxLongTermMemories;
  const totalFullness = stats.total / (caps.maxShortTermMemories + caps.maxLongTermMemories);

  const isCritical = stmFullness > config.stmCriticalThreshold;
  const isWarning = stmFullness > config.stmWarningThreshold ||
    totalFullness > config.totalMemoryWarningThreshold;

  let recommendation = 'Memory levels healthy';
  if (isCritical) {
    recommendation = 'Immediate consolidation recommended';
  } else if (isWarning) {
    recommendation = 'Consider running consolidation soon';
  }

  return {
    stmFullness,
    totalFullness,
    ltmFullness,
    isWarning,
    isCritical,
    recommendation,
  };
}
