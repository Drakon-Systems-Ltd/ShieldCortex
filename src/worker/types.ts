/**
 * Brain Worker Types and Configuration
 *
 * Phase 4 Organic Brain Feature
 *
 * Defines configuration, result types, and status interfaces
 * for the background brain worker.
 */

import { ConsolidationResult } from '../memory/types.js';

/**
 * Worker profile.
 *   - 'full': dashboard / api / worker modes — runs medium tick, cloud sync,
 *     link discovery, the works.
 *   - 'mcp':  default MCP-server mode (one process per Claude Code window) —
 *     keeps consolidation alive but skips heavy/networked work so we don't
 *     multiply background load by the number of open windows. Without this,
 *     hooks-only installs never run consolidation and STM never graduates
 *     to LTM (#45).
 */
export type WorkerProfile = 'full' | 'mcp';

/**
 * Configuration for the brain worker
 */
export interface WorkerConfig {
  /** Light tick interval - activation pruning, predictive check (default: 5 min) */
  lightTickIntervalMs: number;

  /** Medium tick interval - link discovery, contradiction scan (default: 30 min) */
  mediumTickIntervalMs: number;

  /** STM warning threshold - consider consolidation when exceeded (default: 0.7 = 70%) */
  stmWarningThreshold: number;

  /** STM critical threshold - immediate consolidation (default: 0.85 = 85%) */
  stmCriticalThreshold: number;

  /** Total memory warning threshold (default: 0.8 = 80% of 1100 total) */
  totalMemoryWarningThreshold: number;

  /** Max memories to process for link discovery per cycle (default: 10) */
  maxLinksPerCycle: number;

  /** Max contradiction pairs to check per scan (default: 50) */
  contradictionScanLimit: number;

  /** High activity threshold - memories created in 30 min (default: 5) */
  highActivityThreshold: number;

  /** Worker profile - 'full' (default) or 'mcp' (lite, see WorkerProfile docs) */
  profile: WorkerProfile;
}

/**
 * Default worker configuration
 */
export const DEFAULT_WORKER_CONFIG: WorkerConfig = {
  lightTickIntervalMs: 5 * 60 * 1000,       // 5 minutes
  mediumTickIntervalMs: 30 * 60 * 1000,     // 30 minutes
  stmWarningThreshold: 0.7,                  // 70 of 100 STM
  stmCriticalThreshold: 0.85,                // 85 of 100 STM
  totalMemoryWarningThreshold: 0.8,          // 880 of 1100 total
  maxLinksPerCycle: 10,
  contradictionScanLimit: 50,
  highActivityThreshold: 5,
  profile: 'full',
};

/**
 * MCP-profile interval override. 15 min vs full's 5 min — one MCP server runs
 * per Claude Code window, so we want lower per-window cadence to keep total
 * background work in check across many windows.
 */
export const MCP_LIGHT_TICK_INTERVAL_MS = 15 * 60 * 1000;

/**
 * Per-tick budget for the sync retry queue under the MCP profile. MCP-only
 * installs have no full worker, so they MUST drain their own queue or queued
 * audits/memories age out unsent — but one MCP process runs per Claude Code
 * window, so we cap the network work each does per light tick. The full
 * (dashboard) profile keeps its historical unbudgeted cadence.
 */
export const MCP_RETRY_QUEUE_BUDGET = 25;

/**
 * Result of a light tick operation
 */
export interface LightTickResult {
  /** Number of stale activation entries pruned */
  activationsPruned: number;

  /** Consolidation result if predictive consolidation ran, null otherwise */
  predictiveConsolidation: ConsolidationResult | null;

  /** When this tick completed */
  timestamp: Date;
}

/**
 * Result of a medium tick operation
 */
export interface MediumTickResult {
  /** Number of new links discovered and created */
  linksDiscovered: number;

  /** Number of contradictions detected */
  contradictionsFound: number;

  /** Number of contradiction links created */
  contradictionsLinked: number;

  /** Number of memories scanned for links */
  memoriesScanned: number;

  /** When this tick completed */
  timestamp: Date;
}

/**
 * Current status of the brain worker
 */
export interface WorkerStatus {
  /** Whether the worker is currently running */
  isRunning: boolean;

  /** When the last light tick completed */
  lastLightTick: Date | null;

  /** When the last medium tick completed */
  lastMediumTick: Date | null;

  /** When the last predictive consolidation ran */
  lastConsolidation: Date | null;

  /** Cumulative statistics */
  stats: {
    lightTicks: number;
    mediumTicks: number;
    consolidations: number;
  };
}

/**
 * Decision from predictive consolidation check
 */
export interface PredictiveDecision {
  /** Whether consolidation should run */
  shouldRun: boolean;

  /** Human-readable reason for the decision */
  reason: string;

  /** Urgency level of the consolidation need */
  urgency: 'low' | 'medium' | 'high' | 'critical';
}
