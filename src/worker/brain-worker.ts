/**
 * Brain Worker
 *
 * Phase 4 Organic Brain Feature
 *
 * Background worker that performs brain-like maintenance operations:
 * - Light tick (5 min): Prune activation cache, check predictive consolidation
 * - Medium tick (30 min): Discover missing links, scan for contradictions
 *
 * This transforms the memory system from reactive to continuously organic.
 */

import {
  WorkerConfig,
  DEFAULT_WORKER_CONFIG,
  LightTickResult,
  MediumTickResult,
  WorkerStatus,
  MCP_LIGHT_TICK_INTERVAL_MS,
} from './types.js';
import { getDatabase } from '../database/init.js';
import { pruneActivationCache } from '../memory/activation.js';
import { getMemoryStats } from '../memory/store.js';
import { consolidate } from '../memory/consolidate.js';
import {
  detectContradictions,
  linkContradictions,
} from '../memory/contradiction.js';
import { discoverMissingLinks, findUnlinkedMemories } from './link-discovery.js';
import { shouldTriggerPredictiveConsolidation } from './predictive-consolidation.js';
import {
  emitWorkerLightTick,
  emitWorkerMediumTick,
  emitPredictiveConsolidation,
} from '../api/events.js';
import { processRetryQueue, purgeOldEntries } from '../cloud/sync-queue.js';
import { sendHeartbeat } from '../cloud/sync.js';
import { refreshCloudIronDome, applyCachedCloudPatterns } from '../cloud/iron-dome-sync.js';
import { isFeatureEnabled } from '../license/gate.js';
import { existsSync, mkdirSync, writeFileSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

const WORKER_STATE_DIR = join(homedir(), '.shieldcortex', 'state');
const WORKER_STATE_FILE = join(WORKER_STATE_DIR, 'worker.json');

function persistWorkerState(profile: string, lastLightTick: Date): void {
  try {
    if (!existsSync(WORKER_STATE_DIR)) mkdirSync(WORKER_STATE_DIR, { recursive: true });
    writeFileSync(
      WORKER_STATE_FILE,
      JSON.stringify({ pid: process.pid, profile, lastLightTick: lastLightTick.toISOString() }, null, 2),
      'utf-8'
    );
  } catch {
    // Best-effort: doctor will warn if the file is stale or missing
  }
}

/**
 * Brain Worker Class
 *
 * Manages background processing timers and operations.
 * Designed to be started by the visualization server and run continuously.
 */
export class BrainWorker {
  private lightTimer: NodeJS.Timeout | null = null;
  private mediumTimer: NodeJS.Timeout | null = null;
  private initialLightTickTimer: NodeJS.Timeout | null = null;
  private isRunning = false;
  private config: WorkerConfig;

  // Statistics tracking
  private stats = {
    lightTicks: 0,
    mediumTicks: 0,
    consolidations: 0,
  };

  // Timestamps
  private lastLightTick: Date | null = null;
  private lastMediumTick: Date | null = null;
  private lastConsolidation: Date | null = null;

  /**
   * Create a new BrainWorker
   *
   * @param config - Partial configuration to override defaults. When `profile`
   *                is 'mcp' and no explicit `lightTickIntervalMs` is provided,
   *                the lite 15-minute cadence is applied so MCP-server-mode
   *                workers don't run as often as dashboard-mode ones.
   */
  constructor(config: Partial<WorkerConfig> = {}) {
    const merged = { ...DEFAULT_WORKER_CONFIG, ...config };
    if (merged.profile === 'mcp' && config.lightTickIntervalMs === undefined) {
      merged.lightTickIntervalMs = MCP_LIGHT_TICK_INTERVAL_MS;
    }
    this.config = merged;
  }

  /**
   * Start the background worker
   * Sets up interval timers for light and medium ticks
   */
  start(): void {
    if (this.isRunning) {
      console.log('[BrainWorker] Already running');
      return;
    }

    this.isRunning = true;
    console.log(`[BrainWorker] Starting background worker (profile=${this.config.profile} pid=${process.pid})`);
    console.log(`[BrainWorker] Light tick interval: ${this.config.lightTickIntervalMs / 1000}s`);
    if (this.config.profile === 'full') {
      console.log(`[BrainWorker] Medium tick interval: ${this.config.mediumTickIntervalMs / 1000}s`);
    } else {
      console.log('[BrainWorker] MCP profile — medium tick + cloud sync disabled');
    }

    // Light tick — every 5 min (full) or every 15 min (mcp)
    this.lightTimer = setInterval(
      () => this.lightTick(),
      this.config.lightTickIntervalMs
    );
    this.lightTimer.unref();

    // Medium tick — full profile only. mcp-mode skips link discovery,
    // contradiction scans, graph maintenance, and sync-queue purging — those
    // are dashboard concerns and shouldn't multiply across N MCP windows.
    if (this.config.profile === 'full') {
      this.mediumTimer = setInterval(
        () => this.mediumTick(),
        this.config.mediumTickIntervalMs
      );
      this.mediumTimer.unref();
    }

    // Apply cached cloud Iron Dome patterns immediately on start (Pro+, full only)
    if (this.config.profile === 'full' && isFeatureEnabled('custom_injection_patterns')) {
      try {
        applyCachedCloudPatterns();
      } catch {
        // Non-critical — cloud patterns are best-effort
      }
    }

    // Run initial light tick after a short delay (10 seconds)
    // This allows the server to fully initialize first
    this.initialLightTickTimer = setTimeout(() => {
      if (this.isRunning) {
        this.lightTick();
      }
    }, 10000);
    this.initialLightTickTimer.unref();
  }

  /**
   * Stop the background worker
   * Clears all interval timers
   */
  stop(): void {
    if (!this.isRunning) {
      console.log('[BrainWorker] Not running');
      return;
    }

    this.isRunning = false;

    if (this.lightTimer) {
      clearInterval(this.lightTimer);
      this.lightTimer = null;
    }

    if (this.mediumTimer) {
      clearInterval(this.mediumTimer);
      this.mediumTimer = null;
    }

    if (this.initialLightTickTimer) {
      clearTimeout(this.initialLightTickTimer);
      this.initialLightTickTimer = null;
    }

    console.log('[BrainWorker] Stopped');
  }

  /**
   * Check if the worker is currently running
   */
  isActive(): boolean {
    return this.isRunning;
  }

  /**
   * Light tick - runs every 5 minutes
   *
   * Operations:
   * 1. Prune stale activation cache entries
   * 2. Check if predictive consolidation should run
   */
  async lightTick(): Promise<LightTickResult> {
    const result: LightTickResult = {
      activationsPruned: 0,
      predictiveConsolidation: null,
      timestamp: new Date(),
    };

    try {
      // 1. Prune activation cache
      result.activationsPruned = pruneActivationCache();

      // 2. Check if predictive consolidation is needed
      const stats = getMemoryStats();
      const decision = shouldTriggerPredictiveConsolidation(stats, this.config);

      if (decision.shouldRun) {
        console.log(`[BrainWorker] Predictive consolidation triggered: ${decision.reason}`);
        result.predictiveConsolidation = consolidate();
        this.lastConsolidation = new Date();
        this.stats.consolidations++;

        // Emit event for dashboard
        emitPredictiveConsolidation({
          trigger: decision.reason,
          urgency: decision.urgency,
          result: result.predictiveConsolidation,
        });
      }

      // 3-5: cloud sync (retry queue, heartbeat, Iron Dome) — full profile only.
      // Skipped under MCP profile so we don't fan out N concurrent network calls
      // from N open Claude Code windows.
      if (this.config.profile === 'full') {
        try {
          const retryResult = await processRetryQueue();
          if (retryResult.processed > 0) {
            console.log(
              `[BrainWorker] Sync retry queue: processed ${retryResult.processed} ` +
              `(${retryResult.succeeded} ok, ${retryResult.failed} retry, ${retryResult.permanentlyFailed} failed)`
            );
          }
        } catch (retryError) {
          console.error('[BrainWorker] Sync retry queue failed:', retryError);
        }

        if (isFeatureEnabled('cloud_sync')) {
          try {
            sendHeartbeat();
          } catch {
            // Truly silent — heartbeat is best-effort
          }
        }

        if (isFeatureEnabled('custom_injection_patterns')) {
          try {
            await refreshCloudIronDome();
          } catch {
            // Non-critical — cloud Iron Dome sync is best-effort
          }
        }
      }

      // Update stats
      this.lastLightTick = result.timestamp;
      this.stats.lightTicks++;

      // Persist worker freshness for `shieldcortex doctor` to detect stalls.
      persistWorkerState(this.config.profile, result.timestamp);

      // Emit light tick event
      emitWorkerLightTick(result);

      // Log summary
      if (result.activationsPruned > 0 || result.predictiveConsolidation) {
        console.log(
          `[BrainWorker] Light tick: pruned ${result.activationsPruned} activations` +
          (result.predictiveConsolidation
            ? `, consolidated ${result.predictiveConsolidation.consolidated}`
            : '')
        );
      }

    } catch (e) {
      console.error('[BrainWorker] Light tick failed:', e);
    }

    return result;
  }

  /**
   * Medium tick - runs every 30 minutes
   *
   * Operations:
   * 1. Discover and create missing links
   * 2. Scan for contradictions
   */
  async mediumTick(): Promise<MediumTickResult> {
    const result: MediumTickResult = {
      linksDiscovered: 0,
      contradictionsFound: 0,
      contradictionsLinked: 0,
      memoriesScanned: 0,
      timestamp: new Date(),
    };

    try {
      // 1. Link discovery - find unlinked memories and create relationships
      const unlinked = findUnlinkedMemories(this.config.maxLinksPerCycle);
      result.memoriesScanned = unlinked.length;
      result.linksDiscovered = discoverMissingLinks(this.config.maxLinksPerCycle);

      // 2. Contradiction scan
      const contradictions = detectContradictions({
        minScore: 0.5,
        limit: this.config.contradictionScanLimit,
      });
      result.contradictionsFound = contradictions.length;
      result.contradictionsLinked = linkContradictions(contradictions);

      // Update stats
      this.lastMediumTick = result.timestamp;
      this.stats.mediumTicks++;

      // Emit medium tick event
      emitWorkerMediumTick(result);

      // Log summary
      console.log(
        `[BrainWorker] Medium tick: scanned ${result.memoriesScanned} memories, ` +
        `discovered ${result.linksDiscovered} links, ` +
        `found ${result.contradictionsFound} contradictions`
      );

    } catch (e) {
      console.error('[BrainWorker] Medium tick failed:', e);
    }

    // ONTOLOGY: Graph maintenance — prune orphan entities
    try {
      const db = getDatabase();
      const orphans = db.prepare(`
        SELECT e.id FROM entities e
        WHERE e.memory_count = 0
        AND NOT EXISTS (SELECT 1 FROM triples WHERE subject_id = e.id OR object_id = e.id)
      `).all() as Array<{ id: number }>;

      if (orphans.length > 0) {
        const deleteStmt = db.prepare('DELETE FROM entities WHERE id = ?');
        for (const orphan of orphans) {
          deleteStmt.run(orphan.id);
        }
      }

      const entityCount = (db.prepare('SELECT COUNT(*) as c FROM entities').get() as { c: number }).c;
      const tripleCount = (db.prepare('SELECT COUNT(*) as c FROM triples').get() as { c: number }).c;
      console.log(`[brain-worker] Graph: ${entityCount} entities, ${tripleCount} triples${orphans.length > 0 ? `, pruned ${orphans.length} orphans` : ''}`);
    } catch (e) {
      console.error('[brain-worker] Graph maintenance failed:', e);
    }

    // Purge old sync queue entries (> 7 days)
    try {
      const purged = purgeOldEntries();
      if (purged > 0) {
        console.log(`[BrainWorker] Purged ${purged} old sync queue entries`);
      }
    } catch (e) {
      console.error('[BrainWorker] Sync queue purge failed:', e);
    }

    return result;
  }

  /**
   * Get current worker status
   */
  getStatus(): WorkerStatus {
    return {
      isRunning: this.isRunning,
      lastLightTick: this.lastLightTick,
      lastMediumTick: this.lastMediumTick,
      lastConsolidation: this.lastConsolidation,
      stats: { ...this.stats },
    };
  }

  /**
   * Get current configuration
   */
  getConfig(): WorkerConfig {
    return { ...this.config };
  }

  /**
   * Update configuration
   * Note: Changes won't affect running timers until restart
   */
  updateConfig(config: Partial<WorkerConfig>): void {
    this.config = { ...this.config, ...config };
  }

  // Manual triggers for testing and API endpoints

  /**
   * Manually trigger a light tick
   * Useful for testing or immediate cache pruning
   */
  triggerLightTick(): Promise<LightTickResult> {
    return this.lightTick();
  }

  /**
   * Manually trigger a medium tick
   * Useful for testing or immediate link discovery
   */
  triggerMediumTick(): Promise<MediumTickResult> {
    return this.mediumTick();
  }
}

// Default singleton instance (optional - server can create its own)
let defaultWorker: BrainWorker | null = null;

/**
 * Get or create the default worker instance.
 * The first call wins — subsequent calls return the existing singleton even
 * if a different config is passed. That's intentional: it prevents accidental
 * re-instantiation from creating two competing timer sets within one process.
 */
export function getDefaultWorker(config?: Partial<WorkerConfig>): BrainWorker {
  if (!defaultWorker) {
    defaultWorker = new BrainWorker(config);
  }
  return defaultWorker;
}

/**
 * Start the default worker if not already running. Forwards config to the
 * underlying constructor on first call (used by MCP-server mode to start
 * with `profile: 'mcp'`).
 */
export function startDefaultWorker(config?: Partial<WorkerConfig>): BrainWorker {
  const worker = getDefaultWorker(config);
  if (!worker.isActive()) {
    worker.start();
  }
  return worker;
}

/**
 * Stop the default worker
 */
export function stopDefaultWorker(): void {
  if (defaultWorker) {
    defaultWorker.stop();
  }
}
