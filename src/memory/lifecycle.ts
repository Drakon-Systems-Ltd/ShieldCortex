/**
 * Memory lifecycle operations.
 *
 * Phase 2 of the audit-recommended store.ts split. The "lifecycle"
 * group is the set of functions that mutate a memory's state over
 * time *without* being CRUD: access reinforcement, search
 * reinforcement, enrichment, decay-score persistence, STM→LTM
 * promotion, and bulk decay cleanup. Lifted out of store.ts (still
 * 1,800+ lines after phase 1) so each concern can be read on its
 * own. No behaviour change vs the original implementation — exports
 * re-emerge from store.ts via a barrel re-export so existing import
 * paths keep working.
 *
 * Imports from store.ts (getMemoryById, rowToMemory, getMemoriesByType,
 * MAX_CONTENT_SIZE) form a module cycle. Both directions only invoke
 * the imported symbols inside function bodies — ESM live bindings
 * handle this correctly at runtime. As of phase 3, reinforceFromSearch
 * and enrichMemory are consumed by search-recall.ts (not store.ts);
 * that import is non-cyclic since search-recall.ts is a leaf consumer
 * of lifecycle.ts.
 */

import { getDatabase } from '../database/init.js';
import {
  Memory,
  MemoryConfig,
  DEFAULT_CONFIG,
} from './types.js';
import {
  calculateReinforcementBoost,
  calculateDecayedScore,
  AUTO_EXTRACT_SALIENCE_CAP,
} from './decay.js';
import { activateMemory as spreadActivation } from './activation.js';
import { jaccardSimilarity } from './similarity.js';
import {
  emitMemoryAccessed,
  emitMemoryUpdated,
  persistEvent,
} from '../api/events.js';
import { createMemoryLink } from './links.js';
import type { DefenceSource } from '../defence/types.js';
import { runDefencePipeline } from '../defence/index.js';
import { createContentHash } from '../defence/audit/logger.js';

// Enrichment text is recall-query / caller-derived (attacker-influenced); scan
// it before persisting. Trust doesn't matter here (the row keeps its own) — we
// only act on the firewall verdict, so a low-trust web source is fine.
const ENRICH_SOURCE: DefenceSource = { type: 'web', identifier: 'enrichment' };
// Cyclic import — see header. getMemoryById/rowToMemory/getMemoriesByType
// live in store.ts; MAX_CONTENT_SIZE is the per-memory content budget
// that both truncateContent (store.ts) and enrichMemory (here) honour.
import {
  getMemoryById,
  rowToMemory,
  getMemoriesByType,
  MAX_CONTENT_SIZE,
} from './store.js';

/**
 * Access a memory (updates access count and timestamp, returns reinforced memory)
 */
export function accessMemory(
  id: number,
  config: MemoryConfig = DEFAULT_CONFIG,
  source?: DefenceSource,
): Memory | null {
  const db = getDatabase();
  const memory = getMemoryById(id, source);
  if (!memory) return null;

  // Calculate new salience with reinforcement
  const newSalience = calculateReinforcementBoost(memory, config);

  db.prepare(`
    UPDATE memories
    SET access_count = access_count + 1,
        last_accessed = CURRENT_TIMESTAMP,
        salience = ?
    WHERE id = ?
  `).run(newSalience, id);

  const updatedMemory = getMemoryById(id)!;

  // Load entity_ids so the pulse layer can highlight related graph nodes
  // on access. Mirrors the entity_ids payload extension on memory_created.
  const entityIds = (
    db
      .prepare('SELECT entity_id FROM memory_entities WHERE memory_id = ?')
      .all(id) as { entity_id: number }[]
  ).map((r) => r.entity_id);

  // Emit event for real-time dashboard (in-process)
  emitMemoryAccessed(updatedMemory, newSalience, entityIds);
  // Persist event for cross-process IPC (MCP → Dashboard)
  persistEvent('memory_accessed', {
    memoryId: id,
    memory: updatedMemory,
    newSalience,
    entity_ids: entityIds,
  });

  // ORGANIC FEATURE: Link strengthening on co-access
  // If memory A and B are both accessed within 5 minutes, strengthen their link
  // This mimics Hebbian learning: "neurons that fire together, wire together"
  try {
    const recentlyAccessed = db.prepare(`
      SELECT id FROM memories
      WHERE last_accessed > datetime('now', '-5 minutes')
        AND id != ?
      LIMIT 10
    `).all(id) as { id: number }[];

    for (const recent of recentlyAccessed) {
      // Check if link exists in either direction
      const existingLink = db.prepare(`
        SELECT id, strength FROM memory_links
        WHERE (source_id = ? AND target_id = ?) OR (source_id = ? AND target_id = ?)
      `).get(id, recent.id, recent.id, id) as { id: number; strength: number } | undefined;

      if (existingLink) {
        // Strengthen existing link (cap at 1.0)
        const newStrength = Math.min(1.0, existingLink.strength + 0.05);
        db.prepare('UPDATE memory_links SET strength = ? WHERE id = ?')
          .run(newStrength, existingLink.id);
      } else {
        // Create new weak link for co-accessed memories
        createMemoryLink(id, recent.id, 'related', 0.2);
      }
    }
  } catch (e) {
    // Don't fail memory access if link strengthening fails
    console.error('[shieldcortex] Link strengthening failed:', e);
  }

  // ORGANIC FEATURE: Spreading Activation (Phase 2)
  // Activate this memory and spread activation to linked memories
  // This makes related memories easier to recall in subsequent searches
  spreadActivation(id);

  return updatedMemory;
}

/**
 * Reinforce a memory that appeared in search results
 * Gives a small salience boost with diminishing returns based on access count.
 * ORGANIC FEATURE: Searched memories get reinforced, closing the feedback loop
 * so frequently-found memories grow stronger over time.
 */
export function reinforceFromSearch(memoryId: number): void {
  const db = getDatabase();
  const memory = db.prepare('SELECT salience, access_count, capture_method FROM memories WHERE id = ?').get(memoryId) as any;
  if (!memory) return;

  // Small salience boost per search appearance (diminishing returns)
  const boost = Math.max(0.005, 0.02 / (1 + memory.access_count * 0.1));
  // Forward-only ratchet cap (Phase 1a): auto-extracted captures never reinforce
  // past the 0.6 extraction cap; deliberate captures keep the 1.0 ceiling.
  const ceiling = memory.capture_method === 'auto' ? AUTO_EXTRACT_SALIENCE_CAP : 1.0;
  const newSalience = Math.min(ceiling, memory.salience + boost);

  db.prepare(`
    UPDATE memories
    SET last_accessed = CURRENT_TIMESTAMP,
        access_count = access_count + 1,
        salience = ?
    WHERE id = ?
  `).run(newSalience, memoryId);
}

// ============================================
// ORGANIC FEATURE: Memory Enrichment (Phase 3)
// ============================================

// Enrichment configuration
const ENRICHMENT_SIMILARITY_THRESHOLD = 0.3; // Min similarity to trigger enrichment
const ENRICHMENT_COOLDOWN_HOURS = 1; // Don't enrich same memory within 1 hour
const MAX_ENRICHMENT_SIZE = 2000; // Max chars to add per enrichment

// Track last enrichment times (in-memory, ephemeral like activation cache)
const enrichmentTimestamps = new Map<number, number>();
let enrichmentCallCount = 0;

function pruneEnrichmentTimestamps(): void {
  const now = Date.now();
  const cooldownMs = ENRICHMENT_COOLDOWN_HOURS * 60 * 60 * 1000;
  for (const [memoryId, timestamp] of enrichmentTimestamps) {
    if (now - timestamp > cooldownMs) {
      enrichmentTimestamps.delete(memoryId);
    }
  }
}

/**
 * Enrichment result indicating what happened
 */
export interface EnrichmentResult {
  enriched: boolean;
  reason: string;
}

/**
 * Enrich a memory with additional context
 *
 * This adds timestamped context to a memory when:
 * 1. The new context is sufficiently related but different (new information)
 * 2. The memory hasn't been enriched recently (cooldown)
 * 3. The content won't exceed the size limit
 *
 * ORGANIC FEATURE: Memories grow with new context over time,
 * mimicking how human memories are reconsolidated with new information
 *
 * @param memoryId - ID of the memory to enrich
 * @param newContext - New context to add
 * @param contextType - Type of context ('search' | 'access' | 'related')
 * @returns EnrichmentResult indicating success or failure with reason
 */
export function enrichMemory(
  memoryId: number,
  newContext: string,
  contextType: 'search' | 'access' | 'related' = 'access'
): EnrichmentResult {
  // Prune stale cooldown entries every 100 calls
  if (++enrichmentCallCount % 100 === 0) {
    pruneEnrichmentTimestamps();
  }

  const db = getDatabase();
  const memory = getMemoryById(memoryId);

  if (!memory) {
    return { enriched: false, reason: 'Memory not found' };
  }

  // Check cooldown
  const lastEnrichment = enrichmentTimestamps.get(memoryId);
  const now = Date.now();
  if (lastEnrichment && (now - lastEnrichment) < ENRICHMENT_COOLDOWN_HOURS * 60 * 60 * 1000) {
    return { enriched: false, reason: 'Enrichment cooldown active' };
  }

  // Check similarity - should be related but not too similar (new info)
  const similarity = jaccardSimilarity(memory.content, newContext);
  if (similarity > 0.8) {
    return { enriched: false, reason: 'Context too similar (no new information)' };
  }
  if (similarity < ENRICHMENT_SIMILARITY_THRESHOLD) {
    return { enriched: false, reason: 'Context not sufficiently related' };
  }

  // Truncate context if needed
  const truncatedContext = newContext.slice(0, MAX_ENRICHMENT_SIZE);

  // Build enrichment block with timestamp
  const timestamp = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
  const enrichmentBlock = `\n\n---\n[${timestamp}] ${contextType}: ${truncatedContext}`;

  // Check size limit (leave 500 char buffer for future enrichments)
  const newContent = memory.content + enrichmentBlock;
  if (newContent.length > MAX_CONTENT_SIZE - 500) {
    return { enriched: false, reason: 'Content size limit reached' };
  }

  // DEFENCE: re-scan the merged content before persisting — the read-path
  // analogue of mergeMemories. The appended text comes from a recall query /
  // caller and could straddle an injection or credential into a clean stored
  // row. Skip (don't poison) on a non-ALLOW verdict.
  // ENRICH_SOURCE is a code constant (attested by construction). Keep the
  // deliberate low-trust scan for the VERDICT (see the source note above) but
  // stamp attestation so an enrichment-channel BLOCK accrues to that channel
  // instead of dropping to NULL. Trust and attestation are separate concerns.
  const defenceResult = runDefencePipeline(newContent, memory.title, ENRICH_SOURCE, undefined, memory.project ?? undefined, { sourceAttested: true });
  if (defenceResult.firewall.result !== 'ALLOW') {
    return { enriched: false, reason: `Enrichment blocked by defence: ${defenceResult.firewall.reason}` };
  }

  // Update memory (recompute content_hash — the integrity snapshot must track
  // the enriched content, not the pre-enrichment original).
  db.prepare(`
    UPDATE memories
    SET content = ?,
        content_hash = ?,
        last_accessed = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(newContent, createContentHash(newContent), memoryId);

  // Update cooldown timestamp
  enrichmentTimestamps.set(memoryId, now);

  // Emit update event for dashboard
  const updatedMemory = getMemoryById(memoryId)!;
  emitMemoryUpdated(updatedMemory);

  return { enriched: true, reason: `Added ${contextType} context (${truncatedContext.length} chars)` };
}

/**
 * Clear enrichment cooldown for a memory (for testing)
 */
export function clearEnrichmentCooldown(memoryId: number): void {
  enrichmentTimestamps.delete(memoryId);
}

/**
 * Get enrichment cooldown status for a memory
 */
export function getEnrichmentCooldownStatus(memoryId: number): {
  onCooldown: boolean;
  remainingMs: number;
} {
  const lastEnrichment = enrichmentTimestamps.get(memoryId);
  if (!lastEnrichment) {
    return { onCooldown: false, remainingMs: 0 };
  }

  const cooldownMs = ENRICHMENT_COOLDOWN_HOURS * 60 * 60 * 1000;
  const elapsed = Date.now() - lastEnrichment;
  const remaining = Math.max(0, cooldownMs - elapsed);

  return {
    onCooldown: remaining > 0,
    remainingMs: remaining,
  };
}

/**
 * Update persisted decay scores for all memories
 * Called during consolidation and periodically by the API server
 * Returns the number of memories updated
 */
export function updateDecayScores(): number {
  const db = getDatabase();

  // Get all memories
  const memories = db.prepare('SELECT * FROM memories').all() as Record<string, unknown>[];

  let updated = 0;
  const updateStmt = db.prepare('UPDATE memories SET decayed_score = ? WHERE id = ?');

  for (const row of memories) {
    const memory = rowToMemory(row);
    const decayedScore = calculateDecayedScore(memory);

    // Only update if score has changed significantly (saves writes)
    const currentScore = row.decayed_score as number | null;
    if (currentScore === null || Math.abs(currentScore - decayedScore) > 0.01) {
      updateStmt.run(decayedScore, memory.id);
      updated++;
    }
  }

  return updated;
}

/**
 * Promote a memory from short-term to long-term
 */
export function promoteMemory(id: number): Memory | null {
  const db = getDatabase();
  db.prepare(`
    UPDATE memories
    SET type = 'long_term'
    WHERE id = ? AND type = 'short_term'
  `).run(id);

  return getMemoryById(id);
}

/**
 * Bulk delete decayed memories
 */
export function cleanupDecayedMemories(
  config: MemoryConfig = DEFAULT_CONFIG
): number {
  const db = getDatabase();

  // Get all short-term memories and check decay
  const shortTerm = getMemoriesByType('short_term', 1000);
  const toDelete: number[] = [];

  for (const memory of shortTerm) {
    const decayedScore = calculateDecayedScore(memory, config);
    if (decayedScore < config.salienceThreshold) {
      toDelete.push(memory.id);
    }
  }

  if (toDelete.length > 0) {
    const placeholders = toDelete.map(() => '?').join(',');
    db.prepare(`DELETE FROM memories WHERE id IN (${placeholders})`).run(...toDelete);
  }

  return toDelete.length;
}
