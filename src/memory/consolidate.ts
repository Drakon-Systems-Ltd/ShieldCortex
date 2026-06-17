/**
 * Memory Consolidation System
 *
 * Like sleep consolidation in human brains, this system:
 * - Moves worthy short-term memories to long-term storage
 * - Strengthens frequently accessed memories
 * - Cleans up decayed/irrelevant memories
 * - Merges similar memories to reduce redundancy
 */

import type Database from 'better-sqlite3';
import { getDatabase, withTransaction } from '../database/init.js';
import { expireQuarantineItems } from '../defence/quarantine/auto-expire.js';
import {
  Memory,
  MemoryConfig,
  DEFAULT_CONFIG,
  ConsolidationResult,
  ContextSummary,
} from './types.js';
import {
  getMemoriesByType,
  getRecentMemories,
  getHighPriorityMemories,
  promoteMemory,
  deleteMemory,
  searchMemories,
  getMemoryStats,
  updateDecayScores,
  addMemory,
  rowToMemory,
} from './store.js';
import {
  calculateDecayedScore,
  shouldPromoteToLongTerm,
  shouldPromoteEpisodic,
  shouldDelete,
  processDecay,
} from './decay.js';
import {
  detectContradictions,
  linkContradictions,
} from './contradiction.js';
import { jaccardSimilarity } from './similarity.js';
import { pruneActivationCache } from './activation.js';
// Static import of the shared effective-salience helper. Every other src/ file
// (cli/memory.ts, the recall hook) reaches salience.mjs via a relative path
// because `scripts/` lives outside tsconfig's rootDir; a static top-level
// import compiles clean (tsc keeps the dist layout intact and emits the same
// '../../scripts/lib/salience.mjs' specifier the dynamic import did) and lets
// these consolidation functions stay SYNCHRONOUS — better-sqlite3 transactions
// cannot await, and consolidate()/deduplicateMemories() have several sync
// callers. One source of truth: this is the same computeEffectiveSalience the
// recall hook and `shieldcortex memory downvote` use.
// @ts-expect-error — importing a .mjs hook util that has no .d.ts
import { computeEffectiveSalience } from '../../scripts/lib/salience.mjs';

/**
 * Run full consolidation process
 * This is like the brain's sleep consolidation - should be run periodically
 */
export function consolidate(
  config: MemoryConfig = DEFAULT_CONFIG
): ConsolidationResult {
  // Wrap entire consolidation in a transaction for atomicity
  return withTransaction(() => {
    const db = getDatabase();
    let consolidated = 0;
    let decayed = 0;
    let deleted = 0;

    // Get all short-term memories
    const shortTermMemories = getMemoriesByType('short_term', config.maxShortTermMemories * 2);

    // Process decay for all memories
    const { toDelete, toPromote, updated } = processDecay(shortTermMemories, config);

    // Promote worthy memories
    for (const id of toPromote) {
      promoteMemory(id);
      consolidated++;
    }

    // Delete decayed memories (excluding those just promoted)
    for (const id of toDelete) {
      if (!toPromote.includes(id)) {
        deleteMemory(id);
        deleted++;
      }
    }

    // Update decayed scores in database
    const updateStmt = db.prepare('UPDATE memories SET salience = ? WHERE id = ?');
    for (const [id, score] of updated) {
      if (!toDelete.includes(id)) {
        updateStmt.run(score, id);
        decayed++;
      }
    }

    // Enforce memory limits
    deleted += enforceMemoryLimits(config);

    // Persist updated decay scores for efficient sorting
    updateDecayScores();

    // Evolve salience based on structural importance
    let salienceEvolved = 0;
    try {
      salienceEvolved = evolveSalience(db);
    } catch (e) {
      console.error('[shieldcortex] Salience evolution failed:', e);
    }

    // ORGANIC FEATURE: Contradiction Detection (Phase 3)
    // Detect and link contradicting memories during consolidation
    let contradictionsFound = 0;
    let contradictionsLinked = 0;

    try {
      const contradictions = detectContradictions({ minScore: 0.5, limit: 50 });
      contradictionsFound = contradictions.length;
      contradictionsLinked = linkContradictions(contradictions);
    } catch (e) {
      console.error('[shieldcortex] Contradiction detection failed:', e);
    }

    // Prune activation cache to prevent unbounded growth
    pruneActivationCache();

    // Content-aware deduplication of long-term memories
    let deduplicated = 0;
    try {
      const dedup = deduplicateMemories();
      deduplicated = dedup.merged;
    } catch (e) {
      console.error('[shieldcortex] Deduplication failed:', e);
    }

    return { consolidated, decayed, deleted, contradictionsFound, contradictionsLinked, salienceEvolved, deduplicated };
  });
}

/**
 * Adjust salience based on structural importance (link count, contradiction status).
 * Called during consolidation.
 */
function evolveSalience(db: any): number {
  let updated = 0;

  // Boost highly-linked memories (hub bonus)
  const hubs = db.prepare(`
    SELECT m.id, m.salience,
      (SELECT COUNT(*) FROM memory_links WHERE source_id = m.id OR target_id = m.id) as link_count
    FROM memories m
    WHERE m.type IN ('long_term', 'episodic')
  `).all() as { id: number; salience: number; link_count: number }[];

  for (const hub of hubs) {
    if (hub.link_count < 2) continue;
    const linkBonus = Math.min(0.1, Math.log2(hub.link_count) * 0.03);
    const newSalience = Math.min(1.0, hub.salience + linkBonus);
    if (newSalience > hub.salience) {
      db.prepare('UPDATE memories SET salience = ? WHERE id = ?').run(newSalience, hub.id);
      updated++;
    }
  }

  // Penalize contradicted memories slightly (both sides)
  const contradicted = db.prepare(`
    SELECT DISTINCT source_id, target_id
    FROM memory_links
    WHERE relationship = 'contradicts'
  `).all() as { source_id: number; target_id: number }[];

  for (const pair of contradicted) {
    for (const id of [pair.source_id, pair.target_id]) {
      const mem = db.prepare('SELECT salience FROM memories WHERE id = ?').get(id) as any;
      if (mem && mem.salience > 0.3) {
        db.prepare('UPDATE memories SET salience = ? WHERE id = ?')
          .run(mem.salience - 0.02, id);
        updated++;
      }
    }
  }

  return updated;
}

/**
 * Compute Levenshtein distance between two strings.
 * Returns normalised similarity (0.0 = no match, 1.0 = identical).
 */
function levenshteinSimilarity(a: string, b: string): number {
  const la = a.length;
  const lb = b.length;
  if (la === 0 && lb === 0) return 1;
  if (la === 0 || lb === 0) return 0;

  const prev = new Array<number>(lb + 1);
  const curr = new Array<number>(lb + 1);
  for (let j = 0; j <= lb; j++) prev[j] = j;

  for (let i = 1; i <= la; i++) {
    curr[0] = i;
    for (let j = 1; j <= lb; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
    }
    for (let j = 0; j <= lb; j++) prev[j] = curr[j];
  }

  const maxLen = Math.max(la, lb);
  return 1 - prev[lb] / maxLen;
}

/**
 * Extract words from text, lowercased and deduplicated.
 */
function extractWords(text: string): Set<string> {
  return new Set(
    text.toLowerCase().replace(/[^a-z0-9\s]/g, ' ').split(/\s+/).filter(w => w.length > 1)
  );
}

/**
 * Compute word-overlap ratio between two texts.
 * Returns the proportion of shared words relative to the smaller set.
 */
function wordOverlap(a: string, b: string): number {
  const wordsA = extractWords(a);
  const wordsB = extractWords(b);
  if (wordsA.size === 0 || wordsB.size === 0) return 0;

  let shared = 0;
  for (const w of wordsA) {
    if (wordsB.has(w)) shared++;
  }
  const minSize = Math.min(wordsA.size, wordsB.size);
  return shared / minSize;
}

/**
 * Count shared words between two texts.
 */
function sharedWordCount(a: string, b: string): number {
  const wordsA = extractWords(a);
  const wordsB = extractWords(b);
  let count = 0;
  for (const w of wordsA) {
    if (wordsB.has(w)) count++;
  }
  return count;
}

export interface DuplicateMemoryPair {
  memoryA: Memory;
  memoryB: Memory;
  recommendedKeepId: number;
  similarity: string;
  titleSimilarity: number;
  contentOverlap: number;
  sharedWords: number;
}

export function findDuplicateMemoryPairs(options?: {
  project?: string;
  limit?: number;
}): DuplicateMemoryPair[] {
  const db = getDatabase();
  const limit = options?.limit ?? 20;
  const rows = options?.project
    ? db.prepare(
      "SELECT * FROM memories WHERE type = 'long_term' AND project = ? AND COALESCE(status, 'active') NOT IN ('archived', 'suppressed') ORDER BY created_at ASC",
    ).all(options.project) as Record<string, unknown>[]
    : db.prepare(
      "SELECT * FROM memories WHERE type = 'long_term' AND COALESCE(status, 'active') NOT IN ('archived', 'suppressed') ORDER BY created_at ASC",
    ).all() as Record<string, unknown>[];

  const groups = new Map<string, Record<string, unknown>[]>();
  for (const mem of rows) {
    const cat = (mem.category as string) || 'note';
    if (!groups.has(cat)) groups.set(cat, []);
    groups.get(cat)!.push(mem);
  }

  const pairs: DuplicateMemoryPair[] = [];
  const seen = new Set<string>();

  for (const [, group] of groups) {
    if (group.length < 2) continue;

    for (let i = 0; i < group.length && pairs.length < limit; i++) {
      const memA = group[i];
      for (let j = i + 1; j < group.length && pairs.length < limit; j++) {
        const memB = group[j];
        const idA = memA.id as number;
        const idB = memB.id as number;
        const pairKey = `${Math.min(idA, idB)}:${Math.max(idA, idB)}`;
        if (seen.has(pairKey)) continue;

        const titleA = (memA.title as string) || '';
        const titleB = (memB.title as string) || '';
        const contentA = (memA.content as string) || '';
        const contentB = (memB.content as string) || '';

        const titleSimilarity = levenshteinSimilarity(titleA.toLowerCase(), titleB.toLowerCase());
        const sharedWords = sharedWordCount(titleA, titleB);
        const titlesMatch = titleSimilarity > 0.7 || sharedWords >= 3 || titleA.toLowerCase() === titleB.toLowerCase();
        if (!titlesMatch) continue;

        const contentOverlap = wordOverlap(contentA, contentB);
        if (contentOverlap <= 0.5) continue;

        const salienceA = (memA.salience as number) || 0;
        const salienceB = (memB.salience as number) || 0;
        const createdA = new Date((memA.created_at as string) || 0).getTime();
        const createdB = new Date((memB.created_at as string) || 0).getTime();
        const recommendedKeepId =
          salienceA > salienceB || (salienceA === salienceB && createdA >= createdB)
            ? idA
            : idB;

        pairs.push({
          memoryA: rowToMemory(memA),
          memoryB: rowToMemory(memB),
          recommendedKeepId,
          similarity: `title=${titleSimilarity.toFixed(2)}, content=${contentOverlap.toFixed(2)}`,
          titleSimilarity,
          contentOverlap,
          sharedWords,
        });

        seen.add(pairKey);
      }
    }
  }

  return pairs;
}

/**
 * De-duplicate long-term memories found as duplicate PAIRS by
 * findDuplicateMemoryPairs (same project|category, similar title + >0.5 content
 * overlap). Runs every ~4h on the auto path: server.ts setInterval → fullCleanup
 * → consolidate → deduplicateMemories.
 *
 * B11 (memory-quality fix): the previous implementation built
 * `kept.content + "\n\nMerged from duplicate:\n" + uniqueSentences` and wrote it
 * back with `UPDATE memories SET content = ?`. That was the SECOND lossy-append
 * site (mergeSimilarMemories was the first) and kept generating ever-growing
 * "frankenmemories" on this path even after the first site was fixed. The kept
 * memory's `content` is now NEVER modified.
 *
 * New policy (identical to mergeSimilarMemories — one source of truth):
 *   - KEEP the higher-EFFECTIVE-salience member of the pair (computeEffectiveSalience
 *     via the shared salience.mjs — recency/access/pin/downvote, same ranking as
 *     recall and the downvote CLI). NOTE: this can differ from the pair's raw
 *     `recommendedKeepId`, which only considered raw salience + recency.
 *   - Dispose the loser via the shared disposeLoser: combined similarity
 *     (re-measured vs the kept row) ≥ 0.85 → DELETE; below → DOWNVOTE (reversible).
 *   - Tags are unioned onto the kept row (metadata only, non-lossy). The kept
 *     content and salience are untouched.
 *
 * Defence re-scan removed (B11): the old re-scan existed ONLY to validate the
 * SYNTHESIZED concatenated merged body before persisting it (two individually-
 * clean rows could straddle a credential pattern across the join). Now that no
 * concatenation happens here, there is no synthesized content to scan — the kept
 * row's bytes are written verbatim and unchanged, exactly as they already exist
 * in `memories`. So this pass introduces no new bytes to validate. (This is a
 * narrow claim about THIS path: it does not assume every row was scanned at write
 * time — e.g. importMemories inserts rows with no scan — only that the dedup no
 * longer fabricates a new body that would need scanning.) Dropping the re-scan
 * also avoids re-auditing unchanged content on every 4h pass.
 *
 * Only rows clustered in THIS pass are acted on; historical merged rows are not
 * rewritten (effective salience demotes them over time). STM→LTM promotion is
 * handled separately by processDecay/promoteMemory in consolidate().
 */
export function deduplicateMemories(options?: { dryRun?: boolean }): {
  merged: number;
  pairs: Array<{ kept: number; removed: number; similarity: string }>;
} {
  const dryRun = options?.dryRun ?? false;

  return withTransaction(() => {
    const db = getDatabase();
    const pairs: Array<{ kept: number; removed: number; similarity: string }> = [];
    const disposed = new Set<number>();
    const nowIso = new Date().toISOString();
    const downvoteStmt = db.prepare(DOWNVOTE_SQL) as Database.Statement<[string, number]>;

    // findDuplicateMemoryPairs returns rowToMemory-converted objects, which omit
    // downvote_count. Fetch raw rows on demand so effective-salience ranking and
    // the loser disposal see the full signal.
    const rawRowStmt = db.prepare('SELECT * FROM memories WHERE id = ?');
    const rawRow = (id: number) => rawRowStmt.get(id) as Record<string, unknown> | undefined;

    for (const pair of findDuplicateMemoryPairs()) {
      if (disposed.has(pair.memoryA.id) || disposed.has(pair.memoryB.id)) continue;

      const rowA = rawRow(pair.memoryA.id);
      const rowB = rawRow(pair.memoryB.id);
      if (!rowA || !rowB) continue; // already gone (e.g. deleted earlier this pass)

      // KEEP the higher-effective-salience member (tie → keep A, the older row
      // by findDuplicateMemoryPairs' created_at ASC ordering).
      const keepA = effectiveSalienceOfRow(rowA) >= effectiveSalienceOfRow(rowB);
      const kept = keepA ? pair.memoryA : pair.memoryB;
      const loser = keepA ? pair.memoryB : pair.memoryA;

      if (!dryRun) {
        // Union the loser's tags onto the kept row (metadata only, non-lossy).
        const mergedTags = [...new Set([...kept.tags, ...loser.tags])];
        db.prepare('UPDATE memories SET tags = ? WHERE id = ?')
          .run(JSON.stringify(mergedTags), kept.id);

        // Shared disposal policy — identical to mergeSimilarMemories.
        disposeLoser(
          { content: kept.content, title: kept.title },
          { id: loser.id, content: loser.content, title: loser.title },
          downvoteStmt,
          nowIso
        );
      }

      disposed.add(loser.id);
      pairs.push({
        kept: kept.id,
        removed: loser.id,
        similarity: pair.similarity,
      });
    }

    return { merged: pairs.length, pairs };
  });
}

/**
 * Group memories by topic and create summary memories for large clusters.
 */
export function clusterAndSummarise(options?: { minClusterSize?: number }): {
  clusters: number;
  summariesCreated: number;
} {
  const minSize = options?.minClusterSize ?? 5;

  return withTransaction(() => {
    const db = getDatabase();
    let clusters = 0;
    let summariesCreated = 0;

    // Get all LTM memories with their tags
    const ltmMemories = db.prepare(
      "SELECT * FROM memories WHERE type = 'long_term' ORDER BY category ASC, created_at ASC"
    ).all() as Record<string, unknown>[];

    // Group by category + shared tags
    // Key: "category|tag1,tag2,..." (sorted tags)
    const tagGroups = new Map<string, Record<string, unknown>[]>();

    for (const mem of ltmMemories) {
      let tags: string[] = [];
      try {
        tags = JSON.parse((mem.tags as string) || '[]') as string[];
      } catch {
        // skip invalid tags
      }

      // Skip auto-summary memories from being clustered again
      const title = (mem.title as string) || '';
      if (title.startsWith('Summary:')) continue;

      const category = (mem.category as string) || 'note';
      const sortedTags = tags.filter(t => t !== 'auto-summary').sort();
      const key = `${category}|${sortedTags.join(',')}`;

      if (!tagGroups.has(key)) tagGroups.set(key, []);
      tagGroups.get(key)!.push(mem);
    }

    for (const [key, group] of tagGroups) {
      if (group.length < minSize) continue;

      clusters++;

      const [category, tagsStr] = key.split('|');
      const commonTags = tagsStr || 'general';
      const summaryTitle = `Summary: ${category} — ${commonTags}`;

      // Check if a summary already exists for this cluster
      const existing = db.prepare(
        "SELECT id FROM memories WHERE title = ? AND type = 'long_term'"
      ).get(summaryTitle) as { id: number } | undefined;

      if (existing) continue;

      // Create bullet list of all memory titles
      const bulletList = group
        .map(m => `- ${(m.title as string) || 'Untitled'}`)
        .join('\n');
      const summaryContent = `Cluster of ${group.length} memories:\n${bulletList}`;

      // Determine project from group (use most common)
      const projectCounts = new Map<string, number>();
      for (const m of group) {
        const proj = (m.project as string) || '';
        projectCounts.set(proj, (projectCounts.get(proj) || 0) + 1);
      }
      let bestProject = '';
      let bestCount = 0;
      for (const [proj, count] of projectCounts) {
        if (count > bestCount) {
          bestProject = proj;
          bestCount = count;
        }
      }

      addMemory(
        {
          type: 'long_term',
          category: category as any,
          title: summaryTitle,
          content: summaryContent,
          project: bestProject || undefined,
          tags: ['auto-summary'],
          salience: 0.6,
        },
        undefined,
        // System-generated consolidation summary — honest cli provenance
        // (trust 0.9, above the auto-quarantine band so it isn't held).
        { type: 'cli', identifier: 'consolidate:summary' },
      );

      summariesCreated++;
    }

    return { clusters, summariesCreated };
  });
}

/**
 * Enforce maximum memory limits
 * Removes lowest-priority memories when limits are exceeded
 */
export function enforceMemoryLimits(config: MemoryConfig = DEFAULT_CONFIG): number {
  // Note: If called within consolidate(), this is already in a transaction
  // If called standalone, we wrap it for safety
  const db = getDatabase();
  let deleted = 0;

  // Check short-term memory limit
  const shortTermCount = (db.prepare(
    "SELECT COUNT(*) as count FROM memories WHERE type = 'short_term'"
  ).get() as { count: number }).count;

  if (shortTermCount > config.maxShortTermMemories) {
    const toRemove = shortTermCount - config.maxShortTermMemories;
    const lowPriority = db.prepare(`
      SELECT id FROM memories
      WHERE type = 'short_term'
      ORDER BY salience ASC, last_accessed ASC
      LIMIT ?
    `).all(toRemove) as { id: number }[];

    for (const { id } of lowPriority) {
      deleteMemory(id);
      deleted++;
    }
  }

  // Check long-term memory limit (more lenient)
  const longTermCount = (db.prepare(
    "SELECT COUNT(*) as count FROM memories WHERE type = 'long_term'"
  ).get() as { count: number }).count;

  if (longTermCount > config.maxLongTermMemories) {
    const toRemove = longTermCount - config.maxLongTermMemories;
    const lowPriority = db.prepare(`
      SELECT id FROM memories
      WHERE type = 'long_term'
      ORDER BY salience ASC, access_count ASC, last_accessed ASC
      LIMIT ?
    `).all(toRemove) as { id: number }[];

    for (const { id } of lowPriority) {
      deleteMemory(id);
      deleted++;
    }
  }

  return deleted;
}

/**
 * Combined-similarity bar at/above which a clustered loser is considered a
 * NEAR-IDENTICAL duplicate of the kept memory. Such a loser's content is, by
 * construction, almost entirely contained in the kept memory, so deleting it
 * loses no real information — this is the non-lossy successor to the old
 * concatenate-then-delete behaviour, minus the concatenation. Moderate
 * near-dups (similarityThreshold ≤ combined < this) keep some distinct content,
 * so we DOWNVOTE rather than delete them (reversible, non-lossy).
 */
const NEAR_IDENTICAL_DELETE_THRESHOLD = 0.85;

/**
 * Effective salience of a raw `memories` row, via the shared
 * scripts/lib/salience.mjs helper (recency × access × pin × downvote_penalty).
 * One source of truth with recall ranking and the `shieldcortex memory
 * downvote` CLI, so "highest-salience to keep" and "downvoted to demote" agree.
 */
function effectiveSalienceOfRow(m: Record<string, unknown>): number {
  return computeEffectiveSalience({
    salience: (m.salience as number) ?? 0,
    last_accessed: (m.last_accessed as string) ?? null,
    access_count: (m.access_count as number) ?? 0,
    pinned: (m.pinned as number) ?? 0,
    downvote_count: (m.downvote_count as number) ?? 0,
  });
}

/**
 * The single, shared loser-disposal policy used by BOTH dedup paths
 * (mergeSimilarMemories on short-term clusters, deduplicateMemories on
 * long-term duplicate pairs). Re-measures combined similarity (content 0.6 +
 * title 0.4) of the loser AGAINST THE KEPT memory and:
 *   - combined ≥ NEAR_IDENTICAL_DELETE_THRESHOLD → DELETE (near-identical;
 *     the loser's content is already contained in the kept row, and no reaping
 *     path reads downvote_count/effective salience, so deleting near-identical
 *     losers is what keeps the store bounded — see mergeSimilarMemories' header)
 *   - below that bar → DOWNVOTE (reversible, non-lossy; effective salience
 *     sinks it in recall while its distinct content survives intact)
 *
 * The loser's `content` is NEVER read into the kept row — no frankenmerge.
 * `kept`/`loser` carry only title+content for the similarity re-measure.
 * `downvoteStmt` is the caller-prepared DOWNVOTE_SQL statement, bound (?, ?) =
 * (last_downvoted_at iso string, id).
 */
type LoserDisposition = 'deleted' | 'downvoted';

function disposeLoser(
  kept: { content: string; title: string },
  loser: { id: number; content: string; title: string },
  downvoteStmt: Database.Statement<[string, number]>,
  nowIso: string
): LoserDisposition {
  const cSim = jaccardSimilarity(kept.content, loser.content);
  const tSim = jaccardSimilarity(kept.title, loser.title);
  const combinedToKept = cSim * 0.6 + tSim * 0.4;

  if (combinedToKept >= NEAR_IDENTICAL_DELETE_THRESHOLD) {
    deleteMemory(loser.id);
    return 'deleted';
  }
  downvoteStmt.run(nowIso, loser.id);
  return 'downvoted';
}

/**
 * The shared downvote SQL — prepared once per pass by each caller and handed to
 * disposeLoser. Reversible soft demotion: bumps downvote_count (effective
 * salience reads it) and stamps last_downvoted_at.
 */
const DOWNVOTE_SQL = `
  UPDATE memories
  SET downvote_count = COALESCE(downvote_count, 0) + 1,
      last_downvoted_at = ?
  WHERE id = ?
`;

/**
 * Find clusters of similar short-term memories within each project|category,
 * KEEP the single highest-effective-salience member, and demote the rest
 * WITHOUT destroying or concatenating their content.
 *
 * B11 (memory-quality fix): the previous implementation appended every loser's
 * body into the kept memory ("Consolidated context:" bullets) and deleted the
 * losers. Over ~417 live rows this produced 188 ever-growing "frankenmemories"
 * — exactly the garbled content users complained about. The kept memory's
 * `content` is now NEVER modified.
 *
 * Disposition per loser (see NEAR_IDENTICAL_DELETE_THRESHOLD):
 *   - combined ≥ 0.85  → DELETE (near-identical; content already in the kept row)
 *   - combined < 0.85  → DOWNVOTE (reversible; sinks via effective salience)
 *
 * Why the split exists at all: NO reaping path (decay.ts shouldDelete,
 * prune.ts, expiry.ts, enforceMemoryLimits) reads `downvote_count` or effective
 * salience — they all order by raw `salience`. So downvote-ONLY would leave the
 * store unbounded (the dups sink in recall but never get pruned). Deleting the
 * near-identical losers keeps the store bounded with zero information loss; the
 * moderate near-dups are preserved and merely demoted.
 *
 * Tags are unioned onto the kept row and access counts summed (metadata only,
 * non-lossy). STM→LTM promotion is handled separately by processDecay/
 * promoteMemory in consolidate(); this function only de-duplicates.
 *
 * Returns the count of deleted (near-identical) losers.
 */
export function mergeSimilarMemories(
  project?: string,
  similarityThreshold: number = 0.25
): number {
  return withTransaction(() => {
    const db = getDatabase();
    let deleted = 0;

    // Step 1: Get all short-term memories, optionally filtered by project
    let sql = "SELECT * FROM memories WHERE type = 'short_term'";
    const params: unknown[] = [];
    if (project) {
      sql += ' AND project = ?';
      params.push(project);
    }
    sql += ' ORDER BY created_at ASC';

    const memories = db.prepare(sql).all(...params) as Record<string, unknown>[];

    // Step 2: Group by project|category
    const groups = new Map<string, Record<string, unknown>[]>();
    for (const mem of memories) {
      const key = `${mem.project || ''}|${mem.category || ''}`;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key)!.push(mem);
    }

    // Step 3: For each group with 2+ members, find clusters
    for (const [, group] of groups) {
      if (group.length < 2) continue;

      // Track which memories have been clustered
      const clustered = new Set<number>();

      for (let i = 0; i < group.length; i++) {
        if (clustered.has(i)) continue;

        const cluster: number[] = [i]; // indices into group
        const memA = group[i];

        for (let j = i + 1; j < group.length; j++) {
          if (clustered.has(j)) continue;

          const memB = group[j];
          const contentSim = jaccardSimilarity(
            memA.content as string,
            memB.content as string
          );
          const titleSim = jaccardSimilarity(
            memA.title as string,
            memB.title as string
          );
          const combinedSim = contentSim * 0.6 + titleSim * 0.4;

          // THRESHOLD RECONCILIATION (B11, reconciled with Task 8's write-path
          // dedup):
          //   - Task 8's write-path SKIP fires at combined ≥ 0.5 and is STRICT
          //     because skipping a write is IRREVERSIBLE data loss — the memory
          //     is never stored.
          //   - Consolidate stays AGGRESSIVE at 0.25 because its action is now
          //     REVERSIBLE: moderate near-dups are DOWNVOTED — a soft demotion
          //     that leaves the row + its content intact (clearing
          //     downvote_count restores the prior ranking), not the old
          //     concatenate-into-kept + delete, which destroyed data.
          //   The two thresholds no longer conflict: a pair at combined ~0.3
          //   (below the 0.5 write-skip, above this 0.25 bar) survives the
          //   write but is demoted here via reversible downvote. Only
          //   near-IDENTICAL losers (≥ 0.85, content already in the kept row)
          //   are deleted — see NEAR_IDENTICAL_DELETE_THRESHOLD.
          if (combinedSim >= similarityThreshold) {
            cluster.push(j);
          }
        }

        if (cluster.length < 2) continue;

        // Mark all as clustered
        for (const idx of cluster) clustered.add(idx);

        // Step 4: Resolve the cluster WITHOUT lossy concatenation.
        // KEEP the single highest-EFFECTIVE-salience member (downvotes,
        // recency, pins and access all factor in — same ranking the recall
        // hook uses). The kept row's `content` is NEVER touched.
        const clusterMems = cluster.map(idx => group[idx]);
        clusterMems.sort((a, b) => effectiveSalienceOfRow(b) - effectiveSalienceOfRow(a));

        const kept = clusterMems[0];
        const losers = clusterMems.slice(1);

        // Merge tags onto the kept row (union — metadata only, non-lossy) and
        // accumulate the losers' access counts so reinforcement history isn't
        // lost. The kept content and salience stay exactly as they were.
        const allTags = new Set<string>();
        for (const m of clusterMems) {
          try {
            const tags = JSON.parse((m.tags as string) || '[]') as string[];
            for (const t of tags) allTags.add(t);
          } catch {
            // skip invalid tags
          }
        }
        const totalAccessCount = clusterMems.reduce(
          (sum, m) => sum + ((m.access_count as number) || 0),
          0
        );

        // Promote the kept memory to long-term and absorb the union'd tags +
        // summed access count. NOTE: content is deliberately omitted from this
        // UPDATE — no frankenmerge.
        db.prepare(`
          UPDATE memories
          SET type = 'long_term',
              tags = ?,
              access_count = ?
          WHERE id = ?
        `).run(
          JSON.stringify([...allTags]),
          totalAccessCount,
          kept.id as number
        );

        // Dispose of each loser via the SHARED disposal policy (disposeLoser):
        // near-identical (≥ 0.85 vs the kept row) → DELETE; moderate → DOWNVOTE.
        // Identical policy to deduplicateMemories — one source of truth.
        const nowIso = new Date().toISOString();
        const downvoteStmt = db.prepare(DOWNVOTE_SQL) as Database.Statement<[string, number]>;

        const keptText = { content: kept.content as string, title: kept.title as string };
        for (const loser of losers) {
          const disposition = disposeLoser(
            keptText,
            {
              id: loser.id as number,
              content: loser.content as string,
              title: loser.title as string,
            },
            downvoteStmt,
            nowIso
          );
          if (disposition === 'deleted') deleted++;
        }
      }
    }

    return deleted;
  });
}

/**
 * Generate a context summary for session start
 * Provides a high-level view of relevant memories
 */
export async function generateContextSummary(
  project?: string,
  config: MemoryConfig = DEFAULT_CONFIG
): Promise<ContextSummary> {
  // Get recent memories
  const recentMemories = getRecentMemories(10, project);

  // Get key architecture decisions
  const keyDecisions = (await searchMemories({
    query: '',
    project,
    category: 'architecture',
    minSalience: 0.6,
    limit: 5,
  }, config)).map(r => r.memory);

  // Get active patterns
  const activePatterns = (await searchMemories({
    query: '',
    project,
    category: 'pattern',
    minSalience: 0.5,
    limit: 5,
  }, config)).map(r => r.memory);

  // Get pending items
  const pendingItems = (await searchMemories({
    query: '',
    project,
    category: 'todo',
    limit: 10,
  }, config)).map(r => r.memory);

  return {
    project,
    recentMemories,
    keyDecisions,
    activePatterns,
    pendingItems,
  };
}

/**
 * Format context summary as a readable string
 */
export function formatContextSummary(summary: ContextSummary): string {
  const lines: string[] = [];

  if (summary.project) {
    lines.push(`## Project: ${summary.project}\n`);
  }

  if (summary.keyDecisions.length > 0) {
    lines.push('### Key Decisions');
    for (const memory of summary.keyDecisions) {
      lines.push(`- **${memory.title}**: ${memory.content.slice(0, 100)}${memory.content.length > 100 ? '...' : ''}`);
    }
    lines.push('');
  }

  if (summary.activePatterns.length > 0) {
    lines.push('### Active Patterns');
    for (const memory of summary.activePatterns) {
      lines.push(`- **${memory.title}**: ${memory.content.slice(0, 100)}${memory.content.length > 100 ? '...' : ''}`);
    }
    lines.push('');
  }

  if (summary.pendingItems.length > 0) {
    lines.push('### Pending Items');
    for (const memory of summary.pendingItems) {
      lines.push(`- [ ] ${memory.title}`);
    }
    lines.push('');
  }

  if (summary.recentMemories.length > 0) {
    lines.push('### Recent Context');
    for (const memory of summary.recentMemories.slice(0, 5)) {
      lines.push(`- ${memory.title} (${memory.category})`);
    }
  }

  return lines.join('\n');
}

/**
 * Start a new session
 * Creates a session record and returns relevant context
 */
export async function startSession(project?: string): Promise<{
  sessionId: number;
  context: ContextSummary;
}> {
  const db = getDatabase();

  // Create session record
  const result = db.prepare(`
    INSERT INTO sessions (project) VALUES (?)
  `).run(project || null);

  const sessionId = result.lastInsertRowid as number;

  // Generate context summary
  const context = await generateContextSummary(project);

  return { sessionId, context };
}

/**
 * End a session
 * Updates session record with summary
 */
export function endSession(
  sessionId: number,
  summary?: string
): void {
  const db = getDatabase();

  // Get counts from this session
  const stats = db.prepare(`
    SELECT
      (SELECT COUNT(*) FROM memories WHERE created_at >= s.started_at) as created,
      (SELECT COUNT(*) FROM memories WHERE last_accessed >= s.started_at) as accessed
    FROM sessions s WHERE s.id = ?
  `).get(sessionId) as { created: number; accessed: number } | undefined;

  db.prepare(`
    UPDATE sessions
    SET ended_at = CURRENT_TIMESTAMP,
        summary = ?,
        memories_created = ?,
        memories_accessed = ?
    WHERE id = ?
  `).run(
    summary || null,
    stats?.created || 0,
    stats?.accessed || 0,
    sessionId
  );
}

/**
 * Get suggested context for the current query
 * Returns memories that might be relevant to what the user is working on
 */
export async function getSuggestedContext(
  currentContext: string,
  project?: string,
  limit: number = 5
): Promise<Memory[]> {
  // Search for relevant memories based on current context
  const results = await searchMemories({
    query: currentContext,
    project,
    minSalience: 0.4,
    limit,
    includeDecayed: false,
  });

  return results.map(r => r.memory);
}

/**
 * Export memories as JSON (for backup/transfer)
 */
export function exportMemories(project?: string): string {
  const db = getDatabase();

  let sql = 'SELECT * FROM memories';
  const params: unknown[] = [];
  if (project) {
    sql += ' WHERE project = ?';
    params.push(project);
  }
  sql += ' ORDER BY created_at ASC';

  const rows = db.prepare(sql).all(...params);
  return JSON.stringify(rows, null, 2);
}

/**
 * Import memories from JSON
 */
export function importMemories(json: string): number {
  // Wrap in transaction for atomic import. addMemory opens its own nested
  // transaction (better-sqlite3 SAVEPOINT), so a per-row block rolls back only
  // that row and the clean rows still commit.
  return withTransaction(() => {
    const memories = JSON.parse(json) as Record<string, unknown>[];

    // SELECT * exports store tags/metadata as JSON TEXT — parse back to the
    // array/object shapes addMemory expects.
    const parseJsonField = <T>(value: unknown, fallback: T): T => {
      if (typeof value !== 'string') return (value as T) ?? fallback;
      try {
        return JSON.parse(value) as T;
      } catch {
        return fallback;
      }
    };

    let imported = 0;
    for (const memory of memories) {
      try {
        // Route every imported row through the defence pipeline + attribute it
        // to file:import (trust 0.4 — below the auto-quarantine band). Closes
        // the raw-INSERT bypass that admitted unscanned rows at trust 1.0 /
        // 'user:direct'. The pipeline BLOCKs poisoned rows (caught below).
        addMemory(
          {
            type: memory.type as Parameters<typeof addMemory>[0]['type'],
            category: memory.category as Parameters<typeof addMemory>[0]['category'],
            title: String(memory.title ?? ''),
            content: String(memory.content ?? ''),
            project: typeof memory.project === 'string' ? memory.project : undefined,
            tags: parseJsonField<string[]>(memory.tags, []),
            salience: typeof memory.salience === 'number' ? memory.salience : 0.5,
            metadata: parseJsonField<Record<string, unknown>>(memory.metadata, {}),
          },
          DEFAULT_CONFIG,
          { type: 'file', identifier: 'import' },
        );
        imported++;
      } catch {
        // Skip rows the defence pipeline blocks (poisoned), or invalid entries.
      }
    }

    return imported;
  });
}

/**
 * Vacuum database to reclaim space after deletions
 * Run periodically or after major cleanup operations
 */
export function vacuumDatabase(): { success: boolean; message: string } {
  try {
    const db = getDatabase();
    db.exec('VACUUM');
    return { success: true, message: 'Database vacuumed successfully' };
  } catch (error) {
    return { success: false, message: `Vacuum failed: ${error}` };
  }
}

/**
 * Preview what consolidation would do without actually doing it
 * Useful for dry-run mode
 */
export function previewConsolidation(
  config: MemoryConfig = DEFAULT_CONFIG
): {
  toPromote: Memory[];
  toDelete: Memory[];
  totalShortTerm: number;
  totalLongTerm: number;
} {
  const db = getDatabase();

  // Get all short-term memories
  const shortTermMemories = getMemoriesByType('short_term', config.maxShortTermMemories * 2);

  // Get episodic memories too
  const episodicMemories = getMemoriesByType('episodic', 100);

  // Process decay to see what would happen
  const { toDelete: deleteIds, toPromote: promoteIds } = processDecay(
    [...shortTermMemories, ...episodicMemories],
    config
  );

  // Map IDs back to memories
  const allMemories = [...shortTermMemories, ...episodicMemories];
  const toPromote = allMemories.filter(m => promoteIds.includes(m.id));
  const toDelete = allMemories.filter(m => deleteIds.includes(m.id) && !promoteIds.includes(m.id));

  // Get counts
  const totalShortTerm = (db.prepare(
    "SELECT COUNT(*) as count FROM memories WHERE type = 'short_term'"
  ).get() as { count: number }).count;

  const totalLongTerm = (db.prepare(
    "SELECT COUNT(*) as count FROM memories WHERE type = 'long_term'"
  ).get() as { count: number }).count;

  return { toPromote, toDelete, totalShortTerm, totalLongTerm };
}

/**
 * Check if consolidation should be triggered based on memory state
 * Returns true if consolidation is recommended
 */
export function shouldTriggerConsolidation(
  config: MemoryConfig = DEFAULT_CONFIG
): { shouldRun: boolean; reason: string } {
  const stats = getMemoryStats();
  const stmFullness = stats.shortTerm / config.maxShortTermMemories;

  // Trigger early when approaching capacity
  if (stmFullness > 0.8) {
    return {
      shouldRun: true,
      reason: `Short-term memory at ${Math.round(stmFullness * 100)}% capacity`,
    };
  }

  // Check if many memories are below threshold
  const db = getDatabase();
  const lowScoreCount = (db.prepare(`
    SELECT COUNT(*) as count FROM memories
    WHERE type = 'short_term' AND decayed_score < ?
  `).get(config.salienceThreshold) as { count: number }).count;

  if (lowScoreCount > 10) {
    return {
      shouldRun: true,
      reason: `${lowScoreCount} memories below salience threshold`,
    };
  }

  return { shouldRun: false, reason: 'No consolidation needed' };
}

/**
 * Full cleanup: consolidate + vacuum
 * Best run periodically to keep database healthy
 */
export function fullCleanup(
  config: MemoryConfig = DEFAULT_CONFIG
): { consolidation: ConsolidationResult; vacuumed: boolean; merged: number; quarantineExpired: number } {
  // Run consolidation
  const consolidation = consolidate(config);

  // Merge similar memories
  const merged = mergeSimilarMemories();

  // Expire old quarantine items
  let quarantineExpired = 0;
  try {
    quarantineExpired = expireQuarantineItems();
  } catch { /* defence module may not be available */ }

  // Vacuum if we deleted anything
  let vacuumed = false;
  if (consolidation.deleted > 0 || merged > 0) {
    const vacResult = vacuumDatabase();
    vacuumed = vacResult.success;
  }

  return { consolidation, vacuumed, merged, quarantineExpired };
}

// ── v4.0.0: Dream Mode — Advanced Memory Consolidation ──────────

export interface DreamModeResult {
  nearDuplicatesMerged: number;
  archivalCandidates: number;
  contradictionsDetected: number;
  totalProcessed: number;
}

/**
 * "Dream Mode" — comprehensive memory consolidation.
 *
 * 1. Find near-duplicates by embedding similarity >0.9, merge them
 * 2. Flag memories >30 days old with no access as archival candidates
 * 3. Detect and flag contradictions
 *
 * DISPOSAL POLICY — deliberately DIVERGES from the auto path:
 * This is the EXPLICIT, user-invoked `shieldcortex consolidate` command (and the
 * public `consolidateMemories` export). Because the user has actively asked for a
 * consolidation, aggressive cleanup is the intended behaviour: the loser of every
 * duplicate pair is HARD-DELETED. This is on purpose and must NOT be replaced with
 * the gentle `disposeLoser` policy.
 *
 * Contrast with the 4-hourly AUTO path (deduplicateMemories / mergeSimilarMemories),
 * which runs UNATTENDED and therefore uses the conservative `disposeLoser`: it only
 * deletes near-identical losers (combined ≥ 0.85, content already contained in the
 * kept row) and merely DOWNVOTES (reversible) the moderate near-dups. That caution
 * is right for an unsupervised background job, but wrong for a deliberate manual
 * cleanup the user explicitly triggered.
 *
 * The two paths DO share keep-selection: both pick the kept row by EFFECTIVE
 * salience (effectiveSalienceOfRow — recency/access/pin/downvote), so the row that
 * survives is consistent across all three dedup sites. Effective salience also
 * discriminates where the pair's raw `recommendedKeepId` (raw salience + recency)
 * ties at 1.0.
 */
export function consolidateMemories(): DreamModeResult {
  // Wrap the dedup delete loop in a transaction for atomicity: previously each
  // pair was deleted on a bare getDatabase() with no transaction, so a mid-loop
  // failure left partial deletes (some losers gone, tag-merges half-applied).
  return withTransaction(() => {
    const db = getDatabase();
    let nearDuplicatesMerged = 0;
    let archivalCandidates = 0;
    let contradictionsDetected = 0;

    // findDuplicateMemoryPairs returns rowToMemory-converted objects, which omit
    // downvote_count. Fetch raw rows on demand so effective-salience keep-selection
    // sees the full signal (same pattern as deduplicateMemories).
    const rawRowStmt = db.prepare('SELECT * FROM memories WHERE id = ?');
    const rawRow = (id: number) => rawRowStmt.get(id) as Record<string, unknown> | undefined;

    // Step 1: Find and merge near-duplicates
    const duplicatePairs = findDuplicateMemoryPairs({ limit: 100 });
    for (const pair of duplicatePairs) {
      try {
        const memA = pair.memoryA;
        const memB = pair.memoryB;
        if (!memA || !memB) continue;

        // KEEP the higher-EFFECTIVE-salience member (recency/access/pin/downvote),
        // consistent with deduplicateMemories and mergeSimilarMemories — one source
        // of truth via effectiveSalienceOfRow. This can differ from the pair's raw
        // `recommendedKeepId` (raw salience + recency), which can't break a 1.0 tie.
        const rowA = rawRow(memA.id);
        const rowB = rawRow(memB.id);
        if (!rowA || !rowB) continue; // already gone (deleted earlier this pass)

        // Tie → keep A (the older row by findDuplicateMemoryPairs' created_at ASC).
        const keepA = effectiveSalienceOfRow(rowA) >= effectiveSalienceOfRow(rowB);
        const kept = keepA ? memA : memB;
        const removed = keepA ? memB : memA;

        // Merge tags from both onto the kept row (metadata only, non-lossy).
        const mergedTags = [...new Set([...kept.tags, ...removed.tags])];
        db.prepare('UPDATE memories SET tags = ? WHERE id = ?')
          .run(JSON.stringify(mergedTags), kept.id);

        // Aggressive hard-DELETE of the loser — intended for this manual command
        // (see the disposal-policy note in the function header).
        deleteMemory(removed.id);
        nearDuplicatesMerged++;
      } catch {
        // Skip problematic pairs
      }
    }

    // Step 2: Flag stale memories for archival (>30 days, no access)
    const thirtyDaysAgo = new Date(Date.now() - 30 * 86_400_000).toISOString();
    const staleRows = db.prepare(`
      SELECT id FROM memories
      WHERE status = 'active'
        AND last_accessed < ?
        AND access_count <= 1
        AND pinned = 0
    `).all(thirtyDaysAgo) as { id: number }[];

    for (const row of staleRows) {
      try {
        db.prepare("UPDATE memories SET status = 'archived', updated_at = CURRENT_TIMESTAMP WHERE id = ?")
          .run(row.id);
        archivalCandidates++;
      } catch {
        // Skip
      }
    }

    // Step 3: Detect contradictions
    try {
      const contradictions = detectContradictions();
      if (contradictions.length > 0) {
        contradictionsDetected = linkContradictions(contradictions);
      }
    } catch {
      // Contradiction detection may fail on empty/small DBs
    }

    const totalProcessed = duplicatePairs.length + staleRows.length;

    // Completion summary — without this, a quiet pass produced a 2-line
    // near-empty report with no signal as to whether it under-extracted, errored,
    // or legitimately had nothing to do (Jarvis P3, 2026-06-08).
    const summary = totalProcessed === 0
      ? '[dream] nothing to consolidate (0 candidates this pass)'
      : `[dream] merged ${nearDuplicatesMerged}, archived ${archivalCandidates}, ` +
        `contradictions ${contradictionsDetected} (from ${totalProcessed} candidates)`;
    console.error(summary);

    return {
      nearDuplicatesMerged,
      archivalCandidates,
      contradictionsDetected,
      totalProcessed,
    };
  });
}
