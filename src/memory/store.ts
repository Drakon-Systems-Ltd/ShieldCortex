/**
 * Memory Store
 *
 * Core CRUD operations for the memory database.
 * Handles storage, retrieval, and management of memories.
 */

import { randomUUID } from 'crypto';
import { getDatabase, isDatabaseInitialized, withTransaction } from '../database/init.js';
import { sourceKey } from '../threat-graph/keys.js';
import { shouldAutoRelease, recordAutoRelease } from '../threat-graph/allowance.js';
import { detectionKeys, exemplarHash } from '../threat-graph/decision.js';
import { isAutoReleaseEnabled } from '../cloud/config.js';
import {
  Memory,
  MemoryInput,
  MemoryType,
  MemoryCategory,
  MemoryStatus,
  MemorySourceKind,
  MemoryCaptureMethod,
  SearchOptions,
  SearchResult,
  MemoryConfig,
  DEFAULT_CONFIG,
  MemoryPurpose,
  MemoryScope,
} from './types.js';
import {
  calculateSalience,
  suggestCategory,
  extractTags,
  analyzeSalienceFactors,
} from './salience.js';
import { resolveMemoryConfig } from './config.js';
import { calculateDecayedScore } from './decay.js';
import {
  emitMemoryCreated,
  emitMemoryDeleted,
  emitMemoryUpdated,
  persistEvent,
} from '../api/events.js';
import { generateEmbedding, cosineSimilarity } from '../embeddings/index.js';
import { isPaused } from '../api/control.js';
import { extractFromMemory } from '../graph/extract.js';
import { processExtractionResult, removeMemoryGraph, replaceMemoryGraph } from '../graph/resolve.js';
import type { TripleProvenance } from '../graph/resolve.js';
import { runDefencePipeline, storeFragmentationData } from '../defence/index.js';
import { resolveDisposition } from '../defence/disposition.js';
import { syncQuarantineToCloud } from '../cloud/quarantine-sync.js';
import { syncGraphDeleteForMemoryToCloud, syncGraphForMemoryToCloud } from '../cloud/graph-sync.js';
import { syncMemoryDeleteToCloud, syncMemoryUpsertToCloud } from '../cloud/memory-sync.js';
import { isFeatureEnabled } from '../license/gate.js';
import type { DefenceSource, DefencePipelineResult, AuditOperation } from '../defence/types.js';
import { checkAccess } from '../defence/trust/access-control.js';
import { scoreSource } from '../defence/trust/source-scorer.js';
import { logAudit, createContentHash, attestedFlag } from '../defence/audit/logger.js';
import { dispatchWebhook } from '../events/webhooks.js';
import { safeJsonParse } from './fts.js';
// Internal use of the link API. links.ts also imports from store.ts (getMemoryById,
// rowToMemory) — the cycle is safe because both directions only invoke the imported
// symbols inside function bodies, never at module load. ESM live bindings handle it.
// Same function-body-only cycle pattern applies to lifecycle.ts and search-recall.ts.
import { createMemoryLink, detectRelationships } from './links.js';

// Anti-bloat: Maximum content size per memory (10KB).
// Exported because lifecycle.ts also enforces this budget inside enrichMemory.
export const MAX_CONTENT_SIZE = 10 * 1024;

// Synthetic source for writes that arrive without an attributed DefenceSource
// (dashboard REST POST, bulk paths, etc). It MUST score strictly below the
// 0.5–0.7 auto-quarantine band (web = 0.3) so unattributed writes are SCANNED
// + stamped low-trust rather than admitted unscanned at trust 1.0 — but are not
// force-quarantined (which would make every source-less write throw). Closing
// the old `if (source)` defence-pipeline bypass.
export const UNATTRIBUTED_SOURCE: DefenceSource = { type: 'web', identifier: 'unattributed' };

// Track truncation info globally for the last addMemory call
let lastTruncationInfo: { wasTruncated: boolean; originalLength: number; truncatedLength: number } | null = null;

/**
 * Truncate content if it exceeds max size (in bytes, not characters)
 * Uses byte length to handle multi-byte Unicode correctly (emoji, CJK, etc.)
 * Returns both the content and truncation info
 */
function truncateContent(content: string): { content: string; wasTruncated: boolean; originalLength: number } {
  const byteLength = Buffer.byteLength(content, 'utf-8');
  if (byteLength > MAX_CONTENT_SIZE) {
    // Binary search to find the right truncation point in bytes
    // Reserve 50 bytes for the truncation message
    const targetBytes = MAX_CONTENT_SIZE - 50;
    let low = 0;
    let high = content.length;
    while (low < high) {
      const mid = Math.floor((low + high + 1) / 2);
      if (Buffer.byteLength(content.slice(0, mid), 'utf-8') <= targetBytes) {
        low = mid;
      } else {
        high = mid - 1;
      }
    }
    return {
      content: content.slice(0, low) + '\n\n[Content truncated - exceeded 10KB limit]',
      wasTruncated: true,
      originalLength: byteLength,
    };
  }
  return { content, wasTruncated: false, originalLength: byteLength };
}

/**
 * Get truncation info from the last addMemory call
 */
export function getLastTruncationInfo() {
  return lastTruncationInfo;
}

function inferSourceDetails(input: MemoryInput, source?: DefenceSource): {
  sourceKind: MemorySourceKind;
  captureMethod: MemoryCaptureMethod;
  sourceValue: string | null;
} {
  const tags = (input.tags ?? []).map((tag) => tag.toLowerCase());
  const metadata = input.metadata ?? {};
  const metadataSourceType = typeof metadata.sourceType === 'string' ? metadata.sourceType : null;
  const metadataSourceIdentifier = typeof metadata.sourceIdentifier === 'string' ? metadata.sourceIdentifier : null;

  if ((tags.includes('session-end') || tags.includes('session-stop') || tags.includes('keyword-trigger')) && metadataSourceType === 'hook') {
    return {
      sourceKind: 'hook',
      captureMethod: tags.includes('auto-extracted') ? 'auto' : 'hook',
      sourceValue: `hook:${metadataSourceIdentifier ?? 'openclaw'}`,
    };
  }
  if ((tags.includes('realtime-plugin') || tags.includes('llm-output')) && metadataSourceType === 'agent') {
    return {
      sourceKind: 'agent',
      captureMethod: tags.includes('auto-extracted') ? 'auto' : 'plugin',
      sourceValue: `agent:${metadataSourceIdentifier ?? 'openclaw-plugin'}`,
    };
  }

  if (tags.includes('openclaw-hook')) {
    return { sourceKind: 'hook', captureMethod: tags.includes('auto-extracted') ? 'auto' : 'hook', sourceValue: 'hook:openclaw' };
  }
  if (tags.includes('realtime-plugin') || tags.includes('llm-output')) {
    return { sourceKind: 'plugin', captureMethod: tags.includes('auto-extracted') ? 'auto' : 'plugin', sourceValue: 'agent:openclaw-plugin' };
  }
  if (source?.type === 'hook') {
    return { sourceKind: 'hook', captureMethod: 'hook', sourceValue: `${source.type}:${source.identifier}` };
  }
  if (source?.type === 'agent') {
    return { sourceKind: 'agent', captureMethod: 'plugin', sourceValue: `${source.type}:${source.identifier}` };
  }
  if (source?.type === 'api') {
    return { sourceKind: 'api', captureMethod: 'api', sourceValue: `${source.type}:${source.identifier}` };
  }
  if (source?.type === 'cli') {
    return { sourceKind: 'cli', captureMethod: 'manual', sourceValue: `${source.type}:${source.identifier}` };
  }

  return {
    sourceKind: input.sourceKind ?? 'user',
    captureMethod: input.captureMethod ?? (tags.includes('auto-extracted') ? 'auto' : 'manual'),
    sourceValue: input.source ?? (source ? `${source.type}:${source.identifier}` : 'user:direct'),
  };
}

/**
 * Convert database row to Memory object
 */
export function rowToMemory(row: Record<string, unknown>): Memory {
  return {
    id: row.id as number,
    uuid: row.uuid as string,
    type: row.type as MemoryType,
    category: row.category as MemoryCategory,
    title: row.title as string,
    content: row.content as string,
    project: row.project as string | undefined,
    tags: safeJsonParse(row.tags as string, []),
    salience: row.salience as number,
    accessCount: row.access_count as number,
    lastAccessed: new Date(row.last_accessed as string),
    createdAt: new Date(row.created_at as string),
    updatedAt: new Date((row.updated_at as string) ?? (row.created_at as string)),
    decayedScore: (row.decayed_score as number) ?? (row.salience as number),
    metadata: safeJsonParse(row.metadata as string, {}),
    embedding: row.embedding as Buffer | undefined,
    scope: (row.scope as 'project' | 'global') ?? 'project',
    transferable: Boolean(row.transferable),
    status: ((row.status as MemoryStatus | undefined) ?? 'active'),
    pinned: Boolean(row.pinned),
    reviewedAt: row.reviewed_at ? new Date(row.reviewed_at as string) : null,
    reviewedBy: (row.reviewed_by as string | null) ?? null,
    sourceKind: ((row.source_kind as MemorySourceKind | undefined) ?? 'user'),
    captureMethod: ((row.capture_method as MemoryCaptureMethod | undefined) ?? 'manual'),
    trustScore: Number(row.trust_score ?? 1),
    sensitivityLevel: (row.sensitivity_level as string | undefined) ?? 'INTERNAL',
    source: (row.source as string | null) ?? null,
    cloudExcluded: Boolean(row.cloud_excluded),
    memoryPurpose: ((row.memory_purpose as MemoryPurpose | undefined) ?? 'project'),
    memoryScope: ((row.memory_scope as MemoryScope | undefined) ?? 'private'),
  };
}

/**
 * Detect if memory content suggests global applicability
 * Used to auto-set scope to 'global' for transferable knowledge
 */
// Default to project scope. Only auto-promote when the memory carries an
// explicit "applies everywhere" signal — a global tag, or a universality
// keyword in content of a generic category that doesn't reference any
// project-specific identifier.
function detectGlobalPattern(content: string, category: MemoryCategory, tags: string[]): boolean {
  const globalTags = ['universal', 'global', 'general', 'cross-project'];
  if (tags.some(t => globalTags.includes(t.toLowerCase()))) return true;

  const universalCategories: MemoryCategory[] = ['pattern', 'preference'];
  if (!universalCategories.includes(category)) return false;

  const universalKeywords = [
    'always ', 'never ', 'best practice', 'general rule',
    'universal', 'in every project', 'across projects', 'globally',
  ];
  const lower = content.toLowerCase();
  if (!universalKeywords.some(k => lower.includes(k))) return false;

  // Filesystem paths, URLs, env vars, or dotted identifiers are strong
  // signals the note pins to a specific project or system.
  const projectSpecificMarkers = /(\/[A-Za-z0-9_.-]+){2,}|https?:\/\/|\b[A-Z][A-Z0-9_]{3,}\b|\b\w+\.\w+\(/;
  if (projectSpecificMarkers.test(content)) return false;

  return true;
}

// ── Rate Limiter ──
// Tracks write attempts per source to prevent audit log flooding

const RATE_LIMIT_WINDOW_MS = 60_000; // 1 minute
const RATE_LIMIT_MAX = 20; // max writes per window per source
let rateLimitPruneCount = 0;

function checkRateLimit(source: DefenceSource): boolean {
  const db = getDatabase();
  const key = `${source.type}:${source.identifier}`;
  const now = Date.now();

  // Prune expired entries every 50 checks
  if (++rateLimitPruneCount % 50 === 0) {
    try {
      db.prepare('DELETE FROM rate_limits WHERE ? - window_start_ms > ?')
        .run(now, RATE_LIMIT_WINDOW_MS * 2);
    } catch {
      // Table may not exist yet in legacy DBs — fall through to allow
    }
  }

  try {
    const row = db.prepare('SELECT write_count, window_start_ms FROM rate_limits WHERE source_key = ?')
      .get(key) as { write_count: number; window_start_ms: number } | undefined;

    if (!row || now - row.window_start_ms > RATE_LIMIT_WINDOW_MS) {
      // New window — upsert
      db.prepare(
        'INSERT INTO rate_limits (source_key, write_count, window_start_ms) VALUES (?, 1, ?) ON CONFLICT(source_key) DO UPDATE SET write_count = 1, window_start_ms = ?'
      ).run(key, now, now);
      return true;
    }

    // Increment counter
    const newCount = row.write_count + 1;
    db.prepare('UPDATE rate_limits SET write_count = ? WHERE source_key = ?')
      .run(newCount, key);

    if (newCount > RATE_LIMIT_MAX) {
      return false; // rate limited
    }
    return true;
  } catch {
    // If rate_limits table doesn't exist (legacy DB), allow the write
    return true;
  }
}

// ── Read-Time Access Control ──

// Exported because search-recall.ts also calls logAccessDenial inside its
// post-search ACL filter (cycle artifact, not intended public API).
export function logAccessDenial(
  memoryId: number,
  source: DefenceSource,
  reason: string,
  operation: AuditOperation = 'read',
  attested?: boolean,
): void {
  const trust = scoreSource(source).score;
  logAudit({
    memory_id: memoryId,
    project: null,
    timestamp: new Date().toISOString(),
    source_type: source.type,
    source_identifier: source.identifier,
    trust_score: trust,
    sensitivity_level: 'INTERNAL',
    firewall_result: 'BLOCK',
    operation,
    anomaly_score: 0,
    threat_indicators: '[]',
    blocked_patterns: '[]',
    reason: `Access denied: ${reason}`,
    fragmentation_score: null,
    pipeline_duration_ms: 0,
    // A denial is a BLOCK keyed to a source; carrying attestation lets the
    // threat graph accrue a spoofer's denied reads instead of dropping them.
    source_attested: attestedFlag(attested),
  });
}

/**
 * Provenance ledger: record an ALLOWED read. Emitted ONCE per tool call (not per
 * row) to keep the audit table bounded — recall returns up to 50 rows, so a
 * per-row emit would flood it. memory_id carries the single id for single-target
 * reads; the full id list (capped) goes in blocked_patterns for forensics.
 */
export function logAllowedRead(
  source: DefenceSource,
  tool: string,
  memoryIds: number[],
  project?: string | null,
  attested?: boolean,
): void {
  if (memoryIds.length === 0) return;
  logAudit({
    memory_id: memoryIds.length === 1 ? memoryIds[0] : null,
    project: project ?? null,
    timestamp: new Date().toISOString(),
    source_type: source.type,
    source_identifier: source.identifier,
    trust_score: scoreSource(source).score,
    sensitivity_level: 'INTERNAL',
    firewall_result: 'ALLOW',
    operation: 'read',
    anomaly_score: 0,
    threat_indicators: '[]',
    blocked_patterns: JSON.stringify(memoryIds.slice(0, 50)),
    reason: `read ${memoryIds.length} memor${memoryIds.length === 1 ? 'y' : 'ies'} via ${tool}`,
    fragmentation_score: null,
    pipeline_duration_ms: null,
    source_attested: attestedFlag(attested),
  });
}

/**
 * Provenance ledger: record an ALLOWED delete (one row per deleted memory).
 * memory_id is NULL by design — the row is emitted after the DELETE, and the
 * audit.memory_id FK is ON DELETE SET NULL, so a live reference can't survive.
 * The deleted id is preserved in `reason` + `blocked_patterns` for forensics.
 */
export function logAllowedDelete(
  memoryId: number,
  source: DefenceSource,
  project?: string | null,
  operation: AuditOperation = 'delete',
  attested?: boolean,
): void {
  logAudit({
    memory_id: null,
    project: project ?? null,
    timestamp: new Date().toISOString(),
    source_type: source.type,
    source_identifier: source.identifier,
    trust_score: scoreSource(source).score,
    sensitivity_level: 'INTERNAL',
    firewall_result: 'ALLOW',
    operation,
    anomaly_score: 0,
    threat_indicators: '[]',
    blocked_patterns: JSON.stringify([memoryId]),
    reason: `deleted memory #${memoryId}`,
    fragmentation_score: null,
    pipeline_duration_ms: null,
    source_attested: attestedFlag(attested),
  });
}

/**
 * Filter raw DB rows by access control before converting to Memory objects.
 * Returns only rows the source is allowed to read.
 */
function filterRowsByAccess(
  rows: Record<string, unknown>[],
  source: DefenceSource,
  attested?: boolean,
): Record<string, unknown>[] {
  return rows.filter(row => {
    const policy = checkAccess(
      {
        id: row.id as number,
        source: row.source as string | null,
        sensitivity_level: row.sensitivity_level as string | null,
      },
      source,
      'read',
    );
    if (!policy.canRead) {
      logAccessDenial(row.id as number, source, policy.reason, 'read', attested);
      return false;
    }
    return true;
  });
}

/**
 * Error thrown when memory creation is paused
 */
export class MemoryPausedError extends Error {
  constructor() {
    super('Memory creation is currently paused. Use the dashboard to resume.');
    this.name = 'MemoryPausedError';
  }
}

/**
 * Error thrown when memory is blocked by the defence firewall
 */
export class MemoryBlockedError extends Error {
  constructor(reason: string) {
    super(`Memory blocked by defence firewall: ${reason}`);
    this.name = 'MemoryBlockedError';
  }
}

/**
 * Store a blocked memory in quarantine for later review
 */
function quarantineMemory(input: MemoryInput, source: DefenceSource, result: DefencePipelineResult): void {
  try {
    const db = getDatabase();
    // Defensive: coerce firewall_result if content was blocked but result is still ALLOW
    const firewallResult = result.firewall.result === 'ALLOW' ? 'BLOCK' : result.firewall.result;
    db.prepare(`INSERT INTO quarantine (original_title, original_content, project, source_type, source_identifier, reason, threat_indicators, anomaly_score, firewall_result, audit_id, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')`)
      .run(input.title, input.content, input.project ?? null, source.type, source.identifier, result.firewall.reason, JSON.stringify(result.firewall.threatIndicators), result.firewall.anomalyScore, firewallResult, result.auditId);

    // Webhook notification (fire-and-forget)
    dispatchWebhook('memory_quarantined', { id: null, title: input.title, reason: result.firewall.reason });

    // Cloud quarantine sync is handled upstream:
    // - Pipeline QUARANTINE → synced by pipeline.ts step 9
    // - Post-pipeline override (sub-agent trust) → synced by addMemory() override block
  } catch (e) {
    console.error('[shieldcortex] Failed to quarantine memory:', e);
  }
}

/**
 * Add a new memory
 */
export function addMemory(
  input: MemoryInput,
  config: MemoryConfig = resolveMemoryConfig(),
  source?: DefenceSource,
  options?: { sourceAttested?: boolean },
): Memory {
  // Check if memory creation is paused
  if (isPaused()) {
    throw new MemoryPausedError();
  }

  // RATE LIMITING: Block sources that exceed write rate
  if (source && !checkRateLimit(source)) {
    logAudit({
      memory_id: null,
      project: input.project ?? null,
      timestamp: new Date().toISOString(),
      source_type: source.type,
      source_identifier: source.identifier,
      trust_score: scoreSource(source).score,
      sensitivity_level: 'INTERNAL',
      firewall_result: 'BLOCK',
      operation: 'write',
      anomaly_score: 1.0,
      threat_indicators: JSON.stringify(['rate_limit_exceeded']),
      blocked_patterns: '[]',
      reason: `Rate limited: exceeded ${RATE_LIMIT_MAX} writes/minute`,
      fragmentation_score: null,
      pipeline_duration_ms: 0,
      // BLOCK keyed to the caller — carries the same attestation the pipeline
      // row would, so a flood from an attested source can accrue.
      source_attested: attestedFlag(options?.sourceAttested),
    });
    throw new MemoryBlockedError(`Rate limited: exceeded ${RATE_LIMIT_MAX} writes per minute`);
  }

  // DEFENCE PIPELINE: Scan EVERY write before storage. Source-less writes get a
  // conservative low-trust synthetic source (UNATTRIBUTED_SOURCE = web:0.3) so
  // they are still scanned + stamped low-trust instead of admitted unscanned at
  // trust 1.0 — closing the old `if (source)` bypass. Rate-limiting stays gated
  // on an explicit source (above) so bulk source-less/import writes aren't
  // throttled by the shared synthetic key.
  const effectiveSource: DefenceSource = source ?? UNATTRIBUTED_SOURCE;
  const defenceResult: DefencePipelineResult = runDefencePipeline(
    input.content, input.title, effectiveSource, undefined, input.project,
    { sourceAttested: options?.sourceAttested },
  );

  // P1/WS4: the ONE verdict→disposition mapping, shared with the hook path
  // (save-memory.mjs) so the runtimes cannot drift. It folds in the sub-agent
  // trust-band hold (0.5–0.7) and the block/quarantine hold policy.
  const disposition = resolveDisposition({
    allowed: defenceResult.allowed,
    firewallResult: defenceResult.firewall.result,
    trustScore: defenceResult.trust.score,
    reason: defenceResult.firewall.reason,
  });

  if (disposition.action === 'quarantine') {
    // Auto-release (threat-graph Loop 3): if this detector firing is a
    // standing operator allowance for this source AND the content
    // near-duplicates an approved exemplar, admit instead of hold. Default
    // off; fails CLOSED — any error keeps the item quarantined.
    let autoReleased = false;
    // Never even attempt release on a hard BLOCK (invariant 2). resolveDisposition
    // maps BOTH BLOCK and QUARANTINE to action='quarantine', so the verdict must
    // be checked explicitly here — not the disposition action.
    if (isAutoReleaseEnabled() && disposition.firewallResult === 'QUARANTINE') {
      try {
        const key = sourceKey(effectiveSource.type, effectiveSource.identifier);
        const hash = exemplarHash(input.title, input.content);
        // The COMPLETE detection set — patterns AND indicators — must all be
        // allowed, or an item with an unlisted detection would slip through.
        const patterns = detectionKeys(
          defenceResult.firewall.blockedPatterns ?? [],
          defenceResult.firewall.threatIndicators ?? [],
        );
        const now = Date.now();
        if (shouldAutoRelease({ sourceKey: key, patterns, contentHash: hash, verdict: 'QUARANTINE', nowMs: now }).release) {
          recordAutoRelease({ sourceKey: key, patterns, contentHash: hash, nowMs: now });
          autoReleased = true;
        }
      } catch {
        autoReleased = false;
      }
    }

    if (!autoReleased) {
    // Reflect the resolved verdict/reason back so quarantineMemory + audit record it.
    defenceResult.allowed = false;
    defenceResult.firewall.result = disposition.firewallResult;
    defenceResult.firewall.reason = disposition.reason;

    // A sub-agent-band hold was an ALLOW at the pipeline, so pipeline.ts did NOT
    // sync it — sync the now-held content here (genuine BLOCK/QUARANTINE were
    // already synced inside the pipeline).
    if (disposition.subAgentHold && isFeatureEnabled('cloud_sync')) try {
      const indicators = defenceResult.firewall.threatIndicators.map(t =>
        typeof t === 'string' ? t : (t as { pattern?: string }).pattern ?? String(t)
      );
      syncQuarantineToCloud({
        original_content: input.content,
        original_title: input.title,
        source_type: effectiveSource.type,
        source_identifier: effectiveSource.identifier,
        reason: defenceResult.firewall.reason,
        threat_indicators: indicators,
        anomaly_score: defenceResult.firewall.anomalyScore,
        firewall_result: defenceResult.firewall.result,
        project: input.project ?? null,
        sensitivity_level: defenceResult.sensitivity.level,
      });
    } catch {
      // Cloud sync must never affect local quarantine flow
    }

    quarantineMemory(input, effectiveSource, defenceResult);
    throw new MemoryBlockedError(defenceResult.firewall.reason);
    }
    // auto-released → fall through to normal storage. Stamp the verdict ALLOW
    // (and a distinguishing reason) so the stored memory's defence_verdict is
    // not left reading 'quarantine'/'block' — the normal store path reads
    // defenceResult for the stamped verdict. The auto_release audit row above
    // is the reviewable record of why.
    defenceResult.allowed = true;
    defenceResult.firewall.result = 'ALLOW';
    defenceResult.firewall.reason = `auto-released against a standing operator allowance (was: ${defenceResult.firewall.reason})`;
  }

  const db = getDatabase();

  // Calculate salience if not provided
  const salience = input.salience ?? calculateSalience(input);

  // Suggest category if not provided
  const category = input.category ?? suggestCategory(input);

  // Extract tags
  const tags = extractTags(input);

  // Determine type
  const type = input.type ?? (salience >= config.consolidationThreshold ? 'long_term' : 'short_term');

  // Determine scope and transferable flag for cross-project knowledge
  const scope = input.scope ??
    (detectGlobalPattern(input.content, category, tags) ? 'global' : 'project');
  const transferable = input.transferable ?? (scope === 'global' ? 1 : 0);
  const sourceDetails = inferSourceDetails({ ...input, tags }, effectiveSource);
  const status = input.status ?? 'active';
  const pinned = input.pinned ? 1 : 0;
  const cloudExcluded = input.cloudExcluded ? 1 : 0;

  // P1/WS3: stamp the pipeline's disposition. A row only reaches this INSERT
  // when the write was accepted (block/quarantine threw above), so this is the
  // real ALLOW verdict — never the schema's 'unverified' funnel-bypass default.
  const defenceVerdict = defenceResult.firewall.result.toLowerCase();
  const stmt = db.prepare(`
    INSERT INTO memories (
      uuid, type, category, title, content, project, tags, salience, metadata, scope, transferable,
      status, pinned, reviewed_at, reviewed_by, source_kind, capture_method, defence_verdict, cloud_excluded, memory_purpose, memory_scope, updated_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
  `);

  // Anti-bloat: Truncate content if too large
  const truncationResult = truncateContent(input.content);

  // Store truncation info for the remember tool to access
  lastTruncationInfo = {
    wasTruncated: truncationResult.wasTruncated,
    originalLength: truncationResult.originalLength,
    truncatedLength: truncationResult.content.length,
  };

  // Transaction: INSERT + defence UPDATE must be atomic to prevent wrong trust scores
  const insertedId = db.transaction(() => {
    const memoryUuid = randomUUID();
    const result = stmt.run(
      memoryUuid,
      type,
      category,
      input.title,
      truncationResult.content,
      input.project || null,
      JSON.stringify(tags),
      salience,
      JSON.stringify(input.metadata || {}),
      scope,
      transferable,
      status,
      pinned,
      input.reviewedBy ? new Date().toISOString() : null,
      input.reviewedBy ?? null,
      sourceDetails.sourceKind,
      sourceDetails.captureMethod,
      defenceVerdict,
      cloudExcluded,
      input.memoryPurpose || 'project',
      input.memoryScope || 'private'
    );

    // defenceResult is always set now (every write is scanned), so always stamp
    // the pipeline's real trust + sensitivity alongside the resolved source —
    // no source-less branch can default to trust 1.0 / unscanned INTERNAL.
    db.prepare(`UPDATE memories SET trust_score = ?, sensitivity_level = ?, source = ?, content_hash = ? WHERE id = ?`)
      // content_hash = SHA-256 of the SUBMITTED content (a write-time provenance
      // snapshot), matching the write-audit row in pipeline.ts. Consistent for
      // >10KB memories too (where the STORED content is truncated).
      .run(defenceResult.trust.score, defenceResult.sensitivity.level, sourceDetails.sourceValue, createContentHash(input.content), result.lastInsertRowid);

    return result.lastInsertRowid as number;
  })();

  const memory = getMemoryById(insertedId)!;

  // ONTOLOGY: Extract entities and triples FIRST so the memory_created
  // payload can carry entity_ids. The pulse layer (Living Constellation
  // Graph) maps memory_created events to graph nodes via these IDs —
  // without them, Layer A/B of PulseDriver silently never fires.
  // processExtractionResult writes to memory_entities synchronously, so we
  // can query it back immediately for the event payload.
  let entityIds: number[] = [];
  try {
    const extraction = extractFromMemory(input.title, truncationResult.content, category);
    if (extraction.entities.length > 0) {
      // Phase E: stamp write-time provenance so relation-channel conflicts can be
      // adjudicated by writer + trust. writer_trust is capped for unattested
      // (claimed) sources at store time inside processExtractionResult.
      processExtractionResult(extraction, memory.id, {
        writerSource: sourceKey(effectiveSource.type, effectiveSource.identifier),
        writerTrust: defenceResult.trust.score,
        attested: options?.sourceAttested ?? false,
      });
      if (isFeatureEnabled('cloud_sync')) {
        syncGraphForMemoryToCloud(memory.id);
      }
    }
    entityIds = (
      db
        .prepare('SELECT entity_id FROM memory_entities WHERE memory_id = ?')
        .all(memory.id) as { entity_id: number }[]
    ).map((r) => r.entity_id);
  } catch (e) {
    console.error('[shieldcortex] Entity extraction failed:', e);
  }

  // Emit event for real-time dashboard (in-process)
  emitMemoryCreated(memory, entityIds);
  // Persist event for cross-process IPC (MCP → Dashboard)
  persistEvent('memory_created', { memory, entity_ids: entityIds });

  // Webhook notification (fire-and-forget)
  dispatchWebhook('memory_created', { id: memory.id, title: memory.title, category: memory.category });

  if (isFeatureEnabled('cloud_sync')) {
    syncMemoryUpsertToCloud(memory);
  }

  // ORGANIC FEATURE: Auto-link to related memories
  // This builds the knowledge graph automatically as memories are created
  try {
    const relationships = detectRelationships(memory);
    for (const rel of relationships.slice(0, 3)) { // Top 3 most relevant
      createMemoryLink(memory.id, rel.targetId, rel.relationship, rel.strength);
    }
  } catch (e) {
    // Don't fail memory creation if linking fails
    console.error('[shieldcortex] Auto-link failed:', e);
  }

  // DEFENCE: Store fragmentation data for cross-memory payload detection.
  // Un-gated from `if (source)` so source-less writes also feed the temporal
  // assembly corpus (a blind spot the write-bypass left).
  try {
    storeFragmentationData(memory.id, truncationResult.content);
  } catch (e) {
    console.warn('[shieldcortex] Fragmentation data storage failed:', e instanceof Error ? e.message : e);
  }

  // SEMANTIC SEARCH: Generate embedding asynchronously (don't block INSERT)
  const memoryId = memory.id;
  generateEmbedding(input.title + ' ' + truncationResult.content)
    .then(embedding => {
      try {
        // Validate embedding exists and has expected structure
        if (embedding && embedding.buffer) {
          db.prepare('UPDATE memories SET embedding = ? WHERE id = ?')
            .run(Buffer.from(embedding.buffer), memoryId);
        } else {
          console.warn('[shieldcortex] Embedding generation returned invalid result for memory', memoryId);
        }
      } catch (e) {
        const errMsg = e instanceof Error ? e.message : String(e);
        if (/database connection is not open/i.test(errMsg)) {
          return;
        }
        console.error('[shieldcortex] Failed to store embedding:', e);
      }
    })
    .catch(e => {
      if (
        e instanceof Error &&
        (
          e.message.includes('Embedding worker unavailable') ||
          e.message.includes('Embeddings disabled via SHIELDCORTEX_SKIP_EMBEDDINGS=1')
        )
      ) {
        return;
      }
      console.error('[shieldcortex] Failed to generate embedding:', e);
    });

  // Anti-bloat: Check if limits exceeded and trigger async cleanup
  // We use setImmediate to not block the insert response
  if (process.env.NODE_ENV !== 'test') {
    setImmediate(() => {
      try {
        if (!isDatabaseInitialized()) {
          return;
        }
        const stats = getMemoryStats();
        if (
          stats.shortTerm > config.maxShortTermMemories ||
          stats.longTerm > config.maxLongTermMemories
        ) {
          // Import dynamically to avoid circular dependency
          import('./consolidate.js').then(({ enforceMemoryLimits }) => {
            if (typeof enforceMemoryLimits === 'function') {
              enforceMemoryLimits(config);
            }
          }).catch((e) => {
            // Log but don't fail - consolidation will happen on next scheduled run
            console.warn('[shieldcortex] Async cleanup import failed:', e instanceof Error ? e.message : e);
          });
        }
      } catch (e) {
        // Log unexpected errors in async cleanup
        console.warn('[shieldcortex] Async cleanup check failed:', e instanceof Error ? e.message : e);
      }
    });
  }

  return memory;
}

/**
 * Get a memory by ID
 */
export function getMemoryById(id: number, source?: DefenceSource, attested?: boolean): Memory | null {
  const db = getDatabase();
  const row = db.prepare('SELECT * FROM memories WHERE id = ?').get(id) as Record<string, unknown> | undefined;
  if (!row) return null;

  // ACCESS CONTROL: Check read permission
  if (source) {
    const policy = checkAccess(
      { id: row.id as number, source: row.source as string | null, sensitivity_level: row.sensitivity_level as string | null },
      source,
      'read',
    );
    if (!policy.canRead) {
      logAccessDenial(id, source, policy.reason, 'read', attested);
      return null;
    }
  }

  return rowToMemory(row);
}

/**
 * Recompute and persist the `memories.embedding` vector for a memory whose
 * embedded text (title/content) just changed. Fire-and-forget, mirroring
 * addMemory's write: the caller is expected to have already cleared the column
 * (`embedding = NULL`) synchronously so no stale vector is readable in the gap
 * before this lands. No-ops cleanly when embeddings are disabled/unavailable.
 */
function refreshEmbeddingAsync(memoryId: number, title: string, content: string): void {
  const db = getDatabase();
  generateEmbedding(title + ' ' + content)
    .then((embedding) => {
      try {
        if (embedding && embedding.buffer) {
          db.prepare('UPDATE memories SET embedding = ? WHERE id = ?')
            .run(Buffer.from(embedding.buffer), memoryId);
        }
      } catch (e) {
        const errMsg = e instanceof Error ? e.message : String(e);
        if (/database connection is not open/i.test(errMsg)) return;
        console.error('[shieldcortex] Failed to store refreshed embedding:', e);
      }
    })
    .catch((e) => {
      if (
        e instanceof Error &&
        (
          e.message.includes('Embedding worker unavailable') ||
          e.message.includes('Embeddings disabled via SHIELDCORTEX_SKIP_EMBEDDINGS=1')
        )
      ) {
        return;
      }
      console.error('[shieldcortex] Failed to regenerate embedding:', e);
    });
}

/**
 * Update a memory
 */
/**
 * Provenance for triples re-extracted on an update/merge (Phase E). Uses the
 * memory's own stored source/trust, always treated as unattested — the update
 * re-scan runs unattributed, so writer_trust is conservatively capped. Returns
 * undefined when the memory has no recorded source (→ NULL provenance).
 */
function updateProvenance(memory: Memory): TripleProvenance | undefined {
  if (!memory.source) return undefined;
  return { writerSource: memory.source, writerTrust: memory.trustScore, attested: false };
}

export function updateMemory(
  id: number,
  updates: Partial<MemoryInput>
): Memory | null {
  const db = getDatabase();
  const existing = getMemoryById(id);
  if (!existing) return null;

  // DEFENCE: re-scan when content/title changes — the UPDATE path is otherwise
  // an unscanned write (reachable via remember-dedup + the dashboard PATCH).
  // Mirror mergeMemories: fail closed on a non-ALLOW verdict so a poison content
  // replace can't overwrite a clean row unchecked.
  if (updates.content !== undefined || updates.title !== undefined) {
    const scanContent = updates.content !== undefined ? updates.content : existing.content;
    const scanTitle = updates.title !== undefined ? updates.title : existing.title;
    const defenceResult = runDefencePipeline(scanContent, scanTitle, UNATTRIBUTED_SOURCE, undefined, existing.project ?? undefined);
    if (defenceResult.firewall.result !== 'ALLOW') {
      throw new MemoryBlockedError(defenceResult.firewall.reason);
    }
  }

  const fields: string[] = [];
  const values: unknown[] = [];

  if (updates.title !== undefined) {
    fields.push('title = ?');
    values.push(updates.title);
  }
  if (updates.content !== undefined) {
    fields.push('content = ?');
    values.push(updates.content);
  }
  if (updates.type !== undefined) {
    fields.push('type = ?');
    values.push(updates.type);
  }
  if (updates.category !== undefined) {
    fields.push('category = ?');
    values.push(updates.category);
  }
  if (updates.project !== undefined) {
    fields.push('project = ?');
    values.push(updates.project);
  }
  if (updates.scope !== undefined) {
    fields.push('scope = ?');
    values.push(updates.scope);
  }
  if (updates.transferable !== undefined) {
    fields.push('transferable = ?');
    values.push(updates.transferable ? 1 : 0);
  }
  if (updates.tags !== undefined) {
    fields.push('tags = ?');
    values.push(JSON.stringify(updates.tags));
  }
  if (updates.salience !== undefined) {
    fields.push('salience = ?');
    values.push(updates.salience);
  }
  if (updates.metadata !== undefined) {
    fields.push('metadata = ?');
    values.push(JSON.stringify(updates.metadata));
  }
  if (updates.status !== undefined) {
    fields.push('status = ?');
    values.push(updates.status);
  }
  if (updates.pinned !== undefined) {
    fields.push('pinned = ?');
    values.push(updates.pinned ? 1 : 0);
  }
  if (updates.reviewedBy !== undefined) {
    fields.push('reviewed_by = ?');
    values.push(updates.reviewedBy);
    fields.push('reviewed_at = ?');
    values.push(updates.reviewedBy ? new Date().toISOString() : null);
  }
  if (updates.sourceKind !== undefined) {
    fields.push('source_kind = ?');
    values.push(updates.sourceKind);
  }
  if (updates.captureMethod !== undefined) {
    fields.push('capture_method = ?');
    values.push(updates.captureMethod);
  }
  if (updates.trustScore !== undefined) {
    fields.push('trust_score = ?');
    values.push(updates.trustScore);
  }
  if (updates.sensitivityLevel !== undefined) {
    fields.push('sensitivity_level = ?');
    values.push(updates.sensitivityLevel);
  }
  if (updates.source !== undefined) {
    fields.push('source = ?');
    values.push(updates.source);
  }
  if (updates.cloudExcluded !== undefined) {
    fields.push('cloud_excluded = ?');
    values.push(updates.cloudExcluded ? 1 : 0);
  }

  if (updates.memoryPurpose !== undefined) {
    fields.push('memory_purpose = ?');
    values.push(updates.memoryPurpose);
  }
  if (updates.memoryScope !== undefined) {
    fields.push('memory_scope = ?');
    values.push(updates.memoryScope);
  }

  // STALENESS: if the embedded text (title/content) changes, the persisted
  // `memories.embedding` no longer reflects the current content. The recall reuse
  // path (findSimilarMemories) scores candidates straight off this column, so a
  // stale vector would let recall match on outdated content. Clear it in the SAME
  // UPDATE — no window where the old vector is readable — then recompute below,
  // mirroring addMemory's fire-and-forget embedding write. Cleared-but-not-yet-
  // recomputed rows are simply absent from vector recall until the recompute
  // lands (FTS still covers them); a stale match is the unacceptable outcome.
  const embeddedTextChanged = updates.title !== undefined || updates.content !== undefined;
  if (embeddedTextChanged) {
    fields.push('embedding = NULL');
  }

  // STALENESS: content_hash is a write-time integrity snapshot. When content
  // changes it must be recomputed in the SAME UPDATE — otherwise the stored hash
  // refers to the old content and any tamper check false-positives on a
  // legitimately-edited memory.
  if (updates.content !== undefined) {
    fields.push('content_hash = ?');
    values.push(createContentHash(updates.content));
  }

  if (fields.length === 0) return existing;

  values.push(id);
  db.prepare(`UPDATE memories SET ${fields.join(', ')}, updated_at = CURRENT_TIMESTAMP WHERE id = ?`).run(...values);

  const updatedMemory = getMemoryById(id)!;

  if (embeddedTextChanged) {
    refreshEmbeddingAsync(updatedMemory.id, updatedMemory.title, updatedMemory.content);
  }

  const shouldRefreshGraph =
    updates.title !== undefined ||
    updates.content !== undefined ||
    updates.category !== undefined;

  if (shouldRefreshGraph) {
    try {
      const extraction = extractFromMemory(
        updatedMemory.title,
        updatedMemory.content,
        updatedMemory.category,
      );
      // Phase E: an update is a write. Re-extracted triples carry the memory's
      // own source/trust as provenance, treated as unattested (the update
      // re-scan runs unattributed) so a claimed identity can't refresh into
      // high conflict-trust.
      replaceMemoryGraph(updatedMemory.id, extraction, updateProvenance(updatedMemory));
    } catch (e) {
      console.error('[shieldcortex] Entity extraction refresh failed:', e);
    }
  }

  // Provenance ledger: a content/title change is an update-class mutation.
  if (updates.content !== undefined || updates.title !== undefined) {
    const changed = [updates.title !== undefined ? 'title' : null, updates.content !== undefined ? 'content' : null].filter(Boolean).join('+');
    logAudit({
      memory_id: id,
      project: updatedMemory.project ?? null,
      timestamp: new Date().toISOString(),
      source_type: 'cli',
      source_identifier: 'memory-update',
      trust_score: updatedMemory.trustScore ?? 1,
      sensitivity_level: updatedMemory.sensitivityLevel ?? 'INTERNAL',
      firewall_result: 'ALLOW',
      operation: 'update',
      content_hash: updates.content !== undefined ? createContentHash(updates.content) : null,
      anomaly_score: 0,
      threat_indicators: '[]',
      blocked_patterns: '[]',
      reason: `updated memory #${id} (${changed})`,
      fragmentation_score: null,
      pipeline_duration_ms: null,
    });
  }

  // Emit event for real-time dashboard (in-process)
  emitMemoryUpdated(updatedMemory);
  // Persist event for cross-process IPC (MCP → Dashboard)
  persistEvent('memory_updated', { memory: updatedMemory });

  if (isFeatureEnabled('cloud_sync')) {
    syncMemoryUpsertToCloud(updatedMemory);
    syncGraphForMemoryToCloud(updatedMemory.id);
  }

  return updatedMemory;
}

function uniqueSentencesFrom(source: string, existing: string): string[] {
  const existingSentences = new Set(
    existing
      .split(/[.!?\n]+/)
      .map((sentence) => sentence.trim().toLowerCase())
      .filter(Boolean),
  );

  return source
    .split(/[.!?\n]+/)
    .map((sentence) => sentence.trim())
    .filter((sentence) => sentence.length > 0 && !existingSentences.has(sentence.toLowerCase()));
}

export function mergeMemories(
  keptId: number,
  removedId: number,
  options?: { reviewedBy?: string | null },
  source: DefenceSource = { type: 'cli', identifier: 'merge' },
): Memory | null {
  if (keptId === removedId) return getMemoryById(keptId);

  return withTransaction(() => {
    const db = getDatabase();
    const kept = getMemoryById(keptId);
    const removed = getMemoryById(removedId);

    if (!kept || !removed) return null;

    const mergedSnippets = uniqueSentencesFrom(removed.content, kept.content);
    const mergedContent = mergedSnippets.length > 0
      ? `${kept.content}\n\nMerged from duplicate (${removed.title}):\n${mergedSnippets.join('. ')}.`
      : kept.content;

    // DEFENCE PIPELINE: re-scan the *merged* content. Two individually-clean
    // memories can produce content that straddles a credential or injection
    // pattern across the join (kept.content + " " + removed sentences). This
    // is the one path that mechanically constructs new content from existing
    // rows — without this re-scan the "every byte in `memories` has been
    // scanned" invariant is broken. Throwing here rolls back the transaction
    // so neither the kept row nor the removed row changes.
    const mergedTitle = kept.title;
    const defenceResult = runDefencePipeline(
      mergedContent,
      mergedTitle,
      source,
      undefined,
      kept.project ?? removed.project ?? undefined,
    );
    if (defenceResult.firewall.result !== 'ALLOW') {
      throw new MemoryBlockedError(defenceResult.firewall.reason);
    }

    const mergedTags = Array.from(new Set([...(kept.tags ?? []), ...(removed.tags ?? [])]));
    const mergedFrom = Array.isArray(kept.metadata?.mergedFrom)
      ? [...kept.metadata.mergedFrom as unknown[]]
      : [];
    mergedFrom.push({
      id: removed.id,
      uuid: removed.uuid,
      title: removed.title,
      mergedAt: new Date().toISOString(),
    });

    const mergedMetadata = {
      ...kept.metadata,
      mergedFrom,
      mergedFromCount: mergedFrom.length,
    };

    const mergedStatus: MemoryStatus =
      kept.status === 'canonical' || removed.status === 'canonical'
        ? 'canonical'
        : kept.status === 'active' || removed.status === 'active'
          ? 'active'
          : kept.status;

    const mergedPinned = kept.pinned || removed.pinned || mergedStatus === 'canonical';
    const mergedCloudExcluded = kept.cloudExcluded || removed.cloudExcluded;
    const mergedScope = kept.scope === 'global' || removed.scope === 'global' ? 'global' : 'project';
    const mergedProject = kept.project ?? removed.project ?? null;
    const mergedTransferable = kept.transferable || removed.transferable;
    const mergedSalience = Math.max(kept.salience, removed.salience);
    const mergedTrustScore = Math.max(kept.trustScore ?? 0, removed.trustScore ?? 0);
    const mergedAccessCount = kept.accessCount + removed.accessCount;
    const mergedLastAccessed = new Date(
      Math.max(new Date(kept.lastAccessed).getTime(), new Date(removed.lastAccessed).getTime()),
    ).toISOString();
    const mergedReviewedBy = options?.reviewedBy ?? kept.reviewedBy ?? 'review-merge';
    const mergedSensitivity = kept.sensitivityLevel === 'SECRET' || removed.sensitivityLevel === 'SECRET'
      ? 'SECRET'
      : kept.sensitivityLevel === 'CONFIDENTIAL' || removed.sensitivityLevel === 'CONFIDENTIAL'
        ? 'CONFIDENTIAL'
        : kept.sensitivityLevel ?? removed.sensitivityLevel ?? 'INTERNAL';

    db.prepare(`
      UPDATE memories
      SET content = ?,
          content_hash = ?,
          tags = ?,
          salience = ?,
          project = ?,
          metadata = ?,
          scope = ?,
          transferable = ?,
          status = ?,
          pinned = ?,
          reviewed_by = ?,
          reviewed_at = ?,
          trust_score = ?,
          sensitivity_level = ?,
          cloud_excluded = ?,
          access_count = ?,
          last_accessed = ?,
          embedding = NULL,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(
      mergedContent,
      createContentHash(mergedContent),
      JSON.stringify(mergedTags),
      mergedSalience,
      mergedProject,
      JSON.stringify(mergedMetadata),
      mergedScope,
      mergedTransferable ? 1 : 0,
      mergedStatus,
      mergedPinned ? 1 : 0,
      mergedReviewedBy,
      new Date().toISOString(),
      mergedTrustScore,
      mergedSensitivity,
      mergedCloudExcluded ? 1 : 0,
      mergedAccessCount,
      mergedLastAccessed,
      kept.id,
    );

    const updatedMemory = getMemoryById(kept.id)!;

    try {
      const extraction = extractFromMemory(
        updatedMemory.title,
        updatedMemory.content,
        updatedMemory.category,
      );
      replaceMemoryGraph(updatedMemory.id, extraction, updateProvenance(updatedMemory));
    } catch (e) {
      console.error('[shieldcortex] Entity extraction refresh failed after merge:', e);
    }

    // The merge UPDATE cleared `embedding` (the merged content differs from the
    // pre-merge vector); recompute it for the new canonical content so the recall
    // reuse path never scores against a stale pre-merge vector.
    refreshEmbeddingAsync(updatedMemory.id, updatedMemory.title, updatedMemory.content);

    emitMemoryUpdated(updatedMemory);
    persistEvent('memory_updated', { memory: updatedMemory, mergedFromId: removed.id });

    if (isFeatureEnabled('cloud_sync')) {
      syncMemoryUpsertToCloud(updatedMemory);
      syncGraphForMemoryToCloud(updatedMemory.id);
    }

    deleteMemory(removed.id);
    return updatedMemory;
  });
}

/**
 * Delete a memory
 */
export function deleteMemory(
  id: number,
  source?: DefenceSource,
  opts?: { mode?: 'delete' | 'revoke' },
  attested?: boolean,
): boolean {
  const db = getDatabase();
  const aclOp = opts?.mode ?? 'delete';

  // ACCESS CONTROL: Check delete permission. mode 'revoke' uses the
  // trust-hierarchy rule (own OR outrank); 'delete' (default) stays own-only.
  if (source) {
    const row = db.prepare('SELECT id, source, sensitivity_level FROM memories WHERE id = ?').get(id) as Record<string, unknown> | undefined;
    if (row) {
      const policy = checkAccess(
        { id: row.id as number, source: row.source as string | null, sensitivity_level: row.sensitivity_level as string | null },
        source,
        aclOp,
      );
      if (!policy.canDelete) {
        logAccessDenial(id, source, policy.reason, aclOp, attested);
        return false;
      }
    }
  }

  // Get memory before deletion for event
  const memory = getMemoryById(id);

  if (memory) {
    try {
      removeMemoryGraph(id);
    } catch (e) {
      console.error('[shieldcortex] Graph cleanup before delete failed:', e);
    }
  }

  const result = db.prepare('DELETE FROM memories WHERE id = ?').run(id);

  // Emit event for real-time dashboard (in-process)
  if (result.changes > 0 && memory) {
    // Provenance ledger: record the allowed delete (one row per memory) when the
    // caller is attributed. Internal source-less deletes (merge/consolidation)
    // are machinery, not user actions, so they're not audited here.
    if (source) {
      logAllowedDelete(id, source, (memory.project as string | undefined) ?? null, aclOp, attested);
    }
    if (isFeatureEnabled('cloud_sync')) {
      syncMemoryDeleteToCloud(memory);
      syncGraphDeleteForMemoryToCloud(memory);
    }
    emitMemoryDeleted(id, memory.title);
    // Persist event for cross-process IPC (MCP → Dashboard)
    persistEvent('memory_deleted', { memoryId: id, title: memory.title });
  }

  return result.changes > 0;
}


/**
 * Get all memories for a project
 */
export function getProjectMemories(
  project: string,
  config: MemoryConfig = resolveMemoryConfig()
): Memory[] {
  const db = getDatabase();
  const rows = db.prepare(`
    SELECT * FROM memories
    WHERE project = ?
    ORDER BY salience DESC, last_accessed DESC
  `).all(project) as Record<string, unknown>[];

  return rows.map(row => {
    const memory = rowToMemory(row);
    memory.decayedScore = calculateDecayedScore(memory, config);
    return memory;
  });
}

/**
 * Get recent memories
 */
export interface MemoryListFilters {
  type?: string;
  category?: string;
}

/**
 * Build the shared `WHERE` fragment for project + type + category filters.
 * Returned `clause` is the full `WHERE ...` string (empty when no filters),
 * so the SAME predicate drives both the page query and its COUNT(*) — keeping
 * pagination `total`/`hasMore` honest under filters (Phase 17 A3).
 */
function buildMemoryFilterClause(
  project?: string,
  filters?: MemoryListFilters,
): { clause: string; params: unknown[] } {
  const conds: string[] = [];
  const params: unknown[] = [];
  if (project) {
    conds.push('project = ?');
    params.push(project);
  }
  if (filters?.type) {
    conds.push('type = ?');
    params.push(filters.type);
  }
  if (filters?.category) {
    conds.push('category = ?');
    params.push(filters.category);
  }
  return { clause: conds.length ? `WHERE ${conds.join(' AND ')}` : '', params };
}

/**
 * Count memories matching the project + type/category filters. Used by the
 * dashboard memories route so `total`/`hasMore` reflect the filtered set.
 */
export function countMemories(project?: string, filters?: MemoryListFilters): number {
  const db = getDatabase();
  const { clause, params } = buildMemoryFilterClause(project, filters);
  return (db.prepare(`SELECT COUNT(*) as count FROM memories ${clause}`).get(...params) as { count: number }).count;
}

export function getRecentMemories(
  limit: number = 10,
  project?: string,
  source?: DefenceSource,
  filters?: MemoryListFilters,
  attested?: boolean,
): Memory[] {
  const db = getDatabase();
  const { clause, params } = buildMemoryFilterClause(project, filters);
  let sql = `SELECT * FROM memories ${clause}`;

  sql += ' ORDER BY last_accessed DESC LIMIT ?';
  params.push(source ? limit * 2 : limit); // over-fetch when access-filtering

  let rows = db.prepare(sql).all(...params) as Record<string, unknown>[];
  if (source) rows = filterRowsByAccess(rows, source, attested);
  return rows.slice(0, limit).map(rowToMemory);
}

/**
 * Get memories by type
 */
export function getMemoriesByType(
  type: MemoryType,
  limit: number = 50
): Memory[] {
  const db = getDatabase();
  const rows = db.prepare(`
    SELECT * FROM memories
    WHERE type = ?
    ORDER BY salience DESC, last_accessed DESC
    LIMIT ?
  `).all(type, limit) as Record<string, unknown>[];

  return rows.map(rowToMemory);
}

/**
 * Get high-priority memories (for context injection)
 */
export function getHighPriorityMemories(
  limit: number = 10,
  project?: string,
  source?: DefenceSource,
  filters?: MemoryListFilters,
  attested?: boolean,
): Memory[] {
  const db = getDatabase();
  // Phase 1b: gate + order on EFFECTIVE salience (the decaying score), not raw
  // salience. Raw salience is a one-way ratchet, so a stale long-lived row sits
  // at 1.0 forever and used to top this no-re-rank path. COALESCE falls back to
  // raw salience when decayed_score is unset (never-scored rows unaffected).
  let sql = `SELECT * FROM memories WHERE COALESCE(decayed_score, salience) >= 0.6`;
  const params: unknown[] = [];

  if (project) {
    sql += ' AND project = ?';
    params.push(project);
  }
  if (filters?.type) {
    sql += ' AND type = ?';
    params.push(filters.type);
  }
  if (filters?.category) {
    sql += ' AND category = ?';
    params.push(filters.category);
  }

  sql += ' ORDER BY COALESCE(decayed_score, salience) DESC, last_accessed DESC LIMIT ?';
  params.push(source ? limit * 2 : limit);

  let rows = db.prepare(sql).all(...params) as Record<string, unknown>[];
  if (source) rows = filterRowsByAccess(rows, source, attested);
  return rows.slice(0, limit).map(rowToMemory);
}

/** Count high-priority memories (effective salience >= 0.6) matching the filters. */
export function countHighPriorityMemories(project?: string, filters?: MemoryListFilters): number {
  const db = getDatabase();
  let sql = `SELECT COUNT(*) as count FROM memories WHERE COALESCE(decayed_score, salience) >= 0.6`;
  const params: unknown[] = [];
  if (project) {
    sql += ' AND project = ?';
    params.push(project);
  }
  if (filters?.type) {
    sql += ' AND type = ?';
    params.push(filters.type);
  }
  if (filters?.category) {
    sql += ' AND category = ?';
    params.push(filters.category);
  }
  return (db.prepare(sql).get(...params) as { count: number }).count;
}

/**
 * Get memory statistics
 */
export function getMemoryStats(project?: string): {
  total: number;
  shortTerm: number;
  longTerm: number;
  episodic: number;
  byCategory: Record<string, number>;
  averageSalience: number;
} {
  const db = getDatabase();

  let whereClause = '';
  const params: unknown[] = [];
  if (project) {
    whereClause = 'WHERE project = ?';
    params.push(project);
  }

  const total = (db.prepare(`SELECT COUNT(*) as count FROM memories ${whereClause}`).get(...params) as { count: number }).count;

  const shortTerm = (db.prepare(`SELECT COUNT(*) as count FROM memories ${whereClause} ${whereClause ? 'AND' : 'WHERE'} type = 'short_term'`).get(...params) as { count: number }).count;

  const longTerm = (db.prepare(`SELECT COUNT(*) as count FROM memories ${whereClause} ${whereClause ? 'AND' : 'WHERE'} type = 'long_term'`).get(...params) as { count: number }).count;

  const episodic = (db.prepare(`SELECT COUNT(*) as count FROM memories ${whereClause} ${whereClause ? 'AND' : 'WHERE'} type = 'episodic'`).get(...params) as { count: number }).count;

  const avgResult = db.prepare(`SELECT AVG(salience) as avg FROM memories ${whereClause}`).get(...params) as { avg: number | null };
  const averageSalience = avgResult.avg || 0;

  // Get counts by category
  const categoryRows = db.prepare(`
    SELECT category, COUNT(*) as count
    FROM memories ${whereClause}
    GROUP BY category
  `).all(...params) as { category: string; count: number }[];

  const byCategory: Record<string, number> = {};
  for (const row of categoryRows) {
    byCategory[row.category] = row.count;
  }

  return {
    total,
    shortTerm,
    longTerm,
    episodic,
    byCategory,
    averageSalience,
  };
}


// ============================================================================
// MEMORY RELATIONSHIPS (LINKS) — moved to ./links.ts
// ============================================================================
// The link API was extracted into src/memory/links.ts so the store module can
// be read concern-by-concern instead of as one 2,100-line file. Re-exported
// here so every existing `import { ... } from '.../store.js'` path keeps
// working with zero behaviour change.
export {
  createMemoryLink,
  getRelatedMemories,
  deleteMemoryLink,
  getAllMemoryLinks,
  detectRelationships,
  type RelationshipType,
  type MemoryLink,
} from './links.js';

// ============================================================================
// MEMORY LIFECYCLE — moved to ./lifecycle.ts
// ============================================================================
// Phase 2 of the store.ts split. The lifecycle group (access reinforcement,
// search reinforcement, enrichment, decay-score persistence, STM→LTM
// promotion, decayed-memory cleanup) lives in src/memory/lifecycle.ts.
// Re-exported here so every existing `import { ... } from '.../store.js'`
// path keeps working with zero behaviour change.
export {
  accessMemory,
  reinforceFromSearch,
  enrichMemory,
  clearEnrichmentCooldown,
  getEnrichmentCooldownStatus,
  updateDecayScores,
  promoteMemory,
  cleanupDecayedMemories,
  type EnrichmentResult,
} from './lifecycle.js';

// ============================================================================
// MEMORY SEARCH / RECALL — moved to ./search-recall.ts
// ============================================================================
// Phase 3 of the store.ts split. The search/recall group (the public
// `searchMemories`, `searchMemoriesExplained`, `recallWithEmbeddings`
// entry points plus the internal `searchMemoriesInternal` pipeline and
// the module-level `searchCount` activation-cache pruner) lives in
// src/memory/search-recall.ts. Re-exported here so every existing
// `import { ... } from '.../store.js'` path keeps working with zero
// behaviour change. search-recall.ts imports `rowToMemory` and
// `logAccessDenial` back from store.ts via the same function-body-only
// cycle pattern used by links.ts and lifecycle.ts.
export {
  searchMemories,
  searchMemoriesExplained,
  recallWithEmbeddings,
} from './search-recall.js';
