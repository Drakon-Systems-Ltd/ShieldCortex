import type { Express, Request, Response } from 'express';
import { homedir } from 'os';
import { join } from 'path';
import { existsSync, readdirSync, readFileSync } from 'fs';
import { getDatabase, withTransaction } from '../../database/init.js';
import { Memory } from '../../memory/types.js';
import {
  searchMemories,
  getRecentMemories,
  getHighPriorityMemories,
  countMemories,
  countHighPriorityMemories,
  getMemoryStats,
  getMemoryById,
  addMemory,
  deleteMemory,
  accessMemory,
  updateMemory,
  mergeMemories,
  promoteMemory,
  createMemoryLink,
  rowToMemory,
  enrichMemory,
} from '../../memory/store.js';
import { calculateDecayedScore } from '../../memory/decay.js';
import {
  consolidate,
  findDuplicateMemoryPairs,
  formatContextSummary,
  generateContextSummary,
} from '../../memory/consolidate.js';
import { getActivationStats, getActiveMemories } from '../../memory/activation.js';
import { detectContradictions, getContradictionsFor } from '../../memory/contradiction.js';
import { emitConsolidation } from '../events.js';
import type { IronDomeRouteGuardOptions, Middleware as IronDomeMiddleware } from '../iron-dome-route-guard.js';

type Middleware = (_req: Request, res: Response, next: (err?: unknown) => void) => void;

interface MemoryRouteDeps {
  requireNotLocked: Middleware;
  requireIronDomeAction: (options: IronDomeRouteGuardOptions) => IronDomeMiddleware;
}

/** Upper bound on memories a single bulk-review call may touch (actions are reversible). */
const MAX_BULK_REVIEW = 1000;

type ReviewActionOptions = { reviewedBy?: string; project?: string | null; scope?: 'project' | 'global' };

/**
 * Resolve a review action keyword into the `updateMemory` field updates. Shared
 * by the single PATCH /api/memories/:id/review route and the bulk endpoint so the
 * action vocabulary lives in one place. Returns null for an unknown action.
 */
function buildReviewUpdates(action: string, opts: ReviewActionOptions): Record<string, unknown> | null {
  const reviewActor = typeof opts.reviewedBy === 'string' && opts.reviewedBy.trim() ? opts.reviewedBy.trim() : 'dashboard';
  const map: Record<string, Record<string, unknown>> = {
    archive: { status: 'archived', reviewedBy: reviewActor },
    suppress: { status: 'suppressed', reviewedBy: reviewActor },
    restore: { status: 'active', reviewedBy: reviewActor },
    pin: { pinned: true, reviewedBy: reviewActor },
    unpin: { pinned: false, reviewedBy: reviewActor },
    canonicalize: { status: 'canonical', pinned: true, reviewedBy: reviewActor },
    excludeCloud: { cloudExcluded: true, reviewedBy: reviewActor },
    includeCloud: { cloudExcluded: false, reviewedBy: reviewActor },
    rescopeProject: { scope: 'project', project: opts.project ?? null, reviewedBy: reviewActor },
    rescopeGlobal: { scope: 'global', project: null, reviewedBy: reviewActor },
  };
  const updates = map[action];
  if (!updates) return null;
  return { ...updates, ...(opts.scope ? { scope: opts.scope } : {}) };
}

export function registerMemoryRoutes(app: Express, deps: MemoryRouteDeps): void {
  const { requireNotLocked, requireIronDomeAction } = deps;

  function deriveLocalOpenClawSessionId(memory: Memory): string | null {
    if (typeof memory.metadata?.sessionId === 'string' && memory.metadata.sessionId.length > 0) {
      return memory.metadata.sessionId;
    }

    if (memory.source?.startsWith('agent:openclaw-plugin:')) {
      return memory.source.slice('agent:openclaw-plugin:'.length);
    }

    const tagSet = new Set(memory.tags.map((tag) => tag.toLowerCase()));
    const looksOpenClaw =
      memory.sourceKind === 'hook'
      || memory.sourceKind === 'plugin'
      || memory.source?.includes('openclaw') === true
      || tagSet.has('session-end')
      || tagSet.has('session-stop')
      || tagSet.has('keyword-trigger')
      || tagSet.has('openclaw-hook')
      || tagSet.has('llm-output')
      || tagSet.has('realtime-plugin')
      || memory.project === 'openclaw';

    if (!looksOpenClaw) return null;

    const createdAt = memory.createdAt.toISOString().slice(0, 10);
    const projectBucket = memory.project?.trim() ? memory.project.trim() : 'unscoped';
    return `legacy-openclaw:${projectBucket}:${createdAt}`;
  }

  app.get('/api/capture/openclaw/sessions', requireNotLocked, (req: Request, res: Response) => {
    try {
      const limit = Math.min(parseInt(req.query.limit as string, 10) || 20, 100);
      const auditDir = join(homedir(), '.shieldcortex', 'audit');
      const db = getDatabase();

      const rows = db.prepare(`
        SELECT * FROM memories
        WHERE source_kind IN ('hook', 'plugin') OR source LIKE 'hook:openclaw%' OR source LIKE 'agent:openclaw-plugin%'
        ORDER BY updated_at DESC
        LIMIT 500
      `).all() as Record<string, unknown>[];
      const openClawMemories = rows.map(rowToMemory);

      const sessionMap = new Map<string, {
        sessionId: string;
        firstSeenAt: string;
        lastSeenAt: string;
        storedMemoryCount: number;
        loggedSaved: number;
        skipped: number;
        threats: number;
        blocked: number;
        quarantined: number;
        autoExtracted: number;
        keywordTriggered: number;
        pinned: number;
        suppressed: number;
        hooks: Set<string>;
        models: Set<string>;
        agentIds: Set<string>;
        memoryIds: Set<number>;
        previews: string[];
        events: Array<{
          ts: string;
          type: 'memory' | 'threat' | 'blocked' | 'quarantine';
          hook?: string;
          model?: string;
          preview?: string;
          count?: number;
          skipped?: number;
        }>;
      }>();

      const getSession = (sessionId: string) => {
        let session = sessionMap.get(sessionId);
        if (!session) {
          session = {
            sessionId,
            firstSeenAt: new Date().toISOString(),
            lastSeenAt: new Date(0).toISOString(),
            storedMemoryCount: 0,
            loggedSaved: 0,
            skipped: 0,
            threats: 0,
            blocked: 0,
            quarantined: 0,
            autoExtracted: 0,
            keywordTriggered: 0,
            pinned: 0,
            suppressed: 0,
            hooks: new Set<string>(),
            models: new Set<string>(),
            agentIds: new Set<string>(),
            memoryIds: new Set<number>(),
            previews: [],
            events: [],
          };
          sessionMap.set(sessionId, session);
        }
        return session;
      };

      for (const memory of openClawMemories) {
        const sessionId = deriveLocalOpenClawSessionId(memory);
        if (!sessionId) continue;
        const session = getSession(sessionId);
        const createdAt = memory.createdAt.toISOString();
        if (createdAt < session.firstSeenAt) session.firstSeenAt = createdAt;
        if (createdAt > session.lastSeenAt) session.lastSeenAt = createdAt;
        session.storedMemoryCount += 1;
        session.memoryIds.add(memory.id);
        if (typeof memory.metadata?.agentId === 'string') session.agentIds.add(memory.metadata.agentId);
        if (memory.captureMethod === 'auto' || memory.captureMethod === 'plugin' || memory.captureMethod === 'hook') {
          session.autoExtracted += 1;
        }
        if (typeof memory.metadata?.trigger === 'string' || memory.tags.includes('keyword_trigger')) {
          session.keywordTriggered += 1;
        }
        if (memory.pinned) session.pinned += 1;
        if (memory.status === 'suppressed') session.suppressed += 1;
      }

      if (existsSync(auditDir)) {
        const files = readdirSync(auditDir)
          .filter((file) => /^realtime-\d{4}-\d{2}-\d{2}\.jsonl$/.test(file))
          .sort()
          .slice(-14);

        for (const file of files) {
          const raw = readFileSync(join(auditDir, file), 'utf-8');
          for (const line of raw.split('\n')) {
            if (!line.trim()) continue;
            try {
              const entry = JSON.parse(line) as Record<string, unknown>;
              const sessionId = typeof entry.sessionId === 'string' ? entry.sessionId : null;
              if (!sessionId) continue;
              const session = getSession(sessionId);
              const ts = typeof entry.ts === 'string' ? entry.ts : new Date().toISOString();
              if (ts < session.firstSeenAt) session.firstSeenAt = ts;
              if (ts > session.lastSeenAt) session.lastSeenAt = ts;
              if (typeof entry.hook === 'string') session.hooks.add(entry.hook);
              if (typeof entry.model === 'string') session.models.add(entry.model);
              if (entry.type === 'memory') {
                const count = Number(entry.count ?? 0);
                const skipped = Number(entry.skipped ?? 0);
                session.loggedSaved += count;
                session.skipped += skipped;
                session.events.push({
                  ts,
                  type: 'memory',
                  hook: typeof entry.hook === 'string' ? entry.hook : undefined,
                  model: typeof entry.model === 'string' ? entry.model : undefined,
                  preview: typeof entry.preview === 'string' ? entry.preview : undefined,
                  count,
                  skipped,
                });
                if (typeof entry.preview === 'string' && session.previews.length < 6) {
                  session.previews.push(entry.preview);
                }
              }
              if (entry.type === 'threat') {
                session.threats += 1;
                const preview = typeof entry.preview === 'string' ? entry.preview : undefined;
                const lower = preview?.toLowerCase() ?? '';
                if (lower.includes('quarantine')) session.quarantined += 1;
                if (lower.includes('block')) session.blocked += 1;
                session.events.push({
                  ts,
                  type: lower.includes('quarantine') ? 'quarantine' : lower.includes('block') ? 'blocked' : 'threat',
                  hook: typeof entry.hook === 'string' ? entry.hook : undefined,
                  model: typeof entry.model === 'string' ? entry.model : undefined,
                  preview,
                });
                if (preview && session.previews.length < 6) {
                  session.previews.push(preview);
                }
              }
            } catch {
              // ignore malformed lines
            }
          }
        }
      }

      const sessions = Array.from(sessionMap.values())
        .map((session) => ({
          sessionId: session.sessionId,
          firstSeenAt: session.firstSeenAt,
          lastSeenAt: session.lastSeenAt,
          saved: Math.max(session.storedMemoryCount, session.loggedSaved),
          skipped: session.skipped,
          threats: session.threats,
          blocked: session.blocked,
          quarantined: session.quarantined,
          autoExtracted: session.autoExtracted,
          keywordTriggered: session.keywordTriggered,
          pinned: session.pinned,
          suppressed: session.suppressed,
          hooks: Array.from(session.hooks),
          models: Array.from(session.models),
          agentIds: Array.from(session.agentIds),
          previews: session.previews,
          events: session.events
            .sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime())
            .slice(0, 24),
          memories: openClawMemories
            .filter((memory) => session.memoryIds.has(memory.id))
            .sort((a, b) => new Date(b.updatedAt ?? b.createdAt).getTime() - new Date(a.updatedAt ?? a.createdAt).getTime())
            .slice(0, 12),
        }))
        .sort((a, b) => new Date(b.lastSeenAt).getTime() - new Date(a.lastSeenAt).getTime())
        .slice(0, limit);

      const summary = {
        sessions: sessions.length,
        saved: sessions.reduce((sum, session) => sum + session.saved, 0),
        skipped: sessions.reduce((sum, session) => sum + session.skipped, 0),
        threats: sessions.reduce((sum, session) => sum + session.threats, 0),
      };

      res.json({ summary, sessions });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/memories', requireNotLocked, async (req: Request, res: Response) => {
    try {
      const project = typeof req.query.project === 'string' ? req.query.project : undefined;
      const type = typeof req.query.type === 'string' ? req.query.type : undefined;
      const category = typeof req.query.category === 'string' ? req.query.category : undefined;
      const limitStr = typeof req.query.limit === 'string' ? req.query.limit : '50';
      const offsetStr = typeof req.query.offset === 'string' ? req.query.offset : '0';
      const mode = typeof req.query.mode === 'string' ? req.query.mode : 'recent';
      const query = typeof req.query.query === 'string' ? req.query.query : undefined;

      const limit = Math.min(parseInt(limitStr, 10) || 50, 1000);
      const offset = parseInt(offsetStr, 10) || 0;

      // Push the type/category filters into the query so the page rows AND the
      // `total` count share one predicate — otherwise `total`/`hasMore` reflect
      // the unfiltered grand count (Phase 17 A3).
      const filters = { type, category };

      let memories: Memory[];
      let total: number;
      if (mode === 'search' && query) {
        // searchMemories already applies type/category filters internally, so
        // the filtered total is the size of the full result set. Fetch a
        // generous window (capped) and count what comes back.
        const SEARCH_TOTAL_CAP = 1000;
        const results = await searchMemories({
          query,
          project,
          type: type as Memory['type'] | undefined,
          category: category as Memory['category'] | undefined,
          limit: SEARCH_TOTAL_CAP,
        });
        const allMatches = results.map((result) => result.memory);
        total = allMatches.length;
        memories = allMatches;
      } else if (mode === 'important') {
        memories = getHighPriorityMemories(limit + offset + 1, project, undefined, filters);
        total = countHighPriorityMemories(project, filters);
      } else {
        memories = getRecentMemories(limit + offset + 1, project, undefined, filters);
        total = countMemories(project, filters);
      }

      const hasMore = offset + limit < total;
      const paginatedMemories = memories.slice(offset, offset + limit);

      // Batch-load entity_ids per memory so the constellation graph client
      // can map list rows to graph nodes without an N+1 fetch.
      const ids = paginatedMemories.map((m) => m.id);
      const linkRows =
        ids.length === 0
          ? []
          : (getDatabase()
              .prepare(
                `SELECT memory_id, entity_id FROM memory_entities WHERE memory_id IN (${ids
                  .map(() => '?')
                  .join(',')})`,
              )
              .all(...ids) as { memory_id: number; entity_id: number }[]);
      const byMemoryId = new Map<number, number[]>();
      for (const row of linkRows) {
        const arr = byMemoryId.get(row.memory_id) ?? [];
        arr.push(row.entity_id);
        byMemoryId.set(row.memory_id, arr);
      }
      const memoriesWithDecay = paginatedMemories.map((memory) => ({
        ...memory,
        decayedScore: calculateDecayedScore(memory),
        entity_ids: byMemoryId.get(memory.id) ?? [],
      }));

      res.json({
        memories: memoriesWithDecay,
        pagination: {
          offset,
          limit,
          total,
          hasMore,
        },
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/memories/activity', requireNotLocked, (req: Request, res: Response) => {
    try {
      const project = typeof req.query.project === 'string' ? req.query.project : undefined;
      const db = getDatabase();

      const query = project
        ? `SELECT date(created_at) as date, COUNT(*) as count
           FROM memories WHERE project = ?
           GROUP BY date(created_at)
           ORDER BY date DESC
           LIMIT 365`
        : `SELECT date(created_at) as date, COUNT(*) as count
           FROM memories
           GROUP BY date(created_at)
           ORDER BY date DESC
           LIMIT 365`;

      const rows = project
        ? db.prepare(query).all(project) as { date: string; count: number }[]
        : db.prepare(query).all() as { date: string; count: number }[];

      res.json({ activity: rows });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/memories/quality', requireNotLocked, (req: Request, res: Response) => {
    try {
      const project = typeof req.query.project === 'string' ? req.query.project : undefined;
      const db = getDatabase();

      const projectFilter = project ? 'AND project = ?' : '';
      const params = project ? [project] : [];

      const neverAccessed = db.prepare(`
        SELECT id, title, category, type, created_at, salience
        FROM memories WHERE access_count = 0 ${projectFilter}
        AND created_at < datetime('now', '-1 day')
        ORDER BY created_at DESC LIMIT 50
      `).all(...params) as Array<Record<string, unknown>>;

      const stale = db.prepare(`
        SELECT id, title, category, type, last_accessed, decayed_score, salience
        FROM memories WHERE decayed_score < 0.3 ${projectFilter}
        AND last_accessed < datetime('now', '-30 days')
        ORDER BY decayed_score ASC LIMIT 50
      `).all(...params) as Array<Record<string, unknown>>;

      const duplicates = db.prepare(`
        SELECT m1.id as id1, m1.title as title_a, m2.id as id2, m2.title as title_b
        FROM memories m1
        JOIN memories m2 ON m1.title = m2.title AND m1.id < m2.id
        WHERE COALESCE(m1.status, 'active') NOT IN ('archived', 'suppressed')
          AND COALESCE(m2.status, 'active') NOT IN ('archived', 'suppressed')
          AND m1.reviewed_at IS NULL AND m2.reviewed_at IS NULL
          ${project ? 'AND m1.project = ?' : ''}
        LIMIT 50
      `).all(...params) as Array<Record<string, unknown>>;

      const lowTrust = db.prepare(`
        SELECT id, title, category, project, trust_score, source_kind, capture_method
        FROM memories WHERE trust_score < 0.7 ${projectFilter}
        ORDER BY trust_score ASC, updated_at DESC LIMIT 50
      `).all(...params) as Array<Record<string, unknown>>;

      const noisyAutoExtracted = db.prepare(`
        SELECT id, title, category, project, source_kind, capture_method, tags, trust_score
        FROM memories
        WHERE (capture_method = 'auto' OR tags LIKE '%auto-extracted%') ${projectFilter}
        ORDER BY updated_at DESC LIMIT 50
      `).all(...params) as Array<Record<string, unknown>>;

      const projectless = db.prepare(`
        SELECT id, title, category, scope, source_kind, capture_method
        FROM memories
        WHERE (project IS NULL OR project = '') AND scope != 'global'
        ORDER BY updated_at DESC LIMIT 50
      `).all() as Array<Record<string, unknown>>;

      const statusCounts = db.prepare(`
        SELECT status, COUNT(*) as count
        FROM memories
        ${project ? 'WHERE project = ?' : ''}
        GROUP BY status
      `).all(...params) as Array<{ status: string; count: number }>;

      res.json({
        neverAccessed: { count: neverAccessed.length, items: neverAccessed },
        stale: { count: stale.length, items: stale },
        duplicates: { count: duplicates.length, items: duplicates },
        lowTrust: { count: lowTrust.length, items: lowTrust },
        noisyAutoExtracted: { count: noisyAutoExtracted.length, items: noisyAutoExtracted },
        projectless: { count: projectless.length, items: projectless },
        status: statusCounts.reduce<Record<string, number>>((acc, row) => {
          acc[row.status] = row.count;
          return acc;
        }, {}),
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/review/queue', requireNotLocked, (req: Request, res: Response) => {
    try {
      const project = typeof req.query.project === 'string' ? req.query.project : undefined;
      const limit = Math.min(parseInt(req.query.limit as string, 10) || 20, 100);
      const db = getDatabase();
      const projectFilter = project ? 'AND project = ?' : '';
      const params = project ? [project] : [];

      const stale = db.prepare(`
        SELECT * FROM memories
        WHERE COALESCE(status, 'active') NOT IN ('archived', 'suppressed')
        AND reviewed_at IS NULL
        AND decayed_score < 0.3 ${projectFilter}
        AND last_accessed < datetime('now', '-30 days')
        ORDER BY decayed_score ASC LIMIT ?
      `).all(...params, limit) as Record<string, unknown>[];

      const neverUsed = db.prepare(`
        SELECT * FROM memories
        WHERE COALESCE(status, 'active') NOT IN ('archived', 'suppressed')
        AND reviewed_at IS NULL
        AND access_count = 0 ${projectFilter}
        AND created_at < datetime('now', '-1 day')
        ORDER BY created_at DESC LIMIT ?
      `).all(...params, limit) as Record<string, unknown>[];

      const lowTrust = db.prepare(`
        SELECT * FROM memories
        WHERE COALESCE(status, 'active') NOT IN ('archived', 'suppressed')
        AND reviewed_at IS NULL
        AND trust_score < 0.7 ${projectFilter}
        ORDER BY trust_score ASC, updated_at DESC LIMIT ?
      `).all(...params, limit) as Record<string, unknown>[];

      const noisyAutoExtracted = db.prepare(`
        SELECT * FROM memories
        WHERE COALESCE(status, 'active') NOT IN ('archived', 'suppressed')
        AND reviewed_at IS NULL
        AND (capture_method = 'auto' OR tags LIKE '%auto-extracted%') ${projectFilter}
        ORDER BY updated_at DESC LIMIT ?
      `).all(...params, limit) as Record<string, unknown>[];

      const projectless = db.prepare(`
        SELECT * FROM memories
        WHERE COALESCE(status, 'active') NOT IN ('archived', 'suppressed')
        AND reviewed_at IS NULL
        AND (project IS NULL OR project = '') AND scope != 'global'
        ORDER BY updated_at DESC LIMIT ?
      `).all(limit) as Record<string, unknown>[];

      const openClawSummary = db.prepare(`
        SELECT
          COUNT(*) as total,
          SUM(CASE WHEN capture_method = 'auto' THEN 1 ELSE 0 END) as auto_count,
          SUM(CASE WHEN tags LIKE '%keyword-trigger%' THEN 1 ELSE 0 END) as keyword_count,
          SUM(CASE WHEN status = 'suppressed' THEN 1 ELSE 0 END) as suppressed_count,
          SUM(CASE WHEN pinned = 1 THEN 1 ELSE 0 END) as pinned_count
        FROM memories
        WHERE (source_kind IN ('hook', 'plugin') OR tags LIKE '%openclaw%')
        ${project ? 'AND project = ?' : ''}
      `).get(...params) as {
        total: number;
        auto_count: number;
        keyword_count: number;
        suppressed_count: number;
        pinned_count: number;
      };

      // True totals (not limited) for summary counts
      const bf = `COALESCE(status, 'active') NOT IN ('archived', 'suppressed') AND reviewed_at IS NULL`;
      const pf = projectFilter;
      const countSql = `
        SELECT
          (SELECT COUNT(*) FROM memories WHERE ${bf} AND decayed_score < 0.3 ${pf} AND last_accessed < datetime('now', '-30 days')) as stale,
          (SELECT COUNT(*) FROM memories WHERE ${bf} AND access_count = 0 ${pf} AND created_at < datetime('now', '-1 day')) as never_used,
          (SELECT COUNT(*) FROM memories WHERE ${bf} AND trust_score < 0.7 ${pf}) as low_trust,
          (SELECT COUNT(*) FROM memories WHERE ${bf} AND (capture_method = 'auto' OR tags LIKE '%auto-extracted%') ${pf}) as noisy_auto,
          (SELECT COUNT(*) FROM memories WHERE ${bf} AND (project IS NULL OR project = '') AND scope != 'global') as projectless
      `;
      // Each subquery with projectFilter needs one param; projectless doesn't use it
      const countParams = project ? [project, project, project, project] : [];
      const counts = db.prepare(countSql).get(...countParams) as {
        stale: number;
        never_used: number;
        low_trust: number;
        noisy_auto: number;
        projectless: number;
      };

      const contradictions = detectContradictions({
        project,
        minScore: 0.4,
        limit,
      });
      const duplicates = findDuplicateMemoryPairs({ project, limit });

      res.json({
        summary: {
          stale: counts.stale,
          neverUsed: counts.never_used,
          lowTrust: counts.low_trust,
          noisyAutoExtracted: counts.noisy_auto,
          projectless: counts.projectless,
          contradictions: contradictions.length,
          duplicates: duplicates.length,
        },
        openClaw: {
          total: openClawSummary.total ?? 0,
          autoExtracted: openClawSummary.auto_count ?? 0,
          keywordTriggered: openClawSummary.keyword_count ?? 0,
          suppressed: openClawSummary.suppressed_count ?? 0,
          pinned: openClawSummary.pinned_count ?? 0,
        },
        sections: {
          stale: stale.map(rowToMemory),
          neverUsed: neverUsed.map(rowToMemory),
          lowTrust: lowTrust.map(rowToMemory),
          noisyAutoExtracted: noisyAutoExtracted.map(rowToMemory),
          projectless: projectless.map(rowToMemory),
          duplicates,
          contradictions: contradictions.map((item) => ({
            memoryA: item.memoryA,
            memoryB: item.memoryB,
            score: item.score,
            reason: item.reason,
            sharedTopics: item.sharedTopics,
          })),
        },
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/memories/merge', requireNotLocked, requireIronDomeAction({
    action: 'modify_records',
    channel: 'dashboard',
    sourceIdentifier: 'dashboard:memory-merge',
    enforceAmber: true,
  }), (req: Request, res: Response) => {
    try {
      const { keptId, removedId, reviewedBy } = req.body as {
        keptId?: number;
        removedId?: number;
        reviewedBy?: string;
      };

      if (!Number.isInteger(keptId) || !Number.isInteger(removedId)) {
        return res.status(400).json({ error: 'keptId and removedId are required integers' });
      }

      if (keptId === removedId) {
        return res.status(400).json({ error: 'keptId and removedId must be different' });
      }

      const merged = mergeMemories(
        keptId as number,
        removedId as number,
        { reviewedBy },
        { type: 'api', identifier: 'dashboard:memory-merge' },
      );
      if (!merged) {
        return res.status(404).json({ error: 'Unable to merge memories' });
      }

      res.json(merged);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/memories/:id', requireNotLocked, (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id as string, 10);
      const memory = getMemoryById(id);
      if (!memory) {
        return res.status(404).json({ error: 'Memory not found' });
      }
      res.json({
        ...memory,
        decayedScore: calculateDecayedScore(memory),
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/memories', requireNotLocked, requireIronDomeAction({
    action: 'modify_records',
    channel: 'dashboard',
    sourceIdentifier: 'dashboard:memory-create',
    enforceAmber: true,
  }), (req: Request, res: Response) => {
    try {
      const { title, content, type, category, project, tags, salience, memoryPurpose, memoryScope } = req.body;

      if (!title || !content) {
        return res.status(400).json({ error: 'Title and content required' });
      }

      const memory = addMemory(
        {
          title,
          content,
          type: type || 'short_term',
          category: category || 'note',
          project,
          tags: tags || [],
          salience,
          memoryPurpose: memoryPurpose || undefined,
          memoryScope: memoryScope || undefined,
        },
        undefined,
        // Operator-attributable dashboard write → api:dashboard (trust 0.7):
        // scanned like every write, but stays broadly recallable (above the
        // sub-agent band) rather than the generic unattributed 0.3.
        { type: 'api', identifier: 'dashboard' },
      );

      res.status(201).json(memory);
    } catch (error) {
      if ((error as Error).name === 'MemoryPausedError') {
        return res.status(503).json({
          error: 'Memory creation is paused',
          paused: true,
          message: 'Use the dashboard control panel to resume memory creation.',
        });
      }
      // The dashboard write is now scanned — surface a defence block as a 422,
      // not a generic 500.
      if ((error as Error).name === 'MemoryBlockedError') {
        return res.status(422).json({
          error: 'Blocked by the defence pipeline',
          blocked: true,
          message: (error as Error).message,
        });
      }
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.delete('/api/memories/:id', requireNotLocked, requireIronDomeAction({
    action: 'delete',
    channel: 'dashboard',
    sourceIdentifier: (req: Request) => `dashboard:memory-delete:${req.params.id ?? 'unknown'}`,
  }), (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id as string, 10);
      // Attribute the dashboard delete so it lands on the provenance ledger
      // (the primary human-initiated delete — the source-less exemption is only
      // for internal consolidate/merge machinery).
      const success = deleteMemory(id, { type: 'api', identifier: `dashboard:memory-delete:${id}` });
      if (!success) {
        return res.status(404).json({ error: 'Memory not found' });
      }
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/memories/:id/access', requireNotLocked, (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id as string, 10);
      const memory = accessMemory(id);
      if (!memory) {
        return res.status(404).json({ error: 'Memory not found' });
      }
      res.json({
        ...memory,
        decayedScore: calculateDecayedScore(memory),
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/stats', (req: Request, res: Response) => {
    try {
      const project = typeof req.query.project === 'string' ? req.query.project : undefined;
      const stats = getMemoryStats(project);
      const db = getDatabase();
      const rawRows = db.prepare(
        project
          ? 'SELECT * FROM memories WHERE project = ?'
          : 'SELECT * FROM memories',
      ).all(project ? [project] : []) as Record<string, unknown>[];

      const allMemories = rawRows.map(rowToMemory);
      const decayDistribution = {
        healthy: 0,
        fading: 0,
        critical: 0,
      };

      for (const memory of allMemories) {
        const score = calculateDecayedScore(memory);
        if (score > 0.35) decayDistribution.healthy++;
        else if (score > 0.2) decayDistribution.fading++;
        else decayDistribution.critical++;
      }

      const activation = getActivationStats();

      res.json({
        ...stats,
        decayDistribution,
        activation,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/health-score', requireNotLocked, (_req: Request, res: Response) => {
    try {
      const db = getDatabase();
      const totalCount = (db.prepare('SELECT COUNT(*) as count FROM memories').get() as { count: number }).count;
      const freshCount = (db.prepare('SELECT COUNT(*) as count FROM memories WHERE decayed_score > 0.3').get() as { count: number }).count;
      const freshnessScore = totalCount > 0 ? Math.round((freshCount / totalCount) * 100) : 100;
      const freshPct = totalCount > 0 ? Math.round((freshCount / totalCount) * 100) : 100;

      const linkedCount = (db.prepare('SELECT COUNT(DISTINCT memory_id) as count FROM memory_entities').get() as { count: number }).count;
      const coverageScore = totalCount > 0 ? Math.round((linkedCount / totalCount) * 100) : 0;

      const contradictionCount = (db.prepare("SELECT COUNT(*) as count FROM memory_links WHERE relationship = 'contradicts'").get() as { count: number }).count;
      const consistencyScore = Math.max(0, 100 - (contradictionCount * 10));

      const lastConsolidated = db.prepare(
        "SELECT created_at FROM memories WHERE type = 'long_term' AND tags LIKE '%auto-consolidated%' ORDER BY created_at DESC LIMIT 1",
      ).get() as { created_at: string } | undefined;

      let consolidationScore = 25;
      if (lastConsolidated) {
        const hoursAgo = (Date.now() - new Date(lastConsolidated.created_at).getTime()) / (1000 * 60 * 60);
        if (hoursAgo <= 4) consolidationScore = 100;
        else if (hoursAgo <= 8) consolidationScore = 75;
        else if (hoursAgo <= 24) consolidationScore = 50;
      }

      const overall = Math.round(
        freshnessScore * 0.3 +
        coverageScore * 0.25 +
        consistencyScore * 0.25 +
        consolidationScore * 0.2,
      );

      let consolidationDetail = 'No consolidated memories found';
      if (lastConsolidated) {
        const hoursAgo = (Date.now() - new Date(lastConsolidated.created_at).getTime()) / (1000 * 60 * 60);
        consolidationDetail = hoursAgo < 1
          ? 'Last consolidated less than 1 hour ago'
          : `Last consolidated ${Math.round(hoursAgo)} hours ago`;
      }

      res.json({
        overall,
        components: {
          freshness: {
            score: freshnessScore,
            label: 'Memory Freshness',
            detail: `${freshPct}% of memories above decay threshold`,
          },
          coverage: {
            score: coverageScore,
            label: 'Graph Coverage',
            detail: `${coverageScore}% of memories have entity links`,
          },
          consistency: {
            score: consistencyScore,
            label: 'Consistency',
            detail: `${contradictionCount} contradictions detected`,
          },
          consolidation: {
            score: consolidationScore,
            label: 'Consolidation',
            detail: consolidationDetail,
          },
        },
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/activation', requireNotLocked, (_req: Request, res: Response) => {
    try {
      res.json({
        activeMemories: getActiveMemories(),
        stats: getActivationStats(),
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/contradictions', requireNotLocked, (req: Request, res: Response) => {
    try {
      const project = typeof req.query.project === 'string' ? req.query.project : undefined;
      const category = typeof req.query.category === 'string' ? req.query.category : undefined;
      const minScoreStr = typeof req.query.minScore === 'string' ? req.query.minScore : '0.4';
      const limitStr = typeof req.query.limit === 'string' ? req.query.limit : '20';

      const contradictions = detectContradictions({
        project,
        category: category as Memory['category'] | undefined,
        minScore: parseFloat(minScoreStr) || 0.4,
        limit: parseInt(limitStr, 10) || 20,
      });

      res.json({
        contradictions: contradictions.map((item) => ({
          memoryAId: item.memoryA.id,
          memoryATitle: item.memoryA.title,
          memoryBId: item.memoryB.id,
          memoryBTitle: item.memoryB.title,
          score: item.score,
          reason: item.reason,
          sharedTopics: item.sharedTopics,
        })),
        count: contradictions.length,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/memories/:id/contradictions', requireNotLocked, (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id as string, 10);
      if (Number.isNaN(id)) {
        return res.status(400).json({ error: 'Invalid memory ID' });
      }

      const contradictions = getContradictionsFor(id);
      res.json({
        memoryId: id,
        contradictions: contradictions.map((item) => ({
          contradictingMemoryId: item.memoryB.id,
          contradictingMemoryTitle: item.memoryB.title,
          score: item.score,
          reason: item.reason,
          sharedTopics: item.sharedTopics,
        })),
        count: contradictions.length,
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/memories/:id/enrich', requireNotLocked, requireIronDomeAction({
    action: 'modify_records',
    channel: 'dashboard',
    sourceIdentifier: (req: Request) => `dashboard:memory-enrich:${req.params.id ?? 'unknown'}`,
    enforceAmber: true,
  }), (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id as string, 10);
      if (Number.isNaN(id)) {
        return res.status(400).json({ error: 'Invalid memory ID' });
      }

      const { context, contextType } = req.body;
      if (!context || typeof context !== 'string') {
        return res.status(400).json({ error: 'Context string required in request body' });
      }

      const validTypes = ['search', 'access', 'related'];
      const type = validTypes.includes(contextType) ? contextType : 'access';

      res.json(enrichMemory(id, context, type));
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/projects', (_req: Request, res: Response) => {
    try {
      const db = getDatabase();
      const projects = db.prepare(`
        SELECT DISTINCT project, COUNT(*) as memory_count
        FROM memories
        WHERE project IS NOT NULL AND project != ''
        GROUP BY project
        ORDER BY memory_count DESC
      `).all() as { project: string; memory_count: number }[];
      const totalCount = db.prepare('SELECT COUNT(*) as count FROM memories').get() as { count: number };

      res.json({
        projects: [
          { project: null, memory_count: totalCount.count, label: 'All Projects' },
          ...projects.map((project) => ({ ...project, label: project.project })),
        ],
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/links', requireNotLocked, (req: Request, res: Response) => {
    try {
      const project = typeof req.query.project === 'string' ? req.query.project : undefined;
      const db = getDatabase();

      const query = project
        ? `
          SELECT
            ml.*,
            m1.title as source_title,
            m1.category as source_category,
            m1.type as source_type,
            m2.title as target_title,
            m2.category as target_category,
            m2.type as target_type
          FROM memory_links ml
          JOIN memories m1 ON ml.source_id = m1.id
          JOIN memories m2 ON ml.target_id = m2.id
          WHERE m1.project = ? OR m2.project = ?
          ORDER BY ml.created_at DESC
          LIMIT 500
        `
        : `
          SELECT
            ml.*,
            m1.title as source_title,
            m1.category as source_category,
            m1.type as source_type,
            m2.title as target_title,
            m2.category as target_category,
            m2.type as target_type
          FROM memory_links ml
          JOIN memories m1 ON ml.source_id = m1.id
          JOIN memories m2 ON ml.target_id = m2.id
          ORDER BY ml.created_at DESC
          LIMIT 500
        `;

      const links = project
        ? db.prepare(query).all(project, project)
        : db.prepare(query).all();

      res.json(links);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Consolidation is a maintenance operation (STM→LTM promotion + low-salience
  // dedupe), not arbitrary delete. Use 'modify_records' (AMBER) so the
  // dashboard can trigger it without the RED 'delete' gate that always blocks.
  // Mirrors the action used by /api/worker/trigger-{light,medium}.
  app.post('/api/consolidate', requireNotLocked, requireIronDomeAction({
    action: 'modify_records',
    channel: 'dashboard',
    sourceIdentifier: 'dashboard:consolidate',
    enforceAmber: true,
  }), (_req: Request, res: Response) => {
    try {
      const result = consolidate();
      emitConsolidation(result);
      res.json({ success: true, ...result });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Threshold-based prune: delete memories below salience X older than Y days.
  // dryRun:true (default) returns counts + sample without touching the DB.
  // Auto-backs-up the DB before any destructive write — backupPath returned.
  app.post('/api/memories/prune', requireNotLocked, requireIronDomeAction({
    action: 'modify_records',
    channel: 'dashboard',
    sourceIdentifier: 'dashboard:memories-prune',
    enforceAmber: true,
  }), async (req: Request, res: Response) => {
    try {
      const { salienceLte, ageDaysGte, project, excludePinned, dryRun } = req.body ?? {};
      if (salienceLte !== undefined && (typeof salienceLte !== 'number' || salienceLte < 0 || salienceLte > 1)) {
        return res.status(400).json({ error: 'salienceLte must be a number 0..1' });
      }
      if (ageDaysGte !== undefined && (typeof ageDaysGte !== 'number' || ageDaysGte < 0)) {
        return res.status(400).json({ error: 'ageDaysGte must be a number >= 0' });
      }
      if (project !== undefined && project !== null && typeof project !== 'string') {
        return res.status(400).json({ error: 'project must be a string when provided' });
      }
      if (excludePinned !== undefined && typeof excludePinned !== 'boolean') {
        return res.status(400).json({ error: 'excludePinned must be a boolean' });
      }
      if (dryRun !== undefined && typeof dryRun !== 'boolean') {
        return res.status(400).json({ error: 'dryRun must be a boolean' });
      }

      const { pruneMemories } = await import('../../memory/prune.js');
      const result = await pruneMemories({
        salienceLte,
        ageDaysGte,
        project: project ?? undefined,
        excludePinned,
        dryRun,
      });
      res.json({ success: true, ...result });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Project-scoped dedupe: cluster near-duplicate long-term memories and keep
  // the highest-salience representative. dryRun:true (default) returns the
  // groups without merging. Auto-backs-up the DB before any merge.
  app.post('/api/memories/dedupe', requireNotLocked, requireIronDomeAction({
    action: 'modify_records',
    channel: 'dashboard',
    sourceIdentifier: 'dashboard:memories-dedupe',
    enforceAmber: true,
  }), async (req: Request, res: Response) => {
    try {
      const { project, dryRun, limit } = req.body ?? {};
      if (project !== undefined && project !== null && typeof project !== 'string') {
        return res.status(400).json({ error: 'project must be a string when provided' });
      }
      if (dryRun !== undefined && typeof dryRun !== 'boolean') {
        return res.status(400).json({ error: 'dryRun must be a boolean' });
      }
      if (limit !== undefined && (typeof limit !== 'number' || limit < 1 || limit > 1000)) {
        return res.status(400).json({ error: 'limit must be a number 1..1000' });
      }

      const { dedupeMemories } = await import('../../memory/dedupe-runner.js');
      const result = await dedupeMemories({
        project: project ?? undefined,
        dryRun,
        limit,
      });
      res.json({ success: true, ...result });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/context', requireNotLocked, async (req: Request, res: Response) => {
    try {
      const project = typeof req.query.project === 'string' ? req.query.project : undefined;
      const summary = await generateContextSummary(project);
      res.json({
        summary,
        formatted: formatContextSummary(summary),
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/suggestions', requireNotLocked, (req: Request, res: Response) => {
    try {
      const query = typeof req.query.q === 'string' ? req.query.q : '';
      const limit = typeof req.query.limit === 'string' ? parseInt(req.query.limit, 10) : 10;

      if (!query || query.length < 2) {
        return res.json({ suggestions: [] });
      }

      const db = getDatabase();
      const suggestions: Array<{ text: string; type: string; count: number }> = [];

      const titleMatches = db.prepare(`
        SELECT DISTINCT title, COUNT(*) as count
        FROM memories
        WHERE title LIKE ?
        GROUP BY title
        ORDER BY count DESC, last_accessed DESC
        LIMIT ?
      `).all(`%${query}%`, limit) as { title: string; count: number }[];
      for (const match of titleMatches) {
        suggestions.push({ text: match.title, type: 'title', count: match.count });
      }

      const categoryMatches = db.prepare(`
        SELECT DISTINCT category, COUNT(*) as count
        FROM memories
        WHERE category LIKE ?
        GROUP BY category
        ORDER BY count DESC
        LIMIT 5
      `).all(`%${query}%`) as { category: string; count: number }[];
      for (const match of categoryMatches) {
        suggestions.push({ text: match.category, type: 'category', count: match.count });
      }

      const projectMatches = db.prepare(`
        SELECT DISTINCT project, COUNT(*) as count
        FROM memories
        WHERE project IS NOT NULL AND project LIKE ?
        GROUP BY project
        ORDER BY count DESC
        LIMIT 5
      `).all(`%${query}%`) as { project: string; count: number }[];
      for (const match of projectMatches) {
        suggestions.push({ text: match.project, type: 'project', count: match.count });
      }

      const tagRows = db.prepare(`
        SELECT tags FROM memories
        WHERE tags IS NOT NULL AND tags != '[]'
        LIMIT 500
      `).all() as { tags: string }[];
      const tagCounts = new Map<string, number>();
      for (const row of tagRows) {
        try {
          const tags = JSON.parse(row.tags) as string[];
          for (const tag of tags) {
            if (tag.toLowerCase().includes(query.toLowerCase())) {
              tagCounts.set(tag, (tagCounts.get(tag) || 0) + 1);
            }
          }
        } catch {
          // Ignore malformed tag rows.
        }
      }
      const tagMatches = Array.from(tagCounts.entries())
        .map(([text, count]) => ({ text, type: 'tag', count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 5);
      suggestions.push(...tagMatches);

      const dedupedSuggestions = suggestions.filter(
        (suggestion, index, all) =>
          index === all.findIndex((other) =>
            other.text.toLowerCase() === suggestion.text.toLowerCase() && other.type === suggestion.type,
          ),
      );

      const limitedSuggestions = dedupedSuggestions
        .sort((a, b) => b.count - a.count)
        .slice(0, limit);

      res.json({ suggestions: limitedSuggestions });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/memories/:id/boost', requireNotLocked, requireIronDomeAction({
    action: 'modify_records',
    channel: 'dashboard',
    sourceIdentifier: (req: Request) => `dashboard:memory-boost:${req.params.id ?? 'unknown'}`,
    enforceAmber: true,
  }), (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id as string, 10);
      const memory = getMemoryById(id);
      if (!memory) {
        return res.status(404).json({ error: 'Memory not found' });
      }
      const updated = updateMemory(id, { salience: Math.min(1.0, (memory.salience ?? 0.5) + 0.15) });
      res.json(updated);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/memories/:id/demote', requireNotLocked, requireIronDomeAction({
    action: 'modify_records',
    channel: 'dashboard',
    sourceIdentifier: (req: Request) => `dashboard:memory-demote:${req.params.id ?? 'unknown'}`,
    enforceAmber: true,
  }), (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id as string, 10);
      const memory = getMemoryById(id);
      if (!memory) {
        return res.status(404).json({ error: 'Memory not found' });
      }
      const updated = updateMemory(id, { salience: Math.max(0.05, (memory.salience ?? 0.5) - 0.15) });
      res.json(updated);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/memories/:id/promote', requireNotLocked, requireIronDomeAction({
    action: 'modify_records',
    channel: 'dashboard',
    sourceIdentifier: (req: Request) => `dashboard:memory-promote:${req.params.id ?? 'unknown'}`,
    enforceAmber: true,
  }), (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id as string, 10);
      const memory = promoteMemory(id);
      if (!memory) {
        return res.status(404).json({ error: 'Memory not found' });
      }
      res.json(memory);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.patch('/api/memories/:id', requireNotLocked, requireIronDomeAction({
    action: 'modify_records',
    channel: 'dashboard',
    sourceIdentifier: (req: Request) => `dashboard:memory-update:${req.params.id ?? 'unknown'}`,
    enforceAmber: true,
  }), (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id as string, 10);
      const { title, content, category, tags, importance, status, pinned, reviewedBy, cloudExcluded, scope, project, memoryPurpose, memoryScope } = req.body;

      if (title !== undefined && (typeof title !== 'string' || title.trim().length === 0)) {
        return res.status(400).json({ error: 'Title must be a non-empty string' });
      }
      if (content !== undefined && typeof content !== 'string') {
        return res.status(400).json({ error: 'Content must be a string' });
      }
      const validCategories = ['architecture', 'pattern', 'preference', 'error', 'context', 'learning', 'todo', 'note', 'relationship', 'custom'];
      if (category !== undefined && !validCategories.includes(category)) {
        return res.status(400).json({ error: `Category must be one of: ${validCategories.join(', ')}` });
      }
      if (tags !== undefined && (!Array.isArray(tags) || !tags.every((tag: unknown) => typeof tag === 'string'))) {
        return res.status(400).json({ error: 'Tags must be an array of strings' });
      }
      if (importance !== undefined && (typeof importance !== 'number' || importance < 0 || importance > 1)) {
        return res.status(400).json({ error: 'Importance must be a number between 0 and 1' });
      }
      if (status !== undefined && !['active', 'archived', 'suppressed', 'canonical'].includes(status)) {
        return res.status(400).json({ error: 'Invalid review status' });
      }
      if (pinned !== undefined && typeof pinned !== 'boolean') {
        return res.status(400).json({ error: 'Pinned must be boolean' });
      }
      if (cloudExcluded !== undefined && typeof cloudExcluded !== 'boolean') {
        return res.status(400).json({ error: 'cloudExcluded must be boolean' });
      }
      if (reviewedBy !== undefined && reviewedBy !== null && typeof reviewedBy !== 'string') {
        return res.status(400).json({ error: 'reviewedBy must be string or null' });
      }
      if (scope !== undefined && !['project', 'global'].includes(scope)) {
        return res.status(400).json({ error: 'scope must be project or global' });
      }
      if (project !== undefined && project !== null && typeof project !== 'string') {
        return res.status(400).json({ error: 'project must be string or null' });
      }

      const updates: Record<string, unknown> = {};
      if (title !== undefined) updates.title = title.trim();
      if (content !== undefined) updates.content = content;
      if (category !== undefined) updates.category = category;
      if (tags !== undefined) updates.tags = tags;
      if (importance !== undefined) updates.salience = importance;
      if (status !== undefined) updates.status = status;
      if (pinned !== undefined) updates.pinned = pinned;
      if (reviewedBy !== undefined) updates.reviewedBy = reviewedBy;
      if (cloudExcluded !== undefined) updates.cloudExcluded = cloudExcluded;
      if (scope !== undefined) updates.scope = scope;
      if (project !== undefined) updates.project = project;

      const updated = updateMemory(id, updates);
      if (!updated) {
        return res.status(404).json({ error: 'Memory not found' });
      }
      res.json(updated);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.patch('/api/memories/:id/review', requireNotLocked, requireIronDomeAction({
    action: 'modify_records',
    channel: 'dashboard',
    sourceIdentifier: (req: Request) => `dashboard:memory-review:${req.params.id ?? 'unknown'}`,
    enforceAmber: true,
  }), (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id as string, 10);
      const { action, reviewedBy, project, scope } = req.body as {
        action?: string;
        reviewedBy?: string;
        project?: string | null;
        scope?: 'project' | 'global';
      };
      if (Number.isNaN(id)) {
        return res.status(400).json({ error: 'Invalid memory ID' });
      }

      const updates = buildReviewUpdates(action ?? '', { reviewedBy, project, scope });
      if (!updates) {
        return res.status(400).json({ error: 'Unsupported review action' });
      }

      const updated = updateMemory(id, updates);
      if (!updated) {
        return res.status(404).json({ error: 'Memory not found' });
      }
      res.json(updated);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Bulk review: apply one reversible review action to many memories at once, so
  // the dashboard's large triage queues (Never Used, Noisy Auto, …) can be cleared
  // without one round-trip per card. Mirrors the quarantine bulk-approve pattern.
  // Reversible actions only (archive/suppress/restore/pin/…) — there is no bulk
  // delete here. Best-effort with a per-row failure list; capped at MAX_BULK_REVIEW.
  app.post('/api/memories/review/bulk', requireNotLocked, requireIronDomeAction({
    action: 'modify_records',
    channel: 'dashboard',
    sourceIdentifier: 'dashboard:memory-review-bulk',
    enforceAmber: true,
  }), (req: Request, res: Response) => {
    try {
      const { ids, action, reviewedBy, project, scope } = req.body as {
        ids?: unknown;
        action?: string;
        reviewedBy?: string;
        project?: string | null;
        scope?: 'project' | 'global';
      };

      if (!Array.isArray(ids) || ids.length === 0) {
        return res.status(400).json({ error: 'ids must be a non-empty array' });
      }
      const numericIds = Array.from(new Set(ids.filter((x): x is number => Number.isInteger(x))));
      if (numericIds.length === 0) {
        return res.status(400).json({ error: 'ids must contain integers' });
      }
      if (numericIds.length > MAX_BULK_REVIEW) {
        return res.status(400).json({ error: `Too many ids (max ${MAX_BULK_REVIEW}) — narrow the selection.` });
      }

      const updates = buildReviewUpdates(action ?? '', { reviewedBy, project, scope });
      if (!updates) {
        return res.status(400).json({ error: 'Unsupported review action' });
      }

      let updated = 0;
      const failed: number[] = [];
      withTransaction(() => {
        for (const id of numericIds) {
          if (updateMemory(id, updates)) updated += 1;
          else failed.push(id);
        }
      });

      res.json({ success: true, updated, total: numericIds.length, failed });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/memories/:id/quarantine', requireNotLocked, requireIronDomeAction({
    action: 'modify_records',
    channel: 'dashboard',
    sourceIdentifier: (req: Request) => `dashboard:memory-quarantine:${req.params.id ?? 'unknown'}`,
    enforceAmber: true,
  }), (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id as string, 10);
      const memory = getMemoryById(id);
      if (!memory) {
        return res.status(404).json({ error: 'Memory not found' });
      }

      const db = getDatabase();
      db.prepare(
        `INSERT INTO quarantine (original_title, original_content, source_type, source_identifier, reason, project, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)`,
      ).run(
        memory.title,
        memory.content,
        'dashboard',
        'brain-control',
        req.body.reason || 'Manually quarantined from Brain dashboard',
        memory.project || null,
        new Date().toISOString(),
      );

      deleteMemory(id, { type: 'api', identifier: `dashboard:quarantine-delete:${id}` });
      res.json({ success: true, quarantined: id });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/links', requireNotLocked, requireIronDomeAction({
    action: 'modify_records',
    channel: 'dashboard',
    sourceIdentifier: 'dashboard:memory-link-create',
    enforceAmber: true,
  }), (req: Request, res: Response) => {
    try {
      const { sourceId, targetId, relationship, strength } = req.body;
      if (!sourceId || !targetId || !relationship) {
        return res.status(400).json({ error: 'sourceId, targetId, and relationship are required' });
      }

      const link = createMemoryLink(sourceId, targetId, relationship, strength ?? 0.5);
      if (!link) {
        return res.status(404).json({ error: 'One or both memories not found, or self-link attempted' });
      }

      res.json(link);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // (Note: there used to be a second, ungated `app.post('/api/consolidate', ...)`
  // here calling `consolidateMemories()`. It was dead code — Express dispatches
  // to the first matching route and the gated one above won. Removed in
  // favour of the gated route to avoid future contributors thinking either
  // would actually run.)

}
