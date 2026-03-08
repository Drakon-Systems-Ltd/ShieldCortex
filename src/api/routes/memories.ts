import type { Express, Request, Response } from 'express';
import { getDatabase } from '../../database/init.js';
import { Memory } from '../../memory/types.js';
import {
  searchMemories,
  getRecentMemories,
  getHighPriorityMemories,
  getMemoryStats,
  getMemoryById,
  addMemory,
  deleteMemory,
  accessMemory,
  updateMemory,
  promoteMemory,
  createMemoryLink,
  rowToMemory,
  enrichMemory,
} from '../../memory/store.js';
import { calculateDecayedScore } from '../../memory/decay.js';
import {
  consolidate,
  formatContextSummary,
  generateContextSummary,
} from '../../memory/consolidate.js';
import { getActivationStats, getActiveMemories } from '../../memory/activation.js';
import { detectContradictions, getContradictionsFor } from '../../memory/contradiction.js';
import { emitConsolidation } from '../events.js';

type Middleware = (_req: Request, res: Response, next: (err?: unknown) => void) => void;

export function registerMemoryRoutes(app: Express, requireNotLocked: Middleware): void {
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

      let memories: Memory[];
      if (mode === 'search' && query) {
        const results = await searchMemories({
          query,
          project,
          type: type as Memory['type'] | undefined,
          category: category as Memory['category'] | undefined,
          limit: limit + offset + 1,
        });
        memories = results.map((result) => result.memory);
      } else if (mode === 'important') {
        memories = getHighPriorityMemories(limit + offset + 1, project);
      } else {
        memories = getRecentMemories(limit + offset + 1, project);
      }

      if (type) {
        memories = memories.filter((memory) => memory.type === type);
      }
      if (category) {
        memories = memories.filter((memory) => memory.category === category);
      }

      const stats = getMemoryStats(project);
      const total = stats.total;
      const hasMore = memories.length > offset + limit;
      const paginatedMemories = memories.slice(offset, offset + limit);
      const memoriesWithDecay = paginatedMemories.map((memory) => ({
        ...memory,
        decayedScore: calculateDecayedScore(memory),
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
        ${project ? 'WHERE m1.project = ?' : ''}
        LIMIT 50
      `).all(...params) as Array<Record<string, unknown>>;

      res.json({
        neverAccessed: { count: neverAccessed.length, items: neverAccessed },
        stale: { count: stale.length, items: stale },
        duplicates: { count: duplicates.length, items: duplicates },
      });
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

  app.post('/api/memories', requireNotLocked, (req: Request, res: Response) => {
    try {
      const { title, content, type, category, project, tags, salience } = req.body;

      if (!title || !content) {
        return res.status(400).json({ error: 'Title and content required' });
      }

      const memory = addMemory({
        title,
        content,
        type: type || 'short_term',
        category: category || 'note',
        project,
        tags: tags || [],
        salience,
      });

      res.status(201).json(memory);
    } catch (error) {
      if ((error as Error).name === 'MemoryPausedError') {
        return res.status(503).json({
          error: 'Memory creation is paused',
          paused: true,
          message: 'Use the dashboard control panel to resume memory creation.',
        });
      }
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.delete('/api/memories/:id', requireNotLocked, (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id as string, 10);
      const success = deleteMemory(id);
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

  app.post('/api/memories/:id/enrich', requireNotLocked, (req: Request, res: Response) => {
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

  app.post('/api/consolidate', requireNotLocked, (_req: Request, res: Response) => {
    try {
      const result = consolidate();
      emitConsolidation(result);
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

  app.post('/api/memories/:id/boost', requireNotLocked, (req: Request, res: Response) => {
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

  app.post('/api/memories/:id/demote', requireNotLocked, (req: Request, res: Response) => {
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

  app.post('/api/memories/:id/promote', requireNotLocked, (req: Request, res: Response) => {
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

  app.patch('/api/memories/:id', requireNotLocked, (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id as string, 10);
      const { title, content, category, tags, importance } = req.body;

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

      const updates: Record<string, unknown> = {};
      if (title !== undefined) updates.title = title.trim();
      if (content !== undefined) updates.content = content;
      if (category !== undefined) updates.category = category;
      if (tags !== undefined) updates.tags = tags;
      if (importance !== undefined) updates.salience = importance;

      const updated = updateMemory(id, updates);
      if (!updated) {
        return res.status(404).json({ error: 'Memory not found' });
      }
      res.json(updated);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/memories/:id/quarantine', requireNotLocked, (req: Request, res: Response) => {
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

      deleteMemory(id);
      res.json({ success: true, quarantined: id });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/links', requireNotLocked, (req: Request, res: Response) => {
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
}
