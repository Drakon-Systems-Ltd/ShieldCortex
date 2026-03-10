import type { Express, Request, Response } from 'express';
import { searchMemoriesExplained } from '../../memory/store.js';
import type { Memory } from '../../memory/types.js';
import { getMemoryById, getRecentMemories } from '../../memory/store.js';

type Middleware = (_req: Request, res: Response, next: (err?: unknown) => void) => void;

export function registerRecallRoutes(app: Express, requireNotLocked: Middleware): void {
  app.get('/api/recall/explain', requireNotLocked, async (req: Request, res: Response) => {
    try {
      const query = typeof req.query.query === 'string' ? req.query.query.trim() : '';
      if (!query) {
        return res.status(400).json({ error: 'query is required' });
      }

      const project = typeof req.query.project === 'string' ? req.query.project : undefined;
      const type = typeof req.query.type === 'string' ? req.query.type : undefined;
      const category = typeof req.query.category === 'string' ? req.query.category : undefined;
      const limit = Math.min(parseInt(req.query.limit as string, 10) || 10, 50);
      const includeDecayed = req.query.includeDecayed === 'true';
      const includeGlobal = req.query.includeGlobal !== 'false';
      const includeArchived = req.query.includeArchived === 'true';
      const includeSuppressed = req.query.includeSuppressed === 'true';
      const expectedId = typeof req.query.expectedId === 'string' ? parseInt(req.query.expectedId, 10) : null;

      const results = await searchMemoriesExplained({
        query,
        project,
        type: type as Memory['type'] | undefined,
        category: category as Memory['category'] | undefined,
        limit,
        includeDecayed,
        includeGlobal,
        includeArchived,
        includeSuppressed,
      });

      let expectedMemory: Record<string, unknown> | null = null;
      if (expectedId && Number.isFinite(expectedId)) {
        const memory = getMemoryById(expectedId);
        if (memory) {
          const foundIndex = results.findIndex((result) => result.memory.id === expectedId);
          expectedMemory = {
            id: memory.id,
            title: memory.title,
            status: memory.status,
            pinned: memory.pinned,
            cloudExcluded: memory.cloudExcluded,
            trustScore: memory.trustScore,
            captureMethod: memory.captureMethod,
            sourceKind: memory.sourceKind,
            rank: foundIndex >= 0 ? foundIndex + 1 : null,
            eligible: memory.status !== 'archived' && memory.status !== 'suppressed',
            reasons: [
              ...(memory.status === 'archived' ? ['Archived memories are excluded from normal recall'] : []),
              ...(memory.status === 'suppressed' ? ['Suppressed memories are excluded from normal recall'] : []),
              ...(memory.trustScore < 0.7 ? [`Low trust source (${memory.trustScore.toFixed(2)})`] : []),
              ...(memory.cloudExcluded ? ['Excluded from cloud sync'] : []),
              ...(foundIndex === -1 ? ['Did not rank in the current result window'] : []),
            ],
          };
        }
      }

      const misses = getRecentMemories(200, project).filter((memory) => {
        if (results.some((result) => result.memory.id === memory.id)) return false;
        if (memory.status === 'archived' || memory.status === 'suppressed') return false;
        return memory.salience >= 0.65 || memory.pinned;
      }).slice(0, 5).map((memory) => ({
        id: memory.id,
        title: memory.title,
        status: memory.status,
        salience: memory.salience,
        captureMethod: memory.captureMethod,
        sourceKind: memory.sourceKind,
        whyNotRecalled: [
          'Lower relevance for this query than the returned set',
          ...(memory.pinned ? ['Pinned memories are still query-sensitive, not guaranteed results'] : []),
          ...(memory.trustScore < 0.7 ? [`Low trust source (${memory.trustScore.toFixed(2)})`] : []),
        ],
      }));

      res.json({
        query,
        project: project ?? null,
        total: results.length,
        sideEffects: 'disabled',
        results,
        expectedMemory,
        misses,
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });
}
