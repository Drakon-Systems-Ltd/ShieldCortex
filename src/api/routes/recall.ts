import type { Express, Request, Response } from 'express';
import { searchMemoriesExplained } from '../../memory/store.js';
import type { Memory } from '../../memory/types.js';

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

      const results = await searchMemoriesExplained({
        query,
        project,
        type: type as Memory['type'] | undefined,
        category: category as Memory['category'] | undefined,
        limit,
        includeDecayed,
        includeGlobal,
      });

      res.json({
        query,
        project: project ?? null,
        total: results.length,
        sideEffects: 'disabled',
        results,
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });
}
