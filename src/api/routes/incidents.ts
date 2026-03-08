import type { Express, Request, Response } from 'express';
import { queryIncidentReplay } from '../../defence/audit/queries.js';

export function registerIncidentRoutes(app: Express): void {
  app.get('/api/v1/incidents/replay', (req: Request, res: Response) => {
    try {
      const limit = Math.min(parseInt(req.query.limit as string, 10) || 200, 500);
      const startTime = typeof req.query.startTime === 'string' ? req.query.startTime : undefined;
      const endTime = typeof req.query.endTime === 'string' ? req.query.endTime : undefined;
      const project = typeof req.query.project === 'string' ? req.query.project : undefined;
      const sourceIdentifier = typeof req.query.sourceIdentifier === 'string' ? req.query.sourceIdentifier : undefined;
      const memoryId = req.query.memoryId ? parseInt(req.query.memoryId as string, 10) : undefined;

      const events = queryIncidentReplay({
        startTime,
        endTime,
        project,
        sourceIdentifier,
        memoryId,
        limit,
      });

      res.json({
        events,
        total: events.length,
        coverage: {
          sources: ['defence_audit', 'quarantine', 'events'],
          note: 'Replay is best-effort. Durable audit and quarantine history is complete; generic event coverage depends on the retained events table window.',
        },
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });
}
