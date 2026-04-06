import type { Express, Request, Response } from 'express';
import {
  listFindings,
  getFinding,
  updateFindingStatus,
  deleteFinding,
  quarantineFile,
  getStats,
} from '../../xray/findings-store.js';
import type { FindingStatus, ActionableXRayFinding } from '../../xray/types.js';
import { getGuidance, isLikelySystemFile } from '../../xray/guidance.js';

type Middleware = (req: Request, res: Response, next: (err?: unknown) => void) => void;

/** Enrich a finding with guidance and system-file flag */
function enrichFinding(f: ActionableXRayFinding) {
  const guidance = getGuidance(f.category, f.severity);
  const systemFile = isLikelySystemFile(f.file || f.target);
  return { ...f, guidance, systemFile };
}

export function registerXRayFindingRoutes(app: Express, requireNotLocked: Middleware): void {

  // List findings with optional filters
  app.get('/api/xray/findings', (req: Request, res: Response) => {
    const status = req.query.status as FindingStatus | undefined;
    const target = req.query.target as string | undefined;
    const severity = req.query.severity as string | undefined;
    const limit = Number(req.query.limit) || 100;
    const findings = listFindings({ status, target, severity, limit }).map(enrichFinding);
    res.json({ findings });
  });

  // Get finding stats
  app.get('/api/xray/findings/stats', (_req: Request, res: Response) => {
    res.json(getStats());
  });

  // Get single finding
  app.get('/api/xray/findings/:id', (req: Request, res: Response) => {
    const finding = getFinding(String(req.params.id));
    if (!finding) return res.status(404).json({ error: 'Finding not found' });
    res.json({ finding: enrichFinding(finding) });
  });

  // Update finding status (acknowledge, ignore, resolve)
  app.patch('/api/xray/findings/:id', requireNotLocked, (req: Request, res: Response) => {
    const { status, note } = req.body as { status?: FindingStatus; note?: string };
    if (!status || !['reviewed', 'ignored', 'resolved'].includes(status)) {
      return res.status(400).json({ error: 'status must be one of: reviewed, ignored, resolved' });
    }
    const updated = updateFindingStatus(String(req.params.id), status, note);
    if (!updated) return res.status(404).json({ error: 'Finding not found' });
    res.json({ finding: updated });
  });

  // Quarantine the file associated with a finding
  app.post('/api/xray/findings/:id/quarantine', requireNotLocked, (req: Request, res: Response) => {
    const { note } = req.body as { note?: string };
    const result = quarantineFile(String(req.params.id), note);
    if (result.error && !result.moved) {
      return res.status(result.error === 'Finding not found' ? 404 : 400).json(result);
    }
    res.json(result);
  });

  // Delete a finding record
  app.delete('/api/xray/findings/:id', requireNotLocked, (req: Request, res: Response) => {
    const deleted = deleteFinding(String(req.params.id));
    if (!deleted) return res.status(404).json({ error: 'Finding not found' });
    res.json({ deleted: true });
  });
}
