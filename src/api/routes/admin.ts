import type { Express, Request, Response } from 'express';
import { getDatabase } from '../../database/init.js';
import { getCloudConfig, getDeviceId, getDeviceName } from '../../cloud/config.js';
import { queryAgentOperations, queryAgentRegistry, queryAgentTimeline, queryAuditLogs, getAuditStats } from '../../defence/audit/queries.js';
import {
  approveQuarantineItem,
  approveQuarantineItems,
  rejectQuarantineItem,
  rejectQuarantineItems,
} from '../../defence/quarantine/review.js';
import { getLicense, getLicenseTier, activateLicense, deactivateLicense } from '../../license/store.js';
import { listFeatures } from '../../license/gate.js';
import type { GatedFeature } from '../../license/gate.js';
import { isFeatureEnabled } from '../../license/gate.js';
import type { LocalAiExplainSubject, LocalAiExplainSubjectKind } from '../../defence/explainer/types.js';
import { validateOnceNow } from '../../license/validate.js';
import type { BrainWorker } from '../../worker/brain-worker.js';
import type { IronDomeRouteGuardOptions, Middleware as IronDomeMiddleware } from '../iron-dome-route-guard.js';
import { existsSync, readFileSync, readdirSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

type Middleware = (_req: Request, res: Response, next: (err?: unknown) => void) => void;
type FeatureMiddlewareFactory = (feature: GatedFeature) => Middleware;

interface AdminRouteDeps {
  brainWorker: BrainWorker;
  requireNotLocked: Middleware;
  requireProFeature: FeatureMiddlewareFactory;
  requireIronDomeAction: (options: IronDomeRouteGuardOptions) => IronDomeMiddleware;
}

interface InterceptAuditEntry {
  type: 'intercept';
  tool: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  firewallResult: string;
  threats: string[];
  anomalyScore: number;
  action: string;
  outcome: string;
  preview: string;
  ts: string;
}

function parseAnnotationJson(value: unknown): unknown | null {
  if (typeof value !== 'string' || !value.trim()) return null;
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function readTailLines(path: string, count: number): string[] {
  try {
    if (!existsSync(path)) return [];
    return readFileSync(path, 'utf-8').trim().split('\n').filter(Boolean).slice(-count);
  } catch {
    return [];
  }
}

function isModelCacheReady(cacheDir: string): boolean {
  try {
    return existsSync(cacheDir) && readdirSync(cacheDir).length > 0;
  } catch {
    return false;
  }
}

const LOCAL_AI_SUBJECT_KINDS = new Set<LocalAiExplainSubjectKind>([
  'memory',
  'memory_file',
  'xray_finding',
  'quarantine_item',
  'audit_event',
  'generic',
]);

function cleanString(value: unknown, max: number): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed ? trimmed.slice(0, max) : undefined;
}

function cleanStringArray(value: unknown, maxItems: number, maxLength: number): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  return value
    .map((item) => cleanString(item, maxLength))
    .filter((item): item is string => Boolean(item))
    .slice(0, maxItems);
}

function cleanMetadata(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const entries = Object.entries(value as Record<string, unknown>).slice(0, 40);
  return Object.fromEntries(entries);
}

function parseLocalAiSubject(value: unknown): LocalAiExplainSubject | null {
  if (!value || typeof value !== 'object') return null;
  const body = value as Record<string, unknown>;
  const kind = body.kind;
  const title = cleanString(body.title, 240);
  const content = cleanString(body.content, 20_000);

  if (typeof kind !== 'string' || !LOCAL_AI_SUBJECT_KINDS.has(kind as LocalAiExplainSubjectKind)) return null;
  if (!title || !content) return null;

  return {
    kind: kind as LocalAiExplainSubjectKind,
    title,
    content,
    project: cleanString(body.project, 160) ?? null,
    source: cleanString(body.source, 240) ?? null,
    signals: cleanStringArray(body.signals, 20, 120),
    metadata: cleanMetadata(body.metadata),
  };
}

export function registerAdminRoutes(app: Express, deps: AdminRouteDeps): void {
  const { brainWorker, requireNotLocked, requireProFeature, requireIronDomeAction } = deps;

  app.get('/api/v1/audit', (req: Request, res: Response) => {
    try {
      const options: Record<string, unknown> = {};
      if (req.query.startTime) options.startTime = req.query.startTime;
      if (req.query.endTime) options.endTime = req.query.endTime;
      if (req.query.source) options.source = req.query.source;
      if (req.query.firewallResult) options.firewallResult = req.query.firewallResult;
      if (req.query.operation) options.operation = req.query.operation as string;
      if (req.query.limit) options.limit = parseInt(req.query.limit as string, 10);
      if (req.query.project) options.project = req.query.project as string;

      const logs = queryAuditLogs(options);
      res.json({ logs, total: logs.length });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/v1/audit/stats', (req: Request, res: Response) => {
    try {
      const timeRange = (req.query.timeRange as '24h' | '7d' | '30d') ?? '24h';
      const project = req.query.project as string | undefined;
      res.json(getAuditStats(timeRange, project));
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/v1/intercepts', (req: Request, res: Response) => {
    try {
      const limit = parseInt(req.query.limit as string, 10) || 100;
      const severityFilter = typeof req.query.severity === 'string' ? req.query.severity : undefined;
      const outcomeFilter = typeof req.query.outcome === 'string' ? req.query.outcome : undefined;
      const toolFilter = typeof req.query.tool === 'string' ? req.query.tool : undefined;

      const auditDir = join(homedir(), '.shieldcortex', 'audit');
      const entries: InterceptAuditEntry[] = [];

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
              const parsed = JSON.parse(line) as Record<string, unknown>;
              if (parsed.type !== 'intercept') continue;

              const entry: InterceptAuditEntry = {
                type: 'intercept',
                tool: typeof parsed.tool === 'string' ? parsed.tool : 'unknown',
                severity: parsed.severity === 'critical' || parsed.severity === 'high' || parsed.severity === 'medium' || parsed.severity === 'low'
                  ? parsed.severity
                  : 'low',
                firewallResult: typeof parsed.firewallResult === 'string' ? parsed.firewallResult : 'UNKNOWN',
                threats: Array.isArray(parsed.threats) ? parsed.threats.filter((item): item is string => typeof item === 'string') : [],
                anomalyScore: typeof parsed.anomalyScore === 'number' ? parsed.anomalyScore : 0,
                action: typeof parsed.action === 'string' ? parsed.action : 'unknown',
                outcome: typeof parsed.outcome === 'string' ? parsed.outcome : 'unknown',
                preview: typeof parsed.preview === 'string' ? parsed.preview : '',
                ts: typeof parsed.ts === 'string' ? parsed.ts : new Date().toISOString(),
              };

              if (severityFilter && entry.severity !== severityFilter) continue;
              if (outcomeFilter && entry.outcome !== outcomeFilter) continue;
              if (toolFilter && entry.tool !== toolFilter) continue;

              entries.push(entry);
            } catch {
              // ignore malformed lines
            }
          }
        }
      }

      entries.sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime());
      const limited = entries.slice(0, limit);

      const summary = limited.reduce((acc, entry) => {
        acc.total += 1;
        if (entry.outcome === 'approved') acc.approved += 1;
        if (entry.outcome === 'denied' || entry.outcome === 'auto_denied') acc.denied += 1;
        if (entry.outcome === 'failure_allowed' || entry.outcome === 'failure_denied') acc.failures += 1;
        acc.bySeverity[entry.severity] = (acc.bySeverity[entry.severity] || 0) + 1;
        acc.byTool[entry.tool] = (acc.byTool[entry.tool] || 0) + 1;
        return acc;
      }, {
        total: 0,
        approved: 0,
        denied: 0,
        failures: 0,
        bySeverity: {} as Record<string, number>,
        byTool: {} as Record<string, number>,
      });

      const topTools = Object.entries(summary.byTool)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([tool, count]) => ({ tool, count }));

      res.json({
        entries: limited,
        total: entries.length,
        summary: {
          total: summary.total,
          approved: summary.approved,
          denied: summary.denied,
          failures: summary.failures,
          bySeverity: summary.bySeverity,
          topTools,
        },
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/v1/agents', (req: Request, res: Response) => {
    try {
      const timeRange = (req.query.timeRange as '24h' | '7d' | '30d') ?? '24h';
      const project = req.query.project as string | undefined;
      res.json({ agents: queryAgentRegistry(timeRange, project) });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/v1/agents/:identifier/timeline', (req: Request, res: Response) => {
    try {
      const identifier = decodeURIComponent(req.params.identifier as string);
      const timeRange = (req.query.timeRange as '24h' | '7d' | '30d') ?? '24h';
      const project = req.query.project as string | undefined;
      res.json({ points: queryAgentTimeline(identifier, timeRange, project) });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/v1/agents/:identifier/operations', (req: Request, res: Response) => {
    try {
      const identifier = decodeURIComponent(req.params.identifier as string);
      const limit = parseInt(req.query.limit as string, 10) || 50;
      const offset = parseInt(req.query.offset as string, 10) || 0;
      const firewallResult = req.query.firewallResult as 'ALLOW' | 'BLOCK' | 'QUARANTINE' | undefined;
      const project = req.query.project as string | undefined;
      res.json({
        entries: queryAgentOperations(identifier, { limit, offset, project, firewallResult }),
        limit,
        offset,
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/v1/quarantine', (req: Request, res: Response) => {
    try {
      const db = getDatabase();
      const status = typeof req.query.status === 'string' && req.query.status.trim()
        ? req.query.status.trim()
        : 'pending';
      const limit = parseInt(req.query.limit as string, 10) || 50;
      const project = typeof req.query.project === 'string' && req.query.project.trim()
        ? req.query.project.trim()
        : undefined;
      const sourceType = typeof req.query.sourceType === 'string' && req.query.sourceType.trim()
        ? req.query.sourceType.trim()
        : undefined;
      const clauses = ['status = ?'];
      const params: Array<string | number> = [status];
      if (project) {
        clauses.push('project = ?');
        params.push(project);
      }
      if (sourceType) {
        clauses.push('source_type = ?');
        params.push(sourceType);
      }
      const whereSql = clauses.join(' AND ');
      const rows = db.prepare(`SELECT * FROM quarantine WHERE ${whereSql} ORDER BY created_at DESC LIMIT ?`)
        .all(...params, limit) as Record<string, unknown>[];
      const countSql = `SELECT COUNT(*) as count FROM quarantine WHERE ${whereSql}`;
      const countParams = params;
      const countRow = db.prepare(countSql).get(...countParams) as { count: number } | undefined;
      const annotationByItem = new Map<number, unknown>();
      const ids = rows
        .map((row) => Number(row.id))
        .filter((id) => Number.isInteger(id) && id > 0);

      if (ids.length > 0) {
        const placeholders = ids.map(() => '?').join(',');
        const annotationRows = db.prepare(`
          SELECT qa.item_id, qa.annotation_json
          FROM quarantine_annotations qa
          JOIN (
            SELECT item_id, MAX(generated_at) AS generated_at
            FROM quarantine_annotations
            WHERE item_id IN (${placeholders})
            GROUP BY item_id
          ) latest
            ON latest.item_id = qa.item_id
           AND latest.generated_at = qa.generated_at
        `).all(...ids) as Array<{ item_id: number; annotation_json: string }>;

        for (const annotationRow of annotationRows) {
          annotationByItem.set(annotationRow.item_id, parseAnnotationJson(annotationRow.annotation_json));
        }
      }

      res.json({
        items: rows.map((row) => ({
          ...row,
          title: row.original_title,
          content: row.original_content,
          annotation: annotationByItem.get(Number(row.id)) ?? null,
        })),
        total: countRow?.count ?? rows.length,
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/v1/review-copilot/status', async (_req: Request, res: Response) => {
    try {
      const { getReviewCopilotConfig } = await import('../../cloud/config.js');
      const config = getReviewCopilotConfig();
      const cacheReady = isModelCacheReady(config.modelCacheDir);
      const recentTelemetry = readTailLines(config.telemetryPath, 10)
        .map((line) => {
          try { return JSON.parse(line) as Record<string, unknown>; }
          catch { return null; }
        })
        .filter(Boolean);

      res.json({
        enabled: config.enabled,
        featureEnabled: isFeatureEnabled('local_ai_explainer'),
        modelId: config.modelId,
        modelCacheDir: config.modelCacheDir,
        modelCached: cacheReady,
        telemetryPath: config.telemetryPath,
        inferenceTimeoutMs: config.inferenceTimeoutMs,
        workerHeapMB: config.workerHeapMB,
        recentTelemetry,
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/v1/local-ai/status', async (_req: Request, res: Response) => {
    try {
      const { getReviewCopilotConfig } = await import('../../cloud/config.js');
      const config = getReviewCopilotConfig();
      const cacheReady = isModelCacheReady(config.modelCacheDir);
      const recentTelemetry = readTailLines(config.telemetryPath, 10)
        .map((line) => {
          try { return JSON.parse(line) as Record<string, unknown>; }
          catch { return null; }
        })
        .filter(Boolean);

      res.json({
        enabled: config.enabled,
        featureEnabled: isFeatureEnabled('local_ai_explainer'),
        modelId: config.modelId,
        modelCacheDir: config.modelCacheDir,
        modelCached: cacheReady,
        telemetryPath: config.telemetryPath,
        inferenceTimeoutMs: config.inferenceTimeoutMs,
        workerHeapMB: config.workerHeapMB,
        recentTelemetry,
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/v1/local-ai/explain', requireNotLocked, requireProFeature('local_ai_explainer'), async (req: Request, res: Response) => {
    try {
      const subject = parseLocalAiSubject(req.body);
      if (!subject) {
        return res.status(400).json({ error: 'Invalid explanation subject' });
      }

      const { getReviewCopilotConfig } = await import('../../cloud/config.js');
      const config = getReviewCopilotConfig();
      if (!config.enabled) {
        return res.status(409).json({ error: 'Local AI Explainer is disabled', code: 'LOCAL_AI_EXPLAINER_DISABLED' });
      }
      if (!isModelCacheReady(config.modelCacheDir)) {
        return res.status(409).json({ error: 'Local AI Explainer model is not cached', code: 'LOCAL_AI_EXPLAINER_MODEL_NOT_CACHED' });
      }

      const { explainLocalAiSubject } = await import('../../defence/explainer/index.js');
      const explanation = await explainLocalAiSubject(subject);
      res.json({ success: true, explanation });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/v1/memory-files/scan', requireNotLocked, requireProFeature('memory_file_scan'), async (_req: Request, res: Response) => {
    try {
      const { queueMemoryFileScanFindings, scanMemoryFilesDetailed } = await import('../../audit/memory-scanner.js');
      const result = scanMemoryFilesDetailed();
      const quarantine = queueMemoryFileScanFindings(result);
      res.json({
        success: true,
        scannedAt: result.scannedAt,
        summary: result.summary,
        quarantine,
        files: result.files,
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/v1/quarantine/:id/annotation', (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id as string, 10);
      if (!Number.isInteger(id) || id <= 0) {
        return res.status(400).json({ error: 'Invalid quarantine id' });
      }
      const db = getDatabase();
      const row = db.prepare(`
        SELECT annotation_json
        FROM quarantine_annotations
        WHERE item_id = ?
        ORDER BY generated_at DESC
        LIMIT 1
      `).get(id) as { annotation_json: string } | undefined;
      res.json({ annotation: row ? parseAnnotationJson(row.annotation_json) : null });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/v1/quarantine/:id/annotate', requireNotLocked, requireProFeature('local_ai_explainer'), async (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id as string, 10);
      if (!Number.isInteger(id) || id <= 0) {
        return res.status(400).json({ error: 'Invalid quarantine id' });
      }
      const { getReviewCopilotConfig } = await import('../../cloud/config.js');
      const config = getReviewCopilotConfig();
      if (!config.enabled) {
        return res.status(409).json({ error: 'Local AI Explainer is disabled', code: 'LOCAL_AI_EXPLAINER_DISABLED' });
      }
      if (!isModelCacheReady(config.modelCacheDir)) {
        return res.status(409).json({ error: 'Local AI Explainer model is not cached', code: 'LOCAL_AI_EXPLAINER_MODEL_NOT_CACHED' });
      }
      const { annotateQuarantineItem } = await import('../../defence/judge/annotate.js');
      const annotation = await annotateQuarantineItem(id);
      res.json({ success: Boolean(annotation), annotation });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/v1/quarantine/annotate-pending', requireNotLocked, requireProFeature('local_ai_explainer'), async (req: Request, res: Response) => {
    try {
      const limit = Number(req.body?.limit ?? 25);
      if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
        return res.status(400).json({ error: 'limit must be an integer between 1 and 100' });
      }
      const { getReviewCopilotConfig } = await import('../../cloud/config.js');
      const config = getReviewCopilotConfig();
      if (!config.enabled) {
        return res.status(409).json({ error: 'Local AI Explainer is disabled', code: 'LOCAL_AI_EXPLAINER_DISABLED' });
      }
      if (!isModelCacheReady(config.modelCacheDir)) {
        return res.status(409).json({ error: 'Local AI Explainer model is not cached', code: 'LOCAL_AI_EXPLAINER_MODEL_NOT_CACHED' });
      }
      const project = typeof req.body?.project === 'string' && req.body.project.trim()
        ? req.body.project.trim()
        : undefined;
      const { annotatePendingQuarantineItems } = await import('../../defence/judge/annotate.js');
      const result = await annotatePendingQuarantineItems({ limit, project });
      res.json({ success: true, ...result });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/v1/quarantine/:id/approve', requireNotLocked, requireIronDomeAction({
    action: 'modify_records',
    channel: 'dashboard',
    sourceIdentifier: (req: Request) => `dashboard:quarantine-approve:${req.params.id ?? 'unknown'}`,
    enforceAmber: true,
  }), (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id as string, 10);
      const reviewedBy = req.body?.reviewedBy ?? 'api';
      const result = approveQuarantineItem(id, reviewedBy);
      if (!result) {
        return res.status(404).json({ error: 'Quarantine entry not found or already reviewed' });
      }
      res.json({ success: true, ...result });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/v1/quarantine/:id/reject', requireNotLocked, requireIronDomeAction({
    action: 'modify_records',
    channel: 'dashboard',
    sourceIdentifier: (req: Request) => `dashboard:quarantine-reject:${req.params.id ?? 'unknown'}`,
    enforceAmber: true,
  }), (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id as string, 10);
      const reviewedBy = req.body?.reviewedBy ?? 'api';
      const result = rejectQuarantineItem(id, reviewedBy);
      if (!result) {
        return res.status(404).json({ error: 'Quarantine entry not found or already reviewed' });
      }
      res.json({ success: true, ...result });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/v1/quarantine/bulk-approve', requireNotLocked, requireIronDomeAction({
    action: 'modify_records',
    channel: 'dashboard',
    sourceIdentifier: 'dashboard:quarantine-bulk-approve',
    enforceAmber: true,
  }), (req: Request, res: Response) => {
    try {
      const rawIds = req.body?.ids;
      if (!Array.isArray(rawIds) || rawIds.length === 0 || !rawIds.every((id: unknown) => Number.isInteger(id))) {
        return res.status(400).json({ error: 'ids must be a non-empty array of integers' });
      }
      const ids = rawIds as number[];
      const reviewedBy = req.body?.reviewedBy ?? 'dashboard';
      res.json(approveQuarantineItems(ids, reviewedBy));
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/v1/quarantine/bulk-reject', requireNotLocked, requireIronDomeAction({
    action: 'modify_records',
    channel: 'dashboard',
    sourceIdentifier: 'dashboard:quarantine-bulk-reject',
    enforceAmber: true,
  }), (req: Request, res: Response) => {
    try {
      const rawIds = req.body?.ids;
      if (!Array.isArray(rawIds) || rawIds.length === 0 || !rawIds.every((id: unknown) => Number.isInteger(id))) {
        return res.status(400).json({ error: 'ids must be a non-empty array of integers' });
      }
      const ids = rawIds as number[];
      const reviewedBy = req.body?.reviewedBy ?? 'dashboard';
      res.json(rejectQuarantineItems(ids, reviewedBy));
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/quarantine/sync-to-cloud', requireNotLocked, requireIronDomeAction({
    action: 'export_data',
    channel: 'dashboard',
    sourceIdentifier: 'dashboard:quarantine-sync',
  }), async (_req: Request, res: Response) => {
    try {
      const config = getCloudConfig();
      if (!config.cloudEnabled || !config.cloudApiKey) {
        return res.status(400).json({ error: 'Cloud not configured. Enable cloud sync first.' });
      }

      const db = getDatabase();
      const rows = db.prepare('SELECT * FROM quarantine WHERE status = ? ORDER BY created_at ASC')
        .all('pending') as Record<string, unknown>[];

      if (rows.length === 0) {
        return res.json({ synced: 0, message: 'No pending quarantine items to sync.' });
      }

      let synced = 0;
      const errors: string[] = [];
      for (const row of rows) {
        try {
          const indicators: string[] = (() => {
            try { return JSON.parse((row.threat_indicators as string) ?? '[]'); }
            catch { return []; }
          })();

          const response = await fetch(`${config.cloudBaseUrl}/v1/quarantine/ingest`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              Authorization: `Bearer ${config.cloudApiKey}`,
            },
            body: JSON.stringify({
              original_content: row.original_content,
              original_title: row.original_title ?? undefined,
              source_type: row.source_type ?? 'unknown',
              source_identifier: row.source_identifier ?? 'unknown',
              reason: row.reason ?? 'Unknown reason',
              threat_indicators: indicators,
              anomaly_score: row.anomaly_score ?? 0,
              firewall_result: row.firewall_result ?? 'QUARANTINE',
            }),
            signal: AbortSignal.timeout(10_000),
          });

          if (response.ok) {
            synced++;
          } else {
            const body = await response.text().catch(() => '');
            errors.push(`Item ${row.id}: ${response.status} ${body.substring(0, 100)}`);
          }
        } catch (error) {
          errors.push(`Item ${row.id}: ${(error as Error).message}`);
        }
      }

      res.json({ synced, total: rows.length, errors: errors.length > 0 ? errors : undefined });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/worker/status', (_req: Request, res: Response) => {
    try {
      res.json(brainWorker.getStatus());
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/worker/trigger-light', requireNotLocked, requireIronDomeAction({
    action: 'modify_records',
    channel: 'dashboard',
    sourceIdentifier: 'dashboard:worker-trigger-light',
    enforceAmber: true,
  }), async (_req: Request, res: Response) => {
    try {
      const result = await brainWorker.triggerLightTick();
      res.json({ success: true, ...result, timestamp: result.timestamp.toISOString() });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/worker/trigger-medium', requireNotLocked, requireIronDomeAction({
    action: 'modify_records',
    channel: 'dashboard',
    sourceIdentifier: 'dashboard:worker-trigger-medium',
    enforceAmber: true,
  }), async (_req: Request, res: Response) => {
    try {
      const result = await brainWorker.triggerMediumTick();
      res.json({ success: true, ...result, timestamp: result.timestamp.toISOString() });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/license/status', (_req: Request, res: Response) => {
    try {
      const info = getLicense();
      res.json({
        tier: getLicenseTier(),
        valid: info.valid,
        email: info.email,
        expiresAt: info.expiresAt?.toISOString() ?? null,
        daysUntilExpiry: info.daysUntilExpiry,
        teamId: info.teamId,
        // Auto Pro trial retired — field kept (always null) for dashboard compat.
        trial: null,
        features: listFeatures(),
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/license/activate', requireIronDomeAction({
    action: 'modify_config',
    channel: 'dashboard',
    sourceIdentifier: 'dashboard:license-activate',
    enforceAmber: true,
  }), async (req: Request, res: Response) => {
    try {
      const { key } = req.body;
      if (!key || typeof key !== 'string') {
        return res.status(400).json({ error: 'License key is required' });
      }

      const info = activateLicense(key.trim());
      const validationStatus = await validateOnceNow();
      res.json({
        success: true,
        tier: info.tier,
        valid: info.valid,
        email: info.email,
        expiresAt: info.expiresAt?.toISOString() ?? null,
        daysUntilExpiry: info.daysUntilExpiry,
        validationStatus,
        features: listFeatures(),
      });
    } catch (error) {
      res.status(400).json({ error: (error as Error).message });
    }
  });

  app.post('/api/license/deactivate', requireIronDomeAction({
    action: 'modify_config',
    channel: 'dashboard',
    sourceIdentifier: 'dashboard:license-deactivate',
    enforceAmber: true,
  }), (_req: Request, res: Response) => {
    try {
      deactivateLicense();
      res.json({ success: true, tier: 'free', features: listFeatures() });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/firewall-rules', requireProFeature('custom_firewall_rules'), async (_req: Request, res: Response) => {
    try {
      const { listFirewallRules } = await import('../../defence/custom-rules/store.js');
      const rules = listFirewallRules();
      res.json({ rules, total: rules.length });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/firewall-rules', requireProFeature('custom_firewall_rules'), requireIronDomeAction({
    action: 'modify_firewall',
    channel: 'dashboard',
    sourceIdentifier: 'dashboard:firewall-rule-create',
  }), async (req: Request, res: Response) => {
    try {
      const { createFirewallRule } = await import('../../defence/custom-rules/store.js');
      const { name, priority, condition_type, condition_value, action } = req.body;
      if (!name || !condition_type || !condition_value || !action) {
        return res.status(400).json({ error: 'name, condition_type, condition_value, and action are required' });
      }
      const rule = createFirewallRule({ name, priority: priority ?? 100, condition_type, condition_value, action });
      res.status(201).json(rule);
    } catch (error) {
      const msg = (error as Error).message;
      res.status(msg.includes('Maximum') ? 400 : 500).json({ error: msg });
    }
  });

  app.patch('/api/firewall-rules/:id', requireProFeature('custom_firewall_rules'), requireIronDomeAction({
    action: 'modify_firewall',
    channel: 'dashboard',
    sourceIdentifier: 'dashboard:firewall-rule-update',
  }), async (req: Request, res: Response) => {
    try {
      const { updateFirewallRule } = await import('../../defence/custom-rules/store.js');
      const rule = updateFirewallRule(Number(req.params.id), req.body);
      if (!rule) return res.status(404).json({ error: 'Rule not found' });
      res.json(rule);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.delete('/api/firewall-rules/:id', requireProFeature('custom_firewall_rules'), requireIronDomeAction({
    action: 'modify_firewall',
    channel: 'dashboard',
    sourceIdentifier: 'dashboard:firewall-rule-delete',
  }), async (req: Request, res: Response) => {
    try {
      const { deleteFirewallRule } = await import('../../defence/custom-rules/store.js');
      const deleted = deleteFirewallRule(Number(req.params.id));
      if (!deleted) return res.status(404).json({ error: 'Rule not found' });
      res.json({ success: true, id: Number(req.params.id) });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/patterns', requireProFeature('custom_injection_patterns'), async (_req: Request, res: Response) => {
    try {
      const { listCustomPatterns } = await import('../../defence/custom-patterns/store.js');
      const patterns = listCustomPatterns();
      res.json({ patterns, total: patterns.length });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/patterns', requireProFeature('custom_injection_patterns'), requireIronDomeAction({
    action: 'modify_config',
    channel: 'dashboard',
    sourceIdentifier: 'dashboard:pattern-create',
    enforceAmber: true,
  }), async (req: Request, res: Response) => {
    try {
      const { createCustomPattern, validateRegex } = await import('../../defence/custom-patterns/store.js');
      const { name, category, severity, regex, description } = req.body;
      if (!name || !regex) {
        return res.status(400).json({ error: 'name and regex are required' });
      }
      const validation = validateRegex(regex);
      if (!validation.valid) {
        return res.status(400).json({ error: validation.error });
      }
      const pattern = createCustomPattern({
        name,
        category: category || 'custom',
        severity: severity || 'medium',
        regex,
        description,
      });
      res.status(201).json(pattern);
    } catch (error) {
      const msg = (error as Error).message;
      const status = msg.includes('Maximum') || msg.includes('Invalid') || msg.includes('rejected') ? 400 : 500;
      res.status(status).json({ error: msg });
    }
  });

  app.delete('/api/patterns/:id', requireProFeature('custom_injection_patterns'), requireIronDomeAction({
    action: 'modify_config',
    channel: 'dashboard',
    sourceIdentifier: 'dashboard:pattern-delete',
    enforceAmber: true,
  }), async (req: Request, res: Response) => {
    try {
      const { deleteCustomPattern } = await import('../../defence/custom-patterns/store.js');
      const deleted = deleteCustomPattern(Number(req.params.id));
      if (!deleted) return res.status(404).json({ error: 'Pattern not found' });
      res.json({ success: true, id: Number(req.params.id) });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/patterns/:id/test', requireProFeature('custom_injection_patterns'), async (req: Request, res: Response) => {
    try {
      const { testPattern } = await import('../../defence/custom-patterns/store.js');
      const { text } = req.body;
      if (!text) return res.status(400).json({ error: 'text is required' });
      res.json(testPattern(Number(req.params.id), text));
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/iron-dome/policies', requireProFeature('custom_iron_dome_policies'), async (_req: Request, res: Response) => {
    try {
      const { listIronDomePolicies } = await import('../../defence/iron-dome/custom-policies.js');
      const policies = listIronDomePolicies();
      res.json({ policies, total: policies.length });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/iron-dome/policies', requireProFeature('custom_iron_dome_policies'), requireIronDomeAction({
    action: 'modify_config',
    channel: 'dashboard',
    sourceIdentifier: 'dashboard:iron-dome-policy-create',
    enforceAmber: true,
  }), async (req: Request, res: Response) => {
    try {
      const { createIronDomePolicy } = await import('../../defence/iron-dome/custom-policies.js');
      const { name, description, config } = req.body;
      if (!name) return res.status(400).json({ error: 'name is required' });
      res.status(201).json(createIronDomePolicy({ name, description, config: config || {} }));
    } catch (error) {
      const msg = (error as Error).message;
      res.status(msg.includes('Maximum') ? 400 : 500).json({ error: msg });
    }
  });

  app.delete('/api/iron-dome/policies/:id', requireProFeature('custom_iron_dome_policies'), requireIronDomeAction({
    action: 'modify_config',
    channel: 'dashboard',
    sourceIdentifier: 'dashboard:iron-dome-policy-delete',
    enforceAmber: true,
  }), async (req: Request, res: Response) => {
    try {
      const { deleteIronDomePolicy } = await import('../../defence/iron-dome/custom-policies.js');
      const deleted = deleteIronDomePolicy(Number(req.params.id));
      if (!deleted) return res.status(404).json({ error: 'Policy not found' });
      res.json({ success: true, id: Number(req.params.id) });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.put('/api/iron-dome/policies/:id/activate', requireProFeature('custom_iron_dome_policies'), requireIronDomeAction({
    action: 'modify_config',
    channel: 'dashboard',
    sourceIdentifier: 'dashboard:iron-dome-policy-activate',
    enforceAmber: true,
  }), async (req: Request, res: Response) => {
    try {
      const { activateIronDomePolicy } = await import('../../defence/iron-dome/custom-policies.js');
      const policy = activateIronDomePolicy(Number(req.params.id));
      if (!policy) return res.status(404).json({ error: 'Policy not found' });
      res.json(policy);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/audit/export', requireProFeature('audit_export'), async (req: Request, res: Response) => {
    try {
      const { exportAuditJSON, exportAuditCSV } = await import('../../defence/audit/export.js');
      const format = (req.query.format as string) || 'json';
      const startTime = req.query.startTime as string | undefined;
      const endTime = req.query.endTime as string | undefined;

      if (format === 'csv') {
        const csv = exportAuditCSV(startTime, endTime);
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="shieldcortex-audit-${Date.now()}.csv"`);
        return res.send(csv);
      }

      const json = exportAuditJSON(startTime, endTime);
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="shieldcortex-audit-${Date.now()}.json"`);
      res.send(json);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/skills/deep-scan', requireProFeature('skill_scanner_deep'), async (req: Request, res: Response) => {
    try {
      const { runDeepScan } = await import('../../defence/skill-scanner/deep-scan.js');
      const { files } = req.body;
      if (!files || !Array.isArray(files) || files.length === 0) {
        return res.status(400).json({ error: 'files array is required (each with name and content)' });
      }
      res.json(await runDeepScan(files));
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });
}
