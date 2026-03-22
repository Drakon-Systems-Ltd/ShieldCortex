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
import { getLicense, getLicenseTier, getTrialStatus, activateLicense, deactivateLicense } from '../../license/store.js';
import { listFeatures } from '../../license/gate.js';
import type { GatedFeature } from '../../license/gate.js';
import { validateOnceNow } from '../../license/validate.js';
import type { BrainWorker } from '../../worker/brain-worker.js';
import type { IronDomeRouteGuardOptions, Middleware as IronDomeMiddleware } from '../iron-dome-route-guard.js';
import { existsSync } from 'fs';
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

export function registerAdminRoutes(app: Express, deps: AdminRouteDeps): void {
  const { brainWorker, requireNotLocked, requireProFeature, requireIronDomeAction } = deps;

  app.get('/api/v1/audit', (req: Request, res: Response) => {
    try {
      const options: Record<string, unknown> = {};
      if (req.query.startTime) options.startTime = req.query.startTime;
      if (req.query.endTime) options.endTime = req.query.endTime;
      if (req.query.source) options.source = req.query.source;
      if (req.query.firewallResult) options.firewallResult = req.query.firewallResult;
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
      const status = req.query.status ?? 'pending';
      const limit = parseInt(req.query.limit as string, 10) || 50;
      const project = req.query.project as string | undefined;
      const sql = project
        ? 'SELECT * FROM quarantine WHERE status = ? AND project = ? ORDER BY created_at DESC LIMIT ?'
        : 'SELECT * FROM quarantine WHERE status = ? ORDER BY created_at DESC LIMIT ?';
      const params = project ? [status, project, limit] : [status, limit];
      const rows = db.prepare(sql).all(...params) as Record<string, unknown>[];
      res.json({
        items: rows.map((row) => ({
          ...row,
          title: row.original_title,
          content: row.original_content,
        })),
        total: rows.length,
      });
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
      const ids: number[] = req.body?.ids;
      if (!Array.isArray(ids) || ids.length === 0) {
        return res.status(400).json({ error: 'ids must be a non-empty array of numbers' });
      }
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
      const ids: number[] = req.body?.ids;
      if (!Array.isArray(ids) || ids.length === 0) {
        return res.status(400).json({ error: 'ids must be a non-empty array of numbers' });
      }
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
      const licenseFile = join(process.env.SHIELDCORTEX_CONFIG_DIR || join(homedir(), '.shieldcortex'), 'license.json');
      const trial = getTrialStatus(existsSync(licenseFile));
      res.json({
        tier: getLicenseTier(),
        valid: info.valid,
        email: info.email,
        expiresAt: info.expiresAt?.toISOString() ?? null,
        daysUntilExpiry: info.daysUntilExpiry,
        teamId: info.teamId,
        trial: trial
          ? {
              active: trial.active,
              daysRemaining: trial.daysRemaining,
              expiresAt: trial.expiresAt,
            }
          : null,
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
