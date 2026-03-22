import type { Express, Request, Response } from 'express';
import { WebSocket } from 'ws';
import type { MemoryEvent } from '../events.js';
import { getLifetimeStats } from '../../defence/audit/queries.js';
import { getAuditStats } from '../../defence/audit/queries.js';
import { isDatabaseInitialized } from '../../database/init.js';
import {
  getCloudConfig,
  getCloudSyncControls,
  getDeviceId,
  getDeviceName,
  getDefenceMode,
  getOpenClawMemoryConfig,
  isConfigTampered,
  readRawConfig,
  setCloudConfig,
  setCloudSyncControls,
  setDefenceMode,
  setOpenClawMemoryConfig,
  type DefenceMode,
} from '../../cloud/config.js';
import { getQueueStats } from '../../cloud/sync-queue.js';
import { getDatabase } from '../../database/init.js';
import { getRequiredTier, isFeatureEnabled } from '../../license/gate.js';
import { getLicense } from '../../license/store.js';
import { getTrialStatus } from '../../license/trial.js';
import { existsSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { getControlStatus, isKillSwitchActive, pause, resume } from '../control.js';
import {
  checkForUpdates,
  getCurrentVersion,
  getRunningVersion,
  performUpdate,
  scheduleRestart,
} from '../version.js';
import type { IronDomeRouteGuardOptions, Middleware as IronDomeMiddleware } from '../iron-dome-route-guard.js';

interface SystemRouteDeps {
  broadcast: (event: MemoryEvent) => void;
  clients: Set<WebSocket>;
  requireIronDomeAction: (options: IronDomeRouteGuardOptions) => IronDomeMiddleware;
}

export function registerSystemRoutes(app: Express, deps: SystemRouteDeps): void {
  const { broadcast, clients, requireIronDomeAction } = deps;

  app.get('/api/system/status', (_req: Request, res: Response) => {
    try {
      const licenseFile = join(homedir(), '.shieldcortex', 'license.json');
      const licenseFileExists = existsSync(licenseFile);
      const license = getLicense();
      const trial = getTrialStatus(licenseFileExists);

      const trialInfo = trial
        ? {
            active: trial.active,
            daysRemaining: trial.daysRemaining,
            expiresAt: trial.expiresAt.slice(0, 10), // YYYY-MM-DD
          }
        : null;

      // Stats (best effort — never fail the status endpoint)
      let stats: Record<string, unknown> | null = null;
      try {
        if (isDatabaseInitialized()) {
          const lifetime = getLifetimeStats();
          const h24  = getAuditStats('24h');
          const d7   = getAuditStats('7d');
          stats = {
            lifetime: {
              totalScans:         lifetime.totalScans,
              threatsBlocked:     lifetime.threatsBlocked,
              quarantined:        lifetime.quarantined,
              credentialLeaks:    lifetime.credentialLeaks,
              memoriesProtected:  lifetime.memoriesProtected,
            },
            last24h: {
              totalScans:  h24.totalOperations,
              blocked:     h24.blockedCount,
              quarantined: h24.quarantinedCount,
            },
            last7d: {
              totalScans:  d7.totalOperations,
              blocked:     d7.blockedCount,
              quarantined: d7.quarantinedCount,
            },
          };
        }
      } catch {
        // Stats unavailable — still return the rest of the status
      }

      res.json({
        tier: license.valid ? license.tier : (trial?.active ? 'pro' : 'free'),
        licenseValid: license.valid,
        trial: trialInfo,
        ...(stats ? { stats } : {}),
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/control/status', (_req: Request, res: Response) => {
    try {
      res.json(getControlStatus());
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/control/pause', (_req: Request, res: Response) => {
    try {
      if (isKillSwitchActive()) {
        return res.status(409).json({ error: 'Kill switch is active — use /api/iron-dome/resume to deactivate first', code: 'KILL_SWITCH_ACTIVE' });
      }
      pause();
      res.json({ paused: true, message: 'Memory creation paused' });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/control/resume', (_req: Request, res: Response) => {
    try {
      if (isKillSwitchActive()) {
        return res.status(409).json({ error: 'Kill switch is active — use /api/iron-dome/resume to deactivate first', code: 'KILL_SWITCH_ACTIVE' });
      }
      resume();
      res.json({ paused: false, message: 'Memory creation resumed' });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/cloud/config', (_req: Request, res: Response) => {
    try {
      const config = getCloudConfig();
      res.json({
        enabled: config.cloudEnabled,
        apiKeySet: !!config.cloudApiKey,
        baseUrl: config.cloudBaseUrl,
        syncControls: getCloudSyncControls(),
        openclawMemory: getOpenClawMemoryConfig(),
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/cloud/config', requireIronDomeAction({
    action: 'modify_config',
    channel: 'dashboard',
    sourceIdentifier: 'dashboard:cloud-config',
    enforceAmber: true,
  }), (req: Request, res: Response) => {
    try {
      const existingConfig = getCloudConfig();
      const {
        cloudApiKey,
        cloudEnabled,
        cloudBaseUrl,
        cloudSyncProjectMode,
        cloudSyncProjects,
        cloudSyncContentMode,
        cloudSyncExcludeSensitive,
        openclawAutoMemory,
        openclawAutoMemoryDedupe,
        openclawAutoMemoryNoveltyThreshold,
        openclawAutoMemoryMaxRecent,
      } = req.body;

      if (cloudApiKey !== undefined && typeof cloudApiKey !== 'string') {
        return res.status(400).json({ error: 'cloudApiKey must be a string' });
      }
      if (cloudEnabled !== undefined && typeof cloudEnabled !== 'boolean') {
        return res.status(400).json({ error: 'cloudEnabled must be a boolean' });
      }
      if (cloudBaseUrl !== undefined && typeof cloudBaseUrl !== 'string') {
        return res.status(400).json({ error: 'cloudBaseUrl must be a string' });
      }
      if (openclawAutoMemory !== undefined && typeof openclawAutoMemory !== 'boolean') {
        return res.status(400).json({ error: 'openclawAutoMemory must be a boolean' });
      }
      if (openclawAutoMemoryDedupe !== undefined && typeof openclawAutoMemoryDedupe !== 'boolean') {
        return res.status(400).json({ error: 'openclawAutoMemoryDedupe must be a boolean' });
      }
      if (
        openclawAutoMemoryNoveltyThreshold !== undefined &&
        (typeof openclawAutoMemoryNoveltyThreshold !== 'number' || Number.isNaN(openclawAutoMemoryNoveltyThreshold))
      ) {
        return res.status(400).json({ error: 'openclawAutoMemoryNoveltyThreshold must be a number' });
      }
      if (
        openclawAutoMemoryMaxRecent !== undefined &&
        (typeof openclawAutoMemoryMaxRecent !== 'number' || Number.isNaN(openclawAutoMemoryMaxRecent))
      ) {
        return res.status(400).json({ error: 'openclawAutoMemoryMaxRecent must be a number' });
      }
      if (
        cloudSyncProjectMode !== undefined &&
        cloudSyncProjectMode !== 'all' &&
        cloudSyncProjectMode !== 'include' &&
        cloudSyncProjectMode !== 'exclude'
      ) {
        return res.status(400).json({ error: 'cloudSyncProjectMode must be all, include, or exclude' });
      }
      if (
        cloudSyncContentMode !== undefined &&
        cloudSyncContentMode !== 'full' &&
        cloudSyncContentMode !== 'metadata'
      ) {
        return res.status(400).json({ error: 'cloudSyncContentMode must be full or metadata' });
      }
      if (
        cloudSyncExcludeSensitive !== undefined &&
        typeof cloudSyncExcludeSensitive !== 'boolean'
      ) {
        return res.status(400).json({ error: 'cloudSyncExcludeSensitive must be a boolean' });
      }
      if (
        cloudSyncProjects !== undefined &&
        (!Array.isArray(cloudSyncProjects) || cloudSyncProjects.some((value) => typeof value !== 'string'))
      ) {
        return res.status(400).json({ error: 'cloudSyncProjects must be an array of strings' });
      }

      const normalizedApiKey =
        cloudApiKey !== undefined
          ? cloudApiKey.trim()
          : existingConfig.cloudApiKey;
      const normalizedBaseUrl =
        cloudBaseUrl !== undefined
          ? cloudBaseUrl.trim()
          : existingConfig.cloudBaseUrl;
      let normalizedProjects: string[] | undefined;
      if (cloudSyncProjects !== undefined) {
        const projectValues = cloudSyncProjects as string[];
        normalizedProjects = Array.from(
          new Set(
            projectValues
              .map((value) => value.trim())
              .filter((value) => value.length > 0),
          ),
        ).sort((a, b) => a.localeCompare(b));
      }

      if (cloudEnabled === true && !normalizedApiKey) {
        return res.status(400).json({ error: 'Cloud API key required before enabling cloud sync' });
      }

      try {
        new URL(normalizedBaseUrl);
      } catch {
        return res.status(400).json({ error: 'cloudBaseUrl must be a valid absolute URL' });
      }

      setCloudConfig({
        ...(cloudApiKey !== undefined && { cloudApiKey: normalizedApiKey }),
        ...(cloudEnabled !== undefined && { cloudEnabled }),
        ...(cloudBaseUrl !== undefined && { cloudBaseUrl: normalizedBaseUrl }),
      });

      setCloudSyncControls({
        ...(cloudSyncProjectMode !== undefined && { projectMode: cloudSyncProjectMode }),
        ...(normalizedProjects !== undefined && { projects: normalizedProjects }),
        ...(cloudSyncContentMode !== undefined && { contentMode: cloudSyncContentMode }),
        ...(cloudSyncExcludeSensitive !== undefined && { excludeSensitive: cloudSyncExcludeSensitive }),
      });

      setOpenClawMemoryConfig({
        ...(openclawAutoMemory !== undefined && { autoMemory: openclawAutoMemory }),
        ...(openclawAutoMemoryDedupe !== undefined && { dedupe: openclawAutoMemoryDedupe }),
        ...(openclawAutoMemoryNoveltyThreshold !== undefined && { noveltyThreshold: openclawAutoMemoryNoveltyThreshold }),
        ...(openclawAutoMemoryMaxRecent !== undefined && { maxRecent: openclawAutoMemoryMaxRecent }),
      });

      const updated = getCloudConfig();
      res.json({
        success: true,
        enabled: updated.cloudEnabled,
        apiKeySet: !!updated.cloudApiKey,
        baseUrl: updated.cloudBaseUrl,
        syncControls: getCloudSyncControls(),
        openclawMemory: getOpenClawMemoryConfig(),
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/defence/config', (_req: Request, res: Response) => {
    try {
      res.json({ mode: getDefenceMode(), tampered: isConfigTampered() });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/defence/config', requireIronDomeAction({
    action: 'modify_config',
    channel: 'dashboard',
    sourceIdentifier: 'dashboard:defence-config',
    enforceAmber: true,
  }), (req: Request, res: Response) => {
    try {
      const { mode } = req.body;
      const validModes: DefenceMode[] = ['strict', 'balanced', 'permissive'];
      if (!mode || !validModes.includes(mode)) {
        return res.status(400).json({ error: `Invalid mode. Must be one of: ${validModes.join(', ')}` });
      }
      setDefenceMode(mode);
      res.json({ success: true, mode });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/cloud/sync-status', (_req: Request, res: Response) => {
    try {
      const config = getCloudConfig();
      const raw = readRawConfig();
      const queue = getQueueStats();

      res.json({
        enabled: config.cloudEnabled,
        apiKeySet: !!config.cloudApiKey,
        baseUrl: config.cloudBaseUrl,
        featureEnabled: isFeatureEnabled('cloud_sync'),
        requiredTier: getRequiredTier('cloud_sync'),
        controls: getCloudSyncControls(),
        lastSyncAt: (typeof raw.lastSyncAt === 'string' ? raw.lastSyncAt : null) as string | null,
        device: {
          id: getDeviceId(),
          name: getDeviceName(),
          platform: `${process.platform}/${process.arch}`,
        },
        queue: {
          pending: queue.pending,
          failed: queue.failed,
          synced: queue.synced,
          byKind: queue.byKind,
          oldestPendingAt: queue.oldestPendingAt,
          nextRetryAt: queue.nextRetryAt,
          lastError: queue.lastError,
          lastErrorKind: queue.lastErrorKind,
          latestFailureAt: queue.latestFailureAt,
        },
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/cloud/projects', (_req: Request, res: Response) => {
    try {
      const db = getDatabase();
      const rows = db.prepare(`
        SELECT project, COUNT(*) as count
        FROM memories
        WHERE project IS NOT NULL AND TRIM(project) != ''
        GROUP BY project
        ORDER BY count DESC, project ASC
      `).all() as Array<{ project: string; count: number }>;

      res.json({
        projects: rows.map((row) => ({
          project: row.project,
          count: Number(row.count ?? 0),
        })),
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/version', (_req: Request, res: Response) => {
    try {
      const version = getCurrentVersion();
      const runningVersion = getRunningVersion();
      res.json({ version, runningVersion, stale: runningVersion !== version });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/version/check', async (req: Request, res: Response) => {
    try {
      res.json(await checkForUpdates(req.query.force === 'true'));
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/version/update', requireIronDomeAction({
    action: 'update_package',
    channel: 'dashboard',
    sourceIdentifier: 'dashboard:version-update',
    enforceAmber: true,
  }), async (_req: Request, res: Response) => {
    try {
      broadcast({
        type: 'update_started',
        timestamp: new Date().toISOString(),
        data: { message: 'Update in progress...' },
      } as MemoryEvent);

      const result = await performUpdate();

      broadcast({
        type: result.success ? 'update_complete' : 'update_failed',
        timestamp: new Date().toISOString(),
        data: result,
      } as MemoryEvent);

      res.json(result);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/version/restart', requireIronDomeAction({
    action: 'restart_service',
    channel: 'dashboard',
    sourceIdentifier: 'dashboard:version-restart',
    enforceAmber: true,
  }), (_req: Request, res: Response) => {
    try {
      broadcast({
        type: 'server_restarting',
        timestamp: new Date().toISOString(),
        data: { message: 'Server restarting in 3 seconds...' },
      } as MemoryEvent);

      for (const client of clients) {
        try {
          if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({
              type: 'server_restarting',
              timestamp: new Date().toISOString(),
              data: { reconnectIn: 5000 },
            }));
          }
        } catch (error) {
          console.error('[shieldcortex] WebSocket send failed during restart:', error);
        }
      }

      res.json({ success: true, message: 'Server will restart in 3 seconds' });
      scheduleRestart(3000);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });
}
