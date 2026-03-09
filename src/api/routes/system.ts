import type { Express, Request, Response } from 'express';
import { WebSocket } from 'ws';
import type { MemoryEvent } from '../events.js';
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
import { getControlStatus, isKillSwitchActive, pause, resume } from '../control.js';
import {
  checkForUpdates,
  getCurrentVersion,
  getRunningVersion,
  performUpdate,
  scheduleRestart,
} from '../version.js';

interface SystemRouteDeps {
  broadcast: (event: MemoryEvent) => void;
  clients: Set<WebSocket>;
}

export function registerSystemRoutes(app: Express, deps: SystemRouteDeps): void {
  const { broadcast, clients } = deps;

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

  app.post('/api/cloud/config', (req: Request, res: Response) => {
    try {
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

      setCloudConfig({
        ...(cloudApiKey !== undefined && { cloudApiKey }),
        ...(cloudEnabled !== undefined && { cloudEnabled }),
        ...(cloudBaseUrl !== undefined && { cloudBaseUrl }),
      });

      setCloudSyncControls({
        ...(cloudSyncProjectMode !== undefined && { projectMode: cloudSyncProjectMode }),
        ...(cloudSyncProjects !== undefined && { projects: cloudSyncProjects }),
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

  app.post('/api/defence/config', (req: Request, res: Response) => {
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

  app.post('/api/version/update', async (_req: Request, res: Response) => {
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

  app.post('/api/version/restart', (_req: Request, res: Response) => {
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
