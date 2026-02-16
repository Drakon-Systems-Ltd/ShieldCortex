/**
 * Visualization API Server
 *
 * Provides REST endpoints and WebSocket for the Brain Dashboard.
 * Runs alongside or instead of the MCP server.
 */

import express, { Request, Response } from 'express';
import cors from 'cors';
import { createServer } from 'http';
import { existsSync, unlinkSync } from 'fs';
import { homedir } from 'os';
import { generateSessionToken, cleanupSessionToken, validateSessionToken, getSessionToken } from './session-token.js';
import { WebSocketServer, WebSocket } from 'ws';
import { getDatabase, initDatabase, checkpointWal } from '../database/init.js';
import { Memory, MemoryConfig, DEFAULT_CONFIG } from '../memory/types.js';
import {
  searchMemories,
  getRecentMemories,
  getHighPriorityMemories,
  getMemoryStats,
  getMemoryById,
  addMemory,
  deleteMemory,
  accessMemory,
  updateDecayScores,
  updateMemory,
  promoteMemory,
  createMemoryLink,
  rowToMemory,
} from '../memory/store.js';
import {
  consolidate,
  generateContextSummary,
  formatContextSummary,
} from '../memory/consolidate.js';
import { calculateDecayedScore } from '../memory/decay.js';
import { getActivationStats, getActiveMemories } from '../memory/activation.js';
import { detectContradictions, getContradictionsFor } from '../memory/contradiction.js';
import { enrichMemory } from '../memory/store.js';
import {
  memoryEvents,
  MemoryEvent,
  emitDecayTick,
  emitConsolidation,
  getUnprocessedEvents,
  markEventsProcessed,
  cleanupOldEvents,
} from './events.js';
import { BrainWorker } from '../worker/brain-worker.js';
import { isPaused, pause, resume, getControlStatus } from './control.js';
import { getCurrentVersion, getRunningVersion, checkForUpdates, performUpdate, scheduleRestart } from './version.js';
import { runDefencePipeline } from '../defence/pipeline.js';
import { DEFAULT_DEFENCE_CONFIG } from '../defence/types.js';
import type { DefenceSource, DefenceConfig } from '../defence/types.js';
import { queryAuditLogs, getAuditStats, queryAgentRegistry, queryAgentTimeline, queryAgentOperations } from '../defence/audit/queries.js';
import { logAudit } from '../defence/audit/index.js';
import { getCloudConfig, setCloudConfig, readRawConfig, getTrustedSkills, addTrustedSkill, removeTrustedSkill, getDeviceId, getDeviceName, getDefenceMode, setDefenceMode, isConfigTampered, type DefenceMode } from '../cloud/config.js';
import { getQueueStats } from '../cloud/sync-queue.js';
import { scanSkill, scanSkillContent, discoverSkillFiles } from '../defence/skill-scanner/index.js';

const PORT = process.env.PORT || 3001;

// Track connected WebSocket clients
const clients = new Set<WebSocket>();

/**
 * Start the visualization API server
 */
export function startVisualizationServer(dbPath?: string): void {
  // Initialize database
  initDatabase(dbPath || DEFAULT_CONFIG.dbPath);

  const app = express();
  const server = createServer(app);

  // Middleware — CORS restricted to localhost by default
  const allowedOrigins = process.env.CORTEX_CORS_ORIGINS
    ? process.env.CORTEX_CORS_ORIGINS.split(',').map(s => s.trim())
    : ['http://localhost:3030', 'http://localhost:3000', 'http://127.0.0.1:3030', 'http://127.0.0.1:3000'];

  app.use(cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (curl, server-to-server, same-origin)
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error(`Origin ${origin} not allowed by CORS`));
      }
    },
  }));
  app.use(express.json());

  // ── Session Auth ────────────────────────────────────────
  // Generate per-session token (written to ~/.shieldcortex/.api-token)
  generateSessionToken();

  // Auth middleware: require Bearer token on all mutating requests
  app.use((req: Request, res: Response, next) => {
    // Allow GET, OPTIONS, HEAD — read-only
    if (['GET', 'OPTIONS', 'HEAD'].includes(req.method)) {
      return next();
    }
    // Allow the one-time token claim endpoint without auth
    if (req.path === '/api/auth/session-token') {
      return next();
    }
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ error: 'Unauthorized', code: 'AUTH_REQUIRED' });
      return;
    }
    const token = authHeader.slice(7);
    if (!validateSessionToken(token)) {
      res.status(401).json({ error: 'Invalid token', code: 'AUTH_INVALID' });
      return;
    }
    next();
  });

  // Token handshake — dashboard claims on load (survives page refresh)
  app.get('/api/auth/session-token', (_req: Request, res: Response) => {
    const token = getSessionToken();
    if (!token) {
      res.status(500).json({ error: 'No session token available' });
      return;
    }
    res.json({ token });
  });

  // ============================================
  // REST API ENDPOINTS
  // ============================================

  // Health check
  app.get('/api/health', (_req: Request, res: Response) => {
    const version = getRunningVersion();
    res.json({ status: 'ok', timestamp: new Date().toISOString(), version });
  });

  // Get all memories with filters and pagination
  app.get('/api/memories', async (req: Request, res: Response) => {
    try {
      // Extract query params as strings
      const project = typeof req.query.project === 'string' ? req.query.project : undefined;
      const type = typeof req.query.type === 'string' ? req.query.type : undefined;
      const category = typeof req.query.category === 'string' ? req.query.category : undefined;
      const limitStr = typeof req.query.limit === 'string' ? req.query.limit : '50';
      const offsetStr = typeof req.query.offset === 'string' ? req.query.offset : '0';
      const mode = typeof req.query.mode === 'string' ? req.query.mode : 'recent';
      const query = typeof req.query.query === 'string' ? req.query.query : undefined;

      const limit = Math.min(parseInt(limitStr, 10) || 50, 1000); // Cap at 1000, default 50
      const offset = parseInt(offsetStr, 10) || 0; // Default 0

      let memories: Memory[];

      if (mode === 'search' && query) {
        const results = await searchMemories({
          query,
          project,
          type: type as Memory['type'] | undefined,
          category: category as Memory['category'] | undefined,
          limit: limit + offset + 1, // Fetch extra to check hasMore
        });
        memories = results.map(r => r.memory);
      } else if (mode === 'important') {
        memories = getHighPriorityMemories(limit + offset + 1, project);
      } else {
        memories = getRecentMemories(limit + offset + 1, project);
      }

      // Filter by type and category if provided
      if (type) {
        memories = memories.filter(m => m.type === type);
      }
      if (category) {
        memories = memories.filter(m => m.category === category);
      }

      // Get total count for pagination
      const stats = getMemoryStats(project);
      const total = stats.total;

      // Apply pagination
      const hasMore = memories.length > offset + limit;
      const paginatedMemories = memories.slice(offset, offset + limit);

      // Add computed decayed score to each memory
      const memoriesWithDecay = paginatedMemories.map(m => ({
        ...m,
        decayedScore: calculateDecayedScore(m),
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

  // Activity data for heatmap (must be before :id route)
  app.get('/api/memories/activity', (req: Request, res: Response) => {
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

  // Memory quality analysis (must be before :id route)
  app.get('/api/memories/quality', (req: Request, res: Response) => {
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

  // Get single memory by ID
  app.get('/api/memories/:id', (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id as string);
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

  // Create memory
  app.post('/api/memories', (req: Request, res: Response) => {
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
      // Handle paused state gracefully
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

  // Delete memory
  app.delete('/api/memories/:id', (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id as string);
      const success = deleteMemory(id);
      if (!success) {
        return res.status(404).json({ error: 'Memory not found' });
      }
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Access/reinforce memory
  app.post('/api/memories/:id/access', (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id as string);
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

  // Get statistics
  app.get('/api/stats', (req: Request, res: Response) => {
    try {
      const project = typeof req.query.project === 'string' ? req.query.project : undefined;
      const stats = getMemoryStats(project);

      // Add decay distribution
      const db = getDatabase();
      const rawRows = db.prepare(
        project
          ? 'SELECT * FROM memories WHERE project = ?'
          : 'SELECT * FROM memories'
      ).all(project ? [project] : []) as Record<string, unknown>[];

      // Convert raw DB rows to Memory objects (snake_case -> camelCase)
      const allMemories = rawRows.map(rowToMemory);

      const decayDistribution = {
        healthy: 0,  // > 0.35 (realistic given base salience 0.25 + access bonus)
        fading: 0,   // 0.2 - 0.35
        critical: 0, // < 0.2 (approaching deletion threshold)
      };

      for (const m of allMemories) {
        const score = calculateDecayedScore(m);
        if (score > 0.35) decayDistribution.healthy++;
        else if (score > 0.2) decayDistribution.fading++;
        else decayDistribution.critical++;
      }

      // Get spreading activation stats (Phase 2 organic feature)
      const activationStats = getActivationStats();

      res.json({
        ...stats,
        decayDistribution,
        activation: activationStats,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Get currently activated memories (spreading activation)
  app.get('/api/activation', (_req: Request, res: Response) => {
    try {
      const activeMemories = getActiveMemories();
      const stats = getActivationStats();

      res.json({
        activeMemories,
        stats,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // ============================================
  // ORGANIC BRAIN ENDPOINTS (Phase 3)
  // ============================================

  // Get detected contradictions
  app.get('/api/contradictions', (req: Request, res: Response) => {
    try {
      const project = typeof req.query.project === 'string' ? req.query.project : undefined;
      const category = typeof req.query.category === 'string' ? req.query.category : undefined;
      const minScoreStr = typeof req.query.minScore === 'string' ? req.query.minScore : '0.4';
      const limitStr = typeof req.query.limit === 'string' ? req.query.limit : '20';

      const minScore = parseFloat(minScoreStr) || 0.4; // Default 0.4
      const limit = parseInt(limitStr, 10) || 20; // Default 20

      const contradictions = detectContradictions({
        project,
        category: category as Memory['category'] | undefined,
        minScore,
        limit,
      });

      res.json({
        contradictions: contradictions.map(c => ({
          memoryAId: c.memoryA.id,
          memoryATitle: c.memoryA.title,
          memoryBId: c.memoryB.id,
          memoryBTitle: c.memoryB.title,
          score: c.score,
          reason: c.reason,
          sharedTopics: c.sharedTopics,
        })),
        count: contradictions.length,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Get contradictions for a specific memory
  app.get('/api/memories/:id/contradictions', (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id as string);
      if (isNaN(id)) {
        return res.status(400).json({ error: 'Invalid memory ID' });
      }

      const contradictions = getContradictionsFor(id);

      res.json({
        memoryId: id,
        contradictions: contradictions.map(c => ({
          contradictingMemoryId: c.memoryB.id,
          contradictingMemoryTitle: c.memoryB.title,
          score: c.score,
          reason: c.reason,
          sharedTopics: c.sharedTopics,
        })),
        count: contradictions.length,
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Manually enrich a memory with new context
  app.post('/api/memories/:id/enrich', (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id as string);
      if (isNaN(id)) {
        return res.status(400).json({ error: 'Invalid memory ID' });
      }

      const { context, contextType } = req.body;
      if (!context || typeof context !== 'string') {
        return res.status(400).json({ error: 'Context string required in request body' });
      }

      const validTypes = ['search', 'access', 'related'];
      const type = validTypes.includes(contextType) ? contextType : 'access';

      const result = enrichMemory(id, context, type);
      res.json(result);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Get list of all projects
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

      // Add "All Projects" option with total count
      const totalCount = db.prepare('SELECT COUNT(*) as count FROM memories').get() as { count: number };

      res.json({
        projects: [
          { project: null, memory_count: totalCount.count, label: 'All Projects' },
          ...projects.map(p => ({ ...p, label: p.project })),
        ],
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // ============================================
  // CONTROL ENDPOINTS
  // ============================================

  // Get control status
  app.get('/api/control/status', (_req: Request, res: Response) => {
    try {
      const status = getControlStatus();
      res.json(status);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Pause memory creation
  app.post('/api/control/pause', (_req: Request, res: Response) => {
    try {
      pause();
      res.json({ paused: true, message: 'Memory creation paused' });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Resume memory creation
  app.post('/api/control/resume', (_req: Request, res: Response) => {
    try {
      resume();
      res.json({ paused: false, message: 'Memory creation resumed' });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // ============================================
  // CLOUD CONFIG ENDPOINTS
  // ============================================

  // Get cloud configuration status
  app.get('/api/cloud/config', (_req: Request, res: Response) => {
    try {
      const config = getCloudConfig();
      res.json({
        enabled: config.cloudEnabled,
        apiKeySet: !!config.cloudApiKey,
        baseUrl: config.cloudBaseUrl,
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Update cloud configuration
  app.post('/api/cloud/config', (req: Request, res: Response) => {
    try {
      const { cloudApiKey, cloudEnabled, cloudBaseUrl } = req.body;
      setCloudConfig({
        ...(cloudApiKey !== undefined && { cloudApiKey }),
        ...(cloudEnabled !== undefined && { cloudEnabled }),
        ...(cloudBaseUrl !== undefined && { cloudBaseUrl }),
      });
      const updated = getCloudConfig();
      res.json({
        success: true,
        enabled: updated.cloudEnabled,
        apiKeySet: !!updated.cloudApiKey,
        baseUrl: updated.cloudBaseUrl,
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // ============================================
  // DEFENCE CONFIG ENDPOINTS
  // ============================================

  // Get defence configuration (firewall mode + integrity status)
  app.get('/api/defence/config', (_req: Request, res: Response) => {
    try {
      res.json({ mode: getDefenceMode(), tampered: isConfigTampered() });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Update defence configuration (firewall mode)
  app.post('/api/defence/config', (req: Request, res: Response) => {
    try {
      const { mode } = req.body;
      const validModes: DefenceMode[] = ['strict', 'balanced', 'permissive'];
      if (!mode || !validModes.includes(mode)) {
        res.status(400).json({ error: `Invalid mode. Must be one of: ${validModes.join(', ')}` });
        return;
      }
      setDefenceMode(mode);
      res.json({ success: true, mode });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Get cloud sync status (queue stats + config)
  app.get('/api/cloud/sync-status', (_req: Request, res: Response) => {
    try {
      const config = getCloudConfig();
      const raw = readRawConfig();
      const queue = getQueueStats();

      res.json({
        enabled: config.cloudEnabled,
        apiKeySet: !!config.cloudApiKey,
        lastSyncAt: (typeof raw.lastSyncAt === 'string' ? raw.lastSyncAt : null) as string | null,
        queue: {
          pending: queue.pending,
          failed: queue.failed,
        },
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // ============================================
  // VERSION ENDPOINTS
  // ============================================

  // Get current version (with stale detection)
  app.get('/api/version', (_req: Request, res: Response) => {
    try {
      const version = getCurrentVersion();
      const runningVersion = getRunningVersion();
      res.json({ version, runningVersion, stale: runningVersion !== version });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Check for updates
  app.get('/api/version/check', async (req: Request, res: Response) => {
    try {
      const forceRefresh = req.query.force === 'true';
      const versionInfo = await checkForUpdates(forceRefresh);
      res.json(versionInfo);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Perform update
  app.post('/api/version/update', async (_req: Request, res: Response) => {
    try {
      // Notify clients that update is starting
      broadcast({
        type: 'update_started',
        timestamp: new Date().toISOString(),
        data: { message: 'Update in progress...' },
      } as MemoryEvent);

      const result = await performUpdate();

      // Notify clients of result
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

  // Restart server
  app.post('/api/version/restart', (_req: Request, res: Response) => {
    try {
      // Notify all WebSocket clients
      broadcast({
        type: 'server_restarting',
        timestamp: new Date().toISOString(),
        data: { message: 'Server restarting in 3 seconds...' },
      } as MemoryEvent);

      // Close WebSocket connections gracefully
      for (const client of clients) {
        try {
          if (client.readyState === WebSocket.OPEN) {
            client.send(
              JSON.stringify({
                type: 'server_restarting',
                timestamp: new Date().toISOString(),
                data: { reconnectIn: 5000 },
              })
            );
          }
        } catch (e) {
          console.error('[shieldcortex] WebSocket send failed during restart:', e);
        }
      }

      // Schedule restart after response is sent
      res.json({ success: true, message: 'Server will restart in 3 seconds' });

      scheduleRestart(3000);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Get memory links/relationships
  app.get('/api/links', (req: Request, res: Response) => {
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

  // ============================================
  // INSIGHTS ENDPOINTS
  // ============================================

  // (activity and quality routes moved above :id route)

  // ============================================
  // SQL CONSOLE ENDPOINT
  // ============================================

  // Execute SQL query (with safety restrictions)
  app.post('/api/sql', (req: Request, res: Response) => {
    try {
      const { query, allowWrite } = req.body;

      if (!query || typeof query !== 'string') {
        return res.status(400).json({ error: 'Query string required' });
      }

      const upperQuery = query.toUpperCase().trim();

      // Always block DROP and TRUNCATE
      if (/\bDROP\b/.test(upperQuery) || /\bTRUNCATE\b/.test(upperQuery)) {
        return res.status(403).json({
          error: 'DROP and TRUNCATE operations are blocked for safety',
        });
      }

      // Block writes unless explicitly allowed
      const isWriteOperation =
        upperQuery.startsWith('INSERT') ||
        upperQuery.startsWith('UPDATE') ||
        upperQuery.startsWith('DELETE') ||
        upperQuery.startsWith('ALTER') ||
        upperQuery.startsWith('CREATE');

      if (isWriteOperation && !allowWrite) {
        return res.status(403).json({
          error: 'Write operations are disabled. Enable allowWrite to execute.',
        });
      }

      const db = getDatabase();
      const startTime = Date.now();

      // Execute query
      const isSelect = upperQuery.startsWith('SELECT') || upperQuery.startsWith('PRAGMA');

      if (isSelect) {
        const rows = db.prepare(query).all() as Record<string, unknown>[];
        const executionTime = Date.now() - startTime;

        // Get column names from first row or empty
        const columns = rows.length > 0 ? Object.keys(rows[0]) : [];

        res.json({
          columns,
          rows,
          rowCount: rows.length,
          executionTime,
        });
      } else {
        // Write operation
        const result = db.prepare(query).run();
        const executionTime = Date.now() - startTime;

        res.json({
          columns: ['changes', 'lastInsertRowid'],
          rows: [{ changes: result.changes, lastInsertRowid: result.lastInsertRowid }],
          rowCount: 1,
          executionTime,
        });
      }
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Trigger consolidation
  app.post('/api/consolidate', (_req: Request, res: Response) => {
    try {
      const result = consolidate();
      // Emit event for Activity log
      emitConsolidation(result);
      res.json({
        success: true,
        ...result,
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Get context summary
  app.get('/api/context', async (req: Request, res: Response) => {
    try {
      const project = typeof req.query.project === 'string' ? req.query.project : undefined;
      const summary = await generateContextSummary(project);
      const formatted = formatContextSummary(summary);

      res.json({
        summary,
        formatted,
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Get search suggestions (for autocomplete)
  app.get('/api/suggestions', (req: Request, res: Response) => {
    try {
      const query = typeof req.query.q === 'string' ? req.query.q : '';
      const limit = typeof req.query.limit === 'string' ? parseInt(req.query.limit) : 10;

      if (!query || query.length < 2) {
        return res.json({ suggestions: [] });
      }

      const db = getDatabase();

      // Get suggestions from memory titles, categories, tags, and projects
      const suggestions: Array<{ text: string; type: string; count: number }> = [];

      // Search titles that contain the query
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

      // Get matching categories
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

      // Get matching projects
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

      // Sort by count and limit total results
      suggestions.sort((a, b) => b.count - a.count);
      const limitedSuggestions = suggestions.slice(0, limit);

      res.json({ suggestions: limitedSuggestions });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // ============================================
  // GRAPH / ONTOLOGY ENDPOINTS
  // ============================================

  // List entities with optional filters and pagination
  app.get('/api/graph/entities', (req: Request, res: Response) => {
    try {
      const db = getDatabase();
      const type = typeof req.query.type === 'string' ? req.query.type : undefined;
      const minMentions = typeof req.query.minMentions === 'string' ? parseInt(req.query.minMentions) : 0;
      const limit = typeof req.query.limit === 'string' ? Math.min(parseInt(req.query.limit), 500) : 100;
      const offset = typeof req.query.offset === 'string' ? parseInt(req.query.offset) : 0;

      let whereClause = 'WHERE 1=1';
      const params: unknown[] = [];

      if (type) {
        whereClause += ' AND type = ?';
        params.push(type);
      }
      if (minMentions > 0) {
        whereClause += ' AND memory_count >= ?';
        params.push(minMentions);
      }

      const totalRow = db.prepare(`SELECT COUNT(*) as count FROM entities ${whereClause}`).get(...params) as { count: number };
      const total = totalRow.count;

      const rows = db.prepare(
        `SELECT * FROM entities ${whereClause} ORDER BY memory_count DESC LIMIT ? OFFSET ?`
      ).all(...params, limit, offset) as Record<string, unknown>[];

      const entities = rows.map((r: any) => {
        let aliases: string[] = [];
        try { aliases = JSON.parse(r.aliases || '[]'); } catch { aliases = []; }
        return {
          id: r.id,
          name: r.name,
          type: r.type,
          memoryCount: r.memory_count ?? 0,
          aliases,
          createdAt: r.created_at,
          updatedAt: r.updated_at,
        };
      });

      res.json({ entities, total, offset, limit, hasMore: offset + limit < total });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Get triples for a specific entity
  app.get('/api/graph/entities/:id/triples', (req: Request, res: Response) => {
    try {
      const db = getDatabase();
      const id = parseInt(req.params.id as string);
      if (isNaN(id)) {
        return res.status(400).json({ error: 'Invalid entity ID' });
      }

      const rows = db.prepare(`
        SELECT t.*, s.name as subject_name, s.type as subject_type,
               o.name as object_name, o.type as object_type
        FROM triples t
        JOIN entities s ON s.id = t.subject_id
        JOIN entities o ON o.id = t.object_id
        WHERE t.subject_id = ? OR t.object_id = ?
        ORDER BY t.created_at DESC
      `).all(id, id) as Record<string, unknown>[];

      res.json({ triples: rows });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Get memories linked to a specific entity
  app.get('/api/graph/entities/:id/memories', (req: Request, res: Response) => {
    try {
      const db = getDatabase();
      const id = parseInt(req.params.id as string);
      if (isNaN(id)) {
        return res.status(400).json({ error: 'Invalid entity ID' });
      }

      const rows = db.prepare(`
        SELECT m.id, m.title, m.type, m.category, m.salience, m.created_at
        FROM memories m
        JOIN memory_entities me ON me.memory_id = m.id
        WHERE me.entity_id = ?
        ORDER BY m.salience DESC, m.created_at DESC
        LIMIT 50
      `).all(id) as Record<string, unknown>[];

      res.json({ memories: rows });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // List triples with optional predicate filter and pagination
  app.get('/api/graph/triples', (req: Request, res: Response) => {
    try {
      const db = getDatabase();
      const predicate = typeof req.query.predicate === 'string' ? req.query.predicate : undefined;
      const limit = typeof req.query.limit === 'string' ? Math.min(parseInt(req.query.limit), 500) : 100;
      const offset = typeof req.query.offset === 'string' ? parseInt(req.query.offset) : 0;

      let whereClause = '';
      const params: unknown[] = [];

      if (predicate) {
        whereClause = 'WHERE t.predicate = ?';
        params.push(predicate);
      }

      const totalRow = db.prepare(
        `SELECT COUNT(*) as count FROM triples t ${whereClause}`
      ).get(...params) as { count: number };
      const total = totalRow.count;

      const rows = db.prepare(`
        SELECT t.*, s.name as subject_name, s.type as subject_type,
               o.name as object_name, o.type as object_type
        FROM triples t
        JOIN entities s ON s.id = t.subject_id
        JOIN entities o ON o.id = t.object_id
        ${whereClause}
        ORDER BY t.created_at DESC
        LIMIT ? OFFSET ?
      `).all(...params, limit, offset) as Record<string, unknown>[];

      res.json({ triples: rows, total, offset, limit, hasMore: offset + limit < total });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Search entities by name
  app.get('/api/graph/search', (req: Request, res: Response) => {
    try {
      const db = getDatabase();
      const q = typeof req.query.q === 'string' ? req.query.q : '';

      if (!q) {
        return res.status(400).json({ error: 'Query parameter "q" is required' });
      }

      const rows = db.prepare(
        `SELECT * FROM entities WHERE LOWER(name) LIKE ? ORDER BY memory_count DESC LIMIT 20`
      ).all(`%${q.toLowerCase()}%`) as Record<string, unknown>[];

      const entities = rows.map((r: any) => {
        let aliases: string[] = [];
        try { aliases = JSON.parse(r.aliases || '[]'); } catch { aliases = []; }
        return {
          id: r.id,
          name: r.name,
          type: r.type,
          memoryCount: r.memory_count ?? 0,
          aliases,
        };
      });

      res.json({ entities });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Find path between two entities using BFS
  app.get('/api/graph/paths', (req: Request, res: Response) => {
    try {
      const db = getDatabase();
      const fromName = typeof req.query.from === 'string' ? req.query.from : '';
      const toName = typeof req.query.to === 'string' ? req.query.to : '';

      if (!fromName || !toName) {
        return res.status(400).json({ error: 'Both "from" and "to" query parameters are required' });
      }

      const fromRow = db.prepare(
        'SELECT * FROM entities WHERE LOWER(name) = LOWER(?)'
      ).get(fromName) as any;
      if (!fromRow) {
        return res.status(404).json({ error: `Entity "${fromName}" not found` });
      }

      const toRow = db.prepare(
        'SELECT * FROM entities WHERE LOWER(name) = LOWER(?)'
      ).get(toName) as any;
      if (!toRow) {
        return res.status(404).json({ error: `Entity "${toName}" not found` });
      }

      if (fromRow.id === toRow.id) {
        return res.json({ path: [{ entity: fromRow.name, predicate: '(self)' }], sourceMemories: [] });
      }

      // BFS
      const maxDepth = 4;
      interface BFSNode { id: number; name: string; parentId: number | null; predicate: string; sourceMemoryId: number | null; }
      const visited = new Map<number, BFSNode>();
      visited.set(fromRow.id, { id: fromRow.id, name: fromRow.name, parentId: null, predicate: '', sourceMemoryId: null });

      let frontier: number[] = [fromRow.id];
      let found = false;

      for (let d = 0; d < maxDepth && !found; d++) {
        const nextFrontier: number[] = [];
        for (const nodeId of frontier) {
          const outgoing = db.prepare(
            'SELECT t.object_id as next_id, t.predicate, t.source_memory_id, e.name FROM triples t JOIN entities e ON e.id = t.object_id WHERE t.subject_id = ?'
          ).all(nodeId) as any[];
          for (const row of outgoing) {
            if (!visited.has(row.next_id)) {
              visited.set(row.next_id, { id: row.next_id, name: row.name, parentId: nodeId, predicate: row.predicate, sourceMemoryId: row.source_memory_id });
              nextFrontier.push(row.next_id);
              if (row.next_id === toRow.id) { found = true; break; }
            }
          }
          if (found) break;

          const incoming = db.prepare(
            'SELECT t.subject_id as next_id, t.predicate, t.source_memory_id, e.name FROM triples t JOIN entities e ON e.id = t.subject_id WHERE t.object_id = ?'
          ).all(nodeId) as any[];
          for (const row of incoming) {
            if (!visited.has(row.next_id)) {
              visited.set(row.next_id, { id: row.next_id, name: row.name, parentId: nodeId, predicate: `~${row.predicate}`, sourceMemoryId: row.source_memory_id });
              nextFrontier.push(row.next_id);
              if (row.next_id === toRow.id) { found = true; break; }
            }
          }
          if (found) break;
        }
        frontier = nextFrontier;
        if (frontier.length === 0) break;
      }

      if (!found) {
        return res.json({ path: [], sourceMemories: [], message: 'No path found' });
      }

      // Reconstruct path
      const path: Array<{ entity: string; predicate: string }> = [];
      const sourceMemoryIds: number[] = [];
      let current: BFSNode | undefined = visited.get(toRow.id);

      while (current) {
        path.unshift({ entity: current.name, predicate: current.predicate });
        if (current.sourceMemoryId) sourceMemoryIds.push(current.sourceMemoryId);
        current = current.parentId !== null ? visited.get(current.parentId) : undefined;
      }

      // Fetch source memories
      const sourceMemories = sourceMemoryIds.length > 0
        ? db.prepare(`SELECT id, title FROM memories WHERE id IN (${sourceMemoryIds.map(() => '?').join(',')})`).all(...sourceMemoryIds)
        : [];

      res.json({ path, sourceMemories });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // ============================================
  // BRAIN CONTROL CENTRE
  // ============================================

  // Boost memory salience (+0.15, capped at 1.0)
  app.post('/api/memories/:id/boost', (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id as string);
      const memory = getMemoryById(id);
      if (!memory) {
        return res.status(404).json({ error: 'Memory not found' });
      }
      const newSalience = Math.min(1.0, (memory.salience ?? 0.5) + 0.15);
      const updated = updateMemory(id, { salience: newSalience });
      res.json(updated);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Demote memory salience (-0.15, floor at 0.05)
  app.post('/api/memories/:id/demote', (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id as string);
      const memory = getMemoryById(id);
      if (!memory) {
        return res.status(404).json({ error: 'Memory not found' });
      }
      const newSalience = Math.max(0.05, (memory.salience ?? 0.5) - 0.15);
      const updated = updateMemory(id, { salience: newSalience });
      res.json(updated);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Promote memory from STM to LTM
  app.post('/api/memories/:id/promote', (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id as string);
      const memory = promoteMemory(id);
      if (!memory) {
        return res.status(404).json({ error: 'Memory not found' });
      }
      res.json(memory);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Update memory (partial: title, content, tags, category)
  app.patch('/api/memories/:id', (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id as string);
      const updated = updateMemory(id, req.body);
      if (!updated) {
        return res.status(404).json({ error: 'Memory not found' });
      }
      res.json(updated);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Quarantine a memory (move to quarantine table, delete original)
  app.post('/api/memories/:id/quarantine', (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id as string);
      const memory = getMemoryById(id);
      if (!memory) {
        return res.status(404).json({ error: 'Memory not found' });
      }
      const db = getDatabase();
      db.prepare(
        `INSERT INTO quarantine (original_title, original_content, source_type, source_identifier, reason, project, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)`
      ).run(
        memory.title,
        memory.content,
        'dashboard',
        'brain-control',
        req.body.reason || 'Manually quarantined from Brain dashboard',
        memory.project || null,
        new Date().toISOString()
      );
      deleteMemory(id);
      res.json({ success: true, quarantined: id });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Create a manual link between two memories
  app.post('/api/links', (req: Request, res: Response) => {
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

  // ============================================
  // SKILL SCANNER
  // ============================================

  // Scan a skill/instruction file for threats
  app.post('/api/skills/scan', (req: Request, res: Response) => {
    try {
      const { path: filePath, content, format, name, mode } = req.body;

      if (!filePath && !content) {
        return res.status(400).json({ error: 'Either "path" (file path) or "content" (raw content) is required' });
      }

      let result;
      if (filePath) {
        result = scanSkill(filePath, { mode });
      } else {
        result = scanSkillContent(content, { mode }, format, name);
      }

      res.json(result);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Scan all installed skills/hooks across known locations
  app.post('/api/skills/scan-all', (req: Request, res: Response) => {
    try {
      const { dir } = req.body ?? {};
      const files = discoverSkillFiles(dir);
      const trusted = getTrustedSkills();

      const results = files.map((fp) => {
        const r = scanSkill(fp);
        return {
          path: fp,
          safe: r.safe,
          skillName: r.skillName,
          format: r.format,
          riskLevel: r.riskLevel,
          summary: r.summary,
          findings: r.findings,
          scanDurationMs: r.scanDurationMs,
          trusted: trusted.includes(fp),
        };
      });

      const threatCount = results.filter((r) => !r.safe && !r.trusted).length;
      const scannedAt = new Date().toISOString();

      res.json({
        files: results,
        totalScanned: results.length,
        threatCount,
        scannedAt,
      });

      // Fire-and-forget: sync results to cloud
      const cloudConfig = getCloudConfig();
      if (cloudConfig.cloudEnabled && cloudConfig.cloudApiKey) {
        const payload = {
          files: results.map((r) => ({
            file_path: r.path,
            skill_name: r.skillName,
            format: r.format,
            risk_level: r.riskLevel,
            safe: r.safe,
            summary: r.summary,
            findings: r.findings,
            scan_duration_ms: r.scanDurationMs,
            trusted: r.trusted,
          })),
          device_id: getDeviceId(),
          device_name: getDeviceName(),
          platform: process.platform,
          scanned_at: scannedAt,
        };

        fetch(`${cloudConfig.cloudBaseUrl}/v1/skills/ingest`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${cloudConfig.cloudApiKey}`,
          },
          body: JSON.stringify(payload),
          signal: AbortSignal.timeout(15_000),
        }).catch(() => {});
      }
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Trust a skill file
  app.post('/api/skills/trust', (req: Request, res: Response) => {
    try {
      const { path: filePath } = req.body;
      if (!filePath || typeof filePath !== 'string') {
        return res.status(400).json({ error: '"path" is required' });
      }
      addTrustedSkill(filePath);
      res.json({ trusted: true, path: filePath });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Untrust a skill file
  app.delete('/api/skills/trust', (req: Request, res: Response) => {
    try {
      const { path: filePath } = req.body;
      if (!filePath || typeof filePath !== 'string') {
        return res.status(400).json({ error: '"path" is required' });
      }
      removeTrustedSkill(filePath);
      res.json({ trusted: false, path: filePath });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Delete a skill file (security: only allows known skill locations)
  app.delete('/api/skills/file', (req: Request, res: Response) => {
    try {
      const { path: filePath } = req.body;
      if (!filePath || typeof filePath !== 'string') {
        return res.status(400).json({ error: '"path" is required' });
      }

      // Security: only allow deletion of files in known skill directories
      const home = homedir();
      const allowedPrefixes = [
        `${home}/.claude/`,
        `${home}/.openclaw/`,
      ];
      const allowedFiles = [
        '.cursorrules', '.windsurfrules', '.clinerules',
        'CLAUDE.md', 'copilot-instructions.md',
        '.aider.conf.yml',
      ];
      const isAllowed = allowedPrefixes.some(p => filePath.startsWith(p))
        || allowedFiles.some(f => filePath.endsWith(`/${f}`));

      if (!isAllowed) {
        return res.status(403).json({ error: 'Path is not in a known skill directory' });
      }

      if (!existsSync(filePath)) {
        return res.status(404).json({ error: 'File not found' });
      }

      // Check cloud connection is required for deletion
      const cloudConfig = getCloudConfig();
      if (!cloudConfig.cloudEnabled || !cloudConfig.cloudApiKey) {
        return res.status(403).json({ error: 'Cloud connection required for skill removal', requiresCloud: true });
      }

      unlinkSync(filePath);
      // Also remove from trusted list if present
      removeTrustedSkill(filePath);
      res.json({ deleted: true, path: filePath });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // ============================================
  // BRAIN WORKER (Phase 4)
  // ============================================

  // ── Defence API v1 ──────────────────────────────────────────

  // Scan content through the defence pipeline
  // NOTE: config parameter is intentionally ignored — always uses persisted mode (security hardening)
  app.post('/api/v1/scan', (req: Request, res: Response) => {
    try {
      const { content, title, source } = req.body;
      if (!content || typeof content !== 'string') {
        return res.status(400).json({ error: 'content (string) is required' });
      }

      // Log if caller tried to override config (potential tampering)
      if (req.body.config) {
        try {
          logAudit({
            memory_id: null,
            project: null,
            timestamp: new Date().toISOString(),
            source_type: 'api',
            source_identifier: 'rest-api',
            trust_score: 0,
            sensitivity_level: 'INTERNAL',
            firewall_result: 'ALLOW',
            anomaly_score: 0.5,
            threat_indicators: '["config_tampering"]',
            blocked_patterns: '[]',
            reason: 'config_override_attempt: scan endpoint config parameter ignored',
            fragmentation_score: null,
            pipeline_duration_ms: 0,
          });
        } catch { /* audit is best-effort */ }
      }

      const defenceSource: DefenceSource = {
        type: source?.type ?? 'api',
        identifier: source?.identifier ?? 'rest-api',
      };

      // Always use persisted config — no per-request overrides via HTTP
      const defenceConfig: DefenceConfig = { ...DEFAULT_DEFENCE_CONFIG, mode: getDefenceMode() };

      const result = runDefencePipeline(
        content,
        title ?? 'Untitled',
        defenceSource,
        defenceConfig,
      );

      res.json(result);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Batch scan multiple items
  // NOTE: config parameter is intentionally ignored — always uses persisted mode (security hardening)
  app.post('/api/v1/scan/batch', (req: Request, res: Response) => {
    try {
      const { items, source } = req.body;
      if (!Array.isArray(items) || items.length === 0) {
        return res.status(400).json({ error: 'items (array) is required' });
      }
      if (items.length > 100) {
        return res.status(400).json({ error: 'Maximum 100 items per batch' });
      }

      const defenceSource: DefenceSource = {
        type: source?.type ?? 'api',
        identifier: source?.identifier ?? 'rest-api',
      };

      // Always use persisted config — no per-request overrides via HTTP
      const defenceConfig: DefenceConfig = { ...DEFAULT_DEFENCE_CONFIG, mode: getDefenceMode() };

      const results = items.map((item: { content: string; title?: string }) => {
        if (!item.content || typeof item.content !== 'string') {
          return { error: 'content (string) is required', allowed: false };
        }
        return runDefencePipeline(
          item.content,
          item.title ?? 'Untitled',
          defenceSource,
          defenceConfig,
        );
      });

      res.json({ results, total: results.length });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Query audit logs
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

  // Audit statistics
  app.get('/api/v1/audit/stats', (req: Request, res: Response) => {
    try {
      const timeRange = (req.query.timeRange as '24h' | '7d' | '30d') ?? '24h';
      const project = req.query.project as string | undefined;
      const stats = getAuditStats(timeRange, project);
      res.json(stats);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Agent registry — distinct agents aggregated from audit logs
  app.get('/api/v1/agents', (req: Request, res: Response) => {
    try {
      const timeRange = (req.query.timeRange as '24h' | '7d' | '30d') ?? '24h';
      const project = req.query.project as string | undefined;
      const agents = queryAgentRegistry(timeRange, project);
      res.json({ agents });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Agent trust score timeline
  app.get('/api/v1/agents/:identifier/timeline', (req: Request, res: Response) => {
    try {
      const identifier = decodeURIComponent(req.params.identifier as string);
      const timeRange = (req.query.timeRange as '24h' | '7d' | '30d') ?? '24h';
      const project = req.query.project as string | undefined;
      const points = queryAgentTimeline(identifier, timeRange, project);
      res.json({ points });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Agent operations — paginated audit entries for one agent
  app.get('/api/v1/agents/:identifier/operations', (req: Request, res: Response) => {
    try {
      const identifier = decodeURIComponent(req.params.identifier as string);
      const limit = parseInt(req.query.limit as string, 10) || 50;
      const offset = parseInt(req.query.offset as string, 10) || 0;
      const firewallResult = req.query.firewallResult as string | undefined;
      const project = req.query.project as string | undefined;
      const entries = queryAgentOperations(identifier, {
        limit, offset, project,
        firewallResult: firewallResult as 'ALLOW' | 'BLOCK' | 'QUARANTINE' | undefined,
      });
      res.json({ entries, limit, offset });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // List quarantined items
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
      const items = rows.map((r) => ({
        ...r,
        title: r.original_title,
        content: r.original_content,
      }));
      res.json({ items, total: items.length });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Approve quarantined item
  app.post('/api/v1/quarantine/:id/approve', (req: Request, res: Response) => {
    try {
      const db = getDatabase();
      const id = parseInt(req.params.id as string, 10);
      const reviewedBy = req.body?.reviewedBy ?? 'api';
      const result = db.prepare(
        'UPDATE quarantine SET status = ?, reviewed_at = ?, reviewed_by = ? WHERE id = ? AND status = ?'
      ).run('approved', new Date().toISOString(), reviewedBy, id, 'pending');
      if (result.changes === 0) {
        return res.status(404).json({ error: 'Quarantine entry not found or already reviewed' });
      }
      res.json({ success: true, id, status: 'approved' });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Reject quarantined item
  app.post('/api/v1/quarantine/:id/reject', (req: Request, res: Response) => {
    try {
      const db = getDatabase();
      const id = parseInt(req.params.id as string, 10);
      const reviewedBy = req.body?.reviewedBy ?? 'api';
      const notes = req.body?.notes ?? null;
      const result = db.prepare(
        'UPDATE quarantine SET status = ?, reviewed_at = ?, reviewed_by = ? WHERE id = ? AND status = ?'
      ).run('rejected', new Date().toISOString(), reviewedBy, id, 'pending');
      if (result.changes === 0) {
        return res.status(404).json({ error: 'Quarantine entry not found or already reviewed' });
      }
      res.json({ success: true, id, status: 'rejected' });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Retroactive sync: push existing quarantine items to cloud
  app.post('/api/quarantine/sync-to-cloud', async (_req: Request, res: Response) => {
    try {
      const config = getCloudConfig();
      if (!config.cloudEnabled || !config.cloudApiKey) {
        return res.status(400).json({ error: 'Cloud not configured. Enable cloud sync first.' });
      }

      const db = getDatabase();
      const rows = db.prepare(
        'SELECT * FROM quarantine WHERE status = ? ORDER BY created_at ASC'
      ).all('pending') as Record<string, unknown>[];

      if (rows.length === 0) {
        return res.json({ synced: 0, message: 'No pending quarantine items to sync.' });
      }

      let synced = 0;
      const errors: string[] = [];

      for (const row of rows) {
        try {
          const indicators: string[] = (() => {
            try { return JSON.parse(row.threat_indicators as string ?? '[]'); }
            catch { return []; }
          })();

          const resp = await fetch(`${config.cloudBaseUrl}/v1/quarantine/ingest`, {
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

          if (resp.ok) {
            synced++;
          } else {
            const body = await resp.text().catch(() => '');
            errors.push(`Item ${row.id}: ${resp.status} ${body.substring(0, 100)}`);
          }
        } catch (e) {
          errors.push(`Item ${row.id}: ${(e as Error).message}`);
        }
      }

      res.json({ synced, total: rows.length, errors: errors.length > 0 ? errors : undefined });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Create and start the background brain worker
  const brainWorker = new BrainWorker();

  // Worker status endpoint
  app.get('/api/worker/status', (_req: Request, res: Response) => {
    try {
      res.json(brainWorker.getStatus());
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Manually trigger light tick (for testing)
  app.post('/api/worker/trigger-light', async (_req: Request, res: Response) => {
    try {
      const result = await brainWorker.triggerLightTick();
      res.json({
        success: true,
        ...result,
        timestamp: result.timestamp.toISOString(),
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Manually trigger medium tick (for testing)
  app.post('/api/worker/trigger-medium', async (_req: Request, res: Response) => {
    try {
      const result = await brainWorker.triggerMediumTick();
      res.json({
        success: true,
        ...result,
        timestamp: result.timestamp.toISOString(),
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // ============================================
  // WEBSOCKET SERVER
  // ============================================

  const wss = new WebSocketServer({ server, path: '/ws/events' });

  wss.on('connection', (ws: WebSocket) => {
    clients.add(ws);
    console.log(`[WS] Client connected. Total: ${clients.size}`);

    // Send initial state
    const stats = getMemoryStats();
    const memories = getRecentMemories(100);
    const memoriesWithDecay = memories.map(m => ({
      ...m,
      decayedScore: calculateDecayedScore(m),
    }));

    try {
      ws.send(JSON.stringify({
        type: 'initial_state',
        timestamp: new Date().toISOString(),
        data: {
          stats,
          memories: memoriesWithDecay,
        },
      }));
    } catch (e) {
      console.error('[shieldcortex] Failed to send initial state:', e);
    }

    ws.on('close', () => {
      clients.delete(ws);
      console.log(`[WS] Client disconnected. Total: ${clients.size}`);
    });

    ws.on('error', (error) => {
      console.error('[WS] Error:', error);
      clients.delete(ws);
      try { ws.close(); } catch { /* already closing */ }
    });
  });

  // Broadcast events to all connected clients
  function broadcast(event: MemoryEvent): void {
    const message = JSON.stringify(event);
    for (const client of clients) {
      try {
        if (client.readyState === WebSocket.OPEN) {
          client.send(message);
        }
      } catch (e) {
        console.error('[shieldcortex] Broadcast failed for client:', e);
        clients.delete(client);
        try { client.close(); } catch { /* already closing */ }
      }
    }
  }

  // Subscribe to memory events
  memoryEvents.onMemoryEvent((event) => {
    broadcast(event);
  });

  // Decay tick - update clients with decay changes every 30 seconds
  let decayTickCount = 0;
  setInterval(() => {
    const db = getDatabase();
    const rawRows = db.prepare(
      'SELECT * FROM memories ORDER BY last_accessed DESC LIMIT 200'
    ).all() as Record<string, unknown>[];

    // Convert raw DB rows to Memory objects (snake_case -> camelCase)
    const memories = rawRows.map(rowToMemory);

    const updates: Array<{ memoryId: number; oldScore: number; newScore: number }> = [];

    for (const memory of memories) {
      const newScore = calculateDecayedScore(memory);
      // Only include memories that have decayed significantly since last update
      // Compare to decayedScore (not salience) to detect actual changes
      if (Math.abs(newScore - memory.decayedScore) > 0.01) {
        updates.push({
          memoryId: memory.id,
          oldScore: memory.decayedScore,
          newScore,
        });
      }
    }

    if (updates.length > 0) {
      emitDecayTick(updates);
    }

    // Persist decay scores and checkpoint WAL every 5 minutes (10 ticks)
    decayTickCount++;
    if (decayTickCount >= 10) {
      decayTickCount = 0;
      try {
        updateDecayScores();
        // Checkpoint WAL to prevent file bloat and reduce contention
        const checkpoint = checkpointWal();
        if (checkpoint.walPages > 0) {
          console.log(`[WAL] Checkpointed ${checkpoint.checkpointed}/${checkpoint.walPages} pages`);
        }
      } catch (error) {
        console.error('[Maintenance] Failed to persist decay scores or checkpoint:', error);
      }
    }
  }, 30000);

  // ============================================
  // CROSS-PROCESS EVENT POLLING (IPC)
  // ============================================

  // Poll database for events from MCP process every 500ms
  const eventPollInterval = setInterval(() => {
    try {
      const events = getUnprocessedEvents(50);
      if (events.length > 0) {
        const ids: number[] = [];
        for (const event of events) {
          broadcast({ type: event.type, data: event.data, timestamp: event.timestamp });
          ids.push(event.id);
        }
        markEventsProcessed(ids);
        console.log(`[Events] Processed ${events.length} cross-process events`);
      }
    } catch (error) {
      // Don't spam logs on transient errors
      if (Math.random() < 0.1) {
        console.error('[Events] Event polling error:', error);
      }
    }
  }, 500);

  // Cleanup old processed events every hour
  const cleanupInterval = setInterval(() => {
    try {
      cleanupOldEvents();
    } catch (error) {
      console.error('[Events] Cleanup error:', error);
    }
  }, 60 * 60 * 1000);

  // ============================================
  // START SERVER
  // ============================================

  // Start brain worker before starting server
  brainWorker.start();

  // Graceful shutdown handler
  function gracefulShutdown(signal: string) {
    console.log(`\n[Server] Received ${signal}, shutting down gracefully...`);

    // Clean up session token file
    cleanupSessionToken();

    // Stop the brain worker
    brainWorker.stop();

    // Clear polling intervals
    clearInterval(eventPollInterval);
    clearInterval(cleanupInterval);

    // Close WebSocket connections
    for (const client of clients) {
      client.close();
    }
    clients.clear();

    // Close the HTTP server
    server.close(() => {
      console.log('[Server] HTTP server closed');

      // Checkpoint WAL before exit
      try {
        checkpointWal();
        console.log('[Server] WAL checkpointed');
      } catch (e) {
        console.error('[Server] Failed to checkpoint WAL:', e);
      }

      process.exit(0);
    });

    // Force exit after 10 seconds
    setTimeout(() => {
      console.error('[Server] Forced exit after timeout');
      process.exit(1);
    }, 10000);
  }

  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));

  // Handle port-in-use and other listen errors gracefully
  server.on('error', (err: NodeJS.ErrnoException) => {
    if (err.code === 'EADDRINUSE') {
      console.error(`\n[ShieldCortex] Port ${PORT} is already in use.`);
      console.error(`Another ShieldCortex instance may be running.\n`);
      console.error(`  To fix:`);
      console.error(`    1. Kill the existing process: lsof -ti :${PORT} | xargs kill`);
      console.error(`    2. Or choose a different port: PORT=3002 npx shieldcortex --mode api\n`);
    } else {
      console.error(`[ShieldCortex] Server error: ${err.message}`);
    }
    // Stop worker and clean up before exiting
    brainWorker.stop();
    clearInterval(eventPollInterval);
    clearInterval(cleanupInterval);
    process.exit(1);
  });

  server.listen(PORT, () => {
    console.log(`
╔══════════════════════════════════════════════════════════════╗
║             🧠 ShieldCortex API Server                       ║
╠══════════════════════════════════════════════════════════════╣
║  REST API:    http://localhost:${PORT}/api                        ║
║  WebSocket:   ws://localhost:${PORT}/ws/events                    ║
║                                                              ║
║  Endpoints:                                                  ║
║    GET  /api/health         - Health check                   ║
║    GET  /api/memories       - List memories                  ║
║    GET  /api/memories/:id   - Get memory                     ║
║    POST /api/memories       - Create memory                  ║
║    DEL  /api/memories/:id   - Delete memory                  ║
║    POST /api/memories/:id/access - Reinforce memory          ║
║    GET  /api/stats          - Memory statistics              ║
║    GET  /api/links          - Memory relationships           ║
║    POST /api/consolidate    - Trigger consolidation          ║
║    GET  /api/context        - Context summary                ║
║    GET  /api/suggestions    - Search autocomplete            ║
║                                                              ║
║  Control:                                                    ║
║    GET  /api/control/status - Get pause state & uptime       ║
║    POST /api/control/pause  - Pause memory creation          ║
║    POST /api/control/resume - Resume memory creation         ║
║                                                              ║
║  Defence API:                                                ║
║    POST /api/v1/scan             - Scan content              ║
║    POST /api/v1/scan/batch       - Batch scan                ║
║    GET  /api/v1/audit            - Query audit logs          ║
║    GET  /api/v1/audit/stats      - Audit statistics          ║
║    GET  /api/v1/quarantine       - List quarantined items    ║
║    POST /api/v1/quarantine/:id/approve - Approve item        ║
║    POST /api/v1/quarantine/:id/reject  - Reject item         ║
║                                                              ║
║  Brain Worker:                                               ║
║    GET  /api/worker/status       - Worker status             ║
║    POST /api/worker/trigger-light  - Trigger light tick      ║
║    POST /api/worker/trigger-medium - Trigger medium tick     ║
╚══════════════════════════════════════════════════════════════╝
    `);
  });
}
