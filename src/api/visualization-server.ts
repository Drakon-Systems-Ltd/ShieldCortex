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
import { resolve, join } from 'path';
import { generateSessionToken, cleanupSessionToken, validateSessionToken, getSessionToken } from './session-token.js';
import { WebSocketServer, WebSocket } from 'ws';
import { getDatabase, initDatabase, checkpointWal } from '../database/init.js';
import { MemoryConfig, DEFAULT_CONFIG } from '../memory/types.js';
import { getRecentMemories, getMemoryStats, rowToMemory, updateDecayScores } from '../memory/store.js';
import { calculateDecayedScore } from '../memory/decay.js';
import {
  memoryEvents,
  MemoryEvent,
  emitDecayTick,
  getUnprocessedEvents,
  markEventsProcessed,
  cleanupOldEvents,
} from './events.js';
import { BrainWorker } from '../worker/brain-worker.js';
import { isPaused, isKillSwitchActive, getKillSwitchMeta, activateKillSwitch, deactivateKillSwitch } from './control.js';
import { getRunningVersion } from './version.js';
import { runDefencePipeline } from '../defence/pipeline.js';
import { DEFAULT_DEFENCE_CONFIG } from '../defence/types.js';
import type { DefenceSource, DefenceConfig } from '../defence/types.js';
import { queryAgentOperations } from '../defence/audit/queries.js';
import { logAudit } from '../defence/audit/index.js';
import { getCloudConfig, getTrustedSkills, addTrustedSkill, removeTrustedSkill, getDeviceId, getDeviceName, getDefenceMode } from '../cloud/config.js';
import { scanSkill, scanSkillContent, discoverSkillFiles } from '../defence/skill-scanner/index.js';
import { getIronDomeStatus, activateIronDome, deactivateIronDome, scanForInjection, logIronDomeAudit, updateIronDomeConfig } from '../defence/iron-dome/index.js';
import type { IronDomeProfile } from '../defence/iron-dome/index.js';
import { requireFeature, FeatureGatedError } from '../license/gate.js';
import type { GatedFeature } from '../license/gate.js';
import type { FeatureGatedResponse } from '../license/types.js';
import { registerAdminRoutes } from './routes/admin.js';
import { registerGraphRoutes } from './routes/graph.js';
import { registerIncidentRoutes } from './routes/incidents.js';
import { registerMemoryRoutes } from './routes/memories.js';
import { registerRecallRoutes } from './routes/recall.js';
import { registerSystemRoutes } from './routes/system.js';
import { registerXRayRoutes } from './routes/xray.js';
import { registerXRayFindingRoutes } from './routes/xray-findings.js';
import { registerDigestRoutes } from './routes/digest.js';
import { registerSessionRoutes } from './routes/sessions.js';
import { createIronDomeRouteGuard } from './iron-dome-route-guard.js';
import { readAndClearDetectionEvents } from '../xray/activity.js';
import { classifySqlQuery } from './sql-classifier.js';

const PORT = process.env.PORT || 3001;

// ── Defence source whitelist (Fix #13) ──────────────────────────────────────
// The DefenceSource.type field is part of the threat-model surface — caller-
// controlled `source.type` values pollute Iron Dome dashboards and audit
// queries. Normalise unknown values to 'api' silently (defence in depth) and
// cap identifier length to avoid log-explosion attacks.
const ALLOWED_DEFENCE_SOURCE_TYPES: ReadonlyArray<DefenceSource['type']> = [
  'user', 'cli', 'hook', 'email', 'web', 'agent', 'file', 'api', 'tool_response',
] as const;
const MAX_SOURCE_IDENTIFIER_LENGTH = 200;

/**
 * Normalise an incoming `source` object from a REST request body into a
 * trusted `DefenceSource`.
 *
 * - Unknown `type` values fall back to `'api'` (no rejection — defence in depth)
 * - `identifier` longer than {@link MAX_SOURCE_IDENTIFIER_LENGTH} is truncated
 *   with an ellipsis ("…") so the truncation is visible in audit logs
 * - Non-string identifiers fall back to `'rest-api'`
 *
 * Exported for unit tests.
 */
export function normaliseDefenceSource(raw: unknown): DefenceSource {
  const candidate = (raw ?? {}) as { type?: unknown; identifier?: unknown };

  const rawType = typeof candidate.type === 'string' ? candidate.type : undefined;
  const type: DefenceSource['type'] =
    rawType && (ALLOWED_DEFENCE_SOURCE_TYPES as ReadonlyArray<string>).includes(rawType)
      ? (rawType as DefenceSource['type'])
      : 'api';

  const rawIdentifier = typeof candidate.identifier === 'string' ? candidate.identifier : 'rest-api';
  const identifier =
    rawIdentifier.length > MAX_SOURCE_IDENTIFIER_LENGTH
      ? rawIdentifier.slice(0, MAX_SOURCE_IDENTIFIER_LENGTH - 1) + '…'
      : rawIdentifier;

  return { type, identifier };
}

export const __test__ = {
  ALLOWED_DEFENCE_SOURCE_TYPES,
  MAX_SOURCE_IDENTIFIER_LENGTH,
};

/**
 * In-memory counters for FEATURE_GATED (403) responses per feature.
 * Lightweight telemetry to detect noisy free-tier clients hammering gated endpoints.
 */
const gatedCounters: Record<string, number> = {};

/**
 * Express middleware that gates an endpoint behind a Pro/Team licence feature.
 * Wraps requireFeature() — one source of truth for tier checks.
 * Returns a structured 403 (FeatureGatedResponse) if the feature isn't enabled.
 */
function requireProFeature(feature: GatedFeature) {
  return (_req: Request, res: Response, next: (err?: unknown) => void) => {
    try {
      requireFeature(feature);
      next();
    } catch (err) {
      if (err instanceof FeatureGatedError) {
        gatedCounters[err.feature] = (gatedCounters[err.feature] || 0) + 1;
        const body: FeatureGatedResponse = {
          error: 'Feature requires upgrade',
          code: 'FEATURE_GATED',
          feature: err.feature,
          requiredTier: err.requiredTier,
          upgradeUrl: 'https://shieldcortex.ai/pricing',
        };
        return res.status(403).json(body);
      }
      next(err);
    }
  };
}

// Track connected WebSocket clients
const clients = new Set<WebSocket>();

/**
 * Handler for `POST /api/v1/scan`.
 *
 * Scans content through the defence pipeline. The `config` field on the
 * request body is intentionally ignored — runtime always uses the persisted
 * defence mode. Any attempt to override config is logged as a BLOCK with
 * RESTRICTED sensitivity so incident-triage queries surface it (Fix #13).
 *
 * Exported for unit tests.
 */
export function handleV1Scan(req: Request, res: Response): void {
  try {
    const { content, title, source } = req.body;
    if (!content || typeof content !== 'string') {
      res.status(400).json({ error: 'content (string) is required' });
      return;
    }

    // Log if caller tried to override config (potential tampering).
    // Fix #13: record as BLOCK / RESTRICTED so incident-triage queries
    // filtering on firewall_result IN ('BLOCK','QUARANTINE') surface
    // config-tampering attempts.
    if (req.body.config) {
      try {
        logAudit({
          memory_id: null,
          project: null,
          timestamp: new Date().toISOString(),
          source_type: 'api',
          source_identifier: 'rest-api',
          trust_score: 0,
          sensitivity_level: 'RESTRICTED',
          firewall_result: 'BLOCK',
          anomaly_score: 0.5,
          threat_indicators: '["config_tampering"]',
          blocked_patterns: '[]',
          reason: 'config_override_attempt: scan endpoint config parameter ignored',
          fragmentation_score: null,
          pipeline_duration_ms: 0,
        });
      } catch { /* audit is best-effort */ }
    }

    // Fix #13: whitelist source.type and cap identifier length
    const defenceSource = normaliseDefenceSource(source);

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
}

/**
 * Handler for `POST /api/v1/scan/batch`.
 *
 * Scans up to 100 items in one request. Like {@link handleV1Scan}, the
 * `config` field is intentionally ignored; source is normalised through
 * {@link normaliseDefenceSource} (Fix #13).
 *
 * Exported for unit tests.
 */
export function handleV1ScanBatch(req: Request, res: Response): void {
  try {
    const { items, source } = req.body;
    if (!Array.isArray(items) || items.length === 0) {
      res.status(400).json({ error: 'items (array) is required' });
      return;
    }
    if (items.length > 100) {
      res.status(400).json({ error: 'Maximum 100 items per batch' });
      return;
    }

    // Fix #13: whitelist source.type and cap identifier length
    const defenceSource = normaliseDefenceSource(source);

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
}

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

  // Auth middleware: require Bearer token on all requests except public paths
  const publicPaths = ['/api/health', '/api/auth/session-token'];
  app.use((req: Request, res: Response, next) => {
    // Dashboard pages and static assets must load before the client can fetch
    // its API session token. Protect API routes, not the Next.js shell.
    if (!req.path.startsWith('/api/')) {
      return next();
    }
    // Allow OPTIONS/HEAD for CORS preflight
    if (['OPTIONS', 'HEAD'].includes(req.method)) {
      return next();
    }
    // Public endpoints that never need auth
    if (publicPaths.includes(req.path)) {
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
  // KILL SWITCH GUARD MIDDLEWARE
  // ============================================

  /**
   * Express middleware that blocks requests when the kill switch is active.
   * Returns 423 Locked with kill switch metadata.
   */
  function requireNotLocked(_req: Request, res: Response, next: (err?: unknown) => void) {
    if (!isKillSwitchActive()) return next();
    const meta = getKillSwitchMeta();
    res.status(423).json({
      error: 'Kill switch active — operation blocked',
      code: 'KILL_SWITCH_ACTIVE',
      killSwitch: meta,
    });
  }

  function classifySqlAction(req: Request): string {
    const query = typeof req.body?.query === 'string' ? req.body.query : '';
    if (!query.trim()) return 'database_migrate';

    // PURGE is application-level (not a real SQL keyword) — keep the regex check.
    if (/\bPURGE\b/i.test(query)) return 'destroy';

    const classification = classifySqlQuery(query);
    if (classification.kind === 'read') return 'run_report';
    if (classification.kind === 'destroy') return 'destroy';
    if (classification.kind === 'write' && classification.operation === 'DELETE') return 'delete';
    return 'database_migrate';
  }

  // ============================================
  // REST API ENDPOINTS
  // ============================================

  // Health check
  app.get('/api/health', (_req: Request, res: Response) => {
    const version = getRunningVersion();
    res.json({ status: 'ok', timestamp: new Date().toISOString(), version });
  });

  // Feature-gated response counters (detect noisy free-tier clients)
  app.get('/api/gated-stats', (_req: Request, res: Response) => {
    const total = Object.values(gatedCounters).reduce((sum, n) => sum + n, 0);
    res.json({ total, byFeature: { ...gatedCounters } });
  });

  registerMemoryRoutes(app, {
    requireNotLocked,
    requireIronDomeAction: createIronDomeRouteGuard,
  });
  registerRecallRoutes(app, requireNotLocked);
  registerXRayRoutes(app, requireNotLocked);
  registerXRayFindingRoutes(app, requireNotLocked);
  registerSystemRoutes(app, {
    broadcast,
    clients,
    requireIronDomeAction: createIronDomeRouteGuard,
  });
  registerDigestRoutes(app);

  // ============================================
  // INSIGHTS ENDPOINTS
  // ============================================

  // (activity and quality routes moved above :id route)

  // ============================================
  // SQL CONSOLE ENDPOINT
  // ============================================

  // Execute SQL query (with safety restrictions)
  app.post('/api/sql', requireNotLocked, createIronDomeRouteGuard({
    action: classifySqlAction,
    channel: 'dashboard',
    sourceIdentifier: 'dashboard:sql-console',
    enforceAmber: true,
  }), (req: Request, res: Response) => {
    try {
      const { query, allowWrite } = req.body;

      if (!query || typeof query !== 'string') {
        return res.status(400).json({ error: 'Query string required' });
      }

      // Classify the query — robust against CTE prefixes that would bypass
      // a naive `startsWith('INSERT'|'UPDATE'|...)` check, e.g.
      //   WITH t AS (SELECT 1) INSERT INTO memories VALUES (...)
      const classification = classifySqlQuery(query);

      // Always block DROP and TRUNCATE (and reject anything we can't classify)
      if (classification.kind === 'destroy') {
        return res.status(403).json({
          error: 'DROP and TRUNCATE operations are blocked for safety',
        });
      }

      if (classification.kind === 'reject') {
        return res.status(400).json({
          error: `Query rejected: ${classification.reason}`,
        });
      }

      // Block writes unless explicitly allowed
      if (classification.kind === 'write' && !allowWrite) {
        return res.status(403).json({
          error: 'Write operations are disabled. Enable allowWrite to execute.',
        });
      }

      const db = getDatabase();
      const startTime = Date.now();

      if (classification.kind === 'read') {
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
        // Write operation (allowWrite === true at this point)
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

  registerGraphRoutes(app, requireNotLocked);
  registerSessionRoutes(app, requireNotLocked);

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

      if (filePath) {
        const resolved = resolve(filePath);
        const home = homedir();
        const allowedPrefixes = [
          process.cwd(),
          join(home, '.claude'),
          join(home, '.openclaw'),
          join(home, '.cursor'),
          join(home, '.windsurf'),
          join(home, '.codex'),
          join(home, '.shieldcortex'),
        ];
        if (!allowedPrefixes.some(prefix => resolved.startsWith(prefix))) {
          return res.status(403).json({ error: 'Path outside allowed directories' });
        }
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
  app.post('/api/skills/trust', createIronDomeRouteGuard({
    action: 'modify_config',
    channel: 'dashboard',
    sourceIdentifier: 'dashboard:skill-trust',
    enforceAmber: true,
  }), (req: Request, res: Response) => {
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
  app.delete('/api/skills/trust', createIronDomeRouteGuard({
    action: 'modify_config',
    channel: 'dashboard',
    sourceIdentifier: 'dashboard:skill-untrust',
    enforceAmber: true,
  }), (req: Request, res: Response) => {
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
  app.delete('/api/skills/file', createIronDomeRouteGuard({
    action: 'delete_file',
    channel: 'dashboard',
    sourceIdentifier: 'dashboard:skill-delete',
  }), (req: Request, res: Response) => {
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
  // IRON DOME (Behaviour Protection)
  // ============================================

  app.get('/api/iron-dome/status', (_req: Request, res: Response) => {
    try {
      const status = getIronDomeStatus();
      res.json(status);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/iron-dome/activate', (req: Request, res: Response) => {
    try {
      const { profile } = req.body;
      const validProfiles: IronDomeProfile[] = ['school', 'enterprise', 'personal', 'paranoid'];
      if (profile && !validProfiles.includes(profile)) {
        return res.status(400).json({ error: `Invalid profile. Must be one of: ${validProfiles.join(', ')}` });
      }
      const config = activateIronDome(profile);
      res.json({ success: true, config });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/iron-dome/deactivate', (_req: Request, res: Response) => {
    try {
      deactivateIronDome();
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/iron-dome/config', (req: Request, res: Response) => {
    try {
      const { killPhrase, trustedChannels } = req.body ?? {};

      if (killPhrase !== undefined) {
        if (typeof killPhrase !== 'string' || killPhrase.trim().length < 3 || killPhrase.trim().length > 80) {
          return res.status(400).json({ error: 'killPhrase must be a string between 3 and 80 characters' });
        }
      }

      if (trustedChannels !== undefined) {
        if (!Array.isArray(trustedChannels) || trustedChannels.some((value) => typeof value !== 'string')) {
          return res.status(400).json({ error: 'trustedChannels must be an array of strings' });
        }
      }

      const config = updateIronDomeConfig({
        ...(killPhrase !== undefined ? { killPhrase } : {}),
        ...(trustedChannels !== undefined ? { trustedChannels } : {}),
      });

      res.json({ success: true, config });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Emergency Stop — activates kill switch, blocks ALL agent operations
  app.post('/api/iron-dome/emergency-stop', (_req: Request, res: Response) => {
    try {
      activateKillSwitch({ source: 'manual' });
      res.json({
        stopped: true,
        killSwitchActive: true,
        message: 'Kill switch activated. All agent operations blocked. Iron Dome remains active. Investigate before resuming.',
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Resume agent operations after investigation (requires reason)
  app.post('/api/iron-dome/resume', (req: Request, res: Response) => {
    try {
      const reason = req.body?.reason || 'Resumed via dashboard';
      deactivateKillSwitch(reason);
      res.json({
        resumed: true,
        killSwitchActive: false,
        message: 'Kill switch deactivated. Agent operations resumed. Iron Dome continues protecting.',
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/iron-dome/scan', (req: Request, res: Response) => {
    try {
      const { text } = req.body;
      if (!text || typeof text !== 'string') {
        return res.status(400).json({ error: 'text (string) is required' });
      }
      const result = scanForInjection(text);
      res.json(result);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/iron-dome/audit', (req: Request, res: Response) => {
    try {
      const limit = parseInt(req.query.limit as string, 10) || 50;
      const logs = queryAgentOperations('iron-dome', { limit });
      res.json({ logs, total: logs.length });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // ============================================
  // BRAIN WORKER (Phase 4)
  // ============================================

  // ── Defence API v1 ──────────────────────────────────────────

  app.post('/api/v1/scan', handleV1Scan);
  app.post('/api/v1/scan/batch', handleV1ScanBatch);

  const brainWorker = new BrainWorker();
  registerIncidentRoutes(app);
  registerAdminRoutes(app, {
    brainWorker,
    requireNotLocked,
    requireProFeature,
    requireIronDomeAction: createIronDomeRouteGuard,
  });

  // Catch-all for unmatched API routes — return JSON instead of Express HTML 404
  app.all('/api/*', (_req: Request, res: Response) => {
    res.status(404).json({ error: 'Not found' });
  });

  // ============================================
  // WEBSOCKET SERVER
  // ============================================

  const wss = new WebSocketServer({ server, path: '/ws/events' });

  wss.on('connection', (ws: WebSocket, req) => {
    // Validate auth token from query string: ws://localhost:3001/ws/events?token=<token>
    const url = new URL(req.url ?? '', `http://${req.headers.host}`);
    const token = url.searchParams.get('token');
    if (!token || !validateSessionToken(token)) {
      ws.close(4401, 'Unauthorized');
      return;
    }

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
  const decayTickInterval = setInterval(() => {
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

  // Poll for X-Ray watch detections every 3 seconds and broadcast to WebSocket clients
  const xrayDetectionInterval = setInterval(() => {
    const events = readAndClearDetectionEvents();
    for (const event of events) {
      broadcast({
        type: 'xray_detection',
        timestamp: (event.timestamp as string) || new Date().toISOString(),
        data: event,
      });
    }
  }, 3000);

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
    clearInterval(decayTickInterval);
    clearInterval(eventPollInterval);
    clearInterval(cleanupInterval);
    clearInterval(xrayDetectionInterval);

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
      console.error(`    2. Or choose a different port: PORT=3002 shieldcortex --mode api\n`);
    } else {
      console.error(`[ShieldCortex] Server error: ${err.message}`);
    }
    // Stop worker and clean up before exiting
    brainWorker.stop();
    clearInterval(eventPollInterval);
    clearInterval(cleanupInterval);
    process.exit(1);
  });

  const HOST = process.env.SHIELDCORTEX_HOST || '127.0.0.1';
  server.listen(Number(PORT), HOST, () => {
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
