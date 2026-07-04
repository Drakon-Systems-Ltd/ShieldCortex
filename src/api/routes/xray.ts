import type { Express, Request, Response } from 'express';
import { execFile, spawn, type ChildProcess } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { getRequiredTier, isFeatureEnabled, requireFeature, FeatureGatedError } from '../../license/gate.js';
import type { FeatureGatedResponse } from '../../license/types.js';
import type { XRayResult } from '../../xray/types.js';
import { scanDirectory } from '../../xray/dir-scanner.js';
import { scanFile } from '../../xray/file-scanner.js';
import { inspectNpmPackage } from '../../xray/npm-inspector.js';
import { calculateTrustScore } from '../../xray/trust-score.js';
import {
  appendActivity,
  appendHistory,
  createHistoryEntry,
  getHistoryEntry,
  type XRayActivityEntry,
  type XRayHistoryEntry,
  type XRayWatchSessionEntry,
  readActivity,
  readHistory,
  readWatchSessions,
} from '../../xray/activity.js';
import { addFindings } from '../../xray/findings-store.js';

type Middleware = (_req: Request, res: Response, next: (err?: unknown) => void) => void;

function runAppleScript(lines: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile('osascript', lines.flatMap((line) => ['-e', line]), (error, stdout, stderr) => {
      if (error) {
        const message = stderr?.trim() || error.message;
        reject(new Error(message));
        return;
      }
      resolve(stdout.trim());
    });
  });
}

function detectTargetType(target: string): 'npm' | 'file' | 'dir' {
  if (target.startsWith('.') || target.startsWith('/') || target.startsWith('~')) {
    const resolved = path.resolve(target);
    const stat = fs.statSync(resolved);
    return stat.isDirectory() ? 'dir' : 'file';
  }

  if (fs.existsSync(target)) {
    const stat = fs.statSync(target);
    return stat.isDirectory() ? 'dir' : 'file';
  }

  return 'npm';
}

function toFeatureGateBody(err: FeatureGatedError): FeatureGatedResponse {
  return {
    error: 'Feature requires an Enterprise licence',
    code: 'FEATURE_GATED',
    feature: err.feature,
    requiredTier: err.requiredTier,
    upgradeUrl: 'mailto:sales@drakonsystems.com',
  };
}

function matchesText(value: string, query: string | undefined): boolean {
  if (!query) return true;
  return value.toLowerCase().includes(query.toLowerCase());
}

function filterHistory(entries: XRayHistoryEntry[], req: Request): XRayHistoryEntry[] {
  const risk = typeof req.query.risk === 'string' ? req.query.risk.toUpperCase() : undefined;
  const targetType = typeof req.query.targetType === 'string' ? req.query.targetType : undefined;
  const deep = typeof req.query.deep === 'string' ? req.query.deep === 'true' : undefined;
  const search = typeof req.query.search === 'string' ? req.query.search.trim() : undefined;

  return entries.filter((entry) => {
    if (risk && entry.riskLevel !== risk) return false;
    if (targetType && entry.targetType !== targetType) return false;
    if (deep !== undefined && entry.deepScan !== deep) return false;
    if (!matchesText(entry.target, search)) return false;
    return true;
  });
}

function filterActivity(entries: XRayActivityEntry[], req: Request): XRayActivityEntry[] {
  const kind = typeof req.query.kind === 'string' ? req.query.kind : undefined;
  const status = typeof req.query.status === 'string' ? req.query.status : undefined;
  const risk = typeof req.query.risk === 'string' ? req.query.risk.toUpperCase() : undefined;
  const targetType = typeof req.query.targetType === 'string' ? req.query.targetType : undefined;
  const search = typeof req.query.search === 'string' ? req.query.search.trim() : undefined;

  return entries.filter((entry) => {
    if (kind && entry.kind !== kind) return false;
    if (status && entry.status !== status) return false;
    if (risk && entry.riskLevel !== risk) return false;
    if (targetType && entry.targetType !== targetType) return false;
    if (!matchesText(entry.target, search)) return false;
    return true;
  });
}

function filterWatchSessions(entries: XRayWatchSessionEntry[], req: Request): XRayWatchSessionEntry[] {
  const state = typeof req.query.state === 'string' ? req.query.state : undefined;
  const search = typeof req.query.search === 'string' ? req.query.search.trim() : undefined;
  const deep = typeof req.query.deep === 'string' ? req.query.deep === 'true' : undefined;

  return entries.filter((entry) => {
    if (state && state !== 'all' && entry.state !== state) return false;
    if (deep !== undefined && entry.deepScan !== deep) return false;
    if (!matchesText(entry.root, search)) return false;
    return true;
  });
}

export function registerXRayRoutes(app: Express, requireNotLocked: Middleware): void {
  app.post('/api/xray/pick-target', requireNotLocked, async (req: Request, res: Response) => {
    try {
      if (os.platform() !== 'darwin') {
        return res.status(501).json({ error: 'Native picker is currently implemented for macOS only' });
      }

      const kind = req.body?.kind === 'folder' ? 'folder' : 'file';
      const script = kind === 'folder'
        ? [
            'try',
            'set chosenFolder to choose folder with prompt "Choose a folder to scan with ShieldCortex X-Ray"',
            'POSIX path of chosenFolder',
            'on error number -128',
            'return ""',
            'end try',
          ]
        : [
            'try',
            'set chosenFile to choose file with prompt "Choose a file to scan with ShieldCortex X-Ray"',
            'POSIX path of chosenFile',
            'on error number -128',
            'return ""',
            'end try',
          ];

      const selectedPath = await runAppleScript(script);
      res.json({ path: selectedPath || null, kind });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/xray/history', (req: Request, res: Response) => {
    const entries = filterHistory(readHistory(), req);
    res.json({ entries });
  });

  app.get('/api/xray/history/:id', (req: Request, res: Response) => {
    const entry = getHistoryEntry(String(req.params.id));
    if (!entry) {
      return res.status(404).json({ error: 'Scan history entry not found' });
    }
    res.json({ entry });
  });

  app.get('/api/xray/activity', (req: Request, res: Response) => {
    const limit = Math.max(1, Math.min(100, Number(req.query.limit) || 25));
    const entries = filterActivity(readActivity(100), req).slice(0, limit);
    res.json({ entries });
  });

  app.get('/api/xray/watch-sessions', (req: Request, res: Response) => {
    const limit = Math.max(1, Math.min(50, Number(req.query.limit) || 20));
    const entries = filterWatchSessions(readWatchSessions(), req).slice(0, limit);
    res.json({ entries });
  });

  app.get('/api/xray/status', (_req: Request, res: Response) => {
    const history = readHistory();
    const activity = readActivity(12);
    const watchSessions = readWatchSessions();
    const recentBlocks = activity.filter((entry) => entry.status === 'blocked').length;

    res.json({
      capabilities: {
        localScan: true,
        watchMode: true,
        preinstallHook: true,
        npmInspection: isFeatureEnabled('xray_deep'),
        deepScan: isFeatureEnabled('xray_deep'),
        requiredTier: getRequiredTier('xray_deep'),
      },
      summary: {
        scans: history.length,
        blockedEvents: recentBlocks,
        highRiskScans: history.filter((entry) => entry.riskLevel === 'HIGH' || entry.riskLevel === 'CRITICAL').length,
        lastScannedAt: history[0]?.scannedAt ?? null,
        activeWatchRoots: watchSessions.filter((entry) => entry.active).length,
        staleWatchRoots: watchSessions.filter((entry) => entry.state === 'stale').length,
        watchSessions: watchSessions.length,
      },
    });
  });

  app.post('/api/xray/scan', requireNotLocked, async (req: Request, res: Response) => {
    try {
      const target = typeof req.body?.target === 'string' ? req.body.target.trim() : '';
      const deep = req.body?.deep === true;

      if (!target) {
        return res.status(400).json({ error: '"target" is required' });
      }

      if (deep) {
        try {
          requireFeature('xray_deep');
        } catch (err) {
          if (err instanceof FeatureGatedError) {
            return res.status(403).json(toFeatureGateBody(err));
          }
          throw err;
        }
      }

      const targetType = detectTargetType(target);
      // npm registry inspection is Free (xray_deep was un-gated with the
      // Free + Enterprise repricing) — no per-target licence branch needed.

      let result: XRayResult;

      if (targetType === 'npm') {
        result = await inspectNpmPackage(target, deep);
      } else {
        const resolved = path.resolve(target);
        if (!fs.existsSync(resolved)) {
          return res.status(404).json({ error: `Target not found: ${resolved}` });
        }

        const stat = fs.statSync(resolved);
        if (stat.isDirectory()) {
          result = await scanDirectory(resolved, deep);
        } else if (stat.isFile()) {
          const findings = await scanFile(resolved, deep);
          const { score, riskLevel } = calculateTrustScore(findings);
          result = {
            target: resolved,
            trustScore: score,
            riskLevel,
            findings,
            filesScanned: 1,
            scannedAt: new Date(),
            deepScan: deep,
          };
        } else {
          return res.status(400).json({ error: 'Target must be a file, directory, or npm package' });
        }
      }

      const historyEntry = createHistoryEntry(result, targetType);
      appendHistory(historyEntry);

      const persistedFindings = result.findings.length > 0
        ? addFindings(historyEntry.id, 'scan', result.target, result.findings)
        : [];

      appendActivity({
        kind: 'scan',
        status: result.findings.length === 0 ? 'pass' : result.riskLevel === 'LOW' ? 'warn' : 'detected',
        target: result.target,
        targetType,
        deepScan: result.deepScan,
        trustScore: result.trustScore,
        riskLevel: result.riskLevel,
        filesScanned: result.filesScanned,
        findingCount: result.findings.length,
        scannedAt: result.scannedAt.toISOString(),
        summary: result.findings.length === 0
          ? 'No findings detected'
          : `${result.findings.length} findings across ${result.filesScanned} files`,
      });

      res.json({
        result: {
          ...result,
          scannedAt: result.scannedAt.toISOString(),
        },
        persistedFindings,
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // ── Watch mode management (start/stop from dashboard) ────────

  const activeWatchers = new Map<string, ChildProcess>();
  const MAX_CONCURRENT_WATCHERS = 10;

  app.post('/api/xray/watch/start', requireNotLocked, async (req: Request, res: Response) => {
    try {
      const target = typeof req.body?.target === 'string' ? req.body.target.trim() : '';
      const deep = req.body?.deep === true;

      if (!target) {
        return res.status(400).json({ error: '"target" is required' });
      }

      const resolved = path.resolve(target);

      if (!fs.existsSync(resolved)) {
        return res.status(400).json({ error: `Target does not exist: ${resolved}` });
      }

      const stat = fs.statSync(resolved);
      if (!stat.isDirectory()) {
        return res.status(400).json({ error: 'Watch mode only works on directories' });
      }

      // Block overly broad paths that would trigger macOS permission dialogs
      const dangerousPaths = ['/', '/Users', '/tmp', '/private', '/var', '/System', '/Applications'];
      const homedir = os.homedir();
      if (dangerousPaths.includes(resolved) || resolved === homedir) {
        return res.status(400).json({
          error: `Watching "${resolved}" is too broad — it would scan system files and trigger OS permission dialogs. Watch a specific project directory instead, e.g. ${homedir}/Development/my-project`,
        });
      }

      // Check if already watching this directory
      if (activeWatchers.has(resolved)) {
        return res.status(409).json({ error: 'Already watching this directory', root: resolved });
      }

      // Limit concurrent watchers to prevent DoS
      if (activeWatchers.size >= MAX_CONCURRENT_WATCHERS) {
        return res.status(429).json({
          error: `Maximum ${MAX_CONCURRENT_WATCHERS} concurrent watchers reached. Stop an existing watcher first.`,
          activeCount: activeWatchers.size,
        });
      }

      // Spawn shieldcortex xray --watch as a detached child
      const args = ['xray', resolved, '--watch'];
      if (deep) args.push('--deep');

      const shieldcortexBin = process.argv[1]?.replace(/\/dist\/.*$/, '/dist/index.js') || 'shieldcortex';
      const child = spawn(process.execPath, [shieldcortexBin, ...args], {
        detached: true,
        stdio: 'ignore',
        env: { ...process.env },
      });

      child.unref();
      activeWatchers.set(resolved, child);

      child.on('exit', () => {
        activeWatchers.delete(resolved);
      });

      res.json({
        started: true,
        root: resolved,
        deep,
        pid: child.pid,
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post('/api/xray/watch/stop', requireNotLocked, (req: Request, res: Response) => {
    try {
      const target = typeof req.body?.target === 'string' ? req.body.target.trim() : '';

      if (!target) {
        return res.status(400).json({ error: '"target" is required' });
      }

      const resolved = path.resolve(target);
      const child = activeWatchers.get(resolved);

      if (!child) {
        return res.status(404).json({ error: 'No active watcher for this directory', root: resolved });
      }

      child.kill('SIGTERM');
      activeWatchers.delete(resolved);

      res.json({ stopped: true, root: resolved });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/xray/watch/active', (_req: Request, res: Response) => {
    const watchers = Array.from(activeWatchers.entries()).map(([root, child]) => ({
      root,
      pid: child.pid,
      active: !child.killed,
    }));
    res.json({ watchers });
  });
}
