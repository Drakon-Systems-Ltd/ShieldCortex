/**
 * X-Ray Watch Mode
 *
 * Watches a directory for file changes and incrementally re-scans
 * only the changed files, printing new findings as they appear.
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';

import type { XRayFinding } from './types.js';
import { scanFile } from './file-scanner.js';
import { calculateTrustScore } from './trust-score.js';
import {
  appendActivity,
  emitDetectionEvent,
  endWatchSession,
  heartbeatWatchSession,
  recordWatchSessionEvent,
  startWatchSession,
} from './activity.js';
import { addFindings } from './findings-store.js';

// ── Constants ───────────────────────────────────────────────

const DEBOUNCE_MS = 500;
const MAX_FILE_SIZE = 10 * 1024 * 1024;

const IGNORE_DIRS = new Set([
  'node_modules', '.git', '.next', 'dist', 'build', '.cache', '.turbo', '__pycache__', '.venv',
  '.shieldcortex', 'Library', 'Caches', 'Cache_Data', 'GPUCache', 'Code Cache',
  'Application Support', 'Group Containers', 'Saved Application State',
  'Containers', '.Trash', '.npm', '.nvm', '.local',
]);

/** Paths that should never be watched — too broad or trigger OS permission dialogs */
const IGNORE_PATH_PATTERNS = [
  '/private/var/',
  '/var/db/',
  '/var/log/',
  '/var/folders/',
  '/System/',
  '/Applications/',
  '/usr/',
  '/Library/',          // system Library
  '/tmp/com.apple.',
];

// ── Helpers ─────────────────────────────────────────────────

function shouldIgnore(filePath: string): boolean {
  const parts = filePath.split(path.sep);
  if (parts.some(p => IGNORE_DIRS.has(p))) return true;

  // Resolve symlinks to check the real path
  let abs: string;
  try {
    abs = fs.realpathSync(path.resolve(filePath));
  } catch {
    abs = path.resolve(filePath);
  }

  if (IGNORE_PATH_PATTERNS.some(p => abs.includes(p))) return true;

  // Also check the real path's directory components (symlink may land in ignored dir)
  const realParts = abs.split(path.sep);
  if (realParts.some(p => IGNORE_DIRS.has(p))) return true;

  return false;
}

function findingHash(f: XRayFinding): string {
  const key = `${f.file || ''}|${f.category}|${f.title}`;
  return crypto.createHash('sha256').update(key).digest('hex');
}

// ── ANSI colours ────────────────────────────────────────────

const c = {
  reset:     '\x1b[0m',
  bold:      '\x1b[1m',
  dim:       '\x1b[2m',
  red:       '\x1b[31m',
  green:     '\x1b[32m',
  yellow:    '\x1b[33m',
  cyan:      '\x1b[36m',
  brightRed: '\x1b[91m',
};

function severityColour(severity: string): string {
  switch (severity) {
    case 'critical': return c.red;
    case 'high': return c.brightRed;
    case 'medium': return c.yellow;
    case 'low': return c.cyan;
    default: return c.dim;
  }
}

// ── Public API ──────────────────────────────────────────────

/**
 * Watch a directory for changes and incrementally scan changed files.
 */
export async function watchDirectory(
  dirPath: string,
  deep: boolean,
  options?: { json?: boolean },
): Promise<void> {
  const resolved = path.resolve(dirPath);

  // Block overly broad paths that trigger macOS permission dialogs
  const homedir = os.homedir();
  const dangerousPaths = ['/', '/Users', '/tmp', '/private', '/var', '/System', '/Applications', homedir];
  if (dangerousPaths.includes(resolved)) {
    console.error(`${c.red}${c.bold}Error:${c.reset} Watching "${resolved}" is too broad — it would scan system files and trigger OS permission dialogs.`);
    console.error(`${c.dim}Watch a specific project directory instead, e.g.:${c.reset}`);
    console.error(`  shieldcortex xray ${homedir}/Development/my-project --watch`);
    process.exit(1);
  }

  const seenHashes = new Set<string>();
  const json = options?.json ?? false;
  const session = startWatchSession(resolved, deep);

  // Debounce map: filePath → timeout
  const pending = new Map<string, ReturnType<typeof setTimeout>>();
  const heartbeat = setInterval(() => {
    heartbeatWatchSession(session.id);
  }, 30_000);

  console.log(`${c.cyan}${c.bold}Watching ${resolved} for changes... (Ctrl+C to stop)${c.reset}`);

  async function handleChange(filePath: string): Promise<void> {
    const abs = path.resolve(resolved, filePath);

    if (shouldIgnore(abs)) return;

    // Check exists & size
    let stat: fs.Stats;
    try {
      stat = fs.statSync(abs);
    } catch {
      return;
    }
    if (!stat.isFile() || stat.size > MAX_FILE_SIZE) return;

    const findings = await scanFile(abs, deep);
    const newFindings: XRayFinding[] = [];

    for (const f of findings) {
      const h = findingHash(f);
      if (!seenHashes.has(h)) {
        seenHashes.add(h);
        newFindings.push(f);
      }
    }

    if (newFindings.length === 0) return;

    const { score, riskLevel } = calculateTrustScore(newFindings);
    const scannedAt = new Date().toISOString();

    addFindings(session.id, 'watch', abs, newFindings);

    appendActivity({
      kind: 'watch',
      status: 'detected',
      target: abs,
      targetType: 'file',
      deepScan: deep,
      trustScore: score,
      riskLevel,
      filesScanned: 1,
      findingCount: newFindings.length,
      scannedAt,
      summary: `${newFindings.length} new findings detected in watch mode`,
    });
    recordWatchSessionEvent(session.id, {
      findingsDetected: newFindings.length,
      riskLevel,
      summary: `${path.basename(abs)} triggered ${newFindings.length} new findings`,
      scannedAt,
    });
    emitDetectionEvent({
      target: abs,
      findingCount: newFindings.length,
      riskLevel,
      severity: newFindings[0]?.severity ?? 'info',
      summary: `${newFindings.length} new finding${newFindings.length === 1 ? '' : 's'} in ${path.basename(abs)}`,
    });

    if (json) {
      console.log(JSON.stringify({
        file: abs,
        trustScore: score,
        riskLevel,
        findings: newFindings,
        detectedAt: scannedAt,
      }));
    } else {
      console.log('');
      console.log(`${c.bold}[${new Date().toLocaleTimeString()}]${c.reset} ${c.cyan}${abs}${c.reset}  (score: ${score}, risk: ${riskLevel})`);
      for (const f of newFindings) {
        const sc = severityColour(f.severity);
        console.log(`  ${sc}[${f.severity.toUpperCase()}]${c.reset} [${f.category}] ${f.title}`);
        if (f.evidence) {
          console.log(`    ${c.dim}${f.evidence}${c.reset}`);
        }
      }
    }
  }

  const watcher = fs.watch(resolved, { recursive: true }, (_event, filename) => {
    if (!filename) return;
    const filePath = filename.toString();

    // Debounce
    const existing = pending.get(filePath);
    if (existing) clearTimeout(existing);

    pending.set(filePath, setTimeout(() => {
      pending.delete(filePath);
      handleChange(filePath).catch(() => {});
    }, DEBOUNCE_MS));
  });

  // Keep the process alive until Ctrl+C
  return new Promise<void>((resolve) => {
    process.on('SIGINT', () => {
      clearInterval(heartbeat);
      watcher.close();
      endWatchSession(session.id);
      console.log(`\n${c.dim}Watch stopped.${c.reset}`);
      resolve();
    });
  });
}
