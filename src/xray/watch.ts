/**
 * X-Ray Watch Mode
 *
 * Watches a directory for file changes and incrementally re-scans
 * only the changed files, printing new findings as they appear.
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

import type { XRayFinding } from './types.js';
import { scanFile } from './file-scanner.js';
import { calculateTrustScore } from './trust-score.js';
import { formatXRayReport } from './report.js';

// ── Constants ───────────────────────────────────────────────

const DEBOUNCE_MS = 500;
const MAX_FILE_SIZE = 10 * 1024 * 1024;

const IGNORE_DIRS = new Set(['node_modules', '.git', 'dist', 'build']);

// ── Helpers ─────────────────────────────────────────────────

function shouldIgnore(filePath: string): boolean {
  const parts = filePath.split(path.sep);
  return parts.some(p => IGNORE_DIRS.has(p));
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
  const seenHashes = new Set<string>();
  const json = options?.json ?? false;

  // Debounce map: filePath → timeout
  const pending = new Map<string, ReturnType<typeof setTimeout>>();

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

    if (json) {
      const { score, riskLevel } = calculateTrustScore(newFindings);
      console.log(JSON.stringify({
        file: abs,
        trustScore: score,
        riskLevel,
        findings: newFindings,
        detectedAt: new Date().toISOString(),
      }));
    } else {
      const { score, riskLevel } = calculateTrustScore(newFindings);
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
      watcher.close();
      console.log(`\n${c.dim}Watch stopped.${c.reset}`);
      resolve();
    });
  });
}
