/**
 * X-Ray Directory Scanner
 *
 * Walks a directory tree, scans each file, checks package.json if present,
 * and aggregates findings into a single XRayResult.
 */

import fs from 'fs';
import path from 'path';

import type { XRayResult } from './types.js';
import { scanFile } from './file-scanner.js';
import { calculateTrustScore } from './trust-score.js';
import type { XRayFinding } from './types.js';

// ── Constants ───────────────────────────────────────────────

/** Directories to skip when walking. */
const SKIP_DIRS = new Set([
  'node_modules', '.git', '.svn', '.hg', 'dist', 'build', '.next',
  '__pycache__', '.tox', '.venv', 'venv', '.cache', 'coverage',
  'Caches', 'CacheStorage', 'IndexedDB', 'GPUCache',
]);

/** Absolute path prefixes to never scan — system/OS files that always produce false positives. */
const SKIP_PATH_PREFIXES = [
  '/System/',
  '/Library/',
  '/usr/',
  '/bin/',
  '/sbin/',
  '/private/var/',
  '/System/Volumes/Preboot/',
  '/System/Volumes/Data/private/',
];

/** Path segments that indicate non-code data we should skip. */
const SKIP_PATH_SEGMENTS = [
  '/Library/Caches/',
  '/Library/Application Support/Google/Chrome/',
  '/Library/Application Support/Firefox/',
  '/Library/Application Support/Arc/',
  '/Library/Containers/',
  '/Library/News/',
  '/Library/Mail/',
  '/Library/Messages/',
  '/Library/Safari/',
  '/Library/Cookies/',
  '/Library/Saved Application State/',
  '/Library/WebKit/',
  '/.Trash/',
];

/** Maximum number of files to scan per directory. */
const MAX_FILES = 5000;

/** Check if a full file path should be excluded from scanning. */
function isExcludedPath(filePath: string): boolean {
  for (const prefix of SKIP_PATH_PREFIXES) {
    if (filePath.startsWith(prefix)) return true;
  }
  for (const segment of SKIP_PATH_SEGMENTS) {
    if (filePath.includes(segment)) return true;
  }
  return false;
}

// ── Directory walker ────────────────────────────────────────

function walkDir(dirPath: string, files: string[], depth: number = 0): void {
  if (depth > 20 || files.length >= MAX_FILES) return;

  // Skip entire system/cache directory trees early
  if (isExcludedPath(dirPath + '/')) return;

  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dirPath, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (files.length >= MAX_FILES) break;

    const fullPath = path.join(dirPath, entry.name);

    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name) && !entry.name.startsWith('.')) {
        walkDir(fullPath, files, depth + 1);
      }
    } else if (entry.isFile()) {
      if (!isExcludedPath(fullPath)) {
        files.push(fullPath);
      }
    }
  }
}

// ── Public API ──────────────────────────────────────────────

/**
 * Scan an entire directory for X-Ray findings.
 *
 * @param dirPath - Path to the directory to scan
 * @param deep - If true, performs deeper analysis (Pro feature)
 */
export async function scanDirectory(dirPath: string, deep: boolean): Promise<XRayResult> {
  const startTime = Date.now();
  const allFindings: XRayFinding[] = [];

  // Collect files
  const files: string[] = [];
  walkDir(dirPath, files);

  // Scan each file
  for (const file of files) {
    const findings = await scanFile(file, deep);
    allFindings.push(...findings);
  }

  // Check for package.json at root
  const pkgJsonPath = path.join(dirPath, 'package.json');
  if (fs.existsSync(pkgJsonPath) && !files.includes(pkgJsonPath)) {
    const findings = await scanFile(pkgJsonPath, deep);
    allFindings.push(...findings);
  }

  const { score, riskLevel } = calculateTrustScore(allFindings);

  return {
    target: dirPath,
    trustScore: score,
    riskLevel,
    findings: allFindings,
    filesScanned: files.length,
    scannedAt: new Date(),
    deepScan: deep,
  };
}
