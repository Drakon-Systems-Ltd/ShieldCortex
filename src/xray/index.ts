/**
 * X-Ray — Package, File & Plugin Risk Inspector
 *
 * Main entry point for the `shieldcortex xray` CLI command.
 * Inspects npm packages, local files, and directories for hidden risk.
 *
 * Free tier: local scans only (no npm registry), max 5 scans/day.
 * Pro tier:  npm registry analysis, deep scanning, unlimited scans.
 */

import fs from 'fs';
import path from 'path';
import os from 'os';

import { isFeatureEnabled, requireFeature } from '../license/gate.js';
import type { XRayResult } from './types.js';
import { scanFile } from './file-scanner.js';
import { scanDirectory } from './dir-scanner.js';
import { inspectNpmPackage } from './npm-inspector.js';
import { calculateTrustScore } from './trust-score.js';
import { formatXRayReport, formatXRayMarkdown } from './report.js';
import { watchDirectory } from './watch.js';
import { appendActivity, appendHistory, createHistoryEntry, type XRayTargetType } from './activity.js';

// ── Re-exports ──────────────────────────────────────────────

export type { XRayTarget, XRayFinding, XRayCategory, XRayResult } from './types.js';
export { calculateTrustScore } from './trust-score.js';
export { detectPatterns, detectFilenameDirectives } from './patterns.js';
export { scanFile } from './file-scanner.js';
export { scanDirectory } from './dir-scanner.js';
export { inspectNpmPackage } from './npm-inspector.js';
export { formatXRayReport, formatXRayMarkdown } from './report.js';
export { watchDirectory } from './watch.js';
export { handlePreinstallCheck } from './preinstall.js';
export { xrayMemoryContent } from './memory-guard.js';
export type { MemoryGuardResult } from './memory-guard.js';

// ── Usage tracking ──────────────────────────────────────────

const USAGE_FILE = path.join(os.homedir(), '.shieldcortex', 'xray-usage.json');
const FREE_DAILY_LIMIT = 5;

interface UsageData {
  date: string;
  count: number;
}

function getUsage(): UsageData {
  try {
    const raw = fs.readFileSync(USAGE_FILE, 'utf-8');
    return JSON.parse(raw);
  } catch {
    return { date: '', count: 0 };
  }
}

function incrementUsage(): void {
  const today = new Date().toISOString().slice(0, 10);
  const usage = getUsage();

  if (usage.date !== today) {
    // New day — reset
    usage.date = today;
    usage.count = 1;
  } else {
    usage.count++;
  }

  const dir = path.dirname(USAGE_FILE);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(USAGE_FILE, JSON.stringify(usage));
}

function checkFreeLimit(): boolean {
  if (isFeatureEnabled('xray_deep')) return true; // Pro users are unlimited

  const today = new Date().toISOString().slice(0, 10);
  const usage = getUsage();

  if (usage.date !== today) return true; // New day
  return usage.count < FREE_DAILY_LIMIT;
}

// ── Target detection ────────────────────────────────────────

function isNpmPackageName(target: string): boolean {
  // npm package names: lowercase, may start with @scope/
  if (target.startsWith('.') || target.startsWith('/') || target.startsWith('~')) return false;
  if (fs.existsSync(target)) return false; // Local path takes priority
  return /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/.test(target);
}

// ── CLI handler ─────────────────────────────────────────────

/**
 * Handle the `shieldcortex xray` CLI command.
 */
export async function handleXRayCommand(args: string[]): Promise<void> {
  const flags = new Set(args.filter(a => a.startsWith('--')));
  const positional = args.filter(a => !a.startsWith('--'));

  const deep = flags.has('--deep');
  const jsonOutput = flags.has('--json');
  const markdownOutput = flags.has('--markdown');
  const ciMode = flags.has('--ci');
  const watchMode = flags.has('--watch');
  const ciThreshold = (() => {
    const t = args.find(a => a.startsWith('--threshold='));
    if (t) return t.split('=')[1]?.toUpperCase() || 'HIGH';
    return 'HIGH';
  })();

  // Show usage if no target
  if (positional.length === 0) {
    console.error('Usage: shieldcortex xray <target> [--deep] [--json] [--markdown] [--watch]');
    console.error('');
    console.error('  target:     npm package name, local file path, or directory path');
    console.error('  --deep      Deep scan with full analysis (Pro)');
    console.error('  --json      Output JSON result');
    console.error('  --markdown  Output markdown report');
    console.error('  --ci        CI/CD mode: exit code 1 if risk >= threshold');
    console.error('  --threshold=LEVEL  Risk threshold for --ci (CRITICAL|HIGH|MEDIUM|LOW, default: HIGH)');
    console.error('  --watch     Watch directory for changes and scan incrementally');
    console.error('');
    console.error('Examples:');
    console.error('  shieldcortex xray ./src/');
    console.error('  shieldcortex xray package.json');
    console.error('  shieldcortex xray lodash --deep');
    console.error('  shieldcortex xray ./src --watch');
    process.exit(1);
  }

  const target = positional[0];

  // Deep scan requires Pro (checked before watch mode to prevent bypass)
  if (deep) {
    try {
      requireFeature('xray_deep');
    } catch (err) {
      console.error(err instanceof Error ? err.message : String(err));
      process.exit(1);
    }
  }

  // Check free tier limit (checked before watch mode to prevent bypass)
  if (!checkFreeLimit()) {
    console.error('Daily scan limit reached. Upgrade to Pro for unlimited scans.');
    console.error('  https://shieldcortex.ai/pricing');
    process.exit(1);
  }

  // Watch mode — delegate to watchDirectory (after license/usage gates)
  if (watchMode) {
    const resolved = path.resolve(target);
    if (!fs.existsSync(resolved) || !fs.statSync(resolved).isDirectory()) {
      console.error(`--watch requires a directory target: ${resolved}`);
      process.exit(1);
    }
    await watchDirectory(resolved, deep, { json: jsonOutput });
    return;
  }

  let result: XRayResult;
  let targetType: XRayTargetType = 'file';

  if (isNpmPackageName(target)) {
    // NPM package inspection
    if (!isFeatureEnabled('xray_deep')) {
      console.error('npm registry inspection requires a Pro licence.');
      console.error('Free tier supports local file and directory scans only.');
      console.error('  Upgrade: https://shieldcortex.ai/pricing');
      process.exit(1);
    }
    targetType = 'npm';
    result = await inspectNpmPackage(target, deep);
  } else {
    // Local file or directory
    const resolved = path.resolve(target);

    if (!fs.existsSync(resolved)) {
      console.error(`Target not found: ${resolved}`);
      process.exit(1);
    }

    const stat = fs.statSync(resolved);

    if (stat.isDirectory()) {
      targetType = 'dir';
      result = await scanDirectory(resolved, deep);
    } else if (stat.isFile()) {
      targetType = 'file';
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
      console.error(`Target is not a file or directory: ${resolved}`);
      process.exit(1);
    }
  }

  // Track usage
  incrementUsage();
  appendHistory(createHistoryEntry(result, targetType));
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

  // Output
  if (jsonOutput) {
    console.log(JSON.stringify(result, null, 2));
  } else if (markdownOutput) {
    console.log(formatXRayMarkdown(result));
  } else {
    console.log(formatXRayReport(result));
  }

  // CI/CD gate: exit 1 if risk level meets or exceeds threshold
  if (ciMode) {
    const levels: Record<string, number> = { SAFE: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
    const resultLevel = levels[result.riskLevel] ?? 0;
    const thresholdLevel = levels[ciThreshold] ?? 3;
    if (resultLevel >= thresholdLevel) {
      process.exit(1);
    }
    process.exit(0);
  }
}
