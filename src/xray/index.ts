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

// ── Re-exports ──────────────────────────────────────────────

export type { XRayTarget, XRayFinding, XRayCategory, XRayResult } from './types.js';
export { calculateTrustScore } from './trust-score.js';
export { detectPatterns, detectFilenameDirectives } from './patterns.js';
export { scanFile } from './file-scanner.js';
export { scanDirectory } from './dir-scanner.js';
export { inspectNpmPackage } from './npm-inspector.js';
export { formatXRayReport, formatXRayMarkdown } from './report.js';

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

  // Show usage if no target
  if (positional.length === 0) {
    console.error('Usage: shieldcortex xray <target> [--deep] [--json] [--markdown]');
    console.error('');
    console.error('  target:     npm package name, local file path, or directory path');
    console.error('  --deep      Deep scan with full analysis (Pro)');
    console.error('  --json      Output JSON result');
    console.error('  --markdown  Output markdown report');
    console.error('');
    console.error('Examples:');
    console.error('  shieldcortex xray ./src/');
    console.error('  shieldcortex xray package.json');
    console.error('  shieldcortex xray lodash --deep');
    process.exit(1);
  }

  const target = positional[0];

  // Deep scan requires Pro
  if (deep) {
    try {
      requireFeature('xray_deep');
    } catch (err) {
      console.error(err instanceof Error ? err.message : String(err));
      process.exit(1);
    }
  }

  // Check free tier limit
  if (!checkFreeLimit()) {
    console.error('Daily scan limit reached. Upgrade to Pro for unlimited scans.');
    console.error('  https://shieldcortex.ai/pricing');
    process.exit(1);
  }

  let result: XRayResult;

  if (isNpmPackageName(target)) {
    // NPM package inspection
    if (!isFeatureEnabled('xray_deep')) {
      console.error('npm registry inspection requires a Pro licence.');
      console.error('Free tier supports local file and directory scans only.');
      console.error('  Upgrade: https://shieldcortex.ai/pricing');
      process.exit(1);
    }
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
      console.error(`Target is not a file or directory: ${resolved}`);
      process.exit(1);
    }
  }

  // Track usage
  incrementUsage();

  // Output
  if (jsonOutput) {
    console.log(JSON.stringify(result, null, 2));
  } else if (markdownOutput) {
    console.log(formatXRayMarkdown(result));
  } else {
    console.log(formatXRayReport(result));
  }
}
