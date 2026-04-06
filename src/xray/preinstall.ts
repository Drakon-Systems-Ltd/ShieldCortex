/**
 * X-Ray Pre-install Hook
 *
 * Lightweight pre-install check that scans package.json scripts
 * for suspicious patterns. Designed to run as an npm lifecycle script:
 *   "preinstall": "shieldcortex xray-preinstall"
 *
 * Exit 1 blocks install (HIGH+ findings), exit 0 allows.
 */

import fs from 'fs';
import path from 'path';

import type { XRayFinding } from './types.js';
import { detectPatterns } from './patterns.js';
import { calculateTrustScore } from './trust-score.js';
import { appendActivity } from './activity.js';

// ── Constants ───────────────────────────────────────────────

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

// ── Public API ──────────────────────────────────────────────

/**
 * Run a lightweight pre-install check on package.json scripts.
 */
export async function handlePreinstallCheck(): Promise<void> {
  const pkgName = process.env.npm_package_name;
  const pkgVersion = process.env.npm_package_version;

  const cwd = process.cwd();
  const pkgJsonPath = path.join(cwd, 'package.json');

  if (!fs.existsSync(pkgJsonPath)) {
    console.log('ShieldCortex X-Ray pre-install check: PASS (no package.json found)');
    appendActivity({
      kind: 'preinstall',
      status: 'pass',
      target: pkgJsonPath,
      targetType: 'file',
      deepScan: false,
      trustScore: 100,
      riskLevel: 'SAFE',
      filesScanned: 0,
      findingCount: 0,
      scannedAt: new Date().toISOString(),
      summary: 'Skipped: no package.json found',
    });
    process.exit(0);
  }

  let pkgContent: string;
  try {
    pkgContent = fs.readFileSync(pkgJsonPath, 'utf-8');
  } catch {
    console.log('ShieldCortex X-Ray pre-install check: PASS (could not read package.json)');
    appendActivity({
      kind: 'preinstall',
      status: 'warn',
      target: pkgJsonPath,
      targetType: 'file',
      deepScan: false,
      trustScore: 100,
      riskLevel: 'SAFE',
      filesScanned: 0,
      findingCount: 0,
      scannedAt: new Date().toISOString(),
      summary: 'Skipped: could not read package.json',
    });
    process.exit(0);
  }

  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(pkgContent);
  } catch {
    console.log('ShieldCortex X-Ray pre-install check: PASS (invalid package.json)');
    appendActivity({
      kind: 'preinstall',
      status: 'warn',
      target: pkgJsonPath,
      targetType: 'file',
      deepScan: false,
      trustScore: 100,
      riskLevel: 'SAFE',
      filesScanned: 0,
      findingCount: 0,
      scannedAt: new Date().toISOString(),
      summary: 'Skipped: invalid package.json',
    });
    process.exit(0);
  }

  // Scan scripts section only (lightweight, fast)
  const scripts = pkg.scripts as Record<string, string> | undefined;
  const allFindings: XRayFinding[] = [];

  if (scripts && typeof scripts === 'object') {
    const scriptsJson = JSON.stringify({ scripts });
    const findings = detectPatterns(scriptsJson, 'package.json (scripts)');
    allFindings.push(...findings);
  }

  // Also scan the full package.json for metadata injection
  const metaFindings = detectPatterns(pkgContent, 'package.json');
  for (const f of metaFindings) {
    if (f.category === 'metadata-exploit' || f.category === 'ai-directive') {
      allFindings.push(f);
    }
  }

  const { score, riskLevel } = calculateTrustScore(allFindings);
  const maxSeverity = allFindings.reduce(
    (max, f) => Math.max(max, SEVERITY_RANK[f.severity] ?? 0),
    0,
  );

  const label = pkgName
    ? `${pkgName}@${pkgVersion || 'unknown'}`
    : path.basename(cwd);

  if (allFindings.length === 0) {
    console.log(`ShieldCortex X-Ray pre-install check: PASS — ${label} (score: ${score})`);
    appendActivity({
      kind: 'preinstall',
      status: 'pass',
      target: pkgJsonPath,
      targetType: 'file',
      deepScan: false,
      trustScore: score,
      riskLevel,
      filesScanned: 1,
      findingCount: 0,
      scannedAt: new Date().toISOString(),
      summary: `Preinstall check passed for ${label}`,
    });
    process.exit(0);
  }

  // Print findings
  console.log('');
  console.log(`ShieldCortex X-Ray pre-install scan: ${label}`);
  console.log(`  Trust Score: ${score}/100  Risk: ${riskLevel}`);
  console.log('');

  for (const f of allFindings) {
    console.log(`  [${f.severity.toUpperCase()}] [${f.category}] ${f.title}`);
    if (f.evidence) {
      console.log(`    Evidence: ${f.evidence}`);
    }
  }
  console.log('');

  // HIGH or CRITICAL → block
  if (maxSeverity >= SEVERITY_RANK.high) {
    console.log('ShieldCortex X-Ray pre-install check: FAIL — blocking install due to HIGH+ risk findings');
    appendActivity({
      kind: 'preinstall',
      status: 'blocked',
      target: pkgJsonPath,
      targetType: 'file',
      deepScan: false,
      trustScore: score,
      riskLevel,
      filesScanned: 1,
      findingCount: allFindings.length,
      scannedAt: new Date().toISOString(),
      summary: `Blocked install for ${label}`,
    });
    process.exit(1);
  }

  // MEDIUM or below → warn but allow
  console.log('ShieldCortex X-Ray pre-install check: PASS (warnings found, but below blocking threshold)');
  appendActivity({
    kind: 'preinstall',
    status: 'warn',
    target: pkgJsonPath,
    targetType: 'file',
    deepScan: false,
    trustScore: score,
    riskLevel,
    filesScanned: 1,
    findingCount: allFindings.length,
    scannedAt: new Date().toISOString(),
    summary: `Warnings detected for ${label}`,
  });
  process.exit(0);
}
