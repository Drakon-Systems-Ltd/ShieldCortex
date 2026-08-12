/**
 * Dependency Scanner
 *
 * Scans node_modules for:
 *   1. Known malicious packages (CRITICAL)
 *   2. Typosquat packages — Levenshtein distance 1-2 from popular packages (HIGH)
 *   3. Suspicious postinstall scripts — network, exec, credential access patterns (HIGH/MEDIUM)
 *   4. New packages with postinstall scripts published < 7 days ago (MEDIUM)
 *
 * Inspired by the axios 1.14.1 supply chain attack and the Claude Code
 * typosquatting attacks discovered 31 Mar 2026.
 *
 * Usage:
 *   shieldcortex audit --deps                      # scan ./node_modules
 *   shieldcortex audit --deps-global               # scan global npm prefix
 *   shieldcortex audit --deps-path /some/path      # scan specific path
 *   shieldcortex audit --deps --quarantine         # scan + quarantine CRITICAL/HIGH
 *   shieldcortex audit --deps --clean --force      # scan + permanently delete CRITICAL
 *   shieldcortex audit --deps --auto-protect       # scan + auto-quarantine CRITICAL
 */

import { readdirSync, readFileSync, existsSync, mkdirSync, renameSync, rmSync, writeFileSync } from 'fs';
import { mkdirSecure } from '../setup/state-permissions.js';
import { join, resolve } from 'path';
import { execSync } from 'child_process';
import { homedir } from 'os';
import type { AuditFinding, ScannerResult } from './types.js';

const LEARN_MORE_MALICIOUS  = 'https://shieldcortex.ai/docs/threats/supply-chain';
const LEARN_MORE_TYPOSQUAT  = 'https://shieldcortex.ai/docs/threats/typosquatting';
const LEARN_MORE_POSTINSTALL = 'https://shieldcortex.ai/docs/threats/malicious-scripts';

// ── 1. Known Malicious Packages ─────────────────────────────────────────────

const KNOWN_MALICIOUS: string[] = [
  // Discovered packages — add more as they are found
  'plain-crypto-js',
  'color-diff-napi',
  'modifiers-napi',
  // axios supply chain imposters (March/April 2026)
  'axios-http',
  'axios-utils',
  // Claude Code typosquatting (31 Mar 2026)
  'claude-code-sdk',
  'claude-code-helper',
  '@anthropic/claude-code-utils',
  // Common malicious patterns seen in the wild
  'event-stream-http',
  'flatmap-stream',
  'getcookies',
  'eslint-scope-backdoor',
  'eslint-config-airbnb-standard',
  'xpc-connection',
];

// ── 2. Popular Packages for Typosquat Detection ─────────────────────────────

const POPULAR_PACKAGES: string[] = [
  'axios', 'express', 'lodash', 'react', 'next', 'vue', 'crypto-js',
  'webpack', 'babel', 'typescript', 'eslint', 'prettier', 'jest',
  'mocha', 'chalk', 'commander', 'inquirer', 'dotenv', 'cors',
  'body-parser', 'mongoose', 'sequelize', 'prisma', 'socket.io',
  'jsonwebtoken', 'bcrypt', 'uuid', 'moment', 'dayjs', 'sharp',
  'puppeteer', 'playwright', 'onnxruntime-node', 'better-sqlite3',
];

// ── 3. Suspicious Script Patterns ───────────────────────────────────────────

interface SuspiciousPattern {
  regex: RegExp;
  label: string;
}

const SUSPICIOUS_PATTERNS: SuspiciousPattern[] = [
  // Downloading payloads
  { regex: /\bcurl\b/i,                         label: 'curl (payload download)' },
  { regex: /\bwget\b/i,                         label: 'wget (payload download)' },
  { regex: /\bfetch\s*\(/i,                     label: 'fetch() (HTTP request)' },
  { regex: /https?:\/\//i,                      label: 'HTTP/HTTPS URL' },
  // Executing commands
  { regex: /\bexec\s*\(/i,                      label: 'exec() call' },
  { regex: /\bspawn\s*\(/i,                     label: 'spawn() call' },
  { regex: /child_process/i,                    label: 'child_process import' },
  // OS detection (profiling the victim)
  { regex: /os\.platform\s*\(/i,                label: 'os.platform() (OS detection)' },
  { regex: /os\.type\s*\(/i,                    label: 'os.type() (OS detection)' },
  { regex: /process\.platform/i,                label: 'process.platform (OS detection)' },
  // Self-deletion / cleanup
  { regex: /rm\s+-rf/i,                         label: 'rm -rf (file deletion)' },
  { regex: /\bdel\s+\/[sqf]/i,                  label: 'del /s (Windows deletion)' },
  { regex: /\bunlink\s*\(/i,                    label: 'unlink() (file deletion)' },
  // Credential access
  { regex: /\bprocess\.env\b/i,                 label: 'process.env (env access)' },
  { regex: /\$HOME\b|\bHOME\b/,                 label: '$HOME (home dir access)' },
  { regex: /\bUSERPROFILE\b/i,                  label: 'USERPROFILE (Windows home)' },
  { regex: /\.ssh/i,                            label: '.ssh (SSH key access)' },
  { regex: /\.aws/i,                            label: '.aws (AWS credentials)' },
  { regex: /\.npmrc/i,                          label: '.npmrc (npm token access)' },
];

// ── Levenshtein Distance ─────────────────────────────────────────────────────

/**
 * Compute Levenshtein distance between two strings.
 * Standard dynamic-programming implementation, no external deps.
 */
export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  // Use two-row rolling array to save memory
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  let curr = new Array<number>(b.length + 1);

  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(
        curr[j - 1] + 1,      // insertion
        prev[j] + 1,          // deletion
        prev[j - 1] + cost,   // substitution
      );
    }
    // Swap rows
    const _swap = prev; prev = curr; curr = _swap;
  }

  return prev[b.length];
}

// ── Package Discovery ────────────────────────────────────────────────────────

interface PackageInfo {
  name: string;
  version: string;
  scripts?: Record<string, string>;
  _resolved?: string;
  _time?: string;
  /** ISO 8601 timestamp from _time or _resolved metadata */
  publishedAt?: string;
}

function readPackageJson(pkgPath: string): PackageInfo | null {
  const pkgJsonPath = join(pkgPath, 'package.json');
  if (!existsSync(pkgJsonPath)) return null;
  try {
    const raw = readFileSync(pkgJsonPath, 'utf-8');
    return JSON.parse(raw) as PackageInfo;
  } catch {
    return null;
  }
}

/**
 * List all top-level package names in a node_modules directory.
 * Handles scoped packages (@org/pkg).
 */
function listPackages(nodeModulesPath: string): string[] {
  if (!existsSync(nodeModulesPath)) return [];

  let entries: string[];
  try {
    entries = readdirSync(nodeModulesPath);
  } catch {
    return [];
  }

  const packages: string[] = [];
  for (const entry of entries) {
    if (entry.startsWith('.')) continue;
    if (entry.startsWith('@')) {
      // Scoped namespace — list sub-entries
      try {
        const scopedEntries = readdirSync(join(nodeModulesPath, entry));
        for (const sub of scopedEntries) {
          if (!sub.startsWith('.')) {
            packages.push(`${entry}/${sub}`);
          }
        }
      } catch { /* skip */ }
    } else {
      packages.push(entry);
    }
  }
  return packages;
}

// ── Individual Checks ────────────────────────────────────────────────────────

function checkMalicious(name: string): boolean {
  return KNOWN_MALICIOUS.includes(name);
}

function checkTyposquat(name: string): string | null {
  // Strip scope for comparison — "@org/axois" → "axois"
  const bare = name.includes('/') ? name.split('/').pop()! : name;

  for (const popular of POPULAR_PACKAGES) {
    if (name === popular || bare === popular) continue; // exact match, not a typosquat
    const dist = levenshtein(bare, popular);
    if (dist >= 1 && dist <= 2) {
      return popular; // typosquat of this popular package
    }
  }
  return null;
}

function checkSuspiciousScripts(pkg: PackageInfo): { matchCount: number; labels: string[] } {
  const scriptKeys = ['postinstall', 'preinstall', 'install'] as const;
  const matchedLabels: string[] = [];

  for (const key of scriptKeys) {
    const script = pkg.scripts?.[key];
    if (!script) continue;

    for (const { regex, label } of SUSPICIOUS_PATTERNS) {
      if (regex.test(script) && !matchedLabels.includes(label)) {
        matchedLabels.push(label);
      }
    }
  }

  return { matchCount: matchedLabels.length, labels: matchedLabels };
}

function checkPackageAge(pkg: PackageInfo): boolean {
  const hasPostInstall =
    !!pkg.scripts?.postinstall ||
    !!pkg.scripts?.preinstall ||
    !!pkg.scripts?.install;

  if (!hasPostInstall) return false;

  // Try _time field first (some lockfiles embed it), then parse _resolved for date hints
  const timeStr = pkg._time ?? pkg._resolved;
  if (!timeStr) return false;

  // Extract an ISO date if present
  const isoMatch = timeStr.match(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
  if (!isoMatch) return false;

  const published = new Date(isoMatch[0]);
  if (isNaN(published.getTime())) return false;

  const ageMs = Date.now() - published.getTime();
  const sevenDaysMs = 7 * 24 * 60 * 60 * 1000;
  return ageMs < sevenDaysMs;
}

// ── Quarantine / Clean Actions ───────────────────────────────────────────────

export interface QuarantineManifest {
  packageName: string;
  version: string;
  reason: string;
  originalPath: string;
  quarantinedAt: string;
  severity: string;
}

/**
 * Quarantine a package by moving it from node_modules to
 * ~/.shieldcortex/quarantine/deps/<pkg>-<timestamp>/.
 *
 * Creates a manifest.json alongside the quarantined files.
 * Only acts on CRITICAL and HIGH findings.
 *
 * @returns The quarantine destination path, or null if not quarantined.
 */
export function quarantinePackage(
  finding: AuditFinding,
  nodeModulesPath: string,
): string | null {
  // Only quarantine CRITICAL and HIGH
  if (finding.severity !== 'critical' && finding.severity !== 'high') {
    return null;
  }

  // Extract package name from the finding title heuristically
  // Title examples:
  //   "Known malicious package: plain-crypto-js"
  //   "Possible typosquat: "axois" → "axios""
  //   "Suspicious install script in "bad-pkg""
  const nameMatch =
    finding.title.match(/^Known malicious package:\s+(.+)$/) ??
    finding.title.match(/^Possible typosquat:\s+"([^"]+)"/) ??
    finding.title.match(/^Suspicious install script in\s+"([^"]+)"/);

  const pkgName = nameMatch?.[1]?.trim();
  if (!pkgName) return null;

  // Resolve source path
  const pkgParts = pkgName.split('/');
  const srcPath = resolve(join(nodeModulesPath, ...pkgParts));
  if (!existsSync(srcPath)) return null;

  // Determine version from package.json
  const pkg = readPackageJson(srcPath);
  const version = pkg?.version ?? 'unknown';

  // Build quarantine destination
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const safeName = pkgName.replace(/\//g, '__');
  const quarantineBase = join(homedir(), '.shieldcortex', 'quarantine', 'deps');
  const destDir = join(quarantineBase, `${safeName}-${timestamp}`);
  const pkgDestDir = join(destDir, 'pkg');

  mkdirSecure(destDir);

  // Move the package directory
  renameSync(srcPath, pkgDestDir);

  // Write manifest
  const manifest: QuarantineManifest = {
    packageName: pkgName,
    version,
    reason: finding.title,
    originalPath: srcPath,
    quarantinedAt: new Date().toISOString(),
    severity: finding.severity,
  };
  writeFileSync(join(destDir, 'manifest.json'), JSON.stringify(manifest, null, 2));

  return destDir;
}

/**
 * Permanently delete a malicious package from node_modules.
 *
 * Only acts on CRITICAL findings (known malicious packages from blocklist).
 *
 * @returns The package name that was deleted, or null if not deleted.
 */
export function cleanPackage(
  finding: AuditFinding,
  nodeModulesPath: string,
): string | null {
  // Only clean CRITICAL findings
  if (finding.severity !== 'critical') {
    return null;
  }

  // Extract package name from the finding title
  const nameMatch = finding.title.match(/^Known malicious package:\s+(.+)$/);
  const pkgName = nameMatch?.[1]?.trim();
  if (!pkgName) return null;

  const pkgParts = pkgName.split('/');
  const srcPath = resolve(join(nodeModulesPath, ...pkgParts));
  if (!existsSync(srcPath)) return null;

  rmSync(srcPath, { recursive: true, force: true });

  return pkgName;
}

// ── Main Scanner ─────────────────────────────────────────────────────────────

export interface DependencyScanOptions {
  /** Absolute path to node_modules directory */
  nodeModulesPath: string;
}

export function scanDependencies(opts: DependencyScanOptions): ScannerResult {
  const start = Date.now();
  const { nodeModulesPath } = opts;

  if (!existsSync(nodeModulesPath)) {
    return {
      name: 'Dependency Scanner',
      itemsScanned: 0,
      findings: [],
      durationMs: Date.now() - start,
      skipped: true,
      skipReason: `node_modules not found at ${nodeModulesPath}`,
    };
  }

  const packageNames = listPackages(nodeModulesPath);
  const findings: AuditFinding[] = [];

  for (const name of packageNames) {
    const pkgPath = join(nodeModulesPath, ...name.split('/'));
    const pkg = readPackageJson(pkgPath);

    // ── 1. Known malicious ──────────────────────────────────────────
    if (checkMalicious(name)) {
      findings.push({
        scanner: 'dependency',
        severity: 'critical',
        title: `Known malicious package: ${name}`,
        description:
          `"${name}" is a known malicious npm package. Remove it immediately and ` +
          `audit your codebase for any data that may have been exfiltrated.`,
        filePath: join(pkgPath, 'package.json'),
        learnMoreUrl: LEARN_MORE_MALICIOUS,
      });
    }

    // ── 2. Typosquat ────────────────────────────────────────────────
    const typosquatOf = checkTyposquat(name);
    if (typosquatOf) {
      findings.push({
        scanner: 'dependency',
        severity: 'high',
        title: `Possible typosquat: "${name}" → "${typosquatOf}"`,
        description:
          `"${name}" is 1-2 characters away from the popular package "${typosquatOf}". ` +
          `This may be a typosquatting attack. Verify the package is intentional.`,
        filePath: join(pkgPath, 'package.json'),
        learnMoreUrl: LEARN_MORE_TYPOSQUAT,
      });
    }

    if (!pkg) continue;

    // ── 3. Suspicious postinstall ───────────────────────────────────
    const { matchCount, labels } = checkSuspiciousScripts(pkg);
    if (matchCount >= 1) {
      const severity = matchCount >= 2 ? 'high' : 'medium';
      findings.push({
        scanner: 'dependency',
        severity,
        title: `Suspicious install script in "${name}"`,
        description:
          `"${name}" has an install/postinstall script containing suspicious patterns: ` +
          labels.join(', ') + '. Review before trusting this package.',
        filePath: join(pkgPath, 'package.json'),
        matchedText: labels.slice(0, 5).join(', '),
        learnMoreUrl: LEARN_MORE_POSTINSTALL,
      });
    }

    // ── 4. New package with postinstall ────────────────────────────
    if (checkPackageAge(pkg)) {
      findings.push({
        scanner: 'dependency',
        severity: 'medium',
        title: `Newly published package with install script: "${name}"`,
        description:
          `"${name}" was published within the last 7 days and has an install/postinstall ` +
          `script. New packages with install scripts are a common supply-chain attack vector.`,
        filePath: join(pkgPath, 'package.json'),
        learnMoreUrl: LEARN_MORE_MALICIOUS,
      });
    }
  }

  return {
    name: 'Dependency Scanner',
    itemsScanned: packageNames.length,
    findings,
    durationMs: Date.now() - start,
  };
}

/**
 * Resolve the node_modules path for a given mode.
 */
export function resolveNodeModulesPath(
  mode: 'local' | 'global' | 'path',
  customPath?: string,
): string {
  switch (mode) {
    case 'global': {
      try {
        const prefix = execSync('npm prefix -g', { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'ignore'] }).trim();
        return join(prefix, 'lib', 'node_modules');
      } catch {
        // Fallback common locations
        return join('/usr/local/lib', 'node_modules');
      }
    }
    case 'path':
      return customPath ?? join(process.cwd(), 'node_modules');
    case 'local':
    default:
      return join(process.cwd(), 'node_modules');
  }
}
