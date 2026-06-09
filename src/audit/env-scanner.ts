/**
 * Environment Secrets Scanner
 *
 * Finds .env files that AI agents can access and scans them for
 * exposed secrets. Claude Code, Cursor, and other agents automatically
 * load .env files into context — .claudeignore doesn't reliably block this.
 *
 * Reuses the credential-leak detection from Layer 6.
 */

import { existsSync, readFileSync, readdirSync, statSync } from 'fs';
import { join, basename } from 'path';
import { homedir } from 'os';
import { execFileSync } from 'node:child_process';
import type { AuditFinding, ScannerResult } from './types.js';
import { scanForCredentials } from '../defence/credential-leak/index.js';

const LEARN_MORE = 'https://shieldcortex.ai/docs/threats/secret-exposure';

/** .env file patterns */
const ENV_FILE_PATTERNS = [
  '.env',
  '.env.local',
  '.env.development',
  '.env.development.local',
  '.env.production',
  '.env.production.local',
  '.env.staging',
  '.env.test',
  '.env.test.local',
];

/** Maximum file size for env files (256 KB — they shouldn't be large) */
const MAX_ENV_SIZE = 256 * 1024;

/**
 * Discover .env files in the current working directory and parent directories.
 */
function discoverEnvFiles(): string[] {
  const files: string[] = [];
  const cwd = process.cwd();
  const home = homedir();

  // Check CWD
  for (const name of ENV_FILE_PATTERNS) {
    const p = join(cwd, name);
    try {
      if (existsSync(p) && statSync(p).isFile() && statSync(p).size <= MAX_ENV_SIZE) {
        files.push(p);
      }
    } catch { /* ignore */ }
  }

  // Also check common project subdirectories
  const subdirs = ['apps', 'packages', 'services', 'backend', 'frontend', 'api', 'server', 'web', 'webapp'];
  for (const subdir of subdirs) {
    const dir = join(cwd, subdir);
    try {
      if (!existsSync(dir) || !statSync(dir).isDirectory()) continue;
      const entries = readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isDirectory()) {
          for (const name of ENV_FILE_PATTERNS) {
            const p = join(dir, entry.name, name);
            try {
              if (existsSync(p) && statSync(p).isFile() && statSync(p).size <= MAX_ENV_SIZE) {
                files.push(p);
              }
            } catch { /* ignore */ }
          }
        }
      }
    } catch { /* ignore */ }
  }

  // Check home directory for global .env (some tools put secrets here)
  try {
    const homeEnv = join(home, '.env');
    if (existsSync(homeEnv) && statSync(homeEnv).isFile() && statSync(homeEnv).size <= MAX_ENV_SIZE) {
      files.push(homeEnv);
    }
  } catch { /* ignore */ }

  return files;
}

/**
 * Check if a .env file is git-ignored.
 */
function isGitIgnored(filePath: string): boolean {
  try {
    // execFileSync (no shell) — filePath is passed as an argv element, so shell
    // metacharacters in a path can never be interpreted. stderr is piped (not
    // inherited), so a non-repo dir stays quiet without a `2>/dev/null` redirect.
    execFileSync('git', ['check-ignore', '-q', filePath], {
      cwd: process.cwd(),
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    return true; // Exit code 0 means it's ignored
  } catch {
    return false; // Exit code 1 means it's NOT ignored (or git not available)
  }
}

/**
 * Scan a single .env file for secrets.
 */
function scanEnvFile(filePath: string): AuditFinding[] {
  const findings: AuditFinding[] = [];

  let content: string;
  try {
    content = readFileSync(filePath, 'utf-8');
  } catch {
    return findings;
  }

  if (!content.trim()) return findings;

  const fileName = basename(filePath);

  // First: warn that .env files exist and are accessible to agents
  const isIgnored = isGitIgnored(filePath);

  if (!isIgnored) {
    findings.push({
      scanner: 'env',
      severity: 'high',
      title: `Unprotected .env file: ${fileName}`,
      description: 'This .env file is NOT git-ignored. It may be committed to version control and is readable by AI agents.',
      filePath,
      learnMoreUrl: LEARN_MORE,
    });
  }

  // Run credential detection on the file contents
  const credResult = scanForCredentials(content);

  if (credResult.findings.length > 0) {
    // Group by severity for cleaner output
    const criticalCount = credResult.findings.filter(f => f.severity === 'critical').length;
    const highCount = credResult.findings.filter(f => f.severity === 'high').length;
    const mediumCount = credResult.findings.filter(f => f.severity === 'medium').length;

    if (criticalCount > 0) {
      findings.push({
        scanner: 'env',
        severity: 'critical',
        title: `${criticalCount} critical secret(s) in ${fileName}`,
        description: `Found ${criticalCount} critical credential(s) (API keys, private keys) that AI agents can read from this file. Claude Code automatically loads .env files into context.`,
        filePath,
        matchedText: credResult.findings
          .filter(f => f.severity === 'critical')
          .map(f => `${f.provider || f.type}: ${f.match}`)
          .slice(0, 3)
          .join(', '),
        learnMoreUrl: LEARN_MORE,
      });
    }

    if (highCount > 0) {
      findings.push({
        scanner: 'env',
        severity: 'high',
        title: `${highCount} high-severity secret(s) in ${fileName}`,
        description: `Found ${highCount} high-severity credential(s) accessible to AI agents.`,
        filePath,
        learnMoreUrl: LEARN_MORE,
      });
    }

    if (mediumCount > 0) {
      findings.push({
        scanner: 'env',
        severity: 'medium',
        title: `${mediumCount} potential secret(s) in ${fileName}`,
        description: `Found ${mediumCount} potential credential(s) that may be accessible to AI agents.`,
        filePath,
        learnMoreUrl: LEARN_MORE,
      });
    }
  } else {
    // Even if no credentials detected, the fact that a .env file is accessible is noteworthy
    findings.push({
      scanner: 'env',
      severity: 'info',
      title: `Agent-accessible .env file: ${fileName}`,
      description: 'This .env file exists and is readable by AI agents. No credentials were detected but agents may still read its contents.',
      filePath,
      learnMoreUrl: LEARN_MORE,
    });
  }

  return findings;
}

/**
 * Run the environment secrets scanner.
 */
export function scanEnvFiles(): ScannerResult {
  const start = Date.now();
  const files = discoverEnvFiles();

  if (files.length === 0) {
    return {
      name: 'Environment Secrets',
      itemsScanned: 0,
      findings: [],
      durationMs: Date.now() - start,
      skipped: true,
      skipReason: 'No .env files found',
    };
  }

  const allFindings: AuditFinding[] = [];
  for (const file of files) {
    allFindings.push(...scanEnvFile(file));
  }

  return {
    name: 'Environment Secrets',
    itemsScanned: files.length,
    findings: allFindings,
    durationMs: Date.now() - start,
  };
}
