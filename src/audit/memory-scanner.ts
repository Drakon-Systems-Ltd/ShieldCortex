/**
 * Memory Scanner
 *
 * Scans AI agent memory files for planted instructions, poisoned
 * memories, and suspicious content. Checks:
 *   - ~/.claude/ project memory files (CLAUDE.md, memory/)
 *   - ~/.shieldcortex/ memory database
 *   - Cursor/Windsurf persistent memory locations
 */

import { existsSync, readdirSync, readFileSync, statSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import type { AuditFinding, ScannerResult } from './types.js';
import { runDefencePipeline } from '../defence/pipeline.js';
import type { DefenceSource } from '../defence/types.js';

const LEARN_MORE = 'https://shieldcortex.ai/docs/threats/memory-poisoning';

// ── ShieldCortex Own-Hook Whitelist ──

/**
 * Paths belonging to ShieldCortex itself (hooks, plugin manifests, etc.).
 * These should never produce false audit findings (#14).
 */
const SHIELDCORTEX_OWN_PATHS: string[] = [
  'cortex-memory/HOOK.md',
  'cortex-memory/handler.ts',
  'cortex-memory/handler.js',
  'shieldcortex-realtime',
];

function isShieldCortexOwnPath(filePath: string): boolean {
  const normalised = filePath.replace(/\\/g, '/');
  return SHIELDCORTEX_OWN_PATHS.some(p => normalised.includes(p));
}



/** Maximum file size to scan (1 MB) */
const MAX_FILE_SIZE = 1024 * 1024;

/** Maximum number of memory files to scan */
const MAX_FILES = 200;

/** Source for pipeline scans */
const AUDIT_SOURCE: DefenceSource = { type: 'cli', identifier: 'shieldcortex-audit' };

/**
 * Find memory-related files across known AI agent locations.
 */
function discoverMemoryFiles(): string[] {
  const home = homedir();
  const files: string[] = [];

  const addIfFile = (p: string) => {
    try {
      if (existsSync(p) && statSync(p).isFile() && statSync(p).size <= MAX_FILE_SIZE) {
        files.push(p);
      }
    } catch { /* ignore */ }
  };

  /** Directories that are NOT agent memory and should be skipped */
  const SKIP_DIRS = new Set([
    'node_modules', 'extensions', 'cache', 'logs', 'crashReports',
    'CachedData', 'CachedExtensions', 'CachedExtensionVSIXs',
    'User', 'Code', 'globalStorage', 'workspaceStorage',
  ]);

  const walkDir = (dir: string, patterns: RegExp[], maxDepth = 3) => {
    const walk = (d: string, depth: number) => {
      if (depth > maxDepth || files.length >= MAX_FILES) return;
      try {
        if (!existsSync(d)) return;
        const entries = readdirSync(d, { withFileTypes: true });
        for (const entry of entries) {
          if (files.length >= MAX_FILES) return;
          const full = join(d, entry.name);
          if (entry.isFile() && patterns.some(p => p.test(entry.name))) {
            try {
              if (statSync(full).size <= MAX_FILE_SIZE) files.push(full);
            } catch { /* ignore */ }
          } else if (entry.isDirectory() && !entry.name.startsWith('.') && !SKIP_DIRS.has(entry.name)) {
            walk(full, depth + 1);
          }
        }
      } catch { /* ignore */ }
    };
    walk(dir, 0);
  };

  // Claude Code project memories
  walkDir(join(home, '.claude', 'projects'), [/\.md$/], 4);

  // Claude Code global CLAUDE.md
  addIfFile(join(home, '.claude', 'CLAUDE.md'));

  // Note: settings.json is excluded — it contains legitimate permission
  // patterns that trigger false positives in the defence pipeline.

  // Cursor — only scan known memory/rules locations, NOT extensions
  addIfFile(join(home, '.cursor', 'rules', 'global.md'));
  walkDir(join(home, '.cursor', 'rules'), [/\.md$/, /\.mdc$/], 2);
  walkDir(join(home, '.cursor', 'memories'), [/\.md$/, /\.json$/], 2);

  // Windsurf — known memory locations
  walkDir(join(home, '.windsurf', 'memories'), [/\.md$/, /\.json$/], 2);
  walkDir(join(home, '.windsurf', 'rules'), [/\.md$/, /\.mdc$/], 2);

  // CWD-relative project memory files
  const cwd = process.cwd();
  addIfFile(join(cwd, 'CLAUDE.md'));
  walkDir(join(cwd, '.claude', 'commands'), [/\.md$/], 2);

  return files;
}

/**
 * Scan a single memory file through the defence pipeline.
 */
function scanMemoryFile(filePath: string): AuditFinding[] {
  const findings: AuditFinding[] = [];

  let content: string;
  try {
    content = readFileSync(filePath, 'utf-8');
  } catch {
    return findings;
  }

  if (!content.trim()) return findings;

  // Run through the defence pipeline
  try {
    const result = runDefencePipeline(content, `audit:${filePath}`, AUDIT_SOURCE);

    if (result.firewall.result === 'BLOCK') {
      findings.push({
        scanner: 'memory',
        severity: 'critical',
        title: 'Blocked content in memory file',
        description: `Defence pipeline blocked this file: ${result.firewall.reason}`,
        filePath,
        matchedText: result.firewall.blockedPatterns.join(', ').slice(0, 120),
        learnMoreUrl: LEARN_MORE,
      });
    } else if (result.firewall.result === 'QUARANTINE') {
      findings.push({
        scanner: 'memory',
        severity: 'high',
        title: 'Suspicious content in memory file',
        description: `Defence pipeline flagged this file for quarantine: ${result.firewall.reason}`,
        filePath,
        matchedText: result.firewall.blockedPatterns.join(', ').slice(0, 120),
        learnMoreUrl: LEARN_MORE,
      });
    }

    // Check for specific threat indicators
    for (const indicator of result.firewall.threatIndicators) {
      if (indicator === 'instruction_injection') {
        findings.push({
          scanner: 'memory',
          severity: 'critical',
          title: 'Prompt injection detected in memory',
          description: 'This memory file contains instruction injection patterns that could hijack agent behaviour.',
          filePath,
          learnMoreUrl: LEARN_MORE,
        });
      } else if (indicator === 'privilege_escalation') {
        findings.push({
          scanner: 'memory',
          severity: 'high',
          title: 'Privilege escalation in memory',
          description: 'This memory file references sensitive system paths or elevated permissions.',
          filePath,
          learnMoreUrl: LEARN_MORE,
        });
      }
    }

    // Check for credential leaks in memory
    if (result.credentialScan && result.credentialScan.findings.length > 0) {
      for (const cf of result.credentialScan.findings) {
        findings.push({
          scanner: 'memory',
          severity: cf.severity === 'critical' ? 'critical' : cf.severity === 'high' ? 'high' : 'medium',
          title: `Credential leaked in memory: ${cf.provider || cf.type}`,
          description: `A ${cf.type} credential was found stored in agent memory. This could be exfiltrated by a malicious prompt.`,
          filePath,
          matchedText: cf.match,
          learnMoreUrl: 'https://shieldcortex.ai/docs/threats/credential-leak',
        });
      }
    }
  } catch {
    // Pipeline errors shouldn't crash the audit
  }

  // Deduplicate findings for the same file (keep the highest severity)
  const seen = new Set<string>();
  return findings.filter(f => {
    const key = `${f.title}:${f.filePath}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * Run the memory scanner.
 */
export function scanMemories(): ScannerResult {
  const start = Date.now();
  const files = discoverMemoryFiles();

  if (files.length === 0) {
    return {
      name: 'Memory Scanner',
      itemsScanned: 0,
      findings: [],
      durationMs: Date.now() - start,
      skipped: true,
      skipReason: 'No AI agent memory files found',
    };
  }

  const allFindings: AuditFinding[] = [];
  for (const file of files) {
    // Skip ShieldCortex's own hook/plugin files to avoid false positives (#14)
    if (isShieldCortexOwnPath(file)) continue;
    allFindings.push(...scanMemoryFile(file));
  }

  return {
    name: 'Memory Scanner',
    itemsScanned: files.length,
    findings: allFindings,
    durationMs: Date.now() - start,
  };
}
