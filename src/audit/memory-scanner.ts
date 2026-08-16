/**
 * Memory Scanner
 *
 * Scans AI agent memory files for planted instructions, poisoned
 * memories, and suspicious content. Checks:
 *   - ~/.claude/ project memory files (CLAUDE.md, memory/)
 *   - ~/.shieldcortex/ memory database
 *   - Cursor/Windsurf persistent memory locations
 */

import { createHash } from 'crypto';
import { existsSync, readdirSync, readFileSync, statSync } from 'fs';
import { basename, dirname, join } from 'path';
import { homedir } from 'os';
import type { AuditFinding, AuditSeverity, ScannerResult } from './types.js';
import { runDefencePipeline } from '../defence/pipeline.js';
import type { DefenceSource } from '../defence/types.js';
import { getDatabase, withTransaction } from '../database/init.js';

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

export function isShieldCortexOwnMemoryPath(filePath: string): boolean {
  const normalised = filePath.replace(/\\/g, '/');
  return SHIELDCORTEX_OWN_PATHS.some(p => normalised.includes(p));
}

/** Maximum file size to scan (1 MB) */
const MAX_FILE_SIZE = 1024 * 1024;

/** Maximum number of memory files to scan */
const MAX_FILES = 200;

/** Source for legacy CLI audit output */
const AUDIT_SOURCE: DefenceSource = { type: 'cli', identifier: 'shieldcortex-audit' };

export type MemoryFileRisk = 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface MemoryFileEvidence {
  snippet: string;
  reason: string;
}

export interface DiscoveredMemoryFile {
  path: string;
  source: string;
}

export interface MemoryFileScanRecord {
  id: string;
  path: string;
  source: string;
  sizeBytes: number;
  modifiedAt: string | null;
  contentExcerpt: string;
  auditId: number | null;
  anomalyScore: number;
  firewallResult: 'ALLOW' | 'QUARANTINE' | 'BLOCK';
  risk: MemoryFileRisk;
  reason: string;
  threatIndicators: string[];
  evidence: MemoryFileEvidence[];
  findings: AuditFinding[];
}

export interface MemoryFileScanSummary {
  total: number;
  safe: number;
  flagged: number;
  critical: number;
  high: number;
  medium: number;
}

export interface DetailedMemoryFileScanResult {
  scannedAt: string;
  summary: MemoryFileScanSummary;
  files: MemoryFileScanRecord[];
  durationMs: number;
}

export interface MemoryFileQuarantineQueueItem {
  fileId: string;
  path: string;
  quarantineId: number | null;
  status: 'created' | 'updated' | 'skipped_safe' | 'skipped_reviewed';
}

export interface MemoryFileQuarantineQueueResult {
  created: number;
  updated: number;
  skippedSafe: number;
  skippedReviewed: number;
  items: MemoryFileQuarantineQueueItem[];
}

export interface MemoryFileDiscoveryOptions {
  homeDir?: string;
  cwd?: string;
  maxFiles?: number;
  maxFileSize?: number;
}

function fileId(filePath: string): string {
  return createHash('sha256').update(filePath).digest('hex').slice(0, 16);
}

function severityToRisk(severity: AuditSeverity): MemoryFileRisk {
  if (severity === 'critical') return 'CRITICAL';
  if (severity === 'high') return 'HIGH';
  if (severity === 'medium') return 'MEDIUM';
  if (severity === 'low') return 'LOW';
  return 'SAFE';
}

function riskRank(risk: MemoryFileRisk): number {
  switch (risk) {
    case 'CRITICAL': return 5;
    case 'HIGH': return 4;
    case 'MEDIUM': return 3;
    case 'LOW': return 2;
    case 'SAFE': return 1;
  }
}

function mergeRisk(current: MemoryFileRisk, next: MemoryFileRisk): MemoryFileRisk {
  return riskRank(next) > riskRank(current) ? next : current;
}

function excerpt(content: string, max = 4000): string {
  return content.length <= max ? content : `${content.slice(0, max)}\n[truncated]`;
}

function evidenceFromFinding(finding: AuditFinding): MemoryFileEvidence | null {
  if (!finding.matchedText) return null;
  const snippet = finding.matchedText.trim();
  if (!snippet) return null;
  return { snippet: snippet.slice(0, 240), reason: finding.title };
}

function dedupeEvidence(evidence: MemoryFileEvidence[]): MemoryFileEvidence[] {
  const seen = new Set<string>();
  return evidence.filter((entry) => {
    const key = `${entry.reason}:${entry.snippet}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).slice(0, 6);
}

function shouldQueueMemoryFile(file: MemoryFileScanRecord): boolean {
  return file.firewallResult !== 'ALLOW' || riskRank(file.risk) >= riskRank('MEDIUM');
}

function queueFirewallResult(file: MemoryFileScanRecord): 'BLOCK' | 'QUARANTINE' {
  return file.firewallResult === 'BLOCK' ? 'BLOCK' : 'QUARANTINE';
}

function riskToAnomalyScore(risk: MemoryFileRisk): number {
  switch (risk) {
    case 'CRITICAL': return 1;
    case 'HIGH': return 0.8;
    case 'MEDIUM': return 0.55;
    case 'LOW': return 0.2;
    case 'SAFE': return 0;
  }
}

function buildQuarantineTitle(file: MemoryFileScanRecord): string {
  return `Memory file: ${basename(file.path)}`;
}

function buildQuarantineContent(file: MemoryFileScanRecord): string {
  const evidence = file.evidence
    .map((entry) => `- ${entry.reason}: ${entry.snippet}`)
    .join('\n');
  const findings = file.findings
    .map((finding) => `- ${finding.severity.toUpperCase()}: ${finding.title} - ${finding.description}`)
    .join('\n');

  return [
    `Path: ${file.path}`,
    `Source: ${file.source}`,
    `Risk: ${file.risk}`,
    `Firewall result: ${file.firewallResult}`,
    `Reason: ${file.reason}`,
    file.threatIndicators.length > 0 ? `Threat indicators: ${file.threatIndicators.join(', ')}` : '',
    evidence ? `Evidence:\n${evidence}` : '',
    findings ? `Findings:\n${findings}` : '',
    file.contentExcerpt ? `Content excerpt:\n${file.contentExcerpt}` : 'Content excerpt: empty file',
  ].filter(Boolean).join('\n\n');
}

export function queueMemoryFileScanFindings(result: DetailedMemoryFileScanResult): MemoryFileQuarantineQueueResult {
  return withTransaction(() => {
    const db = getDatabase();
    const queue: MemoryFileQuarantineQueueResult = {
      created: 0,
      updated: 0,
      skippedSafe: 0,
      skippedReviewed: 0,
      items: [],
    };

    const reviewedSameContent = db.prepare(`
      SELECT id, status
      FROM quarantine
      WHERE source_type = 'memory_file'
        AND source_identifier = ?
        AND original_content = ?
        AND status IN ('approved', 'rejected', 'expired')
      ORDER BY created_at DESC
      LIMIT 1
    `);
    const pendingForPath = db.prepare(`
      SELECT id
      FROM quarantine
      WHERE source_type = 'memory_file'
        AND source_identifier = ?
        AND status = 'pending'
      ORDER BY created_at DESC
      LIMIT 1
    `);
    const updatePending = db.prepare(`
      UPDATE quarantine
         SET original_title = ?,
             original_content = ?,
             reason = ?,
             threat_indicators = ?,
             anomaly_score = ?,
             firewall_result = ?,
             audit_id = ?
       WHERE id = ?
         AND status = 'pending'
    `);
    const insertPending = db.prepare(`
      INSERT INTO quarantine (
        original_title,
        original_content,
        project,
        source_type,
        source_identifier,
        reason,
        threat_indicators,
        anomaly_score,
        firewall_result,
        audit_id,
        status
      ) VALUES (?, ?, NULL, 'memory_file', ?, ?, ?, ?, ?, ?, 'pending')
    `);

    for (const file of result.files) {
      if (!shouldQueueMemoryFile(file)) {
        queue.skippedSafe += 1;
        queue.items.push({
          fileId: file.id,
          path: file.path,
          quarantineId: null,
          status: 'skipped_safe',
        });
        continue;
      }

      const title = buildQuarantineTitle(file);
      const content = buildQuarantineContent(file);
      const reason = file.reason || 'Memory file scan finding';
      const threatIndicators = JSON.stringify(file.threatIndicators);
      const anomalyScore = file.anomalyScore || riskToAnomalyScore(file.risk);
      const firewallResult = queueFirewallResult(file);

      const reviewed = reviewedSameContent.get(file.path, content) as { id: number; status: string } | undefined;
      if (reviewed) {
        queue.skippedReviewed += 1;
        queue.items.push({
          fileId: file.id,
          path: file.path,
          quarantineId: reviewed.id,
          status: 'skipped_reviewed',
        });
        continue;
      }

      const pending = pendingForPath.get(file.path) as { id: number } | undefined;
      if (pending) {
        updatePending.run(
          title,
          content,
          reason,
          threatIndicators,
          anomalyScore,
          firewallResult,
          file.auditId,
          pending.id,
        );
        queue.updated += 1;
        queue.items.push({
          fileId: file.id,
          path: file.path,
          quarantineId: pending.id,
          status: 'updated',
        });
        continue;
      }

      const inserted = insertPending.run(
        title,
        content,
        file.path,
        reason,
        threatIndicators,
        anomalyScore,
        firewallResult,
        file.auditId,
      );
      queue.created += 1;
      queue.items.push({
        fileId: file.id,
        path: file.path,
        quarantineId: Number(inserted.lastInsertRowid),
        status: 'created',
      });
    }

    return queue;
  });
}

/**
 * Find memory-related files across known AI agent locations.
 */
export function discoverMemoryFiles(options: MemoryFileDiscoveryOptions = {}): DiscoveredMemoryFile[] {
  const home = options.homeDir ?? homedir();
  const cwd = options.cwd ?? process.cwd();
  const maxFiles = options.maxFiles ?? MAX_FILES;
  const maxFileSize = options.maxFileSize ?? MAX_FILE_SIZE;
  const files = new Map<string, DiscoveredMemoryFile>();

  const addDiscoveredFile = (p: string, source: string, stat = statSync(p)) => {
    const key = `${stat.dev}:${stat.ino}`;
    if (!files.has(key)) {
      files.set(key, { path: p, source });
    }
  };

  const resolveActualPath = (p: string): string => {
    try {
      const dir = dirname(p);
      const base = basename(p);
      const entries = readdirSync(dir);
      const exact = entries.find((entry) => entry === base);
      if (exact) return join(dir, exact);
      const caseInsensitive = entries.find((entry) => entry.toLowerCase() === base.toLowerCase());
      return caseInsensitive ? join(dir, caseInsensitive) : p;
    } catch {
      return p;
    }
  };

  const addIfFile = (p: string, source: string) => {
    try {
      if (files.size >= maxFiles) return;
      if (!existsSync(p)) return;
      const actual = resolveActualPath(p);
      const stat = statSync(actual);
      if (stat.isFile() && stat.size <= maxFileSize) {
        addDiscoveredFile(actual, source, stat);
      }
    } catch { /* ignore */ }
  };

  /** Directories that are NOT agent memory and should be skipped */
  const SKIP_DIRS = new Set([
    'node_modules', 'extensions', 'cache', 'logs', 'crashReports',
    'CachedData', 'CachedExtensions', 'CachedExtensionVSIXs',
    'User', 'Code', 'globalStorage', 'workspaceStorage',
  ]);

  const walkDir = (dir: string, patterns: RegExp[], maxDepth = 3, source = 'Memory file') => {
    const walk = (d: string, depth: number) => {
      if (depth > maxDepth || files.size >= maxFiles) return;
      try {
        if (!existsSync(d)) return;
        const entries = readdirSync(d, { withFileTypes: true });
        for (const entry of entries) {
          if (files.size >= maxFiles) return;
          const full = join(d, entry.name);
          if (entry.isFile() && patterns.some(p => p.test(entry.name))) {
            try {
              const stat = statSync(full);
              if (stat.size <= maxFileSize) addDiscoveredFile(full, source, stat);
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
  walkDir(join(home, '.claude', 'projects'), [/\.md$/], 4, 'Claude project memory');

  // Claude Code global memories
  addIfFile(join(home, '.claude', 'CLAUDE.md'), 'Claude global memory');
  addIfFile(join(home, '.claude', 'memory.md'), 'Claude global memory');
  addIfFile(join(home, '.claude', 'MEMORY.md'), 'Claude global memory');
  addIfFile(join(home, '.claude', '.memory.md'), 'Claude global memory');
  walkDir(join(home, '.claude', 'memories'), [/\.md$/], 5, 'Claude global memory');

  // Note: settings.json is excluded — it contains legitimate permission
  // patterns that trigger false positives in the defence pipeline.

  // Cursor — only scan known memory/rules locations, NOT extensions
  addIfFile(join(home, '.cursor', 'rules', 'global.md'), 'Cursor rule memory');
  walkDir(join(home, '.cursor', 'rules'), [/\.md$/, /\.mdc$/], 2, 'Cursor rule memory');
  walkDir(join(home, '.cursor', 'memories'), [/\.md$/, /\.json$/], 2, 'Cursor memory');

  // Windsurf — known memory locations
  walkDir(join(home, '.windsurf', 'memories'), [/\.md$/, /\.json$/], 2, 'Windsurf memory');
  walkDir(join(home, '.windsurf', 'rules'), [/\.md$/, /\.mdc$/], 2, 'Windsurf rule memory');

  // CWD-relative project memory files
  addIfFile(join(cwd, 'CLAUDE.md'), 'Project Claude memory');
  addIfFile(join(cwd, 'memory.md'), 'Project memory');
  addIfFile(join(cwd, 'MEMORY.md'), 'Project memory');
  addIfFile(join(cwd, '.memory.md'), 'Project memory');
  addIfFile(join(cwd, '.claude', 'memory.md'), 'Project Claude memory');
  addIfFile(join(cwd, '.claude', 'MEMORY.md'), 'Project Claude memory');
  addIfFile(join(cwd, '.claude', '.memory.md'), 'Project Claude memory');
  walkDir(join(cwd, '.claude', 'memories'), [/\.md$/], 5, 'Project Claude memory');
  walkDir(join(cwd, '.claude', 'commands'), [/\.md$/], 2, 'Project Claude command memory');

  return [...files.values()];
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
    // Code-constant identity (cli:shieldcortex-audit) → attested by
    // construction; a hostile memory file's BLOCK accrues to the audit channel.
    const result = runDefencePipeline(content, `audit:${filePath}`, AUDIT_SOURCE, undefined, undefined, { sourceAttested: true });

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

function scanMemoryFileDetailed(file: DiscoveredMemoryFile): MemoryFileScanRecord | null {
  let content: string;
  let sizeBytes = 0;
  let modifiedAt: string | null = null;

  try {
    const stat = statSync(file.path);
    sizeBytes = stat.size;
    modifiedAt = stat.mtime.toISOString();
    content = readFileSync(file.path, 'utf-8');
  } catch {
    return null;
  }

  if (!content.trim()) {
    return {
      id: fileId(file.path),
      path: file.path,
      source: file.source,
      sizeBytes,
      modifiedAt,
      contentExcerpt: '',
      auditId: null,
      anomalyScore: 0,
      firewallResult: 'ALLOW',
      risk: 'SAFE',
      reason: 'Empty memory file.',
      threatIndicators: [],
      evidence: [],
      findings: [],
    };
  }

  let firewallResult: 'ALLOW' | 'QUARANTINE' | 'BLOCK' = 'ALLOW';
  let risk: MemoryFileRisk = 'SAFE';
  let reason = 'No threats detected.';
  let threatIndicators: string[] = [];
  let evidence: MemoryFileEvidence[] = [];
  let auditId: number | null = null;
  let anomalyScore = 0;
  const findings: AuditFinding[] = [];

  try {
    const auditSource: DefenceSource = { type: 'cli', identifier: `memory-file:${file.path}` };
    // System-composed identity (the scanner walks the filesystem itself; no
    // caller declares it) → attested. Accrual lands on cli:memory-file:<path>
    // — the hostile FILE's own key — and only ever tightens.
    const result = runDefencePipeline(content, `audit:${file.path}`, auditSource, undefined, undefined, { sourceAttested: true });
    auditId = result.auditId;
    anomalyScore = result.firewall.anomalyScore;
    firewallResult = result.firewall.result;
    reason = result.firewall.reason;
    threatIndicators = result.firewall.threatIndicators;

    if (firewallResult === 'BLOCK') {
      risk = 'CRITICAL';
      findings.push({
        scanner: 'memory',
        severity: 'critical',
        title: 'Blocked content in memory file',
        description: `Defence pipeline blocked this file: ${result.firewall.reason}`,
        filePath: file.path,
        matchedText: result.firewall.blockedPatterns.join(', ').slice(0, 120),
        learnMoreUrl: LEARN_MORE,
      });
    } else if (firewallResult === 'QUARANTINE') {
      risk = 'HIGH';
      findings.push({
        scanner: 'memory',
        severity: 'high',
        title: 'Suspicious content in memory file',
        description: `Defence pipeline flagged this file for quarantine: ${result.firewall.reason}`,
        filePath: file.path,
        matchedText: result.firewall.blockedPatterns.join(', ').slice(0, 120),
        learnMoreUrl: LEARN_MORE,
      });
    }

    for (const indicator of result.firewall.threatIndicators) {
      if (indicator === 'instruction_injection') {
        findings.push({
          scanner: 'memory',
          severity: 'critical',
          title: 'Prompt injection detected in memory',
          description: 'This memory file contains instruction injection patterns that could hijack agent behaviour.',
          filePath: file.path,
          learnMoreUrl: LEARN_MORE,
        });
        risk = mergeRisk(risk, 'CRITICAL');
      } else if (indicator === 'privilege_escalation') {
        findings.push({
          scanner: 'memory',
          severity: 'high',
          title: 'Privilege escalation in memory',
          description: 'This memory file references sensitive system paths or elevated permissions.',
          filePath: file.path,
          learnMoreUrl: LEARN_MORE,
        });
        risk = mergeRisk(risk, 'HIGH');
      }
    }

    if (result.credentialScan && result.credentialScan.findings.length > 0) {
      for (const cf of result.credentialScan.findings) {
        const severity: AuditSeverity = cf.severity === 'critical' ? 'critical' : cf.severity === 'high' ? 'high' : 'medium';
        findings.push({
          scanner: 'memory',
          severity,
          title: `Credential leaked in memory: ${cf.provider || cf.type}`,
          description: `A ${cf.type} credential was found stored in agent memory. This could be exfiltrated by a malicious prompt.`,
          filePath: file.path,
          matchedText: cf.match,
          learnMoreUrl: 'https://shieldcortex.ai/docs/threats/credential-leak',
        });
        risk = mergeRisk(risk, severityToRisk(severity));
      }
    }

    evidence = [
      ...result.firewall.blockedPatterns.map((snippet) => ({
        snippet: snippet.slice(0, 240),
        reason: 'Matched deterministic defence pattern',
      })),
      ...findings.map(evidenceFromFinding).filter((entry): entry is MemoryFileEvidence => Boolean(entry)),
    ];
  } catch {
    firewallResult = 'BLOCK';
    risk = 'CRITICAL';
    reason = 'Pipeline error — fail-closed for security';
    threatIndicators = ['pipeline_error'];
    anomalyScore = 1;
  }

  return {
    id: fileId(file.path),
    path: file.path,
    source: file.source,
    sizeBytes,
    modifiedAt,
    contentExcerpt: excerpt(content),
    auditId,
    anomalyScore,
    firewallResult,
    risk,
    reason,
    threatIndicators,
    evidence: dedupeEvidence(evidence),
    findings,
  };
}

export function scanMemoryFilesDetailed(options: MemoryFileDiscoveryOptions = {}): DetailedMemoryFileScanResult {
  const start = Date.now();
  const discovered = discoverMemoryFiles(options)
    .filter((file) => !isShieldCortexOwnMemoryPath(file.path));
  const files = discovered
    .map(scanMemoryFileDetailed)
    .filter((file): file is MemoryFileScanRecord => Boolean(file))
    .sort((a, b) => riskRank(b.risk) - riskRank(a.risk) || a.path.localeCompare(b.path));

  const summary = files.reduce<MemoryFileScanSummary>((acc, file) => {
    acc.total += 1;
    if (file.risk === 'SAFE' || file.risk === 'LOW') acc.safe += 1;
    else acc.flagged += 1;
    if (file.risk === 'CRITICAL') acc.critical += 1;
    if (file.risk === 'HIGH') acc.high += 1;
    if (file.risk === 'MEDIUM') acc.medium += 1;
    return acc;
  }, {
    total: 0,
    safe: 0,
    flagged: 0,
    critical: 0,
    high: 0,
    medium: 0,
  });

  return {
    scannedAt: new Date().toISOString(),
    summary,
    files,
    durationMs: Date.now() - start,
  };
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
    if (isShieldCortexOwnMemoryPath(file.path)) continue;
    allFindings.push(...scanMemoryFile(file.path));
  }

  return {
    name: 'Memory Scanner',
    itemsScanned: files.length,
    findings: allFindings,
    durationMs: Date.now() - start,
  };
}
