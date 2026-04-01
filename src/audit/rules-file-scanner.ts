/**
 * Rules File Scanner
 *
 * Scans AI agent instruction/rules files for:
 *   - Unicode-hidden backdoors (the "Rules File Backdoor" attack)
 *   - Prompt injection in project configs
 *   - Malicious instructions in CLAUDE.md, .cursorrules, etc.
 *
 * Reuses the skill scanner for threat detection and adds Unicode
 * analysis that the skill scanner doesn't cover in depth.
 */

import { existsSync, readFileSync, statSync } from 'fs';
import { join, basename } from 'path';
import { homedir } from 'os';
import type { AuditFinding, ScannerResult, AuditSeverity } from './types.js';
import { scanSkill, discoverSkillFiles } from '../defence/skill-scanner/index.js';

const LEARN_MORE = 'https://shieldcortex.ai/docs/threats/rules-file-backdoor';

// ── ShieldCortex Own-Hook Whitelist ──

/**
 * Paths belonging to ShieldCortex itself.
 * These are legitimate hooks/plugins that should never be flagged by the
 * audit scanner — doing so produces false HIGH/MEDIUM findings (#14).
 */
const SHIELDCORTEX_OWN_PATHS: string[] = [
  'cortex-memory/HOOK.md',
  'cortex-memory/handler.ts',
  'cortex-memory/handler.js',
  'shieldcortex-realtime',
];

/**
 * Return true if this file belongs to ShieldCortex's own hook/plugin set
 * and should be excluded from audit findings.
 */
function isShieldCortexOwnPath(filePath: string): boolean {
  const normalised = filePath.replace(/\\/g, '/');
  return SHIELDCORTEX_OWN_PATHS.some(p => normalised.includes(p));
}



// ── Unicode Backdoor Detection ──

/** Invisible Unicode characters used in the "Rules File Backdoor" attack. */
const INVISIBLE_UNICODE: Array<{ char: string; name: string; codePoint: string }> = [
  { char: '\u200B', name: 'Zero-Width Space', codePoint: 'U+200B' },
  { char: '\u200C', name: 'Zero-Width Non-Joiner', codePoint: 'U+200C' },
  { char: '\u200D', name: 'Zero-Width Joiner', codePoint: 'U+200D' },
  { char: '\u200E', name: 'Left-to-Right Mark', codePoint: 'U+200E' },
  { char: '\u200F', name: 'Right-to-Left Mark', codePoint: 'U+200F' },
  { char: '\u2060', name: 'Word Joiner', codePoint: 'U+2060' },
  { char: '\u2061', name: 'Function Application', codePoint: 'U+2061' },
  { char: '\u2062', name: 'Invisible Times', codePoint: 'U+2062' },
  { char: '\u2063', name: 'Invisible Separator', codePoint: 'U+2063' },
  { char: '\u2064', name: 'Invisible Plus', codePoint: 'U+2064' },
  { char: '\uFEFF', name: 'Zero-Width No-Break Space (BOM)', codePoint: 'U+FEFF' },
  // Bidirectional text control characters
  { char: '\u202A', name: 'Left-to-Right Embedding', codePoint: 'U+202A' },
  { char: '\u202B', name: 'Right-to-Left Embedding', codePoint: 'U+202B' },
  { char: '\u202C', name: 'Pop Directional Formatting', codePoint: 'U+202C' },
  { char: '\u202D', name: 'Left-to-Right Override', codePoint: 'U+202D' },
  { char: '\u202E', name: 'Right-to-Left Override', codePoint: 'U+202E' },
  { char: '\u2066', name: 'Left-to-Right Isolate', codePoint: 'U+2066' },
  { char: '\u2067', name: 'Right-to-Left Isolate', codePoint: 'U+2067' },
  { char: '\u2068', name: 'First Strong Isolate', codePoint: 'U+2068' },
  { char: '\u2069', name: 'Pop Directional Isolate', codePoint: 'U+2069' },
];

/**
 * Detect invisible Unicode characters in content.
 * BOM at position 0 is normal; all others are suspicious.
 */
function detectInvisibleUnicode(content: string): Array<{ codePoint: string; name: string; count: number }> {
  const found: Array<{ codePoint: string; name: string; count: number }> = [];

  for (const { char, name, codePoint } of INVISIBLE_UNICODE) {
    let count = 0;
    let pos = -1;
    while ((pos = content.indexOf(char, pos + 1)) !== -1) {
      // Skip BOM at position 0
      if (codePoint === 'U+FEFF' && pos === 0) continue;
      count++;
    }
    if (count > 0) {
      found.push({ codePoint, name, count });
    }
  }

  return found;
}

/** Maximum file size for rules files (512 KB) */
const MAX_FILE_SIZE = 512 * 1024;

/**
 * Discover additional rules files beyond what discoverSkillFiles finds.
 * Specifically looks for project-level configs that may have been
 * added by malicious PRs.
 */
function discoverExtraRulesFiles(): string[] {
  const files: string[] = [];
  const cwd = process.cwd();

  const candidates = [
    join(cwd, '.github', 'copilot-instructions.md'),
    join(cwd, '.github', 'CLAUDE.md'),
    join(cwd, '.cursorrules'),
    join(cwd, '.windsurfrules'),
    join(cwd, '.clinerules'),
    join(cwd, 'CLAUDE.md'),
    join(cwd, '.aider.conf.yml'),
    join(cwd, '.continue', 'config.json'),
  ];

  for (const p of candidates) {
    try {
      if (existsSync(p) && statSync(p).isFile() && statSync(p).size <= MAX_FILE_SIZE) {
        files.push(p);
      }
    } catch { /* ignore */ }
  }

  return files;
}

/**
 * Scan a single rules/instruction file.
 */
function scanRulesFile(filePath: string): AuditFinding[] {
  const findings: AuditFinding[] = [];
  const fileName = basename(filePath);

  let content: string;
  try {
    content = readFileSync(filePath, 'utf-8');
  } catch {
    return findings;
  }

  if (!content.trim()) return findings;

  // 1. Unicode backdoor detection
  const unicodeFindings = detectInvisibleUnicode(content);
  if (unicodeFindings.length > 0) {
    const totalHidden = unicodeFindings.reduce((sum, f) => sum + f.count, 0);
    const types = unicodeFindings.map(f => `${f.name} (${f.codePoint}) ×${f.count}`).join(', ');

    findings.push({
      scanner: 'rules',
      severity: 'critical',
      title: `Unicode backdoor in ${fileName}`,
      description: `Found ${totalHidden} invisible Unicode character(s) that could hide malicious instructions from code review. This matches the "Rules File Backdoor" attack pattern (CVE-2025-54135). Characters: ${types}`,
      filePath,
      learnMoreUrl: LEARN_MORE,
    });
  }

  // 2. Run through the skill scanner for threat pattern detection
  try {
    const result = scanSkill(filePath);

    if (!result.safe) {
      for (const finding of result.findings) {
        const severity: AuditSeverity =
          finding.severity === 'critical' ? 'critical' :
          finding.severity === 'high' ? 'high' :
          finding.severity === 'medium' ? 'medium' : 'low';

        findings.push({
          scanner: 'rules',
          severity,
          title: `${finding.pattern} in ${fileName}`,
          description: finding.description,
          filePath,
          matchedText: finding.matchedText,
          learnMoreUrl: LEARN_MORE,
        });
      }
    }
  } catch {
    // Skill scanner errors shouldn't crash the audit
  }

  return findings;
}

/**
 * Run the rules file scanner.
 */
export function scanRulesFiles(): ScannerResult {
  const start = Date.now();

  // Combine skill-discovered files with extra project-level files
  const skillFiles = discoverSkillFiles();
  const extraFiles = discoverExtraRulesFiles();
  const allFiles = [...new Set([...skillFiles, ...extraFiles])];

  if (allFiles.length === 0) {
    return {
      name: 'Rules File Scanner',
      itemsScanned: 0,
      findings: [],
      durationMs: Date.now() - start,
      skipped: true,
      skipReason: 'No agent instruction/rules files found',
    };
  }

  const allFindings: AuditFinding[] = [];
  for (const file of allFiles) {
    // Skip ShieldCortex's own hook/plugin files to avoid false positives (#14)
    if (isShieldCortexOwnPath(file)) continue;
    allFindings.push(...scanRulesFile(file));
  }

  return {
    name: 'Rules File Scanner',
    itemsScanned: allFiles.length,
    findings: allFindings,
    durationMs: Date.now() - start,
  };
}
