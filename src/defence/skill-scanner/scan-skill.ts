/**
 * Skill Scanner — Core Module
 *
 * Scans agent instruction files (skill definitions, tool configs, rules files)
 * for threats using the full ShieldCortex defence pipeline combined with
 * skill-specific pattern detection.
 *
 * Public API:
 *  - scanSkill(filePath, options?)     — read from disc and scan
 *  - scanSkillContent(content, options?) — scan raw content directly
 *
 * Never throws — returns safe defaults on errors.
 */

import { analyzeFirewall } from '../firewall/index.js';
import { classifySensitivity } from '../sensitivity/index.js';
import type {
  DefenceConfig,
  DefenceSource,
  FirewallAnalysis,
  SensitivityClassification,
  ThreatIndicator,
} from '../types.js';
import { DEFAULT_DEFENCE_CONFIG } from '../types.js';
import { detectSkillThreats, detectCodeThreats } from './patterns.js';
import type { SkillThreatResult } from './patterns.js';
import { readSkillFile, parseSkillFile } from './parser.js';
import type { SkillFormat, ParsedSkill } from './parser.js';
import { applyDensityCap } from './scan-profile.js';

// ── Types ────────────────────────────────────────────────────────────────────

export interface SkillScanOptions {
  /** Defence mode override (defaults to config default — 'balanced'). */
  mode?: 'strict' | 'balanced' | 'permissive';
  /** When true, include the matched text snippet in each finding. */
  includeContent?: boolean;
}

export interface SkillThreatFinding {
  /** Pattern group name, e.g. 'tool_injection', 'data_exfiltration'. */
  pattern: string;
  /** Derived severity for this finding. */
  severity: 'low' | 'medium' | 'high' | 'critical';
  /** Human-readable explanation of the threat. */
  description: string;
  /** The text that triggered the finding (truncated to 80 chars). */
  matchedText?: string;
  /** Line number in the source file, if determinable. */
  line?: number;
}

export interface SkillScanResult {
  /** True when no high or critical findings exist. */
  safe: boolean;
  /** Name extracted from the skill file. */
  skillName: string;
  /** Detected format of the skill file. */
  format: SkillFormat;
  /** Individual threat findings. */
  findings: SkillThreatFinding[];
  /** Overall risk level — the highest severity found, or 'safe'. */
  riskLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical';
  /** One-line human-readable summary. */
  summary: string;
  /** Time taken to scan in milliseconds. */
  scanDurationMs: number;
  /**
   * True when the format-aware profile (issue #121) capped one or more findings
   * to 'medium' because the file is a skill/hook doc carrying only imperative-
   * instruction density with no hard exfil/credential/config-mutation signal.
   */
  densityCapped: boolean;
  /** Full firewall analysis result. */
  firewall: FirewallAnalysis;
  /** Sensitivity classification result. */
  sensitivity: SensitivityClassification;
}

// ── Threat Description Map ───────────────────────────────────────────────────

const THREAT_DESCRIPTIONS: Record<string, string> = {
  // Skill-specific patterns
  tool_injection: 'Instructions to execute shell commands or write files',
  scope_escalation: 'Attempts to access files outside the project directory',
  data_exfiltration: 'Instructions to send data to external services',
  persistence: 'Attempts to modify agent configuration files',
  supply_chain: 'Instructions to install packages or modify dependencies',
  agent_manipulation: 'Instructions to disable safety checks or permissions',
  stealth_instruction: 'Hidden instructions using formatting tricks',

  // Code patterns
  dangerous_require: 'Imports dangerous Node.js modules (child_process, net)',
  dangerous_calls: 'Uses dangerous function calls (eval, exec, spawn)',
  filesystem_access: 'Accesses sensitive filesystem paths',
  network_access: 'Makes network requests to external services',

  // Firewall threat indicators
  instruction_injection: 'Prompt injection detected by firewall',
  privilege_escalation: 'Privilege escalation patterns detected',
  encoding_obfuscation: 'Obfuscated or encoded content detected',
  credential_leak: 'Potential credential or secret exposure',
  external_url: 'References to external URLs detected',
  fragmented_payload: 'Fragmented payload assembly detected',
  pipeline_error: 'Defence pipeline encountered an error',
};

// ── Severity Helpers ─────────────────────────────────────────────────────────

/** Severity ranking for comparison. */
const SEVERITY_RANK: Record<string, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/**
 * Derive severity for a firewall threat indicator based on the firewall result.
 */
function deriveFirewallSeverity(
  firewallResult: string,
  indicator: ThreatIndicator,
): 'low' | 'medium' | 'high' | 'critical' {
  if (firewallResult === 'BLOCK') {
    if (indicator === 'instruction_injection' || indicator === 'credential_leak') {
      return 'critical';
    }
    return 'high';
  }
  if (firewallResult === 'QUARANTINE') {
    if (indicator === 'instruction_injection') {
      return 'high';
    }
    return 'medium';
  }
  return 'low';
}

/**
 * Derive severity for a skill/code threat based on its confidence score.
 */
function deriveSkillThreatSeverity(confidence: number): 'low' | 'medium' | 'high' {
  if (confidence >= 0.85) return 'high';
  if (confidence >= 0.6) return 'medium';
  return 'low';
}

/**
 * Return the highest severity from an array of findings, or 'safe' if empty.
 */
function highestSeverity(
  findings: SkillThreatFinding[],
): 'safe' | 'low' | 'medium' | 'high' | 'critical' {
  if (findings.length === 0) return 'safe';

  let maxRank = 0;
  let maxSeverity: 'low' | 'medium' | 'high' | 'critical' = 'low';

  for (const finding of findings) {
    const rank = SEVERITY_RANK[finding.severity] ?? 0;
    if (rank > maxRank) {
      maxRank = rank;
      maxSeverity = finding.severity;
    }
  }

  return maxSeverity;
}

/**
 * Look up a human-readable description for a threat pattern name.
 */
function descriptionFor(pattern: string): string {
  return THREAT_DESCRIPTIONS[pattern] ?? `Threat pattern detected: ${pattern}`;
}

/**
 * Truncate text to a maximum length, appending an ellipsis if needed.
 */
function truncate(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text;
  return text.slice(0, maxLength - 1) + '\u2026';
}

// ── Build Config ─────────────────────────────────────────────────────────────

/**
 * Build a DefenceConfig with the mode optionally overridden.
 */
function buildConfig(mode?: 'strict' | 'balanced' | 'permissive'): DefenceConfig {
  if (!mode || mode === DEFAULT_DEFENCE_CONFIG.mode) {
    return DEFAULT_DEFENCE_CONFIG;
  }
  return { ...DEFAULT_DEFENCE_CONFIG, mode };
}

// ── Core Scan Logic ──────────────────────────────────────────────────────────

/**
 * Internal scan implementation that operates on a ParsedSkill.
 */
function scanParsed(
  parsed: ParsedSkill,
  options?: SkillScanOptions,
): SkillScanResult {
  const startTime = Date.now();
  const includeContent = options?.includeContent ?? false;
  const config = buildConfig(options?.mode);

  const findings: SkillThreatFinding[] = [];

  // 1. Firewall analysis — treat skill files as untrusted (trust 0.3)
  const source: DefenceSource = { type: 'file', identifier: parsed.name };
  const firewall = analyzeFirewall(
    parsed.content,
    parsed.name,
    source,
    0.3,
    config,
  );

  // 2. Sensitivity classification
  const sensitivity = classifySensitivity(parsed.content, parsed.name);

  // 3. Collect findings from firewall threat indicators
  if (firewall.result === 'BLOCK' || firewall.result === 'QUARANTINE') {
    for (const indicator of firewall.threatIndicators) {
      const severity = deriveFirewallSeverity(firewall.result, indicator);
      const finding: SkillThreatFinding = {
        pattern: indicator,
        severity,
        description: descriptionFor(indicator),
      };

      if (includeContent && firewall.blockedPatterns.length > 0) {
        finding.matchedText = truncate(firewall.blockedPatterns[0], 80);
      }

      findings.push(finding);
    }

    // If firewall blocked/quarantined but reported no specific indicators
    if (firewall.threatIndicators.length === 0) {
      findings.push({
        pattern: 'instruction_injection',
        severity: firewall.result === 'BLOCK' ? 'high' : 'medium',
        description: firewall.reason,
      });
    }
  }

  // 4. Skill-specific threat detection
  const skillResult = detectSkillThreats(parsed.content);
  addSkillFindings(findings, skillResult, parsed.content, includeContent);

  // 5. Code threat detection for code-bearing formats
  if (parsed.format === 'hook-js' || parsed.format === 'continue-json') {
    const codeResult = detectCodeThreats(parsed.content);
    addSkillFindings(findings, codeResult, parsed.content, includeContent);
  }

  // 6. Scan metadata values if present
  if (parsed.metadata && Object.keys(parsed.metadata).length > 0) {
    try {
      const metadataStr = JSON.stringify(parsed.metadata);
      const metaResult = detectSkillThreats(metadataStr);
      addSkillFindings(findings, metaResult, metadataStr, includeContent);
    } catch {
      // JSON.stringify failed — skip metadata scan
    }
  }

  // 7. Flag RESTRICTED sensitivity content
  if (sensitivity.level === 'RESTRICTED') {
    findings.push({
      pattern: 'credential_leak',
      severity: 'high',
      description: `RESTRICTED content detected: ${sensitivity.detectedPatterns.join(', ')}`,
    });
  }

  // 8. Deduplicate findings by pattern name (keep highest severity)
  const deduped = deduplicateFindings(findings);

  // 9. Format-aware profile (issue #121): for skill/hook docs, imperative-
  //    instruction density alone cannot carry high/critical — cap to 'medium'
  //    unless a hard exfil/credential/config-mutation signal corroborates it.
  const { findings: profiled, capped: densityCapped } = applyDensityCap(
    deduped,
    parsed.format,
  );

  // 10. Derive overall risk level and safety from the profiled findings
  const riskLevel = highestSeverity(profiled);
  const safe = !profiled.some(
    (f) => f.severity === 'high' || f.severity === 'critical',
  );

  // 11. Generate summary
  const summary = generateSummary(parsed.name, profiled, riskLevel, safe);

  return {
    safe,
    skillName: parsed.name,
    format: parsed.format,
    findings: profiled,
    riskLevel,
    summary,
    scanDurationMs: Date.now() - startTime,
    densityCapped,
    firewall,
    sensitivity,
  };
}

/**
 * Add findings from a SkillThreatResult into the findings array.
 */
function addSkillFindings(
  findings: SkillThreatFinding[],
  result: SkillThreatResult,
  content: string,
  includeContent: boolean,
): void {
  if (!result.detected) return;

  const severity = deriveSkillThreatSeverity(result.confidence);

  for (const threat of result.threats) {
    const finding: SkillThreatFinding = {
      pattern: threat,
      severity,
      description: descriptionFor(threat),
    };

    if (includeContent) {
      // Try to find the first relevant line for context
      const snippet = findSnippetForThreat(content, threat);
      if (snippet) {
        finding.matchedText = truncate(snippet, 80);
      }
    }

    findings.push(finding);
  }
}

/**
 * Attempt to find a content snippet relevant to a named threat.
 * Returns the first line containing a keyword associated with the threat,
 * or null if nothing obvious is found.
 */
function findSnippetForThreat(content: string, threat: string): string | null {
  const keywords: Record<string, string[]> = {
    tool_injection: ['execute', 'run', 'bash', 'shell', 'command', 'script'],
    scope_escalation: ['.ssh', '.aws', '.env', '/etc/', 'process.env'],
    data_exfiltration: ['send', 'post', 'curl', 'upload', 'webhook', 'fetch'],
    persistence: ['.claude', '.cursorrules', 'crontab', 'hook', 'bashrc'],
    supply_chain: ['npm install', 'pip install', 'package.json', 'dependency'],
    agent_manipulation: ['ignore', 'bypass', 'disable', 'override', 'skip'],
    stealth_instruction: ['<!--', '---'],
    dangerous_require: ['child_process', 'require', 'import'],
    dangerous_calls: ['eval', 'exec', 'spawn', 'Function'],
    filesystem_access: ['readFile', 'writeFile', '.env', '.key'],
    network_access: ['http', 'fetch', 'WebSocket', 'listen'],
  };

  const kws = keywords[threat];
  if (!kws) return null;

  const lines = content.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.length === 0) continue;

    for (const kw of kws) {
      if (trimmed.toLowerCase().includes(kw.toLowerCase())) {
        return trimmed;
      }
    }
  }

  return null;
}

/**
 * Deduplicate findings by pattern name, keeping the highest severity instance.
 */
function deduplicateFindings(findings: SkillThreatFinding[]): SkillThreatFinding[] {
  const byPattern = new Map<string, SkillThreatFinding>();

  for (const finding of findings) {
    const existing = byPattern.get(finding.pattern);
    if (!existing) {
      byPattern.set(finding.pattern, finding);
    } else {
      const existingRank = SEVERITY_RANK[existing.severity] ?? 0;
      const newRank = SEVERITY_RANK[finding.severity] ?? 0;
      if (newRank > existingRank) {
        byPattern.set(finding.pattern, finding);
      }
    }
  }

  return [...byPattern.values()];
}

/**
 * Generate a one-line human-readable summary of the scan result.
 */
function generateSummary(
  name: string,
  findings: SkillThreatFinding[],
  riskLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical',
  safe: boolean,
): string {
  if (findings.length === 0) {
    return `${name}: no threats detected`;
  }

  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    severityCounts[f.severity]++;
  }

  const parts: string[] = [];
  if (severityCounts.critical > 0) parts.push(`${severityCounts.critical} critical`);
  if (severityCounts.high > 0) parts.push(`${severityCounts.high} high`);
  if (severityCounts.medium > 0) parts.push(`${severityCounts.medium} medium`);
  if (severityCounts.low > 0) parts.push(`${severityCounts.low} low`);

  const riskLabel = safe ? 'review recommended' : 'unsafe';

  return `${name}: ${findings.length} finding(s) (${parts.join(', ')}) — ${riskLabel}`;
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Scan a skill file from disc for threats.
 *
 * Reads the file, auto-detects its format, and runs the full defence pipeline
 * plus skill-specific pattern detection.
 *
 * Never throws — returns safe defaults if the file cannot be read.
 */
export function scanSkill(
  filePath: string,
  options?: SkillScanOptions,
): SkillScanResult {
  try {
    const parsed = readSkillFile(filePath);
    const result = scanParsed(parsed, options);
    return result;
  } catch {
    // Return a safe default on any unexpected error
    const startTime = Date.now();
    return {
      safe: true,
      skillName: filePath,
      format: 'unknown',
      findings: [],
      riskLevel: 'safe',
      summary: `${filePath}: scan failed — could not read file`,
      scanDurationMs: Date.now() - startTime,
      densityCapped: false,
      firewall: {
        result: 'ALLOW',
        reason: 'Scan failed — file unreadable',
        threatIndicators: [],
        anomalyScore: 0,
        blockedPatterns: [],
      },
      sensitivity: {
        level: 'PUBLIC',
        confidence: 0,
        detectedPatterns: [],
        redactionRequired: false,
      },
    };
  }
}

/**
 * Scan raw skill content for threats without reading from disc.
 *
 * Useful when the content is already in memory (e.g. received via API,
 * read from a database, or extracted from a larger document).
 *
 * @param content  Raw file content to scan
 * @param options  Scan options (mode, includeContent)
 * @param format   Optional format hint — auto-detected as 'unknown' if omitted
 * @param name     Optional skill name — defaults to 'inline'
 */
export function scanSkillContent(
  content: string,
  options?: SkillScanOptions,
  format?: SkillFormat,
  name?: string,
): SkillScanResult {
  try {
    const parsed = parseSkillFile(content, format);

    // Override name if provided
    if (name) {
      parsed.name = name;
    } else if (parsed.name === 'unknown') {
      parsed.name = 'inline';
    }

    return scanParsed(parsed, options);
  } catch {
    // Return a safe default on any unexpected error
    const effectiveName = name ?? 'inline';
    const startTime = Date.now();
    return {
      safe: true,
      skillName: effectiveName,
      format: format ?? 'unknown',
      findings: [],
      riskLevel: 'safe',
      summary: `${effectiveName}: scan failed — unexpected error`,
      scanDurationMs: Date.now() - startTime,
      densityCapped: false,
      firewall: {
        result: 'ALLOW',
        reason: 'Scan failed — unexpected error',
        threatIndicators: [],
        anomalyScore: 0,
        blockedPatterns: [],
      },
      sensitivity: {
        level: 'PUBLIC',
        confidence: 0,
        detectedPatterns: [],
        redactionRequired: false,
      },
    };
  }
}
