/**
 * Credential Leak Detection — Layer 6
 *
 * Detects credentials, secrets, and sensitive tokens accidentally
 * persisted in AI agent memory writes. Supports known API key formats,
 * generic secrets, private keys, connection strings, environment
 * variable patterns, and high-entropy string heuristics.
 */

import {
  ALL_CREDENTIAL_PATTERNS,
  type CredentialPattern,
  type CredentialType,
  type CredentialSeverity,
} from './patterns.js';
import { extractHighEntropyTokens, isWellKnownNonSecret } from './entropy.js';

// ── Public Types ──

export interface CredentialFinding {
  type: CredentialType;
  provider?: string;
  confidence: number;
  severity: CredentialSeverity;
  /** Redacted version showing first/last 4 chars */
  match: string;
  /** Char offset in content */
  position: number;
  action: 'blocked' | 'warned' | 'logged';
}

export interface CredentialScanResult {
  leaked: boolean;
  findings: CredentialFinding[];
  redactedContent?: string;
}

export interface CredentialDetectionConfig {
  enabled: boolean;
  blockOnCritical: boolean;
  blockOnHigh: boolean;
  warnOnMedium: boolean;
  customPatterns: CredentialPattern[];
  allowlist: string[];
}

export const DEFAULT_CREDENTIAL_CONFIG: CredentialDetectionConfig = {
  enabled: true,
  blockOnCritical: true,
  blockOnHigh: true,
  warnOnMedium: true,
  customPatterns: [],
  allowlist: [],
};

// ── Redaction ──

/**
 * Redact a matched secret, showing first and last 4 chars.
 * Very short matches get fully redacted.
 */
function redactMatch(value: string, type: CredentialType): string {
  if (value.length <= 12) return `[REDACTED-${type}]`;
  return `${value.slice(0, 4)}...${value.slice(-4)}`;
}

/**
 * Determine action based on severity and config.
 */
function actionForSeverity(
  severity: CredentialSeverity,
  config: CredentialDetectionConfig,
): 'blocked' | 'warned' | 'logged' {
  if (severity === 'critical' && config.blockOnCritical) return 'blocked';
  if (severity === 'high' && config.blockOnHigh) return 'blocked';
  if (severity === 'medium' && config.warnOnMedium) return 'warned';
  return 'logged';
}

/**
 * Check if a match is in the allowlist.
 * Allowlist entries can be literal prefixes or glob-like patterns.
 */
function isAllowlisted(value: string, allowlist: string[]): boolean {
  for (const entry of allowlist) {
    if (value.startsWith(entry) || value === entry) return true;
  }
  return false;
}

/**
 * Expand a match span to the full contiguous identifier token it sits in, then
 * test it against the well-known-non-secret allowlist (git SHA / UUID).
 *
 * Generic hex patterns (e.g. the 32-hex "Azure" rule) match a SUBSTRING of a
 * 40-hex commit SHA, so checking only the captured value misses it — we must
 * look at the surrounding contiguous run. The token boundary is the usual
 * credential alphabet ([A-Za-z0-9-]); we deliberately do NOT cross `/`, `+`,
 * `=` etc. so a real base64 secret that merely contains a hex-looking run is
 * not whitelisted.
 */
function matchIsWellKnownNonSecret(content: string, start: number, end: number): boolean {
  const tokenChar = /[A-Za-z0-9-]/;
  let s = start;
  let e = end;
  while (s > 0 && tokenChar.test(content[s - 1])) s--;
  while (e < content.length && tokenChar.test(content[e])) e++;
  return isWellKnownNonSecret(content.slice(s, e));
}

// ── Scanner ──

/**
 * Scan content for credential leaks.
 *
 * Checks known API key formats, generic secrets, private keys,
 * connection strings, env variable patterns, and high-entropy strings.
 *
 * @param content - The text content to scan
 * @param config - Optional credential detection configuration
 * @returns Scan result with findings and optional redacted content
 */
export function scanForCredentials(
  content: string,
  config?: Partial<CredentialDetectionConfig>,
): CredentialScanResult {
  const cfg: CredentialDetectionConfig = { ...DEFAULT_CREDENTIAL_CONFIG, ...config };

  if (!cfg.enabled || !content || content.length === 0) {
    return { leaked: false, findings: [] };
  }

  const findings: CredentialFinding[] = [];
  const matchedRanges: Array<{ start: number; end: number; replacement: string }> = [];

  const patterns = [...ALL_CREDENTIAL_PATTERNS, ...cfg.customPatterns];

  // Run all pattern matchers
  for (const pattern of patterns) {
    // Reset regex lastIndex for each scan
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let match: RegExpExecArray | null;

    while ((match = regex.exec(content)) !== null) {
      const fullMatch = match[0];
      // For patterns with capture groups, use the group; otherwise the full match
      const secretValue = match[1] ?? fullMatch;

      // Skip if below minimum length
      if (pattern.minLength && secretValue.length < pattern.minLength) continue;

      // Skip allowlisted values
      if (isAllowlisted(secretValue, cfg.allowlist)) continue;

      // Skip if this range is already covered by a higher-priority pattern
      const start = match.index;
      const end = start + fullMatch.length;
      if (matchedRanges.some(r => start >= r.start && end <= r.end)) continue;

      // Skip well-known PUBLIC identifiers (git SHA / UUID). Generic hex rules
      // match a substring of these, so expand to the full token before testing
      // (Phase 17 A5).
      if (matchIsWellKnownNonSecret(content, start, end)) continue;

      const action = actionForSeverity(pattern.severity, cfg);
      const redacted = redactMatch(secretValue, pattern.type);

      findings.push({
        type: pattern.type,
        provider: pattern.provider,
        confidence: pattern.confidence,
        severity: pattern.severity,
        match: redacted,
        position: start,
        action,
      });

      const replacement = `[REDACTED-${pattern.type}${pattern.provider ? `-${pattern.provider}` : ''}]`;
      matchedRanges.push({ start, end, replacement });
    }
  }

  // Run entropy-based detection for anything not already caught.
  //
  // `extractHighEntropyTokens` returns EVERY occurrence, so the two concerns
  // are separated deliberately here:
  //
  //   redaction — every occurrence gets a range. Missing one leaves the secret
  //               verbatim in output the caller believes is redacted.
  //   reporting — one finding per distinct secret. Turning a repeat into N
  //               findings would inflate audit counts and severity grades
  //               (`medium > 0` drops the grade to C, which exits 1) without
  //               telling the operator anything they did not already know.
  const entropyTokens = extractHighEntropyTokens(content);
  const reportedEntropyTokens = new Set<string>();
  for (const token of entropyTokens) {
    const start = token.position;
    const end = start + token.token.length;

    // Skip if already caught by pattern matching
    if (matchedRanges.some(r =>
      (start >= r.start && start < r.end) ||
      (end > r.start && end <= r.end),
    )) continue;

    // Skip allowlisted
    if (isAllowlisted(token.token, cfg.allowlist)) continue;

    // Range FIRST, and unconditionally — a repeat must still be redacted even
    // though it will not produce a second finding below.
    matchedRanges.push({ start, end, replacement: '[REDACTED-high_entropy]' });

    if (reportedEntropyTokens.has(token.token)) continue;
    reportedEntropyTokens.add(token.token);

    const severity: CredentialSeverity = token.confidence >= 0.8 ? 'medium' : 'low';
    const action = actionForSeverity(severity, cfg);

    findings.push({
      type: 'high_entropy',
      confidence: token.confidence,
      severity,
      match: redactMatch(token.token, 'high_entropy'),
      position: start,
      action,
    });
  }

  // Sort findings by position
  findings.sort((a, b) => a.position - b.position);

  const leaked = findings.length > 0;
  const hasBlocked = findings.some(f => f.action === 'blocked');

  // Build redacted content if any findings
  let redactedContent: string | undefined;
  if (leaked) {
    redactedContent = buildRedactedContent(content, matchedRanges);
  }

  return {
    leaked,
    findings,
    redactedContent: hasBlocked ? redactedContent : redactedContent,
  };
}

// ── Redaction Helper ──

/**
 * Replace all detected secrets in content with [REDACTED-{type}] placeholders.
 * Useful for agents that want to store memory but strip the secrets.
 */
export function redactCredentials(
  content: string,
  config?: Partial<CredentialDetectionConfig>,
): string {
  const result = scanForCredentials(content, config);
  return result.redactedContent ?? content;
}

/**
 * Build redacted content by replacing matched ranges.
 */
function buildRedactedContent(
  content: string,
  ranges: Array<{ start: number; end: number; replacement: string }>,
): string {
  // Sort by start position descending to replace from end to start
  const sorted = [...ranges].sort((a, b) => b.start - a.start);
  let result = content;
  for (const range of sorted) {
    result = result.slice(0, range.start) + range.replacement + result.slice(range.end);
  }
  return result;
}

// Re-export types and utilities
export type { CredentialPattern, CredentialType, CredentialSeverity } from './patterns.js';
export { shannonEntropy, checkHighEntropy } from './entropy.js';
export { ALL_CREDENTIAL_PATTERNS } from './patterns.js';
