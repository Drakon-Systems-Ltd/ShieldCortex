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
 * #205 — documentation / template placeholders are not secrets.
 *
 * ENV_SECRET patterns match `API_KEY=…` assignments at 0.82–0.85 confidence.
 * Without a denylist they fire on every README (`your-api-key-here`,
 * `changeme_in_production`, `replace-with-your-token`). Conservative:
 * only obvious placeholder language, not real-looking random values.
 */
export function isDocumentationPlaceholder(value: string): boolean {
  const v = value.trim().toLowerCase();
  if (!v) return true;

  // Exact common placeholders
  const exact = new Set([
    'changeme',
    'change_me',
    'changeme!',
    'password',
    'secret',
    'secret123',
    'password123',
    'admin',
    'root',
    'todo',
    'fixme',
    'fix_me',
    'example',
    'sample',
    'dummy',
    'placeholder',
    'redacted',
    'xxx',
    'xxxx',
    'xxxxxxxx',
    '<password>',
    '<secret>',
    '<token>',
    '<api_key>',
    'your_password',
    'your_secret',
    'your_token',
    'your_api_key',
    'insert_here',
    'insert-here',
  ]);
  if (exact.has(v)) return true;

  // Phrase-shaped placeholders
  if (/^(your|my|the)[-_ ]?(api[-_ ]?key|secret|token|password|passwd|key)\b/.test(v)) return true;
  if (/\b(your|my)[-_ ]?(api[-_ ]?key|secret|token|password)\b/.test(v)) return true;
  if (/\b(replace|insert|put|enter|set)[-_ ]?(with[-_ ]?)?(your|a|the)[-_ ]?/.test(v)) return true;
  // changeme / change_me anywhere in a short value (changeme_in_production)
  if (/(^|[^a-z])change[-_]?me([^a-z]|$)/.test(v) && v.length < 48) return true;
  if (/\b(change|replace)[-_]?(me)?\b/.test(v) && v.length < 40) return true;
  if (/\b(example|sample|dummy|placeholder|redacted|todo|fixme)\b/.test(v) && v.length < 48) return true;
  if (/^(x{4,}|\*{4,}|\.{4,}|-{4,}|_{4,})$/i.test(value.trim())) return true;
  if (/^<.*>$/.test(value.trim())) return true;
  if (/^(xxx+|yyy+|zzz+|abc+|test|testing|asdf|qwerty)([0-9!@._-]*)?$/i.test(v)) return true;
  // *_in_production / *_here / *_todo style template tails
  if (/_(in_production|here|todo|example|sample|placeholder)$/.test(v) && v.length < 48) return true;

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
  let matchedRanges: Array<{ start: number; end: number; replacement: string }> = [];

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

      // #205: documentation placeholders are not secrets.
      // Only for env-style assignment CAPTURES — never for full connection
      // strings / API keys (those can contain the word "example" in a host).
      if (pattern.type === 'env_secret' && isDocumentationPlaceholder(secretValue)) continue;

      // Skip if this range is already covered by a higher-priority pattern
      const start = match.index;
      const end = start + fullMatch.length;
      if (matchedRanges.some(r => start >= r.start && end <= r.end)) continue;

      // Skip well-known PUBLIC identifiers (git SHA / UUID). Generic hex rules
      // match a substring of these, so expand to the full token before testing
      // (Phase 17 A5 / #205 empty digests).
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
  // Snapshot the pattern layer's ranges BEFORE the entropy loop mutates
  // matchedRanges: finding-emission (below) discriminates against these, and
  // entropy ranges pushed for earlier tokens must never suppress later ones.
  // Merged into disjoint intervals so two overlapping pattern matches cannot
  // double-subtract coverage in the uncovered-length arithmetic.
  const patternRanges = matchedRanges
    .map(r => ({ start: r.start, end: r.end }))
    .sort((a, b) => a.start - b.start)
    .reduce<Array<{ start: number; end: number }>>((merged, r) => {
      const last = merged[merged.length - 1];
      if (last && r.start <= last.end) last.end = Math.max(last.end, r.end);
      else merged.push({ ...r });
      return merged;
    }, []);
  for (const token of entropyTokens) {
    const start = token.position;
    const end = start + token.token.length;

    // Skip only when an earlier pattern already covers the ENTIRE entropy
    // token. A low-confidence pattern can match just the repeated filler prefix
    // of a padded secret (`aaaa...` as a generic hex/Azure key). Treating that
    // partial overlap as "already caught" left the real high-entropy suffix raw
    // in redacted output — exactly the #257 bypass shape.
    if (matchedRanges.some(r => start >= r.start && end <= r.end)) continue;

    // Skip allowlisted
    if (isAllowlisted(token.token, cfg.allowlist)) continue;

    // Range FIRST, and unconditionally — a repeat must still be redacted even
    // though it will not produce a second finding below. Drop narrower pattern
    // ranges contained inside this entropy token so a filler-only match cannot
    // split or shrink the redaction span.
    matchedRanges = matchedRanges.filter(r => !(r.start >= start && r.end <= end));
    matchedRanges.push({ start, end, replacement: '[REDACTED-high_entropy]' });

    if (reportedEntropyTokens.has(token.token)) continue;
    reportedEntropyTokens.add(token.token);

    // #256 invariant: one finding per DISTINCT secret. An env-style assignment
    // (`FOO=<secret>`) tokenises key+secret into one entropy token that extends
    // past the pattern match by a few boilerplate chars, so it is not "fully
    // nested" above — but it is still the SAME secret the pattern already
    // reported. Emit a second finding only when the pattern layer leaves ≥ 20
    // uncovered chars of this token (the tokeniser's own minimum secret
    // length — anything smaller cannot be a distinct secret by the net's own
    // definition). The redaction RANGE above is recorded unconditionally
    // either way: #257 completeness and #256 reporting are separate concerns.
    let uncovered = end - start;
    for (const r of patternRanges) {
      const overlap = Math.min(end, r.end) - Math.max(start, r.start);
      if (overlap > 0) uncovered -= overlap;
    }
    if (uncovered < 20 && uncovered < end - start) continue;

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
  const merged = mergeOverlappingRanges(ranges);
  // Sort by start position descending to replace from end to start
  const sorted = [...merged].sort((a, b) => b.start - a.start);
  let result = content;
  for (const range of sorted) {
    result = result.slice(0, range.start) + range.replacement + result.slice(range.end);
  }
  return result;
}

/**
 * Collapse overlapping (not just nested) ranges into a single span before
 * replacement.
 *
 * `buildRedactedContent` replaces right-to-left on the assumption that ranges
 * never overlap, using offsets computed against the ORIGINAL content. A
 * PARTIAL overlap — e.g. a pattern match whose captured charset stops short
 * of a longer entropy token, so the pattern's end falls strictly inside the
 * entropy token's span while neither range contains the other — breaks that
 * assumption: replacing the first range shrinks/reshapes the working string,
 * and the second range's original-content `end` then lands on the wrong
 * position in that already-mutated string, silently truncating or duplicating
 * output. The two-range-removal dance in `scanForCredentials` only handles
 * the fully-NESTED case (one range wholly inside another); it does not — and
 * structurally cannot, since it only sees one new range at a time — catch a
 * crossing overlap. Merging here makes "ranges never overlap" true by
 * construction for every caller, instead of relying on every producer of
 * `matchedRanges` to keep it true by hand.
 */
function mergeOverlappingRanges(
  ranges: Array<{ start: number; end: number; replacement: string }>,
): Array<{ start: number; end: number; replacement: string }> {
  if (ranges.length <= 1) return ranges;

  const sorted = [...ranges].sort((a, b) => a.start - b.start || a.end - b.end);
  const merged: Array<{ start: number; end: number; replacement: string }> = [sorted[0]];

  for (let i = 1; i < sorted.length; i++) {
    const next = sorted[i];
    const last = merged[merged.length - 1];
    if (next.start < last.end) {
      // Overlapping (or one nested in the other) — union the span. Keep
      // whichever replacement corresponds to the wider original range: it
      // covers strictly more of the underlying secret and is the more
      // complete redaction of the two.
      const wider = next.end - next.start > last.end - last.start ? next : last;
      merged[merged.length - 1] = {
        start: last.start,
        end: Math.max(last.end, next.end),
        replacement: wider.replacement,
      };
    } else {
      merged.push(next);
    }
  }

  return merged;
}

// Re-export types and utilities
export type { CredentialPattern, CredentialType, CredentialSeverity } from './patterns.js';
export { shannonEntropy, checkHighEntropy } from './entropy.js';
export { ALL_CREDENTIAL_PATTERNS } from './patterns.js';
