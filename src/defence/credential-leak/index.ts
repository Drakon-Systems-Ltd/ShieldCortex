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
 * `changeme_in_production`, `replace-with-your-token`).
 *
 * Conservative on purpose (dual-review #280): only obvious template language.
 * Do NOT match bare words like "change"/"replace"/"set" inside real values
 * (`Spring-Change-2024`, `my-secret-prod-7f3a`). Prefer exacts + anchored
 * phrase shapes with length caps.
 */
export function isDocumentationPlaceholder(value: string): boolean {
  const raw = value.trim();
  const v = raw.toLowerCase();
  if (!v) return true;

  // Exact common placeholders (whole value)
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
    'your-api-key',
    'your-api-key-here',
    'your_api_key_here',
    'insert_here',
    'insert-here',
    'replace-with-your-token',
    'replace_with_your_token',
    'replace-with-your-secret',
    'replace_with_your_secret',
    'replace-with-your-password',
    'changeme_in_production',
    'change_me_in_production',
    'changeme-in-production',
  ]);
  if (exact.has(v)) return true;

  // Angle-bracket template tokens: <your-token>, <API_KEY>
  if (/^<[^>]{1,40}>$/.test(raw)) return true;

  // Pure mask runs
  if (/^(x{4,}|\*{4,}|\.{4,}|-{4,}|_{4,})$/i.test(raw)) return true;
  if (/^(xxx+|yyy+|zzz+|asdf|qwerty)([0-9!@._-]*)?$/i.test(v)) return true;

  // Anchored "your/my … key/secret/token/password" whole-value templates.
  // Requires a template tail (here|example|placeholder|xxx|sample) OR ends
  // exactly at the credential noun — not "my-secret-prod-abc123".
  if (
    /^(your|my)[-_ ]+(api[-_ ]?key|secret|token|password|passwd|key)([-_ ]+(here|example|sample|placeholder|xxx+))?$/i.test(v)
  ) {
    return true;
  }

  // Anchored "replace/insert … with your …" whole-value templates only.
  if (
    v.length < 48
    && /^(replace|insert)[-_ ]+(with[-_ ]+)?(your|my|a|the)[-_ ]+(api[-_ ]?key|secret|token|password|key|value)([-_ ]*(here)?)?$/.test(v)
  ) {
    return true;
  }

  // changeme / change_me as a PREFIX of a short template (changeme_in_production)
  if (/^change[-_]?me([-_].{0,24})?$/.test(v) && v.length < 40) return true;

  // *_in_production / *_here when the stem is a known placeholder word
  if (
    /^(change[-_]?me|password|secret|token|api[-_]?key|example|sample|dummy|placeholder|todo|fixme)[-_](in[-_]production|here|example|sample|placeholder|todo)$/.test(v)
    && v.length < 48
  ) {
    return true;
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
function identifierCheck(content: string): (start: number, end: number) => boolean {
  // Index boundaries once, then cache the classification of each expanded span.
  // A long token can contain thousands of bounded Azure matches: walking or
  // slicing that entire token again for each match is quadratic (#51).
  const tokenChar = /[A-Za-z0-9-]/;
  const left = new Uint32Array(content.length + 1);
  const right = new Uint32Array(content.length + 1);
  for (let i = 0; i < content.length; i++) {
    left[i + 1] = tokenChar.test(content[i]) ? left[i] : i + 1;
  }
  right[content.length] = content.length;
  for (let i = content.length - 1; i >= 0; i--) {
    right[i] = tokenChar.test(content[i]) ? right[i + 1] : i;
  }
  const known = new Map<string, boolean>();
  return (start, end) => {
    const s = left[start];
    const e = right[end];
    const key = `${s}:${e}`;
    if (!known.has(key)) known.set(key, isWellKnownNonSecret(content.slice(s, e)));
    return known.get(key)!;
  };
}

type RedactionRange = { start: number; end: number; replacement: string };

/** Stable counting order over input offsets, without match-count sorting cost. */
function orderByPosition<T>(values: T[], length: number, position: (value: T) => number): T[] {
  const buckets = new Map<number, T[]>();
  for (const value of values) {
    const offset = position(value);
    const bucket = buckets.get(offset);
    if (bucket) bucket.push(value);
    else buckets.set(offset, [value]);
  }
  const ordered: T[] = [];
  for (let offset = 0; offset <= length; offset++) {
    const bucket = buckets.get(offset);
    if (bucket) for (const value of bucket) ordered.push(value);
  }
  return ordered;
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

  let findings: CredentialFinding[] = [];
  let matchedRanges: RedactionRange[] = [];
  const matchIsWellKnownNonSecret = identifierCheck(content);
  const rangeEnds = new Uint32Array(content.length + 1);

  const patterns = [...ALL_CREDENTIAL_PATTERNS, ...cfg.customPatterns];

  // Run all pattern matchers
  for (const pattern of patterns) {
    // Regex matches advance monotonically. Prefix-max coverage replaces a
    // repeated .some() over all previous findings, including within a pattern.
    let coverageCursor = 0;
    let coveredEnd = 0;
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
      while (coverageCursor <= start) {
        coveredEnd = Math.max(coveredEnd, rangeEnds[coverageCursor++]);
      }
      if (end <= coveredEnd) continue;

      // Skip well-known PUBLIC identifiers (git SHA / UUID). Generic hex rules
      // match a substring of these, so expand to the full token before testing
      // (Phase 17 A5 / #205 empty digests).
      if (matchIsWellKnownNonSecret(start, end)) continue;

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
      rangeEnds[start] = Math.max(rangeEnds[start], end);
      coveredEnd = Math.max(coveredEnd, end);
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
  // Snapshot pattern coverage as prefix counts. Each character contributes at
  // most once even when patterns overlap; entropy queries are then O(1).
  const coveredBytes = new Uint32Array(content.length + 1);
  let coveredEnd = 0;
  for (let i = 0; i < content.length; i++) {
    coveredEnd = Math.max(coveredEnd, rangeEnds[i]);
    coveredBytes[i + 1] = coveredBytes[i] + (coveredEnd > i ? 1 : 0);
    rangeEnds[i] = coveredEnd;
  }
  const entropyRanges: RedactionRange[] = [];
  for (const token of entropyTokens) {
    const start = token.position;
    const end = start + token.token.length;

    // Skip only when an earlier pattern already covers the ENTIRE entropy
    // token. A low-confidence pattern can match just the repeated filler prefix
    // of a padded secret (`aaaa...` as a generic hex/Azure key). Treating that
    // partial overlap as "already caught" left the real high-entropy suffix raw
    // in redacted output — exactly the #257 bypass shape.
    if (end <= rangeEnds[start]) continue;

    // Skip allowlisted
    if (isAllowlisted(token.token, cfg.allowlist)) continue;

    // Range FIRST, and unconditionally — a repeat must still be redacted even
    // though it will not produce a second finding below. Drop narrower pattern
    // ranges contained inside this entropy token so a filler-only match cannot
    // split or shrink the redaction span.
    entropyRanges.push({ start, end, replacement: '[REDACTED-high_entropy]' });

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
    const uncovered = end - start - (coveredBytes[end] - coveredBytes[start]);
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

  // Remove pattern ranges contained in entropy tokens in one ordered sweep.
  // Entropy tokens are disjoint and already in input order.
  let entropyCursor = 0;
  matchedRanges = orderByPosition(matchedRanges, content.length, r => r.start).filter(r => {
    while (entropyCursor < entropyRanges.length && entropyRanges[entropyCursor].end <= r.start) entropyCursor++;
    const token = entropyRanges[entropyCursor];
    return !token || r.start < token.start || r.end > token.end;
  });
  matchedRanges = orderByPosition([...matchedRanges, ...entropyRanges], content.length, r => r.start);
  findings = orderByPosition(findings, content.length, f => f.position);

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
  // Copy each untouched span once. Repeated right-to-left splicing copies the
  // whole response for every finding even after identifier checks are bounded.
  const parts: string[] = [];
  let cursor = 0;
  for (const range of merged) {
    parts.push(content.slice(cursor, range.start), range.replacement);
    cursor = range.end;
  }
  parts.push(content.slice(cursor));
  return parts.join('');
}

/**
 * Collapse overlapping (not just nested) ranges into a single span before
 * replacement.
 *
 * A pattern and an entropy token can overlap without either containing the
 * other. Removing only nested ranges leaves crossing spans that would make
 * the output cursor move backwards and expose or duplicate original bytes.
 * Merge those spans before copying untouched slices of the ORIGINAL content.
 */
function mergeOverlappingRanges(
  ranges: Array<{ start: number; end: number; replacement: string }>,
): Array<{ start: number; end: number; replacement: string }> {
  if (ranges.length <= 1) return ranges;

  // The scanner supplies ranges in ascending start order.
  const merged: Array<{ start: number; end: number; replacement: string }> = [ranges[0]];

  for (let i = 1; i < ranges.length; i++) {
    const next = ranges[i];
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
