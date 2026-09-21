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
  /**
   * #543 — set when the value only matched after separators (whitespace,
   * zero-width / format characters) were collapsed out of the text. `position`
   * and the redaction range still refer to the ORIGINAL content and span the
   * inserted separators too.
   */
  evasion?: 'separator_split';
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
function matchIsWellKnownNonSecret(content: string, start: number, end: number): boolean {
  const tokenChar = /[A-Za-z0-9-]/;
  let s = start;
  let e = end;
  while (s > 0 && tokenChar.test(content[s - 1])) s--;
  while (e < content.length && tokenChar.test(content[e])) e++;
  return isWellKnownNonSecret(content.slice(s, e));
}

// ── #543: separator-split evasion ──
//
// The provider patterns match contiguous text only. Writing a key as
// `sk-T3st K3yA bCdE …` — or splitting it with a tab, newline, NBSP or a
// zero-width character — produced zero findings, yet removing the separators
// rebuilds the identical value. The fix is NOT to strip whitespace and rescan
// (that loses match positions, so the redaction range would land on the wrong
// bytes) but to scan a collapsed VIEW that remembers where each surviving
// character came from, and act on the original span.

/**
 * Characters treated as separators: every Unicode whitespace (`\s`), the soft
 * hyphen, zero-width space / non-joiner / joiner, the word joiner and the BOM
 * (zero-width no-break space). Visible punctuation is deliberately excluded —
 * `sk-abc.def` reads as a different value; `sk-abc def` does not.
 */
const SEPARATOR_CHAR = /[\s­​-‍⁠﻿]/;

interface CollapsedView {
  /** `content` with every separator removed. */
  text: string;
  /** `map[i]` is the offset in the original content of `text[i]`. */
  map: number[];
}

/**
 * Build the separator-collapsed view. Returns null when the content has no
 * separators at all — the direct pass has already seen everything.
 */
function buildCollapsedView(content: string): CollapsedView | null {
  const chars: string[] = [];
  const map: number[] = [];
  for (let i = 0; i < content.length; i++) {
    const ch = content[i];
    if (SEPARATOR_CHAR.test(ch)) continue;
    chars.push(ch);
    map.push(i);
  }
  if (chars.length === content.length) return null;
  return { text: chars.join(''), map };
}

/**
 * Precision gate for the collapsed pass only. Collapsing whitespace turns
 * ordinary prose into key-shaped runs — `ASIA PACIFIC REGIONAL SALES` becomes
 * `ASIA` + 21 capitals, `key-value pairs are stored …` becomes the Mailgun
 * shape, a line ending in `sk-` glues onto the next sentence. Issued key
 * material of every format the patterns cover carries digits as well as
 * letters (the odds of a 16-char base-32 body with no digit at all are ~4%;
 * for the base-62 bodies they are negligible), while prose has letters only.
 * Requiring both classes in the collapsed value keeps the direct pass exactly
 * as it was and stops the collapsed pass from firing on words.
 */
function collapsedValueLooksLikeKeyMaterial(value: string): boolean {
  return /[0-9]/.test(value) && /[A-Za-z]/.test(value);
}

type MatchedRange = { start: number; end: number; replacement: string };

/**
 * Patterns that consult whitespace themselves (`\s*` around an `=`, a
 * `[^\s"']+` value class, `BEGIN\s+RSA`) define their own token boundaries;
 * collapsing the separators out from under them changes what they mean, so
 * they take no part in the collapsed pass. The provider key formats — the
 * subject of #543 — are all contiguous-alphabet patterns.
 */
function patternConsultsWhitespace(pattern: CredentialPattern): boolean {
  return /\\s/.test(pattern.regex.source);
}

/**
 * A run of characters between separators that reads as key material rather
 * than as a word: it carries a digit, a non-letter (`_ - . / + =`), or mixed
 * case that is not merely Capitalised. `ASIA`, `PACIFIC`, `end`, `Store` are
 * words; `Ab1C`, `sk-`, `WxYz`, `4B1T` are not.
 */
function fragmentLooksLikeKeyMaterial(fragment: string): boolean {
  if (/[0-9]/.test(fragment)) return true;
  if (/[^A-Za-z]/.test(fragment)) return true;
  if (/[A-Z]/.test(fragment) && /[a-z]/.test(fragment) && !/^[A-Z][a-z]+$/.test(fragment)) return true;
  return false;
}

/**
 * Letter pairs that English words almost never contain: the pairs making up
 * the rarest 1% of adjacent-letter occurrences in a 100k-word list (310 of the
 * 676). 93% of dictionary words hold none of them; a random three-letter run
 * avoids them 29% of the time, a six-letter run 5%. Keyed by first letter.
 */
const RARE_BIGRAMS: Record<string, string> = {
  a: 'ajoq',
  b: 'cdfghjkmnpqtvwxz',
  c: 'bdfgjmnpqvwxz',
  d: 'cfhjkpqtxz',
  e: 'j',
  f: 'bcdghjkmnpqvwxz',
  g: 'bcdfjkpqtvwxz',
  h: 'bcdfghjkpqvxz',
  i: 'hijwy',
  j: 'bcdfghjklmnpqrstvwxyz',
  k: 'bcdfgjkmpqtvwxz',
  l: 'hjqrwxz',
  m: 'cdfghjklqrtvwxz',
  n: 'xz',
  o: 'jq',
  p: 'bcdfgjkmnqvwxz',
  q: 'abcdefghijklmnopqrstvwxyz',
  r: 'jqxz',
  s: 'dgjrvxz',
  t: 'dgjkpqvx',
  u: 'hjquvwxy',
  v: 'bcdfghjklmnpqrstuvwxyz',
  w: 'bcdfgjkmpqtuvwxyz',
  x: 'bdfghjklmnoqrsuvwxyz',
  y: 'fghjkquvwxyz',
  z: 'bcdfghjklmnpqrstuvwxy',
};

/**
 * A fragment that reads as an English word: three or more letters, one case or
 * Capitalised, and no letter pair that English does not use. `REGIONAL`,
 * `legacy`, `Store` are words; `QXZJ`, `IOSF`, `Ab1C`, `sk-` are not.
 */
function fragmentReadsAsProse(fragment: string): boolean {
  if (fragment.length < 3 || fragmentLooksLikeKeyMaterial(fragment)) return false;
  const lower = fragment.toLowerCase();
  for (let i = 0; i < lower.length - 1; i++) {
    if (RARE_BIGRAMS[lower[i]]?.includes(lower[i + 1])) return false;
  }
  return true;
}

/**
 * Share of a collapsed hit that must sit in word-reading fragments for the hit
 * to be dismissed as prose. A year or a quarter gives a sentence the digit the
 * key-material gate asks for — `ASIA 2026 REGIONAL SALES REPORT` collapses to
 * a well-formed AWS id — but most of such a hit is still words. Everything
 * that is not a word counts against: digits, punctuation, one- and two-letter
 * pieces. An attacker picks the split points, not the characters, and cannot
 * make a random key read as words: for mixed-case key bodies the odds are
 * negligible; for the upper-case base-32 AWS id a chosen split gets past this
 * a few percent of the time (disclosed residual).
 */
const PROSE_SHARE_TO_DISMISS = 0.6;

/** Does `pattern` match `text` starting exactly at `start` and ending exactly at `end`? */
function matchesSpanExactly(pattern: CredentialPattern, text: string, start: number, end: number): RegExpExecArray | null {
  const sticky = new RegExp(pattern.regex.source, pattern.regex.flags.replace(/[gy]/g, '') + 'y');
  sticky.lastIndex = start;
  // Slicing keeps the characters BEFORE `start` so lookbehinds see context,
  // and makes `end` the end of input so a greedy quantifier stops there.
  const m = sticky.exec(text.slice(0, end));
  return m !== null && m.index === start && m[0].length === end - start ? m : null;
}

/**
 * Second pattern pass over the collapsed view. Each hit is mapped back to its
 * original span, which is what gets recorded (position) and redacted (range).
 *
 * Collapsing also glues a key to the words around it, and an open-ended
 * pattern (`{20,}`) happily swallows `end` in `sk-… end`. So a hit is first
 * trimmed at both ends: a leading or trailing fragment that reads as a word
 * is dropped as long as the pattern still matches what is left. Fragments in
 * the middle are never dropped — an attacker chooses the split points, and
 * the only thing they cannot choose is the key's own characters.
 *
 * A trimmed hit whose original span holds no separator is the direct pass's
 * business and is skipped; a hit that widens a partial direct match (a split
 * that left one fragment long enough to match on its own) supersedes it, so
 * one secret still yields one finding and one redaction covering the whole
 * value.
 */
function scanCollapsedView(
  view: CollapsedView,
  patterns: CredentialPattern[],
  cfg: CredentialDetectionConfig,
  findings: CredentialFinding[],
  matchedRanges: MatchedRange[],
): { findings: CredentialFinding[]; matchedRanges: MatchedRange[] } {
  const { text, map } = view;

  for (const pattern of patterns) {
    if (patternConsultsWhitespace(pattern)) continue;

    const regex = new RegExp(pattern.regex.source, pattern.regex.flags.includes('g') ? pattern.regex.flags : pattern.regex.flags + 'g');
    let match: RegExpExecArray | null;

    while ((match = regex.exec(text)) !== null) {
      if (match[0].length === 0) {
        regex.lastIndex++;
        continue;
      }

      let cStart = match.index;
      let cEnd = cStart + match[0].length;
      let exact: RegExpExecArray | null = match;

      // A range the direct pass (or an earlier collapsed hit) already recorded
      // says where a token BEGINS. The collapsed run may not flow through such
      // a start: `sk-… and ghp_…` collapses to one run, but it is two keys and
      // a word, not one key. Cut the run at the first recorded start strictly
      // inside it and resume scanning from there afterwards.
      const spanStart = map[cStart];
      const spanEnd = map[cEnd - 1] + 1;

      // A recorded range that BEGINS where this run begins means the pattern
      // layer already matched — and redacts — a valid value here. Gluing on
      // whatever follows would swallow a neighbour (`sk-… customer123`, or a
      // second, finely split token) into it. If what follows really is the
      // rest of the same key, redacting the head has already destroyed the
      // credential. Leave that range alone and resume scanning after it.
      const anchored = matchedRanges.find(r => r.start === spanStart && r.end < spanEnd);
      if (anchored) {
        let cc = cStart;
        while (cc < cEnd && map[cc] < anchored.end) cc++;
        regex.lastIndex = cc;
        continue;
      }

      let cutAt = -1;
      for (const r of matchedRanges) {
        if (r.start > spanStart && r.start < spanEnd && (cutAt === -1 || r.start < cutAt)) cutAt = r.start;
      }
      if (cutAt !== -1) {
        let cc = cStart;
        while (cc < cEnd && map[cc] < cutAt) cc++;
        regex.lastIndex = cc;
        exact = matchesSpanExactly(pattern, text, cStart, cc);
        if (!exact) continue;
        cEnd = cc;
      }

      // Fragments of the hit, in collapsed coordinates. A new fragment starts
      // wherever the original offsets stop being consecutive.
      const frags: Array<{ cs: number; ce: number }> = [];
      for (let c = cStart; c < cEnd; c++) {
        const last = frags[frags.length - 1];
        if (last && map[c] === map[c - 1] + 1) last.ce = c + 1;
        else frags.push({ cs: c, ce: c + 1 });
      }
      // Single fragment: no separator inside, the direct pass owns it.
      if (frags.length < 2) continue;

      // Trim the run of word-like fragments off the end, then off the start,
      // as far as the pattern keeps matching. A run made only of 1–2 letter
      // fragments is left alone unless what remains is a single contiguous
      // fragment: `Uv` or `z` at the end of a key split every two characters
      // is the key's own tail, while `ok` after a contiguous key is a word
      // the direct pass has already excluded.
      const isWord = (f: { cs: number; ce: number }) => !fragmentLooksLikeKeyMaterial(text.slice(f.cs, f.ce));
      const hasWord3 = (run: Array<{ cs: number; ce: number }>) => run.some(f => f.ce - f.cs >= 3);
      let fs = 0;
      let fe = frags.length;

      let k = fe;
      while (k > 1 && isWord(frags[k - 1])) k--;
      if (k < fe && (k === 1 || hasWord3(frags.slice(k, fe)))) {
        for (let i = fe - 1; i >= k; i--) {
          const m = matchesSpanExactly(pattern, text, cStart, frags[i - 1].ce);
          if (!m) break;
          exact = m;
          fe = i;
          cEnd = frags[i - 1].ce;
        }
      }
      let j = 0;
      while (j < fe - 1 && isWord(frags[j])) j++;
      if (j > 0 && (fe - j === 1 || hasWord3(frags.slice(0, j)))) {
        for (let i = 0; i < j; i++) {
          const m = matchesSpanExactly(pattern, text, frags[i + 1].cs, cEnd);
          if (!m) break;
          exact = m;
          fs = i + 1;
          cStart = frags[i + 1].cs;
        }
      }
      if (fe - fs < 2) continue;

      let proseChars = 0;
      for (let i = fs; i < fe; i++) {
        if (fragmentReadsAsProse(text.slice(frags[i].cs, frags[i].ce))) proseChars += frags[i].ce - frags[i].cs;
      }
      if (proseChars >= (cEnd - cStart) * PROSE_SHARE_TO_DISMISS) continue;

      const fullMatch = exact[0];
      const secretValue = exact[1] ?? fullMatch;

      if (pattern.minLength && secretValue.length < pattern.minLength) continue;
      if (isAllowlisted(secretValue, cfg.allowlist)) continue;
      if (pattern.type === 'env_secret' && isDocumentationPlaceholder(secretValue)) continue;
      if (!collapsedValueLooksLikeKeyMaterial(secretValue)) continue;

      const start = map[cStart];
      const end = map[cEnd - 1] + 1;

      // Already covered (by the direct pass or an earlier collapsed hit).
      if (matchedRanges.some(r => start >= r.start && end <= r.end)) continue;
      // Git SHA / UUID with a separator inside is still a public identifier.
      // The token is only contiguous in the collapsed view, so test it there.
      if (matchIsWellKnownNonSecret(text, cStart, cEnd)) continue;

      // Supersede narrower pattern-layer hits that sit inside this span: they
      // are fragments of the same secret, not additional secrets.
      findings = findings.filter(f => !(f.position >= start && f.position < end));
      matchedRanges = matchedRanges.filter(r => !(r.start >= start && r.end <= end));

      findings.push({
        type: pattern.type,
        provider: pattern.provider,
        confidence: pattern.confidence,
        severity: pattern.severity,
        match: redactMatch(secretValue, pattern.type),
        position: start,
        action: actionForSeverity(pattern.severity, cfg),
        evasion: 'separator_split',
      });
      matchedRanges.push({
        start,
        end,
        replacement: `[REDACTED-${pattern.type}${pattern.provider ? `-${pattern.provider}` : ''}]`,
      });
    }
  }

  return { findings, matchedRanges };
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
  let matchedRanges: MatchedRange[] = [];

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

  // #543: second pattern pass over the separator-collapsed view, before the
  // entropy net so a split key's fragments are inside a range by the time the
  // tokeniser sees them.
  const collapsed = buildCollapsedView(content);
  if (collapsed) {
    ({ findings, matchedRanges } = scanCollapsedView(
      collapsed, patterns, cfg, findings, matchedRanges,
    ));
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
