/**
 * Credential Leak Detection — Entropy Analysis
 *
 * Shannon entropy calculation for detecting high-entropy strings
 * that look like secrets (random tokens, keys, passwords).
 */

/**
 * Calculate Shannon entropy of a string (bits per character).
 * Higher entropy = more random/unpredictable.
 *
 * Reference values:
 * - English text: ~3.5-4.0
 * - Base64 encoded: ~5.0-5.5
 * - Random hex: ~3.5-4.0
 * - Random alphanumeric: ~5.5-5.9
 * - Crypto keys: ~5.5-6.0+
 */
export function shannonEntropy(str: string): number {
  if (str.length === 0) return 0;

  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }

  let entropy = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/** Minimum string length for entropy-based detection */
export const MIN_ENTROPY_LENGTH = 20;

/** Entropy threshold — strings above this are flagged */
export const ENTROPY_THRESHOLD = 4.5;

/** A repeated unit of up to this many chars counts as filler, e.g. the 'aaaa-' in 'aaaa-aaaa-...'. */
const FILLER_MAX_UNIT_LENGTH = 8;

/** A unit must repeat at least this many times back-to-back to count as filler, not coincidence. */
const FILLER_MIN_REPEATS = 3;

/**
 * Strip a repeated-unit low-entropy run from the START of a string. Every
 * candidate unit length is tried once and the one covering the MOST characters
 * wins — a short unit reliably present (e.g. "a" x4) must not pre-empt a
 * longer one that actually covers the whole filler run (e.g. "aaaa-" x12).
 *
 * This is deliberately single-pass over the token for each unit length. The
 * scanner runs on untrusted content; repeated strip/rescan loops invite
 * avoidable hot-path cost on long low-entropy padding.
 */
function stripLeadingFiller(s: string): string {
  let bestCoverage = 0;
  for (let unit = 1; unit <= FILLER_MAX_UNIT_LENGTH; unit++) {
    if (s.length < unit * FILLER_MIN_REPEATS) continue;
    const chunk = s.slice(0, unit);
    let reps = 1;
    while (s.slice(reps * unit, (reps + 1) * unit) === chunk) reps++;
    if (reps >= FILLER_MIN_REPEATS) bestCoverage = Math.max(bestCoverage, unit * reps);
  }
  return bestCoverage === 0 ? s : s.slice(bestCoverage);
}

/**
 * Strip a repeated low-entropy filler run from both ends of a token, e.g.
 * "aaaa-aaaa-aaaa-<secret>" → "<secret>". This is the direct fix for #257:
 * padding a secret with repeated filler dilutes WHOLE-TOKEN entropy below
 * ENTROPY_THRESHOLD, so `checkHighEntropy` went silent even though the secret
 * itself, scored on its own, is well above threshold.
 *
 * Deliberately narrow — this defeats REPEATED-unit filler specifically, not
 * arbitrary low-entropy affixes (a non-repeating low-entropy prefix like a
 * dictionary word is a harder, attacker-adaptive problem tracked as a known
 * limitation of the entropy net, not fixed here). A sliding fixed-size window
 * was tried first and rejected: measured against random secrets, a 24-32 char
 * window's empirical entropy is biased low by sample size (birthday-style
 * collisions in a short window under-count true alphabet diversity), missing
 * a large fraction of genuine padded secrets — see #257 discussion. Rescoring
 * the full stripped remainder keeps the same sample size — and therefore the
 * same statistical reliability — as the existing bare-secret path.
 */
function stripRepeatedFillerAffixes(token: string): string {
  const stripped = stripLeadingFiller(token);
  const reversed = stripLeadingFiller([...stripped].reverse().join(''));
  return [...reversed].reverse().join('');
}

/**
 * Entropy of a string, accounting for repeated-filler padding (#257): if the
 * whole string scores below a padded secret's true entropy because low-entropy
 * filler dilutes the average, this also scores the filler-stripped core and
 * returns whichever is higher.
 *
 * This is the SINGLE source of truth for "how high-entropy is this token,
 * really" — every gate that decides whether a token looks like a secret based
 * on its entropy (the confidence check below, and the npm-specifier false-
 * positive filter in `isLikelyFalsePositive`) must call this, not
 * `shannonEntropy` directly, or it re-opens the same padding bypass from a
 * different gate.
 */
export function effectiveEntropy(str: string): number {
  const whole = shannonEntropy(str);
  if (whole >= ENTROPY_THRESHOLD) return whole;

  // Only pay for the strip-and-rescore when the fast path already failed, so
  // ordinary content (the common case) stays on the cheap single-call path.
  const core = stripRepeatedFillerAffixes(str);
  if (core.length === str.length || core.length < MIN_ENTROPY_LENGTH) return whole;

  const coreEntropy = shannonEntropy(core);
  return Math.max(whole, coreEntropy);
}

/**
 * Check if a string looks like a high-entropy secret.
 * Returns confidence score (0-1) or null if not suspicious.
 */
export function checkHighEntropy(str: string): { entropy: number; confidence: number } | null {
  if (str.length < MIN_ENTROPY_LENGTH) return null;

  const entropy = effectiveEntropy(str);
  if (entropy < ENTROPY_THRESHOLD) return null;

  // Confidence scales with entropy above threshold
  // 4.5 → 0.50, 5.0 → 0.65, 5.5 → 0.80, 6.0 → 0.95
  const confidence = Math.min(0.95, 0.50 + (entropy - ENTROPY_THRESHOLD) * 0.30);

  return { entropy, confidence };
}

/**
 * Extract candidate high-entropy tokens from content.
 * Looks for long contiguous alphanumeric+special strings
 * that could be secrets.
 *
 * EVERY OCCURRENCE IS RETURNED, including repeats of the same token.
 *
 * This used to de-duplicate on the token string, which quietly made redaction
 * incomplete: the caller derives its redaction ranges from these results, so
 * occurrences 2..N had no range and survived verbatim into "redacted" output.
 * `redactCredentials(S + ' ' + S + ' ' + S)` returned two raw copies of S. A
 * redaction primitive that reports success while leaking is worse than one that
 * fails loudly, and the pattern layer never had the bug — it was specific to
 * the entropy net, which exists for secrets whose shape we do not know.
 *
 * De-duplication is a REPORTING concern and now lives with the caller, which is
 * the only place that can tell a duplicate finding from a duplicate range.
 */
export function extractHighEntropyTokens(
  content: string,
): Array<{ token: string; position: number; entropy: number; confidence: number }> {
  // Match long strings of alphanumeric + common secret chars
  const tokenRegex = /[A-Za-z0-9\-_./+=]{20,}/g;
  const results: Array<{ token: string; position: number; entropy: number; confidence: number }> = [];

  let match: RegExpExecArray | null;
  while ((match = tokenRegex.exec(content)) !== null) {
    const token = match[0];

    // Skip common false positives
    if (isLikelyFalsePositive(token)) continue;

    const result = checkHighEntropy(token);
    if (result) {
      results.push({
        token,
        position: match.index,
        entropy: result.entropy,
        confidence: result.confidence,
      });
    }
  }

  return results;
}

/**
 * Allowlist of well-known PUBLIC identifier shapes that are NOT secrets and
 * must never be flagged as credentials — by ANY detector (pattern OR entropy).
 *
 * Conservative on purpose: only the exact canonical shapes below are excluded,
 * so real secrets (sk_live_..., random base64 tokens) still trip detection.
 * The token is matched on its own boundaries (anchored), so a SHA-shaped
 * substring of a longer secret is NOT what gets matched here — callers pass the
 * isolated token.
 */
export function isWellKnownNonSecret(token: string): boolean {
  const t = token.trim();

  // Canonical UUID (any version), e.g. 550e8400-e29b-41d4-a716-446655440000.
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(t)) return true;

  // Git commit SHA-1 (40 hex) and SHA-256 (64 hex) — public revision ids.
  if (/^[0-9a-f]{40}$/i.test(t)) return true;
  if (/^[0-9a-f]{64}$/i.test(t)) return true;

  // Abbreviated git SHA (7–12 hex, the `git rev-parse --short` range).
  if (/^[0-9a-f]{7,12}$/i.test(t)) return true;

  return false;
}

/**
 * Heuristic filter to reduce false positives from entropy detection.
 */
function isLikelyFalsePositive(token: string): boolean {
  if (isWellKnownNonSecret(token)) return true;
  // UUIDs — legitimate identifiers, not secrets
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(token)) return true;

  // Git commit SHAs (40-char hex)
  if (/^[0-9a-f]{40}$/i.test(token)) return true;

  // Docker image digests
  if (/^sha256.[0-9a-f]{64}$/i.test(token)) return true;

  // Semver versions (possibly with pre-release tags)
  if (/^\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?$/.test(token)) return true;

  // npm package specifiers (e.g., @types/node-18.11.18).
  //
  // Entropy-gated on purpose. The shape [a-z0-9._-] starting with a letter is
  // ALSO the shape of a large share of real key material — sk-proj-…,
  // sk-svcacct-…, dop_v1_…, hvs.…, github_pat_… — so an ungated rule here
  // silently switched the entropy net off for every one of them, which is how
  // an OpenAI project key stayed invisible in all contexts (VDP 2026-08-05).
  // A genuine package specifier is low-entropy; key material is not, so
  // entropy is the discriminator that keeps the rule's intent without the hole.
  //
  // Uses effectiveEntropy, not raw shannonEntropy: this shape (dash-separated,
  // no slashes) is exactly what 'aaaa-'.repeat(n) + <secret> tokenises to, so
  // a raw whole-token check here reopens the #257 padding bypass one gate
  // earlier than `checkHighEntropy` — the token never even reaches it.
  if (
    /^@?[a-z][a-z0-9._-]*(?:\/[a-z][a-z0-9._-]*)?$/i.test(token) &&
    effectiveEntropy(token) < ENTROPY_THRESHOLD
  )
    return true;

  // Pure lowercase with dashes — likely a slug or CSS class
  if (/^[a-z\-]+$/.test(token)) return true;

  // Looks like a file path
  if (token.includes('/') && !token.includes('//') && /\.[a-z]{2,4}$/i.test(token)) return true;

  // Repeated character sequences (aaaaaaa...)
  if (/^(.)\1{10,}$/.test(token)) return true;

  // Common base64 padding pattern (just padding)
  if (/^=+$/.test(token) || /^[A-Za-z0-9+/]*={3,}$/.test(token)) return true;

  // Long runs of a single character class with low variety
  const uniqueChars = new Set(token).size;
  if (uniqueChars < 6 && token.length > 20) return true;

  return false;
}
