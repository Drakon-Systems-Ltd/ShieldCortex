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

/** A unit must repeat at least this many times back-to-back to count as filler, not coincidence. */
const FILLER_MIN_REPEATS = 3;

/**
 * Length of the longest prefix of `s` that is a repeated unit — of ANY
 * length, occurring >= FILLER_MIN_REPEATS times back-to-back. There is
 * deliberately no cap on the unit's length: an earlier version bounded it at
 * 8 chars, which just moved the attacker's cost of evading detection from
 * "find a low-entropy filler" to "pick a 9-char filler unit" — a one-keystroke
 * bypass (#257 follow-up review).
 *
 * Uses the KMP failure/prefix function to find, in one O(n) pass over the
 * whole string, the fundamental period of every prefix — the same
 * "longest coverage wins" result the old per-unit-length loop computed, but
 * without trying each unit length by hand. That matters here specifically:
 * removing the cap without changing the algorithm would have made the loop
 * O(n) unit lengths deep instead of a fixed 8, turning this into O(n^2) on a
 * string an attacker fully controls the length of — an algorithmic-complexity
 * hole on the redaction hot path, exactly the kind of cost trap that made
 * bounding it tempting the first time.
 */
function repeatedFillerPrefixLength(s: string): number {
  const n = s.length;
  if (n < FILLER_MIN_REPEATS) return 0;

  const pi = new Array<number>(n).fill(0);
  let bestCoverage = 0;
  for (let i = 1; i < n; i++) {
    let k = pi[i - 1];
    while (k > 0 && s[i] !== s[k]) k = pi[k - 1];
    if (s[i] === s[k]) k++;
    pi[i] = k;

    const len = i + 1;
    const period = len - k;
    if (period > 0 && period < len && len % period === 0 && len / period >= FILLER_MIN_REPEATS) {
      bestCoverage = len;
    }
  }
  return bestCoverage;
}

/**
 * Strip a repeated-unit low-entropy run from the START of a string.
 */
function stripLeadingFiller(s: string): string {
  const coverage = repeatedFillerPrefixLength(s);
  return coverage === 0 ? s : s.slice(coverage);
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
 * limitation of the entropy net, not fixed here). Repeated filler placed
 * INSIDE a token (`<half1><filler…><half2>`) is likewise NOT covered — only
 * start/end affixes are stripped, so interior filler that drags whole-token
 * entropy under threshold still evades; fixing it means the sliding-window
 * FP/cost trade-off rejected below, so it is a named limitation, not an
 * oversight. Within the affix scope there is
 * no cap on the unit's length — see `repeatedFillerPrefixLength` — so this is
 * not "narrow" in the sense of being evadable by picking a longer unit.
 * A sliding fixed-size window
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

  // #205: well-known empty-content digests. The empty-file MD5 is exactly
  // 32 hex, so Azure's bounded 32-hex rule would still fire without this.
  // Only the canonical empty digests — not arbitrary 32-hex.
  if (/^d41d8cd98f00b204e9800998ecf8427e$/i.test(t)) return true; // MD5("")
  if (/^e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855$/i.test(t)) return true; // SHA-256("")

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

  // Common base64 padding pattern (just padding). Same over-greedy-wildcard
  // hazard as the npm-specifier rule above: `[A-Za-z0-9+/]*` happily eats an
  // entire high-entropy secret and `={3,}` its appended padding, classifying
  // `SECRET===` as "just padding" one gate before the entropy check runs.
  // Valid base64 never carries ≥3 trailing `=`, so gating on the stripped
  // core's entropy cannot reclassify genuine base64 — it only stops the
  // one-keystroke `===` evasion of the very bypass #257 is about.
  if (/^=+$/.test(token)) return true;
  if (
    /^[A-Za-z0-9+/]*={3,}$/.test(token) &&
    effectiveEntropy(token.replace(/=+$/, '')) < ENTROPY_THRESHOLD
  )
    return true;

  // Long runs of a single character class with low variety
  const uniqueChars = new Set(token).size;
  if (uniqueChars < 6 && token.length > 20) return true;

  return false;
}
