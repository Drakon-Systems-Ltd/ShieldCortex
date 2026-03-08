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

/**
 * Check if a string looks like a high-entropy secret.
 * Returns confidence score (0-1) or null if not suspicious.
 */
export function checkHighEntropy(str: string): { entropy: number; confidence: number } | null {
  if (str.length < MIN_ENTROPY_LENGTH) return null;

  const entropy = shannonEntropy(str);
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
 */
export function extractHighEntropyTokens(
  content: string,
): Array<{ token: string; position: number; entropy: number; confidence: number }> {
  // Match long strings of alphanumeric + common secret chars
  const tokenRegex = /[A-Za-z0-9\-_./+=]{20,}/g;
  const results: Array<{ token: string; position: number; entropy: number; confidence: number }> = [];
  const seen = new Set<string>();

  let match: RegExpExecArray | null;
  while ((match = tokenRegex.exec(content)) !== null) {
    const token = match[0];
    if (seen.has(token)) continue;
    seen.add(token);

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
 * Heuristic filter to reduce false positives from entropy detection.
 */
function isLikelyFalsePositive(token: string): boolean {
  // UUIDs — legitimate identifiers, not secrets
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(token)) return true;

  // Git commit SHAs (40-char hex)
  if (/^[0-9a-f]{40}$/i.test(token)) return true;

  // Docker image digests
  if (/^sha256.[0-9a-f]{64}$/i.test(token)) return true;

  // Semver versions (possibly with pre-release tags)
  if (/^\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?$/.test(token)) return true;

  // npm package specifiers (e.g., @types/node-18.11.18)
  if (/^@?[a-z][a-z0-9._-]*(?:\/[a-z][a-z0-9._-]*)?$/i.test(token)) return true;

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
