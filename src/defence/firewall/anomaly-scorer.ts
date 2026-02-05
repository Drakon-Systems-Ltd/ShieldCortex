/**
 * Anomaly Scorer
 *
 * Scores how anomalous content is compared to normal memory patterns.
 * Returns 0 (normal) to 1 (very anomalous).
 */

const URL_PATTERN = /https?:\/\/[^\s"'<>]+/gi;
const SPECIAL_CHAR_PATTERN = /[^a-zA-Z0-9\s.,!?;:'"()\-]/g;
const ALL_CAPS_SECTION = /\b[A-Z]{5,}\b/g;
const EXCESSIVE_PUNCTUATION = /[!?]{3,}/g;
const CODE_INDICATORS = /[{}()\[\];=<>|&$`\\]/g;
// Base64-like pattern: runs of alphanumeric + padding chars
const BASE64_PATTERN = /(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g;

/**
 * Calculate Shannon entropy of a string (bits per character)
 * Higher entropy indicates more random/encoded content
 */
function calculateEntropy(str: string): number {
  if (str.length === 0) return 0;
  const freq: Record<string, number> = {};
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }
  const len = str.length;
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function scoreAnomaly(content: string, title: string): number {
  const signals: number[] = [];

  // Very long content
  if (content.length > 5000) {
    signals.push(Math.min((content.length - 5000) / 10000, 1.0) * 0.3);
  }

  // Special character ratio
  const specialChars = (content.match(SPECIAL_CHAR_PATTERN) || []).length;
  const specialRatio = specialChars / Math.max(content.length, 1);
  if (specialRatio > 0.15) {
    signals.push(Math.min((specialRatio - 0.15) / 0.35, 1.0) * 0.25);
  }

  // Many URLs
  const urls = content.match(URL_PATTERN) || [];
  if (urls.length > 3) {
    signals.push(Math.min((urls.length - 3) / 7, 1.0) * 0.2);
  }

  // Mixed natural language with code/commands
  const words = content.split(/\s+/).length;
  const codeChars = (content.match(CODE_INDICATORS) || []).length;
  const codeRatio = codeChars / Math.max(content.length, 1);
  const hasNaturalLanguage = words > 10;
  if (hasNaturalLanguage && codeRatio > 0.05) {
    signals.push(Math.min(codeRatio / 0.15, 1.0) * 0.2);
  }

  // ALL CAPS sections
  const capsMatches = content.match(ALL_CAPS_SECTION) || [];
  if (capsMatches.length > 2) {
    signals.push(Math.min(capsMatches.length / 10, 1.0) * 0.15);
  }

  // Excessive punctuation
  const punctMatches = content.match(EXCESSIVE_PUNCTUATION) || [];
  if (punctMatches.length > 0) {
    signals.push(Math.min(punctMatches.length / 5, 1.0) * 0.15);
  }

  // Title anomalies — very long or very short titles
  if (title.length > 200) {
    signals.push(0.1);
  } else if (title.length === 0) {
    signals.push(0.05);
  }

  // High ratio of base64-looking content (may hide encoded payloads)
  const base64Matches = content.match(BASE64_PATTERN) || [];
  const base64Length = base64Matches.reduce((sum, m) => sum + m.length, 0);
  const base64Ratio = base64Length / Math.max(content.length, 1);
  if (base64Ratio > 0.3) {
    signals.push(Math.min(base64Ratio, 1.0) * 0.3);
  }

  // High entropy indicates encoded/encrypted content
  const entropy = calculateEntropy(content);
  // Normal English text has entropy ~4.0-4.5, random/encoded ~5.5+
  if (entropy > 5.0 && content.length > 100) {
    signals.push(Math.min((entropy - 5.0) / 2, 1.0) * 0.25);
  }

  // Sum all signals, cap at 1.0
  const score = Math.min(signals.reduce((a, b) => a + b, 0), 1.0);
  return Math.round(score * 100) / 100;
}
