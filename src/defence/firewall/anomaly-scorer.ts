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

  // Sum all signals, cap at 1.0
  const score = Math.min(signals.reduce((a, b) => a + b, 0), 1.0);
  return Math.round(score * 100) / 100;
}
