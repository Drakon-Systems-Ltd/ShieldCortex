/**
 * Encoding Detector
 *
 * Detects obfuscation attempts including base64, unicode tricks,
 * hex encoding, suspicious URL encoding, and invisible characters.
 */

import { hasConfusables } from './confusables.js';
import { detectInstructions } from './instruction-detector.js';

export interface EncodingDetectionResult {
  detected: boolean;
  encodingTypes: string[];
  decodedSnippets: string[];
}

// Base64: at least 20 chars of base64 alphabet, optionally padded
const BASE64_PATTERN = /(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g;

// Hex sequences
const HEX_PATTERN = /(?:0x[0-9a-fA-F]{2}\s*){4,}|(?:\\x[0-9a-fA-F]{2}){4,}|\b[0-9a-fA-F]{20,}\b/g;

// Suspicious URL encoding (4+ encoded chars in sequence)
const URL_ENCODING_PATTERN = /(?:%[0-9A-Fa-f]{2}){4,}/g;

// ROT13: the whole input is decoded (one linear pass) and handed to the
// instruction detector, which already walks every 50k window with overlap
// (scan-windows.ts). There is no run proposer, run cap or per-run slice, so
// there is no prefix an attacker can pad past (issue #506 review: a first-N
// cap and then a 64-run budget were both bypassed by ordinary filler).
// Non-ASCII is blanked before detection so non-Latin phrases (unchanged by
// ROT13) are not double-reported as encoded.
const ROT13_SNIPPET_SPLIT = /[.!?\n]+/;

// Zero-width characters.
// NOTE: presence check only (used with `.test()`), so NO `/g` flag \u2014 a stateful
// `/g` regex advances `lastIndex` across `.test()` calls and flip-flops between
// true/false for identical content, silently missing zero-width smuggling.
const ZERO_WIDTH_PATTERN = /[\u200B\u200C\u200D\uFEFF]/;

// RTL override \u2014 presence check only, NO `/g` (same stateful-test hazard).
const RTL_OVERRIDE_PATTERN = /\u202E/;

// ASCII Latin letters — used by the mixed-script homoglyph signal below.
const ASCII_LATIN = /[A-Za-z]/;

function tryBase64DecodeSingle(str: string): string | null {
  try {
    const decoded = Buffer.from(str, 'base64').toString('utf-8');
    // Check if decoded result looks like readable text (mostly printable ASCII)
    const printableRatio = decoded.replace(/[^\x20-\x7E]/g, '').length / decoded.length;
    if (printableRatio > 0.7 && decoded.length > 3) {
      return decoded.slice(0, 100);
    }
    return null;
  } catch {
    return null;
  }
}

function tryBase64Decode(str: string, maxDepth: number = 3): string | null {
  const decoded = tryBase64DecodeSingle(str);
  if (!decoded) return null;

  if (maxDepth > 1) {
    const innerMatch = decoded.match(BASE64_PATTERN);
    if (innerMatch) {
      const innerDecoded = tryBase64Decode(innerMatch[0], maxDepth - 1);
      if (innerDecoded) {
        return `${decoded} → ${innerDecoded}`;
      }
    }
  }

  return decoded;
}

function tryHexDecode(str: string): string | null {
  try {
    const hexChars = str.replace(/0x|\\x|\s/g, '');
    const bytes = hexChars.match(/.{2}/g);
    if (!bytes) return null;
    const decoded = bytes.map((b) => String.fromCharCode(parseInt(b, 16))).join('');
    const printableRatio = decoded.replace(/[^\x20-\x7E]/g, '').length / decoded.length;
    if (printableRatio > 0.7 && decoded.length > 3) {
      return decoded.slice(0, 100);
    }
    return null;
  } catch {
    return null;
  }
}

function tryUrlDecode(str: string): string | null {
  try {
    const decoded = decodeURIComponent(str);
    if (decoded !== str && decoded.length > 3) {
      return decoded.slice(0, 100);
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Decode the whole input as ROT13 and return a decoded snippet when it holds
 * an instruction the plain text does not. Linear in input size; detection is
 * windowed by detectInstructions itself, so a payload at any offset is seen.
 */
function findRot13Instruction(content: string): string | null {
  if (!/[A-Za-z]/.test(content)) return null;
  const decoded = rot13(content).replace(/[^\x00-\x7F]/g, ' ');
  const hit = detectInstructions(decoded);
  if (!hit.detected) return null;
  // Rare path from here: confirm the hit is new, then locate a snippet.
  const plain = new Set(detectInstructions(content).patterns);
  if (hit.patterns.every((p) => plain.has(p))) return null;
  for (const segment of decoded.split(ROT13_SNIPPET_SPLIT)) {
    if (segment.trim() && detectInstructions(segment).detected) {
      return segment.trim().slice(0, 200);
    }
  }
  // The instruction spans a sentence boundary; report the decoded opener.
  return decoded.trim().slice(0, 200);
}

/** ROT13 over letters only; everything else passes through unchanged. */
function rot13(str: string): string {
  return str.replace(/[A-Za-z]/g, (ch) => {
    const base = ch <= 'Z' ? 65 : 97;
    return String.fromCharCode(((ch.charCodeAt(0) - base + 13) % 26) + base);
  });
}

export function detectEncoding(content: string): EncodingDetectionResult {
  const encodingTypes: string[] = [];
  const decodedSnippets: string[] = [];

  // Base64
  const base64Matches = content.match(BASE64_PATTERN);
  if (base64Matches) {
    for (const match of base64Matches) {
      const decoded = tryBase64Decode(match);
      if (decoded) {
        encodingTypes.push('base64');
        decodedSnippets.push(decoded);
        break;
      }
    }
  }

  // Hex encoding
  const hexMatches = content.match(HEX_PATTERN);
  if (hexMatches) {
    for (const match of hexMatches) {
      const decoded = tryHexDecode(match);
      if (decoded) {
        encodingTypes.push('hex');
        decodedSnippets.push(decoded);
        break;
      }
    }
  }

  // URL encoding
  const urlMatches = content.match(URL_ENCODING_PATTERN);
  if (urlMatches) {
    for (const match of urlMatches) {
      const decoded = tryUrlDecode(match);
      if (decoded) {
        encodingTypes.push('url_encoding');
        decodedSnippets.push(decoded);
        break;
      }
    }
  }

  // ROT13 — only when the decoded text is itself an instruction, and only for
  // patterns the plain text does not already trip (so a plain-text attack is
  // not re-labelled as encoded).
  const rot13Snippet = findRot13Instruction(content);
  if (rot13Snippet) {
    encodingTypes.push('rot13');
    decodedSnippets.push(rot13Snippet);
  }

  // Zero-width characters
  if (ZERO_WIDTH_PATTERN.test(content)) {
    encodingTypes.push('zero_width_chars');
  }

  // RTL override
  if (RTL_OVERRIDE_PATTERN.test(content)) {
    encodingTypes.push('rtl_override');
  }

  // Unicode homoglyphs — mixed-script signal.
  //
  // The old rule ("≥2 Cyrillic confusables") missed a single substitution
  // (`ignorе` with one Cyrillic е reads as Latin and slipped through). The new
  // rule flags 'unicode_homoglyph' when BOTH are true:
  //   1. a curated cross-script confusable is present (hasConfusables — folding
  //      changed something beyond plain NFKC), AND
  //   2. the content also contains an ASCII Latin letter.
  // That combination means a Latin word has a foreign lookalike hidden in it.
  // A wholly-Cyrillic Russian sentence has NO ASCII Latin letters, so it does
  // NOT flag — genuine non-Latin text is left alone. Covers the Cyrillic AND
  // Greek glyphs in the confusables map (a single substitution is enough).
  if (hasConfusables(content) && ASCII_LATIN.test(content)) {
    encodingTypes.push('unicode_homoglyph');
  }

  return {
    detected: encodingTypes.length > 0,
    encodingTypes: [...new Set(encodingTypes)],
    decodedSnippets,
  };
}
