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

// How much decoded text we are willing to quote as evidence, and the window we
// search in when no single sentence carries the match. The step is half a
// window, so any match up to EVIDENCE_MAX_CHARS long lands whole inside one
// window rather than being cut by a boundary.
const EVIDENCE_MAX_CHARS = 200;
const EVIDENCE_WINDOW_CHARS = 2 * EVIDENCE_MAX_CHARS;

// Zero-width characters.
// NOTE: presence check only (used with `.test()`), so NO `/g` flag \u2014 a stateful
// `/g` regex advances `lastIndex` across `.test()` calls and flip-flops between
// true/false for identical content, silently missing zero-width smuggling.
const ZERO_WIDTH_PATTERN = /[\u200B\u200C\u200D\uFEFF]/;

// RTL override — presence check only, NO `/g` (same stateful-test hazard).
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

interface Rot13Finding {
  /**
   * Decoded excerpt that itself trips one of the novel groups, or null when no
   * excerpt short enough to quote does (see findNovelEvidence). Null means
   * "detected, no faithful quote available" — never "not detected".
   */
  evidence: string | null;
}

/**
 * Decode the whole input as ROT13 and report when it holds an instruction the
 * plain text does not. Linear in input size; detection is windowed by
 * detectInstructions itself, so a payload at any offset is seen.
 *
 * LIMITATION (issue #506 / #619 r3), deliberate for this round: novelty is a
 * per-group delta over the WHOLE input, so one plain-text match of a group
 * anywhere silences the encoded copy of that SAME group everywhere else. A
 * mixed plain+encoded input is therefore not always reported as encoded — the
 * plain instruction detector still fires on the plain half, so this is a
 * reporting gap, not a hole in the floor. The alternative (per-offset novelty)
 * re-labels ordinary plain-text attacks as encoded, which is why it is not done
 * here. Pinned by test in __tests__/issue-506-coverage.test.ts.
 */
function findRot13Instruction(content: string): Rot13Finding | null {
  if (!/[A-Za-z]/.test(content)) return null;
  const decoded = rot13(content).replace(/[^\x00-\x7F]/g, ' ');
  const hit = detectInstructions(decoded);
  if (!hit.detected) return null;
  // Rare path from here: confirm the hit is new, then locate evidence for it.
  const plain = new Set(detectInstructions(content).patterns);
  const novel = new Set(hit.patterns.filter((p) => !plain.has(p)));
  if (novel.size === 0) return null;
  return { evidence: findNovelEvidence(decoded, novel) };
}

/**
 * Find a short excerpt of the decoded text that trips one of the NOVEL groups.
 *
 * The excerpt is what downstream re-scans and what a human reads in the
 * verdict, so it has to be evidence of the group that made this "encoded" —
 * not merely of any instruction. Quoting the first decoded sentence that trips
 * ANY group hands back a sentence the plain detector already owns (issue #619
 * r3), and quoting the decoded opener when nothing matched hands back whatever
 * happened to be at offset 0. Both read as proof and are not.
 */
function findNovelEvidence(decoded: string, novel: Set<string>): string | null {
  const provesNovel = (text: string): boolean =>
    detectInstructions(text).patterns.some((p) => novel.has(p));

  // Pass 1 — a whole sentence short enough to quote intact. Best evidence, and
  // the length gate matters: a truncated long segment can drop the very match
  // it was selected for (a payload at the end of a 3kB punctuation-free run).
  for (const segment of decoded.split(ROT13_SNIPPET_SPLIT)) {
    const sentence = segment.trim();
    if (!sentence || sentence.length > EVIDENCE_MAX_CHARS) continue;
    if (provesNovel(sentence)) return sentence;
  }

  // Pass 2 — the match straddles a sentence boundary, or sits inside a run
  // with no sentence punctuation at all. Walk overlapping windows across the
  // WHOLE decoded text (no cutoff an attacker could pad past) and quote the
  // first one that still proves the group. Not trimmed: a leading newline run
  // can be part of the match (delimiter_attack), and trimming would delete the
  // proof from the quote.
  for (let start = 0; start < decoded.length; start += EVIDENCE_MAX_CHARS) {
    const window = decoded.slice(start, start + EVIDENCE_WINDOW_CHARS);
    if (provesNovel(window)) return window;
  }

  // Nothing quotable proves it — the match is longer than a window (e.g. a
  // delimiter_attack newline-run-to-keyword span). Say so by returning null:
  // the caller still reports the encoding, it just offers no excerpt. Downstream
  // re-scan of snippets therefore cannot escalate on this input; a fabricated
  // excerpt would be the worse trade.
  return null;
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
  const rot13Finding = findRot13Instruction(content);
  if (rot13Finding) {
    encodingTypes.push('rot13');
    // Evidence is optional: presence of the encoding does not depend on our
    // being able to quote a short excerpt that proves it.
    if (rot13Finding.evidence) decodedSnippets.push(rot13Finding.evidence);
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
