/**
 * Encoding Detector
 *
 * Detects obfuscation attempts including base64, unicode tricks,
 * hex encoding, suspicious URL encoding, and invisible characters.
 */

import { foldConfusables } from './confusables.js';

export interface EncodingDetectionResult {
  detected: boolean;
  encodingTypes: string[];
  /** Complete readable base64/hex/URL decoded blobs only, never prose windows. */
  decodedSnippets: string[];
  /** Whole normalized documents (raw or decoded), deduplicated and byte-bounded. */
  normalizedContents: string[];
  /** A budget prevented full coverage. Consumers must not silently allow it. */
  scanIncomplete: boolean;
}

export const ENCODING_SCAN_LIMITS = {
  maxInputBytes: 256 * 1024,
  maxCandidates: 64,
  maxCandidateBytes: 256 * 1024,
  maxDecodedBytes: 256 * 1024,
  maxNormalizedBytes: 256 * 1024,
  maxDepth: 3,
} as const;

// Base64: at least 20 chars of base64 alphabet, optionally padded
const BASE64_PATTERN = /[A-Za-z0-9+/]{20,}={0,2}/g;

// Hex sequences
const HEX_PATTERN = /(?:0x[0-9a-fA-F]{2}\s*){4,}|(?:\\x[0-9a-fA-F]{2}){4,}|\b[0-9a-fA-F]{20,}\b/g;

// Suspicious URL encoding (4+ encoded chars in sequence)
const URL_ENCODING_PATTERN = /(?:%[0-9A-Fa-f]{2}){4,}/g;

// Match the sanitiser's smuggling characters, not emoji presentation selectors
// U+FE0E/U+FE0F. Joiners remain detectable even though benign emoji also use them.
// NOTE: presence check only (used with `.test()`), so NO `/g` flag \u2014 a stateful
// `/g` regex advances `lastIndex` across `.test()` calls and flip-flops between
// true/false for identical content, silently missing zero-width smuggling.
const ZERO_WIDTH_PATTERN = /[\u200B\u200C\u200D\uFEFF\u2060\u180E]/;
const ZERO_WIDTH_GLOBAL_PATTERN = new RegExp(ZERO_WIDTH_PATTERN.source, 'g');

/** The same whole-document transform for discovery and raw-redaction rescans. */
export function normalizeEncodingContent(content: string): string {
  return foldConfusables(content).replace(ZERO_WIDTH_GLOBAL_PATTERN, '');
}

// RTL override \u2014 presence check only, NO `/g` (same stateful-test hazard).
const RTL_OVERRIDE_PATTERN = /\u202E/;

// ASCII Latin letters — used by the mixed-script homoglyph signal below.
const ASCII_LATIN = /[A-Za-z]/;

function tryBase64Decode(str: string): string | null {
  try {
    const decoded = Buffer.from(str, 'base64').toString('utf-8');
    // Check if decoded result looks like readable text (mostly printable ASCII)
    const printableRatio = decoded.replace(/[^\x20-\x7E]/g, '').length / decoded.length;
    if (printableRatio > 0.7 && decoded.length > 3) {
      return decoded;
    }
    return null;
  } catch {
    return null;
  }
}

function tryHexDecode(str: string): string | null {
  try {
    const hexChars = str.replace(/0x|\\x|\s/g, '');
    if (hexChars.length % 2 !== 0) return null;
    const decoded = Buffer.from(hexChars, 'hex').toString('utf-8');
    const printableRatio = decoded.replace(/[^\x20-\x7E]/g, '').length / decoded.length;
    if (printableRatio > 0.7 && decoded.length > 3) {
      return decoded;
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
      return decoded;
    }
    return null;
  } catch {
    return null;
  }
}

export function detectEncoding(content: string): EncodingDetectionResult {
  const encodingTypes: string[] = [];
  const decodedSnippets: string[] = [];
  const normalizedContents: string[] = [];
  const decodedSeen = new Set<string>();
  const normalizedSeen = new Set<string>();
  let scanIncomplete = false;
  let candidates = 0;
  let candidateBytes = 0;
  let decodedBytes = 0;
  let normalizedBytes = 0;
  let decodingExhausted = false;

  // Reject oversized surfaces as incomplete, not as a clean prefix. No sliced
  // normalization: quote parity and credential/destination conjunctions belong
  // to the entire document. Character checks avoid encoding an oversized string.
  const fitsInput = content.length <= ENCODING_SCAN_LIMITS.maxInputBytes &&
    Buffer.byteLength(content) <= ENCODING_SCAN_LIMITS.maxInputBytes;
  const queue = fitsInput ? [{ text: content, depth: 0 }] : [];
  if (!fitsInput) scanIncomplete = true;

  const decoders = [
    { type: 'base64', pattern: BASE64_PATTERN, decode: tryBase64Decode },
    { type: 'hex', pattern: HEX_PATTERN, decode: tryHexDecode },
    { type: 'url_encoding', pattern: URL_ENCODING_PATTERN, decode: tryUrlDecode },
  ];

  // Breadth-first discovery retains each full decoded blob, including all
  // siblings and intermediate layers. Only readable decodes spend candidate
  // count/bytes: hashes are not payloads. Failed attempts are still bounded by
  // the input + decoded + normalized surface byte limits and fixed decoders.
  for (let index = 0; index < queue.length; index++) {
    const { text, depth } = queue[index];
    const zeroWidth = ZERO_WIDTH_PATTERN.test(text);
    if (zeroWidth) encodingTypes.push('zero_width_chars');
    if (RTL_OVERRIDE_PATTERN.test(text)) encodingTypes.push('rtl_override');
    const folded = foldConfusables(text);
    const homoglyph = folded !== text.normalize('NFKC') && ASCII_LATIN.test(text);
    if (homoglyph) encodingTypes.push('unicode_homoglyph');

    const surfaces = [text];
    if (homoglyph || zeroWidth) {
      const normalized = folded.replace(ZERO_WIDTH_GLOBAL_PATTERN, '');
      const bytes = Buffer.byteLength(normalized);
      if (!normalizedSeen.has(normalized)) {
        if (normalizedBytes + bytes > ENCODING_SCAN_LIMITS.maxNormalizedBytes) {
          scanIncomplete = true;
        } else {
          normalizedBytes += bytes;
          normalizedSeen.add(normalized);
          normalizedContents.push(normalized);
          if (normalized !== text) surfaces.push(normalized);
        }
      }
    }

    if (decodingExhausted) continue;
    discovery: for (const surface of surfaces) {
      for (const { type, pattern, decode } of decoders) {
        for (const match of surface.matchAll(pattern)) {
          const decoded = decode(match[0]);
          if (!decoded) continue;
          const bytes = Buffer.byteLength(match[0]);
          if (depth >= ENCODING_SCAN_LIMITS.maxDepth ||
              candidates >= ENCODING_SCAN_LIMITS.maxCandidates ||
              candidateBytes + bytes > ENCODING_SCAN_LIMITS.maxCandidateBytes) {
            scanIncomplete = true;
            // A depth limit applies to this branch only; keep scanning siblings.
            if (depth >= ENCODING_SCAN_LIMITS.maxDepth) continue;
            decodingExhausted = true;
            break discovery;
          }
          candidates++;
          candidateBytes += bytes;
          encodingTypes.push(type);
          if (decodedSeen.has(decoded)) continue;
          const outputBytes = Buffer.byteLength(decoded);
          if (decodedBytes + outputBytes > ENCODING_SCAN_LIMITS.maxDecodedBytes) {
            scanIncomplete = true;
            decodingExhausted = true;
            break discovery;
          }
          decodedBytes += outputBytes;
          decodedSeen.add(decoded);
          decodedSnippets.push(decoded);
          queue.push({ text: decoded, depth: depth + 1 });
        }
      }
    }
  }

  if (scanIncomplete) encodingTypes.push('encoding_scan_incomplete');

  return {
    detected: encodingTypes.length > 0,
    encodingTypes: [...new Set(encodingTypes)],
    decodedSnippets,
    normalizedContents,
    scanIncomplete,
  };
}
