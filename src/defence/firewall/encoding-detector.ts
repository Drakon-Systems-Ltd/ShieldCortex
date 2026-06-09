/**
 * Encoding Detector
 *
 * Detects obfuscation attempts including base64, unicode tricks,
 * hex encoding, suspicious URL encoding, and invisible characters.
 */

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

// Zero-width characters.
// NOTE: presence check only (used with `.test()`), so NO `/g` flag \u2014 a stateful
// `/g` regex advances `lastIndex` across `.test()` calls and flip-flops between
// true/false for identical content, silently missing zero-width smuggling.
const ZERO_WIDTH_PATTERN = /[\u200B\u200C\u200D\uFEFF]/;

// RTL override \u2014 presence check only, NO `/g` (same stateful-test hazard).
const RTL_OVERRIDE_PATTERN = /\u202E/;

// Unicode homoglyphs — Cyrillic characters that look like Latin
const CYRILLIC_HOMOGLYPHS = /[\u0430\u0435\u043E\u0440\u0441\u0443\u0445\u0410\u0412\u0415\u041A\u041C\u041D\u041E\u0420\u0421\u0422\u0423\u0425]/g;

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

  // Zero-width characters
  if (ZERO_WIDTH_PATTERN.test(content)) {
    encodingTypes.push('zero_width_chars');
  }

  // RTL override
  if (RTL_OVERRIDE_PATTERN.test(content)) {
    encodingTypes.push('rtl_override');
  }

  // Unicode homoglyphs
  const homoglyphMatches = content.match(CYRILLIC_HOMOGLYPHS);
  if (homoglyphMatches && homoglyphMatches.length >= 2) {
    encodingTypes.push('unicode_homoglyph');
  }

  return {
    detected: encodingTypes.length > 0,
    encodingTypes: [...new Set(encodingTypes)],
    decodedSnippets,
  };
}
