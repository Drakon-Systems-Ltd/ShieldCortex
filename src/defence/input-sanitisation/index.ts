/**
 * Input Sanitisation — Layer 1
 *
 * First line of defence: strips dangerous control characters, null bytes,
 * zero-width characters, BOM markers, and other byte-level threats before
 * any pattern matching or analysis runs.
 *
 * Returns sanitised content + a list of what was stripped.
 */

import type { ThreatIndicator } from '../types.js';

export interface SanitisationResult {
  /** Content with dangerous characters removed */
  sanitised: string;
  /** Whether any sanitisation was applied */
  modified: boolean;
  /** What was stripped */
  strippedCategories: SanitisationCategory[];
  /** Threat indicators to add to pipeline */
  threatIndicators: ThreatIndicator[];
}

export type SanitisationCategory =
  | 'null_byte'
  | 'control_char'
  | 'zero_width'
  | 'bom'
  | 'bidi_override'
  | 'homoglyph_separator';

// ── Patterns ──

/** Null bytes — used to truncate strings in C-based parsers */
const NULL_BYTES = /\0/g;

/** ASCII control characters (0x00-0x1F, 0x7F) except tab, newline, carriage return */
const CONTROL_CHARS = /[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g;

/** Zero-width characters — invisible text that can hide payloads */
const ZERO_WIDTH = /[\u200B\u200C\u200D\uFEFF\u2060\u180E]/g;

/** BOM (Byte Order Mark) — can confuse parsers */
const BOM = /^\uFEFF/;

/** Bidirectional override characters — can visually reorder text to disguise content */
const BIDI_OVERRIDES = /[\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;

/** Unusual Unicode separators that can break tokenisation */
const HOMOGLYPH_SEPARATORS = /[\u2028\u2029\u00A0\u1680\u2000-\u200A\u205F\u3000]/g;

/**
 * Sanitise input content by stripping dangerous byte-level patterns.
 *
 * Designed to be fast and non-blocking — runs before all other layers.
 */
export function sanitiseInput(content: string): SanitisationResult {
  let sanitised = content;
  const strippedCategories: SanitisationCategory[] = [];

  // 0. Unicode NFKC normalisation — collapse combining characters to canonical forms
  sanitised = sanitised.normalize('NFKC');

  // 1. Null bytes
  if (NULL_BYTES.test(sanitised)) {
    strippedCategories.push('null_byte');
    sanitised = sanitised.replace(NULL_BYTES, '');
  }

  // 2. Control characters (keep \t \n \r)
  if (CONTROL_CHARS.test(sanitised)) {
    strippedCategories.push('control_char');
    sanitised = sanitised.replace(CONTROL_CHARS, '');
  }

  // 3. BOM
  if (BOM.test(sanitised)) {
    strippedCategories.push('bom');
    sanitised = sanitised.replace(BOM, '');
  }

  // 4. Zero-width characters
  if (ZERO_WIDTH.test(sanitised)) {
    strippedCategories.push('zero_width');
    sanitised = sanitised.replace(ZERO_WIDTH, '');
  }

  // 5. Bidi overrides
  if (BIDI_OVERRIDES.test(sanitised)) {
    strippedCategories.push('bidi_override');
    sanitised = sanitised.replace(BIDI_OVERRIDES, '');
  }

  // 6. Homoglyph separators → replace with regular space (don't strip entirely)
  if (HOMOGLYPH_SEPARATORS.test(sanitised)) {
    strippedCategories.push('homoglyph_separator');
    sanitised = sanitised.replace(HOMOGLYPH_SEPARATORS, ' ');
  }

  const modified = strippedCategories.length > 0;
  const threatIndicators: ThreatIndicator[] = [];

  if (strippedCategories.includes('null_byte')) {
    threatIndicators.push('encoding_obfuscation');
  }
  if (strippedCategories.includes('zero_width') || strippedCategories.includes('bidi_override')) {
    threatIndicators.push('encoding_obfuscation');
  }

  return { sanitised, modified, strippedCategories, threatIndicators };
}
