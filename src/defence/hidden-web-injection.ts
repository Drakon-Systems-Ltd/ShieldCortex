/**
 * Hidden Web Injection — runtime Environment Firewall signal.
 *
 * The Environment Firewall's URL scanner (`src/environment`) only ran from the
 * manual `shieldcortex env scan` CLI. This composes its hidden-content detector
 * with the write-path instruction detector so the same protection runs
 * AUTOMATICALLY on web content the agent fetches (wired into the tool-response
 * scanner): a page that hides "ignore previous instructions" in white-on-white
 * text, a `display:none` span, or an HTML comment is caught before it becomes
 * trusted context.
 *
 * Precision over recall: hidden content alone is normal (analytics scripts,
 * aria-hidden decoration, cookie banners). The threat is hidden content that
 * carries INSTRUCTION phrasing — concealment + injection. Bidi-override and
 * zero-width characters are flagged on their own, since in fetched content they
 * are almost always adversarial (render-vs-parse deception).
 */

import { analyseHidden } from '../environment/hidden-detector.js';
import { detectInstructions } from './firewall/instruction-detector.js';

export interface HiddenWebInjectionResult {
  detected: boolean;
  /** Concealment techniques that carried injection (or are inherently hostile). */
  techniques: string[];
  /** Instruction-detector pattern names found in the hidden text. */
  patterns: string[];
  /** Clipped sample of the concealed injected text (for audit previews). */
  sample: string;
}

const CLEAN: HiddenWebInjectionResult = { detected: false, techniques: [], patterns: [], sample: '' };

// Concealment techniques whose hidden text we run through the instruction
// detector. `script_tag` is excluded (handled by the encoding/JS layers and far
// too noisy on its own); `meta_refresh` needs other corroboration.
const CONCEALMENT_TECHNIQUES = new Set([
  'display_none', 'visibility_hidden', 'zero_font_size',
  'offscreen_position', 'aria_hidden', 'same_colour_text', 'html_comment',
]);

// Techniques that are adversarial on their own in fetched content.
const INHERENTLY_HOSTILE = new Set(['bidi_override', 'zero_width_text']);

/** Cheap gate: only run on content that is plausibly HTML. */
export function looksLikeHtml(content: string): boolean {
  if (!content || content.length < 12) return false;
  if (!/<\w[\w-]*(\s[^>]*)?>/.test(content)) return false; // has an opening tag
  return /<\/\w[\w-]*>/.test(content) || /<!--/.test(content) || /style\s*=\s*["']/.test(content);
}

export function detectHiddenWebInjection(content: string): HiddenWebInjectionResult {
  if (!looksLikeHtml(content)) return CLEAN;

  const analysis = analyseHidden(content);
  if (analysis.hits.length === 0) return CLEAN;

  const techniques = new Set<string>();
  const patterns = new Set<string>();
  let sample = '';

  // 1) Concealment carrying instruction phrasing = the core trap.
  for (const hit of analysis.hits) {
    if (!CONCEALMENT_TECHNIQUES.has(hit.technique)) continue;
    if (!hit.sample) continue;
    const found = detectInstructions(hit.sample);
    if (found.detected) {
      techniques.add(hit.technique);
      for (const p of found.patterns) patterns.add(p);
      if (!sample) sample = hit.sample.slice(0, 160);
    }
  }

  // 2) Inherently-hostile concealment (bidi / zero-width) — flag on its own.
  for (const hit of analysis.hits) {
    if (INHERENTLY_HOSTILE.has(hit.technique)) {
      techniques.add(hit.technique);
      if (!sample) sample = hit.sample.slice(0, 160);
    }
  }

  if (techniques.size === 0) return CLEAN;
  return {
    detected: true,
    techniques: [...techniques],
    patterns: [...patterns],
    sample,
  };
}
