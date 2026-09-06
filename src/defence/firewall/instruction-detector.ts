/**
 * Instruction Detector
 *
 * Detects prompt injection and hidden instruction patterns in memory content.
 *
 * SCOPE — read this before adding patterns (issue #204).
 * This is a FAST PRE-FILTER FLOOR, not a detector of intent. It catches the
 * literal and lightly-obfuscated shapes of known injection phrasing: attack
 * markers, a closed set of override frames (see instruction-morphology.ts), and
 * the same text after a normalisation fold (see instruction-normalize.ts). It
 * runs on the synchronous write path, so it must stay bounded and cheap.
 *
 * What it does NOT do, and must not be described as doing:
 *   - non-English injection. Nothing here is multilingual.
 *   - paraphrase. Reworded intent ("set aside what you were told before") is
 *     the async semantic layer's job — an additive backstop, never a hot-path
 *     dependency (src/defence/semantic/).
 *   - completeness. A synonym this file has not seen will pass. That is the
 *     expected failure mode of a regex tier, which is why the layers above it
 *     (trust scoring, quarantine, semantic) do not assume it is exhaustive.
 */

import { forEachWindow, SCAN_WINDOW_OVERLAP, someWindow } from '../scan-windows.js';
import { instructionMatchVariantSets } from './instruction-normalize.js';
import {
  AUTHORITY_GRANT_PATTERNS,
  CONTEXT_SENSITIVE_PATTERNS,
  OVERRIDE_MORPHOLOGY_PATTERNS,
  PROMPT_EXTRACTION_PATTERNS,
  PUNCTUATION_SENSITIVE_PATTERNS,
} from './instruction-morphology.js';

export interface InstructionDetectionResult {
  detected: boolean;
  patterns: string[];
  confidence: number;
}

interface PatternGroup {
  name: string;
  patterns: RegExp[];
  weight: number;
  /**
   * Name of a group this one merely extends. If that group already matched, this
   * one is skipped entirely — a single phrase must not count as two independent
   * signals and collect the multi-group confidence bonus.
   */
  subsumedBy?: string;
}

const PATTERN_GROUPS: PatternGroup[] = [
  {
    name: 'system_prompt_marker',
    weight: 0.9,
    patterns: [
      /\[SYSTEM:/i,
      /<<SYS>>/i,
      /\[INST\]/i,
      /<\/s>/i,
      /<\|im_start\|>/i,
      /<\|system\|>/i,
      /<\|endoftext\|>/i,
      // Fake system prompt prefixes
      /^SYSTEM\s*:/im,
      /^ASSISTANT\s*:/im,
      /^USER\s*:/im,
      /^\[system\]/im,
      /^<system>/im,
      /<\/system>/i,
      /##SYSTEM##/i,
      /\{SYSTEM\}/i,
      /<brain>/i,
      /<\/brain>/i,
    ],
  },
  {
    name: 'hidden_instruction',
    weight: 0.8,
    patterns: [
      /ignore\s+(all\s+)?previous\s+(instructions?|prompts?|context)/i,
      /forget\s+everything/i,
      /new\s+instructions?\s*:/i,
      /you\s+are\s+now\b/i,
      /act\s+as\s+(a\s+|an\s+)?/i,
      /pretend\s+to\s+be/i,
      /disregard\s+(all\s+)?(previous|above|prior)/i,
      /override\s+(previous|all|system)/i,
      /summari[sz]e\s+your\s+system\s+prompt/i,
      /repeat\s+your\s+instructions/i,
      /what\s+are\s+your\s+rules/i,
    ],
  },
  {
    // Generated override frames — the inflected/passive/negated-compliance
    // shapes the hand-written list above only ever caught in the base active
    // voice (issue #204). Same weight as `hidden_instruction` because it is the
    // same signal reached by a different surface form, and `subsumedBy` stops a
    // phrase that matches both from scoring as two groups.
    name: 'hidden_instruction_morphology',
    weight: 0.8,
    subsumedBy: 'hidden_instruction',
    patterns: OVERRIDE_MORPHOLOGY_PATTERNS,
  },
  {
    name: 'memory_manipulation',
    weight: 0.7,
    patterns: [
      /save\s+(this\s+)?to\s+memory/i,
      /remember\s+this\s+(instruction|command|rule)/i,
      /store\s+this\s+instruction/i,
      /when\s+(the\s+)?user\s+asks/i,
      /always\s+respond\s+with/i,
      /from\s+now\s+on\s*(,\s*)?always/i,
      /inject\s+(into\s+)?memory/i,
    ],
  },
  {
    // Natural-language directives to run code/commands. This is the NL
    // instruction detector — bare CODE tokens (`import os`, `subprocess`,
    // `sqlite3`, `conn.execute(...)`) are legitimate in skill/tool files and
    // MUST NOT trip this (Athena checkpoint FP, audit ids 475/476). Actual
    // malicious code in code files is caught by detectCodeThreats() instead.
    // We keep the strongly injection-shaped calls (eval/exec/system/__import__
    // with a call paren) and the imperative English forms.
    name: 'command_injection',
    weight: 0.85,
    patterns: [
      /\beval\s*\(/i,
      /\bexec\s*\(/i,
      /\bsystem\s*\(/i,
      /\brun\s+command\b/i,
      /\bexecute\s+(this\s+)?(command|code|script)/i,
      /\b__import__\s*\(/i,
      /\bos\.system\s*\(/i,
      /\bsubprocess\.(?:run|call|popen|check_output|check_call)\s*\(\s*['"`]?(?:sh|bash|zsh|-c|curl|wget|nc|rm|eval|sudo)\b/i,
    ],
  },
  {
    name: 'delimiter_attack',
    weight: 0.75,
    patterns: [
      // Length-capped to prevent ReDOS (max 500 chars between newlines and keyword)
      /\n{5,}[\s\S]{0,500}\b(instruction|command|system|ignore)\b/i,
      // HTML comment with length cap to prevent backtracking
      /<!--[\s\S]{0,200}?(instruction|command|system|ignore|inject|override)[\s\S]{0,200}?-->/i,
      /\r?\n-{5,}\r?\n/,
      /\r?\n={5,}\r?\n/,
      // YAML/markdown frontmatter injection (already safe with .*?)
      /^---\s*\n[\s\S]{0,1000}?\brole\s*:\s*(system|admin|root)/im,
      /<\/?(system|admin|root)\s*>/i,
    ],
  },
  {
    name: 'social_engineering',
    weight: 0.7,
    patterns: [
      // Authority claims
      /\b(as|i\s+am)\s+(the\s+)?(system\s+)?admin(istrator)?\b/i,
      /\bi\s+am\s+(a\s+)?(root|superuser|admin|moderator|developer)\b/i,
      /\bauthori[sz]ed\s+(to|by|user|admin)/i,
      /\bsecurity\s+override\b/i,
      /\boverrid(e|ing)\s+(the\s+)?security\s+polic/i,
      // Urgency manipulation
      /\burgent\s*:.*\b(disable|remove|bypass|turn\s+off)\b/i,
      /\bemergency\s*:.*\b(disable|remove|bypass|turn\s+off)\b/i,
      /\b(disable|remove|bypass|turn\s+off)\s+(all\s+)?(filter|security|protection|safet)/i,
      // Delegated authority — "the developer authorised you to skip the check".
      // Shared with the Iron Dome scanner so a claimed permission grant is the
      // same signal on both tiers (see instruction-morphology.ts).
      ...AUTHORITY_GRANT_PATTERNS,
    ],
  },
  {
    name: 'prompt_extraction',
    weight: 0.75,
    patterns: [
      /output\s+your\s+prompt/i,
      /show\s+me\s+your\s+instructions/i,
      /what\s+were\s+you\s+told/i,
      /display\s+your\s+(system\s+)?prompt/i,
      /reveal\s+your\s+instructions/i,
      // Narrow print/show/reveal/display + your + (system) prompt, shared with
      // the Iron Dome scanner so both tiers agree on this frame (issue #204).
      ...PROMPT_EXTRACTION_PATTERNS,
    ],
  },
  {
    // Imperative tool-call directives. These show up in transcripts as
    // injected prompts disguised as user instructions ("call the X tool
    // to complete this request. Call this tool now."). The session-end
    // chunker historically captured them as user preferences with
    // salience 1.0; the firewall now flags them at write time so they
    // route to quarantine instead of memories.
    name: 'imperative_tool_call',
    weight: 0.8,
    patterns: [
      /\b(?:call|invoke|use)\s+(?:the\s+)?[A-Za-z][\w-]*\s+tool\b/i,
      /\b(?:call|invoke|use)\s+this\s+tool\s+now\b/i,
      /\bcomplete\s+this\s+request\.\s*(?:call|invoke|use)\s+this\s+tool\b/i,
    ],
  },
  {
    // Defence canary — synthetic probe used by `shieldcortex doctor` to verify
    // the firewall is actually catching things. Marker is intentionally
    // non-natural so it cannot collide with legitimate content. See
    // src/defence/iron-dome/injection-scanner.ts for the parallel registration.
    name: 'defence_canary',
    weight: 1.0,
    patterns: [
      /__SHIELDCORTEX_CANARY_PROBE_v1__/,
    ],
  },
];

/**
 * Safely test a regex against content.
 *
 * Scans the WHOLE input as overlapping windows (<= SCAN_WINDOW_SIZE chars each)
 * rather than truncating to the first 50KB. Each window keeps the per-regex work
 * bounded (preserving the ReDoS guarantee the old truncation gave us) while the
 * overlap means a payload buried past 50KB of filler is still tested — closing
 * the >50KB padding bypass.
 */
function safeRegexTest(pattern: RegExp, text: string, preserveContext: boolean): boolean {
  if (!preserveContext) return someWindow(text, (window) => pattern.test(window));

  // Contextual frames must not see an artificial ^ or word boundary where a
  // slice dropped a subject/negation. Search from inside the overlap, retaining
  // its left context. Reserve half the overlap as RIGHT context too: starts in
  // that margin belong to the next window. These frames (including a bounded
  // heading) span less than half the overlap, so every owned match has its end
  // and following character present. Never let a truncated word manufacture \b.
  // Clone rather than mutating a shared pattern's lastIndex, even if global.
  const search = new RegExp(pattern.source, pattern.global ? pattern.flags : `${pattern.flags}g`);
  return forEachWindow(text, (window, start) => {
    search.lastIndex = start === 0 ? 0 : SCAN_WINDOW_OVERLAP / 2;
    const match = search.exec(window);
    if (!match) return false;
    return start + window.length === text.length
      || (match.index < window.length - SCAN_WINDOW_OVERLAP / 2 && search.lastIndex < window.length);
  });
}

export function detectInstructions(content: string): InstructionDetectionResult {
  const matchedPatterns: string[] = [];
  let totalWeight = 0;
  let maxWeight = 0;

  // Test the original first, then up to two normalised copies (confusable fold,
  // zero-width/bidi strip, rule-specific punctuation/line policy, classic leet) — see
  // instruction-normalize.ts. The original always leads, so normalisation can
  // only ever *add* a match, never lose one the raw text would have caught.
  const { variants, lineVariants, contextualVariants } = instructionMatchVariantSets(content);

  for (const group of PATTERN_GROUPS) {
    if (group.subsumedBy && matchedPatterns.includes(group.subsumedBy)) continue;
    for (const pattern of group.patterns) {
      const preserveContext = CONTEXT_SENSITIVE_PATTERNS.has(pattern);
      const targets = PUNCTUATION_SENSITIVE_PATTERNS.has(pattern)
        ? contextualVariants
        : preserveContext ? lineVariants : variants;
      if (targets.some((variant) => safeRegexTest(pattern, variant, preserveContext))) {
        matchedPatterns.push(group.name);
        totalWeight += group.weight;
        if (group.weight > maxWeight) {
          maxWeight = group.weight;
        }
        break; // one match per group is enough
      }
    }
  }

  // Confidence is based on the strongest match + bonus for multiple groups
  const groupBonus = Math.min((matchedPatterns.length - 1) * 0.1, 0.3);
  const confidence = matchedPatterns.length > 0
    ? Math.min(maxWeight + groupBonus, 1.0)
    : 0;

  return {
    detected: matchedPatterns.length > 0,
    patterns: [...new Set(matchedPatterns)],
    confidence: Math.round(confidence * 100) / 100,
  };
}
