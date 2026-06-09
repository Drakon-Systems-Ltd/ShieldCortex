/**
 * Instruction Detector
 *
 * Detects prompt injection and hidden instruction patterns in memory content.
 */

import { foldConfusables } from './confusables.js';

export interface InstructionDetectionResult {
  detected: boolean;
  patterns: string[];
  confidence: number;
}

interface PatternGroup {
  name: string;
  patterns: RegExp[];
  weight: number;
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
    name: 'command_injection',
    weight: 0.85,
    patterns: [
      /\beval\s*\(/i,
      /\bexec\s*\(/i,
      /\bsystem\s*\(/i,
      /\bimport\s+os\b/i,
      /\brun\s+command\b/i,
      /\bexecute\s+(this\s+)?(command|code|script)/i,
      /\b__import__\s*\(/i,
      /\bsubprocess\b/i,
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

// Maximum content length to scan (prevents ReDOS on very long inputs)
const MAX_SCAN_LENGTH = 50000;

/**
 * Safely test a regex against content with length limit
 */
function safeRegexTest(pattern: RegExp, text: string): boolean {
  // Truncate to prevent potential ReDOS on extremely long inputs
  const truncated = text.length > MAX_SCAN_LENGTH ? text.slice(0, MAX_SCAN_LENGTH) : text;
  return pattern.test(truncated);
}

export function detectInstructions(content: string): InstructionDetectionResult {
  const matchedPatterns: string[] = [];
  let totalWeight = 0;
  let maxWeight = 0;

  // Fold cross-script confusables (Cyrillic/Greek homoglyphs + NFKC forms) to
  // their Latin skeleton so a single-glyph substitution like `ignorе` (Cyrillic
  // е) still matches the ASCII patterns. We test the original first, then the
  // folded copy only if folding changed something — testing both means we never
  // *lose* a match that the original would have caught.
  const folded = foldConfusables(content);
  const variants = folded !== content ? [content, folded] : [content];

  for (const group of PATTERN_GROUPS) {
    for (const pattern of group.patterns) {
      if (variants.some((variant) => safeRegexTest(pattern, variant))) {
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
