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
 *   - paraphrase, in any language. The multilingual table (instruction-multilingual.ts)
 *     covers one closed set of explicit imperatives; reworded intent still passes.
 *   - completeness. A synonym this file has not seen will pass. That is the
 *     expected failure mode of a regex tier, which is why the layers above it
 *     (trust scoring, quarantine, semantic) do not assume it is exhaustive.
 */

import { someWindow } from '../scan-windows.js';
import { instructionMatchVariants } from './instruction-normalize.js';
import {
  OVERRIDE_MORPHOLOGY_PATTERNS,
  PROMPT_EXTRACTION_PATTERNS,
} from './instruction-morphology.js';
import { MULTILINGUAL_INJECTION_PHRASES } from './instruction-multilingual.js';

/**
 * Case-insensitive alternation for authority-spoof verbs, built once at load.
 * The label stays case-sensitive (UPPERCASE only) so ordinary "Admin:" email
 * is quiet; the verb is any case so "ADMIN: YOU MUST" is not. Character
 * classes instead of a scoped /i modifier keep Node 22.14 supported.
 */
const anyCase = (phrase: string): string =>
  phrase
    .replace(/[a-z]/gi, (c) => `[${c.toUpperCase()}${c.toLowerCase()}]`)
    .replace(/ /g, '\\s+');
const SPOOF_VERBS = ['you must', 'ignore', 'new instructions', 'override', 'disregard', 'reveal']
  .map(anyCase)
  .join('|');

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

// ── hidden_instruction: `pretend to be` awareness exemption ─────────────────────
// Fold 4 (Case review). An occurrence of "pretend to be" is exempt ONLY when
// its sentence positively identifies awareness / reporting context. Being next
// to a message noun ("emails pretend to be …") is NOT enough: ambiguous text
// keeps the original signal. The exempt shapes, all anchored to the start of
// the sentence (input start, after .!? + space, or a line start / bullet):
//   1. a notice frame ("Security notice:", "Phishing alert:", "Warning:") or a
//      reporting/caution lead ("Be aware that", "Beware of", "Report",
//      "Never trust", "Do not reply to", "Delete") before the subject; or
//   2. a subject that names the threat itself: a threat actor ("scammers",
//      "attackers") or a threat-labelled message ("phishing emails", "fake
//      websites", "scam texts"); or
//   3. a bare message subject ("some emails pretend to be …") whose SAME
//      sentence carries a disclaimer ("… but we will never ask for …", "do
//      not reply").
// Then the subject, an optional that/which/who, up to three hedge words, and
// "pretend to be". Anything else in front of the phrase (an imperative verb,
// "your", a noun without a cue, punctuation) means no exemption. Bounded
// horizontal whitespace only (see NOT_NEGATED in skill-scanner/patterns.ts).
const PT_WS = String.raw`[ \t]{1,4}`;
const PT_ACTOR = String.raw`(?:scammers?|criminals?|attackers?|fraudsters?|hackers?|phishers?|impost[eo]rs?|cybercriminals?|spammers?)`;
const PT_MSG = String.raw`(?:e-?mails?|messages?|texts?|sms(?:es)?|calls?|voicemails?|links?|pop-?ups?|websites?|sites?|web[ \t]?pages?|dms?|notifications?|attachments?)`;
const PT_MSGS = String.raw`${PT_MSG}(?:,?${PT_WS}(?:or|and)${PT_WS}${PT_MSG})?`;
const PT_QUAL = String.raw`(?:scam|phishing|fake|fraudulent|bogus|spoofed|suspicious|malicious|counterfeit|spam|smishing|vishing)`;
const PT_DET = String.raw`(?:(?:some|these|those|many|any|all|such|the|most)${PT_WS})?`;
const PT_REL = String.raw`(?:${PT_WS}(?:that|which|who))?`;
const PT_HEDGE = String.raw`(?:(?:may|might|can|could|will|often|sometimes|usually|frequently|commonly|routinely|try|tries|attempt|attempts)${PT_WS}(?:to${PT_WS})?){0,3}`;
const PT_SENT_START = String.raw`(?:^|[.!?]${PT_WS}|\n[ \t]{0,4})(?:[-*\u2022][ \t]{1,4})?`;
const PT_FRAME = String.raw`(?:(?:(?:(?:it|security|cyber[ \t]?security|phishing|scam|fraud|safety)${PT_WS}(?:notice|alert|reminder|warning|advisory|tip|bulletin))|warning|caution|reminder|notice|heads[ \t-]?up|psa)[ \t]{0,2}[:\u2014-]${PT_WS})`;
const PT_LEAD = String.raw`(?:(?:please${PT_WS})?(?:be${PT_WS}aware${PT_WS}(?:that|of)|beware(?:${PT_WS}of)?|be${PT_WS}(?:wary|careful|suspicious)${PT_WS}(?:of|with)|watch${PT_WS}out${PT_WS}for|look${PT_WS}out${PT_WS}for|note${PT_WS}that|remember${PT_WS}that|never${PT_WS}trust|(?:do${PT_WS}not|don't)${PT_WS}(?:trust|reply${PT_WS}to|respond${PT_WS}to|click|open)|report|delete|block|flag)${PT_WS})`;
const PT_SUBJECT_TAIL = String.raw`${PT_REL}${PT_WS}${PT_HEDGE}`;
// Shapes 1 and 2.
const PT_AWARE_PREFIX = String.raw`${PT_SENT_START}(?:(?:${PT_FRAME}${PT_LEAD}?|${PT_LEAD})${PT_DET}(?:${PT_QUAL}${PT_WS})?(?:${PT_ACTOR}|${PT_MSGS})|${PT_FRAME}?${PT_DET}(?:${PT_QUAL}${PT_WS}(?:${PT_ACTOR}|${PT_MSGS})|${PT_ACTOR}))${PT_SUBJECT_TAIL}`;
// Shape 3: a bare message subject, exempt only with a same-sentence disclaimer.
const PT_BARE_PREFIX = String.raw`${PT_SENT_START}${PT_FRAME}?${PT_DET}${PT_MSGS}${PT_SUBJECT_TAIL}`;
const PT_DISCLAIMER = String.raw`[^.!?\n;]{0,200}?\b(?:(?:will${PT_WS})?never${PT_WS}(?:ever${PT_WS})?ask|will${PT_WS}not${PT_WS}(?:ever${PT_WS})?ask|(?:do${PT_WS}not|don't)${PT_WS}(?:reply|respond))\b`;
const PRETEND_TO_BE_ROW = new RegExp(
  String.raw`\b(?=pretend\s)(?<!${PT_AWARE_PREFIX})(?!(?<=${PT_BARE_PREFIX})pretend${PT_WS}to${PT_WS}be\b${PT_DISCLAIMER})pretend\s+to\s+be`,
  'i',
);

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
      // `pretend to be` — per occurrence; see PRETEND_TO_BE_ROW. Fold 4: the
      // exemption needs POSITIVE awareness context in the same sentence, not
      // just a noun next to the phrase.
      PRETEND_TO_BE_ROW,
      // Extra re-flags (closed lists; a backstop, not the safety mechanism):
      // composing impersonating messages is a directive ("write emails that
      // pretend to be from IT …"), a semicolon-joined follow-up in the same
      // sentence is ambiguous, and a request to send/give something to
      // "them/us/me" is a directive.
      /\b(?:write|send|craft|compose|draft|create|generate|produce)\s+(?:[\w-]+\s+){0,3}?(?:e-?mails?|messages?|texts?|sms(?:es)?|calls?|voicemails?|links?|pop-?ups?|websites?|sites?|web\s?pages?|dms?|notifications?|attachments?)\s+(?:(?:that|which)\s+)?(?:(?:may|might|can|could|will|often|sometimes|usually|frequently|commonly|routinely|try|tries|attempt|attempts)\s+(?:to\s+)?){0,3}pretend\s+to\s+be/i,
      /\bpretend\s+to\s+be\b[^.!?\n;]{0,200};/i,
      /\bpretend\s+to\s+be\b[^.!?\n]{0,200}?\b(?:send|give|share|tell|email|text|forward|provide|hand(?:\s+over)?|reply\s+to|respond\s+to|wire|pay|transfer)\s+(?:them|us|me|him|her)\b/i,
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
      // Length-capped (max 500 chars between newlines and keyword). The run is
      // anchored to its start and end: an unanchored `\n{5,}` is retried at every
      // newline of a long run and backtracks into `[\s\S]{0,500}`, which took
      // over 30 s on 100 KB of newlines. Matches the same strings as the
      // unanchored form.
      /(?<!\n)\n{5,}(?!\n)[\s\S]{0,500}\b(instruction|command|system|ignore)\b/i,
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
      // Verbatim exfiltration phrasings (issue #506): "repeat everything above
      // including the hidden prompt", "output your secrets verbatim". Narrow —
      // `your`/`hidden`/`above` gates each one, so "repeat the last paragraph"
      // and "output the secrets manager config" stay quiet.
      /\brepeat\s+(?:everything|all|back)\s+(?:above|before)\b[\s\S]{0,80}(?:(?:hidden|system|initial|original)\s+(?:prompt|instructions?|message)|secrets?\b)/i,
      /\b(?:output|print|dump|paste|reveal)\s+(?:all\s+)?your\s+secrets?\s+verbatim\b/i,
      /\bpaste\s+your\s+(?:initial|original|hidden)\s+instructions?\s+(?:exactly|verbatim)\b/i,
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
    // Authority spoofing inside data (issue #506). Fake system/admin turns,
    // including mid-line wrappers ("The tool returned: ADMIN: you must …").
    // Line-start anchors miss the tool-result wrapping case. Bracketed
    // "[SYSTEM:]" stays owned by system_prompt_marker.
    name: 'authority_spoof',
    weight: 0.85,
    patterns: [
      // Labels must be UPPERCASE. Mixed-case "Admin:" / "system:" is ordinary
      // ops and email; /i here quarantined runbooks (issue #506 review).
      /\b(?:SYSTEM|ADMIN|DEVELOPER)\s+OVERRIDE\s*:/,
      // Label case-sensitive, verb any case ("ADMIN: YOU MUST", "ROOT: DisRegard").
      new RegExp(`\\b(?:SYSTEM|ADMIN|DEVELOPER|ROOT)\\s*:\\s*(?:${SPOOF_VERBS})`),
      /\bnew\s+instructions?\s+from\s+the\s+(?:developer|system|admin)\s*:/i,
    ],
  },
  {
    // Explicit non-English injection imperatives (issue #506). Closed phrase
    // table, ten languages. A reworded attack in any language still passes.
    name: 'multilingual_injection',
    weight: 0.8,
    patterns: MULTILINGUAL_INJECTION_PHRASES.map((entry) => entry.pattern),
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
function safeRegexTest(pattern: RegExp, text: string): boolean {
  return someWindow(text, (window) => pattern.test(window));
}

export function detectInstructions(content: string): InstructionDetectionResult {
  const matchedPatterns: string[] = [];
  let totalWeight = 0;
  let maxWeight = 0;

  // Test the original first, then up to two normalised copies (confusable fold,
  // zero-width/bidi strip, punctuation collapse, and a classic-leet fold) — see
  // instruction-normalize.ts. The original always leads, so normalisation can
  // only ever *add* a match, never lose one the raw text would have caught.
  const variants = instructionMatchVariants(content);

  for (const group of PATTERN_GROUPS) {
    if (group.subsumedBy && matchedPatterns.includes(group.subsumedBy)) continue;
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
  const groupBonus = Math.min(Math.max(matchedPatterns.length - 1, 0) * 0.1, 0.3);
  const confidence = matchedPatterns.length > 0
    ? Math.min(maxWeight + groupBonus, 1.0)
    : 0;

  return {
    detected: matchedPatterns.length > 0,
    patterns: [...new Set(matchedPatterns)],
    confidence: Math.round(confidence * 100) / 100,
  };
}
