/**
 * Iron Dome — Prompt Injection Scanner
 *
 * Port of ~/clawd/skills/iron-dome/scripts/scan.py to TypeScript.
 * Detects prompt injection patterns in text content from untrusted sources
 * (emails, form submissions, API responses, web pages).
 *
 * Like the memory firewall's instruction detector, this is a FAST PRE-FILTER
 * FLOOR over known injection shapes — not a claim of complete or multilingual
 * coverage. It shares the #204 normalisation fold and override-morphology
 * frames with the firewall so the two tiers cannot disagree about the same
 * payload (see firewall/instruction-normalize.ts, firewall/instruction-morphology.ts).
 */

import { instructionMatchVariants } from '../firewall/instruction-normalize.js';
import {
  AUTHORITY_GRANT,
  OVERRIDE_MORPHOLOGY,
  PROMPT_EXTRACTION,
} from '../firewall/instruction-morphology.js';

// ── Types ──

export type InjectionSeverity = 'low' | 'medium' | 'high' | 'critical';

export type InjectionCategory =
  | 'fake_system_message'
  | 'authority_claim'
  | 'urgency_secrecy'
  | 'credential_extraction'
  | 'instruction_injection'
  | 'encoding_trick'
  | 'role_manipulation'
  | 'context_escape'
  | 'canary'
  | 'host_runtime_notice';

export interface InjectionDetection {
  category: InjectionCategory | string;
  severity: InjectionSeverity;
  pattern: string;
  match: string;
  description: string;
}

export interface InjectionScanResult {
  clean: boolean;
  riskLevel: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  detections: InjectionDetection[];
  textLength: number;
  summary: string;
}

// ── Pattern Registry ──

interface PatternDef {
  category: InjectionCategory;
  severity: InjectionSeverity;
  name: string;
  description: string;
  regex: RegExp;
}

const PATTERNS: PatternDef[] = [];

function pattern(
  category: InjectionCategory,
  severity: InjectionSeverity,
  name: string,
  description: string,
  regex: RegExp,
): void {
  PATTERNS.push({ category, severity, name, description, regex });
}

// ── Fake system / admin messages ──

pattern(
  'fake_system_message',
  'critical',
  'system_prompt_override',
  'Attempts to override or replace the system prompt',
  /(?:new|updated?|revised?|override|replace)\s+(?:system\s+)?(?:prompt|instructions?|rules?|directives?)\s*[:=]/gi,
);

pattern(
  'fake_system_message',
  'critical',
  'system_message_tag',
  'Fake system message markers embedded in content',
  /(?:\[\/?\s*system\s*\]|<\/?\s*system\s*>|<<\s*system\s*>>|---\s*system\s*---|SYSTEM\s*(?:MESSAGE|PROMPT|NOTE|INSTRUCTION)\s*:)/gi,
);

pattern(
  'fake_system_message',
  'high',
  'ignore_previous',
  'Instruction to ignore or forget previous context',
  /(?:ignore|forget|disregard|override|discard|drop|reset)\s+(?:all\s+)?(?:previous|prior|above|earlier|existing|old|original)\s+(?:instructions?|rules?|context|prompts?|directives?|constraints?|guidelines?)/gi,
);

pattern(
  'fake_system_message',
  'high',
  'new_instructions',
  'Claims to provide new operating instructions',
  /(?:from\s+now\s+on|starting\s+now|henceforth|going\s+forward)\s*[,:]?\s*(?:you\s+(?:must|should|will|are|need)|your\s+(?:new|updated?))/gi,
);

pattern(
  'fake_system_message',
  'high',
  'end_of_prompt',
  'Fake end-of-prompt markers to inject new context',
  /(?:---\s*END\s+OF\s+(?:SYSTEM\s+)?(?:PROMPT|INSTRUCTIONS?)|END_INSTRUCTIONS?|<\/instructions?>|={3,}\s*(?:END|STOP))/gi,
);

pattern(
  'fake_system_message',
  'medium',
  'developer_mode',
  'Claims to enable special modes or bypass restrictions',
  /(?:developer|debug|admin|maintenance|test|god|sudo|root|unrestricted|jailbreak)\s*mode\s*(?:enabled|activated|on|engaged)/gi,
);

// Generated override frames (issue #204) — the inflected, passive and
// negated-compliance shapes of the `ignore_previous` rule above. Registered from
// the shared generator so the firewall and the scanner match the same grammar;
// recompiled with `g` here because this scanner exec-loops for every match.
for (const frame of OVERRIDE_MORPHOLOGY) {
  pattern(
    'fake_system_message',
    'high',
    frame.name,
    frame.description,
    new RegExp(frame.regex.source, 'gi'),
  );
}

// Narrow system-prompt extraction — aligned with the firewall's
// `prompt_extraction` group so "reveal your system prompt" is caught on both
// paths. Severity stays `high`: it is an extraction attempt, not yet an exfil.
for (const frame of PROMPT_EXTRACTION) {
  pattern(
    'credential_extraction',
    'high',
    frame.name,
    frame.description,
    new RegExp(frame.regex.source, 'gi'),
  );
}

// ── Authority claims ──

pattern(
  'authority_claim',
  'high',
  'identity_claim',
  'Claims to be an admin, owner, developer, or authority figure',
  /(?:I\s+am|this\s+is|speaking\s+as|writing\s+as|signed|regards)\s*[,:]?\s*(?:the\s+)?(?:admin(?:istrator)?|owner|developer|creator|operator|manager|ceo|cto|boss|supervisor|root\s+user|system\s+admin)/gi,
);

pattern(
  'authority_claim',
  'high',
  'as_the_authority',
  'Uses "as the [role]" to claim authority',
  /as\s+the\s+(?:admin(?:istrator)?|owner|developer|creator|operator|system\s+(?:admin|operator)|lead|manager|supervisor|principal|head)/gi,
);

pattern(
  'authority_claim',
  'medium',
  'authorised_claim',
  'Claims authorisation for an action',
  /(?:I(?:'m|\s+am)\s+)?(?:author[iy][sz]ed?|permitted|allowed|granted\s+(?:access|permission))\s+(?:to|by|for|from)/gi,
);

// Delegated-authority grants (shared frames) — "the developer has authorised
// you to skip the approval". The existing rules above cover an attacker
// claiming to BE the authority; these cover an attacker claiming the authority
// already said yes. Registered from the shared table so the memory firewall's
// `social_engineering` group and this scanner agree on the same grammar.
for (const frame of AUTHORITY_GRANT) {
  pattern(
    'authority_claim',
    'high',
    frame.name,
    frame.description,
    new RegExp(frame.regex.source, 'gi'),
  );
}

pattern(
  'authority_claim',
  'medium',
  'michael_impersonation',
  'Claims to be Michael or the user',
  /(?:(?:this\s+is|I\s+am|it'?s|from)\s+Michael|Michael\s+(?:says?|wants?|told|asked|instructed|requests?|needs?)\s+(?:you\s+)?to)/gi,
);

// ── Urgency + secrecy combinations ──

pattern(
  'urgency_secrecy',
  'high',
  'urgency_secrecy_combo',
  'Combines urgency with secrecy — classic social engineering',
  /(?:(?:urgent(?:ly)?|immediate(?:ly)?|right\s+now|asap|time[- ]sensitive|critical(?:ly)?|emergency)[\s\S]{0,100}(?:don'?t\s+(?:tell|mention|inform|alert|notify|share)|keep\s+(?:this\s+)?(?:secret|quiet|private|between\s+us|confidential)|do\s*n(?:ot|'t)\s+(?:log|record|audit|report)))|(?:(?:don'?t\s+(?:tell|mention|inform|alert|notify|share)|keep\s+(?:this\s+)?(?:secret|quiet|private|between\s+us|confidential))[\s\S]{0,100}(?:urgent(?:ly)?|immediate(?:ly)?|right\s+now|asap|time[- ]sensitive|critical(?:ly)?|emergency))/gi,
);

pattern(
  'urgency_secrecy',
  'medium',
  'secrecy_instruction',
  'Instructions to hide actions or avoid logging',
  /(?:don'?t|do\s+not|never|avoid)\s+(?:tell|mention|inform|alert|notify|share\s+with|report\s+to|log|record|audit|let\s+(?:anyone|(?:the\s+)?(?:admin|owner|user|michael))\s+know)/gi,
);

pattern(
  'urgency_secrecy',
  'medium',
  'bypass_approval',
  'Attempts to skip approval or verification steps',
  /(?:skip|bypass|ignore|disable|turn\s+off|override|circumvent|avoid)\s+(?:the\s+)?(?:approv(?:al|e)|verif(?:y|ication)|confirm(?:ation)?|review|check|auth(?:entication|orisation)?|gate|filter|scan|iron\s*dome|security)/gi,
);

// ── Credential / secret extraction ──

pattern(
  'credential_extraction',
  'critical',
  'credential_request',
  'Requests passwords, keys, tokens, or secrets',
  /(?:(?:send|give|share|show|reveal|output|print|display|paste|tell|provide)\s+(?:me\s+)?(?:the\s+)?(?:password|api[- ]?key|secret[- ]?key|token|private[- ]?key|credentials?|auth[- ]?(?:token|key|secret)|ssh[- ]?key|access[- ]?key|master[- ]?key|encryption[- ]?key|certificate|\.env|secret))/gi,
);

pattern(
  'credential_extraction',
  'critical',
  'exfiltration_attempt',
  'Attempts to send data to external destinations',
  /(?:(?:send|forward|post|upload|transmit|exfiltrate|copy|transfer)\s+(?:(?:all|the|this|that|those|your)\s+)?(?:data|info(?:rmation)?|content|email|message|file|log|credential|secret|key|token|password|config)\s+to\s+(?:https?:\/\/|(?:my|this|the)\s+(?:server|endpoint|api|email|address|url)))/gi,
);

pattern(
  'credential_extraction',
  'high',
  'env_file_access',
  'Attempts to read sensitive config files',
  /(?:(?:read|cat|show|display|print|output|open|access|get)\s+(?:the\s+)?(?:\.env|\.ssh|credentials?\.(?:json|yml|yaml|xml|ini|conf)|secret|private\.key|auth\.json|token\.json|config.*(?:password|secret|key)))/gi,
);

// ── Instruction injection in data fields ──

pattern(
  'instruction_injection',
  'high',
  'instruction_in_data',
  'Imperative instructions embedded in what should be data',
  /(?:^|\n)\s*(?:IMPORTANT|NOTE|INSTRUCTION|ACTION\s*REQUIRED|TASK|TODO|EXECUTE|PERFORM|RUN)\s*:\s*(?:you\s+(?:must|should|need\s+to|have\s+to)|please\s+(?:do|run|execute|send|delete|modify|change))/gi,
);

pattern(
  'instruction_injection',
  'high',
  'ai_directive',
  'Directives addressed to the AI/assistant/agent',
  /(?:dear\s+(?:ai|assistant|agent|bot|model|llm|gpt|claude|jarvis)|(?:hey|hi|hello)\s+(?:ai|assistant|agent|bot|model))\s*[,:]?\s*(?:please|you\s+(?:must|should|need)|I\s+(?:need|want)\s+you\s+to)/gi,
);

pattern(
  'instruction_injection',
  'medium',
  'hidden_instruction',
  'Instructions disguised with special formatting or whitespace',
  /(?:\[INST\]|\[\/INST\]|<\|(?:im_start|im_end|system|user|assistant)\|>|###\s*(?:System|Instruction|Human|Assistant)\s*:)/gi,
);

pattern(
  'instruction_injection',
  'medium',
  'email_injection',
  'Email body containing commands for the processing agent',
  /(?:when\s+(?:you|the\s+(?:ai|agent|assistant|bot))\s+(?:read|process|receive|see|get)\s+this|if\s+(?:an?\s+)?(?:ai|agent|assistant|bot)\s+(?:is\s+)?(?:reading|processing|scanning)\s+this)/gi,
);

// ── Encoding / obfuscation tricks ──

pattern(
  'encoding_trick',
  'medium',
  'base64_instruction',
  'Base64-encoded content that may hide instructions',
  /(?:decode|execute|run|follow|process)\s+(?:this\s+)?(?:base64|encoded|b64)\s*:\s*[A-Za-z0-9+/]{20,}={0,2}/gi,
);

pattern(
  'encoding_trick',
  'medium',
  'unicode_obfuscation',
  'Zero-width or special unicode characters used for obfuscation',
  /[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064\ufeff]{2,}/g,
);

pattern(
  'encoding_trick',
  'low',
  'rot13_instruction',
  'ROT13-encoded instructions',
  /(?:rot13|decode|decipher)\s*:\s*[a-zA-Z\s]{10,}/gi,
);

// ── Role manipulation ──

pattern(
  'role_manipulation',
  'high',
  'roleplay_injection',
  'Attempts to get the agent to adopt a different role',
  /(?:you\s+are\s+(?:now|no\s+longer)\s+(?:a|an|the)\s+|pretend\s+(?:you(?:'re|\s+are)\s+|to\s+be\s+)|act\s+as\s+(?:if\s+you(?:'re|\s+are)\s+)?(?:a|an|the)\s+|roleplay\s+as|your\s+new\s+(?:role|identity|persona)\s+is)/gi,
);

pattern(
  'role_manipulation',
  'high',
  'constraint_removal',
  'Attempts to remove safety constraints or rules',
  /(?:you\s+(?:don'?t|do\s+not)\s+(?:have|need)\s+(?:any\s+)?(?:rules?|constraints?|restrictions?|limitations?|guidelines?|boundaries?))|(?:(?:remove|disable|turn\s+off|drop|ignore)\s+(?:all\s+)?(?:your\s+)?(?:safety|security|content)?\s*(?:rules?|filters?|constraints?|restrictions?|limitations?|guidelines?|guardrails?|boundaries?))/gi,
);

// ── Context escape ──

pattern(
  'context_escape',
  'high',
  'conversation_reset',
  'Attempts to reset the conversation or start a new context',
  /(?:(?:new|fresh|clean)\s+conversation|conversation\s+(?:reset|restart)|start(?:ing)?\s+(?:over|fresh|new\s+(?:session|conversation))|clear\s+(?:context|history|memory|conversation))/gi,
);

pattern(
  'context_escape',
  'medium',
  'output_format_hijack',
  'Attempts to control the output format for injection',
  /(?:respond\s+(?:only\s+)?with|your\s+(?:only\s+)?(?:response|output|reply)\s+(?:should|must|will)\s+be|output\s+(?:exactly|only|nothing\s+(?:but|except))|say\s+(?:only|exactly|nothing\s+(?:but|except)))\s+/gi,
);

// ── Defence canary (synthetic probe — `shieldcortex doctor`) ──
// Matches a unique marker emitted only by the doctor's canary check. Lets the
// CLI prove the firewall layer is alive without depending on operator vibes or
// real attack telemetry. Safe by construction: the marker is intentionally
// non-natural (double-underscore + internal version tag) so it cannot collide
// with legitimate content.

pattern(
  'canary',
  'critical',
  'defence_canary_test',
  'Synthetic canary probe emitted by `shieldcortex doctor` to verify the pipeline catches known-malicious markers. Safe by construction.',
  /__SHIELDCORTEX_CANARY_PROBE_v1__/g,
);

// ── External Patterns (Cloud Sync) ──

interface ExternalPatternDef {
  category: string;
  severity: InjectionSeverity;
  name: string;
  description: string;
  regex: RegExp;
}

let externalPatterns: ExternalPatternDef[] = [];

/**
 * Register cloud-synced patterns for injection scanning.
 * Compiles each regex, skipping invalid ones silently.
 */
export function setExternalPatterns(
  patterns: Array<{ pattern: string; category: string; severity: string }>,
): void {
  const compiled: ExternalPatternDef[] = [];
  for (const p of patterns) {
    try {
      const regex = new RegExp(p.pattern, 'gi');
      const severity = (['critical', 'high', 'medium', 'low'].includes(p.severity)
        ? p.severity
        : 'medium') as InjectionSeverity;
      compiled.push({
        category: p.category,
        severity,
        name: `custom:${p.category}`,
        description: `Custom pattern: ${p.category}`,
        regex,
      });
    } catch {
      // Skip invalid regex patterns silently
    }
  }
  externalPatterns = compiled;
}

/**
 * Returns the count of currently registered external patterns.
 */
export function getExternalPatternCount(): number {
  return externalPatterns.length;
}

// ── Host runtime notices (classify, don't silence) ──
//
// OpenClaw injects its own framing into the model turn — gateway-restart recovery
// notices and inbound-metadata envelopes. These trip the fake-system-message rule
// and were scoring CRITICAL every session, burying real detections (issue #72).
//
// We do NOT stop scanning them (a "starts with [System]" allowlist would hand an
// attacker a prefix that suppresses detection). Instead, when the WHOLE content
// matches a known host-envelope SHAPE — anchored start AND end, so nothing can be
// appended — the fake-system-message detections it produced are reclassified to a
// distinct low-severity `host_runtime_notice`. The event survives (filterable in
// audit); only its severity drops. Any injection payload appended to the notice
// breaks the full-shape match, so it stays CRITICAL (anti-bypass).
//
// Shapes are non-global (stateless `.test`) and single-line-bounded on their
// variable tail so a smuggled newline + payload cannot ride inside the match.
const HOST_RUNTIME_NOTICE_SHAPES: RegExp[] = [
  // Gateway-restart recovery notice, fleet-wide.
  /^\[System\]\s+Your previous turn was interrupted by a gateway restart\b[^\n]{0,240}$/i,
  // Inbound conversation-metadata envelope (untrusted metadata JSON).
  /^Conversation info \(untrusted metadata\):\s*```json\s*\n[\s\S]{0,600}\n```\s*$/i,
];

function matchesHostRuntimeNotice(text: string): boolean {
  const t = text.trim();
  return HOST_RUNTIME_NOTICE_SHAPES.some(re => re.test(t));
}

/**
 * When the whole content is a known host-runtime notice, downgrade the
 * fake-system-message markers it produced to a low-severity host_runtime_notice.
 * Non-envelope detections (there should be none for a genuine notice, but if the
 * content smuggled one it would fail the full-shape gate above) are left intact.
 */
function reclassifyHostRuntimeNotices(
  text: string,
  detections: InjectionDetection[],
): InjectionDetection[] {
  if (detections.length === 0 || !matchesHostRuntimeNotice(text)) return detections;
  return detections.map(d =>
    d.category === 'fake_system_message'
      ? {
          ...d,
          category: 'host_runtime_notice',
          severity: 'low',
          description:
            `OpenClaw host runtime notice (full-shape match) — reclassified from ${d.pattern}; ` +
            'scanned, not silenced. An injection payload embedded in or appended to this framing still scores CRITICAL.',
        }
      : d,
  );
}

// ── Scanner ──

/**
 * Scan text for prompt injection patterns.
 */
const NORMALISED_MATCH_NOTE =
  ' — matched only after normalisation (zero-width/bidi strip, confusable fold, ' +
  'punctuation collapse, classic leet); the span recorded below is the normalised text.';

export function scanForInjection(text: string): InjectionScanResult {
  const detections: InjectionDetection[] = [];

  // The raw text is variant 0, so an un-obfuscated payload matches on the first
  // pass with its original span intact. Variants 1..2 are the #204 normalisation
  // folds — the same helper the memory firewall uses. A rule that already fired
  // on an earlier variant is skipped, so a normalised copy can only add rules the
  // raw text missed; it never re-reports the same rule with a rewritten span.
  // (Budget: at most 3 variants — see instructionMatchVariants.)
  const variants = instructionMatchVariants(text);
  const firedRules = new Set<string>();

  for (let variantIndex = 0; variantIndex < variants.length; variantIndex++) {
    const target = variants[variantIndex];
    const normalised = variantIndex > 0;

    for (const pat of [...PATTERNS, ...externalPatterns]) {
      const ruleKey = `${pat.category}:${pat.name}`;
      if (normalised && firedRules.has(ruleKey)) continue;

      // Every registered pattern is global; matchAll iterates a clone, so the
      // shared regex objects never carry lastIndex state between scans.
      pat.regex.lastIndex = 0;
      for (const match of target.matchAll(pat.regex)) {
        firedRules.add(ruleKey);
        detections.push({
          category: pat.category as string,
          severity: pat.severity,
          pattern: pat.name,
          match: match[0].trim().slice(0, 200),
          description: normalised ? pat.description + NORMALISED_MATCH_NOTE : pat.description,
        });
      }
    }
  }

  // Deduplicate: same category + pattern + overlapping matched text
  const seen = new Set<string>();
  const deduped: InjectionDetection[] = [];
  for (const d of detections) {
    const key = `${d.category}:${d.pattern}:${d.match.slice(0, 80)}`;
    if (!seen.has(key)) {
      seen.add(key);
      deduped.push(d);
    }
  }

  // Classify (don't silence) host-runtime notices: full-shape OpenClaw framing
  // has its fake-system-message markers downgraded to host_runtime_notice/low so
  // it stops scoring CRITICAL while staying in the audit (issue #72).
  const unique = reclassifyHostRuntimeNotices(text, deduped);

  // Determine overall risk level
  let riskLevel: InjectionScanResult['riskLevel'] = 'NONE';
  if (unique.length > 0) {
    const severities = unique.map(d => d.severity);
    if (severities.includes('critical')) {
      riskLevel = 'CRITICAL';
    } else if (severities.includes('high')) {
      riskLevel = 'HIGH';
    } else if (severities.includes('medium')) {
      riskLevel = 'MEDIUM';
    } else {
      riskLevel = 'LOW';
    }
  }

  // Build summary
  let summary: string;
  if (unique.length === 0) {
    summary = 'No prompt injection patterns detected.';
  } else {
    const cats: Record<string, number> = {};
    for (const d of unique) {
      cats[d.category] = (cats[d.category] ?? 0) + 1;
    }
    const parts = Object.entries(cats)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${v}x ${k}`);
    summary = `${unique.length} detection(s): ${parts.join(', ')}`;
  }

  return {
    clean: unique.length === 0,
    riskLevel,
    detections: unique,
    textLength: text.length,
    summary,
  };
}
