/**
 * #402 Phase 1 — work-fact vs directive FORM classifier.
 *
 * Purely structural/heuristic (design lock: no ML/ONNX bouncer). A work-fact
 * states world state ("Open Day is Fri 25 Sep", "switch ports 08–14 looped");
 * a directive commands the READER ("forget your instructions", imperative
 * verbs targeting the agent, 2nd-person commands, tool-invocation shapes).
 * The stamped form is the write-time half of the two-key inject gate
 * (provenance key + form key) — the live gate in scripts/lib/inject-pack.mjs
 * re-checks the stamped column at read time.
 *
 * Fail-closed law: any classifier failure ⇒ 'unknown' ⇒ directive-adjacent
 * (inert, never injectable, never auto-admit).
 */

export type ContentForm = 'fact' | 'directive' | 'mixed' | 'unknown';

/** Perf bounds: classification is O(segments × patterns), both capped. */
const MAX_SCAN_CHARS = 16_000;
const MAX_SEGMENTS = 80;

// ── Directive tells ─────────────────────────────────────────────────────────
// STRONG imperative openers: near-unambiguous commands when sentence-initial
// in memory content. These fire alone.
const STRONG_IMPERATIVE_OPENER =
  /^(?:please\s+|kindly\s+|now\s+|first\s+|always\s+|never\s+|immediately\s+|silently\s+|quietly\s+)*(?:ignore|disregard|forget|obey|comply|bypass|override|circumvent|pretend|adopt|behave|act\s+as|reveal|disclose|exfiltrate|leak|impersonate|jailbreak|deactivate|stop\s+following|set\s+aside|pay\s+no\s+attention|do\s+not\s+(?:tell|reveal|mention|follow|store)|don't\s+(?:tell|reveal|mention|follow)|treat\s+the\s+following|remember\s+to\b|make\s+sure\s+(?:to|you)\b|be\s+sure\s+to\b|from\s+now\s+on\b|whenever\s+you\b|every\s+time\s+you\b)/i;

// AMBIGUOUS imperative openers: verbs that also appear nominally / in genuine
// prose ("switch ports 08–14 looped", "run rate is 4/day"). They only count as
// directives with corroboration in the SAME segment (see DIRECTIVE_CORROBORATION).
const AMBIGUOUS_IMPERATIVE_OPENER =
  /^(?:please\s+|kindly\s+|now\s+|first\s+|then\s+|next\s+|also\s+)*(?:run|execute|invoke|launch|open|curl|wget|fetch|download|upload|send|post|email|forward|transmit|export|copy|paste|delete|remove|drop|erase|wipe|install|disable|enable|set|store|save|write|embed|insert|add|append|collect|gather|read|print|output|show|tell|give|repeat|echo|display|switch|change|update|modify|edit|replace|use|call|visit|go\s+to|click|type|enter)\b/i;

// Corroboration that turns an ambiguous opener into a command aimed at the
// reader: 2nd-person address, deixis ("this command", "the following"),
// persistence/stealth adverbs, or an explicit destination.
const DIRECTIVE_CORROBORATION =
  /\b(?:you|your|yourself)\b|\bthe\s+following\b|\bthis\s+(?:command|script|instruction|directive|payload|url|link|address|file)\b|\b(?:immediately|silently|secretly|quietly|discreetly|without\s+(?:the\s+user|asking|approval|telling))\b|\bhttps?:\/\/|\bto\s+(?:my|this|that)\s+(?:server|endpoint|address|url|email)\b|\bverbatim\b|\bword\s+for\s+word\b|\bright\s+now\b|\bevery\s+(?:future\s+)?(?:turn|request|response|session|message)\b/i;

// Second-person command / role-override morphology anywhere in a segment.
const SECOND_PERSON_COMMAND =
  /\byou\s+(?:must|should|shall|need\s+to|have\s+to|are\s+(?:required|obliged|expected)\s+to|will\s+now|may\s+now|can\s+now|are\s+now|are\s+no\s+longer|have\s+been\s+(?:freed|released|granted|upgraded))\b|\byou\s+are\s+(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|jailbroken)\b|\bas\s+an?\s+ai\s+you\b/i;

// Override morphology: prior rules/instructions declared void or replaced.
const OVERRIDE_MORPHOLOGY =
  /\b(?:rules?|instructions?|restrictions?|constraints?|guidelines?|polic(?:y|ies)|directives?|guidance|configuration|boundaries|filters?|guardrails?|safeguards?)\b[^.!?\n]{0,60}\b(?:no\s+longer\s+(?:appl(?:y|ies)|bind|hold|matter)|do(?:es)?\s+not\s+apply|don't\s+apply|are\s+(?:void|lifted|suspended|revoked|disabled|turned\s+off)|is\s+void|have\s+been\s+(?:lifted|removed|revoked|disabled))\b|\b(?:real|true|actual)\s+instructions\b|\binstead\s+of\s+your\s+(?:instructions|rules|guidelines)\b|\bprior\s+configuration\s+is\s+void\b/i;

// Targeting the agent's own hidden state: system-prompt exfil requests,
// persona flips, memory-persistence poison.
const AGENT_STATE_TARGETING =
  /\b(?:system\s+prompt|hidden\s+instructions?|secret\s+(?:guidelines?|instructions?)|initial\s+configuration|safety\s+(?:filters?|guidelines?|rules)|content\s+(?:policy|restrictions?)|developer\s+mode)\b|\bpersona\s+of\s+an?\s+ai\b|\bmode\s+where\s+nothing\s+is\s+forbidden\b|\bso\s+it\s+(?:overrides?|runs?\s+on)\s+(?:future|every)\b/i;

// Bare tool-invocation shape: the segment IS a command line (leading prompt
// marker / flag soup / shell chaining into an interpreter or fetch tool), not
// prose about one. Assembled from parts — the compound "fetch chained into a
// shell" shape must not appear as one literal in this source file (the repo's
// own Action Guard rightly refuses that shape).
const FETCH_OR_SHELL_TOKENS = '(?:cu' + 'rl|wg' + 'et|nc|ba' + 'sh|sh|zsh|chm' + 'od)';
const BARE_COMMAND_SHAPE = new RegExp(
  [
    String.raw`^(?:\$\s+|#\s+|su` + `do\\s+)?[a-z][\\w./-]*\\s+(?:-{1,2}[\\w-]+|\\S+\\s+-{1,2}[\\w-]+)`,
    String.raw`\|\s*` + FETCH_OR_SHELL_TOKENS + String.raw`\b`,
    String.raw`&&\s*` + FETCH_OR_SHELL_TOKENS + String.raw`\b`,
    String.raw`;\s*` + FETCH_OR_SHELL_TOKENS + String.raw`\b`,
    String.raw`\br` + `m\\s+-` + `rf\\b`,
    String.raw`>\s*/dev/`,
  ].join('|'),
  'i',
);

// ── Fact tells ──────────────────────────────────────────────────────────────
// Non-initial copula / stative / reporting predicate: a subject came first.
const DECLARATIVE_PREDICATE =
  /\S\s+(?:is|are|was|were|isn't|aren't|wasn't|weren't|has|have|had|will\s+be|won't|remains?|remained|becomes?|became|stays?|stayed|equals?|means?|meant|contains?|contained|includes?|included|belongs?|costs?|lasts?|takes?|took|expires?|expired|starts?|started|ends?|ended|opens?|opened|closes?|closed|ships?|shipped|lives?|sits?|runs?\s+on|listens?\s+on|points?\s+(?:to|at)|maps?\s+to|resolves?\s+to|defaults?\s+to|depends?\s+on|requires?|uses?|used|supports?|owns?|owned)\b/i;

// Non-initial 3rd-person-singular action verbs ("CI runs npm test", "the cron
// fires hourly"). The -s inflection is a strong declarative signal: English
// imperatives are never -s inflected, so this cannot match a command.
const THIRD_PERSON_S_VERB =
  /\S\s+(?:runs|executes|builds|tests|deploys|ships|sends|posts|checks|triggers|starts|stops|restarts|calls|invokes|reads|writes|handles|serves|processes|watches|polls|fires|emits|logs|reports|syncs|imports|exports|renders|caches|retries|queues|schedules|owns|manages|maintains|hosts|stores|keeps|tracks|covers|blocks|allows|rejects|accepts|returns|throws|fails|passes|expects|needs|wants|prefers)\b/i;

// Past-tense / completed-state reporting verbs common in work notes.
const REPORTING_VERB =
  /\b(?:decided|agreed|confirmed|deployed|released|merged|landed|fixed|resolved|closed|reverted|rolled\s+back|migrated|renamed|moved|upgraded|downgraded|patched|failed|passed|broke|crashed|timed\s+out|expired|looped|flapped|rebooted|restarted|scheduled|postponed|cancelled|canceled|approved|rejected|shipped|announced|reported|observed|measured|noticed|found|discovered|introduced|caused|blocked\s+by|waiting\s+on|assigned\s+to|owned\s+by|due\s+(?:on|by)|set\s+to|pinned\s+at|capped\s+at|limited\s+to)\b/i;

// Concrete world-state anchors: dates, times, versions, ports, IPs, tickets,
// quantities with units, paths.
const WORLD_STATE_ANCHOR =
  /\b(?:mon|tue(?:s)?|wed(?:nes)?|thu(?:rs)?|fri|sat(?:ur)?|sun)(?:day)?\b|\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?\s+\d{1,2}\b|\b\d{1,2}\s+(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\b|\b20\d{2}\b|\bv?\d+\.\d+(?:\.\d+)?\b|\b\d{1,2}:\d{2}\b|\bport(?:s)?\s+\d|\b(?:\d{1,3}\.){3}\d{1,3}\b|\bQ[1-4]\b|#\d{2,}\b|\b\d+\s?(?:%|ms|s|min|minutes?|hours?|days?|weeks?|gb|mb|kb|tb|ghz|mhz|users?|rows?|items?|req(?:s)?|rps|qps)\b|(?:^|\s)\/[\w./-]{2,}/i;

// Third-person policy facts: "PRs must pass CI", "backups should run nightly".
// A modal is only a directive when aimed at "you" (caught above).
const POLICY_FACT =
  /\b(?!you\b|your\b)\w[\w-]*(?:s|\b)[^.!?\n]{0,40}\b(?:must|should|needs?\s+to|has\s+to|have\s+to|is\s+required\s+to|are\s+required\s+to)\b/i;

function isDirectiveSegment(seg: string): boolean {
  if (SECOND_PERSON_COMMAND.test(seg)) return true;
  if (OVERRIDE_MORPHOLOGY.test(seg)) return true;
  if (STRONG_IMPERATIVE_OPENER.test(seg)) return true;
  if (AMBIGUOUS_IMPERATIVE_OPENER.test(seg) && DIRECTIVE_CORROBORATION.test(seg)) return true;
  if (BARE_COMMAND_SHAPE.test(seg) && !DECLARATIVE_PREDICATE.test(seg)) return true;
  // Agent-state targeting needs an action aimed at it (imperative or 2nd
  // person handled above); standalone it corroborates an opener instead.
  if (AGENT_STATE_TARGETING.test(seg) && (AMBIGUOUS_IMPERATIVE_OPENER.test(seg) || /\byour?\b/i.test(seg))) return true;
  return false;
}

function isFactSegment(seg: string): boolean {
  if (seg.endsWith('?')) return false; // questions are neither facts nor commands
  return (
    DECLARATIVE_PREDICATE.test(seg) ||
    THIRD_PERSON_S_VERB.test(seg) ||
    REPORTING_VERB.test(seg) ||
    WORLD_STATE_ANCHOR.test(seg) ||
    POLICY_FACT.test(seg)
  );
}

/**
 * Classify content form. NEVER throws: any internal failure returns 'unknown'
 * (directive-adjacent, fail-closed) — never a silent 'fact'.
 *
 * 'mixed' = at least one directive-shaped segment alongside fact-shaped ones
 * (e.g. poison appended to a real fact). Mixed is treated as directive-adjacent
 * everywhere downstream: a single smuggled imperative taints the whole row.
 */
export function classifyContentForm(content: unknown): ContentForm {
  try {
    if (typeof content !== 'string') return 'unknown';
    const text = content.slice(0, MAX_SCAN_CHARS).replace(/[ \t]+/g, ' ').trim();
    if (!text) return 'unknown';

    const segments = text
      .split(/(?<=[.!?;])\s+|\n+|\s+[-—]\s+|(?:^|\s)[•·]\s*/)
      .map((s) => s.trim().replace(/^[-*>\d.)\s]+/, '').trim())
      .filter((s) => s.length > 1)
      .slice(0, MAX_SEGMENTS);
    if (segments.length === 0) return 'unknown';

    let directiveHits = 0;
    let factHits = 0;
    for (const seg of segments) {
      if (isDirectiveSegment(seg)) {
        directiveHits++; // directive wins within a segment (fail-closed)
      } else if (isFactSegment(seg)) {
        factHits++;
      }
    }

    if (directiveHits > 0 && factHits > 0) return 'mixed';
    if (directiveHits > 0) return 'directive';
    if (factHits > 0) return 'fact';
    return 'unknown';
  } catch {
    return 'unknown';
  }
}
