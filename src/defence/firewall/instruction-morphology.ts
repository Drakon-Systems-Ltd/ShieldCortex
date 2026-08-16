/**
 * Bounded override-intent morphology (issue #204, Stage 2)
 *
 * The hand-written override patterns only ever matched the base verb in the
 * active voice — `ignore previous instructions`. `Ignoring all previous
 * instructions`, `the prior directives were overridden` and `stop following any
 * previous rules` all walked past both regex tiers untouched. The fix is NOT a
 * longer synonym list (you cannot enumerate a language); it is a small pure
 * generator over four CLOSED tables, compiled once into three frames.
 *
 *   verbs    ignore disregard forget override bypass discard drop reset
 *   forms    base, -s/-es, past, past participle, -ing  (+ 3 irregulars)
 *   objects  previous prior above earlier existing old original
 *   nouns    instructions rules prompts context directives constraints guidelines
 *            filters
 *
 * Every frame requires an OBJECT **and** a NOUN from the closed tables. That
 * requirement is the false-positive floor, and it is deliberate:
 *
 *   "I ignored the previous warning and continued the build"  → no in-set noun
 *   "Please disregard this email if you already replied"      → no object/noun
 *
 * Dropping either requirement to catch a bare `disregard the above` would light
 * up ordinary engineering prose, so we hold. Paraphrase beyond these frames is
 * the async semantic layer's job, not this tier's.
 */

/** Closed verb table — override intent only. Not a general "bad verb" list. */
export const OVERRIDE_VERBS = [
  'ignore',
  'disregard',
  'forget',
  'override',
  'bypass',
  'discard',
  'drop',
  'reset',
] as const;

/** Closed object table — what the payload points backwards at. */
export const OVERRIDE_OBJECTS = [
  'previous',
  'prior',
  'above',
  'earlier',
  'existing',
  'old',
  'original',
] as const;

/**
 * Closed noun table (regex fragments — the trailing `?` carries the plural).
 * `warning`, `email`, `message` are deliberately absent: those are the words
 * that make ordinary prose look like an attack.
 *
 * `filters?` belongs with the other guard-adjacent nouns. `policies?` is not
 * here: it would buy nothing on the current floor and would break the length
 * cap.
 */
export const OVERRIDE_NOUNS = [
  'instructions?',
  'rules?',
  'prompts?',
  'context',
  'directives?',
  'constraints?',
  'guidelines?',
  'filters?',
] as const;

/**
 * The three verbs English does not inflect regularly here. `drop` is absent on
 * purpose — the consonant-doubling rule below produces dropped/dropping without
 * a table entry, and every entry we can derive is one we cannot get wrong.
 */
const IRREGULAR_FORMS: Record<string, { past: string[]; participles: string[]; gerund: string }> = {
  forget: { past: ['forgot'], participles: ['forgotten'], gerund: 'forgetting' },
  override: { past: ['overrode'], participles: ['overridden'], gerund: 'overriding' },
  reset: { past: ['reset'], participles: ['reset'], gerund: 'resetting' },
};

const VOWELS = 'aeiou';

/** Consonant–vowel–consonant ending, which English doubles before a suffix. */
function doublesFinalConsonant(base: string): boolean {
  if (base.length < 3) return false;
  const [c1, v, c2] = base.slice(-3);
  return (
    !VOWELS.includes(c1) &&
    VOWELS.includes(v) &&
    !VOWELS.includes(c2) &&
    !'wxy'.includes(c2)
  );
}

function thirdPerson(base: string): string {
  return /(?:s|x|z|ch|sh)$/.test(base) ? `${base}es` : `${base}s`;
}

function regularPast(base: string): string {
  if (base.endsWith('e')) return `${base}d`;
  if (doublesFinalConsonant(base)) return `${base}${base.slice(-1)}ed`;
  return `${base}ed`;
}

function gerund(base: string): string {
  const irregular = IRREGULAR_FORMS[base]?.gerund;
  if (irregular) return irregular;
  if (base.endsWith('e')) return `${base.slice(0, -1)}ing`;
  if (doublesFinalConsonant(base)) return `${base}${base.slice(-1)}ing`;
  return `${base}ing`;
}

/**
 * Past participles only — the forms that can follow `be`/`were` in the passive
 * frame. `forgetting` is a gerund, not a participle, so it must not appear here.
 */
export function pastParticiples(base: string): string[] {
  const irregular = IRREGULAR_FORMS[base];
  return [...new Set(irregular ? irregular.participles : [regularPast(base)])];
}

/** Every inflection of a base verb we match on. Pure: same input, same output. */
export function verbForms(base: string): string[] {
  const irregular = IRREGULAR_FORMS[base];
  return [
    ...new Set([
      base,
      thirdPerson(base),
      ...(irregular ? [...irregular.past, ...irregular.participles] : [regularPast(base)]),
      gerund(base),
    ]),
  ];
}

/** Longest-first keeps the alternation cheap (no backtrack to a longer arm). */
function alternation(forms: readonly string[]): string {
  return [...forms].sort((a, b) => b.length - a.length).join('|');
}

const VERB_FORMS = alternation(OVERRIDE_VERBS.flatMap(verbForms));
const PARTICIPLES = alternation(OVERRIDE_VERBS.flatMap(pastParticiples));
const OBJECTS = alternation(OVERRIDE_OBJECTS);
const NOUNS = OVERRIDE_NOUNS.join('|');

/** `all of` / `any of` — optional quantifier, no quantifier over a quantifier. */
const QUANTIFIER = String.raw`(?:(?:all|any)\s+(?:of\s+)?)?`;
/** Optional determiner. Closed set; `this`/`that` stay out (see `this email`). */
const DETERMINER = String.raw`(?:(?:the|your|these|those|our|my|its)\s+)?`;
/** Auxiliaries that can front a past participle in the passive frame. */
const PASSIVE_AUX = String.raw`(?:(?:should|must|can|could|may|might|will|shall|needs?\s+to|ought\s+to|are\s+to|is\s+to|to)\s+be|(?:was|were|is|are|has\s+been|have\s+been|had\s+been|being))`;

export interface MorphologyPattern {
  /** Stable rule id — surfaces in audit rows on both detector paths. */
  name: string;
  description: string;
  regex: RegExp;
}

/**
 * Three frames, one compiled regex each. Case-insensitive and NON-global: these
 * are shared module-level objects tested with `.test()`, and a `g` flag would
 * make them stateful across calls. The scanner recompiles with `g` for its
 * exec loop.
 */
export const OVERRIDE_MORPHOLOGY: MorphologyPattern[] = [
  {
    name: 'override_morphology_active',
    description:
      'Override intent in the active voice, any inflection (e.g. "ignoring all previous instructions")',
    regex: new RegExp(
      String.raw`\b(?:${VERB_FORMS})\s+${QUANTIFIER}${DETERMINER}(?:${OBJECTS})\s+(?:${NOUNS})\b`,
      'i',
    ),
  },
  {
    name: 'override_morphology_passive',
    description:
      'Override intent in the passive voice (e.g. "all previous instructions should be disregarded")',
    regex: new RegExp(
      String.raw`\b${QUANTIFIER}${DETERMINER}(?:${OBJECTS})\s+(?:${NOUNS})\s+${PASSIVE_AUX}\s+(?:${PARTICIPLES})\b`,
      'i',
    ),
  },
  {
    name: 'override_morphology_stop_following',
    description:
      'Negated-compliance framing (e.g. "do not follow the earlier instructions")',
    regex: new RegExp(
      String.raw`\b(?:do\s+not|don['’]?t|does\s+not|doesn['’]?t|stop|quit|cease|no\s+longer)\s+follow(?:ing|s)?\s+${QUANTIFIER}${DETERMINER}(?:${OBJECTS})\s+(?:${NOUNS})\b`,
      'i',
    ),
  },
];

/**
 * Direct system-prompt extraction, narrow by design: an imperative reveal verb
 * plus `your` plus `prompt`. `your` is load-bearing — it is what separates
 * "show your system prompt" from "update the system prompt template in the docs".
 *
 * `output`, `dump` and `list` sit with `print/show/reveal/display`. `your`
 * still gates every one of them, so "dump the request log" and "list the
 * prompt templates" stay quiet.
 */
export const PROMPT_EXTRACTION: MorphologyPattern[] = [
  {
    name: 'system_prompt_extraction',
    description:
      'Direct request to print, show, reveal, display, output, dump or list the system prompt',
    regex:
      /\b(?:print|show|reveal|display|output|dump|list)\s+(?:(?:me|us)\s+)?your\s+(?:(?:full|entire|complete|original|initial|exact|actual|verbatim)\s+)?(?:system\s+)?prompts?\b/i,
  },
];

export const OVERRIDE_MORPHOLOGY_PATTERNS: RegExp[] = OVERRIDE_MORPHOLOGY.map(p => p.regex);
export const PROMPT_EXTRACTION_PATTERNS: RegExp[] = PROMPT_EXTRACTION.map(p => p.regex);
