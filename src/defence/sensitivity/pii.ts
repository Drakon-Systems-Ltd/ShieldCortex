/**
 * Deterministic PII detection and write-time redaction (#510, SC-11).
 *
 * Identifiers (NI number, SSN, labelled tax ids, salary figures) are replaced
 * in place with `[REDACTED:<kind>]`. Contact details (email, phone) are only
 * redacted when the same record also holds an identifier — a bare vendor contact
 * stays readable. PII never blocks a write.
 *
 * Matching runs over a NORMALISED copy (NFKC, Unicode decimal digits → ASCII,
 * zero-width/bidi controls dropped, Unicode dashes → "-") so fullwidth,
 * Arabic-Indic and zero-width-split values are caught; the span that is
 * replaced is always mapped back onto the ORIGINAL text.
 *
 * Every regex here is linear: no nested quantifiers, and every repeat that
 * shares characters with its neighbour is bounded.
 */

/**
 * Every kind a `[REDACTED:<kind>]` token can carry — the one source of truth
 * for the detector and for anything that recognises a stored token.
 * `unscanned` marks a metadata subtree dropped at the depth/size bound.
 */
export const PII_KINDS = ['ni-number', 'ssn', 'tax-id', 'salary', 'email', 'phone', 'unscanned'] as const;

export type PIIKind = (typeof PII_KINDS)[number];

export interface PIIFinding {
  kind: PIIKind;
  start: number;
  end: number;
  /** true for identifiers; false for contact details that only ride along. */
  identifier: boolean;
}

export interface PIIRedactionResult {
  text: string;
  redacted: boolean;
  /** Sorted, de-duplicated kinds that were redacted. */
  kinds: PIIKind[];
}

interface PIIPattern {
  kind: PIIKind;
  identifier: boolean;
  pattern: RegExp;
  /** When set, only this capture group (always the tail of the match) is the value. */
  valueGroup?: number;
  /** Structural check on the matched value and the text just before it. */
  accept?: (value: string, before: string) => boolean;
}

// Separator between a label and its value: "salary: ", "UTR = ", "salary is ".
const SEP = String.raw`[\s:=#-]{0,6}(?:(?:is|of|was)\s{1,3})?`;
const AMOUNT = String.raw`(?:(?:GBP|USD|EUR)\s?)?[£$€]?(?:\d{1,3}(?:[,.]\d{3}){1,3}|\d{2,7})(?:\.\d{1,2})?[kK]?(?![\dA-Za-z])`;
// Up to two spaces between the groups of a candidate token.
const SP = ' {0,2}';
const NI_BODY = String.raw`${SP}\d{2}${SP}\d{2}${SP}\d{2}${SP}`;

// A number introduced as an order/ticket/build reference is not a person's
// SSN or phone number, whatever its shape.
const REFERENCE_CONTEXT = /\b(?:order|ticket|ref(?:erence)?|invoice|part|sku|build|case|po|serial|model|item|tracking|version|job|run|batch|release|product)(?:[ _-]?(?:no\.?|number|num|id|code))?[\s:#=-]{0,4}$/i;
const notAReference = (_value: string, before: string) => !REFERENCE_CONTEXT.test(before);

/** HMRC prefix rules: D F I Q U V unused in either position, O unused second, and seven unallocated pairs. */
function isAllocatedNIPrefix(value: string): boolean {
  const prefix = value.replace(/ /g, '').slice(0, 2).toUpperCase();
  if (/[DFIQUV]/.test(prefix) || prefix[1] === 'O') return false;
  return !['BG', 'GB', 'NK', 'KN', 'TN', 'NT', 'ZZ'].includes(prefix);
}

/** SSA rules: area not 000/666/9xx, group not 00, serial not 0000. */
function isIssuableSSN(value: string): boolean {
  const digits = value.replace(/\D/g, '');
  if (digits.length !== 9) return false;
  const area = digits.slice(0, 3);
  if (area === '000' || area === '666' || area[0] === '9') return false;
  return digits.slice(3, 5) !== '00' && digits.slice(5) !== '0000';
}

const PII_PATTERNS: PIIPattern[] = [
  // UK National Insurance number: two letters, six digits, suffix A–D.
  // Unlabelled: upper-case only (hex digests, part numbers) and an allocated prefix.
  {
    kind: 'ni-number',
    identifier: true,
    pattern: new RegExp(String.raw`\b[A-Z]{2}${NI_BODY}[A-D]\b`, 'g'),
    accept: isAllocatedNIPrefix,
  },
  // Labelled: any case and any prefix — the label is the evidence.
  {
    kind: 'ni-number',
    identifier: true,
    pattern: new RegExp(String.raw`\b(?:national insurance(?: number| no\.?)?|nino|ni(?: number| no\.?)?)${SEP}([a-z]{2}${NI_BODY}[a-d])\b`, 'gi'),
    valueGroup: 1,
  },

  // US SSN: dashed anywhere unless introduced as a reference number; dotted,
  // spaced or undashed only with a label.
  {
    kind: 'ssn',
    identifier: true,
    pattern: /(?<![\w-])\d{3}-\d{2}-\d{4}(?![\w-])/g,
    accept: (value, before) => isIssuableSSN(value) && notAReference(value, before),
  },
  {
    kind: 'ssn',
    identifier: true,
    pattern: new RegExp(String.raw`\b(?:ssn|social security(?: number| no\.?)?)${SEP}(\d{3}[-. ]?\d{2}[-. ]?\d{4})(?!\d)`, 'gi'),
    valueGroup: 1,
    accept: isIssuableSSN,
  },

  // Tax identifiers are just digit runs, so they always need a label.
  {
    kind: 'tax-id',
    identifier: true,
    pattern: new RegExp(String.raw`\b(?:utr|unique taxpayer reference|ein|employer identification number|tin|tax(?:payer)? id(?:entification)?(?: number| no\.?)?)${SEP}(\d{2}-\d{7}|\d(?: ?\d){8,9})(?!\d)`, 'gi'),
    valueGroup: 1,
  },

  // Salary figures need salary context; a bare number is never a salary.
  {
    kind: 'salary',
    identifier: true,
    pattern: new RegExp(String.raw`\b(?:salary|salaries|wages?|compensation|remuneration|stipend|pay ?rate|base pay|annual pay)${SEP}(${AMOUNT})`, 'gi'),
    valueGroup: 1,
  },

  // Contact details.
  { kind: 'email', identifier: false, pattern: /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,8}(?![A-Za-z0-9-])/g },
  // UK: 10–11 digits in the usual groupings, so a 9-digit build number is not a phone.
  {
    kind: 'phone',
    identifier: false,
    pattern: /(?<![\w+])(?:\+44 ?(?:\(0\) ?)?|0)(?:\d{2} ?\d{4} ?\d{4}|\d{3,4} ?\d{3} ?\d{3,4}|\d{4} ?\d{5,6})(?!\d)/g,
    accept: notAReference,
  },
  {
    kind: 'phone',
    identifier: false,
    pattern: /(?<![\w+])(?:\+?1[-. ]?)?(?:\(\d{3}\) ?|\d{3}[-. ])\d{3}[-. ]\d{4}(?!\d)/g,
    accept: notAReference,
  },
];

// ── Normalisation ────────────────────────────────────────

// Zero-width, bidi and other invisible format characters (incl. soft hyphen, variation selectors).
const INVISIBLE = /[\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180B-\u180E\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFE00-\uFE0F\uFEFF]/;
const UNICODE_DASH = /[\u2010-\u2015\u2212\uFE58\uFE63\uFF0D]/;
const DECIMAL_DIGIT = /^\p{Nd}$/u;
const ASCII_ONLY = /^[\x00-\x7F]*$/;

/** Value of a non-ASCII decimal digit: every Unicode Nd block is a contiguous run 0–9. */
function decimalDigitValue(codePoint: number): number {
  let value = 0;
  while (value < 9 && DECIMAL_DIGIT.test(String.fromCodePoint(codePoint - value - 1))) value++;
  return value;
}

interface NormalisedText {
  text: string;
  /** Per normalised code unit: [start, end) of its source character in the original. null = identity. */
  starts: number[] | null;
  ends: number[] | null;
}

function normaliseForMatching(original: string): NormalisedText {
  if (ASCII_ONLY.test(original)) return { text: original, starts: null, ends: null };

  const out: string[] = [];
  const starts: number[] = [];
  const ends: number[] = [];
  let index = 0;
  for (const char of original) {
    const start = index;
    index += char.length;
    let mapped = char;
    if (char.charCodeAt(0) >= 0x80) {
      if (INVISIBLE.test(char)) continue;
      mapped = '';
      for (const part of char.normalize('NFKC')) {
        if (part.charCodeAt(0) < 0x80) mapped += part;
        else if (UNICODE_DASH.test(part)) mapped += '-';
        else if (DECIMAL_DIGIT.test(part)) mapped += String(decimalDigitValue(part.codePointAt(0)!));
        else mapped += part;
      }
    }
    for (let i = 0; i < mapped.length; i++) {
      out.push(mapped[i]);
      starts.push(start);
      ends.push(index);
    }
  }
  return { text: out.join(''), starts, ends };
}

// ── Detection ────────────────────────────────────────────

/** Keep the first of each overlapping run; input must be sorted by start. */
function dropOverlaps(sorted: PIIFinding[]): PIIFinding[] {
  const kept: PIIFinding[] = [];
  let lastEnd = -1;
  for (const finding of sorted) {
    if (finding.start < lastEnd) continue;
    kept.push(finding);
    lastEnd = finding.end;
  }
  return kept;
}

/**
 * Find PII spans (offsets into the ORIGINAL text). Identifier findings win over
 * contact findings that overlap them (a UTR is not also a phone number).
 * Result is sorted by position. `label` is scanned as if it preceded the text
 * (a metadata key such as "salary"), and is never part of a finding.
 */
export function detectPII(text: string, label?: string): PIIFinding[] {
  const prefix = label ? `${label.replace(/[_-]+/g, ' ')}: ` : '';
  const normalised = normaliseForMatching(prefix + text);
  const found: PIIFinding[] = [];
  for (const { kind, identifier, pattern, valueGroup, accept } of PII_PATTERNS) {
    // Clone the regex to avoid shared lastIndex state
    const re = new RegExp(pattern.source, pattern.flags);
    for (const match of normalised.text.matchAll(re)) {
      const value = valueGroup ? match[valueGroup] : match[0];
      if (!value) continue;
      const normEnd = (match.index ?? 0) + match[0].length;
      const normStart = normEnd - value.length;
      if (accept && !accept(value, normalised.text.slice(Math.max(0, normStart - 40), normStart))) continue;
      const start = (normalised.starts ? normalised.starts[normStart] : normStart) - prefix.length;
      const end = (normalised.ends ? normalised.ends[normEnd - 1] : normEnd) - prefix.length;
      if (start < 0) continue;
      found.push({ kind, identifier, start, end });
    }
  }

  // Sorted interval sweep: identifiers first, then contacts that clear them.
  const byStart = (a: PIIFinding, b: PIIFinding) => a.start - b.start || b.end - a.end;
  const identifiers = dropOverlaps(found.filter(f => f.identifier).sort(byStart));
  const contacts: PIIFinding[] = [];
  let next = 0;
  for (const contact of found.filter(f => !f.identifier).sort(byStart)) {
    while (next < identifiers.length && identifiers[next].end <= contact.start) next++;
    if (next < identifiers.length && identifiers[next].start < contact.end) continue;
    contacts.push(contact);
  }
  return [...identifiers, ...dropOverlaps(contacts)].sort(byStart);
}

/**
 * Redact identifiers in place; contact details only when an identifier is present.
 */
export function redactPII(
  text: string,
  options?: {
    /** An identifier sits in a sibling field (title vs content), so contacts here go too. */
    identifierElsewhere?: boolean;
    /** Label context for the value, e.g. the metadata key it is stored under. */
    label?: string;
  },
): PIIRedactionResult {
  const findings = detectPII(text, options?.label);
  if (findings.length === 0 || !(options?.identifierElsewhere || findings.some(f => f.identifier))) {
    return { text, redacted: false, kinds: [] };
  }

  const parts: string[] = [];
  let cursor = 0;
  for (const { kind, start, end } of findings) {
    parts.push(text.slice(cursor, start), `[REDACTED:${kind}]`);
    cursor = end;
  }
  parts.push(text.slice(cursor));

  const kinds = [...new Set(findings.map(f => f.kind))].sort();
  return { text: parts.join(''), redacted: true, kinds };
}

/** `SHIELDCORTEX_PII_REDACTION=off` disables redaction; labelling is unaffected. */
export function isPIIRedactionEnabled(): boolean {
  const flag = process.env.SHIELDCORTEX_PII_REDACTION?.trim().toLowerCase();
  return flag !== 'off' && flag !== '0' && flag !== 'false';
}

const REDACTION_TOKEN = new RegExp(String.raw`\[REDACTED:(?:${PII_KINDS.join('|')})\]`);

/**
 * True when stored text already carries a write-time redaction token. Only a
 * COMPLETE token of a kind the detector emits counts — a typed `[REDACTED:fake`
 * is ordinary text.
 */
export function hasRedactionToken(text: string | null | undefined): boolean {
  return typeof text === 'string' && REDACTION_TOKEN.test(text);
}

// ── Persistence boundary ─────────────────────────────────

export interface PersistableFields {
  title?: string | null;
  content?: string | null;
  /** An array, or the JSON-encoded array a row carries. */
  tags?: string[] | string | null;
  /** Any JSON value, or the JSON-encoded string a row carries. */
  metadata?: unknown;
}

export interface PersistenceRedaction<T> {
  fields: T;
  redacted: boolean;
  /** Sorted kinds found anywhere in the record. */
  kinds: PIIKind[];
}

const MAX_METADATA_DEPTH = 8;
const MAX_METADATA_NODES = 5000;

// Metadata keys that NAME the kind of their value (matched lower-cased with
// spaces, underscores and hyphens removed, so `tax_id`, `Tax-ID` and `taxId` agree).
const IDENTIFIER_KEYS: Array<[PIIKind, RegExp]> = [
  ['ni-number', /^(?:ni|nino|ni(?:number|no)|nationalinsurance(?:number|no)?)$/],
  ['ssn', /^(?:ssn|socialsecurity(?:number|no)?)$/],
  ['tax-id', /^(?:utr|uniquetaxpayerreference|ein|employeridentificationnumber|tin|tax(?:payer)?id(?:entification)?(?:number|no)?)$/],
  ['salary', /^(?:salary|salaries|pay|wages?|compensation|remuneration|stipend|payrate|basepay|annualpay)$/],
];

// Child keys that DESCRIBE an identifier rather than hold it: the parent's kind
// is not inherited into them (`{salary:{amount, year, currency}}` loses only
// `amount`). Their strings are still pattern-scanned like any other value.
const DESCRIPTOR_KEYS = /^(?:year|date|period|frequency|currency|band|grade|type|id|notes?|source|updated|created)$/;

function bareKey(key: string): string {
  return key.toLowerCase().replace(/[\s_-]+/g, '');
}

function identifierKeyKind(key: string): PIIKind | undefined {
  const bare = bareKey(key);
  return IDENTIFIER_KEYS.find(([, pattern]) => pattern.test(bare))?.[0];
}

type LeafVisitor = (value: string, label?: string) => string;

interface JsonWalker {
  visit: LeafVisitor;
  /** The value is redacted whole: an identifier by its key alone, or a subtree past the scan bounds. */
  force: (kind: PIIKind) => string;
}

interface WalkState {
  nodes: number;
  depth: number;
  label?: string;
  /** Kind named by the nearest identifier key above this value. */
  keyKind?: PIIKind;
}

/**
 * Rebuild a JSON value with every string (keys included) passed through the
 * walker. Values under an identifier key are redacted whatever their type.
 * FAIL SAFE at the depth/size bound: the unscanned subtree is replaced, never
 * passed through. Date, Buffer/typed arrays, Map and Set keep their type.
 */
function mapJsonStrings(value: unknown, walker: JsonWalker, state: WalkState): unknown {
  const { label, keyKind } = state;
  if (typeof value === 'string') {
    // Under an identifier key any digit takes the WHOLE value. A redaction token
    // in the input exempts nothing ("[REDACTED:salary] 1234567890" is still raw);
    // a bare token has no digit, so an already-redacted value is left alone.
    if (keyKind && /\p{Nd}/u.test(value)) return walker.force(keyKind);
    return walker.visit(value, label);
  }
  if (typeof value === 'number' || typeof value === 'bigint') return keyKind ? walker.force(keyKind) : value;
  if (value === null || typeof value !== 'object') return value;

  // A Date has no enumerable own properties (it would rebuild as {}): keep it a
  // Date — the stores JSON.stringify it to the same ISO string as before.
  if (value instanceof Date) return new Date(value.getTime());
  // Binary data carries no scannable text; rebuilding it by index would corrupt
  // it. Under an identifier key it IS the identifier, so it goes whole.
  if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) return keyKind ? walker.force(keyKind) : value;

  if (state.depth >= MAX_METADATA_DEPTH || state.nodes <= 0) return walker.force('unscanned');
  state.nodes--;

  const child = (item: unknown, key?: string): unknown => {
    const next: WalkState = {
      nodes: state.nodes,
      depth: state.depth + 1,
      label: key ?? label,
      keyKind: key === undefined
        ? keyKind
        : identifierKeyKind(key) ?? (DESCRIPTOR_KEYS.test(bareKey(key)) ? undefined : keyKind),
    };
    const mapped = mapJsonStrings(item, walker, next);
    state.nodes = next.nodes;
    return mapped;
  };
  const mapKey = (key: unknown): unknown => (typeof key === 'string' ? walker.visit(key) : key);

  if (Array.isArray(value)) return value.map(item => child(item));
  if (value instanceof Set) return new Set([...value].map(item => child(item)));
  if (value instanceof Map) {
    return new Map([...value].map(([key, item]) => [mapKey(key), child(item, typeof key === 'string' ? key : undefined)]));
  }
  const out: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    out[walker.visit(key)] = child(item, key);
  }
  return out;
}

/** Apply the walker inside a value that may be JSON-encoded, keeping its encoding. */
function mapJsonish(value: unknown, walker: JsonWalker): unknown {
  if (value === undefined || value === null) return value;
  const fresh = (): WalkState => ({ nodes: MAX_METADATA_NODES, depth: 0 });
  if (typeof value === 'string') {
    let parsed: unknown;
    try { parsed = JSON.parse(value); } catch { return walker.visit(value); }
    if (parsed === null || typeof parsed !== 'object') return walker.visit(value);
    return JSON.stringify(mapJsonStrings(parsed, walker, fresh()));
  }
  return mapJsonStrings(value, walker, fresh());
}

/**
 * THE write-time redactor: every persistence boundary (memory rows, FTS,
 * embedding input, events, sync outbox) stores what this returns. Title,
 * content, tags and every string inside metadata are redacted together — an
 * identifier in any of them takes the contact details in all of them. JSON
 * structure and encoding are preserved. No-op when redaction is switched off.
 */
export function redactForPersistence<T extends PersistableFields>(fields: T): PersistenceRedaction<T> {
  if (!isPIIRedactionEnabled()) return { fields, redacted: false, kinds: [] };

  const kinds = new Set<PIIKind>();
  let identifierFound = false;
  const survey: JsonWalker = {
    visit: (value, label) => {
      for (const finding of detectPII(value, label)) {
        if (finding.identifier) { identifierFound = true; kinds.add(finding.kind); }
      }
      return value;
    },
    force: kind => { identifierFound = true; kinds.add(kind); return ''; },
  };
  const walk = (walker: JsonWalker): T => {
    const out = { ...fields };
    if (typeof fields.title === 'string') out.title = walker.visit(fields.title);
    if (typeof fields.content === 'string') out.content = walker.visit(fields.content);
    if (fields.tags !== undefined && fields.tags !== null) out.tags = mapJsonish(fields.tags, walker) as T['tags'];
    if (fields.metadata !== undefined && fields.metadata !== null) out.metadata = mapJsonish(fields.metadata, walker);
    return out;
  };

  walk(survey);
  if (!identifierFound) return { fields, redacted: false, kinds: [] };

  const redacted = walk({
    visit: (value, label) => {
      const result = redactPII(value, { identifierElsewhere: true, label });
      for (const kind of result.kinds) kinds.add(kind);
      return result.text;
    },
    force: kind => `[REDACTED:${kind}]`,
  });
  return { fields: redacted, redacted: true, kinds: [...kinds].sort() };
}

/** {@link redactForPersistence} for a lone JSON value (or JSON-encoded string), e.g. a session event payload. */
export function redactJsonForPersistence<V>(value: V): V {
  return redactForPersistence({ metadata: value }).fields.metadata as V;
}
