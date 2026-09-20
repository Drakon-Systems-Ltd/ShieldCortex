/**
 * Deterministic PII detection and write-time redaction (#510, SC-11).
 *
 * Identifiers (NI number, SSN, labelled tax ids, salary figures) are replaced
 * in place with `[REDACTED:<kind>]`. Contact details (email, phone) are only
 * redacted when the same text also holds an identifier — a bare vendor contact
 * stays readable. PII never blocks a write.
 *
 * Every regex here is linear: no nested quantifiers, and every repeat that
 * shares characters with its neighbour is bounded.
 */

export type PIIKind = 'ni-number' | 'ssn' | 'tax-id' | 'salary' | 'email' | 'phone';

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
}

// Separator between a label and its value: "salary: ", "UTR = ", "salary is ".
const SEP = String.raw`[\s:=#-]{0,6}(?:(?:is|of|was)\s{1,3})?`;
const AMOUNT = String.raw`(?:(?:GBP|USD|EUR)\s?)?[£$€]?(?:\d{1,3}(?:[,.]\d{3}){1,3}|\d{2,7})(?:\.\d{1,2})?[kK]?(?![\dA-Za-z])`;

const PII_PATTERNS: PIIPattern[] = [
  // UK National Insurance number: two letters, six digits, suffix A–D.
  // Upper-case only when unlabelled, so hex digests and part numbers don't trip.
  { kind: 'ni-number', identifier: true, pattern: /\b[A-Z]{2} ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b/g },
  {
    kind: 'ni-number',
    identifier: true,
    pattern: new RegExp(String.raw`\b(?:national insurance(?: number| no\.?)?|nino|ni(?: number| no\.?)?)${SEP}([a-z]{2} ?\d{2} ?\d{2} ?\d{2} ?[a-d])\b`, 'gi'),
    valueGroup: 1,
  },

  // US SSN: dashed anywhere (never-issued area numbers excluded), undashed only with a label.
  { kind: 'ssn', identifier: true, pattern: /(?<![\w-])(?!000|666|9\d\d)\d{3}-\d{2}-\d{4}(?![\w-])/g },
  {
    kind: 'ssn',
    identifier: true,
    pattern: new RegExp(String.raw`\b(?:ssn|social security(?: number| no\.?)?)${SEP}(\d{9})(?!\d)`, 'gi'),
    valueGroup: 1,
  },

  // Tax identifiers are just digit runs, so they always need a label.
  {
    kind: 'tax-id',
    identifier: true,
    pattern: new RegExp(String.raw`\b(?:utr|unique taxpayer reference|ein|employer identification number|tin|tax(?:payer)? id(?:entification)?(?: number| no\.?)?)${SEP}(\d{2}-\d{7}|\d{5} \d{5}|\d{9,10})(?!\d)`, 'gi'),
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
  { kind: 'phone', identifier: false, pattern: /(?<![\w+])(?:\+44 ?(?:\(0\) ?)?|0)(?:\d{2} ?\d{4} ?\d{4}|\d{3,4} ?\d{3} ?\d{3,4}|\d{4} ?\d{5,6})(?!\d)/g },
  { kind: 'phone', identifier: false, pattern: /(?<![\w+])(?:\+?1[-. ]?)?(?:\(\d{3}\) ?|\d{3}[-. ])\d{3}[-. ]\d{4}(?!\d)/g },
];

function overlaps(a: PIIFinding, b: PIIFinding): boolean {
  return a.start < b.end && b.start < a.end;
}

/**
 * Find PII spans. Identifier findings win over contact findings that overlap
 * them (a UTR is not also a phone number). Result is sorted by position.
 */
export function detectPII(text: string): PIIFinding[] {
  const found: PIIFinding[] = [];
  for (const { kind, identifier, pattern, valueGroup } of PII_PATTERNS) {
    // Clone the regex to avoid shared lastIndex state
    const re = new RegExp(pattern.source, pattern.flags);
    for (const match of text.matchAll(re)) {
      const value = valueGroup ? match[valueGroup] : match[0];
      if (!value) continue;
      const end = (match.index ?? 0) + match[0].length;
      found.push({ kind, identifier, start: end - value.length, end });
    }
  }

  // Identifiers first, then by position, so overlap resolution keeps identifiers.
  found.sort((a, b) => Number(b.identifier) - Number(a.identifier) || a.start - b.start);
  const kept: PIIFinding[] = [];
  for (const finding of found) {
    if (!kept.some(k => overlaps(k, finding))) kept.push(finding);
  }
  return kept.sort((a, b) => a.start - b.start);
}

/**
 * Redact identifiers in place; contact details only when an identifier is present.
 */
export function redactPII(
  text: string,
  options?: { /** An identifier sits in a sibling field (title vs content), so contacts here go too. */ identifierElsewhere?: boolean },
): PIIRedactionResult {
  const findings = detectPII(text);
  if (findings.length === 0 || !(options?.identifierElsewhere || findings.some(f => f.identifier))) {
    return { text, redacted: false, kinds: [] };
  }

  let result = '';
  let cursor = 0;
  for (const { kind, start, end } of findings) {
    result += text.slice(cursor, start) + `[REDACTED:${kind}]`;
    cursor = end;
  }
  result += text.slice(cursor);

  const kinds = [...new Set(findings.map(f => f.kind))].sort();
  return { text: result, redacted: true, kinds };
}

/** `SHIELDCORTEX_PII_REDACTION=off` disables redaction; labelling is unaffected. */
export function isPIIRedactionEnabled(): boolean {
  const flag = process.env.SHIELDCORTEX_PII_REDACTION?.trim().toLowerCase();
  return flag !== 'off' && flag !== '0' && flag !== 'false';
}

/**
 * Redact a memory's title and content together: an identifier in either field
 * takes the contact details in both. No-op when redaction is switched off.
 */
export function redactMemoryPII<T extends { title?: string; content?: string }>(fields: T): T {
  if (!isPIIRedactionEnabled()) return fields;
  const joined = `${fields.title ?? ''}\n${fields.content ?? ''}`;
  if (!detectPII(joined).some(f => f.identifier)) return fields;
  const out = { ...fields };
  if (fields.title !== undefined) out.title = redactPII(fields.title, { identifierElsewhere: true }).text;
  if (fields.content !== undefined) out.content = redactPII(fields.content, { identifierElsewhere: true }).text;
  return out;
}
