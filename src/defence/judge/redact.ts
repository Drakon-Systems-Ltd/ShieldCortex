import { detectPII, redactJsonForPersistence, isPIIRedactionEnabled } from '../sensitivity/pii.js';
import type { PIIKind } from '../sensitivity/pii.js';
import type { ReviewAnnotation } from './types.js';

/**
 * #538: the annotation store is a persistence boundary.
 *
 * The Review Copilot reads a quarantine row and writes about it. Its
 * `evidence[].snippet` entries are verbatim spans of `original_content`, and
 * `summary`, `reasoning` and `similarGroupKey` are free text it composed
 * from that content. All of them are run through the #510 write-time redactor
 * together (an identifier in one takes the contact details in all of them,
 * exactly as for a memory row). The structural fields — `itemId`, `category`,
 * `suggestedAction`, `confidence`, `copilotVersion`, `generatedAt`,
 * `synthetic` — are enumerations, numbers and stamps and are left alone.
 *
 * Second pass, specific to this boundary: the model tends to re-quote an
 * identifier WITHOUT its label ("Identifier QQ123456C quoted verbatim"), and
 * the #510 detector deliberately does not claim an unlabelled identifier-
 * shaped token (residual (1): without a label it is indistinguishable from a
 * hex digest). But here the labelled form is almost always present too — the
 * evidence snippet is verbatim source text — so every identifier VALUE the
 * detector found anywhere in the annotation is scrubbed by exact match from
 * every other free-text field. An identifier the model reformatted (spaces
 * inserted, case changed) is not caught by this pass; that is a disclosed
 * residual, the same one #510 carries for memories.
 *
 * Returns the SAME object when nothing needed redacting (or redaction is
 * switched off), so a caller can tell "unchanged" by identity and avoid
 * rewriting a row it did not change.
 *
 * This module deliberately imports nothing from `database/`, so the migration
 * runner can call it without an import cycle.
 */
export function redactAnnotationForPersistence(annotation: ReviewAnnotation): ReviewAnnotation {
  if (!isPIIRedactionEnabled()) return annotation;

  const { summary, evidence, reasoning, similarGroupKey } = annotation;
  const subset = { summary, evidence, reasoning, similarGroupKey };

  const known = collectIdentifierValues(subset);
  const held = redactJsonForPersistence(subset);
  const scrubbed = known.size > 0 ? scrubKnownValues(held, known) : held;

  if (scrubbed === subset) return annotation;
  return { ...annotation, ...(scrubbed as typeof subset) };
}

/** Shortest identifier value worth an exact-match scrub (a UK NI number is 9). */
const MIN_SCRUB_LENGTH = 5;

/** Every identifier value (offsets are into the ORIGINAL text) found in any string of the tree. */
function collectIdentifierValues(value: unknown): Map<string, PIIKind> {
  const found = new Map<string, PIIKind>();
  visitStrings(value, (text) => {
    for (const finding of detectPII(text)) {
      if (!finding.identifier) continue;
      const raw = text.slice(finding.start, finding.end);
      if (raw.length < MIN_SCRUB_LENGTH || found.has(raw)) continue;
      found.set(raw, finding.kind);
    }
    return text;
  });
  return found;
}

/** Replace each known identifier value, exactly, everywhere; returns the same object when nothing matched. */
function scrubKnownValues<T>(value: T, known: Map<string, PIIKind>): T {
  let changed = false;
  const out = visitStrings(value, (text) => {
    let next = text;
    for (const [raw, kind] of known) {
      if (!next.includes(raw)) continue;
      next = next.split(raw).join(`[REDACTED:${kind}]`);
    }
    if (next !== text) changed = true;
    return next;
  });
  return changed ? (out as T) : value;
}

/** Map every string in a plain-JSON tree (strings, arrays, objects); other leaves pass through. */
function visitStrings(value: unknown, fn: (text: string) => string): unknown {
  if (typeof value === 'string') return fn(value);
  if (Array.isArray(value)) return value.map((item) => visitStrings(item, fn));
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) out[key] = visitStrings(item, fn);
    return out;
  }
  return value;
}
