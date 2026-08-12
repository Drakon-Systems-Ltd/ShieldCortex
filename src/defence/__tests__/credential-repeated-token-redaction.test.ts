import { describe, it, expect } from '@jest/globals';
import { scanForCredentials, redactCredentials } from '../credential-leak/index.js';

/**
 * REDACTION MUST COVER EVERY OCCURRENCE, NOT THE FIRST ONE.
 *
 * `extractHighEntropyTokens` de-duplicated candidates by token STRING, so when
 * the same secret appeared more than once only the first occurrence produced a
 * `matchedRange` — and `buildRedactedContent` cannot redact a range it was
 * never given. `redactCredentials` therefore returned successfully with the
 * secret still present in its output:
 *
 *   redactCredentials(S + ' ' + S + ' ' + S)  ->  2 raw copies survived
 *   redactCredentials(JSON with S twice)      ->  1 raw copy survived
 *
 * A redaction primitive that reports success while leaking is worse than one
 * that fails loudly, and this one feeds tool-response redaction and the
 * operator-facing report paths. The pattern layer never had the bug (a repeated
 * `sk-proj-…` was fully redacted), so it was specific to the entropy net — the
 * layer that exists precisely for secrets whose shape we do not know.
 *
 * The contract pinned here is about COVERAGE, not counting: how many findings a
 * repeat produces is a reporting choice and deliberately left unchanged, but
 * every occurrence must be redacted.
 */

/** No known pattern matches this, so only the entropy net can catch it. */
const UNKNOWN_SHAPE_SECRET = 'X7fQ2mZp9RtL4vNc8KwB3JhD6sYgA1eU5oXiTbMr0PlWnQzVfKjSxE9uYwGdTpAaCvBn';

/** A known-shape key, to prove the pattern layer's behaviour is untouched. */
const KNOWN_SHAPE_KEY = 'sk-proj-Ab3dEfGh1JkLmNoPqRsTuVwXyZ0123456789AbCdEfGhIjKlMnOpQrStUvWxYz';

function rawCopiesLeft(content: string, secret: string): number {
  return redactCredentials(content).split(secret).length - 1;
}

describe('entropy redaction covers every occurrence of a repeated secret', () => {
  it('leaves no raw copy when the secret appears three times', () => {
    const content = `${UNKNOWN_SHAPE_SECRET} ${UNKNOWN_SHAPE_SECRET} ${UNKNOWN_SHAPE_SECRET}`;

    expect(rawCopiesLeft(content, UNKNOWN_SHAPE_SECRET)).toBe(0);
  });

  it('leaves no raw copy when the secret is echoed inside a JSON body', () => {
    // The shape that made this reachable in practice: a session value stored
    // once and echoed back in a nested object.
    const content = JSON.stringify({
      session: UNKNOWN_SHAPE_SECRET,
      refresh: 'noise',
      echo: { session: UNKNOWN_SHAPE_SECRET },
    });

    expect(rawCopiesLeft(content, UNKNOWN_SHAPE_SECRET)).toBe(0);
  });

  it('still leaves no raw copy for a single occurrence', () => {
    // Must-not-break: the case that always worked.
    expect(rawCopiesLeft(UNKNOWN_SHAPE_SECRET, UNKNOWN_SHAPE_SECRET)).toBe(0);
  });

  it('reports the leak, and reporting volume is unchanged for a repeat', () => {
    const once = scanForCredentials(UNKNOWN_SHAPE_SECRET);
    const thrice = scanForCredentials(`${UNKNOWN_SHAPE_SECRET} ${UNKNOWN_SHAPE_SECRET} ${UNKNOWN_SHAPE_SECRET}`);

    expect(once.leaked).toBe(true);
    expect(thrice.leaked).toBe(true);
    // Deliberate: the fix is about redaction coverage. Turning one repeated
    // secret into N findings would inflate audit counts and severity grades for
    // no gain, so the reporting shape is held still.
    expect(thrice.findings.length).toBe(once.findings.length);
  });
});

describe('the pattern layer is untouched', () => {
  it('still redacts every occurrence of a known-shape key', () => {
    expect(rawCopiesLeft(`${KNOWN_SHAPE_KEY} ${KNOWN_SHAPE_KEY}`, KNOWN_SHAPE_KEY)).toBe(0);
  });

  it('still reports a known-shape key at its pattern severity', () => {
    const r = scanForCredentials(KNOWN_SHAPE_KEY);
    expect(r.findings.some(f => f.type !== 'high_entropy')).toBe(true);
  });
});

describe('mixed content redacts both layers', () => {
  it('redacts a repeated unknown-shape secret alongside a known-shape key', () => {
    const content = [
      `api_key=${KNOWN_SHAPE_KEY}`,
      `session=${UNKNOWN_SHAPE_SECRET}`,
      `echo=${UNKNOWN_SHAPE_SECRET}`,
    ].join('\n');

    const redacted = redactCredentials(content);

    expect(redacted).not.toContain(UNKNOWN_SHAPE_SECRET);
    expect(redacted).not.toContain(KNOWN_SHAPE_KEY);
  });
});
