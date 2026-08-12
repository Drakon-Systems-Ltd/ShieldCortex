import { describe, it, expect } from '@jest/globals';
import { scanForCredentials, redactCredentials } from '../credential-leak/index.js';
import { shannonEntropy, effectiveEntropy, ENTROPY_THRESHOLD } from '../credential-leak/entropy.js';

/**
 * #257 — padding a secret with repeated low-entropy filler dropped WHOLE-TOKEN
 * Shannon entropy below ENTROPY_THRESHOLD, so `checkHighEntropy` went silent:
 * no finding, and — because redaction ranges are derived from findings — no
 * redaction either. `redactCredentials` returned the raw secret untouched.
 *
 *   bare secret                     H=5.71  findings=1  raw secret survives: no
 *   'data-'.repeat(10) + secret     H=4.95  findings=1  raw secret survives: no
 *   'aaaa-'.repeat(12) + secret     H=4.31  findings=0  raw secret survives: YES  <-- silent bypass
 *
 * The fix (`effectiveEntropy` in entropy.ts) strips a repeated-unit filler run
 * from both ends of a token and rescores the remainder when the whole-token
 * score misses, then feeds that into BOTH gates that can suppress a token
 * before it is reported: `checkHighEntropy` (the detector) and the
 * npm-package-specifier rule in `isLikelyFalsePositive` (a filter that runs
 * BEFORE the detector and has the identical whole-token-entropy shape of bug —
 * fixing only `checkHighEntropy` left this padding shape invisible, because
 * the dash-separated filler+secret token also matches the npm-specifier shape
 * and was being screened out one gate earlier).
 *
 * A sliding fixed-size window (the other option sketched in #257) was tried
 * and rejected before landing on affix-stripping: measured against randomly
 * generated secrets, a 24-32 char window's empirical entropy is biased low by
 * sample size (birthday-style collisions inside a short window undercount true
 * alphabet diversity), missing a large fraction of genuinely random padded
 * secrets. Stripping the filler and rescoring the FULL remaining secret keeps
 * the sample size — and therefore the statistical reliability — of the
 * existing bare-secret path.
 */

/** No known pattern matches this — only the entropy net can catch it. Same fixture as #257 and PR #256's test. */
const UNKNOWN_SHAPE_SECRET = 'X7fQ2mZp9RtL4vNc8KwB3JhD6sYgA1eU5oXiTbMr0PlWnQzVfKjSxE9uYwGdTpAaCvBn';

function leaksRawSecret(content: string, secret: string): boolean {
  return redactCredentials(content).includes(secret);
}

describe('#257 — entropy detector silently bypassed by low-entropy padding', () => {
  it('bare secret: still flags and redacts (must-not-break baseline)', () => {
    const result = scanForCredentials(UNKNOWN_SHAPE_SECRET);
    expect(result.leaked).toBe(true);
    expect(result.findings.some((f) => f.type === 'high_entropy')).toBe(true);
    expect(leaksRawSecret(UNKNOWN_SHAPE_SECRET, UNKNOWN_SHAPE_SECRET)).toBe(false);
  });

  it("'data-'.repeat(10) + secret: flags and redacts", () => {
    const padded = 'data-'.repeat(10) + UNKNOWN_SHAPE_SECRET;
    const result = scanForCredentials(padded);
    expect(result.leaked).toBe(true);
    expect(result.findings.some((f) => f.type === 'high_entropy')).toBe(true);
    expect(leaksRawSecret(padded, UNKNOWN_SHAPE_SECRET)).toBe(false);
  });

  it("'aaaa-'.repeat(12) + secret: the reported bypass — now flags and redacts", () => {
    const padded = 'aaaa-'.repeat(12) + UNKNOWN_SHAPE_SECRET;

    // Pin the reported symptom: whole-token entropy alone is genuinely below
    // threshold, so a fix that scored only the whole token cannot pass this.
    expect(shannonEntropy(padded)).toBeLessThan(ENTROPY_THRESHOLD);

    const result = scanForCredentials(padded);
    expect(result.leaked).toBe(true);
    expect(result.findings.some((f) => f.type === 'high_entropy')).toBe(true);
    expect(leaksRawSecret(padded, UNKNOWN_SHAPE_SECRET)).toBe(false);
  });

  it('filler suffix (secret + repeated filler) also flags and redacts', () => {
    const padded = UNKNOWN_SHAPE_SECRET + '-aaaa'.repeat(12);
    const result = scanForCredentials(padded);
    expect(result.leaked).toBe(true);
    expect(leaksRawSecret(padded, UNKNOWN_SHAPE_SECRET)).toBe(false);
  });

  it('filler on both ends (prefix and suffix) flags and redacts', () => {
    const padded = 'zzzz-'.repeat(8) + UNKNOWN_SHAPE_SECRET + '-zzzz'.repeat(8);
    const result = scanForCredentials(padded);
    expect(result.leaked).toBe(true);
    expect(leaksRawSecret(padded, UNKNOWN_SHAPE_SECRET)).toBe(false);
  });

  it('a heavier repeated multi-char filler also flags and redacts', () => {
    const padded = 'wxyz-'.repeat(12) + UNKNOWN_SHAPE_SECRET;
    const result = scanForCredentials(padded);
    expect(result.leaked).toBe(true);
    expect(leaksRawSecret(padded, UNKNOWN_SHAPE_SECRET)).toBe(false);
  });

  it('a pure hex filler prefix that pattern-matches as an Azure key cannot suppress entropy redaction', () => {
    // Regression for the second-order #257 bypass: the generic hex/Azure
    // pattern used to claim only the low-entropy filler prefix. The later
    // entropy token overlapped that range and was skipped, so the real unknown
    // secret suffix survived in supposedly redacted output.
    const padded = 'a'.repeat(40) + UNKNOWN_SHAPE_SECRET;
    const result = scanForCredentials(padded);
    expect(result.leaked).toBe(true);
    expect(result.findings.some((f) => f.provider === 'azure')).toBe(true);
    expect(result.findings.some((f) => f.type === 'high_entropy')).toBe(true);
    expect(leaksRawSecret(padded, UNKNOWN_SHAPE_SECRET)).toBe(false);
  });

  it('the same pattern-overlap fix covers a 32-char hex filler prefix', () => {
    const padded = 'f'.repeat(32) + UNKNOWN_SHAPE_SECRET;
    const result = scanForCredentials(padded);
    expect(result.leaked).toBe(true);
    expect(result.findings.some((f) => f.type === 'high_entropy')).toBe(true);
    expect(leaksRawSecret(padded, UNKNOWN_SHAPE_SECRET)).toBe(false);
  });

  it('padding alone, with no secret attached, is NOT promoted to a finding', () => {
    // Stripping filler from both ends of pure filler leaves nothing (or a
    // remainder below MIN_ENTROPY_LENGTH) — must not manufacture a finding
    // out of filler that never contained a secret.
    const pureFiller = 'aaaa-'.repeat(12);
    const result = scanForCredentials(pureFiller);
    expect(result.findings.some((f) => f.type === 'high_entropy')).toBe(false);
  });

  it('effectiveEntropy matches shannonEntropy when there is no repeated filler to strip', () => {
    const ordinary = 'sk-frontend-production-deployment-blue-green';
    expect(effectiveEntropy(ordinary)).toBe(shannonEntropy(ordinary));
  });

  describe('regression: ordinary long benign identifiers stay clean (existing FP pins, unaffected)', () => {
    it.each([
      ['kubernetes-style resource name', 'sk-frontend-production-deployment-blue-green'],
      ['git branch name', 'feature/add-user-authentication-flow-v2'],
      ['file path', 'src/defence/credential-leak/patterns.ts'],
      ['docker image ref', 'registry.fly.io/shieldcortex-api:deployment-01KZ0BEEQE85SGZC'],
      ['CSS class list', 'btn-primary-large-rounded-shadow-hover-active'],
      ['npm package specifier', 'eslint-config-airbnb-typescript'],
      ['scoped npm package specifier', '@types/node-18.11.18'],
      ['repeated-word slug (filler-shaped, but no high-entropy core)', 'test-test-test-test-just-a-normal-descriptive-identifier-name'],
    ])('does not flag: %s', (_label, content) => {
      const result = scanForCredentials(content);
      expect(result.findings.some((f) => f.type === 'high_entropy')).toBe(false);
    });
  });

  it('a known-shape pattern secret padded the same way is unaffected (pattern layer bypasses entropy entirely)', () => {
    const KNOWN_SHAPE_KEY = 'sk-proj-Ab3dEfGh1JkLmNoPqRsTuVwXyZ0123456789AbCdEfGhIjKlMnOpQrStUvWxYz';
    const padded = 'aaaa-'.repeat(12) + KNOWN_SHAPE_KEY;
    const result = scanForCredentials(padded);
    expect(result.findings.some((f) => f.provider === 'openai')).toBe(true);
  });
});
