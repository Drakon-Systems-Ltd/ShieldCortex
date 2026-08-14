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

  it('a pure hex filler prefix cannot suppress entropy redaction (#205: Azure no longer claims nested hex)', () => {
    // Pre-#205: bare [a-f0-9]{32} claimed a 32-hex substring of the 40-hex
    // filler; entropy then skipped the overlapping token and the secret
    // suffix leaked. Post-#205 Azure is hex-bounded so it does NOT match
    // inside a longer hex run — entropy alone must still catch the secret.
    const padded = 'a'.repeat(40) + UNKNOWN_SHAPE_SECRET;
    const result = scanForCredentials(padded);
    expect(result.leaked).toBe(true);
    expect(result.findings.some((f) => f.provider === 'azure')).toBe(false);
    expect(result.findings.some((f) => f.type === 'high_entropy')).toBe(true);
    expect(leaksRawSecret(padded, UNKNOWN_SHAPE_SECRET)).toBe(false);
  });

  it('a 32-char hex filler glued to a secret is still fully redacted by entropy', () => {
    // 32 hex + secret starting with hex letter is ONE contiguous hex-ish run
    // under Azure's bounded rule (lookahead fails). Entropy must cover it.
    const padded = 'f'.repeat(32) + UNKNOWN_SHAPE_SECRET;
    const result = scanForCredentials(padded);
    expect(result.leaked).toBe(true);
    expect(result.findings.some((f) => f.type === 'high_entropy')).toBe(true);
    expect(leaksRawSecret(padded, UNKNOWN_SHAPE_SECRET)).toBe(false);
  });

  it('a standalone 32-hex Azure-shaped token still matches Azure; adjacent unknown secret still redacts', () => {
    // Space separates so Azure can match the bounded 32-hex token.
    const azureKey = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';
    const content = `${azureKey} ${UNKNOWN_SHAPE_SECRET}`;
    const result = scanForCredentials(content);
    expect(result.findings.some((f) => f.provider === 'azure')).toBe(true);
    expect(result.findings.some((f) => f.type === 'high_entropy')).toBe(true);
    expect(leaksRawSecret(content, UNKNOWN_SHAPE_SECRET)).toBe(false);
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

  describe('review follow-up — filler unit length must not be bounded (one-keystroke evasion)', () => {
    it.each([
      ['9-char unit (the reported blocker)', 'aaaaaaaa-'],
      ['10-char unit', 'aaaaaaaaa-'],
      ['13-char unit', 'aaaaaaaaaaaa-'],
    ])('%s: still flags and redacts', (_label, unit) => {
      const padded = unit.repeat(12) + UNKNOWN_SHAPE_SECRET;
      const result = scanForCredentials(padded);
      expect(result.findings.some((f) => f.type === 'high_entropy')).toBe(true);
      expect(leaksRawSecret(padded, UNKNOWN_SHAPE_SECRET)).toBe(false);
    });
  });

  describe('review follow-up — partial pattern/entropy range overlap must not corrupt or leak', () => {
    it('a Basic Auth match that stops short of a longer entropy run does not corrupt the redaction', () => {
      // Basic Auth's captured charset [A-Za-z0-9+/=] stops at '-', but entropy's
      // charset includes '-', so entropy's contiguous run extends past where the
      // pattern match ends. The pattern's full match (starting at "Authorization")
      // also starts BEFORE the entropy run starts. Neither range contains the
      // other — a genuine crossing overlap ([0,45) vs [21,114)), not the nested
      // case `scanForCredentials` already de-dupes.
      //
      // Before the fix, `buildRedactedContent` replaced the [21,114) range
      // first (against the original 114-char content), then replaced [0,45)
      // against the ALREADY-SHRUNK ~44-char result — `result.slice(45)`
      // clamped to '', silently discarding the "[REDACTED-high_entropy]"
      // placeholder and the fact that most of the line had been redacted at
      // all. The observed (wrong) output was exactly '[REDACTED-api_key]'.
      const content = `Authorization: Basic YWxhZGRpbjpvcGVuc2VzYW1l-${UNKNOWN_SHAPE_SECRET}`;
      const result = scanForCredentials(content);
      const redacted = result.redactedContent ?? content;

      // Two independent findings are still reported (reporting is unaffected —
      // only the redaction span construction is).
      expect(result.findings).toHaveLength(2);
      expect(result.findings.some((f) => f.type === 'api_key')).toBe(true);
      expect(result.findings.some((f) => f.type === 'high_entropy')).toBe(true);

      expect(redacted).not.toContain(UNKNOWN_SHAPE_SECRET);
      expect(redacted).not.toMatch(/YWxhZGRpbjpvcGVuc2VzYW1l/);
      // The overlapping ranges are merged into ONE span covering the whole
      // line, labelled with the wider (entropy) replacement — not silently
      // collapsed down to just the narrower pattern placeholder.
      expect(redacted).toBe('[REDACTED-high_entropy]');
    });
  });
});

describe('review regressions — base64-padding FP rule must not swallow secrets', () => {
  it('SECRET + "===" is flagged and redacted (the sibling padding vector)', () => {
    const content = `${UNKNOWN_SHAPE_SECRET}===`;
    const result = scanForCredentials(content);
    expect(result.findings.some((f) => f.type === 'high_entropy')).toBe(true);
    expect(leaksRawSecret(content, UNKNOWN_SHAPE_SECRET)).toBe(false);
  });

  it('pure padding junk is still not flagged', () => {
    expect(scanForCredentials('='.repeat(24)).findings).toHaveLength(0);
    // low-entropy core + >=3 equals: the rule's real target, still clean
    expect(scanForCredentials(`${'abcd'.repeat(5)}====`).findings).toHaveLength(0);
  });
});

describe('review regressions — one finding per distinct secret (#256 invariant)', () => {
  it('ENV_VAR=<pattern-known secret> yields exactly ONE finding, still redacted', () => {
    // Concatenated per house convention so the synthetic fixture never appears
    // as a contiguous key to GitHub push protection (same as credential-leak.test.ts).
    const stripeKey = 'sk_live_' + '4eC39HqLyjWDarjtT1zdp7dc';
    const content = `FOO=${stripeKey}`;
    const result = scanForCredentials(content);
    expect(result.findings).toHaveLength(1);
    const redacted = result.redactedContent ?? content;
    expect(redacted).not.toContain(stripeKey);
  });

  it('two distinct secrets fused into one token still yield two findings', () => {
    // A BOUNDED pattern (AWS AKIA…{16}) covers only its own 20 chars; the
    // uncovered remainder is itself a full secret (>= the tokeniser's 20-char
    // minimum) and must keep its own entropy finding. (An open-ended pattern
    // like stripe's {24,} greedily fuses the whole blob into ONE match — that
    // case is one finding by construction and is not what this guards.)
    const content = `FOO=AKIAIOSFODNN7EXAMPLE${UNKNOWN_SHAPE_SECRET}`;
    const result = scanForCredentials(content);
    expect(result.findings.length).toBeGreaterThanOrEqual(2);
    const redacted = result.redactedContent ?? content;
    expect(redacted).not.toContain(UNKNOWN_SHAPE_SECRET);
    expect(redacted).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });
});
