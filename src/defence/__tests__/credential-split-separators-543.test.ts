/**
 * #543 — credentials split by separators evade the provider patterns.
 *
 * The provider regexes only match contiguous text. A key written as
 * `sk-T3st K3yA bCdE …` (or split by a tab, newline, NBSP, zero-width space …)
 * produced ZERO findings on `main`, yet removing the separators rebuilds the
 * identical value, so anything that re-joins the text — or lets a model read
 * it — still exposes the secret.
 *
 * The fix runs the provider patterns a second time over a separator-collapsed
 * view of the content and maps every hit back to its ORIGINAL span, so the
 * finding's position and the redaction range cover the key AND the inserted
 * separators. Every value below is synthetic, generated for this test.
 *
 * Every "split" case fails if the collapsed pass is removed from
 * `scanForCredentials`; the precision cases fail if the pass is added without
 * the letter+digit gate and the structural prose gate. The `#544` blocks are
 * the review-round-3 blockers (B1 severity-safe resolution, B2 innermost-first
 * trimming, B3 linear trim cost, B4 structural headings and dilution) and the
 * round-4 findings (F1 the heading precision class, judged on a generated
 * corpus; F2 linear cost in the number of split keys; F3 a heading wrapped in
 * quotes, Markdown or JSON is judged like the bare heading; F4 linear cost
 * when the split keys are separated by spaces only) and the round-5 policy:
 * an AWS id split by visible whitespace alone is a stated gap, never a
 * finding; a hit split by an invisible character gets no prose escape.
 */

import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import { scanForCredentials } from '../credential-leak/index.js';
import type { CredentialFinding } from '../credential-leak/index.js';
import { initDatabase, closeDatabase } from '../../database/init.js';
import type { DefenceConfig } from '../types.js';

// ── Synthetic fixtures ──────────────────────────────────────────────────────
//
// Each value satisfies the provider regex in patterns.ts but was typed for this
// test; none has ever been issued by a provider.

// Prefix and body are joined at runtime so no complete key-shaped literal is
// committed: GitHub push protection matches the Stripe shape textually.
const k = (prefix: string, body: string): string => prefix + body;

const KEYS: Array<{ provider: string; key: string; severity: 'critical' | 'high' }> = [
  { provider: 'openai', key: k('sk-', 'T3stK3yAbCdEfGh1JkLmN0pQrStUv2WxYz'), severity: 'critical' },
  { provider: 'openai', key: k('sk-proj-', 'Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv'), severity: 'critical' },
  { provider: 'anthropic', key: k('sk-ant-api03-', 'Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9'), severity: 'critical' },
  // Base-32 body ([A-Z2-7]) like every issued AWS access key id (#544 round 4).
  { provider: 'aws', key: k('AKIA', 'Z7Q3F6XM2K5V4B3T'), severity: 'critical' },
  { provider: 'github', key: k('ghp_', 'Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx2'), severity: 'critical' },
  { provider: 'stripe', key: k('sk_live_', 'Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8'), severity: 'critical' },
  { provider: 'google', key: k('AIza', 'Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx'), severity: 'critical' },
  { provider: 'slack', key: k('xoxb-', '1234567890-Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8'), severity: 'critical' },
  { provider: 'npm', key: k('npm_', 'Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx2'), severity: 'critical' },
  { provider: 'huggingface', key: k('hf_', 'Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1W'), severity: 'critical' },
];

/**
 * Separators an attacker (or a line-wrapping transport) can insert, in the two
 * classes the scanner distinguishes (#544 round 5): VISIBLE whitespace, which
 * ordinary formatting inserts, and INVISIBLE format characters, which nothing
 * but deliberate splitting does.
 */
const SEPARATORS: Array<{ name: string; sep: string; invisible: boolean }> = [
  { name: 'space', sep: ' ', invisible: false },
  { name: 'double space', sep: '  ', invisible: false },
  { name: 'tab', sep: '\t', invisible: false },
  { name: 'newline', sep: '\n', invisible: false },
  { name: 'CRLF', sep: '\r\n', invisible: false },
  { name: 'NBSP', sep: '\u00a0', invisible: false },
  { name: 'space + newline + space', sep: ' \n ', invisible: false },
  { name: 'zero-width space', sep: '\u200b', invisible: true },
  { name: 'zero-width non-joiner', sep: '\u200c', invisible: true },
  { name: 'zero-width joiner', sep: '\u200d', invisible: true },
  { name: 'word joiner', sep: '\u2060', invisible: true },
  { name: 'BOM / ZWNBSP', sep: '\ufeff', invisible: true },
  { name: 'soft hyphen', sep: '\u00ad', invisible: true },
  { name: 'left-to-right mark', sep: '\u200e', invisible: true },
  { name: 'right-to-left override', sep: '\u202e', invisible: true },
  { name: 'first strong isolate', sep: '\u2068', invisible: true },
  { name: 'space + zero-width space', sep: ' \u200b', invisible: true },
];

const ZWSP = '\u200b';

/**
 * Heading-shaped patterns (the AWS id) are never claimed from a hit split by
 * visible whitespace alone (#544 round 5); every other provider is.
 */
const WHITESPACE_GAP = new Set(['aws']);

/** Insert `sep` after every `every` characters of `key` (never at index 0). */
function splitEvery(key: string, sep: string, every: number): string {
  const out: string[] = [];
  for (let i = 0; i < key.length; i += every) out.push(key.slice(i, i + every));
  return out.join(sep);
}

/** Insert `sep` once, half-way through the key. */
function splitOnce(key: string, sep: string): string {
  const mid = Math.floor(key.length / 2);
  return key.slice(0, mid) + sep + key.slice(mid);
}

/** The attacker's re-join: what a model or downstream consumer would do. */
function rejoin(text: string): string {
  return text.replace(/[\s\u00ad\u200b-\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]/g, '');
}

function providerFindings(findings: CredentialFinding[], provider: string): CredentialFinding[] {
  return findings.filter(f => f.type === 'api_key' && f.provider === provider);
}

// ── Positive controls — contiguous keys are still caught, exactly once ──────

describe('#543 positive controls (contiguous)', () => {
  for (const { provider, key, severity } of KEYS) {
    it(`${provider}: contiguous synthetic key is blocked once`, () => {
      const result = scanForCredentials(`note: ${key} end`);
      const hits = providerFindings(result.findings, provider);
      expect(hits).toHaveLength(1);
      expect(hits[0].severity).toBe(severity);
      expect(hits[0].action).toBe('blocked');
      expect(hits[0].evasion).toBeUndefined();
      expect(result.redactedContent).not.toContain(key);
    });
  }
});

// ── The bypass — split keys must be found, blocked and fully redacted ───────

describe('#543 separator-split keys are detected and redacted', () => {
  for (const { provider, key, severity } of KEYS) {
    for (const { name, sep, invisible } of SEPARATORS) {
      for (const [variant, text] of [
        ['split once', splitOnce(key, sep)],
        ['split every 4', splitEvery(key, sep, 4)],
        ['split every 2', splitEvery(key, sep, 2)],
      ] as const) {
        if (WHITESPACE_GAP.has(provider) && !invisible) {
          it(`${provider} / ${name} / ${variant}: stated gap — not claimed from visible whitespace alone`, () => {
            const result = scanForCredentials(`Store this for later: ${text} — thanks`);
            expect(providerFindings(result.findings, provider)).toHaveLength(0);
            expect(result.leaked).toBe(false);
          });
          continue;
        }
        it(`${provider} / ${name} / ${variant}`, () => {
          const prefix = 'Store this for later: ';
          const suffix = ' — thanks';
          const content = prefix + text + suffix;

          const result = scanForCredentials(content);
          expect(result.leaked).toBe(true);

          const hits = providerFindings(result.findings, provider);
          expect(hits).toHaveLength(1);
          expect(hits[0].severity).toBe(severity);
          expect(hits[0].action).toBe('blocked');
          expect(hits[0].evasion).toBe('separator_split');
          // Position is in ORIGINAL coordinates: the first char of the key.
          expect(hits[0].position).toBe(prefix.length);
          // Redacted preview is built from the collapsed value, never the raw one.
          expect(hits[0].match).not.toContain(sep);

          // The redaction covers the key AND the separators: re-joining the
          // redacted text must not rebuild the secret, and no fragment survives.
          const redacted = result.redactedContent ?? content;
          expect(rejoin(redacted)).not.toContain(key);
          expect(redacted).toBe(`${prefix}[REDACTED-api_key-${provider}]${suffix}`);
        });
      }
    }
  }

  it('leaves a direct match alone when a split leaves a head the direct pass already matched', () => {
    // 27 contiguous chars after `sk-` satisfy the legacy OpenAI rule on their
    // own, so the direct pass has already recorded and redacts the head. The
    // collapsed pass must not widen that range: what follows a complete match
    // may be a neighbour, not the rest of the key (#544 review), and a key
    // whose head is redacted is no longer a credential.
    const key = KEYS[0].key;
    const content = `key: ${key.slice(0, 30)} ${key.slice(30)} and`;
    const result = scanForCredentials(content);
    const hits = providerFindings(result.findings, 'openai');
    expect(hits).toHaveLength(1);
    expect(hits[0].evasion).toBeUndefined();
    expect(hits[0].position).toBe('key: '.length);
    expect(result.redactedContent).not.toContain(key.slice(0, 30));
    expect(rejoin(result.redactedContent ?? '')).not.toContain(key);
  });

  it('does not swallow an unrelated identifier after a contiguous key (#544 review)', () => {
    const key = KEYS[1].key;
    const result = scanForCredentials(`${key} customer123`);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].evasion).toBeUndefined();
    expect(result.redactedContent).toBe('[REDACTED-api_key-openai] customer123');
  });

  it('reports a contiguous key and a following finely split key of another provider separately (#544 review)', () => {
    const a = KEYS[1].key;
    const b = splitEvery(KEYS[4].key, ' ', 4);
    const result = scanForCredentials(`${a} ${b}`);
    expect(providerFindings(result.findings, 'openai')).toHaveLength(1);
    const gh = providerFindings(result.findings, 'github');
    expect(gh).toHaveLength(1);
    expect(gh[0].evasion).toBe('separator_split');
    expect(result.redactedContent).toBe('[REDACTED-api_key-openai] [REDACTED-api_key-github]');
  });

  it('finds every split key when several are present', () => {
    const a = splitEvery(KEYS[0].key, ' ', 5);
    const b = splitEvery(KEYS[3].key, ZWSP, 4);
    const result = scanForCredentials(`openai: ${a}\naws: ${b}\n`);
    expect(providerFindings(result.findings, 'openai')).toHaveLength(1);
    expect(providerFindings(result.findings, 'aws')).toHaveLength(1);
    expect(rejoin(result.redactedContent ?? '')).not.toContain(KEYS[0].key);
    expect(rejoin(result.redactedContent ?? '')).not.toContain(KEYS[3].key);
  });

  it('does not merge two contiguous keys separated by a word', () => {
    // `sk-… and ghp_…` collapses to one alphanumeric run; the direct pass has
    // already placed both keys, and the collapsed pass must not flow through
    // the second key's start and swallow it into the first finding.
    const a = KEYS[0].key;
    const b = KEYS[4].key;
    const result = scanForCredentials(`${a} and ${b}`);
    expect(providerFindings(result.findings, 'openai')).toHaveLength(1);
    expect(providerFindings(result.findings, 'github')).toHaveLength(1);
    expect(result.findings.every(f => f.evasion === undefined)).toBe(true);
    expect(result.redactedContent).toBe('[REDACTED-api_key-openai] and [REDACTED-api_key-github]');
  });

  it('does not merge two contiguous keys of the same provider separated by a space', () => {
    const k = KEYS[1].key;
    const result = scanForCredentials(`${k} ${k}`);
    expect(providerFindings(result.findings, 'openai')).toHaveLength(2);
    expect(result.findings.every(f => f.evasion === undefined)).toBe(true);
    expect(result.redactedContent).toBe('[REDACTED-api_key-openai] [REDACTED-api_key-openai]');
  });

  it('reports a split key and a following contiguous key separately', () => {
    // Split every 8 so the last fragment (`v2WxYz`) is key-like; a lone
    // trailing letter before ` and` would be the documented residual instead.
    const a = splitEvery(KEYS[0].key, ' ', 8);
    const b = KEYS[4].key;
    const result = scanForCredentials(`x ${a} and ${b}`);
    const openai = providerFindings(result.findings, 'openai');
    const github = providerFindings(result.findings, 'github');
    expect(openai).toHaveLength(1);
    expect(openai[0].evasion).toBe('separator_split');
    expect(github).toHaveLength(1);
    expect(github[0].evasion).toBeUndefined();
    expect(result.redactedContent).toBe('x [REDACTED-api_key-openai] and [REDACTED-api_key-github]');
  });

  it('does not swallow the word after a contiguous key (trailing trim)', () => {
    // `npm_…Wx2 end` collapses to one run that the open-ended pattern would
    // match whole; the trailing word is trimmed and the direct pass's exact
    // redaction is kept.
    for (const { provider, key } of KEYS) {
      const result = scanForCredentials(`note: ${key} end`);
      expect(result.redactedContent).toBe(`note: [REDACTED-api_key-${provider}] end`);
      expect(result.findings.every(f => f.evasion === undefined)).toBe(true);
    }
  });

  it('trims a 3+ letter word after a finely split key but keeps the key\'s own tail (#544 B2)', () => {
    // The trailing run of letter-only fragments is `z yes`; the word is `yes`
    // and `z` is the key's last character. Trimming stops at the innermost
    // word, so the whole key — including `z` — is redacted.
    const result = scanForCredentials(`k ${splitEvery(KEYS[0].key, ' ', 2)} yes`);
    const hits = providerFindings(result.findings, 'openai');
    expect(hits).toHaveLength(1);
    expect(hits[0].action).toBe('blocked');
    expect(hits[0].position).toBe(2);
    expect(result.redactedContent).toBe('k [REDACTED-api_key-openai] yes');
    expect(rejoin(result.redactedContent ?? '')).not.toContain(KEYS[0].key);
  });

  it('does not swallow the words after a split key', () => {
    const key = KEYS[4].key; // github, open-ended {36,}
    const result = scanForCredentials(`pat ${splitEvery(key, ' ', 6)} and rotate it`);
    expect(result.redactedContent).toBe('pat [REDACTED-api_key-github] and rotate it');
  });

  it('does not swallow the word before a prefix-less hex key', () => {
    // Twilio: `SK` + 32 hex. `face` is hex-alphabet prose before a split key.
    const key = k('SK', '0a1b2c3d4e5f60718293a4b5c6d7e8f9');
    const result = scanForCredentials(`face ${splitEvery(key, ' ', 4)} done`);
    const hits = providerFindings(result.findings, 'twilio');
    expect(hits).toHaveLength(1);
    expect(hits[0].position).toBe('face '.length);
    expect(result.redactedContent).toBe('face [REDACTED-api_key-twilio] done');
  });

  it('honours the allowlist on the collapsed value', () => {
    const key = KEYS[0].key;
    const result = scanForCredentials(splitEvery(key, ' ', 4), { allowlist: [key] });
    expect(providerFindings(result.findings, 'openai')).toHaveLength(0);
  });

  it('custom patterns take part in the collapsed pass', () => {
    const result = scanForCredentials('see acme_ 9Zx8 Yw7V u6Tt 5Ss4 Rr3Q q2Pp 1Oo', {
      customPatterns: [{
        name: 'Acme token',
        type: 'api_key',
        provider: 'acme',
        regex: /acme_[A-Za-z0-9]{24,}/g,
        severity: 'high',
        confidence: 0.9,
      }],
    });
    const hits = providerFindings(result.findings, 'acme');
    expect(hits).toHaveLength(1);
    expect(hits[0].evasion).toBe('separator_split');
  });
});

// ── Precision — ordinary prose that collapses into a key shape must not fire ─

describe('#543 precision: the collapsed pass does not fire on prose', () => {
  const PROSE: Array<[string, string]> = [
    // Shouted heading: `ASIA` + 21 uppercase letters once spaces are removed.
    ['aws', 'ASIA PACIFIC REGIONAL SALES MEETING NOTES'],
    // `key-` + exactly 32 letters then `.` — the Mailgun shape once spaces go.
    ['mailgun', 'The key-value pairs are stored in the database. For later use'],
    // `sk-` + 45 letters — the legacy OpenAI shape with the spaces removed.
    ['openai', 'I like to sk-etch drawings of the beautiful landscape near the river'],
    // A key PREFIX followed by a space and normal words.
    ['openai', 'sk-proj- keys replaced the legacy format in twenty twenty four'],
    // #544 review: a year or a quarter hands prose the digit the key-material
    // gate asks for. Most of the hit still reads as words, so it is dismissed.
    ['aws', 'ASIA 2026 REGIONAL SALES REPORT'],
    ['aws', 'ASIA Q3 REGIONAL SALES MEETING NOTES'],
    ['openai', 'sk-proj- keys replaced the legacy format in 2024'],
    ['github', 'ghp_ tokens are personal access tokens for the platform please rotate'],
    // Line-wrapped prose where a line ends in `sk-`.
    ['openai', 'the doctor asked me to sk-\nip the second appointment because of the strike'],
  ];

  for (const [provider, text] of PROSE) {
    it(`no ${provider} finding for: ${JSON.stringify(text)}`, () => {
      const result = scanForCredentials(text);
      expect(providerFindings(result.findings, provider)).toHaveLength(0);
    });
  }

  it('patterns that consult whitespace themselves are not run on the collapsed view', () => {
    // `PASSWORD: hunter2 and …` — the env-style value class is `[^\\s"']{8,}`,
    // so whitespace IS its delimiter. Collapsed, the capture would become the
    // rest of the sentence. The direct pass sees a 7-char value and stays
    // silent; the collapsed pass must stay silent too.
    const result = scanForCredentials('PASSWORD: hunter2 and then the rest of the sentence 42');
    expect(result.findings.filter(f => f.type === 'env_secret')).toHaveLength(0);
  });

  it('a split UUID is still a well-known public identifier, not a Heroku key', () => {
    const uuid = '3b1f0a9c-7d2e-4f6a-8b0c-1d2e3f4a5b6c';
    const result = scanForCredentials(`id: ${splitOnce(uuid, ' ')}`);
    expect(providerFindings(result.findings, 'heroku')).toHaveLength(0);
  });

  it('an unrelated key after whitespace is not glued onto a bare prefix', () => {
    // `sk-` followed by a newline and an ordinary sentence: no digit, no hit.
    const result = scanForCredentials('prefix is sk-\nand the rest of this line is just words here');
    expect(providerFindings(result.findings, 'openai')).toHaveLength(0);
  });

  it('the existing contiguous behaviour is unchanged for short prefixes', () => {
    expect(scanForCredentials('I like to sk-etch drawings').leaked).toBe(false);
    expect(scanForCredentials('Let me sk-ip that part').leaked).toBe(false);
  });
});

// ── #544 review round 3 ─────────────────────────────────────────────────────

/** Stripe TEST key: medium severity, open-ended `{24,}` body. */
const STRIPE_TEST = k('sk_test_', 'Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8');
/** Google key: critical, fixed-length body. */
const GOOGLE = k('AIza', 'Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx');

describe('#544 B1: a weaker finding never suppresses a stronger one', () => {
  it('control: the split Google key alone is critical/blocked', () => {
    const result = scanForCredentials(splitEvery(GOOGLE, ' ', 4));
    const google = providerFindings(result.findings, 'google');
    expect(google).toHaveLength(1);
    expect(google[0].severity).toBe('critical');
    expect(google[0].action).toBe('blocked');
  });

  it('split Stripe test key followed by split Google key: both reported, Google still blocked', () => {
    // On the previous head the open-ended Stripe pattern swallowed the Google
    // key in the collapsed view and the Google hit was dropped as "already
    // covered": one medium/warned finding for a critical leak.
    const a = splitEvery(STRIPE_TEST, ' ', 4);
    const b = splitEvery(GOOGLE, ' ', 4);
    const result = scanForCredentials(`${a} ${b}`);

    const stripe = providerFindings(result.findings, 'stripe');
    const google = providerFindings(result.findings, 'google');
    expect(stripe).toHaveLength(1);
    expect(stripe[0].severity).toBe('medium');
    expect(stripe[0].position).toBe(0);
    expect(google).toHaveLength(1);
    expect(google[0].severity).toBe('critical');
    expect(google[0].action).toBe('blocked');
    expect(google[0].position).toBe(a.length + 1);
    expect(result.findings.some(f => f.action === 'blocked')).toBe(true);
    expect(result.redactedContent).toBe('[REDACTED-api_key-stripe] [REDACTED-api_key-google]');
  });

  it('contiguous Stripe test key followed by a split Google key', () => {
    const result = scanForCredentials(`${STRIPE_TEST} ${splitEvery(GOOGLE, ' ', 4)}`);
    expect(providerFindings(result.findings, 'stripe')).toHaveLength(1);
    const google = providerFindings(result.findings, 'google');
    expect(google).toHaveLength(1);
    expect(google[0].action).toBe('blocked');
    expect(google[0].evasion).toBe('separator_split');
    expect(result.redactedContent).toBe('[REDACTED-api_key-stripe] [REDACTED-api_key-google]');
  });

  it('split Stripe test key followed by a contiguous Google key: the direct finding survives', () => {
    // The collapsed Stripe run flows through the Google key; the direct pass
    // already placed the Google key, so the run is cut there. The former
    // "supersede narrower pattern-layer hits" filter would have deleted the
    // direct critical finding had the cut not applied.
    const result = scanForCredentials(`${splitEvery(STRIPE_TEST, ' ', 4)} ${GOOGLE}`);
    expect(providerFindings(result.findings, 'stripe')).toHaveLength(1);
    const google = providerFindings(result.findings, 'google');
    expect(google).toHaveLength(1);
    expect(google[0].action).toBe('blocked');
    expect(google[0].evasion).toBeUndefined();
    expect(result.redactedContent).toBe('[REDACTED-api_key-stripe] [REDACTED-api_key-google]');
  });

  it('when the cut span cannot re-validate, the outer hit stays whole and the inner critical finding is still reported', () => {
    // `sk_test_Ab1C` is too short for the Stripe pattern on its own, so the
    // Stripe hit cannot be cut at the Google start and stays whole (medium).
    // Coverage suppression only goes downward: the critical Google finding
    // inside it is kept.
    const result = scanForCredentials(`sk_t est_ Ab1C ${splitEvery(GOOGLE, ' ', 4)}`);
    const google = providerFindings(result.findings, 'google');
    expect(google).toHaveLength(1);
    expect(google[0].severity).toBe('critical');
    expect(google[0].action).toBe('blocked');
    expect(result.findings.some(f => f.action === 'blocked')).toBe(true);
    expect(rejoin(result.redactedContent ?? '')).not.toContain(GOOGLE);
  });
});

describe('#544 B2: trimming never turns a finding into no finding', () => {
  const K = k('sk-', 'A1b2C3d4E5f6G7h8I9j0KlMnOpQrStUvWx');

  it('control: the key split after every character is blocked', () => {
    const result = scanForCredentials(K.split('').join(' '));
    const hits = providerFindings(result.findings, 'openai');
    expect(hits).toHaveLength(1);
    expect(hits[0].action).toBe('blocked');
  });

  it('the same key followed by a word is still blocked, and the word is left outside the redaction', () => {
    // On the previous head the trailing trim walked back through the
    // single-letter fragments `S t U v W x` while the regex kept matching,
    // fell under `minLength`, and the whole candidate was discarded:
    // `leaked === false` for a key that had just been blocked.
    const text = `${K.split('').join(' ')} end`;
    const result = scanForCredentials(text);
    expect(result.leaked).toBe(true);
    const hits = providerFindings(result.findings, 'openai');
    expect(hits).toHaveLength(1);
    expect(hits[0].severity).toBe('critical');
    expect(hits[0].action).toBe('blocked');
    expect(hits[0].position).toBe(0);
    expect(result.redactedContent).toBe('[REDACTED-api_key-openai] end');
    expect(rejoin(result.redactedContent ?? '')).not.toContain(K);
  });

  it('with words on both sides', () => {
    const result = scanForCredentials(`note ${K.split('').join(' ')} and rotate it`);
    const hits = providerFindings(result.findings, 'openai');
    expect(hits).toHaveLength(1);
    expect(hits[0].action).toBe('blocked');
    expect(hits[0].position).toBe('note '.length);
    expect(result.redactedContent).toBe('note [REDACTED-api_key-openai] and rotate it');
  });

  it('a two-letter fragment after a finely split key cannot be told from the key\'s tail and stays inside the redaction', () => {
    // Documented residual: the finding is unaffected; only `ok` is redacted too.
    const result = scanForCredentials(`${splitEvery(K, ' ', 2)} ok`);
    const hits = providerFindings(result.findings, 'openai');
    expect(hits).toHaveLength(1);
    expect(hits[0].action).toBe('blocked');
    expect(result.redactedContent).toBe('[REDACTED-api_key-openai]');
  });
});

describe('#544 B3: trimming cost is linear in the words after a split key', () => {
  const timeScan = (n: number): number => {
    const text = `${splitEvery(KEYS[1].key, ' ', 4)}${' word'.repeat(n)}`;
    let best = Infinity;
    for (let i = 0; i < 3; i++) {
      const t0 = performance.now();
      const result = scanForCredentials(text);
      best = Math.min(best, performance.now() - t0);
      expect(providerFindings(result.findings, 'openai')).toHaveLength(1);
      expect(result.redactedContent).toBe(`[REDACTED-api_key-openai]${' word'.repeat(n)}`);
    }
    return best;
  };

  it('16k trailing words scan in bounded time and grow roughly linearly from 4k', () => {
    // Previous head: ~97 / 344 / 1339 ms for 4k / 8k / 16k (one regex compile
    // and a `slice(0, end)` per trimmed fragment). Now one exact-span check
    // per hit; measured ~5 / 12 / 21 ms. Bounds are generous for CI noise.
    const t4k = timeScan(4000);
    const t16k = timeScan(16000);
    expect(t16k).toBeLessThan(250);
    expect(t16k).toBeLessThan(6 * t4k + 50);
  });
});

describe('#544 B4: numbered headings are dismissed structurally; split keys are not', () => {
  const HEADINGS = [
    // The three already-fixed sentences.
    'ASIA 2026 REGIONAL SALES REPORT',
    'ASIA Q3 REGIONAL SALES MEETING NOTES',
    'sk-proj- keys replaced the legacy format in 2024',
    // The reviewer's heading: collapses to `ASIAQ1Q2Q3Q4REVENUEB`, a
    // well-formed AWS id in which only 11 of 20 characters sit in words.
    'ASIA Q1 Q2 Q3 Q4 REVENUE BY REGION',
    // More of the same class.
    'ASIA FY26 H1 H2 TOTALS BY COUNTRY',
    'ASIA 2025 Q4 SALES BY REGION',
    'ASIA H1 2026 REVENUE BY SEGMENT',
    'ASIA 2026 Q1 Q2 REGIONAL HEADCOUNT',
    'ASIA 1H 2H 2026 NET SALES BY MARKET',
    'ASIA Q4 2025 TOTAL REVENUE AND MARGIN',
    'ASIA Q2 GROSS MARGIN BY PRODUCT LINE',
    'ASIA FY2026 W12 PIPELINE BY OWNER',
    'ASIA Q3 EMEA APAC SALES 2026 UPDATE',
    'Asia Q1 Q2 Q3 Q4 Revenue By Region',
    'asia fy26 h1 h2 totals by country',
  ];

  for (const heading of HEADINGS) {
    it(`no finding for: ${JSON.stringify(heading)}`, () => {
      const result = scanForCredentials(heading);
      expect(result.findings).toHaveLength(0);
      expect(result.leaked).toBe(false);
    });
  }

  const AWS_IDS = [
    KEYS[3].key,
    k('ASIA', '7XQ4KZ2M6VB3TW5N'),
    k('AKIA', 'J5R2WP7QX3ZK4M6T'),
  ];
  for (const id of AWS_IDS) {
    for (const every of [1, 2, 4]) {
      for (const tail of ['', ' REGION', ' end']) {
        it(`${id.slice(0, 4)}… ZWSP-split every ${every}${tail ? ` + ${JSON.stringify(tail)}` : ''} is blocked`, () => {
          const result = scanForCredentials(`id: ${splitEvery(id, ZWSP, every)}${tail}`);
          const aws = providerFindings(result.findings, 'aws');
          expect(aws).toHaveLength(1);
          expect(aws[0].severity).toBe('critical');
          expect(aws[0].action).toBe('blocked');
          expect(aws[0].position).toBe('id: '.length);
          expect(result.redactedContent).toBe(`id: [REDACTED-api_key-aws]${tail}`);
        });
      }
    }
  }

  it('the prose decision cannot be diluted with interleaved filler after a split key', () => {
    // On the previous head the 60% share was computed over the whole swallowed
    // run, so filler that defeats trimming (`hello x9`: a word, then key
    // material) pushed a real split key over the threshold and dismissed it.
    const key = splitEvery(KEYS[1].key, ' ', 4);
    for (const filler of [' hello x9', ' by in to on', ' Q1 2026 by']) {
      const result = scanForCredentials(`${key}${filler.repeat(50)}`);
      const hits = providerFindings(result.findings, 'openai');
      expect(hits).toHaveLength(1);
      expect(hits[0].action).toBe('blocked');
      expect(hits[0].position).toBe(0);
      expect(rejoin(result.redactedContent ?? '')).not.toContain(KEYS[1].key);
    }
  });
});

// ── #544 review round 4 ─────────────────────────────────────────────────────

/** Deterministic PRNG (mulberry32) so the generated corpus is the same on every run. */
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6D2B79F5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** A random synthetic AWS access key id with a base-32 body, as issued ids have. */
function randomAwsId(rnd: () => number): string {
  let body = '';
  for (let i = 0; i < 16; i++) body += BASE32[Math.floor(rnd() * 32)];
  return `AKIA${body}`;
}

function splitFindings(text: string): CredentialFinding[] {
  return scanForCredentials(text).findings.filter(f => f.evasion === 'separator_split');
}

describe('#544 F1: the reviewer\'s headings, in every case shape', () => {
  // Each string is clean on main and produced an AWS critical/blocked finding
  // at the previous head. The first four end the 20-character AWS window
  // mid-word (FOREC|AST, HEAD|COUNT, STATU|S, ACQU|ISITION); `GDP`, `HEADCOUNT`,
  // `PROJECT` and `ACQUISITION` all fail the letter-pair test, which is why a
  // rule that judges words could not clear them without a vocabulary.
  const REVIEWER = [
    'ASIA Q1 GDP GROWTH FORECAST',
    'ASIA 2026 EMPLOYEE HEADCOUNT REPORT',
    'ASIA 2026 PROJECT STATUS UPDATE',
    'ASIA 2026 CUSTOMER ACQUISITION REPORT',
    'ASIA Q1 Q2 Q3 Q4 REVENUE BY REGION',
    'ASIA 2026 REGIONAL SALES REPORT',
    // The same class without a 0/1/8/9 in the window, so the base-32 fact
    // alone does not clear them: alignment does.
    'ASIA Q3 GDP GROWTH FORECAST',
    'ASIA Q3 EMPLOYEE HEADCOUNT REPORT',
    'ASIA Q3 PROJECT STATUS UPDATE',
    'ASIA H2 CUSTOMER ACQUISITION REPORT',
    'ASIA FY26 BUDGET REVIEW BY REGION',
    'ASIA Q3 GDP KPI COGS OPEX REVIEW',
  ];
  const shapes: Array<[string, (s: string) => string]> = [
    ['ALL CAPS', s => s],
    ['Title Case', s => s.split(' ').map(w => /^[A-Z]{2,3}\d*$|^\d/.test(w) && w.length <= 4 ? w : w[0] + w.slice(1).toLowerCase()).join(' ')],
    ['lower case', s => s.toLowerCase()],
  ];
  for (const heading of REVIEWER) {
    for (const [shape, fn] of shapes) {
      it(`${shape}: no finding for ${JSON.stringify(fn(heading))}`, () => {
        const result = scanForCredentials(fn(heading));
        expect(result.findings).toHaveLength(0);
        expect(result.leaked).toBe(false);
      });
    }
  }
});

/**
 * Formatting a heading may wrap it (F3). Each wrapper is applied to a whole
 * heading; the JSON case embeds it as a string value.
 */
const WRAPPERS: Array<[string, (s: string) => string]> = [
  ['double quotes', s => `"${s}"`],
  ['single quotes', s => `'${s}'`],
  ['Markdown bold', s => `**${s}**`],
  ['Markdown italic', s => `_${s}_`],
  ['backticks', s => `\`${s}\``],
  ['parentheses', s => `(${s})`],
  ['square brackets', s => `[${s}]`],
  ['heading prefix', s => `# ${s}`],
  ['list prefix', s => `- ${s}`],
  ['trailing colon', s => `${s}:`],
  ['trailing full stop', s => `${s}.`],
  ['trailing comma', s => `${s},`],
  ['JSON string value', s => JSON.stringify({ title: s })],
];

describe('#544 F3: a wrapped heading is judged like the bare heading', () => {
  // At aad81abb the bare control was clean but the three wrappings below were
  // AWS critical/blocked: the boundary word was extended across the closing
  // quote or asterisks (`REPORT"`), which is neither a word nor letters-only.
  // The word is now the alphanumeric run only.
  const CONTROL = 'ASIA 2026 REGIONAL SALES REPORT';
  it.each([
    ['double-quoted', `"${CONTROL}"`],
    ['Markdown-bold', `**${CONTROL}**`],
    ['JSON title', `{"title": "${CONTROL}"}`],
  ])('reviewer case, %s: no finding', (_name, text) => {
    const result = scanForCredentials(text);
    expect(result.findings).toHaveLength(0);
    expect(result.leaked).toBe(false);
  });

  // The same class WITHOUT a 0/1/8/9 in the window, so the base-32 fact does
  // not clear it: only the boundary-word rule does.
  const NO_BASE32_HELP = [
    'ASIA Q3 GDP GROWTH FORECAST',
    'ASIA Q3 REGIONAL SALES REPORT',
    'ASIA FY26 BUDGET REVIEW BY REGION',
    'ASIA Q3 PROJECT STATUS UPDATE',
  ];
  for (const heading of NO_BASE32_HELP) {
    for (const [name, wrap] of WRAPPERS) {
      it(`${name}: no finding for ${JSON.stringify(wrap(heading))}`, () => {
        expect(splitFindings(wrap(heading))).toHaveLength(0);
      });
    }
  }

  it('wrapping a split key does not hide it', () => {
    const split = splitEvery(KEYS[3].key, ZWSP, 4);
    for (const [name, wrap] of WRAPPERS) {
      const hits = splitFindings(wrap(split));
      expect({ wrapper: name, hits: hits.length, provider: hits[0]?.provider }).toEqual({ wrapper: name, hits: 1, provider: 'aws' });
    }
  });

  it('a comma-delimited ZWSP-split id is still found', () => {
    const split = splitEvery(KEYS[3].key, ZWSP, 4);
    for (const text of [`${split}, ${split}`, `ids: ${split},${split}`, `[${split}, ${split}]`]) {
      const hits = splitFindings(text);
      expect(hits).toHaveLength(2);
      expect(hits.every(h => h.provider === 'aws')).toBe(true);
    }
  });

  it('the hit\'s own punctuation stays inside its fragment', () => {
    // `sk-proj-` holds `-`; only the extension OUTWARD stops at punctuation.
    const split = splitEvery(KEYS[1].key, ' ', 6);
    for (const [name, wrap] of WRAPPERS) {
      const hits = splitFindings(wrap(split));
      expect({ wrapper: name, hits: hits.length }).toEqual({ wrapper: name, hits: 1 });
    }
  });
});

describe('#544 F1: a generated heading corpus produces no split finding', () => {
  // ~150 common report words, abbreviations, years and period tokens, mixed at
  // random behind an `ASIA` / `AKIA` leader. Digit-bearing abbreviations
  // (`B2B`, `3PL`) are deliberately absent: a fragment that mixes letters and
  // digits IS key material by the rule under test, and a heading that holds
  // one still fires when the 20-character window lands on it (documented
  // residual in the CHANGELOG).
  const WORDS = `revenue sales report regional quarterly annual growth forecast outlook summary review update status
    project employee headcount customer acquisition retention pipeline budget actual variance margin gross net
    operating profit loss cost expense capital spend plan target results performance metrics dashboard analysis
    overview market segment region country territory account channel partner product portfolio service pricing
    volume units demand supply inventory logistics shipping orders backlog bookings billing collections
    receivables payables cash flow balance sheet income statement audit compliance risk controls governance
    strategy priorities roadmap initiatives objectives milestones deliverables timeline schedule launch rollout
    adoption engagement satisfaction churn renewal upsell expansion enterprise commercial consumer retail
    wholesale digital online offline marketing campaign leads conversion funnel traffic brand awareness
    advertising promotion discount rebate operations manufacturing production quality defects returns warranty
    maintenance facilities fleet energy workforce staffing hiring attrition training development compensation
    benefits payroll headline highlights lowlights issues actions decisions notes minutes meeting agenda
    attendees deck slides appendix draft final version approved pending open closed total subtotal average
    median peak trough weekly monthly yearly comparison trend baseline benchmark index ranking share mix rate
    ratio percent change delta by and for of the in to on with versus per top bottom north south east west
    central pacific europe america africa china india japan korea australia singapore vietnam thailand
    indonesia philippines malaysia taiwan`.split(/\s+/).filter(Boolean);
  const ACRONYMS = ('GDP KPI HR EBITDA YOY QOQ SKU CAGR ROI ARR MRR NPS CAC LTV COGS SGA OPEX CAPEX FTE PNL SLA '
    + 'OKR EMEA APAC LATAM CFO CEO CRM ERP SAAS IT AI ML FX USD EUR JPY CNY').split(' ');
  const PERIODS = ['2024', '2025', '2026', '2027', '2028', '2029', '2030', '2031', '2032', '2033', 'Q1', 'Q2', 'Q3', 'Q4',
    'H1', 'H2', 'FY24', 'FY25', 'FY26', 'FY27', 'FY2026', 'W12', 'W7', 'M3', '1H', '2H', '3Q', '1st', '2nd', '3rd', '4th',
    '7', '5', '12', '25', '33', '66'];
  const LEADERS = ['ASIA', 'AKIA'];

  function generateHeadings(n: number, seed: number): string[] {
    const rnd = mulberry32(seed);
    const pick = <T,>(a: T[]): T => a[Math.floor(rnd() * a.length)];
    const out: string[] = [];
    for (let i = 0; i < n; i++) {
      const tokens = [pick(LEADERS)];
      const len = 2 + Math.floor(rnd() * 5);
      let hasPeriod = false;
      for (let t = 0; t < len; t++) {
        const x = rnd();
        if (x < 0.20) { tokens.push(pick(PERIODS)); hasPeriod = true; }
        else if (x < 0.35) tokens.push(pick(ACRONYMS));
        else tokens.push(pick(WORDS));
      }
      // Every heading carries a digit somewhere, or it could never match.
      if (!hasPeriod) tokens.splice(1 + Math.floor(rnd() * len), 0, pick(PERIODS));
      const shape = i % 3;
      out.push(tokens.map(w => {
        if (shape === 0) return w.toUpperCase();
        if (shape === 2) return w.toLowerCase();
        return /^[A-Z0-9]+$/.test(w) && w.length <= 6 ? w : w[0].toUpperCase() + w.slice(1).toLowerCase();
      }).join(' '));
    }
    return out;
  }

  const CORPUS = generateHeadings(6000, 543);

  it('the corpus exercises the AWS window shape', () => {
    // Sanity: a large share of the all-caps headings collapse into text the
    // AWS regex matches, so a clean result below is not vacuous.
    const windowed = CORPUS.filter(h => /A[KS]IA[0-9A-Z]{16}/.test(h.replace(/\s+/g, '')));
    expect(windowed.length).toBeGreaterThan(1000);
  });

  it('6,000 generated headings (all-caps, Title, lower) → zero separator_split findings', () => {
    const offenders: string[] = [];
    for (const heading of CORPUS) {
      if (splitFindings(heading).length > 0) offenders.push(heading);
    }
    expect(offenders).toEqual([]);
  });

  it('the same 6,000 headings, each wrapped 13 ways (78,000 texts) → zero separator_split findings', () => {
    const offenders: string[] = [];
    for (const heading of CORPUS) {
      for (const [, wrap] of WRAPPERS) {
        const text = wrap(heading);
        if (splitFindings(text).length > 0) offenders.push(text);
      }
    }
    expect(offenders).toEqual([]);
  });
});

describe('#544 F1: the base-32 fact is consulted by the collapsed pass only', () => {
  // Body holds 9, 8 and 1: not an alphabet an issued id can carry.
  const NOT_BASE32 = k('AKIA', 'Z7Q3F9XM2K8V4B1T');

  it('the direct pass still blocks a contiguous id outside the alphabet (unchanged behaviour)', () => {
    const result = scanForCredentials(`id: ${NOT_BASE32} end`);
    const aws = providerFindings(result.findings, 'aws');
    expect(aws).toHaveLength(1);
    expect(aws[0].action).toBe('blocked');
    expect(aws[0].evasion).toBeUndefined();
    expect(result.redactedContent).toBe('id: [REDACTED-api_key-aws] end');
  });

  it('the collapsed pass does not claim a split value outside the alphabet', () => {
    expect(splitFindings(`id: ${splitEvery(NOT_BASE32, ZWSP, 4)} end`)).toHaveLength(0);
  });

  it('the collapsed pass claims the same split shape inside the alphabet', () => {
    const hits = splitFindings(`id: ${splitEvery(KEYS[3].key, ZWSP, 4)} end`);
    expect(hits).toHaveLength(1);
    expect(hits[0].provider).toBe('aws');
    expect(hits[0].action).toBe('blocked');
  });
});

describe('#544 round 5: policy by separator class for the AWS id', () => {
  const key = KEYS[3].key;
  const REPRO = k('AKIA', 'AB2CD3EF4GH5JK6L');

  it('stated gap: an AWS id split by visible whitespace alone is not claimed', () => {
    // Every rule tried for this window (rounds 3–4) was either evaded by an
    // attacker choosing the split points (94–100%) or blocked an ordinary
    // heading; a rule with both properties buys nothing. The direct pass on
    // the contiguous id is unchanged.
    for (const text of [splitEvery(key, ' ', 4), splitEvery(key, '\n', 4), splitEvery(key, '\t', 1), `X${splitEvery(REPRO, ' ', 4)}`]) {
      expect(splitFindings(`id: ${text} end`)).toHaveLength(0);
    }
    expect(providerFindings(scanForCredentials(`id: ${key} end`).findings, 'aws')).toHaveLength(1);
  });

  it('the gap is the AWS shape only: a fixed-length hex key split by spaces is still found', () => {
    const twilio = k('SK', '0a1b2c3d4e5f60718293a4b5c6d7e8f9');
    const hits = splitFindings(`sid ${splitEvery(twilio, ' ', 4)} end`);
    expect(hits).toHaveLength(1);
    expect(hits[0].provider).toBe('twilio');
  });

  it('reviewer repro: ZWSP-split id is found, and prepending a letter no longer hides it', () => {
    for (const text of [splitEvery(REPRO, ZWSP, 4), `X${splitEvery(REPRO, ZWSP, 4)}`, `X${splitEvery(REPRO, ZWSP, 4)}Y`]) {
      const hits = splitFindings(text);
      expect(hits).toHaveLength(1);
      expect(hits[0].provider).toBe('aws');
      expect(hits[0].action).toBe('blocked');
      expect(rejoin(scanForCredentials(text).redactedContent ?? '')).not.toContain(REPRO);
    }
  });

  it('a hit with one invisible separator among visible ones is judged as invisible', () => {
    const mixed = `${key.slice(0, 8)} ${key.slice(8, 12)}${ZWSP}${key.slice(12, 16)} ${key.slice(16)}`;
    const hits = splitFindings(`id: ${mixed} end`);
    expect(hits).toHaveLength(1);
    expect(hits[0].provider).toBe('aws');
  });

  it('an invisible-split id inside quotes or Markdown is found', () => {
    const split = splitEvery(REPRO, ZWSP, 4);
    for (const text of [`"${split}"`, `**${split}**`, `\`${split}\``, JSON.stringify({ id: split }), `- ${split}:`]) {
      const hits = splitFindings(text);
      expect({ text, hits: hits.length }).toEqual({ text, hits: 1 });
    }
  });

  it('an invisible-split id with words around it is found and only the id is redacted', () => {
    const result = scanForCredentials(`the id ${splitEvery(REPRO, ZWSP, 4)} rotates soon`);
    const hits = providerFindings(result.findings, 'aws');
    expect(hits).toHaveLength(1);
    expect(hits[0].evasion).toBe('separator_split');
    expect(result.redactedContent).toBe('the id [REDACTED-api_key-aws] rotates soon');
  });

  it('no prose escape for invisible separators: a heading-shaped split with ZWSP inside the window fires', () => {
    // Nothing a person types puts a zero-width space between `Q3` and `GDP`;
    // this is the intended behaviour of the invisible class.
    expect(splitFindings(`ASIA${ZWSP}Q3${ZWSP}GDP${ZWSP}GROWTH${ZWSP}FORECAST`)).toHaveLength(1);
  });

  it('an invisible character at the text edge, outside the window, leaves a heading clean', () => {
    for (const heading of ['ASIA Q3 GDP GROWTH FORECAST', 'ASIA B2B SALES FORECAST', 'ASIA 2026 REGIONAL SALES REPORT']) {
      for (const edge of [ZWSP, '\ufeff', '\u200c', '\u00ad', '\u200e']) {
        for (const text of [`${edge}${heading}`, `${heading}${edge}`, `${edge}${heading}${edge}`, `${heading}${edge}\n`]) {
          expect({ text, hits: splitFindings(text).length }).toEqual({ text, hits: 0 });
        }
      }
    }
  });

  it('a random id split by an invisible separator is found whatever the split (seeded sample)', () => {
    const rnd = mulberry32(99);
    const splits: Array<[string, (id: string) => string]> = [
      ['every 1', id => splitEvery(id, ZWSP, 1)],
      ['every 2', id => splitEvery(id, '\u200d', 2)],
      ['every 4', id => splitEvery(id, ZWSP, 4)],
      ['every 5', id => splitEvery(id, '\u2060', 5)],
      ['once', id => splitOnce(id, '\ufeff')],
      ['glued letter + every 4', id => `X${splitEvery(id, ZWSP, 4)}Y`],
    ];
    const ids: string[] = [];
    while (ids.length < 500) {
      const id = randomAwsId(rnd);
      if (/[0-9]/.test(id.slice(4))) ids.push(id); // an id without a digit is the documented letter+digit residual
    }
    for (const [name, fn] of splits) {
      const found = ids.filter(id => splitFindings(`id: ${fn(id)} end`).some(f => f.provider === 'aws')).length;
      expect({ split: name, found }).toEqual({ split: name, found: ids.length });
    }
  });

  it('open-ended and mixed-case patterns keep the strict rule for visible whitespace', () => {
    const result = scanForCredentials(`sk-proj- ${splitEvery(KEYS[1].key.slice(8), ' ', 4)} yes`);
    expect(providerFindings(result.findings, 'openai')).toHaveLength(1);
    expect(splitFindings('sk-proj- keys replaced the legacy format in 2024')).toHaveLength(0);
  });

  it('open-ended patterns get no prose escape for invisible separators either', () => {
    // A sentence the strict rule dismisses when split by spaces …
    const sentence = 'sk-proj- keys replaced the legacy format in 2024';
    expect(splitFindings(sentence)).toHaveLength(0);
    // … is a key when the same gaps hold a zero-width space.
    expect(splitFindings(sentence.replace(/ /g, ZWSP))).toHaveLength(1);
  });
});

describe('#544 round 5: the reviewer\'s digit-abbreviation headings', () => {
  // `ASIA B2B SALES FORECAST` collapses to `ASIAB2BSALESFORECAST`: a well-formed
  // AWS window with `B2B` as key material by any letter-and-digit rule. It
  // was CRITICAL/blocked at 41ee77de; documenting it as a residual does not
  // pass the precision gate. Under the whitespace policy it is not judged.
  const HEADINGS = [
    'ASIA B2B SALES FORECAST',
    'ASIA 3PL COST REVIEW',
    'ASIA B2C P2P 4G 5G ROLLOUT',
    'ASIA 2FA K12 W2 401K REVIEW',
    'ASIA Q1 B2B GROWTH FORECAST',
    'ASIA FY26 H1 3PL LOGISTICS',
  ];
  for (const heading of HEADINGS) {
    for (const [shape, fn] of [['bare', (s: string) => s], ['double-quoted', (s: string) => `"${s}"`], ['lower', (s: string) => s.toLowerCase()]] as const) {
      it(`${shape}: no finding for ${JSON.stringify(fn(heading))}`, () => {
        const result = scanForCredentials(fn(heading));
        expect(result.findings).toHaveLength(0);
        expect(result.leaked).toBe(false);
      });
    }
  }
});

describe('#544 round 5: a generated digit-abbreviation corpus produces no split finding', () => {
  const DIGIT_ABBREVIATIONS = ['B2B', 'B2C', 'C2C', 'P2P', 'D2C', 'O2O', '3PL', '4PL', '4G', '5G', '2FA', 'MFA2', 'K12', 'W2', '1099',
    '401K', 'S3', 'EC2', 'H1B', 'G7', 'G20', 'COVID19', 'Y2K', '3D', '2D', '24X7', '9TO5', '1ST', '2ND', 'TOP10', 'A1', 'B2', 'C3',
    'Q1', 'Q2', 'Q3', 'Q4', 'H1', 'H2', 'FY26', 'FY2026', 'CY25', 'W12', 'M3', '1H', '2H', 'V2', 'V3', 'X1', 'MK2', 'T2', 'E3'];
  const WORDS = 'sales forecast cost review report growth revenue rollout logistics platform strategy pricing budget pipeline'.split(' ');
  const ACRONYMS = 'GDP KPI HR EBITDA YOY SKU ROI ARR NPS COGS OPEX CAPEX EMEA APAC CRM ERP'.split(' ');

  function generate(n: number, seed: number): string[] {
    const rnd = mulberry32(seed);
    const pick = <T,>(a: T[]): T => a[Math.floor(rnd() * a.length)];
    const out: string[] = [];
    for (let i = 0; i < n; i++) {
      const tokens = [pick(['ASIA', 'AKIA'])];
      const len = 2 + Math.floor(rnd() * 5);
      let hasAbbrev = false;
      for (let t = 0; t < len; t++) {
        const x = rnd();
        if (x < 0.35) { tokens.push(pick(DIGIT_ABBREVIATIONS)); hasAbbrev = true; }
        else if (x < 0.5) tokens.push(pick(ACRONYMS));
        else tokens.push(pick(WORDS));
      }
      if (!hasAbbrev) tokens.splice(1 + Math.floor(rnd() * len), 0, pick(DIGIT_ABBREVIATIONS));
      const shape = i % 3;
      out.push(tokens.map(w => shape === 0 ? w.toUpperCase() : shape === 2 ? w.toLowerCase() : (/^[A-Z0-9]+$/.test(w) && w.length <= 6 ? w : w[0].toUpperCase() + w.slice(1).toLowerCase())).join(' '));
    }
    return out;
  }

  const CORPUS = generate(3000, 544);

  it('the corpus exercises the AWS window shape', () => {
    const windowed = CORPUS.filter(h => /A[KS]IA[0-9A-Z]{16}/.test(h.replace(/\s+/g, '')));
    expect(windowed.length).toBeGreaterThan(500);
  });

  it('3,000 digit-abbreviation headings, bare → zero separator_split findings', () => {
    expect(CORPUS.filter(h => splitFindings(h).length > 0)).toEqual([]);
  });

  it('the same headings wrapped 13 ways (39,000 texts) → zero separator_split findings', () => {
    const offenders: string[] = [];
    for (const heading of CORPUS) for (const [, wrap] of WRAPPERS) { const t = wrap(heading); if (splitFindings(t).length > 0) offenders.push(t); }
    expect(offenders).toEqual([]);
  });

  it('the same headings with an invisible character at either edge (18,000 texts) → zero separator_split findings', () => {
    const offenders: string[] = [];
    for (const heading of CORPUS) {
      for (const edge of [ZWSP, '\ufeff', '\u00ad']) {
        for (const t of [`${edge}${heading}`, `${heading}${edge}`]) if (splitFindings(t).length > 0) offenders.push(t);
      }
    }
    expect(offenders).toEqual([]);
  });
});

describe('#544 F2 / F4: cost is linear in the number of split keys', () => {
  // Two separators per shape: the reviewer's space-split ids (no finding by
  // the whitespace policy, so this is the pure cost of discovering and
  // dismissing N candidates) and the same ids ZWSP-split (N findings).
  const timeScan = (n: number, joiner: string, sep = ' '): number => {
    const rnd = mulberry32(7);
    const text = Array.from({ length: n }, () => splitEvery(randomAwsId(rnd), sep, 4)).join(joiner);
    let best = Infinity;
    for (let i = 0; i < 3; i++) {
      const t0 = performance.now();
      const result = scanForCredentials(text);
      best = Math.min(best, performance.now() - t0);
      const found = providerFindings(result.findings, 'aws').length;
      // ~96% of ids carry a digit; with an invisible separator all of those are found.
      if (sep === ' ') expect(found).toBe(0);
      else expect(found).toBeGreaterThan(n * 0.9);
    }
    return best;
  };

  it('F2: 8k split ids joined by " | " cost at most a generous linear multiple of 1k', () => {
    // Previous head: 23 / 120 / 393 / 2404 ms for 1k / 2k / 4k / 8k ids
    // (resolution filtered every candidate against every candidate, and the
    // redaction spliced the content once per finding). Now 14 / 25 / 47 / 92
    // ms on the development box. The bound is on the RATIO so a slow CI box
    // passes; the old code's ratio was over 100.
    for (const sep of [' ', ZWSP]) {
      const t1k = timeScan(1000, ' | ', sep);
      const t8k = timeScan(8000, ' | ', sep);
      expect(t8k).toBeLessThan(20 * t1k + 200);
      expect(t8k).toBeLessThan(4000);
    }
  });

  it('F4: 3200 split ids joined by a single space cost at most a generous linear multiple of 800', () => {
    // With spaces only the collapsed view is ONE alphanumeric run, and the
    // well-known-identifier check walked it whole for every hit: 415 / 1704 /
    // 6551 ms for 800 / 1600 / 3200 ids at the previous head (comma-joined
    // controls 12 / 22 / 56 ms). Now 14 / 30 / 46 ms. Same ratio bound as F2;
    // the old ratio was about 16 for a 4x input.
    for (const sep of [' ', ZWSP]) {
      const t800 = timeScan(800, ' ', sep);
      const t3200 = timeScan(3200, ' ', sep);
      expect(t3200).toBeLessThan(10 * t800 + 200);
      expect(t3200).toBeLessThan(4000);
    }
  });
});

// ── Consumer — the defence pipeline blocks a split key on memory write ──────

describe('#543 pipeline consumer', () => {
  beforeAll(() => {
    initDatabase(':memory:');
  });

  afterAll(() => {
    closeDatabase();
  });

  const testConfig: DefenceConfig = {
    mode: 'balanced',
    enableFragmentationDetection: false,
    fragmentationWindowHours: 24,
    trustThresholdForActions: 0.7,
    autoQuarantineThreshold: 0.3,
    flagThreshold: 0.5,
    strictSourceMode: false,
  };

  it('blocks a memory write carrying a space-split key', async () => {
    const { runDefencePipeline } = await import('../pipeline.js');
    const result = runDefencePipeline(
      `Save this: my API key is ${splitEvery(KEYS[0].key, ' ', 4)}`,
      'API key note',
      { type: 'agent', identifier: 'test-agent' },
      testConfig,
    );
    expect(result.allowed).toBe(false);
    expect(result.firewall.result).toBe('BLOCK');
    expect(result.firewall.threatIndicators).toContain('credential_leak');
    expect(result.credentialScan?.leaked).toBe(true);
  });

  it('blocks a memory write carrying a split Stripe test key followed by a split Google key (#544 B1)', async () => {
    const { runDefencePipeline } = await import('../pipeline.js');
    const result = runDefencePipeline(
      `${splitEvery(STRIPE_TEST, ' ', 4)} ${splitEvery(GOOGLE, ' ', 4)}`,
      'keys note',
      { type: 'agent', identifier: 'test-agent' },
      testConfig,
    );
    expect(result.allowed).toBe(false);
    expect(result.firewall.threatIndicators).toContain('credential_leak');
    expect(result.credentialScan?.findings.some(f => f.provider === 'google' && f.action === 'blocked')).toBe(true);
  });

  it('blocks a memory write carrying a zero-width-space-split AWS access key id', async () => {
    const { runDefencePipeline } = await import('../pipeline.js');
    const result = runDefencePipeline(
      `aws id:\n${splitEvery(KEYS[3].key, ZWSP, 4)}\n`,
      'cloud note',
      { type: 'agent', identifier: 'test-agent' },
      testConfig,
    );
    expect(result.allowed).toBe(false);
    expect(result.firewall.threatIndicators).toContain('credential_leak');
  });
});
