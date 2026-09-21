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
 * the letter+digit gate.
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
  { provider: 'aws', key: k('AKIA', 'Z7Q3F9XM2K8V4B1T'), severity: 'critical' },
  { provider: 'github', key: k('ghp_', 'Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx2'), severity: 'critical' },
  { provider: 'stripe', key: k('sk_live_', 'Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8'), severity: 'critical' },
  { provider: 'google', key: k('AIza', 'Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx'), severity: 'critical' },
  { provider: 'slack', key: k('xoxb-', '1234567890-Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8'), severity: 'critical' },
  { provider: 'npm', key: k('npm_', 'Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx2'), severity: 'critical' },
  { provider: 'huggingface', key: k('hf_', 'Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1W'), severity: 'critical' },
];

/** Separators an attacker (or a line-wrapping transport) can insert. */
const SEPARATORS: Array<{ name: string; sep: string }> = [
  { name: 'space', sep: ' ' },
  { name: 'double space', sep: '  ' },
  { name: 'tab', sep: '\t' },
  { name: 'newline', sep: '\n' },
  { name: 'CRLF', sep: '\r\n' },
  { name: 'NBSP', sep: ' ' },
  { name: 'zero-width space', sep: '​' },
  { name: 'zero-width joiner', sep: '‍' },
  { name: 'word joiner', sep: '⁠' },
  { name: 'BOM / ZWNBSP', sep: '﻿' },
  { name: 'soft hyphen', sep: '­' },
  { name: 'space + newline + space', sep: ' \n ' },
];

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
  return text.replace(/[\s­​-‍⁠﻿]/g, '');
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
    for (const { name, sep } of SEPARATORS) {
      for (const [variant, text] of [
        ['split once', splitOnce(key, sep)],
        ['split every 4', splitEvery(key, sep, 4)],
        ['split every 2', splitEvery(key, sep, 2)],
      ] as const) {
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

  it('reports one finding per secret when a split leaves a fragment the direct pass already matched', () => {
    // 27 contiguous chars after `sk-` satisfy the legacy OpenAI rule on their
    // own; the collapsed pass must supersede that partial hit with the full
    // span, not add a second finding for the same secret.
    const key = KEYS[0].key;
    const content = `key: ${key.slice(0, 30)} ${key.slice(30)} and`;
    const result = scanForCredentials(content);
    const hits = providerFindings(result.findings, 'openai');
    expect(hits).toHaveLength(1);
    expect(hits[0].evasion).toBe('separator_split');
    expect(result.findings).toHaveLength(1);
    expect(result.redactedContent).toBe('key: [REDACTED-api_key-openai] and');
  });

  it('finds every split key when several are present', () => {
    const a = splitEvery(KEYS[0].key, ' ', 5);
    const b = splitEvery(KEYS[3].key, '\n', 4);
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

  it('leaves a 3+ letter word after a finely split key outside the redaction', () => {
    // Residual, by design: the attacker picks the split points, so a trailing
    // run of same-case alphabetic fragments that holds a 3+ letter word cannot
    // be told from following prose, and the whole run is trimmed as far as the
    // pattern allows — here the key's last letter `z` stays outside the span.
    // The finding still blocks; only the redaction span is affected.
    const result = scanForCredentials(`k ${splitEvery(KEYS[0].key, ' ', 2)} yes`);
    expect(providerFindings(result.findings, 'openai')[0].action).toBe('blocked');
    expect(result.redactedContent).toBe('k [REDACTED-api_key-openai] z yes');
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

  it('blocks a memory write carrying a newline-split AWS access key id', async () => {
    const { runDefencePipeline } = await import('../pipeline.js');
    const result = runDefencePipeline(
      `aws id:\n${splitEvery(KEYS[3].key, '\n', 4)}\n`,
      'cloud note',
      { type: 'agent', identifier: 'test-agent' },
      testConfig,
    );
    expect(result.allowed).toBe(false);
    expect(result.firewall.threatIndicators).toContain('credential_leak');
  });
});
