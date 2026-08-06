/**
 * Current provider key-format coverage.
 *
 * Origin: a VDP report on 2026-08-05 showed the OpenAI detector missed
 * `sk-proj-*` — the default OpenAI key format since 2024 — because the regex
 * disallowed dashes. Auditing the rest of the file found the same staleness in
 * eight more providers, and a deeper root cause in the entropy net (below).
 *
 * This file is the standing rail: a detector that goes stale as a provider
 * rotates its format fails HERE, rather than in a stranger's email.
 *
 * ALL key material below is fabricated. Bodies are typed out as obvious
 * placeholder runs, never copied from a real credential.
 */
import { describe, it, expect } from '@jest/globals';
import { scanForCredentials } from '../credential-leak/index.js';
import { shannonEntropy, ENTROPY_THRESHOLD } from '../credential-leak/entropy.js';

/** Detected as a credential of any kind, by any detector. */
function detects(content: string): boolean {
  return scanForCredentials(content).findings.length > 0;
}

/** Detected specifically by a named provider pattern, not merely by entropy. */
function detectsAsProvider(content: string, provider: string): boolean {
  return scanForCredentials(content).findings.some((f) => f.provider === provider);
}

// Fabricated bodies. Long enough to clear each pattern's minimum length.
const B62 = 'aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789AbCdEfGh';
const HEX32 = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6';
const HEX40 = `${HEX32}a1b2c3d4`;
const HEX64 = `${HEX32}${HEX32}`;

describe('current provider key formats', () => {
  describe('OpenAI — the reported gap', () => {
    it('detects the legacy sk- format (unchanged behaviour)', () => {
      expect(detectsAsProvider(`sk-${B62}`, 'openai')).toBe(true);
    });

    // The reported bug. Every one of these was ALLOW before the fix.
    it.each([
      ['project key (default since 2024)', `sk-proj-${B62}`],
      ['service account key', `sk-svcacct-${B62}`],
      ['admin key (org billing/membership)', `sk-admin-${B62}`],
    ])('detects the %s', (_label, key) => {
      expect(detectsAsProvider(key, 'openai')).toBe(true);
    });

    // The researcher demonstrated the bypass in six separate contexts, not
    // just as a bare token. All six are pinned.
    it.each([
      ['bare', `sk-proj-${B62}`],
      ['in a sentence', `Please use my OpenAI key: sk-proj-${B62} for the calls`],
      ['in JSON', `{"api_key": "sk-proj-${B62}"}`],
      ['in a code block', '```\n' + `sk-proj-${B62}` + '\n```'],
      ['behind a label', `OpenAI: sk-proj-${B62}`],
      ['in single quotes', `key='sk-proj-${B62}'`],
    ])('detects a project key %s', (_ctx, content) => {
      expect(detects(content)).toBe(true);
    });

    it('does not double-report an Anthropic key as OpenAI', () => {
      // Why the fix enumerates prefixes instead of allowing `-` after `sk-`:
      // a free dash would make every sk-ant- key match the OpenAI pattern too.
      const providers = scanForCredentials(`sk-ant-api03-${B62}`).findings.map((f) => f.provider);
      expect(providers).toContain('anthropic');
      expect(providers).not.toContain('openai');
    });
  });

  describe('formats found stale while auditing the rest of the file', () => {
    it.each([
      ['GitHub App installation token (ghs_) — had no pattern at all', `ghs_${B62}`, 'github'],
      ['GitHub user-to-server token (ghu_)', `ghu_${B62}`, 'github'],
      ['GitHub refresh token (ghr_)', `ghr_${B62}`, 'github'],
      ['AWS STS temporary key (ASIA)', 'ASIAIOSFODNN7EXAMPLE', 'aws'],
      ['Stripe restricted key (rk_live_)', `rk_live_${B62}`, 'stripe'],
      ['Stripe webhook signing secret', `whsec_${B62}`, 'stripe'],
      ['Slack user token (xoxp-)', `xoxp-1234567890-1234567890123-${B62}`, 'slack'],
      ['Slack rotating token (xoxe.)', `xoxe.xoxb-1-${B62}`, 'slack'],
      ['Google OAuth client secret (GOCSPX-)', `GOCSPX-${B62}`, 'google'],
      ['DigitalOcean OAuth token (doo_v1_)', `doo_v1_${HEX64}`, 'digitalocean'],
      ['Twilio SID with uppercase hex', `SK${HEX32.toUpperCase()}`, 'twilio'],
    ])('detects %s', (_label, key, provider) => {
      expect(detectsAsProvider(key, provider)).toBe(true);
    });

    it('still detects the formats that were already covered', () => {
      for (const [key, provider] of [
        [`sk-ant-api03-${B62}`, 'anthropic'],
        ['AKIAIOSFODNN7EXAMPLE', 'aws'],
        [`ghp_${B62}`, 'github'],
        [`sk_live_${B62}`, 'stripe'],
        [`SG.${B62.slice(0, 22)}.${B62.slice(0, 43)}`, 'sendgrid'],
        [`AIza${B62.slice(0, 35)}`, 'google'],
        [`npm_${B62}`, 'npm'],
        [`hf_${B62.slice(0, 34)}`, 'huggingface'],
        [`dop_v1_${HEX64}`, 'digitalocean'],
        [`hvs.${B62}`, 'hashicorp'],
      ] as const) {
        expect(detectsAsProvider(key, provider)).toBe(true);
      }
    });
  });

  describe('entropy net — the root cause beneath the reported bug', () => {
    // The npm-package-specifier allowlist matched ANY token of
    // [a-z0-9._-] starting with a letter, case-insensitively. That is the
    // shape of most modern key material, so the entropy fallback — the net
    // that should catch formats no regex knows yet — was switched off for the
    // whole class. Fixing only the OpenAI regex would have left the net broken
    // for the NEXT format a provider invents.
    it('catches a novel dashed key shape that no pattern knows', () => {
      expect(detects(`zz-newprovider-${B62}`)).toBe(true);
    });

    it('the novel shape is genuinely above the entropy threshold', () => {
      expect(shannonEntropy(`zz-newprovider-${B62}`)).toBeGreaterThan(ENTROPY_THRESHOLD);
    });

    it('still ignores genuine npm package specifiers', () => {
      for (const spec of ['@types/node-18.11.18', 'eslint-config-airbnb-typescript', '@babel/plugin-transform-runtime']) {
        expect(detects(spec)).toBe(false);
      }
    });
  });

  describe('precision — realistic non-secrets must stay clean', () => {
    // Recall changes are where false positives get introduced. This battery is
    // the counterweight; the codebase has paid for FP regressions before.
    it.each([
      ['hyphenated prose starting sk-', 'I want to sk-etch out the sk-eleton of the plan'],
      ['kubernetes resource name', 'sk-frontend-production-deployment-blue-green'],
      ['git branch name', 'feature/add-user-authentication-flow-v2'],
      ['file path', 'src/defence/credential-leak/patterns.ts'],
      ['semver with prerelease', '4.47.30-beta.1'],
      ['git SHA', HEX40],
      ['sha256 digest', `sha256:${HEX64}`],
      ['UUID', '550e8400-e29b-41d4-a716-446655440000'],
      ['docker image ref', 'registry.fly.io/shieldcortex-api:deployment-01KZ0BEEQE85SGZC'],
      ['CSS class list', 'btn-primary-large-rounded-shadow-hover-active'],
      ['English sentence', 'The quick brown fox jumps over the lazy dog repeatedly today'],
      ['env var name without a value', 'OPENAI_API_KEY'],
      ['redacted key in a log line', 'using key sk-proj-****REDACTED****'],
    ])('does not flag %s', (_label, content) => {
      expect(detects(content)).toBe(false);
    });

    it('reports a Stripe publishable key, but only at medium severity', () => {
      // Publishable keys are designed to be public, so this is deliberately
      // not a critical finding — pinned because it is easy to "tidy" either
      // into silence (losing a real signal) or up to critical (noise).
      const findings = scanForCredentials('pk_test_TYooMQauvdEDq54NiTphI7jx').findings;
      expect(findings.length).toBeGreaterThan(0);
      expect(findings.every((f) => f.severity !== 'critical')).toBe(true);
    });
  });
});
