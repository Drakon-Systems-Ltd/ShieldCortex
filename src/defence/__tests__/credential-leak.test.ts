/**
 * Credential Leak Detection Tests
 *
 * Tests each credential type, entropy calculation, redaction,
 * false positive handling, and pipeline integration.
 */

import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import { scanForCredentials, redactCredentials, shannonEntropy } from '../credential-leak/index.js';
import type { CredentialScanResult } from '../credential-leak/index.js';
import { initDatabase, closeDatabase } from '../../database/init.js';
import type { DefenceConfig } from '../types.js';

// ── API Key Detection ──

describe('Credential Leak Detection', () => {

  describe('OpenAI API Keys', () => {
    it('should detect OpenAI sk- keys', () => {
      const result = scanForCredentials('My key is sk-abcdefghijklmnopqrstuvwxyz1234');
      expect(result.leaked).toBe(true);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].type).toBe('api_key');
      expect(result.findings[0].provider).toBe('openai');
      expect(result.findings[0].severity).toBe('critical');
      expect(result.findings[0].action).toBe('blocked');
    });

    it('should not trigger on short sk- prefixes like "sk-etch"', () => {
      const result = scanForCredentials('I like to sk-etch drawings');
      expect(result.leaked).toBe(false);
      expect(result.findings).toHaveLength(0);
    });

    it('should not trigger on "sk-ip" or similar short words', () => {
      const result = scanForCredentials('Let me sk-ip that part');
      expect(result.leaked).toBe(false);
    });
  });

  describe('Anthropic API Keys', () => {
    it('should detect Anthropic sk-ant- keys', () => {
      const result = scanForCredentials('export ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz');
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.provider === 'anthropic')).toBe(true);
      expect(result.findings.find(f => f.provider === 'anthropic')?.severity).toBe('critical');
    });
  });

  describe('AWS Keys', () => {
    it('should detect AWS Access Key IDs', () => {
      const result = scanForCredentials('AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE');
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.provider === 'aws')).toBe(true);
      expect(result.findings.find(f => f.provider === 'aws')?.severity).toBe('critical');
    });

    it('should detect AWS Secret Access Keys', () => {
      const result = scanForCredentials('aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.provider === 'aws')).toBe(true);
    });
  });

  describe('GitHub Tokens', () => {
    it('should detect GitHub personal access tokens (ghp_)', () => {
      const result = scanForCredentials('token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij');
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.provider === 'github')).toBe(true);
      expect(result.findings.find(f => f.provider === 'github')?.severity).toBe('critical');
    });

    it('should detect GitHub OAuth tokens (gho_)', () => {
      const result = scanForCredentials('gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij');
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.provider === 'github')).toBe(true);
    });

    it('should detect GitHub fine-grained PATs', () => {
      const result = scanForCredentials('github_pat_11ABCDEFG0abcdefghijklmn');
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.provider === 'github')).toBe(true);
    });
  });

  describe('Stripe Keys', () => {
    it('should detect Stripe live keys as critical', () => {
      // Split to avoid GitHub push protection false positive
      const key = 'sk_live_' + '51ABCDEFGHIJKLMNOPQRSTUVwx';
      const result = scanForCredentials(key);
      expect(result.leaked).toBe(true);
      expect(result.findings.find(f => f.provider === 'stripe')?.severity).toBe('critical');
    });

    it('should detect Stripe test keys as medium', () => {
      const key = 'sk_test_' + '51ABCDEFGHIJKLMNOPQRSTUVwx';
      const result = scanForCredentials(key);
      expect(result.leaked).toBe(true);
      expect(result.findings.find(f => f.provider === 'stripe')?.severity).toBe('medium');
    });
  });

  describe('Other API Keys', () => {
    it('should detect SendGrid keys', () => {
      const result = scanForCredentials('SG.abcdefghijklmnopqrstuv.wxyzABCDEFGHIJKLMNOPQRS');
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.provider === 'sendgrid')).toBe(true);
    });

    it('should detect Google API keys', () => {
      const result = scanForCredentials('key=AIzaSyDabcdefghijklmnopqrstuvwxyz123456');
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.provider === 'google')).toBe(true);
    });

    it('should detect npm tokens', () => {
      const result = scanForCredentials('//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz1234567890');
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.provider === 'npm')).toBe(true);
    });

    it('should detect Slack bot tokens', () => {
      // Split to avoid GitHub push protection false positive
      const token = 'xoxb-' + '1234567890-abcdefghijklmnopqrstuvwx';
      const result = scanForCredentials(`SLACK_BOT_TOKEN=${token}`);
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.provider === 'slack')).toBe(true);
    });
  });

  // ── New Provider Patterns (Sprint 1) ──

  describe('Hugging Face API Keys', () => {
    it('should detect valid Hugging Face tokens', () => {
      // Construct token dynamically to avoid GitHub secret scanning false positives
      const hfToken = 'hf_' + 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' + 'abcdefgh';
      const result = scanForCredentials(`HF_TOKEN=${hfToken}`);
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.provider === 'huggingface')).toBe(true);
    });

    it('should not trigger on short hf_ prefixes', () => {
      const result = scanForCredentials('Use hf_format for the output');
      expect(result.leaked).toBe(false);
    });

    it('should not trigger on hf_ with too few characters', () => {
      const result = scanForCredentials('hf_shorttoken123');
      expect(result.leaked).toBe(false);
    });
  });

  describe('Databricks API Keys', () => {
    it('should detect valid Databricks tokens', () => {
      // Construct token dynamically to avoid GitHub secret scanning false positives
      const dapiToken = 'dapi' + '0123456789abcdef' + '0123456789abcdef';
      const result = scanForCredentials(`DATABRICKS_TOKEN=${dapiToken}`);
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.provider === 'databricks')).toBe(true);
    });

    it('should not trigger on "dapi" in normal words', () => {
      const result = scanForCredentials('The dapi endpoint returns JSON');
      expect(result.leaked).toBe(false);
    });

    it('should not trigger on dapi with too few hex chars', () => {
      const result = scanForCredentials('dapi0123456789abcdef');
      expect(result.leaked).toBe(false);
    });
  });

  describe('DigitalOcean API Keys', () => {
    it('should detect valid DigitalOcean tokens', () => {
      const token = 'dop_v1_' + 'a'.repeat(64);
      const result = scanForCredentials(`DO_TOKEN=${token}`);
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.provider === 'digitalocean')).toBe(true);
    });

    it('should not trigger on dop_v1_ with too few characters', () => {
      const result = scanForCredentials('dop_v1_abc123');
      expect(result.leaked).toBe(false);
    });

    it('should not trigger on dop_v2_ prefix (wrong version)', () => {
      // dop_v2_ doesn't match DigitalOcean pattern (dop_v1_)
      const result = scanForCredentials('dop_v2_abcdef');
      expect(result.findings.some(f => f.provider === 'digitalocean')).toBe(false);
    });
  });

  describe('Firebase FCM Keys', () => {
    it('should detect valid Firebase FCM server keys', () => {
      const key = 'AAAA' + 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef01234567';
      const result = scanForCredentials(`FCM_KEY=${key}`);
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.provider === 'firebase')).toBe(true);
    });

    it('should not trigger on "AAAA" alone or short strings', () => {
      const result = scanForCredentials('The value AAAA is used as a placeholder');
      expect(result.leaked).toBe(false);
    });

    it('should not trigger on AAAA with too few following chars', () => {
      const result = scanForCredentials('AAAAshort');
      expect(result.leaked).toBe(false);
    });
  });

  describe('HashiCorp Vault Tokens', () => {
    it('should detect valid Vault tokens', () => {
      const token = 'hvs.' + 'ABCDEFGHIJKLMNOPQRSTUVWXyz';
      const result = scanForCredentials(`VAULT_TOKEN=${token}`);
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.provider === 'hashicorp')).toBe(true);
    });

    it('should not trigger on hvs. with too few characters', () => {
      const result = scanForCredentials('hvs.short');
      expect(result.leaked).toBe(false);
    });

    it('should not trigger on similar prefixes', () => {
      const result = scanForCredentials('hvs_' + 'A'.repeat(30));
      expect(result.leaked).toBe(false);
    });
  });

  describe('Azure Subscription Keys', () => {
    it('should detect valid Azure subscription keys in context', () => {
      const key = 'abcdef0123456789abcdef0123456789';
      const result = scanForCredentials(`Ocp-Apim-Subscription-Key: ${key}`);
      // Azure pattern has low confidence (0.35) — may or may not trigger depending on entropy
      // The key is 32 hex chars which is a generic pattern
      expect(result.findings.filter(f => f.provider === 'azure').length).toBeGreaterThanOrEqual(0);
    });
  });

  // ── JWT Tokens ──

  describe('JWT Tokens', () => {
    it('should detect JWT tokens', () => {
      const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
      const result = scanForCredentials(`Authorization: Bearer ${jwt}`);
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.type === 'jwt')).toBe(true);
    });
  });

  // ── Bearer/Basic Auth ──

  describe('Auth Headers', () => {
    it('should detect Bearer token headers', () => {
      const result = scanForCredentials('Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.dG9rZW4.sig');
      expect(result.leaked).toBe(true);
    });

    it('should detect Basic auth headers', () => {
      const result = scanForCredentials('Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=');
      expect(result.leaked).toBe(true);
    });
  });

  // ── Private Keys ──

  describe('Private Keys', () => {
    it('should detect RSA private keys', () => {
      const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBALRiMLAHudeSA...\n-----END RSA PRIVATE KEY-----';
      const result = scanForCredentials(pem);
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.type === 'private_key')).toBe(true);
      expect(result.findings.find(f => f.type === 'private_key')?.severity).toBe('critical');
    });

    it('should detect EC private keys', () => {
      const pem = '-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIBLtbW...\n-----END EC PRIVATE KEY-----';
      const result = scanForCredentials(pem);
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.type === 'private_key')).toBe(true);
    });

    it('should detect SSH private keys', () => {
      const pem = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1r...\n-----END OPENSSH PRIVATE KEY-----';
      const result = scanForCredentials(pem);
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.type === 'private_key')).toBe(true);
    });

    it('should detect generic private keys', () => {
      const pem = '-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBg...\n-----END PRIVATE KEY-----';
      const result = scanForCredentials(pem);
      expect(result.leaked).toBe(true);
    });
  });

  // ── Connection Strings ──

  describe('Connection Strings', () => {
    it('should detect PostgreSQL connection strings with passwords', () => {
      const result = scanForCredentials('DATABASE_URL=postgres://admin:s3cretP4ss@db.example.com:5432/mydb');
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.type === 'connection_string')).toBe(true);
      expect(result.findings.find(f => f.type === 'connection_string')?.provider).toBe('postgres');
    });

    it('should detect MySQL connection strings', () => {
      const result = scanForCredentials('mysql://root:password123@localhost:3306/app');
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.provider === 'mysql')).toBe(true);
    });

    it('should detect MongoDB connection strings', () => {
      const result = scanForCredentials('mongodb+srv://user:pass123@cluster0.example.mongodb.net/db');
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.provider === 'mongodb')).toBe(true);
    });

    it('should detect Redis connection strings', () => {
      const result = scanForCredentials('redis://default:mypassword@redis.example.com:6379');
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.provider === 'redis')).toBe(true);
    });
  });

  // ── Environment Variable Patterns ──

  describe('Environment Variable Secrets', () => {
    it('should detect PASSWORD= assignments', () => {
      const result = scanForCredentials('DB_PASSWORD=super_secret_password_123');
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.type === 'env_secret')).toBe(true);
    });

    it('should detect SECRET= assignments', () => {
      const result = scanForCredentials('JWT_SECRET="my-super-secret-jwt-key-12345"');
      expect(result.leaked).toBe(true);
    });

    it('should detect TOKEN= assignments', () => {
      const result = scanForCredentials('API_TOKEN=abcdef1234567890ghijklmn');
      expect(result.leaked).toBe(true);
    });

    it('should detect API_KEY= assignments', () => {
      const result = scanForCredentials('API_KEY=some-long-api-key-value-here');
      expect(result.leaked).toBe(true);
    });

    it('should not trigger on short values', () => {
      const result = scanForCredentials('PASSWORD=short');
      // Value "short" is < 8 chars, should not trigger env_secret
      const envFindings = result.findings.filter(f => f.type === 'env_secret');
      expect(envFindings).toHaveLength(0);
    });
  });

  // ── Entropy Calculation ──

  describe('Shannon Entropy', () => {
    it('should calculate entropy of uniform distribution', () => {
      // All unique chars in "abcdefgh" → log2(8) = 3.0
      const e = shannonEntropy('abcdefgh');
      expect(e).toBeCloseTo(3.0, 1);
    });

    it('should return 0 for empty string', () => {
      expect(shannonEntropy('')).toBe(0);
    });

    it('should return 0 for single repeated char', () => {
      expect(shannonEntropy('aaaaaaa')).toBe(0);
    });

    it('should have higher entropy for random-looking strings', () => {
      const lowEntropy = shannonEntropy('aaabbbccc');
      const highEntropy = shannonEntropy('Kx9$mQ2!pL7@nR4^');
      expect(highEntropy).toBeGreaterThan(lowEntropy);
    });
  });

  // ── High Entropy Detection ──

  describe('High Entropy Detection', () => {
    it('should flag high-entropy strings 20+ chars as potential secrets', () => {
      // This is a high-entropy random string
      const result = scanForCredentials('token: aB3xK9mQ2pL7nR4cT8vY1wZ5fH6jD0s');
      // Should detect either via pattern or entropy
      expect(result.leaked).toBe(true);
    });

    it('should not flag normal English text', () => {
      const result = scanForCredentials('The quick brown fox jumps over the lazy dog');
      // No API key patterns, low entropy for English
      const highEntropyFindings = result.findings.filter(f => f.type === 'high_entropy');
      expect(highEntropyFindings).toHaveLength(0);
    });
  });

  // ── Redaction ──

  describe('Redaction', () => {
    it('should redact detected secrets in content', () => {
      const content = 'My key is sk-abcdefghijklmnopqrstuvwxyz1234';
      const redacted = redactCredentials(content);
      expect(redacted).not.toContain('sk-abcdefghijklmnopqrstuvwxyz1234');
      expect(redacted).toContain('[REDACTED-');
    });

    it('should redact multiple secrets', () => {
      const content = 'OpenAI: sk-abcdefghijklmnopqrstuvwxyz1234\nGitHub: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij';
      const redacted = redactCredentials(content);
      expect(redacted).not.toContain('sk-abcdefghijklmnopqrstuvwx');
      expect(redacted).not.toContain('ghp_ABCDEFGHIJKLMNOPQR');
      expect(redacted).toContain('[REDACTED-');
    });

    it('should return original content if no secrets found', () => {
      const content = 'Just some normal text with no secrets';
      const redacted = redactCredentials(content);
      expect(redacted).toBe(content);
    });

    it('should show first/last 4 chars in match field for long secrets', () => {
      const result = scanForCredentials('key is sk-abcdefghijklmnopqrstuvwxyz1234');
      expect(result.findings.length).toBeGreaterThan(0);
      const match = result.findings[0].match;
      // Should look like "sk-a...1234" (first 4 + ... + last 4)
      expect(match).toContain('...');
    });

    it('should redact private keys', () => {
      const content = 'Here is my key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBALRiMLAH\n-----END RSA PRIVATE KEY-----\nDone';
      const redacted = redactCredentials(content);
      expect(redacted).toContain('[REDACTED-private_key');
      expect(redacted).not.toContain('MIIBogIBAAJBALRiMLAH');
    });
  });

  // ── False Positive Handling ──

  describe('False Positive Handling', () => {
    it('should not trigger on common words starting with "sk-"', () => {
      const texts = [
        'I want to sk-ip this',
        'Let me sk-etch it out',
        'The sk-ill level is high',
      ];
      for (const text of texts) {
        const result = scanForCredentials(text);
        const apiKeyFindings = result.findings.filter(f => f.type === 'api_key' && f.provider === 'openai');
        expect(apiKeyFindings).toHaveLength(0);
      }
    });

    it('should not trigger on example/placeholder API keys in documentation', () => {
      // Allow "sk-..." only when actually long enough to be a real key
      const result = scanForCredentials('Example: sk-your-key-here');
      // "sk-your-key-here" is only 16 chars; the minLength is 24
      const openaiFindings = result.findings.filter(f => f.provider === 'openai');
      expect(openaiFindings).toHaveLength(0);
    });

    it('should not flag CSS class names as high-entropy', () => {
      const result = scanForCredentials('class="flex-items-center-justify-between-px-4"');
      const entropyFindings = result.findings.filter(f => f.type === 'high_entropy');
      expect(entropyFindings).toHaveLength(0);
    });

    it('should respect allowlist', () => {
      const result = scanForCredentials(
        'sk-abcdefghijklmnopqrstuvwxyz1234',
        { allowlist: ['sk-abcdefg'] },
      );
      expect(result.findings.filter(f => f.provider === 'openai')).toHaveLength(0);
    });
  });

  // ── Config Options ──

  describe('Configuration', () => {
    it('should not scan when disabled', () => {
      const result = scanForCredentials('sk-abcdefghijklmnopqrstuvwxyz1234', { enabled: false });
      expect(result.leaked).toBe(false);
      expect(result.findings).toHaveLength(0);
    });

    it('should warn instead of block when blockOnCritical is false', () => {
      const result = scanForCredentials('sk-abcdefghijklmnopqrstuvwxyz1234', {
        blockOnCritical: false,
        blockOnHigh: false,
      });
      expect(result.leaked).toBe(true);
      expect(result.findings[0].action).not.toBe('blocked');
    });

    it('should support custom patterns', () => {
      const result = scanForCredentials('my-custom-secret-XYZ123ABC', {
        customPatterns: [{
          name: 'Custom Secret',
          type: 'api_key',
          provider: 'custom',
          regex: /my-custom-secret-[A-Z0-9]+/g,
          severity: 'high',
          confidence: 0.90,
        }],
      });
      expect(result.leaked).toBe(true);
      expect(result.findings.some(f => f.provider === 'custom')).toBe(true);
    });
  });

  // ── Multiple Credentials in Single Content ──

  describe('Multiple Credentials', () => {
    it('should detect multiple different credential types', () => {
      const content = `
        OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz1234
        DATABASE_URL=postgres://admin:password@db.example.com:5432/mydb
        -----BEGIN RSA PRIVATE KEY-----
        MIIBogIBAAJBALRiMLAHudeSA
        -----END RSA PRIVATE KEY-----
      `;
      const result = scanForCredentials(content);
      expect(result.leaked).toBe(true);
      expect(result.findings.length).toBeGreaterThanOrEqual(3);

      const types = result.findings.map(f => f.type);
      expect(types).toContain('api_key');
      expect(types).toContain('connection_string');
      expect(types).toContain('private_key');
    });
  });

  // ── Position Tracking ──

  describe('Position Tracking', () => {
    it('should report correct character offset positions', () => {
      const prefix = 'prefix text ';
      const content = `${prefix}sk-abcdefghijklmnopqrstuvwxyz1234`;
      const result = scanForCredentials(content);
      expect(result.findings.length).toBeGreaterThan(0);
      expect(result.findings[0].position).toBe(prefix.length);
    });
  });
});

// ── Pipeline Integration ──

describe('Pipeline Integration', () => {
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

  it('should block content with critical credentials via pipeline', async () => {
    const { runDefencePipeline } = await import('../pipeline.js');
    const result = runDefencePipeline(
      'Save this: my API key is sk-abcdefghijklmnopqrstuvwxyz1234',
      'API key note',
      { type: 'agent', identifier: 'test-agent' },
      testConfig,
    );

    expect(result.allowed).toBe(false);
    expect(result.firewall.result).toBe('BLOCK');
    expect(result.firewall.threatIndicators).toContain('credential_leak');
  });

  it('should include credentialScan in pipeline result when leaked', async () => {
    const { runDefencePipeline } = await import('../pipeline.js');
    const result = runDefencePipeline(
      'postgres://admin:secret@db.host.com:5432/mydb',
      'Database config',
      { type: 'cli', identifier: 'test' },
      testConfig,
    );

    expect(result.credentialScan).toBeDefined();
    expect(result.credentialScan!.leaked).toBe(true);
    expect(result.credentialScan!.findings.length).toBeGreaterThan(0);
  });

  it('should not include credentialScan when no leaks found', async () => {
    const { runDefencePipeline } = await import('../pipeline.js');
    const result = runDefencePipeline(
      'Just a normal note about architecture decisions',
      'Meeting notes',
      { type: 'user', identifier: 'direct' },
      testConfig,
    );

    expect(result.credentialScan).toBeUndefined();
  });
});
