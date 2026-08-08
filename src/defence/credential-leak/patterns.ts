/**
 * Credential Leak Detection — Pattern Definitions
 *
 * Known API key formats, secret patterns, and heuristic matchers
 * for detecting accidentally persisted credentials in AI agent memory.
 */

export interface CredentialPattern {
  name: string;
  type: CredentialType;
  provider?: string;
  regex: RegExp;
  severity: CredentialSeverity;
  /** Base confidence when pattern matches (can be boosted by entropy) */
  confidence: number;
  /** Minimum match length to avoid false positives */
  minLength?: number;
}

export type CredentialType =
  | 'api_key'
  | 'jwt'
  | 'private_key'
  | 'connection_string'
  | 'env_secret'
  | 'high_entropy';

export type CredentialSeverity = 'critical' | 'high' | 'medium' | 'low';

// ── Known API Key Patterns ──

export const API_KEY_PATTERNS: CredentialPattern[] = [
  // OpenAI — legacy `sk-` + body. No longer issued, but still valid in the wild.
  {
    name: 'OpenAI API Key',
    type: 'api_key',
    provider: 'openai',
    regex: /sk-[A-Za-z0-9]{20,}/g,
    severity: 'critical',
    confidence: 0.95,
    minLength: 24,
  },
  // OpenAI — modern prefixed keys. `sk-proj-` has been the default since 2024,
  // so the legacy pattern above misses essentially every key issued since.
  //
  // The prefixes are enumerated rather than allowing `-` freely after `sk-`
  // (i.e. NOT /sk-[A-Za-z0-9\-_]{20,}/). A free dash would match ordinary
  // hyphenated prose starting "sk-" and would also double-fire on every
  // Anthropic `sk-ant-` key. Enumeration keeps recall without spending
  // precision — the thing this codebase can least afford.
  {
    name: 'OpenAI Project API Key',
    type: 'api_key',
    provider: 'openai',
    regex: /sk-proj-[A-Za-z0-9_-]{20,}/g,
    severity: 'critical',
    confidence: 0.97,
  },
  {
    name: 'OpenAI Service Account Key',
    type: 'api_key',
    provider: 'openai',
    regex: /sk-svcacct-[A-Za-z0-9_-]{20,}/g,
    severity: 'critical',
    confidence: 0.97,
  },
  {
    // Org-level: billing, membership and project administration.
    name: 'OpenAI Admin Key',
    type: 'api_key',
    provider: 'openai',
    regex: /sk-admin-[A-Za-z0-9_-]{20,}/g,
    severity: 'critical',
    confidence: 0.97,
  },
  // Anthropic
  {
    name: 'Anthropic API Key',
    type: 'api_key',
    provider: 'anthropic',
    regex: /sk-ant-[A-Za-z0-9\-_]{20,}/g,
    severity: 'critical',
    confidence: 0.98,
  },
  // AWS Access Key. ASIA = STS temporary credentials; short-lived, but a live
  // one plus its session token is full account access for its TTL.
  {
    name: 'AWS Access Key ID',
    type: 'api_key',
    provider: 'aws',
    regex: /A[KS]IA[0-9A-Z]{16}/g,
    severity: 'critical',
    confidence: 0.97,
  },
  // AWS Secret Key (typically base64-like, 40 chars)
  {
    name: 'AWS Secret Access Key',
    type: 'api_key',
    provider: 'aws',
    regex: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|SecretAccessKey)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/g,
    severity: 'critical',
    confidence: 0.95,
  },
  // GitHub tokens
  {
    name: 'GitHub Personal Access Token',
    type: 'api_key',
    provider: 'github',
    regex: /ghp_[A-Za-z0-9]{36,}/g,
    severity: 'critical',
    confidence: 0.98,
  },
  {
    name: 'GitHub OAuth Token',
    type: 'api_key',
    provider: 'github',
    regex: /gho_[A-Za-z0-9]{36,}/g,
    severity: 'critical',
    confidence: 0.98,
  },
  {
    // ghu_ user-to-server, ghs_ App installation, ghr_ refresh.
    // ghs_ in particular is what CI and agent runners carry, and it had no
    // pattern at all before this — the widest of the confirmed gaps.
    name: 'GitHub App Token',
    type: 'api_key',
    provider: 'github',
    regex: /gh[usr]_[A-Za-z0-9]{36,}/g,
    severity: 'critical',
    confidence: 0.98,
  },
  {
    name: 'GitHub Fine-grained PAT',
    type: 'api_key',
    provider: 'github',
    regex: /github_pat_[A-Za-z0-9_]{22,}/g,
    severity: 'critical',
    confidence: 0.98,
  },
  // Stripe
  {
    name: 'Stripe Live Key',
    type: 'api_key',
    provider: 'stripe',
    regex: /sk_live_[A-Za-z0-9]{24,}/g,
    severity: 'critical',
    confidence: 0.98,
  },
  {
    name: 'Stripe Test Key',
    type: 'api_key',
    provider: 'stripe',
    regex: /sk_test_[A-Za-z0-9]{24,}/g,
    severity: 'medium',
    confidence: 0.95,
  },
  {
    // Restricted keys. Stripe's own guidance now steers users off sk_ onto
    // rk_, so today's gap is tomorrow's default.
    name: 'Stripe Restricted Key',
    type: 'api_key',
    provider: 'stripe',
    regex: /rk_(?:live|test)_[A-Za-z0-9]{24,}/g,
    severity: 'critical',
    confidence: 0.97,
  },
  {
    name: 'Stripe Publishable Key',
    type: 'api_key',
    provider: 'stripe',
    regex: /pk_(?:live|test)_[A-Za-z0-9]{24,}/g,
    severity: 'medium',
    confidence: 0.90,
  },
  {
    // Webhook signing secret — forges inbound events if leaked.
    name: 'Stripe Webhook Signing Secret',
    type: 'api_key',
    provider: 'stripe',
    regex: /whsec_[A-Za-z0-9]{24,}/g,
    severity: 'critical',
    confidence: 0.96,
  },
  // Twilio
  {
    name: 'Twilio API Key',
    type: 'api_key',
    provider: 'twilio',
    // Twilio's spec permits uppercase hex; the old class missed those SIDs.
    regex: /SK[a-fA-F0-9]{32}/g,
    severity: 'critical',
    confidence: 0.90,
  },
  // SendGrid
  {
    name: 'SendGrid API Key',
    type: 'api_key',
    provider: 'sendgrid',
    regex: /SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{22,}/g,
    severity: 'critical',
    confidence: 0.97,
  },
  // Slack
  {
    name: 'Slack Bot Token',
    type: 'api_key',
    provider: 'slack',
    regex: /xoxb-[0-9]{10,}-[0-9A-Za-z\-]{20,}/g,
    severity: 'critical',
    confidence: 0.96,
  },
  {
    // xoxp- user tokens carry a human's full workspace scope — arguably worse
    // than the bot token above. xoxa-/xoxr- are the legacy app/refresh pair.
    name: 'Slack User Token',
    type: 'api_key',
    provider: 'slack',
    regex: /xox[par]-[0-9]{10,}-[0-9A-Za-z\-]{20,}/g,
    severity: 'critical',
    confidence: 0.96,
  },
  {
    // App-level token (connections/socket mode).
    name: 'Slack App-Level Token',
    type: 'api_key',
    provider: 'slack',
    regex: /xapp-[0-9]-[A-Z0-9]{9,}-[0-9]{10,}-[a-f0-9]{40,}/g,
    severity: 'critical',
    confidence: 0.96,
  },
  {
    // Rotation-era tokens: xoxe.xoxb-… / xoxe-… . The bot pattern above
    // cannot match these — its `[0-9]{10,}` segment fails on the xoxe prefix.
    name: 'Slack Rotating Token',
    type: 'api_key',
    provider: 'slack',
    regex: /xoxe[.-][A-Za-z0-9.\-]{20,}/g,
    severity: 'critical',
    confidence: 0.95,
  },
  {
    name: 'Slack Webhook URL',
    type: 'api_key',
    provider: 'slack',
    regex: /https:\/\/hooks\.slack\.com\/(?:services|triggers)\/T[A-Z0-9]{8,}\/B?[A-Z0-9]{8,}\/[A-Za-z0-9]{20,}/g,
    severity: 'high',
    confidence: 0.95,
  },
  // Google
  {
    name: 'Google API Key',
    type: 'api_key',
    provider: 'google',
    regex: /AIza[A-Za-z0-9\-_]{35}/g,
    severity: 'critical',
    confidence: 0.95,
  },
  {
    name: 'Google OAuth Client Secret',
    type: 'api_key',
    provider: 'google',
    regex: /GOCSPX-[A-Za-z0-9_-]{20,}/g,
    severity: 'critical',
    confidence: 0.97,
  },
  // Mailgun
  {
    name: 'Mailgun API Key',
    type: 'api_key',
    provider: 'mailgun',
    regex: /key-[A-Za-z0-9]{32}/g,
    severity: 'critical',
    confidence: 0.85,
  },
  // npm
  {
    name: 'npm Access Token',
    type: 'api_key',
    provider: 'npm',
    regex: /npm_[A-Za-z0-9]{36,}/g,
    severity: 'critical',
    confidence: 0.97,
  },
  // Heroku
  {
    name: 'Heroku API Key',
    type: 'api_key',
    provider: 'heroku',
    regex: /[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/g,
    severity: 'low',
    confidence: 0.30,
    // UUIDs are very common — only flagged as low confidence
  },
  // Hugging Face
  {
    name: 'Hugging Face API Token',
    type: 'api_key',
    provider: 'huggingface',
    regex: /hf_[A-Za-z0-9]{34,}/g,
    severity: 'critical',
    confidence: 0.96,
  },
  // Databricks
  {
    name: 'Databricks API Token',
    type: 'api_key',
    provider: 'databricks',
    regex: /dapi[a-f0-9]{32,}/g,
    severity: 'critical',
    confidence: 0.94,
  },
  // DigitalOcean
  {
    name: 'DigitalOcean Personal Access Token',
    type: 'api_key',
    provider: 'digitalocean',
    // dop_ personal access, doo_ OAuth access, dor_ refresh.
    regex: /do[opr]_v1_[a-f0-9]{64}/g,
    severity: 'critical',
    confidence: 0.97,
  },
  // Firebase Cloud Messaging
  {
    name: 'Firebase Cloud Messaging Key',
    type: 'api_key',
    provider: 'firebase',
    regex: /AAAA[A-Za-z0-9_-]{40,}/g,
    severity: 'critical',
    confidence: 0.90,
    minLength: 44,
  },
  // HashiCorp Vault
  {
    name: 'HashiCorp Vault Token',
    type: 'api_key',
    provider: 'hashicorp',
    regex: /hvs\.[A-Za-z0-9_-]{24,}/g,
    severity: 'critical',
    confidence: 0.96,
  },
  // Azure Subscription Key
  {
    name: 'Azure Subscription Key',
    type: 'api_key',
    provider: 'azure',
    regex: /[a-f0-9]{32}/g,
    severity: 'medium',
    confidence: 0.35,
    minLength: 32,
  },
];

// ── Generic Secret Patterns ──

export const GENERIC_SECRET_PATTERNS: CredentialPattern[] = [
  // JWT tokens
  {
    name: 'JWT Token',
    type: 'jwt',
    regex: /eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/g,
    severity: 'high',
    confidence: 0.92,
  },
  // Bearer tokens in headers
  {
    name: 'Bearer Token',
    type: 'api_key',
    regex: /(?:Authorization|authorization)\s*:\s*Bearer\s+([A-Za-z0-9\-_./+=]{20,})/g,
    severity: 'high',
    confidence: 0.90,
  },
  // Basic auth headers
  {
    name: 'Basic Auth Header',
    type: 'api_key',
    regex: /(?:Authorization|authorization)\s*:\s*Basic\s+([A-Za-z0-9+/=]{8,})/g,
    severity: 'high',
    confidence: 0.88,
  },
];

// ── Private Key Patterns ──

export const PRIVATE_KEY_PATTERNS: CredentialPattern[] = [
  {
    name: 'RSA Private Key',
    type: 'private_key',
    provider: 'rsa',
    regex: /-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+RSA\s+PRIVATE\s+KEY-----/g,
    severity: 'critical',
    confidence: 0.99,
  },
  {
    name: 'EC Private Key',
    type: 'private_key',
    provider: 'ec',
    regex: /-----BEGIN\s+EC\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+EC\s+PRIVATE\s+KEY-----/g,
    severity: 'critical',
    confidence: 0.99,
  },
  {
    name: 'Generic Private Key',
    type: 'private_key',
    regex: /-----BEGIN\s+(?:ENCRYPTED\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:ENCRYPTED\s+)?PRIVATE\s+KEY-----/g,
    severity: 'critical',
    confidence: 0.99,
  },
  {
    name: 'SSH Private Key',
    type: 'private_key',
    provider: 'ssh',
    regex: /-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+OPENSSH\s+PRIVATE\s+KEY-----/g,
    severity: 'critical',
    confidence: 0.99,
  },
];

// ── Connection String Patterns ──

export const CONNECTION_STRING_PATTERNS: CredentialPattern[] = [
  {
    name: 'PostgreSQL Connection String',
    type: 'connection_string',
    provider: 'postgres',
    regex: /postgres(?:ql)?:\/\/[^\s"'`]+:[^\s"'`@]+@[^\s"'`]+/g,
    severity: 'critical',
    confidence: 0.95,
  },
  {
    name: 'MySQL Connection String',
    type: 'connection_string',
    provider: 'mysql',
    regex: /mysql:\/\/[^\s"'`]+:[^\s"'`@]+@[^\s"'`]+/g,
    severity: 'critical',
    confidence: 0.95,
  },
  {
    name: 'MongoDB Connection String',
    type: 'connection_string',
    provider: 'mongodb',
    regex: /mongodb(?:\+srv)?:\/\/[^\s"'`]+:[^\s"'`@]+@[^\s"'`]+/g,
    severity: 'critical',
    confidence: 0.95,
  },
  {
    name: 'Redis Connection String',
    type: 'connection_string',
    provider: 'redis',
    regex: /redis(?:s)?:\/\/[^\s"'`]*:[^\s"'`@]+@[^\s"'`]+/g,
    severity: 'critical',
    confidence: 0.93,
  },
];

// ── Environment Variable Patterns ──

export const ENV_SECRET_PATTERNS: CredentialPattern[] = [
  {
    name: 'Password Assignment',
    type: 'env_secret',
    regex: /(?:PASSWORD|PASSWD|DB_PASS|DB_PASSWORD|ADMIN_PASSWORD|ROOT_PASSWORD)\s*[=:]\s*["']?([^\s"']{8,})["']?/gi,
    severity: 'high',
    confidence: 0.85,
  },
  {
    name: 'Secret Assignment',
    type: 'env_secret',
    regex: /(?:SECRET|SECRET_KEY|APP_SECRET|JWT_SECRET|SESSION_SECRET|ENCRYPTION_KEY)\s*[=:]\s*["']?([^\s"']{8,})["']?/gi,
    severity: 'high',
    confidence: 0.85,
  },
  {
    name: 'Token Assignment',
    type: 'env_secret',
    regex: /(?:TOKEN|ACCESS_TOKEN|REFRESH_TOKEN|AUTH_TOKEN|API_TOKEN|BEARER_TOKEN)\s*[=:]\s*["']?([^\s"']{8,})["']?/gi,
    severity: 'high',
    confidence: 0.82,
  },
  {
    name: 'API Key Assignment',
    type: 'env_secret',
    regex: /(?:API_KEY|APIKEY|API_SECRET)\s*[=:]\s*["']?([^\s"']{8,})["']?/gi,
    severity: 'high',
    confidence: 0.82,
  },
];

// ── All Patterns Combined (in priority order) ──

export const ALL_CREDENTIAL_PATTERNS: CredentialPattern[] = [
  ...PRIVATE_KEY_PATTERNS,
  ...API_KEY_PATTERNS,
  ...CONNECTION_STRING_PATTERNS,
  ...GENERIC_SECRET_PATTERNS,
  ...ENV_SECRET_PATTERNS,
];

// ── Single Source of Truth — pattern lookup by name (Phase 17 C3) ──

/** Index of every credential pattern by its `name`, for cross-module reuse. */
const PATTERNS_BY_NAME: ReadonlyMap<string, CredentialPattern> = new Map(
  ALL_CREDENTIAL_PATTERNS.map((p) => [p.name, p]),
);

/**
 * Fetch specific credential pattern SOURCES by name from the single source of
 * truth. Lets other detectors (e.g. fragmentation entity extraction) reuse the
 * canonical token regexes instead of maintaining their own divergent copies —
 * WITHOUT pulling in the broad/low-confidence heuristics, so detection scope is
 * unchanged. Throws on an unknown name so a rename can never silently drop a
 * provider.
 */
export function getCredentialRegexesByName(names: string[]): RegExp[] {
  return names.map((name) => {
    const pattern = PATTERNS_BY_NAME.get(name);
    if (!pattern) {
      throw new Error(`Unknown credential pattern name: "${name}"`);
    }
    // Fresh RegExp so callers don't share lastIndex state with the source.
    return new RegExp(pattern.regex.source, pattern.regex.flags);
  });
}
