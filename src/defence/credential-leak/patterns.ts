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
  // OpenAI
  {
    name: 'OpenAI API Key',
    type: 'api_key',
    provider: 'openai',
    regex: /sk-[A-Za-z0-9]{20,}/g,
    severity: 'critical',
    confidence: 0.95,
    minLength: 24,
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
  // AWS Access Key
  {
    name: 'AWS Access Key ID',
    type: 'api_key',
    provider: 'aws',
    regex: /AKIA[0-9A-Z]{16}/g,
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
    name: 'Stripe Publishable Key',
    type: 'api_key',
    provider: 'stripe',
    regex: /pk_(?:live|test)_[A-Za-z0-9]{24,}/g,
    severity: 'medium',
    confidence: 0.90,
  },
  // Twilio
  {
    name: 'Twilio API Key',
    type: 'api_key',
    provider: 'twilio',
    regex: /SK[a-f0-9]{32}/g,
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
    name: 'Slack Webhook URL',
    type: 'api_key',
    provider: 'slack',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{20,}/g,
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
    regex: /dop_v1_[a-f0-9]{64}/g,
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
