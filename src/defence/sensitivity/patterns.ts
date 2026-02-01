/**
 * Detection patterns for sensitive content classification.
 *
 * Each pattern set is ordered by priority: RESTRICTED > CONFIDENTIAL > INTERNAL.
 */

export interface SensitivityPattern {
  pattern: RegExp;
  label: string;
  weight: number;
}

// ── RESTRICTED — credentials, secrets, PII that must never leak ──

export const RESTRICTED_PATTERNS: SensitivityPattern[] = [
  // Passwords
  { pattern: /password\s*[:=]\s*\S+/gi, label: 'password', weight: 0.95 },
  { pattern: /passwd\s*[:=]\s*\S+/gi, label: 'password', weight: 0.95 },

  // AWS keys
  { pattern: /AKIA[0-9A-Z]{16}/g, label: 'aws-access-key', weight: 0.99 },
  { pattern: /aws_secret_access_key\s*[:=]\s*\S+/gi, label: 'aws-secret-key', weight: 0.99 },

  // GitHub tokens
  { pattern: /gh[ps]_[A-Za-z0-9_]{36,}/g, label: 'github-token', weight: 0.98 },
  { pattern: /github_pat_[A-Za-z0-9_]{22,}/g, label: 'github-pat', weight: 0.98 },

  // Stripe keys
  { pattern: /sk_live_[A-Za-z0-9]{24,}/g, label: 'stripe-secret-key', weight: 0.98 },
  { pattern: /rk_live_[A-Za-z0-9]{24,}/g, label: 'stripe-restricted-key', weight: 0.98 },

  // Generic API keys
  { pattern: /api[_-]?key\s*[:=]\s*\S+/gi, label: 'api-key', weight: 0.90 },
  { pattern: /api[_-]?secret\s*[:=]\s*\S+/gi, label: 'api-secret', weight: 0.92 },
  { pattern: /bearer\s+[A-Za-z0-9\-._~+/]+=*/gi, label: 'bearer-token', weight: 0.90 },

  // Private keys
  { pattern: /-----BEGIN RSA PRIVATE KEY-----/g, label: 'rsa-private-key', weight: 1.0 },
  { pattern: /-----BEGIN EC PRIVATE KEY-----/g, label: 'ec-private-key', weight: 1.0 },
  { pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g, label: 'pgp-private-key', weight: 1.0 },
  { pattern: /-----BEGIN PRIVATE KEY-----/g, label: 'private-key', weight: 1.0 },

  // SSN
  { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, label: 'ssn', weight: 0.93 },

  // Credit card numbers (basic Luhn-length patterns)
  { pattern: /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/g, label: 'credit-card', weight: 0.95 },
];

// ── CONFIDENTIAL — personal / financial data ──

export const CONFIDENTIAL_PATTERNS: SensitivityPattern[] = [
  // Email addresses
  { pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, label: 'email-address', weight: 0.75 },

  // Phone numbers
  { pattern: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, label: 'phone-number', weight: 0.70 },
  { pattern: /\b\+44\s?\d{4}\s?\d{6}\b/g, label: 'uk-phone-number', weight: 0.70 },

  // Physical addresses (street number + street name pattern)
  { pattern: /\b\d{1,5}\s[A-Z][a-z]+(?:\s[A-Z][a-z]+)*\s(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct)\b/g, label: 'physical-address', weight: 0.72 },

  // Financial — account numbers, sort codes, IBANs
  { pattern: /\baccount\s*(?:number|no|#)\s*[:=]?\s*\d{6,}/gi, label: 'account-number', weight: 0.85 },
  { pattern: /\bsort\s*code\s*[:=]?\s*\d{2}-?\d{2}-?\d{2}\b/gi, label: 'sort-code', weight: 0.85 },
  { pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]{0,16})\b/g, label: 'iban', weight: 0.88 },

  // Personal names with identifiers
  { pattern: /\b(?:patient|employee|client|customer)\s*(?:id|#|number)\s*[:=]?\s*\S+/gi, label: 'personal-identifier', weight: 0.80 },

  // Medical terms
  { pattern: /\b(?:diagnosis|prescription|medication|treatment|symptoms?|blood\s*type|allergies|medical\s*record)\b/gi, label: 'medical-term', weight: 0.65 },
];

// ── INTERNAL — org-internal references ──

export const INTERNAL_PATTERNS: SensitivityPattern[] = [
  // Internal URLs
  { pattern: /https?:\/\/localhost[:\d]*/g, label: 'localhost-url', weight: 0.55 },
  { pattern: /https?:\/\/[a-zA-Z0-9.-]+\.local\b/g, label: 'local-domain', weight: 0.55 },
  { pattern: /https?:\/\/[a-zA-Z0-9.-]+\.internal\b/g, label: 'internal-domain', weight: 0.55 },

  // Internal file paths
  { pattern: /(?:\/(?:home|Users)\/\w+\/|C:\\Users\\\w+\\)/g, label: 'internal-path', weight: 0.50 },

  // Project names with internal identifiers
  { pattern: /\b(?:PROJ|INT|PRIV)-\d{3,}/g, label: 'internal-project-id', weight: 0.55 },
  { pattern: /\bjira[:\s]+[A-Z]+-\d+\b/gi, label: 'internal-ticket', weight: 0.50 },

  // Meeting notes / draft markers
  { pattern: /\b(?:meeting\s*notes?|standup|retro(?:spective)?|sprint\s*review)\b/gi, label: 'meeting-notes', weight: 0.45 },
  { pattern: /\b(?:DRAFT|INTERNAL(?:\s+ONLY)?|DO NOT (?:SHARE|DISTRIBUTE))\b/gi, label: 'internal-label', weight: 0.60 },
];
