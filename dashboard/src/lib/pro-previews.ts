/**
 * Static preview data for Pro-gated panels.
 * Rendered behind the blur overlay so free users can see what they're missing.
 */

// ── Custom Firewall Rules ─────────────────────────────────

export interface PreviewFirewallRule {
  id: number;
  name: string;
  priority: number;
  condition_type: string;
  condition_value: string;
  action: 'block' | 'allow' | 'quarantine';
  enabled: boolean;
}

export const PREVIEW_FIREWALL_RULES: PreviewFirewallRule[] = [
  {
    id: 1,
    name: 'Block API key patterns',
    priority: 1,
    condition_type: 'regex',
    condition_value: 'sk-[a-zA-Z0-9]{32,}',
    action: 'block',
    enabled: true,
  },
  {
    id: 2,
    name: 'Quarantine code injection',
    priority: 2,
    condition_type: 'regex',
    condition_value: 'eval\\(|Function\\(',
    action: 'quarantine',
    enabled: true,
  },
  {
    id: 3,
    name: 'Allow internal docs',
    priority: 10,
    condition_type: 'source',
    condition_value: 'agent:docs-helper',
    action: 'allow',
    enabled: false,
  },
];

// ── Custom Injection Patterns ─────────────────────────────

export interface PreviewPattern {
  id: number;
  name: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  regex: string;
  description: string;
  enabled: boolean;
}

export const PREVIEW_PATTERNS: PreviewPattern[] = [
  {
    id: 1,
    name: 'Internal tool abuse',
    category: 'tool_misuse',
    severity: 'high',
    regex: 'execute_tool\\(.*?delete|drop|truncate',
    description: 'Detects attempts to use internal tools for destructive operations.',
    enabled: true,
  },
  {
    id: 2,
    name: 'PII exfiltration',
    category: 'data_leak',
    severity: 'critical',
    regex: '(SSN|social.security|\\d{3}-\\d{2}-\\d{4})',
    description: 'Catches social security number patterns in agent memory writes.',
    enabled: true,
  },
  {
    id: 3,
    name: 'Prompt override attempt',
    category: 'injection',
    severity: 'medium',
    regex: 'ignore.*(previous|above|prior).*instructions',
    description: 'Detects common prompt injection override phrases.',
    enabled: true,
  },
];

// ── Custom Iron Dome Policies ─────────────────────────────

export interface PreviewPolicy {
  id: number;
  name: string;
  description: string;
  is_active: boolean;
}

export const PREVIEW_POLICIES: PreviewPolicy[] = [
  {
    id: 1,
    name: 'Strict Healthcare',
    description: 'Blocks all PII patterns, requires approval for external actions, whitelists only HIPAA-compliant channels.',
    is_active: true,
  },
  {
    id: 2,
    name: 'Dev Sandbox',
    description: 'Permissive mode for development. Allows all channels, logs but does not block. Ideal for testing.',
    is_active: false,
  },
];

// ── Audit Export ──────────────────────────────────────────

export const PREVIEW_EXPORT = {
  lastExport: '2025-12-15T14:30:00Z',
  totalRecords: 2847,
  formats: ['JSON', 'CSV'] as const,
};

// ── Deep Skill Scanner ───────────────────────────────────

export interface PreviewDeepScanResult {
  correlations: Array<{
    files: string[];
    finding: string;
    severity: 'critical' | 'high' | 'medium';
  }>;
  intentBreakdown: Record<string, number>;
  recommendations: string[];
  degraded: boolean;
}

export const PREVIEW_DEEP_SCAN: PreviewDeepScanResult = {
  correlations: [
    {
      files: ['SKILL.md', 'handler.js'],
      finding: 'Skill declares read-only but handler writes to filesystem',
      severity: 'high',
    },
    {
      files: ['SKILL.md', 'config.json'],
      finding: 'Config enables network access not mentioned in skill manifest',
      severity: 'medium',
    },
    {
      files: ['handler.js', 'utils.js'],
      finding: 'Dynamic eval() used in utility imported by main handler',
      severity: 'critical',
    },
  ],
  intentBreakdown: {
    'File access': 45,
    'Network calls': 30,
    'Process exec': 15,
    'Memory write': 10,
  },
  recommendations: [
    'Restrict filesystem writes to a sandboxed directory',
    'Add explicit network permission declarations to SKILL.md',
  ],
  degraded: false,
};
