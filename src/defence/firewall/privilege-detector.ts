/**
 * Privilege Detector
 *
 * Detects credential references, external URLs, system access,
 * and network exfiltration attempts in memory content.
 */

export interface PrivilegeDetectionResult {
  detected: boolean;
  indicators: string[];
  severity: 'low' | 'medium' | 'high';
}

interface IndicatorGroup {
  name: string;
  severity: 'low' | 'medium' | 'high';
  patterns: RegExp[];
}

const INDICATOR_GROUPS: IndicatorGroup[] = [
  {
    name: 'credential_reference',
    severity: 'high',
    patterns: [
      /\bpassword\s*[=:]/i,
      /\bapi[_-]?key\s*[=:]/i,
      /\bsecret[_-]?key\s*[=:]/i,
      /\btoken\s*[=:]/i,
      /\bbearer\s+[A-Za-z0-9._~+/=-]+/i,
      /\bauth[_-]?token\s*[=:]/i,
      /\bcredential\s*[=:]/i,
      /\bprivate[_-]?key\b/i,
      /\bAKIA[0-9A-Z]{16}\b/, // AWS access key pattern
    ],
  },
  {
    name: 'system_access',
    severity: 'high',
    patterns: [
      /\bsudo\b/i,
      /\bchmod\s+[0-7]{3,4}\b/,
      /\bchown\b/i,
      /\/etc\/passwd\b/,
      /\/etc\/shadow\b/,
      /\broot\s+access\b/i,
      /\badmin\s+(access|privileges?|rights?|panel)\b/i,
    ],
  },
  {
    name: 'destructive_filesystem',
    severity: 'high',
    patterns: [
      /\brm\s+-rf\b/,
      /\bdel\s+\/f\b/i,
      /\bformat\s+[a-z]:/i,
      /\bmkfs\b/,
      /\brmdir\s+\/s\b/i,
    ],
  },
  {
    name: 'network_exfiltration',
    severity: 'medium',
    patterns: [
      /\bcurl\s+.*(-d|--data)\b/i,
      /\bwget\s/i,
      /\bfetch\s*\(/i,
      /\bXMLHttpRequest\b/,
      /\bsend\s+to\s+/i,
      /\bexfiltrate\b/i,
      /\bupload\s+to\s+/i,
    ],
  },
  {
    name: 'external_url',
    severity: 'low',
    patterns: [
      /https?:\/\/[^\s"'<>]+/i,
    ],
  },
];

const SEVERITY_ORDER: Record<string, number> = { low: 0, medium: 1, high: 2 };

export function detectPrivilegeEscalation(content: string): PrivilegeDetectionResult {
  const indicators: string[] = [];
  let highestSeverity: 'low' | 'medium' | 'high' = 'low';

  for (const group of INDICATOR_GROUPS) {
    for (const pattern of group.patterns) {
      if (pattern.test(content)) {
        indicators.push(group.name);
        if (SEVERITY_ORDER[group.severity] > SEVERITY_ORDER[highestSeverity]) {
          highestSeverity = group.severity;
        }
        break;
      }
    }
  }

  return {
    detected: indicators.length > 0,
    indicators: [...new Set(indicators)],
    severity: indicators.length > 0 ? highestSeverity : 'low',
  };
}
