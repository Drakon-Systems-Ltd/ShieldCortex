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
  /**
   * Optional custom matcher. When present it REPLACES the regex-list test for
   * this group — used where a simple pattern over-matches (e.g. external_url,
   * which must exclude loopback/private/tailnet hosts).
   */
  match?: (content: string) => boolean;
}

// Authority (host[:port]) immediately after an http(s):// scheme.
const URL_AUTHORITY_RE = /\bhttps?:\/\/([^\s"'<>/]+)/gi;

/** Extract the bare host from a URL authority (`host`, `host:port`, `[ipv6]:port`). */
function hostFromAuthority(authority: string): string {
  const h = authority.toLowerCase();
  if (h.startsWith('[')) {
    const end = h.indexOf(']');
    return end > 0 ? h.slice(1, end) : h.slice(1);
  }
  return h.replace(/:\d+$/, ''); // strip trailing :port
}

/**
 * A host that never leaves the machine or the private/tailnet: loopback,
 * RFC1918, CGNAT/tailscale (100.64/10), link-local, and *.local / *.internal /
 * *.ts.net names. These are diagnostics, not off-host exfiltration.
 */
function isLocalHost(host: string): boolean {
  const h = host.replace(/\.$/, '');
  if (!h) return false;
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  if (h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.ts.net')) return true;
  if (h === '::1' || h === '0:0:0:0:0:0:0:1') return true;
  if (h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe80:')) return true; // ULA / link-local IPv6
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = Number(m[1]);
    const b = Number(m[2]);
    if (a === 127 || a === 0) return true;              // loopback / this-host
    if (a === 10) return true;                          // RFC1918
    if (a === 192 && b === 168) return true;            // RFC1918
    if (a === 172 && b >= 16 && b <= 31) return true;   // RFC1918
    if (a === 169 && b === 254) return true;            // link-local
    if (a === 100 && b >= 64 && b <= 127) return true;  // CGNAT / tailnet
  }
  return false;
}

/** True only if content contains at least one URL pointing at a non-local host. */
function hasExternalUrl(content: string): boolean {
  for (const m of content.matchAll(URL_AUTHORITY_RE)) {
    if (!isLocalHost(hostFromAuthority(m[1]))) return true;
  }
  return false;
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
    patterns: [], // matching is delegated to `match` below (loopback-aware)
    match: hasExternalUrl,
  },
];

const SEVERITY_ORDER: Record<string, number> = { low: 0, medium: 1, high: 2 };

export function detectPrivilegeEscalation(content: string): PrivilegeDetectionResult {
  const indicators: string[] = [];
  let highestSeverity: 'low' | 'medium' | 'high' = 'low';

  for (const group of INDICATOR_GROUPS) {
    const matched = group.match
      ? group.match(content)
      : group.patterns.some((pattern) => pattern.test(content));
    if (matched) {
      indicators.push(group.name);
      if (SEVERITY_ORDER[group.severity] > SEVERITY_ORDER[highestSeverity]) {
        highestSeverity = group.severity;
      }
    }
  }

  return {
    detected: indicators.length > 0,
    indicators: [...new Set(indicators)],
    severity: indicators.length > 0 ? highestSeverity : 'low',
  };
}
