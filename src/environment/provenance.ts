import type { ProvenanceResult, ProvenanceSignals } from './types.js';

const SUSPICIOUS_TLDS = new Set([
  'zip', 'mov', 'top', 'xyz', 'click', 'country', 'link', 'gq', 'ml', 'tk', 'cf', 'ga',
  'quest', 'sbs', 'rest', 'cyou', 'bond', 'cam', 'cfd', 'trade', 'download', 'racing',
]);

const KNOWN_GOOD_DOMAINS = new Set([
  'github.com', 'raw.githubusercontent.com', 'gitlab.com', 'bitbucket.org',
  'npmjs.com', 'registry.npmjs.org', 'pypi.org', 'rubygems.org', 'crates.io',
  'anthropic.com', 'openai.com', 'google.com', 'cloudflare.com',
  'stripe.com', 'mozilla.org', 'w3.org', 'ietf.org', 'python.org',
  'rust-lang.org', 'golang.org', 'nodejs.org', 'typescriptlang.org',
  'arxiv.org', 'wikipedia.org', 'wikimedia.org',
  'shieldcortex.ai', 'drakonsystems.com',
]);

const KNOWN_BAD_DOMAINS = new Set<string>([
  // intentionally empty — populated from threat feeds in later phases
]);

function extractRegistrableDomain(hostname: string): string {
  const parts = hostname.toLowerCase().split('.');
  if (parts.length <= 2) return hostname.toLowerCase();
  return parts.slice(-2).join('.');
}

function isIpAddress(hostname: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || /:/.test(hostname);
}

function hasPunycode(hostname: string): boolean {
  return /xn--/i.test(hostname);
}

export function scoreProvenance(args: {
  originalUrl: string;
  finalUrl: string;
  redirectChain: string[];
}): ProvenanceResult {
  const reasons: string[] = [];
  let score = 0.5;

  let finalParsed: URL;
  try {
    finalParsed = new URL(args.finalUrl);
  } catch {
    return {
      score: 0,
      signals: {
        tls: false,
        redirectCount: args.redirectChain.length,
        redirectChain: args.redirectChain,
        finalDomain: '',
        suspiciousTld: false,
        allowlisted: false,
        denylisted: false,
        isIpAddress: false,
        hasUserInfo: false,
        hasPunycode: false,
      },
      reasons: ['Unparseable final URL'],
    };
  }

  const tls = finalParsed.protocol === 'https:';
  const finalDomain = extractRegistrableDomain(finalParsed.hostname);
  const tld = finalDomain.split('.').pop() || '';
  const suspiciousTld = SUSPICIOUS_TLDS.has(tld);
  const allowlisted = KNOWN_GOOD_DOMAINS.has(finalDomain) || KNOWN_GOOD_DOMAINS.has(finalParsed.hostname);
  const denylisted = KNOWN_BAD_DOMAINS.has(finalDomain) || KNOWN_BAD_DOMAINS.has(finalParsed.hostname);
  const ipHost = isIpAddress(finalParsed.hostname);
  const userInfo = Boolean(finalParsed.username || finalParsed.password);
  const punycode = hasPunycode(finalParsed.hostname);

  if (tls) {
    score += 0.1;
    reasons.push('TLS connection');
  } else {
    score -= 0.25;
    reasons.push('Plain HTTP (no TLS)');
  }

  if (allowlisted) {
    score += 0.3;
    reasons.push(`Allowlisted domain: ${finalDomain}`);
  }
  if (denylisted) {
    score -= 0.8;
    reasons.push(`Denylisted domain: ${finalDomain}`);
  }
  if (suspiciousTld) {
    score -= 0.2;
    reasons.push(`Suspicious TLD: .${tld}`);
  }
  if (ipHost) {
    score -= 0.15;
    reasons.push('Host is raw IP address');
  }
  if (userInfo) {
    score -= 0.3;
    reasons.push('URL contains embedded credentials');
  }
  if (punycode) {
    score -= 0.1;
    reasons.push('Host uses Punycode (possible homograph attack)');
  }

  if (args.redirectChain.length > 0) {
    const originalDomain = (() => {
      try {
        return extractRegistrableDomain(new URL(args.originalUrl).hostname);
      } catch {
        return '';
      }
    })();
    if (originalDomain && originalDomain !== finalDomain) {
      score -= 0.1;
      reasons.push(`Cross-domain redirect: ${originalDomain} → ${finalDomain}`);
    }
    if (args.redirectChain.length >= 3) {
      score -= 0.1;
      reasons.push(`${args.redirectChain.length} redirects before final response`);
    }
  }

  score = Math.max(0, Math.min(1, score));

  const signals: ProvenanceSignals = {
    tls,
    redirectCount: args.redirectChain.length,
    redirectChain: args.redirectChain,
    finalDomain,
    suspiciousTld,
    allowlisted,
    denylisted,
    isIpAddress: ipHost,
    hasUserInfo: userInfo,
    hasPunycode: punycode,
  };

  return { score, signals, reasons };
}
