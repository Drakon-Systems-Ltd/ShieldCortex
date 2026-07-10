/**
 * Credential Exfil Detector
 *
 * A first-class `credential_exfil` classification (v4.47.2). Real credential
 * exfiltration used to fall through to `privilege_escalation` (fleet finding,
 * Edith case e): a credential read piped into an outbound POST scored only as a
 * generic network_exfiltration / external_url signal.
 *
 * This detector fires ONLY on the dangerous conjunction that actually defines
 * exfiltration:
 *
 *   credential-material ACCESS   (reading ~/.aws/credentials, ~/.npmrc tokens,
 *                                 an ssh private key, .env secrets, a 1Password
 *                                 vault item, an AWS access-key id, …)
 *   COMBINED WITH
 *   EXTERNAL outbound MOVEMENT   (curl/wget POST, nc, scp/rsync/ssh, base64+HTTP)
 *                                 to a genuinely off-host destination.
 *
 * Either half on its own is CLEAN — `op item get` piped into a local command,
 * reading `.env` for a local run, and a loopback health check are all routine.
 * The "external" test reuses the v4.47.1 loopback/RFC1918/tailnet rules from
 * privilege-detector (`isLocalHost`), so a credential read moving to 127.0.0.1,
 * an RFC1918 host, or a `*.ts.net` tailnet target is NOT exfiltration
 * (regression ids 289/303/321/325/337 must not regress).
 *
 * Dangerous tier: when this fires the firewall BLOCKs in enforce.
 */

import { hasExternalUrl, isLocalHost } from './privilege-detector.js';

export interface CredentialExfilResult {
  detected: boolean;
  /** Matched credential-material access signals (e.g. `aws_credentials`). */
  credentialAccess: string[];
  /** Matched outbound-movement signals (e.g. `curl_post`, `scp_external`). */
  egress: string[];
  severity: 'high';
}

interface Sig {
  name: string;
  re: RegExp;
}

/**
 * Access to credential material — a secret at rest that a process is reading.
 * These target credential FILES / vault tools / key material specifically, not
 * the bare words "token"/"secret"/"password" (which appear in benign redaction
 * pipelines such as the id-289 diagnostic and must never trip this).
 */
const CREDENTIAL_ACCESS: Sig[] = [
  { name: 'aws_credentials', re: /\.aws\/credentials/i },
  { name: 'npmrc_token', re: /\.npmrc\b/i },
  {
    name: 'ssh_private_key',
    re: /(\.ssh\/id_(?:rsa|ed25519|ecdsa|dsa)|\bid_rsa\b|\bid_ed25519\b|-----BEGIN [A-Z ]*PRIVATE KEY-----)/i,
  },
  // A `.env` / `.env.local` / `path/.env` file reference (needs a boundary char
  // in front so `something.environment` does not match).
  { name: 'dotenv_secret', re: /(?:^|[\s=/'"(`])\.env(?:\.[\w.]+)?\b/i },
  { name: 'onepassword_read', re: /\bop\s+(?:item\s+get|read|get\s+item|document\s+get)\b/i },
  { name: 'gcloud_creds', re: /\.config\/gcloud\b/i },
  { name: 'kube_config', re: /\.kube\/config\b/i },
  { name: 'docker_config', re: /\.docker\/config\.json/i },
  { name: 'git_credentials', re: /\.git-credentials\b/i },
  { name: 'gnupg', re: /\.gnupg\b/i },
  { name: 'aws_access_key', re: /\bAKIA[0-9A-Z]{12,}\b/ },
];

/** A shell/network mechanism capable of moving bytes off the host. */
const EGRESS_TOOL = /\b(?:curl|wget|nc|ncat|netcat|scp|rsync|sftp|ftp|telnet)\b/i;
const HTTP_POST_LIB = /\b(?:requests\.(?:post|put)|http\.post|urllib\.request|axios\.(?:post|put)|XMLHttpRequest)\b|\bfetch\s*\(/i;

/** Off-host destinations named as a bare host (no URL scheme): scp/rsync/nc/ssh. */
const BARE_HOST = '([a-z0-9][a-z0-9.-]*\\.[a-z]{2,}|(?:\\d{1,3}\\.){3}\\d{1,3})';
const SCP_TARGET = new RegExp(`\\b(?:scp|rsync|sftp)\\b[^\\n|]*?(?:[\\w.-]+@)?${BARE_HOST}:`, 'gi');
const NC_TARGET = new RegExp(`\\b(?:nc|ncat|netcat)\\b\\s+(?:-\\w+\\s+)*${BARE_HOST}\\b`, 'gi');
const SSH_TARGET = new RegExp(`\\bssh\\b[^\\n|]*?\\s(?:[\\w.-]+@)${BARE_HOST}\\b`, 'gi');

/** Collect non-local bare-host destinations from scp/rsync/nc/ssh invocations. */
function externalBareHosts(content: string): string[] {
  const hosts: string[] = [];
  for (const re of [SCP_TARGET, NC_TARGET, SSH_TARGET]) {
    for (const m of content.matchAll(re)) {
      if (m[1]) hosts.push(m[1]);
    }
  }
  return hosts.filter((h) => !isLocalHost(h));
}

/**
 * Detect credential-material access combined with external outbound movement.
 *
 * `detected` is true only when BOTH halves are present AND the movement targets
 * a genuinely off-host destination. Local/private/tailnet destinations do not
 * count (they are diagnostics, not exfiltration).
 */
export function detectCredentialExfil(content: string): CredentialExfilResult {
  const text = content || '';

  const credentialAccess = CREDENTIAL_ACCESS.filter((s) => s.re.test(text)).map((s) => s.name);
  const egress: string[] = [];

  if (credentialAccess.length > 0) {
    const hasEgressTool = EGRESS_TOOL.test(text) || HTTP_POST_LIB.test(text);
    if (hasEgressTool) {
      if (hasExternalUrl(text)) egress.push('external_http');
      if (externalBareHosts(text).length > 0) egress.push('external_host');
    }
  }

  const detected = credentialAccess.length > 0 && egress.length > 0;
  return {
    detected,
    credentialAccess,
    egress,
    severity: 'high',
  };
}
