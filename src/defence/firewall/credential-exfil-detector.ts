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

/** Off-host destinations named as a bare host (no URL scheme): scp/rsync/nc/ssh, curl/wget. */
const BARE_HOST = '([a-z0-9][a-z0-9.-]*\\.[a-z]{2,}|(?:\\d{1,3}\\.){3}\\d{1,3})';
const SCP_TARGET = new RegExp(`\\b(?:scp|rsync|sftp)\\b[^\\n|]*?(?:[\\w.-]+@)?${BARE_HOST}:`, 'gi');
const NC_TARGET = new RegExp(`\\b(?:nc|ncat|netcat)\\b\\s+(?:-\\w+\\s+)*${BARE_HOST}\\b`, 'gi');
const SSH_TARGET = new RegExp(`\\bssh\\b[^\\n|]*?\\s(?:[\\w.-]+@)${BARE_HOST}\\b`, 'gi');

/**
 * curl/wget also accept a scheme-less `host[:port][/path]` target (#566). The
 * host ends at the same shell metacharacters as the guard's RE_URL_TOKEN, so a
 * chained command after `;` or `|` can never become part of the "host".
 */
const CURL_WGET_CMD = /(?:^|[\s;&|()`'"/])(curl|wget)(?=\s)/gi;
const CURL_WGET_TARGET = new RegExp(
  String.raw`^(?:\/\/)?(?:[^\s;&|<>()\`'"\\@/]+@)?` +
    BARE_HOST +
    String.raw`\.?(?::\d+)?(?=$|[\s/?#;&|<>()\`'"\\])`,
  'i',
);
/**
 * Options whose NEXT word is a value (file, header, body, …), never the target.
 * The long sets are every value-taking option printed by `curl --help all`
 * (curl 8.5.0, plus the `[protocol://]host` forms `--proxy`/`--preproxy`) and
 * `wget --help` (1.21.4), so an unlisted option cannot turn its file argument
 * into a "host". `--url` is handled separately: its value IS a target.
 */
const CURL_SHORT_VALUE = new Set('ACDEFHKPQTUXYbcdehmortuwxyz'.split(''));
const WGET_SHORT_VALUE = new Set('ABDIOPQRTUXaeilotw'.split(''));
const CURL_LONG_VALUE = new Set([
  'abstract-unix-socket', 'alt-svc', 'aws-sigv4', 'cacert', 'capath', 'cert', 'cert-type',
  'ciphers', 'config', 'connect-timeout', 'connect-to', 'continue-at', 'cookie', 'cookie-jar',
  'create-file-mode', 'crlfile', 'curves', 'data', 'data-ascii', 'data-binary', 'data-raw',
  'data-urlencode', 'delegation', 'dns-interface', 'dns-ipv4-addr', 'dns-ipv6-addr', 'dns-servers',
  'doh-url', 'dump-header', 'egd-file', 'engine', 'etag-compare', 'etag-save', 'expect100-timeout',
  'form', 'form-string', 'ftp-account', 'ftp-alternative-to-user', 'ftp-method', 'ftp-port',
  'ftp-ssl-ccc-mode', 'happy-eyeballs-timeout-ms', 'header', 'help', 'hostpubmd5', 'hostpubsha256',
  'hsts', 'interface', 'ipfs-gateway', 'json', 'keepalive-time', 'key', 'key-type', 'krb',
  'libcurl', 'limit-rate', 'local-port', 'login-options', 'mail-auth', 'mail-from', 'mail-rcpt',
  'max-filesize', 'max-redirs', 'max-time', 'netrc-file', 'noproxy', 'oauth2-bearer', 'output',
  'output-dir', 'parallel-max', 'pass', 'pinnedpubkey', 'preproxy', 'proto', 'proto-default',
  'proto-redir', 'proxy', 'proxy-cacert', 'proxy-capath', 'proxy-cert', 'proxy-cert-type',
  'proxy-ciphers', 'proxy-crlfile', 'proxy-header', 'proxy-key', 'proxy-key-type', 'proxy-pass',
  'proxy-pinnedpubkey', 'proxy-service-name', 'proxy-tls13-ciphers', 'proxy-tlsauthtype',
  'proxy-tlspassword', 'proxy-tlsuser', 'proxy-user', 'proxy1.0', 'pubkey', 'quote', 'random-file',
  'range', 'rate', 'referer', 'request', 'request-target', 'resolve', 'retry', 'retry-delay',
  'retry-max-time', 'sasl-authzid', 'service-name', 'socks4', 'socks4a', 'socks5',
  'socks5-gssapi-service', 'socks5-hostname', 'speed-limit', 'speed-time', 'stderr',
  'telnet-option', 'tftp-blksize', 'time-cond', 'tls-max', 'tls13-ciphers', 'tlsauthtype',
  'tlspassword', 'tlsuser', 'trace', 'trace-ascii', 'trace-config', 'unix-socket', 'upload-file',
  'url-query', 'user', 'user-agent', 'variable', 'write-out',
]);
const WGET_LONG_VALUE = new Set([
  'accept', 'accept-regex', 'append-output', 'backups', 'base', 'bind-address', 'body-data',
  'body-file', 'ca-certificate', 'ca-directory', 'certificate', 'certificate-type', 'ciphers',
  'compression', 'config', 'connect-timeout', 'crl-file', 'cut-dirs', 'default-page',
  'directory-prefix', 'dns-timeout', 'domains', 'exclude-directories', 'exclude-domains',
  'execute', 'follow-tags', 'ftp-password', 'ftp-user', 'header', 'http-password', 'http-user',
  'ignore-tags', 'include-directories', 'input-file', 'level', 'limit-rate', 'load-cookies',
  'local-encoding', 'method', 'output-document', 'output-file', 'password', 'pinnedpubkey',
  'post-data', 'post-file', 'prefer-family', 'private-key', 'private-key-type', 'progress',
  'proxy-password', 'proxy-user', 'quota', 'random-file', 'read-timeout', 'referer', 'regex-type',
  'reject', 'reject-regex', 'rejected-log', 'remote-encoding', 'report-speed',
  'restrict-file-names', 'retry-on-http-error', 'save-cookies', 'secure-protocol', 'start-pos',
  'timeout', 'tries', 'use-askpass', 'user', 'user-agent', 'wait', 'waitretry', 'warc-dedup',
  'warc-file', 'warc-header', 'warc-max-size', 'warc-tempdir',
]);

interface ShellWord {
  word: string;
  /** The word follows `<` / `>` — a redirection file, never a target. */
  redirect: boolean;
}

/**
 * Split the text after a curl/wget command word into shell words, the way the
 * shell would:
 * - quotes are removed; inside double quotes `\` escapes only `"\$` `` ` `` and
 *   a newline, elsewhere it escapes the next character or joins a continued line;
 * - an unquoted `;`, `|`, `&&`, `&` or newline ends the statement, and an
 *   unquoted `#` word opens a comment that runs to the end of the line;
 * - `<`, `>`, `2>&1`, `>&2` and `&>` are redirections: the word they take is a
 *   file descriptor or path, never a target;
 * - unquoted `()` and backticks separate words.
 */
function statementWords(content: string, start: number): ShellWord[] {
  const words: ShellWord[] = [];
  let cur = '';
  let inWord = false;
  let quote: string | null = null;
  let redirectNext = false;
  let curRedirect = false;
  const begin = () => {
    if (inWord) return;
    inWord = true;
    curRedirect = redirectNext;
    redirectNext = false;
  };
  const flush = () => {
    if (inWord) words.push({ word: cur, redirect: curRedirect });
    cur = '';
    inWord = false;
  };
  for (let i = start; i < content.length; i++) {
    const c = content[i];
    if (quote) {
      if (c === quote) quote = null;
      else if (c === '\\' && quote === '"' && i + 1 < content.length) {
        const n = content[i + 1];
        if (n === '\n') i++;
        else if (n === '"' || n === '\\' || n === '$' || n === '`') {
          cur += n;
          i++;
        } else cur += c;
      } else cur += c;
      continue;
    }
    if (c === "'" || c === '"') {
      begin();
      quote = c;
      continue;
    }
    if (c === '\\') {
      if (i + 1 >= content.length) break;
      if (content[i + 1] === '\n') {
        i++; // line continuation: the statement carries on
        continue;
      }
      begin();
      cur += content[++i];
      continue;
    }
    if (c === ';' || c === '|' || c === '\n') break;
    if (c === '#' && !inWord) break;
    if (c === '&') {
      if (content[i + 1] === '>') {
        flush(); // `&>file`: the `>` that follows marks the redirection
        continue;
      }
      if (redirectNext && !inWord) continue; // `2>&1` / `>&2`: descriptor dup
      break; // `&` / `&&`: statement end
    }
    if (/\s/.test(c) || c === '(' || c === ')' || c === '`' || c === '<' || c === '>') {
      flush();
      if (c === '<' || c === '>') redirectNext = true;
      continue;
    }
    begin();
    cur += c;
  }
  flush();
  return words;
}

/** Scheme-less target hosts named in curl/wget invocations; option values are skipped. */
function curlWgetTargets(content: string): string[] {
  const hosts: string[] = [];
  const push = (word: string) => {
    const t = word.match(CURL_WGET_TARGET);
    if (t?.[1]) hosts.push(t[1]);
  };
  for (const m of content.matchAll(CURL_WGET_CMD)) {
    const isCurl = m[1].toLowerCase() === 'curl';
    const shortValue = isCurl ? CURL_SHORT_VALUE : WGET_SHORT_VALUE;
    const longValue = isCurl ? CURL_LONG_VALUE : WGET_LONG_VALUE;
    const words = statementWords(content, (m.index ?? 0) + m[0].length);
    for (let i = 0; i < words.length; i++) {
      const { word, redirect } = words[i];
      if (redirect) continue;
      if (word.startsWith('--')) {
        const eq = word.indexOf('=');
        const name = (eq === -1 ? word.slice(2) : word.slice(2, eq)).toLowerCase();
        // `--url X` names the destination explicitly: its value IS a target.
        if (name === 'url') {
          if (eq !== -1) push(word.slice(eq + 1));
          else if (i + 1 < words.length) push(words[++i].word);
        } else if (eq === -1 && longValue.has(name)) {
          i++;
        }
        continue;
      }
      if (word.length > 1 && word.startsWith('-')) {
        // Short cluster (`-sT`): a value-taking letter takes the rest of the
        // word, or the next word when it is the last letter.
        for (let j = 1; j < word.length; j++) {
          if (shortValue.has(word[j])) {
            if (j === word.length - 1) i++;
            break;
          }
        }
        continue;
      }
      push(word);
    }
  }
  return hosts;
}

/** Collect non-local bare-host destinations from scp/rsync/nc/ssh/curl/wget invocations. */
function externalBareHosts(content: string): string[] {
  const hosts: string[] = [];
  for (const re of [SCP_TARGET, NC_TARGET, SSH_TARGET]) {
    for (const m of content.matchAll(re)) {
      if (m[1]) hosts.push(m[1]);
    }
  }
  hosts.push(...curlWgetTargets(content));
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
