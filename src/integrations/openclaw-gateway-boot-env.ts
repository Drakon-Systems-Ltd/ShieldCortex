/**
 * The local OpenClaw gateway's own boot credential, for one `openclaw` child
 * (#1105).
 *
 * `shieldcortex update` installs the realtime plugin with `openclaw plugins
 * install --force …`. On a host whose `gateway.auth.token` (or `.password`) is
 * a secret reference that only the operator's interactive shell resolves,
 * OpenClaw refuses that install outright: the child has no
 * OPENCLAW_GATEWAY_TOKEN / OPENCLAW_GATEWAY_PASSWORD and cannot resolve the
 * reference itself. The gateway service has the value: OpenClaw writes the
 * gateway unit's environment to `<stateDir>/gateway.systemd.env` (mode 0600,
 * `EnvironmentFile=` of the unit; OpenClaw 2026.11.4
 * dist/systemd-service-files-*.mjs `SYSTEMD_GATEWAY_DOTENV_FILENAME`,
 * dist/systemd-*.mjs `mutation.publish(environmentFilePath, content, 384)`).
 *
 * This module reads exactly that file, and only to hand the two gateway
 * credential keys to the one install child that OpenClaw just refused. Rules:
 *
 *  - Fixed path: `<home>/.openclaw/gateway.systemd.env`. No path comes from an
 *    environment variable, a config value, or the unit file. When anything
 *    could point OpenClaw at a different state dir, config or gateway
 *    (OPENCLAW_STATE_DIR, OPENCLAW_HOME, OPENCLAW_PROFILE, OPENCLAW_CONFIG_PATH,
 *    OPENCLAW_GATEWAY_URL) the file is not read at all.
 *  - Local gateway only: OpenClaw sends an env token to a REMOTE gateway too
 *    (env-first precedence, dist/credentials-*.mjs), so a config in
 *    `gateway.mode: "remote"`, or one that cannot be read, is never given the
 *    local gateway's credential. The refusal must also name the local
 *    gateway's own `gateway.auth.token` / `gateway.auth.password`.
 *  - Owner-checked: opened with O_NOFOLLOW (a symlink is refused), then
 *    checked on the open descriptor — a regular file, one link, owned by the
 *    user running update, not writable by group or others, at most 64 KiB —
 *    inside a `~/.openclaw` that is owned by that user and not writable by
 *    group or others.
 *  - Parsed, never run: plain `KEY=VALUE` lines in systemd EnvironmentFile
 *    form. Only OPENCLAW_GATEWAY_TOKEN and OPENCLAW_GATEWAY_PASSWORD are
 *    taken. A value that would need shell or systemd expansion (`$…`, a
 *    backtick), or any quoting this parser does not recognise exactly, is not
 *    used.
 *  - Nothing is written, cached, logged or printed. Callers get the values
 *    only to put them in one child's env, and `redactGatewayCredentials` to
 *    scrub them from anything that child said back.
 */
import fs from 'fs';
import path from 'path';

export const GATEWAY_CREDENTIAL_KEYS = ['OPENCLAW_GATEWAY_TOKEN', 'OPENCLAW_GATEWAY_PASSWORD'] as const;
export type GatewayCredentialKey = (typeof GATEWAY_CREDENTIAL_KEYS)[number];
export type GatewayCredentials = Partial<Record<GatewayCredentialKey, string>>;

/** What every message calls the file. Never an absolute path: it names the operator's home. */
export const GATEWAY_BOOT_ENV_DISPLAY = '~/.openclaw/gateway.systemd.env';

/** The local gateway's own auth secrets: the only refusals the boot env can answer. */
const LOCAL_AUTH_PATHS = new Set(['gateway.auth.token', 'gateway.auth.password']);

/**
 * Anything that makes OpenClaw use a state dir, config or gateway other than
 * the default one under `home` — then the fixed path may belong to a
 * different gateway than the one the install talks to.
 */
const LOCATION_OVERRIDES = [
  'OPENCLAW_GATEWAY_URL',
  'OPENCLAW_STATE_DIR',
  'OPENCLAW_HOME',
  'OPENCLAW_PROFILE',
  'OPENCLAW_CONFIG_PATH',
] as const;

const MAX_BOOT_ENV_BYTES = 64 * 1024;

export type GatewayBootCredentials =
  | { used: true; env: GatewayCredentials; keys: GatewayCredentialKey[] }
  | { used: false; reason: string };

function isCredentialKey(key: string): key is GatewayCredentialKey {
  return (GATEWAY_CREDENTIAL_KEYS as readonly string[]).includes(key);
}

/**
 * One systemd EnvironmentFile value, decoded the way OpenClaw's own serializer
 * writes it (bare when it needs no quoting, else double-quoted with `\\`, `\"`,
 * `` \` `` and `\$` escapes), plus a plain single-quoted form. Anything else —
 * an unescaped `$` or backtick (systemd may expand it), any other backslash,
 * unbalanced quotes, inner whitespace in a bare value, a control character —
 * is null: the gateway's real value cannot be known for certain, so none is
 * used.
 */
function decodeValue(raw: string): string | null {
  const v = raw.trim();
  if (!v) return null;
  let out = '';
  if (v.startsWith('"')) {
    if (v.length < 2 || !v.endsWith('"')) return null;
    const inner = v.slice(1, -1);
    for (let i = 0; i < inner.length; i++) {
      const c = inner[i];
      if (c === '\\') {
        const next = inner[i + 1];
        if (next === undefined || !'\\"`$'.includes(next)) return null;
        out += next;
        i++;
        continue;
      }
      if (c === '"' || c === '$' || c === '`') return null;
      out += c;
    }
  } else if (v.startsWith("'")) {
    if (v.length < 2 || !v.endsWith("'")) return null;
    out = v.slice(1, -1);
    if (/['"$`\\]/.test(out)) return null;
  } else {
    if (/[\s'"$`\\]/.test(v)) return null;
    out = v;
  }
  // eslint-disable-next-line no-control-regex
  if (!out || /[\x00-\x1f\x7f]/.test(out)) return null;
  return out;
}

/**
 * The two gateway credential keys out of a systemd EnvironmentFile body. Pure.
 *
 * Every other key is ignored without being decoded. The last line for a key
 * wins, as in systemd — and when that last line is one this parser will not
 * decode, the key is dropped rather than an earlier value used.
 */
export function parseGatewayBootEnv(content: string): GatewayCredentials {
  const out: GatewayCredentials = {};
  for (const raw of content.split('\n')) {
    const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    const t = line.trimStart();
    if (!t || t.startsWith('#') || t.startsWith(';')) continue;
    const eq = t.indexOf('=');
    if (eq <= 0) continue;
    const key = t.slice(0, eq).trim();
    if (!isCredentialKey(key)) continue;
    const value = decodeValue(t.slice(eq + 1));
    if (value === null) delete out[key];
    else out[key] = value;
  }
  return out;
}

/** `gateway.mode` from the default OpenClaw config, or null when it cannot be read. */
function readGatewayMode(home: string): 'local' | 'remote' | null {
  try {
    const cfg = JSON.parse(fs.readFileSync(path.join(home, '.openclaw', 'openclaw.json'), 'utf-8')) as unknown;
    if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg)) return null;
    const mode = (cfg as { gateway?: { mode?: unknown } }).gateway?.mode;
    return mode === 'remote' ? 'remote' : 'local';
  } catch {
    return null;
  }
}

/** Why an owned-private check failed, or null when it passed. */
function ownerProblem(st: fs.Stats, euid: number): string | null {
  if (st.uid !== euid) return 'is not owned by the user running update';
  if ((st.mode & 0o022) !== 0) return 'is writable by group or others';
  return null;
}

/** The file's text, or why it was not read. Every check runs on the open descriptor. */
function readOwnedBootEnv(home: string, euid: number): { text: string } | { reason: string } {
  const dir = path.join(home, '.openclaw');
  let dirStat: fs.Stats;
  try {
    dirStat = fs.statSync(dir);
  } catch {
    return { reason: '~/.openclaw could not be read' };
  }
  if (!dirStat.isDirectory()) return { reason: '~/.openclaw is not a directory' };
  const dirProblem = ownerProblem(dirStat, euid);
  if (dirProblem) return { reason: `~/.openclaw ${dirProblem}` };

  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0);
  let fd: number;
  try {
    fd = fs.openSync(path.join(dir, 'gateway.systemd.env'), flags);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    if (code === 'ENOENT') return { reason: `there is no ${GATEWAY_BOOT_ENV_DISPLAY}` };
    if (code === 'ELOOP') return { reason: `${GATEWAY_BOOT_ENV_DISPLAY} is a symbolic link` };
    return { reason: `${GATEWAY_BOOT_ENV_DISPLAY} could not be opened (${code ?? 'error'})` };
  }
  const buf = Buffer.alloc(MAX_BOOT_ENV_BYTES + 1);
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) return { reason: `${GATEWAY_BOOT_ENV_DISPLAY} is not a regular file` };
    const problem = ownerProblem(st, euid);
    if (problem) return { reason: `${GATEWAY_BOOT_ENV_DISPLAY} ${problem}` };
    if (st.nlink !== 1) return { reason: `${GATEWAY_BOOT_ENV_DISPLAY} has more than one hard link` };
    let n = 0;
    while (n < buf.length) {
      const got = fs.readSync(fd, buf, n, buf.length - n, null);
      if (got === 0) break;
      n += got;
    }
    if (n > MAX_BOOT_ENV_BYTES) return { reason: `${GATEWAY_BOOT_ENV_DISPLAY} is larger than 64 KiB` };
    return { text: buf.subarray(0, n).toString('utf8') };
  } catch (err) {
    return { reason: `${GATEWAY_BOOT_ENV_DISPLAY} could not be read (${(err as NodeJS.ErrnoException)?.code ?? 'error'})` };
  } finally {
    buf.fill(0);
    try { fs.closeSync(fd); } catch { /* already closed */ }
  }
}

/**
 * The local gateway's boot credential for ONE install child that OpenClaw
 * refused for an unresolvable gateway secret reference, or why there is none.
 *
 * `refusedPath` is the config path OpenClaw's refusal named. `geteuid` is a
 * parameter only so a test can stand in for a file owned by someone else.
 * The reason strings never contain a credential value or an absolute path.
 */
export function resolveGatewayBootCredentials(params: {
  home: string;
  refusedPath: string | null;
  env?: NodeJS.ProcessEnv;
  geteuid?: () => number;
}): GatewayBootCredentials {
  const env = params.env ?? process.env;
  if (GATEWAY_CREDENTIAL_KEYS.some((k) => env[k]?.trim())) {
    return { used: false, reason: 'OPENCLAW_GATEWAY_TOKEN or OPENCLAW_GATEWAY_PASSWORD is already set here, so the boot env was not read' };
  }
  if (!params.refusedPath || !LOCAL_AUTH_PATHS.has(params.refusedPath)) {
    return { used: false, reason: 'the refusal did not name the local gateway\'s own gateway.auth.token or gateway.auth.password' };
  }
  const override = LOCATION_OVERRIDES.find((k) => env[k]?.trim());
  if (override) {
    return { used: false, reason: `${override} is set, so ${GATEWAY_BOOT_ENV_DISPLAY} may not belong to the gateway this install talks to` };
  }
  const geteuid = params.geteuid ?? (typeof process.geteuid === 'function' ? process.geteuid.bind(process) : undefined);
  if (!geteuid) return { used: false, reason: 'the boot env\'s owner cannot be checked on this platform' };
  const mode = readGatewayMode(params.home);
  if (mode === null) return { used: false, reason: '~/.openclaw/openclaw.json could not be read to confirm a local gateway' };
  if (mode === 'remote') return { used: false, reason: 'gateway.mode is remote, so the local gateway\'s credential is not this install\'s' };

  const read = readOwnedBootEnv(params.home, geteuid());
  if ('reason' in read) return { used: false, reason: read.reason };
  const creds = parseGatewayBootEnv(read.text);
  const keys = GATEWAY_CREDENTIAL_KEYS.filter((k) => creds[k] !== undefined);
  if (keys.length === 0) {
    return { used: false, reason: `${GATEWAY_BOOT_ENV_DISPLAY} has no plain OPENCLAW_GATEWAY_TOKEN or OPENCLAW_GATEWAY_PASSWORD line` };
  }
  return { used: true, env: creds, keys };
}

/**
 * Replace every credential value in `text` with `[redacted:$KEY]`, longest
 * first so a value that prefixes another cannot leave a tail behind. Applied
 * to everything the install child said before it reaches the screen: the
 * shared reporter only redacts `process.env` secrets of 8+ characters, and
 * these values were never in `process.env`.
 */
export function redactGatewayCredentials(text: string, creds: GatewayCredentials): string {
  const entries = Object.entries(creds)
    .filter((e): e is [string, string] => typeof e[1] === 'string' && e[1].length > 0)
    .sort((a, b) => b[1].length - a[1].length);
  let out = text;
  for (const [key, value] of entries) out = out.split(value).join(`[redacted:$${key}]`);
  return out;
}
