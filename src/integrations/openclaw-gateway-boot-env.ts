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
 *    OPENCLAW_GATEWAY_URL, OPENCLAW_GATEWAY_PORT, or any legacy CLAWDBOT_*
 *    variable) the file is not read at all. Nor is it when either dotenv file
 *    OpenClaw loads into its OWN process at startup names one of them:
 *    `~/.openclaw/.env` and `~/.config/openclaw/gateway.env` are applied to
 *    the child's environment first-wins with no OPENCLAW_* blocklist (OpenClaw
 *    2026.11.4 dist/cli/run-main.js `shouldLoadCliDotEnv`,
 *    dist/dotenv-global-*.mjs `resolveGlobalDotEnvFiles`), before the gateway
 *    URL and port are chosen. Both are read the hardened way below (the first
 *    through the checked directory); a missing one is fine, one that cannot
 *    be read is a refusal. The custom state dir OpenClaw could use is never
 *    resolved here: every variable that would move it is a refusal above.
 *  - Local gateway only, as OpenClaw would resolve it: OpenClaw sends an env
 *    token to a REMOTE gateway too (env-first precedence,
 *    dist/credentials-*.mjs), and the mode it acts on is the one AFTER `$include`
 *    files and `${VAR}` substitution (dist/io.read-helpers-*.mjs). This module
 *    resolves neither, so a config that uses either anywhere, sets an
 *    OPENCLAW_* / CLAWDBOT_* variable in its `env` block (applied to the
 *    process before the gateway URL is chosen), is not strict JSON, or has a
 *    `gateway.mode` other than absent or exactly "local", is never given the
 *    local gateway's credential. The refusal must also name the local
 *    gateway's own `gateway.auth.token` / `gateway.auth.password`.
 *  - No diagnostics that could print a child's environment: Node's
 *    `child_process` debug log writes every spawn's env to this process's
 *    stderr, and it is switched on from NODE_DEBUG at startup. Any non-blank
 *    NODE_DEBUG or NODE_DEBUG_NATIVE, a `child_process` debug log already on,
 *    or a NODE_OPTIONS the child would inherit that asks for a diagnostic
 *    report, a trace, an inspector or a heap snapshot (each can write the
 *    child's environment out), and nothing is borrowed.
 *  - Bound to the directory it checked: `~/.openclaw` must not be a symbolic
 *    link. It is opened O_DIRECTORY|O_NOFOLLOW and checked on that descriptor
 *    (a directory, owned by the user running update, not writable by group or
 *    others); both files are then opened THROUGH that descriptor
 *    (`/proc/self/fd/<n>/…`, where the kernel provides it; elsewhere by path,
 *    with only the post-open identity check below) with O_NOFOLLOW, and the
 *    directory's identity is re-checked after each open. Each file is
 *    checked on its own descriptor; the boot env must be a regular file, one
 *    link, owned by that user, not writable by group or others, at most
 *    64 KiB. Without O_NOFOLLOW, O_DIRECTORY and O_NONBLOCK nothing is read.
 *  - Parsed, never run: entries found the way systemd's EnvironmentFile
 *    parser finds them (a backslash-newline continues a value, a quoted value
 *    can span lines), but only a credential entry on ONE line, in the form
 *    OpenClaw's serializer writes, is taken. Only OPENCLAW_GATEWAY_TOKEN and
 *    OPENCLAW_GATEWAY_PASSWORD are taken. A value that would need shell or
 *    systemd expansion (`$…`, a backtick), any quoting OpenClaw's serializer
 *    does not write, or a file that is not valid UTF-8, is not used.
 *  - Nothing is written, cached, logged or printed. Callers get the values
 *    only to put them in one child's env; whatever that child says back is
 *    never shown (update.ts reports it in fixed words), and
 *    `redactGatewayCredentials` scrubs them as a second line of defence.
 */
import fs from 'fs';
import path from 'path';
import { debuglog } from 'util';

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
 * different gateway than the one the install talks to. Any non-blank
 * CLAWDBOT_* variable (the pre-rename spelling of the state-dir and config
 * overrides) counts too; see `LEGACY_OVERRIDE_PREFIX`.
 */
const LOCATION_OVERRIDES = [
  'OPENCLAW_GATEWAY_URL',
  // Env-first over the config's gateway.port (resolveGatewayPort): the local
  // URL's port can be anything, including a listener that is not the gateway.
  'OPENCLAW_GATEWAY_PORT',
  'OPENCLAW_STATE_DIR',
  'OPENCLAW_HOME',
  'OPENCLAW_PROFILE',
  'OPENCLAW_CONFIG_PATH',
] as const;

/** Every legacy (pre-OpenClaw) variable is treated as a location override. */
const LEGACY_OVERRIDE_PREFIX = 'CLAWDBOT_';

const MAX_BOOT_ENV_BYTES = 64 * 1024;
/** OpenClaw's own cap for a dotenv file (`MAX_DOTENV_FILE_BYTES`); a larger one is not read here. */
const MAX_DOTENV_BYTES = 1024 * 1024;
/** openclaw.json is read only to find the gateway mode; a config past this is not read. */
const MAX_CONFIG_BYTES = 4 * 1024 * 1024;

export type GatewayBootCredentials =
  | { used: true; env: GatewayCredentials; keys: GatewayCredentialKey[] }
  | { used: false; reason: string };

function isCredentialKey(key: string): key is GatewayCredentialKey {
  return (GATEWAY_CREDENTIAL_KEYS as readonly string[]).includes(key);
}

/**
 * One systemd EnvironmentFile value, decoded the way OpenClaw's own serializer
 * writes it: bare when it needs no quoting, else double-quoted with `\\`,
 * `\"`, `` \` `` and `\$` escapes. Anything else — single quotes (the
 * serializer never writes them, so they did not come from OpenClaw), an
 * unescaped `$` or backtick (systemd may expand it), any other backslash,
 * unbalanced quotes, inner whitespace in a bare value, a control character —
 * is null: the gateway's real value cannot be known for certain, so none is
 * used.
 */
function decodeValue(raw: string): string | null {
  // systemd strips spaces and tabs around a value, nothing else: a JS trim()
  // would also drop a no-break space or a BOM the gateway keeps.
  const v = raw.replace(/^[ \t]+|[ \t]+$/g, '');
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
  } else {
    if (/[\s'"$`\\]/.test(v)) return null;
    out = v;
  }
  // eslint-disable-next-line no-control-regex
  if (!out || /[\x00-\x1f\x7f]/.test(out)) return null;
  return out;
}

/** systemd's env-file character classes (src/basic/env-file.c: NEWLINE, WHITESPACE, COMMENTS). */
const SD_NEWLINE = '\n\r';
const SD_WHITESPACE = ' \t\n\r';
const SD_COMMENTS = '#;';

type SdState =
  | 'preKey' | 'key' | 'preValue' | 'value' | 'valueEscape'
  | 'singleQuote' | 'doubleQuote' | 'doubleQuoteEscape' | 'comment' | 'commentEscape';

/**
 * The two gateway credential keys out of a systemd EnvironmentFile body. Pure.
 *
 * Entries are found the way systemd's own parser finds them
 * (`parse_env_file_internal`, src/basic/env-file.c): `\n` and `\r` both end
 * a line, a backslash-newline in a value is a continuation, a quoted value
 * runs on across lines, and nothing after a NUL is read. A line that only
 * LOOKS like `OPENCLAW_GATEWAY_TOKEN=…` but is the tail of another entry is
 * therefore not a credential. A credential entry is taken only when it sits
 * on one line and decodes in the form OpenClaw's serializer writes; one that
 * runs past its line has a line break in its raw text, which `decodeValue`
 * never accepts, so it is not used. A comment ending in a backslash means
 * nothing is used at all: systemd before v254 continues such a comment onto
 * the next line and v254 and later do not, so what the gateway got depends on
 * a version this cannot know (OpenClaw's serializer writes no comments).
 *
 * Every other key is ignored without being decoded. The last entry for a key
 * wins, as in systemd — and when that last entry is one this parser will not
 * use, the key is dropped rather than an earlier value used.
 */
export function parseGatewayBootEnv(content: string): GatewayCredentials {
  const out: GatewayCredentials = {};
  const nul = content.indexOf('\0');
  const text = nul === -1 ? content : content.slice(0, nul);
  let state: SdState = 'preKey';
  let keyStart = 0;
  let keyEnd = 0;
  let valueStart = 0;
  /** A comment ended in a backslash-newline: what follows depends on the systemd version. */
  let versionDependent = false;

  const finish = (end: number) => {
    const key = text.slice(keyStart, keyEnd).replace(/[ \t]+$/, '');
    if (!isCredentialKey(key)) return;
    // An entry that ran on past its line keeps that line break in this raw
    // slice; decodeValue refuses it (whitespace in a bare value, a control
    // character in a quoted one).
    const value = decodeValue(text.slice(valueStart, end));
    if (value === null) delete out[key];
    else out[key] = value;
  };

  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    const newline = SD_NEWLINE.includes(c);
    switch (state) {
      case 'preKey':
        if (SD_COMMENTS.includes(c)) state = 'comment';
        else if (!SD_WHITESPACE.includes(c)) {
          state = 'key';
          keyStart = i;
        }
        break;
      case 'key':
        if (newline) state = 'preKey';
        else if (c === '=') {
          state = 'preValue';
          keyEnd = i;
          valueStart = i + 1;
        }
        break;
      case 'preValue':
      case 'value':
        if (newline) {
          finish(i);
          state = 'preKey';
        } else if (c === '\\') state = 'valueEscape';
        else if (state === 'preValue' && c === "'") state = 'singleQuote';
        else if (state === 'preValue' && c === '"') state = 'doubleQuote';
        else if (state === 'preValue' && !SD_WHITESPACE.includes(c)) state = 'value';
        break;
      case 'valueEscape':
        state = 'value';
        break;
      case 'singleQuote':
        if (c === "'") state = 'preValue';
        break;
      case 'doubleQuote':
        if (c === '"') state = 'preValue';
        else if (c === '\\') state = 'doubleQuoteEscape';
        break;
      case 'doubleQuoteEscape':
        state = 'doubleQuote';
        break;
      case 'comment':
        if (c === '\\') state = 'commentEscape';
        else if (newline) state = 'preKey';
        break;
      case 'commentEscape':
        if (newline) {
          versionDependent = true;
          state = 'preKey';
        } else state = 'comment';
        break;
    }
  }
  // End of input inside an entry: systemd keeps what it has.
  if (state === 'preValue' || state === 'value' || state === 'valueEscape' || state === 'singleQuote'
    || state === 'doubleQuote' || state === 'doubleQuoteEscape') {
    finish(text.length);
  }
  return versionDependent ? {} : out;
}

type Owned = { uid: number | bigint; mode: number | bigint };

/** Why an owned-private check failed, or null when it passed. */
function ownerProblem(st: Owned, euid: number): string | null {
  if (Number(st.uid) !== euid) return 'is not owned by the user running update';
  if ((Number(st.mode) & 0o022) !== 0) return 'is writable by group or others';
  return null;
}

const errCode = (err: unknown): string => (err as NodeJS.ErrnoException)?.code ?? 'error';

/**
 * The open flags every read here needs, or null when this platform lacks one —
 * then nothing is read. Never `?? 0`: a missing O_NOFOLLOW would follow a
 * symlink, a missing O_DIRECTORY would accept a file, a missing O_NONBLOCK
 * would block on a FIFO.
 */
function openFlags(): { dir: number; file: number } | null {
  const c = fs.constants as Partial<Record<'O_RDONLY' | 'O_NOFOLLOW' | 'O_DIRECTORY' | 'O_NONBLOCK', number>>;
  const { O_RDONLY, O_NOFOLLOW, O_DIRECTORY, O_NONBLOCK } = c;
  if (typeof O_RDONLY !== 'number') return null;
  for (const flag of [O_NOFOLLOW, O_DIRECTORY, O_NONBLOCK]) {
    if (typeof flag !== 'number' || flag === 0) return null;
  }
  return {
    dir: O_RDONLY | (O_DIRECTORY as number) | (O_NOFOLLOW as number),
    file: O_RDONLY | (O_NOFOLLOW as number) | (O_NONBLOCK as number),
  };
}

/** `~/.openclaw`, open, and the identity it was checked under. */
interface StateDir {
  fd: number;
  dev: bigint;
  ino: bigint;
  path: string;
}

/**
 * Open `~/.openclaw` without following a link and check it on that
 * descriptor, or say why not. A symlinked `~/.openclaw` is refused even when
 * its target would pass: what the checks describe must be the directory
 * itself, not wherever a link points.
 */
function openStateDir(home: string, euid: number, flags: { dir: number }): { dir: StateDir } | { reason: string } {
  const dirPath = path.join(home, '.openclaw');
  let pre: fs.BigIntStats;
  try {
    pre = fs.lstatSync(dirPath, { bigint: true });
  } catch {
    return { reason: '~/.openclaw could not be read' };
  }
  if (pre.isSymbolicLink()) return { reason: '~/.openclaw is a symbolic link' };
  if (!pre.isDirectory()) return { reason: '~/.openclaw is not a directory' };
  let fd: number;
  try {
    fd = fs.openSync(dirPath, flags.dir);
  } catch (err) {
    const code = errCode(err);
    if (code === 'ELOOP') return { reason: '~/.openclaw is a symbolic link' };
    if (code === 'ENOTDIR') return { reason: '~/.openclaw is not a directory' };
    return { reason: `~/.openclaw could not be opened (${code})` };
  }
  let reason: string;
  try {
    const st = fs.fstatSync(fd, { bigint: true });
    if (!st.isDirectory()) reason = '~/.openclaw is not a directory';
    else if (st.dev !== pre.dev || st.ino !== pre.ino) reason = '~/.openclaw changed while it was being checked';
    else {
      const problem = ownerProblem(st, euid);
      if (!problem) return { dir: { fd, dev: st.dev, ino: st.ino, path: dirPath } };
      reason = `~/.openclaw ${problem}`;
    }
  } catch (err) {
    reason = `~/.openclaw could not be read (${errCode(err)})`;
  }
  try { fs.closeSync(fd); } catch { /* already closed */ }
  return { reason };
}

/** Thrown by `openInDir` when `~/.openclaw` is no longer the directory that was checked. */
const DIR_CHANGED = 'SC_STATE_DIR_CHANGED';

/**
 * Open `name` inside the checked directory, never through a link. Where the
 * kernel provides `/proc/self/fd`, the path goes THROUGH the directory's own
 * descriptor, so the file is the one in the directory that was checked even
 * if `~/.openclaw` is swapped meanwhile. Elsewhere (macOS) the open goes by
 * path, and the only guard is the identity check that follows it: that
 * catches a swap still in place when the file has been opened, not one made
 * and undone around the open. Either way, a `~/.openclaw` that is no longer
 * the checked directory after the open — or is now a link — is refused,
 * because it is no longer the one the gateway reads either.
 */
function openInDir(dir: StateDir, name: string, flags: number): number {
  const viaFd = `/proc/self/fd/${dir.fd}`;
  let bound = false;
  try {
    const st = fs.statSync(viaFd, { bigint: true });
    bound = st.dev === dir.dev && st.ino === dir.ino;
  } catch {
    bound = false;
  }
  const fd = fs.openSync(path.join(bound ? viaFd : dir.path, name), flags);
  let still = false;
  try {
    const now = fs.lstatSync(dir.path, { bigint: true });
    still = !now.isSymbolicLink() && now.dev === dir.dev && now.ino === dir.ino;
  } catch {
    still = false;
  }
  if (!still) {
    try { fs.closeSync(fd); } catch { /* already closed */ }
    throw Object.assign(new Error('~/.openclaw changed while it was being read'), { code: DIR_CHANGED });
  }
  return fd;
}

/** Fill `buf` from `fd` until EOF or `buf` is full; the byte count. Size `buf` one past the limit to detect more. */
function readBounded(fd: number, buf: Buffer): number {
  let n = 0;
  while (n < buf.length) {
    const got = fs.readSync(fd, buf, n, buf.length - n, null);
    if (got === 0) break;
    n += got;
  }
  return n;
}

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);
const own = (o: Record<string, unknown>, k: string): unknown =>
  Object.prototype.hasOwnProperty.call(o, k) ? o[k] : undefined;

/**
 * Why this config cannot be confirmed to be a LOCAL gateway as OpenClaw would
 * resolve it, or null when it is. OpenClaw acts on the config after `$include`
 * and `${VAR}` substitution (dist/io.read-helpers-*.mjs), and applies the
 * config's `env` block to its own process before it picks the gateway URL —
 * none of which is resolved here, so any of them anywhere fails closed. The
 * mode must be absent (OpenClaw's default, local) or exactly "local".
 */
function localGatewayProblem(cfg: unknown): string | null {
  if (!isPlainObject(cfg)) return '~/.openclaw/openclaw.json is not a JSON object, so a local gateway could not be confirmed';
  const stack: unknown[] = [cfg];
  while (stack.length > 0) {
    const cur = stack.pop();
    if (typeof cur === 'string') {
      if (cur.includes('${')) return '~/.openclaw/openclaw.json uses ${…} substitution, so the gateway mode OpenClaw resolves cannot be confirmed local';
    } else if (Array.isArray(cur)) {
      for (const item of cur) stack.push(item);
    } else if (isPlainObject(cur)) {
      for (const [k, v] of Object.entries(cur)) {
        if (k === '$include') return '~/.openclaw/openclaw.json uses $include, so the gateway mode OpenClaw resolves cannot be confirmed local';
        if (k.includes('${')) return '~/.openclaw/openclaw.json uses ${…} substitution, so the gateway mode OpenClaw resolves cannot be confirmed local';
        stack.push(v);
      }
    }
  }
  const gateway = own(cfg, 'gateway');
  if (gateway !== undefined) {
    if (!isPlainObject(gateway)) return 'gateway in ~/.openclaw/openclaw.json is not an object, so a local gateway could not be confirmed';
    const mode = own(gateway, 'mode');
    if (mode === 'remote') return 'gateway.mode is remote, so the local gateway\'s credential is not this install\'s';
    if (mode !== undefined && mode !== 'local') return 'gateway.mode is not exactly "local", so a local gateway could not be confirmed';
  }
  const envBlock = own(cfg, 'env');
  if (envBlock !== undefined) {
    const vars = isPlainObject(envBlock) ? own(envBlock, 'vars') : undefined;
    if (!isPlainObject(envBlock) || (vars !== undefined && !isPlainObject(vars))) {
      return 'the env block in ~/.openclaw/openclaw.json could not be checked, so a local gateway could not be confirmed';
    }
    const names = [...Object.keys(envBlock), ...(vars ? Object.keys(vars) : [])];
    if (names.some((n) => /^(OPENCLAW_|CLAWDBOT_)/i.test(n.trim()))) {
      return 'the env block in ~/.openclaw/openclaw.json sets an OPENCLAW_* or CLAWDBOT_* variable, which can point the install at another gateway';
    }
  }
  return null;
}

/** Why `openclaw.json` (read through the checked directory) does not confirm a local gateway, or null. */
function confirmLocalGateway(dir: StateDir, flags: { file: number }): string | null {
  const unread = '~/.openclaw/openclaw.json could not be read to confirm a local gateway';
  let fd: number;
  try {
    fd = openInDir(dir, 'openclaw.json', flags.file);
  } catch (err) {
    const code = errCode(err);
    if (code === DIR_CHANGED) return '~/.openclaw changed while it was being read';
    if (code === 'ELOOP') return '~/.openclaw/openclaw.json is a symbolic link, so it was not read to confirm a local gateway';
    return unread;
  }
  const buf = Buffer.alloc(MAX_CONFIG_BYTES + 1);
  try {
    if (!fs.fstatSync(fd).isFile()) return '~/.openclaw/openclaw.json is not a regular file, so it was not read to confirm a local gateway';
    const n = readBounded(fd, buf);
    if (n > MAX_CONFIG_BYTES) return '~/.openclaw/openclaw.json is larger than 4 MiB, so it was not read to confirm a local gateway';
    let cfg: unknown;
    try {
      cfg = JSON.parse(buf.subarray(0, n).toString('utf8'));
    } catch {
      // OpenClaw parses JSON5; this reads strict JSON only, so a config with
      // comments, unquoted keys or trailing commas is not confirmed local.
      return '~/.openclaw/openclaw.json is not strict JSON (JSON5 configs are not read here), so a local gateway could not be confirmed';
    }
    return localGatewayProblem(cfg);
  } catch {
    return unread;
  } finally {
    // The config can hold secrets of its own; nothing here keeps them.
    buf.fill(0);
    try { fs.closeSync(fd); } catch { /* already closed */ }
  }
}

/** The boot env's text (read through the checked directory), or why it was not read. */
function readOwnedBootEnv(dir: StateDir, euid: number, flags: { file: number }): { text: string } | { reason: string } {
  let fd: number;
  try {
    fd = openInDir(dir, 'gateway.systemd.env', flags.file);
  } catch (err) {
    const code = errCode(err);
    if (code === DIR_CHANGED) return { reason: '~/.openclaw changed while it was being read' };
    if (code === 'ENOENT') return { reason: `there is no ${GATEWAY_BOOT_ENV_DISPLAY}` };
    if (code === 'ELOOP') return { reason: `${GATEWAY_BOOT_ENV_DISPLAY} is a symbolic link` };
    return { reason: `${GATEWAY_BOOT_ENV_DISPLAY} could not be opened (${code})` };
  }
  const buf = Buffer.alloc(MAX_BOOT_ENV_BYTES + 1);
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) return { reason: `${GATEWAY_BOOT_ENV_DISPLAY} is not a regular file` };
    const problem = ownerProblem(st, euid);
    if (problem) return { reason: `${GATEWAY_BOOT_ENV_DISPLAY} ${problem}` };
    if (st.nlink !== 1) return { reason: `${GATEWAY_BOOT_ENV_DISPLAY} has more than one hard link` };
    const n = readBounded(fd, buf);
    if (n > MAX_BOOT_ENV_BYTES) return { reason: `${GATEWAY_BOOT_ENV_DISPLAY} is larger than 64 KiB` };
    // systemd refuses a value that is not valid UTF-8; a lenient decode would
    // hand the child a value the gateway never had.
    try {
      return { text: new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(buf.subarray(0, n)) };
    } catch {
      return { reason: `${GATEWAY_BOOT_ENV_DISPLAY} is not valid UTF-8` };
    }
  } catch (err) {
    return { reason: `${GATEWAY_BOOT_ENV_DISPLAY} could not be read (${errCode(err)})` };
  } finally {
    buf.fill(0);
    try { fs.closeSync(fd); } catch { /* already closed */ }
  }
}

/** What every message calls the two dotenv files OpenClaw loads at startup. Never an absolute path. */
export const STATE_DOTENV_DISPLAY = '~/.openclaw/.env';
export const GATEWAY_DOTENV_DISPLAY = '~/.config/openclaw/gateway.env';

/**
 * The override a dotenv file's text names, or null. Not a parse: ANY
 * mention of an override name as a whole word counts — an assignment in
 * whatever syntax dotenv accepts (`export K=…`, `K: …`, after a `\r` or a
 * U+2028 that ends a line for it), a commented-out line, or text inside some
 * other value — case-insensitively. dotenv keys are ASCII and taken
 * literally, so whatever OpenClaw would set is always among what this finds.
 * A legacy name is reported generically: the matched text is the file's,
 * not ours to print.
 */
function dotEnvOverride(text: string): string | null {
  for (const name of LOCATION_OVERRIDES) {
    if (new RegExp(`(?<![A-Za-z0-9_])${name}(?![A-Za-z0-9_])`, 'i').test(text)) return name;
  }
  return /(?<![A-Za-z0-9_])CLAWDBOT_/i.test(text) ? 'a CLAWDBOT_* variable' : null;
}

/**
 * Why a dotenv file OpenClaw loads into the install child's own environment
 * rules the borrow out, or null when the file is absent or names no
 * override. `open` throws as `fs.openSync` does. A file that is a link, not
 * a regular file, not the user's own and private, over OpenClaw's own 1 MiB
 * cap, or unreadable is a refusal: what it would set cannot be ruled out.
 */
function dotEnvProblem(display: string, open: () => number, euid: number): string | null {
  const why = 'so it could not be ruled out that it points the install at another gateway';
  let fd: number;
  try {
    fd = open();
  } catch (err) {
    const code = errCode(err);
    // Absent — or a path through a non-directory, which OpenClaw cannot read either.
    if (code === 'ENOENT' || code === 'ENOTDIR') return null;
    if (code === DIR_CHANGED) return '~/.openclaw changed while it was being read';
    if (code === 'ELOOP') return `${display} is a symbolic link, ${why}`;
    return `${display} could not be opened (${code}), ${why}`;
  }
  const buf = Buffer.alloc(MAX_DOTENV_BYTES + 1);
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) return `${display} is not a regular file, ${why}`;
    const problem = ownerProblem(st, euid);
    if (problem) return `${display} ${problem}, ${why}`;
    const n = readBounded(fd, buf);
    if (n > MAX_DOTENV_BYTES) return `${display} is larger than 1 MiB, ${why}`;
    const named = dotEnvOverride(buf.subarray(0, n).toString('utf8'));
    if (named) {
      return `${display} names ${named}, which OpenClaw loads into the install's own environment and which can point it at another gateway`;
    }
    return null;
  } catch (err) {
    return `${display} could not be read (${errCode(err)}), ${why}`;
  } finally {
    // Provider keys live in these files; nothing here keeps them.
    buf.fill(0);
    try { fs.closeSync(fd); } catch { /* already closed */ }
  }
}

/**
 * Why the dotenv files the install child loads at startup rule the borrow
 * out, or null. `~/.openclaw/.env` is read through the checked directory;
 * `~/.config/openclaw/gateway.env` by its fixed path under `home` (the HOME
 * the child is given), never following a link at the file itself. A dotenv
 * in the child's working directory needs no check: OpenClaw drops every
 * OPENCLAW_* key from it (dist/dotenv-*.mjs `BLOCKED_WORKSPACE_DOTENV_PREFIXES`)
 * and no longer reads CLAWDBOT_*.
 */
function runtimeDotEnvProblem(dir: StateDir, home: string, euid: number, flags: { file: number }): string | null {
  return dotEnvProblem(STATE_DOTENV_DISPLAY, () => openInDir(dir, '.env', flags.file), euid)
    ?? dotEnvProblem(GATEWAY_DOTENV_DISPLAY, () => fs.openSync(path.join(home, '.config', 'openclaw', 'gateway.env'), flags.file), euid);
}

/**
 * NODE_OPTIONS a Node child inherits that can write its environment out: a
 * diagnostic report (`--report-*` includes every environment variable), a
 * trace (`--trace-env` prints the values it reads), an inspector or debug
 * port, a heap snapshot (every string in the heap), or an env file loaded at
 * startup. Node accepts `_` for `-` in option names, so both are matched.
 */
const NODE_OPTIONS_DIAGNOSTICS = /--(?:report|trace|inspect|debug|heapsnapshot|env-file)/;

/**
 * Which Node diagnostic would print a spawned child's environment, or null.
 * Node's `child_process` debug log formats each spawn's options — env
 * included — to THIS process's stderr, and the sections it logs are fixed
 * from NODE_DEBUG when Node starts: removing the variable later does not turn
 * them off, so the live switch is asked as well. Any non-blank NODE_DEBUG
 * counts, whatever it names: the retry child inherits it too — and so would it
 * inherit a diagnostic NODE_OPTIONS.
 */
function spawnDiagnostics(env: NodeJS.ProcessEnv): string | null {
  for (const k of ['NODE_DEBUG', 'NODE_DEBUG_NATIVE'] as const) {
    if (env[k]?.trim()) return k;
  }
  const nodeOptions = env.NODE_OPTIONS?.toLowerCase().replace(/_/g, '-');
  if (nodeOptions && NODE_OPTIONS_DIAGNOSTICS.test(nodeOptions)) return 'NODE_OPTIONS';
  return debuglog('child_process').enabled ? 'NODE_DEBUG' : null;
}

/** The first location override set in `env`: an OPENCLAW_* one, or any legacy CLAWDBOT_* variable. */
function locationOverride(env: NodeJS.ProcessEnv): string | null {
  const named = LOCATION_OVERRIDES.find((k) => env[k]?.trim());
  if (named) return named;
  const legacy = Object.keys(env).find((k) => k.toUpperCase().startsWith(LEGACY_OVERRIDE_PREFIX) && env[k]?.trim());
  if (!legacy) return null;
  return /^[A-Za-z0-9_]{1,64}$/.test(legacy) ? legacy : 'a CLAWDBOT_* variable';
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
  const diagnostics = spawnDiagnostics(env);
  if (diagnostics) {
    const what = diagnostics === 'NODE_OPTIONS' ? 'NODE_OPTIONS asks for a Node diagnostic' : `${diagnostics} is set`;
    return { used: false, reason: `${what}, and Node's diagnostics would print the retry child's environment, so ${GATEWAY_BOOT_ENV_DISPLAY} was not read` };
  }
  const override = locationOverride(env);
  if (override) {
    return { used: false, reason: `${override} is set, so ${GATEWAY_BOOT_ENV_DISPLAY} may not belong to the gateway this install talks to` };
  }
  const geteuid = params.geteuid ?? (typeof process.geteuid === 'function' ? process.geteuid.bind(process) : undefined);
  if (!geteuid) return { used: false, reason: 'the boot env\'s owner cannot be checked on this platform' };
  const flags = openFlags();
  if (!flags) return { used: false, reason: `${GATEWAY_BOOT_ENV_DISPLAY} cannot be opened without following links on this platform` };
  const euid = geteuid();

  const opened = openStateDir(params.home, euid, flags);
  if ('reason' in opened) return { used: false, reason: opened.reason };
  try {
    const notLocal = confirmLocalGateway(opened.dir, flags);
    if (notLocal) return { used: false, reason: notLocal };
    const dotEnv = runtimeDotEnvProblem(opened.dir, params.home, euid, flags);
    if (dotEnv) return { used: false, reason: dotEnv };
    const read = readOwnedBootEnv(opened.dir, euid, flags);
    if ('reason' in read) return { used: false, reason: read.reason };
    const creds = parseGatewayBootEnv(read.text);
    const keys = GATEWAY_CREDENTIAL_KEYS.filter((k) => creds[k] !== undefined);
    if (keys.length === 0) {
      return { used: false, reason: `${GATEWAY_BOOT_ENV_DISPLAY} has no plain OPENCLAW_GATEWAY_TOKEN or OPENCLAW_GATEWAY_PASSWORD line` };
    }
    return { used: true, env: creds, keys };
  } finally {
    try { fs.closeSync(opened.dir.fd); } catch { /* already closed */ }
  }
}

/**
 * Replace every credential value in `text` with `[redacted:$KEY]`, longest
 * first so a value that prefixes another cannot leave a tail behind. A second
 * line of defence only: update never shows what the credentialed child said
 * (it reports that child's ending in fixed words), and an exact match cannot
 * catch a value the child re-encoded, trimmed or cut apart.
 */
export function redactGatewayCredentials(text: string, creds: GatewayCredentials): string {
  const entries = Object.entries(creds)
    .filter((e): e is [string, string] => typeof e[1] === 'string' && e[1].length > 0)
    .sort((a, b) => b[1].length - a[1].length);
  let out = text;
  for (const [key, value] of entries) out = out.split(value).join(`[redacted:$${key}]`);
  return out;
}
