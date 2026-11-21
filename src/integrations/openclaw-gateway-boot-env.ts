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
 * An operator can add more `EnvironmentFile=` lines to that unit (or a
 * drop-in) and keep the credential there instead — e.g.
 * `~/.openclaw/secrets/gateway-boot.env` after the generated file. systemd
 * reads every listed file in order, a later file overriding an earlier one per
 * key, so the gateway's value is whatever the LAST file that sets the key
 * says (#1105 reopened, clawdbot1).
 *
 * This module reads those files, and only to hand the two gateway credential
 * keys to the one install child that OpenClaw just refused. Rules:
 *
 *  - Paths come only from the unit's effective EnvironmentFiles as systemd
 *    reports them (`systemctl --user show -p EnvironmentFiles
 *    openclaw-gateway.service`, drop-ins included), constrained to the checked
 *    state dir: every listed path must be a plain absolute path inside
 *    `<home>/.openclaw/` — no `.`/`..`/empty segment, no wildcard — or nothing
 *    is read. When systemd gives no answer (not Linux, no systemctl, no user
 *    manager, the unit unknown or listing no file) only the fixed
 *    `<home>/.openclaw/gateway.systemd.env` is read, exactly as before. No
 *    path comes from an environment variable, a config value, or the unit
 *    file's text. When anything
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
 *    child's environment out), or that preloads a module (`--require`, `-r`,
 *    `--import`, `--loader`), and nothing is borrowed. NODE_OPTIONS is
 *    checked as Node splits it (double quotes and the backslash escapes
 *    inside them are Node's to remove); one Node cannot split is a refusal.
 *  - Bound to the directory it checked: `~/.openclaw` must not be a symbolic
 *    link. It is opened O_DIRECTORY|O_NOFOLLOW and checked on that descriptor
 *    (a directory, owned by the user running update, not writable by group or
 *    others); both files are then opened THROUGH that descriptor
 *    (`/proc/self/fd/<n>/…`, where the kernel provides it; elsewhere by path,
 *    with only the post-open identity check below) with O_NOFOLLOW, and the
 *    directory's identity is re-checked after each open. A unit-listed file
 *    in a subdirectory is reached one component at a time the same way: each
 *    directory on its path opened through its parent's descriptor with
 *    O_DIRECTORY|O_NOFOLLOW and given the state dir's checks, and every
 *    directory above it re-checked after each open. Each file is
 *    checked on its own descriptor; a boot env must be a regular file, one
 *    link, owned by that user, not writable by group or others, at most
 *    64 KiB. A link anywhere on the way, or any failed check, means nothing
 *    is used. Without O_NOFOLLOW, O_DIRECTORY and O_NONBLOCK nothing is read.
 *  - Same order and precedence as systemd: listed files are applied in order,
 *    later over earlier, per key. A file listed with `-` that does not exist
 *    is skipped; a required one that does not exist means nothing is used
 *    (systemd would not start the unit). When the LAST file that sets a key
 *    sets it in a form not taken here, that key is not used at all — an
 *    earlier file's value is not what the gateway has.
 *  - systemctl is run by fixed absolute path (`/usr/bin/systemctl`, else
 *    `/bin/systemctl`), with fixed arguments, no shell, a short timeout, and
 *    an environment of only LC_ALL and the two variables that locate the user
 *    manager; what it prints is parsed, never shown.
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
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
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

/**
 * `from` is set only when the files came from the gateway unit's
 * EnvironmentFiles: the file(s) the used keys came from, each as
 * `~/.openclaw/…` (or a fixed phrase), never an absolute path. Without it the
 * keys came from `GATEWAY_BOOT_ENV_DISPLAY`.
 */
export type GatewayBootCredentials =
  | { used: true; env: GatewayCredentials; keys: GatewayCredentialKey[]; from?: string[] }
  | { used: false; reason: string };

/** The gateway's systemd user unit, as OpenClaw installs it. */
export const GATEWAY_UNIT = 'openclaw-gateway.service';

/**
 * Runs systemctl with these arguments and this complete environment; null when
 * it could not be run (missing, killed, timed out). A parameter only so a test
 * can stand in for a host's systemd.
 */
export type SystemctlRunner = (
  args: readonly string[],
  env: Record<string, string>,
) => { status: number | null; stdout: string } | null;

/** One `EnvironmentFiles=` entry as systemd reports it. */
export interface UnitEnvironmentFile {
  path: string;
  /** `ignore_errors=yes` — the `-` prefix: a missing file is skipped. */
  optional: boolean;
}

/**
 * What systemd says about the gateway unit's EnvironmentFiles:
 *  - `files`: the unit is loaded; its effective list, in order (may be empty);
 *  - `unknown`: no answer about a loadable unit (no systemd, no user manager,
 *    the unit not found / masked / not loadable);
 *  - `unparsable`: systemd answered with something this does not understand.
 */
export type UnitEnvironmentFiles =
  | { kind: 'files'; files: UnitEnvironmentFile[] }
  | { kind: 'unknown' }
  | { kind: 'unparsable' };

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
 * runs on across lines. A body with a NUL byte in it is not used at all:
 * OpenClaw's serializer never writes one, and nothing here depends on what
 * a given systemd makes of the bytes around it. A line that only
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
export function parseGatewayBootEnv(text: string): GatewayCredentials {
  const out: GatewayCredentials = {};
  for (const [key, entry] of Object.entries(parseGatewayBootEnvEntries(text)) as [GatewayCredentialKey, GatewayKeyEntry][]) {
    if (entry.kind === 'value') out[key] = entry.value;
  }
  return out;
}

/**
 * What one file says about a credential key: absent (no entry), a value this
 * takes, or `unusable` — the file's last entry for the key is in a form this
 * does not take (or what the file sets cannot be known at all), so the
 * gateway's value for it is not knowable from here.
 */
export type GatewayKeyEntry = { kind: 'value'; value: string } | { kind: 'unusable' };

/**
 * `parseGatewayBootEnv`, per key: absent keys are missing from the result.
 * Needed across several files: an `unusable` last entry in a LATER file
 * overrides an earlier file's value in the gateway, so it must not fall back
 * to it. A body with a NUL, or one whose meaning depends on the systemd
 * version, marks both keys unusable. Pure.
 */
export function parseGatewayBootEnvEntries(text: string): Partial<Record<GatewayCredentialKey, GatewayKeyEntry>> {
  const allUnusable = (): Partial<Record<GatewayCredentialKey, GatewayKeyEntry>> =>
    Object.fromEntries(GATEWAY_CREDENTIAL_KEYS.map((k) => [k, { kind: 'unusable' }]));
  const out: Partial<Record<GatewayCredentialKey, GatewayKeyEntry>> = {};
  if (text.includes('\0')) return allUnusable();
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
    out[key] = value === null ? { kind: 'unusable' } : { kind: 'value', value };
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
  return versionDependent ? allUnusable() : out;
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

/**
 * `~/.openclaw` (or a directory under it, reached from it), open, and the
 * identity it was checked under. `parent` is the checked directory it was
 * opened through; every one up to `~/.openclaw` is re-checked after each open.
 */
interface StateDir {
  fd: number;
  dev: bigint;
  ino: bigint;
  path: string;
  parent?: StateDir;
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

/**
 * The path `name` inside the checked directory is opened by: through the
 * directory's own descriptor where the kernel provides `/proc/self/fd`, else
 * by path (see `openInDir`).
 */
function inDirPath(dir: StateDir, name: string): string {
  const viaFd = `/proc/self/fd/${dir.fd}`;
  let bound = false;
  try {
    const st = fs.statSync(viaFd, { bigint: true });
    bound = st.dev === dir.dev && st.ino === dir.ino;
  } catch {
    bound = false;
  }
  return path.join(bound ? viaFd : dir.path, name);
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
 * because it is no longer the one the gateway reads either. For a directory
 * below `~/.openclaw` the same holds for it and every directory above it.
 */
function openInDir(dir: StateDir, name: string, flags: number): number {
  const fd = fs.openSync(inDirPath(dir, name), flags);
  let still = true;
  for (let d: StateDir | undefined = dir; d && still; d = d.parent) {
    try {
      const now = fs.lstatSync(d.path, { bigint: true });
      still = !now.isSymbolicLink() && now.dev === d.dev && now.ino === d.ino;
    } catch {
      still = false;
    }
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

/** One boot env file's text, or that it does not exist, or why it was not read. */
type EnvFileRead = { text: string } | { missing: true } | { reason: string };

/**
 * A boot env's text, read as `name` through the checked directory `dir`, or
 * why it was not read. `display` is what every reason calls it (never an
 * absolute path). Absent is reported as `missing`; what that means is the
 * caller's to say.
 */
function readOwnedEnvFile(dir: StateDir, name: string, display: string, euid: number, flags: { file: number }): EnvFileRead {
  let fd: number;
  try {
    fd = openInDir(dir, name, flags.file);
  } catch (err) {
    const code = errCode(err);
    if (code === DIR_CHANGED) return { reason: '~/.openclaw changed while it was being read' };
    if (code === 'ENOENT') return { missing: true };
    if (code === 'ELOOP') return { reason: `${display} is a symbolic link` };
    return { reason: `${display} could not be opened (${code})` };
  }
  const buf = Buffer.alloc(MAX_BOOT_ENV_BYTES + 1);
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) return { reason: `${display} is not a regular file` };
    const problem = ownerProblem(st, euid);
    if (problem) return { reason: `${display} ${problem}` };
    if (st.nlink !== 1) return { reason: `${display} has more than one hard link` };
    const n = readBounded(fd, buf);
    if (n > MAX_BOOT_ENV_BYTES) return { reason: `${display} is larger than 64 KiB` };
    // systemd refuses a value that is not valid UTF-8; a lenient decode would
    // hand the child a value the gateway never had.
    let text: string;
    try {
      text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(buf.subarray(0, n));
    } catch {
      return { reason: `${display} is not valid UTF-8` };
    }
    // Rejected, not cut short: OpenClaw never writes a NUL, so a file with one
    // is not the file it wrote.
    if (text.includes('\0')) return { reason: `${display} contains a NUL byte` };
    return { text };
  } catch (err) {
    return { reason: `${display} could not be read (${errCode(err)})` };
  } finally {
    buf.fill(0);
    try { fs.closeSync(fd); } catch { /* already closed */ }
  }
}

/** The fixed boot env's text (read through the checked directory), or why it was not read. */
function readOwnedBootEnv(dir: StateDir, euid: number, flags: { file: number }): { text: string } | { reason: string } {
  const read = readOwnedEnvFile(dir, 'gateway.systemd.env', GATEWAY_BOOT_ENV_DISPLAY, euid, flags);
  return 'missing' in read ? { reason: `there is no ${GATEWAY_BOOT_ENV_DISPLAY}` } : read;
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
 * NODE_OPTIONS arguments a Node child inherits that can write its environment
 * out: a diagnostic report (`--report-*` includes every environment
 * variable), a trace (`--trace-env` prints the values it reads), an inspector
 * or debug port, a heap snapshot (every string in the heap), or an env file
 * loaded at startup. Matched anywhere in an argument, after lower-casing and
 * `_` → `-` (Node accepts `_` for `-` in option names).
 */
const NODE_OPTIONS_DIAGNOSTICS = /--(?:report|trace|inspect|debug|heapsnapshot|env-file)/;

/**
 * NODE_OPTIONS arguments that load code of someone else's choosing into the
 * child before OpenClaw runs — code that then holds the child's environment:
 * `--require` / `-r`, `--import`, `--loader` / `--experimental-loader`.
 */
const NODE_OPTIONS_PRELOADS = /--(?:require|import|loader|experimental-loader)|^-r$/;

/**
 * NODE_OPTIONS split into the arguments Node takes from it, the way Node
 * splits it (src/node_options.cc `ParseNodeOptionsEnvVar`): only a space
 * outside double quotes separates; a double quote opens or closes quoting and
 * is dropped; inside quotes a backslash is dropped and the character after it
 * kept as is; outside quotes a backslash is an ordinary character. So
 * `--re"port"-on-signal` is `--report-on-signal` to Node. Null when Node
 * itself rejects the value — a quote left open, or a backslash ending it
 * inside quotes — since then which options it carries is not established.
 * Pure.
 */
export function nodeOptionsArgs(value: string): string[] | null {
  const args: string[] = [];
  let quoted = false;
  let startsNew = true;
  for (let i = 0; i < value.length; i++) {
    let c = value[i];
    if (c === '\\' && quoted) {
      if (i + 1 === value.length) return null;
      c = value[++i];
    } else if (c === ' ' && !quoted) {
      startsNew = true;
      continue;
    } else if (c === '"') {
      quoted = !quoted;
      continue;
    }
    if (startsNew) {
      args.push(c);
      startsNew = false;
    } else {
      args[args.length - 1] += c;
    }
  }
  return quoted ? null : args;
}

/**
 * Why the NODE_OPTIONS the retry child inherits could expose its environment,
 * or null. Each argument is checked as Node reads it (`nodeOptionsArgs`), and
 * the value as written is checked too, for a Node that splits it more simply.
 * A value Node cannot split is a refusal. Never quotes the value.
 */
function nodeOptionsProblem(raw: string): string | null {
  const args = nodeOptionsArgs(raw);
  if (!args) {
    return 'NODE_OPTIONS has an unclosed quote or ends in a backslash inside quotes, so which options the retry child would get could not be established';
  }
  const seen = [raw, ...args].map((a) => a.toLowerCase().replace(/_/g, '-'));
  if (seen.some((a) => NODE_OPTIONS_DIAGNOSTICS.test(a))) {
    return 'NODE_OPTIONS asks for a Node diagnostic, and Node\'s diagnostics would print the retry child\'s environment';
  }
  if (seen.some((a) => NODE_OPTIONS_PRELOADS.test(a))) {
    return 'NODE_OPTIONS preloads a module (--require, -r, --import or --loader), and that code would run inside the retry child with its environment';
  }
  return null;
}

/**
 * Why a Node diagnostic or preload could expose a spawned child's
 * environment, or null. Node's `child_process` debug log formats each
 * spawn's options — env included — to THIS process's stderr, and the
 * sections it logs are fixed from NODE_DEBUG when Node starts: removing the
 * variable later does not turn them off, so the live switch is asked as
 * well. Any non-blank NODE_DEBUG counts, whatever it names: the retry child
 * inherits it too — as it inherits NODE_OPTIONS.
 */
function childEnvExposure(env: NodeJS.ProcessEnv): string | null {
  const printed = 'and Node\'s diagnostics would print the retry child\'s environment';
  for (const k of ['NODE_DEBUG', 'NODE_DEBUG_NATIVE'] as const) {
    if (env[k]?.trim()) return `${k} is set, ${printed}`;
  }
  const nodeOptions = env.NODE_OPTIONS ? nodeOptionsProblem(env.NODE_OPTIONS) : null;
  if (nodeOptions) return nodeOptions;
  return debuglog('child_process').enabled ? `NODE_DEBUG is set, ${printed}` : null;
}

/** The first location override set in `env`: an OPENCLAW_* one, or any legacy CLAWDBOT_* variable. */
function locationOverride(env: NodeJS.ProcessEnv): string | null {
  const named = LOCATION_OVERRIDES.find((k) => env[k]?.trim());
  if (named) return named;
  const legacy = Object.keys(env).find((k) => k.toUpperCase().startsWith(LEGACY_OVERRIDE_PREFIX) && env[k]?.trim());
  if (!legacy) return null;
  return /^[A-Za-z0-9_]{1,64}$/.test(legacy) ? legacy : 'a CLAWDBOT_* variable';
}

/** Where systemctl lives; fixed, never looked up on PATH (as `/bin/ps` in approve-provenance.ts). */
const SYSTEMCTL_CANDIDATES = ['/usr/bin/systemctl', '/bin/systemctl'] as const;
const SYSTEMCTL_TIMEOUT_MS = 3000;
const MAX_SYSTEMCTL_BYTES = 64 * 1024;
/** More EnvironmentFiles than this is not a unit OpenClaw or an operator wrote by hand. */
const MAX_UNIT_ENV_FILES = 32;

/** The fixed argv: one unit, two properties, nothing taken from the environment or a config. */
export const SYSTEMCTL_SHOW_ARGS = [
  '--user', '--no-pager', 'show', '--property=LoadState', '--property=EnvironmentFiles', '--', GATEWAY_UNIT,
] as const;

/**
 * This host's systemctl, or null when there is none to ask about `home`'s
 * gateway: not Linux, no systemctl at a fixed path, or `home` is not the home
 * of the user this process runs as — `systemctl --user` reaches only that
 * user's manager, whose units do not describe a gateway under another home.
 */
function hostSystemctl(home: string): SystemctlRunner | null {
  if (process.platform !== 'linux') return null;
  let ownHome: string;
  try {
    ownHome = os.userInfo().homedir;
  } catch {
    return null;
  }
  if (!ownHome || path.resolve(ownHome) !== path.resolve(home)) return null;
  const bin = SYSTEMCTL_CANDIDATES.find((p) => {
    try {
      return fs.statSync(p).isFile();
    } catch {
      return false;
    }
  });
  if (!bin) return null;
  return (args, env) => {
    const r = spawnSync(bin, args, {
      encoding: 'utf8',
      env,
      shell: false,
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: SYSTEMCTL_TIMEOUT_MS,
      maxBuffer: MAX_SYSTEMCTL_BYTES,
      windowsHide: true,
    });
    if (r.error || r.signal) return null;
    return { status: r.status, stdout: typeof r.stdout === 'string' ? r.stdout : '' };
  };
}

/**
 * The whole environment systemctl is given: a fixed locale and the two
 * variables that locate the user's manager, nothing else — never a gateway
 * credential, never anything the caller's environment adds.
 */
export function systemctlChildEnv(env: NodeJS.ProcessEnv): Record<string, string> {
  const out: Record<string, string> = { LC_ALL: 'C' };
  for (const k of ['XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS'] as const) {
    const v = env[k];
    if (typeof v === 'string' && v !== '') out[k] = v;
  }
  return out;
}

/**
 * `systemctl show --property=LoadState --property=EnvironmentFiles` output,
 * parsed. systemd prints one `EnvironmentFiles=<path> (ignore_errors=yes|no)`
 * line per entry (src/systemctl/systemctl-show.c, `"%s (ignore_errors=%s)"`;
 * checked on systemd 255), in the order it reads them, and nothing for an
 * empty list; `LoadState=not-found` for a unit it does not know. Any other
 * line, a missing LoadState, or a control character is `unparsable`. Pure.
 */
export function parseUnitEnvironmentFiles(stdout: string): UnitEnvironmentFiles {
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x09\x0b-\x1f\x7f]/.test(stdout)) return { kind: 'unparsable' };
  let loadState: string | null = null;
  const files: UnitEnvironmentFile[] = [];
  for (const line of stdout.split('\n')) {
    if (line === '') continue;
    const load = line.match(/^LoadState=([a-z-]+)$/);
    if (load) {
      if (loadState !== null) return { kind: 'unparsable' };
      loadState = load[1];
      continue;
    }
    const entry = line.match(/^EnvironmentFiles=(.+) \(ignore_errors=(yes|no)\)$/);
    if (!entry) return { kind: 'unparsable' };
    files.push({ path: entry[1], optional: entry[2] === 'yes' });
  }
  if (loadState === null) return { kind: 'unparsable' };
  // not-found, masked, bad-setting, error…: systemd cannot start the unit from
  // what it has, so it names no environment the gateway was started with.
  if (loadState !== 'loaded') return { kind: 'unknown' };
  if (files.length > MAX_UNIT_ENV_FILES) return { kind: 'unparsable' };
  return { kind: 'files', files };
}

/** What systemd says the gateway unit loads, asked once through `run`. */
function unitEnvironmentFiles(run: SystemctlRunner | null, env: NodeJS.ProcessEnv): UnitEnvironmentFiles {
  if (!run) return { kind: 'unknown' };
  let r: ReturnType<SystemctlRunner>;
  try {
    r = run(SYSTEMCTL_SHOW_ARGS, systemctlChildEnv(env));
  } catch {
    return { kind: 'unknown' };
  }
  // No answer, or a failed one (no user bus: "Failed to connect to bus"):
  // there is no manager to ask. An unknown unit is exit 0 + not-found.
  if (!r || r.status !== 0) return { kind: 'unknown' };
  return parseUnitEnvironmentFiles(r.stdout);
}

/** A path segment safe to show as part of `~/.openclaw/…`: it came from systemctl, so only a plain name is echoed. */
const DISPLAY_SEGMENT = /^[A-Za-z0-9._@+-]{1,64}$/;

/** `~/.openclaw/<segments>` when every segment is plain, else `fallback`. */
function displayUnder(segments: readonly string[], fallback: string): string {
  return segments.every((s) => DISPLAY_SEGMENT.test(s)) ? `~/.openclaw/${segments.join('/')}` : fallback;
}

/** One listed file, checked to lie inside `~/.openclaw`: its segments below it, and its display name. */
interface PlannedEnvFile {
  segments: string[];
  display: string;
  optional: boolean;
}

/**
 * A listed EnvironmentFile as segments below `~/.openclaw`, or why the whole
 * resolution is refused. The listed text must be absolute, have no wildcard
 * (systemd globs it; this does not), start with `<home>/.openclaw/`, and have
 * no empty, `.` or `..` segment below it. Reasons never quote the listed path.
 */
function planEnvFile(stateDirPath: string, f: UnitEnvironmentFile): PlannedEnvFile | { reason: string } {
  const listed = `the gateway unit (${GATEWAY_UNIT}) lists an EnvironmentFile`;
  if (!path.isAbsolute(f.path)) return { reason: `${listed} that is not an absolute path, so no boot env was read` };
  if (/[*?[\\]/.test(f.path)) return { reason: `${listed} with a wildcard or backslash, which is not read here, so no boot env was read` };
  const prefix = `${stateDirPath}/`;
  if (!f.path.startsWith(prefix)) return { reason: `${listed} outside ~/.openclaw, which is not read here, so no boot env was read` };
  const segments = f.path.slice(prefix.length).split('/');
  if (segments.some((s) => s === '' || s === '.' || s === '..')) {
    return { reason: `${listed} under ~/.openclaw with an empty, "." or ".." path segment, so no boot env was read` };
  }
  return { segments, display: displayUnder(segments, 'an EnvironmentFile under ~/.openclaw'), optional: f.optional };
}

/**
 * A planned file's text, reached from the checked `~/.openclaw` one component
 * at a time: each directory on the way opened through its parent's descriptor
 * with O_DIRECTORY|O_NOFOLLOW and given the state dir's checks (a directory,
 * the user's own, not writable by group or others), the file itself given
 * the boot env checks. A missing file or directory is `missing`.
 */
function readPlannedEnvFile(dir: StateDir, plan: PlannedEnvFile, euid: number, flags: { dir: number; file: number }): EnvFileRead {
  const opened: number[] = [];
  const notRead = `so ${plan.display} was not read`;
  try {
    let cur = dir;
    for (let i = 0; i < plan.segments.length - 1; i++) {
      const seg = plan.segments[i];
      const sub = displayUnder(plan.segments.slice(0, i + 1), 'a directory under ~/.openclaw');
      let fd: number;
      try {
        fd = openInDir(cur, seg, flags.dir);
      } catch (err) {
        const code = errCode(err);
        if (code === DIR_CHANGED) return { reason: '~/.openclaw changed while it was being read' };
        if (code === 'ENOENT') return { missing: true };
        if (code === 'ELOOP') return { reason: `${sub} is a symbolic link, ${notRead}` };
        if (code === 'ENOTDIR') {
          // Linux reports a link opened O_DIRECTORY|O_NOFOLLOW as ENOTDIR;
          // looked at (not followed) only to name it. Refused either way.
          let link = false;
          try {
            link = fs.lstatSync(inDirPath(cur, seg)).isSymbolicLink();
          } catch {
            link = false;
          }
          return { reason: `${sub} ${link ? 'is a symbolic link' : 'is not a directory'}, ${notRead}` };
        }
        return { reason: `${sub} could not be opened (${code}), ${notRead}` };
      }
      opened.push(fd);
      let st: fs.BigIntStats;
      try {
        st = fs.fstatSync(fd, { bigint: true });
      } catch (err) {
        return { reason: `${sub} could not be read (${errCode(err)}), ${notRead}` };
      }
      if (!st.isDirectory()) return { reason: `${sub} is not a directory, ${notRead}` };
      const problem = ownerProblem(st, euid);
      if (problem) return { reason: `${sub} ${problem}, ${notRead}` };
      cur = { fd, dev: st.dev, ino: st.ino, path: path.join(cur.path, seg), parent: cur };
    }
    return readOwnedEnvFile(cur, plan.segments[plan.segments.length - 1], plan.display, euid, flags);
  } finally {
    for (const fd of opened) {
      try { fs.closeSync(fd); } catch { /* already closed */ }
    }
  }
}

/**
 * The credential keys the gateway unit's EnvironmentFiles give it, read as
 * systemd reads them: every listed file in order, later over earlier, per
 * key. Every path is checked before any file is read; any refusal is the
 * whole resolution's. A key whose LAST setting is one this does not take is
 * not used — not even an earlier file's value for it, which the gateway does
 * not have.
 */
function credentialsFromUnitFiles(
  dir: StateDir,
  files: UnitEnvironmentFile[],
  euid: number,
  flags: { dir: number; file: number },
): GatewayBootCredentials {
  const plans: PlannedEnvFile[] = [];
  for (const f of files) {
    const plan = planEnvFile(dir.path, f);
    if ('reason' in plan) return { used: false, reason: plan.reason };
    plans.push(plan);
  }
  const lists = `the EnvironmentFiles systemd lists for ${GATEWAY_UNIT}`;
  const state: Partial<Record<GatewayCredentialKey, { entry: GatewayKeyEntry; display: string }>> = {};
  const read: string[] = [];
  for (const plan of plans) {
    const got = readPlannedEnvFile(dir, plan, euid, flags);
    if ('missing' in got) {
      if (plan.optional) continue;
      return {
        used: false,
        reason: `${plan.display} is a required EnvironmentFile of ${GATEWAY_UNIT} (no "-") but does not exist, so the gateway's environment is not known and no boot env was used`,
      };
    }
    if ('reason' in got) return { used: false, reason: `${got.reason} (one of ${lists}), so no boot env was used` };
    read.push(plan.display);
    const entries = parseGatewayBootEnvEntries(got.text);
    for (const k of GATEWAY_CREDENTIAL_KEYS) {
      const entry = entries[k];
      if (entry) state[k] = { entry, display: plan.display };
    }
  }
  const env: GatewayCredentials = {};
  const from: string[] = [];
  const unusable: string[] = [];
  for (const k of GATEWAY_CREDENTIAL_KEYS) {
    const s = state[k];
    if (!s) continue;
    if (s.entry.kind === 'value') {
      env[k] = s.entry.value;
      if (!from.includes(s.display)) from.push(s.display);
    } else {
      unusable.push(`${k} (in ${s.display})`);
    }
  }
  const keys = GATEWAY_CREDENTIAL_KEYS.filter((k) => env[k] !== undefined);
  if (keys.length > 0) return { used: true, env, keys, from };
  if (unusable.length > 0) {
    return {
      used: false,
      reason: unusable.length === 1
        ? `the last setting of ${unusable[0]} in ${lists} is not a plain line, so no earlier value was used`
        : `the last settings of ${unusable.join(' and ')} in ${lists} are not plain lines, so no earlier value was used`,
    };
  }
  if (read.length === 0) return { used: false, reason: `none of ${lists} exists (all are optional)` };
  return {
    used: false,
    reason: `${read.join(', ')} (${lists}) ${read.length === 1 ? 'has' : 'have'} no plain OPENCLAW_GATEWAY_TOKEN or OPENCLAW_GATEWAY_PASSWORD line`,
  };
}

/**
 * The local gateway's boot credential for ONE install child that OpenClaw
 * refused for an unresolvable gateway secret reference, or why there is none.
 *
 * `refusedPath` is the config path OpenClaw's refusal named. `geteuid` is a
 * parameter only so a test can stand in for a file owned by someone else;
 * `systemctl` only so a test can stand in for a host's systemd (null: there
 * is none). The reason strings never contain a credential value or an
 * absolute path.
 */
export function resolveGatewayBootCredentials(params: {
  home: string;
  refusedPath: string | null;
  env?: NodeJS.ProcessEnv;
  geteuid?: () => number;
  systemctl?: SystemctlRunner | null;
}): GatewayBootCredentials {
  const env = params.env ?? process.env;
  if (GATEWAY_CREDENTIAL_KEYS.some((k) => env[k]?.trim())) {
    return { used: false, reason: 'OPENCLAW_GATEWAY_TOKEN or OPENCLAW_GATEWAY_PASSWORD is already set here, so the boot env was not read' };
  }
  if (!params.refusedPath || !LOCAL_AUTH_PATHS.has(params.refusedPath)) {
    return { used: false, reason: 'the refusal did not name the local gateway\'s own gateway.auth.token or gateway.auth.password' };
  }
  const exposure = childEnvExposure(env);
  if (exposure) return { used: false, reason: `${exposure}, so ${GATEWAY_BOOT_ENV_DISPLAY} was not read` };
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
    // Every refusal above has run; only now is systemd asked which files the
    // gateway unit loads, and only then is any of them read.
    const run = params.systemctl !== undefined ? params.systemctl : hostSystemctl(params.home);
    const unit = unitEnvironmentFiles(run, env);
    if (unit.kind === 'unparsable') {
      return { used: false, reason: `systemctl's answer about ${GATEWAY_UNIT}'s EnvironmentFiles was not understood, so no boot env was read` };
    }
    if (unit.kind === 'files' && unit.files.length > 0) return credentialsFromUnitFiles(opened.dir, unit.files, euid, flags);
    // No systemd answer (not Linux, no systemctl, no user manager, the unit
    // unknown or listing no file): read the fixed file only, exactly as
    // before. Safe because nothing about that read depends on systemd — it is
    // the file OpenClaw itself writes for the unit, under the checked
    // directory, with every check above — and its keys still go only to the
    // one retry child for a confirmed local gateway. At worst the value is
    // not the gateway's current one and the retry fails as it did before.
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
