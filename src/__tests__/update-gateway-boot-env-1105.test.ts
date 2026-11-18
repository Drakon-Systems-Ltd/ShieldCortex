import {
  chmodSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { parsePluginListEntry, stepOpenClawPlugin, updateVerdict } from '../cli/update.js';
import { buildUpdateSummary, renderUpdateSummary, type UpdateSummaryInput } from '../cli/update-summary.js';
import { NO_STYLE } from '../cli/term-ui.js';
import {
  GATEWAY_BOOT_ENV_DISPLAY,
  parseGatewayBootEnv,
  redactGatewayCredentials,
  resolveGatewayBootCredentials,
} from '../integrations/openclaw-gateway-boot-env.js';
import type { CapturedError } from '../integrations/child-output.js';

/**
 * #1105 — `shieldcortex update` on a host whose `gateway.auth.token` is a
 * secret reference only the operator's interactive shell resolves.
 *
 *  1. OpenClaw refuses the install child (no OPENCLAW_GATEWAY_TOKEN/PASSWORD,
 *     reference unresolvable). The one retry now carries the local gateway's
 *     own boot credential from `~/.openclaw/gateway.systemd.env` — the file
 *     OpenClaw writes as the gateway unit's EnvironmentFile — in that child's
 *     env only, after fixed-path, owner, mode and local-gateway checks
 *     (r2: no symlinked `~/.openclaw`, the gateway mode as OpenClaw would
 *     resolve it, no Node spawn diagnostics), and nothing that child says is
 *     shown.
 *  2. When the install is still refused, OpenClaw's own plugin list is read
 *     before the closing screen: a previous version still listed and enabled
 *     is "plugin not updated (still on X)" — installed and listed, never
 *     "running" — and a check that proved the plugin absent stays red.
 *
 * r3 (CASE B1): the install child loads `~/.openclaw/.env` and
 * `~/.config/openclaw/gateway.env` into its own environment at startup, so a
 * gateway URL, port or location override in either refuses the borrow too.
 *
 * The directory-swap race and missing open flags are pinned in
 * update-gateway-boot-env-1105-fs.test.ts, which replaces `fs` for the module.
 */

const CLI = '5.20.1';
const BEFORE = '5.20.0';
const FORCE_INSTALL = 'openclaw plugins install --force @drakon-systems/shieldcortex-realtime@latest';
const INSTALL_ARGS = FORCE_INSTALL.split(' ').slice(1);
/** OpenClaw 2026.11.4's exact refusal (dist/credentials-*.mjs, `GatewaySecretRefUnavailableError`). */
const SECRET_REF_STDERR = [
  'gateway.auth.token is configured as a secret reference but is unavailable in this command path.',
  'Fix: set OPENCLAW_GATEWAY_TOKEN/OPENCLAW_GATEWAY_PASSWORD, pass explicit --token/--password,',
  'or run a gateway command path that resolves secret references before credential selection.',
].join('\n');
/** Deliberately low-entropy and not credential-shaped: only #1105's own redaction can catch it. */
const TOKEN = 'plain-words-gateway-token';
const PASSWORD = 'plain-words-gateway-password';

/** Every env name that changes what the boot env is, or whether it is read. */
const ENV_KEYS = [
  'OPENCLAW_GATEWAY_TOKEN',
  'OPENCLAW_GATEWAY_PASSWORD',
  'OPENCLAW_GATEWAY_URL',
  'OPENCLAW_STATE_DIR',
  'OPENCLAW_HOME',
  'OPENCLAW_PROFILE',
  'OPENCLAW_CONFIG_PATH',
  'CLAWDBOT_STATE_DIR',
  'CLAWDBOT_CONFIG_PATH',
  'CLAWDBOT_GATEWAY_URL',
  'OPENCLAW_GATEWAY_PORT',
  'NODE_DEBUG',
  'NODE_DEBUG_NATIVE',
  'NODE_OPTIONS',
] as const;

let home: string;
let saved: Record<string, string | undefined>;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'sc-1105-home-'));
  const oc = join(home, '.openclaw');
  mkdirSync(join(oc, 'plugins'), { recursive: true });
  // Explicit modes: the runner's umask must not decide whether the checks pass.
  chmodSync(oc, 0o700);
  writeFileSync(join(oc, 'plugins', 'installs.json'), JSON.stringify({ installRecords: { 'shieldcortex-realtime': {} } }));
  // The reporter's host: local gateway, token is a secret reference.
  writeConfig('local');
  saved = {};
  for (const k of ENV_KEYS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
});

afterEach(() => {
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
  rmSync(home, { recursive: true, force: true });
});

function writeConfig(mode: 'local' | 'remote' | null) {
  writeRawConfig({
    gateway: {
      ...(mode ? { mode } : {}),
      auth: { mode: 'token', token: { source: 'exec', provider: 'vault', id: 'gateway/token' } },
    },
  });
}

/** openclaw.json exactly as given (an object is serialized; a string is written verbatim). */
function writeRawConfig(body: unknown) {
  writeFileSync(join(home, '.openclaw', 'openclaw.json'), typeof body === 'string' ? body : JSON.stringify(body));
}

const bootEnvPath = () => join(home, '.openclaw', 'gateway.systemd.env');
/** The two dotenv files OpenClaw 2026.11.4 loads into a CLI child's env at startup (dist/dotenv-global-*.mjs). */
const stateDotEnvPath = () => join(home, '.openclaw', '.env');
const gatewayDotEnvPath = () => join(home, '.config', 'openclaw', 'gateway.env');

/** A dotenv file as an operator would leave it: theirs, mode 0600 (explicit, so the umask cannot decide). */
function writeDotEnv(file: string, body: string | Buffer, mode = 0o600) {
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, body);
  chmodSync(file, mode);
}

/** The boot env as OpenClaw writes it: serialized entries, mode 0600. */
function writeBootEnv(body: string | Buffer, mode = 0o600) {
  writeFileSync(bootEnvPath(), body);
  chmodSync(bootEnvPath(), mode);
}

function resolve(over: Partial<Parameters<typeof resolveGatewayBootCredentials>[0]> = {}) {
  return resolveGatewayBootCredentials({ home, refusedPath: 'gateway.auth.token', env: process.env, ...over });
}

/** Every file under `dir`, recursively (symlinks not followed). */
function filesUnder(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...filesUnder(p));
    else if (e.isFile()) out.push(p);
  }
  return out;
}

/** Capture everything written to stdout/stderr while `fn` runs. */
async function captureOutput<T>(fn: () => Promise<T>): Promise<{ value: T; out: string }> {
  const chunks: string[] = [];
  const o = process.stdout.write.bind(process.stdout);
  const e = process.stderr.write.bind(process.stderr);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (process.stdout as any).write = (c: any) => { chunks.push(String(c)); return true; };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (process.stderr as any).write = (c: any) => { chunks.push(String(c)); return true; };
  try {
    return { value: await fn(), out: chunks.join('') };
  } finally {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (process.stdout as any).write = o;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (process.stderr as any).write = e;
  }
}

describe('#1105 — parsing the gateway boot env (KEY=VALUE only, never run)', () => {
  it('reads both credential keys in the forms OpenClaw\'s serializer writes', () => {
    // serializeSystemdEnvironmentFileValue: bare when nothing needs quoting,
    // else double quotes with \\ \" \` \$ escapes.
    const body = [
      '# generated',
      `OPENCLAW_GATEWAY_TOKEN=${TOKEN}`,
      'OPENCLAW_GATEWAY_PASSWORD="a b\\"c\\$d\\`e\\\\f"',
    ].join('\n');
    expect(parseGatewayBootEnv(body)).toEqual({
      OPENCLAW_GATEWAY_TOKEN: TOKEN,
      OPENCLAW_GATEWAY_PASSWORD: 'a b"c$d`e\\f',
    });
  });

  it('accepts comments, blank lines and CRLF endings', () => {
    const body = ['; note', '', `OPENCLAW_GATEWAY_TOKEN=${TOKEN}\r`, '# end\r'].join('\n');
    expect(parseGatewayBootEnv(body)).toEqual({ OPENCLAW_GATEWAY_TOKEN: TOKEN });
  });

  it('takes nothing but the two credential keys — every other assignment is ignored', () => {
    const body = [
      'NODE_OPTIONS=--require=/tmp/evil.js',
      'PATH=/tmp/evil',
      'LD_PRELOAD=/tmp/evil.so',
      'OPENCLAW_GATEWAY_URL=wss://elsewhere.example',
      'export OPENCLAW_GATEWAY_TOKEN=exported',
      'openclaw_gateway_token=lowercase',
    ].join('\n');
    expect(parseGatewayBootEnv(body)).toEqual({});
  });

  it.each([
    ['a shell variable', '$OTHER_TOKEN'],
    ['a braced variable', '${OTHER_TOKEN}'],
    ['a command substitution', '$(cat /etc/passwd)'],
    ['a backtick substitution', '`id`'],
    ['an unescaped $ inside double quotes', '"pre$OTHER"'],
    ['an unknown escape', '"a\\nb"'],
    ['unbalanced double quotes', '"abc'],
    ['an unescaped inner double quote', '"ab"cd"'],
    ['unbalanced single quotes', "'abc"],
    // #1105 r2 (nit): OpenClaw's serializer never writes single quotes, so a
    // single-quoted value did not come from it.
    ['a single-quoted value', "'two words'"],
    ['a single-quoted value with no space', "'tok'"],
    ['inner whitespace in a bare value', 'two words'],
    ['a trailing comment', 'tok # comment'],
    ['a bare backslash', 'to\\k'],
    ['an empty value', ''],
    ['an empty quoted value', '""'],
    ['a control character', '"a\tb"'],
  ])('refuses %s rather than guess what the gateway got', (_label, raw) => {
    expect(parseGatewayBootEnv(`OPENCLAW_GATEWAY_TOKEN=${raw}`)).toEqual({});
  });

  it('the last line for a key wins, as in systemd — and an undecodable last line drops the key', () => {
    expect(parseGatewayBootEnv('OPENCLAW_GATEWAY_TOKEN=first\nOPENCLAW_GATEWAY_TOKEN=second')).toEqual({ OPENCLAW_GATEWAY_TOKEN: 'second' });
    expect(parseGatewayBootEnv('OPENCLAW_GATEWAY_TOKEN=first\nOPENCLAW_GATEWAY_TOKEN=$LATER')).toEqual({});
  });

  // #1105 r3 (CASE nit 1): systemd's EnvironmentFile parser
  // (src/basic/env-file.c) joins a backslash-newline onto the value, and a
  // quoted value runs on across lines — OpenClaw's serializer double-quotes a
  // value with a newline in it. A line inside another entry is not a key.
  it.each([
    ['a backslash continuation of another value', 'FOO=bar\\\nOPENCLAW_GATEWAY_TOKEN=inside-foo'],
    ['a continuation after a value with spaces before the backslash', 'FOO=bar \\\nOPENCLAW_GATEWAY_TOKEN=inside-foo'],
    ['a continuation that is a \\r line end', 'FOO=bar\\\rOPENCLAW_GATEWAY_TOKEN=inside-foo'],
    ['a double-quoted value spanning lines (as OpenClaw writes a value with a newline)', 'CERT="line one\nOPENCLAW_GATEWAY_TOKEN=inside-cert\nline three"'],
    ['a single-quoted value spanning lines', "FOO='a\nOPENCLAW_GATEWAY_TOKEN=inside-foo\n'"],
    ['a backslash-newline inside double quotes', 'FOO="a\\\nOPENCLAW_GATEWAY_TOKEN=inside-foo\nrest"'],
    ['an unterminated quote running to the end of the file', 'FOO="a\nOPENCLAW_GATEWAY_TOKEN=inside-foo\n'],
  ])('a credential line inside %s is not a credential', (_label, body) => {
    expect(parseGatewayBootEnv(body)).toEqual({});
  });

  it('a credential entry that runs past its own line is dropped, not cut short or joined', () => {
    // systemd would give "abcdef" and "abc\ndef"; neither is a form OpenClaw
    // writes, and the raw text keeps the line break decodeValue refuses.
    expect(parseGatewayBootEnv('OPENCLAW_GATEWAY_TOKEN=abc\\\ndef')).toEqual({});
    expect(parseGatewayBootEnv('OPENCLAW_GATEWAY_TOKEN="abc\ndef"')).toEqual({});
    expect(parseGatewayBootEnv('OPENCLAW_GATEWAY_TOKEN=first\nOPENCLAW_GATEWAY_TOKEN="abc\ndef"')).toEqual({});
  });

  it('a real credential line after a multi-line entry closes is read', () => {
    expect(parseGatewayBootEnv(`CERT="line one\nline two"\nOPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`)).toEqual({ OPENCLAW_GATEWAY_TOKEN: TOKEN });
    expect(parseGatewayBootEnv(`FOO=a\\\nb\nOPENCLAW_GATEWAY_TOKEN=${TOKEN}`)).toEqual({ OPENCLAW_GATEWAY_TOKEN: TOKEN });
  });

  it('a comment ending in a backslash makes the whole file version-dependent: nothing is used', () => {
    // systemd < v254 continues the comment onto the next line; v254+ does not.
    expect(parseGatewayBootEnv(`# note \\\nOPENCLAW_GATEWAY_TOKEN=${TOKEN}`)).toEqual({});
    expect(parseGatewayBootEnv(`OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n; note \\\nOTHER=1`)).toEqual({});
    // An escaped backslash at the end of a comment is not a continuation.
    expect(parseGatewayBootEnv(`# note \\\\\nOPENCLAW_GATEWAY_TOKEN=${TOKEN}`)).toEqual({ OPENCLAW_GATEWAY_TOKEN: TOKEN });
  });

  it('a lone \\r ends a line and nothing after a NUL is read, as in systemd', () => {
    expect(parseGatewayBootEnv(`FOO=1\rOPENCLAW_GATEWAY_TOKEN=${TOKEN}`)).toEqual({ OPENCLAW_GATEWAY_TOKEN: TOKEN });
    expect(parseGatewayBootEnv(`OPENCLAW_GATEWAY_TOKEN=${TOKEN}\0\nOPENCLAW_GATEWAY_TOKEN=after-nul`)).toEqual({ OPENCLAW_GATEWAY_TOKEN: TOKEN });
    expect(parseGatewayBootEnv(`FOO=1\0\nOPENCLAW_GATEWAY_TOKEN=${TOKEN}`)).toEqual({});
  });

  it('only spaces and tabs are trimmed: a no-break space or BOM around a value is not dropped silently', () => {
    const nbsp = String.fromCharCode(0xa0);
    const bom = String.fromCharCode(0xfeff);
    expect(parseGatewayBootEnv(`OPENCLAW_GATEWAY_TOKEN=${TOKEN}${nbsp}`)).toEqual({});
    expect(parseGatewayBootEnv(`OPENCLAW_GATEWAY_TOKEN=${bom}${TOKEN}`)).toEqual({});
    expect(parseGatewayBootEnv(`OPENCLAW_GATEWAY_TOKEN= \t${TOKEN} \t`)).toEqual({ OPENCLAW_GATEWAY_TOKEN: TOKEN });
  });
});

describe('#1105 — reading the gateway boot env: fixed path, owner-checked, local gateway only', () => {
  it('a 0600 file the user owns, in a private ~/.openclaw, for a local gateway: both keys', () => {
    writeBootEnv(`OPENCLAW_GATEWAY_TOKEN=${TOKEN}\nOPENCLAW_GATEWAY_PASSWORD=${PASSWORD}\nOTHER=x\n`);
    expect(resolve()).toEqual({
      used: true,
      env: { OPENCLAW_GATEWAY_TOKEN: TOKEN, OPENCLAW_GATEWAY_PASSWORD: PASSWORD },
      keys: ['OPENCLAW_GATEWAY_TOKEN', 'OPENCLAW_GATEWAY_PASSWORD'],
    });
  });

  it('a config with no gateway.mode is a local gateway, as in OpenClaw', () => {
    writeConfig(null);
    writeBootEnv(`OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
    expect(resolve()).toMatchObject({ used: true, keys: ['OPENCLAW_GATEWAY_TOKEN'] });
  });

  it('reading it writes nothing: the file and its directory are unchanged', () => {
    writeBootEnv(`OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
    const before = statSync(bootEnvPath());
    const listing = readdirSync(join(home, '.openclaw')).sort();
    resolve();
    const after = statSync(bootEnvPath());
    expect(after.mtimeMs).toBe(before.mtimeMs);
    expect(after.mode).toBe(before.mode);
    expect(readFileSync(bootEnvPath(), 'utf-8')).toBe(`OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
    expect(readdirSync(join(home, '.openclaw')).sort()).toEqual(listing);
  });

  type Refusal = [string, () => void, RegExp, Partial<Parameters<typeof resolveGatewayBootCredentials>[0]>?];
  const REFUSALS: Refusal[] = [
    ['a gateway credential already in this environment', () => { process.env.OPENCLAW_GATEWAY_PASSWORD = 'operator-set'; }, /already set here/],
    ['a refusal about the remote gateway\'s token', () => {}, /did not name the local gateway/, { refusedPath: 'gateway.remote.token' }],
    ['a refusal that named no path', () => {}, /did not name the local gateway/, { refusedPath: null }],
    ['OPENCLAW_GATEWAY_URL set', () => { process.env.OPENCLAW_GATEWAY_URL = 'wss://elsewhere.example'; }, /OPENCLAW_GATEWAY_URL is set/],
    ['OPENCLAW_STATE_DIR set', () => { process.env.OPENCLAW_STATE_DIR = '/srv/other'; }, /OPENCLAW_STATE_DIR is set/],
    ['OPENCLAW_HOME set', () => { process.env.OPENCLAW_HOME = '/srv/other'; }, /OPENCLAW_HOME is set/],
    ['OPENCLAW_PROFILE set', () => { process.env.OPENCLAW_PROFILE = 'work'; }, /OPENCLAW_PROFILE is set/],
    ['OPENCLAW_CONFIG_PATH set', () => { process.env.OPENCLAW_CONFIG_PATH = '/srv/other.json'; }, /OPENCLAW_CONFIG_PATH is set/],
    ['a remote gateway', () => writeConfig('remote'), /gateway\.mode is remote/],
    ['a config that cannot be read', () => rmSync(join(home, '.openclaw', 'openclaw.json')), /could not be read to confirm a local gateway/],
    ['a config that is not JSON', () => writeFileSync(join(home, '.openclaw', 'openclaw.json'), '{ gateway: '), /is not strict JSON \(JSON5 configs are not read here\)/],
    ['no boot env file', () => rmSync(bootEnvPath()), /there is no ~\/\.openclaw\/gateway\.systemd\.env/],
    ['a group-writable file', () => chmodSync(bootEnvPath(), 0o620), /writable by group or others/],
    ['a world-writable file', () => chmodSync(bootEnvPath(), 0o602), /writable by group or others/],
    ['~/.openclaw and the file owned by someone else', () => {}, /~\/\.openclaw is not owned by the user running update/, { geteuid: () => (process.geteuid?.() ?? 0) + 1 }],
    ['a group-writable ~/.openclaw', () => chmodSync(join(home, '.openclaw'), 0o770), /~\/\.openclaw is writable by group or others/],
    ['a symlink to a private file', () => {
      const elsewhere = join(home, 'elsewhere.env');
      writeFileSync(elsewhere, `OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`, { mode: 0o600 });
      rmSync(bootEnvPath());
      symlinkSync(elsewhere, bootEnvPath());
    }, /is a symbolic link/],
    ['a second hard link', () => linkSync(bootEnvPath(), join(home, '.openclaw', 'second-link.env')), /more than one hard link/],
    ['a directory at the path', () => { rmSync(bootEnvPath()); mkdirSync(bootEnvPath(), { mode: 0o700 }); }, /is not a regular file/],
    ['a file over 64 KiB', () => writeBootEnv(`OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n#${'x'.repeat(64 * 1024)}\n`), /larger than 64 KiB/],
    ['a file with no plain credential line', () => writeBootEnv('OPENCLAW_GATEWAY_TOKEN=$FROM_ELSEWHERE\nOTHER=1\n'), /has no plain OPENCLAW_GATEWAY_TOKEN or OPENCLAW_GATEWAY_PASSWORD line/],

    // #1105 r2 B-dir: `~/.openclaw` itself must not be a link — even to a
    // directory the user owns, mode 0700, holding a valid 0600 boot env.
    ['~/.openclaw as a symlink to a private directory the user owns', () => {
      const real = join(home, 'real-openclaw');
      renameSync(join(home, '.openclaw'), real);
      chmodSync(real, 0o700);
      expect(statSync(join(real, 'gateway.systemd.env')).mode & 0o777).toBe(0o600);
      symlinkSync(real, join(home, '.openclaw'));
    }, /^~\/\.openclaw is a symbolic link$/],

    // #1105 r2 B1: the mode OpenClaw acts on is resolved AFTER $include and
    // ${VAR} substitution, and after the config's env block is applied. None
    // of that is resolved here, so every such form fails closed.
    ['$include at the top level', () => writeRawConfig({ $include: './gateway.json5' }), /uses \$include/],
    ['$include nested under gateway', () => writeRawConfig({ gateway: { $include: './remote.json5' } }), /uses \$include/],
    ['$include inside an array', () => writeRawConfig({ gateway: { mode: 'local' }, agents: [{ $include: './a.json5' }] }), /uses \$include/],
    ['$include spelled with a JSON escape', () => writeRawConfig('{"gateway":{"\\u0024include":"./remote.json5"}}'), /uses \$include/],
    ['${VAR} as gateway.mode', () => writeRawConfig({ gateway: { mode: '${OPENCLAW_MODE}' } }), /uses \$\{…\} substitution/],
    ['${VAR:-remote} as gateway.mode', () => writeRawConfig({ gateway: { mode: '${MODE:-remote}' } }), /uses \$\{…\} substitution/],
    ['${VAR} in any other string', () => writeRawConfig({ gateway: { mode: 'local' }, agents: { list: [{ name: 'a-${HOSTNAME}' }] } }), /uses \$\{…\} substitution/],
    ['${VAR} in a key', () => writeRawConfig({ gateway: { mode: 'local' }, '${KEY}': 1 }), /uses \$\{…\} substitution/],
    ['gateway.mode "Remote" (not exactly "local")', () => writeRawConfig({ gateway: { mode: 'Remote' } }), /gateway\.mode is not exactly "local"/],
    ['gateway.mode " remote " (OpenClaw trims it)', () => writeRawConfig({ gateway: { mode: ' remote ' } }), /gateway\.mode is not exactly "local"/],
    ['gateway.mode null', () => writeRawConfig({ gateway: { mode: null } }), /gateway\.mode is not exactly "local"/],
    ['gateway that is not an object', () => writeRawConfig({ gateway: 'remote' }), /gateway in ~\/\.openclaw\/openclaw\.json is not an object/],
    ['a config that is not a JSON object', () => writeRawConfig('[]'), /is not a JSON object/],
    ['a JSON5 config (strict JSON is all this reader knows)', () => writeRawConfig('{ // remote below?\n "gateway": { "mode": "local" } }'), /is not strict JSON \(JSON5 configs are not read here\)/],
    ['an env block that sets OPENCLAW_GATEWAY_URL', () => writeRawConfig({ gateway: { mode: 'local' }, env: { OPENCLAW_GATEWAY_URL: 'wss://elsewhere.example' } }), /env block .* sets an OPENCLAW_\* or CLAWDBOT_\* variable/],
    ['env.vars that sets OPENCLAW_GATEWAY_URL', () => writeRawConfig({ gateway: { mode: 'local' }, env: { vars: { OPENCLAW_GATEWAY_URL: 'wss://elsewhere.example' } } }), /env block .* sets an OPENCLAW_\* or CLAWDBOT_\* variable/],
    ['env.vars that sets a lower-case clawdbot_ variable', () => writeRawConfig({ env: { vars: { clawdbot_state_dir: '/srv/other' } } }), /env block .* sets an OPENCLAW_\* or CLAWDBOT_\* variable/],
    ['an env block that is not an object', () => writeRawConfig({ env: 'OPENCLAW_GATEWAY_URL=wss://x' }), /env block .* could not be checked/],
    ['a symlinked openclaw.json (to a valid local config)', () => {
      const elsewhere = join(home, 'local-config.json');
      writeFileSync(elsewhere, JSON.stringify({ gateway: { mode: 'local' } }), { mode: 0o600 });
      rmSync(join(home, '.openclaw', 'openclaw.json'));
      symlinkSync(elsewhere, join(home, '.openclaw', 'openclaw.json'));
    }, /openclaw\.json is a symbolic link/],

    // Grok nit: the legacy spellings relocate OpenClaw too — any CLAWDBOT_*.
    ['CLAWDBOT_STATE_DIR set', () => { process.env.CLAWDBOT_STATE_DIR = '/srv/other'; }, /CLAWDBOT_STATE_DIR is set/],
    ['CLAWDBOT_CONFIG_PATH set', () => { process.env.CLAWDBOT_CONFIG_PATH = '/srv/other.json'; }, /CLAWDBOT_CONFIG_PATH is set/],
    ['any other CLAWDBOT_* variable set', () => { process.env.CLAWDBOT_GATEWAY_URL = 'wss://elsewhere.example'; }, /CLAWDBOT_GATEWAY_URL is set/],

    // #1105 r2 B4: Node's child_process debug log prints every spawn's env to
    // this process's stderr. Any non-blank NODE_DEBUG refuses the borrow,
    // whatever it names — and so does NODE_DEBUG_NATIVE.
    ['NODE_DEBUG=child_process', () => { process.env.NODE_DEBUG = 'child_process'; }, /^NODE_DEBUG is set, and Node's diagnostics would print the retry child's environment/],
    ['NODE_DEBUG=CHILD_PROCESS (Node matches sections case-insensitively)', () => { process.env.NODE_DEBUG = 'CHILD_PROCESS'; }, /^NODE_DEBUG is set/],
    ['NODE_DEBUG=* (wildcard)', () => { process.env.NODE_DEBUG = '*'; }, /^NODE_DEBUG is set/],
    ['NODE_DEBUG=child* (prefix wildcard)', () => { process.env.NODE_DEBUG = 'child*'; }, /^NODE_DEBUG is set/],
    ['NODE_DEBUG=net,child_process (a list)', () => { process.env.NODE_DEBUG = 'net,child_process'; }, /^NODE_DEBUG is set/],
    ['NODE_DEBUG=http (any section at all)', () => { process.env.NODE_DEBUG = 'http'; }, /^NODE_DEBUG is set/],
    ['NODE_DEBUG_NATIVE set', () => { process.env.NODE_DEBUG_NATIVE = 'all'; }, /^NODE_DEBUG_NATIVE is set/],

    // #1105 r3 (CASE nit 3): the retry child inherits NODE_OPTIONS, and a
    // diagnostic report, an env trace, an inspector or a heap snapshot can
    // each write its environment out.
    ['NODE_OPTIONS=--report-on-fatalerror', () => { process.env.NODE_OPTIONS = '--report-on-fatalerror'; }, /^NODE_OPTIONS asks for a Node diagnostic, and Node's diagnostics would print the retry child's environment/],
    ['NODE_OPTIONS with --report_on_signal (underscore spelling)', () => { process.env.NODE_OPTIONS = '--max-old-space-size=4096 --report_on_signal'; }, /^NODE_OPTIONS asks for a Node diagnostic/],
    ['NODE_OPTIONS=--trace-env', () => { process.env.NODE_OPTIONS = '--trace-env'; }, /^NODE_OPTIONS asks for a Node diagnostic/],
    ['NODE_OPTIONS=--trace-warnings', () => { process.env.NODE_OPTIONS = '--trace-warnings'; }, /^NODE_OPTIONS asks for a Node diagnostic/],
    ['NODE_OPTIONS=--inspect=0', () => { process.env.NODE_OPTIONS = '--inspect=0'; }, /^NODE_OPTIONS asks for a Node diagnostic/],
    ['NODE_OPTIONS=--heapsnapshot-signal=SIGUSR2', () => { process.env.NODE_OPTIONS = '--heapsnapshot-signal=SIGUSR2'; }, /^NODE_OPTIONS asks for a Node diagnostic/],

    // #1105 r3 (CASE B1): OPENCLAW_GATEWAY_PORT beats the config's port.
    ['OPENCLAW_GATEWAY_PORT set', () => { process.env.OPENCLAW_GATEWAY_PORT = '9'; }, /^OPENCLAW_GATEWAY_PORT is set/],

    // #1105 r3 (CASE B1): the dotenv files OpenClaw loads into the install
    // child's own env at startup — first-wins, no OPENCLAW_* blocklist — are
    // location overrides too. CASE's three live-reproduced rows first.
    ['~/.openclaw/.env sets OPENCLAW_GATEWAY_URL (CASE row 1)', () => writeDotEnv(stateDotEnvPath(), 'OPENCLAW_GATEWAY_URL=wss://remote.example:443\n'),
      /^~\/\.openclaw\/\.env names OPENCLAW_GATEWAY_URL, which OpenClaw loads into the install's own environment/],
    ['~/.config/openclaw/gateway.env sets OPENCLAW_GATEWAY_URL (CASE row 2)', () => writeDotEnv(gatewayDotEnvPath(), 'OPENCLAW_GATEWAY_URL=wss://remote.example:443\n'),
      /^~\/\.config\/openclaw\/gateway\.env names OPENCLAW_GATEWAY_URL/],
    ['~/.openclaw/.env sets OPENCLAW_GATEWAY_PORT (CASE row 3)', () => writeDotEnv(stateDotEnvPath(), 'OPENCLAW_GATEWAY_PORT=9\n'),
      /^~\/\.openclaw\/\.env names OPENCLAW_GATEWAY_PORT/],
    ...([
      ['OPENCLAW_STATE_DIR', 'OPENCLAW_STATE_DIR=/srv/other\n'],
      ['OPENCLAW_HOME', 'OPENCLAW_HOME=/srv/other\n'],
      ['OPENCLAW_PROFILE', 'OPENCLAW_PROFILE=work\n'],
      ['OPENCLAW_CONFIG_PATH', 'OPENCLAW_CONFIG_PATH=/srv/other.json\n'],
      ['OPENCLAW_GATEWAY_URL', 'export OPENCLAW_GATEWAY_URL=wss://remote.example\n'],
      ['OPENCLAW_GATEWAY_URL', 'OPENCLAW_GATEWAY_URL: wss://remote.example\n'],
      ['OPENCLAW_GATEWAY_URL', 'A=1\rOPENCLAW_GATEWAY_URL=wss://remote.example\n'],
      ['OPENCLAW_GATEWAY_URL', '# OPENCLAW_GATEWAY_URL=wss://remote.example (any mention counts)\n'],
      ['OPENCLAW_GATEWAY_PORT', 'openclaw_gateway_port=9\n'],
      ['a CLAWDBOT_\\* variable', 'CLAWDBOT_STATE_DIR=/srv/other\n'],
    ] as const).flatMap(([name, body]): Refusal[] => [
      [`~/.openclaw/.env: ${JSON.stringify(body)}`, () => writeDotEnv(stateDotEnvPath(), `OPENROUTER_API_KEY=sk-or-x\n${body}`),
        new RegExp(`^~/\\.openclaw/\\.env names ${name}`)],
      [`~/.config/openclaw/gateway.env: ${JSON.stringify(body)}`, () => writeDotEnv(gatewayDotEnvPath(), body),
        new RegExp(`^~/\\.config/openclaw/gateway\\.env names ${name}`)],
    ]),
    ['a symlinked ~/.openclaw/.env', () => {
      const elsewhere = join(home, 'elsewhere.env');
      writeFileSync(elsewhere, 'OPENROUTER_API_KEY=x\n', { mode: 0o600 });
      symlinkSync(elsewhere, stateDotEnvPath());
    }, /^~\/\.openclaw\/\.env is a symbolic link, so it could not be ruled out/],
    ['a symlinked ~/.config/openclaw/gateway.env', () => {
      const elsewhere = join(home, 'elsewhere.env');
      writeFileSync(elsewhere, 'OPENROUTER_API_KEY=x\n', { mode: 0o600 });
      mkdirSync(dirname(gatewayDotEnvPath()), { recursive: true });
      symlinkSync(elsewhere, gatewayDotEnvPath());
    }, /^~\/\.config\/openclaw\/gateway\.env is a symbolic link/],
    ['a group-writable ~/.openclaw/.env', () => writeDotEnv(stateDotEnvPath(), 'OPENROUTER_API_KEY=x\n', 0o620),
      /^~\/\.openclaw\/\.env is writable by group or others/],
    ['a world-writable ~/.config/openclaw/gateway.env', () => writeDotEnv(gatewayDotEnvPath(), 'OPENROUTER_API_KEY=x\n', 0o602),
      /^~\/\.config\/openclaw\/gateway\.env is writable by group or others/],
    ['a directory at ~/.openclaw/.env', () => mkdirSync(stateDotEnvPath(), { mode: 0o700 }), /^~\/\.openclaw\/\.env is not a regular file/],
    ['a ~/.openclaw/.env over 1 MiB', () => writeDotEnv(stateDotEnvPath(), `A=${'x'.repeat(1024 * 1024)}\n`), /^~\/\.openclaw\/\.env is larger than 1 MiB/],
    ['a boot env that is not valid UTF-8', () => writeBootEnv(Buffer.concat([Buffer.from(`OPENCLAW_GATEWAY_TOKEN=${TOKEN}\nOTHER=`), Buffer.from([0xff, 0x0a])])),
      /^~\/\.openclaw\/gateway\.systemd\.env is not valid UTF-8$/],
  ];

  it.each(REFUSALS)('not used: %s', (_label, arrange, reason, over = {}) => {
    writeBootEnv(`OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
    arrange();
    const r = resolve(over);
    expect(r.used).toBe(false);
    if (r.used) return;
    expect(r.reason).toMatch(reason);
    // A reason is shown to the operator: never the value, never the absolute home.
    expect(r.reason).not.toContain(TOKEN);
    expect(r.reason).not.toContain(home);
  });

  it('gateway.mode exactly "local", with a $schema key and an unrelated env var: used', () => {
    writeRawConfig({
      $schema: 'https://docs.openclaw.ai/schema/openclaw.json',
      gateway: { mode: 'local', auth: { mode: 'token', token: { source: 'exec', provider: 'vault', id: 'gateway/token' } } },
      env: { vars: { HTTP_PROXY: 'http://proxy.internal:3128' } },
    });
    writeBootEnv(`OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
    expect(resolve()).toMatchObject({ used: true, keys: ['OPENCLAW_GATEWAY_TOKEN'] });
  });

  it('control (#1105 r3): both dotenv files present with unrelated keys — still used', () => {
    writeDotEnv(stateDotEnvPath(), [
      'OPENROUTER_API_KEY=sk-or-unrelated',
      'HTTP_PROXY=http://proxy.internal:3128',
      // Names that merely CONTAIN an override name are other keys.
      'MY_OPENCLAW_GATEWAY_URL=wss://not-read.example',
      'OPENCLAW_GATEWAY_URL_NOTE=not-read',
      '',
    ].join('\n'));
    writeDotEnv(gatewayDotEnvPath(), 'ANTHROPIC_API_KEY=sk-ant-unrelated\n');
    writeBootEnv(`OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
    expect(resolve()).toMatchObject({ used: true, keys: ['OPENCLAW_GATEWAY_TOKEN'] });
  });

  it('control (#1105 r3): a ~/.config that is a file (no gateway.env can exist) — still used', () => {
    writeFileSync(join(home, '.config'), 'not a directory');
    writeBootEnv(`OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
    expect(resolve()).toMatchObject({ used: true });
  });

  it('control (#1105 r3): a NODE_OPTIONS with no diagnostic option — still used', () => {
    process.env.NODE_OPTIONS = '--max-old-space-size=4096 --use-openssl-ca';
    writeBootEnv(`OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
    expect(resolve()).toMatchObject({ used: true });
  });

  it('reading the dotenv files writes nothing and the refusal never quotes them', () => {
    const body = 'OPENROUTER_API_KEY=sk-or-secret-provider-key\nOPENCLAW_GATEWAY_URL=wss://remote.example:443\n';
    writeDotEnv(stateDotEnvPath(), body);
    writeBootEnv(`OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
    const before = statSync(stateDotEnvPath());
    const r = resolve();
    expect(r.used).toBe(false);
    if (r.used) return;
    expect(r.reason).not.toMatch(/sk-or-secret|remote\.example/);
    expect(statSync(stateDotEnvPath()).mtimeMs).toBe(before.mtimeMs);
    expect(readFileSync(stateDotEnvPath(), 'utf-8')).toBe(body);
  });

  it('NODE_DEBUG refuses before anything is read: no ~/.openclaw at all still names NODE_DEBUG', () => {
    rmSync(join(home, '.openclaw'), { recursive: true, force: true });
    process.env.NODE_DEBUG = 'child_process';
    expect(resolve()).toEqual({ used: false, reason: expect.stringMatching(/^NODE_DEBUG is set/) });
  });

  it('a FIFO at the path is refused without blocking the read', () => {
    rmSync(bootEnvPath(), { force: true });
    const made = spawnSync('mkfifo', ['-m', '600', bootEnvPath()]);
    if (made.status !== 0) return; // no mkfifo on this runner: the directory case covers non-regular files
    const r = resolve();
    expect(r).toMatchObject({ used: false, reason: expect.stringMatching(/is not a regular file/) });
  });

  it('redaction replaces every value, longest first', () => {
    const creds = { OPENCLAW_GATEWAY_TOKEN: 'abc', OPENCLAW_GATEWAY_PASSWORD: 'abcdef' };
    expect(redactGatewayCredentials('x abcdef y abc z', creds))
      .toBe('x [redacted:$OPENCLAW_GATEWAY_PASSWORD] y [redacted:$OPENCLAW_GATEWAY_TOKEN] z');
  });
});

describe('#1105 — what `openclaw plugins list --json` says is there', () => {
  const doc = (entry: Record<string, unknown>) => JSON.stringify({ plugins: [{ id: 'shieldcortex-realtime', ...entry }] });
  it.each([
    ['enabled and loaded (OpenClaw 2026.11.4\'s record)', { version: BEFORE, enabled: true, status: 'loaded' }, { version: BEFORE, enabled: true }],
    ['disabled', { version: BEFORE, enabled: false, status: 'disabled' }, { version: BEFORE, enabled: false }],
    ['status only', { version: BEFORE, status: 'loaded' }, { version: BEFORE, enabled: true }],
    ['enabled, but in error', { version: BEFORE, enabled: true, status: 'error' }, { version: BEFORE, enabled: false }],
    ['no enabled state at all', { version: BEFORE }, { version: BEFORE, enabled: null }],
    ['no valid version', { version: 'garbage', enabled: true }, { version: null, enabled: true }],
  ])('%s', (_label, entry, want) => {
    expect(parsePluginListEntry(`[plugins] loading\n${doc(entry)}`)).toEqual(want);
  });
});

describe('#1105 — the update step: SecretRef token, no gateway credential in the environment', () => {
  type Call = { args: string[]; env: NodeJS.ProcessEnv };

  /**
   * A fake `openclaw` that refuses exactly as OpenClaw does while
   * `gateway.auth.token` is a secret reference and the child has neither
   * credential — and records the env every child got.
   */
  function fakeOpenClaw(opts: {
    list?: Record<string, unknown> | null;
    /** What a retry that HAS a credential ends with, instead of installing. */
    credentialedEnding?: Partial<CapturedError>;
    /** OpenClaw's refusal to a child with no credential (default: the token path). */
    refusal?: string;
  } = {}) {
    const calls: Call[] = [];
    let onDisk = BEFORE;
    const run = (_cmd: string, args: string[], o: { env?: NodeJS.ProcessEnv } = {}) => {
      const env = { ...(o.env ?? process.env) };
      calls.push({ args, env });
      if (args[0] === 'plugins' && args[1] === 'list') {
        return opts.list === null
          ? Promise.reject(Object.assign(new Error('exit 1'), { exitCode: 1, stdout: '', stderr: 'no list' }))
          : Promise.resolve({
            stdout: JSON.stringify({ plugins: [{ id: 'shieldcortex-realtime', version: onDisk, ...(opts.list ?? {}) }] }),
            stderr: '',
          });
      }
      const hasCredential = Boolean(env.OPENCLAW_GATEWAY_TOKEN || env.OPENCLAW_GATEWAY_PASSWORD);
      if (!hasCredential) {
        return Promise.reject(Object.assign(new Error('exit 1: openclaw plugins install'), {
          exitCode: 1, command: FORCE_INSTALL, stdout: '', stderr: opts.refusal ?? SECRET_REF_STDERR,
        }) as CapturedError);
      }
      if (opts.credentialedEnding) {
        return Promise.reject(Object.assign(new Error('exit 1: openclaw plugins install'), {
          exitCode: 1, command: FORCE_INSTALL, stdout: '', stderr: '', ...opts.credentialedEnding,
        }) as CapturedError);
      }
      onDisk = CLI;
      return Promise.resolve({ stdout: 'Installed shieldcortex-realtime', stderr: '' });
    };
    return { run: run as never, calls, readPluginVersion: () => onDisk };
  }

  function step(f: ReturnType<typeof fakeOpenClaw>) {
    return captureOutput(() => stepOpenClawPlugin(home, {
      run: f.run,
      readPluginVersion: f.readPluginVersion,
      readCliVersion: () => CLI,
    }));
  }

  const installs = (f: ReturnType<typeof fakeOpenClaw>) => f.calls.filter((c) => c.args[1] === 'install');

  it('the boot-env fallback lands the install — the credential reaches the retry child and nothing else', async () => {
    writeBootEnv(`OPENCLAW_SERVICE_KIND=gateway\nOPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
    const bootBefore = statSync(bootEnvPath());
    const f = fakeOpenClaw();
    const { value: r, out } = await step(f);

    expect(r.status).toBe('ok');
    expect(r.summary).toBe(`${BEFORE} → ${CLI}`);
    expect(r.unfinished).toBeUndefined();
    expect(r.recovery).toBeUndefined();
    expect(r.detail?.[0]).toBe(
      `first install refused: gateway.auth.token is a gateway secret reference OpenClaw could not resolve for it; retried \`openclaw plugins install --force\` once with OPENCLAW_GATEWAY_TOKEN from the local gateway's boot env (${GATEWAY_BOOT_ENV_DISPLAY}), passed only to that child`,
    );

    // Same command both times; only the retry's env carries the credential,
    // and only the two credential keys were taken from the file.
    expect(installs(f).map((c) => c.args)).toEqual([INSTALL_ARGS, INSTALL_ARGS]);
    const [first, retry] = installs(f);
    expect(first.env.OPENCLAW_GATEWAY_TOKEN).toBeUndefined();
    expect(retry.env.OPENCLAW_GATEWAY_TOKEN).toBe(TOKEN);
    expect(retry.env.OPENCLAW_SERVICE_KIND).toBe(first.env.OPENCLAW_SERVICE_KIND);
    const { OPENCLAW_GATEWAY_TOKEN: _t, ...retryRest } = retry.env;
    expect(retryRest).toEqual(first.env);
    for (const c of f.calls) {
      expect(c.args).not.toContain('--token');
      expect(c.args.join(' ')).not.toContain(TOKEN);
    }

    // Never logged or printed, never in this process's env, never written.
    expect(out).not.toContain(TOKEN);
    expect(JSON.stringify(r)).not.toContain(TOKEN);
    expect(process.env.OPENCLAW_GATEWAY_TOKEN).toBeUndefined();
    const bootAfter = statSync(bootEnvPath());
    expect(bootAfter.mtimeMs).toBe(bootBefore.mtimeMs);
    for (const file of filesUnder(home)) {
      if (file === bootEnvPath()) continue;
      expect(readFileSync(file, 'utf-8')).not.toContain(TOKEN);
    }
  });

  it('a password-only boot env passes only the password', async () => {
    writeBootEnv(`OPENCLAW_GATEWAY_PASSWORD="${PASSWORD}"\n`);
    const f = fakeOpenClaw();
    const { value: r } = await step(f);

    expect(r.status).toBe('ok');
    const [first, retry] = installs(f);
    expect(first.env.OPENCLAW_GATEWAY_PASSWORD).toBeUndefined();
    expect(retry.env.OPENCLAW_GATEWAY_PASSWORD).toBe(PASSWORD);
    expect(retry.env.OPENCLAW_GATEWAY_TOKEN).toBeUndefined();
    expect(r.detail?.[0]).toContain('once with OPENCLAW_GATEWAY_PASSWORD from the local gateway\'s boot env');
  });

  it('a password-path refusal is named as gateway.auth.password, and the retry carries only the password', async () => {
    writeBootEnv(`OPENCLAW_GATEWAY_PASSWORD=${PASSWORD}\n`);
    const f = fakeOpenClaw({ refusal: SECRET_REF_STDERR.replace('gateway.auth.token', 'gateway.auth.password') });
    const { value: r, out } = await step(f);

    expect(r.status).toBe('ok');
    const [first, retry] = installs(f);
    expect(first.env.OPENCLAW_GATEWAY_PASSWORD).toBeUndefined();
    expect(retry.env.OPENCLAW_GATEWAY_PASSWORD).toBe(PASSWORD);
    expect(retry.env.OPENCLAW_GATEWAY_TOKEN).toBeUndefined();
    expect(r.detail?.[0]).toMatch(/^first install refused: gateway\.auth\.password is a gateway secret reference/);
    expect(out).not.toContain(PASSWORD);
  });

  it('a password-path refusal that is refused twice names gateway.auth.password, not "a gateway config value"', async () => {
    const f = fakeOpenClaw({ refusal: SECRET_REF_STDERR.replace('gateway.auth.token', 'gateway.auth.password') });
    const { value: r } = await step(f);
    expect(r.summary).toMatch(/OpenClaw refused twice: gateway\.auth\.password is a gateway secret reference/);
    expect(r.detail?.[0]).toMatch(/^first install refused: gateway\.auth\.password is/);
  });

  describe('#1105 r2 B3 — a credentialed retry is reported in fixed words, never in what the child said', () => {
    /**
     * A value OpenClaw's serializer would write double-quoted (inner quote,
     * backslash, surrounding spaces), and every way a child could echo it that
     * an exact-value scrub misses.
     */
    const RAW = '  q"uo\\te-s3cr3t-Vx7  ';
    const LINE = 'OPENCLAW_GATEWAY_TOKEN="  q\\"uo\\\\te-s3cr3t-Vx7  "';
    const ECHOES = {
      json: JSON.stringify(RAW),
      jsonTrimmed: JSON.stringify(RAW.trim()),
      trimmed: RAW.trim(),
      partial: 's3cr3t-Vx7',
      percent: encodeURIComponent(RAW.trim()),
      base64: Buffer.from(RAW.trim()).toString('base64'),
      shellQuoted: `'${RAW.trim().replace(/'/g, "'\\''")}'`,
    };
    /** Fragments no output may contain, whichever echo they came from. */
    const FRAGMENTS = ['s3cr3t', 'Vx7', 'uo\\te', 'uo\\\\te', 'q\\"uo', ECHOES.percent, ECHOES.base64, 'rejected token', 'child-said'];

    function assertNothingFromTheChild(r: unknown, out: string) {
      const shown = JSON.stringify(r);
      for (const frag of FRAGMENTS) {
        expect(out).not.toContain(frag);
        expect(shown).not.toContain(frag);
      }
    }

    it('the boot env line decodes to the raw value the child is given', () => {
      expect(parseGatewayBootEnv(LINE)).toEqual({ OPENCLAW_GATEWAY_TOKEN: RAW });
    });

    it('quoted, JSON-escaped, trimmed, partial, encoded and split echoes never reach any output', async () => {
      writeBootEnv(`${LINE}\n`);
      const f = fakeOpenClaw({
        list: { enabled: true, status: 'loaded' },
        credentialedEnding: {
          exitCode: 1,
          // One half of the trimmed value on each stream, and every echo whole.
          stdout: [`child-said token=${ECHOES.trimmed.slice(0, 7)}`, ...Object.values(ECHOES)].join('\n'),
          stderr: [`Error: gateway rejected token ${ECHOES.json}`, ECHOES.trimmed.slice(7), `{"token":${ECHOES.jsonTrimmed}}`, `auth=${ECHOES.shellQuoted}`].join('\n'),
          message: `exit 1: gateway rejected token ${ECHOES.trimmed}`,
        },
      });
      const { value: r, out } = await step(f);

      expect(installs(f)[1].env.OPENCLAW_GATEWAY_TOKEN).toBe(RAW);
      expect(r.status).toBe('warn');
      expect(r.unfinished).toBe(true);
      expect(r.summary).toMatch(/^update failed — openclaw plugins install exited 1 \(its output is withheld: this retry carried the gateway credential\)/);
      expect(r.rerun).toBe(FORCE_INSTALL);
      assertNothingFromTheChild(r, out);
    });

    it('a child that timed out: the timeout, and nothing it said', async () => {
      writeBootEnv(`${LINE}\n`);
      const f = fakeOpenClaw({
        credentialedEnding: { exitCode: null, timedOut: true, stdout: `child-said ${ECHOES.trimmed}`, stderr: ECHOES.json },
      });
      const { value: r, out } = await step(f);
      expect(r.status).toBe('warn');
      expect((r.detail ?? []).join('\n')).not.toContain('child-said');
      assertNothingFromTheChild(r, out);
    });

    it('a credentialed child refused for the reference again: the refused-twice message, in fixed words', async () => {
      writeBootEnv(`${LINE}\n`);
      const f = fakeOpenClaw({
        list: { enabled: true, status: 'loaded' },
        credentialedEnding: { stderr: `${SECRET_REF_STDERR}\nchild-said token was ${ECHOES.json}` },
      });
      const { value: r, out } = await step(f);
      expect(r.summary).toBe(
        `not updated — still on v${BEFORE}; OpenClaw refused twice: gateway.auth.token is a gateway secret reference it could not resolve here`,
      );
      expect(r.recovery?.command).toBe(FORCE_INSTALL);
      expect(r.detail).toContain('gateway.auth.token is configured as a secret reference but is unavailable in this command path.');
      expect(r.detail).toContain('its output is withheld: this retry carried the gateway credential');
      assertNothingFromTheChild(r, out);
    });

    it('a credentialed child refused for an unsettled reload: the drain recovery, in fixed words', async () => {
      writeBootEnv(`${LINE}\n`);
      const f = fakeOpenClaw({
        credentialedEnding: {
          stderr: `plugin shieldcortex-realtime admitted work did not settle within 60s; the previous plugin generation stays active. child-said ${ECHOES.trimmed}`,
        },
      });
      const { value: r, out } = await step(f);
      expect(r.summary).toMatch(/^files saved — the previous plugin generation stays active/);
      expect(r.recovery?.command).toBe('openclaw plugins reload shieldcortex-realtime --wait');
      assertNothingFromTheChild(r, out);
    });

    it('a credential shorter than the shared reporter\'s 8-character floor: not shown either', async () => {
      writeBootEnv('OPENCLAW_GATEWAY_TOKEN=Qz7k\n');
      const f = fakeOpenClaw({ credentialedEnding: { stderr: 'auth failed for Qz7k' } });
      const { value: r, out } = await step(f);
      expect(out).not.toContain('Qz7k');
      expect(out).not.toContain('auth failed');
      expect(JSON.stringify(r)).not.toContain('Qz7k');
    });

    it('the exact-value scrub (the second line of defence) replaces a short value too', () => {
      const creds = { OPENCLAW_GATEWAY_TOKEN: 'Qz7k' };
      expect(redactGatewayCredentials('auth failed for Qz7k', creds)).toBe('auth failed for [redacted:$OPENCLAW_GATEWAY_TOKEN]');
    });
  });

  it('the operator\'s own credential is never replaced — the boot env is not read and the retry is identical', async () => {
    writeBootEnv(`OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
    process.env.OPENCLAW_GATEWAY_PASSWORD = 'operator-chosen';
    const calls: Call[] = [];
    const run = (_cmd: string, args: string[], o: { env?: NodeJS.ProcessEnv } = {}) => {
      calls.push({ args, env: { ...(o.env ?? process.env) } });
      if (args[1] === 'list') return Promise.resolve({ stdout: '{"plugins":[]}', stderr: '' });
      return Promise.reject(Object.assign(new Error('exit 1'), { exitCode: 1, stdout: '', stderr: SECRET_REF_STDERR }));
    };
    const { value: r } = await captureOutput(() => stepOpenClawPlugin(home, {
      run: run as never, readPluginVersion: () => BEFORE, readCliVersion: () => CLI,
    }));

    const inst = calls.filter((c) => c.args[1] === 'install');
    expect(inst).toHaveLength(2);
    expect(inst[1].env).toEqual(inst[0].env);
    expect(inst[1].env.OPENCLAW_GATEWAY_TOKEN).toBeUndefined();
    expect(r.detail?.[1]).toMatch(/^gateway boot env not used: .*already set here/);
  });

  it('a remote gateway never gets the local gateway\'s credential', async () => {
    writeConfig('remote');
    writeBootEnv(`OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
    const f = fakeOpenClaw({ list: { enabled: true, status: 'loaded' } });
    const { value: r } = await step(f);

    for (const c of f.calls) expect(c.env.OPENCLAW_GATEWAY_TOKEN).toBeUndefined();
    expect(r.status).toBe('warn');
    expect(r.detail?.[1]).toMatch(/gateway boot env not used: gateway\.mode is remote/);
  });

  it.each([
    ['~/.openclaw/.env', () => writeDotEnv(stateDotEnvPath(), 'OPENCLAW_GATEWAY_URL=wss://remote.example:443\n'), /~\/\.openclaw\/\.env names OPENCLAW_GATEWAY_URL/],
    ['~/.config/openclaw/gateway.env', () => writeDotEnv(gatewayDotEnvPath(), 'OPENCLAW_GATEWAY_URL=wss://remote.example:443\n'), /~\/\.config\/openclaw\/gateway\.env names OPENCLAW_GATEWAY_URL/],
    ['~/.openclaw/.env (port)', () => writeDotEnv(stateDotEnvPath(), 'OPENCLAW_GATEWAY_PORT=9\n'), /~\/\.openclaw\/\.env names OPENCLAW_GATEWAY_PORT/],
  ] as const)('#1105 r3 B1: a gateway override in %s — no child ever gets the local credential', async (_label, arrange, reason) => {
    writeBootEnv(`OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
    arrange();
    const f = fakeOpenClaw({ list: { enabled: true, status: 'loaded' } });
    const { value: r, out } = await step(f);

    expect(installs(f)).toHaveLength(2);
    for (const c of f.calls) {
      expect(c.env.OPENCLAW_GATEWAY_TOKEN).toBeUndefined();
      expect(c.env.OPENCLAW_GATEWAY_PASSWORD).toBeUndefined();
    }
    expect(r.status).toBe('warn');
    expect(r.detail?.[1]).toMatch(new RegExp(`^gateway boot env not used: ${reason.source}`));
    expect(JSON.stringify(r) + out).not.toContain(TOKEN);
  });

  describe('no boot env: refused twice — the accurate message', () => {
    async function refusedTwice(list: Record<string, unknown> | null) {
      const f = fakeOpenClaw({ list });
      return { ...(await step(f)), f };
    }

    it('reads OpenClaw\'s plugin list and says the plugin is still on the previous version', async () => {
      const { value: r, f } = await refusedTwice({ enabled: true, status: 'loaded' });

      expect(f.calls.map((c) => c.args)).toEqual([INSTALL_ARGS, INSTALL_ARGS, ['plugins', 'list', '--json']]);
      // The list read never carries a credential either.
      expect(f.calls[2].env.OPENCLAW_GATEWAY_TOKEN).toBeUndefined();
      expect(r.status).toBe('warn');
      expect(r.unfinished).toBe(true);
      expect(r.stillOn).toBe(BEFORE);
      expect(r.summary).toBe(
        `not updated — still on v${BEFORE}; OpenClaw refused twice: gateway.auth.token is a gateway secret reference it could not resolve here`,
      );
      expect(r.recovery?.command).toBe(FORCE_INSTALL);
      const detail = (r.detail ?? []).join('\n');
      expect(detail).toContain(`gateway boot env not used: there is no ${GATEWAY_BOOT_ENV_DISPLAY}`);
      expect(detail).toContain(`OpenClaw's own plugin list still shows shieldcortex-realtime v${BEFORE}, enabled`);
    });

    it.each([
      ['lists it disabled', { enabled: false, status: 'disabled' }],
      ['cannot be read', null],
    ])('claims nothing when the list %s', async (_label, list) => {
      const { value: r } = await refusedTwice(list);
      expect(r.stillOn).toBeUndefined();
      expect(r.summary).toMatch(/^not applied — OpenClaw refused twice/);
    });

    /** The reported closing screen: Guard on, and the end-of-run check said the gateway has no plugin. */
    function closing(r: { status: UpdateSummaryInput['plugin']['status']; rerun?: string; recovery?: { command: string; note?: string }; stillOn?: string }): UpdateSummaryInput {
      return {
        fromVersion: BEFORE,
        toVersion: CLI,
        packageState: 'updated',
        engine: { ok: true },
        plugin: { status: r.status, rerun: r.rerun, recovery: r.recovery, ...(r.stillOn ? { stillOn: r.stillOn } : {}) },
        skill: { status: 'ok' },
        guardOn: true,
        protection: { status: 'failed', loaded: 'no', pluginVersion: BEFORE, expectedVersion: CLI, nextCommand: 'shieldcortex repair' },
      };
    }

    it('a check that proved the plugin absent stays red — the still-installed version is named inside it (#1105 r2 B5)', async () => {
      const { value: r } = await refusedTwice({ enabled: true, status: 'loaded' });
      const input = closing(r);
      const summary = buildUpdateSummary(input);
      const openclaw = summary.rows.find((x) => x.label === 'OpenClaw');
      const guard = summary.rows.find((x) => x.label === 'Guard');

      // Inventory (OpenClaw's plugin list) cannot contradict a runtime check
      // that proved the plugin absent: both rows stay red.
      expect(openclaw).toMatchObject({
        mark: 'fail',
        text: `plugin not updated (${BEFORE} still installed), and the gateway started without the ShieldCortex plugin`,
      });
      expect(guard).toMatchObject({ mark: 'fail', text: 'on, but OpenClaw isn\'t running the plugin' });
      expect(summary.headline).toBe('failed');
      const screen = renderUpdateSummary(summary, input, { width: 100, style: NO_STYLE, ascii: true }).join('\n');
      expect(screen).toContain(`${BEFORE} still installed`);
      expect(screen).not.toContain('keeps running');
    });

    it('a failed check with loaded "no" and a still-listed plugin: red, and the run still exits non-zero', async () => {
      const { value: r } = await refusedTwice({ enabled: true, status: 'loaded' });
      expect(r.unfinished).toBe(true);
      const summary = buildUpdateSummary({
        ...closing(r),
        protection: { status: 'failed', loaded: 'no', pluginVersion: BEFORE, expectedVersion: CLI },
      });
      expect(summary.rows.filter((x) => x.mark === 'fail').map((x) => x.label)).toEqual(['OpenClaw', 'Guard']);
      expect(summary.headline).toBe('failed');
      // runUpdate sets `failed` for a failed check; the refused step alone is
      // unfinished — either way the exit code stays 1.
      expect(updateVerdict({ failed: true, attention: true, unfinished: r.unfinished === true }).exitCode).toBe(1);
      expect(updateVerdict({ failed: false, attention: true, unfinished: r.unfinished === true }).exitCode).toBe(1);
    });

    it('a plugin OpenClaw lists as disabled keeps the red "not running" finding', async () => {
      const { value: r } = await refusedTwice({ enabled: false, status: 'disabled' });
      const summary = buildUpdateSummary(closing(r));
      expect(summary.rows.find((x) => x.label === 'OpenClaw')).toMatchObject({ mark: 'fail' });
      expect(summary.rows.find((x) => x.label === 'Guard')).toMatchObject({ mark: 'fail', text: 'on, but OpenClaw isn\'t running the plugin' });
      expect(summary.headline).toBe('failed');
    });

    it('with loading unproven, the OpenClaw row says installed and listed — never "running" (#1105 r2 B5)', async () => {
      const { value: r } = await refusedTwice({ enabled: true, status: 'loaded' });
      const input: UpdateSummaryInput = { ...closing(r), protection: { status: 'unproven', loaded: 'unknown', pluginVersion: BEFORE } };
      const summary = buildUpdateSummary(input);
      expect(summary.rows.find((x) => x.label === 'OpenClaw')).toMatchObject({
        mark: 'check',
        text: `plugin not updated (still on ${BEFORE})`,
        why: 'The previous version is still installed and listed enabled.',
      });
      expect(summary.rows.find((x) => x.label === 'Guard')).toMatchObject({
        mark: 'check',
        text: 'on, but couldn\'t confirm OpenClaw is checking tool calls',
        command: FORCE_INSTALL,
      });
      expect(summary.headline).toBe('check');
      const screen = renderUpdateSummary(summary, input, { width: 100, style: NO_STYLE, ascii: true }).join('\n');
      expect(screen).not.toMatch(/running the previous|keeps running|is running/);
    });
  });

  /**
   * Through the real spawn (no `run` seam): an `openclaw` on PATH that installs
   * only when its env carries the expected token, and logs whether it had one
   * — never the value.
   */
  describe('real spawn', () => {
    let binDir: string;
    let savedPath: string | undefined;

    afterEach(() => {
      if (savedPath === undefined) delete process.env.PATH;
      else process.env.PATH = savedPath;
      savedPath = undefined;
      if (binDir) rmSync(binDir, { recursive: true, force: true });
    });

    function setUp() {
      binDir = mkdtempSync(join(tmpdir(), 'sc-1105-bin-'));
      const log = join(binDir, 'calls.log');
      const installed = join(binDir, 'installed');
      const script = [
        '#!/bin/sh',
        `if [ "$1" = plugins ] && [ "$2" = list ]; then echo "list" >> '${log}'; echo '{"plugins":[]}'; exit 0; fi`,
        `if [ "\${OPENCLAW_GATEWAY_TOKEN:-}" = '${TOKEN}' ]; then echo "install token=match" >> '${log}'; : > '${installed}'; echo "Installed"; exit 0; fi`,
        `if [ -n "\${OPENCLAW_GATEWAY_TOKEN:-}" ]; then echo "install token=other" >> '${log}'; else echo "install token=unset" >> '${log}'; fi`,
        `echo ${JSON.stringify(SECRET_REF_STDERR.split('\n')[0])} >&2`,
        'exit 1',
        '',
      ].join('\n');
      const file = join(binDir, 'openclaw');
      mkdirSync(dirname(file), { recursive: true });
      writeFileSync(file, script, { mode: 0o755 });
      chmodSync(file, 0o755);
      savedPath = process.env.PATH;
      process.env.PATH = `${binDir}:/usr/bin:/bin`;
      return {
        calls: () => (existsSync(log) ? readFileSync(log, 'utf-8').trim().split('\n') : []),
        installed: () => existsSync(installed),
      };
    }

    it('first child has no token and is refused; the retry child gets the boot-env token and installs', async () => {
      writeBootEnv(`OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
      const fake = setUp();
      const { value: r, out } = await captureOutput(() => stepOpenClawPlugin(home, {
        readPluginVersion: () => (fake.installed() ? CLI : BEFORE),
        readCliVersion: () => CLI,
      }));

      expect(fake.calls()).toEqual(['install token=unset', 'install token=match']);
      expect(r.status).toBe('ok');
      expect(r.summary).toBe(`${BEFORE} → ${CLI}`);
      expect(out).not.toContain(TOKEN);
      expect(process.env.OPENCLAW_GATEWAY_TOKEN).toBeUndefined();
    });

    it('no boot env: refused twice, then the list — and the accurate message', async () => {
      const fake = setUp();
      const { value: r } = await captureOutput(() => stepOpenClawPlugin(home, {
        readPluginVersion: () => (fake.installed() ? CLI : BEFORE),
        readCliVersion: () => CLI,
      }));

      expect(fake.calls()).toEqual(['install token=unset', 'install token=unset', 'list']);
      expect(fake.installed()).toBe(false);
      expect(r.status).toBe('warn');
      expect(r.recovery?.command).toBe(FORCE_INSTALL);
      expect((r.detail ?? []).join('\n')).toContain(`gateway boot env not used: there is no ${GATEWAY_BOOT_ENV_DISPLAY}`);
    });
  });
});

/**
 * `runUpdate` spawns npm and re-execs the new CLI, so the hand-off from the
 * plugin step to the closing screen is pinned at the source, as #221 does.
 */
describe('#1105 — the closing screen is given what the plugin step found', () => {
  it('runUpdate passes the still-listed version to the summary', () => {
    const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'cli', 'update.ts'), 'utf-8');
    expect(src).toMatch(/stillOn: pluginResult\.stillOn/);
  });
});

/**
 * #1105 r2 B4, through a real Node process: Node fixes its debug sections from
 * NODE_DEBUG at startup, so a process that removes the variable later still
 * logs every spawn's env to stderr. The module is transpiled on its own (it
 * imports only `fs`, `path` and `util`) and run in a child Node whose startup
 * env has NODE_DEBUG, which the driver deletes before asking.
 */
describe('#1105 r2 B4 — a child_process debug log switched on at startup refuses the borrow', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'sc-1105-debuglog-'));
    const srcFile = join(dirname(fileURLToPath(import.meta.url)), '..', 'integrations', 'openclaw-gateway-boot-env.ts');
    const js = ts.transpileModule(readFileSync(srcFile, 'utf-8'), {
      compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
    }).outputText;
    writeFileSync(join(dir, 'boot-env.mjs'), js);
    writeFileSync(join(dir, 'driver.mjs'), [
      "import { resolveGatewayBootCredentials } from './boot-env.mjs';",
      'const hadDebug = process.env.NODE_DEBUG !== undefined;',
      'delete process.env.NODE_DEBUG;',
      "const r = resolveGatewayBootCredentials({ home: process.argv[2], refusedPath: 'gateway.auth.token', env: process.env });",
      "process.stdout.write('RESULT ' + JSON.stringify({ hadDebug, used: r.used, reason: r.used ? null : r.reason }) + '\\n');",
      '',
    ].join('\n'));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  function runDriver(nodeDebug?: string) {
    const env: NodeJS.ProcessEnv = { PATH: process.env.PATH, HOME: home };
    if (nodeDebug !== undefined) env.NODE_DEBUG = nodeDebug;
    const res = spawnSync(process.execPath, [join(dir, 'driver.mjs'), home], { env, encoding: 'utf-8', timeout: 30000 });
    const line = (res.stdout ?? '').split('\n').find((l) => l.startsWith('RESULT '));
    expect(line).toBeDefined();
    return { result: JSON.parse(line!.slice('RESULT '.length)) as { hadDebug: boolean; used: boolean; reason: string | null }, stderr: res.stderr ?? '' };
  }

  it('control: the same process without NODE_DEBUG borrows the credential', () => {
    writeBootEnv(`OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
    const { result } = runDriver();
    expect(result).toEqual({ hadDebug: false, used: true, reason: null });
  });

  it.each(['child_process', 'CHILD_PROCESS', '*', 'net,child_process'])(
    'NODE_DEBUG=%s at startup, deleted from process.env before the call: refused',
    (value) => {
      writeBootEnv(`OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
      const { result, stderr } = runDriver(value);
      expect(result.hadDebug).toBe(true);
      expect(result.used).toBe(false);
      expect(result.reason).toMatch(/^NODE_DEBUG is set, and Node's diagnostics would print the retry child's environment/);
      expect(stderr).not.toContain(TOKEN);
    },
  );
});
