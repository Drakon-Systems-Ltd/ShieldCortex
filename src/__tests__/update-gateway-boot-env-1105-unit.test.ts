import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { stepOpenClawPlugin } from '../cli/update.js';
import {
  GATEWAY_BOOT_ENV_DISPLAY,
  GATEWAY_UNIT,
  SYSTEMCTL_SHOW_ARGS,
  parseGatewayBootEnvEntries,
  parseUnitEnvironmentFiles,
  resolveGatewayBootCredentials,
  systemctlChildEnv,
  type SystemctlRunner,
} from '../integrations/openclaw-gateway-boot-env.js';
import type { CapturedError } from '../integrations/child-output.js';

/**
 * #1105 reopened (clawdbot1, ShieldCortex 5.20.2) — the gateway unit loads
 * TWO EnvironmentFiles and the token lives in the second:
 *
 *   EnvironmentFile=-/home/ubuntu/.openclaw/gateway.systemd.env
 *   EnvironmentFile=-/home/ubuntu/.openclaw/secrets/gateway-boot.env
 *
 * The boot-env fallback read only the first and reported "no plain
 * OPENCLAW_GATEWAY_TOKEN … line". It now asks systemd for the unit's
 * effective EnvironmentFiles and reads each, in order, later over earlier,
 * per key — every path inside the checked `~/.openclaw`, reached one
 * component at a time. systemd is never asked for real here: every test hands
 * the module a `systemctl` runner that answers as systemd 255 does.
 */

const TOKEN = 'plain-words-gateway-token';
const LATER_TOKEN = 'plain-words-later-token';
const PASSWORD = 'plain-words-gateway-password';

const ENV_KEYS = [
  'OPENCLAW_GATEWAY_TOKEN',
  'OPENCLAW_GATEWAY_PASSWORD',
  'OPENCLAW_GATEWAY_URL',
  'OPENCLAW_GATEWAY_PORT',
  'OPENCLAW_STATE_DIR',
  'OPENCLAW_HOME',
  'OPENCLAW_PROFILE',
  'OPENCLAW_CONFIG_PATH',
  'NODE_DEBUG',
  'NODE_DEBUG_NATIVE',
  'NODE_OPTIONS',
  'XDG_RUNTIME_DIR',
  'DBUS_SESSION_BUS_ADDRESS',
  'SC_1105_UNRELATED',
] as const;

let home: string;
let saved: Record<string, string | undefined>;

const oc = () => join(home, '.openclaw');
const generated = () => join(oc(), 'gateway.systemd.env');
const secretsDir = () => join(oc(), 'secrets');
const secrets = () => join(secretsDir(), 'gateway-boot.env');

/** An env file as an operator would leave it: theirs, mode 0600. */
function writeEnv(file: string, body: string, mode = 0o600) {
  writeFileSync(file, body);
  chmodSync(file, mode);
}

function makeSecretsDir(mode = 0o700) {
  mkdirSync(secretsDir(), { recursive: true });
  chmodSync(secretsDir(), mode);
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'sc-1105-unit-'));
  mkdirSync(join(oc(), 'plugins'), { recursive: true });
  chmodSync(oc(), 0o700);
  writeFileSync(join(oc(), 'plugins', 'installs.json'), JSON.stringify({ installRecords: { 'shieldcortex-realtime': {} } }));
  writeFileSync(join(oc(), 'openclaw.json'), JSON.stringify({
    gateway: { mode: 'local', auth: { mode: 'token', token: { source: 'exec', provider: 'vault', id: 'gateway/token' } } },
  }));
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

type SystemctlCall = { args: readonly string[]; env: Record<string, string> };

/** A systemctl that answers `show` with `lines` (systemd 255 prints EnvironmentFiles before LoadState). */
function systemd(lines: string[], status: number | null = 0) {
  const calls: SystemctlCall[] = [];
  const run: SystemctlRunner = (args, env) => {
    calls.push({ args, env });
    return { status, stdout: lines.length > 0 ? `${lines.join('\n')}\n` : '' };
  };
  return { run, calls };
}

const entry = (p: string, optional = true) => `EnvironmentFiles=${p} (ignore_errors=${optional ? 'yes' : 'no'})`;

/** The reporter's unit: both files optional, generated file first. */
function clawdbotUnit() {
  return systemd([entry(generated()), entry(secrets()), 'LoadState=loaded']);
}

function resolve(run: SystemctlRunner | null, over: Partial<Parameters<typeof resolveGatewayBootCredentials>[0]> = {}) {
  return resolveGatewayBootCredentials({ home, refusedPath: 'gateway.auth.token', env: process.env, systemctl: run, ...over });
}

/** A reason names files only as `~/.openclaw/…` or in fixed words: no absolute path, no value. */
function expectCleanReason(r: ReturnType<typeof resolve>) {
  expect(r.used).toBe(false);
  const reason = r.used ? '' : r.reason;
  expect(reason).not.toContain(home);
  expect(reason).not.toMatch(/(?:^|[\s(,])\/[A-Za-z]/);
  for (const v of [TOKEN, LATER_TOKEN, PASSWORD]) expect(reason).not.toContain(v);
}

describe('#1105 reopened — every EnvironmentFile the gateway unit loads, in order', () => {
  it('acceptance: two EnvironmentFiles, the token only in the second (secrets/gateway-boot.env) — used', () => {
    writeEnv(generated(), 'OPENCLAW_SERVICE_KIND=gateway\nOPENCLAW_GATEWAY_PORT=18789\n');
    makeSecretsDir();
    writeEnv(secrets(), `OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
    const unit = clawdbotUnit();
    expect(resolve(unit.run)).toEqual({
      used: true,
      env: { OPENCLAW_GATEWAY_TOKEN: TOKEN },
      keys: ['OPENCLAW_GATEWAY_TOKEN'],
      from: ['~/.openclaw/secrets/gateway-boot.env'],
    });
    expect(unit.calls).toHaveLength(1);
  });

  it('both files set the token: the later file wins, as in systemd', () => {
    writeEnv(generated(), `OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
    makeSecretsDir();
    writeEnv(secrets(), `OPENCLAW_GATEWAY_TOKEN=${LATER_TOKEN}\n`);
    expect(resolve(clawdbotUnit().run)).toEqual({
      used: true,
      env: { OPENCLAW_GATEWAY_TOKEN: LATER_TOKEN },
      keys: ['OPENCLAW_GATEWAY_TOKEN'],
      from: ['~/.openclaw/secrets/gateway-boot.env'],
    });
  });

  it('listed order decides, not file names: the generated file listed LAST wins', () => {
    writeEnv(generated(), `OPENCLAW_GATEWAY_TOKEN=${LATER_TOKEN}\n`);
    makeSecretsDir();
    writeEnv(secrets(), `OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
    const unit = systemd([entry(secrets()), entry(generated()), 'LoadState=loaded']);
    expect(resolve(unit.run)).toMatchObject({ used: true, env: { OPENCLAW_GATEWAY_TOKEN: LATER_TOKEN }, from: [GATEWAY_BOOT_ENV_DISPLAY] });
  });

  it('keys from different files: each from the last file that sets it, both files named', () => {
    writeEnv(generated(), `OPENCLAW_GATEWAY_PASSWORD=${PASSWORD}\n`);
    makeSecretsDir();
    writeEnv(secrets(), `OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
    expect(resolve(clawdbotUnit().run)).toEqual({
      used: true,
      env: { OPENCLAW_GATEWAY_TOKEN: TOKEN, OPENCLAW_GATEWAY_PASSWORD: PASSWORD },
      keys: ['OPENCLAW_GATEWAY_TOKEN', 'OPENCLAW_GATEWAY_PASSWORD'],
      from: ['~/.openclaw/secrets/gateway-boot.env', GATEWAY_BOOT_ENV_DISPLAY],
    });
  });

  it.each([
    ['a ${VAR} expansion', 'OPENCLAW_GATEWAY_TOKEN=${OTHER}\n'],
    ['single quotes', `OPENCLAW_GATEWAY_TOKEN='${LATER_TOKEN}'\n`],
    ['a value spanning lines', `OPENCLAW_GATEWAY_TOKEN="${LATER_TOKEN}\nmore"\n`],
    ['a backslash continuation', `OPENCLAW_GATEWAY_TOKEN=${LATER_TOKEN}\\\nmore\n`],
    ['a comment ending in a backslash (systemd-version dependent)', `# note \\\nOPENCLAW_GATEWAY_TOKEN=${LATER_TOKEN}\n`],
  ])('the later file sets the token as %s, the earlier one plainly: the earlier value is NOT used', (label, later) => {
    writeEnv(generated(), `OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
    makeSecretsDir();
    writeEnv(secrets(), later);
    const r = resolve(clawdbotUnit().run);
    // What a version-dependent file sets cannot be known at all: both keys.
    expect(r).toEqual({
      used: false,
      reason: label.includes('version dependent)')
        ? 'the last settings of OPENCLAW_GATEWAY_TOKEN (in ~/.openclaw/secrets/gateway-boot.env) and OPENCLAW_GATEWAY_PASSWORD (in ~/.openclaw/secrets/gateway-boot.env) in the EnvironmentFiles systemd lists for openclaw-gateway.service are not plain lines, so no earlier value was used'
        : 'the last setting of OPENCLAW_GATEWAY_TOKEN (in ~/.openclaw/secrets/gateway-boot.env) in the EnvironmentFiles systemd lists for openclaw-gateway.service is not a plain line, so no earlier value was used',
    });
    expectCleanReason(r);
  });

  it('an unusable later token drops only that key: a plain password elsewhere is still passed', () => {
    writeEnv(generated(), `OPENCLAW_GATEWAY_TOKEN=${TOKEN}\nOPENCLAW_GATEWAY_PASSWORD=${PASSWORD}\n`);
    makeSecretsDir();
    writeEnv(secrets(), 'OPENCLAW_GATEWAY_TOKEN=$OTHER\n');
    expect(resolve(clawdbotUnit().run)).toEqual({
      used: true,
      env: { OPENCLAW_GATEWAY_PASSWORD: PASSWORD },
      keys: ['OPENCLAW_GATEWAY_PASSWORD'],
      from: [GATEWAY_BOOT_ENV_DISPLAY],
    });
  });

  it('a later file that does not mention the key leaves the earlier value in place', () => {
    writeEnv(generated(), `OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
    makeSecretsDir();
    writeEnv(secrets(), 'UNRELATED=$EXPANDED\n');
    expect(resolve(clawdbotUnit().run)).toMatchObject({ used: true, env: { OPENCLAW_GATEWAY_TOKEN: TOKEN }, from: [GATEWAY_BOOT_ENV_DISPLAY] });
  });

  it('an optional (-) file that does not exist is skipped', () => {
    makeSecretsDir();
    writeEnv(secrets(), `OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
    expect(resolve(clawdbotUnit().run)).toMatchObject({ used: true, env: { OPENCLAW_GATEWAY_TOKEN: TOKEN } });
  });

  it('an optional file whose directory does not exist is skipped', () => {
    writeEnv(generated(), `OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
    expect(resolve(clawdbotUnit().run)).toMatchObject({ used: true, env: { OPENCLAW_GATEWAY_TOKEN: TOKEN }, from: [GATEWAY_BOOT_ENV_DISPLAY] });
  });

  it('a required (no -) file that does not exist: refused — systemd would not start the unit', () => {
    writeEnv(generated(), `OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
    const r = resolve(systemd([entry(generated()), entry(secrets(), false), 'LoadState=loaded']).run);
    expect(r).toEqual({
      used: false,
      reason: '~/.openclaw/secrets/gateway-boot.env is a required EnvironmentFile of openclaw-gateway.service (no "-") but does not exist, so the gateway\'s environment is not known and no boot env was used',
    });
    expectCleanReason(r);
  });

  it('every listed file optional and missing: says so, names nothing absolute', () => {
    const r = resolve(clawdbotUnit().run);
    expect(r).toEqual({ used: false, reason: 'none of the EnvironmentFiles systemd lists for openclaw-gateway.service exists (all are optional)' });
  });

  it('no plain line in any listed file: the reason names the files read and that systemd listed them', () => {
    writeEnv(generated(), 'OPENCLAW_SERVICE_KIND=gateway\n');
    makeSecretsDir();
    writeEnv(secrets(), 'OTHER=1\n');
    const r = resolve(clawdbotUnit().run);
    expect(r).toEqual({
      used: false,
      reason: '~/.openclaw/gateway.systemd.env, ~/.openclaw/secrets/gateway-boot.env (the EnvironmentFiles systemd lists for openclaw-gateway.service) have no plain OPENCLAW_GATEWAY_TOKEN or OPENCLAW_GATEWAY_PASSWORD line',
    });
    expectCleanReason(r);
  });
});

describe('#1105 reopened — listed paths are constrained to the checked ~/.openclaw', () => {
  beforeEach(() => {
    writeEnv(generated(), `OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
  });

  it.each([
    ['outside ~/.openclaw (elsewhere in home)', () => join(home, 'elsewhere.env'), /outside ~\/\.openclaw/],
    ['outside ~/.openclaw (a system file)', () => '/etc/environment', /outside ~\/\.openclaw/],
    ['a sibling whose name only starts with .openclaw', () => join(home, '.openclaw-other', 'x.env'), /outside ~\/\.openclaw/],
    ['the state dir itself', () => oc(), /outside ~\/\.openclaw/],
    ['through ..', () => `${oc()}/../.openclaw/gateway.systemd.env`, /"\.\."/],
    ['through .', () => `${oc()}/./gateway.systemd.env`, /"\.\."/],
    ['with an empty segment', () => `${oc()}//gateway.systemd.env`, /"\.\."/],
    ['not absolute', () => 'relative/gateway.env', /not an absolute path/],
    ['a wildcard', () => `${oc()}/*.env`, /wildcard/],
  ])('a listed path %s: refused, even with a usable file listed before it', (_label, listed, why) => {
    const r = resolve(systemd([entry(generated()), entry(listed()), 'LoadState=loaded']).run);
    expect(r).toMatchObject({ used: false, reason: expect.stringMatching(why) });
    expectCleanReason(r);
  });

  it('a symbolic link as an intermediate directory: refused, nothing read through it', () => {
    const real = join(home, 'real-secrets');
    mkdirSync(real, { mode: 0o700 });
    chmodSync(real, 0o700);
    writeEnv(join(real, 'gateway-boot.env'), `OPENCLAW_GATEWAY_TOKEN=${LATER_TOKEN}\n`);
    symlinkSync(real, secretsDir());
    const r = resolve(clawdbotUnit().run);
    expect(r).toEqual({
      used: false,
      reason: '~/.openclaw/secrets is a symbolic link, so ~/.openclaw/secrets/gateway-boot.env was not read (one of the EnvironmentFiles systemd lists for openclaw-gateway.service), so no boot env was used',
    });
    expectCleanReason(r);
  });

  it('a symbolic link as the listed file itself: refused', () => {
    makeSecretsDir();
    writeEnv(join(secretsDir(), 'real.env'), `OPENCLAW_GATEWAY_TOKEN=${LATER_TOKEN}\n`);
    symlinkSync(join(secretsDir(), 'real.env'), secrets());
    const r = resolve(clawdbotUnit().run);
    expect(r).toMatchObject({ used: false, reason: expect.stringMatching(/^~\/\.openclaw\/secrets\/gateway-boot\.env is a symbolic link/) });
    expectCleanReason(r);
  });

  it.each([0o770, 0o707, 0o777])('an intermediate directory with mode %o: refused', (mode) => {
    makeSecretsDir(mode);
    writeEnv(secrets(), `OPENCLAW_GATEWAY_TOKEN=${LATER_TOKEN}\n`);
    const r = resolve(clawdbotUnit().run);
    expect(r).toEqual({
      used: false,
      reason: '~/.openclaw/secrets is writable by group or others, so ~/.openclaw/secrets/gateway-boot.env was not read (one of the EnvironmentFiles systemd lists for openclaw-gateway.service), so no boot env was used',
    });
    expectCleanReason(r);
  });

  it('an intermediate path that is a file, not a directory: refused', () => {
    writeEnv(secretsDir(), 'not a dir\n');
    const r = resolve(clawdbotUnit().run);
    expect(r).toMatchObject({ used: false, reason: expect.stringMatching(/^~\/\.openclaw\/secrets is not a directory/) });
    expectCleanReason(r);
  });

  it('a listed file writable by group: refused with the existing file checks', () => {
    makeSecretsDir();
    writeEnv(secrets(), `OPENCLAW_GATEWAY_TOKEN=${LATER_TOKEN}\n`, 0o620);
    const r = resolve(clawdbotUnit().run);
    expect(r).toMatchObject({ used: false, reason: expect.stringMatching(/^~\/\.openclaw\/secrets\/gateway-boot\.env is writable by group or others/) });
    expectCleanReason(r);
  });

  it('a listed file owned by someone else: refused', () => {
    makeSecretsDir();
    writeEnv(secrets(), `OPENCLAW_GATEWAY_TOKEN=${LATER_TOKEN}\n`);
    const r = resolve(clawdbotUnit().run, { geteuid: () => 4242 });
    // ~/.openclaw itself is checked first under the same uid.
    expect(r).toMatchObject({ used: false, reason: expect.stringMatching(/is not owned by the user running update/) });
    expectCleanReason(r);
  });

  it('a file name that is not plain is never echoed: it is read, and named in fixed words', () => {
    const odd = join(oc(), 'gate way$(id).env');
    writeEnv(odd, 'OTHER=1\n');
    const r = resolve(systemd([entry(odd), 'LoadState=loaded']).run);
    expect(r).toEqual({
      used: false,
      reason: 'an EnvironmentFile under ~/.openclaw (the EnvironmentFiles systemd lists for openclaw-gateway.service) has no plain OPENCLAW_GATEWAY_TOKEN or OPENCLAW_GATEWAY_PASSWORD line',
    });
  });
});

describe('#1105 reopened — no systemd answer: exactly the old single-file behaviour', () => {
  const OLD_NO_LINE = `${GATEWAY_BOOT_ENV_DISPLAY} has no plain OPENCLAW_GATEWAY_TOKEN or OPENCLAW_GATEWAY_PASSWORD line`;

  it.each<[string, () => SystemctlRunner | null]>([
    ['no systemctl on this host', () => null],
    ['systemctl could not be run (killed, timed out)', () => () => null],
    ['systemctl threw', () => () => { throw new Error('spawn failure'); }],
    ['no user manager ("Failed to connect to bus", exit 1)', () => systemd([], 1).run],
    ['the unit is unknown (LoadState=not-found)', () => systemd(['LoadState=not-found']).run],
    ['the unit is masked', () => systemd(['LoadState=masked']).run],
    ['the unit lists no EnvironmentFile', () => systemd(['LoadState=loaded']).run],
  ])('%s: the fixed file only, the old result shape (no `from`)', (_label, make) => {
    writeEnv(generated(), `OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
    // A file the unit would list is present but must not be read on this path.
    makeSecretsDir();
    writeEnv(secrets(), `OPENCLAW_GATEWAY_TOKEN=${LATER_TOKEN}\n`);
    expect(resolve(make())).toEqual({ used: true, env: { OPENCLAW_GATEWAY_TOKEN: TOKEN }, keys: ['OPENCLAW_GATEWAY_TOKEN'] });
  });

  it('no systemd answer and no plain line: the exact old reason', () => {
    writeEnv(generated(), 'OPENCLAW_SERVICE_KIND=gateway\n');
    expect(resolve(systemd(['LoadState=not-found']).run)).toEqual({ used: false, reason: OLD_NO_LINE });
  });

  it('no systemd answer and no file: the exact old reason', () => {
    expect(resolve(null)).toEqual({ used: false, reason: `there is no ${GATEWAY_BOOT_ENV_DISPLAY}` });
  });

  it('the default (no runner given) for a home that is not this user\'s own never asks systemd: old behaviour', () => {
    writeEnv(generated(), `OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
    const r = resolveGatewayBootCredentials({ home, refusedPath: 'gateway.auth.token', env: process.env });
    expect(r).toEqual({ used: true, env: { OPENCLAW_GATEWAY_TOKEN: TOKEN }, keys: ['OPENCLAW_GATEWAY_TOKEN'] });
  });
});

describe('#1105 reopened — the systemctl child and its answer', () => {
  it('fixed argv; the child env is LC_ALL plus the two user-manager locators, never a credential or anything else', () => {
    writeEnv(generated(), `OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
    process.env.XDG_RUNTIME_DIR = '/run/user/4242';
    process.env.DBUS_SESSION_BUS_ADDRESS = 'unix:path=/run/user/4242/bus';
    process.env.SC_1105_UNRELATED = 'should-not-pass';
    const unit = clawdbotUnit();
    expect(resolve(unit.run)).toMatchObject({ used: true });
    expect(unit.calls).toHaveLength(1);
    const [{ args, env }] = unit.calls;
    expect(args).toEqual(['--user', '--no-pager', 'show', '--property=LoadState', '--property=EnvironmentFiles', '--', GATEWAY_UNIT]);
    expect(args).toEqual(SYSTEMCTL_SHOW_ARGS);
    expect(env).toEqual({ LC_ALL: 'C', XDG_RUNTIME_DIR: '/run/user/4242', DBUS_SESSION_BUS_ADDRESS: 'unix:path=/run/user/4242/bus' });
    expect(Object.keys(env)).not.toContain('OPENCLAW_GATEWAY_TOKEN');
    expect(Object.keys(env)).not.toContain('OPENCLAW_GATEWAY_PASSWORD');
  });

  it('systemctlChildEnv drops credential keys even if a caller\'s env had them', () => {
    const env = systemctlChildEnv({ OPENCLAW_GATEWAY_TOKEN: 'x', OPENCLAW_GATEWAY_PASSWORD: 'y', PATH: '/usr/bin', XDG_RUNTIME_DIR: '/run/user/1' });
    expect(env).toEqual({ LC_ALL: 'C', XDG_RUNTIME_DIR: '/run/user/1' });
  });

  it.each<[string, () => void, Partial<Parameters<typeof resolveGatewayBootCredentials>[0]>]>([
    ['a credential already in the environment', () => { process.env.OPENCLAW_GATEWAY_TOKEN = 'already-here'; }, {}],
    ['a refusal that is not the local gateway auth', () => {}, { refusedPath: 'models.providers.x.apiKey' }],
    ['NODE_DEBUG set', () => { process.env.NODE_DEBUG = 'child_process'; }, {}],
    ['a location override', () => { process.env.OPENCLAW_STATE_DIR = '/elsewhere'; }, {}],
    ['a remote gateway', () => { writeFileSync(join(oc(), 'openclaw.json'), JSON.stringify({ gateway: { mode: 'remote' } })); }, {}],
    ['a dotenv naming an override', () => { writeEnv(join(oc(), '.env'), 'OPENCLAW_GATEWAY_URL=ws://x\n'); }, {}],
  ])('every earlier refusal still runs first — %s: systemctl is never asked', (_label, arrange, over) => {
    writeEnv(generated(), `OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
    arrange();
    const unit = clawdbotUnit();
    expect(resolve(unit.run, over)).toMatchObject({ used: false });
    expect(unit.calls).toHaveLength(0);
  });

  it.each([
    ['a junk line', (p: string) => [entry(p), 'JUNK sc-marker-$(id) /etc/shadow', 'LoadState=loaded']],
    ['an entry without ignore_errors', (p: string) => [`EnvironmentFiles=${p} sc-marker`, 'LoadState=loaded']],
    ['no LoadState', (p: string) => [entry(p)]],
    ['two LoadStates', (p: string) => [entry(p), 'LoadState=loaded', 'LoadState=loaded']],
    ['a control character', (p: string) => [`${entry(p)}\u001b[31msc-marker`, 'LoadState=loaded']],
  ])('an answer with %s: refused in fixed words, nothing of it echoed', (_label, lines) => {
    writeEnv(generated(), `OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
    const r = resolve(systemd(lines(generated())).run);
    expect(r).toEqual({
      used: false,
      reason: 'systemctl\'s answer about openclaw-gateway.service\'s EnvironmentFiles was not understood, so no boot env was read',
    });
    expectCleanReason(r);
    expect(JSON.stringify(r)).not.toContain('sc-marker');
  });

  it('parses systemd 255\'s own output (captured from a transient user unit)', () => {
    const out = [
      'EnvironmentFiles=/tmp/sc-nonexist-a (ignore_errors=yes)',
      'EnvironmentFiles=/dev/null (ignore_errors=no)',
      'EnvironmentFiles=/tmp/with space/x (ignore_errors=yes)',
      'LoadState=loaded',
      '',
    ].join('\n');
    expect(parseUnitEnvironmentFiles(out)).toEqual({
      kind: 'files',
      files: [
        { path: '/tmp/sc-nonexist-a', optional: true },
        { path: '/dev/null', optional: false },
        { path: '/tmp/with space/x', optional: true },
      ],
    });
    expect(parseUnitEnvironmentFiles('LoadState=not-found\n')).toEqual({ kind: 'unknown' });
    expect(parseUnitEnvironmentFiles('LoadState=loaded\n')).toEqual({ kind: 'files', files: [] });
    expect(parseUnitEnvironmentFiles('')).toEqual({ kind: 'unparsable' });
  });

  it('more than 32 EnvironmentFiles is refused', () => {
    const lines = Array.from({ length: 33 }, () => entry(generated()));
    expect(parseUnitEnvironmentFiles([...lines, 'LoadState=loaded'].join('\n'))).toEqual({ kind: 'unparsable' });
  });
});

describe('#1105 reopened — the parser reports each key as absent, a value, or unusable', () => {
  it.each<[string, string, ReturnType<typeof parseGatewayBootEnvEntries>]>([
    ['absent', 'OTHER=1\n', {}],
    ['a value', `OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`, { OPENCLAW_GATEWAY_TOKEN: { kind: 'value', value: TOKEN } }],
    ['unusable', 'OPENCLAW_GATEWAY_TOKEN=$X\n', { OPENCLAW_GATEWAY_TOKEN: { kind: 'unusable' } }],
    ['last entry wins (usable after unusable)', `OPENCLAW_GATEWAY_TOKEN=$X\nOPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`, { OPENCLAW_GATEWAY_TOKEN: { kind: 'value', value: TOKEN } }],
    ['last entry wins (unusable after usable)', `OPENCLAW_GATEWAY_TOKEN=${TOKEN}\nOPENCLAW_GATEWAY_TOKEN=$X\n`, { OPENCLAW_GATEWAY_TOKEN: { kind: 'unusable' } }],
    ['version-dependent comment: both unusable', '# x \\\nOTHER=1\n', { OPENCLAW_GATEWAY_TOKEN: { kind: 'unusable' }, OPENCLAW_GATEWAY_PASSWORD: { kind: 'unusable' } }],
    ['a NUL byte: both unusable', 'OTHER=\0\n', { OPENCLAW_GATEWAY_TOKEN: { kind: 'unusable' }, OPENCLAW_GATEWAY_PASSWORD: { kind: 'unusable' } }],
  ])('%s', (_label, text, want) => {
    expect(parseGatewayBootEnvEntries(text)).toEqual(want);
  });
});

describe('#1105 reopened — the update step names the file the key came from, never an absolute path', () => {
  const CLI = '5.20.1';
  const BEFORE = '5.20.0';
  const SECRET_REF_STDERR = [
    'gateway.auth.token is configured as a secret reference but is unavailable in this command path.',
    'Fix: set OPENCLAW_GATEWAY_TOKEN/OPENCLAW_GATEWAY_PASSWORD, pass explicit --token/--password,',
    'or run a gateway command path that resolves secret references before credential selection.',
  ].join('\n');

  async function quietly<T>(fn: () => Promise<T>): Promise<{ value: T; out: string }> {
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

  /** A fake `openclaw` that refuses any install child without a gateway credential, as OpenClaw 2026.11.4 does. */
  function fakeOpenClaw() {
    const installs: NodeJS.ProcessEnv[] = [];
    let onDisk = BEFORE;
    const run = (_cmd: string, args: string[], o: { env?: NodeJS.ProcessEnv } = {}) => {
      const env = { ...(o.env ?? process.env) };
      if (args[0] === 'plugins' && args[1] === 'list') {
        return Promise.resolve({ stdout: JSON.stringify({ plugins: [{ id: 'shieldcortex-realtime', version: onDisk }] }), stderr: '' });
      }
      installs.push(env);
      if (!env.OPENCLAW_GATEWAY_TOKEN && !env.OPENCLAW_GATEWAY_PASSWORD) {
        return Promise.reject(Object.assign(new Error('exit 1: openclaw plugins install'), {
          exitCode: 1, stdout: '', stderr: SECRET_REF_STDERR,
        }) as CapturedError);
      }
      onDisk = CLI;
      return Promise.resolve({ stdout: 'Installed shieldcortex-realtime', stderr: '' });
    };
    return { run: run as never, installs, readPluginVersion: () => onDisk };
  }

  it('token in ~/.openclaw/secrets/gateway-boot.env: the retry lands and the detail names that file', async () => {
    writeEnv(generated(), 'OPENCLAW_SERVICE_KIND=gateway\n');
    makeSecretsDir();
    writeEnv(secrets(), `OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
    const f = fakeOpenClaw();
    const { value: r, out } = await quietly(() => stepOpenClawPlugin(home, {
      confirmPublished: async () => ({ published: true as const }),
      run: f.run,
      readPluginVersion: f.readPluginVersion,
      readCliVersion: () => CLI,
      bootEnvSystemctl: clawdbotUnit().run,
    }));
    expect(r.status).toBe('ok');
    expect(r.detail?.[0]).toBe(
      'first install refused: gateway.auth.token is a gateway secret reference OpenClaw could not resolve for it; retried `openclaw plugins install --force` once with OPENCLAW_GATEWAY_TOKEN from the local gateway\'s boot env (~/.openclaw/secrets/gateway-boot.env), passed only to that child',
    );
    expect(f.installs).toHaveLength(2);
    expect(f.installs[0].OPENCLAW_GATEWAY_TOKEN).toBeUndefined();
    expect(f.installs[1].OPENCLAW_GATEWAY_TOKEN).toBe(TOKEN);
    const shown = `${out}\n${JSON.stringify(r)}`;
    expect(shown).not.toContain(home);
    expect(shown).not.toContain(TOKEN);
  });

  it('a refused resolution is reported without an absolute path', async () => {
    writeEnv(generated(), `OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
    const f = fakeOpenClaw();
    const { value: r, out } = await quietly(() => stepOpenClawPlugin(home, {
      confirmPublished: async () => ({ published: true as const }),
      run: f.run,
      readPluginVersion: f.readPluginVersion,
      readCliVersion: () => CLI,
      bootEnvSystemctl: systemd([entry(generated()), entry('/etc/environment'), 'LoadState=loaded']).run,
    }));
    expect(r.status).not.toBe('ok');
    const detail = (r.detail ?? []).join('\n');
    expect(detail).toContain('gateway boot env not used: the gateway unit (openclaw-gateway.service) lists an EnvironmentFile outside ~/.openclaw');
    const shown = `${out}\n${JSON.stringify(r)}`;
    expect(shown).not.toContain(home);
    expect(shown).not.toContain('/etc/environment');
    expect(shown).not.toContain(TOKEN);
  });
});
