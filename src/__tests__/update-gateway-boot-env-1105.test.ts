import {
  chmodSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { parsePluginListEntry, stepOpenClawPlugin } from '../cli/update.js';
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
 *     env only, after fixed-path, owner, mode and local-gateway checks.
 *  2. When the install is still refused, OpenClaw's own plugin list is read
 *     before the closing screen: a previous version still listed and enabled
 *     is "plugin not updated (still on X)", not "the gateway started without
 *     the ShieldCortex plugin" / "OpenClaw isn't running the plugin".
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
  writeFileSync(join(home, '.openclaw', 'openclaw.json'), JSON.stringify({
    gateway: {
      ...(mode ? { mode } : {}),
      auth: { mode: 'token', token: { source: 'exec', provider: 'vault', id: 'gateway/token' } },
    },
  }));
}

const bootEnvPath = () => join(home, '.openclaw', 'gateway.systemd.env');

/** The boot env as OpenClaw writes it: serialized entries, mode 0600. */
function writeBootEnv(body: string, mode = 0o600) {
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

  it('accepts a plain single-quoted value, comments, blank lines and CRLF endings', () => {
    const body = ['; note', '', "OPENCLAW_GATEWAY_TOKEN='two words'\r", '# end\r'].join('\n');
    expect(parseGatewayBootEnv(body)).toEqual({ OPENCLAW_GATEWAY_TOKEN: 'two words' });
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
    ['a config that is not JSON', () => writeFileSync(join(home, '.openclaw', 'openclaw.json'), '{ gateway: '), /could not be read to confirm a local gateway/],
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
          exitCode: 1, command: FORCE_INSTALL, stdout: '', stderr: SECRET_REF_STDERR,
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

  it('whatever the child says back is scrubbed of the credential before it reaches the screen', async () => {
    writeBootEnv(`OPENCLAW_GATEWAY_TOKEN=${TOKEN}\n`);
    const f = fakeOpenClaw({
      list: { enabled: true, status: 'loaded' },
      credentialedEnding: { stderr: `gateway rejected token ${TOKEN}: unauthorized (token=${TOKEN})` },
    });
    const { value: r, out } = await step(f);

    expect(r.status).toBe('warn');
    expect(r.unfinished).toBe(true);
    const shown = [r.summary ?? '', ...(r.detail ?? [])].join('\n');
    expect(shown).toContain('rejected token [redacted:$OPENCLAW_GATEWAY_TOKEN]');
    expect(shown).not.toContain(TOKEN);
    expect(out).not.toContain(TOKEN);
    // Not even part of it. The shared reporter's own redaction rewrites
    // `…-token` and `token=…` shapes; run before the exact-value scrub, it cut
    // the value apart and left `plain-words-gateway-` on screen.
    expect(shown).not.toContain('plain-words');
    expect(out).not.toContain('plain-words');
  });

  it('a credential shorter than the shared reporter\'s 8-character floor is scrubbed too', async () => {
    writeBootEnv('OPENCLAW_GATEWAY_TOKEN=Qz7k\n');
    const f = fakeOpenClaw({ credentialedEnding: { stderr: 'auth failed for Qz7k' } });
    const { value: r, out } = await step(f);

    const shown = [r.summary ?? '', ...(r.detail ?? [])].join('\n');
    expect(shown).toContain('auth failed for [redacted:$OPENCLAW_GATEWAY_TOKEN]');
    expect(shown).not.toContain('Qz7k');
    expect(out).not.toContain('Qz7k');
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

    it('the closing screen says "not updated (still on X)", never "not running"', async () => {
      const { value: r } = await refusedTwice({ enabled: true, status: 'loaded' });
      const input = closing(r);
      const summary = buildUpdateSummary(input);
      const openclaw = summary.rows.find((x) => x.label === 'OpenClaw');
      const guard = summary.rows.find((x) => x.label === 'Guard');

      expect(openclaw).toMatchObject({ mark: 'check', text: `plugin not updated (still on ${BEFORE})`, command: FORCE_INSTALL, commandLabel: 'Fix' });
      expect(guard).toMatchObject({ mark: 'check', text: 'on, but couldn\'t confirm OpenClaw is checking tool calls', command: FORCE_INSTALL, commandLabel: 'Fix' });
      expect(summary.headline).toBe('check');
      const screen = renderUpdateSummary(summary, input, { width: 100, style: NO_STYLE, ascii: true }).join('\n');
      expect(screen).not.toContain('started without');
      expect(screen).not.toContain('isn\'t running');
      expect(screen).not.toContain('not running');
      expect(screen).toContain(`still on ${BEFORE}`);
    });

    it('a plugin OpenClaw lists as disabled keeps the red "not running" finding', async () => {
      const { value: r } = await refusedTwice({ enabled: false, status: 'disabled' });
      const summary = buildUpdateSummary(closing(r));
      expect(summary.rows.find((x) => x.label === 'OpenClaw')).toMatchObject({ mark: 'fail' });
      expect(summary.rows.find((x) => x.label === 'Guard')).toMatchObject({ mark: 'fail', text: 'on, but OpenClaw isn\'t running the plugin' });
      expect(summary.headline).toBe('failed');
    });

    it('with no failed check, the OpenClaw row still names the version it is on', async () => {
      const { value: r } = await refusedTwice({ enabled: true, status: 'loaded' });
      const summary = buildUpdateSummary({ ...closing(r), protection: { status: 'unproven', loaded: 'unknown', pluginVersion: BEFORE } });
      expect(summary.rows.find((x) => x.label === 'OpenClaw')).toMatchObject({
        mark: 'check',
        text: `plugin not updated (still on ${BEFORE})`,
        why: 'OpenClaw keeps running the previous plugin.',
      });
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
