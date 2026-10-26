/**
 * #922 slice 1 (PR-A): `shieldcortex guard posture`, read-only.
 *
 * Exit 0 when the planes agree (or none is present), 4 when they disagree,
 * 1 for any argument other than `--json` — there is no writer in this
 * release, so a posture word is a usage error, never a write.
 *
 * Isolation as in doctor-guard-posture-922: one temp dir holds the config
 * dir, protected root, OpenClaw home and the mocked os.homedir().
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeAll, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { snapshot } from '../../posture/__tests__/self-report-fixture.js';

type Guard = typeof import('../guard.js');
type Config = typeof import('../../cloud/config.js');

let guard: Guard;
let config: Config;
let PROTECTED_ROOT_ENV: string;

beforeAll(async () => {
  ({ PROTECTED_ROOT_ENV } = await import('../../defence/iron-dome/protected-root.js'));
  config = await import('../../cloud/config.js');
  guard = await import('../guard.js');
});

let tmp: string;
let home: string;
let configDir: string;
let saved: Record<string, string | undefined>;
let out: string[];
let err: string[];

function signed(actionGuard: Record<string, unknown>): void {
  fs.writeFileSync(path.join(configDir, 'config.json'), JSON.stringify({ actionGuard }));
  config.clearCloudConfigCache();
}

function openclawEntry(entry: Record<string, unknown>): void {
  fs.mkdirSync(path.join(home, '.openclaw'), { recursive: true });
  fs.writeFileSync(path.join(home, '.openclaw', 'openclaw.json'), JSON.stringify({
    plugins: { entries: { 'shieldcortex-realtime': entry } },
  }));
}

function claudeHookWired(): void {
  fs.mkdirSync(path.join(home, '.claude'), { recursive: true });
  fs.writeFileSync(path.join(home, '.claude', 'settings.json'), JSON.stringify({
    hooks: { PreToolUse: [{ hooks: [{ type: 'command', command: 'npx shieldcortex hook pre-tool-use' }] }] },
  }));
}

async function run(...argv: string[]): Promise<number> {
  out = [];
  err = [];
  return guard.runGuardCommand(['posture', ...argv], { home });
}

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-922-cmd-'));
  home = path.join(tmp, 'home');
  configDir = path.join(tmp, 'cfg');
  fs.mkdirSync(home);
  fs.mkdirSync(configDir);
  fs.mkdirSync(path.join(tmp, 'root'));
  saved = {
    SHIELDCORTEX_CONFIG_DIR: process.env.SHIELDCORTEX_CONFIG_DIR,
    [PROTECTED_ROOT_ENV]: process.env[PROTECTED_ROOT_ENV],
    OPENCLAW_HOME: process.env.OPENCLAW_HOME,
  };
  process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
  process.env[PROTECTED_ROOT_ENV] = path.join(tmp, 'root');
  process.env.OPENCLAW_HOME = home;
  jest.spyOn(os, 'homedir').mockReturnValue(home);
  jest.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.map(String).join(' ')); });
  jest.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { err.push(a.map(String).join(' ')); });
  config.clearCloudConfigCache();
});

afterEach(() => {
  jest.restoreAllMocks();
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  config.clearCloudConfigCache();
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe('#922 shieldcortex guard posture (read-only)', () => {
  it('agreeing planes exit 0 and list every plane, absent ones included', async () => {
    claudeHookWired();
    signed({ enabled: true, enforce: false });
    expect(await run()).toBe(0);
    const text = out.join('\n');
    expect(text).toMatch(/^Action Guard posture \(read-only\) — signed: advisory/);
    expect(text).toMatch(/Claude Code hook\s+advisory\s+config\.json actionGuard/);
    expect(text).toMatch(/OpenClaw plugin\s+absent/);
    expect(text).toMatch(/Hermes\s+absent/);
    expect(text).toMatch(/^WARN: advisory on the one compared plane \(Claude Code hook\)/m);
  });

  it('the #634 shape exits 4 and prints the overriding key and a fix with no enabling command', async () => {
    claudeHookWired();
    signed({ enabled: true, enforce: true });
    openclawEntry({ enabled: true, config: { actionGuard: { enforce: false } } });
    expect(await run()).toBe(guard.GUARD_POSTURE_MISMATCH_EXIT);
    expect(guard.GUARD_POSTURE_MISMATCH_EXIT).toBe(4);
    const text = out.join('\n');
    expect(text).toMatch(/OpenClaw plugin\s+advisory\s+.*openclaw\.json plugin entry actionGuard\.enforce=false overrides signed/);
    expect(text).toMatch(/^MISMATCH: planes disagree/m);
    expect(text).toMatch(/^Fix: /m);
    expect(text).not.toMatch(/`[^`]*(guard posture (advisory|enforce)|--action-guard-(enable|enforce))[^`]*`/);
  });

  it('no plane present exits 0 and says so', async () => {
    expect(await run()).toBe(0);
    expect(out.join('\n')).toMatch(/no gate plane is installed on this box/);
  });

  it('--json is the report plus the doctor row, parseable, with the same exit code', async () => {
    claudeHookWired();
    signed({ enabled: true, enforce: true });
    openclawEntry({ enabled: true, config: { actionGuard: { enforce: false } } });
    expect(await run('--json')).toBe(4);
    const parsed = JSON.parse(out.join('\n'));
    expect(parsed.verdict).toBe('mismatch');
    expect(parsed.signed).toBe('enforce');
    expect(parsed.planes.map((p: { plane: string; posture: string }) => [p.plane, p.posture])).toEqual([
      ['claude', 'enforce'],
      ['openclaw', 'advisory'],
    ]);
    expect(parsed.row.label).toBe('Action guard posture');
    expect(parsed.row.status).toBe('fail');
  });

  it.each([['off'], ['advisory'], ['enforce'], ['--dry-run'], ['--yes']])(
    '`guard posture %s` is a usage error (exit 1) and writes nothing',
    async (arg) => {
      claudeHookWired();
      signed({ enabled: true, enforce: true });
      openclawEntry({ enabled: true, config: { actionGuard: { enforce: false } } });
      const before = snapshot(tmp);
      expect(await run(arg)).toBe(1);
      expect(err.join('\n')).toMatch(/only reads; it takes no posture argument in this release/);
      expect(snapshot(tmp)).toEqual(before);
    },
  );

  it('reading the posture leaves the whole tree byte-identical', async () => {
    claudeHookWired();
    signed({ enabled: false });
    openclawEntry({ enabled: true, config: { actionGuard: { enabled: true } } });
    const before = snapshot(tmp);
    expect(await run()).toBe(4);
    expect(await run('--json')).toBe(4);
    expect(snapshot(tmp)).toEqual(before);
  });

  it('`guard --help` documents the read-only subcommand and where each plane reads its posture', async () => {
    out = [];
    expect(await guard.runGuardCommand(['--help'])).toBe(0);
    const help = out.join('\n');
    expect(help).toMatch(/shieldcortex guard posture \[--json\]/);
    expect(help).toMatch(/read-only/);
    expect(help).toMatch(/SHIELDCORTEX_ENFORCE in the Hermes gateway environment/);
  });
});
