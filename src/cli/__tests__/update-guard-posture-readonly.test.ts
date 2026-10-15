/**
 * #773 follow-up — the update closing screen reads the Guard switch without
 * changing anything, and an unreadable config is "unknown", never "off".
 *
 * `getActionGuardCoreConfig()` is not a read-only accessor: on an unsigned
 * config it adopts the file by writing `.config-sig` (minting `.integrity-key`
 * on the way), on a legacy-signed config it self-heals by rewriting
 * `config.json`, and with an unverifiable policy lock it emits an audit event.
 * The update screen only needs to SAY what the switch is, so it must do none of
 * that. Every case here runs in a temp HOME / config dir / protected root.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { createHmac } from 'crypto';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

type ConfigModule = typeof import('../../cloud/config.js');
type UpdateModule = typeof import('../update.js');

const auditCalls: unknown[] = [];

let home: string;
let configDir: string;
let protectedRoot: string;
const saved: Record<string, string | undefined> = {};
const ENV_KEYS = ['HOME', 'SHIELDCORTEX_CONFIG_DIR', 'SHIELDCORTEX_PROTECTED_ROOT'];

/** Fresh module graph per test, with the audit sink replaced by a recorder. */
async function fresh(): Promise<{ config: ConfigModule; clearLockReport: () => void }> {
  jest.resetModules();
  jest.unstable_mockModule('../../defence/iron-dome/audit.js', () => ({
    logIronDomeAudit: (event: unknown) => { auditCalls.push(event); },
  }));
  const config = await import('../../cloud/config.js');
  const lock = await import('../../defence/iron-dome/policy-lock.js');
  lock.clearPolicyLockReportState();
  return { config, clearLockReport: () => lock.clearPolicyLockReportState() };
}

async function freshUpdate(): Promise<UpdateModule> {
  await fresh();
  return import('../update.js');
}

/** Every file under the temp roots: path → bytes + mtime. */
function snapshot(): Map<string, string> {
  const out = new Map<string, string>();
  const walk = (dir: string): void => {
    for (const name of fs.readdirSync(dir)) {
      const p = path.join(dir, name);
      const st = fs.lstatSync(p);
      if (st.isDirectory()) {
        out.set(p, `dir ${st.mtimeMs}`);
        walk(p);
      } else {
        let bytes = '<unreadable>';
        try { bytes = fs.readFileSync(p).toString('base64'); } catch { /* chmod 000 case */ }
        out.set(p, `${st.mtimeMs} ${st.mode} ${bytes}`);
      }
    }
  };
  walk(home);
  walk(protectedRoot);
  return out;
}

/** Let the lazy audit import (fire-and-forget) settle. */
async function settle(): Promise<void> {
  for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r));
}

const KEY = 'a'.repeat(64);
const hmac = (s: string): string => createHmac('sha256', KEY).update(s, 'utf-8').digest('hex');
const file = (name: string): string => path.join(configDir, name);

function writeConfig(obj: unknown): string {
  const content = JSON.stringify(obj, null, 2);
  fs.writeFileSync(file('config.json'), content);
  return content;
}

function writeSameUidLock(policy: unknown = { actionGuard: { enabled: true } }): void {
  fs.writeFileSync(path.join(protectedRoot, 'policy.json'), JSON.stringify(policy, null, 2));
}

const SETUPS: Record<string, () => void> = {
  'unsigned config, no key yet': () => {
    writeConfig({ actionGuard: { enabled: false } });
  },
  'legacy-signed config with a stale embedded sig (self-healable)': () => {
    fs.writeFileSync(file('.integrity-key'), KEY);
    const content = writeConfig({ actionGuard: { enabled: false }, _sig: '0'.repeat(64) });
    fs.writeFileSync(file('.config-sig'), hmac(content));
  },
  'signed config whose integrity key is missing': () => {
    const body = { actionGuard: { enabled: false } };
    writeConfig({ ...body, _sig: hmac(JSON.stringify(body, null, 2)) });
  },
  'policy-locked host (same-UID lock: unverifiable)': () => {
    fs.writeFileSync(file('.integrity-key'), KEY);
    const body = { actionGuard: { enabled: false } };
    writeConfig({ ...body, _sig: hmac(JSON.stringify(body, null, 2)) });
    writeSameUidLock();
  },
};

beforeEach(() => {
  for (const k of ENV_KEYS) saved[k] = process.env[k];
  home = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-773-home-')));
  protectedRoot = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-773-root-')));
  configDir = path.join(home, '.shieldcortex');
  fs.mkdirSync(configDir);
  process.env.HOME = home;
  process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
  process.env.SHIELDCORTEX_PROTECTED_ROOT = protectedRoot;
  auditCalls.length = 0;
  jest.spyOn(console, 'error').mockImplementation(() => undefined);
});

afterEach(() => {
  jest.restoreAllMocks();
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
  try { fs.chmodSync(file('config.json'), 0o600); } catch { /* may not exist */ }
  fs.rmSync(home, { recursive: true, force: true });
  fs.rmSync(protectedRoot, { recursive: true, force: true });
});

describe('the update screen reads the Guard switch without writing', () => {
  for (const [name, setup] of Object.entries(SETUPS)) {
    it(`readActionGuardCoreConfigReadOnly writes nothing: ${name}`, async () => {
      setup();
      const { config } = await fresh();
      const before = snapshot();
      config.readActionGuardCoreConfigReadOnly();
      await settle();
      expect(snapshot()).toEqual(before);
      expect(auditCalls).toEqual([]);
    });

    it(`the update screen's reader writes nothing: ${name}`, async () => {
      setup();
      const update = await freshUpdate();
      const before = snapshot();
      await update.readGuardSwitch();
      await settle();
      expect(snapshot()).toEqual(before);
      expect(fs.existsSync(file('.config-sig'))).toBe(before.has(file('.config-sig')));
      expect(fs.existsSync(file('.integrity-key'))).toBe(before.has(file('.integrity-key')));
      expect(auditCalls).toEqual([]);
    });
  }

  it('a missing integrity key reads as the fail-closed posture, not off', async () => {
    SETUPS['signed config whose integrity key is missing']();
    const { config } = await fresh();
    const core = config.readActionGuardCoreConfigReadOnly();
    expect(core === null || core.enabled === true).toBe(true);
  });

  // Positive controls: the observer can see the writes the mutating path makes.
  it('control: getActionGuardCoreConfig adopts an unsigned config by writing .config-sig and .integrity-key', async () => {
    SETUPS['unsigned config, no key yet']();
    const { config } = await fresh();
    const before = snapshot();
    config.getActionGuardCoreConfig();
    expect(snapshot()).not.toEqual(before);
    expect(fs.existsSync(file('.config-sig'))).toBe(true);
    expect(fs.existsSync(file('.integrity-key'))).toBe(true);
  });

  it('control: getActionGuardCoreConfig self-heals a legacy-signed config by rewriting it', async () => {
    SETUPS['legacy-signed config with a stale embedded sig (self-healable)']();
    const { config } = await fresh();
    const before = snapshot();
    config.getActionGuardCoreConfig();
    expect(snapshot()).not.toEqual(before);
    expect(fs.existsSync(file('.config-sig'))).toBe(false);
  });

  it('control: getActionGuardCoreConfig audits an unverifiable lock', async () => {
    SETUPS['policy-locked host (same-UID lock: unverifiable)']();
    const { config, clearLockReport } = await fresh();
    config.readActionGuardCoreConfigReadOnly();
    await settle();
    expect(auditCalls).toEqual([]);
    clearLockReport();
    config.getActionGuardCoreConfig();
    await settle();
    expect(auditCalls.length).toBeGreaterThan(0);
  });
});

describe('read-only posture equals getActionGuardCoreConfig for every readable config', () => {
  const CASES: Record<string, { config: unknown; lock?: unknown }> = {
    'no config file': { config: undefined },
    'empty object': { config: {} },
    'top-level only, enabled true': { config: { actionGuard: { enabled: true, enforce: false } } },
    'top-level only, enabled false': { config: { actionGuard: { enabled: false } } },
    'top-level, enabled missing': { config: { actionGuard: { enforce: true } } },
    'top-level, enabled "true" (string)': { config: { actionGuard: { enabled: 'true' } } },
    'alias only, enabled true': { config: { interceptor: { actionGuard: { enabled: true, readinessGate: true } } } },
    'alias only, enabled false': { config: { interceptor: { actionGuard: { enabled: false } } } },
    'both, top-level off wins over alias on': {
      config: { actionGuard: { enabled: false }, interceptor: { actionGuard: { enabled: true, enforce: false } } },
    },
    'both, top-level on wins over alias off': {
      config: { actionGuard: { enabled: true }, interceptor: { actionGuard: { enabled: false, readinessGate: true } } },
    },
    'actionGuard is an array (ignored)': { config: { actionGuard: [true], interceptor: { actionGuard: { enabled: true } } } },
    'policy lock forces enabled over a config that says off': {
      config: { actionGuard: { enabled: false, enforce: false } },
      lock: { actionGuard: { enabled: true } },
    },
  };

  for (const [name, c] of Object.entries(CASES)) {
    it(name, async () => {
      if (c.config !== undefined) writeConfig(c.config);
      if (c.lock !== undefined) writeSameUidLock(c.lock);
      const { config } = await fresh();
      const readOnly = config.readActionGuardCoreConfigReadOnly();
      const effective = config.getActionGuardCoreConfig();
      expect(readOnly).toEqual(effective);
    });
  }
});

describe('an unreadable config is unknown, never "off (the default)"', () => {
  async function renderFor(guard: 'on' | 'off' | 'unknown'): Promise<string> {
    const { buildUpdateSummary, renderUpdateSummary } = await import('../update-summary.js');
    // Same mapping runUpdate() uses.
    const input = {
      fromVersion: '5.9.0',
      toVersion: '5.10.0',
      packageState: 'updated' as const,
      engine: { ok: true },
      plugin: { status: 'ok' as const },
      skill: { status: 'ok' as const },
      guardOn: guard !== 'off',
      guardUnknown: guard === 'unknown',
      protection: { status: 'unproven' as const, loaded: 'unknown' as const },
    };
    const summary = buildUpdateSummary(input);
    return renderUpdateSummary(summary, input, { width: 80, ascii: true }).join('\n');
  }

  it('corrupt JSON reads as unknown', async () => {
    fs.writeFileSync(file('config.json'), '{ "actionGuard": { "enabled": tru');
    const update = await freshUpdate();
    const { readActionGuardCoreConfigReadOnly } = await import('../../cloud/config.js');
    expect(readActionGuardCoreConfigReadOnly()).toBeNull();
    const guard = await update.readGuardSwitch();
    expect(guard).toBe('unknown');
    const screen = await renderFor(guard);
    expect(screen).not.toContain('off (the default)');
    expect(screen).toContain('couldn\'t read the Guard setting');
    expect(screen).toContain('shieldcortex doctor');
  });

  const asRoot = process.getuid?.() === 0;
  (asRoot ? it.skip : it)('a config file that cannot be read reads as unknown', async () => {
    writeConfig({ actionGuard: { enabled: false } });
    fs.chmodSync(file('config.json'), 0o000);
    const update = await freshUpdate();
    const { readActionGuardCoreConfigReadOnly } = await import('../../cloud/config.js');
    expect(readActionGuardCoreConfigReadOnly()).toBeNull();
    const guard = await update.readGuardSwitch();
    expect(guard).toBe('unknown');
    expect(await renderFor(guard)).not.toContain('off (the default)');
  });

  it('unknown keeps the row a thing to check; a readable off config is still "off (the default)"', async () => {
    const { buildUpdateSummary } = await import('../update-summary.js');
    const base = {
      fromVersion: '5.9.0', toVersion: '5.10.0', packageState: 'updated' as const,
      engine: { ok: true }, plugin: { status: 'ok' as const }, skill: { status: 'ok' as const },
      protection: { status: 'ok' as const },
    };
    const unknown = buildUpdateSummary({ ...base, guardOn: true, guardUnknown: true });
    expect(unknown.rows.find((r) => r.label === 'Guard')).toMatchObject({ mark: 'check', command: 'shieldcortex doctor' });
    expect(unknown.headline).toBe('check');

    writeConfig({ actionGuard: { enabled: false } });
    const update = await freshUpdate();
    expect(await update.readGuardSwitch()).toBe('off');
    expect(await renderFor('off')).toContain('off (the default)');
  });
});
