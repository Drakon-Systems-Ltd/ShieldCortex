/**
 * #773 follow-up — the update closing screen reads the Guard switch without
 * changing anything, and an unreadable config is "unknown", never "off".
 *
 * `getActionGuardCoreConfig()` is not a read-only accessor: on an unsigned
 * config it adopts the file by writing `.config-sig` (minting `.integrity-key`
 * on the way), on a legacy-signed config it self-heals by rewriting
 * `config.json`, and with an unverifiable policy lock it emits an audit event.
 * The update screen only needs to SAY what the switch is, so it must do none of
 * that, and where the getter's answer depends on one of those writes
 * succeeding, the screen says "unknown" rather than guessing. Every case here
 * runs in a temp HOME / config dir / protected root.
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
async function fresh(): Promise<{ config: ConfigModule }> {
  jest.resetModules();
  jest.unstable_mockModule('../../defence/iron-dome/audit.js', () => ({
    logIronDomeAudit: (event: unknown) => { auditCalls.push(event); },
  }));
  const config = await import('../../cloud/config.js');
  const lock = await import('../../defence/iron-dome/policy-lock.js');
  lock.clearPolicyLockReportState();
  return { config };
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

/** Key + embedded `_sig`: a config the getter verifies without writing. */
function writeSignedConfig(body: Record<string, unknown>): void {
  fs.writeFileSync(file('.integrity-key'), KEY);
  writeConfig({ ...body, _sig: hmac(JSON.stringify(body, null, 2)) });
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
  try { fs.chmodSync(configDir, 0o700); } catch { /* may not exist */ }
  try { fs.chmodSync(file('config.json'), 0o600); } catch { /* may not exist */ }
  try { fs.chmodSync(file('.integrity-key'), 0o600); } catch { /* may not exist */ }
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

  it('a read-only read does not use up the audit a later getActionGuardCoreConfig owes', async () => {
    SETUPS['policy-locked host (same-UID lock: unverifiable)']();
    const { config } = await fresh();
    config.readActionGuardCoreConfigReadOnly();
    await settle();
    expect(auditCalls).toEqual([]);
    // No report-state reset in between: same process, same lock state.
    config.getActionGuardCoreConfig();
    await settle();
    expect(auditCalls.length).toBeGreaterThan(0);
  });
});

describe('read-only posture equals getActionGuardCoreConfig for every signed config', () => {
  const CASES: Record<string, { config: Record<string, unknown> | undefined; lock?: unknown }> = {
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
    // A same-UID lock cannot be verified, so this proves the strict floor for
    // an UNVERIFIABLE lock is applied the same way, not a verified lock.
    'same-UID (unverifiable) policy lock floors a config that says off to strict': {
      config: { actionGuard: { enabled: false, enforce: false } },
      lock: { actionGuard: { enabled: true } },
    },
  };

  for (const [name, c] of Object.entries(CASES)) {
    it(name, async () => {
      if (c.config !== undefined) writeSignedConfig(c.config);
      if (c.lock !== undefined) writeSameUidLock(c.lock);
      const { config } = await fresh();
      const readOnly = config.readActionGuardCoreConfigReadOnly();
      const effective = config.getActionGuardCoreConfig();
      expect(readOnly).not.toBeNull();
      expect(readOnly).toEqual(effective);
    });
  }
});

describe('read-only posture equals getActionGuardCoreConfig across integrity verdicts', () => {
  // Verdicts that do not depend on a write: the read-only answer is definitive.
  // A missing key is 'tampered' whether or not minting one would succeed: a
  // freshly minted random key cannot match the stored signature.
  const INTEGRITY_CASES: Record<string, () => void> = {
    'tampered: embedded sig does not match, no legacy sig': () => {
      fs.writeFileSync(file('.integrity-key'), KEY);
      writeConfig({ actionGuard: { enabled: false }, _sig: '0'.repeat(64) });
    },
    'missing key: embedded-signed config, no .integrity-key': SETUPS['signed config whose integrity key is missing'],
    'self-heal: stale embedded sig, valid legacy sig': SETUPS['legacy-signed config with a stale embedded sig (self-healable)'],
    'signed, enabled false': () => writeSignedConfig({ actionGuard: { enabled: false } }),
    'signed, enabled true': () => writeSignedConfig({ actionGuard: { enabled: true } }),
  };
  for (const [name, setup] of Object.entries(INTEGRITY_CASES)) {
    it(name, async () => {
      setup();
      const { config } = await fresh();
      const readOnly = config.readActionGuardCoreConfigReadOnly();
      const effective = config.getActionGuardCoreConfig();
      expect(readOnly).not.toBeNull();
      expect(readOnly).toEqual(effective);
    });
  }
});

describe('a config with no signature yet is unknown read-only, never off', () => {
  // The getter adopts an unsigned config by writing `.config-sig` (minting
  // `.integrity-key` if needed): 'valid' if that write succeeds, strict if it
  // fails. Read-only cannot know which, so it answers unknown in every case.
  const asRoot = process.getuid?.() === 0;
  const lockedDir = (): string => path.join(home, 'locked');
  const sigDir = (): string => path.join(home, 'sigdir');

  const UNSIGNED: Record<string, { setup: () => void; getterEnabled: boolean; chmod?: boolean }> = {
    'key present, dir writable (adoption succeeds)': {
      setup: () => {
        fs.writeFileSync(file('.integrity-key'), KEY);
        writeConfig({ actionGuard: { enabled: false } });
      },
      getterEnabled: false,
    },
    'readable but unwritable dir, no key': {
      setup: () => {
        writeConfig({ actionGuard: { enabled: false } });
        fs.chmodSync(configDir, 0o500);
      },
      getterEnabled: true,
      chmod: true,
    },
    'readable but unwritable dir, key present': {
      setup: () => {
        fs.writeFileSync(file('.integrity-key'), KEY);
        writeConfig({ actionGuard: { enabled: false } });
        fs.chmodSync(configDir, 0o500);
      },
      getterEnabled: true,
      chmod: true,
    },
    'writable dir, key present but unreadable and unwritable': {
      setup: () => {
        fs.writeFileSync(file('.integrity-key'), KEY);
        fs.chmodSync(file('.integrity-key'), 0o000);
        writeConfig({ actionGuard: { enabled: false } });
      },
      getterEnabled: true,
      chmod: true,
    },
    // B2-R 1: the key write follows a dangling symlink into a mode-500 dir.
    'B2-R key-target-unwritable: .integrity-key is a dangling symlink into a mode-500 dir': {
      setup: () => {
        fs.mkdirSync(lockedDir());
        fs.symlinkSync(path.join(lockedDir(), 'key'), file('.integrity-key'));
        fs.chmodSync(lockedDir(), 0o500);
        writeConfig({ actionGuard: { enabled: false } });
      },
      getterEnabled: true,
      chmod: true,
    },
    // B2-R 2: the sig write follows a dangling symlink into a mode-500 dir.
    'B2-R sig-target-unwritable: .config-sig is a dangling symlink into a mode-500 dir': {
      setup: () => {
        fs.writeFileSync(file('.integrity-key'), KEY);
        fs.mkdirSync(lockedDir());
        fs.symlinkSync(path.join(lockedDir(), 'sig'), file('.config-sig'));
        fs.chmodSync(lockedDir(), 0o500);
        writeConfig({ actionGuard: { enabled: false } });
      },
      getterEnabled: true,
      chmod: true,
    },
    // B2-R 3: the key path is a writable directory, so minting fails.
    'B2-R key-is-directory: .integrity-key is a writable directory': {
      setup: () => {
        fs.mkdirSync(file('.integrity-key'));
        writeConfig({ actionGuard: { enabled: false } });
      },
      getterEnabled: true,
    },
    // N1: the dir is not writable, but the sig write goes through a symlink to
    // a writable dir, so adoption succeeds and the getter reports off.
    'N1 sig-via-symlink: mode-500 config dir, .config-sig symlinks into a writable dir': {
      setup: () => {
        fs.writeFileSync(file('.integrity-key'), KEY);
        fs.mkdirSync(sigDir());
        fs.symlinkSync(path.join(sigDir(), 'sig'), file('.config-sig'));
        writeConfig({ actionGuard: { enabled: false } });
        fs.chmodSync(configDir, 0o500);
      },
      getterEnabled: false,
      chmod: true,
    },
  };

  for (const [name, c] of Object.entries(UNSIGNED)) {
    (c.chmod && asRoot ? it.skip : it)(name, async () => {
      try {
        c.setup();
        const update = await freshUpdate();
        const { readActionGuardCoreConfigReadOnly, getActionGuardCoreConfig } = await import('../../cloud/config.js');
        const before = snapshot();
        expect(readActionGuardCoreConfigReadOnly()).toBeNull();
        expect(await update.readGuardSwitch()).toBe('unknown');
        await settle();
        expect(snapshot()).toEqual(before);
        // What the getter then reports, by writing: either answer was possible.
        expect(getActionGuardCoreConfig().enabled).toBe(c.getterEnabled);
      } finally {
        try { fs.chmodSync(lockedDir(), 0o700); } catch { /* may not exist */ }
        fs.chmodSync(configDir, 0o700);
      }
    });
  }

  // B3: a strict verdict the getter cached after a failed adoption outlives
  // the permission problem (config.json's mtime is unchanged). One process, no
  // cache or report-state reset between steps.
  (asRoot ? it.skip : it)('B3: strict cached after a failed adoption, permissions since recovered, is unknown', async () => {
    try {
      writeConfig({ actionGuard: { enabled: false } });
      const { config } = await fresh();
      fs.chmodSync(configDir, 0o500);
      expect(config.getActionGuardCoreConfig().enabled).toBe(true); // adoption fails, strict cached
      fs.chmodSync(configDir, 0o700);
      expect(config.readActionGuardCoreConfigReadOnly()).toBeNull();
      const update = await import('../update.js'); // same module graph, cache still warm
      const guard = await update.readGuardSwitch();
      expect(guard).toBe('unknown');
      expect(config.getActionGuardCoreConfig().enabled).toBe(true); // still the cached strict verdict
      const { buildUpdateSummary } = await import('../update-summary.js');
      const summary = buildUpdateSummary({
        fromVersion: '5.9.0', toVersion: '5.10.0', packageState: 'updated',
        engine: { ok: true }, plugin: { status: 'ok' }, skill: { status: 'ok' },
        guardOn: guard !== 'off', guardUnknown: guard === 'unknown',
        protection: { status: 'ok' },
      });
      expect(summary.headline).toBe('check');
      expect(summary.rows.find((r) => r.label === 'Guard')).toMatchObject({ mark: 'check' });
    } finally {
      fs.chmodSync(configDir, 0o700);
    }
  });

  // B3-R3: empty/whitespace early-return used to skip the cache-disagreement
  // check, so a file blanked in place (same size, mtime restored) read as off
  // while the getter still served cached strict-ON. #878 r2 keys the cache on
  // ctime too, which nothing restores: the getter re-reads the blanked file,
  // so the two readers agree on what is now enforced instead of disagreeing.
  // (The disagreement check stays for filesystems that do not track ctime.)
  (asRoot ? it.skip : it)('B3-R3: emptying config.json in place after a cached strict verdict is re-read by both readers', async () => {
    try {
      writeConfig({ actionGuard: { enabled: false } });
      const { config } = await fresh();
      fs.chmodSync(configDir, 0o500);
      expect(config.getActionGuardCoreConfig().enabled).toBe(true); // adoption fails, strict cached
      fs.chmodSync(configDir, 0o700);
      const cfg = file('config.json');
      const st = fs.statSync(cfg);
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 30); // coarse ctime clock
      fs.writeFileSync(cfg, ' '.repeat(st.size - 1) + '\n');
      fs.utimesSync(cfg, st.atime, st.mtime);
      const after = fs.statSync(cfg);
      expect([after.ino, after.size]).toEqual([st.ino, st.size]);
      expect(Math.abs(after.mtimeMs - st.mtimeMs)).toBeLessThan(1); // within the read-only tolerance
      expect(after.ctimeMs).not.toBe(st.ctimeMs);
      // The getter no longer answers from its cached strict verdict...
      expect(config.getActionGuardCoreConfig().enabled).toBe(false);
      // ...so the read-only reader has nothing to disagree with.
      expect(config.readActionGuardCoreConfigReadOnly()).toEqual({ enabled: false, enforce: true, readinessGate: false });
      const update = await import('../update.js');
      expect(await update.readGuardSwitch()).toBe('off');
    } finally {
      fs.chmodSync(configDir, 0o700);
    }
  });

  // Same shape on a signed config: the key could not be read (or replaced), so
  // the getter cached strict; the key is readable again but config.json is
  // unchanged, so the getter keeps answering from its cache.
  (asRoot ? it.skip : it)('a strict verdict cached while the key was unreadable is unknown after the key recovers', async () => {
    try {
      writeSignedConfig({ actionGuard: { enabled: false } });
      fs.chmodSync(file('.integrity-key'), 0o000);
      const { config } = await fresh();
      expect(config.getActionGuardCoreConfig().enabled).toBe(true);
      fs.chmodSync(file('.integrity-key'), 0o600);
      expect(config.readActionGuardCoreConfigReadOnly()).toBeNull();
      expect(config.getActionGuardCoreConfig().enabled).toBe(true);
    } finally {
      fs.chmodSync(file('.integrity-key'), 0o600);
    }
  });
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
    expect(screen).toContain('couldn\'t confirm the Guard setting');
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

  async function expectUnknownScreen(): Promise<void> {
    const update = await freshUpdate();
    const { readActionGuardCoreConfigReadOnly } = await import('../../cloud/config.js');
    expect(readActionGuardCoreConfigReadOnly()).toBeNull();
    const guard = await update.readGuardSwitch();
    expect(guard).toBe('unknown');
    const screen = await renderFor(guard);
    expect(screen).not.toContain('off (the default)');
    expect(screen).toMatch(/\[!\]\s+Guard\s+couldn't confirm the Guard setting/);
    expect(screen).toContain('couldn\'t confirm the Guard setting');
    expect(screen.split('\n')[0]).toMatch(/things? to check/);
  }

  (asRoot ? it.skip : it)('a config dir that cannot be entered reads as unknown, not off', async () => {
    writeConfig({ actionGuard: { enabled: true } });
    fs.chmodSync(configDir, 0o000);
    try {
      await expectUnknownScreen();
    } finally {
      fs.chmodSync(configDir, 0o700);
    }
  });

  (asRoot ? it.skip : it)('a warm cache does not hide read permission lost since the last read', async () => {
    writeConfig({ actionGuard: { enabled: false } });
    const { config } = await fresh();
    expect(config.getActionGuardCoreConfig().enabled).toBe(false); // warms the raw cache
    fs.chmodSync(file('config.json'), 0o000); // mtime unchanged: the cache key still matches
    expect(config.readActionGuardCoreConfigReadOnly()).toBeNull();
    const update = await import('../update.js'); // same module graph, cache still warm
    const guard = await update.readGuardSwitch();
    expect(guard).toBe('unknown');
    const screen = await renderFor(guard);
    expect(screen).not.toContain('off (the default)');
    expect(screen).toContain('couldn\'t confirm the Guard setting');
  });

  it('a dangling config.json symlink is unknown, not off', async () => {
    fs.symlinkSync(path.join(configDir, 'missing-target.json'), file('config.json'));
    expect(fs.lstatSync(file('config.json')).isSymbolicLink()).toBe(true);
    const update = await freshUpdate();
    const { readActionGuardCoreConfigReadOnly } = await import('../../cloud/config.js');
    expect(readActionGuardCoreConfigReadOnly()).toBeNull();
    const guard = await update.readGuardSwitch();
    expect(guard).toBe('unknown');
    expect(await renderFor(guard)).not.toContain('off (the default)');
    expect(await renderFor(guard)).toContain('couldn\'t confirm the Guard setting');
  });

  it('a genuinely missing config (or config dir) is still off', async () => {
    let update = await freshUpdate();
    expect(await update.readGuardSwitch()).toBe('off');
    fs.rmSync(configDir, { recursive: true, force: true });
    update = await freshUpdate();
    expect(await update.readGuardSwitch()).toBe('off');
  });

  it('unknown Guard with a failed OpenClaw check: red OpenClaw row and a failed headline', async () => {
    const { buildUpdateSummary, renderUpdateSummary } = await import('../update-summary.js');
    const input = {
      fromVersion: '5.9.0', toVersion: '5.10.0', packageState: 'updated' as const,
      engine: { ok: true }, plugin: { status: 'ok' as const }, skill: { status: 'ok' as const },
      guardOn: true, guardUnknown: true,
      protection: { status: 'failed' as const, loaded: 'no' as const },
    };
    const summary = buildUpdateSummary(input);
    expect(summary.headline).toBe('failed');
    expect(summary.rows.find((r) => r.label === 'OpenClaw')).toMatchObject({ mark: 'fail' });
    expect(summary.rows.find((r) => r.label === 'Guard')).toMatchObject({ mark: 'check', text: 'couldn\'t confirm the Guard setting' });
    const lines = renderUpdateSummary(summary, input, { width: 80, ascii: true });
    expect(lines[0]).toMatch(/^Update failed/);
    expect(lines.join('\n')).toMatch(/\[x\]\s+OpenClaw\s+the gateway started without/);
  });

  it('a genuinely empty or whitespace-only config with a cold cache is still off', async () => {
    fs.writeFileSync(file('config.json'), '');
    let update = await freshUpdate();
    expect(await update.readGuardSwitch()).toBe('off');
    fs.writeFileSync(file('config.json'), '  \n');
    update = await freshUpdate();
    expect(await update.readGuardSwitch()).toBe('off');
  });

  it('unknown keeps the row a thing to check; a signed off config is still "off (the default)"', async () => {
    const { buildUpdateSummary } = await import('../update-summary.js');
    const base = {
      fromVersion: '5.9.0', toVersion: '5.10.0', packageState: 'updated' as const,
      engine: { ok: true }, plugin: { status: 'ok' as const }, skill: { status: 'ok' as const },
      protection: { status: 'ok' as const },
    };
    const unknown = buildUpdateSummary({ ...base, guardOn: true, guardUnknown: true });
    expect(unknown.rows.find((r) => r.label === 'Guard')).toMatchObject({ mark: 'check', command: 'shieldcortex doctor' });
    expect(unknown.headline).toBe('check');

    writeSignedConfig({ actionGuard: { enabled: false } });
    const update = await freshUpdate();
    expect(await update.readGuardSwitch()).toBe('off');
    expect(await renderFor('off')).toContain('off (the default)');
  });
});
