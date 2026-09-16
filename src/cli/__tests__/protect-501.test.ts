/**
 * #501 — `shieldcortex protect`, `config --policy-status`, and the two doctor
 * rows.
 *
 * The write path cannot be exercised here: writing a genuinely uid-0-owned file
 * needs privilege, and a suite that ran privileged would be asserting against a
 * host where the lock is meaningless anyway. What CAN be asserted without it,
 * and is asserted here, is everything that decides whether the write is correct
 * — the refusal, the policy that would be written, and what an operator is told
 * afterwards. The ownership rules themselves are covered against the injected
 * seam in `src/defence/iron-dome/__tests__/protected-root-501.test.ts`, and the
 * privileged case is the CI job in the design doc.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import {
  buildLockedPolicy,
  parseProtectArgs,
  policyStatusLines,
  resolveSourceConfigPath,
  runProtect,
} from '../protect.js';
import { POLICY_LOCK_FILENAME, clearPolicyLockReportState } from '../../defence/iron-dome/policy-lock.js';
import { PROTECTED_ROOT_ENV } from '../../defence/iron-dome/protected-root.js';

const OPTS = { dryRun: false, fromConfig: false } as const;

let protectedRoot: string;
let configDir: string;
let prevProtectedRoot: string | undefined;
let prevConfigDir: string | undefined;

beforeEach(() => {
  protectedRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-501-protect-root-'));
  configDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-501-protect-cfg-'));
  prevProtectedRoot = process.env[PROTECTED_ROOT_ENV];
  prevConfigDir = process.env.SHIELDCORTEX_CONFIG_DIR;
  process.env[PROTECTED_ROOT_ENV] = protectedRoot;
  process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
  clearPolicyLockReportState();
});

afterEach(() => {
  jest.restoreAllMocks();
  if (prevProtectedRoot === undefined) delete process.env[PROTECTED_ROOT_ENV];
  else process.env[PROTECTED_ROOT_ENV] = prevProtectedRoot;
  if (prevConfigDir === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
  else process.env.SHIELDCORTEX_CONFIG_DIR = prevConfigDir;
  fs.rmSync(protectedRoot, { recursive: true, force: true });
  fs.rmSync(configDir, { recursive: true, force: true });
});

describe('#501 parseProtectArgs', () => {
  it('defaults to a real write of the safe posture', () => {
    expect(parseProtectArgs([])).toEqual({ dryRun: false, fromConfig: false, sourceConfig: undefined });
  });

  it('reads --dry-run, --from-config and --config <path>', () => {
    expect(parseProtectArgs(['--dry-run', '--from-config', '--config', '/tmp/x.json']))
      .toEqual({ dryRun: true, fromConfig: true, sourceConfig: '/tmp/x.json' });
  });

  it('ignores a --config with no value', () => {
    expect(parseProtectArgs(['--config', '--dry-run']).sourceConfig).toBeUndefined();
  });
});

describe('#501 buildLockedPolicy — what protect would pin', () => {
  it('forces the guard ON by default, whatever the config says', () => {
    // A command called `protect` that froze the guard OFF because that happened
    // to be today's config would be a trap.
    const policy = buildLockedPolicy({ actionGuard: { enabled: false, enforce: false } }, OPTS);
    expect(policy.actionGuard).toMatchObject({ enabled: true, enforce: true });
  });

  it('--from-config pins exactly what the config says, including off', () => {
    const policy = buildLockedPolicy(
      { actionGuard: { enabled: false, enforce: false } },
      { ...OPTS, fromConfig: true },
    );
    expect(policy.actionGuard).toMatchObject({ enabled: false, enforce: false });
  });

  it('carries autoApprove through as the ceiling, dropping non-strings', () => {
    const policy = buildLockedPolicy({ actionGuard: { autoApprove: ['ls', 7, 'git status'] } }, OPTS);
    expect(policy.actionGuard?.autoApprove).toEqual(['ls', 'git status']);
  });

  it('pins an empty ceiling when the config has no autoApprove', () => {
    expect(buildLockedPolicy({}, OPTS).actionGuard?.autoApprove).toEqual([]);
  });

  it('pins the broker off unless the config explicitly enabled it', () => {
    expect(buildLockedPolicy({}, OPTS).actionGuard?.broker).toEqual({ enabled: false });
    expect(buildLockedPolicy({ actionGuard: { broker: { enabled: true } } }, OPTS).actionGuard?.broker)
      .toEqual({ enabled: true });
  });

  it('applies the #209 alias merge — top-level wins, alias gap-fills', () => {
    const policy = buildLockedPolicy({
      actionGuard: { autoApprove: ['top'] },
      interceptor: { actionGuard: { autoApprove: ['alias'], broker: { enabled: true } } },
    }, OPTS);
    expect(policy.actionGuard?.autoApprove).toEqual(['top']);
    expect(policy.actionGuard?.broker).toEqual({ enabled: true });
  });

  it('pins defenceMode when the config sets a valid one, and omits junk', () => {
    expect(buildLockedPolicy({ defenceMode: 'strict' }, OPTS).defenceMode).toBe('strict');
    expect(buildLockedPolicy({ defenceMode: 'paranoid' }, OPTS).defenceMode).toBeUndefined();
  });

  it('omits the memory block entirely when nothing is configured', () => {
    // A lock that invented a posture nobody chose would be pinning the
    // operator's config to a value they never set.
    expect(buildLockedPolicy({}, OPTS).memory).toBeUndefined();
  });

  it('pins the sidecar-posture pair when the config declares it', () => {
    const policy = buildLockedPolicy({
      memory: { hostContract: { posture: 'mcp_sidecar_no_inject' }, inject: { mode: 'off' } },
    }, OPTS);
    expect(policy.memory).toEqual({ hostContract: { posture: 'mcp_sidecar_no_inject' }, inject: { mode: 'off' } });
  });

  it('stamps the schema version, so a later reader knows what it has', () => {
    expect(buildLockedPolicy({}, OPTS).version).toBe(1);
  });
});

describe('#501 resolveSourceConfigPath', () => {
  it('honours an explicit --config', () => {
    expect(resolveSourceConfigPath({ ...OPTS, sourceConfig: '/tmp/explicit.json' })).toBe('/tmp/explicit.json');
  });

  it('honours SHIELDCORTEX_CONFIG_DIR ahead of any guess', () => {
    expect(resolveSourceConfigPath(OPTS)).toBe(path.join(configDir, 'config.json'));
  });
});

describe('#501 runProtect refuses to write a lock it could rewrite', () => {
  it('refuses when the process is unprivileged, and says why', () => {
    // This suite runs unprivileged, which IS the case under test. Running it
    // the other way would assert nothing, so skip honestly rather than pass
    // vacuously.
    if (typeof process.geteuid === 'function' && process.geteuid() === 0) return;
    const result = runProtect([]);
    expect(result.code).toBe(1);
    const text = result.lines.join('\n');
    expect(text).toMatch(/Refusing to write the policy lock/);
    expect(text).toMatch(/not privileged/);
    expect(text).toMatch(/`shieldcortex protect` as root/);
    expect(text).toMatch(/--dry-run/);
    expect(fs.existsSync(path.join(protectedRoot, POLICY_LOCK_FILENAME))).toBe(false);
  });

  it('--dry-run needs no privilege, writes nothing, and shows the exact policy', () => {
    fs.writeFileSync(path.join(configDir, 'config.json'), JSON.stringify({
      actionGuard: { enabled: false, autoApprove: ['ls'] },
      defenceMode: 'balanced',
    }));
    const result = runProtect(['--dry-run']);
    expect(result.code).toBe(0);
    const text = result.lines.join('\n');
    expect(text).toMatch(/Would write/);
    expect(text).toMatch(/"enabled": true/);
    expect(text).toMatch(/"ls"/);
    expect(text).toMatch(/only TIGHTEN/);
    expect(fs.existsSync(path.join(protectedRoot, POLICY_LOCK_FILENAME))).toBe(false);
  });

  it('--dry-run says so plainly when there is no config to read', () => {
    expect(runProtect(['--dry-run']).lines.join('\n')).toMatch(/No config at .* — pinning defaults/);
  });

  it('--dry-run warns rather than guessing when the config is corrupt', () => {
    fs.writeFileSync(path.join(configDir, 'config.json'), '{ not json');
    const result = runProtect(['--dry-run']);
    expect(result.lines.join('\n')).toMatch(/could not be parsed — pinning defaults/);
    expect(result.code).toBe(0);
  });
});

describe('#501 config --policy-status', () => {
  it('names the risk when the host is unlocked, and what to run', () => {
    const text = policyStatusLines().join('\n');
    expect(text).toMatch(/policy unlocked: a same-user process can disable the guard/);
    expect(text).toMatch(/`shieldcortex protect` as root/);
  });

  it('describes an unverifiable lock and the posture it forces', () => {
    fs.writeFileSync(path.join(protectedRoot, POLICY_LOCK_FILENAME), JSON.stringify({ actionGuard: { enabled: true } }));
    const text = policyStatusLines().join('\n');
    expect(text).toMatch(/UNVERIFIABLE/);
    expect(text).toMatch(/strict fail-closed posture/);
    expect(text).toMatch(/actionGuard\.enabled = true/);
  });

  it('never warns on stderr just for being asked — it is a read', () => {
    fs.writeFileSync(path.join(protectedRoot, POLICY_LOCK_FILENAME), '{ broken');
    const spy = jest.spyOn(console, 'error').mockImplementation(() => undefined);
    policyStatusLines();
    const calls = spy.mock.calls.length;
    spy.mockRestore();
    expect(calls).toBe(0);
  });
});

describe('#501 doctor rows', () => {
  async function rows() {
    const { policyLockRows } = await import('../doctor.js');
    return policyLockRows();
  }

  it('FAILS on an unlocked host while the guard is enabled', async () => {
    fs.writeFileSync(path.join(configDir, 'config.json'), JSON.stringify({ actionGuard: { enabled: true } }));
    const lock = (await rows()).find((r) => r.label.includes('policy lock'))!;
    expect(lock.status).toBe('fail');
    expect(lock.message).toMatch(/policy unlocked: a same-user process can disable the guard/);
    expect(lock.fix).toMatch(/`shieldcortex protect` as root/);
  });

  it('only WARNS on an unlocked host while the guard is off', async () => {
    fs.writeFileSync(path.join(configDir, 'config.json'), JSON.stringify({ actionGuard: { enabled: false } }));
    const lock = (await rows()).find((r) => r.label.includes('policy lock'))!;
    expect(lock.status).toBe('warn');
    expect(lock.message).toMatch(/nothing pinned to lose yet/);
  });

  it('FAILS on a lock that exists but cannot be verified', async () => {
    fs.writeFileSync(path.join(protectedRoot, POLICY_LOCK_FILENAME), JSON.stringify({ actionGuard: { enabled: true } }));
    const lock = (await rows()).find((r) => r.label.includes('policy lock'))!;
    expect(lock.status).toBe('fail');
    expect(lock.message).toMatch(/UNVERIFIABLE/);
  });

  it('describes the integrity signature as a corruption check, pointing at the lock for the rest', async () => {
    const integrity = (await rows()).find((r) => r.label.includes('config integrity'))!;
    expect(integrity.message).toMatch(/corruption/i);
    expect(integrity.message).toMatch(/not tamper protection/);
    expect(integrity.message).toMatch(/policy lock/);
  });

  it('always emits both rows, so a green half cannot hide a red one', async () => {
    const labels = (await rows()).map((r) => r.label);
    expect(labels.filter((l) => l.includes('policy lock'))).toHaveLength(1);
    expect(labels.filter((l) => l.includes('config integrity'))).toHaveLength(1);
  });
});
