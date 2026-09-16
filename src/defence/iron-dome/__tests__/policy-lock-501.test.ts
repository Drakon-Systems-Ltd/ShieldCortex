/**
 * #501 — the policy lock: precedence, fail-closed posture, and refusals.
 *
 * Every case runs against the injected stat seam, so the ROOT-OWNED positive
 * path — the one that is otherwise unreachable without real sudo — is asserted
 * here alongside the negative ones, rather than assumed.
 */
import { beforeEach, describe, expect, it, jest } from '@jest/globals';
import {
  DEFAULT_PROTECTED_ROOT,
  POLICY_LOCK_FILENAME,
  PROTECTED_POLICY_KEYS_V1,
  PolicyLockRefusal,
  STRICT_FAILCLOSED_POSTURE,
  applyPolicyLock,
  applyStrictFailClosedPosture,
  assertPolicyLockAllows,
  clearPolicyLockReportState,
  describePolicyLock,
  isPolicyKeyLocked,
  policyLockCoverage,
  readPolicyLock,
  wouldLoosen,
  type PolicyLockState,
} from '../policy-lock.js';
import type { ProtectedFsSeam, ProtectedStat } from '../protected-root.js';

const AGENT_UID = 1001;
const LOCK_PATH = `${DEFAULT_PROTECTED_ROOT}/${POLICY_LOCK_FILENAME}`;

type Entry = { uid?: number; mode?: number; kind?: 'file' | 'dir' | 'symlink'; target?: string };

function seamOf(
  entries: Record<string, Entry>,
  files: Record<string, string> = {},
  opts: { platform?: NodeJS.Platform; euid?: number | null } = {},
): ProtectedFsSeam {
  const stat = (path: string, follow: boolean): ProtectedStat | null => {
    const e = entries[path];
    if (!e) return null;
    const kind = e.kind ?? 'file';
    if (kind === 'symlink' && follow) return e.target ? stat(e.target, true) : null;
    return {
      uid: e.uid ?? 0,
      gid: 0,
      mode: e.mode ?? (kind === 'dir' ? 0o40755 : 0o100644),
      isFile: kind === 'file',
      isDirectory: kind === 'dir',
      isSymbolicLink: kind === 'symlink',
    };
  };
  return {
    lstat: (p) => stat(p, false),
    stat: (p) => stat(p, true),
    readlink: (p) => {
      const e = entries[p];
      return e?.kind === 'symlink' && e.target ? e.target : null;
    },
    readFile: (p) => files[p] ?? null,
    geteuid: () => (opts.euid === undefined ? AGENT_UID : opts.euid),
    platform: opts.platform ?? 'linux',
    env: () => undefined,
  };
}

/** A host whose /etc/shieldcortex/policy.json is genuinely root-owned. */
function lockedSeam(policy: unknown, overrides: Record<string, Entry> = {}): ProtectedFsSeam {
  return seamOf(
    {
      '/': { kind: 'dir', mode: 0o40755 },
      '/etc': { kind: 'dir', mode: 0o40755 },
      [DEFAULT_PROTECTED_ROOT]: { kind: 'dir', mode: 0o40755 },
      [LOCK_PATH]: { kind: 'file', mode: 0o100644 },
      ...overrides,
    },
    { [LOCK_PATH]: typeof policy === 'string' ? policy : JSON.stringify(policy) },
  );
}

const UNLOCKED_SEAM = seamOf({ '/': { kind: 'dir', mode: 0o40755 }, '/etc': { kind: 'dir', mode: 0o40755 } });

const FULL_POLICY = {
  version: 1,
  actionGuard: { enabled: true, enforce: true, autoApprove: ['ls', 'git status'], broker: { enabled: false } },
  defenceMode: 'balanced',
  memory: { hostContract: { posture: 'mcp_sidecar_no_inject' }, inject: { mode: 'off' } },
};

function silently<T>(fn: () => T): T {
  const spy = jest.spyOn(console, 'error').mockImplementation(() => undefined);
  try { return fn(); } finally { spy.mockRestore(); }
}

beforeEach(() => clearPolicyLockReportState());

describe('#501 readPolicyLock — what the host actually is', () => {
  it('reads a verified, root-owned lock', () => {
    const state = readPolicyLock({ seam: lockedSeam(FULL_POLICY) });
    expect(state.status).toBe('locked');
    expect(state.status === 'locked' && state.policy.actionGuard?.enabled).toBe(true);
    expect(state.path).toBe(LOCK_PATH);
  });

  it('reports an absent lock as absent, not as a failure', () => {
    const state = readPolicyLock({ seam: UNLOCKED_SEAM });
    expect(state).toEqual({ status: 'absent', path: LOCK_PATH });
  });

  it.each([
    ['owned by the agent uid', { [LOCK_PATH]: { kind: 'file' as const, uid: AGENT_UID } }, 'owned-by-agent'],
    ['in an agent-owned directory', { [DEFAULT_PROTECTED_ROOT]: { kind: 'dir' as const, uid: AGENT_UID } }, 'parent-owned-by-agent'],
    ['in a world-writable directory', { [DEFAULT_PROTECTED_ROOT]: { kind: 'dir' as const, mode: 0o40777 } }, 'parent-group-or-other-writable'],
    ['a symlink', { [LOCK_PATH]: { kind: 'symlink' as const, target: '/etc/shieldcortex/real.json' } }, 'symlink'],
  ])('reports a lock %s as unverifiable (%#)', (_label, overrides, reason) => {
    const state = silently(() => readPolicyLock({ seam: lockedSeam(FULL_POLICY, overrides) }));
    expect(state.status).toBe('unverifiable');
    expect(state.status === 'unverifiable' && state.reason).toBe(reason);
  });

  it('reports unparseable JSON as unverifiable', () => {
    const state = silently(() => readPolicyLock({ seam: lockedSeam('{ not json') }));
    expect(state.status === 'unverifiable' && state.reason).toBe('parse-failed');
  });

  it.each([
    ['a non-object top level', '[]'],
    ['a string where a boolean belongs', JSON.stringify({ actionGuard: { enabled: 'true' } })],
    ['a non-array autoApprove', JSON.stringify({ actionGuard: { autoApprove: 'ls' } })],
    ['a non-string autoApprove entry', JSON.stringify({ actionGuard: { autoApprove: ['ls', 7] } })],
    ['an invalid defenceMode', JSON.stringify({ defenceMode: 'paranoid' })],
    // #522 review round-6 follow-up (F2): `x in DEFENCE_MODE_RANK` used to
    // answer `true` for any inherited Object.prototype key. These must be
    // rejected exactly like 'paranoid' — a schema failure, not a mode.
    ['a defenceMode of "toString" (Object.prototype key)', JSON.stringify({ defenceMode: 'toString' })],
    ['a defenceMode of "constructor" (Object.prototype key)', JSON.stringify({ defenceMode: 'constructor' })],
    ['a defenceMode of "hasOwnProperty" (Object.prototype key)', JSON.stringify({ defenceMode: 'hasOwnProperty' })],
    ['a defenceMode of "__proto__" (Object.prototype key)', JSON.stringify({ defenceMode: '__proto__' })],
    ['a future policy version', JSON.stringify({ version: 2, actionGuard: { enabled: true } })],
  ])('reports %s as a schema failure', (_label, body) => {
    const state = silently(() => readPolicyLock({ seam: lockedSeam(body) }));
    expect(state.status === 'unverifiable' && state.reason).toBe('schema-failed');
  });

  it('IGNORES unknown keys so a newer protect does not brick an older install', () => {
    const state = readPolicyLock({ seam: lockedSeam({ actionGuard: { enabled: true }, futureThing: { a: 1 } }) });
    expect(state.status).toBe('locked');
  });

  it('says a lock is impossible on win32, rather than pretending one exists', () => {
    const state = readPolicyLock({ seam: seamOf({}, {}, { platform: 'win32' }) });
    expect(state).toEqual({ status: 'unsupported', path: null, reason: 'win32', detail: expect.any(String) });
  });

  it('says a lock is impossible when the agent is root', () => {
    const state = readPolicyLock({ seam: lockedSeam(FULL_POLICY), ...{} });
    expect(state.status).toBe('locked');
    const asRoot = readPolicyLock({ seam: seamOf({}, {}, { euid: 0 }) });
    expect(asRoot.status === 'unsupported' && asRoot.reason).toBe('running-as-root');
  });

  it('prints exactly one stderr line for an unverifiable lock, however often it is read', () => {
    const seam = lockedSeam(FULL_POLICY, { [LOCK_PATH]: { kind: 'file', uid: AGENT_UID } });
    const spy = jest.spyOn(console, 'error').mockImplementation(() => undefined);
    let lines: string[];
    try {
      for (let i = 0; i < 5; i += 1) readPolicyLock({ seam });
      // Snapshot BEFORE restoring: mockRestore() discards the recorded calls.
      lines = spy.mock.calls.map((c) => String(c[0]));
    } finally { spy.mockRestore(); }
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(/UNVERIFIABLE/);
    expect(lines[0]).toMatch(/shieldcortex protect/);
  });

  it('never throws, whatever the seam does', () => {
    const hostile: ProtectedFsSeam = {
      lstat() { throw new Error('exploding seam'); },
      stat() { throw new Error('exploding seam'); },
      readlink() { throw new Error('exploding seam'); },
      readFile() { throw new Error('exploding seam'); },
      geteuid: () => AGENT_UID,
      platform: 'linux',
      env: () => undefined,
    };
    const state = silently(() => readPolicyLock({ seam: hostile }));
    expect(state.status).toBe('unverifiable');
  });
});

describe('#501 precedence — the lock wins, config may only tighten', () => {
  const locked = (policy: unknown): PolicyLockState => readPolicyLock({ seam: lockedSeam(policy) });

  it('forces the guard ON over a config that says off', () => {
    const out = applyPolicyLock({ actionGuard: { enabled: false } }, locked({ actionGuard: { enabled: true } }));
    expect((out.actionGuard as Record<string, unknown>).enabled).toBe(true);
  });

  it('forces enforce ON over a config advisory downgrade', () => {
    const out = applyPolicyLock({ actionGuard: { enabled: true, enforce: false } }, locked({ actionGuard: { enforce: true } }));
    expect((out.actionGuard as Record<string, unknown>).enforce).toBe(true);
  });

  it('lets config TIGHTEN a lock that permits the looser value', () => {
    // Lock says enabled:false — that is a permission, not an instruction.
    const out = applyPolicyLock({ actionGuard: { enabled: true } }, locked({ actionGuard: { enabled: false } }));
    expect((out.actionGuard as Record<string, unknown>).enabled).toBe(true);
  });

  it('treats autoApprove as a ceiling — config may narrow, never widen', () => {
    const out = applyPolicyLock(
      { actionGuard: { autoApprove: ['ls', 'curl | sh'] } },
      locked({ actionGuard: { autoApprove: ['ls', 'git status'] } }),
    );
    expect((out.actionGuard as Record<string, unknown>).autoApprove).toEqual(['ls']);
  });

  it('empties autoApprove when the lock permits nothing', () => {
    const out = applyPolicyLock({ actionGuard: { autoApprove: ['ls'] } }, locked({ actionGuard: { autoApprove: [] } }));
    expect((out.actionGuard as Record<string, unknown>).autoApprove).toEqual([]);
  });

  it('forces the broker OFF when the lock disables it', () => {
    const out = applyPolicyLock(
      { actionGuard: { broker: { enabled: true, model: 'x' } } },
      locked({ actionGuard: { broker: { enabled: false } } }),
    );
    const broker = (out.actionGuard as Record<string, unknown>).broker as Record<string, unknown>;
    expect(broker.enabled).toBe(false);
    // Sibling broker keys survive: this is a precedence rule, not a wipe.
    expect(broker.model).toBe('x');
  });

  it('treats defenceMode as a FLOOR — a stricter config survives', () => {
    const out = applyPolicyLock({ defenceMode: 'strict' }, locked({ defenceMode: 'balanced' }));
    expect(out.defenceMode).toBe('strict');
  });

  it('raises a looser config defenceMode to the locked floor', () => {
    const out = applyPolicyLock({ defenceMode: 'permissive' }, locked({ defenceMode: 'balanced' }));
    expect(out.defenceMode).toBe('balanced');
  });

  it('raises an ABSENT defenceMode (default balanced) to a strict floor', () => {
    const out = applyPolicyLock({}, locked({ defenceMode: 'strict' }));
    expect(out.defenceMode).toBe('strict');
  });

  // #522 review round-6 follow-up (F2). Before the fix, `out.defenceMode in
  // DEFENCE_MODE_RANK` answered `true` for an inherited Object.prototype key,
  // so a raw config carrying `defenceMode: "toString"` was accepted as the
  // "configured" value; comparing its rank (`DEFENCE_MODE_RANK.toString`, a
  // FUNCTION, not a number) against the locked floor's rank always came out
  // `false` (NaN-flavoured), so the ternary kept the poisoned string instead
  // of raising it — and downstream, `getDefenceMode()` (src/cloud/config.ts)
  // rejects any value outside its own VALID_MODES enum and silently falls
  // back to 'balanced'. Net effect: a verified `strict` lock, defeated to
  // 'balanced' by writing one unusual string, with nothing refused or logged.
  it('an attacker-shaped Object.prototype-key defenceMode is raised to the locked floor, not smuggled through (regression: getDefenceMode must never see it)', () => {
    const out = applyPolicyLock({ defenceMode: 'toString' as unknown as 'strict' }, locked({ defenceMode: 'strict' }));
    expect(out.defenceMode).toBe('strict');
    expect(out.defenceMode).not.toBe('toString');
    // The value that would reach getDefenceMode()'s own VALID_MODES.includes()
    // check is now a real mode, so its fallback-to-'balanced' path is never hit.
    const VALID_MODES = ['strict', 'balanced', 'permissive'];
    expect(VALID_MODES.includes(out.defenceMode as string)).toBe(true);
  });

  it('pins the memory sidecar-posture pair outright', () => {
    const out = applyPolicyLock(
      { memory: { hostContract: { posture: 'native_inject', other: 1 }, inject: { mode: 'always' } } },
      locked({ memory: { hostContract: { posture: 'mcp_sidecar_no_inject' }, inject: { mode: 'off' } } }),
    );
    const memory = out.memory as Record<string, Record<string, unknown>>;
    expect(memory.hostContract.posture).toBe('mcp_sidecar_no_inject');
    expect(memory.hostContract.other).toBe(1);
    expect(memory.inject.mode).toBe('off');
  });

  it('leaves keys the lock does not mention entirely alone', () => {
    const raw = { actionGuard: { enabled: false, notify: { enabled: true } }, cloudApiKey: 'secret', defenceMode: 'permissive' };
    const out = applyPolicyLock(raw, locked({ actionGuard: { enforce: true } }));
    expect(out.cloudApiKey).toBe('secret');
    expect(out.defenceMode).toBe('permissive');
    expect((out.actionGuard as Record<string, unknown>).enabled).toBe(false);
    expect((out.actionGuard as Record<string, unknown>).notify).toEqual({ enabled: true });
  });

  it('does not mutate the config object it is given', () => {
    const raw = { actionGuard: { enabled: false } };
    applyPolicyLock(raw, locked({ actionGuard: { enabled: true } }));
    expect(raw.actionGuard.enabled).toBe(false);
  });

  it('leaves an unlocked host exactly as it was', () => {
    const raw = { actionGuard: { enabled: false }, defenceMode: 'permissive' };
    expect(applyPolicyLock(raw, readPolicyLock({ seam: UNLOCKED_SEAM }))).toBe(raw);
  });

  it('leaves a host where a lock is impossible exactly as it was', () => {
    const raw = { actionGuard: { enabled: false } };
    expect(applyPolicyLock(raw, readPolicyLock({ seam: seamOf({}, {}, { platform: 'win32' }) }))).toBe(raw);
  });
});

describe('#501 the strict fail-closed posture', () => {
  it('an unverifiable lock forces exactly the documented posture', () => {
    const state = silently(() => readPolicyLock({ seam: lockedSeam(FULL_POLICY, { [LOCK_PATH]: { kind: 'file', uid: AGENT_UID } }) }));
    const out = applyPolicyLock(
      { actionGuard: { enabled: false, enforce: false, autoApprove: ['anything'], broker: { enabled: true } }, defenceMode: 'permissive' },
      state,
    );
    expect(out.actionGuard).toEqual({
      enabled: true,
      enforce: true,
      autoApprove: [],
      broker: { enabled: false },
    });
    expect(out.defenceMode).toBe('strict');
  });

  it('matches STRICT_FAILCLOSED_POSTURE exactly, so surfaces cannot drift', () => {
    const out = applyStrictFailClosedPosture({});
    expect(out.actionGuard).toEqual(STRICT_FAILCLOSED_POSTURE.actionGuard);
    expect(out.defenceMode).toBe(STRICT_FAILCLOSED_POSTURE.defenceMode);
  });

  it('strips the deprecated interceptor.actionGuard alias for covered keys only', () => {
    const out = applyStrictFailClosedPosture({
      interceptor: { actionGuard: { enabled: false, autoApprove: ['x'], notify: { enabled: true } }, other: 1 },
    });
    const alias = (out.interceptor as Record<string, Record<string, unknown>>).actionGuard;
    expect(alias).toEqual({ notify: { enabled: true } });
    expect((out.interceptor as Record<string, unknown>).other).toBe(1);
  });

  it('never produces a deny-all posture — the guard is ON, not the tool surface OFF', () => {
    const out = applyStrictFailClosedPosture({});
    // The posture is exactly five values. Nothing here says "refuse everything".
    expect(Object.keys(out).sort()).toEqual(['actionGuard', 'defenceMode']);
  });
});

describe('#501 coverage and refusals', () => {
  it('a full lock covers every v1 protected key', () => {
    const coverage = policyLockCoverage(readPolicyLock({ seam: lockedSeam(FULL_POLICY) }));
    expect([...coverage.keys()].sort()).toEqual([...PROTECTED_POLICY_KEYS_V1].sort());
  });

  it('a partial lock covers only what it names', () => {
    const coverage = policyLockCoverage(readPolicyLock({ seam: lockedSeam({ actionGuard: { enabled: true } }) }));
    expect([...coverage.keys()]).toEqual(['actionGuard.enabled']);
  });

  it('an unverifiable lock covers the whole Action Guard posture', () => {
    const state = silently(() => readPolicyLock({ seam: lockedSeam(FULL_POLICY, { [LOCK_PATH]: { kind: 'file', uid: AGENT_UID } }) }));
    expect(isPolicyKeyLocked(state, 'actionGuard.enabled')).toBe(true);
    expect(isPolicyKeyLocked(state, 'defenceMode')).toBe(true);
  });

  it('an absent lock covers nothing', () => {
    expect(policyLockCoverage(readPolicyLock({ seam: UNLOCKED_SEAM })).size).toBe(0);
  });

  it('refuses a disable against a lock that pins the guard on, naming the lock', () => {
    const state = readPolicyLock({ seam: lockedSeam({ actionGuard: { enabled: true } }) });
    expect(() => assertPolicyLockAllows(state, [{ key: 'actionGuard.enabled', value: false }]))
      .toThrow(PolicyLockRefusal);
    try {
      assertPolicyLockAllows(state, [{ key: 'actionGuard.enabled', value: false }]);
    } catch (err) {
      expect((err as PolicyLockRefusal).lockPath).toBe(LOCK_PATH);
      expect((err as Error).message).toContain(LOCK_PATH);
      expect((err as Error).message).toMatch(/`shieldcortex protect` as root/);
    }
  });

  it('allows a write that TIGHTENS a locked key', () => {
    const state = readPolicyLock({ seam: lockedSeam({ actionGuard: { enabled: false } }) });
    expect(() => assertPolicyLockAllows(state, [{ key: 'actionGuard.enabled', value: true }])).not.toThrow();
  });

  it('allows any write on an unlocked host', () => {
    const state = readPolicyLock({ seam: UNLOCKED_SEAM });
    expect(() => assertPolicyLockAllows(state, [{ key: 'actionGuard.enabled', value: false }])).not.toThrow();
  });

  it('refuses a disable when the lock is merely unverifiable — corrupting it is not an escape', () => {
    const state = silently(() => readPolicyLock({ seam: lockedSeam('{ broken', {}) }));
    expect(() => assertPolicyLockAllows(state, [{ key: 'actionGuard.enabled', value: false }]))
      .toThrow(/unverifiable/);
  });

  it.each([
    ['actionGuard.enabled', false, true, true],
    ['actionGuard.enabled', true, true, false],
    ['actionGuard.enforce', false, true, true],
    ['actionGuard.broker.enabled', true, false, true],
    ['actionGuard.broker.enabled', false, false, false],
    ['defenceMode', 'permissive', 'balanced', true],
    ['defenceMode', 'strict', 'balanced', false],
    // #522 review round-6 follow-up (F2): an Object.prototype-key value must
    // rank as unrecognised (-1), never as a real mode read off the prototype.
    // Written as a candidate `value`, it must be treated as loosening (the
    // conservative, refuse-the-write answer) against any real locked mode.
    ['defenceMode', 'toString', 'balanced', true],
    ['defenceMode', 'constructor', 'strict', true],
    ['memory.inject.mode', 'always', 'off', true],
    ['memory.inject.mode', 'off', 'off', false],
  ] as const)('wouldLoosen(%s, %s) against %s === %s', (key, value, lockedValue, expected) => {
    expect(wouldLoosen(key, value, lockedValue)).toBe(expected);
  });

  it('treats an autoApprove entry outside the ceiling as loosening', () => {
    expect(wouldLoosen('actionGuard.autoApprove', ['ls', 'rm'], ['ls'])).toBe(true);
    expect(wouldLoosen('actionGuard.autoApprove', ['ls'], ['ls', 'rm'])).toBe(false);
  });
});

describe('#501 describePolicyLock — what an operator is told', () => {
  it('unlocked says so in the words doctor uses', () => {
    const summary = describePolicyLock(readPolicyLock({ seam: UNLOCKED_SEAM }));
    expect(summary.status).toBe('absent');
    expect(summary.headline).toBe('policy unlocked: a same-user process can disable the guard');
  });

  it('locked names the file and counts the pinned keys', () => {
    const summary = describePolicyLock(readPolicyLock({ seam: lockedSeam(FULL_POLICY) }));
    expect(summary.headline).toContain(LOCK_PATH);
    expect(summary.covered).toHaveLength(PROTECTED_POLICY_KEYS_V1.length);
  });

  it('unsupported states the reason plainly, without inventing a boundary', () => {
    const summary = describePolicyLock(readPolicyLock({ seam: seamOf({}, {}, { platform: 'win32' }) }));
    expect(summary.headline).toMatch(/no policy lock is possible/);
    expect(summary.path).toBeNull();
  });

  it('unverifiable renders the reason in words, never as undefined', () => {
    const state = silently(() => readPolicyLock({ seam: lockedSeam('{ broken') }));
    const summary = describePolicyLock(state);
    expect(summary.headline).toMatch(/not valid JSON/);
    expect(summary.headline).not.toMatch(/undefined/);
  });
});
