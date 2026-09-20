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
  preflightLockDestination,
  resolveAgentUid,
  resolveSourceConfigPath,
  runProtect,
  safeDefaultPolicy,
} from '../protect.js';
import { DEFAULT_DEFENCE_MODE, POLICY_LOCK_FILENAME, clearPolicyLockReportState } from '../../defence/iron-dome/policy-lock.js';
import { PROTECTED_ROOT_ENV, type ProtectedFsSeam, type ProtectedStat } from '../../defence/iron-dome/protected-root.js';

const OPTS = { dryRun: false, fromConfig: false } as const;
const FROM_CONFIG = { dryRun: false, fromConfig: true } as const;

/**
 * Everything a same-UID process could seed into config.json to loosen the
 * lock it is about to be given. Each value is the loose end of its key's
 * order, so the default run's output can be compared against it wholesale.
 */
const LOOSE_CONFIG = {
  actionGuard: {
    enabled: false,
    enforce: false,
    autoApprove: ['anything-goes'],
    broker: { enabled: true },
    reviewedScripts: [{ path: '/tmp/x.sh', sha256: 'a'.repeat(64) }],
  },
  interceptor: { actionGuard: { autoApprove: ['alias-loosening'] } },
  defenceMode: 'permissive',
  memory: { hostContract: { posture: 'mcp_sidecar_no_inject' }, inject: { mode: 'off' } },
};

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
    const policy = buildLockedPolicy({ actionGuard: { enabled: false, enforce: false } }, FROM_CONFIG);
    expect(policy.actionGuard).toMatchObject({ enabled: false, enforce: false });
  });

  // #522 (GPT-6 round-6, item 3): the default run must not carry ANY
  // same-UID value into the root-owned lock. Item A had made that argument
  // for reviewedScripts; autoApprove, the broker switch, defenceMode and the
  // memory posture were still read straight out of config.json.
  it('the default pins the safe posture and nothing from a loosened config reaches it', () => {
    expect(buildLockedPolicy(LOOSE_CONFIG, OPTS)).toEqual(safeDefaultPolicy());
    expect(safeDefaultPolicy()).toEqual({
      version: 1,
      actionGuard: { enabled: true, enforce: true, autoApprove: [], broker: { enabled: false }, reviewedScripts: [] },
      defenceMode: DEFAULT_DEFENCE_MODE,
    });
  });

  it('the default pins the same thing for an empty config as for a loosened one', () => {
    expect(buildLockedPolicy({}, OPTS)).toEqual(buildLockedPolicy(LOOSE_CONFIG, OPTS));
  });

  it('--from-config carries autoApprove through as the ceiling, dropping non-strings', () => {
    const policy = buildLockedPolicy({ actionGuard: { autoApprove: ['ls', 7, 'git status'] } }, FROM_CONFIG);
    expect(policy.actionGuard?.autoApprove).toEqual(['ls', 'git status']);
  });

  it('the default pins an empty autoApprove ceiling even when the config lists entries', () => {
    expect(buildLockedPolicy({}, OPTS).actionGuard?.autoApprove).toEqual([]);
    expect(buildLockedPolicy({ actionGuard: { autoApprove: ['ls'] } }, OPTS).actionGuard?.autoApprove).toEqual([]);
  });

  it('the default pins the broker off even when the config enabled it; --from-config may pin it on', () => {
    expect(buildLockedPolicy({}, OPTS).actionGuard?.broker).toEqual({ enabled: false });
    expect(buildLockedPolicy({ actionGuard: { broker: { enabled: true } } }, OPTS).actionGuard?.broker)
      .toEqual({ enabled: false });
    expect(buildLockedPolicy({ actionGuard: { broker: { enabled: true } } }, FROM_CONFIG).actionGuard?.broker)
      .toEqual({ enabled: true });
  });

  it('--from-config applies the #209 alias merge — top-level wins, alias gap-fills', () => {
    const policy = buildLockedPolicy({
      actionGuard: { autoApprove: ['top'] },
      interceptor: { actionGuard: { autoApprove: ['alias'], broker: { enabled: true } } },
    }, FROM_CONFIG);
    expect(policy.actionGuard?.autoApprove).toEqual(['top']);
    expect(policy.actionGuard?.broker).toEqual({ enabled: true });
  });

  it('the default pins the defenceMode FLOOR at the product default, whatever the config says', () => {
    expect(buildLockedPolicy({}, OPTS).defenceMode).toBe(DEFAULT_DEFENCE_MODE);
    expect(buildLockedPolicy({ defenceMode: 'permissive' }, OPTS).defenceMode).toBe(DEFAULT_DEFENCE_MODE);
    expect(buildLockedPolicy({ defenceMode: 'strict' }, OPTS).defenceMode).toBe(DEFAULT_DEFENCE_MODE);
  });

  it('--from-config pins defenceMode when the config sets a valid one, and omits junk', () => {
    expect(buildLockedPolicy({ defenceMode: 'strict' }, FROM_CONFIG).defenceMode).toBe('strict');
    expect(buildLockedPolicy({ defenceMode: 'paranoid' }, FROM_CONFIG).defenceMode).toBeUndefined();
  });

  it('the default omits the memory block entirely, even when the config declares one', () => {
    // A lock that invented a posture nobody chose would be pinning the
    // operator's config to a value they never set — and one that copied a
    // same-UID posture would be pinning a value the agent chose.
    expect(buildLockedPolicy({}, OPTS).memory).toBeUndefined();
    expect(buildLockedPolicy(LOOSE_CONFIG, OPTS).memory).toBeUndefined();
    expect(buildLockedPolicy({}, FROM_CONFIG).memory).toBeUndefined();
  });

  it('--from-config pins the sidecar-posture pair when the config declares it', () => {
    const policy = buildLockedPolicy({
      memory: { hostContract: { posture: 'mcp_sidecar_no_inject' }, inject: { mode: 'off' } },
    }, FROM_CONFIG);
    expect(policy.memory).toEqual({ hostContract: { posture: 'mcp_sidecar_no_inject' }, inject: { mode: 'off' } });
  });

  it('stamps the schema version, so a later reader knows what it has', () => {
    expect(buildLockedPolicy({}, OPTS).version).toBe(1);
    expect(buildLockedPolicy({}, FROM_CONFIG).version).toBe(1);
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
    expect(text).toMatch(/only TIGHTEN/);
    // #522 (GPT-6 round-6, item 3): the default run does not read the file, so
    // its autoApprove entry is not in the printed policy — and the operator is
    // told which switch WOULD pin it.
    expect(text).not.toMatch(/"ls"/);
    expect(text).toMatch(/config\.json is not read/);
    expect(text).toMatch(/--from-config/);
    expect(fs.existsSync(path.join(protectedRoot, POLICY_LOCK_FILENAME))).toBe(false);
  });

  it("--dry-run --from-config shows the config's own values, including the ceiling entries", () => {
    fs.writeFileSync(path.join(configDir, 'config.json'), JSON.stringify({
      actionGuard: { enabled: false, autoApprove: ['ls'] },
      defenceMode: 'balanced',
    }));
    const text = runProtect(['--dry-run', '--from-config']).lines.join('\n');
    expect(text).toMatch(/"enabled": false/);
    expect(text).toMatch(/"ls"/);
    expect(text).not.toMatch(/config\.json is not read/);
  });

  it('--dry-run --from-config with no config to read is REFUSED, not pinned as "defaults" (#522 Tars r7, P2)', () => {
    // An empty config maps to an Action Guard that is OFF, so "defaults" here
    // would have frozen the guard off under the word "defaults". The full
    // privileged/no-write assertions are in the r7 block below.
    const result = runProtect(['--dry-run', '--from-config']);
    const text = result.lines.join('\n');
    expect(result.code).toBe(1);
    expect(text).toMatch(/Refusing to write the policy lock: --from-config pins the values in .* and there is no config there/);
    expect(text).not.toMatch(/Would write/);
    expect(text).not.toMatch(/"enabled": false/);
    expect(text).not.toMatch(/pinning defaults/);
  });

  it('--dry-run --from-config with a corrupt config is REFUSED, not guessed (#522 Tars r7, P2)', () => {
    fs.writeFileSync(path.join(configDir, 'config.json'), '{ not json');
    const result = runProtect(['--dry-run', '--from-config']);
    const text = result.lines.join('\n');
    expect(result.code).toBe(1);
    expect(text).toMatch(/--from-config pins the values in .* and it could not be parsed/);
    expect(text).not.toMatch(/Would write/);
    expect(text).not.toMatch(/"enabled": false/);
  });

  it('a --config path without --from-config is noted and not read', () => {
    const explicit = path.join(configDir, 'explicit.json');
    fs.writeFileSync(explicit, JSON.stringify({ actionGuard: { autoApprove: ['from-explicit'] } }));
    const text = runProtect(['--dry-run', '--config', explicit]).lines.join('\n');
    expect(text).toMatch(/--config is only read together with --from-config/);
    expect(text).not.toMatch(/from-explicit/);
  });

  it('--dry-run reports whether the destination would verify for the agent', () => {
    // The suite's tmp root is owned by this very uid, which is the agent uid
    // the seam reports — so the honest answer is "would be refused". The
    // identity line is asserted too: before #522 r7 an unprivileged run with no
    // SUDO_UID was judged as `nobody`, and on macOS CI (a 0700 per-user temp
    // root, no world-writable ancestor) that reported the destination as
    // verifying — the Linux pass was /tmp's 1777 refusing for the wrong reason.
    const self = typeof process.geteuid === 'function' ? process.geteuid() : null;
    const prevSudoUid = process.env.SUDO_UID;
    delete process.env.SUDO_UID;
    try {
      const text = runProtect(['--dry-run']).lines.join('\n');
      expect(text).toMatch(/would be REFUSED/);
      expect(text).toMatch(/would not verify for the agent/);
      if (self !== null && self !== 0) {
        expect(text).toMatch(new RegExp(`Judging the destination as agent uid ${self} \\(this process's own uid`));
      }
    } finally {
      if (prevSudoUid !== undefined) process.env.SUDO_UID = prevSudoUid;
    }
  });
});

describe('#501 protect writes to the root the RUNTIME reads (review SHOULD-FIX-6)', () => {
  /**
   * Pretend to be the privileged process `protect` is actually run as.
   *
   * This is the mode the defect lived in, and the only mode that matters:
   * `resolveProtectedRoot()` answers `running-as-root` for a euid-0 caller —
   * correct for an AGENT, useless for `protect` — so the old code fell through
   * to `DEFAULT_PROTECTED_ROOT` every time and never consulted the pointer file
   * that `readPolicyLockInner` DOES honour. On a pointer host that wrote a lock
   * nobody reads, with uid/mode evidence and a green verify printed next to it.
   *
   * `SUDO_UID` is set for the same reason `verifyAsAgent` reads it: the root
   * `protect` should resolve is the root the unprivileged agent will resolve.
   */
  function asPrivileged<T>(run: () => T): T {
    const prevSudoUid = process.env.SUDO_UID;
    process.env.SUDO_UID = String(typeof process.geteuid === 'function' ? process.geteuid() : 1001);
    const spy = jest.spyOn(process, 'geteuid').mockReturnValue(0);
    try {
      return run();
    } finally {
      spy.mockRestore();
      if (prevSudoUid === undefined) delete process.env.SUDO_UID;
      else process.env.SUDO_UID = prevSudoUid;
    }
  }

  it('the privileged DRY RUN resolves the same root as the unprivileged one', () => {
    // The parity the README promises at `protect --dry-run`: "exactly what would
    // be pinned". Before the fix the two halves disagreed — the unprivileged
    // dry run printed the resolved root and the privileged write used
    // /etc/shieldcortex.
    const wouldWrite = (lines: string[]) => lines.find((l) => l.startsWith('Would write')) ?? '';
    const unprivileged = wouldWrite(runProtect(['--dry-run']).lines);
    const privileged = wouldWrite(asPrivileged(() => runProtect(['--dry-run']).lines));
    expect(privileged).toBe(unprivileged);
    expect(privileged).toContain(path.join(protectedRoot, POLICY_LOCK_FILENAME));
  });

  it('the privileged WRITE targets that same root, not the default one — and is judged there', () => {
    // The consequence, stated where it bites. Before SHOULD-FIX-6 this ran
    // against /etc/shieldcortex; the seam stands in for the pointer file a real
    // pointer host has, and what is under test is that `protect` resolves the
    // root the AGENT resolves. The root it resolves to here is owned by this
    // uid, which is exactly the destination #522 (GPT-6 round-6, item 2) says
    // must be refused BEFORE anything is created — the old assertion at this
    // spot enshrined write-then-fail.
    const result = asPrivileged(() => runProtect([]));
    const lockPath = path.join(protectedRoot, POLICY_LOCK_FILENAME);
    const text = result.lines.join('\n');
    expect(text).toContain(path.dirname(lockPath));
    expect(text).not.toMatch(/\/etc\/shieldcortex/);
    expect(text).toMatch(/Refusing to write the policy lock/);
    expect(text).toMatch(/would not verify for the agent/);
    expect(text).toMatch(/Nothing was written/);
    expect(text).not.toMatch(/WROTE/);
    expect(result.code).toBe(1);
    expect(fs.existsSync(lockPath)).toBe(false);
  });
});

describe('#522 protect judges the destination BEFORE touching the disk (GPT-6 round-6, item 2)', () => {
  function asPrivileged<T>(run: () => T): T {
    const prevSudoUid = process.env.SUDO_UID;
    process.env.SUDO_UID = String(typeof process.geteuid === 'function' ? process.geteuid() : 1001);
    const spy = jest.spyOn(process, 'geteuid').mockReturnValue(0);
    try {
      return run();
    } finally {
      spy.mockRestore();
      if (prevSudoUid === undefined) delete process.env.SUDO_UID;
      else process.env.SUDO_UID = prevSudoUid;
    }
  }

  /**
   * The zero-mutation canary. `code: 1` and a refusal LINE are not the claim
   * #522 item 2 makes — the claim is that the privileged run touched nothing,
   * and the old write-then-fail path returned `code: 1` too. So snapshot the
   * destination's own metadata as well as its contents: `mkdirSync` would add
   * an entry, `chmodSync(protectedRoot, 0o755)` would change `mode`, and
   * `writeFileSync`/`renameSync` of the temp file would move `mtimeMs`.
   */
  const snapshot = (dir: string) => {
    const st = fs.statSync(dir);
    return { entries: fs.readdirSync(dir).sort(), mode: st.mode, uid: st.uid, gid: st.gid, mtimeMs: st.mtimeMs };
  };

  it('an agent-owned EXISTING root is refused with nothing created, chmodded or renamed inside it', () => {
    const before = snapshot(protectedRoot);
    const result = asPrivileged(() => runProtect([]));
    expect(result.code).toBe(1);
    expect(result.lines.join('\n')).toMatch(/Nothing was written/);
    expect(snapshot(protectedRoot)).toEqual(before);
  });

  it('a MISSING root under an agent-owned parent is refused and the root is not created', () => {
    const nested = path.join(protectedRoot, 'nested', 'deeper');
    process.env[PROTECTED_ROOT_ENV] = nested;
    const result = asPrivileged(() => runProtect([]));
    expect(result.code).toBe(1);
    expect(result.lines.join('\n')).toMatch(/Refusing to write the policy lock/);
    expect(fs.existsSync(nested)).toBe(false);
    expect(fs.existsSync(path.join(protectedRoot, 'nested'))).toBe(false);
  });

  describe('preflightLockDestination, against an injected seam', () => {
    const AGENT = 1001;
    const ROOT_DIR: ProtectedStat = { uid: 0, gid: 0, mode: 0o40755, isFile: false, isDirectory: true, isSymbolicLink: false };
    const AGENT_DIR: ProtectedStat = { ...ROOT_DIR, uid: AGENT };
    const WORLD_WRITABLE_DIR: ProtectedStat = { ...ROOT_DIR, mode: 0o40777 };

    /** Unknown paths are root-owned 0755 directories; `null` means absent. */
    function seam(entries: Record<string, ProtectedStat | null>): ProtectedFsSeam {
      const lstat = (p: string): ProtectedStat | null => (p in entries ? entries[p] : ROOT_DIR);
      return {
        lstat,
        stat: lstat,
        readlink: () => null,
        readFile: () => null,
        geteuid: () => AGENT,
        platform: 'linux',
        env: () => undefined,
      };
    }

    it('passes a root-owned chain whose root already exists', () => {
      const v = preflightLockDestination('/etc/shieldcortex/policy.json', seam({ '/etc/shieldcortex/policy.json': null }));
      expect(v.ok).toBe(true);
    });

    it('passes a MISSING root whose first existing ancestor chain is root-owned', () => {
      const v = preflightLockDestination(
        '/etc/shieldcortex/policy.json',
        seam({ '/etc/shieldcortex/policy.json': null, '/etc/shieldcortex': null }),
      );
      expect(v.ok).toBe(true);
    });

    it('refuses an existing root owned by the agent', () => {
      const v = preflightLockDestination(
        '/etc/shieldcortex/policy.json',
        seam({ '/etc/shieldcortex/policy.json': null, '/etc/shieldcortex': AGENT_DIR }),
      );
      expect(v).toMatchObject({ ok: false, reason: 'parent-owned-by-agent' });
    });

    it("refuses a MISSING root whose parent the agent owns — the mkdir would be on the agent's terms", () => {
      const v = preflightLockDestination(
        '/home/agent/.protected/policy.json',
        seam({ '/home/agent/.protected/policy.json': null, '/home/agent/.protected': null, '/home/agent': AGENT_DIR }),
      );
      expect(v).toMatchObject({ ok: false, reason: 'parent-owned-by-agent' });
    });

    it('refuses a world-writable ancestor anywhere on the chain', () => {
      const v = preflightLockDestination(
        '/etc/shieldcortex/policy.json',
        seam({ '/etc/shieldcortex/policy.json': null, '/etc': WORLD_WRITABLE_DIR }),
      );
      expect(v).toMatchObject({ ok: false, reason: 'parent-group-or-other-writable' });
    });

    it('refuses to replace a directory sitting at the lock path', () => {
      const v = preflightLockDestination('/etc/shieldcortex/policy.json', seam({ '/etc/shieldcortex/policy.json': ROOT_DIR }));
      expect(v).toMatchObject({ ok: false, reason: 'not-regular-file' });
    });

    it('refuses when the runtime has no effective uid to compare against', () => {
      const s = { ...seam({}), geteuid: () => null };
      expect(preflightLockDestination('/etc/shieldcortex/policy.json', s)).toMatchObject({ ok: false, reason: 'euid-unavailable' });
    });
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

  it('FAILS on an unlocked host only when a live plane is gating', async () => {
    fs.writeFileSync(path.join(configDir, 'config.json'), JSON.stringify({ actionGuard: { enabled: true } }));
    const lock = (await rows()).find((r) => r.label.includes('policy lock'))!;
    // No OpenClaw plugin on this fixture → leftover signed-on is not live.
    expect(lock.status).toBe('warn');
    expect(lock.message).toMatch(/not unprotected/i);
    expect(lock.fix).toMatch(/Do not run protect/i);
  });

  it('only WARNS on an unlocked host while the guard is off', async () => {
    fs.writeFileSync(path.join(configDir, 'config.json'), JSON.stringify({ actionGuard: { enabled: false } }));
    const lock = (await rows()).find((r) => r.label.includes('policy lock'))!;
    expect(lock.status).toBe('warn');
    expect(lock.message).toMatch(/not unprotected|nothing pinned to lose yet/i);
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

describe('#522 r7 (Tars) — the agent uid is resolved, never guessed; --from-config needs a real source', () => {
  const SELF = typeof process.geteuid === 'function' ? process.geteuid() : 1001;
  const lockPath = () => path.join(protectedRoot, POLICY_LOCK_FILENAME);

  /** Same zero-mutation canary as the item-2 block: entries, mode, owner and mtime of the destination. */
  const snapshot = (dir: string) => {
    const st = fs.statSync(dir);
    return { entries: fs.readdirSync(dir).sort(), mode: st.mode, uid: st.uid, gid: st.gid, mtimeMs: st.mtimeMs };
  };

  /**
   * Run with `SUDO_UID` set to `sudoUid`, or absent when `undefined` — the
   * state a system service or an already-privileged shell invokes `protect`
   * in — and, when `privileged`, with `geteuid` answering 0 the way the real
   * `protect` sees it.
   */
  function withIdentity<T>(privileged: boolean, sudoUid: string | undefined, run: () => T): T {
    const prev = process.env.SUDO_UID;
    if (sudoUid === undefined) delete process.env.SUDO_UID;
    else process.env.SUDO_UID = sudoUid;
    const spy = privileged ? jest.spyOn(process, 'geteuid').mockReturnValue(0) : null;
    try {
      return run();
    } finally {
      spy?.mockRestore();
      if (prev === undefined) delete process.env.SUDO_UID;
      else process.env.SUDO_UID = prev;
    }
  }

  describe('resolveAgentUid', () => {
    it('--agent-uid wins over SUDO_UID', () => {
      expect(resolveAgentUid({ agentUid: '1234' }, { SUDO_UID: '999' }, 0)).toMatchObject({ ok: true, uid: 1234, source: 'flag' });
    });

    it('SUDO_UID names the agent when there is no flag', () => {
      expect(resolveAgentUid({}, { SUDO_UID: '999' }, 0)).toMatchObject({ ok: true, uid: 999, source: 'env' });
    });

    it('an unprivileged process with no other source is its own agent', () => {
      expect(resolveAgentUid({}, {}, 1001)).toMatchObject({ ok: true, uid: 1001, source: 'self' });
    });

    it('an unprivileged process trusts its own uid over a stale or foreign SUDO_UID (code review, #522 r7)', () => {
      // SUDO_UID names whoever launched the run, not necessarily this process:
      // a launch targeted at a different account, or a value left over from an
      // unrelated earlier context, can leave it set on a process that is really
      // someone else. That is only ambiguous while this process cannot answer
      // for itself; here it can, and its own identity is what gets judged.
      expect(resolveAgentUid({}, { SUDO_UID: '999' }, 1001)).toMatchObject({ ok: true, uid: 1001, source: 'self' });
    });

    it('a privileged process with nothing to go on is refused — never judged as nobody', () => {
      const v = resolveAgentUid({}, {}, 0);
      expect(v.ok).toBe(false);
      if (!v.ok) expect(v.detail).toMatch(/no SUDO_UID/);
    });

    it('a runtime with no euid and no source is refused', () => {
      expect(resolveAgentUid({}, {}, null)).toMatchObject({ ok: false });
    });

    it('uid 0 is refused from either source', () => {
      expect(resolveAgentUid({ agentUid: '0' }, {}, 0)).toMatchObject({ ok: false });
      expect(resolveAgentUid({}, { SUDO_UID: '0' }, 0)).toMatchObject({ ok: false });
    });

    it.each(['abc', '', '-1', '1.5', '12abc'])('a malformed --agent-uid %j is refused by name', (raw) => {
      const v = resolveAgentUid({ agentUid: raw }, { SUDO_UID: '999' }, 0);
      expect(v.ok).toBe(false);
      if (!v.ok) expect(v.detail).toMatch(/--agent-uid/);
    });

    it('a malformed SUDO_UID is refused rather than falling through to a guess', () => {
      expect(resolveAgentUid({}, { SUDO_UID: 'x' }, 0)).toMatchObject({ ok: false });
    });

    it('parseProtectArgs keeps the raw --agent-uid value, and a trailing flag as the empty string', () => {
      expect(parseProtectArgs(['--agent-uid', '1001']).agentUid).toBe('1001');
      expect(parseProtectArgs(['--agent-uid']).agentUid).toBe('');
      expect(parseProtectArgs([]).agentUid).toBeUndefined();
    });
  });

  describe('P1 — a privileged run with no SUDO_UID', () => {
    it('is REFUSED before anything is resolved, judged or written', () => {
      // Before the fix this run was judged as uid 65534. The suite root is
      // owned by SELF, so to "nobody" it is owned by another uid — and on a
      // chain with no world-writable ancestor the old code went on to mkdir,
      // write and print "Policy lock written" into a directory SELF owns.
      const before = snapshot(protectedRoot);
      const result = withIdentity(true, undefined, () => runProtect([]));
      const text = result.lines.join('\n');
      expect(result.code).toBe(1);
      expect(text).toMatch(/Refusing to write the policy lock: cannot tell which uid the agent runs as/);
      expect(text).toMatch(/no SUDO_UID/);
      expect(text).toMatch(/--agent-uid/);
      expect(text).toMatch(/Nothing was written/);
      expect(text).not.toMatch(/Judging the destination/);
      expect(text).not.toMatch(/verifies for the agent/);
      expect(text).not.toMatch(/WROTE|Policy lock written/);
      expect(fs.existsSync(lockPath())).toBe(false);
      expect(snapshot(protectedRoot)).toEqual(before);
    });

    it('is refused as --dry-run too, with no policy printed and no false "verifies"', () => {
      const result = withIdentity(true, undefined, () => runProtect(['--dry-run']));
      const text = result.lines.join('\n');
      expect(result.code).toBe(1);
      expect(text).toMatch(/cannot tell which uid the agent runs as/);
      expect(text).not.toMatch(/Would write/);
      expect(text).not.toMatch(/verifies for the agent/);
    });

    it('SUDO_UID=0 is refused: it says nothing about the agent', () => {
      const before = snapshot(protectedRoot);
      const result = withIdentity(true, '0', () => runProtect([]));
      expect(result.code).toBe(1);
      expect(result.lines.join('\n')).toMatch(/SUDO_UID is 0/);
      expect(snapshot(protectedRoot)).toEqual(before);
    });

    it('a malformed --agent-uid is refused with nothing written', () => {
      const before = snapshot(protectedRoot);
      const result = withIdentity(true, undefined, () => runProtect(['--agent-uid', 'agent']));
      expect(result.code).toBe(1);
      expect(result.lines.join('\n')).toMatch(/--agent-uid "agent" is not a uid/);
      expect(snapshot(protectedRoot)).toEqual(before);
    });

    it('--agent-uid names the agent, and the destination is then judged for THAT uid', () => {
      // The positive control for the flag: the same run, now told the agent
      // is SELF, gets as far as the destination — and refuses it for the right
      // reason, because SELF owns it. Judged as nobody it would have "verified".
      const before = snapshot(protectedRoot);
      const result = withIdentity(true, undefined, () => runProtect(['--agent-uid', String(SELF)]));
      const text = result.lines.join('\n');
      expect(text).toMatch(new RegExp(`Judging the destination as agent uid ${SELF} \\(from --agent-uid\\)`));
      expect(text).toMatch(/would not verify for the agent/);
      expect(text).toMatch(/Nothing was written/);
      expect(result.code).toBe(1);
      expect(snapshot(protectedRoot)).toEqual(before);
    });

    it('--agent-uid overrides a SUDO_UID that names someone else', () => {
      const text = withIdentity(true, String(SELF + 1), () => runProtect(['--dry-run', '--agent-uid', String(SELF)])).lines.join('\n');
      expect(text).toMatch(new RegExp(`agent uid ${SELF} \\(from --agent-uid\\)`));
      expect(text).not.toMatch(new RegExp(`agent uid ${SELF + 1}`));
    });

    it('SUDO_UID positive control: the invoking uid is the agent, and is named as such', () => {
      const text = withIdentity(true, String(SELF), () => runProtect(['--dry-run'])).lines.join('\n');
      expect(text).toMatch(new RegExp(`Judging the destination as agent uid ${SELF} \\(from SUDO_UID\\)`));
      expect(text).toMatch(/would be REFUSED/);
    });

    it('an unprivileged --dry-run with no SUDO_UID is judged as its own uid — the macOS CI case', () => {
      // macOS CI failed at "reports whether the destination would verify": its
      // per-user temp root has no world-writable ancestor, so judged as nobody
      // the SELF-owned root "verified". Judged as SELF it is refused everywhere.
      const text = withIdentity(false, undefined, () => runProtect(['--dry-run'])).lines.join('\n');
      expect(text).toMatch(new RegExp(`Judging the destination as agent uid ${SELF} \\(this process's own uid`));
      expect(text).toMatch(/would be REFUSED/);
      expect(text).toMatch(/would not verify for the agent/);
    });

    it('an unprivileged --dry-run judges itself even with a stale/foreign SUDO_UID set (code review, #522 r7)', () => {
      // SUDO_UID is whoever launched the run, not this process. Left set from
      // some other context on an otherwise-ordinary run it must not steer the
      // check onto a uid this process is not — that would be exactly the false
      // "verifies" this whole file exists to close, one env var later.
      const text = withIdentity(false, String(SELF + 1), () => runProtect(['--dry-run'])).lines.join('\n');
      expect(text).toMatch(new RegExp(`Judging the destination as agent uid ${SELF} \\(this process's own uid`));
      expect(text).not.toMatch(new RegExp(`agent uid ${SELF + 1}`));
    });
  });

  describe('P2 — --from-config with no usable source', () => {
    const refusedWithNothingWritten = (args: string[], reason: RegExp) => {
      const before = snapshot(protectedRoot);
      const result = withIdentity(true, String(SELF), () => runProtect(args));
      const text = result.lines.join('\n');
      expect(result.code).toBe(1);
      expect(text).toMatch(/Refusing to write the policy lock: --from-config pins the values in/);
      expect(text).toMatch(reason);
      expect(text).toMatch(/Nothing was written/);
      expect(text).not.toMatch(/"enabled": false/);
      expect(text).not.toMatch(/pinning defaults/);
      expect(text).not.toMatch(/WROTE|Policy lock written/);
      expect(fs.existsSync(lockPath())).toBe(false);
      expect(snapshot(protectedRoot)).toEqual(before);
      return text;
    };

    it('no config: the privileged run is refused, nothing written, the guard not pinned OFF', () => {
      // Before the fix: exit 0, "No config … pinning defaults", and a lock with
      // actionGuard.enabled:false — the guard frozen off under that prose.
      refusedWithNothingWritten(['--from-config'], /there is no config there/);
    });

    it('corrupt config: refused the same way', () => {
      fs.writeFileSync(path.join(configDir, 'config.json'), '{ not json');
      refusedWithNothingWritten(['--from-config'], /it could not be parsed/);
    });

    it('a config that is not a JSON object: refused the same way', () => {
      fs.writeFileSync(path.join(configDir, 'config.json'), '[]');
      refusedWithNothingWritten(['--from-config'], /it is not a JSON object/);
    });

    it('the refusal comes BEFORE the destination is judged, so it is not masked by a bad root', () => {
      const text = refusedWithNothingWritten(['--from-config'], /there is no config there/);
      expect(text).not.toMatch(/would not verify for the agent/);
    });

    it('--dry-run --from-config refuses the same way and prints no policy', () => {
      const result = withIdentity(true, String(SELF), () => runProtect(['--dry-run', '--from-config']));
      expect(result.code).toBe(1);
      expect(result.lines.join('\n')).not.toMatch(/Would write|"enabled"/);
    });

    it('positive control: a present config is pinned verbatim, including an Action Guard that is OFF', () => {
      fs.writeFileSync(path.join(configDir, 'config.json'), JSON.stringify({ actionGuard: { enabled: false } }));
      const result = withIdentity(true, String(SELF), () => runProtect(['--dry-run', '--from-config']));
      const text = result.lines.join('\n');
      expect(result.code).toBe(0);
      expect(text).toMatch(/Pinning the values in .*config\.json verbatim \(--from-config\)/);
      expect(text).toMatch(/"enabled": false/);
    });

    it('a symlinked config.json is refused without ever being followed — an elevated run must not chase a same-account link (code review, #522 r7)', () => {
      // The account that owns config.json also owns the whole read path, and
      // could point it anywhere this process can read. Following it would let
      // that account use an elevated read to reach a file it cannot read
      // itself; the target here is deliberately something ordinary, because
      // the point is that the link is refused BEFORE its target is ever
      // resolved, whatever that target is.
      const target = path.join(os.tmpdir(), `sc-501-protect-cfg-target-${process.pid}-${Date.now()}`);
      fs.writeFileSync(target, 'ACTUALLY-SECRET-CONTENT-MUST-NOT-APPEAR-IN-OUTPUT');
      try {
        fs.symlinkSync(target, path.join(configDir, 'config.json'));
        const text = refusedWithNothingWritten(['--from-config'], /it is a symlink/);
        expect(text).not.toMatch(/ACTUALLY-SECRET-CONTENT-MUST-NOT-APPEAR-IN-OUTPUT/);
      } finally {
        fs.rmSync(target, { force: true });
      }
    });

    it('a parse failure never echoes the parser message, so a symlinked or foreign file cannot leak a fragment through it', () => {
      // V8's own JSON.parse error message quotes back (up to 10 chars of) the
      // leading token it choked on ("Unexpected token 'S', \"SECRETXYZ \"...
      // is not valid JSON") — real content, not a generic description. That is
      // the fragment this refusal must never repeat.
      fs.writeFileSync(path.join(configDir, 'config.json'), 'SECRETXYZ garbage, not json at all');
      const text = refusedWithNothingWritten(['--from-config'], /it could not be parsed as JSON/);
      expect(text).not.toMatch(/SECRETXYZ/);
    });
  });
});
