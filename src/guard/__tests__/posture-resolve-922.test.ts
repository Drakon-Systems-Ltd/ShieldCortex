/**
 * #922 slice 1 (PR-A): the pure plane-posture resolver behind doctor's
 * `Action guard posture` row and `shieldcortex guard posture`.
 *
 * Hook: config.json bare parse → lock. OpenClaw: entry merged OVER config.json
 * → lock (plugins/openclaw/index.ts mergeConfigs + applyPolicyLockToPluginConfig).
 * Hermes: #613 self-report only. Hook/plugin disagreeing, or Hermes looser,
 * is a mismatch; Hermes tighter is shown, not failed.
 */
import { describe, expect, it } from '@jest/globals';
import {
  guardPostureRow,
  resolvePlanePostures,
  type PostureInputs,
} from '../posture-switch.js';
import type { PolicyLockState } from '../../defence/iron-dome/policy-lock.js';
import { deriveToolGateRecord, type PostureRecord, type SelfReport } from '../../posture/posture-record.js';
import { NOW, reportBody } from '../../posture/__tests__/self-report-fixture.js';

const NO_LOCK: PolicyLockState = { status: 'absent', path: '/etc/shieldcortex/policy.json' };
const lockPinning = (actionGuard: Record<string, unknown>): PolicyLockState =>
  ({ status: 'locked', path: '/etc/shieldcortex/policy.json', policy: { actionGuard } }) as unknown as PolicyLockState;

function entry(config: Record<string, unknown>, enabled?: boolean): Record<string, unknown> {
  return { plugins: { entries: { 'shieldcortex-realtime': { ...(enabled === undefined ? {} : { enabled }), config } } } };
}

function hermes(configured: string, over: Record<string, unknown> = {}): PostureRecord {
  return deriveToolGateRecord({
    runtime: 'hermes',
    profile: String(over.profile ?? 'default'),
    installed: 'yes',
    read: { kind: 'valid', report: reportBody({ configured_posture: configured, ...over }) as unknown as SelfReport },
    liveness: 'alive',
    nowMs: NOW,
  });
}

function inputs(over: Partial<PostureInputs> = {}): PostureInputs {
  return {
    signedRaw: {},
    integrity: 'valid',
    lock: NO_LOCK,
    claudeWired: true,
    openclaw: { state: 'absent' },
    postureRecords: [],
    ...over,
  };
}

const posturesOf = (r: ReturnType<typeof resolvePlanePostures>) =>
  Object.fromEntries(r.planes.map((p) => [p.plane, p.posture]));

/** Backticked commands in a fix that could turn a plane up. */
const ENABLING = /`[^`]*(guard posture (advisory|enforce)|--action-guard-(enable|enforce))[^`]*`/;

describe('#922 resolvePlanePostures — agreement matrix', () => {
  it.each([
    [{}, 'off'],
    [{ actionGuard: { enabled: true, enforce: false } }, 'advisory'],
    [{ actionGuard: { enabled: true } }, 'enforce'],
    [{ actionGuard: { enabled: true, enforce: true, readinessGate: true } }, 'enforce-when-ready'],
  ])('signed %j with no overlay → hook and plugin both %s, agree', (signedRaw, want) => {
    const r = resolvePlanePostures(inputs({ signedRaw, openclaw: { state: 'ok', raw: entry({}) } }));
    expect(posturesOf(r)).toEqual({ claude: want, openclaw: want });
    expect(r.verdict).toBe('agree');
    expect(r.reference).toBe(want);
    expect(r.signed).toBe(want);
  });

  it('an absent plane is not compared: hook only → agree on that one plane', () => {
    const r = resolvePlanePostures(inputs({ signedRaw: { actionGuard: { enabled: true } } }));
    expect(r.planes.map((p) => p.plane)).toEqual(['claude']);
    expect(r.verdict).toBe('agree');
  });

  it('no plane at all → none, graded by the signed config', () => {
    const r = resolvePlanePostures(inputs({ claudeWired: false }));
    expect(r.verdict).toBe('none');
    const row = guardPostureRow(r);
    expect(row.status).toBe('warn');
    expect(row.message).toMatch(/no gate plane is installed on this box/);
  });

  it('openclaw.json without our plugin entry is not a plane', () => {
    const r = resolvePlanePostures(inputs({ openclaw: { state: 'ok', raw: { plugins: { entries: {} } } } }));
    expect(r.planes.map((p) => p.plane)).toEqual(['claude']);
  });

  it('the scoped package id is read as the plugin entry too', () => {
    const raw = { plugins: { entries: { '@drakon-systems/shieldcortex-realtime': { config: { actionGuard: { enabled: true } } } } } };
    const r = resolvePlanePostures(inputs({ claudeWired: false, openclaw: { state: 'ok', raw } }));
    expect(posturesOf(r)).toEqual({ openclaw: 'enforce' });
  });
});

describe('#922 resolvePlanePostures — the #634 shape and other overlays', () => {
  it('#634: signed enforce + entry enforce:false → plugin advisory → mismatch naming the overriding key', () => {
    const r = resolvePlanePostures(inputs({
      signedRaw: { actionGuard: { enabled: true, enforce: true } },
      openclaw: { state: 'ok', raw: entry({ actionGuard: { enforce: false } }) },
    }));
    expect(posturesOf(r)).toEqual({ claude: 'enforce', openclaw: 'advisory' });
    expect(r.verdict).toBe('mismatch');
    const row = guardPostureRow(r);
    expect(row.status).toBe('fail');
    expect(row.message).toMatch(/planes disagree — Claude Code hook enforce, OpenClaw plugin advisory \(openclaw\.json plugin entry actionGuard\.enforce=false overrides signed\)/);
    expect(row.message).toMatch(/One posture must hold on every plane/);
  });

  it('the entry alias interceptor.actionGuard overlays too (top-level entry key wins)', () => {
    const r = resolvePlanePostures(inputs({
      signedRaw: { actionGuard: { enabled: true } },
      openclaw: { state: 'ok', raw: entry({ interceptor: { actionGuard: { enforce: false } }, actionGuard: {} }) },
    }));
    expect(posturesOf(r).openclaw).toBe('advisory');
  });

  it('entry enabled:true under a signed off → plugin enforce, hook off → mismatch', () => {
    const r = resolvePlanePostures(inputs({ openclaw: { state: 'ok', raw: entry({ actionGuard: { enabled: true } }) } }));
    expect(posturesOf(r)).toEqual({ claude: 'off', openclaw: 'enforce' });
    expect(r.verdict).toBe('mismatch');
  });

  it('entry interceptor.enabled:false → plugin off', () => {
    const r = resolvePlanePostures(inputs({
      signedRaw: { actionGuard: { enabled: true } },
      openclaw: { state: 'ok', raw: entry({ interceptor: { enabled: false } }) },
    }));
    expect(posturesOf(r).openclaw).toBe('off');
    expect(r.planes.find((p) => p.plane === 'openclaw')!.overrides).toContain('openclaw.json plugin entry interceptor.enabled=false');
  });

  it('a disabled plugin entry is present but dormant, and counts as off', () => {
    const r = resolvePlanePostures(inputs({ claudeWired: false, openclaw: { state: 'ok', raw: entry({}, false) } }));
    const oc = r.planes.find((p) => p.plane === 'openclaw')!;
    expect(oc.posture).toBe('off');
    expect(oc.dormant).toBe(true);
    expect(guardPostureRow(r).message).toMatch(/OpenClaw plugin disabled in openclaw\.json/);
  });

  it('the readiness gate comes from the signed config only, never from the entry', () => {
    const fromEntry = resolvePlanePostures(inputs({
      signedRaw: { actionGuard: { enabled: true } },
      openclaw: { state: 'ok', raw: entry({ actionGuard: { readinessGate: true } }) },
    }));
    expect(posturesOf(fromEntry)).toEqual({ claude: 'enforce', openclaw: 'enforce' });
    const fromSigned = resolvePlanePostures(inputs({
      signedRaw: { actionGuard: { enabled: true, readinessGate: true } },
      openclaw: { state: 'ok', raw: entry({}) },
    }));
    expect(posturesOf(fromSigned)).toEqual({ claude: 'enforce-when-ready', openclaw: 'enforce-when-ready' });
  });

  it('signed alias interceptor.actionGuard gap-fills on both planes (#209)', () => {
    const r = resolvePlanePostures(inputs({
      signedRaw: { actionGuard: { enabled: true }, interceptor: { actionGuard: { enforce: false } } },
      openclaw: { state: 'ok', raw: entry({}) },
    }));
    expect(posturesOf(r)).toEqual({ claude: 'advisory', openclaw: 'advisory' });
    expect(guardPostureRow(r).message).toMatch(/interceptor\.actionGuard\.enforce: false/);
  });

  it('malformed or unreadable openclaw.json → plugin unknown, not compared, never assumed off', () => {
    for (const openclaw of [{ state: 'malformed' as const }, { state: 'unreadable' as const, detail: 'EACCES' }]) {
      const r = resolvePlanePostures(inputs({ signedRaw: { actionGuard: { enabled: true } }, openclaw }));
      expect(posturesOf(r)).toEqual({ claude: 'enforce', openclaw: null });
      expect(r.verdict).toBe('agree');
      expect(guardPostureRow(r).message).toMatch(/not compared: OpenClaw plugin unknown/);
    }
  });
});

describe('#922 resolvePlanePostures — policy lock and tamper', () => {
  it('the lock out-ranks the entry: entry enforce:false under a lock pinning enforce → plugin enforce, agree', () => {
    const r = resolvePlanePostures(inputs({
      signedRaw: { actionGuard: { enabled: true } },
      lock: lockPinning({ enabled: true, enforce: true }),
      openclaw: { state: 'ok', raw: entry({ actionGuard: { enabled: false, enforce: false }, interceptor: { enabled: false } }) },
    }));
    expect(posturesOf(r)).toEqual({ claude: 'enforce', openclaw: 'enforce' });
    expect(r.verdict).toBe('agree');
  });

  it('the lock turns a signed off up on the hook and in the signed posture', () => {
    const r = resolvePlanePostures(inputs({ signedRaw: { actionGuard: { enabled: false } }, lock: lockPinning({ enabled: true, enforce: true }) }));
    expect(r.signed).toBe('enforce');
    expect(posturesOf(r).claude).toBe('enforce');
  });

  it('an unverifiable lock → strict on every plane', () => {
    const lock = { status: 'unverifiable', path: '/etc/shieldcortex/policy.json', reason: 'not-root-owned', detail: 'x' } as unknown as PolicyLockState;
    const r = resolvePlanePostures(inputs({ lock, openclaw: { state: 'ok', raw: entry({ actionGuard: { enforce: false } }) } }));
    expect(posturesOf(r)).toEqual({ claude: 'enforce', openclaw: 'enforce' });
  });

  it('tampered config: the runtimes still read its bytes (they do not check _sig); the signed posture is unknown', () => {
    const r = resolvePlanePostures(inputs({
      signedRaw: { actionGuard: { enabled: false } },
      integrity: 'tampered',
      openclaw: { state: 'ok', raw: entry({ actionGuard: { enabled: true } }) },
    }));
    expect(r.signed).toBeNull();
    expect(posturesOf(r)).toEqual({ claude: 'off', openclaw: 'enforce' });
    const row = guardPostureRow(r);
    expect(row.status).toBe('fail');
    expect(row.fix).toMatch(/cannot be trusted \(integrity: tampered\)/);
    expect(row.fix ?? '').not.toMatch(/`/);
  });
});

describe('#922 resolvePlanePostures — Hermes from #613 self-reports', () => {
  it('Hermes looser than the hook → mismatch', () => {
    const r = resolvePlanePostures(inputs({ signedRaw: { actionGuard: { enabled: true } }, postureRecords: [hermes('advisory')] }));
    expect(posturesOf(r)).toEqual({ claude: 'enforce', hermes: 'advisory' });
    expect(r.verdict).toBe('mismatch');
    const row = guardPostureRow(r);
    expect(row.message).toMatch(/Hermes advisory \(self-report\)/);
    expect(row.fix).toMatch(/SHIELDCORTEX_ENFORCE/);
    expect(row.fix ?? '').not.toMatch(ENABLING);
  });

  it('Q4, pending: Hermes enforcing on a default (signed off) box is shown as tighter, not failed', () => {
    const r = resolvePlanePostures(inputs({ postureRecords: [hermes('enforce')] }));
    expect(r.verdict).toBe('agree');
    expect(r.hermesTighter).toBe(true);
    const row = guardPostureRow(r);
    expect(row.status).toBe('warn');
    expect(row.message).toMatch(/Hermes enforce \(self-report\) is tighter than the other planes/);
    expect(row.fix).toMatch(/Do not enable Action Guard from this warning/);
  });

  it('Q3: signed enforce-when-ready + Hermes enforce is the documented tighter deviation, not a FAIL', () => {
    const r = resolvePlanePostures(inputs({
      signedRaw: { actionGuard: { enabled: true, readinessGate: true } },
      postureRecords: [hermes('enforce')],
    }));
    expect(r.verdict).toBe('agree');
    expect(guardPostureRow(r).status).toBe('pass');
  });

  it('two Hermes profiles disagreeing is a mismatch on their own', () => {
    const r = resolvePlanePostures(inputs({
      claudeWired: false,
      postureRecords: [hermes('enforce'), hermes('advisory', { profile: 'work' })],
    }));
    expect(r.planes.find((p) => p.plane === 'hermes')!.values).toEqual(['advisory', 'enforce']);
    expect(r.verdict).toBe('mismatch');
  });

  it('intentionally-off and loaded:false read as off', () => {
    expect(posturesOf(resolvePlanePostures(inputs({ claudeWired: false, postureRecords: [hermes('intentionally-off')] }))).hermes).toBe('off');
    expect(posturesOf(resolvePlanePostures(inputs({ claudeWired: false, postureRecords: [hermes('enforce', { loaded: false })] }))).hermes).toBe('off');
  });

  it('a stale or ended report is not evidence: Hermes installed but unknown, not compared', () => {
    const stale = deriveToolGateRecord({
      runtime: 'hermes', profile: 'default', installed: 'yes',
      read: { kind: 'valid', report: reportBody({ configured_posture: 'advisory' }) as unknown as SelfReport },
      liveness: 'alive', nowMs: NOW + 48 * 3_600_000,
    });
    const ended = deriveToolGateRecord({
      runtime: 'hermes', profile: 'default', installed: 'yes',
      read: { kind: 'valid', report: reportBody({ configured_posture: 'advisory' }) as unknown as SelfReport },
      liveness: 'ended', nowMs: NOW,
    });
    for (const rec of [stale, ended]) {
      const r = resolvePlanePostures(inputs({ signedRaw: { actionGuard: { enabled: true } }, postureRecords: [rec] }));
      expect(posturesOf(r)).toEqual({ claude: 'enforce', hermes: null });
      expect(r.verdict).toBe('agree');
    }
  });

  it('records from other runtimes are ignored', () => {
    const cc = deriveToolGateRecord({
      runtime: 'claude_code', profile: 'default', installed: 'yes',
      read: { kind: 'valid', report: reportBody({ runtime: 'claude_code', configured_posture: 'advisory' }) as unknown as SelfReport },
      liveness: 'alive', nowMs: NOW,
    });
    const r = resolvePlanePostures(inputs({ signedRaw: { actionGuard: { enabled: true } }, postureRecords: [cc] }));
    expect(r.planes.map((p) => p.plane)).toEqual(['claude']);
  });
});

describe('#922 guardPostureRow — status and honest fixes', () => {
  it('off and advisory warn with the old "do not enable" text; enforce passes', () => {
    const off = guardPostureRow(resolvePlanePostures(inputs()));
    expect(off.status).toBe('warn');
    expect(off.fix).toBe('Action Guard is off. That is the default. Do not enable Action Guard from this warning. Do not add a webhook.');
    const adv = guardPostureRow(resolvePlanePostures(inputs({ signedRaw: { actionGuard: { enabled: true, enforce: false } } })));
    expect(adv.status).toBe('warn');
    expect(adv.message).toMatch(/warn-mode/);
    const on = guardPostureRow(resolvePlanePostures(inputs({ signedRaw: { actionGuard: { enabled: true } } })));
    expect(on.status).toBe('pass');
    expect(on.fix).toBeUndefined();
    for (const row of [off, adv]) expect(row.fix ?? '').not.toMatch(ENABLING);
  });

  it('a mismatch whose fix turns nothing on names the signed setter: signed off, plugin enforce', () => {
    const row = guardPostureRow(resolvePlanePostures(inputs({ openclaw: { state: 'ok', raw: entry({ actionGuard: { enabled: true } }) } })));
    expect(row.status).toBe('fail');
    expect(row.fix).toMatch(/Run `shieldcortex config --action-guard-disable`/);
    expect(row.fix).toMatch(/restart the OpenClaw gateway/);
    expect(row.fix ?? '').not.toMatch(ENABLING);
  });

  it('signed advisory, plugin enforce → the advisory setter', () => {
    const row = guardPostureRow(resolvePlanePostures(inputs({
      signedRaw: { actionGuard: { enabled: true, enforce: false } },
      openclaw: { state: 'ok', raw: entry({ actionGuard: { enforce: true } }) },
    })));
    expect(row.fix).toMatch(/Run `shieldcortex config --action-guard-advisory`/);
  });

  it('a mismatch whose fix would turn a plane up names no posture command (#634, Q2 pending)', () => {
    const shapes: PostureInputs[] = [
      inputs({ signedRaw: { actionGuard: { enabled: true } }, openclaw: { state: 'ok', raw: entry({ actionGuard: { enforce: false } }) } }),
      inputs({ signedRaw: { actionGuard: { enabled: true, enforce: false } }, openclaw: { state: 'ok', raw: entry({ actionGuard: { enabled: false } }) } }),
      inputs({ signedRaw: { actionGuard: { enabled: true } }, postureRecords: [hermes('advisory')] }),
    ];
    for (const shape of shapes) {
      const row = guardPostureRow(resolvePlanePostures(shape));
      expect(row.status).toBe('fail');
      expect(row.fix ?? '').not.toMatch(ENABLING);
      expect(row.fix ?? '').not.toMatch(/--action-guard-(disable|advisory)/);
    }
  });

  it('every row, over a broad input grid, keeps enabling commands out of warn rows and raising FAILs', () => {
    const signeds = [{}, { actionGuard: { enabled: true, enforce: false } }, { actionGuard: { enabled: true } }, { actionGuard: { enabled: true, readinessGate: true } }];
    const entries = [null, {}, { actionGuard: { enabled: false } }, { actionGuard: { enabled: true } }, { actionGuard: { enforce: false } }, { actionGuard: { enabled: true, enforce: false } }];
    const hermesSets = [[], [hermes('enforce')], [hermes('advisory')], [hermes('intentionally-off')]];
    let checked = 0;
    for (const signedRaw of signeds) for (const e of entries) for (const postureRecords of hermesSets) {
      const row = guardPostureRow(resolvePlanePostures(inputs({
        signedRaw,
        openclaw: e === null ? { state: 'absent' } : { state: 'ok', raw: entry(e) },
        postureRecords,
      })));
      if (row.status !== 'pass') {
        expect(row.fix ?? '').not.toMatch(ENABLING);
        checked += 1;
      }
    }
    expect(checked).toBeGreaterThan(20);
  });
});
