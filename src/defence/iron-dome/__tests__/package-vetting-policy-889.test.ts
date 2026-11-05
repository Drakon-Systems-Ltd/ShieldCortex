import { describe, it, expect } from '@jest/globals';
import { applyPolicyLock, applyStrictFailClosedPosture, type PolicyLockState } from '../policy-lock.js';

/**
 * #889 review item 6: `actionGuard.packageVetting.enabled:false` switches off the
 * known-malicious package floor, so it must not survive a lock or the strict
 * fail-closed posture. The other vetting keys (minAgeDays) only tune advisories.
 */
const raw = () => ({
  actionGuard: { enabled: true, packageVetting: { enabled: false, minAgeDays: 3 } },
  interceptor: { actionGuard: { packageVetting: { enabled: false, minAgeDays: 2 } } },
});

describe('packageVetting opt-out vs lock / strict posture (#889 review item 6)', () => {
  it('strict fail-closed posture drops enabled:false (top-level and deprecated alias), keeps minAgeDays', () => {
    const out = applyStrictFailClosedPosture(raw()) as ReturnType<typeof raw>;
    expect(out.actionGuard.packageVetting).toEqual({ minAgeDays: 3 });
    expect((out.interceptor.actionGuard as { packageVetting: unknown }).packageVetting).toEqual({ minAgeDays: 2 });
  });

  it('an unverifiable lock applies the same posture', () => {
    const state: PolicyLockState = { status: 'unverifiable', path: '/x', reason: 'bad', detail: 'bad' };
    const out = applyPolicyLock(raw(), state) as ReturnType<typeof raw>;
    expect(out.actionGuard.packageVetting).toEqual({ minAgeDays: 3 });
  });

  it('a verified lock drops enabled:false even when the lock does not mention packageVetting', () => {
    const state = { status: 'locked', path: '/x', policy: { v: 1, actionGuard: { enabled: true } } } as unknown as PolicyLockState;
    const out = applyPolicyLock(raw(), state) as ReturnType<typeof raw>;
    expect(out.actionGuard.packageVetting).toEqual({ minAgeDays: 3 });
  });

  it('an unlocked host keeps the operator opt-out (control)', () => {
    const state: PolicyLockState = { status: 'absent', path: '/x' };
    const input = raw();
    expect((applyPolicyLock(input, state) as ReturnType<typeof raw>).actionGuard.packageVetting).toEqual({ enabled: false, minAgeDays: 3 });
  });
});
