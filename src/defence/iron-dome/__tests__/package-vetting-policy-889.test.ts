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

// ── Fable 1920Z rubric D: the deprecated alias under a verified lock ───────

describe('verified lock scrubs the interceptor.actionGuard alias (rubric D)', () => {
  const locked = { status: 'locked', path: '/x', policy: { v: 1, actionGuard: { enabled: true } } } as unknown as PolicyLockState;
  const aliasOnly = () => ({
    actionGuard: { enabled: true },
    interceptor: { actionGuard: { packageVetting: { enabled: false, minAgeDays: 2 } } },
  });

  it('drops enabled:false from the alias, keeps minAgeDays', () => {
    const out = applyPolicyLock(aliasOnly(), locked) as ReturnType<typeof aliasOnly>;
    expect(out.interceptor.actionGuard.packageVetting).toEqual({ minAgeDays: 2 });
  });

  it('both spellings are scrubbed together', () => {
    const out = applyPolicyLock(raw(), locked) as ReturnType<typeof raw>;
    expect(out.actionGuard.packageVetting).toEqual({ minAgeDays: 3 });
    expect(out.interceptor.actionGuard.packageVetting).toEqual({ minAgeDays: 2 });
  });

  it('hook surface: the hook merges {...alias, ...top}; after the lock no opt-out survives the merge', () => {
    const out = applyPolicyLock(aliasOnly(), locked) as ReturnType<typeof aliasOnly>;
    const merged = { ...out.interceptor.actionGuard, ...out.actionGuard } as { packageVetting?: { enabled?: boolean } };
    expect(merged.packageVetting?.enabled).not.toBe(false);
    expect(merged.packageVetting && 'enabled' in merged.packageVetting).toBe(false);
  });

  it('plugin surface: the plugin view carries its own actionGuard (the alias spelling) as the top-level block', () => {
    const view = { actionGuard: { packageVetting: { enabled: false } } };
    const out = applyPolicyLock(view, locked) as { actionGuard: { packageVetting: Record<string, unknown> } };
    expect('enabled' in out.actionGuard.packageVetting).toBe(false);
  });

  it('an unlocked host keeps the alias opt-out (control)', () => {
    const state: PolicyLockState = { status: 'absent', path: '/x' };
    const out = applyPolicyLock(aliasOnly(), state) as ReturnType<typeof aliasOnly>;
    expect(out.interceptor.actionGuard.packageVetting).toEqual({ enabled: false, minAgeDays: 2 });
  });

  it('does not mutate its input', () => {
    const input = aliasOnly();
    applyPolicyLock(input, locked);
    expect(input.interceptor.actionGuard.packageVetting).toEqual({ enabled: false, minAgeDays: 2 });
  });
});
