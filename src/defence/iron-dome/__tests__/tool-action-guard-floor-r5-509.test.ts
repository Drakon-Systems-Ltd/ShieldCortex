/**
 * #509 round 5, finding 1 — the cheap, concrete classifier gaps GPT-6 found
 * against cf1cdfe3 land on the self-protection floor: a relative guard-state
 * path after `cd ~/.shieldcortex` in the same command, the guard directory
 * (or `approvals/`) itself moved / copied over / removed, and the native
 * OpenClaw `process` write payload. Best-effort by design — symlinks,
 * interpreters and an earlier `cd` are out of scope (see the design doc's
 * threat boundary); the promotion notice is the detection control.
 */
import { describe, it, expect } from '@jest/globals';
import { GUARD_SELF_PROTECTION_SIGNALS, evaluateToolCall, isGuardSelfProtectionVerdict } from '../tool-action-guard.js';

describe('#509 r5 finding 1 — cheap concrete classifier gaps land on the floor', () => {
  const floor = (command: string) => evaluateToolCall('Bash', { command }).signals.filter((s) => GUARD_SELF_PROTECTION_SIGNALS.includes(s));

  it('a relative guard-state path after `cd ~/.shieldcortex` in the same command', () => {
    expect(floor("cd ~/.shieldcortex; printf '{}' > approvals/guard-readiness.json")).toContain('touch-approval-store');
    expect(floor('cd $HOME/.shieldcortex && echo x >> ./approvals/guard-readiness-transitions.jsonl')).toContain('touch-approval-store');
    expect(floor('pushd /home/u/.shieldcortex/ && tee leases/x < /tmp/y')).toContain('touch-decisions-ledger');
    expect(floor('cd ~/.shieldcortex && echo {} > config.json')).toContain('touch-guard-config');
    const v = evaluateToolCall('Bash', { command: "cd ~/.shieldcortex; printf '{}' > approvals/guard-readiness.json" });
    expect(v.decision).toBe('require_approval');
  });

  it('pure inspection after the cd is not a mutation, and naming the directory without a mutation is nothing', () => {
    expect(floor('cd ~/.shieldcortex && ls approvals')).toEqual([]);
    expect(floor('cd ~/.shieldcortex && cat approvals/approvals.json | wc -l')).toEqual([]);
    expect(floor('ls ~/.shieldcortex')).toEqual([]);
    expect(floor('cd ~/projects && echo {} > config.json')).toEqual([]);
  });

  it('moving / copying over the guard directory or approvals/ itself', () => {
    expect(floor('mv ~/.shieldcortex /tmp/sc-review-state-backup')).toContain('touch-approval-store');
    expect(floor('mv "$HOME/.shieldcortex/" /tmp/x')).toContain('touch-approval-store');
    expect(floor('cp -r /tmp/forged/. ~/.shieldcortex/')).toContain('touch-approval-store');
    expect(floor('rsync -a /tmp/forged/ /home/u/.shieldcortex')).toContain('touch-approval-store');
    expect(floor('rmdir ~/.shieldcortex/approvals')).toContain('touch-approval-store');
    expect(floor('mv ~/notes.txt /tmp/x')).toEqual([]);
  });

  it('the native OpenClaw `process` write payload runs through the floor', () => {
    const write = evaluateToolCall('process', { action: 'write', sessionId: 'shell-1', data: "printf '{}' > ~/.shieldcortex/approvals/guard-readiness.json\n" });
    expect(write.decision).toBe('require_approval');
    expect(write.signals).toEqual(expect.arrayContaining(['openclaw-process-mutate', 'touch-approval-store']));
    expect(isGuardSelfProtectionVerdict(write.signals)).toBe(true);
    const ordinary = evaluateToolCall('process', { action: 'write', sessionId: 'shell-1', data: 'ls -la\n' });
    expect(ordinary.signals).toEqual(['openclaw-process-mutate']);
    expect(isGuardSelfProtectionVerdict(ordinary.signals)).toBe(false);
  });
});
