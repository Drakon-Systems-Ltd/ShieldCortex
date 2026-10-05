import { describe, it, expect } from '@jest/globals';
import { createInterceptor, DEFAULT_CONFIG } from '../interceptor.js';
import { evaluateToolCall } from '../../../src/defence/iron-dome/tool-action-guard.js';

/**
 * #509 r5 finding 3: nothing but a human answer releases the guard
 * self-protection floor. GPT-6 r3 showed `echo {} >> …/guard-readiness-
 * transitions.jsonl` — classified `require_approval` with
 * `touch-approval-store` — allowed by `autoApprove: ["exec"]` without the
 * approver being asked (enforcing and advisory), and by
 * `failurePolicy.high: "allow"` when unattended, when the approver threw and
 * during an evaluator outage. Each of those exits now denies (or asks) for a
 * floor signal; an ordinary dangerous op still takes the configured exit, so
 * the settings keep their meaning.
 */

const okPipeline = () => ({
  allowed: true,
  firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [] as string[], anomalyScore: 0, blockedPatterns: [] as string[] },
  trust: { score: 0.5 },
  sensitivity: { level: 'INTERNAL' },
  fragmentation: null,
  auditId: 1,
});

const FLOOR_WRITE = { command: 'echo {} >> ~/.shieldcortex/approvals/guard-readiness-transitions.jsonl' };
const FLOOR_WRITES = [
  FLOOR_WRITE,
  { command: 'echo {} > ~/.shieldcortex/config.json' },
  { command: "cd ~/.shieldcortex; printf '{}' > approvals/guard-readiness.json" },
];
const ORDINARY = { command: 'sudo systemctl stop ssh' };

function interceptor(guard: Record<string, unknown>, extra: Record<string, unknown> = {}, evaluator: unknown = evaluateToolCall) {
  const config = {
    ...DEFAULT_CONFIG,
    ...extra,
    actionGuard: { ...DEFAULT_CONFIG.actionGuard, enabled: true, ...guard },
  } as any;
  return createInterceptor(config, okPipeline as any, evaluator ? { evaluateToolCall: evaluator as any } : {});
}

const ALLOW_POLICY = { failurePolicy: { ...DEFAULT_CONFIG.failurePolicy, high: 'allow' } };

describe('#509 r5 finding 3 — the OpenClaw interceptor never auto-approves or failure-allows the floor', () => {
  it('the floor write really is require_approval + touch-approval-store (the premise)', () => {
    const v = evaluateToolCall('Bash', FLOOR_WRITE);
    expect(v.decision).toBe('require_approval');
    expect(v.signals).toContain('touch-approval-store');
  });

  for (const enforce of [true, false]) {
    it(`autoApprove ["exec", "touch-approval-store"] (${enforce ? 'enforcing' : 'advisory'}): the approver IS asked, and a "no" denies`, async () => {
      const i = interceptor({ enforce, autoApprove: ['exec', 'touch-approval-store'] });
      for (const args of FLOOR_WRITES) {
        let asked = 0;
        await expect(
          i.handleToolCall({ toolName: 'Bash', arguments: args, requireApproval: async () => { asked += 1; return false; } }),
        ).rejects.toThrow(/denied by user/);
        expect({ args, asked }).toEqual({ args, asked: 1 });
      }
      // The allowlist still works for an ordinary dangerous op.
      const j = interceptor({ enforce, autoApprove: ['privilege-escalation'] });
      await expect(j.handleToolCall({ toolName: 'Bash', arguments: ORDINARY })).resolves.toBeUndefined();
    });
  }

  it('autoApprove + unattended (no approver): the floor write is DENIED', async () => {
    const i = interceptor({ enforce: true, autoApprove: ['exec'] });
    await expect(i.handleToolCall({ toolName: 'Bash', arguments: FLOOR_WRITE })).rejects.toThrow(/blocked/);
  });

  it('failurePolicy.high "allow", unattended: the floor write is DENIED; an ordinary op still follows the policy', async () => {
    const i = interceptor({ enforce: true }, ALLOW_POLICY);
    for (const args of FLOOR_WRITES) {
      await expect(i.handleToolCall({ toolName: 'Bash', arguments: args })).rejects.toThrow(/blocked/);
    }
    await expect(i.handleToolCall({ toolName: 'Bash', arguments: ORDINARY })).resolves.toBeUndefined();
  });

  it('failurePolicy.high "allow", the approver throws: the floor write is DENIED; an ordinary op still follows the policy', async () => {
    const i = interceptor({ enforce: true }, ALLOW_POLICY);
    const boom = async (): Promise<boolean> => { throw new Error('approver exploded'); };
    await expect(i.handleToolCall({ toolName: 'Bash', arguments: FLOOR_WRITE, requireApproval: boom })).rejects.toThrow(/blocked/);
    await expect(i.handleToolCall({ toolName: 'Bash', arguments: ORDINARY, requireApproval: boom })).resolves.toBeUndefined();
  });

  it('failurePolicy.high "allow", evaluator outage: the fallback floor write is DENIED; an ordinary op still follows the policy', async () => {
    const throwing = () => { throw new Error('evaluator down'); };
    const i = interceptor({ enforce: true }, ALLOW_POLICY, throwing);
    await expect(i.handleToolCall({ toolName: 'Bash', arguments: FLOOR_WRITE })).rejects.toThrow(/blocked/);
    await expect(i.handleToolCall({ toolName: 'Bash', arguments: { command: 'echo {} > ~/.shieldcortex/config.json' } })).rejects.toThrow(/blocked/);
    await expect(i.handleToolCall({ toolName: 'Bash', arguments: ORDINARY })).resolves.toBeUndefined();
  });

  it('the native process write payload carrying a guard-state write is gated, not an ordinary mutation autoApprove can release', async () => {
    const i = interceptor({ enforce: true, autoApprove: ['exec', 'openclaw-process-mutate'] });
    const args = { action: 'write', sessionId: 'shell-1', data: "printf '{}' > ~/.shieldcortex/approvals/guard-readiness.json\n" };
    let asked = 0;
    await expect(
      i.handleToolCall({ toolName: 'process', arguments: args, requireApproval: async () => { asked += 1; return false; } }),
    ).rejects.toThrow(/denied by user/);
    expect(asked).toBe(1);
  });
});
