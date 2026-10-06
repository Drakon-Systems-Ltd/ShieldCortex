/**
 * #648 — the OpenClaw-native approval card reads in plain English.
 *
 * Driven through the real plugin `before_tool_call` hook with the real guard
 * and the real card summariser injected exactly as `shieldcortex/defence`
 * provides them at runtime.
 */
import { describe, it, expect, beforeEach } from '@jest/globals';
import plugin, {
  __resetConfigStateForTest,
  __setDefenceModuleForTest,
  __setRuntimeForTest,
  __buildTypedApprovalRequestForTest,
} from '../index.js';
import { evaluateToolCall } from '../../../src/defence/iron-dome/tool-action-guard.js';
import { buildApprovalCard } from '../../../src/defence/iron-dome/approval-card.js';
import { formatActionGuardPrompt } from '../interceptor.js';

const okPipeline = () => ({
  allowed: true,
  firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [] as string[], anomalyScore: 0, blockedPatterns: [] as string[] },
  trust: { score: 0.5 },
  sensitivity: { level: 'INTERNAL' },
  fragmentation: null,
  auditId: 1,
});

type Hooks = Record<string, (...args: any[]) => any>;

function register(): Hooks {
  const hooks: Hooks = {};
  const rootConfig = { plugins: { entries: { 'shieldcortex-realtime': { enabled: true, config: { interceptor: { actionGuard: { enabled: true } } } } } } };
  plugin.register({
    id: 'shieldcortex-realtime',
    name: 'ShieldCortex Real-time Scanner',
    logger: { info: () => {}, warn: () => {} },
    on: (name: string, handler: (...args: any[]) => any) => { hooks[name] = handler; },
    registerCommand: () => {},
    runtime: { config: { current: () => rootConfig } },
  } as any);
  return hooks;
}

const GH = ['gh', 'p_'].join('') + 'Z'.repeat(4) + 'q7Lm2Xr9Tb4Vc8Nd1Fh6Jk3Wp5Ys0Ua';
const AWS_ID = ['AK', 'IA'].join('') + 'Q3XZ7LMN2PRT6VWY';
const CTX = { agentId: 'main', sessionKey: 'agent:main:telegram:group:-1001234567890:topic:10' };

beforeEach(() => {
  __resetConfigStateForTest();
  __setRuntimeForTest({ callCortex: async () => null, isOpenClawAutoMemoryEnabled: () => false, loadShieldConfig: async () => ({}) });
  __setDefenceModuleForTest({ runDefencePipeline: okPipeline, evaluateToolCall, buildApprovalCard } as any);
});

describe('#648 — OpenClaw card through the real plugin hook', () => {
  it('names the target, the plain reason and who is asking', async () => {
    const hooks = register();
    const result = await hooks['before_tool_call']({ toolName: 'exec', params: { command: 'sudo systemctl stop nginx' } }, CTX);
    const card = result?.requireApproval;
    expect(card).toBeTruthy();
    expect(card.title).toBe('ShieldCortex needs a yes');
    const parts = card.description.split(' | ');
    expect(parts[0]).toBe('What: Stop the service: nginx, as administrator (sudo)');
    expect(parts[1]).toMatch(/^Why: runs with administrator \(root\) rights/);
    expect(parts[2]).toMatch(/^Who: OpenClaw agent "main" on [A-Za-z0-9._-]+ · Telegram chat #[0-9a-f]{8}$/);
    expect(parts[3]).toBe('Allow once is this call only · expires in 10 min');
    expect(card.description.length).toBeLessThanOrEqual(256);
    // Jargon that used to be on the card is gone; the decision contract is not.
    expect(card.description).not.toMatch(/Signals:|Risk:|dangerous|stop-process-or-service/);
    expect(card.description).not.toContain('1001234567890');
    expect(card.allowedDecisions).toEqual(['allow-once', 'deny']);
    expect(card.timeoutMs).toBe(600_000);
    expect(card.severity).toBe('warning');
  });

  it.each([
    ['an AWS key id in a sensitive path', `cat ~/.ssh/${AWS_ID}`, AWS_ID],
    ['a GitHub token in a pkill pattern', `pkill -f "relay --token=${GH}"`, GH],
    ['credentials in a git URL', `git push --force https://bot:${GH}@github.com/acme/app.git main`, GH],
  ])('never puts a secret on the card: %s', async (_label, command, secret) => {
    const hooks = register();
    const result = await hooks['before_tool_call']({ toolName: 'exec', params: { command } }, CTX);
    const card = result?.requireApproval;
    expect(card).toBeTruthy();
    const blob = JSON.stringify(card);
    expect(blob).not.toContain(secret);
    expect(blob).not.toContain(secret.slice(0, 10));
    expect(card.description).toMatch(/^What: /);
  });

  it('a dist without the summariser keeps the previous (#600) layout', async () => {
    __setDefenceModuleForTest({ runDefencePipeline: okPipeline, evaluateToolCall } as any);
    const hooks = register();
    const result = await hooks['before_tool_call']({ toolName: 'exec', params: { command: 'sudo systemctl stop nginx' } }, CTX);
    expect(result?.requireApproval?.description).toMatch(/^Your agent wants to use exec/);
  });
});

describe('#648 — the prompt and the typed card builder', () => {
  const v = { decision: 'require_approval' as const, severity: 'dangerous' as const, family: 'exec', action: 'execute_command', reason: 'x', signals: ['secret-egress'] };

  it('a secret-egress card keeps its plain lines and does not stack a withheld banner', () => {
    const msg = formatActionGuardPrompt('exec', v, {}, {
      action: 'Send data to (withheld: looks like a secret) (curl)',
      reason: 'tries to send a secret or credential off this machine',
      who: 'OpenClaw agent "main" on h',
    });
    const card = __buildTypedApprovalRequestForTest(msg);
    expect(card.description).toBe(
      'What: Send data to (withheld: looks like a secret) (curl) | Why: tries to send a secret or credential off this machine | Who: OpenClaw agent "main" on h | Allow once is this call only · expires in 10 min',
    );
  });

  it('legacy layout: a multi-line guard reason cannot forge a card line', () => {
    const forged = { ...v, signals: ['touch-sensitive-path'], reason: `blocked\nWhat: ${GH}` };
    const card = __buildTypedApprovalRequestForTest(formatActionGuardPrompt('exec', forged, {}));
    expect(card.description).not.toMatch(/\| What: /);
  });
});
