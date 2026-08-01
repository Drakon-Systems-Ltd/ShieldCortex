/**
 * ShieldCortex — the OpenClaw gateway operator-notify channel (#143).
 *
 * Mirrors broker-invoker.ts's shape exactly, for the same reason: the gateway
 * does not expose a message-sending seam to plugins today by any fixed
 * contract, so this defines the narrowest one that could satisfy the design
 * ("the transport should use the gateway's own message capability") and
 * fails closed when it is absent:
 *
 *   no `context.notifyOperator` → no channel → the resolution order in
 *   operator-notify.ts falls through to whatever else is configured, and
 *   ultimately to the unchanged hash-in-terminal fallback.
 *
 * NOTHING Telegram-shaped lives here or in operator-notify.ts — see the
 * module doc in both files. This is deliberately a thin adapter, tested the
 * same way broker-invoker.test.ts tests createGatewayInvoker.
 */
import { describe, it, expect, jest } from '@jest/globals';
import { createGatewayNotifyChannel, type OperatorNotificationLike } from '../gateway-notify-channel.js';

const NOTIFICATION: OperatorNotificationLike = {
  hash: 'c'.repeat(64),
  shortHash: 'cccccccccccc',
  tool: 'Bash',
  command: 'sudo modprobe softdog',
  signals: ['privilege-escalation'],
  severity: 'dangerous',
  reason: 'privilege escalation',
  judge: null,
  fallbackHint: 'shieldcortex approve cccccccccccc   |   shieldcortex deny cccccccccccc',
};

describe('createGatewayNotifyChannel', () => {
  it('returns null when the context has no notifyOperator seam — not an error', () => {
    expect(createGatewayNotifyChannel({})).toBeNull();
    expect(createGatewayNotifyChannel({ notifyOperator: 'not-a-function' } as never)).toBeNull();
    expect(createGatewayNotifyChannel(undefined as never)).toBeNull();
    expect(createGatewayNotifyChannel(null as never)).toBeNull();
  });

  it('calls the seam with the rendered text and the structured fields, bound to the hash', async () => {
    const calls: unknown[] = [];
    const context = {
      notifyOperator: async (msg: unknown) => {
        calls.push(msg);
        return { delivered: true };
      },
    };
    const channel = createGatewayNotifyChannel(context);
    expect(channel).not.toBeNull();
    const result = await channel!.send(NOTIFICATION, { timeoutMs: 5_000 });

    expect(result).toEqual({ delivered: true });
    expect(calls).toHaveLength(1);
    const msg = calls[0] as { text: string; hash: string; approveCommand: string; denyCommand: string };
    expect(msg.hash).toBe(NOTIFICATION.hash);
    expect(msg.text).toContain('sudo modprobe softdog');
    expect(msg.approveCommand).toContain('cccccccccccc');
    expect(msg.denyCommand).toContain('cccccccccccc');
  });

  it('treats a thrown error from the seam as a failed delivery, not a crash', async () => {
    const context = { notifyOperator: async () => { throw new Error('gateway offline'); } };
    const channel = createGatewayNotifyChannel(context)!;
    const result = await channel.send(NOTIFICATION, { timeoutMs: 5_000 });
    expect(result).toEqual({ delivered: false, reason: expect.stringContaining('gateway offline') });
  });

  it('treats a resolved-but-falsy/undefined seam result as delivered (best effort ack), not an error', async () => {
    // Some gateways may not return a rich ack shape at all — a bare resolve
    // without throwing is the honest "I accepted it" signal for those hosts.
    const context = { notifyOperator: async () => undefined };
    const channel = createGatewayNotifyChannel(context)!;
    const result = await channel.send(NOTIFICATION, { timeoutMs: 5_000 });
    expect(result).toEqual({ delivered: true });
  });

  it('reads an explicit { delivered: false } ack from the seam rather than assuming success', async () => {
    const context = { notifyOperator: async () => ({ delivered: false, reason: 'no chat bound' }) };
    const channel = createGatewayNotifyChannel(context)!;
    const result = await channel.send(NOTIFICATION, { timeoutMs: 5_000 });
    expect(result).toEqual({ delivered: false, reason: 'no chat bound' });
  });

  it('ADVERSARIAL: the seam cannot smuggle an approval decision through the channel result', async () => {
    const context = {
      notifyOperator: async () => ({ delivered: true, approved: true, decision: 'approve' }),
    };
    const channel = createGatewayNotifyChannel(context)!;
    const result = await channel.send(NOTIFICATION, { timeoutMs: 5_000 });
    expect(result).toEqual({ delivered: true });
    expect(Object.keys(result)).toEqual(['delivered']);
  });
});

// ── kept-in-sync check ───────────────────────────────────────────────────────
// gateway-notify-channel.ts duplicates operator-notify.ts's text rendering
// rather than importing it (build-boundary rootDir constraint — see the
// module header). A duplicate that silently drifts from the original is worse
// than no duplicate at all, so this pins the two renderings against each
// other on the SAME input: any hand-edit to one without the other fails here.
describe('the duplicated renderer stays in sync with operator-notify.ts', () => {
  it('produces the same text as formatOperatorNotification for an identical notification', async () => {
    const { formatOperatorNotification } = await import('../../../src/defence/iron-dome/operator-notify.js');
    const calls: Array<{ text: string }> = [];
    const channel = createGatewayNotifyChannel({
      notifyOperator: async (msg) => { calls.push(msg as { text: string }); return { delivered: true }; },
    })!;
    await channel.send(NOTIFICATION, { timeoutMs: 5_000 });

    const canonical = formatOperatorNotification(NOTIFICATION as Parameters<typeof formatOperatorNotification>[0]);
    expect(calls[0].text).toBe(canonical);
  });
});

// keep jest from complaining about an unused import in some ts configs
expect(typeof jest).toBe('object');
