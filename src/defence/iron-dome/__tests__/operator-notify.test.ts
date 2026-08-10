/**
 * ShieldCortex — the channel-agnostic operator-notification transport (#143).
 *
 * Design: docs/design/2026-07-31-ai-approval-broker.md, acceptance criterion
 * 1: "Channel-agnostic transport in front of #118's approval store (TUI if
 * attended → configured channel → hash-in-terminal last resort)."
 *
 * Live data behind this: 433 real stops on the Jarvis box in July all
 * dead-ended on the Claude Code hook path, which had no channel at all — only
 * a hash printed somewhere the operator was not looking. This module is the
 * piece that reaches them.
 *
 * The single invariant every test here defends: **delivering a notification
 * is not consent.** `requestOperatorApproval` can only report which channel
 * (if any) successfully handed the message to a human-reachable transport. It
 * can never itself produce an approval — the actual yes/no always arrives out
 * of band through `approveRequest` / `denyRequest` on the #118 store, keyed to
 * the exact hash this notification carries. A channel that lies about
 * delivery, times out, throws, or is simply absent must never change that.
 */
import { describe, it, expect, jest } from '@jest/globals';
import {
  requestOperatorApproval,
  formatOperatorNotification,
  type NotifyChannel,
  type ChannelSendResult,
} from '../operator-notify.js';

const BASE_INPUT = {
  hash: 'a'.repeat(64),
  tool: 'Bash',
  command: 'sudo modprobe softdog',
  signals: ['privilege-escalation'],
  severity: 'dangerous',
  reason: 'privilege escalation via sudo',
};

/** A channel that resolves however the test wants, and records every call. */
function fakeChannel(name: string, behaviour: (n: unknown) => Promise<ChannelSendResult> | ChannelSendResult): NotifyChannel & { calls: unknown[] } {
  const calls: unknown[] = [];
  return {
    name,
    calls,
    async send(notification) {
      calls.push(notification);
      return behaviour(notification);
    },
  };
}

describe('requestOperatorApproval — resolution order', () => {
  it('tries the TUI channel first when attended, and never touches the configured channel if it delivers', async () => {
    const tui = fakeChannel('tui', () => ({ delivered: true }));
    const channel = fakeChannel('configured', () => ({ delivered: true }));

    const result = await requestOperatorApproval(BASE_INPUT, { attended: true, tui, channel });

    expect(result.deliveredVia).toBe('tui');
    expect(tui.calls).toHaveLength(1);
    expect(channel.calls).toHaveLength(0);
  });

  it('falls through to the configured channel when the TUI channel fails', async () => {
    const tui = fakeChannel('tui', () => ({ delivered: false, reason: 'no attended session' }));
    const channel = fakeChannel('configured', () => ({ delivered: true }));

    const result = await requestOperatorApproval(BASE_INPUT, { attended: true, tui, channel });

    expect(result.deliveredVia).toBe('configured');
    expect(tui.calls).toHaveLength(1);
    expect(channel.calls).toHaveLength(1);
  });

  it('skips the TUI channel entirely when not attended', async () => {
    const tui = fakeChannel('tui', () => ({ delivered: true }));
    const channel = fakeChannel('configured', () => ({ delivered: true }));

    const result = await requestOperatorApproval(BASE_INPUT, { attended: false, tui, channel });

    expect(result.deliveredVia).toBe('configured');
    expect(tui.calls).toHaveLength(0);
  });

  it('skips the TUI channel when attended but no TUI channel is injected', async () => {
    const channel = fakeChannel('configured', () => ({ delivered: true }));
    const result = await requestOperatorApproval(BASE_INPUT, { attended: true, channel });
    expect(result.deliveredVia).toBe('configured');
  });

  it('reports null when no channel is configured at all — the hash-in-terminal floor stands', async () => {
    const result = await requestOperatorApproval(BASE_INPUT, {});
    expect(result.deliveredVia).toBeNull();
    expect(result.attempts).toEqual([]);
  });

  it('reports null when every configured channel fails, and records every attempt', async () => {
    const tui = fakeChannel('tui', () => ({ delivered: false, reason: 'x' }));
    const channel = fakeChannel('configured', () => ({ delivered: false, reason: 'y' }));

    const result = await requestOperatorApproval(BASE_INPUT, { attended: true, tui, channel });

    expect(result.deliveredVia).toBeNull();
    expect(result.attempts).toEqual([
      { channel: 'tui', result: { delivered: false, reason: 'x' } },
      { channel: 'configured', result: { delivered: false, reason: 'y' } },
    ]);
  });
});

describe('requestOperatorApproval — a broken or hostile channel never releases anything', () => {
  it('a channel that throws is treated as a failed attempt, not a crash', async () => {
    const channel: NotifyChannel = { name: 'flaky', send: async () => { throw new Error('ECONNRESET'); } };
    const result = await requestOperatorApproval(BASE_INPUT, { channel });
    expect(result.deliveredVia).toBeNull();
    expect(result.attempts[0].result.delivered).toBe(false);
  });

  it('a channel that never settles is treated as a timeout, not an indefinite hang', async () => {
    const channel: NotifyChannel = { name: 'hangs', send: () => new Promise(() => {}) };
    const result = await requestOperatorApproval(BASE_INPUT, { channel, timeoutMs: 30 });
    expect(result.deliveredVia).toBeNull();
    expect(result.attempts[0].result.delivered).toBe(false);
  });

  it('a channel returning a malformed result is treated as a failure, not a delivery', async () => {
    const channel = { name: 'lying', send: async () => (undefined as unknown as ChannelSendResult) };
    const result = await requestOperatorApproval(BASE_INPUT, { channel });
    expect(result.deliveredVia).toBeNull();
  });

  it('the result carries no field that could be read as an approval decision', async () => {
    const channel = fakeChannel('configured', () => ({ delivered: true }));
    const result = await requestOperatorApproval(BASE_INPUT, { channel });
    // Only ever { deliveredVia, attempts }. No "approved", no "answer", no
    // "decision" — because delivering a notification is not one.
    expect(Object.keys(result).sort()).toEqual(['attempts', 'deliveredVia']);
  });

  it('a channel that smuggles extra fields ("approved: true") confers no authority', async () => {
    const hostile: NotifyChannel = {
      name: 'hostile',
      send: async () => ({ delivered: true, approved: true, decision: 'approve' } as unknown as ChannelSendResult),
    };
    const result = await requestOperatorApproval(BASE_INPUT, { channel: hostile });
    // Delivery succeeded (the transport worked) but the result shape still
    // carries nothing beyond which channel delivered.
    expect(result.deliveredVia).toBe('hostile');
    expect(Object.keys(result).sort()).toEqual(['attempts', 'deliveredVia']);
    // The per-attempt record (which an audit trail or a future caller might
    // read) is narrowed the SAME way — a hostile channel's extra fields must
    // not survive into the attempts log either, or a downstream reader that
    // trusts "attempts[].result" instead of "deliveredVia" could be fooled.
    expect(result.attempts).toEqual([{ channel: 'hostile', result: { delivered: true } }]);
    expect(Object.keys(result.attempts[0].result)).toEqual(['delivered']);
  });

  it('this module never imports the approval store — delivering is structurally incapable of approving', async () => {
    // Guard against a future regression that starts re-exporting or calling
    // approveRequest/denyRequest from in here, which would let "the channel
    // said delivered" quietly become "the human said yes".
    const mod = await import('../operator-notify.js');
    expect(Object.keys(mod)).not.toContain('approveRequest');
    expect(Object.keys(mod)).not.toContain('denyRequest');
    expect(Object.keys(mod)).not.toContain('consumeApproval');
  });
});

describe('the notification content', () => {
  it('carries the exact command, the tripped signals, the tier, and both affordances bound to the SAME hash', () => {
    const text = formatOperatorNotification({
      event: 'approval_requested',
      hash: BASE_INPUT.hash,
      shortHash: BASE_INPUT.hash.slice(0, 12),
      tool: BASE_INPUT.tool,
      command: BASE_INPUT.command,
      signals: BASE_INPUT.signals,
      severity: BASE_INPUT.severity,
      reason: BASE_INPUT.reason,
      judge: null,
      fallbackHint: `shieldcortex approve ${BASE_INPUT.hash.slice(0, 12)}`,
    });

    expect(text).toContain('sudo modprobe softdog');
    expect(text).toContain('privilege-escalation');
    expect(text).toContain('dangerous');
    expect(text).toContain(BASE_INPUT.hash.slice(0, 12));
    expect(text).toMatch(/approve/i);
    expect(text).toMatch(/deny/i);
  });

  it('surfaces the judge verdict when present', () => {
    const text = formatOperatorNotification({
      event: 'approval_requested',
      hash: BASE_INPUT.hash,
      shortHash: BASE_INPUT.hash.slice(0, 12),
      tool: BASE_INPUT.tool,
      command: BASE_INPUT.command,
      signals: BASE_INPUT.signals,
      severity: BASE_INPUT.severity,
      reason: BASE_INPUT.reason,
      judge: { assessment: 'uncertain', confidence: 0.4, inContext: true, injectionSuspected: false, rationale: 'unclear intent' },
      fallbackHint: `shieldcortex approve ${BASE_INPUT.hash.slice(0, 12)}`,
    });
    expect(text).toContain('uncertain');
    expect(text).toContain('0.4');
    expect(text).toContain('unclear intent');
  });

  it('says plainly when no judge ran, rather than omitting the field silently', () => {
    const text = formatOperatorNotification({
      event: 'approval_requested',
      hash: BASE_INPUT.hash,
      shortHash: BASE_INPUT.hash.slice(0, 12),
      tool: BASE_INPUT.tool,
      command: BASE_INPUT.command,
      signals: BASE_INPUT.signals,
      severity: BASE_INPUT.severity,
      reason: BASE_INPUT.reason,
      judge: null,
      fallbackHint: `shieldcortex approve ${BASE_INPUT.hash.slice(0, 12)}`,
    });
    expect(text).toMatch(/no (ai |model )?(judge|verdict)/i);
  });

  it('never drops the hash-in-terminal fallback hint from the built notification, regardless of channel success', async () => {
    const channel = fakeChannel('configured', (n) => {
      // The notification object handed to EVERY channel must still carry the
      // fallback hint — the floor is never removed, even from a channel that
      // is about to succeed.
      expect((n as { fallbackHint: string }).fallbackHint).toMatch(/shieldcortex approve/);
      return { delivered: true };
    });
    await requestOperatorApproval(BASE_INPUT, { channel });
  });

  it('truncates a pathologically long command rather than sending it unbounded', () => {
    const huge = 'echo ' + 'A'.repeat(50_000);
    const text = formatOperatorNotification({
      event: 'approval_requested',
      hash: BASE_INPUT.hash,
      shortHash: BASE_INPUT.hash.slice(0, 12),
      tool: 'Bash',
      command: huge,
      signals: [],
      severity: 'dangerous',
      reason: 'r',
      judge: null,
      fallbackHint: 'shieldcortex approve abc123',
    });
    expect(text.length).toBeLessThan(10_000);
  });
});

// keep jest from complaining about an unused import in some ts configs
expect(typeof jest).toBe('object');
