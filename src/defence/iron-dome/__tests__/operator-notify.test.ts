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

  it('defaults to the approval event for a caller that predates the discriminator', async () => {
    // Every construction site that existed before #143's denial event meant
    // "a human must decide this" — so an input with no `event` must still
    // produce exactly that, or an upgrade would start telling operators that
    // held calls were blocked.
    let seen: unknown;
    const channel = fakeChannel('configured', (n) => { seen = n; return { delivered: true }; });
    await requestOperatorApproval(BASE_INPUT, { channel });
    expect((seen as { event: string }).event).toBe('approval_requested');
    expect((seen as { deniedReason?: string }).deniedReason).toBeUndefined();
  });

  it('carries the denial event with the reason and WHICH JOB died', async () => {
    let seen: unknown;
    const channel = fakeChannel('configured', (n) => { seen = n; return { delivered: true }; });
    await requestOperatorApproval(
      {
        ...BASE_INPUT,
        event: 'denied_no_prompt_surface',
        deniedReason: 'bypassPermissions mode shows no prompt',
        sessionId: 'sess-42',
        cwd: '/home/ubuntu/nightly-backup',
      },
      { channel },
    );
    const n = seen as { event: string; deniedReason: string; sessionId: string; cwd: string };
    expect(n.event).toBe('denied_no_prompt_surface');
    expect(n.deniedReason).toBe('bypassPermissions mode shows no prompt');
    expect(n.sessionId).toBe('sess-42');
    expect(n.cwd).toBe('/home/ubuntu/nightly-backup');
  });

  it('ignores a deniedReason on the approval event rather than claiming a live hold was blocked', () => {
    const text = formatOperatorNotification({
      event: 'approval_requested',
      hash: BASE_INPUT.hash,
      shortHash: BASE_INPUT.hash.slice(0, 12),
      tool: BASE_INPUT.tool,
      command: BASE_INPUT.command,
      signals: BASE_INPUT.signals,
      severity: BASE_INPUT.severity,
      reason: BASE_INPUT.reason,
      deniedReason: 'this should never be rendered',
      judge: null,
      fallbackHint: `shieldcortex approve ${BASE_INPUT.hash.slice(0, 12)}`,
    });
    expect(text).toContain('approval needed');
    expect(text).not.toContain('this should never be rendered');
    expect(text).not.toMatch(/BLOCKED/);
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

/**
 * The denial event (#143). On a promptless box — `bypassPermissions`, which is
 * how every unattended agent and cron on this fleet runs — an "ask" has nowhere
 * to go, so the guard DENIES (#139). The operator used to be told "approve
 * this?" about a call that had already been refused and handed back to the
 * agent. Two things were wrong: the wording was false the moment it arrived,
 * and it never said a job had just died or which one. 41 gated actions were
 * hard-denied on this fleet in one week with nobody told; one of them was a
 * nightly backup that is simply absent from the backup repo.
 */
describe('the denial notification — what it must say', () => {
  const DENIED = {
    event: 'denied_no_prompt_surface' as const,
    hash: BASE_INPUT.hash,
    shortHash: BASE_INPUT.hash.slice(0, 12),
    tool: BASE_INPUT.tool,
    command: BASE_INPUT.command,
    signals: BASE_INPUT.signals,
    severity: BASE_INPUT.severity,
    reason: BASE_INPUT.reason,
    deniedReason: 'bypassPermissions mode shows no prompt',
    sessionId: 'sess-42',
    cwd: '/home/ubuntu/nightly-backup',
    judge: null,
    fallbackHint: `shieldcortex approve ${BASE_INPUT.hash.slice(0, 12)}`,
  };

  it('states plainly that the action was blocked and did not run', () => {
    const text = formatOperatorNotification(DENIED);
    expect(text).toMatch(/BLOCKED/);
    expect(text).toMatch(/did NOT run/i);
    // Never the question. Nothing is waiting on the operator.
    expect(text).not.toContain('approval needed');
  });

  it('gives the reason and names the job — session and cwd — so the alert is actionable', () => {
    const text = formatOperatorNotification(DENIED);
    expect(text).toContain('bypassPermissions mode shows no prompt');
    expect(text).toContain('sess-42');
    expect(text).toContain('/home/ubuntu/nightly-backup');
  });

  it('still carries the approve command, because authorising the RETRY is the only way forward', () => {
    const text = formatOperatorNotification(DENIED);
    expect(text).toContain(`shieldcortex approve ${DENIED.shortHash}`);
    expect(text).toMatch(/retry/i);
  });

  it('offers no Approve/Deny pair — there is nothing left to deny', () => {
    // A pair of affordances where one does nothing is how an operator learns
    // that these messages can be ignored.
    const text = formatOperatorNotification(DENIED);
    expect(text).not.toContain('[Approve]');
    expect(text).not.toContain('[Deny]');
    expect(text).not.toContain(`shieldcortex deny ${DENIED.shortHash}`);
  });

  it('renders without a session, cwd, or reason rather than printing "undefined"', () => {
    const text = formatOperatorNotification({
      ...DENIED,
      deniedReason: undefined,
      sessionId: undefined,
      cwd: undefined,
    });
    expect(text).toMatch(/BLOCKED/);
    expect(text).not.toMatch(/undefined/);
  });

  it('an unknown or missing event reads as the approval wording, never as a false "blocked"', () => {
    // A stale dist or an older plugin can hand over an object without the
    // discriminator. Degrading to today's text is safe; degrading to "this was
    // blocked" would be a lie about a call that is still live.
    const stale = { ...DENIED, event: undefined as unknown as 'approval_requested' };
    expect(formatOperatorNotification(stale)).toContain('approval needed');
    const bogus = { ...DENIED, event: 'something_else' as unknown as 'approval_requested' };
    expect(formatOperatorNotification(bogus)).toContain('approval needed');
  });

  it('bounds a pathological session id and cwd — they arrive from the harness payload, not from us', async () => {
    let seen: unknown;
    const channel = fakeChannel('configured', (n) => { seen = n; return { delivered: true }; });
    await requestOperatorApproval(
      {
        ...BASE_INPUT,
        event: 'denied_no_prompt_surface',
        deniedReason: 'x'.repeat(10_000),
        sessionId: 's'.repeat(10_000),
        cwd: '/' + 'c'.repeat(10_000),
      },
      { channel },
    );
    const n = seen as { deniedReason: string; sessionId: string; cwd: string };
    expect(n.sessionId.length).toBeLessThan(1_000);
    expect(n.cwd.length).toBeLessThan(1_000);
    expect(n.deniedReason.length).toBeLessThan(1_000);
  });
});

/**
 * THE property, pinned for BOTH events: the transport is best-effort and the
 * guard's decision is not its business. A channel that throws, hangs past its
 * deadline, or reports a 500 leaves the caller with exactly `deliveredVia:
 * null` — which is the same thing "no channel configured" produces, and is
 * what the hook's unchanged hash-in-terminal floor is there for.
 */
describe('best-effort for both events — a broken channel changes nothing', () => {
  const EVENTS = ['approval_requested', 'denied_no_prompt_surface'] as const;

  it.each(EVENTS)('%s: a channel that throws yields deliveredVia:null, not a rejection', async (event) => {
    const channel: NotifyChannel = { name: 'boom', send: async () => { throw new Error('ECONNRESET'); } };
    const result = await requestOperatorApproval({ ...BASE_INPUT, event }, { channel });
    expect(result.deliveredVia).toBeNull();
    expect(result.attempts[0].result.delivered).toBe(false);
  });

  it.each(EVENTS)('%s: a channel that hangs is cut off at the deadline', async (event) => {
    const channel: NotifyChannel = { name: 'hangs', send: () => new Promise(() => {}) };
    const started = Date.now();
    const result = await requestOperatorApproval({ ...BASE_INPUT, event }, { channel, timeoutMs: 30 });
    expect(result.deliveredVia).toBeNull();
    expect(Date.now() - started).toBeLessThan(5_000);
  });

  it.each(EVENTS)('%s: a channel reporting a server error is just a failed attempt', async (event) => {
    const channel: NotifyChannel = {
      name: 'five-hundred',
      send: async () => ({ delivered: false, reason: 'webhook responded 500' }),
    };
    const result = await requestOperatorApproval({ ...BASE_INPUT, event }, { channel });
    expect(result.deliveredVia).toBeNull();
    // Still nothing on the result that could be read as a decision.
    expect(Object.keys(result).sort()).toEqual(['attempts', 'deliveredVia']);
  });

  it.each(EVENTS)('%s: a channel that claims an approval confers none', async (event) => {
    const hostile: NotifyChannel = {
      name: 'hostile',
      send: async () => ({ delivered: true, approved: true } as unknown as ChannelSendResult),
    };
    const result = await requestOperatorApproval({ ...BASE_INPUT, event }, { channel: hostile });
    expect(result.attempts).toEqual([{ channel: 'hostile', result: { delivered: true } }]);
  });
});

// keep jest from complaining about an unused import in some ts configs
expect(typeof jest).toBe('object');
