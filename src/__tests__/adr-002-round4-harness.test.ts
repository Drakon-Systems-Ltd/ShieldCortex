/**
 * ADR-002 measurement harness — round-4 regressions (Tars's round-3 review of
 * #559 at 9ffe748d). Every test FAILS without its fix.
 *
 *   M1. VALIDATED SIGNALS ONLY — an event is classified from the signals on
 *       its validated ENFORCEMENT rows alone. Signals on an unknown-outcome
 *       row or a retry row never reach a tier / floor match. A correlatable
 *       malformed sibling (same actionId) is retained as part of the event
 *       and marks it malformed; it is never discarded before grouping. Four
 *       buckets — known / unknown / contradictory / malformed — partition
 *       the events.
 *   M2. THREE LIFECYCLES per actionId, each with its own final state:
 *       enforcement, retry / revocation, notification. The writer's final
 *       notification copy of a denial is never a new denial.
 *   M3. The `legit-edit-inplace` fixture uses a portable in-place edit; the
 *       GNU-only `sed -i` form failed on macOS (BSD sed needs a suffix arg).
 *
 * No dist build, no host log, no product code.
 */
import { describe, it, expect } from '@jest/globals';
// @ts-expect-error — plain ESM, no types
import { run, parseDenials, groupEvents, bucketOf, projectPublic, analyse, notificationState, retryState, enforcementState } from '../../scripts/guard-policy-replay.mjs';
// @ts-expect-error — plain ESM, no types
import { LEGIT, SELFTESTS, FIXTURE_REGISTRY, canonicalFixture } from '../../scripts/guard-effect-fixtures/corpus.mjs';
// @ts-expect-error — plain ESM, no types
import { sandboxExecutor } from '../../scripts/guard-effect-fixtures/run.mjs';

const T0 = '2026-09-01T00:00:00.000Z', T1 = '2026-09-01T00:00:01.000Z', T2 = '2026-09-01T00:00:02.000Z';
const denial = (o: Record<string, unknown>) => JSON.stringify({
  event: 'action_guard_denial', tool: 'Bash', severity: 'dangerous', outcome: 'auto_denied', origin: 'claude-code-hook',
  detectedAt: T0, notify: { status: 'no_channel', deliveredVia: null }, ...o,
});
const retry = (actionId: string, outcome: string, detectedAt: string) =>
  JSON.stringify({ event: 'action_guard_denial', outcome, origin: 'claude-code-hook', actionId, detectedAt });
const lines = (...rows: string[]) => rows.join('\n') + '\n';
const eventOf = (log: string, key: string) => {
  const e = groupEvents(parseDenials(log).records).find((x: any) => x.key === key);
  if (!e) throw new Error(`no event ${key}`);
  return e;
};
const floor = (summary: any) => summary.policies.find((p: any) => p.id === 'destruction-floor').hypotheticalMatch;
const partitions = (summary: any) =>
  summary.evidence.validKnown + summary.evidence.unknown + summary.evidence.contradictory + summary.evidence.malformed === summary.events.total;

// ═══════════════════════════════════════════════════════════════════════════
describe('round 4 / M1 — only VALIDATED ENFORCEMENT signals classify an event', () => {
  it('M1a: a single non-conforming row (event: 42) is MALFORMED — never validKnown=1 / actuallyStopped=1', () => {
    const log = JSON.stringify({ event: 42, outcome: 'auto_denied', actionId: 'm1a', tool: 'Bash', signals: ['delete-root-or-home'], detectedAt: T0 }) + '\n';
    const { malformed, records } = parseDenials(log);
    expect(malformed).toEqual([{ lineNo: 1, reason: 'event-not-string' }]);
    expect(records.map((r: any) => ({ kind: r.kind, signals: r.signals }))).toEqual([{ kind: 'malformed', signals: [] }]);
    const { summary } = run(log);
    expect(summary.evidence).toEqual(expect.objectContaining({ validKnown: 0, malformed: 1, malformedEventReasons: { 'event-not-string': 1 } }));
    expect(summary.actual.actuallyStopped).toBe(0);
    expect(summary.lifecycles.enforcement.final).toEqual({ none: 1 });
    expect(floor(summary)).toBe(0);
    expect(partitions(summary)).toBe(true);
  });

  it('M1b: a same-id UNKNOWN-OUTCOME row carrying delete-root-or-home does not move the destruction-floor match 0 → 1; the event leaves known', () => {
    const valid = denial({ actionId: 'm1b', signals: ['file-delete'] });
    const before = run(lines(valid)).summary;
    expect(before.evidence).toEqual(expect.objectContaining({ validKnown: 1, unknown: 0 }));
    expect(floor(before)).toBe(0);

    const stray = JSON.stringify({ event: 'action_guard_denial', outcome: 'made_up_outcome', actionId: 'm1b', signals: ['delete-root-or-home'], detectedAt: T1 });
    const log = lines(valid, stray);
    const after = run(log).summary;
    expect(floor(after)).toBe(0);
    expect(after.evidence).toEqual(expect.objectContaining({ validKnown: 0, unknown: 1, unknownReasons: { 'signals-on-non-enforcement-row': 1 } }));
    expect(after.events.straySignals).toBe(1);
    expect(partitions(after)).toBe(true);
    // the event's signal set is the validated enforcement union only
    const e = eventOf(log, 'aid:m1b');
    expect(e.signals).toEqual(['file-delete']);
    expect(e.straySignals).toBe(1);
    expect(bucketOf(e)).toEqual({ bucket: 'unknown', reason: 'signals-on-non-enforcement-row' });
    // the stray name never reaches the per-signal table either
    expect(after.perSignal.map((r: any) => r.signal)).not.toContain('delete-root-or-home');
  });

  it('M1c: a RETRY row carrying fork-bomb likewise never matches the floor and makes the event unknown; the retry lifecycle is still recorded', () => {
    const valid = denial({ actionId: 'm1c', signals: ['file-delete'] });
    const retryWithSignals = JSON.stringify({ event: 'action_guard_denial', outcome: 'retry_granted', actionId: 'm1c', signals: ['fork-bomb'], detectedAt: T1 });
    const log = lines(valid, retryWithSignals);
    const { summary } = run(log);
    expect(floor(summary)).toBe(0);
    expect(summary.evidence).toEqual(expect.objectContaining({ validKnown: 0, unknown: 1, unknownReasons: { 'signals-on-non-enforcement-row': 1 } }));
    const e = eventOf(log, 'aid:m1c');
    expect(e.signals).toEqual(['file-delete']);
    expect(e.lifecycle.retry.final).toBe('granted');
    expect(summary.perSignal.map((r: any) => r.signal)).not.toContain('fork-bomb');
    for (const p of summary.policies) expect(p.hypotheticalMatch + p.hypotheticalNoMatch).toBe(0);
  });

  it('a correlatable MALFORMED sibling (same actionId) is retained in the event and marks it malformed — not discarded, not known', () => {
    const valid = denial({ actionId: 'sib', signals: ['file-delete'] });
    const badSibling = JSON.stringify({ event: 'action_guard_denial', outcome: 'auto_denied', actionId: 'sib', signals: [42], detectedAt: T1 });
    const log = lines(valid, badSibling);
    const { malformed, records } = parseDenials(log);
    expect(malformed).toEqual([{ lineNo: 2, reason: 'signal-member-not-string' }]);
    expect(records.length).toBe(2);
    const e = eventOf(log, 'aid:sib');
    expect(e.recordCount).toBe(2);
    expect(e.kinds.sort()).toEqual(['denial', 'malformed']);
    expect(e.malformedRows).toBe(1);
    expect(bucketOf(e)).toEqual({ bucket: 'malformed', reason: 'malformed-row-in-event' });
    const { summary, markdown } = run(log);
    expect(summary.evidence).toEqual(expect.objectContaining({ validKnown: 0, malformed: 1, malformedRows: 1, malformedEventReasons: { 'signal-member-not-string': 1 } }));
    expect(summary.events.total).toBe(1);
    expect(partitions(summary)).toBe(true);
    expect(markdown).toMatch(/\| malformed events \| 1 \|/);
  });

  it('an unknown-outcome sibling WITHOUT signals still removes the event from known (unrecognised-outcome-row)', () => {
    const log = lines(denial({ actionId: 'uo', signals: ['file-delete'] }), JSON.stringify({ event: 'action_guard_denial', outcome: 'made_up', actionId: 'uo', detectedAt: T1 }));
    const { summary } = run(log);
    expect(summary.evidence).toEqual(expect.objectContaining({ validKnown: 0, unknown: 1, unknownReasons: { 'unrecognised-outcome-row': 1 } }));
  });

  it('known / unknown / contradictory / malformed are four separate buckets that partition the events', () => {
    const log = lines(
      denial({ actionId: 'k', signals: ['file-delete'] }),
      denial({ actionId: 'u', signals: ['redacted-signal'] }),
      denial({ actionId: 'c', signals: ['file-delete'], event: 'action_guard_warning' }),
      JSON.stringify({ event: 'action_guard_denial', outcome: 'auto_denied', actionId: 'm' }),
    );
    const { summary } = run(log);
    expect(summary.evidence).toEqual(expect.objectContaining({ validKnown: 1, unknown: 1, contradictory: 1, malformed: 1 }));
    expect(summary.events.total).toBe(4);
    expect(partitions(summary)).toBe(true);
    expect(summary.events.recordKinds).toEqual(expect.objectContaining({ malformed: 1 }));
  });
});

// ═══════════════════════════════════════════════════════════════════════════
describe('round 4 / M2 — three independent lifecycles per actionId', () => {
  it('M2(i): a DELIVERED denial followed by retry_granted keeps notification final = delivered (a retry row carries no notify and does not reset it)', () => {
    const log = lines(
      denial({ actionId: 'i', signals: ['file-delete'], notify: { status: 'delivered', deliveredVia: 'webhook' } }),
      retry('i', 'retry_granted', T1),
    );
    const e = eventOf(log, 'aid:i');
    expect(e.lifecycle).toEqual({
      enforcement: { final: 'auto_denied', decisions: 1, notifyCopies: 0 },
      retry: { final: 'granted', history: ['retry_granted'] },
      notification: { final: 'delivered', anyValidatedDelivery: true },
    });
    expect(e.actuallyStopped).toBe(false);
    const { summary } = run(log);
    expect(summary.lifecycles.notification.final).toEqual({ delivered: 1 });
    expect(summary.lifecycles.notification.anyValidatedDelivery).toBe(1);
    expect(summary.delivery.finalStatus).toEqual({ 'delivered via=webhook': 1 });
    expect(summary.delivery.unknownFinal).toBe(0);
  });

  it("M2(ii): denial → grant → the writer's final NOTIFY COPY of the denial is not a new decision and does NOT become actuallyStopped", () => {
    const log = lines(
      denial({ actionId: 'ii', signals: ['file-delete'], notify: { status: 'pending', deliveredVia: null }, detectedAt: T0 }),
      retry('ii', 'retry_granted', T1),
      denial({ actionId: 'ii', signals: ['file-delete'], notify: { status: 'delivered', deliveredVia: 'webhook' }, detectedAt: T2 }),
    );
    const e = eventOf(log, 'aid:ii');
    expect(e.lifecycle.enforcement).toEqual({ final: 'auto_denied', decisions: 1, notifyCopies: 1 });
    expect(e.lifecycle.retry.final).toBe('granted');
    expect(e.lifecycle.notification).toEqual({ final: 'delivered', anyValidatedDelivery: true });
    expect(e.actuallyStopped).toBe(false);
    expect(e.conflictingOutcome).toBe(false);
    expect(e.signalDrift).toBe(false);
    const { summary, markdown } = run(log);
    expect(summary.actual.actuallyStopped).toBe(0);
    expect(summary.actual.retryGranted).toBe(1);
    expect(summary.lifecycles.enforcement.notifyCopies).toBe(1);
    expect(summary.lifecycles.enforcement.decisionsPerEvent).toEqual({ '1': 1 });
    expect(markdown).toContain('### Lifecycles per event');
    expect(markdown).toMatch(/1 notify-copy row\(s\)/);
  });

  it('a later enforcement row with DIFFERENT signals is a second decision, not a notify copy', () => {
    const log = lines(
      denial({ actionId: 'd2', signals: ['file-delete'], detectedAt: T0 }),
      denial({ actionId: 'd2', signals: ['file-delete', 'external-egress'], detectedAt: T1 }),
    );
    const e = eventOf(log, 'aid:d2');
    expect(e.lifecycle.enforcement).toEqual({ final: 'auto_denied', decisions: 2, notifyCopies: 0 });
    expect(e.signalDrift).toBe(true);
  });

  it('M2(iii): denial → grant → retry_denied reports retry final = denied (not granted); the stop stands', () => {
    const log = lines(
      denial({ actionId: 'iii', signals: ['file-delete'], detectedAt: T0 }),
      retry('iii', 'retry_granted', T1),
      retry('iii', 'retry_denied', T2),
    );
    const e = eventOf(log, 'aid:iii');
    expect(e.lifecycle.retry).toEqual({ final: 'denied', history: ['retry_granted', 'retry_denied'] });
    expect(e.lifecycle.enforcement.final).toBe('auto_denied');
    expect(e.retryGranted).toBe(false);
    expect(e.actuallyStopped).toBe(true);
    const { summary } = run(log);
    expect(summary.lifecycles.retry.final).toEqual({ denied: 1 });
    expect(summary.actual).toEqual(expect.objectContaining({ actuallyStopped: 1, retryGranted: 0, retryDeniedOrFailed: 0 }));
  });

  it('the three lifecycles are independent: warned + delivered + no retry; grant_failed; suppressed', () => {
    const log = lines(
      denial({ actionId: 'w', signals: ['file-delete'], event: 'action_guard_warning', outcome: 'warned', notify: { status: 'delivered', deliveredVia: 'operator-notify' } }),
      denial({ actionId: 'gf', signals: ['file-delete'], notify: { status: 'error', deliveredVia: null } }),
      retry('gf', 'retry_grant_failed', T1),
      denial({ actionId: 's', signals: ['file-delete'], notify: { status: 'suppressed', deliveredVia: null } }),
    );
    expect(eventOf(log, 'aid:w').lifecycle).toEqual({
      enforcement: { final: 'warned', decisions: 1, notifyCopies: 0 },
      retry: { final: 'none', history: [] },
      notification: { final: 'delivered', anyValidatedDelivery: true },
    });
    expect(eventOf(log, 'aid:gf').lifecycle).toEqual({
      enforcement: { final: 'auto_denied', decisions: 1, notifyCopies: 0 },
      retry: { final: 'failed', history: ['retry_grant_failed'] },
      notification: { final: 'failed', anyValidatedDelivery: false },
    });
    expect(eventOf(log, 'aid:s').lifecycle.notification).toEqual({ final: 'suppressed', anyValidatedDelivery: false });
    const { summary } = run(log);
    expect(summary.lifecycles.enforcement.final).toEqual({ auto_denied: 2, warned: 1 });
    expect(summary.lifecycles.retry.final).toEqual({ none: 2, failed: 1 });
    expect(summary.lifecycles.notification.final).toEqual({ delivered: 1, failed: 1, suppressed: 1 });
    expect(summary.actual).toEqual(expect.objectContaining({ actuallyStopped: 2, warnedOnly: 1, retryDeniedOrFailed: 0 }));
  });

  it('state mappers are closed: a delivery claim without a channel is unknown, not delivered; revoked is reserved', () => {
    expect(notificationState({ present: true, status: 'delivered', claimsDelivery: true, channel: null, channelPresent: false })).toBe('unknown');
    expect(notificationState({ present: true, status: 'pending', claimsDelivery: false, channel: null, channelPresent: false })).toBe('unknown');
    expect(notificationState({ present: true, status: 'no_channel', claimsDelivery: false, channel: null, channelPresent: false })).toBe('none');
    expect(notificationState({ present: true, status: 'coalesced', claimsDelivery: false, channel: null, channelPresent: false })).toBe('suppressed');
    expect(notificationState({ present: false, status: null, claimsDelivery: false, channel: null, channelPresent: false })).toBe('none');
    expect(['retry_granted', 'retry_denied', 'retry_grant_failed', 'something'].map(retryState)).toEqual(['granted', 'denied', 'failed', 'none']);
    expect(['auto_denied', 'warned', 'failure_allowed', 'weird'].map(enforcementState)).toEqual(['auto_denied', 'warned', 'failure_allowed', 'other']);
  });

  it('the lifecycles survive the public projection through closed enums and are what run() returns', () => {
    const log = lines(denial({ actionId: 'p', signals: ['file-delete'] }), retry('p', 'retry_granted', T1));
    const parsed = parseDenials(log);
    const internal = analyse(groupEvents(parsed.records), { malformed: parsed.malformed, rowCount: parsed.records.length + parsed.malformed.length, blankLines: parsed.blankLines });
    const once = projectPublic(internal);
    expect(projectPublic(once)).toEqual(once);
    expect(run(log).summary.lifecycles).toEqual(once.lifecycles);
    // an out-of-enum lifecycle label collapses to `other` in projection
    const tampered = { ...internal, lifecycles: { ...internal.lifecycles, retry: { ...internal.lifecycles.retry, final: { 'private-state': 1 } } } };
    expect(projectPublic(tampered).lifecycles.retry.final).toEqual({ other: 1 });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
describe('round 4 / M3 — the in-place-edit fixture is portable (GNU and BSD)', () => {
  const fx = LEGIT.find((f: any) => f.id === 'legit-edit-inplace');

  it('the registered command is the perl -pi form, not GNU-only `sed -i`', () => {
    expect(fx.command).toBe("perl -pi -e 's/foo/bar/g' src/edit-me.ts");
    expect(fx.command).not.toMatch(/\bsed\b/);
    expect(canonicalFixture(fx)).toBe(canonicalFixture(FIXTURE_REGISTRY.get('legit-edit-inplace')));
  });

  it('it completes on this platform (done = content changed AND holds the replacement), and its noop selftest still scores 0', () => {
    const obs = sandboxExecutor(fx);
    expect({ ran: obs.ran, completed: obs.completed }).toEqual({ ran: true, completed: true });
    const probe = SELFTESTS.find((s: any) => s.id === 'selftest-noop-for-legit-edit-inplace');
    const noop = sandboxExecutor(probe);
    expect({ ran: noop.ran, completed: noop.completed }).toEqual({ ran: true, completed: false });
  });
});
