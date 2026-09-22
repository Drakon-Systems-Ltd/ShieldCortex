/**
 * ADR-002 measurement harness — round-5 regressions (Tars's round-4 review of
 * #559 at d9d71691). Half A accounting only. Every test FAILS without its fix.
 *
 *   M1(a) INPUT ACCOUNTING — one input row is counted exactly once:
 *         rows.total = parsed + malformed; blank lines separate; retaining a
 *         malformed object for correlation never adds a second count.
 *   M1(b) NO DECLARED-PAIR SHORTCUT — an event with no validated enforcement
 *         decision is never known / stopped; a retry row is validated against
 *         the same schema as an enforcement row (present string event equal to
 *         action_guard_denial); an unvalidated retry row is malformed or
 *         contradictory and never sets retry = granted.
 *   M1(c) LEGACY ACCEPTANCE is explicit and closed — the only pre-schema
 *         tolerances are: no notify, no actionId, no origin / sessionId.
 *   M2    RETRY LIFECYCLE IS A HISTORY — grantSeen latches on any validated
 *         grant; effective is the current state; a grant_failed AFTER a grant is
 *         a failed re-issue (unknown), not a revocation; the earlier grant
 *         survives in the public projection.
 *
 * No dist build, no host log, no product code.
 */
import { describe, it, expect } from '@jest/globals';
// @ts-expect-error — plain ESM, no types
import { run, parseDenials, groupEvents, analyse, projectPublic, classifyRecord, bucketOf, retryLifecycle, retryHistoryKey, RETRY_STATES } from '../../scripts/guard-policy-replay.mjs';

const T0 = '2026-09-01T00:00:00.000Z', T1 = '2026-09-01T00:00:01.000Z', T2 = '2026-09-01T00:00:02.000Z', T3 = '2026-09-01T00:00:03.000Z';
const denial = (o: Record<string, unknown>) => JSON.stringify({
  event: 'action_guard_denial', tool: 'Bash', severity: 'dangerous', outcome: 'auto_denied', origin: 'claude-code-hook',
  detectedAt: T0, notify: { status: 'no_channel', deliveredVia: null }, ...o,
});
const retry = (actionId: string, outcome: string, detectedAt: string, extra: Record<string, unknown> = {}) =>
  JSON.stringify({ event: 'action_guard_denial', outcome, origin: 'claude-code-hook', actionId, detectedAt, ...extra });
const lines = (...rows: string[]) => rows.join('\n') + '\n';
const eventOf = (log: string, key: string) => {
  const e = groupEvents(parseDenials(log).records).find((x: any) => x.key === key);
  if (!e) throw new Error(`no event ${key}`);
  return e;
};
const partitions = (summary: any) =>
  summary.evidence.validKnown + summary.evidence.unknown + summary.evidence.contradictory + summary.evidence.malformed === summary.events.total;
const rowsOf = (summary: any) => {
  const { total, parsed, malformed, blankLines } = summary.rows;
  return { total, parsed, malformed, blankLines };
};

// ═══════════════════════════════════════════════════════════════════════════
describe('round 5 / M1(a) — one input row is counted exactly once', () => {
  it('M1a: a single non-conforming row (event: 42) is total=1 / parsed=0 / malformed=1 — never 2 / 1 / 1', () => {
    const log = JSON.stringify({ event: 42, outcome: 'auto_denied', actionId: 'm1a', tool: 'Bash', signals: ['delete-root-or-home'], detectedAt: T0 }) + '\n';
    const parsed = parseDenials(log);
    expect(parsed.rows).toEqual({ total: 1, parsed: 0, malformed: 1, blankLines: 0, lines: 1 });
    // the malformed object IS retained as a record for correlation…
    expect(parsed.records.map((r: any) => r.kind)).toEqual(['malformed']);
    // …but that retention adds nothing to any count
    const { summary, markdown } = run(log);
    expect(rowsOf(summary)).toEqual({ total: 1, parsed: 0, malformed: 1, blankLines: 0 });
    expect(summary.rows.total).toBe(summary.rows.parsed + summary.rows.malformed);
    expect(markdown).toMatch(/\| 1 \| 0 \| \*\*1\*\* \| 0 \| 1 \|/);
  });

  it('M1a: one valid row + one malformed row is total=2 / parsed=1 / malformed=1 (never 3); total = parsed + malformed and lines = total + blank', () => {
    const log = lines(
      denial({ actionId: 'v', signals: ['file-delete'] }),
      '',
      JSON.stringify({ event: 42, outcome: 'auto_denied', actionId: 'x', signals: ['file-delete'], detectedAt: T1 }),
      '   ',
      'not json',
    );
    const { summary } = run(log);
    expect(rowsOf(summary)).toEqual({ total: 3, parsed: 1, malformed: 2, blankLines: 2 });
    expect(summary.rows.lines).toBe(5);
    expect(summary.rows.total).toBe(summary.rows.parsed + summary.rows.malformed);
    expect(summary.rows.lines).toBe(summary.rows.total + summary.rows.blankLines);
    // the two-row pin exactly as reviewed
    const two = lines(denial({ actionId: 'v', signals: ['file-delete'] }), JSON.stringify({ event: 42, outcome: 'auto_denied', actionId: 'x', signals: ['file-delete'], detectedAt: T1 }));
    expect(rowsOf(run(two).summary)).toEqual({ total: 2, parsed: 1, malformed: 1, blankLines: 0 });
    // and a malformed SIBLING retained inside a valid event still counts once
    const sib = lines(denial({ actionId: 's', signals: ['file-delete'] }), JSON.stringify({ event: 'action_guard_denial', outcome: 'auto_denied', actionId: 's', signals: [42], detectedAt: T1 }));
    const sibS = run(sib).summary;
    expect(rowsOf(sibS)).toEqual({ total: 2, parsed: 1, malformed: 1, blankLines: 0 });
    expect(sibS.events.total).toBe(1);
    expect(sibS.evidence.malformedRows).toBe(1);
  });

  it('analyse refuses a caller that re-derives a total from record arrays; run() passes the parser result through', () => {
    const log = lines(denial({ actionId: 'a', signals: ['file-delete'] }));
    const parsed = parseDenials(log);
    expect(() => analyse(groupEvents(parsed.records), { malformed: parsed.malformed, rowCount: parsed.records.length + parsed.malformed.length, blankLines: 0 })).toThrow(/round-5 M1a/);
    const once = projectPublic(analyse(groupEvents(parsed.records), parsed));
    expect(run(log).summary).toEqual(once);
    expect(projectPublic(once)).toEqual(once);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
describe('round 5 / M1(b) — no declared-pair shortcut', () => {
  it('M1b: an event with NO validated enforcement row is never known and never actually stopped, whatever its retry rows say', () => {
    for (const log of [
      lines(retry('ro', 'retry_granted', T1)),
      lines(retry('ro', 'retry_granted', T1), retry('ro', 'retry_denied', T2)),
      lines(retry('ro', 'retry_grant_failed', T1)),
      // an enforcement row that FAILED its contract is not a decision either
      lines(JSON.stringify({ event: 'action_guard_denial', outcome: 'auto_denied', actionId: 'ro', detectedAt: T0 }), retry('ro', 'retry_granted', T1)),
    ]) {
      const e = eventOf(log, 'aid:ro');
      expect(e.hasEnforcement).toBe(false);
      expect(e.actuallyStopped).toBe(false);
      const { summary } = run(log);
      expect(summary.evidence.validKnown).toBe(0);
      expect(summary.actual.actuallyStopped).toBe(0);
      expect(summary.known.total).toBe(0);
      expect(partitions(summary)).toBe(true);
    }
  });

  it('M1b: a retry_granted row whose event is MISSING is malformed (missing-event), never dnp_retry, never retry = granted', () => {
    const bare = { outcome: 'retry_granted', origin: 'claude-code-hook', actionId: 'rb', detectedAt: T1 };
    expect(classifyRecord(bare)).toEqual({ kind: 'other', reason: 'missing-event' });
    const log = lines(denial({ actionId: 'rb', signals: ['file-delete'] }), JSON.stringify(bare));
    const parsed = parseDenials(log);
    expect(parsed.malformed).toEqual([{ lineNo: 2, reason: 'missing-event' }]);
    expect(parsed.records.map((r: any) => r.kind)).toEqual(['denial', 'malformed']);
    const e = eventOf(log, 'aid:rb');
    expect(e.lifecycle.retry).toEqual({ effective: 'none', grantSeen: false, history: [] });
    expect(e.retryGranted).toBe(false);
    expect(bucketOf(e)).toEqual({ bucket: 'malformed', reason: 'malformed-row-in-event' });
    // the unvalidated retry row is not accepted as a grant — and not ignored: the stop is UNCONFIRMED, not stopped
    expect(e.actuallyStopped).toBe(false);
    expect(e.stopUnconfirmed).toBe(true);
    const { summary } = run(log);
    expect(summary.evidence).toEqual(expect.objectContaining({ validKnown: 0, malformed: 1, malformedEventReasons: { 'missing-event': 1 } }));
    expect(summary.actual).toEqual(expect.objectContaining({ actuallyStopped: 0, stopUnconfirmed: 1, retryGranted: 0 }));
    expect(summary.lifecycles.retry.effective).toEqual({ none: 1 });
    expect(summary.lifecycles.retry.grantSeen).toBe(0);
    // a null event is a missing event too, not a silently tolerated one
    expect(parseDenials(JSON.stringify({ ...bare, event: null }) + '\n').malformed).toEqual([{ lineNo: 1, reason: 'missing-event' }]);
  });

  it('M1b: a retry_granted row whose event is UNKNOWN or a WARNING is contradictory (retry-event-mismatch), never dnp_retry, never retry = granted', () => {
    for (const ev of ['something_else', 'action_guard_warning']) {
      const bad = { event: ev, outcome: 'retry_granted', origin: 'claude-code-hook', actionId: 'rc', detectedAt: T1 };
      expect(classifyRecord(bad)).toEqual({ kind: 'contradictory', reason: 'retry-event-mismatch' });
      const log = lines(denial({ actionId: 'rc', signals: ['file-delete'] }), JSON.stringify(bad));
      expect(parseDenials(log).records.map((r: any) => r.kind)).toEqual(['denial', 'contradictory']);
      const e = eventOf(log, 'aid:rc');
      expect(e.lifecycle.retry).toEqual({ effective: 'none', grantSeen: false, history: [] });
      expect(e.retryGranted).toBe(false);
      expect(bucketOf(e)).toEqual({ bucket: 'contradictory', reason: 'event-outcome-mismatch' });
      expect(e.actuallyStopped).toBe(false);
      expect(e.stopUnconfirmed).toBe(true);
      const { summary, markdown } = run(log);
      expect(summary.evidence).toEqual(expect.objectContaining({ validKnown: 0, contradictory: 1, contradictoryReasons: { 'event-outcome-mismatch': 1 } }));
      expect(summary.actual).toEqual(expect.objectContaining({ actuallyStopped: 0, stopUnconfirmed: 1, retryGranted: 0 }));
      expect(markdown).toMatch(/\| stop unconfirmed \| 1 \|/);
      expect(summary.lifecycles.retry.grantSeen).toBe(0);
      expect(partitions(summary)).toBe(true);
    }
    // the same rule for every retry outcome, not just grants
    for (const outcome of ['retry_denied', 'retry_grant_failed']) {
      expect(classifyRecord({ event: 'action_guard_warning', outcome }).kind).toBe('contradictory');
      expect(classifyRecord({ outcome })).toEqual({ kind: 'other', reason: 'missing-event' });
      expect(classifyRecord({ event: 'action_guard_denial', outcome }).kind).toBe('dnp_retry');
    }
  });

  it('M1b: a retry row is validated against the SAME pinned schema as an enforcement row (notify shape included)', () => {
    const log = lines(
      denial({ actionId: 'rn', signals: ['file-delete'] }),
      retry('rn', 'retry_granted', T1, { notify: { status: 42 } }),
    );
    const parsed = parseDenials(log);
    expect(parsed.malformed).toEqual([{ lineNo: 2, reason: 'notify-status-not-string' }]);
    const e = eventOf(log, 'aid:rn');
    expect(e.lifecycle.retry.effective).toBe('none');
    expect(run(log).summary.evidence.malformed).toBe(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
describe('round 5 / M1(c) — legacy acceptance is explicit and closed', () => {
  // The shapes every shipped writer produced, transcribed from git history:
  //   #247 (12 Aug 2026): event, outcome, tool, surface, signals, severity, reason, [correlationId], detectedAt
  //   #284 (14 Aug 2026): + origin, [sessionId], [actionId], [notify]
  //   #310 (19 Aug 2026): retry rows: event, outcome, origin, reason, [tool], [actionId], detectedAt
  const pre284 = (o: Record<string, unknown>) => JSON.stringify({
    event: 'action_guard_denial', outcome: 'auto_denied', tool: 'Bash', surface: 'Bash: [redacted]',
    signals: ['file-delete'], severity: 'dangerous', reason: 'r', detectedAt: T0, ...o,
  });

  it('a pre-#284 row (no origin, no actionId, no sessionId, no notify) is ACCEPTED into its declared bucket', () => {
    const log = lines(pre284({ correlationId: 'c1' }), pre284({}), pre284({ event: 'action_guard_warning', outcome: 'warned' }));
    const parsed = parseDenials(log);
    expect(parsed.malformed).toEqual([]);
    expect(parsed.rows).toEqual({ total: 3, parsed: 3, malformed: 0, blankLines: 0, lines: 3 });
    expect(parsed.records.map((r: any) => r.kind)).toEqual(['denial', 'denial', 'warning']);
    const { summary } = run(log);
    expect(summary.events.keyedBy).toEqual({ line: 2, correlationId: 1 });
    expect(summary.evidence).toEqual(expect.objectContaining({ validKnown: 3, unknown: 0, contradictory: 0, malformed: 0 }));
    expect(summary.lifecycles.notification.final).toEqual({ none: 3 });
    expect(summary.actual).toEqual(expect.objectContaining({ actuallyStopped: 2, warnedOnly: 1 }));
  });

  it('anything else outside the pinned schema is MALFORMED with a named reason — no silent tolerance, no inference', () => {
    const cases: Array<[string, Record<string, unknown>]> = [
      ['missing-event', { outcome: 'auto_denied', signals: ['file-delete'] }],
      ['missing-event', { event: null, outcome: 'auto_denied', signals: ['file-delete'] }],
      ['missing-outcome', { event: 'action_guard_denial', signals: ['file-delete'] }],
      ['missing-outcome', { event: 'action_guard_denial', outcome: '', signals: ['file-delete'] }],
      ['event-not-string', { event: 42, outcome: 'auto_denied', signals: ['file-delete'] }],
      ['missing-signals', { event: 'action_guard_denial', outcome: 'auto_denied' }],
      ['missing-signals', { event: 'action_guard_warning', outcome: 'warned' }],
      ['signals-not-array', { event: 'action_guard_denial', outcome: 'auto_denied', signals: 'file-delete' }],
      ['signal-member-not-string', { event: 'action_guard_denial', outcome: 'auto_denied', signals: [42] }],
      ['notify-not-object', { event: 'action_guard_denial', outcome: 'auto_denied', signals: ['file-delete'], notify: 'delivered' }],
      ['notify-status-not-string', { event: 'action_guard_denial', outcome: 'auto_denied', signals: ['file-delete'], notify: { status: 1 } }],
      ['notify-channel-not-string', { event: 'action_guard_denial', outcome: 'auto_denied', signals: ['file-delete'], notify: { status: 'delivered', deliveredVia: ['a'] } }],
    ];
    for (const [reason, row] of cases) {
      const parsed = parseDenials(JSON.stringify({ actionId: 'x', detectedAt: T0, ...row }) + '\n');
      expect(parsed.malformed).toEqual([{ lineNo: 1, reason }]);
      expect(parsed.rows).toEqual({ total: 1, parsed: 0, malformed: 1, blankLines: 0, lines: 1 });
      expect(parsed.records.map((r: any) => ({ kind: r.kind, signals: r.signals, notify: r.notify.present }))).toEqual([{ kind: 'malformed', signals: [], notify: false }]);
      const { summary } = run(JSON.stringify({ actionId: 'x', detectedAt: T0, ...row }) + '\n');
      expect(summary.evidence).toEqual(expect.objectContaining({ validKnown: 0, malformed: 1 }));
      expect(summary.actual.actuallyStopped).toBe(0);
    }
    // not-JSON / not-object lines are malformed rows without a record
    const parsed = parseDenials('nope\n[1,2]\nnull\n');
    expect(parsed.malformed.map((m: any) => m.reason)).toEqual(['not-json', 'not-object', 'not-object']);
    expect(parsed.records).toEqual([]);
    expect(parsed.rows).toEqual({ total: 3, parsed: 0, malformed: 3, blankLines: 0, lines: 3 });
  });

  it('the malformed reason is the first failing check in the documented order (outcome, event type, signals, notify, missing event)', () => {
    // outcome missing outranks everything; a missing event is reported LAST so a
    // signals / notify defect on the same row keeps its own name
    expect(parseDenials(JSON.stringify({ signals: [42] }) + '\n').malformed[0].reason).toBe('missing-outcome');
    expect(parseDenials(JSON.stringify({ outcome: 'auto_denied', signals: [42] }) + '\n').malformed[0].reason).toBe('signal-member-not-string');
    expect(parseDenials(JSON.stringify({ outcome: 'auto_denied', signals: ['file-delete'], notify: 'x' }) + '\n').malformed[0].reason).toBe('notify-not-object');
    expect(parseDenials(JSON.stringify({ outcome: 'auto_denied', signals: ['file-delete'] }) + '\n').malformed[0].reason).toBe('missing-event');
    expect(parseDenials(JSON.stringify({ event: 42, outcome: 'auto_denied' }) + '\n').malformed[0].reason).toBe('event-not-string');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
describe('round 5 / M2 — the retry lifecycle is a history, not last-row-wins', () => {
  it("M2: Tars's timeline denial → grant → grant_failed is a FAILED RE-ISSUE: effective=unknown, grantSeen=true, actuallyStopped=false; the earlier grant stays in the public projection", () => {
    const log = lines(
      denial({ actionId: 't', signals: ['file-delete'], detectedAt: T0 }),
      retry('t', 'retry_granted', T1),
      retry('t', 'retry_grant_failed', T2),
    );
    const e = eventOf(log, 'aid:t');
    expect(e.lifecycle.retry).toEqual({ effective: 'unknown', grantSeen: true, history: ['granted', 'failed'] });
    expect(e.lifecycle.enforcement.final).toBe('auto_denied');
    expect(e.actuallyStopped).toBe(false);
    expect(e.retryGranted).toBe(false);
    const { summary, markdown } = run(log);
    expect(summary.actual).toEqual(expect.objectContaining({ actuallyStopped: 0, retryGranted: 0, retryDeniedOrFailed: 0, retryUnresolved: 1 }));
    expect(summary.lifecycles.retry).toEqual(expect.objectContaining({
      effective: { unknown: 1 }, grantSeen: 1, histories: { 'granted -> failed': 1 }, total: 1,
    }));
    expect(markdown).toContain('grant seen on 1 of 1 event(s)');
    expect(markdown).toContain('granted -> failed=1');
    expect(markdown).toMatch(/\| retry unresolved \| 1 \|/);
    // and the policy table does not count it as "matched and actually stopped"
    for (const p of summary.policies) expect(p.matchedAndActuallyStopped).toBe(0);
  });

  it('M2: the three round-4 timelines still hold — (i) grant keeps delivered; (ii) notify copy is not a decision; (iii) grant → denied is denied and the stop stands', () => {
    const i = lines(denial({ actionId: 'i', signals: ['file-delete'], notify: { status: 'delivered', deliveredVia: 'webhook' } }), retry('i', 'retry_granted', T1));
    expect(eventOf(i, 'aid:i').lifecycle).toEqual({
      enforcement: { final: 'auto_denied', decisions: 1, notifyCopies: 0 },
      retry: { effective: 'granted', grantSeen: true, history: ['granted'] },
      notification: { final: 'delivered', anyValidatedDelivery: true },
    });
    expect(eventOf(i, 'aid:i').actuallyStopped).toBe(false);

    const ii = lines(
      denial({ actionId: 'ii', signals: ['file-delete'], notify: { status: 'pending', deliveredVia: null }, detectedAt: T0 }),
      retry('ii', 'retry_granted', T1),
      denial({ actionId: 'ii', signals: ['file-delete'], notify: { status: 'delivered', deliveredVia: 'webhook' }, detectedAt: T2 }),
    );
    const eii = eventOf(ii, 'aid:ii');
    expect(eii.lifecycle.enforcement).toEqual({ final: 'auto_denied', decisions: 1, notifyCopies: 1 });
    expect(eii.lifecycle.retry).toEqual({ effective: 'granted', grantSeen: true, history: ['granted'] });
    expect(eii.actuallyStopped).toBe(false);

    const iii = lines(denial({ actionId: 'iii', signals: ['file-delete'], detectedAt: T0 }), retry('iii', 'retry_granted', T1), retry('iii', 'retry_denied', T2));
    const eiii = eventOf(iii, 'aid:iii');
    expect(eiii.lifecycle.retry).toEqual({ effective: 'denied', grantSeen: true, history: ['granted', 'denied'] });
    expect(eiii.actuallyStopped).toBe(true);
    const s3 = run(iii).summary;
    expect(s3.actual).toEqual(expect.objectContaining({ actuallyStopped: 1, retryGranted: 0, retryUnresolved: 0 }));
    expect(s3.lifecycles.retry).toEqual(expect.objectContaining({ effective: { denied: 1 }, grantSeen: 1, histories: { 'granted -> denied': 1 } }));
  });

  it('M2: retryLifecycle state table — grantSeen latches; failed with no grant is failed; a later grant re-grants; order matters', () => {
    expect(retryLifecycle([])).toEqual({ effective: 'none', grantSeen: false, history: [] });
    expect(retryLifecycle(['retry_grant_failed'])).toEqual({ effective: 'failed', grantSeen: false, history: ['failed'] });
    expect(retryLifecycle(['retry_grant_failed', 'retry_granted'])).toEqual({ effective: 'granted', grantSeen: true, history: ['failed', 'granted'] });
    expect(retryLifecycle(['retry_granted', 'retry_grant_failed'])).toEqual({ effective: 'unknown', grantSeen: true, history: ['granted', 'failed'] });
    expect(retryLifecycle(['retry_granted', 'retry_grant_failed', 'retry_granted'])).toEqual({ effective: 'granted', grantSeen: true, history: ['granted', 'failed', 'granted'] });
    expect(retryLifecycle(['retry_granted', 'retry_denied'])).toEqual({ effective: 'denied', grantSeen: true, history: ['granted', 'denied'] });
    expect(retryLifecycle(['retry_denied', 'retry_granted'])).toEqual({ effective: 'granted', grantSeen: true, history: ['denied', 'granted'] });
    expect(retryLifecycle(['retry_denied'])).toEqual({ effective: 'denied', grantSeen: false, history: ['denied'] });
    expect(retryLifecycle(['retry_revoked'])).toEqual({ effective: 'revoked', grantSeen: false, history: ['revoked'] });
    // grant_failed after denied-after-grant is still a failed re-issue after a grant seen
    expect(retryLifecycle(['retry_granted', 'retry_denied', 'retry_grant_failed']).effective).toBe('unknown');
    expect(RETRY_STATES).toContain('unknown');
  });

  it('M2: the rows are ordered by detectedAt, not by file position — grant_failed → grant written out of order is still a grant', () => {
    const log = lines(
      denial({ actionId: 'o', signals: ['file-delete'], detectedAt: T0 }),
      retry('o', 'retry_grant_failed', T3),
      retry('o', 'retry_granted', T2),
    );
    const e = eventOf(log, 'aid:o');
    expect(e.lifecycle.retry).toEqual({ effective: 'unknown', grantSeen: true, history: ['granted', 'failed'] });
    expect(e.actuallyStopped).toBe(false);
  });

  it('M2: the public projection carries grantSeen and the history distribution through closed enums; actionIds never appear', () => {
    const log = lines(
      denial({ actionId: 'secret-action-id-1', signals: ['file-delete'], detectedAt: T0 }),
      retry('secret-action-id-1', 'retry_granted', T1),
      retry('secret-action-id-1', 'retry_grant_failed', T2),
      denial({ actionId: 'secret-action-id-2', signals: ['file-delete'], detectedAt: T0 }),
      retry('secret-action-id-2', 'retry_granted', T1),
      denial({ actionId: 'secret-action-id-3', signals: ['file-delete'], detectedAt: T0 }),
    );
    const parsed = parseDenials(log);
    const internal = analyse(groupEvents(parsed.records), parsed);
    const once = projectPublic(internal);
    expect(projectPublic(once)).toEqual(once);
    expect(run(log).summary).toEqual(once);
    expect(once.lifecycles.retry).toEqual({
      effective: { granted: 1, none: 1, unknown: 1 },
      grantSeen: 2,
      histories: { 'granted': 1, 'granted -> failed': 1, 'none': 1 },
      total: 3,
      note: expect.stringContaining('failed re-issue'),
    });
    const json = JSON.stringify(once);
    expect(json).not.toContain('secret-action-id');
    expect(run(log).markdown).not.toContain('secret-action-id');
    // tampered internal labels collapse to `other`, step by step
    const tampered = { ...internal, lifecycles: { ...internal.lifecycles, retry: { ...internal.lifecycles.retry, histories: { 'granted -> private-state': 1 }, effective: { 'private-state': 1 } } } };
    const p = projectPublic(tampered).lifecycles.retry;
    expect(p.histories).toEqual({ 'granted -> other': 1 });
    expect(p.effective).toEqual({ other: 1 });
    // long histories are capped with a closed marker, never truncated silently
    expect(retryHistoryKey(new Array(12).fill('granted'))).toBe(new Array(8).fill('granted').join(' -> ') + ' -> more');
  });
});
