/**
 * ADR-002 measurement harness, Half A — proves the logged-signal replay per
 * #555/#556 AND Tars's round-2 findings:
 *   4. ACTUAL outcome (what stopped) is separated from HYPOTHETICAL tier match;
 *      a `warned` record is NOT counted as a stopped action; no 100% baseline.
 *   5. retry lifecycle rows (same actionId, no signals) are first-class records,
 *      not malformed, and a retry grant is not proof of execution.
 *   7. delivery is tracked across ALL records (never "person reached"); field
 *      types are validated (signals:[42] is malformed); non-conforming signal
 *      names are never echoed verbatim.
 *
 * Pure: imports the harness .mjs directly, no dist build, no host log.
 */
import { describe, it, expect } from '@jest/globals';
// @ts-expect-error — plain ESM helper, no types
import { run, parseDenials, groupEvents, classifyRecord, safeSignalName } from '../../scripts/guard-policy-replay.mjs';

const row = (o: Record<string, unknown>) => JSON.stringify({
  event: 'action_guard_denial', tool: 'Bash', surface: 'Bash: [redacted] fields=command',
  severity: 'dangerous', outcome: 'auto_denied', origin: 'claude-code-hook',
  detectedAt: '2026-09-01T00:00:00.000Z', notify: { status: 'no_channel', deliveredVia: null }, ...o,
});

const LOG = [
  row({ actionId: 'a1', signals: ['delete-root-or-home'], detectedAt: '2026-08-16T01:00:00.000Z' }),
  row({ actionId: 'a1', signals: ['delete-root-or-home'], detectedAt: '2026-08-16T01:00:01.000Z' }),
  row({ actionId: 'a2', signals: ['external-egress'] }),
  row({ actionId: 'a3', signals: ['modify-scheduler'] }),
  row({ actionId: 'a4', signals: ['pipe-download-to-shell'] }),
  row({ actionId: 'a5', signals: ['touch-sensitive-path'] }),
  // a WARNED event: advisory, emits no permission decision — must not count as stopped
  row({ actionId: 'a6', signals: ['file-delete'], outcome: 'warned', event: 'action_guard_warning', detectedAt: '2026-08-17T00:00:00.000Z' }),
  // a denial that is later granted ONE retry (finding 5): the retry row has no signals
  row({ actionId: 'a7', signals: ['touch-sensitive-path'], outcome: 'auto_denied', detectedAt: '2026-08-18T00:00:00.000Z' }),
  JSON.stringify({ event: 'action_guard_denial', outcome: 'retry_granted', origin: 'claude-code-hook', actionId: 'a7', detectedAt: '2026-08-18T00:00:05.000Z' }),
  // a delivered-then-nothing event (finding 7): first record delivered, final coalesced
  row({ actionId: 'a8', signals: ['secret-egress'], notify: { status: 'delivered', deliveredVia: 'redacted-channel' }, detectedAt: '2026-08-19T00:00:00.000Z' }),
  row({ actionId: 'a8', signals: ['secret-egress'], notify: { status: 'coalesced', deliveredVia: null }, detectedAt: '2026-08-19T00:00:02.000Z' }),
  // unknown bucket
  row({ actionId: 'u1', signals: ['redacted-signal'] }),
  row({ actionId: 'u2', signals: [] }),
  // malformed
  'this is not json at all',
  JSON.stringify({ actionId: 'bad', tool: 'Bash', signals: ['file-delete'] }), // no outcome
  JSON.stringify({ actionId: 'badsig', tool: 'Bash', outcome: 'auto_denied', signals: [42] }), // signal not string
].join('\n') + '\n';

describe('ADR-002 Half A — parsing, record kinds, validation', () => {
  it('counts malformed rows including a non-string signal member (finding 7), never skips', () => {
    const { malformed, records } = parseDenials(LOG);
    expect(malformed.map((m: any) => m.reason).sort()).toEqual(['missing-outcome', 'not-json', 'signal-member-not-string']);
    // 13 conforming rows + the 2 malformed JSON rows retained as `malformed` records (round 4, M1)
    expect(records.length).toBe(15);
    expect(records.filter((r: any) => r.kind === 'malformed').length).toBe(2);
  });

  it('classifies a signal-less retry row as dnp_retry, not malformed (finding 5)', () => {
    const retry = JSON.parse(JSON.stringify({ event: 'action_guard_denial', outcome: 'retry_granted', actionId: 'a7' }));
    expect(classifyRecord(retry).kind).toBe('dnp_retry');
    const { malformed } = parseDenials(LOG);
    expect(malformed.some((m: any) => m.reason === 'missing-signals')).toBe(false);
  });

  it('keeps the retry row in its event lifecycle keyed by actionId (finding 5)', () => {
    const events = groupEvents(parseDenials(LOG).records);
    const a7 = events.find((e: any) => e.key === 'aid:a7')!;
    expect(a7.recordCount).toBe(2);
    expect(a7.kinds.sort()).toEqual(['denial', 'dnp_retry']);
    expect(a7.retryGranted).toBe(true);
  });
});

describe('ADR-002 Half A — ACTUAL outcome vs HYPOTHETICAL match (finding 4)', () => {
  it('a warned event is NOT counted as actually stopped', () => {
    const events = groupEvents(parseDenials(LOG).records);
    const a6 = events.find((e: any) => e.key === 'aid:a6')!;
    expect(a6.finalEnfOutcome).toBe('warned');
    expect(a6.actuallyStopped).toBe(false);
  });

  it('a denial later granted a retry is not "actually stopped" (retry is not execution proof)', () => {
    const events = groupEvents(parseDenials(LOG).records);
    const a7 = events.find((e: any) => e.key === 'aid:a7')!;
    expect(a7.actuallyStopped).toBe(false);
    expect(a7.retryGranted).toBe(true);
  });

  it('summary reports a separate actual-outcome accounting and no 100% baseline', () => {
    const { summary, markdown } = run(LOG);
    expect(summary.actual.actuallyStopped).toBeGreaterThanOrEqual(1);
    expect(summary.actual.warnedOnly).toBe(1);
    expect(summary.actual.retryGranted).toBe(1);
    expect(markdown).toContain('HYPOTHETICAL signal-set match (NOT an enforcement rate)');
    expect(markdown).not.toMatch(/100\.0% ?gated/);
    for (const p of summary.policies) {
      expect(p).toHaveProperty('hypotheticalMatch');
      expect(p).toHaveProperty('matchedAndActuallyStopped');
      expect(p).not.toHaveProperty('gated');
    }
  });

  it('applies the three policies as signal-set matches on the known events', () => {
    const { summary } = run(LOG);
    const byId = Object.fromEntries(summary.policies.map((p: any) => [p.id, p]));
    expect(byId['destruction-floor'].hypotheticalMatch).toBe(1);
    expect(byId['broad-floor'].hypotheticalMatch).toBe(3);
  });
});

describe('ADR-002 Half A — delivery across all records + privacy (finding 7)', () => {
  it('a delivered-then-coalesced event counts as a validated delivery (not just final status)', () => {
    const { summary } = run(LOG);
    expect(summary.delivery.anyValidatedDelivery).toBe(1);
    expect(summary.delivery.coalescedEver).toBeGreaterThanOrEqual(1);
    expect(JSON.stringify(summary.delivery)).not.toMatch(/person/i);
  });

  it('never echoes a signal name outside the writer\'s vocabulary verbatim (membership, not syntax — round 3)', () => {
    // A vocabulary member passes; a lexically valid but unregistered name, a
    // name with spaces/semicolons/uppercase, and a non-string are all redacted.
    expect(safeSignalName('file-delete')).toBe('file-delete');
    expect(safeSignalName('legit-name')).toBe('<signal-outside-vocabulary-redacted>');
    expect(safeSignalName('Injected Title; SELECT 1')).toBe('<signal-outside-vocabulary-redacted>');
    expect(safeSignalName(42 as any)).toBe('<signal-outside-vocabulary-redacted>');
  });

  it('buckets redacted/empty rows as unknown and excludes them from percentages', () => {
    const { summary } = run(LOG);
    expect(summary.unknown.total).toBeGreaterThanOrEqual(2);
    for (const p of summary.policies) {
      expect(p.hypotheticalMatch + p.hypotheticalNoMatch).toBe(summary.known.total);
    }
  });

  it('counts pipe-download-to-shell as injection-flavoured (the omission the original had)', () => {
    const { summary } = run(LOG);
    expect(summary.injection.set).toContain('pipe-download-to-shell');
  });

  it('prints the required banner and never claims classifier/effect measurement', () => {
    const { markdown, summary } = run(LOG);
    expect(summary.banner).toContain('NOT a classifier replay');
    expect(summary.banner).toContain('NOT an effect-achieved measurement');
    expect(markdown).toContain('excluded from every %');
  });
});
