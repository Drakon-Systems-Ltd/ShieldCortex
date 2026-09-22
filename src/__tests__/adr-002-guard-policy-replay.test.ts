/**
 * ADR-002 measurement harness, Half A — proof the logged-signal replay behaves
 * per #555/#556: malformed rows counted (never skipped), all records kept per
 * actionId (conflicts surfaced), redacted/empty rows bucketed "unknown" and
 * excluded from every percentage, the three policies evaluated on logged
 * signals, and `pipe-download-to-shell` inside the injection set.
 *
 * Pure: imports the harness .mjs directly, no dist build, no host log.
 */
import { describe, it, expect } from '@jest/globals';
// @ts-expect-error — plain ESM helper, no types
import { run, parseDenials, groupEvents } from '../../scripts/guard-policy-replay.mjs';

// A tiny synthetic denials log. Signal NAMES are inert strings (not command
// shapes), so this fixture carries nothing the guard would flag.
const row = (o: Record<string, unknown>) => JSON.stringify({
  event: 'action_guard_denial',
  tool: 'Bash',
  surface: 'Bash: [redacted] fields=command',
  severity: 'dangerous',
  outcome: 'auto_denied',
  origin: 'claude-code-hook',
  detectedAt: '2026-09-01T00:00:00.000Z',
  notify: { status: 'no_channel', deliveredVia: null },
  ...o,
});

const LOG = [
  // one event, two records (pending + final), destruction-floor class
  row({ actionId: 'a1', signals: ['delete-root-or-home'], detectedAt: '2026-08-16T01:00:00.000Z' }),
  row({ actionId: 'a1', signals: ['delete-root-or-home'], detectedAt: '2026-08-16T01:00:01.000Z' }),
  // an external-egress event: dangerous today, on NEITHER floor as written
  row({ actionId: 'a2', signals: ['external-egress'] }),
  // a persistence event: broad-floor only
  row({ actionId: 'a3', signals: ['modify-scheduler'] }),
  // an injection-flavoured event that the original script omitted
  row({ actionId: 'a4', signals: ['pipe-download-to-shell'] }),
  // a sensitive-path event: current tiers only
  row({ actionId: 'a5', signals: ['touch-sensitive-path'] }),
  // conflicting outcome across an event's records
  row({ actionId: 'a6', signals: ['file-delete'], outcome: 'warned', event: 'action_guard_warning', detectedAt: '2026-08-17T00:00:00.000Z' }),
  row({ actionId: 'a6', signals: ['file-delete'], outcome: 'auto_denied', detectedAt: '2026-08-17T00:00:02.000Z' }),
  // unknown bucket: a redacted-only row and an empty-signals row
  row({ actionId: 'u1', signals: ['redacted-signal'] }),
  row({ actionId: 'u2', signals: [] }),
  // malformed: not JSON, and JSON missing a required field
  'this is not json at all',
  JSON.stringify({ actionId: 'bad', tool: 'Bash', signals: ['file-delete'] }), // no outcome
].join('\n') + '\n';

describe('ADR-002 Half A — logged-signal policy replay', () => {
  it('counts malformed rows, never silently skips them', () => {
    const { malformed, rows } = parseDenials(LOG);
    expect(malformed.length).toBe(2);
    expect(malformed.map(m => m.reason).sort()).toEqual(['missing-outcome', 'not-json']);
    // the well-formed rows still parsed
    expect(rows.length).toBe(10);
  });

  it('keeps every record per actionId and flags a conflicting outcome', () => {
    const events = groupEvents(parseDenials(LOG).rows);
    const a1 = events.find(e => e.key === 'aid:a1')!;
    expect(a1.recordCount).toBe(2);
    const a6 = events.find(e => e.key === 'aid:a6')!;
    expect(a6.conflictingOutcome).toBe(true);
    expect(a6.outcomes.sort()).toEqual(['auto_denied', 'warned']);
  });

  it('buckets redacted/empty rows as unknown and excludes them from percentages', () => {
    const { summary } = run(LOG);
    expect(summary.unknown.total).toBe(2); // u1 redacted, u2 empty
    // every policy percentage is over KNOWN events only
    const known = summary.known.total;
    expect(known).toBe(6); // a1..a6, minus the 2 unknown
    for (const p of summary.policies) {
      expect(p.gated + p.auditOnly).toBe(known);
    }
  });

  it('applies the three policies to the logged signals correctly', () => {
    const { summary } = run(LOG);
    const byId = Object.fromEntries(summary.policies.map((p: any) => [p.id, p]));
    // current tiers gate everything a denials log contains
    expect(byId['current-tiers'].gated).toBe(summary.known.total);
    // destruction floor gates only delete-root-or-home (a1); a6 file-delete is off it
    expect(byId['destruction-floor'].gated).toBe(1);
    // broad floor gates delete-root-or-home (a1) + modify-scheduler (a3)
    expect(byId['broad-floor'].gated).toBe(2);
  });

  it('counts pipe-download-to-shell as injection-flavoured (the omission the original had)', () => {
    const { summary } = run(LOG);
    expect(summary.injection.set).toContain('pipe-download-to-shell');
    // a2 external-egress + a4 pipe-download-to-shell are the injection-flavoured known events
    expect(summary.injection.withSignal).toBe(2);
  });

  it('prints the required banner and never claims classifier/effect measurement', () => {
    const { markdown, summary } = run(LOG);
    expect(summary.banner).toContain('NOT a classifier replay');
    expect(summary.banner).toContain('NOT an effect-achieved measurement');
    expect(markdown).toContain('excluded from every percentage');
  });

  it('reports notify delivery and finds nothing delivered in the fixture', () => {
    const { summary } = run(LOG);
    expect(summary.notify.deliveredToSomeone).toBe(0);
  });
});
