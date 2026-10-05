/**
 * #509 round 8 (SF6): the readiness recompute on the OpenClaw gateway.
 *
 * `resolveReadiness` recomputes from up to 64 MB of audit, synchronously, on
 * the gateway's event loop (the plugin runs in-process). And when the newest-
 * first byte budget cuts below the 7 days the intervention proxy needs, the
 * old report said "observed calls span 6.3 days" — true, and never going to
 * change: the install could not promote, and nothing said why.
 *
 * The gateway now recomputes through `resolveReadinessAsync` — the same
 * decision, reading and parsing in slices that yield to the event loop — and a
 * budget cut below the window says so plainly.
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { appendFileSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  computeReadiness,
  computeReadinessAsync,
  currentReadinessPin,
  initReadinessTransitions,
  readTransitionRecord,
  resolveReadiness,
  resolveReadinessAsync,
  transitionsPathFor,
  type ReadinessPaths,
  type ReadinessPin,
} from '../guard-readiness.js';

const DAY = 24 * 60 * 60 * 1000;
const NOW = Date.parse('2026-09-28T12:00:00.000Z');
const CHANNEL = { configured: true, kind: 'webhook', pushesNotices: true };
const PIN = currentReadinessPin() as ReadinessPin;
const WITH_REVIEWED = {
  effectivenessRegistry: [{ ...PIN, reviewedAt: new Date(NOW - DAY).toISOString(), reviewedBy: 'fixture reviewer', reference: 'test fixture', cases: 60 }],
} as const;

let root: string;
let paths: ReadinessPaths;
let seq = 0;

function write(rows: Array<Record<string, unknown>>): void {
  mkdirSync(paths.auditDir, { recursive: true });
  const byFile = new Map<string, string[]>();
  for (const r of rows) {
    const f = join(paths.auditDir, `realtime-${String(r.ts).slice(0, 10)}.jsonl`);
    byFile.set(f, [...(byFile.get(f) ?? []), JSON.stringify(r)]);
  }
  for (const [f, lines] of byFile) appendFileSync(f, `${lines.join('\n')}\n`);
}

function call(ts: number, outcome = 'allowed', pad = 0): Record<string, unknown> {
  seq += 1;
  return {
    ts: new Date(ts).toISOString(), auditEventId: `e${seq.toString(16).padStart(10, '0')}`, readinessPin: PIN,
    type: 'intercept', origin: 'claude-code-hook', tool: 'Bash', severity: outcome === 'allowed' ? 'low' : 'high',
    action: outcome === 'allowed' ? 'allow' : 'require_approval', outcome,
    ...(pad ? { preview: 'x'.repeat(pad) } : {}),
  };
}

/** `perDay` calls on each of the last `days` days (newest day = today). */
function history(days: number, perDay: number, pad = 0): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  for (let d = days - 1; d >= 0; d -= 1) {
    for (let i = 0; i < perDay; i += 1) out.push(call(NOW - d * DAY - 6 * 60 * 60 * 1000 + i * 1000, i % 400 === 0 ? 'would_hold' : 'allowed', pad));
  }
  return out;
}

function reached(n: number): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  for (let i = 0; i < n; i += 1) {
    const t = NOW - DAY + i * 1000;
    out.push({ ts: new Date(t).toISOString(), auditEventId: `q${i}`, readinessPin: PIN, type: 'approval_reach', origin: 'claude-code-hook', reachId: `r${i}`, attemptId: `a${i}`, phase: 'request' });
    out.push({ ts: new Date(t + 30_000).toISOString(), auditEventId: `s${i}`, type: 'approval_reach', origin: 'claude-code-hook', reachId: `r${i}`, attemptId: `a${i}`, phase: 'answer', answer: 'approve' });
  }
  return out;
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'sc-readiness-r8-'));
  paths = { auditDir: join(root, 'audit'), statePath: join(root, 'approvals', 'guard-readiness.json'), readAuditDirs: [join(root, 'audit')] };
  initReadinessTransitions({ postureChanged: true, reason: 'test posture', paths, now: NOW - 60 * DAY });
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

describe('#509 r8 SF6 — a byte budget that cuts below the window is reported, not silent', () => {
  it('10 days of history, a budget that holds ~3: "not enough history measured", naming the budget', () => {
    write(history(10, 120, 200));
    const report = computeReadiness({ channel: CHANNEL, paths, now: NOW, readBudgetBytes: 100 * 1024 });
    expect(report.truncated).toBe(true);
    expect(report.intervention.pass).toBe(false);
    expect(report.intervention.missing).toMatch(/not enough history measured/);
    expect(report.intervention.missing).toMatch(/read budget/);
    expect(report.intervention.missing).not.toMatch(/^observed calls span/);
  });

  it('the same history inside the budget: the span is measured normally (no false alarm)', () => {
    write(history(10, 120, 200));
    const report = computeReadiness({ channel: CHANNEL, paths, now: NOW });
    expect(report.truncated).toBe(false);
    expect(report.intervention.missing ?? '').not.toMatch(/not enough history measured/);
    expect(report.intervention.total).toBe(1200);
  });
});

describe('#509 r8 SF6 — the gateway recompute yields to the event loop', () => {
  it('computeReadinessAsync gives the sync answer, and the event loop runs while it reads', async () => {
    // ~5 MB of audit: enough slices that a blocking read would starve the loop.
    write([...history(9, 1300, 300), ...reached(25)]);
    const sync = computeReadiness({ channel: CHANNEL, paths, now: NOW, ...WITH_REVIEWED });
    let ticks = 0;
    let stop = false;
    const tick = (): void => { ticks += 1; if (!stop) setImmediate(tick); };
    setImmediate(tick);
    const asyncReport = await computeReadinessAsync({ channel: CHANNEL, paths, now: NOW, ...WITH_REVIEWED });
    stop = true;
    expect({ ...asyncReport, computedAt: 'x' }).toEqual({ ...sync, computedAt: 'x' });
    expect(sync.ready).toBe(true);
    expect(ticks).toBeGreaterThan(5);
  });

  it('resolveReadinessAsync makes the same transition as the sync resolver (promotion journalled once)', async () => {
    write([...history(9, 120), ...reached(25)]);
    const r = await resolveReadinessAsync({ channel: CHANNEL, paths, now: NOW, ...WITH_REVIEWED });
    expect(r).toMatchObject({ mode: 'enforcing', transition: 'promote' });
    expect(readTransitionRecord(transitionsPathFor(paths)).last).toMatchObject({ event: 'promote', to: 'enforcing' });
    // The next call (sync, fresh cache) agrees and transitions nothing.
    expect(resolveReadiness({ channel: CHANNEL, paths, now: NOW + 1000, ...WITH_REVIEWED })).toMatchObject({ mode: 'enforcing', transition: null, cached: true });
  });
});
