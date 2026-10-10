/**
 * #719 — readiness evidence is keyed on the POLICY hash, not the adapter's
 * package version. A release that keeps the hash keeps its evidence; one that
 * changes it carries the old evidence at a discount
 * (`actionGuard.readiness.priorPolicyCarry`, default 0.5) and only once the
 * new policy has its own fresh window (≥ 100 calls over ≥ 48h, at the same
 * rate threshold).
 *
 * Every test runs against a throwaway audit directory and config tree; the
 * live ~/.shieldcortex is never read.
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { appendFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  DEFAULT_PRIOR_POLICY_CARRY,
  FRESH_POLICY_MIN_CALLS,
  FRESH_POLICY_MIN_SPAN_MS,
  computeReadiness,
  computeReadinessAsync,
  currentReadinessPin,
  initReadinessTransitions,
  normalisePriorPolicyCarry,
  readPriorPolicyCarry,
  resolveReadiness,
  type ReadinessPaths,
  type ReadinessPin,
} from '../guard-readiness.js';

const DAY = 24 * 60 * 60 * 1000;
const HOUR = 60 * 60 * 1000;
const NOW = Date.parse('2026-10-10T20:00:00.000Z');
const CHANNEL = { configured: true, kind: 'openclaw-card', pushesNotices: true };

/** The release in force, and the one before it under the SAME policy hash. */
const H = 'tool-action-guard:1111111111111111';
const H_PRIME = 'tool-action-guard:2222222222222222';
const V1_H: ReadinessPin = { adapter: 'claude-code-hook@5.5.0', policy: H };
const V2_H: ReadinessPin = { adapter: 'claude-code-hook@5.6.0', policy: H };
const V2_H_PRIME: ReadinessPin = { adapter: 'claude-code-hook@5.6.0', policy: H_PRIME };

const reviewed = (pin: ReadinessPin) => ({
  effectivenessRegistry: [{ ...pin, reviewedAt: new Date(NOW - DAY).toISOString(), reviewedBy: 'fixture reviewer', reference: 'test fixture', cases: 60 }],
});

let root: string;
let paths: ReadinessPaths;
let seq = 0;

function write(rows: Array<Record<string, unknown>>): void {
  mkdirSync(paths.auditDir, { recursive: true });
  for (const r of rows) appendFileSync(join(paths.auditDir, `realtime-${String(r.ts).slice(0, 10)}.jsonl`), `${JSON.stringify(r)}\n`);
}

function row(ts: number, pin: ReadinessPin, fields: Record<string, unknown>): Record<string, unknown> {
  seq += 1;
  return { ts: new Date(ts).toISOString(), auditEventId: `e${seq.toString(16).padStart(8, '0')}`, readinessPin: pin, ...fields };
}

/** `total` hook calls under `pin`, evenly from `fromMs` to `toMs`, the first `stops` of them would-holds. */
function calls(pin: ReadinessPin, total: number, stops: number, fromMs: number, toMs: number): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  for (let i = 0; i < total; i += 1) {
    const ts = fromMs + Math.floor(((toMs - fromMs) * i) / Math.max(1, total - 1));
    const stop = i < stops;
    out.push(row(ts, pin, {
      type: 'intercept', origin: 'claude-code-hook', tool: 'Bash',
      severity: stop ? 'high' : 'low', action: stop ? 'require_approval' : 'allow', outcome: stop ? 'would_hold' : 'allowed',
    }));
  }
  return out;
}

/** `answered` reached round-trips + `unanswered` expired requests under `pin`, from `at`. */
function reach(pin: ReadinessPin, answered: number, unanswered: number, at = NOW - DAY): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  for (let i = 0; i < answered + unanswered; i += 1) {
    seq += 1;
    const attemptId = `a-${pin.policy.slice(-4)}-${seq}`;
    const t = at + i * 1000;
    out.push(row(t, pin, { type: 'approval_reach', reachId: `r${seq}`, attemptId, phase: 'request' }));
    if (i < answered) out.push(row(t + 60_000, pin, { type: 'approval_reach', reachId: `r${seq}`, attemptId, phase: 'answer', answer: 'approve' }));
  }
  return out;
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'sc-readiness-719-'));
  paths = {
    auditDir: join(root, 'audit'),
    statePath: join(root, 'approvals', 'guard-readiness.json'),
    readAuditDirs: [join(root, 'audit')],
  };
  initReadinessTransitions({ postureChanged: true, reason: 'test posture', paths, now: NOW - 60 * DAY });
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

describe('#719 same policy hash across adapter versions', () => {
  it('rows from adapter v1 + hash H count in full toward readiness on adapter v2 + hash H', () => {
    write(calls(V1_H, 600, 3, NOW - 10 * DAY, NOW - 2 * HOUR));
    write(reach(V1_H, 25, 0));
    const r = computeReadiness({ ...reviewed(V2_H), channel: CHANNEL, paths, now: NOW, pin: V2_H, priorPolicyCarry: 0.5 });
    expect(r.intervention.total).toBe(600);
    expect(r.intervention.fresh.total).toBe(600);
    expect(r.intervention.retained).toBe(600);
    expect(r.intervention.carried.rawTotal).toBe(0);
    expect(r.intervention.freshWindow.required).toBe(false);
    expect(r.intervention.otherVersion).toBe(0);
    expect(r.reachability).toMatchObject({ reached: 25, resolved: 25, retained: 25 });
    expect(r.carry.earlierReleases).toEqual(['claude-code-hook@5.5.0']);
    expect(r.carry.priorPolicies).toEqual([]);
    expect(r.ready).toBe(true);
  });

  it('an enforcing install stays enforcing across a release that keeps the hash', () => {
    write(calls(V1_H, 600, 0, NOW - 10 * DAY, NOW - 2 * HOUR));
    write(reach(V1_H, 25, 0));
    expect(resolveReadiness({ ...reviewed(V1_H), channel: CHANNEL, paths, now: NOW - HOUR, pin: V1_H }).mode).toBe('enforcing');
    const after = resolveReadiness({ ...reviewed(V2_H), channel: CHANNEL, paths, now: NOW, pin: V2_H });
    expect(after.transition).toBeNull();
    expect(after.mode).toBe('enforcing');
  });

  it("another adapter's rows never count, even under the same policy hash", () => {
    const oc: ReadinessPin = { adapter: 'openclaw-interceptor@5.5.0', policy: H };
    write(reach(oc, 25, 0));
    const r = computeReadiness({ channel: CHANNEL, paths, now: NOW, pin: V2_H });
    expect(r.reachability.resolved).toBe(0);
    expect(r.reachability.otherVersion).toBe(25);
  });
});

describe('#719 policy hash change H → H′', () => {
  it('carries the discounted count and demands the fresh window', () => {
    write(calls(V1_H, 1000, 0, NOW - 12 * DAY, NOW - 2 * DAY));
    write(reach(V1_H, 30, 0, NOW - 3 * DAY));
    const r = computeReadiness({ ...reviewed(V2_H_PRIME), channel: CHANNEL, paths, now: NOW, pin: V2_H_PRIME, priorPolicyCarry: 0.5 });
    expect(r.intervention.carried).toEqual({ rawStops: 0, rawTotal: 1000, stops: 0, total: 500 });
    expect(r.intervention.fresh.total).toBe(0);
    expect(r.intervention.total).toBe(500);
    expect(r.intervention.freshWindow).toEqual({ required: true, pass: false });
    expect(r.intervention.missing).toMatch(/fresh window under this one \(≥ 100 calls over ≥ 2\.0 days\): so far 0 call\(s\)/);
    expect(r.reachability.carried).toEqual({ rawReached: 30, rawResolved: 30, reached: 15, resolved: 15 });
    expect(r.carry.priorPolicies).toEqual([H]);
    expect(r.ready).toBe(false);
  });

  it('a fresh window too short in time (≥ 100 calls, < 48h) still holds the carry back', () => {
    write(calls(V1_H, 1000, 0, NOW - 12 * DAY, NOW - 2 * DAY));
    write(calls(V2_H_PRIME, 150, 0, NOW - 20 * HOUR, NOW - HOUR));
    write(reach(V2_H_PRIME, 25, 0));
    const r = computeReadiness({ ...reviewed(V2_H_PRIME), channel: CHANNEL, paths, now: NOW, pin: V2_H_PRIME });
    expect(r.intervention.total).toBe(650);
    expect(r.intervention.freshWindow.pass).toBe(false);
    expect(r.intervention.missing).toMatch(/so far 150 call\(s\) over 0\.8 days/);
    expect(r.ready).toBe(false);
  });

  it('once the fresh window is met, carried + fresh evidence can promote', () => {
    write(calls(V1_H, 1000, 0, NOW - 12 * DAY, NOW - 3 * DAY));
    write(calls(V2_H_PRIME, FRESH_POLICY_MIN_CALLS, 1, NOW - 3 * DAY, NOW - HOUR));
    write(reach(V2_H_PRIME, 25, 0));
    const r = computeReadiness({ ...reviewed(V2_H_PRIME), channel: CHANNEL, paths, now: NOW, pin: V2_H_PRIME });
    expect(r.intervention).toMatchObject({ total: 600, stops: 1, pass: true, freshWindow: { required: true, pass: true } });
    expect(r.intervention.spanMs).toBeGreaterThanOrEqual(7 * DAY);
    expect(r.ready).toBe(true);
  });

  it('the new policy must meet the rate on its own: a fresh would-stop rate above 2% blocks the carry', () => {
    write(calls(V1_H, 4000, 0, NOW - 12 * DAY, NOW - 3 * DAY));
    write(calls(V2_H_PRIME, 100, 5, NOW - 3 * DAY, NOW - HOUR));
    write(reach(V2_H_PRIME, 25, 0));
    const r = computeReadiness({ ...reviewed(V2_H_PRIME), channel: CHANNEL, paths, now: NOW, pin: V2_H_PRIME });
    // Combined, 5 / 2100 is well under 2% — the fresh 5% is what fails.
    expect(r.intervention.rate).toBeLessThan(0.02);
    expect(r.intervention.freshWindow.pass).toBe(false);
    expect(r.intervention.missing).toMatch(/fresh would-stop rate 5\.0% is above 2\.0%/);
    expect(r.ready).toBe(false);
  });

  it('the discount rounds the count down and the would-stops up — it can only tighten the rate', () => {
    write(calls(V1_H, 3, 1, NOW - 5 * DAY, NOW - 4 * DAY));
    const r = computeReadiness({ channel: CHANNEL, paths, now: NOW, pin: V2_H_PRIME, priorPolicyCarry: 0.5 });
    expect(r.intervention.carried).toEqual({ rawStops: 1, rawTotal: 3, stops: 1, total: 1 });
  });

  it('carry 0 restores "a rule change starts over"', () => {
    write(calls(V1_H, 1000, 0, NOW - 12 * DAY, NOW - 2 * DAY));
    write(reach(V1_H, 30, 0, NOW - 3 * DAY));
    const r = computeReadiness({ channel: CHANNEL, paths, now: NOW, pin: V2_H_PRIME, priorPolicyCarry: 0 });
    expect(r.intervention.total).toBe(0);
    expect(r.intervention.carried.rawTotal).toBe(1000);
    expect(r.intervention.freshWindow.required).toBe(false);
    expect(r.reachability.resolved).toBe(0);
    // A prior policy's round-trip is not used while nothing of it is carried.
    expect(r.reachability.lastRoundTripAt).toBeNull();
  });

  it('the sliced async reader counts exactly what the sync reader counts', async () => {
    write(calls(V1_H, 700, 4, NOW - 12 * DAY, NOW - 3 * DAY));
    write(calls(V2_H_PRIME, 130, 1, NOW - 3 * DAY, NOW - HOUR));
    write(reach(V1_H, 12, 2, NOW - 4 * DAY));
    write(reach(V2_H_PRIME, 9, 1));
    const opts = { channel: CHANNEL, paths, now: NOW, pin: V2_H_PRIME, priorPolicyCarry: 0.5 };
    const sync = computeReadiness(opts);
    const async = await computeReadinessAsync(opts);
    expect(async.intervention).toEqual(sync.intervention);
    expect(async.reachability).toEqual(sync.reachability);
    expect(async.carry).toEqual(sync.carry);
  });
});

describe('#719 actionGuard.readiness.priorPolicyCarry', () => {
  it('defaults to 0.5', () => {
    expect(DEFAULT_PRIOR_POLICY_CARRY).toBe(0.5);
    expect(FRESH_POLICY_MIN_CALLS).toBe(100);
    expect(FRESH_POLICY_MIN_SPAN_MS).toBe(48 * HOUR);
    expect(normalisePriorPolicyCarry(undefined)).toEqual({ value: 0.5, source: 'default' });
  });

  it('accepts a number in [0, 1]; anything else falls back to the default (never clamped up)', () => {
    expect(normalisePriorPolicyCarry(0)).toEqual({ value: 0, source: 'config' });
    expect(normalisePriorPolicyCarry(1)).toEqual({ value: 1, source: 'config' });
    expect(normalisePriorPolicyCarry(0.25)).toEqual({ value: 0.25, source: 'config' });
    for (const bad of [5, -1, '0.9', null, Number.NaN, Infinity, {}]) {
      expect(normalisePriorPolicyCarry(bad)).toEqual({ value: 0.5, source: 'default' });
    }
  });

  it('is read from the shield config under the given home', () => {
    const home = join(root, 'home');
    mkdirSync(join(home, '.shieldcortex'), { recursive: true });
    expect(readPriorPolicyCarry(home)).toEqual({ value: 0.5, source: 'default' });
    writeFileSync(join(home, '.shieldcortex', 'config.json'), JSON.stringify({ actionGuard: { readiness: { priorPolicyCarry: 0.2 } } }));
    expect(readPriorPolicyCarry(home)).toEqual({ value: 0.2, source: 'config' });
    writeFileSync(join(home, '.shieldcortex', 'config.json'), '{not json');
    expect(readPriorPolicyCarry(home)).toEqual({ value: 0.5, source: 'default' });
  });

  it('the configured value drives the computed carry', () => {
    const home = join(root, 'home');
    mkdirSync(join(home, '.shieldcortex'), { recursive: true });
    writeFileSync(join(home, '.shieldcortex', 'config.json'), JSON.stringify({ actionGuard: { readiness: { priorPolicyCarry: 0.2 } } }));
    write(calls(V1_H, 1000, 0, NOW - 12 * DAY, NOW - 2 * DAY));
    const r = computeReadiness({ channel: CHANNEL, paths, home, now: NOW, pin: V2_H_PRIME });
    expect(r.carry).toMatchObject({ priorPolicyCarry: 0.2, source: 'config' });
    expect(r.intervention.carried.total).toBe(200);
  });
});

describe('#719 the pin in force', () => {
  it('is keyed by adapter name + policy family', () => {
    const pin = currentReadinessPin() as ReadinessPin;
    expect(pin.adapter).toMatch(/^claude-code-hook@/);
    expect(pin.policy.startsWith('tool-action-guard:')).toBe(true);
  });
});
