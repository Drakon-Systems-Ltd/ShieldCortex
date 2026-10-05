/**
 * #509 round 9: the async evidence read on the OpenClaw gateway, hardened.
 *
 *  - T1: a resolve the gateway gave up on (timed out) is aborted, and an
 *    aborted resolve writes nothing — no transition, no state — however late
 *    its read settles.
 *  - T3: rows that cannot count for THIS adapter (other planes, other
 *    adapters) are dropped as they are read, not kept for the whole window.
 *  - T4: a line with no newline cannot make the reader re-split an ever-growing
 *    carry: past the cap it is one unparseable line, and reading goes on.
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  computeReadiness,
  computeReadinessAsync,
  currentReadinessPin,
  initReadinessTransitions,
  MAX_EVIDENCE_LINE_CHARS,
  readTransitionRecord,
  resolveReadinessAsync,
  transitionsPathFor,
  type ReadinessPaths,
  type ReadinessPin,
} from '../guard-readiness.js';

const DAY = 24 * 60 * 60 * 1000;
const NOW = Date.parse('2026-09-28T12:00:00.000Z');
const CHANNEL = { configured: true, kind: 'webhook', pushesNotices: true };
const OPENCLAW = 'openclaw-interceptor' as const;
const HOOK = 'claude-code-hook' as const;
const PIN = currentReadinessPin() as ReadinessPin;
const OC_PIN = currentReadinessPin(OPENCLAW) as ReadinessPin;
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

function call(ts: number, origin: string = HOOK, pin: ReadinessPin = PIN, outcome = 'allowed'): Record<string, unknown> {
  seq += 1;
  return {
    ts: new Date(ts).toISOString(), auditEventId: `e${seq.toString(16).padStart(10, '0')}`, readinessPin: pin,
    type: 'intercept', origin, tool: 'Bash', severity: outcome === 'allowed' ? 'low' : 'high',
    action: outcome === 'allowed' ? 'allow' : 'require_approval', outcome,
  };
}

function history(days: number, perDay: number, origin: string = HOOK, pin: ReadinessPin = PIN): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  for (let d = days - 1; d >= 0; d -= 1) {
    for (let i = 0; i < perDay; i += 1) out.push(call(NOW - d * DAY - 6 * 60 * 60 * 1000 + i * 1000, origin, pin, i % 400 === 0 ? 'would_hold' : 'allowed'));
  }
  return out;
}

function reached(n: number, origin: string = HOOK, pin: ReadinessPin = PIN): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  for (let i = 0; i < n; i += 1) {
    const t = NOW - DAY + i * 1000;
    out.push({ ts: new Date(t).toISOString(), auditEventId: `q${origin}${i}`, readinessPin: pin, type: 'approval_reach', origin, reachId: `r${origin}${i}`, attemptId: `a${origin}${i}`, phase: 'request' });
    out.push({ ts: new Date(t + 30_000).toISOString(), auditEventId: `s${origin}${i}`, type: 'approval_reach', origin, reachId: `r${origin}${i}`, attemptId: `a${origin}${i}`, phase: 'answer', answer: 'approve' });
  }
  return out;
}

/** Rows from other planes: never readiness evidence for any adapter. */
function otherPlanes(n: number): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  for (let i = 0; i < n; i += 1) {
    seq += 1;
    out.push({ ts: new Date(NOW - 2 * DAY + i * 1000).toISOString(), auditEventId: `m${seq}`, type: 'memory_write', origin: 'mcp', tool: 'remember', firewallResult: 'ALLOW' });
  }
  return out;
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'sc-readiness-r9-'));
  paths = { auditDir: join(root, 'audit'), statePath: join(root, 'approvals', 'guard-readiness.json'), readAuditDirs: [join(root, 'audit')] };
  initReadinessTransitions({ postureChanged: true, reason: 'test posture', paths, now: NOW - 60 * DAY });
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

describe('#509 r9 T1 — an aborted async resolve writes nothing', () => {
  it('aborted while it reads: rejects, and the promotion it would have made is neither journalled nor cached', async () => {
    write([...history(9, 120), ...reached(25)]);
    const ac = new AbortController();
    const p = resolveReadinessAsync({ channel: CHANNEL, paths, now: NOW, ...WITH_REVIEWED, signal: ac.signal });
    ac.abort();
    await expect(p).rejects.toThrow(/abort/i);
    expect(readTransitionRecord(transitionsPathFor(paths)).last).toMatchObject({ event: 'init', to: 'shadow' });
    expect(existsSync(paths.statePath)).toBe(false);
    // Not aborted, the same resolve promotes (so the test above proves the abort).
    await expect(resolveReadinessAsync({ channel: CHANNEL, paths, now: NOW, ...WITH_REVIEWED }))
      .resolves.toMatchObject({ mode: 'enforcing', transition: 'promote' });
  });

  it('already aborted: rejects before reading anything', async () => {
    const ac = new AbortController();
    ac.abort();
    await expect(resolveReadinessAsync({ channel: CHANNEL, paths, now: NOW, signal: ac.signal })).rejects.toThrow(/abort/i);
    expect(existsSync(paths.statePath)).toBe(false);
  });
});

describe('#509 r9 T3 — only rows that can count for this adapter are kept', () => {
  it('other planes and the other adapter are dropped at ingest; the report is unchanged, sync and async alike', async () => {
    const mine = [...history(8, 30, OPENCLAW, OC_PIN), ...reached(5, OPENCLAW, OC_PIN)];
    write([...mine, ...history(8, 50, HOOK, PIN), ...reached(7, HOOK, PIN), ...otherPlanes(400)]);
    const kept: number[] = [];
    const opts = { channel: CHANNEL, paths, now: NOW, adapter: OPENCLAW, onEvidenceRead: (e: { rowsKept: number }) => { kept.push(e.rowsKept); } };
    const sync = computeReadiness(opts);
    const asyncReport = await computeReadinessAsync(opts);
    expect({ ...asyncReport, computedAt: 'x' }).toEqual({ ...sync, computedAt: 'x' });
    // Kept: this adapter's calls, requests and answers, plus the hook's 7
    // answers (answers bind by attempt id, whatever their origin). Not kept:
    // the hook's 400 calls and 7 requests, and the 400 other-plane rows.
    expect(kept).toEqual([mine.length + 7, mine.length + 7]);
    // …and still accounted for where the report says so.
    expect(sync.intervention.total).toBe(240);
    expect(sync.intervention.otherVersion).toBe(400);
    expect(sync.reachability.otherVersion).toBe(7);
    expect(sync.adapterRows).toBe(mine.length - 5);
  });
});

describe('#509 r9 T4 — a newline-free file cannot stall the sliced reader', () => {
  it('an 8 MB line with no newline: one unparseable line, bounded time, the loop keeps turning — sync and async agree', async () => {
    mkdirSync(paths.auditDir, { recursive: true });
    const day = new Date(NOW - DAY).toISOString().slice(0, 10);
    writeFileSync(join(paths.auditDir, `realtime-${day}.jsonl`), 'z'.repeat(8 * 1024 * 1024));
    let ticks = 0;
    let stop = false;
    const tick = (): void => { ticks += 1; if (!stop) setImmediate(tick); };
    setImmediate(tick);
    const t0 = Date.now();
    const report = await computeReadinessAsync({ channel: CHANNEL, paths, now: NOW });
    const ms = Date.now() - t0;
    stop = true;
    expect(report.integrity.unparseableLines).toBe(1);
    expect(report.integrity.pass).toBe(false);
    expect(ms).toBeLessThan(3000);
    expect(ticks).toBeGreaterThan(5);
    expect(computeReadiness({ channel: CHANNEL, paths, now: NOW }).integrity.unparseableLines).toBe(1);
  });

  it('an oversized line then real rows: the oversized one is counted once and the rows after it are read', async () => {
    mkdirSync(paths.auditDir, { recursive: true });
    const day = new Date(NOW - DAY).toISOString().slice(0, 10);
    const rows = history(1, 20).map((r) => ({ ...r, ts: `${day}T10:00:00.000Z` }));
    writeFileSync(
      join(paths.auditDir, `realtime-${day}.jsonl`),
      `${'z'.repeat(MAX_EVIDENCE_LINE_CHARS + 3 * 256 * 1024)}\n${rows.map((r) => JSON.stringify(r)).join('\n')}\n`,
    );
    const sync = computeReadiness({ channel: CHANNEL, paths, now: NOW });
    const asyncReport = await computeReadinessAsync({ channel: CHANNEL, paths, now: NOW });
    expect(asyncReport.integrity.unparseableLines).toBe(1);
    expect(asyncReport.intervention.total).toBe(20);
    expect({ ...asyncReport, computedAt: 'x' }).toEqual({ ...sync, computedAt: 'x' });
  });

  it('the cap is larger than any legitimate row (≥ 1 MB)', () => {
    expect(MAX_EVIDENCE_LINE_CHARS).toBeGreaterThanOrEqual(1024 * 1024);
  });
});
