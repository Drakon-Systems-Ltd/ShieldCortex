/**
 * #654 — the OpenClaw summariser (`recordActionGuardDegraded`) as a receipt
 * reader: explicit membership, identity resolution, honest write status and
 * positive-completion coverage.
 *
 * Every fixture runs in a throwaway HOME with a pinned salt; the live
 * ~/.shieldcortex is never read. Renames, prepends and permission changes are
 * FIXTURE SETUP standing for history the product found on disk — they are not
 * evidence that the product may rewrite anything. HIST1 checks that each run
 * only ever appends: every file's pre-run bytes stay a byte-identical prefix.
 */
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import {
  appendFileSync, chmodSync, existsSync, linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync,
  renameSync, rmSync, symlinkSync, truncateSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  __setSessionGuardTestHooks,
  guardIdentity,
  MAX_RECEIPT_IDENTITIES,
  recordActionGuardDegraded,
  sessionKeyFor,
  v1Fingerprint,
} from '../session-guard.js';

const SALT = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const OTHER_SALT = 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210';
const T = '2026-10-01T10:00:00.000Z';
const asRoot = typeof process.getuid === 'function' && process.getuid() === 0;
const itNonRoot = asRoot ? it.skip : it;

let home: string;

function auditDir(): string { return join(home, '.shieldcortex', 'audit'); }
function key(id: string, salt = SALT): string { return sessionKeyFor(id, { salt })!; }
function indexFile(id: string): string { return join(auditDir(), 'session-guard', `${key(id)}.jsonl`); }
function today(): string { return new Date().toISOString().slice(0, 10); }
function realtimeFile(date = today()): string { return join(auditDir(), `realtime-${date}.jsonl`); }

function guard(id: string, over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    type: 'intercept', origin: 'openclaw-interceptor', sessionKey: key(id), action: 'require_approval',
    outcome: 'failure_denied', tool: 'Bash', threats: ['secret-egress'], ts: T, ...over,
  };
}
function eid(n: number): string { return n.toString(16).padStart(32, '0'); }
function nonceOf(n: number): string { return `${n.toString(16).padStart(31, '0')}a`; }
function bound(nonce: string, over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    plane: 'action_guard', gatewayInstanceId: 'gw-fixture', hookName: 'before_tool_call',
    pluginId: 'shieldcortex-realtime', nonce, seq: 7, actionKey: 'rm <home>', ...over,
  };
}

function appendLine(file: string, row: Record<string, unknown> | string): number {
  mkdirSync(join(file, '..'), { recursive: true });
  const before = existsSync(file) ? readFileSync(file, 'utf8') : '';
  const lineIndex = before === '' ? 0 : before.split('\n').length - 1;
  appendFileSync(file, `${typeof row === 'string' ? row : JSON.stringify(row)}\n`);
  return lineIndex;
}
function appendIndex(id: string, row: Record<string, unknown>): number {
  return appendLine(indexFile(id), { recordKind: row.type === 'session_summary' ? 'summary' : 'guard', ...row });
}
function physKeyIndex(id: string, lineIndex: number): string { return `${indexFile(id)}:${lineIndex}`; }

function legacyReceipt(id: string, fps: string[]): Record<string, unknown> {
  return {
    type: 'session_summary', origin: 'claude-code-stop-hook', sessionKey: key(id), action: 'session_health',
    outcome: 'action_guard_degraded', guardOutcomeCount: fps.length, guardFingerprints: fps,
    outcomes: { failure_denied: fps.length }, threats: [], ts: '2026-10-01T11:00:00.000Z',
  };
}
/** HEAD's OpenClaw summary shape: no fingerprints at all. */
function fingerprintlessSummary(id: string, lastGuardTs = T): Record<string, unknown> {
  return {
    type: 'session_summary', origin: 'openclaw-session-end', sessionKey: key(id), action: 'session_health',
    outcome: 'action_guard_degraded', guardOutcomeCount: 1, outcomes: { failure_denied: 1 }, threats: [],
    firstGuardTs: lastGuardTs, lastGuardTs, ts: '2026-10-01T12:00:00.000Z',
  };
}

function run(id: string) {
  return recordActionGuardDegraded(id, { home, salt: SALT });
}

/** Run `fn` with `path` at `mode`, always restoring it (fixtures must stay removable). */
function withMode<T>(path: string, mode: number, restore: number, fn: () => T): T {
  chmodSync(path, mode);
  try {
    return fn();
  } finally {
    chmodSync(path, restore);
  }
}

function rowsOf(file: string): Array<Record<string, unknown>> {
  if (!existsSync(file)) return [];
  return readFileSync(file, 'utf8').split('\n').filter(Boolean).flatMap((l) => {
    try { return [JSON.parse(l)]; } catch { return []; }
  });
}
function realtimeRows(): Array<Record<string, unknown>> {
  if (!existsSync(auditDir())) return [];
  return readdirSync(auditDir()).filter((f) => /^realtime-\d{4}-\d{2}-\d{2}\.jsonl$/.test(f))
    .flatMap((f) => rowsOf(join(auditDir(), f)));
}
function newReceipts(id: string): Array<Record<string, any>> {
  return realtimeRows().filter((r) => r.type === 'session_summary' && r.sessionKey === key(id)
    && r.origin === 'openclaw-session-end' && r.fingerprintScheme === 2) as Array<Record<string, any>>;
}

// ---- HIST1: snapshot after setup, compare the pre-existing byte prefix after the run.
function walk(dir: string, out: string[] = []): string[] {
  if (!existsSync(dir)) return out;
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = lstatSync(p);
    if (st.isDirectory()) walk(p, out);
    else if (st.isFile()) out.push(p);
  }
  return out;
}
function snapshot(): Map<string, Buffer> {
  return new Map(walk(home).map((p) => [p, readFileSync(p)]));
}
function expectAppendOnly(snap: Map<string, Buffer>): void {
  for (const [p, before] of snap) {
    const after = readFileSync(p);
    expect(after.length).toBeGreaterThanOrEqual(before.length);
    expect(after.subarray(0, before.length).equals(before)).toBe(true);
  }
}

/** The summariser contract every receipt assertion checks. */
function expectReceipt(r: Record<string, any>, want: {
  count: number; basis: { eventId?: number; bindingNonce?: number; physicalRow?: number };
  exact: boolean; reasons?: string[]; coverage?: 'bounded-complete' | 'partial';
}): void {
  expect(r.guardOutcomeCount).toBe(want.count);
  expect(r.guardFingerprints).toHaveLength(want.count);
  expect(new Set(r.guardFingerprints).size).toBe(want.count);
  expect(r.fingerprintScheme).toBe(2);
  expect(r.identityBasis).toEqual({ eventId: 0, bindingNonce: 0, physicalRow: 0, ...want.basis });
  expect(r.eventCountExact).toBe(want.exact);
  if (want.reasons && want.reasons.length) {
    expect(r.historicalOverlap).toBe('possible');
    expect([...r.overlapReasons].sort()).toEqual([...want.reasons].sort());
  } else {
    expect(r.historicalOverlap).toBeUndefined();
    expect(r.overlapReasons).toBeUndefined();
  }
  expect(r.coverage).toBe(want.coverage ?? 'bounded-complete');
  expect(r.coverageGaps).toBeDefined();
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'sc-654-sg-'));
  __setSessionGuardTestHooks(null);
});
afterEach(() => {
  __setSessionGuardTestHooks(null);
  try { rmSync(home, { recursive: true, force: true }); } catch { /* best effort */ }
});

describe('#654 identity resolution (guardIdentity)', () => {
  it('a strict 32-hex string ID is the eventId basis and its fingerprint is HEAD v1', () => {
    const row = guard('s', { auditEventId: eid(1) });
    const id = guardIdentity(row, '/x/a.jsonl:0');
    expect(id.basis).toBe('eventId');
    expect(id.primary).toBe(id.v1);
    // Position-independent: the same ID at another position is the same event.
    expect(guardIdentity(row, '/y/b.jsonl:9').primary).toBe(id.primary);
  });

  it('R4: an ID beats a nonce, and the primary stays byte-compatible with HEAD v1', () => {
    const row = guard('s', { auditEventId: eid(2), ...bound(nonceOf(2)) });
    const id = guardIdentity(row, '/x/a.jsonl:3');
    expect(id.basis).toBe('eventId');
    expect(id.primary).toBe(v1Fingerprint(row, '/x/a.jsonl:3'));
  });

  it('a valid nonce without an ID is the bindingNonce basis, shared by both copies, distinct from v1', () => {
    const row = guard('s', bound(nonceOf(3)));
    const a = guardIdentity(row, '/x/index.jsonl:0');
    const b = guardIdentity(row, '/x/realtime.jsonl:5');
    expect(a.basis).toBe('bindingNonce');
    expect(a.primary).toBe(b.primary);
    expect(a.v1).not.toBe(b.v1);
    expect(a.primary).not.toBe(a.v1);
  });

  it('R5: malformed IDs and nonces fall through without throwing', () => {
    const malformedIds: unknown[] = [eid(4).slice(1), `${eid(4)}0`, eid(4).toUpperCase().replace(/0/g, 'A'), 12345, null];
    for (const auditEventId of malformedIds) {
      const id = guardIdentity(guard('s', { auditEventId }), '/x/a.jsonl:1');
      expect(id.basis).toBe('physicalRow');
    }
    const malformedBindings: Array<Record<string, unknown>> = [
      bound(nonceOf(5), { actionKey: undefined }),
      bound(nonceOf(5), { seq: 0 }),
      bound(nonceOf(5), { seq: 1.5 }),
      bound(nonceOf(5), { plane: 'somewhere_else' }),
      bound(nonceOf(5).toUpperCase().replace(/0/g, 'F')),
    ];
    for (const b of malformedBindings) {
      expect(guardIdentity(guard('s', b), '/x/a.jsonl:1').basis).toBe('physicalRow');
    }
  });

  it('N2 coercion edge: a one-element-array ID is not eventId, but v1 keeps HEAD\'s coerced bytes', () => {
    const coerced = [eid(6)];
    const withoutNonce = guardIdentity(guard('s', { auditEventId: coerced }), '/x/a.jsonl:0');
    expect(withoutNonce.basis).toBe('physicalRow');
    // HEAD keys this on the coerced string, so the position does not change it.
    expect(withoutNonce.v1).toBe(guardIdentity(guard('s', { auditEventId: coerced }), '/y/b.jsonl:4').v1);
    expect(withoutNonce.v1).toBe(guardIdentity(guard('s', { auditEventId: eid(6) }), '/z:0').v1);
    const withNonce = guardIdentity(guard('s', { auditEventId: coerced, ...bound(nonceOf(6)) }), '/x/a.jsonl:0');
    expect(withNonce.basis).toBe('bindingNonce');
    expect(withNonce.v1).toBe(withoutNonce.v1);
  });
});

describe('#654 OpenClaw summariser — explicit membership', () => {
  it('R1/W5: an ID row (index-only, as when the producer realtime sink failed) counts once, then is existing', () => {
    appendIndex('r1', guard('r1', { auditEventId: eid(10) }));
    const snap = snapshot();
    const first = run('r1');
    expect(first).toMatchObject({ recorded: true, count: 1, receipt: 'primary+index', indexMirror: 'ok', coverage: 'bounded-complete' });
    const second = run('r1');
    expect(second).toMatchObject({ recorded: true, count: 0, existing: true, coverage: 'bounded-complete' });
    const receipts = newReceipts('r1');
    expect(receipts).toHaveLength(1);
    expectReceipt(receipts[0], { count: 1, basis: { eventId: 1 }, exact: true });
    expect(rowsOf(indexFile('r1')).filter((r) => r.recordKind === 'summary')).toHaveLength(1);
    expectAppendOnly(snap);
  });

  it('R3: a historical bound row (nonce only) counts once with exact cardinality', () => {
    appendIndex('r3', guard('r3', bound(nonceOf(11))));
    const first = run('r3');
    expect(first.count).toBe(1);
    expectReceipt(newReceipts('r3')[0], { count: 1, basis: { bindingNonce: 1 }, exact: true });
    expect(run('r3')).toMatchObject({ existing: true, count: 0 });
  });

  it('R6: two distinct IDs (and two distinct nonces) with identical content and ts count 2 each', () => {
    appendIndex('r6', guard('r6', { auditEventId: eid(12) }));
    appendIndex('r6', guard('r6', { auditEventId: eid(13) }));
    appendIndex('r6', guard('r6', bound(nonceOf(12))));
    appendIndex('r6', guard('r6', bound(nonceOf(13))));
    expect(run('r6').count).toBe(4);
    expectReceipt(newReceipts('r6')[0], { count: 4, basis: { eventId: 2, bindingNonce: 2 }, exact: true });
  });

  it('H4: a new distinct deny after a summary is summarised (HEAD returned existing — RC5)', () => {
    appendIndex('h4', guard('h4', { auditEventId: eid(14) }));
    expect(run('h4').count).toBe(1);
    appendIndex('h4', guard('h4', { auditEventId: eid(15), ts: '2026-10-01T09:00:00.000Z' }));
    const second = run('h4');
    expect(second).toMatchObject({ recorded: true, count: 1 });
    expect(second.existing).toBeUndefined();
    const receipts = newReceipts('h4');
    expect(receipts).toHaveLength(2);
    expect(receipts[1].guardFingerprints).not.toContain(receipts[0].guardFingerprints[0]);
    expect(run('h4')).toMatchObject({ existing: true, count: 0 });
  });

  it('R7: a pre-patch HEAD v1 receipt (physical fingerprints) still covers its rows', () => {
    const line = appendIndex('r7', guard('r7', bound(nonceOf(16))));
    appendIndex('r7', legacyReceipt('r7', [v1Fingerprint(guard('r7', bound(nonceOf(16))), physKeyIndex('r7', line))]));
    const snap = snapshot();
    expect(run('r7')).toMatchObject({ recorded: true, count: 0, existing: true, coverage: 'bounded-complete' });
    expect(newReceipts('r7')).toHaveLength(0);
    expectAppendOnly(snap);
  });

  it('R8a: an observable index alias still covers a nonce row whose realtime copy was renamed away', () => {
    const row = guard('r8a', bound(nonceOf(17)));
    const rtLine = appendLine(realtimeFile('2026-10-01'), row);
    const ixLine = appendIndex('r8a', row);
    appendIndex('r8a', legacyReceipt('r8a', [
      v1Fingerprint(row, `${realtimeFile('2026-10-01')}:${rtLine}`),
      v1Fingerprint(row, physKeyIndex('r8a', ixLine)),
    ]));
    renameSync(realtimeFile('2026-10-01'), join(auditDir(), 'archived-2026-10-01.jsonl'));
    expect(run('r8a')).toMatchObject({ existing: true, count: 0 });
    expect(newReceipts('r8a')).toHaveLength(0);
  });

  it('R8b: a reachable legacy receipt that could only have listed the moved copy → recount, disclosed', () => {
    const row = guard('r8b', bound(nonceOf(18)));
    const rtLine = appendLine(realtimeFile('2026-10-01'), row);
    appendIndex('r8b', row);
    appendIndex('r8b', legacyReceipt('r8b', [v1Fingerprint(row, `${realtimeFile('2026-10-01')}:${rtLine}`)]));
    renameSync(realtimeFile('2026-10-01'), join(auditDir(), 'archived-2026-10-01.jsonl'));
    const result = run('r8b');
    expect(result).toMatchObject({ recorded: true, count: 1, coverage: 'bounded-complete' });
    expectReceipt(newReceipts('r8b')[0], {
      count: 1, basis: { bindingNonce: 1 }, exact: true, reasons: ['position-dependent-receipt'],
    });
  });

  it('R9 — undetectable overlap (G2): pins limitation; a receipt only in a renamed file leaves no indicator', () => {
    const row = guard('r9', bound(nonceOf(19)));
    const rtLine = appendLine(realtimeFile('2026-10-01'), row);
    appendIndex('r9', row);
    appendLine(realtimeFile('2026-10-01'), legacyReceipt('r9', [v1Fingerprint(row, `${realtimeFile('2026-10-01')}:${rtLine}`)]));
    renameSync(realtimeFile('2026-10-01'), join(auditDir(), 'archived-2026-10-01.jsonl'));
    expect(run('r9').count).toBe(1);
    // Must NOT be "fixed" by inference from the missing file.
    expectReceipt(newReceipts('r9')[0], { count: 1, basis: { bindingNonce: 1 }, exact: true });
  });

  it('L7: a mirrored legacy ID-less row counts once here (index-only guards), labelled not exact', () => {
    const row = guard('l7');
    appendLine(realtimeFile('2026-10-01'), row);
    appendIndex('l7', row);
    expect(run('l7').count).toBe(1);
    expectReceipt(newReceipts('l7')[0], { count: 1, basis: { physicalRow: 1 }, exact: false });
  });

  it('L2/L5: identical or same-cleaned ID-less rows are distinct physical rows — never merged by content', () => {
    appendIndex('l2', guard('l2'));
    appendIndex('l2', guard('l2'));
    appendIndex('l2', guard('l2', { threats: ['raw-label-one'] }));
    appendIndex('l2', guard('l2', { threats: ['raw-label-two'] }));
    expect(run('l2').count).toBe(4);
    expectReceipt(newReceipts('l2')[0], { count: 4, basis: { physicalRow: 4 }, exact: false });
    expect(run('l2')).toMatchObject({ existing: true, count: 0 });
  });

  it('L4: after a receipt over ID-less rows, a new identical-content row is pending and disclosed', () => {
    appendIndex('l4', guard('l4'));
    expect(run('l4').count).toBe(1);
    appendIndex('l4', guard('l4'));
    expect(run('l4').count).toBe(1);
    const receipts = newReceipts('l4');
    expectReceipt(receipts[1], { count: 1, basis: { physicalRow: 1 }, exact: false, reasons: ['position-dependent-receipt'] });
  });

  it('L6: lines prepended before a covered ID-less row (fixture-only) → recount, not suppression', () => {
    appendIndex('l6', guard('l6'));
    expect(run('l6').count).toBe(1);
    const original = readFileSync(indexFile('l6'), 'utf8');
    writeFileSync(indexFile('l6'), `${JSON.stringify({ type: 'noise' })}\n${original}`);
    const again = run('l6');
    expect(again.count).toBe(1);
    expectReceipt(newReceipts('l6')[1], { count: 1, basis: { physicalRow: 1 }, exact: false, reasons: ['position-dependent-receipt'] });
  });

  it('H1: a fingerprint-less summary never suppresses — late, equal and backdated ID guards all count', () => {
    appendLine(realtimeFile('2026-10-01'), fingerprintlessSummary('h1'));
    appendIndex('h1', fingerprintlessSummary('h1'));
    appendIndex('h1', guard('h1', { auditEventId: eid(20), ts: '2026-10-01T09:59:59.000Z' }));
    appendIndex('h1', guard('h1', { auditEventId: eid(21), ts: T }));
    appendIndex('h1', guard('h1', { auditEventId: eid(22), ts: '2026-10-01T10:00:01.000Z' }));
    expect(run('h1').count).toBe(3);
    const r = newReceipts('h1')[0];
    expectReceipt(r, { count: 3, basis: { eventId: 3 }, exact: true, reasons: ['fingerprintless-summary'] });
    expect(r.unknownMembershipSummaryRows).toBe(2);
  });

  it('H1 single-copy variant counts one physical observation', () => {
    appendIndex('h1s', fingerprintlessSummary('h1s'));
    appendIndex('h1s', guard('h1s', { auditEventId: eid(23) }));
    expect(run('h1s').count).toBe(1);
    expect(newReceipts('h1s')[0].unknownMembershipSummaryRows).toBe(1);
  });

  it('H2: a historical summary over its own legacy rows → recount with disclosure, then existing', () => {
    appendIndex('h2', guard('h2'));
    appendIndex('h2', fingerprintlessSummary('h2'));
    expect(run('h2').count).toBe(1);
    expectReceipt(newReceipts('h2')[0], { count: 1, basis: { physicalRow: 1 }, exact: false, reasons: ['fingerprintless-summary'] });
    expect(run('h2')).toMatchObject({ existing: true, count: 0 });
    expect(rowsOf(indexFile('h2')).filter((r) => r.recordKind === 'summary')).toHaveLength(2);
  });

  it('W7: a Claude receipt present only in realtime (synthetic same key) is honoured', () => {
    const row = guard('w7', { origin: 'claude-code-hook', auditEventId: eid(24) });
    appendIndex('w7', row);
    appendLine(realtimeFile('2026-10-01'), legacyReceipt('w7', [v1Fingerprint(row, 'unused')]));
    expect(run('w7')).toMatchObject({ existing: true, count: 0, coverage: 'bounded-complete' });
  });

  it('F-1: notify rows and foreign-sessionKey rows in the index are ignored', () => {
    appendIndex('f1', guard('f1', { action: 'notify', auditEventId: eid(25) }));
    appendIndex('f1', guard('f1', { sessionKey: key('someone-else'), auditEventId: eid(26) }));
    appendIndex('f1', guard('f1', { auditEventId: eid(27) }));
    expect(run('f1').count).toBe(1);
    expect(newReceipts('f1')[0].guardFingerprints).toEqual([v1Fingerprint(guard('f1', { auditEventId: eid(27) }), '')]);
  });

  it('F-2: OpenClaw\'s own outcome set (card_* and denied) is counted here (G7)', () => {
    let n = 30;
    for (const outcome of ['card_denied', 'card_timeout', 'card_cancelled', 'denied']) {
      appendIndex('f2', guard('f2', { outcome, auditEventId: eid(n += 1) }));
    }
    appendIndex('f2', guard('f2', { outcome: 'approved_once', auditEventId: eid(n += 1) }));
    expect(run('f2').count).toBe(4);
  });

  it('X2: a divergent salt is a different key — no cross-suppression', () => {
    appendIndex('x2', guard('x2', { auditEventId: eid(40) }));
    const other = recordActionGuardDegraded('x2', { home, salt: OTHER_SALT });
    expect(other.sessionKey).not.toBe(key('x2'));
    expect(other).toMatchObject({ recorded: false, count: 0 });
    expect(run('x2').count).toBe(1);
  });
});

describe('#654 OpenClaw summariser — write status (A9)', () => {
  it('W1: a mirror failure after the primary landed is primary-only, and the next pass recovers it', () => {
    appendIndex('w1', guard('w1', { auditEventId: eid(50) }));
    appendIndex('w1', guard('w1', { auditEventId: eid(51) }));
    __setSessionGuardTestHooks({
      beforeAppend: ({ target }) => { if (target === 'mirror') throw new Error('fixture: mirror append fails'); },
    });
    const first = run('w1');
    // The guards were read from this index: the recovery pass below reads the same one.
    expect(first).toMatchObject({ recorded: true, count: 2, receipt: 'primary-only', indexMirror: 'failed' });
    const primary = newReceipts('w1');
    expect(primary).toHaveLength(1);
    expect(primary[0].receipt).toBeUndefined();
    expect(primary[0].indexMirror).toBeUndefined();
    expect(rowsOf(indexFile('w1')).filter((r) => r.recordKind === 'summary')).toHaveLength(0);

    __setSessionGuardTestHooks(null);
    const snap = snapshot();
    const second = run('w1');
    expect(second.coverageGaps?.guards.index).toBe('read');
    expect(second).toMatchObject({ recorded: true, count: 0, existing: true, coverage: 'bounded-complete' });
    expect(newReceipts('w1')).toHaveLength(1);
    expectAppendOnly(snap);
  });

  it('W3: a failed primary is never coverage; the next call summarises the same rows once', () => {
    appendIndex('w3', guard('w3', { auditEventId: eid(52) }));
    __setSessionGuardTestHooks({
      beforeAppend: ({ target }) => { if (target === 'primary') throw new Error('fixture: primary append fails'); },
    });
    expect(run('w3')).toMatchObject({ recorded: false, count: 1, receipt: 'none', indexMirror: 'not-attempted' });
    expect(rowsOf(indexFile('w3')).filter((r) => r.recordKind === 'summary')).toHaveLength(0);
    __setSessionGuardTestHooks(null);
    expect(run('w3')).toMatchObject({ recorded: true, count: 1, receipt: 'primary+index' });
    expect(run('w3')).toMatchObject({ existing: true, count: 0 });
  });

  it('W4: both sinks failing is the same as W3 — no mirror without a primary', () => {
    appendIndex('w4', guard('w4', { auditEventId: eid(53) }));
    const attempts: string[] = [];
    __setSessionGuardTestHooks({
      beforeAppend: ({ target }) => { attempts.push(target); throw new Error('fixture: sink down'); },
    });
    expect(run('w4')).toMatchObject({ recorded: false, receipt: 'none', indexMirror: 'not-attempted' });
    expect(attempts).toEqual(['primary']);
  });
});

describe('#654 OpenClaw summariser — bounded reads and positive completion (A10)', () => {
  it('B9(i): a fresh root is a KNOWN absence — bounded-complete, nothing found', () => {
    const result = run('b9');
    expect(result).toMatchObject({ recorded: false, count: 0, coverage: 'bounded-complete' });
    expect(result.coverageGaps?.receipts).toMatchObject({ auditDir: 'absent', index: 'absent' });
    expect(result.coverageGaps?.guards).toMatchObject({ auditDir: 'not-sought', index: 'absent' });
  });

  it('B9(ii): index present, audit dir listed with no realtime files → bounded-complete', () => {
    appendIndex('b9b', guard('b9b', { auditEventId: eid(60) }));
    const result = run('b9b');
    expect(result).toMatchObject({ recorded: true, count: 1, coverage: 'bounded-complete' });
    expect(result.coverageGaps?.receipts).toMatchObject({ auditDir: 'listed', index: 'read', skippedFiles: 0, failedFiles: 0 });
  });

  it('B1: past the 256-file cap a receipt is unseen → recount with receipt-coverage-partial', () => {
    const row = guard('b1', { auditEventId: eid(61) });
    appendIndex('b1', row);
    for (let i = 0; i < 257; i += 1) {
      const date = `2025-${String(1 + Math.floor(i / 28)).padStart(2, '0')}-${String(1 + (i % 28)).padStart(2, '0')}`;
      appendLine(realtimeFile(date), i === 0 ? legacyReceipt('b1', [v1Fingerprint(row, '')]) : { type: 'noise' });
    }
    const result = run('b1');
    expect(result).toMatchObject({ recorded: true, count: 1, coverage: 'partial' });
    expect(result.coverageGaps!.receipts.skippedFiles).toBeGreaterThan(0);
    expectReceipt(newReceipts('b1')[0], {
      count: 1, basis: { eventId: 1 }, exact: true, coverage: 'partial', reasons: ['receipt-coverage-partial'],
    });
  });

  it('B2: an oversized realtime candidate is skipped (sparse, never read) → partial', () => {
    appendIndex('b2', guard('b2', { auditEventId: eid(62) }));
    const big = realtimeFile('2026-09-30');
    appendLine(big, { type: 'noise' });
    truncateSync(big, 64 * 1024 * 1024 + 1);
    const result = run('b2');
    expect(result.coverage).toBe('partial');
    expect(result.coverageGaps!.receipts.skippedFiles).toBe(1);
  });

  it('B3: an index past its 64 MiB prefix is truncated → partial, the receipt past it is unseen', () => {
    const row = guard('b3', { auditEventId: eid(63) });
    appendIndex('b3', row);
    truncateSync(indexFile('b3'), 64 * 1024 * 1024 + 16);
    appendFileSync(indexFile('b3'), `\n${JSON.stringify({ recordKind: 'summary', ...legacyReceipt('b3', [v1Fingerprint(row, '')]) })}\n`);
    const result = run('b3');
    expect(result.coverageGaps!.receipts.index).toBe('truncated');
    expect(result.coverageGaps!.guards.index).toBe('truncated');
    expect(result).toMatchObject({ recorded: true, count: 1, coverage: 'partial' });
    expect(newReceipts('b3')[0].overlapReasons).toContain('receipt-coverage-partial');
  }, 60_000);

  it('B4: a crafted >1 MiB receipt line is dropped, suppresses nothing, and is disclosed', () => {
    const row = guard('b4', { auditEventId: eid(64) });
    appendIndex('b4', row);
    appendIndex('b4', { ...legacyReceipt('b4', [v1Fingerprint(row, '')]), pad: 'x'.repeat(1024 * 1024 + 8) });
    const result = run('b4');
    expect(result).toMatchObject({ recorded: true, count: 1, coverage: 'partial' });
    expect(result.coverageGaps!.receipts.droppedLines).toBeGreaterThan(0);
  });

  it('B5: 16,385 pending IDs → batches of 16,384 + 1, each under 1 MiB, no identity twice', () => {
    const lines: string[] = [];
    for (let i = 0; i < MAX_RECEIPT_IDENTITIES + 1; i += 1) {
      lines.push(JSON.stringify({ recordKind: 'guard', ...guard('b5', { auditEventId: eid(100_000 + i) }) }));
    }
    mkdirSync(join(auditDir(), 'session-guard'), { recursive: true });
    writeFileSync(indexFile('b5'), `${lines.join('\n')}\n`);
    const first = run('b5');
    expect(first).toMatchObject({ recorded: true, count: MAX_RECEIPT_IDENTITIES, pendingRemaining: 1 });
    const primaryLines = readFileSync(realtimeFile(), 'utf8').split('\n').filter(Boolean);
    expect(Buffer.byteLength(primaryLines[0], 'utf8')).toBeLessThan(1024 * 1024);
    const second = run('b5');
    expect(second).toMatchObject({ recorded: true, count: 1 });
    expect(second.pendingRemaining).toBeUndefined();
    const receipts = newReceipts('b5');
    expect(receipts).toHaveLength(2);
    expectReceipt(receipts[0], { count: MAX_RECEIPT_IDENTITIES, basis: { eventId: MAX_RECEIPT_IDENTITIES }, exact: true });
    expect(receipts[0].pendingRemaining).toBe(1);
    const all = [...receipts[0].guardFingerprints, ...receipts[1].guardFingerprints];
    expect(new Set(all).size).toBe(MAX_RECEIPT_IDENTITIES + 1);
    expect(run('b5')).toMatchObject({ existing: true, count: 0 });
  }, 60_000);

  it('B6: symlinked index, symlinked and hard-linked realtime candidates are refused → partial', () => {
    const victim = join(home, 'victim.jsonl');
    writeFileSync(victim, `${JSON.stringify({ recordKind: 'guard', ...guard('b6', { auditEventId: eid(65) }) })}\n`);
    mkdirSync(join(auditDir(), 'session-guard'), { recursive: true });
    symlinkSync(victim, indexFile('b6'));
    symlinkSync(victim, realtimeFile('2026-09-01'));
    appendLine(realtimeFile('2026-09-02'), { type: 'noise' });
    linkSync(realtimeFile('2026-09-02'), join(home, 'hardlink-copy'));
    const snap = snapshot();
    const result = run('b6');
    expect(result).toMatchObject({ recorded: false, count: 0, coverage: 'partial' });
    expect(result.coverageGaps!.receipts.index).toBe('refused');
    expect(result.coverageGaps!.guards.index).toBe('refused');
    expect(result.coverageGaps!.receipts.refusedFiles).toBe(2);
    expect(readFileSync(victim, 'utf8')).toBe(`${JSON.stringify({ recordKind: 'guard', ...guard('b6', { auditEventId: eid(65) }) })}\n`);
    expectAppendOnly(snap);
  });

  itNonRoot('B7: an unreadable receipt file is a failed source → recount, partial on the result', () => {
    const row = guard('b7', { auditEventId: eid(66) });
    appendIndex('b7', row);
    appendLine(realtimeFile('2026-09-03'), legacyReceipt('b7', [v1Fingerprint(row, '')]));
    const result = withMode(realtimeFile('2026-09-03'), 0o000, 0o600, () => run('b7'));
    expect(result).toMatchObject({ recorded: true, count: 1, coverage: 'partial' });
    expect(result.coverageGaps!.receipts.failedFiles).toBe(1);
  });

  itNonRoot('B8: an audit dir that cannot be listed is NEVER bounded-complete (discovery failure)', () => {
    const row = guard('b8', { auditEventId: eid(67) });
    appendIndex('b8', row);
    // A primary-only receipt for the guard, in the file the next receipt also appends to.
    appendLine(realtimeFile(), legacyReceipt('b8', [v1Fingerprint(row, '')]));
    const result = withMode(auditDir(), 0o100, 0o700, () => run('b8'));
    expect(result.coverageGaps!.receipts.auditDir).toBe('failed');
    expect(result).toMatchObject({ recorded: true, count: 1, coverage: 'partial' });
    const r = newReceipts('b8')[0];
    expectReceipt(r, { count: 1, basis: { eventId: 1 }, exact: true, coverage: 'partial', reasons: ['receipt-coverage-partial'] });
  });

  itNonRoot('B10: an index that cannot be inspected is failed, not absent', () => {
    appendIndex('b10', guard('b10', { auditEventId: eid(68) }));
    const result = withMode(join(auditDir(), 'session-guard'), 0o000, 0o700, () => run('b10'));
    expect(result).toMatchObject({ recorded: false, count: 0, coverage: 'partial' });
    expect(result.coverageGaps!.receipts.index).toBe('failed');
    expect(result.coverageGaps!.guards.index).toBe('failed');
  });

  it('B11 (receipts pass): a mid-stream failure after a guard line, before a receipt line → recount, disclosed', () => {
    const row = guard('b11', { auditEventId: eid(69) });
    appendIndex('b11', row);
    const file = realtimeFile('2026-09-04');
    appendLine(file, row);
    appendLine(file, { type: 'noise', pad: 'x'.repeat(70 * 1024) });
    appendLine(file, legacyReceipt('b11', [v1Fingerprint(row, '')]));
    __setSessionGuardTestHooks({
      beforeReadChunk: ({ pass, file: f, chunk }) => {
        if (pass === 'receipts' && f === file && chunk >= 1) throw new Error('fixture: EIO mid-stream');
      },
    });
    const result = run('b11');
    expect(result.coverageGaps!.receipts.failedFiles).toBe(1);
    expect(result.coverageGaps!.guards.failedFiles).toBe(0);
    expect(result).toMatchObject({ recorded: true, count: 1, coverage: 'partial' });
    expect(newReceipts('b11')[0].overlapReasons).toEqual(['receipt-coverage-partial']);
  });

  it('B11 (guards pass): an index failing mid-stream contributes no guards and no overlap reason', () => {
    appendIndex('b11g', guard('b11g', { auditEventId: eid(70) }));
    appendIndex('b11g', { type: 'noise', pad: 'x'.repeat(70 * 1024) } as Record<string, unknown>);
    appendIndex('b11g', guard('b11g', { auditEventId: eid(71) }));
    __setSessionGuardTestHooks({
      beforeReadChunk: ({ pass, chunk }) => {
        if (pass === 'guards' && chunk >= 1) throw new Error('fixture: EIO mid-stream');
      },
    });
    const result = run('b11g');
    expect(result.coverageGaps!.guards.index).toBe('failed');
    expect(result.coverageGaps!.receipts.index).toBe('read');
    // Rows from a source that failed are neither counted nor allowed to suppress.
    expect(result).toMatchObject({ recorded: false, count: 0, coverage: 'partial' });
    expect(newReceipts('b11g')).toHaveLength(0);
  });

  it('B12(i): existing:true travels with partial coverage and one gap line (kinds and counts, no paths)', () => {
    const row = guard('b12', { auditEventId: eid(72) });
    appendIndex('b12', row);
    appendIndex('b12', legacyReceipt('b12', [v1Fingerprint(row, '')]));
    const outside = join(home, 'outside.jsonl');
    writeFileSync(outside, '\n');
    mkdirSync(auditDir(), { recursive: true });
    symlinkSync(outside, realtimeFile('2026-09-05'));
    const lines: string[] = [];
    const spy = jest.spyOn(console, 'error').mockImplementation((...args: unknown[]) => { lines.push(args.map(String).join(' ')); });
    let result: ReturnType<typeof run>;
    try {
      result = run('b12');
    } finally {
      spy.mockRestore();
    }
    expect(result).toMatchObject({ recorded: true, existing: true, count: 0, coverage: 'partial' });
    expect(result.coverageGaps!.receipts.refusedFiles).toBe(1);
    const gapLines = lines.filter((l) => l.includes('coverage=partial'));
    expect(gapLines).toHaveLength(1);
    expect(gapLines[0]).toContain('refusedFiles=1');
    expect(gapLines[0]).not.toContain(home);
  });
});
