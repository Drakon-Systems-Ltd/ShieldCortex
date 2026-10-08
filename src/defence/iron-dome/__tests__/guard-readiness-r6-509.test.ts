/**
 * #509 round 6 — regressions for the Claude confirmation review of 10535bc5
 * (REVIEW-r5-claude.md). Each was reproduced against that head first.
 *
 *  S1  A forged demotion after a real promotion — `init`/`recover` → shadow
 *      with no `demote` between — is a doctor FAIL and a hook tamper signal.
 *  N2  A promotion notice that FAILED to send is not reported as a forgery;
 *      one with NO recorded attempt is.
 *  N3  Notice and init appends take the writer lock; the under-lock re-check
 *      in resolveReadiness is driven by a real interleaving.
 *  N4  The journal read is bounded.
 * (N1 is in tool-action-guard-floor-r6-509; S2 in enforcement-surface-parity.)
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as readiness from '../guard-readiness.js';
import {
  computeReadiness,
  currentReadinessPin,
  describeHumanChannel,
  durableMode,
  initReadinessTransitions,
  lastPromotion,
  previewMode,
  readTransitionRecord,
  readinessPaths,
  recordTransitionNotice,
  resolveReadiness,
  transitionsPathFor,
  type EffectivenessEvidence,
  type ReadinessPaths,
  type ReadinessPin,
  type TransitionRecord,
} from '../guard-readiness.js';
import { describePromotionNotice } from '../../../cli/guard.js';

// Round-6 exports, read through the namespace so this suite still LOADS
// against the pre-fix head (10535bc5) and each regression fails on its own.
const r6 = readiness as unknown as {
  unexplainedDemotion?: (rec: TransitionRecord) => { event: string; ts: string } | null;
  JOURNAL_READ_MAX_BYTES?: number;
};
const unexplainedDemotion = (rec: TransitionRecord) => {
  expect(typeof r6.unexplainedDemotion).toBe('function');
  return r6.unexplainedDemotion!(rec);
};
type ResolveOpts = Parameters<typeof resolveReadiness>[0] & { beforeLock?: () => void };
const resolve = (o: ResolveOpts) => resolveReadiness(o as Parameters<typeof resolveReadiness>[0]);

const DAY = 24 * 60 * 60 * 1000;
const MIN = 60 * 1000;
const NOW = Date.parse('2026-09-29T12:00:00.000Z');
const PIN = currentReadinessPin() as ReadinessPin;
const WEBHOOK = describeHumanChannel({ enabled: true, webhookUrl: 'https://example.invalid/hook' });
const REVIEWED: readonly EffectivenessEvidence[] = [
  { ...PIN, reviewedAt: new Date(NOW - DAY).toISOString(), reviewedBy: 'fixture reviewer', reference: 'test fixture', cases: 60 },
];

let root: string;
let home: string;
let paths: ReadinessPaths;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'sc-readiness-r6-'));
  home = join(root, 'home');
  mkdirSync(join(home, '.shieldcortex', 'approvals'), { recursive: true });
  paths = readinessPaths({ home });
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

function writeRows(rows: Array<Record<string, unknown>>): void {
  mkdirSync(paths.auditDir, { recursive: true });
  let n = 0;
  for (const r of rows) {
    const full: Record<string, unknown> = { auditEventId: `r6-${(n += 1)}`, readinessPin: PIN, ...r };
    appendFileSync(join(paths.auditDir, `realtime-${String(full.ts).slice(0, 10)}.jsonl`), `${JSON.stringify(full)}\n`);
  }
}

/** 500 qualifying calls over eight days and 20 answered approvals: ready with REVIEWED. */
function seedReadyEvidence(): void {
  const rows: Array<Record<string, unknown>> = [];
  for (let i = 0; i < 500; i += 1) {
    rows.push({ ts: new Date(NOW - 8 * DAY + Math.floor((i * 8 * DAY) / 500) + 1000).toISOString(), type: 'intercept', origin: 'claude-code-hook', tool: 'Bash', severity: 'low', action: 'allow', outcome: 'allowed' });
  }
  for (let i = 0; i < 20; i += 1) {
    const t = NOW - DAY + i * MIN;
    rows.push({ ts: new Date(t).toISOString(), type: 'approval_reach', reachId: `g${i}`, attemptId: `ga${i}`, phase: 'request' });
    rows.push({ ts: new Date(t + 30_000).toISOString(), type: 'approval_reach', reachId: `g${i}`, attemptId: `ga${i}`, phase: 'answer', answer: 'approve' });
  }
  writeRows(rows);
}

function writeJournal(entries: Array<Record<string, unknown>>): void {
  writeFileSync(transitionsPathFor(paths), entries.map((e) => JSON.stringify(e)).join('\n') + '\n');
}
const journal = () => readTransitionRecord(transitionsPathFor(paths));
const shadowCache = (at: number) =>
  writeFileSync(paths.statePath, JSON.stringify({ version: 1, mode: 'shadow', computedAt: new Date(at).toISOString(), pin: PIN }));

// The reviewer's S1 forgery: a real, delivered promotion 40 days ago (its
// audit row has aged out of the 30-day window), then a same-UID writer
// appends init → shadow and a fresh shadow cache. The promote entry stays.
const promotedAt = new Date(NOW - 40 * DAY).toISOString();
const REAL_PROMOTION = [
  { ts: new Date(NOW - 60 * DAY).toISOString(), event: 'init', to: 'shadow', reason: 'posture' },
  { ts: promotedAt, event: 'promote', to: 'enforcing', pin: PIN },
  { ts: new Date(NOW - 40 * DAY + 1000).toISOString(), event: 'notice', of: 'promote', transitionTs: promotedAt, delivered: true, channel: 'webhook' },
];
const FORGED_INIT = { ts: new Date(NOW - 5 * MIN).toISOString(), event: 'init', to: 'shadow', reason: 'posture' };

// ─────────────────────────────────────────────────────────────────────────────

describe('#509 r6 S1 — a forged demotion after a real promotion is loud', () => {
  it('unexplainedDemotion: init/recover → shadow after a promote with no demote between', () => {
    writeJournal([...REAL_PROMOTION, FORGED_INIT]);
    expect(unexplainedDemotion(journal())).toMatchObject({ event: 'init', ts: FORGED_INIT.ts });
    writeJournal([...REAL_PROMOTION, { ts: FORGED_INIT.ts, event: 'recover', to: 'shadow', pin: PIN }]);
    expect(unexplainedDemotion(journal())).toMatchObject({ event: 'recover' });
    // Explained: a demote between them, or no promotion at all, or enforcing.
    writeJournal([...REAL_PROMOTION, { ts: new Date(NOW - 10 * DAY).toISOString(), event: 'demote', to: 'shadow', pin: PIN, reason: 'r' }, FORGED_INIT]);
    expect(unexplainedDemotion(journal())).toBeNull();
    writeJournal([REAL_PROMOTION[0]]);
    expect(unexplainedDemotion(journal())).toBeNull();
    writeJournal(REAL_PROMOTION);
    expect(unexplainedDemotion(journal())).toBeNull();
  });

  it('doctor FAILs, naming an unexplained demotion — not "SHADOW (not ready yet) … Nothing is broken"', async () => {
    const { checkActionGuardReadiness } = await import('../../../cli/doctor.js');
    writeJournal([...REAL_PROMOTION, FORGED_INIT]);
    shadowCache(NOW - MIN);
    const record = journal();
    const report = computeReadiness({ channel: WEBHOOK, paths, now: NOW });
    expect(report.lastTransition).toBeNull(); // the audit row has aged out
    // What buildReadinessSummary computed at 10535bc5 for this install.
    const summary = {
      posture: 'enforce-when-ready', lockOverrides: false, mode: 'shadow', channel: WEBHOOK, report, state: null,
      demoted: false, record, recordUnknown: false, recentTamper: null, lastPromotion: lastPromotion(record),
    };
    const rows = await checkActionGuardReadiness({ summary: () => summary as never });
    const fail = rows.find((r) => r.status === 'fail');
    expect(fail).toBeDefined();
    expect(fail!.message).toMatch(/unexplained demotion/i);
    expect(fail!.message).toContain(FORGED_INIT.ts);
    expect(rows.some((r) => /Nothing is broken/.test(r.fix ?? ''))).toBe(false);
  });

  it('guard readiness / doctor preview does not trust it either: the promotion stands', () => {
    writeJournal([...REAL_PROMOTION, FORGED_INIT]);
    shadowCache(NOW - MIN);
    const record = journal();
    const state = JSON.parse(readFileSync(paths.statePath, 'utf8'));
    // Evidence ready: the hook will keep enforcing.
    seedReadyEvidence();
    const ready = computeReadiness({ channel: WEBHOOK, paths, now: NOW, effectivenessRegistry: REVIEWED });
    expect(ready.ready).toBe(true);
    expect(previewMode({ state, report: ready, now: NOW, record })).toBe('enforcing');
  });

  it('the hook treats it as a tamper signal: evidence NOT ready ⇒ a full, journalled demotion (announced), never a quiet shadow', () => {
    writeJournal([...REAL_PROMOTION, FORGED_INIT]);
    shadowCache(NOW - MIN);
    const r = resolve({ channel: WEBHOOK, paths, now: NOW });
    expect(r.cached).toBe(false);
    expect(r.tamper).toMatch(/unexplained/i);
    expect(r.transition).toBe('demote');
    const rec = journal();
    expect(rec.last?.event).toBe('demote');
    expect(rec.entries.some((e) => e.event === 'tamper' && /unexplained/i.test(e.reason ?? ''))).toBe(true);
    expect(unexplainedDemotion(rec)).toBeNull();
  });

  it('the hook treats it as a tamper signal: evidence ready ⇒ keeps enforcing and re-anchors the journal', () => {
    writeJournal([...REAL_PROMOTION, FORGED_INIT]);
    shadowCache(NOW - MIN);
    seedReadyEvidence();
    const r = resolve({ channel: WEBHOOK, paths, now: NOW, effectivenessRegistry: REVIEWED });
    expect(r.mode).toBe('enforcing');
    expect(r.tamper).toMatch(/unexplained/i);
    expect(r.transition).toBeNull();
    expect(durableMode(journal())).toBe('enforcing');
    expect(journal().last?.event).toBe('recover');
  });

  it('re-selecting the posture after a promotion is an explained demotion, not a forgery', () => {
    writeJournal(REAL_PROMOTION);
    expect(initReadinessTransitions({ postureChanged: true, reason: 'posture set again', paths, now: NOW })).toBe(true);
    const rec = journal();
    expect(rec.last?.event).toBe('init');
    expect(unexplainedDemotion(rec)).toBeNull();
    expect(rec.entries.filter((e) => e.event === 'demote')).toHaveLength(1);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('#509 r6 N2 — a failed notice is not a forgery; a missing notice attempt may be', () => {
  it('failed: points at the channel, says nothing about forgery', () => {
    const text = describePromotionNotice({ promotedAt, notice: 'failed', reason: 'webhook 503' });
    expect(text).toMatch(/failed to send/i);
    expect(text).toMatch(/check your (notice )?channel/i);
    expect(text).not.toMatch(/forge/i);
  });

  it('none: no attempt recorded — possible forgery', () => {
    const text = describePromotionNotice({ promotedAt, notice: 'none' });
    expect(text).toMatch(/no notice attempt recorded/i);
    expect(text).toMatch(/possible forgery/i);
  });

  it('delivered: hold it against what you received', () => {
    const text = describePromotionNotice({ promotedAt, notice: 'delivered', channel: 'webhook' });
    expect(text).toMatch(/delivered via webhook/);
    expect(text).toMatch(/did not receive/i);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('#509 r6 N3 — journal writers take the lock; the under-lock re-check is driven', () => {
  /** A lock held by a live writer (mtime = the test clock, so never stale). */
  function holdLock(): string {
    const lock = `${paths.statePath}.lock`;
    writeFileSync(lock, String(NOW));
    utimesSync(lock, new Date(NOW), new Date(NOW));
    return lock;
  }

  it('recordTransitionNotice does not append while another writer holds the lock, and does once it is free', () => {
    writeJournal(REAL_PROMOTION.slice(0, 2));
    const lock = holdLock();
    expect(recordTransitionNotice({ of: 'promote', transitionAt: promotedAt, delivered: true, channel: 'webhook', paths, now: NOW })).toBe(false);
    expect(journal().entries.filter((e) => e.event === 'notice')).toHaveLength(0);
    rmSync(lock);
    expect(recordTransitionNotice({ of: 'promote', transitionAt: promotedAt, delivered: true, channel: 'webhook', paths, now: NOW })).toBe(true);
    expect(journal().entries.filter((e) => e.event === 'notice')).toHaveLength(1);
    expect(existsSync(lock)).toBe(false);
  });

  it('initReadinessTransitions does not append while another writer holds the lock', () => {
    const lock = holdLock();
    expect(initReadinessTransitions({ postureChanged: true, reason: 'x', paths, now: NOW })).toBe(false);
    expect(journal().status).toBe('missing');
    rmSync(lock);
    expect(initReadinessTransitions({ postureChanged: true, reason: 'x', paths, now: NOW })).toBe(true);
    expect(durableMode(journal())).toBe('shadow');
  });

  it('another process promotes between our pre-lock read and our lock: we do not promote (or announce) a second time', () => {
    writeJournal([REAL_PROMOTION[0]]);
    seedReadyEvidence();
    const path = transitionsPathFor(paths);
    const r = resolve({
      channel: WEBHOOK, paths, now: NOW, effectivenessRegistry: REVIEWED,
      beforeLock: () => appendFileSync(path, `${JSON.stringify({ ts: new Date(NOW - 1000).toISOString(), event: 'promote', to: 'enforcing', pin: PIN })}\n`),
    });
    expect(r.transition).toBeNull();
    expect(r.mode).toBe('enforcing');
    expect(journal().entries.filter((e) => e.event === 'promote')).toHaveLength(1);
  });

  // (The r5 finding-7 interleaving now runs through this same seam, in
  // guard-readiness-r5-509.)
  it('another process promotes while we decided shadow: we answer enforcing and write no shadow cache over it', () => {
    writeJournal([REAL_PROMOTION[0]]);
    const path = transitionsPathFor(paths);
    const r = resolve({
      channel: WEBHOOK, paths, now: NOW,
      beforeLock: () => appendFileSync(path, `${JSON.stringify({ ts: new Date(NOW - 1000).toISOString(), event: 'promote', to: 'enforcing', pin: PIN })}\n`),
    });
    expect(r.mode).toBe('enforcing');
    expect(existsSync(paths.statePath)).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('#509 r6 N4 — the journal read is bounded', () => {
  it('a journal over the read cap is unreadable (unknown ⇒ the loud path), not read into memory', () => {
    expect(typeof r6.JOURNAL_READ_MAX_BYTES).toBe('number');
    const cap = r6.JOURNAL_READ_MAX_BYTES!;
    const line = `${JSON.stringify({ ts: new Date(NOW - DAY).toISOString(), event: 'tamper', pin: PIN, reason: 'x'.repeat(300) })}\n`;
    const body = line.repeat(Math.ceil((cap + 1) / line.length));
    writeFileSync(transitionsPathFor(paths), `${JSON.stringify(REAL_PROMOTION[1])}\n${body}`);
    const rec = journal();
    expect(rec.status).toBe('unreadable');
    expect(durableMode(rec)).toBe('unknown');
    // Just under the cap still reads.
    writeFileSync(transitionsPathFor(paths), `${JSON.stringify(REAL_PROMOTION[1])}\n${line}`);
    expect(journal().status).toBe('ok');
    // The hook's answer for an oversized journal is the unknown-record protocol.
    writeFileSync(transitionsPathFor(paths), `${JSON.stringify(REAL_PROMOTION[1])}\n${body}`);
    const r = resolve({ channel: WEBHOOK, paths, now: NOW });
    expect(r.demotionReason ?? '').toMatch(/missing or unreadable/);
    expect(readdirSync(join(home, '.shieldcortex', 'approvals')).some((f) => f.includes('.corrupt-'))).toBe(true);
  });
});
