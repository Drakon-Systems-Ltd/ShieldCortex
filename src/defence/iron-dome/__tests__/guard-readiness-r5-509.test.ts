/**
 * #509 round 5 — regressions for the GPT-6 r3 confirmation of cf1cdfe3. Each
 * was reproduced against that head before it was fixed. Findings proven
 * through the built hook live in src/__tests__/pre-tool-hook-*-509.test.ts
 * and plugins/openclaw/__tests__/self-protection-exits-509.test.ts.
 *
 *  1  Promotions are journalled with their notice so a forged one is loud.
 *     (The classifier gaps are in tool-action-guard-floor-r5-509.test.ts.)
 *  2  Option A: reviewed effectiveness evidence is ALWAYS required — the
 *     removed setting, passed anyway, changes nothing.
 *  4  An explicit-attempt answer after the attempt's lifetime grants nothing;
 *     the attempt is validated before `already-approved`.
 *  5  The webhook deny command names its attempt.
 *  6  A credential-bearing webhook URL is no channel, for readiness and
 *     transport alike.
 *  7  Compaction re-reads the journal under the writer lock.
 *  8  Every retained journal entry is bounded.
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as readiness from '../guard-readiness.js';
import {
  AWAITING_EFFECTIVENESS_MESSAGE,
  JOURNAL_MAX_BYTES,
  REACH_ANSWER_WINDOW_MS,
  compactTransitionRecord,
  computeReadiness,
  currentReadinessPin,
  describeHumanChannel,
  durableMode,
  needsCompaction,
  readTransitionRecord,
  readinessPaths,
  recordApprovalReach,
  resolveReadiness,
  transitionsPathFor,
  type EffectivenessEvidence,
  type ReadinessPaths,
  type ReadinessPin,
} from '../guard-readiness.js';

// Round-5 exports, read through the namespace so this suite still LOADS
// against the pre-fix head (cf1cdfe3) and each regression fails on its own.
const r5 = readiness as unknown as {
  JOURNAL_REASON_MAX: typeof readiness.JOURNAL_REASON_MAX;
  lastPromotion: typeof readiness.lastPromotion;
  recordTransitionNotice: typeof readiness.recordTransitionNotice;
};
const lastPromotion: typeof readiness.lastPromotion = (rec) => r5.lastPromotion(rec);
const recordTransitionNotice: typeof readiness.recordTransitionNotice = (o) => r5.recordTransitionNotice(o);
const JOURNAL_REASON_MAX = () => r5.JOURNAL_REASON_MAX;
import { approveRequest, consumeApproval, denyRequest, listApprovals, recordPending } from '../action-approvals.js';
import { normaliseNotifyConfig, normaliseWebhookUrl } from '../notify-config.js';

const DAY = 24 * 60 * 60 * 1000;
const MIN = 60 * 1000;
const NOW = Date.parse('2026-09-29T12:00:00.000Z');
const PIN = currentReadinessPin() as ReadinessPin;
const WEBHOOK = describeHumanChannel({ enabled: true, webhookUrl: 'https://example.invalid/hook' });
/** Stands for a build that ships reviewed evidence for this pin (the shipped registry is empty). */
const REVIEWED: readonly EffectivenessEvidence[] = [
  { ...PIN, reviewedAt: new Date(NOW - DAY).toISOString(), reviewedBy: 'fixture reviewer', reference: 'test fixture', cases: 60 },
];

let root: string;
let home: string;
let paths: ReadinessPaths;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'sc-readiness-r5-'));
  home = join(root, 'home');
  mkdirSync(join(home, '.shieldcortex', 'approvals'), { recursive: true });
  paths = readinessPaths({ home });
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

function auditRows(): Array<Record<string, unknown>> {
  if (!existsSync(paths.auditDir)) return [];
  return readdirSync(paths.auditDir)
    .flatMap((f) => readFileSync(join(paths.auditDir, f), 'utf8').split('\n').filter(Boolean))
    .map((l) => JSON.parse(l) as Record<string, unknown>);
}
const reachAnswers = () => auditRows().filter((r) => r.type === 'approval_reach' && r.phase === 'answer');

function writeRows(rows: Array<Record<string, unknown>>): void {
  mkdirSync(paths.auditDir, { recursive: true });
  let n = 0;
  for (const r of rows) {
    const full = { auditEventId: `r5-${(n += 1)}`, readinessPin: PIN, ...r };
    appendFileSync(join(paths.auditDir, `realtime-${String(full.ts).slice(0, 10)}.jsonl`), `${JSON.stringify(full)}\n`);
  }
}

/** GPT-6's fixture: 500 qualifying calls spanning eight days, 20 answered approvals. */
function seedGpt6Fixture(): void {
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

// ─────────────────────────────────────────────────────────────────────────────

describe('#509 r5 finding 2 — option A: reviewed effectiveness evidence is always required', () => {
  it('GPT-6 fixture (500 calls / 8 days / 20 answered, valid webhook, EMPTY registry, legacy option false) does NOT promote', () => {
    seedGpt6Fixture();
    writeJournal([{ ts: new Date(NOW - 30 * DAY).toISOString(), event: 'init', to: 'shadow', reason: 'posture' }]);
    const legacy = { requireEffectivenessEvidence: false } as unknown as Record<string, never>;
    const out = resolveReadiness({ channel: WEBHOOK, paths, now: NOW, ...legacy });
    expect(out.mode).toBe('shadow');
    expect(out.transition).toBeNull();
    expect(out.report?.proxiesMet).toBe(true);
    expect(out.report?.ready).toBe(false);
    expect(out.report?.missing).toEqual([AWAITING_EFFECTIVENESS_MESSAGE]);
    expect(durableMode(readTransitionRecord(transitionsPathFor(paths)))).toBe('shadow');
  });

  it('the same fixture with reviewed evidence in the build DOES promote — the fixture is otherwise ready', () => {
    seedGpt6Fixture();
    writeJournal([{ ts: new Date(NOW - 30 * DAY).toISOString(), event: 'init', to: 'shadow', reason: 'posture' }]);
    const out = resolveReadiness({ channel: WEBHOOK, paths, now: NOW, effectivenessRegistry: REVIEWED });
    expect(out).toMatchObject({ mode: 'enforcing', transition: 'promote' });
    expect(out.transitionAt).toBe(new Date(NOW).toISOString());
  });

  it('the option is gone: no normaliser, constant or config key is exported', () => {
    const mod = readiness as unknown as Record<string, unknown>;
    expect(mod.effectivenessEvidenceRequired).toBeUndefined();
    expect(mod.EFFECTIVENESS_EVIDENCE_REQUIRED).toBeUndefined();
    expect(mod.EFFECTIVENESS_EVIDENCE_CONFIG_KEY).toBeUndefined();
    const rep = computeReadiness({ channel: WEBHOOK, paths, now: NOW, ...({ requireEffectivenessEvidence: false } as object) });
    expect(rep.effectiveness.pass).toBe(false);
    expect('required' in rep.effectiveness).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('#509 r5 finding 4 — attempt binding: expiry, and validation before already-approved', () => {
  const input = { command: 'deploy prod' };

  function deliver(t: number): { hash: string; attemptId: string } {
    const p = recordPending({ tool: 'Bash', input, summary: 'deploy', signals: ['x'] }, { home, now: t });
    recordApprovalReach({ hash: p.hash, attemptId: p.reachAttemptId, phase: 'request', channel: 'webhook' }, { home, now: t });
    return { hash: p.hash, attemptId: String(p.reachAttemptId) };
  }

  it('4a: A delivered, 20 minutes pass with NO replacement, A answered with its own id ⇒ stale-attempt, no consumable approval', () => {
    const t0 = NOW - 60 * MIN;
    const a = deliver(t0);
    expect(approveRequest(a.hash, { home, now: t0 + 20 * MIN, attemptId: a.attemptId })).toEqual({ ok: false, reason: 'stale-attempt' });
    expect(consumeApproval('Bash', input, { home, now: t0 + 21 * MIN })).toBeNull();
    expect(reachAnswers()).toHaveLength(0);
  });

  it('4a: the same for a late deny — nothing is removed, and the request stays pending', () => {
    const t0 = NOW - 60 * MIN;
    const a = deliver(t0);
    expect(denyRequest(a.hash, { home, now: t0 + 20 * MIN, attemptId: a.attemptId })).toEqual({ ok: false, reason: 'stale-attempt' });
    expect(listApprovals({ home, now: t0 + 20 * MIN }).map((r) => r.hash)).toEqual([a.hash]);
  });

  it('4a: inside the attempt lifetime the explicit answer still binds', () => {
    const t0 = NOW - 60 * MIN;
    const a = deliver(t0);
    expect(approveRequest(a.hash, { home, now: t0 + REACH_ANSWER_WINDOW_MS - 1000, attemptId: a.attemptId }).ok).toBe(true);
    expect(reachAnswers().map((r) => r.attemptId)).toEqual([a.attemptId]);
  });

  it('4b: A delivered, B replaces it, B approved, then A\'s card answer ⇒ stale-attempt (not already-approved), and A records no reach', async () => {
    const a = deliver(NOW - 5 * MIN);
    const b = deliver(NOW - 2 * MIN);
    expect(approveRequest(b.hash, { home, now: NOW - MIN, attemptId: b.attemptId }).ok).toBe(true);
    expect(approveRequest(a.hash, { home, now: NOW - 30_000, attemptId: a.attemptId })).toEqual({ ok: false, reason: 'stale-attempt' });

    const before = computeReadiness({ channel: WEBHOOK, paths, now: NOW }).reachability;
    expect([before.reached, before.pending]).toEqual([1, 1]);

    // A's card is tapped: the OpenClaw waiter processes it.
    const { runWaiter, parseWaiterArgs } = await import('../openclaw-approval-waiter.js');
    const argv = ['--params-b64', Buffer.from('{}').toString('base64'), '--hash', a.hash, '--attempt', a.attemptId, '--openclaw-bin', '/bin/false', '--receipt', join(root, 'r.json')];
    const exec = ((_f: string, _a: string[], _o: unknown, cb: (e: Error | null, out: string) => void) => {
      setImmediate(() => cb(null, JSON.stringify({ decision: 'allow-once' })));
    }) as never;
    await runWaiter(parseWaiterArgs(argv)!, {
      execFileImpl: exec,
      approveImpl: ((h: string, o: { attemptId?: string }) => approveRequest(h, { home, now: NOW - 10_000, ...o })) as never,
      denyImpl: ((h: string, o: { attemptId?: string }) => denyRequest(h, { home, now: NOW - 10_000, ...o })) as never,
      recordReachImpl: ((i: Parameters<typeof recordApprovalReach>[0]) => recordApprovalReach(i, { home, now: NOW - 10_000 })) as never,
    });
    const after = computeReadiness({ channel: WEBHOOK, paths, now: NOW }).reachability;
    expect([after.reached, after.pending]).toEqual([1, 1]);
    expect(reachAnswers().map((r) => r.attemptId)).toEqual([b.attemptId]);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('#509 r5 finding 5 — the webhook deny command is attempt-bound', () => {
  it('A\'s captured denyCommand, replayed after B was delivered, removes nothing', async () => {
    const { createWebhookNotifyChannel } = await import('../webhook-notify-channel.js');
    const bodies: Array<Record<string, unknown>> = [];
    const fetchImpl = (async (_u: unknown, init: { body: string }) => {
      bodies.push(JSON.parse(init.body));
      return { ok: true, status: 200 } as Response;
    }) as unknown as typeof fetch;
    const channel = createWebhookNotifyChannel({ url: 'https://example.invalid/hook', fetchImpl });
    const input = { command: 'deploy prod' };
    const t0 = NOW - 30 * MIN;
    const a = recordPending({ tool: 'Bash', input, summary: 'deploy', signals: ['x'] }, { home, now: t0 });
    await channel.send({
      hash: a.hash, shortHash: a.hash.slice(0, 12), attemptId: a.reachAttemptId, tool: 'Bash', command: 'deploy prod',
      signals: ['x'], severity: 'dangerous', reason: 'r', event: 'approval_requested',
    } as never, { timeoutMs: 1000 });
    const denyCommand = String(bodies[0].denyCommand);
    expect(denyCommand).toBe(`shieldcortex deny ${a.hash.slice(0, 12)} --attempt ${a.reachAttemptId}`);
    expect(String(bodies[0].approveCommand)).toContain(`--attempt ${a.reachAttemptId}`);

    const b = recordPending({ tool: 'Bash', input, summary: 'deploy', signals: ['x'] }, { home, now: t0 + 20 * MIN });
    expect(b.reachAttemptId).not.toBe(a.reachAttemptId);
    const { runDeny } = await import('../../../cli/deny.js');
    const errs: string[] = [];
    const code = runDeny(denyCommand.split(' ').slice(2), {
      home, now: t0 + 21 * MIN, interactive: true, provenance: () => ({ ok: true }) as never, log: () => {}, error: (m) => errs.push(m),
    });
    expect(code).toBe(1);
    expect(errs.join('\n')).toMatch(/not the current request/);
    expect(listApprovals({ home, now: t0 + 21 * MIN }).map((r) => r.reachAttemptId)).toEqual([b.reachAttemptId]);
    expect(reachAnswers()).toHaveLength(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('#509 r5 finding 6 — a credential-bearing webhook URL is no notice channel', () => {
  it('https://user:pass@example.invalid/hook: the shared validator refuses it, so readiness reports no notice channel', () => {
    for (const url of ['https://user:pass@example.invalid/hook', 'https://user@example.invalid/hook', 'http://:pw@example.invalid/h']) {
      expect(normaliseWebhookUrl(url)).toBeUndefined();
      expect(normaliseNotifyConfig({ enabled: true, webhookUrl: url }).webhookUrl).toBeUndefined();
      expect(describeHumanChannel({ enabled: true, webhookUrl: url })).toEqual({ configured: false, kind: null, pushesNotices: false });
      expect(describeHumanChannel({ enabled: true, openclaw: true, webhookUrl: url }).pushesNotices).toBe(false);
    }
    const rep = computeReadiness({ channel: describeHumanChannel({ enabled: true, webhookUrl: 'https://user:pass@example.invalid/hook' }), paths, now: NOW });
    expect(rep.noticeChannel.pass).toBe(false);
    expect(normaliseWebhookUrl('https://example.invalid/hook')).toBe('https://example.invalid/hook');
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('#509 r5 finding 7 — compaction re-reads the journal under the lock', () => {
  it('GPT-6 A/B interleaving: A snapshots an oversized journal, B promotes, A compacts ⇒ the promotion survives', () => {
    const lines: Array<Record<string, unknown>> = [{ ts: new Date(NOW - 30 * DAY).toISOString(), event: 'init', to: 'shadow', reason: 'posture' }];
    for (let i = 0; i < 400; i += 1) lines.push({ ts: new Date(NOW - 10 * DAY + i).toISOString(), event: 'tamper', pin: PIN, reason: `r${i}` });
    writeJournal(lines);
    const path = transitionsPathFor(paths);
    // A: the pre-lock read of an oversized journal that needs compacting.
    const snapshot = readTransitionRecord(path);
    expect(needsCompaction(snapshot)).toBe(true);
    // B: promotes (journal entry + enforcing cache) and releases the lock.
    appendFileSync(path, `${JSON.stringify({ ts: new Date(NOW - 1000).toISOString(), event: 'promote', to: 'enforcing', pin: PIN })}\n`);
    writeFileSync(paths.statePath, JSON.stringify({ version: 1, mode: 'enforcing', computedAt: new Date(NOW - 1000).toISOString(), pin: PIN }));
    // A: acquires the lock and compacts, still holding its snapshot.
    (compactTransitionRecord as unknown as (...a: unknown[]) => boolean)(path, NOW, snapshot);
    const rec = readTransitionRecord(path);
    expect(rec.entries.filter((e) => e.event === 'promote')).toHaveLength(1);
    expect(durableMode(rec)).toBe('enforcing');
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('#509 r5 finding 8 — every retained journal entry is bounded', () => {
  it('a tamper entry with a 2,000,000-character reason: after compaction the journal is under its byte bound and needs no compaction', () => {
    const path = transitionsPathFor(paths);
    writeJournal([
      { ts: new Date(NOW - 30 * DAY).toISOString(), event: 'init', to: 'shadow', reason: 'posture' },
      { ts: new Date(NOW - 20 * DAY).toISOString(), event: 'promote', to: 'enforcing', pin: PIN },
      { ts: new Date(NOW - DAY).toISOString(), event: 'tamper', pin: PIN, reason: 'x'.repeat(2_000_000), junk: 'y'.repeat(100_000) },
    ]);
    expect(statSync(path).size).toBeGreaterThan(2_000_000);
    expect(compactTransitionRecord(path, NOW)).toBe(true);
    expect(statSync(path).size).toBeLessThan(JOURNAL_MAX_BYTES);
    const rec = readTransitionRecord(path);
    expect(needsCompaction(rec)).toBe(false);
    expect(durableMode(rec)).toBe('enforcing');
    const tamper = rec.entries.find((e) => e.event === 'tamper')!;
    expect(tamper.reason!.length).toBe(JOURNAL_REASON_MAX());
    expect('junk' in tamper).toBe(false);
  });

  it('the same record read before compaction is already clipped in memory, and a fresh-cache call compacts it once', () => {
    const path = transitionsPathFor(paths);
    writeJournal([
      { ts: new Date(NOW - 30 * DAY).toISOString(), event: 'init', to: 'shadow', reason: 'x'.repeat(2_000_000) },
    ]);
    expect(readTransitionRecord(path).entries[0].reason!.length).toBe(JOURNAL_REASON_MAX());
    writeFileSync(paths.statePath, JSON.stringify({ version: 1, mode: 'shadow', computedAt: new Date(NOW - 1000).toISOString(), pin: PIN }));
    expect(resolveReadiness({ channel: WEBHOOK, paths, now: NOW }).cached).toBe(true);
    const size = statSync(path).size;
    expect(size).toBeLessThan(JOURNAL_MAX_BYTES);
    resolveReadiness({ channel: WEBHOOK, paths, now: NOW + 1000 });
    expect(statSync(path).size).toBe(size);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('#509 r5 finding 1 — promotions are journalled with their notice', () => {
  const promoteAt = new Date(NOW - DAY).toISOString();
  const base = [
    { ts: new Date(NOW - 30 * DAY).toISOString(), event: 'init', to: 'shadow', reason: 'posture' },
    { ts: promoteAt, event: 'promote', to: 'enforcing', pin: PIN },
  ];

  it('delivered / failed / none', () => {
    writeJournal(base);
    const path = transitionsPathFor(paths);
    expect(lastPromotion(readTransitionRecord(path))).toEqual({ promotedAt: promoteAt, notice: 'none' });
    recordTransitionNotice({ of: 'promote', transitionAt: promoteAt, delivered: false, reason: 'receiver down', paths, now: NOW - DAY + 1000 });
    expect(lastPromotion(readTransitionRecord(path))).toEqual({ promotedAt: promoteAt, notice: 'failed', reason: 'receiver down' });
    recordTransitionNotice({ of: 'promote', transitionAt: promoteAt, delivered: true, channel: 'webhook', paths, now: NOW - DAY + 2000 });
    expect(lastPromotion(readTransitionRecord(path))).toEqual({ promotedAt: promoteAt, notice: 'delivered', channel: 'webhook' });
    // A notice entry never changes the mode the record reports.
    expect(durableMode(readTransitionRecord(path))).toBe('enforcing');
  });

  it('a notice for an EARLIER promotion does not vouch for the newest one', () => {
    const later = new Date(NOW - 60_000).toISOString();
    writeJournal([
      ...base,
      { ts: new Date(NOW - DAY + 1000).toISOString(), event: 'notice', of: 'promote', transitionTs: promoteAt, delivered: true, channel: 'webhook' },
      { ts: new Date(NOW - 2 * 60_000).toISOString(), event: 'demote', to: 'shadow', pin: PIN, reason: 'r' },
      { ts: later, event: 'promote', to: 'enforcing', pin: PIN },
    ]);
    expect(lastPromotion(readTransitionRecord(transitionsPathFor(paths)))).toEqual({ promotedAt: later, notice: 'none' });
  });

  it('compaction keeps the newest promotion and its notice', () => {
    const entries: Array<Record<string, unknown>> = [
      ...base,
      { ts: new Date(NOW - DAY + 1000).toISOString(), event: 'notice', of: 'promote', transitionTs: promoteAt, delivered: false, reason: 'down' },
    ];
    for (let i = 0; i < 400; i += 1) entries.push({ ts: new Date(NOW - DAY + 5000 + i).toISOString(), event: 'tamper', pin: PIN, reason: `t${i}` });
    writeJournal(entries);
    expect(compactTransitionRecord(transitionsPathFor(paths), NOW)).toBe(true);
    expect(lastPromotion(readTransitionRecord(transitionsPathFor(paths)))).toEqual({ promotedAt: promoteAt, notice: 'failed', reason: 'down' });
  });

  it('doctor reports the last promotion time from the journal, and warns when it was not announced', async () => {
    const { checkActionGuardReadiness } = await import('../../../cli/doctor.js');
    writeJournal(base);
    const record = readTransitionRecord(transitionsPathFor(paths));
    const report = computeReadiness({ channel: WEBHOOK, paths, now: NOW });
    const summary = {
      posture: 'enforce-when-ready', lockOverrides: false, mode: 'enforcing', channel: WEBHOOK, report, state: null,
      demoted: false, record, recordUnknown: false, recentTamper: null, lastPromotion: lastPromotion(record),
    };
    const rows = await checkActionGuardReadiness({ summary: () => summary as never });
    const row = rows.find((r) => r.label === 'Action guard last promotion');
    expect(row).toBeDefined();
    expect(row!.status).toBe('warn');
    expect(row!.message).toContain(promoteAt);
    expect(row!.message).toMatch(/NO notice attempt recorded/);
  });
});
