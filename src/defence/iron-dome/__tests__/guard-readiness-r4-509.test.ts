/**
 * #509 round 4 — regressions for the GPT-6 r2 confirmation of 977ee3dd.
 * Each was reproduced against that head before it was fixed. (R4-1, the
 * self-protection floor, is proven through the built hook in
 * src/__tests__/pre-tool-hook-self-protection-floor-509.test.ts.)
 *
 *  R4-2  An answer names the attempt it answers. An answer to an expired
 *        attempt A grants nothing and counts for nobody, even while a newer
 *        attempt B for the same command is pending. A hash-only answer from a
 *        terminal still approves the CURRENT attempt but is not counted as
 *        reaching a human through the channel.
 *  R4-3  Readiness decides whether a webhook can push notices with the
 *        transport's own validator, never a looser check of its own.
 *  R4-4  The transition journal is bounded: a durable checkpoint plus a small
 *        active journal; compaction keeps the latest promotion/demotion, and
 *        repeated tamper reports are rate-bounded.
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  JOURNAL_MAX_BYTES,
  JOURNAL_MAX_ENTRIES,
  REACH_ANSWER_WINDOW_MS,
  compactTransitionRecord,
  computeReadiness,
  durableMode,
  isDemoted,
  readTransitionRecord,
  resolveReadiness,
  transitionsPathFor,
  currentReadinessPin,
  readinessPaths,
  recordApprovalReach,
  type ReadinessPaths,
  type ReadinessPin,
} from '../guard-readiness.js';
import { approveRequest, consumeApproval, denyRequest, recordPending } from '../action-approvals.js';

const DAY = 24 * 60 * 60 * 1000;
const NOW = Date.parse('2026-09-28T12:00:00.000Z');
const PIN = currentReadinessPin() as ReadinessPin;
const CHANNEL = { configured: true, kind: 'webhook', pushesNotices: true };
const PROXIES_ONLY = { requireEffectivenessEvidence: false } as const;

let root: string;
let home: string;
let paths: ReadinessPaths;

function reachRows(): Array<Record<string, unknown>> {
  if (!existsSync(paths.auditDir)) return [];
  return readdirSync(paths.auditDir)
    .flatMap((f) => readFileSync(join(paths.auditDir, f), 'utf8').split('\n').filter(Boolean))
    .map((l) => JSON.parse(l) as Record<string, unknown>)
    .filter((r) => r.type === 'approval_reach');
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'sc-readiness-r4-'));
  home = join(root, 'home');
  mkdirSync(join(home, '.shieldcortex'), { recursive: true });
  paths = readinessPaths({ home });
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

/** What the hook does for one refused call it delivers to the channel. */
function deliver(input: Record<string, unknown>, t: number): { hash: string; attemptId: string } {
  const pending = recordPending({ tool: 'Bash', input, summary: 'deploy', signals: ['x'] }, { home, now: t });
  recordApprovalReach({ hash: pending.hash, attemptId: pending.reachAttemptId, phase: 'request', channel: 'webhook' }, { home, now: t });
  return { hash: pending.hash, attemptId: String(pending.reachAttemptId) };
}

describe('#509 R4-2 — a late answer binds to the attempt it names, or to nothing', () => {
  const input = { command: 'deploy prod' };

  it('A delivered, B delivered 20 min later, A answered ⇒ nothing granted, B not reached, A not reached', () => {
    const t0 = NOW - 2 * 60 * 60 * 1000;
    const a = deliver(input, t0);
    const b = deliver(input, t0 + 20 * 60 * 1000);
    expect(b.attemptId).not.toBe(a.attemptId);
    expect(b.hash).toBe(a.hash);

    const late = approveRequest(a.hash, { home, now: t0 + 21 * 60 * 1000, attemptId: a.attemptId });
    expect(late).toEqual({ ok: false, reason: 'stale-attempt' });
    // No consumable approval exists for the command.
    expect(consumeApproval('Bash', input, { home, now: t0 + 22 * 60 * 1000 })).toBeNull();
    // Neither attempt got an answer row.
    expect(reachRows().filter((r) => r.phase === 'answer')).toHaveLength(0);
    const rep = computeReadiness({ ...PROXIES_ONLY, channel: CHANNEL, paths, now: NOW });
    expect(rep.reachability.resolved).toBe(2);
    expect(rep.reachability.reached).toBe(0);
  });

  it('the same for a late DENY: A\'s "no" does not remove B, and counts for nobody', () => {
    const t0 = NOW - 2 * 60 * 60 * 1000;
    const a = deliver(input, t0);
    const b = deliver(input, t0 + 20 * 60 * 1000);
    expect(denyRequest(a.hash, { home, now: t0 + 21 * 60 * 1000, attemptId: a.attemptId })).toEqual({ ok: false, reason: 'stale-attempt' });
    // B is still pending and answerable by its own id.
    expect(approveRequest(b.hash, { home, now: t0 + 22 * 60 * 1000, attemptId: b.attemptId }).ok).toBe(true);
    const answers = reachRows().filter((r) => r.phase === 'answer');
    expect(answers.map((r) => r.attemptId)).toEqual([b.attemptId]);
  });

  it('an answer that names the CURRENT attempt approves it and counts it as reached', () => {
    const t0 = NOW - DAY;
    const a = deliver(input, t0);
    expect(approveRequest(a.hash.slice(0, 12), { home, now: t0 + 60_000, attemptId: a.attemptId }).ok).toBe(true);
    const rep = computeReadiness({ ...PROXIES_ONLY, channel: CHANNEL, paths, now: NOW });
    expect(rep.reachability.reached).toBe(1);
    expect(rep.reachability.resolved).toBe(1);
  });

  it('back-compat: a hash-only answer from a terminal approves the CURRENT attempt but is not counted as a channel reach', () => {
    const t0 = NOW - DAY;
    const a = deliver(input, t0);
    const b = deliver(input, t0 + 20 * 60 * 1000);
    const out = approveRequest(a.hash.slice(0, 12), { home, now: t0 + 21 * 60 * 1000 });
    expect(out.ok).toBe(true);
    expect(out.ok && out.record.reachAttemptId).toBe(b.attemptId);
    expect(consumeApproval('Bash', input, { home, now: t0 + 22 * 60 * 1000 })).not.toBeNull();
    const rep = computeReadiness({ ...PROXIES_ONLY, channel: CHANNEL, paths, now: NOW });
    expect(rep.reachability.reached).toBe(0);
    expect(rep.reachability.resolved).toBe(2);
  });

  it('a malformed attempt id is refused, never matched by prefix', () => {
    const a = deliver(input, NOW - DAY);
    expect(approveRequest(a.hash, { home, now: NOW - DAY + 1000, attemptId: a.attemptId.slice(0, 8) })).toEqual({ ok: false, reason: 'stale-attempt' });
    expect(approveRequest(a.hash, { home, now: NOW - DAY + 1000, attemptId: '' })).toEqual({ ok: false, reason: 'stale-attempt' });
  });

  it('REACH_ANSWER_WINDOW_MS is shorter than the A→B gap used above (the scenario is a real expiry)', () => {
    expect(REACH_ANSWER_WINDOW_MS).toBeLessThan(20 * 60 * 1000);
  });
});

describe('#509 R4-2 — the attempt id rides the notification, the card waiter and the answer API', () => {
  const input = { command: 'deploy prod' };

  it('the notification names its attempt in the printed commands and the webhook payload', async () => {
    const notify = await import('../operator-notify.js');
    const sent: Array<Record<string, unknown>> = [];
    const channel = { name: 'capture', async send(n: Record<string, unknown>) { sent.push(n); return { delivered: true as const }; } };
    const hash = 'a'.repeat(64);
    await notify.requestOperatorApproval(
      { hash, attemptId: '0123456789abcdef01234567', tool: 'Bash', command: 'deploy prod', signals: ['x'], severity: 'dangerous', reason: 'r', event: 'approval_requested' } as never,
      { channel: channel as never, timeoutMs: 1000 },
    );
    expect(sent[0].attemptId).toBe('0123456789abcdef01234567');
    expect(String(sent[0].fallbackHint)).toContain(`approve ${hash.slice(0, 12)} --attempt 0123456789abcdef01234567`);
    expect(notify.formatOperatorNotification(sent[0] as never)).toContain('--attempt 0123456789abcdef01234567');
    // A caller that predates attempt ids keeps the #118 form, byte for byte.
    sent.length = 0;
    await notify.requestOperatorApproval(
      { hash, tool: 'Bash', command: 'deploy prod', signals: ['x'], severity: 'dangerous', reason: 'r', event: 'approval_requested' } as never,
      { channel: channel as never, timeoutMs: 1000 },
    );
    expect(sent[0].attemptId).toBeUndefined();
    expect(String(sent[0].fallbackHint)).toBe(`shieldcortex approve ${hash.slice(0, 12)}   |   shieldcortex deny ${hash.slice(0, 12)}`);
  });

  it('the review sequence through the OpenClaw waiter: A delivered, B 20 min later, A\'s card tapped ⇒ nothing granted, nothing counted', async () => {
    const { runWaiter, parseWaiterArgs } = await import('../openclaw-approval-waiter.js');
    const t0 = NOW - 2 * 60 * 60 * 1000;
    const a = deliver(input, t0);
    deliver(input, t0 + 20 * 60 * 1000);
    const receiptDir = mkdtempSync(join(root, 'rcpt-'));
    const argv = ['--params-b64', Buffer.from('{}').toString('base64'), '--hash', a.hash, '--attempt', a.attemptId, '--openclaw-bin', '/bin/false', '--receipt', join(receiptDir, 'r.json')];
    const args = parseWaiterArgs(argv);
    expect(args?.attemptId).toBe(a.attemptId);
    const exec = ((_f: string, _a: string[], _o: unknown, cb: (e: Error | null, out: string) => void) => {
      setImmediate(() => cb(null, JSON.stringify({ id: 'plugin:x', decision: 'allow-once' })));
    }) as never;
    const at = t0 + 21 * 60 * 1000;
    const out = await runWaiter(args!, {
      execFileImpl: exec,
      approveImpl: ((h: string, o: { attemptId?: string }) => approveRequest(h, { home, now: at, ...o })) as never,
      denyImpl: ((h: string, o: { attemptId?: string }) => denyRequest(h, { home, now: at, ...o })) as never,
      recordReachImpl: ((i: Parameters<typeof recordApprovalReach>[0]) => recordApprovalReach(i, { home, now: at })) as never,
    });
    expect(out).toEqual({ acted: 'approved', ok: false });
    expect(consumeApproval('Bash', input, { home, now: at + 1000 })).toBeNull();
    expect(reachRows().filter((r) => r.phase === 'answer')).toHaveLength(0);
    const rep = computeReadiness({ ...PROXIES_ONLY, channel: CHANNEL, paths, now: NOW });
    expect(rep.reachability.reached).toBe(0);
  });

  it('a waiter argv with a malformed --attempt is refused outright', async () => {
    const { parseWaiterArgs } = await import('../openclaw-approval-waiter.js');
    const base = ['--params-b64', 'e30=', '--hash', 'a'.repeat(64), '--openclaw-bin', '/bin/false', '--receipt', '/tmp/x'];
    expect(parseWaiterArgs([...base, '--attempt', 'zz'])).toBeNull();
    expect(parseWaiterArgs([...base, '--attempt'])).toBeNull();
    expect(parseWaiterArgs(base)?.attemptId).toBeUndefined();
  });

  it('`shieldcortex approve <hash> --attempt <A>` from a TTY refuses a stale attempt; hash-only approves the current one', async () => {
    const { runApprove } = await import('../../../cli/approve.js');
    const t0 = NOW - 2 * 60 * 60 * 1000;
    const a = deliver(input, t0);
    const b = deliver(input, t0 + 20 * 60 * 1000);
    const errs: string[] = [];
    const deps = { home, now: t0 + 21 * 60 * 1000, interactive: true, provenance: () => ({ ok: true }) as never, log: () => {}, error: (m: string) => errs.push(m) };
    expect(runApprove([a.hash.slice(0, 12), '--attempt', a.attemptId], deps as never)).toBe(1);
    expect(errs.join('\n')).toMatch(/not the current request/);
    expect(runApprove([a.hash.slice(0, 12), '--attempt', b.attemptId], deps as never)).toBe(0);
    const answers = reachRows().filter((r) => r.phase === 'answer');
    expect(answers.map((r) => r.attemptId)).toEqual([b.attemptId]);
  });
});

describe('#509 R4-3 — readiness and the transport agree on which webhooks exist', () => {
  it('a 2,074-character URL the transport drops does not count as a notice channel', async () => {
    const { describeHumanChannel } = await import('../guard-readiness.js');
    const { normaliseNotifyConfig } = await import('../notify-config.js');
    const url = `https://example.invalid/${'x'.repeat(2050)}`;
    expect(url.length).toBe(2074);
    const raw = { enabled: true, openclaw: true, webhookUrl: url };
    expect(normaliseNotifyConfig(raw).webhookUrl).toBeUndefined();
    expect(describeHumanChannel(raw)).toEqual({ configured: true, kind: 'openclaw-card', pushesNotices: false });
    // Webhook alone, too long: no channel at all.
    expect(describeHumanChannel({ enabled: true, webhookUrl: url }).configured).toBe(false);
  });

  it('a non-http scheme is no webhook, in both', async () => {
    const { describeHumanChannel } = await import('../guard-readiness.js');
    const { normaliseNotifyConfig } = await import('../notify-config.js');
    for (const webhookUrl of ['ftp://example.invalid/h', 'file:///tmp/h', 'javascript:alert(1)']) {
      expect(normaliseNotifyConfig({ enabled: true, webhookUrl }).webhookUrl).toBeUndefined();
      expect(describeHumanChannel({ enabled: true, openclaw: true, webhookUrl }).pushesNotices).toBe(false);
      expect(describeHumanChannel({ enabled: true, webhookUrl }).configured).toBe(false);
    }
  });

  it('whatever the transport keeps, readiness counts — over a table of edge inputs', async () => {
    const { describeHumanChannel } = await import('../guard-readiness.js');
    const { normaliseNotifyConfig } = await import('../notify-config.js');
    const urls = [
      'https://example.invalid/h', ' https://example.invalid/h ', 'http://x', `https://e.invalid/${'y'.repeat(2000)}`,
      `https://e.invalid/${'y'.repeat(2100)}`, '', '   ', 'not a url', 'HTTPS://E.INVALID/', 42, null,
    ];
    for (const webhookUrl of urls) {
      const raw = { enabled: true, openclaw: true, webhookUrl };
      expect({ webhookUrl, pushes: describeHumanChannel(raw).pushesNotices })
        .toEqual({ webhookUrl, pushes: normaliseNotifyConfig(raw).webhookUrl !== undefined });
    }
  });
});

describe('#509 R4-4 — the transition journal is bounded', () => {
  const CH = CHANNEL;
  const resolveAt = (now: number) => resolveReadiness({ ...PROXIES_ONLY, channel: CH, paths, now });

  function seedJournal(n: number, promoteAt: number): void {
    const lines: string[] = [];
    lines.push(JSON.stringify({ ts: new Date(promoteAt - DAY).toISOString(), event: 'init', to: 'shadow', reason: 'test posture' }));
    lines.push(JSON.stringify({ ts: new Date(promoteAt).toISOString(), event: 'promote', to: 'enforcing', pin: PIN }));
    for (let i = 0; i < n; i += 1) {
      lines.push(JSON.stringify({ ts: new Date(promoteAt + 1000 + i).toISOString(), event: 'tamper', pin: PIN, reason: `forged cache ${i}` }));
    }
    mkdirSync(join(home, '.shieldcortex', 'approvals'), { recursive: true });
    writeFileSync(transitionsPathFor(paths), `${lines.join('\n')}\n`);
  }

  it('a 100,000-entry journal is compacted on the next call and stays bounded; the promotion survives', () => {
    seedJournal(100_000, NOW - 40 * DAY);
    const before = statSync(transitionsPathFor(paths)).size;
    expect(before).toBeGreaterThan(5_000_000);
    const r = resolveAt(NOW);
    // Evidence is empty, so the 40-day-old promotion is honoured, then the grace runs.
    expect(r.mode).toBe('enforcing');
    const rec = readTransitionRecord(transitionsPathFor(paths));
    expect(rec.status).toBe('ok');
    expect(rec.entries.length).toBeLessThanOrEqual(JOURNAL_MAX_ENTRIES);
    expect(statSync(transitionsPathFor(paths)).size).toBeLessThan(JOURNAL_MAX_BYTES);
    expect(durableMode(rec)).toBe('enforcing');
    expect(rec.entries.some((e) => e.event === 'promote' && e.ts === new Date(NOW - 40 * DAY).toISOString())).toBe(true);
    const cp = rec.entries.find((e) => e.event === 'checkpoint') as Record<string, unknown> | undefined;
    expect(cp).toBeDefined();
    expect(Number(cp!.compacted)).toBeGreaterThan(99_000);
  });

  it('the latest demotion survives compaction too, and the record still reads as demoted', () => {
    seedJournal(5_000, NOW - 40 * DAY);
    appendFileSync(transitionsPathFor(paths), `${JSON.stringify({ ts: new Date(NOW - 10 * DAY).toISOString(), event: 'demote', to: 'shadow', pin: PIN, reason: 'r' })}\n`);
    for (let i = 0; i < 400; i += 1) {
      appendFileSync(transitionsPathFor(paths), `${JSON.stringify({ ts: new Date(NOW - 9 * DAY + i).toISOString(), event: 'tamper', pin: PIN, reason: `later ${i}` })}\n`);
    }
    compactTransitionRecord(transitionsPathFor(paths), NOW);
    const rec = readTransitionRecord(transitionsPathFor(paths));
    expect(rec.entries.length).toBeLessThanOrEqual(JOURNAL_MAX_ENTRIES);
    expect(durableMode(rec)).toBe('shadow');
    expect(rec.last?.event).toBe('demote');
    expect(rec.entries.some((e) => e.event === 'promote')).toBe(true);
    expect(isDemoted(null, null, rec)).toBe(true);
  });

  function writeReadyEvidence(): void {
    mkdirSync(paths.auditDir, { recursive: true });
    const out: string[] = [];
    let n = 0;
    const row = (ts: number, f: Record<string, unknown>) => JSON.stringify({ ts: new Date(ts).toISOString(), auditEventId: `r4e${(n += 1)}`, readinessPin: PIN, ...f });
    for (let i = 0; i < 1000; i += 1) {
      const stop = i < 5;
      out.push(row(NOW - 8 * DAY + Math.floor((i * 7.5 * DAY) / 1000), { type: 'intercept', origin: 'claude-code-hook', tool: 'Bash', severity: stop ? 'high' : 'low', action: stop ? 'require_approval' : 'allow', outcome: stop ? 'would_hold' : 'allowed' }));
    }
    for (let i = 0; i < 25; i += 1) {
      out.push(row(NOW - DAY + i * 1000, { type: 'approval_reach', reachId: `q${i}`, attemptId: `a${i}`, phase: 'request' }));
      out.push(row(NOW - DAY + i * 1000 + 60_000, { type: 'approval_reach', reachId: `q${i}`, attemptId: `a${i}`, phase: 'answer', answer: 'approve' }));
    }
    for (const line of out) {
      const day = String(JSON.parse(line).ts).slice(0, 10);
      appendFileSync(join(paths.auditDir, `realtime-${day}.jsonl`), `${line}\n`);
    }
  }

  it('repeated identical tamper reports are rate-bounded: a forged cache refreshed every call adds one journal entry per window', () => {
    writeReadyEvidence();
    mkdirSync(join(home, '.shieldcortex', 'approvals'), { recursive: true });
    writeFileSync(transitionsPathFor(paths), `${JSON.stringify({ ts: new Date(NOW - 50 * DAY).toISOString(), event: 'promote', to: 'enforcing', pin: PIN })}\n`);
    for (let i = 0; i < 50; i += 1) {
      const t = NOW + i * 60_000;
      writeFileSync(paths.statePath, JSON.stringify({ version: 1, mode: 'shadow', computedAt: new Date(t).toISOString(), pin: PIN }));
      const r = resolveAt(t);
      expect(r.mode).toBe('enforcing'); // the forged cache never loosens
      expect(r.tamper).toBeTruthy(); // and every call still reports it
    }
    const tampers = readTransitionRecord(transitionsPathFor(paths)).entries.filter((e) => e.event === 'tamper');
    expect(tampers.length).toBeGreaterThanOrEqual(1);
    expect(tampers.length).toBeLessThanOrEqual(2);
  });

  it('a fresh-cache call on a compacted journal parses a bounded record (no full-history read)', () => {
    seedJournal(100_000, NOW - 2 * DAY);
    resolveAt(NOW); // compacts
    const size = statSync(transitionsPathFor(paths)).size;
    const r = resolveAt(NOW + 1000);
    expect(r.cached).toBe(true);
    expect(statSync(transitionsPathFor(paths)).size).toBe(size);
    expect(size).toBeLessThan(JOURNAL_MAX_BYTES);
  });
});
