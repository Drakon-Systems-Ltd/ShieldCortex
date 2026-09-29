/**
 * #509 round 3 — regressions for the six findings of the GPT-6 review of
 * a850d3ee. Each was reproduced against that head before it was fixed.
 *
 *  1. `--action-guard-enforce-when-ready` is enforcement-loosening on an
 *     enforcing install: classified with `--action-guard-disable/advisory`
 *     in the core guard and every WS2 fallback list (the hook-level proof is
 *     in src/__tests__/pre-tool-hook-enforce-when-ready-509.test.ts).
 *  2. The readiness cache may only TIGHTEN: a forged fresh `shadow` on a
 *     promoted install is distrusted, reported as tampering, and — when the
 *     evidence says not ready — demoted with the full protocol.
 *  3. Promotion history lives in a durable, append-only transition record
 *     outside the rolling window; a lost or damaged record is UNKNOWN, which
 *     is treated as potentially demoted, never as never-ready.
 *  4. An OpenClaw-only channel (approval cards, no pushed notices) cannot be
 *     promoted: a later demotion could not reach the operator.
 *  5. Every delivered approval attempt has its own correlation id; an answer
 *     binds to one attempt and earlier timeouts stay in the denominator.
 *  6. Every complete audit line is parsed and validated before any filter;
 *     a malformed record invalidates the measurement.
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  DEMOTE_AFTER_FAILING_MS,
  NO_NOTICE_CHANNEL_MESSAGE,
  READINESS_CACHE_TTL_MS,
  REACH_ANSWER_WINDOW_MS,
  UNKNOWN_RECORD_REASON,
  computeReadiness,
  currentReadinessPin,
  describeHumanChannel,
  initReadinessTransitions,
  isDemoted,
  previewMode,
  readReadinessState,
  readTransitionRecord,
  readinessPaths,
  recordApprovalReach,
  resolveReadiness,
  transitionsPathFor,
  type ReadinessPaths,
  type ReadinessPin,
} from '../guard-readiness.js';
import { approveRequest, recordPending } from '../action-approvals.js';
import { evaluateToolCall } from '../tool-action-guard.js';

const DAY = 24 * 60 * 60 * 1000;
const NOW = Date.parse('2026-09-28T12:00:00.000Z');
const PIN = currentReadinessPin() as ReadinessPin;
const CHANNEL = { configured: true, kind: 'webhook', pushesNotices: true };
const PROXIES_ONLY = { requireEffectivenessEvidence: false } as const;
const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..');

let root: string;
let paths: ReadinessPaths;
let seq = 0;

function row(ts: number, fields: Record<string, unknown>): Record<string, unknown> {
  seq += 1;
  return { ts: new Date(ts).toISOString(), auditEventId: `r3e${seq}`, readinessPin: PIN, ...fields };
}
function auditFile(ts: number): string {
  return join(paths.auditDir, `realtime-${new Date(ts).toISOString().slice(0, 10)}.jsonl`);
}
function write(rows: Array<Record<string, unknown>>): void {
  mkdirSync(paths.auditDir, { recursive: true });
  for (const r of rows) appendFileSync(auditFile(Date.parse(String(r.ts))), `${JSON.stringify(r)}\n`);
}
function calls(total: number, stops: number, end = NOW): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  for (let i = 0; i < total; i += 1) {
    const ts = end - 8 * DAY + Math.floor((i * 8 * DAY) / total) + 1000;
    const stop = i < stops;
    out.push(row(ts, { type: 'intercept', origin: 'claude-code-hook', tool: 'Bash', severity: stop ? 'high' : 'low', action: stop ? 'require_approval' : 'allow', outcome: stop ? 'would_hold' : 'allowed' }));
  }
  return out;
}
function reach(answered: number, end = NOW): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  for (let i = 0; i < answered; i += 1) {
    const t = end - DAY + i * 1000;
    out.push(row(t, { type: 'approval_reach', reachId: `rq${i}`, attemptId: `at${i}-${end}`, phase: 'request' }));
    out.push(row(t + 60_000, { type: 'approval_reach', reachId: `rq${i}`, attemptId: `at${i}-${end}`, phase: 'answer', answer: 'approve' }));
  }
  return out;
}
function readyEvidence(end = NOW): void {
  write(calls(1000, 5, end));
  write(reach(25, end));
}
function forgedWouldBlocks(at: number): void {
  const forged: Array<Record<string, unknown>> = [];
  for (let i = 0; i < 300; i += 1) {
    forged.push(row(at + i, { type: 'intercept', origin: 'claude-code-hook', tool: 'Bash', severity: 'high', action: 'require_approval', outcome: 'would_block' }));
  }
  write(forged);
}
function forgeShadowCache(at: number): void {
  mkdirSync(dirname(paths.statePath), { recursive: true });
  writeFileSync(paths.statePath, JSON.stringify({ version: 1, mode: 'shadow', computedAt: new Date(at).toISOString(), pin: PIN }));
}
function auditRows(): Array<Record<string, unknown>> {
  if (!existsSync(paths.auditDir)) return [];
  return readdirSync(paths.auditDir)
    .flatMap((f) => readFileSync(join(paths.auditDir, f), 'utf8').split('\n').filter(Boolean))
    .map((l) => JSON.parse(l) as Record<string, unknown>);
}
const record = () => readTransitionRecord(transitionsPathFor(paths));
const resolve = (now: number, channel = CHANNEL) => resolveReadiness({ ...PROXIES_ONLY, channel, paths, now });

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'sc-readiness-r3-'));
  paths = {
    auditDir: join(root, 'audit'),
    statePath: join(root, 'approvals', 'guard-readiness.json'),
    readAuditDirs: [join(root, 'audit')],
  };
  initReadinessTransitions({ postureChanged: true, reason: 'test posture', paths, now: NOW - 90 * DAY });
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

// ── Finding 1 ───────────────────────────────────────────────────────────────

describe('#509 r3 finding 1 — the enforce-when-ready flag is enforcement-loosening', () => {
  it('the core guard classifies it with --action-guard-disable/advisory (and the npx form)', () => {
    for (const command of [
      'shieldcortex config --action-guard-enforce-when-ready',
      'npx shieldcortex config --action-guard-enforce-when-ready',
      'bash -c "shieldcortex config --action-guard-enforce-when-ready"',
    ]) {
      const v = evaluateToolCall('Bash', { command });
      expect([command, v.decision]).not.toEqual([command, 'allow']);
      expect(v.signals).toContain('disable-action-guard');
    }
    // The advisory flag, for reference: the same class.
    expect(evaluateToolCall('Bash', { command: 'shieldcortex config --action-guard-advisory' }).signals).toContain('disable-action-guard');
  });

  it('every WS2 fallback list (hook, OpenClaw interceptor, Hermes) matches it too', () => {
    const flag = 'shieldcortex config --action-guard-enforce-when-ready';
    const jsRule = (file: string): RegExp => {
      const text = readFileSync(join(REPO, file), 'utf8');
      const m = /\{ re: \/(--action-guard-\(\?:[^/]+)\/(\w*), signal: 'disable-action-guard' \}/.exec(text);
      expect([file, m !== null]).toEqual([file, true]);
      return new RegExp(m![1], m![2]);
    };
    expect(jsRule('scripts/pre-tool-hook.mjs').test(flag)).toBe(true);
    expect(jsRule('plugins/openclaw/interceptor.ts').test(flag)).toBe(true);
    const py = readFileSync(join(REPO, 'plugins/hermes/shieldcortex/sc_client.py'), 'utf8');
    const pm = /re\.compile\(r"(--action-guard-\(\?:[^"]+)"/.exec(py);
    expect(pm).not.toBeNull();
    expect(new RegExp(pm![1], 'i').test(flag)).toBe(true);
  });
});

// ── Finding 2 ───────────────────────────────────────────────────────────────

describe('#509 r3 finding 2 — a forged fresh cache can only tighten', () => {
  function promote(): void {
    readyEvidence();
    expect(resolve(NOW).transition).toBe('promote');
    expect(record().last?.event).toBe('promote');
  }

  it('promoted + forged fresh {mode:"shadow", computedAt:now, pin} + failing evidence ⇒ an ANNOUNCED demotion, never a silent shadow', () => {
    promote();
    const t = NOW + 60_000;
    forgedWouldBlocks(t - 30_000);
    forgeShadowCache(t);
    const r = resolve(t);
    expect(r.cached).toBe(false);
    expect(r.mode).toBe('shadow');
    expect(r.transition).toBe('demote');
    expect(r.demotionReason).toMatch(/would intervene/);
    expect(r.demotionReason).toMatch(/cache said shadow/);
    expect(r.tamper).toMatch(/cache said shadow while the durable transition record says enforcing/);
    // Audited: the transition, and the tamper signal.
    expect(auditRows().filter((x) => x.type === 'readiness_transition').map((x) => x.to)).toEqual(['enforcing', 'shadow']);
    expect(auditRows().some((x) => x.type === 'readiness_tamper')).toBe(true);
    // Durable: demote and tamper entries; doctor's isDemoted sees it.
    const rec = record();
    expect(rec.last?.event).toBe('demote');
    expect(rec.lastTamper?.reason).toMatch(/cache said shadow/);
    expect(isDemoted(readReadinessState(paths.statePath), null, rec)).toBe(true);
  });

  it('promoted + forged fresh shadow cache + evidence still ready ⇒ keeps ENFORCING, and reports the tamper', () => {
    promote();
    forgeShadowCache(NOW + 1000);
    const r = resolve(NOW + 1000);
    expect(r.mode).toBe('enforcing');
    expect(r.cached).toBe(false);
    expect(r.transition).toBeNull();
    expect(r.tamper).toBeTruthy();
    expect(record().lastTamper).not.toBeNull();
    // Doctor's read-only preview agrees with the hook.
    forgeShadowCache(NOW + 2000);
    const rep = computeReadiness({ ...PROXIES_ONLY, channel: CHANNEL, paths, now: NOW + 2000 });
    expect(previewMode({ state: readReadinessState(paths.statePath), report: rep, now: NOW + 2000, record: record() })).toBe('enforcing');
  });

  it('refreshing computedAt repeatedly extends nothing: every call recomputes and enforces', () => {
    promote();
    for (let i = 1; i <= 6; i += 1) {
      const t = NOW + i * (READINESS_CACHE_TTL_MS / 3);
      forgeShadowCache(t);
      const r = resolve(t);
      expect([i, r.mode, r.cached]).toEqual([i, 'enforcing', false]);
    }
    expect(auditRows().filter((x) => x.type === 'readiness_transition').map((x) => x.to)).toEqual(['enforcing']);
  });

  it('a fresh cache that AGREES with the record is still the cheap path', () => {
    promote();
    const r = resolve(NOW + 1000);
    expect(r.cached).toBe(true);
    expect(r.mode).toBe('enforcing');
  });
});

// ── Finding 3 ───────────────────────────────────────────────────────────────

describe('#509 r3 finding 3 — promotion history does not expire', () => {
  it('a 32-day-old promotion + lost state file + insufficient evidence ⇒ still enforcing, then an ANNOUNCED demotion', () => {
    const promotedAt = NOW - 32 * DAY;
    readyEvidence(promotedAt);
    expect(resolve(promotedAt).transition).toBe('promote');
    rmSync(paths.statePath);
    // 32 days on: the evidence (and the audit's promotion row) has aged out
    // of every rolling window; only the durable record remembers.
    expect(computeReadiness({ ...PROXIES_ONLY, channel: CHANNEL, paths, now: NOW }).lastTransition).toBeNull();
    const first = resolve(NOW);
    expect(first.mode).toBe('enforcing');
    expect(first.transition).toBeNull();
    const later = resolve(NOW + READINESS_CACHE_TTL_MS + DEMOTE_AFTER_FAILING_MS);
    expect(later.mode).toBe('shadow');
    expect(later.transition).toBe('demote');
    expect(record().last?.event).toBe('demote');
    expect(isDemoted(readReadinessState(paths.statePath), null, record())).toBe(true);
  });

  it('a MISSING transition record (and state) is unknown ⇒ an announced demotion, never "never ready"', () => {
    rmSync(transitionsPathFor(paths));
    const r = resolve(NOW);
    expect(r.mode).toBe('shadow');
    expect(r.transition).toBe('demote');
    expect(r.demotionReason).toContain(UNKNOWN_RECORD_REASON);
    expect(auditRows().find((x) => x.type === 'readiness_transition')?.from).toBe('unknown');
    expect(record().last?.event).toBe('demote');
    expect(isDemoted(null, null, record())).toBe(true);
  });

  it('while unknown, the read-only doctor view says demoted too', () => {
    rmSync(transitionsPathFor(paths));
    const rec = record();
    expect(rec.status).toBe('missing');
    expect(isDemoted(null, null, rec)).toBe(true);
    const rep = computeReadiness({ ...PROXIES_ONLY, channel: CHANNEL, paths, now: NOW });
    expect(previewMode({ state: null, report: rep, now: NOW, record: rec })).toBe('shadow');
    expect(existsSync(transitionsPathFor(paths))).toBe(false); // preview wrote nothing
  });

  it('an UNREADABLE (corrupt) record is unknown too: quarantined, then an announced demotion', () => {
    appendFileSync(transitionsPathFor(paths), 'NOT A RECORD\n');
    expect(record().status).toBe('unreadable');
    const r = resolve(NOW);
    expect(r.transition).toBe('demote');
    expect(r.demotionReason).toContain(UNKNOWN_RECORD_REASON);
    expect(readdirSync(dirname(paths.statePath)).some((f) => f.includes('.corrupt-'))).toBe(true);
    expect(record().status).toBe('ok');
  });

  it('unknown record while the evidence is ready ⇒ promotes (a tightening), no demotion', () => {
    rmSync(transitionsPathFor(paths));
    readyEvidence();
    const r = resolve(NOW);
    expect(r.mode).toBe('enforcing');
    expect(r.transition).toBe('promote');
  });

  it('re-running the posture command cannot clear a recorded demotion; a posture change starts a new record entry', () => {
    rmSync(transitionsPathFor(paths));
    resolve(NOW); // unknown ⇒ demote recorded
    expect(initReadinessTransitions({ postureChanged: false, reason: 'rerun', paths, now: NOW + 1 })).toBe(false);
    expect(record().last?.event).toBe('demote');
    expect(initReadinessTransitions({ postureChanged: true, reason: 'from off', paths, now: NOW + 2 })).toBe(true);
    expect(record().last?.event).toBe('init');
  });

  it('the record lives in the approval store and is gated by touch-approval-store', () => {
    const home = '/home/u';
    const p = transitionsPathFor(readinessPaths({ home }));
    expect(p).toBe('/home/u/.shieldcortex/approvals/guard-readiness-transitions.jsonl');
    for (const command of [
      'rm ~/.shieldcortex/approvals/guard-readiness-transitions.jsonl',
      'echo {} >> ~/.shieldcortex/approvals/guard-readiness-transitions.jsonl',
    ]) {
      const v = evaluateToolCall('Bash', { command });
      expect(v.decision).not.toBe('allow');
      expect(v.signals).toContain('touch-approval-store');
    }
    expect(evaluateToolCall('Write', { file_path: p, content: '' }).decision).not.toBe('allow');
  });
});

// ── Finding 4 ───────────────────────────────────────────────────────────────

describe('#509 r3 finding 4 — an OpenClaw-only channel cannot be promoted', () => {
  it('{enabled:true, openclaw:true} without a webhook: approvals yes, pushed notices no', () => {
    expect(describeHumanChannel({ enabled: true, openclaw: true })).toEqual({ configured: true, kind: 'openclaw-card', pushesNotices: false });
    expect(describeHumanChannel({ enabled: true, openclaw: true, webhookUrl: 'https://hooks.example/x' }))
      .toEqual({ configured: true, kind: 'openclaw-card', pushesNotices: true });
    expect(describeHumanChannel({ enabled: true, webhookUrl: 'https://hooks.example/x' }).pushesNotices).toBe(true);
  });

  it('perfect proxies on an OpenClaw-only install stay in SHADOW, and readiness says why', () => {
    readyEvidence();
    const openclawOnly = describeHumanChannel({ enabled: true, openclaw: true });
    const rep = computeReadiness({ ...PROXIES_ONLY, channel: openclawOnly, paths, now: NOW });
    expect(rep.reachability.pass).toBe(true);
    expect(rep.noticeChannel.pass).toBe(false);
    expect(rep.ready).toBe(false);
    expect(rep.missing).toContain(NO_NOTICE_CHANNEL_MESSAGE);
    const r = resolve(NOW, openclawOnly);
    expect(r.mode).toBe('shadow');
    expect(r.transition).toBeNull();
    // Add the webhook: the same evidence promotes.
    const both = describeHumanChannel({ enabled: true, openclaw: true, webhookUrl: 'https://hooks.example/x' });
    expect(resolve(NOW + READINESS_CACHE_TTL_MS, both).transition).toBe('promote');
  });
});

// ── Finding 5 ───────────────────────────────────────────────────────────────

describe('#509 r3 finding 5 — each approval attempt counts on its own', () => {
  it('20 commands × (10 expired + 1 answered) through the real store ⇒ ~9%, not ready', () => {
    const home = join(root, 'home');
    mkdirSync(join(home, '.shieldcortex'), { recursive: true });
    const homePaths = readinessPaths({ home });
    const gap = REACH_ANSWER_WINDOW_MS + 60_000;
    const start = NOW - 5 * DAY;
    for (let c = 0; c < 20; c += 1) {
      const input = { command: `deploy target-${c}` };
      for (let k = 0; k < 11; k += 1) {
        const t = start + (c * 11 + k) * gap;
        // What the hook does for one refused, delivered call.
        const pending = recordPending({ tool: 'Bash', input, summary: `deploy ${c}`, signals: ['x'] }, { home, now: t });
        expect(typeof pending.reachAttemptId).toBe('string');
        recordApprovalReach({ hash: pending.hash, attemptId: pending.reachAttemptId, phase: 'request', channel: 'webhook' }, { home, now: t });
        if (k === 10) expect(approveRequest(pending.hash, { home, now: t + 60_000, attemptId: pending.reachAttemptId }).ok).toBe(true);
      }
    }
    const rep = computeReadiness({ ...PROXIES_ONLY, channel: CHANNEL, paths: homePaths, now: NOW });
    expect(rep.reachability.resolved).toBe(220);
    expect(rep.reachability.reached).toBe(20);
    expect(rep.reachability.rate).toBeCloseTo(20 / 220, 5);
    expect(rep.reachability.pass).toBe(false);
    expect(rep.reachability.missing).toMatch(/9\.1%/);
  });

  it('an answer that names no attempt binds to nothing', () => {
    write(reach(25));
    write([
      row(NOW - DAY, { type: 'approval_reach', reachId: 'z', attemptId: 'z-1', phase: 'request' }),
      row(NOW - DAY + 1000, { type: 'approval_reach', reachId: 'z', phase: 'answer', answer: 'approve' }),
    ]);
    const rep = computeReadiness({ ...PROXIES_ONLY, channel: CHANNEL, paths, now: NOW });
    expect(rep.reachability.resolved).toBe(26);
    expect(rep.reachability.reached).toBe(25);
  });
});

// ── Finding 6 ───────────────────────────────────────────────────────────────

describe('#509 r3 finding 6 — corrupt evidence never qualifies', () => {
  it('a complete corrupt line with no evidence token ("BROKEN JSON") ⇒ not ready, with a named reason', () => {
    readyEvidence();
    expect(computeReadiness({ ...PROXIES_ONLY, channel: CHANNEL, paths, now: NOW }).ready).toBe(true);
    appendFileSync(auditFile(NOW - 2 * DAY), 'BROKEN JSON\n');
    const rep = computeReadiness({ ...PROXIES_ONLY, channel: CHANNEL, paths, now: NOW });
    expect(rep.integrity.unparseableLines).toBe(1);
    expect(rep.ready).toBe(false);
    expect(rep.missing.join('\n')).toMatch(/1 malformed audit record/);
  });

  it('a corrupted would-stop row no longer improves the rate: it invalidates the measurement', () => {
    readyEvidence();
    const f = readdirSync(paths.auditDir).map((n) => join(paths.auditDir, n)).find((p) => readFileSync(p, 'utf8').includes('"would_hold"'))!;
    const lines = readFileSync(f, 'utf8').split('\n');
    const i = lines.findIndex((l) => l.includes('"would_hold"'));
    expect(i).toBeGreaterThan(-1);
    lines[i] = lines[i].replace('{', '{BROKEN');
    writeFileSync(f, lines.join('\n'));
    expect(computeReadiness({ ...PROXIES_ONLY, channel: CHANNEL, paths, now: NOW }).ready).toBe(false);
  });

  it('valid JSON with the wrong shape for an evidence type is malformed too', () => {
    readyEvidence();
    appendFileSync(auditFile(NOW - DAY), `${JSON.stringify({ type: 'intercept', origin: 'claude-code-hook', ts: 'not-a-date', outcome: 'allowed', action: 'allow' })}\n`);
    appendFileSync(auditFile(NOW - DAY), '[1,2,3]\n');
    const rep = computeReadiness({ ...PROXIES_ONLY, channel: CHANNEL, paths, now: NOW });
    expect(rep.integrity.unparseableLines).toBe(2);
    expect(rep.ready).toBe(false);
  });

  it('other planes\' well-formed rows are fine', () => {
    readyEvidence();
    appendFileSync(auditFile(NOW - DAY), `${JSON.stringify({ type: 'memory_write', ts: new Date(NOW - DAY).toISOString() })}\n`);
    expect(computeReadiness({ ...PROXIES_ONLY, channel: CHANNEL, paths, now: NOW }).ready).toBe(true);
  });

  it('a final partial line with NO trailing newline is ignored — only when it is the last line', () => {
    readyEvidence();
    appendFileSync(auditFile(NOW - DAY), 'BROKEN JSON');
    const inFlight = computeReadiness({ ...PROXIES_ONLY, channel: CHANNEL, paths, now: NOW });
    expect(inFlight.integrity.unparseableLines).toBe(0);
    expect(inFlight.ready).toBe(true);
    // Once another row lands after it, it is a complete corrupt line.
    appendFileSync(auditFile(NOW - DAY), `\n${JSON.stringify({ type: 'memory_write', ts: new Date(NOW - DAY).toISOString() })}\n`);
    const complete = computeReadiness({ ...PROXIES_ONLY, channel: CHANNEL, paths, now: NOW });
    expect(complete.integrity.unparseableLines).toBe(1);
    expect(complete.ready).toBe(false);
  });
});
