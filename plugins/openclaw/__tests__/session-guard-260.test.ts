import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { createHmac } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { evaluateToolCall } from '../../../src/defence/iron-dome/tool-action-guard.js';
import {
  appendSessionGuardIndex,
  GUARD_DEGRADED_OUTCOMES,
  recordActionGuardDegraded,
  sessionKeyFor,
} from '../../../src/defence/iron-dome/session-guard.js';
import plugin, {
  __resetConfigStateForTest,
  __setDefenceModuleForTest,
  __setRuntimeForTest,
} from '../index.js';
import { createInterceptor, DEFAULT_CONFIG, type InterceptAuditEntry } from '../interceptor.js';

/**
 * #260 / #242 — the OpenClaw interceptor must write the same session-guard
 * index the Claude Code hook writes, and session_end / agent_end must emit
 * action_guard_degraded. A populated sink nobody summarises is #253.
 */

const SALT = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const okPipeline = () => ({
  allowed: true,
  firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [] as string[], anomalyScore: 0, blockedPatterns: [] as string[] },
  trust: { score: 0.5 },
  sensitivity: { level: 'INTERNAL' },
  fragmentation: null,
  auditId: 1,
});

function expectedKey(sessionId: string): string {
  return `sc-${createHmac('sha256', SALT).update(`action-guard-session:${sessionId}`).digest('hex').slice(0, 16)}`;
}

function makeApi() {
  const hooks: Record<string, (...args: any[]) => any> = {};
  const api = {
    id: 'shieldcortex-realtime',
    name: 'ShieldCortex Real-time Scanner',
    logger: { info: () => {}, warn: () => {} },
    on: (name: string, handler: (...args: any[]) => any) => { hooks[name] = handler; },
    registerCommand: () => {},
    runtime: { config: { current: () => ({ plugins: { entries: { 'shieldcortex-realtime': { enabled: true, config: { interceptor: { actionGuard: { enabled: true } } } } } } }) } },
  };
  return { api, hooks };
}

describe('#260 interceptor stamps origin + sessionKey and indexes a deny', () => {
  const originalAuditDir = process.env.SHIELDCORTEX_AUDIT_DIR;
  const originalSalt = process.env.SHIELDCORTEX_SESSION_SALT;
  let auditDir = '';

  beforeEach(() => {
    auditDir = mkdtempSync(join(tmpdir(), 'sc-260-int-'));
    process.env.SHIELDCORTEX_AUDIT_DIR = auditDir;
    process.env.SHIELDCORTEX_SESSION_SALT = SALT;
  });

  afterEach(() => {
    if (originalAuditDir === undefined) delete process.env.SHIELDCORTEX_AUDIT_DIR;
    else process.env.SHIELDCORTEX_AUDIT_DIR = originalAuditDir;
    if (originalSalt === undefined) delete process.env.SHIELDCORTEX_SESSION_SALT;
    else process.env.SHIELDCORTEX_SESSION_SALT = originalSalt;
    try { rmSync(auditDir, { recursive: true, force: true }); } catch { /* best effort */ }
  });

  it('an unattended dangerous deny carries origin=openclaw-interceptor and a sc- sessionKey', async () => {
    const captured: InterceptAuditEntry[] = [];
    const indexed: InterceptAuditEntry[] = [];
    const sessionId = 'agent:main:cron:backup';
    const { handleToolCall } = createInterceptor({ ...DEFAULT_CONFIG, actionGuard: { enabled: true, enforce: true, autoApprove: [] } } as never, okPipeline as never, {
      evaluateToolCall: evaluateToolCall as never,
      onAuditEntry: (e) => captured.push(e),
      sessionGuard: {
        keyFor: (id) => sessionKeyFor(id, { salt: SALT }),
        index: (entry) => { indexed.push(entry); },
      },
    });

    await expect(handleToolCall({
      toolName: 'Bash',
      arguments: { command: 'sudo systemctl stop ssh' },
      sessionId,
    })).rejects.toThrow(/blocked/);

    const row = captured.find((e) => e.outcome === 'failure_denied' || e.outcome === 'auto_denied' || e.outcome === 'denied');
    expect(row).toBeDefined();
    expect(row!.origin).toBe('openclaw-interceptor');
    expect(row!.sessionKey).toBe(expectedKey(sessionId));
    expect(indexed.some((e) => e.sessionKey === expectedKey(sessionId) && e.origin === 'openclaw-interceptor')).toBe(true);
  });

  it('a row without a session id still stamps origin, and is not indexed under a forged key', async () => {
    const indexed: InterceptAuditEntry[] = [];
    const captured: InterceptAuditEntry[] = [];
    const { handleToolCall } = createInterceptor({ ...DEFAULT_CONFIG, actionGuard: { enabled: true, enforce: true, autoApprove: [] } } as never, okPipeline as never, {
      evaluateToolCall: evaluateToolCall as never,
      onAuditEntry: (e) => captured.push(e),
      sessionGuard: {
        keyFor: (id) => sessionKeyFor(id, { salt: SALT }),
        index: (entry) => { indexed.push(entry); },
      },
    });

    await expect(handleToolCall({
      toolName: 'Bash',
      arguments: { command: 'sudo systemctl stop ssh' },
    })).rejects.toThrow(/blocked/);

    expect(captured[0]?.origin).toBe('openclaw-interceptor');
    expect(captured[0]?.sessionKey).toBeUndefined();
    expect(indexed.every((e) => e.sessionKey === undefined)).toBe(true);
  });
});

describe('#260 plugin session_end / agent_end summarise the OpenClaw index', () => {
  const originalAuditDir = process.env.SHIELDCORTEX_AUDIT_DIR;
  const originalSalt = process.env.SHIELDCORTEX_SESSION_SALT;
  let auditDir = '';

  beforeEach(() => {
    auditDir = mkdtempSync(join(tmpdir(), 'sc-260-plug-'));
    process.env.SHIELDCORTEX_AUDIT_DIR = auditDir;
    process.env.SHIELDCORTEX_SESSION_SALT = SALT;
    __resetConfigStateForTest();
    __setRuntimeForTest({
      callCortex: async () => null,
      isOpenClawAutoMemoryEnabled: () => false,
      loadShieldConfig: async () => ({}),
    } as never);
    __setDefenceModuleForTest({
      runDefencePipeline: okPipeline,
      evaluateToolCall,
      sessionKeyFor: (id) => sessionKeyFor(id, { salt: SALT }),
      appendSessionGuardIndex: ({ entry }) => appendSessionGuardIndex({ entry }),
      recordActionGuardDegraded: (id, opts) => recordActionGuardDegraded(id, { salt: SALT, origin: opts?.origin }),
    } as never);
  });

  afterEach(() => {
    __setDefenceModuleForTest(undefined);
    __setRuntimeForTest(null);
    __resetConfigStateForTest();
    if (originalAuditDir === undefined) delete process.env.SHIELDCORTEX_AUDIT_DIR;
    else process.env.SHIELDCORTEX_AUDIT_DIR = originalAuditDir;
    if (originalSalt === undefined) delete process.env.SHIELDCORTEX_SESSION_SALT;
    else process.env.SHIELDCORTEX_SESSION_SALT = originalSalt;
    try { rmSync(auditDir, { recursive: true, force: true }); } catch { /* best effort */ }
  });

  it('registers session_end and agent_end even when they cannot block', () => {
    const { api, hooks } = makeApi();
    plugin.register(api);
    expect(typeof hooks.session_end).toBe('function');
    expect(typeof hooks.agent_end).toBe('function');
  });

  it('indexes an unattended deny then emits action_guard_degraded at session_end', async () => {
    const { api, hooks } = makeApi();
    plugin.register(api);

    const sessionId = 'agent:main:cron:backup';
    const result = await hooks.before_tool_call(
      { toolName: 'Bash', params: { command: 'sudo systemctl stop ssh' } },
      { sessionId },
    );
    expect(result?.block).toBe(true);

    const key = expectedKey(sessionId);
    const indexFile = join(auditDir, 'session-guard', `${key}.jsonl`);
    expect(existsSync(indexFile)).toBe(true);

    hooks.session_end({ sessionId }, { sessionId });

    const files = readdirSync(auditDir).filter((f) => /^realtime-.*\.jsonl$/.test(f));
    expect(files.length).toBeGreaterThan(0);
    const rows = files.flatMap((f) =>
      readFileSync(join(auditDir, f), 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)),
    );
    const summary = rows.find((r) => r.type === 'session_summary');
    expect(summary).toMatchObject({
      origin: 'openclaw-session-end',
      sessionKey: key,
      outcome: 'action_guard_degraded',
    });
    expect(summary.guardOutcomeCount).toBeGreaterThan(0);
  });

  it('agent_end is idempotent with session_end — one summary, not two', async () => {
    const { api, hooks } = makeApi();
    plugin.register(api);

    const sessionId = 'agent:main:cron:once-only';
    await hooks.before_tool_call(
      { toolName: 'Bash', params: { command: 'sudo systemctl stop ssh' } },
      { sessionId },
    );
    hooks.session_end({ sessionId }, { sessionId });
    hooks.agent_end({ sessionId }, { sessionId });

    const files = readdirSync(auditDir).filter((f) => /^realtime-.*\.jsonl$/.test(f));
    const rows = files.flatMap((f) =>
      readFileSync(join(auditDir, f), 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)),
    );
    const summaries = rows.filter((r) => r.type === 'session_summary' && r.outcome === 'action_guard_degraded');
    expect(summaries).toHaveLength(1);
  });

  it('#654 H4: a deny after agent_end is still summarised at session_end (HEAD returned existing — RC5)', async () => {
    const { api, hooks } = makeApi();
    plugin.register(api);

    const sessionId = 'agent:main:cron:h4';
    const key = expectedKey(sessionId);
    const indexFile = join(auditDir, 'session-guard', `${key}.jsonl`);
    const indexed = () => readFileSync(indexFile, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
      .filter((r) => r.recordKind === 'guard');
    await hooks.before_tool_call({ toolName: 'Bash', params: { command: 'sudo systemctl stop ssh' } }, { sessionId });
    hooks.agent_end({ sessionId }, { sessionId });
    const firstGuards = indexed().length;
    expect(firstGuards).toBeGreaterThan(0);
    await hooks.before_tool_call({ toolName: 'Bash', params: { command: 'sudo systemctl stop sshd' } }, { sessionId });
    const newGuards = indexed().length - firstGuards;
    expect(newGuards).toBeGreaterThan(0);
    hooks.session_end({ sessionId }, { sessionId });

    const files = readdirSync(auditDir).filter((f) => /^realtime-.*\.jsonl$/.test(f));
    const rows = files.flatMap((f) =>
      readFileSync(join(auditDir, f), 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)),
    );
    const summaries = rows.filter((r) => r.type === 'session_summary' && r.outcome === 'action_guard_degraded');
    expect(summaries).toHaveLength(2);
    expect(summaries[0].guardOutcomeCount).toBe(firstGuards);
    expect(summaries[1].guardOutcomeCount).toBe(newGuards);
    // Each receipt lists only what it counted: no identity appears twice.
    expect(summaries[1].guardFingerprints.some((fp: string) => summaries[0].guardFingerprints.includes(fp))).toBe(false);
  });

  it('#654 H1: a HEAD-shaped fingerprint-less summary in realtime and the index never suppresses a later deny', async () => {
    const { api, hooks } = makeApi();
    plugin.register(api);

    const sessionId = 'agent:main:cron:h1';
    const key = expectedKey(sessionId);
    const indexFile = join(auditDir, 'session-guard', `${key}.jsonl`);
    // HEAD's OpenClaw summary lists no fingerprints and was written to both
    // sinks. Its lastGuardTs is after every guard below, so they are also
    // "backdated" against it; HEAD short-circuited on it regardless (RC5).
    const headSummary = {
      type: 'session_summary', recordKind: 'summary', origin: 'openclaw-session-end', sessionKey: key,
      action: 'session_health', outcome: 'action_guard_degraded', guardOutcomeCount: 1,
      outcomes: { failure_denied: 1 }, threats: [], firstGuardTs: '2099-01-01T00:00:00.000Z',
      lastGuardTs: '2099-01-01T00:00:00.000Z', ts: '2099-01-01T00:00:01.000Z',
    };
    mkdirSync(join(auditDir, 'session-guard'), { recursive: true });
    appendFileSync(join(auditDir, 'realtime-2026-01-01.jsonl'), `${JSON.stringify(headSummary)}\n`);
    appendFileSync(indexFile, `${JSON.stringify(headSummary)}\n`);

    await hooks.before_tool_call({ toolName: 'Bash', params: { command: 'sudo systemctl stop ssh' } }, { sessionId });
    const guards = readFileSync(indexFile, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
      .filter((r) => r.recordKind === 'guard' && r.action !== 'notify' && GUARD_DEGRADED_OUTCOMES.has(String(r.outcome)));
    expect(guards.length).toBeGreaterThan(0);
    hooks.session_end({ sessionId }, { sessionId });

    const files = readdirSync(auditDir).filter((f) => /^realtime-.*\.jsonl$/.test(f));
    const rows = files.flatMap((f) =>
      readFileSync(join(auditDir, f), 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)),
    );
    const receipts = rows.filter((r) => r.type === 'session_summary' && r.sessionKey === key && r.fingerprintScheme === 2);
    expect(receipts).toHaveLength(1);
    expect(receipts[0]).toMatchObject({
      origin: 'openclaw-session-end',
      guardOutcomeCount: guards.length,
      identityBasis: { eventId: guards.length, bindingNonce: 0, physicalRow: 0 },
      eventCountExact: true,
      historicalOverlap: 'possible',
      overlapReasons: ['fingerprintless-summary'],
      // One historical summary, observed once in realtime and once in the index.
      unknownMembershipSummaryRows: 2,
      coverage: 'bounded-complete',
    });
  });
});
