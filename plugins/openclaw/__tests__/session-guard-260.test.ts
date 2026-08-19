import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { createHmac } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { evaluateToolCall } from '../../../src/defence/iron-dome/tool-action-guard.js';
import {
  appendSessionGuardIndex,
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
    runtime: { config: { current: () => ({ plugins: { entries: { 'shieldcortex-realtime': { enabled: true, config: {} } } } }) } },
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
    const { handleToolCall } = createInterceptor(DEFAULT_CONFIG, okPipeline as never, {
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
    const { handleToolCall } = createInterceptor(DEFAULT_CONFIG, okPipeline as never, {
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
});
