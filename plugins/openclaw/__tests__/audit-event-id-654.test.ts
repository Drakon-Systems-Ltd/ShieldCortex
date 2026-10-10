import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { attachEnforcementBinding } from '../../../src/defence/iron-dome/enforcement-binding.js';
import {
  appendSessionGuardIndex,
  recordActionGuardDegraded,
  sessionKeyFor,
} from '../../../src/defence/iron-dome/session-guard.js';
import {
  __resetAuditSinkFailuresForTest,
  createInterceptor,
  DEFAULT_CONFIG,
  type InterceptAuditEntry,
} from '../interceptor.js';

/**
 * #654 — the OpenClaw producer mints ONE `auditEventId` per emitted row, in
 * `emitAuditWith`, before fan-out. Both persisted copies (realtime and the
 * session-guard index) and the `onAuditEntry` callback carry the same value,
 * so the stop hook can join the copies instead of counting each by file:line.
 *
 * Every fixture writes into a throwaway audit dir; the live ~/.shieldcortex is
 * never read.
 */

const __dirname = dirname(fileURLToPath(import.meta.url));
const STOP_HOOK = resolve(__dirname, '..', '..', '..', 'scripts', 'stop-hook.mjs');
const SALT = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const ID = /^[a-f0-9]{32}$/;
const HOOK_DEGRADED = new Set(['auto_denied', 'denied_no_prompt_surface', 'failure_denied', 'warned', 'failure_allowed']);

const okPipeline = () => ({
  allowed: true,
  firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [] as string[], anomalyScore: 0, blockedPatterns: [] as string[] },
  trust: { score: 0.5 },
  sensitivity: { level: 'INTERNAL' },
  fragmentation: null,
  auditId: 1,
});

/** A deterministic unattended deny, so the row is a degraded guard in both readers. */
const blockVerdict = () => ({
  decision: 'block', severity: 'catastrophic', family: 'exec', action: 'execute_command',
  reason: 'blocked', signals: ['recursive-force-delete'],
});

let home: string;
let auditDir: string;
const originalAuditDir = process.env.SHIELDCORTEX_AUDIT_DIR;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'sc-654-oc-'));
  auditDir = join(home, '.shieldcortex', 'audit');
  process.env.SHIELDCORTEX_AUDIT_DIR = auditDir;
  __resetAuditSinkFailuresForTest();
});

afterEach(() => {
  if (originalAuditDir === undefined) delete process.env.SHIELDCORTEX_AUDIT_DIR;
  else process.env.SHIELDCORTEX_AUDIT_DIR = originalAuditDir;
  __resetAuditSinkFailuresForTest();
  try { rmSync(home, { recursive: true, force: true }); } catch { /* best effort */ }
});

function rows(file: string): Array<Record<string, any>> {
  if (!existsSync(file)) return [];
  return readFileSync(file, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
}
function realtimeRows(dir = auditDir): Array<Record<string, any>> {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((f) => /^realtime-.*\.jsonl$/.test(f)).flatMap((f) => rows(join(dir, f)));
}
function indexRows(key: string, dir = auditDir): Array<Record<string, any>> {
  return rows(join(dir, 'session-guard', `${key}.jsonl`));
}
function strip(row: Record<string, any>): Record<string, any> {
  const { recordKind: _kind, ...rest } = row;
  return rest;
}

type Opts = {
  bind?: 'real' | 'none' | ((e: InterceptAuditEntry, args?: Record<string, unknown>) => InterceptAuditEntry);
  indexHome?: string;
};

function build(opts: Opts = {}) {
  const captured: InterceptAuditEntry[] = [];
  const bindAudit = opts.bind === undefined || opts.bind === 'real'
    ? (entry: InterceptAuditEntry, args?: Record<string, unknown>) => attachEnforcementBinding(entry as never, {
      plane: 'action_guard', hookName: 'before_tool_call', pluginId: 'shieldcortex-realtime',
      tool: entry.tool, args: args ?? {}, home,
    }) as unknown as InterceptAuditEntry
    : opts.bind === 'none' ? undefined : opts.bind;
  const { handleToolCall } = createInterceptor(
    { ...DEFAULT_CONFIG, actionGuard: { enabled: true, enforce: true, autoApprove: [] } } as never,
    okPipeline as never,
    {
      evaluateToolCall: blockVerdict as never,
      onAuditEntry: (e) => { captured.push(e); },
      sessionGuard: {
        keyFor: (id) => sessionKeyFor(id, { salt: SALT }),
        index: (entry) => {
          appendSessionGuardIndex({ ...(opts.indexHome ? { home: opts.indexHome } : {}), entry: { ...entry } as Record<string, unknown> });
        },
      },
      ...(bindAudit ? { bindAudit } : {}),
    },
  );
  const call = (sessionId: string, command = 'rm -rf /') =>
    handleToolCall({ toolName: 'Bash', arguments: { command }, sessionId }).catch(() => { /* a block throws after its row */ });
  return { call, captured };
}

describe('#654 producer — one minted ID per emitted row, shared by every copy', () => {
  it('P1: a bound gated deny carries the same ID on the realtime row, the index row and the callback', async () => {
    const { call, captured } = build();
    await call('p1-session');
    const key = sessionKeyFor('p1-session', { salt: SALT })!;
    const ix = indexRows(key);
    expect(ix).toHaveLength(1);
    const id = ix[0].auditEventId;
    expect(id).toMatch(ID);
    const rt = realtimeRows().filter((r) => r.auditEventId === id);
    expect(rt).toHaveLength(1);
    expect(strip(ix[0])).toEqual(rt[0]);
    expect(captured.filter((e) => e.auditEventId === id)).toHaveLength(1);
    // The binding nonce is independent of the ID, and shared by both copies.
    expect(rt[0].nonce).toMatch(ID);
    expect(ix[0].nonce).toBe(rt[0].nonce);
    expect(id).not.toBe(rt[0].nonce);
    // No other row of the call reuses it.
    const all = realtimeRows().map((r) => r.auditEventId);
    expect(new Set(all).size).toBe(all.length);
  });

  it('P2: with no binder injected the row still carries an ID, and both copies are identical', async () => {
    const { call } = build({ bind: 'none' });
    await call('p2-session');
    const key = sessionKeyFor('p2-session', { salt: SALT })!;
    const ix = indexRows(key);
    expect(ix).toHaveLength(1);
    expect(ix[0].auditEventId).toMatch(ID);
    const rt = realtimeRows().filter((r) => r.auditEventId === ix[0].auditEventId);
    expect(rt).toHaveLength(1);
    expect(rt[0].nonce).toBeUndefined();
    expect(strip(ix[0])).toEqual(rt[0]);
  });

  it('P3: separate emissions with identical tool, args and clock get distinct IDs', async () => {
    const frozen = jest.spyOn(Date.prototype, 'toISOString').mockReturnValue('2026-10-10T08:00:00.000Z');
    let captured: InterceptAuditEntry[];
    try {
      const h = build();
      await h.call('p3-session');
      await h.call('p3-session');
      captured = h.captured;
    } finally {
      frozen.mockRestore();
    }
    expect(captured.length).toBeGreaterThanOrEqual(2);
    expect(new Set(captured.map((e) => e.ts)).size).toBe(1);
    const ids = captured.map((e) => e.auditEventId);
    for (const id of ids) expect(id).toMatch(ID);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('P3: every row of one gated call (e.g. gate_degraded plus a verdict) has its own ID', async () => {
    const entries: InterceptAuditEntry[] = [];
    // No evaluator wired: the guard-unavailable fallback path writes a gate_degraded row.
    const i = createInterceptor(
      { ...DEFAULT_CONFIG, actionGuard: { enabled: true, enforce: true, autoApprove: [] } } as never,
      okPipeline as never,
      { onAuditEntry: (e) => entries.push(e) },
    );
    await i.handleToolCall({ toolName: 'Bash', arguments: { command: 'sudo systemctl stop nginx' } }).catch(() => {});
    expect(entries.some((e) => e.action === 'gate_degraded')).toBe(true);
    const ids = entries.map((e) => e.auditEventId);
    for (const id of ids) expect(id).toMatch(ID);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('P4: a binder that drops or rewrites the ID cannot fork the copies', async () => {
    const forged = 'f'.repeat(32);
    for (const bind of [
      (e: InterceptAuditEntry) => { const { auditEventId: _drop, ...rest } = e; return rest as InterceptAuditEntry; },
      (e: InterceptAuditEntry) => ({ ...e, auditEventId: forged }),
    ]) {
      rmSync(auditDir, { recursive: true, force: true });
      const { call, captured } = build({ bind });
      await call('p4-session');
      const key = sessionKeyFor('p4-session', { salt: SALT })!;
      const ix = indexRows(key);
      expect(ix).toHaveLength(1);
      const id = ix[0].auditEventId;
      expect(id).toMatch(ID);
      expect(id).not.toBe(forged);
      expect(realtimeRows().filter((r) => r.auditEventId === id)).toHaveLength(1);
      expect(captured.filter((e) => e.auditEventId === id)).toHaveLength(1);
      expect(realtimeRows().some((r) => r.auditEventId === forged)).toBe(false);
      expect(captured.some((e) => e.auditEventId === forged)).toBe(false);
    }
  });

  it('P10/W5: an unwritable realtime sink still leaves an ID-bearing index copy; decision unchanged; counted once', async () => {
    const indexHome = mkdtempSync(join(tmpdir(), 'sc-654-oc-ix-'));
    try {
      // The realtime sink cannot create its directory (a file sits there), so
      // it swallows the failure, as in production; the index is elsewhere.
      writeFileSync(join(home, 'not-a-dir'), 'x');
      process.env.SHIELDCORTEX_AUDIT_DIR = join(home, 'not-a-dir');
      const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
      let failed: unknown;
      let control: unknown;
      try {
        const broken = build({ indexHome });
        failed = await broken.call('p10-session').then(() => 'resolved', () => 'rejected');
        process.env.SHIELDCORTEX_AUDIT_DIR = auditDir;
        control = await build().call('p10-control').then(() => 'resolved', () => 'rejected');
      } finally {
        warn.mockRestore();
      }
      expect(failed).toBe(control);
      const key = sessionKeyFor('p10-session', { salt: SALT })!;
      const ixDir = join(indexHome, '.shieldcortex', 'audit');
      const ix = indexRows(key, ixDir);
      expect(ix).toHaveLength(1);
      expect(ix[0].auditEventId).toMatch(ID);
      // W5: the OpenClaw reader counts the indexed ID row once.
      const result = recordActionGuardDegraded('p10-session', { home: indexHome, salt: SALT });
      expect(result).toMatchObject({ recorded: true, count: 1 });
      expect(recordActionGuardDegraded('p10-session', { home: indexHome, salt: SALT })).toMatchObject({ existing: true, count: 0 });
    } finally {
      rmSync(indexHome, { recursive: true, force: true });
    }
  });
});

describe('#654 R2 — real producer output, read by the stop hook', () => {
  it('both copies of a minted-ID OpenClaw row count once in the stop hook, with exact cardinality', async () => {
    const indexHome = home;
    const { call } = build({ indexHome });
    await call('r2-session');
    const key = sessionKeyFor('r2-session', { salt: SALT })!;
    const degraded = realtimeRows().filter((r) => r.sessionKey === key && HOOK_DEGRADED.has(String(r.outcome)));
    expect(degraded.length).toBeGreaterThanOrEqual(1);
    expect(indexRows(key).length).toBe(degraded.length);
    const distinct = new Set(degraded.map((r) => r.auditEventId));

    mkdirSync(join(home, '.shieldcortex'), { recursive: true });
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      HOME: home,
      SHIELDCORTEX_CONFIG_DIR: join(home, '.shieldcortex'),
      SHIELDCORTEX_SESSION_SALT: SALT,
      SHIELDCORTEX_TEST_EMIT_GUARD_RESULT: '1',
    };
    delete env.SHIELDCORTEX_AUDIT_DIR;
    const hook = spawnSync(process.execPath, [STOP_HOOK], { input: JSON.stringify({ session_id: 'r2-session' }), encoding: 'utf8', env });
    expect(hook.status).toBe(0);
    const receipts = realtimeRows().filter((r) => r.origin === 'claude-code-stop-hook' && r.sessionKey === key);
    expect(receipts).toHaveLength(1);
    expect(receipts[0]).toMatchObject({
      guardOutcomeCount: distinct.size,
      identityBasis: { eventId: distinct.size, bindingNonce: 0, physicalRow: 0 },
      eventCountExact: true,
      fingerprintScheme: 2,
      coverage: 'bounded-complete',
    });
  });
});
