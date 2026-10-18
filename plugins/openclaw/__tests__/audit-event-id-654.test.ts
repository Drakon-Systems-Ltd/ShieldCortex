import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { spawnSync } from 'node:child_process';
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { attachEnforcementBinding } from '../../../src/defence/iron-dome/enforcement-binding.js';
import {
  appendSessionGuardIndex,
  guardIdentity,
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
// HIST1: every file that existed before a summariser run keeps its bytes as a
// prefix afterwards (EOF appends only). Returns the post-run check.
function appendOnlyCheck(root: string): () => void {
  const files: string[] = [];
  const visit = (dir: string) => {
    if (!existsSync(dir)) return;
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      const st = lstatSync(p);
      if (st.isDirectory()) visit(p);
      else if (st.isFile() && !name.endsWith('.lock') && name !== 'memories.db') files.push(p);
    }
  };
  visit(root);
  const before = new Map(files.map((p) => [p, readFileSync(p)]));
  return () => {
    for (const [p, bytes] of before) {
      expect(readFileSync(p).subarray(0, bytes.length).equals(bytes)).toBe(true);
    }
  };
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
      let appendOnly = appendOnlyCheck(indexHome);
      const result = recordActionGuardDegraded('p10-session', { home: indexHome, salt: SALT });
      appendOnly();
      expect(result).toMatchObject({ recorded: true, count: 1 });
      appendOnly = appendOnlyCheck(indexHome);
      expect(recordActionGuardDegraded('p10-session', { home: indexHome, salt: SALT })).toMatchObject({ existing: true, count: 0 });
      appendOnly();
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
    };
    delete env.SHIELDCORTEX_AUDIT_DIR;
    const appendOnly = appendOnlyCheck(join(home, '.shieldcortex', 'audit'));
    const hook = spawnSync(process.execPath, [STOP_HOOK], { input: JSON.stringify({ session_id: 'r2-session' }), encoding: 'utf8', env });
    expect(hook.status).toBe(0);
    appendOnly();
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

  it('W5 hook half: a minted-ID row present only in the index counts once in the stop hook; a retry adds nothing', async () => {
    const indexHome = mkdtempSync(join(tmpdir(), 'sc-654-oc-w5-'));
    try {
      // Same producer fault as P10/W5: the realtime sink cannot create its
      // directory and swallows the failure; the index copy lands in indexHome.
      writeFileSync(join(home, 'not-a-dir'), 'x');
      process.env.SHIELDCORTEX_AUDIT_DIR = join(home, 'not-a-dir');
      const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
      try {
        await build({ indexHome }).call('w5-session');
      } finally {
        warn.mockRestore();
        process.env.SHIELDCORTEX_AUDIT_DIR = auditDir;
      }
      const key = sessionKeyFor('w5-session', { salt: SALT })!;
      const ixDir = join(indexHome, '.shieldcortex', 'audit');
      const ixFile = join(ixDir, 'session-guard', `${key}.jsonl`);
      const ix = indexRows(key, ixDir);
      expect(ix).toHaveLength(1);
      expect(ix[0]).toMatchObject({ recordKind: 'guard', origin: 'openclaw-interceptor', sessionKey: key });
      expect(HOOK_DEGRADED.has(String(ix[0].outcome))).toBe(true);
      expect(ix[0].auditEventId).toMatch(ID);
      // Index-only: no realtime copy exists anywhere the hook will look.
      expect(realtimeRows(ixDir)).toEqual([]);
      const ixBefore = readFileSync(ixFile);
      // An eventId-basis fingerprint ignores the physical key.
      const expectedFp = guardIdentity(ix[0], 'unused').primary;

      const env: NodeJS.ProcessEnv = {
        ...process.env,
        HOME: indexHome,
        SHIELDCORTEX_CONFIG_DIR: join(indexHome, '.shieldcortex'),
        SHIELDCORTEX_SESSION_SALT: SALT,
      };
      delete env.SHIELDCORTEX_AUDIT_DIR;
      const runHook = () => {
        const appendOnly = appendOnlyCheck(ixDir);
        const hook = spawnSync(process.execPath, [STOP_HOOK], { input: JSON.stringify({ session_id: 'w5-session' }), encoding: 'utf8', env });
        expect(hook.status).toBe(0);
        appendOnly();
        return hook;
      };
      const receiptsOf = (all: Array<Record<string, any>>) =>
        all.filter((r) => r.origin === 'claude-code-stop-hook' && r.sessionKey === key);

      const first = runHook();
      expect(first.stderr).toContain(`sessionKey=${key} guardOutcomes=1`);
      expect(first.stderr).not.toContain('index mirror FAILED');
      expect(first.stderr).not.toContain('coverage=partial');
      const receipts = receiptsOf(realtimeRows(ixDir));
      expect(receipts).toHaveLength(1);
      expect(receipts[0]).toMatchObject({
        guardOutcomeCount: 1,
        guardFingerprints: [expectedFp],
        identityBasis: { eventId: 1, bindingNonce: 0, physicalRow: 0 },
        eventCountExact: true,
        fingerprintScheme: 2,
        coverage: 'bounded-complete',
      });
      expect(receipts[0]).not.toHaveProperty('historicalOverlap');
      expect(receipts[0]).not.toHaveProperty('pendingRemaining');
      // The mirror is the same receipt; the guard row itself is untouched.
      expect(receiptsOf(indexRows(key, ixDir)).map(strip)).toEqual(receipts);
      expect(indexRows(key, ixDir).filter((r) => r.recordKind === 'guard')).toEqual(ix);

      const second = runHook();
      expect(second.stderr).not.toContain('guardOutcomes=');
      expect(receiptsOf(realtimeRows(ixDir))).toEqual(receipts);
      expect(receiptsOf(indexRows(key, ixDir))).toHaveLength(1);
      expect(indexRows(key, ixDir).filter((r) => r.recordKind === 'guard')).toEqual(ix);
      // The producer's original index bytes survive both runs as a prefix.
      expect(readFileSync(ixFile).subarray(0, ixBefore.length).equals(ixBefore)).toBe(true);
    } finally {
      rmSync(indexHome, { recursive: true, force: true });
    }
  });
});
