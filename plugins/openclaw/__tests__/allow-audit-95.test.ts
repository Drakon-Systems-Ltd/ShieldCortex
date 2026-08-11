import { describe, it, expect, jest, afterEach } from '@jest/globals';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { createInterceptor, DEFAULT_CONFIG, noteAuditSinkFailure, __resetAuditSinkFailuresForTest } from '../interceptor.js';
import type { InterceptAuditEntry } from '../interceptor.js';
import { evaluateToolCall } from '../../../src/defence/iron-dome/tool-action-guard.js';

/**
 * Issue #95 — the Action Guard's audit trail had two silent gaps:
 *  1. allow-decisions were never logged, so "scanned & allowed" was
 *     indistinguishable from "never scanned" in forensics; and
 *  2. an unwritable audit sink was swallowed by a bare catch — entries
 *     dropped with zero operator signal.
 *
 * Design shipped here: RECOGNISED allows (the guard evaluated a known
 * operation family and allowed it — severity 'sensitive'+) are audited as
 * `action: 'allow' / outcome: 'allowed'`; benign allows are not, because on a
 * busy agent every `ls` would drown the stream (`actionGuard.auditAllows:
 * false` opts the recognised-allow entries off too). Sink failures warn once
 * per process, loudly, instead of never.
 */

const okPipeline = () => ({
  allowed: true,
  firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [] as string[], anomalyScore: 0, blockedPatterns: [] as string[] },
  trust: { score: 0.5 },
  sensitivity: { level: 'INTERNAL' },
  fragmentation: null,
  auditId: 1,
});

function makeCapturingInterceptor(overrides: Record<string, unknown> = {}) {
  const entries: InterceptAuditEntry[] = [];
  const config = { ...DEFAULT_CONFIG, ...overrides } as any;
  const i = createInterceptor(config, okPipeline as any, {
    evaluateToolCall: evaluateToolCall as any,
    onAuditEntry: (e) => entries.push(e),
  });
  return { i, entries };
}

describe('#95 — recognised allow-decisions are audited', () => {
  it('a sensitive-tier allow (workspace-local npm install) emits an allow audit entry', async () => {
    const { i, entries } = makeCapturingInterceptor();
    await i.handleToolCall({ toolName: 'Bash', arguments: { command: 'npm install left-pad' } });
    const allow = entries.find((e) => e.action === 'allow');
    expect(allow).toBeDefined();
    expect(allow!.outcome).toBe('allowed');
    expect(allow!.severity).toBe('low');
    expect(allow!.firewallResult).toBe('ACTION_GUARD');
    expect(allow!.threats).toContain('local-package-install');
  });

  it('a benign allow (plain ls) emits NO audit entry — volume discipline', async () => {
    const { i, entries } = makeCapturingInterceptor();
    await i.handleToolCall({ toolName: 'Bash', arguments: { command: 'ls -la' } });
    expect(entries).toHaveLength(0);
  });

  it('actionGuard.auditAllows: false suppresses the recognised-allow entry', async () => {
    const { i, entries } = makeCapturingInterceptor({
      actionGuard: { enabled: true, enforce: true, autoApprove: [], auditAllows: false },
    });
    await i.handleToolCall({ toolName: 'Bash', arguments: { command: 'npm install left-pad' } });
    expect(entries.find((e) => e.action === 'allow')).toBeUndefined();
  });

  it('gated decisions still audit exactly as before (no regression)', async () => {
    const { i, entries } = makeCapturingInterceptor();
    await expect(
      i.handleToolCall({ toolName: 'Bash', arguments: { command: 'rm -rf /' } }),
    ).rejects.toThrow(/blocked/);
    const blocked = entries.find((e) => e.action === 'auto_deny' || e.outcome === 'auto_denied' || e.outcome === 'denied');
    expect(blocked).toBeDefined();
    expect(blocked!.severity).toBe('critical');
  });
});

describe('#226 — interceptor audit isolation', () => {
  const originalAuditDir = process.env.SHIELDCORTEX_AUDIT_DIR;
  let tempAuditDir = '';

  afterEach(() => {
    if (originalAuditDir === undefined) delete process.env.SHIELDCORTEX_AUDIT_DIR;
    else process.env.SHIELDCORTEX_AUDIT_DIR = originalAuditDir;
    if (tempAuditDir) fs.rmSync(tempAuditDir, { recursive: true, force: true });
  });

  it('honours SHIELDCORTEX_AUDIT_DIR per write instead of touching the host audit', async () => {
    tempAuditDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-interceptor-audit-'));
    process.env.SHIELDCORTEX_AUDIT_DIR = tempAuditDir;

    const { i } = makeCapturingInterceptor();
    await i.handleToolCall({ toolName: 'Bash', arguments: { command: 'npm install left-pad' } });

    const files = fs.readdirSync(tempAuditDir).filter((name) => name.endsWith('.jsonl'));
    expect(files).toHaveLength(1);
    const rows = fs.readFileSync(path.join(tempAuditDir, files[0]), 'utf8').trim().split('\n');
    expect(rows).toHaveLength(1);
    expect(JSON.parse(rows[0]).type).toBe('intercept');
  });
});

describe('#95 — audit sink failures are loud, once per process', () => {
  afterEach(() => {
    __resetAuditSinkFailuresForTest();
    jest.restoreAllMocks();
  });

  it('warns exactly once across repeated failures, and counts the drops', () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    noteAuditSinkFailure(new Error('EACCES: permission denied'));
    noteAuditSinkFailure(new Error('EACCES: permission denied'));
    noteAuditSinkFailure(new Error('EACCES: permission denied'));
    const auditWarnings = warn.mock.calls.filter((c) => String(c[0]).includes('audit'));
    expect(auditWarnings).toHaveLength(1);
    expect(String(auditWarnings[0][0])).toMatch(/DROPPED/i);
    expect(String(auditWarnings[0][0])).toContain('EACCES');
  });
});
