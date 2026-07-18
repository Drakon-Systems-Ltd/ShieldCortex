import { describe, it, expect, jest, afterEach } from '@jest/globals';
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
