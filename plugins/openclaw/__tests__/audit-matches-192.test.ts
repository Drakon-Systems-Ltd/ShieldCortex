import { describe, expect, it } from '@jest/globals';
import { createInterceptor, DEFAULT_CONFIG, type InterceptAuditEntry } from '../interceptor.js';
import { evaluateToolCall } from '../../../src/defence/iron-dome/tool-action-guard.js';

/**
 * Issue #192 — the WIRING half: `ToolGuardVerdict.matches` must survive all the
 * way onto the emitted audit entry, or the durable record still cannot explain
 * a denial. The verdict-side tests live in
 * src/defence/iron-dome/__tests__/verdict-matches.test.ts; this file pins that
 * the interceptor actually persists them (delete the guardAuditBase spread and
 * this goes red).
 */

const okPipeline = () => ({
  allowed: true,
  firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [] as string[], anomalyScore: 0, blockedPatterns: [] as string[] },
  trust: { score: 0.5 },
  sensitivity: { level: 'INTERNAL' },
  fragmentation: null,
  auditId: 1,
});

function run() {
  const captured: InterceptAuditEntry[] = [];
  const i = createInterceptor({ ...DEFAULT_CONFIG, actionGuard: { enabled: true, enforce: true, autoApprove: [] } } as never, okPipeline as never, {
    evaluateToolCall: evaluateToolCall as never,
    onAuditEntry: (e) => captured.push(e),
  });
  return { i, captured };
}

describe('#192 — matched spans reach the audit entry', () => {
  it('a gated command’s audit row carries the rule and its span', async () => {
    // Unattended (no requireApproval in context) — dangerous fails closed and
    // throws, but the audit row must already be written, WITH its evidence.
    const { i, captured } = run();
    await expect(
      i.handleToolCall({ toolName: 'Bash', arguments: { command: 'ufw disable' } }),
    ).rejects.toThrow(/blocked/);
    const row = captured.find(e => e.threats.includes('modify-network-firewall'));
    expect(row).toBeDefined();
    expect(row?.matches?.some(m => m.signal === 'modify-network-firewall' && /ufw/.test(m.span))).toBe(true);
  });

  it('an allow row whose verdict produced no spans has no matches field', async () => {
    const { i, captured } = run();
    await i.handleToolCall({ toolName: 'Bash', arguments: { command: 'git push origin main --quiet' } });
    const row = captured.find(e => e.threats.includes('git-mutate'));
    expect(row).toBeDefined();
    expect(row?.matches).toBeUndefined();
  });
});
