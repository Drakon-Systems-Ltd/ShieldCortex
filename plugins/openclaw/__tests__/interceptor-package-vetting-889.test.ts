import { describe, it, expect } from '@jest/globals';
import { createInterceptor, DEFAULT_CONFIG, type InterceptAuditEntry } from '../interceptor.js';
import { evaluateToolCall } from '../../../src/defence/iron-dome/tool-action-guard.js';
import { buildApprovalCard } from '../../../src/defence/iron-dome/approval-card.js';
import { applyVettingToVerdict, type ToolVettingOutcome } from '../../../src/defence/iron-dome/package-vetting.js';

/**
 * #889 phase 1 — the OpenClaw interceptor seam. The vetting runtime is a stub
 * returning a fixed outcome (the lookups themselves are covered in
 * package-vetting-889.test.ts); this pins how the outcome is APPLIED:
 * malicious → catastrophic block on every posture, other findings → reasons on
 * the card and audit row with the decision unchanged, a throwing/absent
 * runtime → the guard's own answer.
 */

const okPipeline = () => ({
  allowed: true,
  firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [] as string[], anomalyScore: 0, blockedPatterns: [] as string[] },
  trust: { score: 0.5 },
  sensitivity: { level: 'INTERNAL' },
  fragmentationScore: null,
  fragmentation: null,
  auditId: 1,
});

const INSTALL = ['npm', 'install', 'some-pkg'].join(' ');
const PIP_INSTALL = ['pip', 'install', 'some-pkg'].join(' ');

const outcome = (over: Partial<ToolVettingOutcome>): ToolVettingOutcome => ({
  malicious: false,
  reasons: [],
  audit: [{ ecosystem: 'npm', name: 'some-pkg', version: '1.0.0', status: 'checked', kinds: [], reasons: [] }],
  ...over,
});

function make(actionGuard: Record<string, unknown>, vet: (() => Promise<ToolVettingOutcome | null>) | null) {
  const audit: InterceptAuditEntry[] = [];
  const config = { ...DEFAULT_CONFIG, actionGuard: { ...DEFAULT_CONFIG.actionGuard, enabled: true, ...actionGuard } } as any;
  const i = createInterceptor(config, okPipeline as any, {
    evaluateToolCall: evaluateToolCall as any,
    buildApprovalCard: buildApprovalCard as any,
    onAuditEntry: (e) => audit.push(e),
    ...(vet ? { packageVetting: { vet: async () => vet(), apply: applyVettingToVerdict as any } } : {}),
  } as any);
  return { i, audit };
}

describe('interceptor — #889 package vetting', () => {
  const malicious = outcome({
    malicious: true,
    reasons: ['OSV lists some-pkg@1.0.0 as known malicious (MAL-2026-18603)'],
    audit: [{ ecosystem: 'npm', name: 'some-pkg', version: '1.0.0', status: 'checked', kinds: ['malicious'], reasons: ['OSV lists some-pkg@1.0.0 as known malicious (MAL-2026-18603)'] }],
  });

  it('a known-malicious package is a hard block even with enforce:false and an approver present', async () => {
    const { i, audit } = make({ enforce: false }, async () => malicious);
    let asked = false;
    await expect(
      i.handleToolCall({ toolName: 'Bash', arguments: { command: INSTALL }, requireApproval: async () => { asked = true; return true; } } as any),
    ).rejects.toThrow(/blocked.*MAL-2026-18603/s);
    expect(asked).toBe(false);
    const row = audit.find((e) => e.outcome === 'auto_denied')!;
    expect(row.threats).toEqual(expect.arrayContaining(['known-malicious-package', 'package-vetting']));
    expect(row.packageVetting?.[0].kinds).toEqual(['malicious']);
  });

  it('is blocked on a plain allow-tier local install too (the guard alone would allow it)', async () => {
    expect(evaluateToolCall('Bash', { command: INSTALL }).decision).toBe('allow');
    const { i } = make({ enforce: true }, async () => malicious);
    await expect(i.handleToolCall({ toolName: 'Bash', arguments: { command: INSTALL } } as any)).rejects.toThrow(/blocked/);
  });

  it('other findings put plain-English reasons on the approval card; the hold itself is unchanged', async () => {
    const reasons = ['OSV: GHSA-abcd-1234-wxyz affects this version', 'published 11 h ago', 'runs a postinstall script on install'];
    const { i, audit } = make({ enforce: true }, async () => outcome({ reasons, audit: [{ ecosystem: 'PyPI', name: 'some-pkg', version: '1.0.0', status: 'checked', kinds: ['advisory', 'new-version', 'install-hook'], reasons }] }));
    let prompt = '';
    await i.handleToolCall({
      toolName: 'Bash', arguments: { command: PIP_INSTALL },
      requireApproval: async (p: string) => { prompt = p; return true; },
    } as any);
    expect(prompt).toContain('GHSA-abcd-1234-wxyz');
    expect(prompt).toContain('published 11 h ago');
    const row = audit.find((e) => e.outcome === 'approved')!;
    expect(row.packageVetting?.[0].kinds).toEqual(['advisory', 'new-version', 'install-hook']);
  });

  it('never blocks on age or hooks alone in advisory mode: warns and allows', async () => {
    const reasons = ['published 3 h ago', 'runs a postinstall script on install'];
    const { i, audit } = make({ enforce: false }, async () => outcome({ reasons, audit: [{ ecosystem: 'PyPI', name: 'some-pkg', status: 'checked', kinds: ['new-version', 'install-hook'], reasons }] }));
    await expect(i.handleToolCall({ toolName: 'Bash', arguments: { command: PIP_INSTALL } } as any)).resolves.toBeUndefined();
    expect(audit[0].outcome).toBe('warned');
    expect(audit[0].packageVetting).toBeDefined();
  });

  it('an allow-tier install with findings stays allowed and the findings reach the audit row', async () => {
    const reasons = ['published 2 h ago'];
    const { i, audit } = make({ enforce: true }, async () => outcome({ reasons, audit: [{ ecosystem: 'npm', name: 'some-pkg', status: 'checked', kinds: ['new-version'], reasons }] }));
    await expect(i.handleToolCall({ toolName: 'Bash', arguments: { command: INSTALL } } as any)).resolves.toBeUndefined();
    expect(audit.find((e) => e.outcome === 'allowed')?.packageVetting?.[0].reasons).toEqual(reasons);
  });

  it('a vetting runtime that throws leaves the guard\'s own verdict', async () => {
    const { i } = make({ enforce: true }, async () => { throw new Error('boom'); });
    await expect(i.handleToolCall({ toolName: 'Bash', arguments: { command: INSTALL } } as any)).resolves.toBeUndefined();
  });

  it('a command that installs nothing by name never reaches an extra decision', async () => {
    const { i, audit } = make({ enforce: true }, async () => null);
    await expect(i.handleToolCall({ toolName: 'Bash', arguments: { command: 'ls -la' } } as any)).resolves.toBeUndefined();
    expect(audit).toEqual([]);
  });

  it('without the runtime (older dist) behaviour is exactly the guard\'s', async () => {
    const { i } = make({ enforce: true }, null);
    await expect(i.handleToolCall({ toolName: 'Bash', arguments: { command: INSTALL } } as any)).resolves.toBeUndefined();
  });
});
