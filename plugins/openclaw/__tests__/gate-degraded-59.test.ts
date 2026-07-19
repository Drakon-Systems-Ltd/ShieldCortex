import { describe, it, expect } from '@jest/globals';
import { createInterceptor, DEFAULT_CONFIG } from '../interceptor.js';
import type { InterceptAuditEntry } from '../interceptor.js';

/**
 * Issue #59 (P1/WS2) — the interceptor's guard-unavailable path used to fail
 * closed ONLY on catastrophic fallback matches; a recognised-DANGEROUS op
 * (sudo, force-push, global install, scheduler mutation, plain rm) fell
 * through to fail-OPEN. This ports the dangerous tier into the fallback: when
 * the guard can't scan, a dangerous shape routes through `failurePolicy`
 * exactly as an unattended real verdict would (deny by default), and EVERY
 * could-not-scan decision leaves a `gate_degraded` audit row so forensics can
 * tell "scanned & allowed" from "could not scan".
 *
 * The zeroth-law line is unchanged: a genuinely benign op still fails OPEN —
 * a degraded guard must not wedge an agent doing normal work — but it now
 * leaves a gate_degraded/failure_allowed breadcrumb instead of a silent pass.
 */

const okPipeline = () => ({
  allowed: true,
  firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [] as string[], anomalyScore: 0, blockedPatterns: [] as string[] },
  trust: { score: 0.5 },
  sensitivity: { level: 'INTERNAL' },
  fragmentation: null,
  auditId: 1,
});

/** Guard-unavailable interceptor: no evaluateToolCall wired → the fallback path. */
function degradedInterceptor(overrides: Record<string, unknown> = {}) {
  const entries: InterceptAuditEntry[] = [];
  const config = { ...DEFAULT_CONFIG, ...overrides } as any;
  const i = createInterceptor(config, okPipeline as any, { onAuditEntry: (e) => entries.push(e) });
  return { i, entries };
}

const degraded = (e: InterceptAuditEntry[]) => e.find((x) => x.action === 'gate_degraded');

describe('#59 — interceptor fails closed on DANGEROUS ops when the guard is unavailable', () => {
  const dangerous: Array<[string, string]> = [
    ['privilege escalation', 'sudo systemctl stop nginx'],
    ['git force-push', 'git push --force origin main'],
    ['global install', 'npm install -g some-pkg'],
    ['scheduler mutation', 'crontab -e'],
    ['plain file delete', 'rm important.txt'],
    ['kill process', 'pkill -9 node'],
    ['firewall change', 'ufw disable'],
  ];

  it.each(dangerous)('denies (failure policy) + audits gate_degraded: %s', async (_name, command) => {
    const { i, entries } = degradedInterceptor();
    await expect(i.handleToolCall({ toolName: 'Bash', arguments: { command } })).rejects.toThrow(/blocked|degraded|fail/i);
    const g = degraded(entries);
    expect(g).toBeDefined();
    expect(g!.outcome).toBe('failure_denied');
    expect(g!.firewallResult).toBe('ACTION_GUARD_FALLBACK');
    expect(g!.threats).toContain('fallback-scan');
  });

  it('respects failurePolicy override (high=allow → allowed, still audited)', async () => {
    const { i, entries } = degradedInterceptor({ failurePolicy: { ...DEFAULT_CONFIG.failurePolicy, high: 'allow' } });
    await expect(i.handleToolCall({ toolName: 'Bash', arguments: { command: 'sudo systemctl stop nginx' } })).resolves.toBeUndefined();
    const g = degraded(entries);
    expect(g).toBeDefined();
    expect(g!.outcome).toBe('failure_allowed');
  });

  it('advisory mode (enforce:false) never denies a dangerous degraded op, but audits it', async () => {
    const { i, entries } = degradedInterceptor({ actionGuard: { enabled: true, enforce: false, autoApprove: [] } });
    await expect(i.handleToolCall({ toolName: 'Bash', arguments: { command: 'git push --force' } })).resolves.toBeUndefined();
    const g = degraded(entries);
    expect(g).toBeDefined();
    expect(g!.outcome).toBe('failure_allowed');
  });
});

describe('#59 — catastrophic degraded path still hard-denies (regression) and benign fails open visibly', () => {
  it('catastrophic still throws when the guard is unavailable', async () => {
    const { i } = degradedInterceptor();
    await expect(i.handleToolCall({ toolName: 'Bash', arguments: { command: 'rm -rf /' } })).rejects.toThrow(/blocked|fallback/i);
  });

  it('catastrophic ignores enforce:false (hard-block tier)', async () => {
    const { i } = degradedInterceptor({ actionGuard: { enabled: true, enforce: false, autoApprove: [] } });
    await expect(i.handleToolCall({ toolName: 'Bash', arguments: { command: 'rm -rf /' } })).rejects.toThrow(/blocked|fallback/i);
  });

  const benign: Array<[string, string]> = [
    ['list', 'ls -la'],
    ['git status', 'git status'],
    ['run tests', 'npm test'],
    ['read-only scheduler', 'crontab -l'],
    ['read-only global query', 'npm ls -g'],
    ['git log', 'git log --oneline -5'],
  ];

  it.each(benign)('allows benign degraded op but leaves a gate_degraded/failure_allowed row: %s', async (_name, command) => {
    const { i, entries } = degradedInterceptor();
    await expect(i.handleToolCall({ toolName: 'Bash', arguments: { command } })).resolves.toBeUndefined();
    const g = degraded(entries);
    expect(g).toBeDefined();
    expect(g!.outcome).toBe('failure_allowed');
    expect(g!.severity).toBe('low');
  });

  // must-still-allow siblings for the 7 shapes added after review — the narrowed
  // real patterns must not over-gate these read-only / non-destructive forms.
  const benignSiblings: Array<[string, string]> = [
    ['plain cat (no pipe-to-shell)', 'cat notes.md'],
    ['cat piped to a non-shell', 'cat access.log | grep 404'],
    ['dd without of= (read/inspect)', 'dd if=disk.img bs=512 count=1 | xxd'],
    ['chmod without -R (single file)', 'chmod 644 config.yml'],
    ['recursive chmod on a NON-system dir', 'chmod -R 755 ./my-project/dist'],
    ['truncate to nonzero size', 'truncate -s 10M sparse.img'],
    // NB: `.env`-in-filename (e.g. deployment.env.example) DOES gate — that is
    // the real guard's touch-sensitive-path pattern (`\.env\b`), faithfully
    // mirrored here; a pre-existing over-match, out of scope for #59.
  ];
  it.each(benignSiblings)('does not over-gate: %s', async (_name, command) => {
    const { i } = degradedInterceptor();
    await expect(i.handleToolCall({ toolName: 'Bash', arguments: { command } })).resolves.toBeUndefined();
  });
});
