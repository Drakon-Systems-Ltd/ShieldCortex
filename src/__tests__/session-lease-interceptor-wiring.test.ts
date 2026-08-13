import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { createInterceptor, DEFAULT_CONFIG } from '../../plugins/openclaw/interceptor.js';
import type { InterceptAuditEntry } from '../../plugins/openclaw/interceptor.js';
import { evaluateToolCallLease } from '../defence/iron-dome/session-lease-store.js';

/**
 * #227 — the OpenClaw plane consults the session action lease.
 *
 * Mirrors the hook-side enforcement suite: a scoped, frozen action is refused
 * BEFORE any approval affordance; unscoped calls are untouched; and a broken
 * lease layer never becomes a new source of denials (state unreadability
 * fails closed inside the store, not here).
 */

const okPipeline = () => ({
  allowed: true,
  firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [] as string[], anomalyScore: 0, blockedPatterns: [] as string[] },
  trust: { score: 0.5 }, sensitivity: { level: 'INTERNAL' }, fragmentation: null, auditId: 1,
});

/** A guard evaluator that allows everything at benign severity — isolating the
 *  lease layer's behaviour from the verdict cascade. */
const allowAll = () => ({
  decision: 'allow', severity: 'benign', family: 'exec', action: 'exec',
  reason: 'allowed', signals: [] as string[],
});

function interceptorWith(
  lease: ((toolName: string, args: Record<string, unknown>, sessionId: string | undefined) => {
    scope: string; decision: { verdict: string; reason: string };
    ledgerChanged?: { fromHash: string; toHash: string };
  } | null) | undefined,
  entries: InterceptAuditEntry[] = [],
) {
  return createInterceptor(
    { ...DEFAULT_CONFIG, actionGuard: { enabled: true, enforce: true, autoApprove: [] } } as never,
    okPipeline as never,
    {
      evaluateToolCall: allowAll as never,
      checkActionLease: lease,
      onAuditEntry: (e) => entries.push(e),
    },
  );
}

describe('#227 — interceptor consults the lease before any approval affordance', () => {
  it('a frozen scope throws a ShieldCortex block naming the freeze', async () => {
    const entries: InterceptAuditEntry[] = [];
    const i = interceptorWith(
      () => ({
        scope: 'npm-publish',
        decision: { verdict: 'frozen', reason: 'npm-publish is FROZEN by a standing decision: "| FROZEN | until review |"' },
      }),
      entries,
    );
    await expect(
      i.handleToolCall({ toolName: 'Bash', arguments: { command: 'npm publish' }, sessionId: 's-1' }),
    ).rejects.toThrow(/ShieldCortex: tool call blocked — .*FROZEN/);
    expect(entries.some((e) => e.outcome === 'auto_denied')).toBe(true);
  });

  it('a held scope is refused with the holder named', async () => {
    const i = interceptorWith(() => ({
      scope: 'install',
      decision: { verdict: 'held', reason: 'install is held by another session (session-b, pid 4242)' },
    }));
    await expect(
      i.handleToolCall({ toolName: 'Bash', arguments: { command: 'npm i -g x' }, sessionId: 's-1' }),
    ).rejects.toThrow(/held by another session \(session-b/);
  });

  it('an unscoped call (lease returns null) proceeds untouched', async () => {
    const i = interceptorWith(() => null);
    await expect(
      i.handleToolCall({ toolName: 'Bash', arguments: { command: 'git status' }, sessionId: 's-1' }),
    ).resolves.toBeUndefined();
  });

  it('a THROWING lease layer never denies (module breakage is not a freeze)', async () => {
    const i = interceptorWith(() => { throw new Error('lease module exploded'); });
    await expect(
      i.handleToolCall({ toolName: 'Bash', arguments: { command: 'npm publish' }, sessionId: 's-1' }),
    ).resolves.toBeUndefined();
  });

  it('no lease layer wired (old package) means no lease refusals', async () => {
    const i = interceptorWith(undefined);
    await expect(
      i.handleToolCall({ toolName: 'Bash', arguments: { command: 'npm publish' }, sessionId: 's-1' }),
    ).resolves.toBeUndefined();
  });
});

describe('#227 — OpenClaw plane end-to-end through the REAL store (review minor-5)', () => {
  let dir: string;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'sc-lease-oc-e2e-')); mkdirSync(dir, { recursive: true }); });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  // Wire the REAL evaluateToolCallLease against a REAL DECISIONS.md in a
  // sandbox dir — no mock. This is the plane the 10-Aug incident happened on.
  const realInterceptor = () => createInterceptor(
    { ...DEFAULT_CONFIG, actionGuard: { enabled: true, enforce: true, autoApprove: [] } } as never,
    okPipeline as never,
    {
      evaluateToolCall: allowAll as never,
      checkActionLease: (t, a, s) => evaluateToolCallLease(t, a, { self: s ?? '', dir }),
      onAuditEntry: () => {},
    },
  );

  it('a real freeze in DECISIONS.md refuses npm publish through the real store', async () => {
    writeFileSync(join(dir, 'DECISIONS.md'), '| FROZEN | no publishes until review |\n');
    await expect(
      realInterceptor().handleToolCall({ toolName: 'Bash', arguments: { command: 'npm publish' }, sessionId: 'oc-1' }),
    ).rejects.toThrow(/ShieldCortex: tool call blocked — .*FROZEN/);
  });

  it('with no freeze, a scoped call proceeds and mutual exclusion binds a second session', async () => {
    await expect(
      realInterceptor().handleToolCall({ toolName: 'Bash', arguments: { command: 'npm install -g x' }, sessionId: 'oc-a' }),
    ).resolves.toBeUndefined();
    // A different session now sees the lease held.
    await expect(
      realInterceptor().handleToolCall({ toolName: 'Bash', arguments: { command: 'npm i --global y' }, sessionId: 'oc-b' }),
    ).rejects.toThrow(/held by another session/);
  });
});
