import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { GUARD_DEGRADED_OUTCOMES } from '../../../src/defence/iron-dome/session-guard.js';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { evaluateToolCall } from '../../../src/defence/iron-dome/tool-action-guard.js';
import plugin, {
  __resetConfigStateForTest,
  __setDefenceModuleForTest,
  __setRuntimeForTest,
} from '../index.js';
import { createInterceptor, DEFAULT_CONFIG, type ApprovalDecisionAudit, type InterceptAuditEntry } from '../interceptor.js';

/**
 * #372 — the operator's answer to an OpenClaw-native approval card must reach
 * the audit stream.
 *
 * #310 made the card real by THROWING out of `requireApproval`, and
 * deliberately wrote no audit row at the throw site: no decision exists when a
 * card is minted. But nothing wrote one when the decision arrived either — the
 * host reports it on `requireApproval.onResolution`, which was never set. An
 * operator tapping "Approve" on a recursive delete therefore left NO SC-side
 * intercept entry at all, and the #260 session summaries could not see it.
 *
 * The contract pinned here:
 *   1. The hold still writes nothing, and the card error is re-thrown intact.
 *   2. The card carries a one-shot writer that snapshots the call AT HOLD TIME
 *      — a later tool call on the same interceptor cannot skew attribution.
 *   3. Resolving writes through the SAME pipeline as every other row
 *      (jsonl + sessionGuard.index + onAuditEntry + origin), exactly once.
 *   4. The plugin maps every host decision onto that writer, and the host
 *      never sees a throw from it.
 */

const DANGEROUS_COMMAND = 'rm /home/u/notes.txt';

const okPipeline = () => ({
  allowed: true,
  firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [] as string[], anomalyScore: 0, blockedPatterns: [] as string[] },
  trust: { score: 0.5 },
  sensitivity: { level: 'INTERNAL' },
  fragmentation: null,
  auditId: 1,
});

/** The bridge as `plugins/openclaw/index.ts` builds it: matched by NAME, and
 *  carrying the interceptor's decision writer once the hold is taken. */
type CardError = Error & { decisionAudit?: ApprovalDecisionAudit };

function mintCard(): CardError {
  const err: CardError = new Error('ShieldCortex approval required');
  err.name = 'TypedApprovalRequest';
  return err;
}

// ==================== 1. Interceptor: the closure itself ====================

describe('#372 interceptor — a held card carries its own decision writer', () => {
  type Harness = {
    handleToolCall: (ctx: Record<string, unknown>) => Promise<void>;
    captured: InterceptAuditEntry[];
    indexed: InterceptAuditEntry[];
  };

  function makeHarness(overrides: {
    keyFor?: (sessionId: string | undefined) => string | null;
  } = {}): Harness {
    const captured: InterceptAuditEntry[] = [];
    const indexed: InterceptAuditEntry[] = [];
    const { handleToolCall } = createInterceptor(
      { ...DEFAULT_CONFIG, actionGuard: { enabled: true, enforce: true, autoApprove: [] } } as never,
      okPipeline as never,
      {
        evaluateToolCall: evaluateToolCall as never,
        onAuditEntry: (e) => { captured.push(e); },
        sessionGuard: {
          keyFor: overrides.keyFor ?? ((id) => (id ? `sc-${id}` : null)),
          index: (entry) => { indexed.push(entry); },
        },
        // Stands in for #224 attachEnforcementBinding: proves WHICH call's args
        // the row was bound to, which is the whole point of capturing at hold.
        bindAudit: (entry, args) => ({ ...entry, actionKey: String(args?.command ?? 'no-args') }),
      },
    );
    return { handleToolCall: handleToolCall as Harness['handleToolCall'], captured, indexed };
  }

  /** Drive a dangerous op up to the mint, and hand back the card the plugin
   *  bridge would receive. */
  async function holdCard(h: Harness, sessionId?: string, command = DANGEROUS_COMMAND): Promise<CardError> {
    const thrown = await h.handleToolCall({
      toolName: 'Bash',
      arguments: { command },
      sessionId,
      requireApproval: async () => { throw mintCard(); },
    }).then(() => null, (err: unknown) => err);
    expect(thrown).toBeInstanceOf(Error);
    expect((thrown as Error).name).toBe('TypedApprovalRequest');
    return thrown as CardError;
  }

  it('mints the card with NO row, re-throws it intact, and attaches the writer', async () => {
    const h = makeHarness();
    const card = await holdCard(h, 'sess-hold');
    // #310 unchanged: a hold is not a decision.
    expect(h.captured).toHaveLength(0);
    expect(h.indexed).toHaveLength(0);
    expect(typeof card.decisionAudit).toBe('function');
  });

  it('an approved card writes exactly one require_approval / approved_once row', async () => {
    const h = makeHarness();
    const card = await holdCard(h, 'sess-approve');

    card.decisionAudit!('approved_once');

    expect(h.captured).toHaveLength(1);
    expect(h.captured[0]).toMatchObject({
      type: 'intercept',
      tool: 'Bash',
      action: 'require_approval',
      outcome: 'approved_once',
      origin: 'openclaw-interceptor',
    });
    // The guard's own bounded preview — never the approval prompt text.
    expect(h.captured[0]!.preview).toContain('Bash');
    expect(h.captured[0]!.preview.length).toBeLessThanOrEqual(200);
  });

  it.each([
    ['card_denied'],
    ['card_timeout'],
    ['card_cancelled'],
  ] as const)('a %s decision writes its own require_approval row', async (outcome) => {
    const h = makeHarness();
    const card = await holdCard(h, `sess-${outcome}`);

    card.decisionAudit!(outcome);

    expect(h.captured).toHaveLength(1);
    expect(h.captured[0]).toMatchObject({ action: 'require_approval', outcome, origin: 'openclaw-interceptor' });
  });

  it('keeps the HOLD-time session and args when the session moves on before the answer', async () => {
    const h = makeHarness();
    const card = await holdCard(h, 'sess-A');

    // Minutes pass. The same interceptor serves another call on another
    // session — the state `emitAudit` reads live is now someone else's.
    await h.handleToolCall({
      toolName: 'Bash',
      arguments: { command: 'sudo systemctl stop ssh' },
      sessionId: 'sess-B',
      requireApproval: async () => true,
    });
    const rowsBefore = h.captured.length;

    card.decisionAudit!('approved_once');

    const decision = h.captured[rowsBefore];
    expect(decision).toMatchObject({ outcome: 'approved_once' });
    expect(decision!.sessionKey).toBe('sc-sess-A');
    expect(decision!.actionKey).toBe(DANGEROUS_COMMAND);
  });

  it('snapshots args at hold time: in-place mutation cannot forge the binding', async () => {
    const h = makeHarness();
    const args: Record<string, unknown> = { command: DANGEROUS_COMMAND };
    const thrown = await h.handleToolCall({
      toolName: 'Bash',
      arguments: args,
      sessionId: 'sess-A',
      requireApproval: async () => { throw mintCard(); },
    }).then(() => null, (err: unknown) => err);
    const card = thrown as CardError;

    // The attacker's move: mutate the SAME object the interceptor saw, then
    // let the operator's approval land. A reference capture would bind the
    // decision row to the rewritten command.
    args.command = 'ls -la';
    card.decisionAudit!('approved_once');

    const decision = h.captured[h.captured.length - 1];
    expect(decision!.actionKey).toBe(DANGEROUS_COMMAND);
  });

  it('stamps decision time as ts and keeps the hold time as heldAtTs', async () => {
    const h = makeHarness();
    const card = await holdCard(h, 'sess-A');
    const heldTs = new Date().toISOString();
    await new Promise((r) => setTimeout(r, 10));

    card.decisionAudit!('approved_once');

    const decision = h.captured[h.captured.length - 1];
    expect(typeof decision!.heldAtTs).toBe('string');
    expect(decision!.heldAtTs! <= heldTs).toBe(true);
    expect(decision!.ts > decision!.heldAtTs!).toBe(true);
  });

  it('the writer refuses an outcome outside the card union at runtime', async () => {
    const h = makeHarness();
    const card = await holdCard(h, 'sess-A');
    const rowsBefore = h.captured.length;

    (card.decisionAudit as unknown as (o: string) => void)('failure_allowed');
    (card.decisionAudit as unknown as (o: string) => void)('constructor');
    expect(h.captured.length).toBe(rowsBefore);

    // The junk attempts must not have eaten the one-shot latch.
    card.decisionAudit!('card_denied');
    expect(h.captured[h.captured.length - 1]).toMatchObject({ outcome: 'card_denied' });
  });

  it('indexes the decision row into the session guard (#260 can see it)', async () => {
    const h = makeHarness();
    const card = await holdCard(h, 'sess-index');

    card.decisionAudit!('card_denied');

    expect(h.indexed).toHaveLength(1);
    expect(h.indexed[0]).toMatchObject({
      outcome: 'card_denied',
      origin: 'openclaw-interceptor',
      sessionKey: 'sc-sess-index',
    });
  });

  it('is one-shot: a second resolution writes nothing', async () => {
    const h = makeHarness();
    const card = await holdCard(h, 'sess-double');

    card.decisionAudit!('approved_once');
    card.decisionAudit!('card_denied');
    card.decisionAudit!('approved_once');

    expect(h.captured).toHaveLength(1);
    expect(h.indexed).toHaveLength(1);
    expect(h.captured[0]!.outcome).toBe('approved_once');
  });

  it('a throwing session-key resolver costs the row its key, never the card', async () => {
    const h = makeHarness({ keyFor: () => { throw new Error('salt unreadable'); } });
    const card = await holdCard(h, 'sess-nokey');

    expect(typeof card.decisionAudit).toBe('function');
    card.decisionAudit!('approved_once');

    expect(h.captured).toHaveLength(1);
    expect(h.captured[0]!.sessionKey).toBeUndefined();
  });

  it('writes the decision to the audit jsonl, same sink as every other row', async () => {
    const previous = process.env.SHIELDCORTEX_AUDIT_DIR;
    const dir = mkdtempSync(join(tmpdir(), 'sc-372-sink-'));
    process.env.SHIELDCORTEX_AUDIT_DIR = dir;
    try {
      const h = makeHarness();
      const card = await holdCard(h, 'sess-sink');
      expect(readdirSync(dir).filter((f) => /^realtime-.*\.jsonl$/.test(f))).toHaveLength(0);

      card.decisionAudit!('approved_once');

      const rows = readdirSync(dir)
        .filter((f) => /^realtime-.*\.jsonl$/.test(f))
        .flatMap((f) => readFileSync(join(dir, f), 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)));
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({ type: 'intercept', action: 'require_approval', outcome: 'approved_once' });
    } finally {
      if (previous === undefined) delete process.env.SHIELDCORTEX_AUDIT_DIR;
      else process.env.SHIELDCORTEX_AUDIT_DIR = previous;
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ==================== 2. Plugin bridge: onResolution wiring ====================

describe('#372 plugin — the host decision reaches the audit stream', () => {
  const originalAuditDir = process.env.SHIELDCORTEX_AUDIT_DIR;
  let auditDir = '';
  let warnings: string[] = [];

  type Hooks = Record<string, (...args: any[]) => any>;

  function makeApi(config: unknown = {}): { api: any; hooks: Hooks } {
    const hooks: Hooks = {};
    const api = {
      id: 'shieldcortex-realtime',
      name: 'ShieldCortex Real-time Scanner',
      logger: { info: () => {}, warn: (m: string) => { warnings.push(m); } },
      on: (name: string, handler: (...args: any[]) => any) => { hooks[name] = handler; },
      registerCommand: () => {},
      runtime: { config: { current: () => ({ plugins: { entries: { 'shieldcortex-realtime': { enabled: true, config } } } }) } },
    };
    return { api, hooks };
  }

  function auditRows(): Array<Record<string, unknown>> {
    return readdirSync(auditDir)
      .filter((f) => /^realtime-.*\.jsonl$/.test(f))
      .flatMap((f) => readFileSync(join(auditDir, f), 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)));
  }

  function stubDefence(extra: Record<string, unknown> = {}) {
    __setDefenceModuleForTest({ runDefencePipeline: okPipeline, evaluateToolCall, ...extra } as never);
  }

  beforeEach(() => {
    auditDir = mkdtempSync(join(tmpdir(), 'sc-372-plug-'));
    process.env.SHIELDCORTEX_AUDIT_DIR = auditDir;
    warnings = [];
    __resetConfigStateForTest();
    __setRuntimeForTest({
      callCortex: async () => null,
      isOpenClawAutoMemoryEnabled: () => false,
      loadShieldConfig: async () => ({}),
    } as never);
    stubDefence();
  });

  afterEach(() => {
    __setDefenceModuleForTest(undefined);
    __setRuntimeForTest(null);
    __resetConfigStateForTest();
    if (originalAuditDir === undefined) delete process.env.SHIELDCORTEX_AUDIT_DIR;
    else process.env.SHIELDCORTEX_AUDIT_DIR = originalAuditDir;
    try { rmSync(auditDir, { recursive: true, force: true }); } catch { /* best effort */ }
  });

  /** Attended session → a real card comes back from the typed hook. */
  async function holdCard(hooks: Hooks, sessionId = 'agent:main:chat:372'): Promise<any> {
    const result = await hooks.before_tool_call(
      { toolName: 'Bash', params: { command: DANGEROUS_COMMAND } },
      { sessionId },
    );
    expect(result?.requireApproval).toBeDefined();
    return result.requireApproval;
  }

  it.each([
    ['allow-once', 'approved_once'],
    ['allow-always', 'approved_once'],
    ['deny', 'card_denied'],
    ['timeout', 'card_timeout'],
    ['cancelled', 'card_cancelled'],
  ])('resolving a card with %s writes outcome %s', async (decision, outcome) => {
    const { api, hooks } = makeApi();
    plugin.register(api);
    const request = await holdCard(hooks);

    expect(auditRows()).toHaveLength(0);
    expect(typeof request.onResolution).toBe('function');
    await request.onResolution(decision);

    const rows = auditRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      type: 'intercept',
      tool: 'Bash',
      action: 'require_approval',
      outcome,
      origin: 'openclaw-interceptor',
    });
  });

  it('a card the host resolves twice still yields one row', async () => {
    const { api, hooks } = makeApi();
    plugin.register(api);
    const request = await holdCard(hooks);

    await request.onResolution('allow-once');
    await request.onResolution('deny');

    expect(auditRows()).toHaveLength(1);
    expect(auditRows()[0]).toMatchObject({ outcome: 'approved_once' });
  });

  it('a decision this build does not know writes nothing and says so', async () => {
    const { api, hooks } = makeApi();
    plugin.register(api);
    const request = await holdCard(hooks);

    // The host awaits this callback; it resolves rather than rejecting.
    expect(() => request.onResolution('allow-for-an-hour')).not.toThrow();

    // Inventing an outcome would forge the operator's answer, so: no row.
    expect(auditRows()).toHaveLength(0);
    expect(warnings.some((w) => /unrecognised approval decision 'allow-for-an-hour'/.test(w))).toBe(true);
  });

  it('an unknown decision reaches the gateway log as a label, not as free text', async () => {
    const { api, hooks } = makeApi();
    plugin.register(api);
    const request = await holdCard(hooks);

    expect(() => request.onResolution('deny\n[shieldcortex] action-guard ALLOWED everything')).not.toThrow();

    expect(auditRows()).toHaveLength(0);
    const warned = warnings.find((w) => /unrecognised approval decision/.test(w));
    expect(warned).toBeDefined();
    expect(warned).not.toContain('\n');
    expect(warned).not.toContain('ALLOWED everything');
  });

  it('a failing audit write never throws into the host', async () => {
    // #224 binding is the one step in the write path that can throw on the
    // host's callback. The operator already decided; that must stand.
    stubDefence({
      attachEnforcementBinding: () => { throw new Error('binding ledger unwritable'); },
    });
    const { api, hooks } = makeApi();
    plugin.register(api);
    const request = await holdCard(hooks);

    expect(() => request.onResolution('allow-once')).not.toThrow();

    // The closure now contains the failure itself (review hardening): the row
    // is lost, the host sees nothing, and the bridge's own failure warn is the
    // backstop for throws ABOVE the closure, not inside it.
    expect(auditRows()).toHaveLength(0);
  });

  it('the memory-write pipeline card also writes a decision row (#372 second site)', async () => {
    // The memory-write pipeline mints cards too; its operator decision must
    // leave the same audit row as the action-guard lane.
    const quarantinePipeline = () => ({
      allowed: false,
      firewall: { result: 'QUARANTINE' as const, reason: 'suspicious', threatIndicators: ['injection'], anomalyScore: 0.7, blockedPatterns: [] as string[] },
      trust: { score: 0.2 },
      sensitivity: { level: 'INTERNAL' },
      fragmentation: null,
      auditId: 2,
    });
    stubDefence({ runDefencePipeline: quarantinePipeline });
    const { api, hooks } = makeApi({ interceptor: { severityActions: { high: 'require_approval' } } });
    plugin.register(api);

    const result = await hooks.before_tool_call(
      { toolName: 'remember', params: { title: 'note', content: 'remember this for later' } },
      { sessionId: 'agent:main:chat:372' },
    );

    expect(result?.requireApproval).toBeDefined();
    expect(result.requireApproval.onResolution).toBeDefined();
    expect(auditRows()).toHaveLength(0);

    await result.requireApproval.onResolution('allow-once');
    const rows = auditRows();
    expect(rows).toHaveLength(1);
    expect(rows[0].action).toBe('require_approval');
    expect(rows[0].outcome).toBe('approved_once');
    expect(rows[0].tool).toBe('remember');
    expect(rows[0].origin).toBe('openclaw-interceptor');
  });

  it('refused card outcomes count as guard degradation; approved_once does not (#260 parity)', () => {
    expect(GUARD_DEGRADED_OUTCOMES.has('card_denied')).toBe(true);
    expect(GUARD_DEGRADED_OUTCOMES.has('card_timeout')).toBe(true);
    expect(GUARD_DEGRADED_OUTCOMES.has('card_cancelled')).toBe(true);
    expect(GUARD_DEGRADED_OUTCOMES.has('approved_once')).toBe(false);
  });
});
