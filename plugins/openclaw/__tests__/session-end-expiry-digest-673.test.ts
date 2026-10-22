import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { appendFileSync, existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { buildApprovalExpiryDigest, EXPIRY_DIGEST_FOOTER } from '../../../src/defence/iron-dome/expiry-digest.js';
import { normaliseNotifyConfig } from '../../../src/defence/iron-dome/notify-config.js';
import {
  APPROVAL_EXPIRY_DIGEST_REASON,
  buildActionGuardOutcomeNotification,
  deliverOperatorNotification,
  type AnyOperatorNotification,
  type NotifyChannel,
} from '../../../src/defence/iron-dome/operator-notify.js';
import {
  appendExpiryDigestRecord,
  appendSessionGuardIndex,
  readSessionGuardIndexBounded,
  recordActionGuardDegraded,
  sessionKeyFor,
} from '../../../src/defence/iron-dome/session-guard.js';
import { createWebhookNotifyChannel } from '../../../src/defence/iron-dome/webhook-notify-channel.js';
import plugin, {
  INSPECTED_BLOCKING_HOSTS,
  __deliverExpiryDigestForTest,
  __resetConfigStateForTest,
  __setDefenceModuleForTest,
  __setGatewayNotifyContextForTest,
  __setRuntimeForTest,
} from '../index.js';

/**
 * #673 — session_end sends ONE reporting-only digest of a host session's
 * recorded `card_timeout` outcomes to the ONE configured webhook. Every case
 * runs against a temp audit root and a fake webhook receiver (no network, no
 * live config) and inspects the RECEIVED body: text and structured fields.
 */

const SALT = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const WEBHOOK = { enabled: true, webhookUrl: 'https://example.invalid/hook' };

type Deps = NonNullable<Parameters<typeof __deliverExpiryDigestForTest>[2]>;
type Mod = NonNullable<Deps['mod']>;

let auditDir = '';
let posts: Array<Record<string, unknown>> = [];
let respond: () => Promise<Response> = async () => new Response('', { status: 200 });

const fetchImpl: typeof fetch = async (_input, init) => {
  posts.push(JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>);
  return respond();
};

const keyOf = (id: string) => sessionKeyFor(id, { salt: SALT }) as string;

/** The module surface the plugin reaches through `shieldcortex/defence`,
 *  bound to the real implementations; only the webhook fetch is faked. */
function makeMod(over: Partial<Mod> = {}): Mod {
  return {
    sessionKeyFor: (id) => sessionKeyFor(id, { salt: SALT }),
    readSessionGuardIndexBounded: (key) => readSessionGuardIndexBounded(key),
    buildApprovalExpiryDigest: (read, opts) => buildApprovalExpiryDigest(read, opts),
    appendExpiryDigestRecord: (key, record) => appendExpiryDigestRecord(key, record),
    appendSessionGuardIndex: ({ entry }) => appendSessionGuardIndex({ entry }),
    recordActionGuardDegraded: (id, opts) => recordActionGuardDegraded(id, { salt: SALT, origin: opts?.origin }),
    normaliseNotifyConfig: (raw) => normaliseNotifyConfig(raw),
    createWebhookNotifyChannel: (opts) => createWebhookNotifyChannel({ ...opts, fetchImpl }) as ReturnType<NonNullable<Mod['createWebhookNotifyChannel']>>,
    buildActionGuardOutcomeNotification: (input) => ({
      ...buildActionGuardOutcomeNotification({
        event: input.event === 'action_guard_denial' ? 'action_guard_denial' : 'action_guard_warning',
        outcome: String(input.outcome),
        tool: String(input.tool),
        surface: String(input.surface),
        signals: Array.isArray(input.signals) ? input.signals.map(String) : [],
        severity: String(input.severity),
        reason: String(input.reason),
        sessionId: String(input.sessionId),
        origin: String(input.origin),
        detectedAt: String(input.detectedAt),
      }),
    }),
    // The plugin's module boundary is untyped (`unknown` in, plain channel
    // shape out) exactly as at runtime; the real core does the rest.
    deliverOperatorNotification: (n, deps) =>
      deliverOperatorNotification(n as AnyOperatorNotification, { ...deps, channels: deps.channels as NotifyChannel[] }),
    ...over,
  };
}

function timeoutRow(sessionId: string, i: number, over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    type: 'intercept',
    origin: 'openclaw-interceptor',
    action: 'require_approval',
    outcome: 'card_timeout',
    sessionKey: keyOf(sessionId),
    tool: 'Bash',
    severity: 'dangerous',
    threats: ['dangerous-shell'],
    heldAtTs: '2026-10-11T12:00:00.000Z',
    ts: `2026-10-11T12:01:${String(i % 60).padStart(2, '0')}.000Z`,
    nonce: (i + 1).toString(16).padStart(32, '0'),
    preview: 'SECRET_PREVIEW_673',
    ...over,
  };
}

function seed(sessionId: string, n: number, from = 0, over: Record<string, unknown> = {}): void {
  for (let i = from; i < from + n; i += 1) {
    expect(appendSessionGuardIndex({ entry: timeoutRow(sessionId, i, over) })).toBe(true);
  }
}

function indexRows(sessionId: string): Array<Record<string, unknown>> {
  const file = join(auditDir, 'session-guard', `${keyOf(sessionId)}.jsonl`);
  if (!existsSync(file)) return [];
  return readFileSync(file, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l) as Record<string, unknown>);
}

const digestRows = (sessionId: string) => indexRows(sessionId).filter((r) => r.recordKind === 'digest');
const entryLines = (body: Record<string, unknown>) => String(body.text).split('\n').filter((l) => l.startsWith('• '));

function run(sessionId: string, deps: Partial<Deps> = {}, ctx: { sessionId?: string } = { sessionId }) {
  return __deliverExpiryDigestForTest({ sessionId }, ctx, { mod: makeMod(), rawNotify: WEBHOOK, hostVersion: null, ...deps });
}

const originalAuditDir = process.env.SHIELDCORTEX_AUDIT_DIR;
const originalSalt = process.env.SHIELDCORTEX_SESSION_SALT;

beforeEach(() => {
  auditDir = mkdtempSync(join(tmpdir(), 'sc-673-plug-'));
  process.env.SHIELDCORTEX_AUDIT_DIR = auditDir;
  process.env.SHIELDCORTEX_SESSION_SALT = SALT;
  posts = [];
  respond = async () => new Response('', { status: 200 });
  __resetConfigStateForTest();
});

afterEach(() => {
  __setDefenceModuleForTest(undefined);
  __setRuntimeForTest(null);
  __resetConfigStateForTest();
  if (originalAuditDir === undefined) delete process.env.SHIELDCORTEX_AUDIT_DIR;
  else process.env.SHIELDCORTEX_AUDIT_DIR = originalAuditDir;
  if (originalSalt === undefined) delete process.env.SHIELDCORTEX_SESSION_SALT;
  else process.env.SHIELDCORTEX_SESSION_SALT = originalSalt;
  rmSync(auditDir, { recursive: true, force: true });
});

describe('#673 one digest per host session', () => {
  it('N=7: exactly one POST with 7 entries, owned outcome/reason, no approval fields; attempt then delivered receipt', async () => {
    seed('s-seven', 7);
    await run('s-seven');
    expect(posts).toHaveLength(1);
    const body = posts[0];
    expect(entryLines(body)).toHaveLength(7);
    expect(body).toMatchObject({ outcome: 'approval_expiry_digest', reason: APPROVAL_EXPIRY_DIGEST_REASON, sessionId: keyOf('s-seven') });
    for (const field of ['hash', 'shortHash', 'approveCommand', 'denyCommand', 'command', 'attemptId']) expect(body).not.toHaveProperty(field);
    expect(JSON.stringify(body)).not.toContain('SECRET_PREVIEW_673');
    expect(String(body.text).endsWith(EXPIRY_DIGEST_FOOTER)).toBe(true);
    expect(digestRows('s-seven').map((r) => [r.phase, r.status])).toEqual([['attempt', undefined], ['receipt', 'delivered']]);
  });

  it('interleaved sessions A and B each get only their own entries', async () => {
    seed('s-a', 2);
    seed('s-b', 3, 10);
    seed('s-a', 1, 20);
    await run('s-a');
    await run('s-b');
    expect(posts).toHaveLength(2);
    expect(posts[0].sessionId).toBe(keyOf('s-a'));
    expect(entryLines(posts[0])).toHaveLength(3);
    expect(posts[1].sessionId).toBe(keyOf('s-b'));
    expect(entryLines(posts[1])).toHaveLength(3);
  });

  it('a reused session sends no second digest; later timeouts are not covered', async () => {
    seed('s-reuse', 2);
    await run('s-reuse');
    seed('s-reuse', 4, 10);
    await run('s-reuse');
    expect(posts).toHaveLength(1);
    expect(entryLines(posts[0])).toHaveLength(2);
  });

  it('an old #260 summary with no digest row does not suppress the digest', async () => {
    seed('s-summary', 2);
    recordActionGuardDegraded('s-summary', { salt: SALT });
    await run('s-summary');
    expect(posts).toHaveLength(1);
  });

  it('zero recorded timeouts writes nothing and sends nothing', async () => {
    seed('s-none', 2, 0, { outcome: 'card_denied' });
    seed('s-none', 1, 5, { outcome: 'card_cancelled' });
    // approved_once is not degraded, so the index never holds it; written
    // raw here to prove the digest would not count it if it did.
    appendFileSync(join(auditDir, 'session-guard', `${keyOf('s-none')}.jsonl`), `${JSON.stringify({ recordKind: 'guard', ...timeoutRow('s-none', 9, { outcome: 'approved_once' }) })}\n`);
    await run('s-none');
    expect(posts).toHaveLength(0);
    expect(digestRows('s-none')).toHaveLength(0);
  });
});

describe('#673 duplicate, concurrent and pre-attempted callbacks', () => {
  it('two synchronous session_end calls make one POST; a later call after the receipt makes none', async () => {
    seed('s-dup', 3);
    await Promise.all([run('s-dup'), run('s-dup')]);
    expect(posts).toHaveLength(1);
    await run('s-dup');
    expect(posts).toHaveLength(1);
  });

  it('a pre-existing attempt with no receipt sends nothing and claims no delivery', async () => {
    seed('s-unknown', 2);
    appendExpiryDigestRecord(keyOf('s-unknown'), { digestId: 'f'.repeat(32), phase: 'attempt', observed: 2, rendered: 2, complete: true, transport: 'webhook' });
    await run('s-unknown');
    expect(posts).toHaveLength(0);
    expect(digestRows('s-unknown').some((r) => r.status === 'delivered')).toBe(false);
  });
});

describe('#673 identity', () => {
  it('conflicting event and ctx session ids send nothing', async () => {
    seed('s-x', 2);
    seed('s-y', 2);
    const err = jest.spyOn(console, 'error').mockImplementation(() => {});
    await __deliverExpiryDigestForTest({ sessionId: 's-x' }, { sessionId: 's-y' }, { mod: makeMod(), rawNotify: WEBHOOK, hostVersion: null });
    expect(posts).toHaveLength(0);
    expect(err.mock.calls.map((c) => String(c[0]))).toContain('[shieldcortex] expiry digest skipped: conflicting session identity');
    err.mockRestore();
  });

  it('blank or missing identity sends nothing', async () => {
    seed('s-blank', 2);
    await __deliverExpiryDigestForTest({ sessionId: '   ' }, { sessionId: '' }, { mod: makeMod(), rawNotify: WEBHOOK, hostVersion: null });
    await __deliverExpiryDigestForTest(undefined, undefined, { mod: makeMod(), rawNotify: WEBHOOK, hostVersion: null });
    expect(posts).toHaveLength(0);
  });

  it('an untrimmed id resolves to the key the interceptor stamped', async () => {
    seed('s-trim', 2);
    await __deliverExpiryDigestForTest({ sessionId: '  s-trim  ' }, { sessionId: 's-trim' }, { mod: makeMod(), rawNotify: WEBHOOK, hostVersion: null });
    expect(posts).toHaveLength(1);
    expect(posts[0].sessionId).toBe(keyOf('s-trim'));
  });
});

describe('#673 transport and failures', () => {
  it.each([
    ['notify disabled', { enabled: false, webhookUrl: 'https://example.invalid/hook' }],
    ['no webhook', { enabled: true }],
    ['no notify config', undefined],
  ])('%s → local_only and 0 sends', async (_label, rawNotify) => {
    seed('s-local', 2);
    await run('s-local', { rawNotify });
    expect(posts).toHaveLength(0);
    expect(digestRows('s-local').map((r) => [r.phase, r.transport])).toEqual([['local_only', null]]);
  });

  it.each([['torn fragment', '{'], ['valid object', JSON.stringify({ note: 'last row' })]])(
    'B2 local_only after an unterminated %s stays suppressed when webhook is later enabled', async (_label, tail) => {
      const sessionId = 's-local-tail';
      seed(sessionId, 2);
      expect(recordActionGuardDegraded(sessionId, { salt: SALT }).recorded).toBe(true);
      const file = join(auditDir, 'session-guard', `${keyOf(sessionId)}.jsonl`);
      appendFileSync(file, tail);
      await run(sessionId, { rawNotify: { enabled: false } });
      expect(posts).toHaveLength(0);
      const first = readSessionGuardIndexBounded(keyOf(sessionId));
      expect(first.rows.filter((r) => r.recordKind === 'digest').map((r) => r.phase)).toEqual(['local_only']);
      // Prove suppression comes from the on-disk marker, not process state.
      __resetConfigStateForTest();
      await run(sessionId, { rawNotify: WEBHOOK });
      expect(posts).toHaveLength(0);
      expect(readSessionGuardIndexBounded(keyOf(sessionId)).rows.filter((r) => r.recordKind === 'digest'))
        .toEqual(first.rows.filter((r) => r.recordKind === 'digest'));
    },
  );

  it('a module without the notify transport → local_only and 0 sends', async () => {
    seed('s-oldmod', 2);
    await run('s-oldmod', { mod: makeMod({ deliverOperatorNotification: undefined }) });
    expect(posts).toHaveLength(0);
    expect(digestRows('s-oldmod').map((r) => r.phase)).toEqual(['local_only']);
  });

  it('a module without the digest members does nothing at all', async () => {
    seed('s-nodigest', 2);
    await run('s-nodigest', { mod: makeMod({ buildApprovalExpiryDigest: undefined }) });
    await run('s-nodigest', { mod: null });
    expect(posts).toHaveLength(0);
    expect(digestRows('s-nodigest')).toHaveLength(0);
  });

  it.each([
    ['500', () => Promise.resolve(new Response('', { status: 500 }))],
    ['throw', () => Promise.reject(new Error('socket hang up https://secret.invalid'))],
  ])('webhook %s → receipt failed, no retry, nothing else called', async (_label, impl) => {
    seed('s-fail', 2);
    respond = impl;
    const err = jest.spyOn(console, 'error').mockImplementation(() => {});
    await run('s-fail');
    err.mockRestore();
    expect(posts).toHaveLength(1);
    const rows = digestRows('s-fail');
    expect(rows.map((r) => [r.phase, r.status])).toEqual([['attempt', undefined], ['receipt', 'failed']]);
    expect(JSON.stringify(rows)).not.toContain('secret.invalid');
  });

  it('a malformed delivery result → receipt failed', async () => {
    seed('s-malformed', 2);
    const err = jest.spyOn(console, 'error').mockImplementation(() => {});
    await run('s-malformed', { mod: makeMod({ deliverOperatorNotification: async () => ({ deliveredVia: 'gateway', attempts: [] }) }) });
    err.mockRestore();
    expect(digestRows('s-malformed').map((r) => r.status)).toEqual([undefined, 'failed']);
  });

  it('a hang past the timeout → receipt failed (ambiguous: may still arrive late)', async () => {
    seed('s-hang', 2);
    respond = () => new Promise<Response>(() => { /* never answers */ });
    const err = jest.spyOn(console, 'error').mockImplementation(() => {});
    await run('s-hang', { rawNotify: { ...WEBHOOK, timeoutMs: 500 } });
    expect(err.mock.calls.map((c) => String(c[0])).some((l) => l.includes('may still arrive late'))).toBe(true);
    err.mockRestore();
    expect(digestRows('s-hang').map((r) => r.status)).toEqual([undefined, 'failed']);
  });

  it('a failed attempt append means no send', async () => {
    seed('s-noattempt', 2);
    await run('s-noattempt', { mod: makeMod({ appendExpiryDigestRecord: () => false }) });
    expect(posts).toHaveLength(0);
  });

  it('a failed receipt append leaves the attempt only (completion unknown)', async () => {
    seed('s-noreceipt', 2);
    const append = (key: string, record: Parameters<NonNullable<Mod['appendExpiryDigestRecord']>>[1]) =>
      record.phase === 'receipt' ? false : appendExpiryDigestRecord(key, record);
    await run('s-noreceipt', { mod: makeMod({ appendExpiryDigestRecord: append }) });
    expect(posts).toHaveLength(1);
    expect(digestRows('s-noreceipt').map((r) => r.phase)).toEqual(['attempt']);
  });

  it('with a gateway context and a webhook both set, the gateway is never called', async () => {
    seed('s-gw', 2);
    const notifyOperator = jest.fn(async () => true);
    __setGatewayNotifyContextForTest({ notifyOperator });
    await run('s-gw', { rawNotify: { ...WEBHOOK, openclaw: true } });
    expect(notifyOperator).not.toHaveBeenCalled();
    expect(posts).toHaveLength(1);
  });
});

describe('#673 host version — the complete received notification', () => {
  it('ships with an empty inspected-blocking-host set (no pinned host-contract fixture yet)', () => {
    expect(INSPECTED_BLOCKING_HOSTS.size).toBe(0);
  });

  it.each([['2026.9.6'], ['2026.10.1'], ['2026.5.2'], [null], ['2026.9.6 <script>']])(
    'version %s: N=25, whole footer, and no blocked/skipped claim anywhere',
    async (hostVersion) => {
      seed('s-host', 25);
      await run('s-host', { hostVersion });
      expect(posts).toHaveLength(1);
      const body = posts[0];
      const text = String(body.text);
      expect(text.endsWith(EXPIRY_DIGEST_FOOTER)).toBe(true);
      expect(text).toContain('+15 more recorded in this scan');
      expect(text.length).toBeLessThanOrEqual(4_000);
      const structured = [String(body.outcome), String(body.reason)];
      for (const s of [text, ...structured]) {
        for (const phrase of ['OpenClaw blocked this tool call', '(skipped)', 'was blocked', 'were blocked', 'was skipped', 'were skipped']) {
          expect(s).not.toContain(phrase);
        }
      }
      const stripped = text
        .replace(/Approval timed out\/unresolved; ShieldCortex granted nothing\. Whether this OpenClaw version \([^)]*\) blocked the call has not been verified by ShieldCortex\./g, '')
        .replace(/— why: [^\n]*?\. (?=\n|$)/g, '— ');
      for (const s of [stripped, ...structured]) {
        expect(s).not.toMatch(/block/i);
        expect(s).not.toMatch(/skip/i);
      }
      if (hostVersion === '2026.9.6 <script>') expect(text).toContain('OpenClaw version (unknown)');
    },
  );
});

describe('#673 session_end wiring', () => {
  function makeApi() {
    const hooks: Record<string, (...args: unknown[]) => unknown> = {};
    const api = {
      id: 'shieldcortex-realtime',
      name: 'ShieldCortex Real-time Scanner',
      logger: { info: () => {}, warn: () => {} },
      on: (name: string, handler: (...args: unknown[]) => unknown) => { hooks[name] = handler; },
      registerCommand: () => {},
      runtime: { config: { current: () => ({ plugins: { entries: { 'shieldcortex-realtime': { enabled: true, config: { interceptor: { actionGuard: { enabled: true } } } } } } }) } },
    };
    return { api, hooks };
  }

  async function waitForDigest(sessionId: string): Promise<Array<Record<string, unknown>>> {
    const deadline = Date.now() + 3_000;
    while (Date.now() < deadline) {
      const rows = digestRows(sessionId);
      if (rows.length > 0) return rows;
      await new Promise((r) => setTimeout(r, 20));
    }
    return digestRows(sessionId);
  }

  beforeEach(() => {
    __setRuntimeForTest({
      callCortex: async () => null,
      isOpenClawAutoMemoryEnabled: () => false,
      loadShieldConfig: async () => ({}),
    } as never);
  });

  it('session_end returns synchronously and the digest follows; agent_end alone sends nothing', async () => {
    __setDefenceModuleForTest(makeMod() as never);
    const { api, hooks } = makeApi();
    plugin.register(api as never);
    const sessionId = 's-wired';

    // Early agent_end with nothing recorded: a zero-timeout run, no digest.
    hooks.agent_end({ sessionId }, { sessionId });
    seed(sessionId, 3);
    hooks.agent_end({ sessionId }, { sessionId });
    await new Promise((r) => setTimeout(r, 50));
    expect(digestRows(sessionId)).toHaveLength(0);

    const returned = hooks.session_end({ sessionId }, { sessionId });
    expect(returned).toBeUndefined();
    const rows = await waitForDigest(sessionId);
    // No notify configured in this host config → assembled, kept local.
    expect(rows.map((r) => [r.phase, r.observed])).toEqual([['local_only', 3]]);
    expect(posts).toHaveLength(0);
  });

  it('an earlier agent_end summary does not suppress the later digest', async () => {
    __setDefenceModuleForTest(makeMod() as never);
    const { api, hooks } = makeApi();
    plugin.register(api as never);
    const sessionId = 's-early-summary';
    seed(sessionId, 1, 0, { outcome: 'card_denied' });
    hooks.agent_end({ sessionId }, { sessionId });
    expect(indexRows(sessionId).some((r) => r.outcome === 'action_guard_degraded')).toBe(true);
    seed(sessionId, 2, 10);
    hooks.session_end({ sessionId }, { sessionId });
    const rows = await waitForDigest(sessionId);
    expect(rows.map((r) => r.observed)).toEqual([2]);
  });
});
