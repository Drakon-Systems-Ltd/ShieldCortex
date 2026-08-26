/**
 * Inject pack v2 unit tests (Memory SOTA Track B).
 * Pure module — no DB, no network.
 */
import { describe, expect, it } from '@jest/globals';
import {
  INJECT_CEILINGS,
  NATIVE_INJECT_CONTRACT,
  buildStartPack,
  clampBudgets,
  contentHash,
  contentHashPreimage,
  estimateTokens,
  isInjectEligible,
  normalizeInjectMode,
  normalizeNativeContract,
  readInjectConfig,
  toPackItem,
} from '../../../scripts/lib/inject-pack.mjs';

function row(partial) {
  return {
    id: 1,
    title: 'Decision',
    content: 'Use inject pack v2 with hard ceilings.',
    salience: 0.8,
    trust_score: 0.9,
    sensitivity_level: 'INTERNAL',
    status: 'active',
    host_id: 'tars',
    agent_id: 'hermes',
    project: 'ShieldCortex',
    source: 'test',
    pinned: false,
    // #402: a properly-stamped modern fact row. The two-key inject gate now
    // requires the form key too; these provenance-key tests supply a clean
    // 'fact' stamp so they exercise the trust/scope key in isolation. The form
    // key itself is covered by inject-two-key-402.test.ts.
    content_form: 'fact',
    ...partial,
  };
}

const scope = { hostId: 'tars', agentId: 'hermes', project: 'ShieldCortex' };
const baseOpts = {
  mode: 'start',
  nativeContract: NATIVE_INJECT_CONTRACT.SC_ONLY,
  scope,
};

describe('inject-pack v2', () => {
  it('defaults mode to start and rejects bad native contract', () => {
    expect(normalizeInjectMode(undefined)).toBe('start');
    expect(normalizeInjectMode('both')).toBe('both');
    expect(normalizeNativeContract('coexist_dedup')).toBeNull();
    expect(normalizeNativeContract('sc_only')).toBe('sc_only');
  });

  it('clamps budgets to absolute ceilings', () => {
    const c = clampBudgets('start', { tokens: 99999, rows: 99, perRowTokens: 500 });
    expect(c.tokens).toBe(INJECT_CEILINGS.start.hardMaxTokens);
    expect(c.rows).toBe(INJECT_CEILINGS.start.hardMaxRows);
    expect(c.perRowTokens).toBe(INJECT_CEILINGS.start.maxPerRowTokens);
  });

  it('hash preimage ignores age/trust so rehydrate identity is stable', () => {
    const a = contentHashPreimage({ id: 1, title: 'T', fact: 'F' });
    const b = contentHashPreimage({ id: 1, title: 'T', content: 'F' });
    expect(a).toBe(b);
    expect(contentHash(a)).toMatch(/^[0-9a-f]{8}$/);
  });

  it('rejects unscoped, RESTRICTED, quarantine, low trust', () => {
    expect(isInjectEligible(row({ host_id: null }), scope)).toBe(false);
    expect(isInjectEligible(row({ agent_id: '' }), scope)).toBe(false);
    expect(isInjectEligible(row({ sensitivity_level: 'RESTRICTED' }), scope)).toBe(false);
    expect(isInjectEligible(row({ quarantined: true }), scope)).toBe(false);
    expect(isInjectEligible(row({ trust_score: 0.1, source_attested: false }), scope)).toBe(false);
    expect(isInjectEligible(row(), scope)).toBe(true);
  });

  it('attestation alone does not bypass trust floor (Opus B1 / #348)', () => {
    expect(isInjectEligible(row({
      trust_score: 0.2,
      source_attested: true,
      pinned: false,
    }), scope)).toBe(false);
  });

  it('attested+pinned still requires trust floor', () => {
    expect(isInjectEligible(row({
      trust_score: 0.2,
      source_attested: true,
      pinned: true,
    }), scope)).toBe(false);
    expect(isInjectEligible(row({
      trust_score: 0.6,
      source_attested: true,
      pinned: true,
    }), scope)).toBe(true);
  });

  it('unverified defence_verdict never injects', () => {
    const r = row({ defence_verdict: 'unverified', source_attested: false });
    delete r.trust_score;
    expect(isInjectEligible(r, scope)).toBe(false);
    // even with high trust_score, unverified is hard reject
    expect(isInjectEligible(row({
      trust_score: 0.95,
      defence_verdict: 'unverified',
    }), scope)).toBe(false);
  });

  it('requireScope defaults true; unscoped rejected even if other rows scoped', () => {
    expect(isInjectEligible(row({ host_id: null, agent_id: null }), { requireScope: true })).toBe(false);
    expect(isInjectEligible(row({ host_id: null, agent_id: null }), {})).toBe(false);
  });

  it('clamps pack item salience to 0.7', () => {
    const item = toPackItem(row({ salience: 1.0 }), { perRowTokens: 80 });
    expect(item.salience).toBeLessThanOrEqual(0.7);
  });

  it('builds empty pack when store empty or contract missing', () => {
    const a = buildStartPack([], baseOpts);
    expect(a.items).toEqual([]);
    expect(a.skipped).toBe('empty-or-ineligible');

    const b = buildStartPack([row()], { ...baseOpts, nativeContract: null });
    expect(b.skipped).toBe('missing-native-contract');
    expect(b.text).toBe('');
  });

  it('builds fact-only pack under row/token ceilings (no why field)', () => {
    const rows = Array.from({ length: 20 }, (_, i) => row({
      id: i + 1,
      title: `T${i}`,
      content: `Fact number ${i} `.repeat(30),
      salience: 1 - i * 0.01,
    }));
    const pack = buildStartPack(rows, {
      ...baseOpts,
      budgets: { tokens: 600, rows: 6, perRowTokens: 100 },
    });
    expect(pack.items.length).toBeGreaterThan(0);
    expect(pack.items.length).toBeLessThanOrEqual(6);
    expect(pack.tokens).toBeLessThanOrEqual(600);
    for (const it of pack.items) {
      expect(it).not.toHaveProperty('why');
      expect(it.fact).toBeTruthy();
      expect(it.content_hash).toBeTruthy();
      expect(it.tokens).toBeLessThanOrEqual(100 + 5); // envelope slack
    }
    expect(pack.text).toContain('untrusted data');
    expect(pack.sessionState.pinnedPack.items.length).toBe(pack.items.length);
  });

  it('hash ring suppresses second start inject of same content', () => {
    const rows = [row({ id: 7 })];
    const first = buildStartPack(rows, baseOpts);
    expect(first.items).toHaveLength(1);
    const second = buildStartPack(rows, { ...baseOpts, sessionState: first.sessionState });
    expect(second.items).toHaveLength(0);
  });

  it('rehydrate requires compact signal and is budget-neutral', () => {
    const rows = [row({ id: 3, content: 'Pinned fact for rehydrate.' })];
    const first = buildStartPack(rows, baseOpts);
    const cum = first.sessionState.cumulativeTokens;
    const noSignal = buildStartPack(rows, {
      ...baseOpts,
      sessionState: first.sessionState,
      rehydrate: true,
      compactSignaled: false,
    });
    expect(noSignal.skipped).toBe('rehydrate-without-compact-signal');

    const reh = buildStartPack(rows, {
      ...baseOpts,
      sessionState: first.sessionState,
      rehydrate: true,
      compactSignaled: true,
    });
    expect(reh.items).toHaveLength(1);
    expect(reh.sessionState.cumulativeTokens).toBe(cum);
  });

  it('rehydrate drops rows that lose eligibility (no backfill)', () => {
    const good = row({ id: 1, content: 'keep' });
    const badLater = row({ id: 2, content: 'drop', salience: 0.99 });
    const first = buildStartPack([good, badLater], baseOpts);
    expect(first.items.length).toBeGreaterThanOrEqual(1);
    // live set: id 2 now RESTRICTED
    const live = [
      good,
      { ...badLater, sensitivity_level: 'RESTRICTED' },
    ];
    const reh = buildStartPack(live, {
      ...baseOpts,
      sessionState: first.sessionState,
      rehydrate: true,
      compactSignaled: true,
    });
    expect(reh.items.every((i) => String(i.id) !== '2')).toBe(true);
  });

  it('pins sort first but cannot exceed hard row max', () => {
    const rows = [
      row({ id: 1, pinned: false, salience: 1, content: 'high' }),
      row({ id: 2, pinned: true, salience: 0.1, content: 'pin' }),
    ];
    const pack = buildStartPack(rows, {
      ...baseOpts,
      budgets: { tokens: 800, rows: 1, perRowTokens: 100 },
    });
    expect(pack.items).toHaveLength(1);
    expect(String(pack.items[0].id)).toBe('2');
  });

  it('readInjectConfig surfaces plane and contract', () => {
    const cfg = readInjectConfig({
      memory: {
        plane: 'sc_canonical',
        inject: { mode: 'start', nativeContract: 'disable_native_inject', hostId: 'h', agentId: 'a' },
      },
    });
    expect(cfg.mode).toBe('start');
    expect(cfg.nativeContract).toBe('disable_native_inject');
    expect(cfg.hostId).toBe('h');
    expect(cfg.plane).toBe('sc_canonical');
  });

  it('estimateTokens uses chars/4', () => {
    expect(estimateTokens('abcd')).toBe(1);
    expect(estimateTokens('a'.repeat(8))).toBe(2);
  });

  it('toPackItem never includes why', () => {
    const item = toPackItem(row({ title: 'x', content: 'y' }), { perRowTokens: 50 });
    expect(Object.keys(item).sort()).toEqual(
      // #402: + content_form (fact-frame label). Still no why/rationale field.
      ['age', 'content_form', 'content_hash', 'fact', 'id', 'salience', 'source_ids', 'title', 'tokens', 'trust'].sort(),
    );
    expect(item).not.toHaveProperty('why');
  });
});
