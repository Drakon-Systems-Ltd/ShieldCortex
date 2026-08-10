import { describe, expect, it } from '@jest/globals';
import { reconcilePluginState, planReconcileActions, type PluginLoadState, type ReconcileInput } from '../integrations/openclaw-plugin-index.js';
import { renderPluginLoadVerdict } from '../cli/doctor.js';

/**
 * Issue #222 — doctor reported HEALTHY on a host whose plugin stanza had been
 * wiped by the #214 installer bug. Every unprotected verdict in
 * `reconcilePluginState` was gated behind `enabledInConfig`, and a wipe sets
 * that false, so the fault silenced the alarm built to catch it: three fail
 * rules skipped, fall through to `healthy`, doctor prints
 * "realtime plugin loaded (roster-confirmed)".
 *
 * Field evidence (EDITH, 2026-08-10): unattended 4.47.33 → 4.47.35 install
 * removed the entry and dropped it from plugins.allow; gateway restarted
 * without the plugin; ~1 hour with no memory firewall and no action guard,
 * green ticks throughout.
 *
 * Three things have to hold, and the third is the one that makes this a class
 * fix rather than another patch:
 *
 *   1. installed + stanza absent  ⇒ FAIL (unprotected, and nobody asked for it)
 *   2. installed + enabled:false  ⇒ NOT a fail (a deliberate opt-out is not damage)
 *      and an UNREADABLE config ⇒ NOT a confident fail (unknown ≠ unprotected)
 *   3. doctor's renderer cannot green-tick a state it does not recognise —
 *      the `default: status:'pass'` arm is exactly how a new reconciler state
 *      (including this one) silently reads as healthy.
 */

const PLUGIN_ID = 'shieldcortex-realtime';

function input(overrides: Partial<ReconcileInput> = {}): ReconcileInput {
  return {
    pluginId: PLUGIN_ID,
    expectedVersion: '4.47.36',
    // The wipe: entry deleted (enabled null) AND removed from plugins.allow.
    config: { enabled: null, inAllow: false, readable: true },
    installsJson: { version: '4.47.36', installPath: '/home/u/.openclaw/npm/projects/p/node_modules/x' },
    index: { installRecords: {}, plugins: [], warning: null },
    // The package is still on disk — the updater just installed it.
    onDiskVersion: '4.47.36',
    projectDirs: ['p'],
    liveRoster: null,
    ...overrides,
  } as ReconcileInput;
}

describe('#222 — a wiped stanza is a failure, not health', () => {
  it('FAILS when the package is installed but the stanza is gone', () => {
    const v = reconcilePluginState(input());
    expect(v.severity).toBe('fail');
    expect(v.state).toBe('installed-not-enabled');
  });

  it('says the host is unprotected, and does not claim it is enabled', () => {
    const v = reconcilePluginState(input());
    const reasons = v.reasons.join(' ').toLowerCase();
    expect(reasons).toMatch(/unprotected|not registered|not enabled/);
    // The old healthy verdict asserted "enabled, present on the running gateway
    // boot roster" — the one thing that is provably untrue after a wipe.
    expect(reasons).not.toMatch(/\benabled, present\b/);
  });

  it('recommends re-registering, not reinstalling a package that is already on disk', () => {
    expect(reconcilePluginState(input()).recommendedAction).toBe('re-register');
  });

  it('still FAILS when only the allow-list entry survives being dropped', () => {
    // entry present but disabled-by-absence is covered above; here the entry is
    // gone and allow is gone — the exact #214 shape — with the index still
    // listing it, which is what made every index-derived check read healthy.
    const v = reconcilePluginState(
      input({ index: { installRecords: {}, plugins: [{ pluginId: PLUGIN_ID, enabled: true }], warning: null } }),
    );
    expect(v.severity).toBe('fail');
  });
});

describe('#222 — but an intentional state is not damage', () => {
  it('does NOT fail when the operator explicitly set enabled:false', () => {
    const v = reconcilePluginState(input({ config: { enabled: false, inAllow: false, readable: true } }));
    expect(v.severity).not.toBe('fail');
    expect(v.state).toBe('disabled-by-operator');
  });

  it('does not recommend a reinstall for a deliberate opt-out', () => {
    const v = reconcilePluginState(input({ config: { enabled: false, inAllow: false, readable: true } }));
    expect(v.recommendedAction).toBe('none');
  });

  it('does NOT claim unprotected when openclaw.json could not be read', () => {
    // An unreadable config yields the same {enabled:null, inAllow:false} shape as
    // a wipe. Convicting on it would be a confident answer from a failed read —
    // the fail-open/fail-loud confusion #74 already warns about.
    const v = reconcilePluginState(input({ config: { enabled: null, inAllow: false, readable: false } }));
    expect(v.severity).toBe('warn');
    expect(v.state).toBe('config-unreadable');
  });
});

describe('#222 — doctor cannot green-tick an unrecognised state', () => {
  const ALL_STATES: PluginLoadState[] = [
    'healthy',
    'not-installed',
    'enabled-not-loaded',
    'installed-not-enabled',
    'disabled-by-operator',
    'config-unreadable',
    'index-unreadable',
    'load-unproven',
    'version-regressed',
    'conflicted-metadata',
    'duplicate-install',
  ];

  function verdictFor(state: PluginLoadState) {
    return {
      state,
      severity: 'fail' as const,
      recommendedAction: 'none' as const,
      enabledInConfig: false,
      loadedInIndex: false,
      loadedInLiveRoster: null,
      indexReadable: true,
      openClawTracked: false,
      indexWarnsConflict: false,
      metadataConflict: false,
      indexVersion: null,
      installsJsonVersion: null,
      onDiskVersion: '4.47.36',
      expectedVersion: '4.47.36',
      reasons: ['because'],
    };
  }

  it('renders the wiped state as a FAIL, not a pass', () => {
    const r = renderPluginLoadVerdict(verdictFor('installed-not-enabled'));
    expect(r.status).toBe('fail');
    expect(r.message.toLowerCase()).toMatch(/unprotected/);
    expect(r.fix).toBeTruthy();
  });

  it('only ever renders pass for the genuinely healthy state', () => {
    // The regression that let #222 through: a `default:` arm returning pass, so
    // ANY state the renderer does not know about reads as green.
    for (const state of ALL_STATES) {
      const r = renderPluginLoadVerdict(verdictFor(state));
      if (state !== 'healthy') {
        expect([state, r.status]).not.toEqual([state, 'pass']);
      }
    }
  });

  it('treats a completely unknown state as a warning rather than health', () => {
    const r = renderPluginLoadVerdict(verdictFor('some-future-state' as PluginLoadState));
    expect(r.status).not.toBe('pass');
  });

  it('does not fail a deliberate opt-out', () => {
    const r = renderPluginLoadVerdict(verdictFor('disabled-by-operator'));
    expect(r.status).toBe('info');
  });
});

describe('#222 — repair actually remediates the wiped state', () => {
  const planOpts = {
    pluginId: PLUGIN_ID,
    packageName: '@drakon-systems/shieldcortex-realtime',
    expectedVersion: '4.47.36',
  };

  it('plans a real restore, not an empty no-op', () => {
    // The other half of the bug: doctor can name `shieldcortex repair` as the
    // fix, but if repair has no route for the action it "succeeds" by doing
    // nothing and the host stays unprotected.
    const plan = planReconcileActions(reconcilePluginState(input()), planOpts);
    expect(plan.map((s) => s.kind)).toContain('restore-registration');
  });

  it('restores rather than reinstalling a package that is already correct', () => {
    const kinds = planReconcileActions(reconcilePluginState(input()), planOpts).map((s) => s.kind);
    expect(kinds).not.toContain('openclaw-install');
    expect(kinds).not.toContain('openclaw-install-pinned');
  });

  it('reloads the gateway and re-verifies after restoring', () => {
    // A restored stanza does nothing until the gateway reloads, and a repair
    // that does not re-verify is just a claim.
    const kinds = planReconcileActions(reconcilePluginState(input()), planOpts).map((s) => s.kind);
    expect(kinds).toContain('gateway-reload');
    expect(kinds).toContain('self-check');
    expect(kinds.indexOf('restore-registration')).toBeLessThan(kinds.indexOf('gateway-reload'));
  });

  it('never plans an install for a deliberate opt-out', () => {
    const v = reconcilePluginState(input({ config: { enabled: false, inAllow: false, readable: true } }));
    const kinds = planReconcileActions(v, planOpts).map((s) => s.kind);
    expect(kinds).toEqual(['self-check']);
  });

  it('an unrouted action still plans an honest verification rather than nothing', () => {
    const plan = planReconcileActions(
      { ...reconcilePluginState(input()), recommendedAction: 'some-future-action' as never },
      planOpts,
    );
    expect(plan.length).toBeGreaterThan(0);
    expect(plan.map((s) => s.kind)).toContain('self-check');
  });
});
