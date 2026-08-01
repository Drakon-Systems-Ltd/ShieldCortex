/**
 * Failing-first spec for #152 — the roster proof must read the LIVE roster.
 *
 * Field evidence, 31 Jul 2026 (Michael's MacBook). One `shieldcortex repair`
 * run printed both of these, seconds apart:
 *
 *   • "ABSENT from the RUNNING gateway boot roster — interceptor not loaded,
 *      host unprotected while status reports ON"
 *   • "roster proof: plugin present + enabled in the loaded roster (plugins_json)"
 *
 * Both cannot be true. The reconciler was fixed for #103 to treat the gateway's
 * own boot line as authoritative; `evaluateSelfCheck` was not, and still reads
 * `installed_plugin_index.plugins_json` — INSTALL state — while calling it
 * "the loaded roster".
 *
 * So the one check written specifically to catch an installed-but-not-loaded
 * plugin cannot detect that condition, and returns PASS on a host in exactly
 * it. That is the #74 fail-open wearing the badge of the check meant to stop it.
 *
 * The distinction these tests pin: ABSENT (proven fail-open) and UNPROVEN
 * (roster unreadable) are different answers and must never collapse into each
 * other. Neither is a pass.
 */
import { describe, it, expect } from '@jest/globals';
import { evaluateSelfCheck } from '../openclaw-selfcheck.js';
import type { PluginIndexRow } from '../../integrations/openclaw-plugin-index.js';

const PLUGIN = 'shieldcortex-realtime';

/** An install index that lists the plugin as installed + enabled. */
function indexSaysEnabled(): PluginIndexRow {
  return {
    installRecords: { [PLUGIN]: { source: 'npm', version: '4.47.22' } },
    plugins: [{ pluginId: PLUGIN, enabled: true }],
    warning: null,
    generatedAtMs: 1,
  };
}

const canaryPassed = { ran: true, denied: true, auditEntryFound: true };
const canarySkipped = { ran: false, denied: false, auditEntryFound: false };

describe('#152 — install state is not load state', () => {
  it('does NOT claim a roster proof when the live roster omits the plugin', () => {
    // The MacBook state exactly: index says enabled, gateway booted without it.
    const v = evaluateSelfCheck({
      pluginId: PLUGIN,
      index: indexSaysEnabled(),
      liveRoster: ['anthropic', 'acpx', 'telegram'],
      canary: canaryPassed,
    });

    expect(v.rosterProof).toBe(false);
    expect(v.ok).toBe(false);
    expect(v.rosterState).toBe('absent');
    // And it must say so in the operator's own terms.
    expect(v.reasons.join(' ')).toMatch(/ABSENT from the RUNNING gateway boot roster/i);
  });

  it('never contradicts the reconciler: absent from the live roster is never "present in the loaded roster"', () => {
    const v = evaluateSelfCheck({
      pluginId: PLUGIN,
      index: indexSaysEnabled(),
      liveRoster: ['anthropic'],
      canary: canaryPassed,
    });
    // The precise sentence that appeared on the Mac beneath the contradiction.
    expect(v.reasons.join(' ')).not.toMatch(/plugin present \+ enabled in the loaded roster/i);
  });

  it('grants the roster proof when the RUNNING gateway names the plugin', () => {
    const v = evaluateSelfCheck({
      pluginId: PLUGIN,
      index: indexSaysEnabled(),
      liveRoster: ['anthropic', PLUGIN],
      canary: canaryPassed,
    });
    expect(v.rosterProof).toBe(true);
    expect(v.rosterState).toBe('loaded');
    expect(v.ok).toBe(true);
  });

  it('reports UNPROVEN — not absent, not proven — when the live roster cannot be read', () => {
    // Absence of evidence. Claiming the plugin is missing would be as
    // dishonest as claiming it is loaded; #142 was a false UNPROTECTED from
    // exactly this state.
    const v = evaluateSelfCheck({
      pluginId: PLUGIN,
      index: indexSaysEnabled(),
      liveRoster: null,
      canary: canaryPassed,
    });
    expect(v.rosterState).toBe('unproven');
    expect(v.rosterProof).toBe(false);
    expect(v.ok).toBe(false);
    const reasons = v.reasons.join(' ');
    expect(reasons).toMatch(/could not read the running gateway/i);
    // Must not accuse the host of being unprotected on unreadable evidence.
    expect(reasons).not.toMatch(/ABSENT from the RUNNING/i);
  });

  it('an enabled install index alone is never sufficient — the #103/#152 root', () => {
    // No live roster supplied at all: the index is optimistic, we are not.
    const v = evaluateSelfCheck({
      pluginId: PLUGIN,
      index: indexSaysEnabled(),
      canary: canaryPassed,
    });
    expect(v.rosterProof).toBe(false);
    expect(v.ok).toBe(false);
  });

  it('a live roster hit does not rescue a missing canary', () => {
    // Both proofs are required; neither substitutes for the other.
    const v = evaluateSelfCheck({
      pluginId: PLUGIN,
      index: indexSaysEnabled(),
      liveRoster: [PLUGIN],
      canary: canarySkipped,
    });
    expect(v.rosterProof).toBe(true);
    expect(v.canaryProof).toBe(false);
    expect(v.ok).toBe(false);
  });

  it('still fails honestly when the index is unreadable AND the roster is unknown', () => {
    const v = evaluateSelfCheck({
      pluginId: PLUGIN,
      index: null,
      liveRoster: null,
      canary: canaryPassed,
    });
    expect(v.rosterProof).toBe(false);
    expect(v.ok).toBe(false);
  });

  it('trusts the live roster even when the install index is unreadable', () => {
    // The gateway's own boot line is ground truth; a broken better-sqlite3
    // binding must not be able to veto it.
    const v = evaluateSelfCheck({
      pluginId: PLUGIN,
      index: null,
      liveRoster: [PLUGIN],
      canary: canaryPassed,
    });
    expect(v.rosterProof).toBe(true);
    expect(v.rosterState).toBe('loaded');
  });
});
