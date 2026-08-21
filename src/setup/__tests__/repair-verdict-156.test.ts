/**
 * Failing-first spec for #156's operator-facing half.
 *
 * The report an operator actually received on 1 Aug, on a box that was fine:
 *
 *   ✗ FAILED: could not confirm the plugin is loaded AND enforcing.
 *   roster proof FAILED … the SQLite install index lists it as enabled, but
 *   that is install state, not load state; canary proof FAILED … version proof
 *   FAILED: on-disk build 4.47.22 is OLDER than expected 4.47.24 — a silent
 *   downgrade (the 4.25.4 class); refuse it
 *
 * Every clause true, every clause written for whoever built it. These tests pin
 * the contract that the headline answers the operator's actual question — am I
 * protected, and what do I do next — without inventing certainty the machinery
 * does not have.
 */
import { describe, it, expect } from '@jest/globals';
import { summariseRepair, renderRepairHeadline } from '../repair-verdict.js';

describe('#156 — repair says whether you are protected, in English', () => {
  it('both proofs pass → protected, and nothing is asked of the operator', () => {
    const v = summariseRepair({
      applied: true,
      canaryConsented: true,
      selfCheck: { ok: true, rosterState: 'loaded', canaryProof: true, versionProof: true },
    });
    expect(v.outcome).toBe('protected');
    expect(v.headline).toMatch(/^Protected/);
    expect(v.nextCommand).toBeUndefined();
  });

  it('absent from the running gateway → unprotected, and that IS the alarm', () => {
    const v = summariseRepair({
      applied: true,
      canaryConsented: true,
      selfCheck: { ok: false, rosterState: 'absent' },
    });
    expect(v.outcome).toBe('unprotected');
    expect(v.headline).toMatch(/Not protected/);
  });

  it('a downgrade gets its own words and the command that fixes it', () => {
    const v = summariseRepair({
      applied: true,
      canaryConsented: true,
      selfCheck: { ok: false, rosterState: 'loaded', versionProof: false },
    });
    expect(v.outcome).toBe('unprotected');
    expect(v.nextCommand).toMatch(/npm i -g shieldcortex/);
  });

  it('loaded but canary NOT consented → not an alarm; it is a choice', () => {
    // The operator's morning: three env vars, one omitted, and a paragraph of
    // jargon implying something was wrong. Nothing was wrong.
    const v = summariseRepair({
      applied: true,
      canaryConsented: false,
      selfCheck: { ok: false, rosterState: 'loaded', canaryProof: false, versionProof: true },
    });
    expect(v.outcome).toBe('protected-unproven');
    expect(v.headline).not.toMatch(/FAILED|not protected/i);
    expect(v.nextCommand).toBe('shieldcortex repair');
  });

  it('loaded, canary consented, still unproven → genuinely worth a look', () => {
    const v = summariseRepair({
      applied: true,
      canaryConsented: true,
      selfCheck: { ok: false, rosterState: 'loaded', canaryProof: false, versionProof: true },
    });
    expect(v.outcome).toBe('unknown');
    expect(v.headline).toMatch(/needs a look/i);
  });

  it('a gateway that never reported back is unknown, never "broken"', () => {
    const v = summariseRepair({ applied: true, canaryConsented: true, readinessUnproven: true });
    expect(v.outcome).toBe('unknown');
    expect(v.headline).toMatch(/still be starting/i);
  });

  it('a dry run says so plainly instead of listing consent env vars', () => {
    const v = summariseRepair({ applied: false, canaryConsented: false });
    expect(v.outcome).toBe('dry-run');
    expect(v.nextCommand).toBe('shieldcortex repair');
    expect(v.headline).not.toMatch(/SHIELDCORTEX_ALLOW/);
  });
});

describe('#156 — no internal vocabulary reaches the headline', () => {
  const jargon = /roster proof|plugins_json|4\.25\.4 class|canary proof|version proof|install index|enabled-not-loaded/i;

  const cases = [
    { applied: true, canaryConsented: true, selfCheck: { ok: true, rosterState: 'loaded' as const, canaryProof: true, versionProof: true } },
    { applied: true, canaryConsented: true, selfCheck: { ok: false, rosterState: 'absent' as const } },
    { applied: true, canaryConsented: false, selfCheck: { ok: false, rosterState: 'loaded' as const, canaryProof: false, versionProof: true } },
    { applied: true, canaryConsented: true, selfCheck: { ok: false, rosterState: 'loaded' as const, versionProof: false } },
    { applied: true, canaryConsented: true, readinessUnproven: true },
    { applied: false, canaryConsented: false },
  ];

  it('every outcome renders without a single internal term', () => {
    for (const c of cases) {
      const rendered = renderRepairHeadline(summariseRepair(c)).join(' ');
      expect({ case: JSON.stringify(c).slice(0, 60), rendered: jargon.test(rendered) })
        .toEqual({ case: JSON.stringify(c).slice(0, 60), rendered: false });
    }
  });

  it('offers at most ONE command — never a menu of three env vars', () => {
    for (const c of cases) {
      const v = summariseRepair(c);
      if (!v.nextCommand) continue;
      expect(v.nextCommand.split('shieldcortex').length - 1).toBeLessThanOrEqual(2);
      expect(v.nextCommand).not.toMatch(/SHIELDCORTEX_ALLOW_GATEWAY_\w+=1.*SHIELDCORTEX_ALLOW_GATEWAY_\w+=1/);
    }
  });

  
  it('canary live + roster unread is protected-unproven, never unprotected/FAILED', () => {
    const v = summariseRepair({
      applied: true,
      canaryConsented: true,
      selfCheck: { ok: false, rosterState: 'unproven', canaryProof: true, versionProof: true },
    });
    expect(v.outcome).toBe('protected-unproven');
    expect(v.headline).toMatch(/Enforcement is live|probe denied/i);
    expect(v.headline).not.toMatch(/FAILED|Not protected/i);
    expect(v.nextCommand).toMatch(/gateway restart/);
  });

  it('never claims protection without BOTH proofs — the words changed, the standard did not', () => {
    for (const c of cases) {
      const v = summariseRepair(c);
      if (v.outcome !== 'protected') continue;
      expect(c.selfCheck?.ok).toBe(true);
    }
  });
});
