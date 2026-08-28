/**
 * #394 T2 — plane-law regressions the audit of the shipped surfaces found
 * missing, plus the pure drift model's precedence rules.
 *
 * The signed CLI, the closed enum and `planeSetAt` all shipped in #397 and are
 * covered in config-memory-inject-contract-cli.test.ts. What was NOT covered:
 *
 *  - TWO readers exist for one signed enum (`readMemoryPlane` in cloud/config
 *    and `readMemoryPlaneFromConfig` in cli/doctor). If they ever disagree, the
 *    CLI can write a value the doctor calls illegal, or worse, the doctor can
 *    grade a plane the operator never set. Nothing pinned them together.
 *  - the drift model's signal precedence: positive native evidence must outrank
 *    telemetry gaps, and a gap must never resolve to PASS.
 *  - the dual_legacy 14d time-box escalation note.
 */
import { describe, expect, it } from '@jest/globals';
import { readMemoryPlane } from '../../cloud/config.js';
import { readMemoryPlaneFromConfig } from '../../cli/doctor.js';
import {
  evaluatePlaneDrift,
  DUAL_LEGACY_GRACE_MS,
  type NativeSotEvidence,
  type PlaneDriftCounts,
  type PlaneDriftInput,
} from '../plane-drift.js';

describe('plane reader parity (#394 audit)', () => {
  const cases: Array<{ name: string; raw: Record<string, unknown>; illegal: boolean; plane?: string }> = [
    { name: 'absent → dual_legacy default', raw: {}, illegal: false, plane: 'dual_legacy' },
    { name: 'empty string → dual_legacy default', raw: { memory: { plane: '' } }, illegal: false, plane: 'dual_legacy' },
    { name: 'dual_legacy', raw: { memory: { plane: 'dual_legacy' } }, illegal: false, plane: 'dual_legacy' },
    { name: 'import_only', raw: { memory: { plane: 'import_only' } }, illegal: false, plane: 'import_only' },
    { name: 'sc_canonical', raw: { memory: { plane: 'sc_canonical' } }, illegal: false, plane: 'sc_canonical' },
    { name: 'legacy memoryPlane alias', raw: { memoryPlane: 'import_only' }, illegal: false, plane: 'import_only' },
    // The retired / forbidden values must be illegal in BOTH readers.
    { name: 'coexist_dedup is out of P0', raw: { memory: { plane: 'coexist_dedup' } }, illegal: true },
    { name: 'junk string', raw: { memory: { plane: 'multi_master' } }, illegal: true },
    { name: 'non-string junk', raw: { memory: { plane: ['import_only'] } }, illegal: true },
    { name: 'numeric junk', raw: { memory: { plane: 3 } }, illegal: true },
  ];

  for (const c of cases) {
    it(`agrees on ${c.name}`, () => {
      const fromConfig = readMemoryPlane(c.raw);
      const fromDoctor = readMemoryPlaneFromConfig(c.raw);
      expect(fromDoctor.illegal).toBe(c.illegal);
      expect(fromConfig.illegal).toBe(c.illegal);
      if (!c.illegal) {
        expect(fromDoctor.plane).toBe(c.plane);
        expect(fromConfig.plane).toBe(c.plane);
      }
    });
  }

  it('carries planeSetAt through both readers so the time-box has one source', () => {
    const raw = { memory: { plane: 'dual_legacy', planeSetAt: '2026-01-01T00:00:00.000Z' } };
    expect(readMemoryPlane(raw).planeSetAt).toBe('2026-01-01T00:00:00.000Z');
    expect(readMemoryPlaneFromConfig(raw).planeSetAt).toBe('2026-01-01T00:00:00.000Z');
  });
});

describe('evaluatePlaneDrift precedence', () => {
  const NOW = Date.parse('2026-08-27T12:00:00.000Z');

  const cleanNative: NativeSotEvidence = {
    touched7d: false, touchedPaths: [], bytes: 0, unattestable: [], busActive: [],
  };
  const healthyCounts: PlaneDriftCounts = {
    durableAdmits7d: 4, durableRows: 12, injectable: 6, unscopedExcluded: 0, activity7d: 40,
  };

  function input(over: Partial<PlaneDriftInput> = {}): PlaneDriftInput {
    return {
      plane: 'import_only',
      planeSetAt: null,
      injectOn: true,
      requireScope: true,
      counts: healthyCounts,
      native: cleanNative,
      nowMs: NOW,
      ...over,
    };
  }

  it('passes only when every reading is known and no signal fires', () => {
    const v = evaluatePlaneDrift(input());
    expect(v.status).toBe('pass');
    expect(v.message).toMatch(/no dual-plane drift signal/);
  });

  it('lets positive native evidence outrank an unknown SC side — a defect is decided, not deferred', () => {
    const v = evaluatePlaneDrift(input({
      counts: { ...healthyCounts, durableAdmits7d: null, injectable: null, activity7d: null },
      native: { ...cleanNative, touched7d: true, touchedPaths: ['~/.openclaw/workspace/MEMORY.md'] },
    }));
    expect(v.status).toBe('fail');
    expect(v.message).toMatch(/native agent SoT written inside the window/);
    expect(v.message).not.toMatch(/cannot determine/);
  });

  it('never resolves a telemetry gap to PASS, on any plane', () => {
    for (const plane of ['dual_legacy', 'import_only', 'sc_canonical'] as const) {
      for (const gap of [
        { durableAdmits7d: null },
        { durableRows: null },
        { injectable: null },
        { unscopedExcluded: null },
        { activity7d: null },
      ]) {
        const v = evaluatePlaneDrift(input({ plane, counts: { ...healthyCounts, ...gap } }));
        expect(v.status).toBe('warn');
        expect(v.message).toMatch(/cannot determine drift/);
      }
      const v = evaluatePlaneDrift(input({
        plane,
        native: { ...cleanNative, unattestable: ['OpenClaw state root is unresolvable'] },
      }));
      expect(v.status).toBe('warn');
      expect(v.message).toMatch(/cannot determine drift/);
    }
  });

  it('suppresses the zero-injectable signal when SC is not on the automatic bus (honest sidecar)', () => {
    // An honest `mcp_sidecar_no_inject` host has inject off by design (#393).
    // Nothing is delivered from SC on purpose, so an empty injectable set is
    // not a delivery defect — calling it one would punish the honest posture.
    const v = evaluatePlaneDrift(input({
      plane: 'dual_legacy',
      injectOn: false,
      counts: { ...healthyCounts, injectable: 0 },
    }));
    expect(v.status).toBe('pass');
  });

  it('still fails a bound SC bus that delivers none of its own rows', () => {
    const v = evaluatePlaneDrift(input({ counts: { ...healthyCounts, injectable: 0 } }));
    expect(v.status).toBe('fail');
    expect(v.message).toMatch(/real inject eligibility admits none/);
  });

  it('never green-washes a quiet all-unscoped store when scope is required', () => {
    const quiet = {
      ...healthyCounts,
      durableAdmits7d: 0,
      durableRows: 0,
      injectable: 0,
      unscopedExcluded: 12,
      activity7d: 0,
    };
    expect(evaluatePlaneDrift(input({ plane: 'dual_legacy', counts: quiet })).status).toBe('warn');
    for (const plane of ['import_only', 'sc_canonical'] as const) {
      const v = evaluatePlaneDrift(input({ plane, counts: quiet }));
      expect(v.status).toBe('fail');
      expect(v.message).toMatch(/scope gate excluded 12 unscoped row/);
    }
  });

  it('names the 14d time-box once dual_legacy has aged past the grace window', () => {
    const aged = new Date(NOW - DUAL_LEGACY_GRACE_MS - 1000).toISOString();
    const fresh = new Date(NOW - 1000).toISOString();
    const drifting = {
      plane: 'dual_legacy' as const,
      counts: { ...healthyCounts, durableAdmits7d: 0 },
    };
    expect(evaluatePlaneDrift(input({ ...drifting, planeSetAt: aged })).message)
      .toMatch(/planeSetAt older than 14d/);
    expect(evaluatePlaneDrift(input({ ...drifting, planeSetAt: fresh })).message)
      .not.toMatch(/planeSetAt older than 14d/);
    // A junk stamp must not throw or invent an age.
    expect(evaluatePlaneDrift(input({ ...drifting, planeSetAt: 'not-a-date' })).message)
      .not.toMatch(/planeSetAt older than/);
  });

  it('renders unknown counts as unknown, never as a passing zero', () => {
    const v = evaluatePlaneDrift(input({
      counts: { durableAdmits7d: null, durableRows: null, injectable: null, unscopedExcluded: null, activity7d: null },
    }));
    expect(v.message).toMatch(/sc_durable_admits_7d=unknown/);
    expect(v.message).toMatch(/injectable=unknown/);
    expect(v.message).toMatch(/unscoped_excluded=unknown/);
    expect(v.message).toMatch(/activity_7d=unknown/);
  });
});
