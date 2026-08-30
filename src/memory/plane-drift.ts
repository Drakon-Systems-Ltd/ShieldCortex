/**
 * Dual-plane drift model (#348 T2 / #394, Opus B3).
 *
 * Distinct from the empty-brain check: empty-brain asks "did anything land in
 * SC at all", drift asks "is the NATIVE plane still the brain while config
 * claims SC is". A store full of rows says nothing about which plane the agent
 * actually reads from — that is exactly the green-wash the residual plan names.
 *
 * Same split as `host-contract.ts`: this module is the pure decision, doctor
 * gathers the evidence. Every count is `number | null` and every native reading
 * carries its own unattestable list, because "could not look" must never render
 * as "nothing there" — the #393 lesson applied to the plane surface.
 */

/** Legal plane values this model grades (illegal values fail before here). */
export type MemoryPlane = 'dual_legacy' | 'import_only' | 'sc_canonical';

export interface PlaneDriftCounts {
  /**
   * Active rows admitted in the last 7d INSIDE the configured host/agent scope.
   * A shared DB whose weekly admits all belong to another box has not captured
   * anything here, so the scope filter is part of the honest answer.
   * null = the memories table could not be counted.
   */
  durableAdmits7d: number | null;
  /** Active rows in scope at any age — the denominator for "holds rows, injects none". */
  durableRows: number | null;
  /**
   * Rows the REAL inject predicate (`isInjectEligible`, the one the session-start
   * hook injects with) would admit for this host/agent scope. A weaker doctor
   * predicate here is how a store of unverified/directive/unscoped rows reads as
   * a healthy SC bus. null = eligibility could not be evaluated.
   */
  injectable: number | null;
  /** Active rows excluded for carrying no host/agent scope (reported, per B3). */
  unscopedExcluded: number | null;
  /** Session/hook events in the last 7d. null = NO activity telemetry exists. */
  activity7d: number | null;
}

export interface NativeSotEvidence {
  /** A native agent-SoT artifact was written inside the window. */
  touched7d: boolean;
  /** Human-readable paths of the touched artifacts, freshest listed first. */
  touchedPaths: string[];
  /** Total bytes of present native SoT artifacts. */
  bytes: number;
  /**
   * Reasons the native scan could not be completed — an unresolvable state
   * root, an unreadable store, a listing past the cap. Non-empty means doctor
   * does not know whether native is growing, which is never a PASS.
   */
  unattestable: string[];
  /** Native automatic memory bus PROVEN still on, with the proof. Unknown is not listed. */
  busActive: string[];
}

export interface PlaneDriftInput {
  plane: MemoryPlane;
  planeSetAt: string | null;
  /**
   * True when the SC v2 pack is actually the automatic session-start payload —
   * a legal nativeContract plus a start-capable mode. Only then does inject
   * eligibility decide what the agent receives, so only then is a zero
   * injectable count a delivery defect rather than a non-sequitur.
   */
  injectOn: boolean;
  /** Resolved deny-by-default scope gate — CONFIG, never data-derived (B3). */
  requireScope: boolean;
  counts: PlaneDriftCounts;
  native: NativeSotEvidence;
  nowMs: number;
}

export interface PlaneDriftVerdict {
  status: 'pass' | 'warn' | 'fail';
  message: string;
  fix?: string;
}

/** dual_legacy is time-boxed: past this, the defect warning names the age. */
export const DUAL_LEGACY_GRACE_MS = 14 * 24 * 60 * 60 * 1000;

const RESIDUAL_DOC = 'docs/design/2026-08-22-memory-sota-track-a-residual.md';
const DUAL_LEGACY_FIX =
  'Time-box dual_legacy: land the host contract and run `shieldcortex memories import-native` while native SoT is still growing. '
  + 'Do not flip memory.plane to import_only until that growth has stopped — dual_legacy is a migration escape, not steady state';
const NATIVE_SOT_FIX =
  'Stop native MEMORY.md / memory-store growth as the agent brain — import it through the defended path '
  + `(\`shieldcortex memories import-native\`) or archive it. Flipping memory.plane does not stop native writes (${RESIDUAL_DOC})`;
const NATIVE_BUS_FIX =
  'Turn the host native memory bus off (OpenClaw agents.defaults.memorySearch.enabled=false, '
  + 'Hermes memory.memory_enabled=false) — see the `Memory plane (host contract)` check for the per-runtime proof';
const EMPTY_SC_FIX =
  'Capture or import into SC on this host/agent scope, or stop claiming a plane SC does not hold';
const NO_INJECTABLE_FIX =
  'Fix the rows, not the doctor: stamp content_form, run the defence pipeline over never-scanned legacy rows, '
  + 'and scope writes with hostId/agentId — or set `memory.inject.requireScope` false deliberately if this DB is single-tenant';
const UNSCOPED_STORE_FIX =
  'Scope writes with hostId/agentId, or explicitly disable memory.inject.requireScope only for a genuinely single-tenant DB';

/** `warn` for the deprecated-but-tolerated plane, `fail` where canonicity is claimed. */
function severityFor(plane: MemoryPlane): 'warn' | 'fail' {
  return plane === 'dual_legacy' ? 'warn' : 'fail';
}

function headlineFor(plane: MemoryPlane): string {
  return plane === 'dual_legacy'
    ? 'dual_legacy dual-plane drift (time-boxed defect)'
    : `dual-plane drift under plane=${plane}`;
}

function num(v: number | null): string {
  return v === null ? 'unknown' : String(v);
}

/**
 * The evidence line every verdict carries. Unknowns render as `unknown`, never
 * as `0` — a zero that means "could not count" is how absence becomes proof.
 */
export function formatPlaneDriftDetail(input: PlaneDriftInput): string {
  const { counts, native } = input;
  return [
    `native_sot_touched_7d=${native.touched7d}`,
    `native_sot_bytes=${native.bytes}`,
    `sc_durable_admits_7d=${num(counts.durableAdmits7d)}`,
    `activity_7d=${num(counts.activity7d)}`,
    `injectable=${num(counts.injectable)}`,
    `unscoped_excluded=${num(counts.unscopedExcluded)}`,
    `requireScope=${input.requireScope}`,
  ].join(' ');
}

function agedNote(input: PlaneDriftInput): string {
  if (input.plane !== 'dual_legacy' || !input.planeSetAt) return '';
  const setMs = Date.parse(input.planeSetAt);
  if (Number.isNaN(setMs)) return '';
  return input.nowMs - setMs > DUAL_LEGACY_GRACE_MS ? ' — planeSetAt older than 14d' : '';
}

function listPaths(paths: string[]): string {
  const shown = paths.slice(0, 3).join(', ');
  return paths.length > 3 ? `${shown}, +${paths.length - 3} more` : shown;
}

/**
 * Signal order is deliberate: POSITIVE drift evidence outranks unknowns.
 * A native brain doctor can see growing is a decided defect even when the SC
 * side is only partly countable; only when nothing fires do the gaps decide,
 * and a gap is `cannot determine` (never PASS, per the #394 telemetry law).
 */
export function evaluatePlaneDrift(input: PlaneDriftInput): PlaneDriftVerdict {
  const { plane, counts, native } = input;
  const detail = formatPlaneDriftDetail(input);
  const sev = severityFor(plane);
  const aged = agedNote(input);

  // 1. Native agent SoT written inside the window (primary signal, B3).
  if (native.touched7d) {
    return {
      status: sev,
      message:
        `${headlineFor(plane)}: native agent SoT written inside the window — `
        + `${listPaths(native.touchedPaths)} (${detail})${aged}`,
      fix: plane === 'dual_legacy' ? DUAL_LEGACY_FIX : NATIVE_SOT_FIX,
    };
  }

  // 2. Native automatic memory bus provably still on (signal 2).
  if (native.busActive.length > 0) {
    return {
      status: sev,
      message:
        `${headlineFor(plane)}: native memory bus still switched on — `
        + `${native.busActive.join('; ')} (${detail})${aged}`,
      fix: plane === 'dual_legacy' ? DUAL_LEGACY_FIX : NATIVE_BUS_FIX,
    };
  }

  // 3. Activity bypassing SC entirely — nothing admitted in scope this week.
  if (counts.durableAdmits7d === 0 && (counts.activity7d ?? 0) > 0) {
    return {
      status: sev,
      message:
        `${headlineFor(plane)}: activity bypasses SC — zero durable admits in the last 7d `
        + `for this host/agent scope (${detail})${aged}`,
      fix: plane === 'dual_legacy' ? DUAL_LEGACY_FIX : EMPTY_SC_FIX,
    };
  }

  // 4. SC holds rows the REAL inject gate admits none of (signal 3). The store
  //    looks healthy by row count and delivers nothing on the bus.
  if (input.injectOn && counts.injectable === 0 && (counts.durableRows ?? 0) > 0) {
    return {
      status: sev,
      message:
        `${headlineFor(plane)}: SC holds ${counts.durableRows} durable row(s) but real inject eligibility `
        + `admits none — the SC bus delivers nothing (${detail})${aged}`,
      fix: NO_INJECTABLE_FIX,
    };
  }

  // 5. A deny-by-default scope gate excluding rows is itself plane evidence.
  // Quiet/all-unscoped stores must not green-wash merely because no activity
  // table happened to record a session this week.
  if (input.requireScope && (counts.unscopedExcluded ?? 0) > 0) {
    return {
      status: sev,
      message:
        `${headlineFor(plane)}: scope gate excluded ${counts.unscopedExcluded} unscoped row(s) — `
        + `an unscoped/quiet store cannot prove this plane (${detail})${aged}`,
      fix: plane === 'dual_legacy' ? DUAL_LEGACY_FIX : UNSCOPED_STORE_FIX,
    };
  }

  // 6. Nothing fired. Only now may gaps speak — and they say "cannot determine".
  const unknowns: string[] = [];
  if (counts.durableAdmits7d === null || counts.durableRows === null) {
    unknowns.push('SC durable admits cannot be counted');
  }
  if (counts.injectable === null) unknowns.push('real inject eligibility cannot be evaluated');
  if (counts.unscopedExcluded === null) unknowns.push('scope-exclusion telemetry cannot be counted');
  if (counts.activity7d === null) unknowns.push('no session activity telemetry on this store');
  unknowns.push(...native.unattestable);
  if (unknowns.length > 0) {
    return {
      status: 'warn',
      message: `plane=${plane}: cannot determine drift — ${unknowns.join('; ')} (${detail})`,
      fix: 'Restore the missing telemetry / make the native tree probeable — a plane doctor cannot certify what it cannot read',
    };
  }

  return {
    status: 'pass',
    message: `plane=${plane}: no dual-plane drift signal (${detail})`,
  };
}
