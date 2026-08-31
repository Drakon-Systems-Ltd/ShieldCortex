import fs from 'fs';
import path from 'path';
import { randomUUID } from 'crypto';
import { pathToFileURL } from 'url';
import semver from 'semver';
import {
  readPluginInstallIndex,
  REALTIME_PLUGIN_ID,
  classifyLiveLoadEvidence,
  type PluginIndexRow,
} from '../integrations/openclaw-plugin-index.js';
import {
  readInstalledRealtimePluginVersion,
  resolveRealtimePluginInstallPath,
} from '../integrations/openclaw-plugin-state.js';
import { readLatestBootRoster, findRegistrationSince, findGatewayAttributedRegistrationSince, type BootRoster } from '../integrations/openclaw-gateway-roster.js';
import { readRunningGatewayProcess } from '../integrations/openclaw-gateway-process.js';
import { resolveRepairConsent } from './repair-consent.js';
import { evaluateToolCall } from '../defence/iron-dome/tool-action-guard.js';

/**
 * Honest-state post-install/enable self-check (#74 deliverable 2).
 *
 * Field incident #74 taught that NO existing status surface is trustworthy:
 * `openclaw plugins list`, `~/.openclaw/openclaw.json`, and
 * `shieldcortex openclaw status` all reported the realtime interceptor ON while
 * it was silently dropped from the loaded roster — the host was unprotected.
 *
 * So a flow may report success ONLY when BOTH independent proofs hold:
 *   (a) ROSTER  — the RUNNING gateway's own boot line names the plugin, and
 *   (b) CANARY  — a live enforcement probe confirms the interceptor actually
 *       denied a known-bad operation AND wrote the corresponding audit entry.
 *
 * #152 (Michael's MacBook, 31 Jul 2026): the roster proof used to read
 * `installed_plugin_index.plugins_json` and describe it as "the loaded roster".
 * It is not — it records what OpenClaw has INSTALLED and enabled, which stays
 * true while the gateway boots without the plugin. One repair run therefore
 * printed "ABSENT from the RUNNING gateway boot roster" and "present + enabled
 * in the loaded roster" seconds apart, and the check written to catch the #74
 * fail-open returned PASS on a host sitting in it. The reconciler had already
 * been fixed for this in #103; this module had not. The boot line is now the
 * only thing that can grant the roster proof.
 *
 * Absence of either proof is a HARD FAIL. Silence is never success. The live
 * canary is guarded exactly like the gateway restart (JEST + explicit consent
 * env) so tests and this frozen box never trigger a live gateway operation;
 * callers inject a probe to exercise the wiring.
 */

/**
 * The ONE command that proves enforcement live. Defined here, printed nowhere
 * else from a literal (#154).
 *
 * Field evidence, 1 Aug 2026: `doctor` printed two different commands for this
 * same proof in a single run — `shieldcortex openclaw status` on the Action
 * guard line, `shieldcortex repair` on the plugin line. Only the second reached
 * the self-check; the first accepted the env var and silently ignored it. An
 * operator followed the first, got a directory listing, and learned nothing
 * about whether the host was protected.
 *
 * Both surfaces now run the canary, and both name it from this constant, so a
 * future divergence has to be deliberate rather than accidental.
 */
export const LIVE_CANARY_COMMAND = 'SHIELDCORTEX_ALLOW_GATEWAY_CANARY=1 shieldcortex openclaw status';

export interface CanaryResult {
  /** Whether the live enforcement probe actually executed. */
  ran: boolean;
  /** Whether the known-bad canary operation was denied by the interceptor. */
  denied: boolean;
  /** Whether the deny produced an entry in the realtime audit log. */
  auditEntryFound: boolean;
  detail?: string;
}

/**
 * What we actually know about the RUNNING gateway's roster (#152).
 *
 * The three states must never collapse into each other:
 *   - `loaded`   — the gateway's own boot line names the plugin. Proof.
 *   - `absent`   — the boot line was read and does NOT name it. The #74/#103
 *                  fail-open, proven. A hard failure.
 *   - `unproven` — the boot line could not be read. Absence of evidence.
 *                  Not a pass, but equally not an accusation: #142 was a false
 *                  "UNPROTECTED" produced by treating this state as `absent`.
 */
export type RosterProofState = 'loaded' | 'absent' | 'unproven';

export interface SelfCheckVerdict {
  ok: boolean;
  /** True ONLY for `rosterState === 'loaded'`. */
  rosterProof: boolean;
  /** Which of the three roster answers we actually have. */
  rosterState: RosterProofState;
  canaryProof: boolean;
  /** onDiskVersion >= expectedVersion (inert/true when no expectedVersion given). */
  versionProof: boolean;
  reasons: string[];
}

export interface SelfCheckInput {
  pluginId: string;
  index: PluginIndexRow | null;
  canary: CanaryResult | null;
  /**
   * Plugin ids named on the RUNNING gateway's boot line, or null when it could
   * not be read. This — not the install index — is the roster proof (#152).
   */
  liveRoster?: string[] | null;
  /**
   * A plugin registration line was sighted AFTER the boot roster snapshot
   * (#142). Registration races the snapshot (169 ms margin observed live) and
   * also happens mid-life, so absence-from-snapshot plus a later sighting is
   * AMBIGUOUS — CLI processes write identical lines — and must yield
   * `unproven`, never `absent`. It never grants `loaded` by itself.
   *
   * #216: gateway-PID-attributed registration is NOT this flag — that is
   * `gatewayPidRegistrationSeenAfterBoot` / live-load proof.
   */
  registrationSeenAfterBoot?: boolean;
  /**
   * #216 — a post-boot registration line attributed to the RUNNING gateway
   * PID. Unlike CLI-ambiguous `registrationSeenAfterBoot`, this IS live-load
   * proof (hot-reload after stanza restore). Grants `loaded` when the boot
   * snapshot omitted the plugin.
   */
  gatewayPidRegistrationSeenAfterBoot?: boolean;
  /** The build the flow expects to be enforcing; enables the version proof. */
  expectedVersion?: string;
  /** Ground-truth on-disk version, for the version proof. */
  onDiskVersion?: string | null;
}

/**
 * Pure combiner: success requires ALL proofs. No disk, no gateway — so the
 * all-proofs-or-fail contract is exhaustively unit-tested.
 *
 * The version proof (#3) makes a silent downgrade impossible to report as
 * success: an unpinned `plugins update` that re-resolves to a lower build (the
 * 4.25.4 class) leaves onDiskVersion < expectedVersion, which HARD-FAILS here
 * even when the roster and canary both pass.
 */
export function evaluateSelfCheck(input: SelfCheckInput): SelfCheckVerdict {
  const { pluginId, index, canary } = input;
  const reasons: string[] = [];

  // ── Roster proof (#152) ──────────────────────────────────────────────────
  // The RUNNING gateway's boot line is the only ground truth for what was
  // loaded. `installed_plugin_index.plugins_json` records what is INSTALLED and
  // enabled — a plugin can sit in it, allow-listed and enabled, while the
  // gateway booted without it. Reading the index here and calling it "the
  // loaded roster" is what let this check pass on a host in exactly the
  // condition it exists to catch.
  const liveRoster = input.liveRoster ?? null;
  const enabledInIndex = Boolean(
    index?.plugins?.some((p) => p.pluginId === pluginId && p.enabled === true),
  );

  let rosterState: RosterProofState;
  if (liveRoster == null) {
    // #216: gateway-PID registration can still prove load when the boot line
    // itself was unreadable (log wiped after hot-reload).
    rosterState = input.gatewayPidRegistrationSeenAfterBoot === true ? 'loaded' : 'unproven';
  } else if (liveRoster.includes(pluginId)) {
    rosterState = 'loaded';
  } else if (input.gatewayPidRegistrationSeenAfterBoot === true) {
    // #216: Case #213 shape — boot snapshot missed the plugin, but the running
    // gateway process itself later emitted the registration line.
    rosterState = 'loaded';
  } else if (input.registrationSeenAfterBoot === true) {
    // #142: the boot line is a snapshot and registration races it. A sighting
    // after the snapshot means the snapshot cannot convict — but because CLI
    // processes write identical lines, it cannot acquit either.
    rosterState = 'unproven';
  } else {
    rosterState = 'absent';
  }
  const rosterProof = rosterState === 'loaded';

  if (rosterState === 'loaded') {
    // Prefer the true evidence source. gather/selfcheck may promote pluginId
    // into liveRoster after a gateway-PID hit (#216 dual-review nit) — still
    // say hot-reload when that is how we proved load.
    if (input.gatewayPidRegistrationSeenAfterBoot === true) {
      reasons.push(
        'roster proof: plugin registration attributed to the RUNNING gateway PID after boot — live load proven (hot-reload / post-boot), not merely installed',
      );
    } else {
      reasons.push('roster proof: plugin named on the RUNNING gateway boot roster — actually loaded, not merely installed');
    }
  } else if (rosterState === 'absent') {
    reasons.push('roster proof FAILED: plugin ABSENT from the RUNNING gateway boot roster — interceptor not loaded, host unprotected while status reports ON');
    if (enabledInIndex) {
      reasons.push('the SQLite install index lists it as enabled — install state, not load state; the live roster is authoritative');
    }
  } else if (liveRoster != null && input.registrationSeenAfterBoot === true) {
    reasons.push(
      'roster proof INCONCLUSIVE: absent from the boot roster snapshot, but a plugin registration was sighted after that snapshot — ' +
        'registration races the boot line and CLI processes write identical lines, so neither loaded nor absent can be proven; ' +
        'the consent-gated live canary is the arbiter',
    );
  } else {
    // Unreadable. Say only what is true: we cannot prove it either way.
    reasons.push(
      'roster proof FAILED: could not read the running gateway boot roster (log rotated, wiped, or written elsewhere) — cannot confirm the interceptor is loaded' +
        (enabledInIndex
          ? '; the SQLite install index lists it as enabled, but that is install state, not load state'
          : ''),
    );
  }

  const canaryProof = Boolean(canary && canary.ran && canary.denied && canary.auditEntryFound);
  if (canaryProof) {
    reasons.push('canary proof: live probe was denied by the interceptor and audited');
  } else if (!canary || !canary.ran) {
    reasons.push(`canary proof FAILED: enforcement canary was not executed — cannot confirm the interceptor is live${canary?.detail ? ` (${canary.detail})` : ''}`);
  } else if (!canary.denied) {
    reasons.push('canary proof FAILED: canary operation was NOT denied — interceptor loaded but not enforcing');
  } else {
    reasons.push('canary proof FAILED: canary denied but no audit entry appeared — cannot prove the interceptor fired');
  }

  // Version proof: onDisk must be >= expected. Inert (true) when the caller
  // supplied no expectedVersion (e.g. pure roster+canary unit tests).
  let versionProof = true;
  if (input.expectedVersion) {
    const onDisk = semver.valid(input.onDiskVersion ?? '') ?? semver.valid(semver.coerce(input.onDiskVersion ?? '') ?? '');
    const expected = semver.valid(input.expectedVersion) ?? semver.valid(semver.coerce(input.expectedVersion) ?? '');
    if (!onDisk) {
      versionProof = false;
      reasons.push(`version proof FAILED: could not read the on-disk plugin version to compare against expected ${input.expectedVersion}`);
    } else if (expected && semver.lt(onDisk, expected)) {
      versionProof = false;
      reasons.push(`version proof FAILED: on-disk build ${onDisk} is OLDER than expected ${expected} — a silent downgrade (the 4.25.4 class); refuse it`);
    } else {
      reasons.push(`version proof: on-disk build ${onDisk} satisfies expected ${expected ?? input.expectedVersion}`);
    }
  }

  return { ok: rosterProof && canaryProof && versionProof, rosterProof, rosterState, canaryProof, versionProof, reasons };
}

export interface RunSelfCheckOptions {
  pluginId?: string;
  /** The build the flow expects to be enforcing; enables the version proof (#3). */
  expectedVersion?: string;
  /** Injectable index reader (defaults to the live SQLite read). */
  readIndex?: (home: string) => PluginIndexRow | null;
  /** Injectable on-disk version reader (defaults to the live package.json read). */
  readOnDiskVersion?: (home: string) => string | null;
  /**
   * Injectable live-roster reader (defaults to the gateway's newest
   * `http server listening` boot line, bounded by the running gateway's
   * process start — a line from a previous process proves nothing, #142/#150).
   * Returns null when it cannot be proven.
   */
  readLiveRoster?: () => string[] | null;
  /**
   * Injectable post-boot registration sighting (defaults to scanning the
   * gateway logs for a `[shieldcortex] … registered` line newer than the boot
   * roster snapshot, #142). Only consulted when the roster omits the plugin
   * AND no gateway-PID load proof is present.
   */
  readRegistrationSeenAfterBoot?: () => boolean;
  /**
   * #216 test seam — gateway-PID-attributed registration (defaults to
   * {@link findGatewayAttributedRegistrationSince}).
   */
  findGatewayAttributedRegistration?: (
    sinceMs: number,
    gatewayPid: number,
  ) => { atMs: number; pid: number | null; version: string } | null;
  /**
   * #142 test seam — any dated registration since a bound.
   */
  findAnyRegistrationSince?: (
    sinceMs: number,
  ) => { atMs: number; pid: number | null; version: string } | null;
  /** Injectable live enforcement probe (defaults to the guarded real probe). */
  canaryProbe?: (home: string, pluginId: string) => Promise<CanaryResult>;
}

export interface SelfCheckRunResult extends SelfCheckVerdict {
  index: PluginIndexRow | null;
  /** What the running gateway's boot line said, or null when unreadable. */
  liveRoster: string[] | null;
  canary: CanaryResult;
}

/**
 * Run the self-check against a host: read the loaded roster, run the live
 * canary, and combine. Under a Jest worker or without explicit consent the
 * live canary is skipped (`ran:false`), which makes the check HARD FAIL rather
 * than falsely pass.
 */
export async function runPluginSelfCheck(
  home: string,
  options: RunSelfCheckOptions = {},
): Promise<SelfCheckRunResult> {
  const pluginId = options.pluginId ?? REALTIME_PLUGIN_ID;
  const readIndex = options.readIndex ?? ((h: string) => readPluginInstallIndex(h));
  const readOnDisk = options.readOnDiskVersion ?? ((h: string) => readInstalledRealtimePluginVersion(h));
  // The default roster read touches the host's real gateway log dir
  // (/tmp/openclaw), which no `home` override can redirect — so it must never
  // fire under Jest, or a test would silently inherit THIS box's roster and
  // prove nothing. Tests inject readLiveRoster.
  //
  // #142/#150: the roster line is bounded by the RUNNING gateway's process
  // start (from OpenClaw's own boot-lifecycle table). A boot line from a
  // previous process, or one we cannot bound, yields null — "cannot prove",
  // never a stale answer wearing a fresh badge.
  let latestBoot: BootRoster | null | undefined;
  let gatewayPid: number | null = null;
  let processStartedAtMs: number | null = null;
  const readRoster =
    options.readLiveRoster ??
    (() => {
      if (process.env.JEST_WORKER_ID !== undefined) return null;
      const proc = readRunningGatewayProcess(home);
      if (!proc) return null;
      gatewayPid = proc.pid;
      processStartedAtMs = proc.startedAtMs;
      latestBoot = readLatestBootRoster({ processStartedAtMs: proc.startedAtMs });
      return latestBoot?.plugins ?? null;
    });
  const probe = options.canaryProbe ?? defaultCanaryProbe;

  const index = readIndex(home);
  let liveRoster = readRoster();
  // #216/#142: ONE decision tree with gatherReconcileInput (dual-review #281).
  // Do not re-implement processStartedAtMs coupling here.
  const classified = classifyLiveLoadEvidence({
    pluginId,
    liveRoster,
    gatewayPid,
    bootAtMs: latestBoot?.atMs ?? null,
    processStartedAtMs,
    findGatewayReg:
      options.findGatewayAttributedRegistration ??
      ((sinceMs, pid) =>
        process.env.JEST_WORKER_ID !== undefined
          ? null
          : findGatewayAttributedRegistrationSince(sinceMs, pid)),
    findAnyReg:
      options.findAnyRegistrationSince ??
      ((sinceMs) =>
        process.env.JEST_WORKER_ID !== undefined
          ? null
          : findRegistrationSince(sinceMs)),
  });
  // When tests inject readRegistrationSeenAfterBoot, honour it for the
  // ambiguous path only — never override a gateway-PID load proof.
  let registrationSeenAfterBoot = classified.registrationSeenAfterBoot;
  let gatewayPidRegistrationSeenAfterBoot =
    classified.liveLoadEvidence === 'gateway-pid-registration';
  if (
    options.readRegistrationSeenAfterBoot &&
    !gatewayPidRegistrationSeenAfterBoot &&
    classified.liveLoadEvidence !== 'boot-roster'
  ) {
    registrationSeenAfterBoot = options.readRegistrationSeenAfterBoot();
  }
  liveRoster = classified.liveRoster;

  const onDiskVersion = options.expectedVersion ? readOnDisk(home) : null;
  const canary = await probe(home, pluginId);
  const verdict = evaluateSelfCheck({
    pluginId,
    index,
    liveRoster,
    registrationSeenAfterBoot,
    gatewayPidRegistrationSeenAfterBoot,
    canary,
    expectedVersion: options.expectedVersion,
    onDiskVersion,
  });
  return { ...verdict, index, liveRoster, canary };
}

/** Injectable seams for the live enforcement canary, so the wiring is unit-tested. */
export interface CanaryProbeDeps {
  /** Monotonic-ish clock (ms). */
  now: () => number;
  /** Generates the unique per-probe nonce the synthetic op is tagged with. */
  makeNonce: () => string;
  /**
   * Drives a synthetic, side-effect-free known-bad operation tagged with
   * `nonce` through the plugin's own `before_tool_call` interception path.
   * Returns whether it was actually dispatched (false when guarded/unavailable).
   */
  triggerSyntheticOp: (home: string, pluginId: string, nonce: string) => Promise<{ dispatched: boolean; detail?: string }>;
  /** Looks for a FRESH deny (>= probe start) carrying `nonce` in the audit log. */
  findFresh: (home: string, query: FreshEnforcementQuery) => { found: boolean; at?: string };
}

/**
 * The real live enforcement canary (deps default to the guarded live seams).
 *
 * This is a LIVE PROBE, not an audit-log grep: it stamps a unique nonce, drives
 * a synthetic known-bad op through the interceptor, then requires an audit entry
 * that is BOTH newer than probe start AND carries that nonce. A stale pre-break
 * deny (the aiquant #74 timeline: last real deny at 10:40, interceptor dropped,
 * probe runs at 10:50) satisfies NEITHER gate ⇒ `denied:false` ⇒ the self-check
 * fails loudly instead of reporting "enforcing" off a dead interceptor.
 */
export async function runCanaryProbe(home: string, pluginId: string, deps: CanaryProbeDeps): Promise<CanaryResult> {
  const nonce = deps.makeNonce();
  const sinceMs = deps.now();
  const trigger = await deps.triggerSyntheticOp(home, pluginId, nonce);
  if (!trigger.dispatched) {
    return {
      ran: false,
      denied: false,
      auditEntryFound: false,
      detail: trigger.detail ?? 'synthetic canary op was not dispatched — cannot prove the interceptor is live',
    };
  }
  const fresh = deps.findFresh(home, { nonce, sinceMs });
  return {
    ran: true,
    denied: fresh.found,
    auditEntryFound: fresh.found,
    detail: fresh.found
      ? `interceptor denied + audited the synthetic canary (nonce ${nonce}) at ${fresh.at}`
      : `synthetic canary op dispatched (nonce ${nonce}) but NO fresh matching deny appeared — interceptor loaded-but-not-enforcing or unloaded`,
  };
}

/**
 * The default live enforcement canary. Its live seam
 * ({@link defaultTriggerSyntheticOp}) is GUARDED on `JEST_WORKER_ID` +
 * `SHIELDCORTEX_ALLOW_GATEWAY_CANARY=1` (mirroring the gateway-restart gate), so
 * under a test runner or without consent the op is never dispatched and the
 * probe returns `ran:false` — a hard, honest fail rather than a silent pass.
 */
export async function defaultCanaryProbe(home: string, pluginId: string): Promise<CanaryResult> {
  return runCanaryProbe(home, pluginId, {
    now: () => Date.now(),
    makeNonce: () => `sc-canary-${randomUUID()}`,
    triggerSyntheticOp: defaultTriggerSyntheticOp,
    findFresh: findFreshEnforcementEntry,
  });
}

/** Marker embedded in the synthetic op so its audit entry is unmistakably a
 * canary probe (not a real agent action) to anyone tailing the audit log. */
export const CANARY_MARKER = 'SHIELDCORTEX-CANARY';

/** The synthetic operation the active canary drives through the interceptor. */
export interface SyntheticCanaryOp {
  toolName: string;
  arguments: Record<string, unknown>;
}

/**
 * Build the synthetic canary operation, tagged with the probe `nonce`.
 *
 * It is a known-bad SHAPE — a recursive-force-delete, which the Action Guard
 * hard-blocks as `catastrophic` — so a live interceptor MUST deny it. Yet it is
 * PROVABLY HARMLESS: the delete surface is a synthetic, non-existent `/tmp`
 * path, so even in the failure mode this canary exists to detect (enforcement
 * OFF, the op actually executes) `rm -rf` on a missing path is a no-op. The
 * nonce uniquely identifies this probe's audit entry; {@link CANARY_MARKER}
 * makes its purpose unmistakable to an operator reading the log.
 */
export function buildSyntheticCanaryOp(nonce: string): SyntheticCanaryOp {
  return {
    toolName: 'Bash',
    arguments: {
      // HOME-anchored, not /tmp (#170): the guard now judges a delete by its
      // TARGET, and a /tmp path is workspace-confined — allowed by design. The
      // canary must be a shape the guard will always refuse, so it targets a
      // synthetic dotdir under `~`, which the confinement check permanently
      // rejects (`~` can expand anywhere). Both canary properties survive:
      // catastrophic-shaped (blocked by a live interceptor), and provably
      // harmless in the failure mode this probe exists to detect — if
      // enforcement is OFF and the op executes, `rm -rf` on a nonexistent
      // nonce-named dotdir is a no-op.
      command: `rm -rf ~/.${nonce}`,
      description: `${CANARY_MARKER} synthetic enforcement probe ${nonce} — never executed`,
    },
  };
}

/** The subset of the plugin's compiled interceptor module the canary needs. */
export interface InterceptorLikeModule {
  createInterceptor: (
    config: unknown,
    pipeline: unknown,
    options?: { evaluateToolCall?: unknown },
  ) => { handleToolCall: (ctx: SyntheticCanaryOp) => Promise<void>; resetSession?: () => void };
  DEFAULT_CONFIG: unknown;
}

/** Injectable seams for the active synthetic dispatch, so the wiring is unit-
 * tested without a live gateway or a real ABI/install on disk. */
export interface ActiveDispatchDeps {
  /** Resolve the installed realtime plugin dir (the live interceptor code). */
  resolveInstallPath: (home: string) => string | null;
  /** Load the installed plugin's compiled interceptor module, or null. */
  loadInterceptorModule: (installPath: string) => Promise<InterceptorLikeModule | null>;
  /** The real Tool Action Guard evaluator (`shieldcortex/defence`). */
  evaluator: (toolName: string, args: Record<string, unknown>) => unknown;
}

/** A benign pipeline stub for the memory path — never invoked for the Bash
 * canary op (non-memory tools route to the Action Guard), but createInterceptor
 * requires one. */
const benignPipeline = () => ({
  allowed: true,
  firewall: { result: 'ALLOW' as const, reason: 'canary', threatIndicators: [], anomalyScore: 0, blockedPatterns: [] },
  trust: { score: 1 },
  sensitivity: { level: 'INTERNAL' },
  fragmentation: null,
  auditId: 0,
});

/**
 * Drive the synthetic canary op through the INSTALLED plugin's real interceptor
 * — the same code the gateway loads — so the deny + audit entry are produced by
 * the genuine enforcement path, not a stub. Reuses the installed interceptor
 * (no forked implementation) and the real defence evaluator.
 *
 * Fail-closed at every step: a missing install, an unloadable module, or a
 * construction failure returns `dispatched:false` with a loud, honest detail —
 * never a fabricated pass. `dispatched:true` means only that the op passed
 * through the interceptor; whether it was actually DENIED + AUDITED is confirmed
 * separately by {@link findFreshEnforcementEntry} (the fresh nonce gate).
 *
 * Harmless by construction: the interceptor evaluates + audits BEFORE any
 * execution, and the op itself is a no-op even if it ran (see
 * {@link buildSyntheticCanaryOp}). Nothing here touches the running gateway.
 */
/**
 * Resolve the interceptor config the way the plugin itself does at runtime
 * (index.ts's initInterceptor): the module's DEFAULT_CONFIG with this box's
 * `~/.shieldcortex/config.json` → `interceptor` overrides merged over it.
 * Issue #94: probing with bare DEFAULT_CONFIG was a false-green — a box whose
 * config had opted enforcement down (or re-tuned failurePolicy) was "proven"
 * with settings it doesn't actually run. Any read/parse failure falls back to
 * the defaults, which is exactly what the runtime does with a corrupt config.
 */
export function resolveBoxInterceptorConfig(home: string, defaults: unknown): unknown {
  const base = (defaults && typeof defaults === 'object' ? defaults : {}) as Record<string, unknown>;
  try {
    const raw = JSON.parse(fs.readFileSync(path.join(home, '.shieldcortex', 'config.json'), 'utf-8'));
    const overrides = raw?.interceptor;
    if (!overrides || typeof overrides !== 'object') return { ...base };
    return {
      ...base,
      enabled: overrides.enabled ?? (base.enabled as boolean | undefined),
      severityActions: { ...(base.severityActions as object | undefined), ...(overrides.severityActions ?? {}) },
      failurePolicy: { ...(base.failurePolicy as object | undefined), ...(overrides.failurePolicy ?? {}) },
      actionGuard: { ...(base.actionGuard as object | undefined ?? { enabled: false, enforce: true, autoApprove: [] }), ...(overrides.actionGuard ?? {}) },
    };
  } catch {
    return { ...base };
  }
}

export async function dispatchCanaryThroughInstalledInterceptor(
  home: string,
  _pluginId: string,
  nonce: string,
  deps: ActiveDispatchDeps,
): Promise<{ dispatched: boolean; detail?: string }> {
  const installPath = deps.resolveInstallPath(home);
  if (!installPath) {
    return { dispatched: false, detail: 'realtime plugin not found on disk — cannot dispatch through the live interceptor' };
  }

  let mod: InterceptorLikeModule | null;
  try {
    mod = await deps.loadInterceptorModule(installPath);
  } catch (err) {
    return { dispatched: false, detail: `could not load the installed interceptor module: ${errMsg(err)}` };
  }
  if (!mod || typeof mod.createInterceptor !== 'function' || mod.DEFAULT_CONFIG == null) {
    return { dispatched: false, detail: 'installed interceptor module missing createInterceptor/DEFAULT_CONFIG — cannot actively probe' };
  }

  let interceptor: ReturnType<InterceptorLikeModule['createInterceptor']>;
  try {
    // Quiet logger: canary deny is expected. Dumping action-guard BLOCKED on
    // stderr during `update` scares customers into thinking the upgrade failed.
    const baseCfg: any = resolveBoxInterceptorConfig(home, mod.DEFAULT_CONFIG);
    const quietCfg = { ...baseCfg, logger: { info: () => {}, warn: () => {} } };
    interceptor = mod.createInterceptor(quietCfg, benignPipeline, { evaluateToolCall: deps.evaluator });
  } catch (err) {
    return { dispatched: false, detail: `failed to construct the installed interceptor: ${errMsg(err)}` };
  }

  const op = buildSyntheticCanaryOp(nonce);
  try {
    await interceptor.handleToolCall(op);
    // No throw ⇒ the interceptor did NOT block. The op WAS dispatched, but the
    // absence of a deny is surfaced by findFresh (denied:false → loud fail).
  } catch {
    // A block throws AFTER writing the audit entry — the enforcement firing IS
    // the success signal here; swallow it and let findFresh confirm the deny.
  }
  return { dispatched: true, detail: `synthetic canary (nonce ${nonce}) dispatched through the installed interceptor at ${installPath}` };
}

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** Default active-dispatch seams: the installed-plugin discovery helper (#77),
 * a filesystem import of the installed interceptor, and the real evaluator. */
const defaultActiveDispatchDeps: ActiveDispatchDeps = {
  resolveInstallPath: (home) => resolveRealtimePluginInstallPath(home),
  loadInterceptorModule: defaultLoadInterceptorModule,
  evaluator: (toolName, args) => evaluateToolCall(toolName, args),
};

/** Import the installed plugin's compiled interceptor from its package dir.
 * Best-effort across the shipped layouts (`dist/interceptor.js`, root
 * `interceptor.js`); returns null when none resolves so dispatch fails closed. */
async function defaultLoadInterceptorModule(installPath: string): Promise<InterceptorLikeModule | null> {
  const candidates = [
    path.join(installPath, 'dist', 'interceptor.js'),
    path.join(installPath, 'interceptor.js'),
  ];
  for (const candidate of candidates) {
    if (!fs.existsSync(candidate)) continue;
    const mod = (await import(pathToFileURL(candidate).href)) as Partial<InterceptorLikeModule>;
    if (typeof mod.createInterceptor === 'function' && mod.DEFAULT_CONFIG != null) {
      return mod as InterceptorLikeModule;
    }
  }
  return null;
}

/**
 * The guarded live dispatch seam. Fail-closed by design:
 *   - Under a Jest worker → never dispatches (`ran:false` upstream).
 *   - Without the explicit `SHIELDCORTEX_ALLOW_GATEWAY_CANARY=1` consent env →
 *     identical to the 4.47.3 behaviour: honest "roster proof stands;
 *     enforcement not actively proven".
 *   - With consent → drives the harmless synthetic op through the INSTALLED
 *     interceptor (the real enforcement path) and reports whether it dispatched;
 *     the deny/audit is then confirmed by the fresh nonce gate. A dispatch that
 *     fails or is unobservable is reported loudly as NOT proven — never faked.
 */
export async function defaultTriggerSyntheticOp(
  home: string,
  pluginId: string,
  nonce: string,
): Promise<{ dispatched: boolean; detail?: string }> {
  if (process.env.JEST_WORKER_ID !== undefined) {
    return { dispatched: false, detail: 'skipped under test runner' };
  }
  // #156: a human at a terminal has consented. The probe is harmless by
  // construction (a synthetic recursive-delete of a non-existent /tmp path,
  // evaluated and audited BEFORE any execution), and requiring a third env var
  // to prove enforcement is what made "am I protected?" unanswerable in
  // practice. Headless runs still require the explicit env.
  if (!resolveRepairConsent({ env: process.env, isTty: Boolean(process.stdin.isTTY) }).canary) {
    return {
      dispatched: false,
      detail: 'live canary requires SHIELDCORTEX_ALLOW_GATEWAY_CANARY=1 (drives a synthetic op through the live interceptor) — roster proof stands; enforcement not actively proven',
    };
  }
  // Consent given: perform the real active dispatch through the installed
  // interceptor. Never fabricate — on any failure this returns dispatched:false.
  return dispatchCanaryThroughInstalledInterceptor(home, pluginId, nonce, defaultActiveDispatchDeps);
}

export interface FreshEnforcementQuery {
  /** Unique per-probe marker the synthetic op carried; the audit entry must include it. */
  nonce: string;
  /** Probe start (ms). The matching deny must be at/after this instant. */
  sinceMs: number;
}

/**
 * Look for a FRESH, nonce-matched deny/block in `~/.shieldcortex/audit/realtime-*.jsonl`.
 *
 * Both gates are required and each independently kills the #74 false-positive:
 *   - timestamp >= probe start  ⇒ a stale pre-break deny cannot count, and
 *   - the raw entry contains the unique probe nonce ⇒ unrelated live traffic
 *     cannot count.
 *
 * Best-effort and read-only; returns { found:false } on any error.
 */
export function findFreshEnforcementEntry(
  home: string,
  query: FreshEnforcementQuery,
): { found: boolean; at?: string } {
  try {
    const auditDir = path.join(home, '.shieldcortex', 'audit');
    const files = fs
      .readdirSync(auditDir)
      .filter((f) => f.startsWith('realtime-') && f.endsWith('.jsonl'))
      .sort()
      .reverse();
    for (const file of files.slice(0, 2)) {
      const lines = fs.readFileSync(path.join(auditDir, file), 'utf-8').trim().split('\n');
      for (let i = lines.length - 1; i >= 0; i--) {
        const line = lines[i].trim();
        if (!line) continue;
        // Nonce gate first: the unique marker must appear in the raw entry.
        if (!line.includes(query.nonce)) continue;
        let ev: { ts?: string; timestamp?: string; decision?: string; action?: string };
        try {
          ev = JSON.parse(line);
        } catch {
          continue;
        }
        const decision = String(ev.decision ?? ev.action ?? '').toLowerCase();
        if (!/deny|block/.test(decision)) continue;
        const tsStr = ev.ts ?? ev.timestamp;
        const ts = tsStr ? Date.parse(tsStr) : NaN;
        // Freshness gate: strictly at/after probe start.
        if (!Number.isNaN(ts) && ts >= query.sinceMs) return { found: true, at: tsStr };
      }
    }
  } catch {
    // fall through
  }
  return { found: false };
}
