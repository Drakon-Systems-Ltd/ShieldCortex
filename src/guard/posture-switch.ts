/**
 * #922 slice 1, read-only half: the EFFECTIVE Action Guard posture of every
 * gate plane on this box, resolved once, so `shieldcortex doctor` and
 * `shieldcortex guard posture` cannot disagree about it.
 *
 * Planes:
 *   - Claude Code hook — reads `config.json` with a bare parse (the hook does
 *     not verify `_sig`), then the policy lock (scripts/pre-tool-hook.mjs
 *     `loadActionGuardConfig`).
 *   - OpenClaw plugin — the `openclaw.json` plugin entry deep-merges OVER the
 *     shield config, then the policy lock (plugins/openclaw/index.ts
 *     `mergeConfigs` → `applyPolicyLockToPluginConfig`). Reading the entry
 *     alone is how the #634 shape (signed enforce, entry `enforce:false`)
 *     stayed a host-table word instead of a failure.
 *   - Hermes plugin — does not read ShieldCortex config at all today; its
 *     posture is `SHIELDCORTEX_ENFORCE` in the Hermes gateway environment. The
 *     only evidence here is its #613 self-report, so that is all this reads.
 *
 * The three readers live in three build units and cannot share an import;
 * this file mirrors the Node-side rules by hand, like doctor already does.
 *
 * Nothing here writes. There is no writer in this release.
 */
import fs from 'fs';
import path from 'path';

import {
  configPostureOutlook,
  describeAdoptionBlock,
  getConfigDir,
  inspectConfigIntegrity,
  type ConfigIntegrityReport,
  type UnsignedAdoptionBlock,
} from '../cloud/config.js';
import {
  applyPolicyLock,
  applyStrictFailClosedPosture,
  readPolicyLock,
  type PolicyLockState,
} from '../defence/iron-dome/policy-lock.js';
import { collectPostureRecords, type CollectOptions } from '../posture/collect.js';
import type { PostureRecord } from '../posture/posture-record.js';
import { claudeToolGateWired } from '../setup/host-table.js';
import { openClawEffectiveHome } from '../setup/openclaw-effective-home.js';

export type PlanePosture = 'off' | 'advisory' | 'enforce-when-ready' | 'enforce';

export type PlaneId = 'claude' | 'openclaw' | 'hermes';

/** Lower is looser. */
export const POSTURE_RANK: Record<PlanePosture, number> = {
  off: 0,
  advisory: 1,
  'enforce-when-ready': 2,
  enforce: 3,
};

export const PLANE_LABEL: Record<PlaneId, string> = {
  claude: 'Claude Code hook',
  openclaw: 'OpenClaw plugin',
  hermes: 'Hermes',
};

export const GUARD_POSTURE_LABEL = 'Action guard posture';

const REALTIME_IDS = ['shieldcortex-realtime', '@drakon-systems/shieldcortex-realtime'] as const;

export type OpenClawInput =
  | { state: 'absent' }
  | { state: 'unreadable'; detail: string }
  | { state: 'malformed' }
  | { state: 'ok'; raw: Record<string, unknown> };

export interface PostureInputs {
  /** `config.json` parsed the way the hook parses it; null when absent or unparsable. */
  signedRaw: Record<string, unknown> | null;
  integrity: ConfigIntegrityReport['verdict'];
  /**
   * #878: why an unsigned config.json cannot be adopted (integrity is then
   * `unverified`), from {@link inspectConfigIntegrity}. The signed posture is
   * unknown and is graded as the strict posture the runtime holds — never as
   * the file's own values.
   */
  integrityAdoption?: UnsignedAdoptionBlock;
  /**
   * #878 r5: config.json is a symbolic link ({@link inspectConfigIntegrity}'s
   * `linked`). The hook and the runtime hold a linked file strict unless its
   * signature authenticates it (`valid` / `self-heal`).
   */
  integrityLinked?: boolean;
  lock: PolicyLockState;
  claudeWired: boolean;
  openclaw: OpenClawInput;
  /** #613 records; only `hermes` tool-gate records are read. */
  postureRecords: PostureRecord[];
}

export interface PlaneResult {
  plane: PlaneId;
  label: string;
  /** null = present but the posture cannot be determined; not compared. */
  posture: PlanePosture | null;
  /** Hermes only: more than one value across reporting profiles/instances. */
  values?: PlanePosture[];
  /** Where the value came from, or why it is unknown. */
  source: string;
  /** Overlay keys that make this plane differ from the signed config. */
  overrides: string[];
  /** OpenClaw: host-level `entries[...].enabled:false`. */
  dormant?: boolean;
}

export type PostureVerdict = 'agree' | 'mismatch' | 'none';

export interface PostureReport {
  /** Signed posture with the lock applied, or null when the signed file cannot be trusted. */
  signed: PlanePosture | null;
  integrity: ConfigIntegrityReport['verdict'];
  /** #878: see {@link PostureInputs.integrityAdoption}. */
  integrityAdoption?: UnsignedAdoptionBlock;
  /**
   * The posture doctor's status grades (lock applied — the old config-row
   * view): strict on tamper, and strict for an unsigned file that cannot be
   * adopted (#878), which the runtime holds strict.
   */
  graded: PlanePosture;
  /** The config key behind `graded` when it is off/advisory: top-level, else the #209 alias. */
  gradedKey: string | null;
  planes: PlaneResult[];
  verdict: PostureVerdict;
  /** The posture every compared plane holds when they agree; Hermes is compared against it. */
  reference: PlanePosture | null;
  /** Hermes holds a tighter posture than the hook/plugin (pending owner decision, not a failure). */
  hermesTighter: boolean;
  /** Hermes holds a looser posture than the hook/plugin, or disagrees with itself. */
  hermesLooser: boolean;
  /** The hook and the plugin disagree with each other. */
  nodeMismatch: boolean;
  /** The posture the hook and plugin agree on, or null (none known, or they disagree). Hermes excluded. */
  nodeReference: PlanePosture | null;
  /**
   * #1063 r2: raising the signed setting to a stricter plane's posture would
   * turn some compared plane up ({@link signedRaiseTurnsPlaneUp}). False when
   * the signed posture is unknown or no plane sits above it.
   */
  signedRaiseTurnsPlaneUp: boolean;
}

function isBlock(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

/** Top-level `actionGuard` over the deprecated `interceptor.actionGuard` alias (#209). */
function guardOf(raw: Record<string, unknown>): Record<string, unknown> {
  const interceptor = isBlock(raw.interceptor) ? raw.interceptor : {};
  const alias = isBlock(interceptor.actionGuard) ? interceptor.actionGuard : {};
  const top = isBlock(raw.actionGuard) ? raw.actionGuard : {};
  return { ...alias, ...top };
}

function postureOfGuard(guard: Record<string, unknown>): PlanePosture {
  if (guard.enabled !== true) return 'off';
  if (guard.enforce === false) return 'advisory';
  return guard.readinessGate === true ? 'enforce-when-ready' : 'enforce';
}

function lockPresent(lock: PolicyLockState): boolean {
  return lock.status === 'locked' || lock.status === 'unverifiable';
}

/**
 * The base both runtime readers start from: the file as parsed, with no
 * signature check. Neither the hook (`loadActionGuardConfig`) nor the plugin
 * (the runtime's `loadShieldConfig`) verifies `_sig`, so a tampered file is
 * what they run on; only the policy lock changes it. Doctor's integrity row
 * reports the tamper itself.
 *
 * #878 r4/r5: one exception both readers DO apply — a config.json behind a
 * symbolic link that no signature authenticates is held at the strict
 * fail-closed posture, before the lock and the #209 fold. Unsigned
 * (`unverified`, adoption blocked by the link) and, since r5, `tampered`: both
 * readers recompute the HMAC for a link (scripts/lib/config-authenticity.mjs,
 * the same check as checkConfigIntegrity), so a dummy `_sig` or a junk
 * `.config-sig` no longer passes. Only `valid` / `self-heal` are honoured. The
 * planes must report that, not the target's own values. A regular tampered
 * file is still what the readers run on (above).
 */
function runtimeBase(inputs: PostureInputs): Record<string, unknown> {
  const raw = inputs.signedRaw ?? {};
  if (inputs.signedRaw === null) return raw;
  if (inputs.integrity === 'unverified' && inputs.integrityAdoption === 'linked') {
    return applyStrictFailClosedPosture(raw);
  }
  if (inputs.integrityLinked === true && inputs.integrity !== 'valid' && inputs.integrity !== 'self-heal') {
    return applyStrictFailClosedPosture(raw);
  }
  return raw;
}

/**
 * The hook's view: lock, then the #209 fold. pre-tool-hook.mjs honours
 * readinessGate only when no lock file is present (`inlinePolicyLockPresent`),
 * whichever block it came from — `applyPolicyLock` strips the top-level key,
 * not the alias one, so it is dropped here too.
 */
function lockedGuardOf(raw: Record<string, unknown>, lock: PolicyLockState): Record<string, unknown> {
  const guard = guardOf(applyPolicyLock(raw, lock));
  if (lockPresent(lock)) delete guard.readinessGate;
  return guard;
}

function resolveHook(inputs: PostureInputs): PlaneResult | null {
  if (!inputs.claudeWired) return null;
  return {
    plane: 'claude',
    label: PLANE_LABEL.claude,
    posture: postureOfGuard(lockedGuardOf(runtimeBase(inputs), inputs.lock)),
    source: 'config.json actionGuard',
    overrides: lockPresent(inputs.lock) ? ['policy lock applied'] : [],
  };
}

function openclawEntry(raw: Record<string, unknown>): Record<string, unknown> | null {
  const plugins = isBlock(raw.plugins) ? raw.plugins : null;
  const entries = plugins && isBlock(plugins.entries) ? plugins.entries : null;
  if (!entries) return null;
  for (const id of REALTIME_IDS) {
    if (isBlock(entries[id])) return entries[id] as Record<string, unknown>;
  }
  return null;
}

const PLUGIN_GUARD_BOOLEANS = ['enabled', 'enforce', 'readinessGate'] as const;

/**
 * plugins/openclaw/index.ts `normaliseActionGuardBlock`, for the keys a posture
 * reads: a non-boolean is DROPPED (the #112 `"false"` typo must not change the
 * plugin), so it cannot change this report either. Differs from the hook on
 * purpose — the hook's bare parse reads `enforce !== false`.
 */
function pluginGuardBlock(raw: unknown): Record<string, boolean> {
  if (!isBlock(raw)) return {};
  const out: Record<string, boolean> = {};
  for (const k of PLUGIN_GUARD_BOOLEANS) {
    if (typeof raw[k] === 'boolean') out[k] = raw[k] as boolean;
  }
  return out;
}

/**
 * plugins/openclaw/index.ts `normaliseConfig` for one file: each block is
 * validated BEFORE the #209 alias fold, so an invalid top-level key does not
 * hide a valid alias value.
 */
function pluginGuardOf(raw: Record<string, unknown>): Record<string, boolean> {
  const interceptor = isBlock(raw.interceptor) ? raw.interceptor : {};
  return { ...pluginGuardBlock(interceptor.actionGuard), ...pluginGuardBlock(raw.actionGuard) };
}

function resolveOpenClaw(inputs: PostureInputs): PlaneResult | null {
  const oc = inputs.openclaw;
  if (oc.state === 'absent') return null;
  if (oc.state !== 'ok') {
    return {
      plane: 'openclaw',
      label: PLANE_LABEL.openclaw,
      posture: null,
      source: oc.state === 'malformed' ? 'openclaw.json is not valid JSON' : `openclaw.json could not be read (${oc.detail})`,
      overrides: [],
    };
  }
  const entry = openclawEntry(oc.raw);
  if (!entry) return null;

  // Validated per file, then merged (mergeConfigs): entry wins per key; the
  // readiness gate comes from the base only.
  const baseGuard = pluginGuardOf(runtimeBase(inputs));
  const config = isBlock(entry.config) ? entry.config : {};
  const entryGuard = pluginGuardOf(config);
  const merged: Record<string, unknown> = { ...baseGuard, ...entryGuard };
  if (baseGuard.readinessGate === true) merged.readinessGate = true;
  else delete merged.readinessGate;
  const entryInterceptor = isBlock(config.interceptor) ? config.interceptor : {};

  // applyPolicyLockToPluginConfig: the lock over the merge. It also re-arms
  // the interceptor whenever the locked guard is enabled (withGuardPosture), so
  // a shield-file `interceptor.enabled:false` cannot leave an enabled guard
  // ungated — and with the guard not enabled the posture is off regardless.
  const lockedGuard = guardOf(applyPolicyLock({ actionGuard: merged }, inputs.lock));
  // register(): an entry `interceptor.enabled:false` on a host with no lock
  // means before_tool_call is never registered — no gate, whatever the guard
  // keys say. With a lock present the hook registers and the lock decides.
  const interceptorOff = entryInterceptor.enabled === false && !lockPresent(inputs.lock);

  const overrides: string[] = [];
  for (const k of ['enabled', 'enforce'] as const) {
    if (k in entryGuard && entryGuard[k] !== baseGuard[k]) {
      overrides.push(`openclaw.json plugin entry actionGuard.${k}=${String(entryGuard[k])} overrides signed`);
    }
  }
  if (interceptorOff) overrides.push('openclaw.json plugin entry interceptor.enabled=false');
  const dormant = entry.enabled === false;
  if (dormant) overrides.push('plugin disabled in openclaw.json');
  if (lockPresent(inputs.lock)) overrides.push('policy lock applied');

  return {
    plane: 'openclaw',
    label: PLANE_LABEL.openclaw,
    posture: dormant || interceptorOff ? 'off' : postureOfGuard(lockedGuard),
    source: 'config.json actionGuard merged with the openclaw.json plugin entry',
    overrides,
    ...(dormant ? { dormant: true } : {}),
  };
}

function hermesValue(r: PostureRecord): PlanePosture | null {
  // Only a self-report from a process shown to be running now (#613
  // `postureLevel`): an unverified or unobserved one is unknown, not its claim.
  if (r.configured_posture.method !== 'process-self-report' || r.membership !== 'current') return null;
  if (r.runtime_loaded.value === 'no') return 'off';
  switch (r.configured_posture.value) {
    case 'enforce': return 'enforce';
    case 'advisory': return 'advisory';
    case 'intentionally-off': return 'off';
    default: return null;
  }
}

function resolveHermes(inputs: PostureInputs): PlaneResult | null {
  const recs = inputs.postureRecords.filter((r) => r.runtime === 'hermes' && r.plane === 'tool-gate');
  const values = recs.map(hermesValue).filter((v): v is PlanePosture => v !== null);
  const installed = recs.some((r) => r.installed.value === 'yes');
  if (!installed && values.length === 0) return null;
  const distinct = [...new Set(values)].sort((a, b) => POSTURE_RANK[a] - POSTURE_RANK[b]);
  if (distinct.length === 0) {
    return {
      plane: 'hermes',
      label: PLANE_LABEL.hermes,
      posture: null,
      source: 'no current #613 self-report from a Hermes process',
      overrides: [],
    };
  }
  return {
    plane: 'hermes',
    label: PLANE_LABEL.hermes,
    // The loosest value is the one that matters for a gate.
    posture: distinct[0],
    ...(distinct.length > 1 ? { values: distinct } : {}),
    source: 'self-report',
    overrides: [],
  };
}

/** The integrity report these inputs carry, in the shape {@link configPostureOutlook} reads. */
function outlookOf(inputs: PostureInputs): ReturnType<typeof configPostureOutlook> {
  return configPostureOutlook({ verdict: inputs.integrity, adoption: inputs.integrityAdoption });
}

/** The signed posture, lock applied — null when the file cannot be trusted. */
function signedPosture(inputs: PostureInputs): PlanePosture | null {
  const v = inputs.integrity;
  if (v === 'unreadable' || v === 'malformed' || v === 'unverified') return null;
  if (outlookOf(inputs) !== 'file') return null;
  return postureOfGuard(lockedGuardOf(inputs.signedRaw ?? {}, inputs.lock));
}

/**
 * The view the old `Action guard config` row graded, lock applied: the
 * strict posture wherever the runtime enforces it over the file's values —
 * tampered, and (#878) an unsigned file that cannot be adopted.
 */
function gradedPosture(inputs: PostureInputs): PlanePosture {
  const raw = inputs.signedRaw ?? {};
  const trusted = outlookOf(inputs) === 'file' ? raw : applyStrictFailClosedPosture(raw);
  return postureOfGuard(lockedGuardOf(trusted, inputs.lock));
}

function gradedKeyOf(inputs: PostureInputs, graded: PlanePosture): string | null {
  const k = graded === 'off' ? 'enabled' : graded === 'advisory' ? 'enforce' : null;
  if (!k) return null;
  const raw = inputs.signedRaw ?? {};
  const top = isBlock(raw.actionGuard) ? raw.actionGuard : {};
  const interceptor = isBlock(raw.interceptor) ? raw.interceptor : {};
  const alias = isBlock(interceptor.actionGuard) ? interceptor.actionGuard : {};
  return k in top || !(k in alias) ? `actionGuard.${k}` : `interceptor.actionGuard.${k}`;
}

/**
 * The top-level `actionGuard` keys that make config.json read as `posture`.
 * Every key a posture reads is set as a boolean, so the #209 alias cannot gap-fill
 * one and the plugin's boolean filter keeps them all.
 */
const POSTURE_KEYS: Record<PlanePosture, Record<string, boolean>> = {
  off: { enabled: false },
  advisory: { enabled: true, enforce: false, readinessGate: false },
  'enforce-when-ready': { enabled: true, enforce: true, readinessGate: true },
  enforce: { enabled: true, enforce: true, readinessGate: false },
};

/**
 * #1063 r2: whether raising the signed setting to a stricter plane's posture
 * would turn some compared plane up. Each compared Claude Code hook and
 * OpenClaw plane is re-read, through its own reader, over a config.json carrying
 * that posture. The hook follows the file. The plugin follows it unless its own
 * entry holds it (an entry key, a disabled entry, `interceptor.enabled:false`).
 * Hermes does not read config.json, so it never counts: with the hook unwired
 * and no OpenClaw entry following the file, raising the signed setting changes
 * no compared plane.
 */
function signedRaiseTurnsPlaneUp(inputs: PostureInputs, signed: PlanePosture | null, planes: PlaneResult[]): boolean {
  if (signed === null) return false;
  const followers = planes.filter((p) => p.plane !== 'hermes' && p.posture !== null);
  const targets = new Set(
    planes
      .flatMap((p) => p.values ?? (p.posture === null ? [] : [p.posture]))
      .filter((v) => POSTURE_RANK[v] > POSTURE_RANK[signed]),
  );
  for (const target of targets) {
    const raw = inputs.signedRaw ?? {};
    const guard = isBlock(raw.actionGuard) ? raw.actionGuard : {};
    const raised: PostureInputs = { ...inputs, signedRaw: { ...raw, actionGuard: { ...guard, ...POSTURE_KEYS[target] } } };
    for (const p of followers) {
      const next = (p.plane === 'claude' ? resolveHook(raised) : resolveOpenClaw(raised))?.posture ?? null;
      if (next !== null && POSTURE_RANK[next] > POSTURE_RANK[p.posture as PlanePosture]) return true;
    }
  }
  return false;
}

/** Pure. Same inputs, same report. */
export function resolvePlanePostures(inputs: PostureInputs): PostureReport {
  const planes = [resolveHook(inputs), resolveOpenClaw(inputs), resolveHermes(inputs)].filter(
    (p): p is PlaneResult => p !== null,
  );
  const node = planes.filter((p) => p.plane !== 'hermes' && p.posture !== null);
  const nodeValues = [...new Set(node.map((p) => p.posture as PlanePosture))];
  const nodeMismatch = nodeValues.length > 1;
  const hermes = planes.find((p) => p.plane === 'hermes' && p.posture !== null);
  const hermesValues = hermes ? hermes.values ?? [hermes.posture as PlanePosture] : [];

  let reference: PlanePosture | null = null;
  let hermesTighter = false;
  let hermesLooser = hermesValues.length > 1;
  if (!nodeMismatch && nodeValues.length === 1) {
    reference = nodeValues[0];
    for (const h of hermesValues) {
      if (POSTURE_RANK[h] < POSTURE_RANK[reference]) hermesLooser = true;
      else if (POSTURE_RANK[h] > POSTURE_RANK[reference]) hermesTighter = true;
    }
  } else if (nodeValues.length === 0 && hermesValues.length === 1) {
    reference = hermesValues[0];
  }

  const compared = node.length + (hermes ? 1 : 0);
  const graded = gradedPosture(inputs);
  const verdict: PostureVerdict = nodeMismatch || hermesLooser ? 'mismatch' : compared === 0 ? 'none' : 'agree';
  const signed = signedPosture(inputs);
  return {
    signed,
    integrity: inputs.integrity,
    ...(inputs.integrityAdoption ? { integrityAdoption: inputs.integrityAdoption } : {}),
    graded,
    gradedKey: gradedKeyOf(inputs, graded),
    planes,
    verdict,
    reference,
    hermesTighter,
    hermesLooser,
    nodeMismatch,
    nodeReference: nodeValues.length === 1 ? nodeValues[0] : null,
    signedRaiseTurnsPlaneUp: signedRaiseTurnsPlaneUp(inputs, signed, planes),
  };
}

// ── Reading the inputs (no writes, no adoption, no audit) ──────────────────

export interface ReadPostureOptions {
  /** Home for the Claude Code settings and Hermes artefact probes. */
  home?: string;
  configDir?: string;
  /** Path to openclaw.json; defaults to the OpenClaw-effective home doctor uses. */
  openclawPath?: string | null;
  collect?: Omit<CollectOptions, 'home' | 'configDir'>;
}

function readOpenClawInput(p: string | null): OpenClawInput {
  if (p === null) return { state: 'unreadable', detail: 'the OpenClaw home cannot be resolved' };
  let text: string;
  try {
    if (!fs.existsSync(p)) return { state: 'absent' };
    text = fs.readFileSync(p, 'utf-8');
  } catch (err) {
    return { state: 'unreadable', detail: (err as NodeJS.ErrnoException).code ?? 'read failed' };
  }
  try {
    const parsed = JSON.parse(text) as unknown;
    return isBlock(parsed) ? { state: 'ok', raw: parsed } : { state: 'malformed' };
  } catch {
    return { state: 'malformed' };
  }
}

export function defaultOpenClawConfigPath(): string | null {
  const resolved = openClawEffectiveHome();
  return 'unresolvable' in resolved ? null : path.join(resolved.home, '.openclaw', 'openclaw.json');
}

export function readPostureInputs(opts: ReadPostureOptions = {}): PostureInputs {
  const configDir = opts.configDir ?? getConfigDir();
  // The integrity reader only knows the default config dir; a different file
  // cannot be graded against it, so it is not called valid. #878: its report
  // is the one outlook every grading decision below reads.
  const integrity: Pick<ConfigIntegrityReport, 'verdict' | 'adoption'> & { linked?: boolean } =
    path.resolve(configDir) === path.resolve(getConfigDir()) ? inspectConfigIntegrity() : { verdict: 'unverified' };
  // The hook's own view of the file (a bare parse, as pre-tool-hook.mjs reads
  // it): what the hook and plugin PLANES resolve from. It decides no signed or
  // graded posture by itself — those go through `integrity` above.
  let signedRaw: Record<string, unknown> | null = null;
  try {
    const parsed = JSON.parse(fs.readFileSync(path.join(configDir, 'config.json'), 'utf-8')) as unknown;
    signedRaw = isBlock(parsed) ? parsed : null;
  } catch {
    signedRaw = null;
  }
  let postureRecords: PostureRecord[] = [];
  try {
    postureRecords = collectPostureRecords({ ...(opts.collect ?? {}), home: opts.home, configDir });
  } catch {
    postureRecords = [];
  }
  return {
    signedRaw,
    integrity: integrity.verdict,
    ...(integrity.adoption ? { integrityAdoption: integrity.adoption } : {}),
    ...(integrity.linked ? { integrityLinked: true } : {}),
    lock: readPolicyLock({ audit: false, warn: false }),
    claudeWired: claudeToolGateWired(opts.home),
    openclaw: readOpenClawInput(opts.openclawPath === undefined ? defaultOpenClawConfigPath() : opts.openclawPath),
    postureRecords,
  };
}

export function readGuardPosture(opts: ReadPostureOptions = {}): PostureReport {
  return resolvePlanePostures(readPostureInputs(opts));
}

// ── Rendering ──────────────────────────────────────────────────────────────

function planeWords(p: PlaneResult): string {
  if (p.posture === null) return `${p.label} unknown (${p.source})`;
  const value = p.values ? p.values.join(' and ') : p.posture;
  const notes = [...p.overrides.filter((o) => o !== 'policy lock applied')];
  if (p.plane === 'hermes') notes.unshift(p.source);
  return `${p.label} ${value}${notes.length > 0 ? ` (${notes.join('; ')})` : ''}`;
}

export interface GuardPostureRow {
  label: string;
  status: 'pass' | 'warn' | 'fail';
  message: string;
  fix?: string;
  /** #878: see DoctorReportItem.postureUnknown — the report prints this row's own fix. */
  postureUnknown?: true;
  /**
   * #1037: see DoctorReportItem.fixNoteWithCommands. A mismatch fix states
   * the consequence of each direction and names no posture command; its one
   * backticked command is an inspection step, so the report prints the prose
   * as well as that command.
   */
  fixNoteWithCommands?: true;
}

const OFF_FIX = 'Action Guard is off. That is the default. Do not enable Action Guard from this warning. Do not add a webhook.';
const ADVISORY_FIX =
  'Action Guard is advisory. Do not run --action-guard-enforce from this warning. Enable only after the review loop says yes.';
const HERMES_SOURCE_NOTE =
  'Hermes takes its posture from SHIELDCORTEX_ENFORCE in the Hermes gateway environment, not from config.json; no ShieldCortex command changes it today.';

/**
 * Whether a plane can hold a posture at all. Hermes implements no readiness gate
 * (guard-readiness.ts: the gate runs only in the Claude Code hook and the
 * OpenClaw interceptor; the Hermes plugin's SHIELDCORTEX_ENFORCE resolves to
 * enforce or advisory), so it has no enforce-when-ready.
 */
function planeCanHold(plane: PlaneId, posture: PlanePosture): boolean {
  return !(plane === 'hermes' && posture === 'enforce-when-ready');
}

/**
 * What matching a stricter plane down to each signed setting does to that
 * plane. `enforce` has no entry: no plane is stricter than it.
 *
 * `enforce-when-ready` describes a plane that runs the readiness gate. Over a
 * signed enforce-when-ready no such plane is stricter as resolved above: the
 * hook holds the signed value, and the plugin's readiness gate comes from the
 * signed file only, so its entry can only turn that plane down. The plane above
 * it is Hermes, which cannot hold it ({@link HERMES_NO_READINESS}).
 */
const DOWN_TO_SIGNED: Record<Exclude<PlanePosture, 'enforce'>, string> = {
  off: 'Matching the stricter plane down to the signed setting would turn Action Guard off on that plane.',
  advisory: 'Matching the stricter plane down to the signed setting would drop that plane to advisory ' +
    '(ordinary dangerous ops log but are not gated; catastrophic ops and changes to the guard itself are still held or blocked).',
  'enforce-when-ready': 'Matching the stricter plane down to the signed setting would drop that plane to enforce-when-ready, ' +
    'which stays in shadow until this install meets the readiness conditions ' +
    '(ordinary dangerous ops log but are not gated; catastrophic ops and changes to the guard itself are still held or blocked).',
};

/** #1063 r1: the down consequence for Hermes above a signed enforce-when-ready, which it cannot hold. */
const HERMES_NO_READINESS =
  'Hermes cannot be matched down to the signed setting: it has no enforce-when-ready posture. ' +
  'It enforces, or an explicit SHIELDCORTEX_ENFORCE opt-out makes it advisory.';

/**
 * The fix for a posture mismatch. Never a single command that turns
 * protection down (#1037): restoring the signed value onto a stricter plane
 * would loosen that plane, and raising the signed setting to the stricter
 * plane would turn a plane up. State both. Name neither.
 *
 * #1063: each direction is derived on its own, from every compared value
 * (Hermes profiles included). One plane can sit above the signed setting
 * while another sits below it; the row then states the down consequence for
 * the stricter plane and the up consequence for the looser one.
 *
 * #1063 r1: each consequence is stated only for a plane that can hold the
 * signed setting ({@link planeCanHold}). Hermes above a signed
 * enforce-when-ready gets {@link HERMES_NO_READINESS}, never the readiness
 * shadow, and is not counted as a looser plane that could be put on it.
 *
 * #1063 r2: the signed-setting-up consequence is stated only when raising the
 * signed setting would turn a compared plane up
 * ({@link PostureReport.signedRaiseTurnsPlaneUp}). Hermes does not read
 * config.json, so a Hermes-only stricter plane over an unwired hook gets no
 * such sentence.
 */
function mismatchFix(report: PostureReport): string {
  const s = report.signed;
  if (s === null) {
    return `The signed config cannot be trusted (integrity: ${report.integrity}), so there is no signed posture to restore. ` +
      'Resolve the config integrity row first; this row names no posture command.';
  }
  const compared = report.planes.filter((p) => p.posture !== null);
  const valuesOf = (p: PlaneResult): PlanePosture[] => p.values ?? [p.posture as PlanePosture];
  const above = compared.filter((p) => valuesOf(p).some((v) => POSTURE_RANK[v] > POSTURE_RANK[s]));
  const below = compared.filter((p) => valuesOf(p).some((v) => POSTURE_RANK[v] < POSTURE_RANK[s]));
  const help = '`shieldcortex guard posture --help` lists where each plane reads its posture.';
  if (above.length === 0 || s === 'enforce') {
    const hermesNote = report.hermesLooser ? ` ${HERMES_SOURCE_NOTE}` : '';
    return `The signed posture is ${s}. Putting every plane on it would turn a plane up, so this row names no command: ` +
      `decide which posture you want. ${help}` +
      hermesNote;
  }
  const hermesCannotHold = above.some((p) => !planeCanHold(p.plane, s));
  const down = [
    ...(above.some((p) => planeCanHold(p.plane, s)) ? [DOWN_TO_SIGNED[s]] : []),
    ...(hermesCannotHold ? [HERMES_NO_READINESS] : []),
  ].join(' ');
  const up = below.some((p) => planeCanHold(p.plane, s))
    ? ' Putting a looser plane on the signed setting would turn that plane up.'
    : '';
  const raise = report.signedRaiseTurnsPlaneUp
    ? ' Matching the signed setting up to the stricter plane would turn a plane up.'
    : '';
  const hermesNote = report.hermesLooser || hermesCannotHold ? ` ${HERMES_SOURCE_NOTE}` : '';
  return `${down}${up}${raise} This row names no command. ${help}${hermesNote}`;
}

/**
 * #878: the fix for any non-pass row while the signed posture is unknown
 * because config.json cannot be adopted. It names no posture command: the
 * operator resolves the integrity row first.
 */
const UNKNOWN_FIX =
  'The signed Action Guard posture is unknown until config.json can be adopted (see the config integrity row); ' +
  'the runtime holds the strict fail-closed posture meanwhile. Resolve that row first. This row names no posture ' +
  'command and does not enable Action Guard.';

function signedClause(report: PostureReport): string {
  if (report.signed === null && report.integrityAdoption) {
    return `signed posture unknown (integrity: unverified — ${describeAdoptionBlock(report.integrityAdoption)}; ` +
      'the runtime holds the strict fail-closed posture)';
  }
  if (report.signed === null) return `signed posture unknown (integrity: ${report.integrity})`;
  if (report.graded === 'off') return `Action Guard is off in signed config (\`${report.gradedKey}\` is not true)`;
  if (report.graded === 'advisory') return `signed config runs in warn-mode (\`${report.gradedKey}: false\`)`;
  return `signed ${report.graded}`;
}

/** The single doctor row. */
export function guardPostureRow(report: PostureReport): GuardPostureRow {
  const label = GUARD_POSTURE_LABEL;
  const words = report.planes.map(planeWords).join(', ');
  if (report.verdict === 'mismatch') {
    return {
      label,
      status: 'fail',
      message: `planes disagree — ${words}. One posture must hold on every plane.`,
      fix: mismatchFix(report),
      fixNoteWithCommands: true,
    };
  }
  const graded = report.verdict === 'none' ? report.graded : report.reference ?? report.graded;
  // #878: with no plane compared, an unknown signed posture is all there is
  // to report — a warn, never a pass (the strict grade is what the runtime
  // holds, not a posture anyone chose or can confirm here).
  const signedUnknown = configPostureOutlook({ verdict: report.integrity, adoption: report.integrityAdoption }) === 'unknown';
  const status: GuardPostureRow['status'] =
    graded === 'off' || graded === 'advisory' || (signedUnknown && report.verdict === 'none') ? 'warn' : 'pass';
  const unknown = report.planes.filter((p) => p.posture === null);
  const known = report.planes.filter((p) => p.posture !== null);
  const signed = signedClause(report);
  let message: string;
  if (report.verdict === 'none') {
    message = unknown.length > 0
      ? `${signed}; no plane's posture could be read — ${words}`
      : `${signed}; no gate plane is installed on this box`;
  } else {
    const ref = report.reference as PlanePosture;
    const names = known.filter((p) => !(p.plane === 'hermes' && report.hermesTighter)).map((p) => p.label);
    message = `${ref} on ${names.length === 1 ? 'the one' : `all ${names.length}`} compared plane${names.length === 1 ? '' : 's'} (${names.join(', ')})`;
    if (ref === 'advisory') message += ' — dangerous ops log but are not gated (catastrophic still blocks)';
    if (ref === 'off') message += ' — tool calls are not gated';
    const dormant = known.find((p) => p.dormant);
    if (dormant) message += `; ${dormant.label} disabled in openclaw.json`;
    if (report.hermesTighter) {
      const h = known.find((p) => p.plane === 'hermes')!;
      message += `; ${planeWords(h)} is tighter than the other planes. ${HERMES_SOURCE_NOTE}`;
    }
    if (unknown.length > 0) message += `; not compared: ${unknown.map(planeWords).join(', ')}`;
    message += `; ${signed}`;
  }
  if (status === 'pass') return { label, status, message };
  if (report.integrityAdoption) {
    return { label, status, message, fix: UNKNOWN_FIX, ...(signedUnknown ? { postureUnknown: true as const } : {}) };
  }
  return { label, status, message, fix: graded === 'off' ? OFF_FIX : ADVISORY_FIX };
}

/** Lines for `shieldcortex guard posture`. */
export function formatGuardPostureLines(report: PostureReport): string[] {
  const row = guardPostureRow(report);
  const lines: string[] = [];
  lines.push(`Action Guard posture (read-only) — signed: ${report.signed ?? `unknown (integrity: ${report.integrity})`}`);
  const all: PlaneId[] = ['claude', 'openclaw', 'hermes'];
  const width = Math.max(...all.map((id) => PLANE_LABEL[id].length));
  for (const id of all) {
    const p = report.planes.find((x) => x.plane === id);
    if (!p) {
      lines.push(`  ${PLANE_LABEL[id].padEnd(width)}  absent`);
      continue;
    }
    const value = p.posture === null ? 'unknown' : p.values ? p.values.join(' and ') : p.posture;
    const notes = p.posture === null ? [p.source] : [p.source, ...p.overrides];
    lines.push(`  ${p.label.padEnd(width)}  ${value.padEnd(18)}  ${notes.join('; ')}`);
  }
  lines.push(`${row.status === 'fail' ? 'MISMATCH' : row.status === 'warn' ? 'WARN' : 'OK'}: ${row.message}`);
  if (row.fix) lines.push(`Fix: ${row.fix}`);
  lines.push('Configured posture from files and self-reports, not a check of running processes. OpenClaw reads its plugin entry at gateway start.');
  return lines;
}
