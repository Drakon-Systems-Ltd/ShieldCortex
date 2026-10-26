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

import { getConfigDir, inspectConfigIntegrity, type ConfigIntegrityReport } from '../cloud/config.js';
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
  /** The posture doctor's status grades (strict on tamper, lock applied — the old config-row view). */
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
 */
function runtimeBase(inputs: PostureInputs): Record<string, unknown> {
  return inputs.signedRaw ?? {};
}

function resolveHook(inputs: PostureInputs): PlaneResult | null {
  if (!inputs.claudeWired) return null;
  const locked = applyPolicyLock(runtimeBase(inputs), inputs.lock);
  return {
    plane: 'claude',
    label: PLANE_LABEL.claude,
    posture: postureOfGuard(guardOf(locked)),
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

  const base = runtimeBase(inputs);
  const baseGuard = guardOf(base);
  const config = isBlock(entry.config) ? entry.config : {};
  const entryGuard = guardOf(config);
  // mergeConfigs: entry wins per key; the readiness gate comes from the base only.
  const merged: Record<string, unknown> = { ...baseGuard, ...entryGuard };
  if (baseGuard.readinessGate === true) merged.readinessGate = true;
  else delete merged.readinessGate;
  const entryInterceptor = isBlock(config.interceptor) ? config.interceptor : {};

  // applyPolicyLockToPluginConfig: the lock over the merge.
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
  // Only a fresh self-report from a process that has not ended.
  if (r.configured_posture.method !== 'process-self-report' || r.membership === 'ended') return null;
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
  const unverified = recs.some((r) => hermesValue(r) !== null && r.membership !== 'current');
  return {
    plane: 'hermes',
    label: PLANE_LABEL.hermes,
    // The loosest value is the one that matters for a gate.
    posture: distinct[0],
    ...(distinct.length > 1 ? { values: distinct } : {}),
    source: unverified ? 'self-report, liveness unverified' : 'self-report',
    overrides: [],
  };
}

/** The signed posture, lock applied — null when the file cannot be trusted. */
function signedPosture(inputs: PostureInputs): PlanePosture | null {
  const v = inputs.integrity;
  if (v === 'tampered' || v === 'unreadable' || v === 'malformed' || v === 'unverified') return null;
  return postureOfGuard(guardOf(applyPolicyLock(inputs.signedRaw ?? {}, inputs.lock)));
}

/** The view the old `Action guard config` row graded: strict on tamper, lock applied. */
function gradedPosture(inputs: PostureInputs): PlanePosture {
  const raw = inputs.signedRaw ?? {};
  const trusted = inputs.integrity === 'tampered' ? applyStrictFailClosedPosture(raw) : raw;
  return postureOfGuard(guardOf(applyPolicyLock(trusted, inputs.lock)));
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
  return {
    signed: signedPosture(inputs),
    integrity: inputs.integrity,
    graded,
    gradedKey: gradedKeyOf(inputs, graded),
    planes,
    verdict,
    reference,
    hermesTighter,
    hermesLooser,
    nodeMismatch,
    nodeReference: nodeValues.length === 1 ? nodeValues[0] : null,
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
    integrity: inspectConfigIntegrity().verdict,
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
}

const OFF_FIX = 'Action Guard is off. That is the default. Do not enable Action Guard from this warning. Do not add a webhook.';
const ADVISORY_FIX =
  'Action Guard is advisory. Do not run --action-guard-enforce from this warning. Enable only after the review loop says yes.';
const HERMES_SOURCE_NOTE =
  'Hermes takes its posture from SHIELDCORTEX_ENFORCE in the Hermes gateway environment, not from config.json; no ShieldCortex command changes it today.';

/**
 * The fix for a hook/plugin mismatch. A `$` command only when it can turn
 * nothing on: the signed posture is off or advisory AND no plane is looser
 * than it. The command is the existing signed setter, which mirrors the same
 * value onto the OpenClaw plugin entry.
 */
function mismatchFix(report: PostureReport): string {
  const s = report.signed;
  if (s === null) {
    return `The signed config cannot be trusted (integrity: ${report.integrity}), so there is no signed posture to restore. ` +
      'Resolve the config integrity row first; this row names no posture command.';
  }
  const compared = report.planes.filter((p) => p.posture !== null);
  const noneLooser = compared.every((p) => (p.values ?? [p.posture as PlanePosture]).every((v) => POSTURE_RANK[v] >= POSTURE_RANK[s]));
  const hermesNote = report.hermesLooser ? ` ${HERMES_SOURCE_NOTE}` : '';
  if (report.nodeMismatch && noneLooser && (s === 'off' || s === 'advisory')) {
    const cmd = s === 'off' ? 'shieldcortex config --action-guard-disable' : 'shieldcortex config --action-guard-advisory';
    return `Run \`${cmd}\` to put the signed posture (${s}) back on the OpenClaw plugin entry, then restart the OpenClaw gateway. ` +
      `It turns nothing on.${hermesNote}`;
  }
  return `The signed posture is ${s}. Putting every plane on it would turn a plane up, so this row names no command: ` +
    'decide which posture you want. `shieldcortex guard posture --help` lists where each plane reads its posture.' +
    hermesNote;
}

function signedClause(report: PostureReport): string {
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
    };
  }
  const graded = report.verdict === 'none' ? report.graded : report.reference ?? report.graded;
  const status: GuardPostureRow['status'] = graded === 'off' || graded === 'advisory' ? 'warn' : 'pass';
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
