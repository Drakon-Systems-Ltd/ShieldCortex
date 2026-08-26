/**
 * T1 host contract enforcement — evidence model (#393 / Track A #348).
 *
 * `sc_only` / `disable_native_inject` are bus laws, not labels: with either set,
 * native automatic memory must not own durable context on the hosts this box is
 * bound to. This module is the *pure* half of the proof — doctor reads the disk
 * and hands the readings in, these functions decide what was actually proven.
 *
 * Three rules shape every decision here:
 *
 *  1. **Absence is not proof.** A host config that is missing, unreadable, or
 *     silent on the relevant key resolves to `unknown` (or, where the host
 *     documents a default-ON feature, to `on`) — never to `off_proven`. The old
 *     check returned PASS with "no paper-contract signals on disk", which is
 *     precisely passing from absence.
 *  2. **Evidence is per runtime.** A finding on one host must never produce
 *     remediation for another. A Hermes-primary box was previously told to edit
 *     `agents.defaults.memorySearch` in an OpenClaw config it does not have.
 *  3. **Config intent is not enforcement.** SC-side config (`openclawAutoMemory`,
 *     `memory.hostContract.runtimes`) may only ADD a runtime to the set under
 *     scrutiny. It can never supply the off-proof — only a host's own setting or
 *     artifact state can do that.
 *
 * Normative law: docs/design/2026-08-17-memory-plane-policy-amin.md ("Host
 * contract (bound agents)") and docs/design/2026-08-22-memory-sota-track-a-residual.md
 * (T1, residual lock 9 — Hermes honest sidecar vs contract).
 */

import { isShieldCortexHookCommand, type HookCommandTrust } from '../setup/hook-command-resolution.js';

export const HOST_RUNTIMES = ['openclaw', 'claude_code', 'hermes'] as const;
export type HostRuntimeId = (typeof HOST_RUNTIMES)[number];

/** Legal honest-sidecar posture (residual lock 9). Never a `nativeContract` value. */
export const SIDECAR_POSTURE = 'mcp_sidecar_no_inject';

/**
 * Native automatic-memory ownership on one runtime.
 * `off_proven` requires a positive reading; the other two never PASS.
 */
export type NativeBusState = 'off_proven' | 'on' | 'unknown';

/**
 * Whether ShieldCortex's own automatic pack is wired on that runtime.
 * `wired_proven` is STATIC proof only — the artifact set and host config are
 * verified on disk, but doctor cannot attest that the host actually delivered
 * a pack at runtime, so no message downstream may claim a delivered receipt.
 */
export type ScBusState = 'wired_proven' | 'not_wired' | 'unknown';

export type ProbeRead<T> =
  | { kind: 'present'; value: T }
  | { kind: 'absent' }
  | { kind: 'unreadable'; detail: string };

export type ArtifactProbe =
  | { kind: 'present'; path: string; mtimeMs: number; size: number }
  | { kind: 'absent'; path: string }
  | { kind: 'unreadable'; path: string; detail: string };

export interface HostRuntimeEvidence {
  runtime: HostRuntimeId;
  /** Bound = this box carries evidence the runtime is installed or SC-integrated. */
  bound: boolean;
  boundReason: string;
  nativeBus: NativeBusState;
  scBus: ScBusState;
  /** What was actually read, in operator-readable form. */
  proof: string[];
  /** Remediation for THIS runtime only. Empty when nothing to fix. */
  remediation: string;
}

interface RuntimeCapability {
  label: string;
  /**
   * The documented host setting that turns native automatic memory off, or null
   * when the host exposes none. Doctor proves the setting is set — it cannot
   * attest that the host binary honours it (true for every runtime here).
   */
  nativeOffSetting: string | null;
  /** Does ShieldCortex ship an automatic inject surface for this runtime? */
  scInjectSurface: boolean;
}

export const RUNTIME_CAPABILITY: Record<HostRuntimeId, RuntimeCapability> = {
  openclaw: {
    label: 'OpenClaw',
    nativeOffSetting: 'agents.defaults.memorySearch.enabled=false in ~/.openclaw/openclaw.json',
    scInjectSurface: true,
  },
  claude_code: {
    // Claude Code has no host switch for "native memory plane" — the plane is the
    // memory-tool store itself. Off-proof is therefore artifact absence PLUS SC
    // owning session-start; unreadable evidence still resolves to unknown.
    label: 'Claude Code',
    nativeOffSetting: null,
    scInjectSurface: true,
  },
  hermes: {
    label: 'Hermes',
    nativeOffSetting: 'memory.memory_enabled=false and memory.user_profile_enabled=false in ~/.hermes/config.yaml (and in every ~/.hermes/profiles/*/config.yaml)',
    // SC ships a pre_tool_call action-guard plugin for Hermes, not a bootstrap
    // inject surface. Claiming SC-pack parity on Hermes would be fake (lock 9).
    scInjectSurface: false,
  },
};

const WEEK_MS = 7 * 24 * 60 * 60 * 1000;

function recentArtifacts(probes: ArtifactProbe[], nowMs: number): Array<Extract<ArtifactProbe, { kind: 'present' }>> {
  return probes.filter(
    (p): p is Extract<ArtifactProbe, { kind: 'present' }> =>
      p.kind === 'present' && p.size > 0 && p.mtimeMs >= nowMs - WEEK_MS,
  );
}

function firstUnreadable(probes: ArtifactProbe[]): Extract<ArtifactProbe, { kind: 'unreadable' }> | undefined {
  return probes.find((p): p is Extract<ArtifactProbe, { kind: 'unreadable' }> => p.kind === 'unreadable');
}

function shortPath(p: string): string {
  const home = process.env.HOME;
  return home && p.startsWith(home) ? p.replace(home, '~') : p;
}

// ── Inject mode law (#393 SOL H5) ───────────────────────────────────────────

/** Closed legal set for `memory.inject.mode` — shared law with the emitter. */
export const INJECT_MODES = ['off', 'start', 'turn', 'both'] as const;
export type InjectMode = (typeof INJECT_MODES)[number];

export interface InjectModeReading {
  /** Normalized mode when legal, null when the value is junk. */
  mode: InjectMode | null;
  legal: boolean;
  /** False when the operator wrote nothing and the emitter default applies. */
  explicit: boolean;
  /** Printable raw value for diagnostics. */
  raw: string;
}

/**
 * Doctor-side mirror of `normalizeInjectMode` in scripts/lib/inject-pack.mjs:
 * same closed enum, same trim/lowercase, same `false`/`0` → off, same
 * unset/empty → default `start` — with ONE sanctioned divergence. The runtime
 * quietly normalizes junk to `start` (fail-open toward injecting); doctor
 * refuses to grade junk and reports it illegal, so the contract verdict fails
 * instead of green-washing (`mode:"bogus"` used to PASS while the runtime
 * injected). Parity is pinned by test against the runtime module.
 */
export function readInjectModeStrict(raw: unknown): InjectModeReading {
  if (raw === undefined || raw === null || raw === '') {
    return { mode: 'start', legal: true, explicit: false, raw: '(unset)' };
  }
  if (raw === false || raw === 0) return { mode: 'off', legal: true, explicit: true, raw: String(raw) };
  if (typeof raw === 'string') {
    const m = raw.trim().toLowerCase();
    if ((INJECT_MODES as readonly string[]).includes(m)) {
      return { mode: m as InjectMode, legal: true, explicit: true, raw };
    }
  }
  return { mode: null, legal: false, explicit: true, raw: String(raw) };
}

// ── OpenClaw ────────────────────────────────────────────────────────────────

/**
 * State of the SC cortex-memory hook artifact set under ~/.openclaw/hooks.
 * A bare directory is NOT wiring (SOL #393 H1): `complete` requires every
 * installer-authoritative file (HOOK_FILES: HOOK.md, handler.ts, runtime.mjs)
 * present, non-empty, and byte-current against the packaged source. `stale`
 * means files exist but differ from the packaged source, so what would run
 * cannot be proven to be the SC pack emitter.
 */
export type OpenClawHookArtifacts = 'complete' | 'stale' | 'incomplete' | 'absent' | 'unreadable';

export interface OpenClawWorkspaceProbe {
  /** Workspace root this evidence was read from. */
  path: string;
  /** AGENTS.md text (sc_only: native MD must not be the session brain). */
  agentsMd: ProbeRead<string>;
  /**
   * Workspace bootstrap memory files — BOTH `MEMORY.md` and `memory.md`
   * (#393 SOL r2 B1: OpenClaw bootstraps either spelling into session context
   * natively, so lowercase must not escape the probe).
   */
  memoryFiles: ArtifactProbe[];
}

export interface OpenClawProbe {
  /** `~/.openclaw/openclaw.json` (or OPENCLAW_CONFIG_PATH). */
  config: ProbeRead<Record<string, unknown>>;
  /** SC's cortex-memory hook artifact state — see OpenClawHookArtifacts. */
  scHook: OpenClawHookArtifacts;
  /** SC config `openclawAutoMemory` — intent only; adds scrutiny, never proof. */
  scAutoMemory: boolean;
  /** Stock ~/.openclaw/workspace plus every configured defaults/per-agent workspace. */
  workspaces: OpenClawWorkspaceProbe[];
  /** False when configured workspaces could not all be enumerated. */
  workspaceScanComplete: boolean;
  declared: boolean;
}

/**
 * OpenClaw Memory Search resolves default-ON: the key being absent means the
 * feature is running, so only an explicit `false` proves it off.
 */
function resolveMemorySearchFlag(value: unknown): boolean {
  if (value === false) return false;
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return (value as Record<string, unknown>).enabled !== false;
  }
  return true;
}

/**
 * `hooks.internal.entries.cortex-memory.enabled` — the host-side switch that
 * disables an installed hook without deleting it (#393 SOL H1). Absent key =
 * default enabled (installed hooks load); explicit false = positively
 * disabled; a config that cannot be read proves nothing either way.
 */
function openClawHookConfigEnabled(config: ProbeRead<Record<string, unknown>>): boolean | 'unknown' {
  if (config.kind !== 'present') return 'unknown';
  const obj = (v: unknown): Record<string, unknown> =>
    v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
  const entry = obj(obj(obj(config.value.hooks).internal).entries)['cortex-memory'];
  return obj(entry).enabled === false ? false : true;
}

export function resolveOpenClawEvidence(
  probe: OpenClawProbe,
  ctx: { contract: string; plane: string; nowMs: number },
): HostRuntimeEvidence {
  const cap = RUNTIME_CAPABILITY.openclaw;
  const proof: string[] = [];
  const boundSignals: string[] = [];
  if (probe.config.kind === 'present') boundSignals.push('openclaw.json present');
  if (probe.config.kind === 'unreadable') boundSignals.push('openclaw.json present but unreadable');
  if (probe.scHook !== 'absent') boundSignals.push(`SC cortex-memory hook dir present (${probe.scHook})`);
  if (probe.scAutoMemory) boundSignals.push('openclawAutoMemory=true');
  if (probe.declared) boundSignals.push('declared in memory.hostContract.runtimes');

  if (boundSignals.length === 0) {
    return {
      runtime: 'openclaw',
      bound: false,
      boundReason: 'no OpenClaw config or ShieldCortex integration on this box',
      nativeBus: 'unknown',
      scBus: 'unknown',
      proof: [],
      remediation: '',
    };
  }

  let nativeBus: NativeBusState;
  let remediation = '';

  if (probe.config.kind === 'unreadable') {
    nativeBus = 'unknown';
    proof.push(`openclaw.json unreadable (${probe.config.detail}) — Memory Search cannot be proven off`);
    remediation = `${cap.label}: make openclaw.json readable, then prove ${cap.nativeOffSetting}`;
  } else if (probe.config.kind === 'absent') {
    nativeBus = 'unknown';
    proof.push('openclaw.json absent while OpenClaw looks bound — Memory Search defaults ON and cannot be proven off');
    remediation = `${cap.label}: no host config to read — set ${cap.nativeOffSetting}, or remove the OpenClaw integration if this host is retired`;
  } else {
    const oc = probe.config.value;
    const agents = oc.agents && typeof oc.agents === 'object' && !Array.isArray(oc.agents)
      ? (oc.agents as Record<string, unknown>)
      : {};
    const defaults = agents.defaults && typeof agents.defaults === 'object' && !Array.isArray(agents.defaults)
      ? (agents.defaults as Record<string, unknown>)
      : {};
    const defaultOn = resolveMemorySearchFlag(defaults.memorySearch);
    const reEnabled: string[] = [];
    const list = Array.isArray(agents.list) ? (agents.list as unknown[]) : [];
    list.forEach((entry, i) => {
      if (!entry || typeof entry !== 'object') return;
      const e = entry as Record<string, unknown>;
      const ms = e.memorySearch;
      if (ms === true || (ms && typeof ms === 'object' && !Array.isArray(ms)
        && (ms as Record<string, unknown>).enabled === true)) {
        reEnabled.push(typeof e.name === 'string' ? e.name : `agents.list[${i}]`);
      }
    });

    if (reEnabled.length > 0) {
      nativeBus = 'on';
      proof.push(`per-agent memorySearch re-enabled for ${reEnabled.join(', ')} — a defaults-off entry does not cover them`);
      if (defaultOn) proof.push('agents.defaults.memorySearch also resolves ON');
    } else if (defaultOn) {
      nativeBus = 'on';
      proof.push(
        defaults.memorySearch === undefined
          ? 'agents.defaults.memorySearch unset — OpenClaw Memory Search runs default-ON'
          : 'agents.defaults.memorySearch resolves ON',
      );
    } else {
      nativeBus = 'off_proven';
      proof.push('agents.defaults.memorySearch.enabled=false and no per-agent re-enable');
    }
    if (nativeBus === 'on') {
      remediation = `${cap.label}: set ${cap.nativeOffSetting} and clear per-agent memorySearch overrides`;
    }
  }

  // Every configured workspace is contract surface (SOL H4), not just the
  // stock one. sc_only additionally demotes native MD to non-brain;
  // `disable_native_inject` only governs automatic recall/inject, so a
  // directed "read MEMORY.md" in AGENTS.md is not a violation of that weaker
  // contract. Evidence that WOULD have been consulted but cannot be read caps
  // the proof at unknown — never PASS past an unreadable file.
  const unreadableEvidence: string[] = [];
  for (const ws of probe.workspaces) {
    if (ctx.contract === 'sc_only') {
      if (ws.agentsMd.kind === 'present') {
        const text = ws.agentsMd.value;
        if (/memory\.md/i.test(text) && /(read|every\s+session|always|session\s+brain|soul\.md|user\.md)/i.test(text)) {
          nativeBus = 'on';
          proof.push(`${shortPath(ws.path)}/AGENTS.md still names MEMORY.md as the session brain`);
          remediation = remediation
            || `${cap.label}: stop AGENTS.md pointing the agent at MEMORY.md as its brain (sc_only makes native MD archive/view only)`;
        }
      } else if (ws.agentsMd.kind === 'unreadable') {
        unreadableEvidence.push(`${shortPath(ws.path)}/AGENTS.md (${ws.agentsMd.detail})`);
      }
    }
    // #393 SOL r2 B1: OpenClaw bootstraps MEMORY.md / memory.md into session
    // context natively, regardless of AGENTS.md wording and regardless of
    // plane — a live one IS native automatic memory on the bus under
    // dual_legacy just as under the canonical planes. AGENTS.md wording is
    // corroboration, never a precondition.
    for (const md of ws.memoryFiles) {
      if (md.kind === 'present') {
        if (md.size > 64 && md.mtimeMs >= ctx.nowMs - WEEK_MS) {
          nativeBus = 'on';
          proof.push(
            `${shortPath(md.path)} written within 7d (${md.size}B) — OpenClaw bootstraps workspace memory files into session context natively`,
          );
          remediation = remediation
            || `${cap.label}: a live workspace memory file is still the session brain — archive it or import via the defended path`;
        }
      } else if (md.kind === 'unreadable') {
        unreadableEvidence.push(`${shortPath(md.path)} (${md.detail})`);
      }
    }
  }

  if (nativeBus === 'off_proven' && (unreadableEvidence.length > 0 || !probe.workspaceScanComplete)) {
    nativeBus = 'unknown';
    proof.push(
      unreadableEvidence.length > 0
        ? `workspace evidence unreadable: ${unreadableEvidence.join(', ')}`
        : 'configured workspaces could not all be enumerated — native workspace evidence cannot be proven off',
    );
    remediation = remediation
      || `${cap.label}: make every configured workspace's AGENTS.md / MEMORY.md readable so the contract can be proven`;
  }

  // SC bus: a bare directory is not delivery (SOL H1). Static wiring proof
  // needs the full installer artifact set, byte-current content, and a host
  // config that does not disable the hook — and even then the strongest claim
  // is `wired_proven` (static), never a delivered receipt.
  let scBus: ScBusState;
  const hookEnabled = openClawHookConfigEnabled(probe.config);
  switch (probe.scHook) {
    case 'absent':
      scBus = 'not_wired';
      break;
    case 'incomplete':
      scBus = 'not_wired';
      proof.push('SC cortex-memory hook dir present but required files (HOOK.md/handler.ts/runtime.mjs) missing or empty — a directory is not delivery');
      break;
    case 'unreadable':
      scBus = 'unknown';
      proof.push('SC cortex-memory hook artifacts unreadable — pack delivery cannot be proven');
      break;
    case 'stale':
      scBus = 'unknown';
      proof.push('installed SC hook differs from the packaged source — what runs cannot be proven to deliver the pack');
      break;
    default:
      if (hookEnabled === false) {
        scBus = 'not_wired';
        proof.push('hooks.internal.entries.cortex-memory.enabled=false — the host disables the installed hook');
      } else if (hookEnabled === 'unknown') {
        scBus = 'unknown';
        proof.push('openclaw.json not readable — cannot confirm the host has the SC hook enabled');
      } else {
        scBus = 'wired_proven';
      }
      break;
  }

  return {
    runtime: 'openclaw',
    bound: true,
    boundReason: boundSignals.join(', '),
    nativeBus,
    scBus,
    proof,
    remediation,
  };
}

// ── Claude Code ─────────────────────────────────────────────────────────────

export interface ClaudeCodeProbe {
  /** `~/.claude/settings.json`. */
  settings: ProbeRead<Record<string, unknown>>;
  /** Native memory artifacts: memory-tool stores AND CLAUDE.md preambles. */
  nativeStores: ArtifactProbe[];
  /** False when the store scan itself could not complete (never read as "none"). */
  storeScanComplete: boolean;
  /**
   * Classifies where a shape-valid hook command's executable lands (#393 SOL
   * r2 B3). Doctor injects the real `hookCommandTrust`; injected rather than
   * called directly so this module stays pure and the classifier stays
   * fakeable under test.
   */
  commandTrust: (command: string) => HookCommandTrust;
  declared: boolean;
}

/** Every SessionStart command matching the one supported SC shape (SOL H3). */
function claudeSessionStartCommands(settings: Record<string, unknown>): string[] {
  const hooks = settings.hooks && typeof settings.hooks === 'object' && !Array.isArray(settings.hooks)
    ? (settings.hooks as Record<string, unknown>)
    : {};
  const entries = Array.isArray(hooks.SessionStart) ? (hooks.SessionStart as unknown[]) : [];
  const commands: string[] = [];
  for (const entry of entries) {
    if (!entry || typeof entry !== 'object') continue;
    const inner = (entry as { hooks?: unknown }).hooks;
    if (!Array.isArray(inner)) continue;
    for (const h of inner) {
      if (!h || typeof h !== 'object') continue;
      const hook = h as { type?: unknown; command?: unknown };
      // Exact supported command shape only (SOL H3): a substring match let
      // `echo shieldcortex`, stale wrappers, and lookalike binaries count as
      // SC owning session-start.
      if (hook.type !== undefined && hook.type !== 'command') continue;
      if (isShieldCortexHookCommand(hook.command, 'session-start')) {
        commands.push(hook.command as string);
      }
    }
  }
  return commands;
}

export function resolveClaudeCodeEvidence(
  probe: ClaudeCodeProbe,
  ctx: { contract: string; plane: string; nowMs: number },
): HostRuntimeEvidence {
  const cap = RUNTIME_CAPABILITY.claude_code;
  const boundSignals: string[] = [];
  if (probe.settings.kind === 'present') boundSignals.push('~/.claude/settings.json present');
  if (probe.settings.kind === 'unreadable') boundSignals.push('~/.claude/settings.json present but unreadable');
  // A native memory-tool store IS Claude Code on this box (SOL H2): store
  // evidence binds the runtime even with no settings.json, and an unlistable
  // ~/.claude path is still presence evidence — otherwise a live store could
  // vanish from the verdict while another proven runtime carries it to PASS.
  if (probe.nativeStores.some((p) => p.kind !== 'absent') || !probe.storeScanComplete) {
    boundSignals.push('native memory-tool store evidence on disk');
  }
  if (probe.declared) boundSignals.push('declared in memory.hostContract.runtimes');

  if (boundSignals.length === 0) {
    return {
      runtime: 'claude_code',
      bound: false,
      boundReason: 'no ~/.claude settings or native memory-tool store on this box',
      nativeBus: 'unknown',
      scBus: 'unknown',
      proof: [],
      remediation: '',
    };
  }

  const proof: string[] = [];
  let scBus: ScBusState;
  if (probe.settings.kind === 'unreadable') {
    scBus = 'unknown';
    proof.push(`settings.json unreadable (${probe.settings.detail})`);
  } else if (probe.settings.kind === 'absent') {
    scBus = 'not_wired';
    proof.push('no settings.json — the SC session-start pack is not on this host bus');
  } else {
    // Shape first (SOL H3), then the executable itself (SOL r2 B3): a hook
    // entry whose command cannot run delivers nothing (#146), and one that
    // resolves under a world-writable staging root cannot be attested to BE
    // shieldcortex — wired_proven requires shape AND a clean resolution.
    const commands = claudeSessionStartCommands(probe.settings.value);
    const trust = commands.map((c) => probe.commandTrust(c));
    if (commands.length === 0) {
      scBus = 'not_wired';
      proof.push('no supported SC SessionStart hook command in settings.json');
    } else if (trust.includes('resolves')) {
      scBus = 'wired_proven';
      proof.push('SC SessionStart hook statically wired in settings.json (supported shieldcortex command shape, executable resolves; runtime delivery not attested)');
    } else if (trust.includes('suspicious')) {
      scBus = 'unknown';
      proof.push('SC SessionStart hook command resolves under a world-writable staging path — cannot attest the executable is ShieldCortex');
    } else {
      scBus = 'not_wired';
      proof.push('SC SessionStart hook command does not resolve to a runnable binary — the hook dies silently in a non-interactive shell (#146)');
    }
  }

  let nativeBus: NativeBusState;
  let remediation = '';
  const unreadableStore = firstUnreadable(probe.nativeStores);
  const live = recentArtifacts(probe.nativeStores, ctx.nowMs);
  const anyStore = probe.nativeStores.some((p) => p.kind === 'present');

  if (live.length > 0) {
    nativeBus = 'on';
    proof.push(
      `native memory-tool store written within 7d: ${live
        .map((p) => `${shortPath(p.path)} (${p.size}B)`)
        .join(', ')}`,
    );
    remediation = `${cap.label}: the native memory-tool store still owns durable context — archive those files, or drop the bus-law contract`;
  } else if (!probe.storeScanComplete || unreadableStore) {
    nativeBus = 'unknown';
    proof.push(
      unreadableStore
        ? `native memory store unreadable at ${shortPath(unreadableStore.path)} (${unreadableStore.detail})`
        : 'native memory store scan could not complete',
    );
    remediation = `${cap.label}: make the native memory paths readable so doctor can prove the native plane is off`;
  } else if (probe.settings.kind === 'unreadable') {
    nativeBus = 'unknown';
    remediation = `${cap.label}: make ~/.claude/settings.json readable so doctor can prove who owns session-start`;
  } else if (anyStore) {
    // Present but quiet: not written this week, so it is not demonstrably the
    // live brain — and equally not proven off. Never PASS on a stale artifact.
    nativeBus = 'unknown';
    proof.push('native memory-tool store present but not written in 7d — cannot prove the native plane is off the bus');
    remediation = `${cap.label}: archive the native memory-tool store (or confirm it is retired) so the contract can be proven`;
  } else {
    nativeBus = 'off_proven';
    proof.push('no native memory-tool store present');
  }

  return {
    runtime: 'claude_code',
    bound: true,
    boundReason: boundSignals.join(', '),
    nativeBus,
    scBus,
    proof,
    remediation,
  };
}

// ── Hermes ──────────────────────────────────────────────────────────────────

export interface HermesMemorySwitches {
  /** `memory.memory_enabled` — null when the key is absent inside the block. */
  memoryEnabled: boolean | null;
  /** `memory.user_profile_enabled` — null when absent. */
  userProfileEnabled: boolean | null;
  /** False when no top-level `memory:` block was found at all. */
  blockFound: boolean;
}

export interface HermesProfileProbe {
  /** Profile directory name under ~/.hermes/profiles. */
  name: string;
  /** Parsed switches from that profile's config.yaml; `absent` = no config.yaml. */
  config: ProbeRead<HermesMemorySwitches>;
}

export interface HermesProbe {
  /** Parsed switches from `~/.hermes/config.yaml`. */
  config: ProbeRead<HermesMemorySwitches>;
  /** Per-profile configs under ~/.hermes/profiles/<name>/config.yaml (#393 SOL H6). */
  profiles: HermesProfileProbe[];
  /** False when the profiles dir could not be fully enumerated. */
  profileScanComplete: boolean;
  /** SC's Hermes plugin under ~/.hermes/plugins/shieldcortex. */
  scPluginInstalled: boolean;
  /** `~/.hermes/memories/MEMORY.md`, per-profile stores, … */
  nativeArtifacts: ArtifactProbe[];
  declared: boolean;
}

/**
 * Minimal, deliberately narrow reader for the Hermes `memory:` block.
 *
 * The repo carries no YAML dependency and this needs exactly two booleans, so a
 * scoped scanner beats pulling a parser in. It is fail-closed by construction:
 * anything it cannot read confidently comes back as null / blockFound=false,
 * which resolves to `unknown` upstream — never to `off_proven`.
 */
export function parseHermesMemoryBlock(text: string): HermesMemorySwitches {
  const lines = text.split(/\r?\n/);
  const out: HermesMemorySwitches = { memoryEnabled: null, userProfileEnabled: null, blockFound: false };
  let inBlock = false;
  for (const line of lines) {
    if (/^memory:\s*(#.*)?$/.test(line)) {
      inBlock = true;
      out.blockFound = true;
      continue;
    }
    if (!inBlock) continue;
    if (/^\S/.test(line)) break; // next top-level key ends the block
    if (!line.trim() || line.trim().startsWith('#')) continue;
    const m = /^\s+([A-Za-z_][A-Za-z0-9_]*):\s*(.*?)\s*(?:#.*)?$/.exec(line);
    if (!m) continue;
    const [, key, rawValue] = m;
    if (key !== 'memory_enabled' && key !== 'user_profile_enabled') continue;
    const v = rawValue.replace(/^['"]|['"]$/g, '').toLowerCase();
    const bool = v === 'true' || v === 'yes' || v === 'on'
      ? true
      : v === 'false' || v === 'no' || v === 'off'
        ? false
        : null;
    if (key === 'memory_enabled') out.memoryEnabled = bool;
    else out.userProfileEnabled = bool;
  }
  return out;
}

export function resolveHermesEvidence(
  probe: HermesProbe,
  ctx: { contract: string; plane: string; nowMs: number },
): HostRuntimeEvidence {
  const cap = RUNTIME_CAPABILITY.hermes;
  const boundSignals: string[] = [];
  if (probe.config.kind === 'present') boundSignals.push('~/.hermes/config.yaml present');
  if (probe.config.kind === 'unreadable') boundSignals.push('~/.hermes/config.yaml present but unreadable');
  if (probe.scPluginInstalled) boundSignals.push('SC Hermes plugin installed');
  // A profile tree or native memory artifact IS Hermes on this box (#393 SOL
  // r2 B2): a live ~/.hermes/profiles/*/config.yaml must bind the runtime even
  // with the root config, plugin, and declaration all absent — otherwise a
  // profile-only brain vanishes from the verdict while another proven runtime
  // carries the box to PASS. Mirrors how Claude binds on store presence.
  if (probe.profiles.length > 0 || !probe.profileScanComplete) {
    boundSignals.push('Hermes profile tree present (~/.hermes/profiles)');
  }
  if (probe.nativeArtifacts.some((p) => p.kind !== 'absent')) {
    boundSignals.push('native Hermes memory artifact evidence on disk');
  }
  if (probe.declared) boundSignals.push('declared in memory.hostContract.runtimes');

  if (boundSignals.length === 0) {
    return {
      runtime: 'hermes',
      bound: false,
      boundReason: 'no Hermes config or ShieldCortex plugin on this box',
      nativeBus: 'unknown',
      scBus: 'unknown',
      proof: [],
      remediation: '',
    };
  }

  const proof: string[] = [];
  let nativeBus: NativeBusState;
  let remediation = '';
  const live = recentArtifacts(probe.nativeArtifacts, ctx.nowMs);
  const unreadableArtifact = firstUnreadable(probe.nativeArtifacts);

  if (live.length > 0) {
    // A file written this week outranks any switch: the plane is demonstrably live.
    nativeBus = 'on';
    proof.push(
      `native Hermes memory written within 7d: ${live.map((p) => `${shortPath(p.path)} (${p.size}B)`).join(', ')}`,
    );
  } else if (probe.config.kind === 'unreadable') {
    nativeBus = 'unknown';
    proof.push(`config.yaml unreadable (${probe.config.detail}) — native memory cannot be proven off`);
  } else if (probe.config.kind === 'absent') {
    nativeBus = 'unknown';
    proof.push('config.yaml absent while Hermes looks bound — native memory defaults ON and cannot be proven off');
  } else if (!probe.config.value.blockFound) {
    nativeBus = 'unknown';
    proof.push('no `memory:` block in config.yaml — Hermes memory defaults ON and cannot be proven off');
  } else {
    const { memoryEnabled, userProfileEnabled } = probe.config.value;
    const on: string[] = [];
    if (memoryEnabled !== false) on.push(`memory_enabled=${memoryEnabled === null ? 'unset (default ON)' : memoryEnabled}`);
    if (userProfileEnabled !== false) {
      on.push(`user_profile_enabled=${userProfileEnabled === null ? 'unset (default ON)' : userProfileEnabled}`);
    }
    if (on.length === 0) {
      nativeBus = 'off_proven';
      proof.push('memory_enabled=false and user_profile_enabled=false in config.yaml');
    } else {
      nativeBus = 'on';
      proof.push(`native memory plane still on: ${on.join(', ')}`);
    }
  }

  // Profiles are runtime surface (SOL H6): a ~/.hermes/profiles/*/config.yaml
  // can re-enable native memory that the root config disabled, and doctor
  // cannot prove Hermes' profile-inheritance semantics — so each profile
  // config is evaluated INDEPENDENTLY. A profile whose switches cannot be
  // proven off from its own config caps the proof at unknown, and an
  // incomplete profile scan can never PASS.
  const profilesOn: string[] = [];
  const profilesUnknown: string[] = [];
  for (const p of probe.profiles) {
    if (p.config.kind === 'unreadable') {
      profilesUnknown.push(`${p.name} (config.yaml unreadable: ${p.config.detail})`);
      continue;
    }
    if (p.config.kind === 'absent') {
      profilesUnknown.push(`${p.name} (no config.yaml — its memory switches cannot be proven off)`);
      continue;
    }
    const v = p.config.value;
    if (!v.blockFound) {
      profilesUnknown.push(`${p.name} (no memory block — defaults cannot be proven off)`);
      continue;
    }
    const onSwitches: string[] = [];
    if (v.memoryEnabled !== false) {
      onSwitches.push(`memory_enabled=${v.memoryEnabled === null ? 'unset (default ON)' : v.memoryEnabled}`);
    }
    if (v.userProfileEnabled !== false) {
      onSwitches.push(`user_profile_enabled=${v.userProfileEnabled === null ? 'unset (default ON)' : v.userProfileEnabled}`);
    }
    if (onSwitches.length > 0) profilesOn.push(`${p.name}: ${onSwitches.join(', ')}`);
  }
  if (profilesOn.length > 0) {
    nativeBus = 'on';
    proof.push(`profile config keeps native memory on: ${profilesOn.join(' | ')}`);
  } else if (nativeBus === 'off_proven' && (profilesUnknown.length > 0 || !probe.profileScanComplete)) {
    nativeBus = 'unknown';
    proof.push(
      profilesUnknown.length > 0
        ? `profile switches not proven off: ${profilesUnknown.join(' | ')}`
        : 'profiles dir could not be fully enumerated — profile switches cannot be proven off',
    );
  }

  if (unreadableArtifact && nativeBus === 'off_proven') {
    nativeBus = 'unknown';
    proof.push(`native memory path unreadable at ${shortPath(unreadableArtifact.path)} (${unreadableArtifact.detail})`);
  }

  if (nativeBus !== 'off_proven') {
    // Honest remediation for a Hermes-primary box: fix it on Hermes, or stop
    // claiming the bus law. Never send the operator to an OpenClaw config.
    remediation =
      `${cap.label}: set ${cap.nativeOffSetting}, or — if Hermes must keep its native brain — ` +
      `run \`shieldcortex config --memory-host-posture ${SIDECAR_POSTURE}\` to drop this box to the honest ` +
      'sidecar posture (SC inject off, native keeps the bus)';
  }

  const proofWithSurface = [...proof];
  if (!cap.scInjectSurface) {
    proofWithSurface.push('ShieldCortex has no automatic inject surface on Hermes (action-guard plugin only)');
  }

  return {
    runtime: 'hermes',
    bound: true,
    boundReason: boundSignals.join(', '),
    nativeBus,
    scBus: cap.scInjectSurface ? 'unknown' : 'not_wired',
    proof: proofWithSurface,
    remediation,
  };
}

// ── Verdict ─────────────────────────────────────────────────────────────────

export interface HostContractInput {
  plane: string;
  /** True when ANY inject/bus config exists (mode, legacy keys, or a contract in any location). */
  injectConfigured: boolean;
  /** Normalized mode from readInjectModeStrict — the raw junk string when illegal. */
  injectMode: string;
  /** False when the raw mode is junk the runtime would fail-open to `start` (SOL H5). Default true. */
  injectModeLegal?: boolean;
  /** False when the mode is the emitter default rather than operator-written. Default true. */
  injectModeExplicit?: boolean;
  nativeContract: 'sc_only' | 'disable_native_inject' | null;
  /** Raw `memory.hostContract.posture`, so junk values fail instead of vanishing. */
  postureRaw: string | null;
  runtimes: HostRuntimeEvidence[];
  nowMs: number;
}

export interface HostContractVerdict {
  status: 'pass' | 'warn' | 'fail' | 'info';
  message: string;
  fix?: string;
}

/**
 * Severity for "cannot determine" under each plane, straight from the plane
 * policy drift matrix: dual_legacy is a time-boxed defect mode (WARN), while
 * import_only / sc_canonical claim canonicity and must fail closed.
 * Neither is ever PASS.
 */
function cannotDetermineStatus(plane: string): 'warn' | 'fail' {
  return plane === 'import_only' || plane === 'sc_canonical' ? 'fail' : 'warn';
}

function describe(evidence: HostRuntimeEvidence): string {
  const label = RUNTIME_CAPABILITY[evidence.runtime].label;
  const state = evidence.nativeBus === 'off_proven'
    ? 'native off (proven)'
    : evidence.nativeBus === 'on'
      ? 'native ON'
      : 'native unknown';
  const proof = evidence.proof.length > 0 ? ` — ${evidence.proof.join('; ')}` : '';
  return `${label}: ${state}${proof}`;
}

export function evaluateHostContract(input: HostContractInput): HostContractVerdict {
  const posture = input.postureRaw === null ? null : input.postureRaw.trim();

  if (posture !== null && posture !== SIDECAR_POSTURE) {
    return {
      status: 'fail',
      message: `illegal memory.hostContract.posture "${posture}" (only ${SIDECAR_POSTURE} is legal)`,
      fix: `Run \`shieldcortex config --memory-host-posture ${SIDECAR_POSTURE}\` (or \`--memory-host-posture bus_contract\`) — signed write; do not hand-edit config.json`,
    };
  }

  // SOL H5: doctor and the runtime emitter must share inject-mode semantics.
  // The runtime fail-opens junk to `start` and injects; doctor fails it as
  // illegal instead of grading a mode it cannot prove — either way, no PASS.
  if (input.injectModeLegal === false) {
    return {
      status: 'fail',
      message:
        `illegal memory.inject.mode "${input.injectMode}" — the runtime emitter normalizes junk to "start" ` +
        'and would put the SC pack on the session-start bus, so doctor refuses to grade it',
      fix: `Set memory.inject.mode to one of ${INJECT_MODES.join('|')} (or remove it to accept the default start) — signed write; do not hand-edit config.json`,
    };
  }

  const injectOn = input.injectConfigured && input.injectMode !== 'off';
  const modeLabel = input.injectModeExplicit === false
    ? `${input.injectMode} (emitter default)`
    : input.injectMode;

  // Residual lock 9: honest sidecar OR a bus-law contract, never both.
  if (posture === SIDECAR_POSTURE && injectOn) {
    return {
      status: 'fail',
      message:
        `posture=${SIDECAR_POSTURE} declared while inject mode=${modeLabel} is on` +
        `${input.nativeContract ? ` with nativeContract=${input.nativeContract}` : ''} — sidecar and bus contract are mutually exclusive`,
      fix: `Pick one: \`shieldcortex config --memory-host-posture bus_contract\` to keep the inject bus law, or \`--memory-host-posture ${SIDECAR_POSTURE}\` to turn SC inject off and stay an honest sidecar`,
    };
  }

  if (!injectOn) {
    if (input.plane === 'sc_canonical') {
      return {
        status: 'fail',
        message: 'plane=sc_canonical with SC inject off — canonicity claimed without a bus',
        fix: 'Enable inject with a legal nativeContract, or `shieldcortex config --memory-plane dual_legacy` and declare the honest sidecar posture',
      };
    }
    if (posture === SIDECAR_POSTURE) {
      return {
        status: 'pass',
        message: `honest sidecar (${SIDECAR_POSTURE}): SC inject off, native host memory keeps the automatic bus — no canonicity claimed`,
      };
    }
    if (!input.injectConfigured) {
      // SOL nit: the emitter's default for an unconfigured box is mode=start,
      // not off — it just emits nothing without a legal nativeContract. Saying
      // "inject off" here misstated the runtime.
      return {
        status: 'info',
        message:
          'memory.inject not configured — the emitter defaults to mode=start but emits nothing without a ' +
          'legal nativeContract, so SC is not on the automatic bus and no host contract is claimed',
        fix: `Declare it explicitly with \`shieldcortex config --memory-host-posture ${SIDECAR_POSTURE}\` if this box runs SC as a sidecar`,
      };
    }
    return {
      status: 'info',
      message: 'inject mode=off — SC is not on the automatic bus, so no host contract is claimed',
      fix: `Declare it explicitly with \`shieldcortex config --memory-host-posture ${SIDECAR_POSTURE}\` if this box runs SC as a sidecar`,
    };
  }

  if (!input.nativeContract) {
    return {
      status: 'fail',
      message: `inject mode=${modeLabel} without a legal nativeContract — the bus law cannot even be claimed`,
      fix: 'Run `shieldcortex config --memory-inject-contract sc_only` (or disable_native_inject) — signed write',
    };
  }

  const bound = input.runtimes.filter((r) => r.bound);
  const suffix = ` (contract=${input.nativeContract} plane=${input.plane})`;

  if (bound.length === 0) {
    return {
      status: cannotDetermineStatus(input.plane),
      message:
        `cannot determine host contract${suffix}: no bound host runtime found ` +
        `(looked for ${HOST_RUNTIMES.map((r) => RUNTIME_CAPABILITY[r].label).join(', ')}) — ` +
        'a contract nothing enforces is a paper contract',
      fix:
        'Declare the bound runtime with `shieldcortex config --memory-host-runtime <openclaw|claude_code|hermes>` ' +
        'so its native-memory state can be proven, or turn inject off and declare the honest sidecar posture',
    };
  }

  const onBus = bound.filter((r) => r.nativeBus === 'on');
  const unknownBus = bound.filter((r) => r.nativeBus === 'unknown');
  const remediations = (list: HostRuntimeEvidence[]): string =>
    list.map((r) => r.remediation).filter(Boolean).join(' · ');

  if (onBus.length > 0) {
    return {
      status: 'fail',
      message: `paper contract${suffix}: native automatic memory still owns the bus — ${onBus.map(describe).join(' | ')}`,
      fix: remediations([...onBus, ...unknownBus]) || 'Prove native automatic memory off on every bound runtime (#393)',
    };
  }

  // No SC inject surface anywhere on a box whose contract says the SC pack is the
  // only automatic memory: the claim is unenforceable, not merely unproven.
  if (bound.every((r) => !RUNTIME_CAPABILITY[r.runtime].scInjectSurface)) {
    return {
      status: 'fail',
      message:
        `paper contract${suffix}: no bound runtime has a ShieldCortex inject surface, ` +
        `so the SC start-pack cannot be the automatic bus — ${bound.map(describe).join(' | ')}`,
      fix:
        'Wire the SC session-start pack on a runtime that supports it (`shieldcortex install`), ' +
        `or turn inject off and run \`shieldcortex config --memory-host-posture ${SIDECAR_POSTURE}\``,
    };
  }

  // H4: sc_only claims the SC start-pack IS the automatic durable context, so
  // delivery must be proven per bound runtime — native-off alone is only half
  // the contract. disable_native_inject makes the same demand whenever the
  // configured mode puts the pack on the session-start bus.
  const scProofRequired = input.nativeContract === 'sc_only'
    || input.injectMode === 'start' || input.injectMode === 'both';
  const scMissing = scProofRequired ? bound.filter((r) => r.scBus === 'not_wired') : [];

  if (scMissing.length > 0) {
    const describeGap = (r: HostRuntimeEvidence): string => {
      const label = RUNTIME_CAPABILITY[r.runtime].label;
      return RUNTIME_CAPABILITY[r.runtime].scInjectSurface
        ? `${label}: SC session-start pack not wired`
        : `${label}: ShieldCortex has no automatic inject surface on this runtime`;
    };
    const fixGap = (r: HostRuntimeEvidence): string => {
      const label = RUNTIME_CAPABILITY[r.runtime].label;
      return RUNTIME_CAPABILITY[r.runtime].scInjectSurface
        ? `${label}: wire the SC session-start pack (\`shieldcortex install\`)`
        : `${label}: ${input.nativeContract} cannot be enforced here — turn inject off and run ` +
          `\`shieldcortex config --memory-host-posture ${SIDECAR_POSTURE}\` (honest sidecar)`;
    };
    return {
      status: 'fail',
      message:
        `paper contract${suffix}: the SC start-pack is not proven delivered on every bound runtime — ` +
        `${scMissing.map(describeGap).join(' | ')}`,
      fix: [...scMissing.map(fixGap), ...unknownBus.map((r) => r.remediation).filter(Boolean)].join(' · '),
    };
  }

  const scUnknown = scProofRequired
    ? bound.filter((r) => r.scBus === 'unknown' && r.nativeBus !== 'unknown')
    : [];

  if (unknownBus.length > 0 || scUnknown.length > 0) {
    const parts = [
      ...unknownBus.map(describe),
      ...scUnknown.map((r) => `${RUNTIME_CAPABILITY[r.runtime].label}: native off (proven) but SC pack delivery unknown`),
    ];
    return {
      status: cannotDetermineStatus(input.plane),
      message: `cannot determine host contract${suffix}: ${parts.join(' | ')}`,
      fix: remediations([...unknownBus, ...scUnknown]) || 'Make the host evidence readable so the contract can be proven (#393)',
    };
  }

  // "Enforced" here means: native proven off AND the SC pack statically wired
  // on every bound runtime. Doctor cannot attest live runtime delivery, and
  // the message must never read as a delivered receipt (SOL H1).
  return {
    status: 'pass',
    message:
      `${input.nativeContract} enforced (plane=${input.plane}; static wiring proven — runtime delivery not attested): ` +
      bound.map(describe).join(' | '),
  };
}
