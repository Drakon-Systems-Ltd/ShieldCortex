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

export const HOST_RUNTIMES = ['openclaw', 'claude_code', 'hermes'] as const;
export type HostRuntimeId = (typeof HOST_RUNTIMES)[number];

/** Legal honest-sidecar posture (residual lock 9). Never a `nativeContract` value. */
export const SIDECAR_POSTURE = 'mcp_sidecar_no_inject';

/**
 * Native automatic-memory ownership on one runtime.
 * `off_proven` requires a positive reading; the other two never PASS.
 */
export type NativeBusState = 'off_proven' | 'on' | 'unknown';

/** Whether ShieldCortex's own automatic pack is wired on that runtime. */
export type ScBusState = 'wired' | 'not_wired' | 'unknown';

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
    nativeOffSetting: 'memory.memory_enabled=false and memory.user_profile_enabled=false in ~/.hermes/config.yaml',
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

// ── OpenClaw ────────────────────────────────────────────────────────────────

export interface OpenClawProbe {
  /** `~/.openclaw/openclaw.json` (or OPENCLAW_CONFIG_PATH). */
  config: ProbeRead<Record<string, unknown>>;
  /** SC's cortex-memory hook installed under ~/.openclaw/hooks. */
  scHookInstalled: boolean;
  /** SC config `openclawAutoMemory` — intent only; adds scrutiny, never proof. */
  scAutoMemory: boolean;
  /** Workspace AGENTS.md text (sc_only: native MD must not be the session brain). */
  agentsMd: ProbeRead<string>;
  /** Workspace MEMORY.md stat. */
  memoryMd: ArtifactProbe;
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

export function resolveOpenClawEvidence(
  probe: OpenClawProbe,
  ctx: { contract: string; plane: string; nowMs: number },
): HostRuntimeEvidence {
  const cap = RUNTIME_CAPABILITY.openclaw;
  const proof: string[] = [];
  const boundSignals: string[] = [];
  if (probe.config.kind === 'present') boundSignals.push('openclaw.json present');
  if (probe.config.kind === 'unreadable') boundSignals.push('openclaw.json present but unreadable');
  if (probe.scHookInstalled) boundSignals.push('SC cortex-memory hook installed');
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

  // sc_only additionally demotes native MD to non-brain. `disable_native_inject`
  // only governs automatic recall/inject, so a directed "read MEMORY.md" in
  // AGENTS.md is not a violation of that weaker contract.
  if (ctx.contract === 'sc_only' && probe.agentsMd.kind === 'present') {
    const text = probe.agentsMd.value;
    if (/memory\.md/i.test(text) && /(read|every\s+session|always|session\s+brain|soul\.md|user\.md)/i.test(text)) {
      nativeBus = 'on';
      proof.push('workspace AGENTS.md still names MEMORY.md as the session brain');
      remediation = remediation
        || `${cap.label}: stop AGENTS.md pointing the agent at MEMORY.md as its brain (sc_only makes native MD archive/view only)`;
    }
  }

  if ((ctx.plane === 'sc_canonical' || ctx.plane === 'import_only') && probe.memoryMd.kind === 'present') {
    if (probe.memoryMd.size > 64 && probe.memoryMd.mtimeMs >= ctx.nowMs - WEEK_MS) {
      nativeBus = 'on';
      proof.push(`workspace MEMORY.md written within 7d (${probe.memoryMd.size}B) under plane=${ctx.plane}`);
      remediation = remediation
        || `${cap.label}: MEMORY.md is still growing as SoT — archive it or import via the defended path`;
    }
  }

  return {
    runtime: 'openclaw',
    bound: true,
    boundReason: boundSignals.join(', '),
    nativeBus,
    scBus: probe.scHookInstalled ? 'wired' : 'unknown',
    proof,
    remediation,
  };
}

// ── Claude Code ─────────────────────────────────────────────────────────────

export interface ClaudeCodeProbe {
  /** `~/.claude/settings.json`. */
  settings: ProbeRead<Record<string, unknown>>;
  /** Native memory-tool stores (`~/.claude/memory`, `~/.claude/projects/<key>/memory`). */
  nativeStores: ArtifactProbe[];
  /** False when the store scan itself could not complete (never read as "none"). */
  storeScanComplete: boolean;
  declared: boolean;
}

function claudeSessionStartWired(settings: Record<string, unknown>): boolean {
  const hooks = settings.hooks && typeof settings.hooks === 'object' && !Array.isArray(settings.hooks)
    ? (settings.hooks as Record<string, unknown>)
    : {};
  const entries = Array.isArray(hooks.SessionStart) ? (hooks.SessionStart as unknown[]) : [];
  return entries.some((entry) => {
    if (!entry || typeof entry !== 'object') return false;
    const inner = (entry as { hooks?: unknown }).hooks;
    if (!Array.isArray(inner)) return false;
    return inner.some((h) => {
      const cmd = h && typeof h === 'object' ? (h as { command?: unknown }).command : undefined;
      return typeof cmd === 'string' && cmd.includes('shieldcortex');
    });
  });
}

export function resolveClaudeCodeEvidence(
  probe: ClaudeCodeProbe,
  ctx: { contract: string; plane: string; nowMs: number },
): HostRuntimeEvidence {
  const cap = RUNTIME_CAPABILITY.claude_code;
  const boundSignals: string[] = [];
  if (probe.settings.kind === 'present') boundSignals.push('~/.claude/settings.json present');
  if (probe.settings.kind === 'unreadable') boundSignals.push('~/.claude/settings.json present but unreadable');
  if (probe.declared) boundSignals.push('declared in memory.hostContract.runtimes');

  if (boundSignals.length === 0) {
    return {
      runtime: 'claude_code',
      bound: false,
      boundReason: 'no ~/.claude/settings.json on this box',
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
    scBus = claudeSessionStartWired(probe.settings.value) ? 'wired' : 'not_wired';
    proof.push(scBus === 'wired'
      ? 'SC SessionStart hook wired in settings.json'
      : 'SC SessionStart hook NOT wired in settings.json');
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

export interface HermesProbe {
  /** Parsed switches from `~/.hermes/config.yaml`. */
  config: ProbeRead<HermesMemorySwitches>;
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
  injectConfigured: boolean;
  injectMode: string;
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
  const injectOn = input.injectConfigured && input.injectMode !== 'off';
  const posture = input.postureRaw === null ? null : input.postureRaw.trim();

  if (posture !== null && posture !== SIDECAR_POSTURE) {
    return {
      status: 'fail',
      message: `illegal memory.hostContract.posture "${posture}" (only ${SIDECAR_POSTURE} is legal)`,
      fix: `Run \`shieldcortex config --memory-host-posture ${SIDECAR_POSTURE}\` (or \`--memory-host-posture bus_contract\`) — signed write; do not hand-edit config.json`,
    };
  }

  // Residual lock 9: honest sidecar OR a bus-law contract, never both.
  if (posture === SIDECAR_POSTURE && injectOn) {
    return {
      status: 'fail',
      message:
        `posture=${SIDECAR_POSTURE} declared while inject mode=${input.injectMode} is on` +
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
    return {
      status: 'info',
      message: 'inject off — SC is not on the automatic bus, so no host contract is claimed',
      fix: `Declare it explicitly with \`shieldcortex config --memory-host-posture ${SIDECAR_POSTURE}\` if this box runs SC as a sidecar`,
    };
  }

  if (!input.nativeContract) {
    return {
      status: 'fail',
      message: `inject mode=${input.injectMode} without a legal nativeContract — the bus law cannot even be claimed`,
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
  if (bound.every((r) => r.scBus === 'not_wired')) {
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

  if (unknownBus.length > 0) {
    return {
      status: cannotDetermineStatus(input.plane),
      message: `cannot determine host contract${suffix}: ${unknownBus.map(describe).join(' | ')}`,
      fix: remediations(unknownBus) || 'Make the host evidence readable so the contract can be proven (#393)',
    };
  }

  return {
    status: 'pass',
    message: `${input.nativeContract} enforced (plane=${input.plane}): ${bound.map(describe).join(' | ')}`,
  };
}
