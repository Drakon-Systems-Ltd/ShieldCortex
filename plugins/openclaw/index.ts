/**
 * ShieldCortex Real-time Scanning Plugin for OpenClaw v2026.3.22+
 *
 * Uses typed OpenClaw plugin hooks (`api.on`) for llm_input/llm_output
 * scanning and before_tool_call / before_agent_run interception.
 * `api.registerHook` registers internal HOOK-style automation and does not
 * participate in the agent-loop block/approval semantics ShieldCortex needs.
 *
 * NOT all scanning is fire-and-forget, and the distinction is the product:
 *
 *   llm_input        — OBSERVATION. Fire-and-forget; it has no blocking
 *                      contract, so a detection here cannot stop the turn.
 *   before_agent_run — THE GATE (#225). Awaited by the gateway; its return
 *                      value decides whether the run proceeds. Bounded end to
 *                      end (CONVERSATION_SCAN_MAX_MS for the scan,
 *                      CONVERSATION_NOTIFY_MAX_MS for the alert) because the
 *                      user's turn waits on it, and failing OPEN on every
 *                      internal error — as an EXPLICIT `{ outcome: 'pass' }`
 *                      (#226), never as void, and never by throwing: the host
 *                      registers this hook fail-CLOSED. See `gatePass`.
 *   before_tool_call — the Action Guard's gate, likewise awaited.
 *
 * Both conversation hooks honour `interceptor.conversation.posture`, including
 * `off`, which is read before any scanner, audit write or cloud call.
 */

import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs/promises";
import { existsSync, readdirSync, readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import { homedir, hostname } from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createRequire } from "node:module";

import { readConversationAccess, describeRegisteredHooks } from './conversation-access.js';
import { createSessionTaintStore } from './session-taint.js';
import { classifyConversationOrigin } from './conversation-trust.js';
import type { ConversationTrustDecision } from './conversation-trust.js';
import { createInterceptor, DEFAULT_CONFIG as DEFAULT_INTERCEPTOR_CONFIG } from './interceptor.js';
import type { InterceptorConfig, BrokerRuntime } from './interceptor.js';
import { syncInterceptEvent } from './intercept-ingest.js';
import { cloudSync } from './cloud-sync.js';
import { createGatewayNotifyChannel } from './gateway-notify-channel.js';
import type { GatewayNotifyContext, NotifyChannelLike } from './gateway-notify-channel.js';

// ==================== RESILIENT RUNTIME LOADER ====================
// Resolves runtime.mjs from multiple locations so the plugin works both
// inside the npm package tree AND when copied to ~/.openclaw/extensions/

type OpenClawRuntime = {
  callCortex: (tool: string, args?: Record<string, string>) => Promise<string | null>;
  isOpenClawAutoMemoryEnabled: (config: any) => boolean;
  loadShieldConfig: () => Promise<any>;
};

// The subset of `shieldcortex/defence` the plugin uses in-process. Both the
// `before_tool_call` interceptor (runDefencePipeline) and realtime scanning
// (scanToolResponse) load from the SAME module via getDefenceModule().
type DefenceModule = {
  runDefencePipeline?: (...args: any[]) => any;
  scanToolResponse?: (
    toolName: string,
    content: string,
    mode?: 'advisory' | 'enforce',
  ) => {
    clean: boolean;
    injection: { clean: boolean; riskLevel: string; detections: unknown[] };
  };
  /** #225 sink: the notify transport shared with the Action Guard (#143).
   *  Every member is optional — an older installed dist won't have them, and
   *  the guard must degrade to a loud log rather than fail. The field names
   *  MIRROR `NotifyConfig` in src/defence/iron-dome/notify-config.ts exactly
   *  (`webhookSecret`, not `secret`): a mirror that renames a field silently
   *  drops it, and the field this one would have dropped is the HMAC key —
   *  i.e. every POST would have gone out unsigned. */
  normaliseNotifyConfig?: (raw: unknown) => {
    enabled: boolean;
    timeoutMs: number;
    webhookUrl?: string;
    webhookSecret?: string;
    openclaw: boolean;
  };
  createWebhookNotifyChannel?: (opts: { url: string; secret?: string }) => NotifyChannelLike;
  /** Builds the #225 notification. Used rather than an object literal so the
   *  bounding/truncation rules live in ONE place (see the module doc on
   *  operator-notify.ts) and a plugin cannot hand a channel a malformed shape. */
  buildConversationThreatNotification?: (input: {
    outcome: 'blocked' | 'observed' | 'unavailable';
    posture: string;
    summary: string;
    reason: string;
    sessionId?: string;
    model?: string;
    host?: string;
    detectedAt: string;
  }) => Record<string, unknown>;
  /** The shared delivery core: bounded deadline, every failure normalised,
   *  nothing but the delivered boolean read back from a channel. */
  deliverOperatorNotification?: (
    notification: unknown,
    deps: { channels: NotifyChannelLike[]; timeoutMs?: number },
  ) => Promise<{ deliveredVia: string | null; attempts: Array<{ channel: string; result: { delivered: boolean; reason?: string } }> }>;
  /** #260 — session-guard index + degraded-run summary. Optional so an older
   *  installed dist degrades to "no index" rather than crashing the hook. */
  sessionKeyFor?: (value: string | undefined, opts?: { home?: string; salt?: string }) => string | null;
  appendSessionGuardIndex?: (opts: { home?: string; entry: Record<string, unknown> }) => boolean;
  recordActionGuardDegraded?: (
    rawSessionId: string | undefined,
    opts?: { home?: string; salt?: string; origin?: string },
  ) => { recorded: boolean; count: number; sessionKey?: string; existing?: boolean };
  /** #224 — stamp binding fields on a realtime audit row. Optional so an
   *  older installed package degrades to unbound records, not a crash. */
  attachEnforcementBinding?: (
    entry: Record<string, unknown>,
    ctx: {
      plane: 'action_guard' | 'conversation_firewall';
      hookName: string;
      pluginId: string;
      tool?: string;
      args?: Record<string, unknown>;
      actionKey?: string;
    },
  ) => Record<string, unknown>;
};

let runtimePromise: Promise<OpenClawRuntime> | null = null;

function addRuntimeCandidate(candidates: Set<string>, packageRoot: string) {
  const runtimePath = path.join(packageRoot, "hooks", "openclaw", "cortex-memory", "runtime.mjs");
  if (existsSync(runtimePath)) {
    candidates.add(pathToFileURL(runtimePath).href);
  }
}

function addAncestorCandidates(candidates: Set<string>, startPath: string) {
  let current = path.resolve(startPath);
  let previous = "";
  for (let i = 0; i < 6 && current !== previous; i++) {
    addRuntimeCandidate(candidates, current);
    previous = current;
    current = path.dirname(current);
  }
}

/**
 * Ask Node where the `shieldcortex` package actually is (#174).
 *
 * The plugin declares `shieldcortex` as a peer, so on ANY layout Node's own
 * resolver can find it from here — no guessing at install prefixes. Resolving
 * `shieldcortex/package.json` rather than the runtime file directly is
 * deliberate: `./package.json` is the one subpath the main package's `exports`
 * map always declares, whereas `hooks/openclaw/**` is in `files` but NOT in
 * `exports`, so resolving it throws ERR_PACKAGE_PATH_NOT_EXPORTED.
 *
 * This is the strategy that fixes the reported `~/.local` host, and it works
 * without widening the public `exports` surface.
 */
function addResolvedPeerCandidate(
  candidates: Set<string>,
  fromUrl: string,
  resolve: (spec: string, from: string) => string = (spec, from) => createRequire(from).resolve(spec),
): void {
  try {
    addRuntimeCandidate(candidates, path.dirname(resolve("shieldcortex/package.json", fromUrl)));
  } catch { /* not resolvable from here — later strategies still apply */ }
}

/**
 * Every place the runtime might live, in the order we should try them.
 *
 * `home` is injected because Jest sandboxes SHIELDCORTEX_CONFIG_DIR but never
 * HOME, so a test that did not inject it would probe the developer's real
 * install and pass for the wrong reason.
 */
function collectRuntimeCandidates(
  home: string = homedir(),
  resolveFrom: string = import.meta.url,
): string[] {
  const candidates = new Set<string>();

  // 0. Operator escape hatch. `resolveOpenClawBinary` and the approval channel
  //    already honour an env override for the same class of "we guessed your
  //    install prefix wrong" problem; this list was the only copy without one,
  //    which is why every new prefix (bun, volta, asdf, ~/.local) has needed a
  //    code change. Accepts either the runtime file itself or a package root.
  const envOverride = process.env.SHIELDCORTEX_RUNTIME_PATH?.trim();
  if (envOverride) {
    if (envOverride.endsWith(".mjs") && existsSync(envOverride)) {
      candidates.add(pathToFileURL(envOverride).href);
    } else {
      addRuntimeCandidate(candidates, envOverride);
    }
  }

  // 1. Ask Node. Works on every layout including the ~/.local one this fixes.
  addResolvedPeerCandidate(candidates, resolveFrom);

  // 2. Relative path — the repo/source-tree layout, where ../../hooks/… is real.
  //    GUARDED, unlike before: on an installed layout this resolves to a
  //    non-existent scoped path (`@drakon-systems/hooks/…`), and because it was
  //    the only unguarded entry it became the SOLE list member and its
  //    ERR_MODULE_NOT_FOUND became the operator-visible failure — the exact
  //    message #174 reports. It is a real candidate in the source tree, so it
  //    is kept and screened rather than deleted.
  const relative = fileURLToPath(new URL("../../hooks/openclaw/cortex-memory/runtime.mjs", resolveFrom));
  if (existsSync(relative)) candidates.add(pathToFileURL(relative).href);

  // 3. Config file override. Honours SHIELDCORTEX_CONFIG_DIR like the rest of
  //    the product — reading homedir() directly made this permanently blind on
  //    a host that relocates its config.
  try {
    const configDir = process.env.SHIELDCORTEX_CONFIG_DIR?.trim() || path.join(home, ".shieldcortex");
    const cfgPath = path.join(configDir, "config.json");
    if (existsSync(cfgPath)) {
      const cfg = JSON.parse(readFileSync(cfgPath, "utf-8"));
      if (cfg.installRoot) addRuntimeCandidate(candidates, cfg.installRoot);
    }
  } catch { /* no config */ }

  // 4. Walk up from current file location
  addAncestorCandidates(candidates, path.dirname(fileURLToPath(resolveFrom)));

  // 5. Resolve via common bin symlink paths (no child_process needed)
  for (const binDir of [
    "/usr/local/bin",
    "/opt/homebrew/bin",
    path.join(home, ".npm-global", "bin"),
    path.join(home, ".local", "bin"),            // #174: pip-style / npm --prefix ~/.local
  ]) {
    const binPath = path.join(binDir, "shieldcortex");
    try {
      if (existsSync(binPath)) addAncestorCandidates(candidates, realpathSync(binPath));
    } catch { /* broken symlink */ }
  }

  // 6. Common global install paths (covers npm root -g results without spawning npm)
  for (const root of [
    "/usr/lib/node_modules/shieldcortex",
    "/usr/local/lib/node_modules/shieldcortex",
    "/opt/homebrew/lib/node_modules/shieldcortex",
    path.join(home, ".npm-global", "lib", "node_modules", "shieldcortex"),
    path.join(home, ".local", "lib", "node_modules", "shieldcortex"),   // #174
    path.join(home, ".nvm", "versions", "node"),  // nvm users
  ]) {
    if (root.includes(".nvm")) {
      // For nvm, check the current symlink
      try {
        const currentNode = path.join(home, ".nvm", "current", "lib", "node_modules", "shieldcortex");
        addRuntimeCandidate(candidates, currentNode);
      } catch { /* no nvm */ }
    } else {
      addRuntimeCandidate(candidates, root);
    }
  }

  return [...candidates];
}

// Test seam: lets the jest suite inject a spy runtime without touching disk.
let _runtimeOverride: OpenClawRuntime | null = null;

async function getRuntime(): Promise<OpenClawRuntime> {
  if (_runtimeOverride) return _runtimeOverride;
  if (!runtimePromise) {
    runtimePromise = (async () => {
      const tried: string[] = [];
      let lastError: unknown = null;

      for (const candidate of collectRuntimeCandidates()) {
        tried.push(candidate);
        try {
          const mod = await import(candidate);
          if (typeof mod.createOpenClawRuntime === "function") {
            return mod.createOpenClawRuntime({ logPrefix: "[shieldcortex]" }) as OpenClawRuntime;
          }
        } catch (error) {
          lastError = error;
        }
      }

      // #174: with every candidate screened by existsSync, "none found" is a
      // real outcome and must not render as `Tried: . Last error: unknown
      // error`. Name the escape hatch instead — this message is the only thing
      // an operator on an unusual install prefix has to go on.
      if (tried.length === 0) {
        throw new Error(
          "Could not load OpenClaw runtime: the shieldcortex package was not found from the plugin, " +
          "and no known install prefix contained hooks/openclaw/cortex-memory/runtime.mjs. " +
          "Point at it explicitly with SHIELDCORTEX_RUNTIME_PATH=/path/to/shieldcortex " +
          "(or to the runtime.mjs itself), or reinstall so `shieldcortex` resolves as a peer of the plugin.",
        );
      }
      const detail = lastError instanceof Error ? lastError.message : String(lastError ?? "unknown error");
      throw new Error(`Could not load OpenClaw runtime. Tried: ${tried.join(", ")}. Last error: ${detail}`);
    })();
  }

  return runtimePromise;
}

// ==================== SHARED IN-PROCESS DEFENCE MODULE ====================
// `shieldcortex/defence` is loaded ONCE and shared by both the
// `before_tool_call` interceptor (runDefencePipeline) and realtime scanning
// (scanToolResponse). The dynamic import uses a string-concatenated specifier
// so TypeScript does not resolve it at compile time — the module only exists at
// runtime when the package is installed, not during CI builds of the plugin.
// Returns null (cached) when the module is unavailable so callers can fall back
// to the mcporter shell-out gracefully.
let _defenceModPromise: Promise<DefenceModule | null> | null = null;
let _defenceModOverride: DefenceModule | null | undefined; // undefined = not overridden

async function getDefenceModule(): Promise<DefenceModule | null> {
  if (_defenceModOverride !== undefined) return _defenceModOverride;
  if (!_defenceModPromise) {
    _defenceModPromise = (async () => {
      try {
        const defenceModPath = 'shieldcortex' + '/defence';
        return (await import(/* webpackIgnore: true */ defenceModPath)) as DefenceModule;
      } catch {
        // Older install / package not resolvable — caller falls back.
        return null;
      }
    })();
  }
  return _defenceModPromise;
}

// Test seams (jest only): inject a stub defence module / spy runtime, then reset.
/** Test seam for the conversation-taint store — lets a test assert that a
 *  detection actually reached the store (or, for owner input, did not). */
export function __getSessionTaintForTest(): typeof sessionTaint {
  return sessionTaint;
}

/** Test seam for #174 runtime resolution: `home` and the resolving module URL
 *  are injectable because Jest sandboxes SHIELDCORTEX_CONFIG_DIR but never
 *  HOME, so an un-injected probe would read the developer's real install. */
export function __collectRuntimeCandidatesForTest(home?: string, from?: string): string[] {
  return collectRuntimeCandidates(home, from);
}

export function __setDefenceModuleForTest(mod: DefenceModule | null | undefined): void {
  _defenceModOverride = mod;
  _defenceModPromise = null;
}

/** #260 — emit action_guard_degraded for this session. Never throws, never
 *  waits when the defence module is already injected (the test / in-process
 *  path). A missing module is a silent no-op: session_end cannot block (#112). */
function summariseGuardSession(sessionId: string | null, origin: string): void {
  if (!sessionId) return;
  const run = (mod: DefenceModule | null) => {
    try { mod?.recordActionGuardDegraded?.(sessionId, { origin }); } catch { /* never wedge */ }
  };
  if (_defenceModOverride !== undefined) {
    run(_defenceModOverride);
    return;
  }
  void getDefenceModule().then(run).catch(() => {});
}
export function __setRuntimeForTest(runtime: OpenClawRuntime | null): void {
  _runtimeOverride = runtime;
  if (runtime) runtimePromise = null;
}
export function __resetConfigStateForTest(): void {
  _config = null;
  _configOverride = null;
  _lastShieldConfigRef = null;
  // Re-arm the once-per-load config-failure warning (#226).
  _shieldConfigLoadFailureLogged = false;
  _registered = false;
  _beforeToolCallRegistered = false;
  _registrationError = null;
  _beforeAgentRunRequested = false;
  _conversationAccessGranted = false;
  _gatewayNotifyContext = null;
  _hostRuntimeVersion = null;
  __resetScanUnavailableAlertState();
}

type LlmInputEvent = {
  runId: string; sessionId: string; provider: string; model: string;
  systemPrompt?: string; prompt: string; historyMessages: unknown[]; imagesCount: number;
  /** Host-supplied: this turn came from the gateway's owner. Absent on hosts
   *  that do not report it — treated as NOT the owner, never as trusted. */
  senderIsOwner?: boolean;
};
type LlmOutputEvent = {
  runId: string; sessionId: string; provider: string; model: string;
  assistantTexts: string[]; lastAssistant?: unknown;
  usage?: { input?: number; output?: number; total?: number };
};
type AgentCtx = {
  agentId?: string; sessionKey?: string; sessionId?: string;
  workspaceDir?: string; messageProvider?: string;
};
type TypedBeforeToolCallEvent = {
  toolName: string;
  params?: Record<string, unknown>;
};
type TypedBeforeToolCallResult = {
  block?: boolean;
  blockReason?: string;
  requireApproval?: {
    title: string;
    description: string;
    severity?: "info" | "warning" | "critical";
    timeoutMs?: number;
    timeoutBehavior?: "allow" | "deny";
    allowedDecisions?: Array<"allow-once" | "allow-always" | "deny">;
    onResolution?: (decision: "allow-once" | "allow-always" | "deny" | "timeout" | "cancelled") => Promise<void> | void;
  };
};
type PluginApi = {
  id: string; name: string; logger: { info: (m: string) => void };
  on: (hook: string, handler: (...args: any[]) => any, opts?: Record<string, unknown>) => void;
  [k: string]: any;
};

// ==================== CONFIG ====================

// User-facing interceptor config: a deep-partial of InterceptorConfig. Every
// key is optional — DEFAULT_INTERCEPTOR_CONFIG fills the gaps in
// initInterceptor(), never here, so explicit values (including `false`) always
// win over defaults.
type InterceptSeverity = 'low' | 'medium' | 'high' | 'critical';
const INTERCEPT_SEVERITIES: readonly InterceptSeverity[] = ['low', 'medium', 'high', 'critical'];
const INTERCEPT_ACTIONS = ['log', 'warn', 'require_approval'] as const;
const FAILURE_ACTIONS = ['allow', 'deny'] as const;

interface InterceptorUserConfig {
  enabled?: boolean;
  severityActions?: Partial<Record<InterceptSeverity, (typeof INTERCEPT_ACTIONS)[number]>>;
  failurePolicy?: Partial<Record<InterceptSeverity, (typeof FAILURE_ACTIONS)[number]>>;
  actionGuard?: {
    enabled?: boolean;
    enforce?: boolean;
    autoApprove?: string[];
    auditAllows?: boolean;
    /** AI-assisted approval broker (#143). Passed through RAW: the real
     *  validation is `normaliseBrokerConfig` in the main package, which is the
     *  single place that knows which values would loosen an invariant. Off
     *  unless `enabled: true`. */
    broker?: Record<string, unknown>;
    /** Reviewed-script allowlist (#189). Passed through RAW; validated
     *  entry-by-entry inside createReviewedScriptCheck. */
    reviewedScripts?: unknown[];
    /** Operator-notify transport (#143), reused by the #225 conversation sink.
     *  Passed through RAW for the same reason as `broker`: `normaliseNotifyConfig`
     *  in the main package is the single boundary that knows which values arm a
     *  channel, and splitting that judgement across two files is how one of the
     *  halves ends up being the lenient one. Until #225 this key was silently
     *  DROPPED here, so the plugin could not reach an operator at all even on a
     *  box where the Claude Code hook could. */
    notify?: Record<string, unknown>;
  };
  /** Conversation firewall posture (#225). See CONVERSATION_POSTURES. */
  conversation?: { posture?: ConversationPosture };
}

/**
 * What the conversation firewall is allowed to DO about a detection (#225).
 *
 * Before this existed, scanning ran on `llm_input` — an OpenClaw *observation*
 * hook with no blocking contract — and a detection's entire effect was a
 * console line. The product implied a firewall and shipped a logger. These
 * three postures make the difference explicit and reportable:
 *
 *   off      — do not scan the conversation at all
 *   observe  — scan, audit, notify the operator, NEVER block
 *   enforce  — additionally block the run (via `before_agent_run`)
 *
 * Default is `observe`, deliberately. It is exactly the behaviour that shipped
 * before — but named honestly instead of implied to be protection — and #182
 * says the guard's false-positive rate is still unmeasured. An unmeasured
 * blocker in front of every turn would be a worse incident than the one this
 * fixes; `enforce` is opt-in until that number exists.
 */
export type ConversationPosture = 'off' | 'observe' | 'enforce';
const CONVERSATION_POSTURES: readonly ConversationPosture[] = ['off', 'observe', 'enforce'];

/** Resolve the configured posture. Anything unrecognised resolves DOWN to
 *  `observe`, never up to `enforce`: a typo must not silently start blocking
 *  every turn on an operator's box. */
export function conversationPosture(raw: unknown): ConversationPosture {
  if (!raw || typeof raw !== 'object') return 'observe';
  const value = (raw as { posture?: unknown }).posture;
  return typeof value === 'string' && (CONVERSATION_POSTURES as readonly string[]).includes(value)
    ? (value as ConversationPosture)
    : 'observe';
}

/**
 * A scan outcome as the conversation guard sees it.
 *
 * `available: false` marks a scan that could not be RUN at all — no defence
 * module, no MCP fallback, or a throw inside the scanner. It is deliberately a
 * separate axis from `clean`, and `clean` is set FALSE alongside it, because
 * the bug this replaces returned `{ clean: true, summary: 'scan unavailable' }`
 * from the ordinary unavailable path: every caller that read only `clean` then
 * treated an unscanned turn as a scanned-and-fine one, silently, forever.
 *
 * `errored` is kept as an alias of "not available" for the pure decision
 * function's existing contract.
 */
export interface ConversationScanResult {
  /** Only meaningful when `available` is true. False when unavailable, so a
   *  caller that ignores `available` still cannot read "clean". */
  clean: boolean;
  summary: string;
  /** The scan actually ran and produced a verdict. */
  available: boolean;
  /** Set when the scan could not be completed. Mirrors `!available`. */
  errored?: boolean;
  /** Failure detail, for the audit row and the operator alert. Never contains
   *  scanned content. */
  error?: string;
}

export interface ConversationDecision {
  block: boolean;
  notify: boolean;
  audit: boolean;
  reason: string | null;
  /** What to tell a human happened to this turn — the same vocabulary the
   *  notification carries, so the audit row and the alert cannot disagree. */
  outcome: 'clean' | 'blocked' | 'observed' | 'unavailable' | 'not-scanned';
}

/**
 * The whole decision, as a pure function — no I/O, no hooks, so the posture
 * semantics are testable directly and cannot drift as the plumbing changes.
 *
 * The key line is `notify` on a non-blocking detection: logging is not a sink.
 * The #225 finding was that a HIGH verdict reached a log file and nothing else,
 * so a real threat on a real box was seen by nobody. Under `observe` we still
 * do not stop the turn — but a human hears about it.
 *
 * `trust` is the second input because BLOCKING is a consequence, and #235's rule
 * is that source trust gates consequences (see conversation-trust.ts). It is
 * optional, and its absence means "origin not established", which resolves
 * toward enforcement rather than away from it: a caller that does not know who
 * spoke has not proved the owner did.
 */
export function evaluateConversationRun(
  posture: ConversationPosture,
  scan: ConversationScanResult,
  trust?: ConversationTrustDecision,
): ConversationDecision {
  if (posture === 'off') {
    return { block: false, notify: false, audit: false, reason: null, outcome: 'not-scanned' };
  }

  // Scanner failure fails OPEN — a broken scanner must not wedge every turn,
  // which is the outcome ShieldCortex exists to prevent — but it is reported,
  // because an unprotected turn must never read as a protected one. Note the
  // condition: `available === false` OR the legacy `errored` flag, so a caller
  // still constructing the old shape cannot route an unscanned turn into the
  // clean branch.
  if (scan.available === false || scan.errored) {
    return {
      block: false,
      notify: true,
      audit: true,
      reason: `conversation scan unavailable (${scan.error ?? scan.summary}) — turn allowed UNSCANNED`,
      outcome: 'unavailable',
    };
  }

  if (scan.clean) {
    return { block: false, notify: false, audit: false, reason: null, outcome: 'clean' };
  }

  // #235: the owner's own words are an instruction, so `enforce` does not act on
  // them. This is the branch the whole trust module exists for — a block here
  // does not warn the operator, it DESTROYS their message: OpenClaw keeps only
  // the replacement text. Everything above still happened: the content was
  // scanned, and `notify`/`audit` below are true whoever sent it. Only the
  // consequence is withheld, and the reason says so on the row rather than
  // leaving an enforce-posture host that did not block looking like a bug.
  const trusted = trust !== undefined && !trust.mayTaint;
  const block = posture === 'enforce' && !trusted;
  return {
    block,
    notify: true,
    audit: true,
    reason:
      posture === 'enforce' && trusted
        ? `conversation threat: ${scan.summary} — NOT blocked: ${trust!.reason}`
        : `conversation threat: ${scan.summary}`,
    outcome: block ? 'blocked' : 'observed',
  };
}

// ==================== CONVERSATION PLANE: HOST SUPPORT + CONSENT ============

/**
 * The first OpenClaw build whose plugin SDK declares the `before_agent_run`
 * gate. Established by inspecting published npm artifacts, not by guessing:
 *
 *   2026.5.7        — `hook-types.d.ts` has no `before_agent_run` anywhere (0 hits);
 *                     CONVERSATION_HOOK_NAMES = llm_input, llm_output,
 *                     before_agent_finalize, agent_end
 *   2026.5.9-beta.1 — FIRST published build declaring it: in `PLUGIN_HOOK_NAMES`,
 *                     in `CONVERSATION_HOOK_NAMES`, in `PluginHookHandlerMap`, with
 *                     `PluginHookBeforeAgentRunResult = InputGateDecision | void`
 *   2026.5.12       — first STABLE (non-prerelease) build with it (2026.5.10 and
 *                     2026.5.12 published betas in between; there is no plain
 *                     2026.5.9 release)
 *
 * Below this floor `api.on('before_agent_run', …)` is accepted by the API and
 * then DROPPED by the registry with an `unknown typed hook … ignored`
 * diagnostic — it does not throw. So a version check is the only honest way to
 * know, and claiming enforcement without one is exactly the class of false
 * green #222 is about.
 *
 * ── ONE FLOOR, THREE FILES ────────────────────────────────────────────────
 *
 * The authoritative value is the STABLE release, and it is stated in three
 * places that cannot import each other:
 *
 *   plugins/openclaw/index.ts                       — this constant
 *   src/integrations/openclaw-conversation-capability.ts
 *                                                   — CONVERSATION_ENFORCEMENT_MIN_OPENCLAW
 *   plugins/openclaw/openclaw.plugin.json           — engines.conversationGate
 *
 * THE BOUNDARY IS REAL, not a preference. The plugin ships as its own dist,
 * compiled by `tsconfig.openclaw-plugin.json` with `rootDir:
 * ./plugins/openclaw` and an explicit `include` list; a `src/` import does not
 * merely offend layering, it fails to emit — and the src module imports
 * `semver`, which the plugin bundle does not carry (hence the hand-rolled
 * `compareOpenClawVersions` below). The manifest is JSON read by the host and
 * imports nothing at all.
 *
 * So the three are pinned EQUAL by test instead of shared by import:
 * `src/__tests__/conversation-gate-floor-parity-226.test.ts` reads all three
 * and fails on drift. Change one, that test tells you about the other two.
 *
 * `CONVERSATION_GATE_FIRST_PRERELEASE_OPENCLAW` is deliberately SUBORDINATE: it
 * decides nothing an operator sees. Its only job is to mark the band where a
 * version number alone cannot answer the question — see
 * `hostSupportsConversationGate`.
 */
export const CONVERSATION_GATE_MIN_OPENCLAW = '2026.5.12';
/**
 * Documentation of when the hook first appeared, NOT a second floor.
 *
 * The previous cut used this as the support threshold, which made the plugin's
 * operator-facing verdict disagree with the CLI's on any 2026.5.9-beta.1 →
 * 2026.5.11 host: `shieldcortex doctor` said enforcement was unavailable while
 * the plugin's own status line said supported. Two answers to one question is
 * how the next false green gets built.
 */
export const CONVERSATION_GATE_FIRST_PRERELEASE_OPENCLAW = '2026.5.9-beta.1';

/**
 * Compare two OpenClaw CalVer strings (`2026.5.12`, `2026.5.9-beta.1`).
 * Deliberately local and tiny: the plugin build cannot import semver, and the
 * only question asked is "is this host at or above the floor".
 * Returns null when either side cannot be parsed — "unknown", never "yes".
 */
export function compareOpenClawVersions(a: string, b: string): number | null {
  const parse = (v: string): { nums: number[]; pre: string[] } | null => {
    // Exactly three numeric parts, and only `-` introduces a prerelease. A
    // trailing `.4` is NOT a prerelease tail — it is a version shape we do not
    // understand, and the safe answer to that is "unknown".
    const m = String(v ?? '').trim().match(/^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/);
    if (!m) return null;
    return { nums: [Number(m[1]), Number(m[2]), Number(m[3])], pre: m[4] ? m[4].split('.') : [] };
  };
  const pa = parse(a);
  const pb = parse(b);
  if (!pa || !pb) return null;
  for (let i = 0; i < 3; i++) {
    if (pa.nums[i] !== pb.nums[i]) return pa.nums[i] < pb.nums[i] ? -1 : 1;
  }
  // A prerelease sorts BELOW the same numeric release (2026.5.9-beta.1 < 2026.5.9).
  if (pa.pre.length === 0 && pb.pre.length === 0) return 0;
  if (pa.pre.length === 0) return 1;
  if (pb.pre.length === 0) return -1;
  return comparePrerelease(pa.pre, pb.pre);
}

/** Semver prerelease precedence, restricted to what a CalVer tail can hold:
 *  numeric identifiers compare numerically, a numeric identifier sorts below an
 *  alphanumeric one, and a shorter identifier list sorts below an
 *  otherwise-equal longer one (`beta` < `beta.1` < `beta.2` < `beta.10`).
 *
 *  The string compare this replaces put `beta.10` BELOW `beta.1`, so the tenth
 *  beta of the gate build was classified as predating the first — an error in
 *  the one direction this file must never make, since it demotes a host that
 *  HAS the gate to 'unsupported'. */
function comparePrerelease(a: string[], b: string[]): number {
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const x = a[i];
    const y = b[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const xNum = /^\d+$/.test(x);
    const yNum = /^\d+$/.test(y);
    if (xNum && yNum) {
      const nx = Number(x);
      const ny = Number(y);
      if (nx !== ny) return nx < ny ? -1 : 1;
      continue;
    }
    if (xNum !== yNum) return xNum ? -1 : 1;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

/** What we could establish about the OpenClaw build we are running inside. */
export interface HostOpenClawProbe {
  /** The host runtime version, or null when it could not be established. */
  version: string | null;
  /**
   * Where `version` came from, so a reader can weigh it.
   *
   *   'runtime'      — `api.runtime.version`, the host's own declared runtime
   *                    version (`PluginRuntimeCore.version`). First choice: the
   *                    gateway states it about itself.
   *   'package.json' — the openclaw package.json found by walking up from the
   *                    entry path. A fallback, and wrong on an install whose
   *                    on-disk package and running process differ.
   *   null           — no version evidence at all.
   */
  versionSource?: 'runtime' | 'package.json' | null;
  /** The host package root, or null. */
  root: string | null;
  /**
   * Whether THIS host's shipped hook declarations name `before_agent_run`.
   * true/false when the declarations were found and read; null when they were
   * not (an install without type declarations, an unusual layout).
   *
   * This is the primary evidence, ahead of the version string, because it is a
   * property of the build actually on this box: a fork, a backport or a patched
   * install answers correctly here and would be mis-classified by a version
   * comparison. NOTE: the runtime `openclaw/plugin-sdk` entrypoint exports
   * exactly ten symbols (ContextEngine helpers, onDiagnosticEvent, stringEnum,
   * …) and none of them is the hook-name list — read off 2026.7.1's shipped
   * `dist/plugin-sdk/index.js` — so importing the SDK and asking it directly is
   * not available.
   */
  declaresGate: boolean | null;
}

/** Test seam: pins the host probe without touching disk. */
let _hostProbeOverride: HostOpenClawProbe | null | undefined;
export function __setHostOpenClawProbeForTest(p: HostOpenClawProbe | null | undefined): void {
  _hostProbeOverride = p;
  _hostProbeCache = undefined;
}
let _hostProbeCache: HostOpenClawProbe | undefined;

/**
 * The host runtime version the gateway told us about, captured at register().
 *
 * `api.runtime.version` is declared by the host SDK as
 * `PluginRuntimeCore.version: string` — the version of the OpenClaw runtime
 * this plugin is loaded into (verified against the installed host's
 * `dist/plugin-sdk/src/plugins/runtime/types-core.d.ts`, and `api.runtime` is
 * on `OpenClawPluginApi` in the same build). It is NOT `api.version`, which is
 * the plugin's own version and would answer a completely different question:
 * comparing OUR version against an OpenClaw floor would classify every host as
 * unsupported.
 *
 * It is preferred over the filesystem walk because it is the running process
 * describing itself, where the walk infers from whichever package.json happens
 * to sit above the entry path. Null until a host actually supplies it — an
 * older gateway, a CLI invocation or a test rig may not, and that is UNKNOWN.
 */
let _hostRuntimeVersion: string | null = null;

/** Test seam for the runtime-supplied host version. */
export function __setHostRuntimeVersionForTest(v: string | null): void {
  _hostRuntimeVersion = v;
}

/**
 * Record `api.runtime.version` if this host exposes it. Returns what was
 * recorded (null when nothing usable was offered), and never throws: a host
 * with an exotic `runtime` getter must not take the plugin's registration down.
 */
export function recordHostRuntimeVersion(api: unknown): string | null {
  try {
    const runtime = (api as { runtime?: { version?: unknown } } | null | undefined)?.runtime;
    const version = runtime?.version;
    _hostRuntimeVersion = typeof version === 'string' && version.trim() ? version.trim() : null;
  } catch {
    _hostRuntimeVersion = null;
  }
  return _hostRuntimeVersion;
}

/** Does this host's shipped SDK declare the gate? Bounded, best-effort, and
 *  null on anything unexpected — an unreadable install is UNKNOWN, never
 *  "supported". */
function probeGateDeclaration(root: string): boolean | null {
  const candidates: string[] = [];
  // 2026.5.2-era layout: the declarations live under the plugin-sdk tree.
  candidates.push(path.join(root, 'dist', 'plugin-sdk', 'src', 'plugins', 'hook-types.d.ts'));
  // 2026.6+/2026.7 layout: a single hashed `hook-types-<hash>.d.ts` at dist root.
  try {
    const distDir = path.join(root, 'dist');
    if (existsSync(distDir)) {
      for (const name of readdirSync(distDir)) {
        if (/^hook-types.*\.d\.ts$/.test(name)) candidates.push(path.join(distDir, name));
      }
    }
  } catch { /* fall through to whatever candidates we have */ }

  let sawAny = false;
  for (const file of candidates) {
    try {
      if (!existsSync(file)) continue;
      sawAny = true;
      if (/\bbefore_agent_run\b/.test(readFileSync(file, 'utf-8'))) return true;
    } catch { /* unreadable candidate — try the next */ }
  }
  return sawAny ? false : null;
}

/**
 * Everything we can learn about the host OpenClaw build from inside the plugin.
 *
 * Two independent sources, both read, neither invented:
 *
 *   - `api.runtime.version` — the running gateway's own statement of its
 *     version, captured at register() (see `recordHostRuntimeVersion`). This is
 *     the primary VERSION evidence when the host offers it. Note it is not
 *     `api.version`, which is this plugin's version.
 *   - the filesystem — walk up from the gateway's entry path to the package.json
 *     that names openclaw, then read that install's own shipped hook
 *     declarations. This is the version FALLBACK, and it is the only source of
 *     `declaresGate`, which stays the strongest gate-support evidence of the two
 *     (a backport or a fork answers it correctly where a version comparison
 *     cannot — see `hostSupportsConversationGate`).
 *
 * No process is ever spawned. A null everywhere is a legitimate, frequently
 * correct answer (a CLI invocation, an unusual install layout) and callers must
 * treat it as UNKNOWN — never as "supported".
 */
export function detectHostOpenClaw(): HostOpenClawProbe {
  const disk = detectHostOpenClawFromDisk();
  // The runtime's own version outranks whatever package.json the walk landed
  // on — but only for the version; `declaresGate` and `root` are disk facts and
  // are carried through untouched.
  if (_hostRuntimeVersion) return { ...disk, version: _hostRuntimeVersion, versionSource: 'runtime' };
  return disk;
}

function detectHostOpenClawFromDisk(): HostOpenClawProbe {
  if (_hostProbeOverride !== undefined) return _hostProbeOverride ?? { version: null, root: null, declaresGate: null };
  if (_hostProbeCache !== undefined) return _hostProbeCache;
  _hostProbeCache = (() => {
    const empty: HostOpenClawProbe = { version: null, root: null, declaresGate: null, versionSource: null };
    const entry = process.argv?.[1];
    if (!entry || typeof entry !== 'string') return empty;
    let current: string;
    try {
      current = path.dirname(realpathSync(entry));
    } catch {
      current = path.dirname(entry);
    }
    let previous = '';
    for (let i = 0; i < 8 && current !== previous; i++) {
      try {
        const pkgPath = path.join(current, 'package.json');
        if (existsSync(pkgPath)) {
          const hostPkg = JSON.parse(readFileSync(pkgPath, 'utf-8')) as { name?: unknown; version?: unknown };
          if (hostPkg?.name === 'openclaw') {
            const version = typeof hostPkg.version === 'string' ? hostPkg.version : null;
            return {
              version,
              versionSource: version ? ('package.json' as const) : null,
              root: current,
              declaresGate: probeGateDeclaration(current),
            };
          }
        }
      } catch { /* keep walking up */ }
      previous = current;
      current = path.dirname(current);
    }
    return empty;
  })();
  return _hostProbeCache;
}

/** Convenience for callers that only want the version string. */
export function detectHostOpenClawVersion(): string | null {
  return detectHostOpenClaw().version;
}

export type GateSupport = 'supported' | 'unsupported' | 'unknown';

/**
 * Does this host have the `before_agent_run` gate at all?
 *
 * Order matters: what the installed build DECLARES outranks what its version
 * number implies, and both outrank a guess. There is no branch here that
 * returns 'supported' without evidence.
 */
export function hostSupportsConversationGate(probe: HostOpenClawProbe | string | null): GateSupport {
  const resolved: HostOpenClawProbe =
    typeof probe === 'string' || probe === null
      ? { version: probe, root: null, declaresGate: null }
      : probe;
  if (resolved.declaresGate === true) return 'supported';
  if (resolved.declaresGate === false) return 'unsupported';
  if (!resolved.version) return 'unknown';
  const cmp = compareOpenClawVersions(resolved.version, CONVERSATION_GATE_MIN_OPENCLAW);
  if (cmp === null) return 'unknown';
  if (cmp >= 0) return 'supported';

  // Below the STABLE floor. One band inside that is not honestly 'unsupported':
  // 2026.5.9-beta.1 → 2026.5.11 ship the hook as a prerelease, so calling them
  // unsupported would tell an operator "no posture can block a turn on this
  // host" about a host that blocks. The opposite claim is worse still, so
  // neither is made: this is the absence of a measurement, and
  // `describeConversationPlane` renders it as UNPROVEN and active:false.
  //
  // In practice a real prerelease install lands on `declaresGate` above and
  // never reaches here — this branch is what happens when the declarations
  // could not be read either, i.e. when we genuinely do not know.
  const pre = compareOpenClawVersions(resolved.version, CONVERSATION_GATE_FIRST_PRERELEASE_OPENCLAW);
  if (pre === null) return 'unknown';
  return pre >= 0 ? 'unknown' : 'unsupported';
}

/**
 * Read the operator's CONVERSATION-ACCESS consent for this plugin from the
 * host config: `plugins.entries.<id>.hooks.allowConversationAccess === true`.
 *
 * OpenClaw refuses every conversation hook for a non-bundled plugin without
 * this exact value (registry: `record.origin !== "bundled" &&
 * explicitConversationAccess !== true`). `llm_input` and `llm_output` are on
 * that list in every build; `before_agent_run` joins it in 2026.5.9-beta.1,
 * the same build that first declares the gate at all — so from there on the
 * grant governs the conversation firewall's enforcement point too.
 * Strict `true` only, matching the host: `undefined` and `false` are the same
 * refusal there, and reading them differently here would report protection the
 * gateway is not providing.
 *
 * It is the operator's per-box CONSENT grant, and this plugin only ever READS
 * it. Nothing on the plugin's own path — `register()`, a hook, a background
 * refresh — may write it: a security product that silently grants itself the
 * right to read every conversation is the behaviour this product exists to
 * catch. The only thing that may set it is an explicit, operator-initiated
 * install/repair that says so out loud (#225: "the installer must never set it
 * silently"). Absence is therefore reported, loudly and by name, rather than
 * fixed from in here.
 */
export function readConversationAccessGrant(rootConfig: unknown): boolean {
  if (!rootConfig || typeof rootConfig !== 'object' || Array.isArray(rootConfig)) return false;
  const entries = (rootConfig as {
    plugins?: { entries?: Record<string, { hooks?: { allowConversationAccess?: unknown } } | undefined> };
  }).plugins?.entries;
  const entry = entries?.[PLUGIN_ID] ?? entries?.[PLUGIN_PACKAGE_NAME];
  return entry?.hooks?.allowConversationAccess === true;
}

/**
 * Everything we can HONESTLY say about the conversation plane on this host.
 *
 * Note what is not here: any claim that the gateway accepted the hook.
 * `api.on()` returns void, never throws on an unknown hook name, and never
 * throws on a refused conversation hook — it records a diagnostic and returns —
 * so "the host accepted our registration" is not knowable from inside the
 * plugin, and a flag asserting it would be decoration. What IS knowable is the
 * two facts that decide the outcome: whether the host build has the gate, and
 * whether the operator granted conversation access.
 */
export interface ConversationPlaneState {
  posture: ConversationPosture;
  /** We called `api.on('before_agent_run', …)` this session. */
  hookRequested: boolean;
  gateSupport: GateSupport;
  hostOpenClawVersion: string | null;
  consentGranted: boolean;
  /** True only when the posture is on AND both preconditions hold. */
  active: boolean;
  /** One line, exact about the evidence, for status and doctor. */
  summary: string;
}

export function describeConversationPlane(input: {
  posture: ConversationPosture;
  hookRequested: boolean;
  gateSupport: GateSupport;
  hostOpenClawVersion: string | null;
  consentGranted: boolean;
}): ConversationPlaneState {
  const { posture, hookRequested, gateSupport, hostOpenClawVersion, consentGranted } = input;
  const hostText = hostOpenClawVersion ? `OpenClaw ${hostOpenClawVersion}` : 'OpenClaw version undetermined';

  if (posture === 'off') {
    return {
      ...input,
      active: false,
      summary: 'off — conversation scanning disabled by config (interceptor.conversation.posture=off)',
    };
  }
  if (!consentGranted) {
    return {
      ...input,
      active: false,
      summary:
        `INACTIVE: conversation access NOT granted on this host — set plugins.entries.${PLUGIN_ID}.hooks.allowConversationAccess=true ` +
        'in openclaw.json (operator consent; the installer will never set it for you). Until then the gateway REFUSES llm_input and ' +
        'llm_output for this plugin — and, on builds that have it, before_agent_run too: nothing on the conversation path is scanned or blocked',
    };
  }
  if (gateSupport === 'unsupported') {
    return {
      ...input,
      active: false,
      summary:
        `INACTIVE for enforcement: ${hostText} predates the before_agent_run gate ` +
        `(floor ${CONVERSATION_GATE_MIN_OPENCLAW}; first seen as a prerelease in ${CONVERSATION_GATE_FIRST_PRERELEASE_OPENCLAW}) — ` +
        'observation only; no posture can block a turn on this host',
    };
  }
  if (!hookRequested) {
    return { ...input, active: false, summary: 'INACTIVE: the before_agent_run hook was not registered this session' };
  }
  if (gateSupport === 'unknown') {
    // UNPROVEN IS NOT ACTIVE. Every other branch above is a fact we read — the
    // posture, the grant, the host build. This one is the absence of a
    // measurement: we could not establish that this host has the gate at all,
    // and `api.on` does not acknowledge a registration, so nothing here knows
    // whether the hook exists. Reporting `active: true` with a caveat glued to
    // the summary string — which is what this did — means every caller that
    // reads the boolean instead of the prose (status renderers, doctor, any
    // future check) claims a live firewall on evidence nobody has. Under
    // `enforce` that is the worst version of it: the operator believes turns
    // are being blocked on a host where the gate may be silently dropped.
    return {
      ...input,
      active: false,
      summary:
        `UNPROVEN: could not verify that host ${hostText} provides the before_agent_run gate ` +
        `(no runtime version, no readable hook declarations), and the plugin API does not acknowledge a registration. ` +
        (posture === 'enforce'
          ? 'The posture is enforce, so a dirty verdict WOULD block the run where the gate exists — but that it exists here is not established. Treat this host as observation-only until it is.'
          : 'Detections are audited and sent to the operator where the hook runs at all; nothing is blocked in this posture regardless.'),
    };
  }
  return {
    ...input,
    active: true,
    summary:
      posture === 'enforce'
        ? 'enforce — a dirty verdict BLOCKS the run via before_agent_run'
        : 'observe — detections are audited and sent to the operator; turns are NOT blocked',
  };
}

interface SCConfig {
  cloudEnabled?: boolean;
  cloudApiKey?: string;
  cloudBaseUrl?: string;
  binaryPath?: string;
  openclawAutoMemory?: boolean;
  openclawAutoMemoryDedupe?: boolean;
  openclawAutoMemoryNoveltyThreshold?: number;
  openclawAutoMemoryMaxRecent?: number;
  interceptor?: InterceptorUserConfig;
  /**
   * Source trust for conversation content (see conversation-trust.ts).
   *
   * Declared and PARSED here, not read off an untyped cast. `normaliseConfig`
   * is a strict allowlist — that is the whole point of #112/#115 — so a key it
   * does not name is dropped on both config paths (~/.shieldcortex/config.json
   * and the openclaw.json plugin entry). Landed as a cast against an SCConfig
   * that had no such field, `conversationTrust.trustOwnerInput` was therefore
   * read as `undefined` on every host, and the documented opt-out could not be
   * turned on by anyone. It matters more now that trust also gates BLOCKING:
   * an operator who wants owner input policed like everything else has to have
   * a working way to say so.
   */
  conversationTrust?: { trustOwnerInput?: boolean };
}

const PLUGIN_ID = "shieldcortex-realtime";

/**
 * #233: conversation-level taint, shared between the conversation scan (which
 * writes it) and the Action Guard (which reads it). Both run in THIS process,
 * so an in-memory store is the whole mechanism — keyed per session because one
 * gateway serves many concurrent chats.
 */
const sessionTaint = createSessionTaintStore();
const PLUGIN_PACKAGE_NAME = "@drakon-systems/shieldcortex-realtime";
const PLUGIN_CONFIG_UI_HINTS = {
  binaryPath: {
    label: "ShieldCortex Binary Path",
    help: "Optional absolute path to the shieldcortex CLI when it is not on PATH.",
    placeholder: "/usr/local/bin/shieldcortex",
    advanced: true,
  },
  cloudApiKey: {
    label: "Cloud API Key",
    help: "Optional ShieldCortex Cloud API key used for realtime threat forwarding.",
    sensitive: true,
    placeholder: "sc_...",
  },
  cloudBaseUrl: {
    label: "Cloud Base URL",
    help: "Override the ShieldCortex Cloud API base URL if you use a self-hosted or staging endpoint.",
    placeholder: "https://api.shieldcortex.ai",
    advanced: true,
  },
  openclawAutoMemory: {
    label: "Auto Memory Extraction",
    help: "Extract high-signal decisions and learnings from LLM output into ShieldCortex memory.",
  },
  openclawAutoMemoryDedupe: {
    label: "Dedupe Auto Memory",
    help: "Skip near-duplicate memories before they are written to ShieldCortex.",
    advanced: true,
  },
  openclawAutoMemoryNoveltyThreshold: {
    label: "Novelty Threshold",
    help: "Similarity threshold for duplicate suppression. Higher values keep more memories.",
    advanced: true,
  },
  openclawAutoMemoryMaxRecent: {
    label: "Recent Memory Cache Size",
    help: "How many recent extracted memories to keep in the dedupe cache.",
    advanced: true,
  },
  "interceptor.enabled": {
    label: "Enable Tool Call Interceptor",
    help: "Scan memory-write tool calls and gate suspicious content behind user approval.",
  },
  // #226: these two exist in openclaw.plugin.json's uiHints and were missing
  // here, so the host UI and the plugin's own declared hints described
  // different sets of settings. The manifest parity test now pins the two key
  // sets EQUAL in both directions, because a hint present on only one side is
  // a setting one surface documents and the other silently omits.
  "interceptor.severityActions.high": {
    label: "High Severity Action",
    help: "Action for high-severity threats: log, warn, or require_approval.",
    advanced: true,
  },
  "interceptor.severityActions.critical": {
    label: "Critical Severity Action",
    help: "Action for critical-severity threats: log, warn, or require_approval.",
    advanced: true,
  },
  "interceptor.actionGuard.enabled": {
    label: "Action Guard",
    help: "Gate dangerous shell/file/network/git tool calls before they execute. Catastrophic operations are always blocked while enabled.",
  },
  "interceptor.actionGuard.enforce": {
    label: "Enforce Action Guard",
    help: "Enforce dangerous-operation gating (attended: approval prompt; unattended: failurePolicy). Off = warn-and-allow (advisory). Catastrophic operations block regardless.",
  },
  "interceptor.actionGuard.autoApprove": {
    label: "Action Guard Auto-approve List",
    help: "Family/action/signal names pre-approved for unattended agents that legitimately need specific dangerous operations.",
    advanced: true,
  },
  "interceptor.actionGuard.auditAllows": {
    label: "Audit Recognised Allows",
    help: "Write an audit entry when the guard evaluates a recognised operation and allows it.",
    advanced: true,
  },
  "interceptor.actionGuard.broker.enabled": {
    label: "AI Approval Broker",
    help: "Let a fast model judge dangerous-tier approvals before they reach you: it can deny outright when it sees injection, and release reversible, in-context, high-confidence actions without waiting. Never applies to catastrophic operations. Off by default.",
    advanced: true,
  },
  "interceptor.actionGuard.broker.allowPreClear": {
    label: "Allow Broker Pre-clear",
    help: "Off = every dangerous-tier action still waits for you; the broker can then only harden, never release.",
    advanced: true,
  },
  // #225. The posture is the whole product claim on the conversation path, so
  // it is NOT marked advanced: an operator must be able to see, in the UI that
  // configures this plugin, whether the firewall in front of their prompts can
  // stop anything.
  "interceptor.conversation.posture": {
    label: "Conversation Firewall",
    help:
      "What the conversation firewall does with a detection on the input path. " +
      "off = do not scan; observe = scan, audit and alert the operator but never stop the turn (default); " +
      "enforce = block the run via before_agent_run. Requires plugins.entries.shieldcortex-realtime.hooks.allowConversationAccess=true " +
      "on this host — OpenClaw refuses conversation hooks without that operator grant, and ShieldCortex will never set it for you.",
  },
  "interceptor.actionGuard.notify.enabled": {
    label: "Operator Notifications",
    help: "Reach a human when the guard holds an action, or when the conversation firewall detects a threat. Off by default.",
    advanced: true,
  },
  "interceptor.actionGuard.notify.webhookUrl": {
    label: "Notify Webhook URL",
    help: "http(s) endpoint the notification is POSTed to. Conversation-firewall alerts carry no approve/deny affordance — there is nothing to approve.",
    advanced: true,
  },
  "interceptor.actionGuard.notify.webhookSecret": {
    label: "Notify Webhook Secret",
    help: "HMAC-SHA256 key for X-ShieldCortex-Signature, so the receiver can reject spoofed POSTs.",
    sensitive: true,
    advanced: true,
  },
  "interceptor.actionGuard.notify.openclaw": {
    label: "Notify via OpenClaw",
    help: "Deliver through the gateway's own channel where the runtime provides that seam.",
    advanced: true,
  },
} as const;

const SEVERITY_ACTION_SCHEMA = {
  type: "object",
  additionalProperties: false,
  properties: Object.fromEntries(
    INTERCEPT_SEVERITIES.map((severity) => [severity, { type: "string", enum: [...INTERCEPT_ACTIONS] }]),
  ),
};

const FAILURE_POLICY_SCHEMA = {
  type: "object",
  additionalProperties: false,
  properties: Object.fromEntries(
    INTERCEPT_SEVERITIES.map((severity) => [severity, { type: "string", enum: [...FAILURE_ACTIONS] }]),
  ),
};

/** #225. Mirrored verbatim into openclaw.plugin.json's configSchema — the host
 *  validates the on-disk config against THAT file, so a posture accepted here
 *  and absent there is a config an operator writes from our own docs and the
 *  gateway rejects. */
const CONVERSATION_JSON_SCHEMA = {
  type: "object",
  additionalProperties: false,
  properties: {
    posture: {
      type: "string",
      enum: [...CONVERSATION_POSTURES],
      default: "observe",
      description:
        "off = do not scan the conversation; observe = scan, audit and alert but never block (default); " +
        "enforce = block the run on a dirty verdict via before_agent_run.",
    },
  },
};

/** #235/#226. Mirrored verbatim into openclaw.plugin.json's configSchema, for
 *  the same reason as the conversation posture above: the host validates the
 *  on-disk config against THAT file, and a key our parser reads but neither
 *  schema declares is one an operator cannot set at all. */
const CONVERSATION_TRUST_JSON_SCHEMA = {
  type: "object",
  additionalProperties: false,
  properties: {
    trustOwnerInput: {
      type: "boolean",
      default: true,
      description:
        "Default true: a message the host attributes to the gateway OWNER is an instruction, so a detection in it " +
        "is audited and alerted but never taints the session or blocks the turn. Set false on a host where the owner " +
        "routinely pastes untrusted content and you would rather have the caution than the quiet. Content from " +
        "anyone else — including another agent on a trusted channel — is data regardless of this setting.",
    },
  },
};

/**
 * The Action Guard block, declared ONCE and mounted in BOTH places the parser
 * accepts it (#226).
 *
 * `normaliseConfig` has read a TOP-LEVEL `actionGuard` since #209 — that is the
 * canonical location, and `interceptor.actionGuard` is the deprecated alias
 * kept for pre-#209 configs. The schemas said the opposite: only the nested
 * alias was declared, under `additionalProperties: false`, so a config written
 * from our own documentation — `actionGuard.notify` at the top level — was
 * rejected as an unknown key by any host that validates against the schema.
 * The parser would have kept it; the config never reached the parser. That is
 * the shape behind the original `parsedNotify: null` reproduction.
 *
 * One constant, two mount points, so the two can never drift. Mirrored by hand
 * into openclaw.plugin.json's configSchema (the host validates the on-disk
 * config against THAT file) and pinned equal by manifest-config-schema-226.test.ts.
 */
const ACTION_GUARD_JSON_SCHEMA = {
  type: "object",
  additionalProperties: false,
  properties: {
    enabled: { type: "boolean" },
    enforce: { type: "boolean" },
    autoApprove: { type: "array", items: { type: "string" } },
    auditAllows: { type: "boolean" },
    // #143. Mirrors normaliseBrokerConfig's allowlist; that function still
    // has the last word, so a value that slips past the schema is still
    // range-checked (and dropped) before the broker sees it.
    broker: {
      type: "object",
      additionalProperties: false,
      properties: {
        enabled: { type: "boolean" },
        allowPreClear: { type: "boolean" },
        preClearConfidence: { type: "number", minimum: 0.9, maximum: 1 },
        judgeTimeoutMs: { type: "number", minimum: 500, maximum: 60000 },
        approvalTimeoutMs: {
          type: "object",
          additionalProperties: false,
          properties: {
            sensitive: { type: "number", minimum: 1000, maximum: 3600000 },
            dangerous: { type: "number", minimum: 1000, maximum: 3600000 },
          },
        },
        model: { type: "string" },
      },
    },
    // #143/#225. Mirrors NotifyConfig in notify-config.ts, which still has
    // the last word (strict-true booleans, http(s)-only URL, bounded
    // timeout). Declared here because `additionalProperties: false` above
    // means an undeclared key makes the WHOLE containing block invalid on
    // a host that validates config against this schema — which is how the
    // Action Guard's notify transport came to be unusable from inside the
    // gateway plugin at all.
    notify: {
      type: "object",
      additionalProperties: false,
      properties: {
        enabled: { type: "boolean" },
        webhookUrl: { type: "string" },
        webhookSecret: { type: "string" },
        openclaw: { type: "boolean" },
        timeoutMs: { type: "number", minimum: 500, maximum: 60000 },
      },
    },
    // #189. Each entry pins one script by absolute path + content hash;
    // createReviewedScriptCheck has the last word on every field.
    reviewedScripts: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        properties: {
          path: { type: "string" },
          sha256: { type: "string" },
          note: { type: "string" },
          addedAt: { type: "number" },
        },
        required: ["path", "sha256"],
      },
    },
  },
};

const INTERCEPTOR_JSON_SCHEMA = {
  type: "object",
  additionalProperties: false,
  properties: {
    enabled: { type: "boolean" },
    severityActions: SEVERITY_ACTION_SCHEMA,
    failurePolicy: FAILURE_POLICY_SCHEMA,
    conversation: CONVERSATION_JSON_SCHEMA,
    /** The DEPRECATED alias (#209). Still accepted, still parsed, still
     *  gap-fills the canonical top-level block key by key. */
    actionGuard: ACTION_GUARD_JSON_SCHEMA,
  },
};

const PLUGIN_CONFIG_JSON_SCHEMA = {
  type: "object",
  additionalProperties: false,
  properties: {
    // #115: accepted for schema/UI compatibility but not read — plugin
    // enablement lives host-side at plugins.entries[id].enabled (see
    // rootConfigWith() shape in extractPluginConfig), one level up from this
    // nested `config` object. normaliseConfig() has never populated
    // SCConfig.enabled (no such field exists); documented rather than
    // removed so an existing config.enabled:true/false written by a host UI
    // doesn't fail `additionalProperties:false` validation.
    enabled: { type: "boolean", description: "Unused — plugin on/off is controlled by plugins.entries[id].enabled on the host, not this nested config value." },
    binaryPath: { type: "string" },
    cloudApiKey: { type: "string" },
    cloudBaseUrl: { type: "string" },
    openclawAutoMemory: { type: "boolean" },
    openclawAutoMemoryDedupe: { type: "boolean" },
    openclawAutoMemoryNoveltyThreshold: { type: "number", minimum: 0.6, maximum: 0.99 },
    openclawAutoMemoryMaxRecent: { type: "integer", minimum: 50, maximum: 1000 },
    // #112: without this, `additionalProperties: false` declared the whole
    // interceptor block invalid — mirror openclaw.plugin.json's configSchema.
    interceptor: INTERCEPTOR_JSON_SCHEMA,
    // #209/#226: the CANONICAL Action Guard location. normaliseConfig has read
    // it here since #209 and folds it over the nested alias; the schema did not
    // declare it, so `additionalProperties: false` rejected the documented
    // config shape before the parser ever saw it.
    actionGuard: ACTION_GUARD_JSON_SCHEMA,
    // #235/#226: source trust. Same reason as `actionGuard` above — the parser
    // reads it, so the schema must declare it or `additionalProperties: false`
    // rejects the whole config an operator writes from our documentation.
    conversationTrust: CONVERSATION_TRUST_JSON_SCHEMA,
  },
};

let _config: SCConfig | null = null;
// Identity of the shield config we last merged from. The runtime's
// loadShieldConfig() returns the same parsed object until the file's mtime
// advances; using reference equality lets us re-merge precisely when the
// underlying config has actually changed (dashboard / CLI write).
let _lastShieldConfigRef: unknown = null;
let _configOverride: SCConfig | null = null;
let _version = "0.0.0";
try {
  // Try package.json first, then openclaw.plugin.json (the manifest IS copied to extensions/)
  for (const candidateUrl of [
    new URL("./package.json", import.meta.url),
    new URL("../../package.json", import.meta.url),
    new URL("./openclaw.plugin.json", import.meta.url),
  ]) {
    try {
      const data = JSON.parse(readFileSync(candidateUrl, "utf-8"));
      if (typeof data.version === "string" && data.version.trim()) {
        _version = data.version;
        break;
      }
    } catch {
      // try the next candidate
    }
  }
} catch { /* fallback */ }

let _registered = false;
// Whether register() actually attached the before_tool_call hook this session.
// False when the host config explicitly disables the interceptor — in that
// case the hook must not exist at all, so the host's approval pipeline can
// never route a tool call through this plugin (issue #112 follow-up: on
// unattended Codex agents even a no-op registered hook changes how OpenClaw
// resolves approvals).
let _beforeToolCallRegistered = false;
// #225: whether we CALLED api.on('before_agent_run', …) this session — nothing
// more. It is deliberately not named "…Accepted": `api.on` returns void, never
// throws on an unknown hook name, and never throws when the host refuses a
// conversation hook (it records a diagnostic and returns), so acceptance is not
// observable from in here. The two facts that decide whether the plane is live
// — host build ≥ the gate's floor, and the operator's allowConversationAccess
// grant — are read separately and reported by describeConversationPlane().
let _beforeAgentRunRequested = false;
// The operator's conversation-access grant as read from the host config at
// register() time. Reported by /shieldcortex-status; never written by us.
let _conversationAccessGranted = false;
// #134 §2: register() wraps its whole body in try/catch so a plugin failure
// never blocks channel startup — correct, but it used to report the failure
// with a bare console.warn (bypasses the gateway's structured log, so the
// operator's only view of a dead security plugin is stdout no one reads) and
// the /shieldcortex-status command lived INSIDE the same try block, so a
// crash before that line meant the command never existed at all — the plugin
// couldn't even honestly report its own death. Set here so the status handler
// (registered unconditionally, before the risky init work) can read it.
let _registrationError: string | null = null;

function normaliseConfig(raw: unknown, dropped?: string[]): SCConfig {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return {};

  const value = raw as Record<string, unknown>;
  const config: SCConfig = {};

  if (typeof value.cloudApiKey === "string" && value.cloudApiKey.trim()) {
    config.cloudApiKey = value.cloudApiKey.trim();
  }
  if (typeof value.cloudBaseUrl === "string" && value.cloudBaseUrl.trim()) {
    config.cloudBaseUrl = value.cloudBaseUrl.trim();
  }
  if (typeof value.cloudEnabled === "boolean") {
    config.cloudEnabled = value.cloudEnabled;
  }
  if (typeof value.binaryPath === "string" && value.binaryPath.trim()) {
    config.binaryPath = value.binaryPath.trim();
  }
  if (typeof value.openclawAutoMemory === "boolean") {
    config.openclawAutoMemory = value.openclawAutoMemory;
  }
  if (typeof value.openclawAutoMemoryDedupe === "boolean") {
    config.openclawAutoMemoryDedupe = value.openclawAutoMemoryDedupe;
  }
  if (typeof value.openclawAutoMemoryNoveltyThreshold === "number" && !Number.isNaN(value.openclawAutoMemoryNoveltyThreshold)) {
    config.openclawAutoMemoryNoveltyThreshold = clamp(value.openclawAutoMemoryNoveltyThreshold, 0.6, 0.99);
  }
  if (typeof value.openclawAutoMemoryMaxRecent === "number" && !Number.isNaN(value.openclawAutoMemoryMaxRecent)) {
    config.openclawAutoMemoryMaxRecent = Math.floor(clamp(value.openclawAutoMemoryMaxRecent, 50, 1000));
  }

  // #112: the allowlist above predates the interceptor and silently dropped
  // the entire nested `interceptor` object — `interceptor.enabled: false` was
  // ignored and DEFAULT_INTERCEPTOR_CONFIG re-armed the before_tool_call gate.
  // Validate-and-preserve every nested interceptor key the manifest schema
  // accepts; invalid values are dropped individually, valid siblings survive.
  // #115: `dropped` collects the exact key paths any invalid value was
  // dropped from — undefined here (the configSchema.parse() public contract
  // stays a single return value); applyPluginConfigOverride is the one
  // caller that both has a logger AND matters for this (it ingests the
  // openclaw.json plugin entry a human hand-edits — the Edith #112 incident's
  // `enabled:"false"` was exactly this shape of typo).
  const interceptor = normaliseInterceptorConfig(value.interceptor, dropped);
  if (interceptor) config.interceptor = interceptor;

  // Source trust (#235, wired to the gate in #226). Booleans only, and the
  // block is kept only when it holds a valid one: a `trustOwnerInput: "false"`
  // typo — the exact shape of the #112 incident — must not read as the opt-out
  // having been applied, because the operator who wrote it believes owner input
  // is being policed and it would not be.
  if (value.conversationTrust && typeof value.conversationTrust === "object" && !Array.isArray(value.conversationTrust)) {
    const trustRaw = value.conversationTrust as Record<string, unknown>;
    if (typeof trustRaw.trustOwnerInput === "boolean") {
      config.conversationTrust = { trustOwnerInput: trustRaw.trustOwnerInput };
    } else if (trustRaw.trustOwnerInput !== undefined) {
      dropped?.push("conversationTrust.trustOwnerInput");
    }
  }

  // #209: single source of truth for the Action Guard. A top-level
  // `actionGuard` block governs every surface; `interceptor.actionGuard` is a
  // deprecated alias kept as per-key gap-fill so pre-#209 configs keep their
  // posture. On a conflicting key the top-level value wins. The fold happens
  // HERE, at the parse boundary, so initInterceptor and everything downstream
  // still sees exactly one guard config at `interceptor.actionGuard` and the
  // alias can never leak into the enforcement path. Conflicts are surfaced by
  // `shieldcortex doctor` and the Claude Code hook's stderr note, not logged
  // here — this parse also runs on the shield config file path, which has no
  // logger. Mirrored in scripts/pre-tool-hook.mjs (loadActionGuardConfig) and
  // src/cli/doctor.ts (checkActionGuard); the three build units cannot share
  // an import, so keep them in step by hand.
  const topGuard = normaliseActionGuardBlock(value.actionGuard, dropped, "actionGuard");
  if (topGuard) {
    config.interceptor = {
      ...(config.interceptor ?? {}),
      actionGuard: { ...(config.interceptor?.actionGuard ?? {}), ...topGuard },
    };
  }

  return config;
}

// #115: returns undefined (not {}) when nothing valid was found, matching
// normaliseInterceptorConfig's contract below — an empty/all-invalid map
// must read as "absent" so mergeConfigs/applyPluginConfigOverride treat it
// as no override rather than a truthy-but-empty one.
function normaliseSeverityMap<A extends string>(
  raw: unknown,
  allowed: readonly A[],
  dropped?: string[],
  pathPrefix?: string,
): Partial<Record<InterceptSeverity, A>> | undefined {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const value = raw as Record<string, unknown>;
  const out: Partial<Record<InterceptSeverity, A>> = {};
  for (const severity of INTERCEPT_SEVERITIES) {
    const entry = value[severity];
    if (entry === undefined) continue; // absent, not invalid — nothing to warn about
    if (typeof entry === "string" && (allowed as readonly string[]).includes(entry)) {
      out[severity] = entry as A;
    } else if (pathPrefix) {
      dropped?.push(`${pathPrefix}.${severity}`);
    }
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

/**
 * Validate one Action Guard block. Shared by the deprecated
 * `interceptor.actionGuard` alias and the top-level `actionGuard` key (#209) —
 * `pathPrefix` names which of the two a dropped key came from, so the #115
 * warn log stays exact. Returns undefined (not {}) when nothing valid was
 * found, matching normaliseInterceptorConfig's "empty means absent" contract.
 */
function normaliseActionGuardBlock(
  raw: unknown,
  dropped: string[] | undefined,
  pathPrefix: string,
): InterceptorUserConfig["actionGuard"] | undefined {
  if (raw === undefined) return undefined;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    dropped?.push(pathPrefix);
    return undefined;
  }
  const rawGuard = raw as Record<string, unknown>;
  const guard: NonNullable<InterceptorUserConfig["actionGuard"]> = {};
  if (rawGuard.enabled !== undefined) {
    if (typeof rawGuard.enabled === "boolean") guard.enabled = rawGuard.enabled;
    else dropped?.push(`${pathPrefix}.enabled`);
  }
  if (rawGuard.enforce !== undefined) {
    if (typeof rawGuard.enforce === "boolean") guard.enforce = rawGuard.enforce;
    else dropped?.push(`${pathPrefix}.enforce`);
  }
  if (rawGuard.auditAllows !== undefined) {
    if (typeof rawGuard.auditAllows === "boolean") guard.auditAllows = rawGuard.auditAllows;
    else dropped?.push(`${pathPrefix}.auditAllows`);
  }
  if (rawGuard.autoApprove !== undefined) {
    if (Array.isArray(rawGuard.autoApprove) && rawGuard.autoApprove.every((entry) => typeof entry === "string")) {
      // #115: defensive copy — downstream (initInterceptor's spread into
      // InterceptorConfig) is read-only today, but aliasing the caller's
      // array means a future in-place mutation of the host config object
      // would silently corrupt the normalised config too.
      guard.autoApprove = [...(rawGuard.autoApprove as string[])];
    } else {
      dropped?.push(`${pathPrefix}.autoApprove`);
    }
  }
  // Carried through untouched — normaliseBrokerConfig is the boundary, and
  // splitting that job across two files is how one of the halves ends up
  // being the lenient one.
  if (rawGuard.broker && typeof rawGuard.broker === "object" && !Array.isArray(rawGuard.broker)) {
    guard.broker = rawGuard.broker as Record<string, unknown>;
  }
  // #189: same passthrough discipline — createReviewedScriptCheck is the
  // boundary that shape-validates each entry.
  if (Array.isArray(rawGuard.reviewedScripts)) {
    guard.reviewedScripts = [...rawGuard.reviewedScripts];
  }
  // #143/#225: the notify transport. Same passthrough discipline again —
  // normaliseNotifyConfig is the boundary. Shallow-copied rather than aliased
  // (the #115 reason: a later in-place mutation of the host config object must
  // not reach into the normalised one), and a non-object is DROPPED by name so
  // the #115 warn log can say which key was ignored, rather than silently
  // leaving the operator with a transport that never fires.
  if (rawGuard.notify !== undefined) {
    if (rawGuard.notify && typeof rawGuard.notify === 'object' && !Array.isArray(rawGuard.notify)) {
      guard.notify = { ...(rawGuard.notify as Record<string, unknown>) };
    } else {
      dropped?.push(`${pathPrefix}.notify`);
    }
  }
  return Object.keys(guard).length > 0 ? guard : undefined;
}

function normaliseInterceptorConfig(raw: unknown, dropped?: string[]): InterceptorUserConfig | undefined {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const value = raw as Record<string, unknown>;
  const out: InterceptorUserConfig = {};

  if (value.enabled !== undefined) {
    if (typeof value.enabled === "boolean") out.enabled = value.enabled;
    else dropped?.push("interceptor.enabled");
  }

  const severityActions = normaliseSeverityMap(value.severityActions, INTERCEPT_ACTIONS, dropped, "interceptor.severityActions");
  if (severityActions) out.severityActions = severityActions;

  const failurePolicy = normaliseSeverityMap(value.failurePolicy, FAILURE_ACTIONS, dropped, "interceptor.failurePolicy");
  if (failurePolicy) out.failurePolicy = failurePolicy;

  const actionGuard = normaliseActionGuardBlock(value.actionGuard, dropped, "interceptor.actionGuard");
  if (actionGuard) out.actionGuard = actionGuard;

  // #225: conversation posture. An invalid value is DROPPED (and named in the
  // warn log) rather than coerced, so `conversationPosture()` falls back to
  // `observe` — the safe direction. A typo must never start blocking turns.
  if (value.conversation !== undefined) {
    if (value.conversation && typeof value.conversation === "object" && !Array.isArray(value.conversation)) {
      const posture = (value.conversation as { posture?: unknown }).posture;
      if (posture !== undefined) {
        if (typeof posture === "string" && (CONVERSATION_POSTURES as readonly string[]).includes(posture)) {
          out.conversation = { posture: posture as ConversationPosture };
        } else {
          dropped?.push("interceptor.conversation.posture");
        }
      }
    } else {
      dropped?.push("interceptor.conversation");
    }
  }

  // #115: empty/all-invalid normalises to undefined, not {} — {} is truthy
  // and made applyPluginConfigOverride treat a no-op interceptor block as a
  // real override, inconsistent with normaliseSeverityMap's own contract.
  return Object.keys(out).length > 0 ? out : undefined;
}

/**
 * Merge two normalised configs (#112). Semantics:
 *  - Top-level scalar keys: override wins when present.
 *  - `interceptor` deep-merges PER KEY — per severity entry, per guard flag —
 *    so an override that sets one nested key does not wholesale-discard the
 *    base's other interceptor settings.
 *  - `actionGuard.notify` and `actionGuard.broker` deep-merge per key too
 *    (#226). They are the two OBJECT-valued guard keys, and a shallow spread
 *    replaced them wholesale: an openclaw.json entry that says only
 *    `notify: { enabled: true }` — the shape the UI writes when an operator
 *    ticks "Operator Notifications" — discarded the shield config's
 *    `webhookUrl` and `webhookSecret`, leaving notify ARMED with no channel and
 *    no signing key. Every alert then reported "enabled but no channel is
 *    configured/buildable on this host", which is the #143 silent-no-sink
 *    failure in a new place.
 *  - ARRAY-valued keys (`autoApprove`, `reviewedScripts`) still REPLACE. They
 *    are allowlists: merging two of them would union permissions an operator
 *    removed back into the effective config, which is the wrong direction for a
 *    security control.
 *  - Explicit values, including `false`, always win over base values; absent
 *    keys fall through to the base.
 *  - Defaults are NOT applied here: DEFAULT_INTERCEPTOR_CONFIG only fills the
 *    remaining gaps in initInterceptor(), so it can never override an explicit
 *    user value.
 */
function mergeConfigs(base: SCConfig, override: SCConfig): SCConfig {
  const merged: SCConfig = { ...base, ...override };
  // Per-key, like every other nested block here. A plain spread would let an
  // openclaw.json entry that mentions `conversationTrust` at all replace the
  // shield-config block wholesale, silently reverting an opt-out set in the
  // file the operator considers authoritative.
  if (base.conversationTrust || override.conversationTrust) {
    merged.conversationTrust = { ...base.conversationTrust, ...override.conversationTrust };
  }
  if (base.interceptor || override.interceptor) {
    const b = base.interceptor ?? {};
    const o = override.interceptor ?? {};
    merged.interceptor = { ...b, ...o };
    if (b.severityActions || o.severityActions) {
      merged.interceptor.severityActions = { ...b.severityActions, ...o.severityActions };
    }
    if (b.failurePolicy || o.failurePolicy) {
      merged.interceptor.failurePolicy = { ...b.failurePolicy, ...o.failurePolicy };
    }
    if (b.actionGuard || o.actionGuard) {
      const bg = b.actionGuard ?? {};
      const og = o.actionGuard ?? {};
      const guard: NonNullable<InterceptorUserConfig['actionGuard']> = { ...bg, ...og };
      if (bg.notify || og.notify) guard.notify = { ...bg.notify, ...og.notify };
      if (bg.broker || og.broker) guard.broker = { ...bg.broker, ...og.broker };
      merged.interceptor.actionGuard = guard;
    }
  }
  return merged;
}

function extractPluginConfig(rootConfig: unknown, dropped?: string[]): SCConfig {
  if (!rootConfig || typeof rootConfig !== "object" || Array.isArray(rootConfig)) return {};
  const entries = (rootConfig as {
    plugins?: {
      entries?: Record<string, { config?: unknown } | undefined>;
    };
  }).plugins?.entries;

  const pluginConfig =
    entries?.[PLUGIN_ID]?.config ??
    entries?.[PLUGIN_PACKAGE_NAME]?.config;

  return normaliseConfig(pluginConfig, dropped);
}

function applyPluginConfigOverride(api: PluginApi): void {
  const runtimeConfigApi = api.runtime?.config;
  const runtimeConfig = typeof runtimeConfigApi?.current === "function"
    ? runtimeConfigApi.current()
    : typeof runtimeConfigApi?.loadConfig === "function"
      ? runtimeConfigApi.loadConfig()
      : api.config;
  // #115: name the exact dropped interceptor key(s) in a warn log. Edith's
  // #112 incident (interceptor.enabled:"false", a string not a boolean) took
  // longer to diagnose than it should have because the drop was silent —
  // this is the one normaliseConfig() call site that both parses the
  // human-edited openclaw.json plugin entry AND has a logger to hand.
  const dropped: string[] = [];
  const pluginConfig = extractPluginConfig(runtimeConfig, dropped);
  if (dropped.length > 0) {
    (api.logger as any)?.warn?.(
      `[shieldcortex] plugin config: dropped invalid interceptor key(s), check type/value: ${dropped.join(', ')}`,
    );
  }
  if (Object.keys(pluginConfig).length === 0) return;
  _configOverride = mergeConfigs(_configOverride ?? {}, pluginConfig);
  // Override changed — invalidate so loadConfig() re-merges with new override.
  _config = null;
  _lastShieldConfigRef = null;
}

/**
 * Load the effective config, DEGRADING rather than throwing (#226).
 *
 * `getRuntime()` resolves `shieldcortex/dist/…/runtime.mjs` by walking a list of
 * install locations, and `loadShieldConfig()` then reads a file. Both can fail
 * for ordinary reasons — the package was upgraded underneath a running gateway,
 * a global install moved, `~/.shieldcortex/config.json` is half-written.
 *
 * This used to propagate, and the propagation went somewhere bad: every caller
 * of `loadConfig` is a hook body, and in `handleBeforeAgentRun` the throw was
 * caught by the OUTER catch — the one that fails open. So a host that could not
 * load the runtime produced one console line per turn and NOTHING else: no
 * posture, no scan, no audit row, no alert. Precisely the "unprotected turn that
 * leaves no trace" the #225/#226 work exists to eliminate, reintroduced through
 * the config read rather than through the scanner.
 *
 * Now it degrades to the plugin config from openclaw.json (already normalised by
 * `applyPluginConfigOverride`), or to an empty config. The posture therefore
 * still resolves, the scan still runs, `scanRealtimeContent` reports UNAVAILABLE
 * on its own (the same runtime failure defeats the MCP fallback), and the gate
 * writes its normal audit row and raises its normal alert.
 *
 * It does NOT cache the degraded result — a later successful load must take
 * effect without a restart — and it never claims the shield config loaded: the
 * warning says exactly what is missing, and is bounded, redacted, and emitted
 * ONCE per plugin load (`__resetConfigStateForTest` re-arms it) so a per-turn
 * failure cannot become per-turn log spam.
 */
let _shieldConfigLoadFailureLogged = false;

async function loadConfig(): Promise<SCConfig> {
  let shieldConfigRaw: unknown;
  try {
    shieldConfigRaw = await (await getRuntime()).loadShieldConfig();
  } catch (err) {
    if (!_shieldConfigLoadFailureLogged) {
      _shieldConfigLoadFailureLogged = true;
      const detail = redactNotifyDetail(err instanceof Error ? err.message : String(err)).slice(0, 300);
      console.warn(
        '[shieldcortex] ⚠️ shield config could NOT be loaded — the ShieldCortex runtime did not resolve, ' +
        `or it could not read ~/.shieldcortex/config.json (${detail}). Continuing with the openclaw.json ` +
        'plugin config only; anything configured in the shield config file is NOT in effect, and ' +
        'conversation scanning will report UNAVAILABLE until this is fixed. (Logged once per plugin load.)',
      );
    }
    // A fresh object every time: `_configOverride` is module state and callers
    // must not be handed something they could mutate.
    return mergeConfigs({}, _configOverride ?? {});
  }
  // A load that succeeds after a failure re-arms the warning, so a SECOND
  // outage is reported rather than swallowed by the first one's flag. Set
  // before the cache check: a runtime that hands back the same object every
  // call would otherwise take the early return and leave the flag latched.
  _shieldConfigLoadFailureLogged = false;
  if (_config && shieldConfigRaw === _lastShieldConfigRef) return _config;
  _lastShieldConfigRef = shieldConfigRaw;
  // Plugin config (openclaw.json) deep-merges over the shield config file —
  // see mergeConfigs() for the per-key semantics.
  _config = mergeConfigs(normaliseConfig(shieldConfigRaw), _configOverride ?? {});
  return _config;
}

function isAutoMemoryEnabled(config: SCConfig): boolean {
  return config.openclawAutoMemory === true;
}

function isAutoMemoryDedupeEnabled(config: SCConfig): boolean {
  return config.openclawAutoMemoryDedupe !== false;
}

async function callCortex(tool: string, args: Record<string, string> = {}): Promise<string | null> {
  return (await getRuntime()).callCortex(tool, args);
}

// ==================== REMOTE SCANNING ====================

// Build the `{ clean, summary }` contract from the parsed MCP text response.
// Kept identical to the historical regex parse so the fallback degrades to the
// exact behaviour callers depended on before in-process scanning landed.
function parseScanResponse(response: string): { clean: boolean; summary: string } {
  const cleanMatch = response.match(/\*\*Clean:\*\*\s*(Yes|No)/i);
  const riskMatch = response.match(/\*\*Risk Level:\*\*\s*([A-Za-z]+)/i);
  const detectionsMatch = response.match(/\*\*Detections:\*\*\s*(\d+)/i);

  const clean = cleanMatch ? /yes/i.test(cleanMatch[1]) : true;
  const risk = riskMatch?.[1] ?? "unknown";
  const detections = detectionsMatch?.[1];
  const summary = detections ? `${risk} (${detections} detections)` : risk;

  return { clean, summary };
}

/**
 * Scan one piece of conversation content.
 *
 * The contract changed in #225 and the change is the point: an unavailable
 * scanner is now reported as `available: false, clean: false`, not as the old
 * `{ clean: true, summary: 'scan unavailable' }`. That old return was the
 * quietest bug in this file — the ORDINARY unavailable path (MCP fallback
 * returns nothing, e.g. no shieldcortex binary on PATH) manufactured a clean
 * verdict, so on any box where in-process defence failed to load, every message
 * was reported scanned-and-fine while nothing had been looked at.
 *
 * Fails OPEN — callers must not block on `available: false` — but LOUDLY: the
 * caller audits it, alerts on it, and doctor/status report the plane as
 * unavailable rather than protected.
 */
export async function scanRealtimeContent(text: string): Promise<ConversationScanResult> {
  // PRIMARY: scan in-process via the shared shieldcortex/defence module. The
  // scan is pure (no DB handle required — scanToolResponse's audit write is
  // guarded by isDatabaseInitialized()), so it is safe in the long-lived
  // gateway and avoids booting a cold MCP server per message.
  let defenceMod: DefenceModule | null = null;
  try {
    defenceMod = await getDefenceModule();
  } catch (err) {
    defenceMod = null;
    void err;
  }
  if (defenceMod && typeof defenceMod.scanToolResponse === "function") {
    try {
      const scan = defenceMod.scanToolResponse("openclaw-realtime", text, "advisory");
      // Reproduce the historical summary contract exactly: risk level + detection
      // count only when the injection scan flagged something.
      const risk = scan.injection.clean ? "unknown" : scan.injection.riskLevel;
      const summary = scan.injection.clean
        ? risk
        : `${risk} (${scan.injection.detections.length} detections)`;
      return { clean: scan.clean, summary, available: true };
    } catch (err) {
      // A scanner that THROWS is not a clean verdict either. Same treatment as
      // an absent one: unavailable, reported, never silently allowed to read as
      // protected.
      const detail = err instanceof Error ? err.message : String(err);
      return { clean: false, available: false, errored: true, error: `in-process scanner threw: ${detail}`, summary: "scan unavailable" };
    }
  }

  // FALLBACK: in-process defence unavailable (older install, import failed) —
  // degrade to the MCP shell-out so scanning still happens rather than breaking.
  let response: string | null = null;
  try {
    response = await callCortex("scan_tool_response", {
      toolName: "openclaw-realtime",
      content: text,
      mode: "advisory",
    });
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    return { clean: false, available: false, errored: true, error: `scan fallback failed: ${detail}`, summary: "scan unavailable" };
  }

  if (!response) {
    return {
      clean: false,
      available: false,
      errored: true,
      error: 'no in-process defence module and the MCP fallback returned nothing',
      summary: 'scan unavailable',
    };
  }

  const parsed = parseScanResponse(response);
  return { ...parsed, available: true };
}

/**
 * `scanRealtimeContent` with a hard deadline (#226).
 *
 * Used ONLY by the `before_agent_run` gate, which the gateway awaits: an
 * unbounded scan there is an unbounded pause in front of the user's prompt. The
 * MCP fallback boots a cold server through `npx` and has been measured at ~15s,
 * so "it usually returns quickly" is not a bound.
 *
 * On expiry the result is an ordinary UNAVAILABLE verdict — fail open, audited,
 * alerted — and the error string names the deadline and NOTHING ELSE. It must
 * never quote the prompt: a timeout message is the one error a developer is
 * most likely to paste into an issue.
 *
 * The losing promise is not abandoned silently: a `.catch` is attached before
 * the race so a scan that rejects AFTER the deadline settles into a no-op
 * instead of an unhandled rejection that could take the gateway down under
 * `--unhandled-rejections=strict`.
 */
export async function scanWithDeadline(
  text: string,
  timeoutMs: number = CONVERSATION_SCAN_MAX_MS,
): Promise<ConversationScanResult> {
  const timedOut: ConversationScanResult = {
    clean: false,
    available: false,
    errored: true,
    error: `conversation scan exceeded its ${timeoutMs}ms deadline`,
    summary: 'scan unavailable',
  };

  const scan = scanRealtimeContent(text);
  // Attached BEFORE the race, so a late rejection can never be unhandled.
  scan.catch(() => { /* the race already answered; nothing left to report */ });

  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      scan,
      new Promise<ConversationScanResult>((resolve) => {
        timer = setTimeout(() => resolve(timedOut), timeoutMs);
        // Never hold the process open on the deadline timer alone.
        (timer as { unref?: () => void }).unref?.();
      }),
    ]);
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    return { clean: false, available: false, errored: true, error: detail, summary: 'scan unavailable' };
  } finally {
    if (timer) clearTimeout(timer);
  }
}

// ==================== CONTENT PATTERNS ====================

const PATTERNS: Record<string, RegExp[]> = {
  architecture: [/\b(?:architecture|designed|structured)\b.*?(?:uses?|is|with)\b/i, /\b(?:decided?\s+to|going\s+with|chose)\b/i],
  error: [/\b(?:fixed|resolved|solved)\s+(?:by|with|using)\b/i, /\b(?:solution|fix|root\s*cause)\s+(?:was|is)\b/i],
  learning: [/\b(?:learned|discovered|turns?\s+out|figured\s+out|realized)\b/i],
  preference: [
    /\b(?:I|we|you\s+should)\s+(?:always|never)\b/i,
    /\b(?:always\s+use|never\s+use|never\s+commit)\b/i,
    /\bprefer(?:\s+to)?\s+\w+/i,
    /\bshould\s+always\b/i,
  ],
  note: [/\b(?:important|remember|key\s+point)\s*:/i],
};

function extractMemories(texts: string[]): Array<{ title: string; content: string; category: string }> {
  const out: Array<{ title: string; content: string; category: string }> = [];
  const seen = new Set<string>();
  for (const text of texts) {
    if (text.length < 30) continue;
    for (const [cat, pats] of Object.entries(PATTERNS)) {
      if (pats.some(p => p.test(text))) {
        const title = text.slice(0, 80).replace(/["\n]/g, " ").trim();
        if (!seen.has(title)) { seen.add(title); out.push({ title, content: text.slice(0, 500), category: cat }); }
        break;
      }
      if (out.length >= 3) break;
    }
    if (out.length >= 3) break;
  }
  return out;
}

// ==================== HELPERS ====================

function extractUserContent(msgs: unknown[]): string[] {
  const out: string[] = [];
  for (const msg of msgs) {
    if (!msg || typeof msg !== "object") continue;
    const m = msg as any;
    if (m.role !== "user") continue;
    if (typeof m.content === "string") out.push(m.content);
    else if (Array.isArray(m.content)) for (const b of m.content) if (b?.type === "text") out.push(b.text);
  }
  return out;
}

/** Where the realtime audit jsonl lives.
 *
 *  Resolved PER CALL, and honouring `SHIELDCORTEX_AUDIT_DIR`, so a test can
 *  exercise the hook end-to-end without appending fabricated "threat" rows to
 *  a real box's security audit trail. Default is unchanged
 *  (`~/.shieldcortex/audit`), so nothing moves for an install that does not set
 *  the variable. */
function auditDir(): string {
  const override = process.env.SHIELDCORTEX_AUDIT_DIR;
  if (override && override.trim()) return override.trim();
  return path.join(homedir(), ".shieldcortex", "audit");
}
const NOVELTY_CACHE_FILE = path.join(homedir(), ".shieldcortex", "openclaw-memory-cache.json");
const DEFAULT_NOVELTY_THRESHOLD = 0.88;
const DEFAULT_MAX_RECENT = 300;
const MIN_NOVELTY_CHARS = 40;

/**
 * Append one row to the realtime audit jsonl. Returns WHETHER IT LANDED (#226).
 *
 * This used to swallow every failure and return void, so a caller could not
 * distinguish "the evidence is on disk" from "the disk is full / the audit dir
 * is not writable / it is a file where a directory should be". The
 * `before_agent_run` gate then wrote a decision row, got nothing back, and
 * proceeded to tell the operator — and the delivery row — that the decision was
 * recorded. A security control claiming evidence it does not have is worse than
 * one that admits the gap, because the gap is invisible in exactly the incident
 * where the log matters.
 *
 * Still never throws: a broken audit sink must not become a broken turn.
 */
async function auditLog(entry: Record<string, unknown>): Promise<boolean> {
  const dir = auditDir();
  try {
    const hookName = typeof entry.hook === 'string' && entry.hook ? entry.hook : 'llm_input';
    const plane = hookName === 'before_tool_call' ? 'action_guard' : 'conversation_firewall';
    let bound = entry;
    try {
      const defenceMod = await getDefenceModule();
      if (typeof defenceMod?.attachEnforcementBinding === 'function') {
        bound = defenceMod.attachEnforcementBinding(entry, {
          plane,
          hookName,
          pluginId: 'shieldcortex-realtime',
          actionKey: typeof entry.actionKey === 'string' ? entry.actionKey : `conversation:${hookName}`,
        });
      }
    } catch { /* older package / bind failure — write the unbound row */ }
    await fs.mkdir(dir, { recursive: true });
    await fs.appendFile(
      path.join(dir, `realtime-${new Date().toISOString().slice(0, 10)}.jsonl`),
      JSON.stringify(bound) + "\n",
    );
    return true;
  } catch (err) {
    // LOUD. The detail is the failure and the directory — never the row, which
    // may carry a verdict summary, and never a credential (nothing in this path
    // holds one). Bounded so a pathological error message cannot flood stderr.
    const detail = err instanceof Error ? err.message : String(err);
    console.error(
      `[shieldcortex] ⚠️ AUDIT WRITE FAILED (${dir}) — this event is NOT on disk: ${detail.slice(0, 300)}`,
    );
    return false;
  }
}

// `cloudSync` lives in ./cloud-sync.ts (no fs imports there) so the plugin
// security audit (OpenClaw 2026.4.24+) does not pair file-read with
// network-send in the same source file. See CHANGELOG.md v4.12.8.

type NoveltyEntry = {
  hash: string;
  tokenHashes: string[];
  title: string;
  category: string;
  createdAt: string;
};

function normalizeMemoryText(text: string): string {
  return String(text || "")
    .toLowerCase()
    .replace(/[`"'\\]/g, " ")
    .replace(/https?:\/\/\S+/g, " ")
    .replace(/[^a-z0-9\s]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function hashToken(token: string): string {
  return createHash("sha1").update(token).digest("hex").slice(0, 12);
}

function buildTokenHashes(normalized: string): string[] {
  const words = normalized.split(" ").filter((w) => w.length >= 3);
  const set = new Set<string>();

  for (let i = 0; i < words.length; i++) {
    set.add(hashToken(words[i]));
    if (i < words.length - 1) set.add(hashToken(`${words[i]}_${words[i + 1]}`));
  }

  return Array.from(set).slice(0, 200);
}

function jaccardSimilarity(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 || b.size === 0) return 0;
  let intersection = 0;
  for (const item of a) {
    if (b.has(item)) intersection++;
  }
  const union = a.size + b.size - intersection;
  return union === 0 ? 0 : intersection / union;
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

async function loadNoveltyCache(maxRecent: number): Promise<NoveltyEntry[]> {
  try {
    const raw = JSON.parse(await fs.readFile(NOVELTY_CACHE_FILE, "utf-8"));
    if (!Array.isArray(raw)) return [];
    return raw
      .filter((entry) => entry && typeof entry.hash === "string" && Array.isArray(entry.tokenHashes))
      .slice(0, maxRecent) as NoveltyEntry[];
  } catch {
    return [];
  }
}

async function saveNoveltyCache(entries: NoveltyEntry[]): Promise<void> {
  await fs.mkdir(path.dirname(NOVELTY_CACHE_FILE), { recursive: true });
  await fs.writeFile(NOVELTY_CACHE_FILE, JSON.stringify(entries, null, 2) + "\n", "utf-8");
}

function inspectNovelty(content: string, entries: NoveltyEntry[], threshold: number): {
  allow: boolean;
  contentHash: string | null;
  tokenHashes: string[];
  reason?: string;
} {
  const normalized = normalizeMemoryText(content);
  if (normalized.length < MIN_NOVELTY_CHARS) {
    return { allow: true, contentHash: null, tokenHashes: [] };
  }

  const contentHash = createHash("sha256").update(normalized).digest("hex").slice(0, 24);
  if (entries.some((entry) => entry.hash === contentHash)) {
    return { allow: false, contentHash, tokenHashes: [], reason: "exact duplicate" };
  }

  const tokenHashes = buildTokenHashes(normalized);
  const currentSet = new Set(tokenHashes);

  for (const entry of entries) {
    const score = jaccardSimilarity(currentSet, new Set(entry.tokenHashes || []));
    if (score >= threshold) {
      return {
        allow: false,
        contentHash,
        tokenHashes,
        reason: `near duplicate (similarity ${score.toFixed(2)})`,
      };
    }
  }

  return { allow: true, contentHash, tokenHashes };
}

async function createNoveltyGate(config: SCConfig): Promise<{
  inspect: (content: string) => { allow: boolean; contentHash: string | null; tokenHashes: string[]; reason?: string };
  remember: (memory: { title: string; category: string }, novelty: { contentHash: string | null; tokenHashes: string[] }) => void;
  flush: () => Promise<void>;
}> {
  const thresholdRaw = Number(config.openclawAutoMemoryNoveltyThreshold);
  const maxRecentRaw = Number(config.openclawAutoMemoryMaxRecent);
  const threshold = Number.isFinite(thresholdRaw)
    ? clamp(thresholdRaw, 0.6, 0.99)
    : DEFAULT_NOVELTY_THRESHOLD;
  const maxRecent = Number.isFinite(maxRecentRaw)
    ? Math.floor(clamp(maxRecentRaw, 50, 1000))
    : DEFAULT_MAX_RECENT;

  const enabled = isAutoMemoryDedupeEnabled(config);
  const entries = enabled ? await loadNoveltyCache(maxRecent) : [];
  let dirty = false;

  return {
    inspect(content: string) {
      if (!enabled) return { allow: true, contentHash: null, tokenHashes: [] };
      return inspectNovelty(content, entries, threshold);
    },
    remember(memory, novelty) {
      if (!enabled || !novelty.contentHash || novelty.tokenHashes.length === 0) return;
      entries.unshift({
        hash: novelty.contentHash,
        tokenHashes: novelty.tokenHashes,
        title: String(memory.title || "").slice(0, 120),
        category: String(memory.category || "note"),
        createdAt: new Date().toISOString(),
      });
      if (entries.length > maxRecent) entries.length = maxRecent;
      dirty = true;
    },
    async flush() {
      if (!enabled || !dirty) return;
      await saveNoveltyCache(entries);
    },
  };
}

// ==================== HOOK HANDLERS ====================

// Skip scanning internal OpenClaw content (boot checks, system prompts, heartbeats)
const SKIP_PATTERNS = [
  /^You are running a boot check/i,
  /^Read HEARTBEAT\.md/i,
  /^System:/,
  /^\[System Message\]/,
  /^HEARTBEAT_OK$/,
  /^\[(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s/,  // Timestamped system events
  /^A subagent task/i,
  /subagent.*completed/i,
];
function isInternalContent(text: string): boolean {
  return SKIP_PATTERNS.some(p => p.test(text.trim()));
}

// Awaitable scan body — extracted so the jest suite can verify behaviour
// deterministically. handleLlmInput wraps this fire-and-forget so the hook
// itself stays non-blocking.
export async function scanLlmInput(event: LlmInputEvent, _ctx: AgentCtx): Promise<void> {
  try {
    // #226: THE POSTURE GOVERNS THIS HOOK TOO. `off` means "do not scan the
    // conversation at all", and this observation hook used to ignore it
    // entirely: it scanned every prompt, wrote threat and scan_unavailable rows,
    // and forwarded detections to the cloud on a box whose operator had
    // explicitly turned conversation inspection OFF. The gate honoured the
    // setting, so a reader of `handleBeforeAgentRun` would conclude the product
    // did too. Read it FIRST, before any scanner, any audit row and any cloud
    // call, so `off` costs exactly one config read.
    const cfg = await loadConfig();
    if (conversationPosture(cfg.interceptor?.conversation) === 'off') return;

    // Only scan user content, skip system/boot/heartbeat prompts
    // Trust is resolved per TURN, not per message: the host tells us who sent
    // this turn, but history messages carry no individual attribution, so there
    // is no honest way to score them separately.
    //
    // Resolved LAZILY, on first detection only. Computing it up front would put
    // a config read on every single turn to answer a question that only matters
    // when something is actually found.
    let trustMemo: ConversationTrustDecision | null = null;
    const resolveTrust = async () => {
      if (!trustMemo) {
        // `cfg` is already in hand from the posture read above, so this costs
        // no I/O. It also reads the PARSED field rather than casting the config
        // object — the cast this replaces asserted a key that normaliseConfig
        // drops, so it was always undefined. See SCConfig.conversationTrust.
        trustMemo = classifyConversationOrigin({
          senderIsOwner: event.senderIsOwner,
          trustOwnerInput: cfg.conversationTrust?.trustOwnerInput,
        });
      }
      return trustMemo;
    };
    const userTexts = extractUserContent(event.historyMessages).slice(-5);
    const texts = [event.prompt, ...userTexts].filter(t => t && !isInternalContent(t));
    for (const text of texts) {
      if (!text || text.length < 10) continue;
      const result = await scanRealtimeContent(text);
      // #225: "we could not look" is its own outcome. Before this branch the
      // unavailable path returned clean:true and this loop did nothing at all —
      // an unscanned message was indistinguishable from a scanned one, on the
      // observation hook as well as the gate.
      if (!result.available) {
        // #226: redacted on the CONSOLE too, not only in the row. The reason
        // comes from a transport/scanner failure string, which can name the
        // endpoint it failed to reach — and a gateway's stdout is routinely
        // shipped to a log aggregator, so "ephemeral" is not a property the
        // console actually has.
        const detail = redactNotifyDetail(result.error ?? result.summary);
        console.warn(
          `[shieldcortex] ⚠️ conversation scan UNAVAILABLE (${detail}) — this message was NOT scanned`,
        );
        // AWAITED. The whole function is already fire-and-forget from
        // `handleLlmInput`, so this blocks nothing the gateway is waiting on —
        // and it means the row is on disk before the loop moves to the next
        // message, and that `auditLog`'s new boolean (which logs loudly on
        // failure) is actually reached rather than discarded into a floating
        // promise.
        await auditLog({
          type: 'scan_unavailable', hook: 'llm_input', sessionId: event.sessionId,
          model: event.model, reason: detail,
          chars: text.length,
          contentSha256: createHash('sha256').update(text).digest('hex').slice(0, 16),
          ts: new Date().toISOString(),
        });
        continue;
      }
      if (!result.clean) {
        const trust = await resolveTrust();
        console.warn(`[shieldcortex] ⚠️ Threat in LLM input: ${result.summary} [${trust.origin}]`);
        // #233: THE sink that has teeth. Logging a detection changed nothing —
        // the tool call this injection is steering, one turn later, was
        // evaluated as if it had never been seen. Tainting the session makes
        // the Action Guard tighten by one notch for a bounded window.
        //
        // Source trust gates the CONSEQUENCE, never the detection: the warn and
        // the audit row below happen whoever sent this. What trust decides is
        // whether it may tighten the guard. The operator typing "delete the old
        // logs" is an instruction, and treating it as an attack is the false
        // alarm that gets a control switched off. Everything the agent was
        // handed — including another agent on a closed channel — is data.
        if (trust.mayTaint) {
          sessionTaint.mark(event.sessionId, { reason: `conversation scan: ${result.summary}` });
        }
        // #226: NO `preview`. This row carried the first 100 characters of the
        // prompt — the exact text that tripped an injection detector, i.e.
        // hostile by assumption — into an append-only file that syncs. The gate
        // on the very next hook has recorded only `chars` + `contentSha256`
        // since #225 and says in its own comment that the prompt is never
        // persisted; the observation hook quietly did the opposite, so the
        // claim was false on the path that runs on every single turn. Length
        // plus digest keeps the row correlatable with the gate's row for the
        // same text without storing the text.
        const entry = {
          type: "threat", hook: "llm_input", sessionId: event.sessionId,
          model: event.model, reason: result.summary,
          chars: text.length,
          contentSha256: createHash('sha256').update(text).digest('hex').slice(0, 16),
          // Whether this detection tainted the session (threat-graph Phase D:
          // lets the threat graph attribute taint-raising events). Metadata
          // only — no content, same as the fields above.
          tainted: trust.mayTaint,
          ts: new Date().toISOString(),
        };
        await auditLog(entry);
        loadConfig()
          // Pass the local entry as-is; cloudSync rebuilds a canonical metadata-only
          // entry from named fields and never reads content. No raw LLM input
          // leaves here.
          .then(cfg2 => cloudSync(entry, cfg2))
          .catch(() => {});
      }
    }
  } catch (e) {
    console.error("[shieldcortex] llm_input error:", e instanceof Error ? e.message : String(e));
  }
}

function handleLlmInput(event: LlmInputEvent, ctx: AgentCtx): void {
  // Fire and forget — OBSERVATION ONLY. This hook cannot block (#225); the
  // enforcement point is handleBeforeAgentRun below.
  void scanLlmInput(event, ctx);
}

/**
 * Route a conversation-threat detection to a HUMAN (#225).
 *
 * This is the "sink" the issue is named for. Before it existed, a HIGH verdict
 * produced a console line and an audit row, and a real detection on a live box
 * was seen by nobody. It reuses the Action Guard's notify transport (#143)
 * rather than inventing a second one — two notification paths would drift, and
 * the operator would learn which one to ignore.
 *
 * Returns whether a human was actually reached, so callers (and doctor) can
 * report "detected but undeliverable" instead of implying someone was told.
 * Never throws: a failed notification must not become a failed turn.
 */
/** The longest the conversation gate will wait for an operator alert to be
 *  handed to a transport. See the call site: the user's turn is blocked on this
 *  hook, so the alert's deadline has to be a fraction of the hook's. */
const CONVERSATION_NOTIFY_MAX_MS = 5_000;

/**
 * The longest the conversation gate will wait for a SCAN (#226).
 *
 * `before_agent_run` is awaited by the gateway — the user's turn is stopped
 * dead until this handler returns — and the scan's fallback path is an MCP
 * shell-out that boots a cold server via `npx`, which can take upwards of 15s.
 * That is half the hook's entire 30s budget before an alert and two audit
 * writes are added behind it, and it happens on exactly the hosts where the
 * in-process defence module failed to load: the ones already degraded.
 *
 * Past this deadline the scan is treated as UNAVAILABLE, which fails OPEN (the
 * turn proceeds) and is audited and alerted like any other unavailable scan. A
 * security control that silently adds fifteen seconds to every prompt is one an
 * operator uninstalls.
 */
export const CONVERSATION_SCAN_MAX_MS = 5_000;

/**
 * Repeat-alert suppression for the scan-unavailable path (#226).
 *
 * An unavailable scanner is not a transient event: it is usually a missing
 * install, a broken defence build or an absent binary, and it recurs on EVERY
 * turn. Alerting per turn turns the operator's phone into a metronome and the
 * alert into something they mute — which is the same outcome as never sending
 * one, reached by a more expensive route. First occurrence goes immediately;
 * after that, at most one alert per window, with the suppressed count carried
 * on the next alert that does go out so nothing is lost.
 *
 * THE WINDOW IS PER SESSION, not per process — see `noteScanUnavailable`. A
 * gateway runs many sessions at once, and "we already told you about session A"
 * is not a reason to stay silent about session B.
 *
 * AUDITING IS NOT RATE LIMITED. Every occurrence still writes its row, and the
 * row records whether an alert was suppressed and how many have been seen —
 * the evidence trail must be complete even when the notification stream is not.
 */
export const SCAN_UNAVAILABLE_ALERT_WINDOW_MS = 5 * 60_000;

interface ScanUnavailableAlertState {
  /** Total occurrences this session, across suppressed and alerted. */
  count: number;
  /** `Date.now()` of the last alert we actually sent, null until the first. */
  lastAlertAtMs: number | null;
  /** Occurrences suppressed since that alert. */
  suppressedSinceAlert: number;
  /** Last time this session touched the state — eviction key only, never
   *  reported. */
  lastSeenAtMs: number;
}

/**
 * The bucket used when the host hands us no session identity at all.
 *
 * `before_agent_run`'s context declares `sessionId` and `sessionKey` as
 * OPTIONAL, so both can be absent. Keying such an occurrence under a fixed
 * fallback keeps rate limiting working exactly as it did on a single-session
 * host, and — critically — keeps a nameless occurrence from sharing a bucket
 * with a NAMED one, which is what a `String(undefined)` key would have done.
 */
const SCAN_UNAVAILABLE_FALLBACK_SESSION = '__unkeyed-session__';

/**
 * Cap on distinct sessions tracked at once.
 *
 * `session_end` is what normally frees an entry, and it is not guaranteed: an
 * older host may not emit it, and a crashed session never will. This map is
 * therefore bounded and evicts least-recently-seen first. Overshooting the cap
 * costs at most one extra alert for the evicted session — the safe direction,
 * since the failure mode of eviction is "tell the operator again", not "stay
 * quiet". Each entry is four numbers and a short key, so 512 of them is a few
 * kilobytes in a process that already holds a scanner.
 */
export const SCAN_UNAVAILABLE_MAX_SESSIONS = 512;

const _scanUnavailable = new Map<string, ScanUnavailableAlertState>();

export interface ScanUnavailableAlertDecision {
  alert: boolean;
  /** How many occurrences this session, including this one. */
  count: number;
  /** Occurrences suppressed since the last alert. On an ALERT this is the
   *  backlog being reported and then cleared; on a suppression it is the
   *  running total. */
  suppressedSinceLastAlert: number;
}

/** Normalise whatever the host gave us into a map key. */
function scanUnavailableSessionKey(sessionKey?: string | null): string {
  const trimmed = typeof sessionKey === 'string' ? sessionKey.trim() : '';
  return trimmed === '' ? SCAN_UNAVAILABLE_FALLBACK_SESSION : trimmed;
}

/**
 * Should this scan-unavailable occurrence raise an operator alert?
 *
 * PER SESSION (#226). The first cut kept one module-global counter, which on a
 * gateway — a process that multiplexes every channel and every concurrent
 * agent — meant one session's broken scanner silenced the FIRST failure of
 * every other session for the next five minutes. That is the same class of bug
 * the rate limit exists to avoid, inverted: instead of too many alerts, a real
 * new failure is never reported at all. Suppression is a property of one
 * session's repeating failure, so the state is keyed by one session.
 *
 * Pure apart from the per-session counter it advances, and driven by an
 * injectable `now` so the window is testable without sleeping. Exported for the
 * regression test; not part of the plugin's host-facing surface.
 *
 * The key is a session id, never logged: it reaches this function only to index
 * the map. The audit rows that carry `sessionId` are the deliberate place that
 * fact is recorded.
 */
export function noteScanUnavailable(
  sessionKey?: string | null,
  nowMs: number = Date.now(),
): ScanUnavailableAlertDecision {
  const key = scanUnavailableSessionKey(sessionKey);
  let state = _scanUnavailable.get(key);
  if (!state) {
    evictScanUnavailableOverflow(nowMs);
    state = { count: 0, lastAlertAtMs: null, suppressedSinceAlert: 0, lastSeenAtMs: nowMs };
    _scanUnavailable.set(key, state);
  }
  state.count += 1;
  state.lastSeenAtMs = nowMs;
  const last = state.lastAlertAtMs;
  // A clock that jumped BACKWARDS (NTP step, suspend/resume) must not be able
  // to wedge alerting off forever: treat a negative elapsed as "window over".
  const elapsed = last === null ? Infinity : nowMs - last;
  if (last === null || elapsed >= SCAN_UNAVAILABLE_ALERT_WINDOW_MS || elapsed < 0) {
    const suppressed = state.suppressedSinceAlert;
    state.lastAlertAtMs = nowMs;
    state.suppressedSinceAlert = 0;
    return { alert: true, count: state.count, suppressedSinceLastAlert: suppressed };
  }
  state.suppressedSinceAlert += 1;
  return {
    alert: false,
    count: state.count,
    suppressedSinceLastAlert: state.suppressedSinceAlert,
  };
}

/** Keep the session map bounded when `session_end` never arrives. Evicts the
 *  least-recently-seen entries; an evicted session simply alerts once more. */
function evictScanUnavailableOverflow(nowMs: number): void {
  if (_scanUnavailable.size < SCAN_UNAVAILABLE_MAX_SESSIONS) return;
  const oldestFirst = [..._scanUnavailable.entries()].sort(
    (a, b) => (a[1].lastSeenAtMs ?? nowMs) - (b[1].lastSeenAtMs ?? nowMs),
  );
  const drop = _scanUnavailable.size - SCAN_UNAVAILABLE_MAX_SESSIONS + 1;
  for (const [key] of oldestFirst.slice(0, drop)) _scanUnavailable.delete(key);
}

/**
 * Forget ONE session's suppression window. Called from `session_end`, so a
 * long-lived gateway does not carry a finished session's suppression into a
 * reused id — and, just as importantly, does not clear anyone ELSE's.
 *
 * A `session_end` that names no session clears the fallback bucket only: on a
 * host that supplies no session identity every occurrence lands there, so that
 * is precisely the state that ended.
 */
export function resetScanUnavailableAlertState(sessionKey?: string | null): void {
  _scanUnavailable.delete(scanUnavailableSessionKey(sessionKey));
}

/** Test/reset seam: forget EVERY session. Production never wants this — one
 *  session ending must not re-arm alerting for the others — so it is reachable
 *  only from `__resetConfigStateForTest`. */
export function __resetScanUnavailableAlertState(): void {
  _scanUnavailable.clear();
}

/** What actually happened to an alert, so callers can report it truthfully.
 *  `configured: false` is the honest "nobody opted in" case and is NOT a
 *  failure — it is the #143 default-off contract. */
export interface NotifyOutcome {
  configured: boolean;
  delivered: boolean;
  via: string | null;
  detail: string;
}

/**
 * Make a failure detail safe to PERSIST, SEND or PRINT (#226).
 *
 * The detail is assembled from channel names, scanner errors and whatever a
 * transport said went wrong. Node's fetch failures do not name the URL, but a
 * transport is free to put one in its reason — and a notify webhook URL
 * routinely carries a token in its path or query
 * (`https://hooks.example/services/T0/B0/XXXXXXXX`). So any http(s) URL is
 * reduced to its origin: enough to tell WHICH endpoint failed, not enough to
 * replay a request to it. Bounded too, so a transport that returns a page of
 * HTML cannot bloat the log.
 *
 * EVERY sink gets the redacted string — not just the ones that obviously
 * outlive the process. The audit row is append-only and syncs; the notification
 * leaves the box; and the console is NOT the ephemeral thing an earlier version
 * of this comment claimed it was, because a gateway's stdout is routinely
 * shipped to a log aggregator and kept longer than the audit file. Redacting
 * for the row and not for the other two protected the least exposed of the
 * three.
 */
export function redactNotifyDetail(detail: string): string {
  const withoutUrls = String(detail ?? '').replace(
    /https?:\/\/[^\s'"]+/gi,
    (url) => {
      try {
        return `${new URL(url).origin}/…`;
      } catch {
        return '<url>';
      }
    },
  );
  return withoutUrls.length > 500 ? `${withoutUrls.slice(0, 499)}…` : withoutUrls;
}

/**
 * The seam a gateway MIGHT offer for sending an operator a message, captured at
 * register() time if the API exposes it.
 *
 * No OpenClaw build we have inspected exposes it — neither 2026.5.2 nor
 * 2026.7.1 has a `notifyOperator` anywhere in its plugin API — so in practice
 * the webhook is the load-bearing channel and this stays null. It is read
 * structurally rather than removed because #143's design intent was that on
 * OpenClaw the transport should use the gateway's own message capability, and
 * that only becomes true if the code is ready for the day it appears. Nothing
 * here should be read as "ShieldCortex delivers natively on OpenClaw today".
 */
let _gatewayNotifyContext: GatewayNotifyContext | null = null;
export function __setGatewayNotifyContextForTest(ctx: GatewayNotifyContext | null): void {
  _gatewayNotifyContext = ctx;
}

/**
 * Route a conversation-firewall detection to a HUMAN (#225).
 *
 * This is the "sink" the issue is named for: before it existed, a HIGH verdict
 * produced a console line and an audit row, and a real detection on a live box
 * was seen by nobody.
 *
 * It reuses the Action Guard's #143 transport rather than inventing a second
 * one — but *correctly*, which the first cut did not:
 *
 *   - the notification is built by the main package's
 *     `buildConversationThreatNotification`, so it is a real, bounded
 *     notification with its own event discriminator, NOT an ad-hoc
 *     `{kind, severity, …}` literal cast through `NotifyChannel.send`. A
 *     conversation alert therefore cannot render Approve/Deny controls or a
 *     hash that does not exist — the fields simply are not on the type.
 *   - delivery goes through `deliverOperatorNotification`, the same core the
 *     approval path uses, so the deadline, the malformed-result handling and
 *     the "nothing but the boolean is read back" rule are shared, not copied.
 *   - the webhook secret is read from `webhookSecret` — the field
 *     `normaliseNotifyConfig` actually returns. Mirroring it as `secret`
 *     silently produced UNSIGNED POSTs.
 *   - both channels are offered where the runtime provides them: the gateway's
 *     own message seam first WHERE IT EXISTS (no build we have inspected
 *     exposes one — see `_gatewayNotifyContext`), then the configured webhook,
 *     which is what actually carries an alert off the box today.
 *
 * Returns what happened, and NEVER throws: a failed notification must not
 * become a failed turn.
 */
export async function notifyOperatorOfConversationThreat(input: {
  outcome: 'blocked' | 'observed' | 'unavailable';
  posture: ConversationPosture;
  summary: string;
  reason: string;
  sessionId?: string;
  model?: string;
}): Promise<NotifyOutcome> {
  try {
    const mod = await getDefenceModule();
    const cfg = await loadConfig();
    const raw = cfg.interceptor?.actionGuard?.notify;
    if (!raw) return { configured: false, delivered: false, via: null, detail: 'no notify config' };
    if (typeof mod?.normaliseNotifyConfig !== 'function') {
      return { configured: true, delivered: false, via: null, detail: 'installed shieldcortex build has no notify transport' };
    }
    const notify = mod.normaliseNotifyConfig(raw);
    if (!notify.enabled) return { configured: false, delivered: false, via: null, detail: 'notify disabled' };

    const channels: NotifyChannelLike[] = [];
    // The gateway's own message seam, WHERE the runtime provides one. It would
    // go first, because it would reach the operator on a channel they already
    // read — but `_gatewayNotifyContext` is null on every build we have
    // inspected, so in practice this list starts at the webhook below.
    if (notify.openclaw === true && _gatewayNotifyContext) {
      const gatewayChannel = createGatewayNotifyChannel(_gatewayNotifyContext);
      if (gatewayChannel) channels.push(gatewayChannel);
    }
    if (notify.webhookUrl && typeof mod.createWebhookNotifyChannel === 'function') {
      channels.push(
        mod.createWebhookNotifyChannel({
          url: notify.webhookUrl,
          // The signing key. Passed straight through and never logged — see
          // notify-config.ts, which is the only place this value is parsed.
          secret: notify.webhookSecret,
        }),
      );
    }
    if (channels.length === 0) {
      return { configured: true, delivered: false, via: null, detail: 'notify enabled but no channel is configured/buildable on this host' };
    }

    const notification =
      typeof mod.buildConversationThreatNotification === 'function'
        ? mod.buildConversationThreatNotification({
          outcome: input.outcome,
          posture: input.posture,
          summary: input.summary,
          reason: input.reason,
          sessionId: input.sessionId,
          model: input.model,
          host: hostname(),
          detectedAt: new Date().toISOString(),
        })
        : null;
    if (!notification) {
      // An older dist has the transport but not this event. Sending the
      // approval-shaped payload instead would put an Approve button on an alert
      // with nothing behind it — refuse, and say why.
      return {
        configured: true,
        delivered: false,
        via: null,
        detail: 'installed shieldcortex build predates the conversation-threat notification — refusing to send an approval-shaped alert',
      };
    }

    if (typeof mod.deliverOperatorNotification !== 'function') {
      return { configured: true, delivered: false, via: null, detail: 'installed shieldcortex build has no notification delivery core' };
    }
    const result = await mod.deliverOperatorNotification(notification, {
      channels,
      // Bounded HARDER than the transport's own configured deadline, because
      // this call sits inside a gate the gateway awaits: the user's turn is
      // waiting on it. The hook is registered with a 30s timeout, and a gate
      // that exceeds its own timeout is a security control that fails in a way
      // nobody has reasoned about. The alert is already in the log and the
      // audit row by this point, so what a longer wait buys is one extra retry
      // window on a transport that is, by then, visibly unhealthy.
      timeoutMs: Math.min(notify.timeoutMs ?? CONVERSATION_NOTIFY_MAX_MS, CONVERSATION_NOTIFY_MAX_MS),
    });
    const failures = result.attempts
      .filter((a) => !a.result.delivered)
      .map((a) => `${a.channel}: ${a.result.reason ?? 'failed'}`)
      .join('; ');
    return {
      configured: true,
      delivered: result.deliveredVia !== null,
      via: result.deliveredVia,
      detail: result.deliveredVia ? `delivered via ${result.deliveredVia}` : `undeliverable — ${failures || 'no channel accepted it'}`,
    };
  } catch (err) {
    return {
      configured: true,
      delivered: false,
      via: null,
      detail: `notify error: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

/**
 * The event payload OpenClaw hands `before_agent_run`, as declared by the host
 * SDK (`PluginHookBeforeAgentRunEvent`, hook-types.d.ts). Note what is NOT on
 * it: `sessionId` and `model` live on the CONTEXT, not the event — reading them
 * off the event, as the first cut did, produced `undefined` in every audit row
 * and every alert.
 */
type BeforeAgentRunEvent = {
  prompt?: string;
  messages?: unknown[];
  systemPrompt?: string;
  accountId?: string;
  channelId?: string;
  senderId?: string;
  senderIsOwner?: boolean;
};

/**
 * The gate's return contract, verbatim from the host SDK:
 *
 *   type HookDecisionPass  = { outcome: "pass" }
 *   type HookDecisionBlock = { outcome: "block"; reason: string; message?: string;
 *                              category?: string; metadata?: Record<string, unknown> }
 *   type PluginHookBeforeAgentRunResult = InputGateDecision | void
 *
 * `{ block: true }` — what the first cut returned — is the `before_tool_call`
 * shape, and this gate does not understand it: it is neither "pass" nor
 * "block", so the run would have proceeded while our audit row said BLOCKED.
 * A firewall whose block is a no-op is worse than no firewall, because the
 * evidence says it worked.
 *
 * `reason` is documented as INTERNAL ("core must not log, persist, broadcast,
 * or expose it verbatim"); `message` is the user-facing half. We keep the
 * verdict summary in both — it names the risk level and the detection count,
 * never the offending text.
 *
 * SHAPE IS EXACT, and the host enforces it structurally (`isHookDecision`,
 * hook-runner-global, 2026.7.1-2): a pass must be `{ outcome: 'pass' }` and
 * NOTHING else — the guard is `keys.length === 1`. Adding so much as a
 * `metadata` field to the pass branch for debugging would make it "not a hook
 * decision", and the runner's answer to that is not to ignore it: it is
 * `{ outcome: 'block', reason: 'before_agent_run returned an invalid
 * decision' }`. The failure mode of a malformed ALLOW here is a BLOCKED turn.
 */
export type InputGateDecision =
  | { outcome: 'pass' }
  | { outcome: 'block'; reason: string; message?: string; category?: string; metadata?: Record<string, unknown> };

/**
 * The gate's allow answer, stated explicitly (#226).
 *
 * A fresh literal per call, not a shared constant: the runner passes whatever
 * we return into its own merge/normalise chain, and a frozen singleton handed
 * to a host that decides to annotate it would fail in a way this plugin cannot
 * see. It costs one object per turn.
 *
 * WHY EXPLICIT, when the SDK types the result `InputGateDecision | void` and
 * this handler previously returned `undefined` on every allow path:
 *
 * The 2026.7.1-2 runner contradicts itself about void, one guard deep.
 * `runBeforeAgentRun`'s doc comment says "Handlers that return void are treated
 * as pass", and its `mergeResults` body opens with
 *
 *     if (next === void 0 || next === null) → { outcome: "block",
 *                                               reason: "…invalid decision" }
 *
 * i.e. the merge is written to BLOCK on void. What saves an `undefined` return
 * today is only that `runModifyingHook` never calls the merge for it —
 * `if (handlerResult !== void 0 && (handlerResult !== null || mergeNullResults))`
 * — so the void branch inside the merge is unreachable dead code, while `null`,
 * the sibling value that same line treats identically, reaches it and DOES
 * block. Verified by executing the real 2026.7.1-2 runner: `undefined` → pass,
 * `null` → block/invalid, `{outcome:'pass'}` → pass.
 *
 * So void is not broken here — it is correct by one guard, against a merge
 * function whose stated intent is to reject it. `{ outcome: 'pass' }` is
 * correct under BOTH readings, and is the shape the host validates rather than
 * the shape it happens to skip. That is the difference worth having in front of
 * every user turn.
 */
function gatePass(): InputGateDecision {
  return { outcome: 'pass' };
}

/**
 * The conversation firewall's enforcement point (#225).
 *
 * Unlike `llm_input`, this hook is awaited by the gateway and its return value
 * decides whether the run proceeds. It scans the prompt, applies the configured
 * posture, and — critically — routes a detection to a HUMAN rather than only to
 * a log file. The finding this fixes was that a HIGH verdict on a live box was
 * seen by nobody.
 *
 * Fails OPEN on any internal error: a security plugin that bricks the gateway
 * has caused a worse outage than the one it prevents. Every failure is reported.
 *
 * EVERY path returns a decision — `gatePass()` to allow, `{ outcome: 'block' }`
 * only for a dirty verdict under `enforce`. Nothing returns `undefined`; see
 * `gatePass` for the host-contract reason. "Fails open" therefore now means an
 * explicit pass, which is a stronger statement than the absence of an answer:
 * it is the same word said in the vocabulary the host validates.
 */
export async function handleBeforeAgentRun(
  event: BeforeAgentRunEvent,
  ctx: AgentCtx,
): Promise<InputGateDecision> {
  let posture: ConversationPosture = 'observe';
  try {
    const cfg = await loadConfig();
    posture = conversationPosture(cfg.interceptor?.conversation);
    if (posture === 'off') return gatePass();

    const text = String(event?.prompt ?? '');
    if (!text || text.length < 10 || isInternalContent(text)) return gatePass();

    // sessionId/model come off the hook CONTEXT (PluginHookAgentContext); the
    // event carries neither. Both are optional there too, so both may be absent.
    const sessionId = ctx?.sessionId ?? ctx?.sessionKey;
    const model = (ctx as { modelId?: string } | undefined)?.modelId;

    // scanRealtimeContent no longer throws on the paths that used to (it
    // reports `available:false` instead), but a defensive catch stays: this
    // function's contract is that nothing here can stop a turn by accident.
    // #226: BOUNDED. The gateway awaits this hook, so an unbounded scan is an
    // unbounded pause in front of the user's prompt — see scanWithDeadline.
    let scan: ConversationScanResult;
    try {
      scan = await scanWithDeadline(text);
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      scan = { clean: false, available: false, errored: true, error: detail, summary: 'scan unavailable' };
    }

    // #235: WHO sent this turn, resolved before the verdict is applied.
    // `senderIsOwner` was declared on the event and read by nothing, so the
    // enforce path could block the operator's own paste and destroy it. The
    // config is already loaded, so this is a pure call — no second read.
    const trust = classifyConversationOrigin({
      senderIsOwner: event?.senderIsOwner,
      trustOwnerInput: cfg.conversationTrust?.trustOwnerInput,
    });

    const decision = evaluateConversationRun(posture, scan, trust);

    // #226: REDACT ONCE, then use the redacted string everywhere the reason
    // goes — the persisted decision row, the outbound notification, the block
    // reason, the console line. On the unavailable path `decision.reason`
    // embeds the scanner's own failure string verbatim
    // (`conversation scan unavailable (${scan.error})`), and that string is
    // assembled from a transport error: a cold MCP start, a fetch, a defence
    // build download. Any of those can name the endpoint it failed to reach,
    // and such a URL routinely carries a credential in its path
    // (`https://hooks.example/services/T0/B0/XXXX`). The console line was
    // already redacted while the row and the alert — the two that PERSIST and
    // LEAVE THE BOX — were not, which had the guarantee exactly backwards.
    const safeReason = decision.reason === null ? null : redactNotifyDetail(decision.reason);

    // #226: repeated unavailability alerts at most once per window. Called here
    // rather than at the notify site so the COUNTERS advance on every
    // occurrence, and the decision row can record what was suppressed even when
    // no alert goes out.
    // Keyed by SESSION: a broken scanner in one session must not silence the
    // first report of a broken scanner in another. `sessionId` may be absent —
    // noteScanUnavailable buckets that case separately rather than letting one
    // nameless session stand in for all of them.
    const unavailable = decision.outcome === 'unavailable';
    const alertGate = unavailable ? noteScanUnavailable(sessionId) : null;
    const suppressAlert = alertGate !== null && !alertGate.alert;

    // ── EVIDENCE FIRST, SIDE EFFECT SECOND ────────────────────────────────
    //
    // The decision row is a LOCAL append and it goes to disk before anything
    // leaves this box. The previous order awaited an external notification and
    // then wrote the row — under a comment claiming the row already existed —
    // so every way that call can end badly took the evidence with it: a
    // notification channel that hangs until the gateway's 30s hook timeout
    // fires, a transport that throws past its own catch, an operator restarting
    // the gateway mid-alert, the process dying. In each case the block or the
    // detection HAPPENED and there is no record that it did. That inverts the
    // whole point: a security control's own log must not be contingent on an
    // unrelated network round trip succeeding.
    //
    // The row carries a stable `eventId`, so the delivery row appended after
    // the attempt below can be joined to it without either row having to
    // predict the other's outcome.
    const eventId = randomUUID();
    // #226: whether the decision row ACTUALLY LANDED. `auditLog` used to
    // swallow its failures and return void, so the code below could not tell an
    // append from a silent no-op and every downstream statement — the operator
    // alert, the delivery row, this function's own comments — asserted that
    // evidence existed. Now the boolean is carried, said out loud on stderr,
    // and attached to the alert as a bounded, secret-free fact.
    let decisionRowPersisted = true;
    if (decision.audit) {
      // AWAITED: the row that says what was decided must exist before the
      // decision is handed back, and its success or failure must be READ. The
      // write is a bounded local append wrapped in its own try/catch.
      decisionRowPersisted = await auditLog({
        type: decision.outcome === 'unavailable' ? 'scan_unavailable' : 'threat',
        hook: 'before_agent_run',
        eventId,
        sessionId,
        model,
        // The REDACTED reason. This row is appended to a file that syncs.
        reason: safeReason,
        posture,
        outcome: decision.outcome,
        // #235: the origin, on every conversation decision row. Without it an
        // operator auditing an `enforce` host cannot tell a turn that was not
        // blocked because it was clean from one that was not blocked because
        // the owner sent it — and "why did this not block?" is the question
        // this row exists to answer. A label ('owner'/'non-owner'/'unknown'),
        // never a sender id: the row syncs.
        origin: trust.origin,
        // The verdict summary, never the prompt. The input that trips an
        // injection detector is hostile text by assumption; copying it into an
        // audit row that syncs to the dashboard/cloud would carry the payload
        // one hop further. A length + digest keeps rows correlatable without
        // storing the content.
        verdict: scan.summary,
        chars: text.length,
        contentSha256: createHash('sha256').update(text).digest('hex').slice(0, 16),
        // Deliberately NOT `notified: false`. Nothing has been attempted yet,
        // and a false here would read as "we tried and failed". The attempt's
        // result is its own row, keyed by this eventId.
        notifyPending: decision.notify && !suppressAlert,
        // #226: the unavailability run-length, on EVERY occurrence. Alerting is
        // rate limited; auditing is not, so the row is where the true count
        // lives — and it says explicitly when an alert was withheld, so a gap in
        // the alert stream can never be mistaken for a gap in the failures.
        ...(alertGate
          ? {
            unavailableCount: alertGate.count,
            alertSuppressed: suppressAlert,
            alertSuppressedSinceLastAlert: alertGate.suppressedSinceLastAlert,
          }
          : {}),
        ts: new Date().toISOString(),
      });
      if (!decisionRowPersisted) {
        console.error(
          `[shieldcortex] ⚠️ conversation ${decision.outcome} decision could NOT be written to the audit log — ` +
          'the decision itself still stands, but there is no local record of it. Check the audit directory ' +
          '(SHIELDCORTEX_AUDIT_DIR or ~/.shieldcortex/audit) for permissions or disk space.',
        );
      }
    }

    // The sink. Awaited — the first cut fired this off with `void` and threw
    // the delivery boolean away, so the code could not tell "a human was told"
    // from "nothing left this box". It is bounded (CONVERSATION_NOTIFY_MAX_MS,
    // well under the hook's own 30s timeout) and never throws.
    let notifyResult: NotifyOutcome | null = null;
    if (decision.notify) {
      const label = decision.outcome === 'unavailable' ? 'unavailable' : decision.block ? 'blocked' : 'observed';
      // The same redacted string the row got. A gateway's stdout is routinely
      // shipped to a log aggregator, so "ephemeral" is not a property the
      // console actually has either.
      console.warn(
        `[shieldcortex] ⚠️ ${safeReason ?? 'conversation threat'} — posture=${posture}, outcome=${label}` +
        (suppressAlert
          ? ` (operator alert SUPPRESSED — ${alertGate?.suppressedSinceLastAlert} since the last one; ${alertGate?.count} this session)`
          : ''),
      );
      // Audited above, not alerted. Nothing further is written for a suppressed
      // occurrence: no attempt was made, and a delivery row saying
      // `delivered: false` would read as a transport failure that never
      // happened. The decision itself is unaffected — suppression governs who
      // is TOLD, never what is DECIDED.
      if (!suppressAlert) {
        // The audit-persistence fact rides ALONG with the alert when the local
        // record failed: bounded, no secrets, and it tells the operator that
        // this notification is the only trace of the event. Appended to the
        // reason rather than added as a field so it survives an older installed
        // dist whose notification builder does not know about it.
        const auditNote = decisionRowPersisted ? '' : ' [auditPersistence=failed: no local audit row for this event]';
        const suppressedNote =
          alertGate && alertGate.suppressedSinceLastAlert > 0
            ? ` [${alertGate.suppressedSinceLastAlert} further scan-unavailable event(s) suppressed since the last alert; ${alertGate.count} this session]`
            : '';
        notifyResult = await notifyOperatorOfConversationThreat({
          outcome: label,
          posture,
          summary: scan.summary,
          // REDACTED. This one leaves the box entirely — to a webhook, an
          // aggregator, a phone — so it is the last place a tokenised endpoint
          // URL lifted out of a scanner error may appear.
          reason: `${safeReason ?? 'conversation threat'}${suppressedNote}${auditNote}`,
          sessionId,
          model,
        });
        // Truthful reporting: never imply a human was reached unless a
        // transport said so. "Not configured" is not a failure — it is the #143
        // default.
        if (notifyResult.configured && !notifyResult.delivered) {
          // #226: redacted HERE too, not only on the row below. The same detail
          // string reaches both, and a gateway's stdout is routinely shipped
          // somewhere it outlives the process.
          console.warn(`[shieldcortex] ⚠️ conversation alert UNDELIVERED — ${redactNotifyDetail(notifyResult.detail)}`);
        }
        // Guarded on `audit` because `eventId` has to point at something:
        // `evaluateConversationRun` never sets notify without audit, and if that
        // ever changed, a delivery row keyed to a decision row that was never
        // written would be a dangling reference rather than evidence.
        if (decision.audit) {
          // A SECOND row, not a rewrite of the first. The audit sink is an
          // append-only JSONL file, so "what was decided" and "who was told" are
          // separate facts recorded when each became true, joined by eventId.
          // `via` is the channel NAME ('webhook', 'openclaw-gateway'), never a
          // URL; the detail is redacted before it is persisted.
          await auditLog({
            type: 'notification_delivery',
            hook: 'before_agent_run',
            eventId,
            sessionId,
            configured: notifyResult.configured,
            delivered: notifyResult.delivered,
            via: notifyResult.via,
            detail: redactNotifyDetail(notifyResult.detail),
            // The eventId this row joins on may point at a row that was never
            // written. Say so here rather than leave a dangling reference that
            // reads as a missing file rather than a failed write.
            ...(decisionRowPersisted ? {} : { auditPersistence: 'failed' }),
            ts: new Date().toISOString(),
          });
        }
      }
    }

    // Clean, observed-not-blocked, and scan-unavailable all land here. The
    // audit row and the operator alert above have already recorded what
    // happened; the run itself proceeds, and says so.
    if (!decision.block) return gatePass();
    return {
      outcome: 'block',
      // Redacted for the same reason as the row above: the host SDK documents
      // `reason` as internal, but "internal" is a policy, not a guarantee.
      reason: safeReason ?? 'conversation threat',
      message: `ShieldCortex blocked this turn: ${scan.summary}. The prompt was not sent to the model.`,
      category: 'prompt_injection',
    };
  } catch (e) {
    // Fail open, loudly. Never let the guard's own failure stop the agent.
    //
    // This catch is also why the handler must not be allowed to THROW: the host
    // registers `before_agent_run` as fail-CLOSED
    // (`failurePolicyByHook: { before_agent_run: 'fail-closed' }`), so an
    // exception escaping here does not fail open at all — the gateway catches it
    // and blocks the run with "before_agent_run hook failed". An explicit pass
    // is the only way this function actually keeps its fail-open promise.
    console.error('[shieldcortex] before_agent_run error (failing open):', e instanceof Error ? e.message : String(e));
    return gatePass();
  }
}

// Skip text blocks that are ShieldCortex/OpenClaw tool-result pass-throughs
function isToolResultContent(text: string): boolean {
  // ShieldCortex recall returns "Found N memories:" header
  if (/^Found \d+ memor(?:y|ies):/m.test(text)) return true;
  // ShieldCortex get_context returns structured context blocks
  if (/^## (?:Architecture|Patterns|Preferences|Errors|Context)/m.test(text)) return true;
  // OpenClaw tool-result wrapper markers
  if (/^\[tool_result\b/i.test(text.trim())) return true;
  if (/^<tool_result\b/i.test(text.trim())) return true;
  return false;
}

function handleLlmOutput(event: LlmOutputEvent, ctx: AgentCtx): void {
  // Fire and forget
  (async () => {
    try {
      const config = await loadConfig();
      if (!isAutoMemoryEnabled(config)) return;

      const texts = event.assistantTexts
        .filter(t => t && t.length >= 30)
        .filter(t => !isToolResultContent(t));
      if (!texts.length) return;
      const memories = extractMemories(texts);
      if (!memories.length) return;

      const noveltyGate = await createNoveltyGate(config);
      let saved = 0;
      let skipped = 0;
      for (const mem of memories) {
        const novelty = noveltyGate.inspect(mem.content);
        if (!novelty.allow) {
          skipped++;
          continue;
        }

        const r = await callCortex("remember", {
          title: mem.title, content: mem.content, category: mem.category,
          project: ctx.agentId || "openclaw", scope: "global",
          importance: "normal", tags: "auto-extracted,realtime-plugin,llm-output",
          sourceType: "agent", sourceIdentifier: `openclaw-plugin:${event.sessionId}`,
          sessionId: event.sessionId, agentId: ctx.agentId || "openclaw", workspaceDir: ctx.workspaceDir || "",
        });
        if (r) {
          saved++;
          noveltyGate.remember(mem, novelty);
        }
      }
      await noveltyGate.flush();
      if (saved) {
        console.log(`[shieldcortex] Extracted ${saved} memor${saved === 1 ? "y" : "ies"} from LLM output (${skipped} duplicates skipped)`);
        auditLog({ type: "memory", hook: "llm_output", sessionId: event.sessionId, count: saved, skipped, ts: new Date().toISOString() });
      }
    } catch (e) {
      console.error("[shieldcortex] llm_output error:", e instanceof Error ? e.message : String(e));
    }
  })();
}

class TypedApprovalRequest extends Error {
  request: NonNullable<TypedBeforeToolCallResult["requireApproval"]>;

  constructor(message: string, request: NonNullable<TypedBeforeToolCallResult["requireApproval"]>) {
    super(message);
    this.name = "TypedApprovalRequest";
    this.request = request;
  }
}

function truncateApprovalText(text: string, maxLength: number): string {
  const normalized = text.replace(/\s+/g, " ").trim();
  if (normalized.length <= maxLength) return normalized;
  return `${normalized.slice(0, Math.max(0, maxLength - 1)).trimEnd()}…`;
}

function buildTypedApprovalRequest(message: string): NonNullable<TypedBeforeToolCallResult["requireApproval"]> {
  const lines = message
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter(Boolean)
    .filter((line) => !/^\[(?:Approve|Deny)\]/i.test(line));
  const rawTitle = (lines[0] || "ShieldCortex approval required").replace(/^🛡️\s*/u, "");
  const details = lines.slice(1).join(" | ") || rawTitle;
  const riskText = message.toLowerCase();
  const severity = /\b(?:critical|catastrophic|auto[-_\s]?deny|exfil|rm\s+-rf)\b/u.test(riskText)
    ? "critical"
    : /\b(?:high|dangerous|sensitive|risk|intercepted)\b/u.test(riskText)
      ? "warning"
      : "info";

  return {
    title: truncateApprovalText(rawTitle, 80),
    description: truncateApprovalText(details, 256),
    severity,
    timeoutMs: 120_000,
    timeoutBehavior: "deny",
    allowedDecisions: ["allow-once", "deny"],
  };
}

async function handleTypedBeforeToolCall(
  event: TypedBeforeToolCallEvent,
  interceptor: ReturnType<typeof createInterceptor>,
  logger: PluginApi["logger"],
  sessionId?: string,
): Promise<TypedBeforeToolCallResult | void> {
  try {
    await interceptor.handleToolCall({
      toolName: event.toolName,
      arguments: event.params ?? {},
      sessionId,
      requireApproval: async (message: string) => {
        throw new TypedApprovalRequest(message, buildTypedApprovalRequest(message));
      },
    });
  } catch (err) {
    if (err instanceof TypedApprovalRequest) {
      return { requireApproval: err.request };
    }

    if (err instanceof Error && err.message.startsWith("ShieldCortex:")) {
      return { block: true, blockReason: err.message };
    }

    (logger as any)?.warn?.(`[shieldcortex] before_tool_call error (allowing tool call): ${err instanceof Error ? err.message : err}`);
  }
}

// ==================== PLUGIN EXPORT ====================

/**
 * Assemble the approval broker (#143) from the main package, or return
 * undefined.
 *
 * Undefined is the normal answer and a safe one: no broker means the guard
 * behaves exactly as it did before #143 — every dangerous-tier call goes to the
 * operator. It is returned whenever the broker is not switched on, and whenever
 * the installed `shieldcortex` build is older than the broker (a version skew
 * this plugin has to survive, which is why every piece is looked up by name
 * rather than imported).
 *
 * All four pieces are required together. A half-wired broker — a decision core
 * with no config normaliser, say — would be a policy consuming unvalidated
 * input, which is the one shape this feature must never take.
 */
function resolveBrokerRuntime(
  defenceMod: any,
  rawBrokerConfig: Record<string, unknown> | undefined,
  api: PluginApi,
): BrokerRuntime | undefined {
  try {
    const needed = ['normaliseBrokerConfig', 'brokerDecision', 'runJudge', 'timeoutOutcome'];
    if (needed.some((fn) => typeof defenceMod?.[fn] !== 'function')) {
      if (rawBrokerConfig?.enabled === true) {
        (api.logger as any)?.warn?.('[shieldcortex] approval broker requested but this shieldcortex build does not provide it — every dangerous action still goes to you');
      }
      return undefined;
    }
    const config = defenceMod.normaliseBrokerConfig(rawBrokerConfig);
    if (!config?.enabled) return undefined;

    api.logger?.info?.(
      `[shieldcortex] approval broker ON — judge via the gateway model pool${config.model ? ` (${config.model})` : ''}, pre-clear ${config.allowPreClear ? `at ≥${config.preClearConfidence}` : 'disabled'}`,
    );
    return {
      config,
      runJudge: defenceMod.runJudge,
      // #143 residual, and deliberately NOT in `needed`: an older shieldcortex
      // build has runJudge alone, and the interceptor falls back to it. Missing
      // it costs an audit field, never a gate.
      runJudgeDetailed:
        typeof defenceMod.runJudgeDetailed === 'function' ? defenceMod.runJudgeDetailed : undefined,
      brokerDecision: defenceMod.brokerDecision,
      timeoutOutcome: defenceMod.timeoutOutcome,
      approvalTimeoutMs: typeof defenceMod.approvalTimeoutMs === 'function' ? defenceMod.approvalTimeoutMs : undefined,
    } as BrokerRuntime;
  } catch (err) {
    (api.logger as any)?.warn?.(`[shieldcortex] approval broker unavailable: ${err instanceof Error ? err.message : err} — holding every dangerous action for you`);
    return undefined;
  }
}

export const __testables = { resolveBrokerRuntime };

export default {
  id: PLUGIN_ID,
  name: "ShieldCortex Real-time Scanner",
  description: "Real-time defence scanning on LLM inputs with optional memory extraction from outputs",
  version: _version,
  configSchema: {
    parse(value: unknown) {
      return normaliseConfig(value);
    },
    uiHints: PLUGIN_CONFIG_UI_HINTS,
    jsonSchema: PLUGIN_CONFIG_JSON_SCHEMA,
  },


  register(api: PluginApi) {
    if (_registered) return;
    _registered = true;

    // #226: the host runtime's own version, before anything can throw. It is
    // the primary version evidence for the conversation-gate check — the
    // gateway stating its own version beats inferring one from whichever
    // package.json sits above the entry path. Absent on a host that does not
    // expose it, which stays UNKNOWN rather than becoming a guess.
    recordHostRuntimeVersion(api);

    // --- Interceptor (lazy init) ---
    let interceptorReady: ReturnType<typeof createInterceptor> | null = null;
    let interceptorInitAttempted = false;

    // #134 §2: registered UNCONDITIONALLY, before the try block below that can
    // throw. Previously this command lived inside that try, so a plugin crash
    // meant the operator had no /shieldcortex-status to run at all — the one
    // place they'd look reported nothing, same as it not existing. Now it
    // always exists, and honestly reports DEGRADED when init failed instead of
    // rendering config-derived lines that describe a state the plugin never
    // reached.
    try {
      api.registerCommand({
        name: "shieldcortex-status",
        description: "Show ShieldCortex real-time scanner status",
        async handler() {
          if (_registrationError) {
            return {
              text:
                `ShieldCortex v${_version}\n` +
                `  STATUS: DEGRADED — plugin failed to initialize: ${_registrationError}\n` +
                `  Real-time scanning, memory capture and the Action Guard before_tool_call\n` +
                `  hook are ALL INACTIVE. Channels started normally (fail-open by design —\n` +
                `  a broken security plugin must never block the gateway), but this plugin\n` +
                `  is doing nothing until the underlying error is fixed and the gateway is\n` +
                `  restarted.`,
            };
          }
          const cfg = await loadConfig();
          const autoMemory = isAutoMemoryEnabled(cfg) ? "on" : "off";
          const dedupe = isAutoMemoryDedupeEnabled(cfg) ? "on" : "off";
          const cloud = cfg.cloudApiKey ? "configured" : "not configured";
          // Resolve the Action Guard state the same way initInterceptor() does,
          // so the status line reflects what before_tool_call will actually do.
          const rawInterceptor = cfg.interceptor;
          const guardCfg = {
            ...(DEFAULT_INTERCEPTOR_CONFIG.actionGuard ?? { enabled: true, enforce: true, autoApprove: [] }),
            ...(rawInterceptor && typeof rawInterceptor === 'object' ? rawInterceptor.actionGuard ?? {} : {}),
          };
          const interceptorOn = (rawInterceptor && typeof rawInterceptor === 'object' ? rawInterceptor.enabled : undefined) ?? DEFAULT_INTERCEPTOR_CONFIG.enabled;
          const autoApproved = Array.isArray(guardCfg.autoApprove) ? guardCfg.autoApprove.length : 0;
          const guardState = !_beforeToolCallRegistered
            ? "off (before_tool_call not registered — interceptor disabled in plugin config)"
            : !interceptorOn || !guardCfg.enabled
              ? "off"
              : `${guardCfg.enforce ? "enforce" : "warn"}${autoApproved > 0 ? ` (${autoApproved} auto-approved)` : ""}${interceptorReady ? "" : " — not yet initialised this session"}`;
          const hooksLine = _beforeToolCallRegistered
            ? "llm_input (scan), llm_output (memory), before_tool_call (action guard), session_end (cache reset)"
            // #226: session_end is registered even with the interceptor off —
            // the conversation gate keeps per-session state that needs freeing.
            : "llm_input (scan), llm_output (memory), session_end (cache reset)";
          // #225: the conversation plane, stated as evidence rather than as a
          // tick. Every clause below is something this process actually knows:
          // the configured posture, that we asked for the hook, the host build,
          // and the operator's grant. Nothing here claims the gateway accepted
          // the registration, because the plugin API never says so.
          const hostProbe = detectHostOpenClaw();
          const plane = describeConversationPlane({
            posture: conversationPosture(cfg.interceptor?.conversation),
            hookRequested: _beforeAgentRunRequested,
            gateSupport: hostSupportsConversationGate(hostProbe),
            hostOpenClawVersion: hostProbe.version,
            consentGranted: _conversationAccessGranted,
          });
          const notifyRaw = cfg.interceptor?.actionGuard?.notify;
          const notifyState = notifyRaw && (notifyRaw as { enabled?: unknown }).enabled === true
            ? 'configured'
            : 'not configured — detections reach the audit log and this box only';
          return {
            text:
              `ShieldCortex v${_version}\n` +
              `  Hooks: ${hooksLine}${_beforeAgentRunRequested ? ', before_agent_run (conversation gate, requested)' : ''}\n` +
              `  Action guard: ${guardState}\n` +
              `  Conversation firewall: ${plane.summary}\n` +
              // #226: state the PROVENANCE, not just the value. This flag is a
              // SNAPSHOT taken once, when the plugin loaded — the host reads
              // the grant at hook-registration time and this process never
              // re-reads it. So an operator who has just edited openclaw.json
              // and re-run the command sees the old answer, correctly, and
              // would otherwise conclude the grant does not work. Nothing here
              // is live: changing it requires a gateway restart before either
              // the gateway or this line reflects it.
              `  Conversation access grant: ${_conversationAccessGranted ? 'granted' : 'NOT granted'} (plugins.entries.${PLUGIN_ID}.hooks.allowConversationAccess)\n` +
              '    — read from openclaw.json when this plugin LOADED; it is a snapshot, not a live read.\n' +
              '      Editing that key takes effect only after a gateway restart, for the gateway and for this line.\n' +
              `  Operator notify: ${notifyState}\n` +
              `  Auto memory: ${autoMemory} | Dedupe: ${dedupe}\n` +
              `  Cloud sync: ${cloud}`,
          };
        },
      });
    } catch {
      // Host doesn't support registerCommand at all — nothing more to do here;
      // the try/catch below still logs the substantive init failure loudly.
    }

    try {
    applyPluginConfigOverride(api);

    async function initInterceptor(): Promise<ReturnType<typeof createInterceptor> | null> {
      if (interceptorInitAttempted) return interceptorReady;
      interceptorInitAttempted = true;

      try {
        const scConfig = await loadConfig();
        // Normalised user config (deep-partial); DEFAULT_INTERCEPTOR_CONFIG
        // fills the gaps below — defaults never override explicit values.
        const rawInterceptorConfig = scConfig.interceptor;
        const interceptorConfig: InterceptorConfig = {
          ...DEFAULT_INTERCEPTOR_CONFIG,
          ...(rawInterceptorConfig && typeof rawInterceptorConfig === 'object' ? {
            enabled: rawInterceptorConfig.enabled ?? DEFAULT_INTERCEPTOR_CONFIG.enabled,
            severityActions: { ...DEFAULT_INTERCEPTOR_CONFIG.severityActions, ...rawInterceptorConfig.severityActions },
            failurePolicy: { ...DEFAULT_INTERCEPTOR_CONFIG.failurePolicy, ...rawInterceptorConfig.failurePolicy },
            actionGuard: { ...(DEFAULT_INTERCEPTOR_CONFIG.actionGuard ?? { enabled: true, enforce: true, autoApprove: [] }), ...(rawInterceptorConfig.actionGuard ?? {}) },
          } : {}),
          logger: { info: api.logger?.info ?? console.log, warn: (api.logger as any)?.warn ?? console.warn },
        };

        if (!interceptorConfig.enabled) return null;

        // Shared in-process defence module (same instance realtime scanning
        // uses — see getDefenceModule). Loaded via a string-concatenated
        // specifier so TypeScript doesn't resolve 'shieldcortex/defence' at
        // compile time; it only exists at runtime once the package is installed.
        const defenceMod = await getDefenceModule();
        if (!defenceMod) {
          (api.logger as any)?.warn?.('[shieldcortex] Cannot load defence module — interceptor disabled');
          return null;
        }
        if (typeof defenceMod.runDefencePipeline !== 'function') return null;

        interceptorReady = createInterceptor(interceptorConfig, defenceMod.runDefencePipeline as Parameters<typeof createInterceptor>[1], {
          evaluateToolCall: typeof (defenceMod as any).evaluateToolCall === 'function'
            ? ((defenceMod as any).evaluateToolCall as Parameters<typeof createInterceptor>[2] extends { evaluateToolCall?: infer E } ? E : never)
            : undefined,
          broker: resolveBrokerRuntime(defenceMod, interceptorConfig.actionGuard?.broker, api),
          // #233: the read side of conversation taint. Returns null for a clean
          // or unknown session, so the guard behaves exactly as before unless a
          // conversation detection actually happened in THIS session.
          sessionTaint: (sessionId) => {
            const rec = sessionId ? sessionTaint.get(sessionId) : null;
            return rec ? { reason: rec.reason } : null;
          },
          // #227: session action lease — the fs-backed shared implementation,
          // injected through the same runtime seam as evaluateToolCall. Older
          // installed packages without the export simply leave the option
          // undefined (no lease plane — the capability-honesty surface says so).
          checkActionLease: typeof (defenceMod as any).evaluateToolCallLease === 'function'
            ? (toolName, args, sessionId) =>
                (defenceMod as any).evaluateToolCallLease(toolName, args, { self: sessionId ?? '' })
            : undefined,
          releaseActionLease: typeof (defenceMod as any).releaseToolCallLease === 'function'
            ? (toolName, args, sessionId) =>
                (defenceMod as any).releaseToolCallLease(toolName, args, { self: sessionId ?? '' })
            : undefined,
          // #260: the session-guard index. Same formula as the Claude Code
          // hook. Absent on an older dist — then emitAudit still stamps origin
          // but does not write an index nobody would summarise.
          sessionGuard: typeof defenceMod.sessionKeyFor === 'function' && typeof defenceMod.appendSessionGuardIndex === 'function'
            ? {
                keyFor: (sessionId) => defenceMod.sessionKeyFor!(sessionId),
                index: (entry) => {
                  defenceMod.appendSessionGuardIndex!({ entry: { ...entry } as Record<string, unknown> });
                },
              }
            : undefined,
          onAuditEntry: (entry) => syncInterceptEvent(entry, {
            cloudApiKey: (scConfig as any).cloudApiKey ?? '',
            cloudBaseUrl: (scConfig as any).cloudBaseUrl ?? 'https://api.shieldcortex.ai',
            cloudEnabled: (scConfig as any).cloudEnabled ?? false,
          }),
          bindAudit: typeof (defenceMod as any).attachEnforcementBinding === 'function'
            ? (entry, args) => (defenceMod as any).attachEnforcementBinding(entry, {
                plane: 'action_guard',
                hookName: 'before_tool_call',
                pluginId: 'shieldcortex-realtime',
                tool: entry.tool,
                args: args ?? {},
              }) as typeof entry
            : undefined,
        });
        const guardState = interceptorConfig.actionGuard?.enabled
          ? (interceptorConfig.actionGuard.enforce ? 'Action Guard: enforce' : 'Action Guard: warn')
          : 'Action Guard: off';
        api.logger?.info?.(`[shieldcortex] Interceptor active — memory writes + ${guardState} (shell/file/network/git)`);
        return interceptorReady;
      } catch (err) {
        (api.logger as any)?.warn?.(`[shieldcortex] Interceptor init failed: ${err instanceof Error ? err.message : err}`);
        return null;
      }
    }

    // #112 follow-up: when the host config (openclaw.json plugin entry)
    // explicitly disables the interceptor, do NOT register before_tool_call at
    // all. A registered-but-no-op hook still appears in the host's hook roster
    // and changes how OpenClaw resolves tool-call approvals for unattended
    // Codex agents (plugin.approval.waitDecision waits on a decision no one
    // can give, times out after 120s, and the turn emits no reply). Absent
    // hook = the host's native approval path is untouched.
    //
    // Only the synchronously-available plugin config can gate registration
    // (the shield config file loads async via the runtime); a shield-file-only
    // `enabled:false` keeps the lazy no-op behaviour, which returns
    // immediately and never requests approval — covered by regression tests.
    // Note: re-enabling the interceptor from openclaw.json requires a gateway
    // restart, since registration happens once at plugin load.
    const interceptorDisabledInHostConfig = _configOverride?.interceptor?.enabled === false;

    if (!interceptorDisabledInHostConfig) {
      // Typed before_tool_call hook: this is the OpenClaw agent-loop gate that
      // can block or require approval before the selected tool executes.
      api.on('before_tool_call', async (event: TypedBeforeToolCallEvent, ctx?: { sessionId?: string }) => {
        const interceptor = await initInterceptor();
        if (!interceptor) return;
        // #233: the host supplies the session on the tool CONTEXT, not the
        // event. Without it a taint cannot be matched to the call it should
        // gate, so the escalation would silently never fire.
        return handleTypedBeforeToolCall(event, interceptor, api.logger, ctx?.sessionId);
      }, { priority: 80, timeoutMs: 30_000 });
      _beforeToolCallRegistered = true;
      // NOTE: session_end is NOT registered here — it moved out of this guard
      // in #226 and is registered unconditionally below.
    } else {
      api.logger?.info?.('[shieldcortex] interceptor.enabled:false in plugin config — before_tool_call hook not registered');
    }

    // session_end — registered UNCONDITIONALLY (#226).
    //
    // It used to live inside the `interceptorDisabledInHostConfig` guard above,
    // on the reasoning that it exists for the interceptor's session cache. That
    // stopped being true when `before_agent_run` landed: the gate is registered
    // regardless of `interceptor.enabled` (its posture, not the interceptor
    // flag, decides what it does), and it accumulates per-session
    // scan-unavailable suppression state. With the cleanup hook skipped, a host
    // that disabled the interceptor kept every session's window alive for the
    // life of the gateway process.
    //
    // Registering it does NOT reintroduce #112. That incident was specific to
    // `before_tool_call`: a registered approval hook changes how OpenClaw
    // resolves tool-call approvals for unattended Codex agents, so an
    // unattended turn waited 120s on a decision nobody could give. `session_end`
    // is a notification — it cannot block, approve, or delay anything. It frees
    // local state and, since #260, best-effort summarises a degraded Action
    // Guard session. That write is not a decision and cannot stall the host.
    try {
      api.on('session_end', (event?: { sessionId?: string; sessionKey?: string }, ctx?: AgentCtx) => {
        interceptorReady?.resetSession();
        const endedSession = ctx?.sessionId ?? ctx?.sessionKey ?? event?.sessionId ?? event?.sessionKey ?? null;
        // #226: the scan-unavailable alert window is session state too, and it
        // is keyed per session — so clear THIS session's window and nobody
        // else's. Clearing them all would re-arm alerting for every live
        // session every time any one of them ended.
        resetScanUnavailableAlertState(endedSession);
        // #233: a taint must not outlive the conversation that earned it. Same
        // per-session rule, for the same reason.
        if (endedSession) sessionTaint.clear(endedSession);
        // #260: plane-native summariser. session_end cannot block (#112) —
        // this is a notification hook. The write is best-effort and
        // idempotent with agent_end below.
        summariseGuardSession(endedSession, 'openclaw-session-end');
      });
    } catch {
      // session_end may not be a supported hook — TTL safety net handles this
    }

    // #260: agent_end exists on the engine floor (2026.5.7 already declared
    // it). An unknown typed hook is warn-and-return, not a throw, so we still
    // wrap registration. Same summariser as session_end — whichever fires
    // first writes, the other is a no-op. Do not invent a third sink.
    try {
      api.on('agent_end', (event?: { sessionId?: string; sessionKey?: string }, ctx?: AgentCtx) => {
        const endedSession = ctx?.sessionId ?? ctx?.sessionKey ?? event?.sessionId ?? event?.sessionKey ?? null;
        summariseGuardSession(endedSession, 'openclaw-session-end');
      });
    } catch {
      // Host predates agent_end — session_end is the load-bearing summariser.
    }

    // llm_input/llm_output are CONVERSATION hooks: OpenClaw drops them at
    // registration for a non-bundled plugin unless the host grants
    // plugins.entries.<id>.hooks.allowConversationAccess = true. Registration is
    // still attempted (the host decides, and the grant can be added without a
    // code change), but they must not be CLAIMED afterwards — see the startup
    // line below (#225/#230).
    api.on("llm_input", handleLlmInput, { timeoutMs: 30_000 });
    api.on("llm_output", handleLlmOutput, { timeoutMs: 30_000 });

    // #225: the conversation firewall's ENFORCEMENT point. `llm_input` above is
    // an OpenClaw *observation* hook — it cannot stop anything, which is why a
    // detected injection reached the model regardless and the only trace was a
    // console line. `before_agent_run` is the documented hook that can block a
    // run, so the verdict lands here where it can actually act.
    //
    // Registration is attempted unconditionally: the posture
    // (off/observe/enforce) decides what happens, and it is read per-call so a
    // config change takes effect without a restart. Registering conditionally
    // would make "is the guard wired?" depend on config read at boot — the
    // exact class of silent gap that #214/#222 were.
    //
    // The try/catch is for a host whose `api.on` throws on an unknown name. On
    // the hosts we have inspected it does NOT throw — an unsupported name is
    // dropped with a diagnostic, and a conversation hook without the operator's
    // grant is refused the same way — so a successful call proves only that we
    // ASKED. That is exactly what the flag is named after, and the honest
    // reporting comes from the version + consent evidence below.
    try {
      api.on("before_agent_run", handleBeforeAgentRun, { timeoutMs: 30_000 });
      _beforeAgentRunRequested = true;
    } catch (err) {
      _beforeAgentRunRequested = false;
      (api.logger as any)?.warn?.(
        `[shieldcortex] before_agent_run could not be registered on this host (${err instanceof Error ? err.message : String(err)}) — the conversation firewall cannot block on this gateway`,
      );
    }

    // The gateway's own message seam, WHERE a host provides one (#143's design
    // intent: "on OpenClaw the transport should use the gateway's own message
    // capability"). Probed structurally, never required. No build we have
    // inspected exposes it — `notifyOperator` appears nowhere in the plugin API
    // of 2026.5.2 or 2026.7.1 — so on today's hosts this stays null and
    // conversation alerts go to the webhook.
    const notifyCtx = (api as { runtime?: { notifyOperator?: unknown }; notifyOperator?: unknown });
    if (typeof notifyCtx.notifyOperator === 'function') {
      _gatewayNotifyContext = notifyCtx as GatewayNotifyContext;
    } else if (typeof notifyCtx.runtime?.notifyOperator === 'function') {
      _gatewayNotifyContext = notifyCtx.runtime as GatewayNotifyContext;
    }

    // The operator's conversation-access grant. Read, never written: OpenClaw
    // refuses every conversation hook for a non-bundled plugin without it, so a
    // box missing it runs with NO conversation plane at all — and on four of
    // five fleet hosts surveyed in #222 that was the normal outcome of a
    // documented install. Report it at boot rather than let the operator infer
    // protection from a registration line that only states intent.
    // The host's own in-memory config is the better source (it is what the
    // loader consulted), so it is preferred; the file the host reads is the
    // fallback for a runtime that does not expose it. `readConversationAccess`
    // is #225's shared reader — it also tells us whether the config could be
    // read at all, which is what keeps "not granted" apart from "cannot tell"
    // on the startup line below.
    const diskAccess = readConversationAccess(homedir(), PLUGIN_ID);
    let rootConfigSeen = false;
    try {
      const runtimeConfigApi = (api as PluginApi).runtime?.config;
      const rootConfig = typeof runtimeConfigApi?.current === 'function'
        ? runtimeConfigApi.current()
        : typeof runtimeConfigApi?.loadConfig === 'function'
          ? runtimeConfigApi.loadConfig()
          : (api as PluginApi).config;
      rootConfigSeen = Boolean(rootConfig) && typeof rootConfig === 'object';
      _conversationAccessGranted = rootConfigSeen
        ? readConversationAccessGrant(rootConfig)
        : diskAccess.granted;
    } catch {
      _conversationAccessGranted = diskAccess.granted;
    }
    if (!_conversationAccessGranted) {
      (api.logger as any)?.warn?.(
        `[shieldcortex] conversation firewall INACTIVE: plugins.entries.${PLUGIN_ID}.hooks.allowConversationAccess is not true in openclaw.json — ` +
        'the gateway will refuse llm_input, llm_output and before_agent_run for this plugin. Nothing on the conversation path is scanned or blocked. ' +
        'This is an operator consent grant and ShieldCortex will never set it for you.',
      );
    }

    // #225/#230: this line used to announce `llm_input + llm_output`
    // unconditionally. On any host without the conversation-access grant the
    // gateway logged, on the very next two lines, that it had dropped both — so
    // ShieldCortex was claiming conversation protection it did not have, in the
    // one place an operator looks to confirm startup. Report only what is
    // actually live, and name the missing grant when it is the reason.
    //
    // `before_agent_run` (#226) is on the same list from 2026.5.9-beta.1, so it
    // is claimed only when the grant is present AND registration was attempted
    // this session.
    api.logger.info(
      `[shieldcortex] v${_version} registered (${describeRegisteredHooks({
        access: {
          granted: _conversationAccessGranted,
          // We could read SOMETHING (the host's config or the file) ⇒ the
          // ungranted state is a fact, not a failed measurement.
          readable: rootConfigSeen || diskAccess.readable,
          entryPresent: diskAccess.entryPresent,
        },
        beforeToolCallRegistered: _beforeToolCallRegistered,
        beforeAgentRunRequested: _beforeAgentRunRequested,
      })})`,
    );
    } catch (err) {
      // Plugin must never block channel startup — warn and bail gracefully.
      // #134 §2: this used to be a bare console.warn, which bypasses the
      // gateway's structured log entirely — real-time scanning, memory
      // capture and the Action Guard before_tool_call hook all go dark with
      // no [plugins] line anywhere an operator looks. Route through
      // api.logger.warn (the structured channel) and only fall back to
      // console.error — never console.warn, so a fallback line is visibly
      // distinct from a routed one — if the host doesn't even provide a
      // logger, which would itself be a broken host.
      const msg = err instanceof Error ? err.message : String(err);
      _registrationError = msg;
      const warn = (api.logger as any)?.warn;
      if (typeof warn === 'function') {
        warn.call(api.logger, `[shieldcortex] WARNING: Plugin failed to initialize: ${msg}`);
        warn.call(api.logger, '[shieldcortex] Real-time scanning is disabled. Channels will start normally.');
      } else {
        console.error(`[shieldcortex] WARNING: Plugin failed to initialize (no api.logger available): ${msg}`);
        console.error('[shieldcortex] Real-time scanning is disabled. Channels will start normally.');
      }
    }
  },
};
