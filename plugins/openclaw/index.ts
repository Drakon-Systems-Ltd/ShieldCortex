/**
 * ShieldCortex Real-time Scanning Plugin for OpenClaw v2026.3.22+
 *
 * Uses typed OpenClaw plugin hooks (`api.on`) for llm_input/llm_output
 * scanning and before_tool_call interception. `api.registerHook` registers
 * internal HOOK-style automation and does not participate in the agent-loop
 * block/approval semantics ShieldCortex needs.
 * All scanning operations are fire-and-forget.
 */

import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import { existsSync, readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import { homedir } from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";

import { createInterceptor, DEFAULT_CONFIG as DEFAULT_INTERCEPTOR_CONFIG } from './interceptor.js';
import type { InterceptorConfig, BrokerRuntime } from './interceptor.js';
import { syncInterceptEvent } from './intercept-ingest.js';
import { cloudSync } from './cloud-sync.js';

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

function collectRuntimeCandidates(): string[] {
  const candidates = new Set<string>();

  // 1. Relative path (works when running from within npm package tree)
  candidates.add(new URL("../../hooks/openclaw/cortex-memory/runtime.mjs", import.meta.url).href);

  // 2. Config file override (reads path from ~/.shieldcortex/config.json instead of env var)
  try {
    const cfgPath = path.join(homedir(), ".shieldcortex", "config.json");
    if (existsSync(cfgPath)) {
      const cfg = JSON.parse(readFileSync(cfgPath, "utf-8"));
      if (cfg.installRoot) addRuntimeCandidate(candidates, cfg.installRoot);
    }
  } catch { /* no config */ }

  // 3. Walk up from current file location
  addAncestorCandidates(candidates, path.dirname(fileURLToPath(import.meta.url)));

  // 4. Resolve via common bin symlink paths (no child_process needed)
  for (const binDir of ["/usr/local/bin", "/opt/homebrew/bin", path.join(homedir(), ".npm-global", "bin")]) {
    const binPath = path.join(binDir, "shieldcortex");
    try {
      if (existsSync(binPath)) addAncestorCandidates(candidates, realpathSync(binPath));
    } catch { /* broken symlink */ }
  }

  // 5. Common global install paths (covers npm root -g results without spawning npm)
  for (const root of [
    "/usr/lib/node_modules/shieldcortex",
    "/usr/local/lib/node_modules/shieldcortex",
    "/opt/homebrew/lib/node_modules/shieldcortex",
    path.join(homedir(), ".npm-global", "lib", "node_modules", "shieldcortex"),
    path.join(homedir(), ".nvm", "versions", "node"),  // nvm users
  ]) {
    if (root.includes(".nvm")) {
      // For nvm, check the current symlink
      try {
        const currentNode = path.join(homedir(), ".nvm", "current", "lib", "node_modules", "shieldcortex");
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
export function __setDefenceModuleForTest(mod: DefenceModule | null | undefined): void {
  _defenceModOverride = mod;
  _defenceModPromise = null;
}
export function __setRuntimeForTest(runtime: OpenClawRuntime | null): void {
  _runtimeOverride = runtime;
  if (runtime) runtimePromise = null;
}
export function __resetConfigStateForTest(): void {
  _config = null;
  _configOverride = null;
  _lastShieldConfigRef = null;
  _registered = false;
  _beforeToolCallRegistered = false;
}

type LlmInputEvent = {
  runId: string; sessionId: string; provider: string; model: string;
  systemPrompt?: string; prompt: string; historyMessages: unknown[]; imagesCount: number;
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
}

const PLUGIN_ID = "shieldcortex-realtime";
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

const INTERCEPTOR_JSON_SCHEMA = {
  type: "object",
  additionalProperties: false,
  properties: {
    enabled: { type: "boolean" },
    severityActions: SEVERITY_ACTION_SCHEMA,
    failurePolicy: FAILURE_POLICY_SCHEMA,
    actionGuard: {
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
      },
    },
  },
};

const PLUGIN_CONFIG_JSON_SCHEMA = {
  type: "object",
  additionalProperties: false,
  properties: {
    enabled: { type: "boolean" },
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

function normaliseConfig(raw: unknown): SCConfig {
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
  const interceptor = normaliseInterceptorConfig(value.interceptor);
  if (interceptor) config.interceptor = interceptor;

  return config;
}

function normaliseSeverityMap<A extends string>(
  raw: unknown,
  allowed: readonly A[],
): Partial<Record<InterceptSeverity, A>> | undefined {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const value = raw as Record<string, unknown>;
  const out: Partial<Record<InterceptSeverity, A>> = {};
  for (const severity of INTERCEPT_SEVERITIES) {
    const entry = value[severity];
    if (typeof entry === "string" && (allowed as readonly string[]).includes(entry)) {
      out[severity] = entry as A;
    }
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

function normaliseInterceptorConfig(raw: unknown): InterceptorUserConfig | undefined {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const value = raw as Record<string, unknown>;
  const out: InterceptorUserConfig = {};

  if (typeof value.enabled === "boolean") out.enabled = value.enabled;

  const severityActions = normaliseSeverityMap(value.severityActions, INTERCEPT_ACTIONS);
  if (severityActions) out.severityActions = severityActions;

  const failurePolicy = normaliseSeverityMap(value.failurePolicy, FAILURE_ACTIONS);
  if (failurePolicy) out.failurePolicy = failurePolicy;

  if (value.actionGuard && typeof value.actionGuard === "object" && !Array.isArray(value.actionGuard)) {
    const rawGuard = value.actionGuard as Record<string, unknown>;
    const guard: NonNullable<InterceptorUserConfig["actionGuard"]> = {};
    if (typeof rawGuard.enabled === "boolean") guard.enabled = rawGuard.enabled;
    if (typeof rawGuard.enforce === "boolean") guard.enforce = rawGuard.enforce;
    if (typeof rawGuard.auditAllows === "boolean") guard.auditAllows = rawGuard.auditAllows;
    if (Array.isArray(rawGuard.autoApprove) && rawGuard.autoApprove.every((entry) => typeof entry === "string")) {
      guard.autoApprove = rawGuard.autoApprove as string[];
    }
    // Carried through untouched — normaliseBrokerConfig is the boundary, and
    // splitting that job across two files is how one of the halves ends up
    // being the lenient one.
    if (rawGuard.broker && typeof rawGuard.broker === "object" && !Array.isArray(rawGuard.broker)) {
      guard.broker = rawGuard.broker as Record<string, unknown>;
    }
    if (Object.keys(guard).length > 0) out.actionGuard = guard;
  }

  return out;
}

/**
 * Merge two normalised configs (#112). Semantics:
 *  - Top-level scalar keys: override wins when present.
 *  - `interceptor` deep-merges PER KEY — per severity entry, per guard flag —
 *    so an override that sets one nested key does not wholesale-discard the
 *    base's other interceptor settings.
 *  - Explicit values, including `false`, always win over base values; absent
 *    keys fall through to the base.
 *  - Defaults are NOT applied here: DEFAULT_INTERCEPTOR_CONFIG only fills the
 *    remaining gaps in initInterceptor(), so it can never override an explicit
 *    user value.
 */
function mergeConfigs(base: SCConfig, override: SCConfig): SCConfig {
  const merged: SCConfig = { ...base, ...override };
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
      merged.interceptor.actionGuard = { ...b.actionGuard, ...o.actionGuard };
    }
  }
  return merged;
}

function extractPluginConfig(rootConfig: unknown): SCConfig {
  if (!rootConfig || typeof rootConfig !== "object" || Array.isArray(rootConfig)) return {};
  const entries = (rootConfig as {
    plugins?: {
      entries?: Record<string, { config?: unknown } | undefined>;
    };
  }).plugins?.entries;

  const pluginConfig =
    entries?.[PLUGIN_ID]?.config ??
    entries?.[PLUGIN_PACKAGE_NAME]?.config;

  return normaliseConfig(pluginConfig);
}

function applyPluginConfigOverride(api: PluginApi): void {
  const runtimeConfigApi = api.runtime?.config;
  const runtimeConfig = typeof runtimeConfigApi?.current === "function"
    ? runtimeConfigApi.current()
    : typeof runtimeConfigApi?.loadConfig === "function"
      ? runtimeConfigApi.loadConfig()
      : api.config;
  const pluginConfig = extractPluginConfig(runtimeConfig);
  if (Object.keys(pluginConfig).length === 0) return;
  _configOverride = mergeConfigs(_configOverride ?? {}, pluginConfig);
  // Override changed — invalidate so loadConfig() re-merges with new override.
  _config = null;
  _lastShieldConfigRef = null;
}

async function loadConfig(): Promise<SCConfig> {
  const shieldConfigRaw = await (await getRuntime()).loadShieldConfig();
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

export async function scanRealtimeContent(text: string): Promise<{ clean: boolean; summary: string }> {
  // PRIMARY: scan in-process via the shared shieldcortex/defence module. The
  // scan is pure (no DB handle required — scanToolResponse's audit write is
  // guarded by isDatabaseInitialized()), so it is safe in the long-lived
  // gateway and avoids booting a cold MCP server per message.
  const defenceMod = await getDefenceModule();
  if (defenceMod && typeof defenceMod.scanToolResponse === "function") {
    const scan = defenceMod.scanToolResponse("openclaw-realtime", text, "advisory");
    // Reproduce the historical summary contract exactly: risk level + detection
    // count only when the injection scan flagged something.
    const risk = scan.injection.clean ? "unknown" : scan.injection.riskLevel;
    const summary = scan.injection.clean
      ? risk
      : `${risk} (${scan.injection.detections.length} detections)`;
    return { clean: scan.clean, summary };
  }

  // FALLBACK: in-process defence unavailable (older install, import failed) —
  // degrade to the MCP shell-out so scanning still happens rather than breaking.
  const response = await callCortex("scan_tool_response", {
    toolName: "openclaw-realtime",
    content: text,
    mode: "advisory",
  });

  if (!response) {
    return { clean: true, summary: "scan unavailable" };
  }

  return parseScanResponse(response);
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

const AUDIT_DIR = path.join(homedir(), ".shieldcortex", "audit");
const NOVELTY_CACHE_FILE = path.join(homedir(), ".shieldcortex", "openclaw-memory-cache.json");
const DEFAULT_NOVELTY_THRESHOLD = 0.88;
const DEFAULT_MAX_RECENT = 300;
const MIN_NOVELTY_CHARS = 40;

async function auditLog(entry: Record<string, unknown>) {
  try {
    await fs.mkdir(AUDIT_DIR, { recursive: true });
    await fs.appendFile(
      path.join(AUDIT_DIR, `realtime-${new Date().toISOString().slice(0, 10)}.jsonl`),
      JSON.stringify(entry) + "\n",
    );
  } catch {}
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
    // Only scan user content, skip system/boot/heartbeat prompts
    const userTexts = extractUserContent(event.historyMessages).slice(-5);
    const texts = [event.prompt, ...userTexts].filter(t => t && !isInternalContent(t));
    for (const text of texts) {
      if (!text || text.length < 10) continue;
      const result = await scanRealtimeContent(text);
      if (!result.clean) {
        console.warn(`[shieldcortex] ⚠️ Threat in LLM input: ${result.summary}`);
        const entry = {
          type: "threat", hook: "llm_input", sessionId: event.sessionId,
          model: event.model, reason: result.summary,
          preview: text.slice(0, 100), ts: new Date().toISOString(),
        };
        auditLog(entry);
        loadConfig()
          // Pass the local entry as-is; cloudSync rebuilds a canonical metadata-only
          // entry from named fields and never reads preview/content. No raw LLM input
          // leaves here.
          .then(cfg => cloudSync(entry, cfg))
          .catch(() => {});
      }
    }
  } catch (e) {
    console.error("[shieldcortex] llm_input error:", e instanceof Error ? e.message : String(e));
  }
}

function handleLlmInput(event: LlmInputEvent, ctx: AgentCtx): void {
  // Fire and forget
  void scanLlmInput(event, ctx);
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
): Promise<TypedBeforeToolCallResult | void> {
  try {
    await interceptor.handleToolCall({
      toolName: event.toolName,
      arguments: event.params ?? {},
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
    try {
    applyPluginConfigOverride(api);

    // --- Interceptor (lazy init) ---
    let interceptorReady: ReturnType<typeof createInterceptor> | null = null;
    let interceptorInitAttempted = false;

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
          onAuditEntry: (entry) => syncInterceptEvent(entry, {
            cloudApiKey: (scConfig as any).cloudApiKey ?? '',
            cloudBaseUrl: (scConfig as any).cloudBaseUrl ?? 'https://api.shieldcortex.ai',
            cloudEnabled: (scConfig as any).cloudEnabled ?? false,
          }),
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
      api.on('before_tool_call', async (event: TypedBeforeToolCallEvent) => {
        const interceptor = await initInterceptor();
        if (!interceptor) return;
        return handleTypedBeforeToolCall(event, interceptor, api.logger);
      }, { priority: 80, timeoutMs: 30_000 });
      _beforeToolCallRegistered = true;

      // Try to register session_end for cache cleanup (only meaningful while
      // an interceptor can exist)
      try {
        api.on('session_end', () => { interceptorReady?.resetSession(); });
      } catch {
        // session_end may not be a supported hook — TTL safety net handles this
      }
    } else {
      api.logger?.info?.('[shieldcortex] interceptor.enabled:false in plugin config — before_tool_call hook not registered');
    }

    api.on("llm_input", handleLlmInput, { timeoutMs: 30_000 });
    api.on("llm_output", handleLlmOutput, { timeoutMs: 30_000 });

    // Register a lightweight status command so the plugin is not hook-only
    api.registerCommand({
      name: "shieldcortex-status",
      description: "Show ShieldCortex real-time scanner status",
      async handler() {
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
          : "llm_input (scan), llm_output (memory)";
        return {
          text:
            `ShieldCortex v${_version}\n` +
            `  Hooks: ${hooksLine}\n` +
            `  Action guard: ${guardState}\n` +
            `  Auto memory: ${autoMemory} | Dedupe: ${dedupe}\n` +
            `  Cloud sync: ${cloud}`,
        };
      },
    });

    api.logger.info(`[shieldcortex] v${_version} registered (llm_input + llm_output${_beforeToolCallRegistered ? " + before_tool_call" : ""} + /shieldcortex-status)`);
    } catch (err) {
      // Plugin must never block channel startup — warn and bail gracefully
      const msg = err instanceof Error ? err.message : String(err);
      console.warn(`[shieldcortex] WARNING: Plugin failed to initialize: ${msg}`);
      console.warn('[shieldcortex] Real-time scanning is disabled. Channels will start normally.');
    }
  },
};
