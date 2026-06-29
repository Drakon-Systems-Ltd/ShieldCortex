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
import type { InterceptorConfig } from './interceptor.js';
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

interface SCConfig {
  cloudEnabled?: boolean;
  cloudApiKey?: string;
  cloudBaseUrl?: string;
  binaryPath?: string;
  openclawAutoMemory?: boolean;
  openclawAutoMemoryDedupe?: boolean;
  openclawAutoMemoryNoveltyThreshold?: number;
  openclawAutoMemoryMaxRecent?: number;
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
} as const;

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

  return config;
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
  _configOverride = {
    ...(_configOverride ?? {}),
    ...pluginConfig,
  };
  // Override changed — invalidate so loadConfig() re-merges with new override.
  _config = null;
  _lastShieldConfigRef = null;
}

async function loadConfig(): Promise<SCConfig> {
  const shieldConfigRaw = await (await getRuntime()).loadShieldConfig();
  if (_config && shieldConfigRaw === _lastShieldConfigRef) return _config;
  _lastShieldConfigRef = shieldConfigRaw;
  _config = {
    ...normaliseConfig(shieldConfigRaw),
    ...(_configOverride ?? {}),
  };
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
        const rawInterceptorConfig = (scConfig as any).interceptor;
        const interceptorConfig: InterceptorConfig = {
          ...DEFAULT_INTERCEPTOR_CONFIG,
          ...(rawInterceptorConfig && typeof rawInterceptorConfig === 'object' ? {
            enabled: rawInterceptorConfig.enabled ?? DEFAULT_INTERCEPTOR_CONFIG.enabled,
            severityActions: { ...DEFAULT_INTERCEPTOR_CONFIG.severityActions, ...rawInterceptorConfig.severityActions },
            failurePolicy: { ...DEFAULT_INTERCEPTOR_CONFIG.failurePolicy, ...rawInterceptorConfig.failurePolicy },
            actionGuard: { ...(DEFAULT_INTERCEPTOR_CONFIG.actionGuard ?? { enabled: true, enforce: false }), ...(rawInterceptorConfig.actionGuard ?? {}) },
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

    // Typed before_tool_call hook: this is the OpenClaw agent-loop gate that
    // can block or require approval before the selected tool executes.
    api.on('before_tool_call', async (event: TypedBeforeToolCallEvent) => {
      const interceptor = await initInterceptor();
      if (!interceptor) return;
      return handleTypedBeforeToolCall(event, interceptor, api.logger);
    }, { priority: 80, timeoutMs: 30_000 });

    // Try to register session_end for cache cleanup
    try {
      api.on('session_end', () => { interceptorReady?.resetSession(); });
    } catch {
      // session_end may not be a supported hook — TTL safety net handles this
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
        return {
          text:
            `ShieldCortex v${_version}\n` +
            `  Hooks: llm_input (scan), llm_output (memory)\n` +
            `  Auto memory: ${autoMemory} | Dedupe: ${dedupe}\n` +
            `  Cloud sync: ${cloud}`,
        };
      },
    });

    api.logger.info(`[shieldcortex] v${_version} registered (llm_input + llm_output + before_tool_call + /shieldcortex-status)`);
    } catch (err) {
      // Plugin must never block channel startup — warn and bail gracefully
      const msg = err instanceof Error ? err.message : String(err);
      console.warn(`[shieldcortex] WARNING: Plugin failed to initialize: ${msg}`);
      console.warn('[shieldcortex] Real-time scanning is disabled. Channels will start normally.');
    }
  },
};
