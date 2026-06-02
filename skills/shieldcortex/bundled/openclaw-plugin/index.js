/**
 * ShieldCortex Real-time Scanning Plugin for OpenClaw v2026.3.22+
 *
 * Uses explicit capability registration (registerHook + registerCommand)
 * for llm_input/llm_output scanning and optional memory extraction.
 * All scanning operations are fire-and-forget.
 */
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import { existsSync, readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import { homedir } from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createInterceptor, DEFAULT_CONFIG as DEFAULT_INTERCEPTOR_CONFIG } from './interceptor.js';
import { syncInterceptEvent } from './intercept-ingest.js';
import { cloudSync } from './cloud-sync.js';
let runtimePromise = null;
function addRuntimeCandidate(candidates, packageRoot) {
    const runtimePath = path.join(packageRoot, "hooks", "openclaw", "cortex-memory", "runtime.mjs");
    if (existsSync(runtimePath)) {
        candidates.add(pathToFileURL(runtimePath).href);
    }
}
function addAncestorCandidates(candidates, startPath) {
    let current = path.resolve(startPath);
    let previous = "";
    for (let i = 0; i < 6 && current !== previous; i++) {
        addRuntimeCandidate(candidates, current);
        previous = current;
        current = path.dirname(current);
    }
}
function collectRuntimeCandidates() {
    const candidates = new Set();
    // 1. Relative path (works when running from within npm package tree)
    candidates.add(new URL("../../hooks/openclaw/cortex-memory/runtime.mjs", import.meta.url).href);
    // 2. Config file override (reads path from ~/.shieldcortex/config.json instead of env var)
    try {
        const cfgPath = path.join(homedir(), ".shieldcortex", "config.json");
        if (existsSync(cfgPath)) {
            const cfg = JSON.parse(readFileSync(cfgPath, "utf-8"));
            if (cfg.installRoot)
                addRuntimeCandidate(candidates, cfg.installRoot);
        }
    }
    catch { /* no config */ }
    // 3. Walk up from current file location
    addAncestorCandidates(candidates, path.dirname(fileURLToPath(import.meta.url)));
    // 4. Resolve via common bin symlink paths (no child_process needed)
    for (const binDir of ["/usr/local/bin", "/opt/homebrew/bin", path.join(homedir(), ".npm-global", "bin")]) {
        const binPath = path.join(binDir, "shieldcortex");
        try {
            if (existsSync(binPath))
                addAncestorCandidates(candidates, realpathSync(binPath));
        }
        catch { /* broken symlink */ }
    }
    // 5. Common global install paths (covers npm root -g results without spawning npm)
    for (const root of [
        "/usr/lib/node_modules/shieldcortex",
        "/usr/local/lib/node_modules/shieldcortex",
        "/opt/homebrew/lib/node_modules/shieldcortex",
        path.join(homedir(), ".npm-global", "lib", "node_modules", "shieldcortex"),
        path.join(homedir(), ".nvm", "versions", "node"), // nvm users
    ]) {
        if (root.includes(".nvm")) {
            // For nvm, check the current symlink
            try {
                const currentNode = path.join(homedir(), ".nvm", "current", "lib", "node_modules", "shieldcortex");
                addRuntimeCandidate(candidates, currentNode);
            }
            catch { /* no nvm */ }
        }
        else {
            addRuntimeCandidate(candidates, root);
        }
    }
    return [...candidates];
}
async function getRuntime() {
    if (!runtimePromise) {
        runtimePromise = (async () => {
            const tried = [];
            let lastError = null;
            for (const candidate of collectRuntimeCandidates()) {
                tried.push(candidate);
                try {
                    const mod = await import(candidate);
                    if (typeof mod.createOpenClawRuntime === "function") {
                        return mod.createOpenClawRuntime({ logPrefix: "[shieldcortex]" });
                    }
                }
                catch (error) {
                    lastError = error;
                }
            }
            const detail = lastError instanceof Error ? lastError.message : String(lastError ?? "unknown error");
            throw new Error(`Could not load OpenClaw runtime. Tried: ${tried.join(", ")}. Last error: ${detail}`);
        })();
    }
    return runtimePromise;
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
    },
};
let _config = null;
// Identity of the shield config we last merged from. The runtime's
// loadShieldConfig() returns the same parsed object until the file's mtime
// advances; using reference equality lets us re-merge precisely when the
// underlying config has actually changed (dashboard / CLI write).
let _lastShieldConfigRef = null;
let _configOverride = null;
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
        }
        catch {
            // try the next candidate
        }
    }
}
catch { /* fallback */ }
let _registered = false;
function normaliseConfig(raw) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw))
        return {};
    const value = raw;
    const config = {};
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
function extractPluginConfig(rootConfig) {
    if (!rootConfig || typeof rootConfig !== "object" || Array.isArray(rootConfig))
        return {};
    const entries = rootConfig.plugins?.entries;
    const pluginConfig = entries?.[PLUGIN_ID]?.config ??
        entries?.[PLUGIN_PACKAGE_NAME]?.config;
    return normaliseConfig(pluginConfig);
}
function applyPluginConfigOverride(api) {
    const runtimeConfigApi = api.runtime?.config;
    const runtimeConfig = typeof runtimeConfigApi?.current === "function"
        ? runtimeConfigApi.current()
        : typeof runtimeConfigApi?.loadConfig === "function"
            ? runtimeConfigApi.loadConfig()
            : api.config;
    const pluginConfig = extractPluginConfig(runtimeConfig);
    if (Object.keys(pluginConfig).length === 0)
        return;
    _configOverride = {
        ...(_configOverride ?? {}),
        ...pluginConfig,
    };
    // Override changed — invalidate so loadConfig() re-merges with new override.
    _config = null;
    _lastShieldConfigRef = null;
}
async function loadConfig() {
    const shieldConfigRaw = await (await getRuntime()).loadShieldConfig();
    if (_config && shieldConfigRaw === _lastShieldConfigRef)
        return _config;
    _lastShieldConfigRef = shieldConfigRaw;
    _config = {
        ...normaliseConfig(shieldConfigRaw),
        ...(_configOverride ?? {}),
    };
    return _config;
}
function isAutoMemoryEnabled(config) {
    return config.openclawAutoMemory === true;
}
function isAutoMemoryDedupeEnabled(config) {
    return config.openclawAutoMemoryDedupe !== false;
}
async function callCortex(tool, args = {}) {
    return (await getRuntime()).callCortex(tool, args);
}
// ==================== REMOTE SCANNING ====================
async function scanRealtimeContent(text) {
    const response = await callCortex("scan_tool_response", {
        toolName: "openclaw-realtime",
        content: text,
        mode: "advisory",
    });
    if (!response) {
        return { clean: true, summary: "scan unavailable" };
    }
    const cleanMatch = response.match(/\*\*Clean:\*\*\s*(Yes|No)/i);
    const riskMatch = response.match(/\*\*Risk Level:\*\*\s*([A-Za-z]+)/i);
    const detectionsMatch = response.match(/\*\*Detections:\*\*\s*(\d+)/i);
    const clean = cleanMatch ? /yes/i.test(cleanMatch[1]) : true;
    const risk = riskMatch?.[1] ?? "unknown";
    const detections = detectionsMatch?.[1];
    const summary = detections ? `${risk} (${detections} detections)` : risk;
    return { clean, summary };
}
// ==================== CONTENT PATTERNS ====================
const PATTERNS = {
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
function extractMemories(texts) {
    const out = [];
    const seen = new Set();
    for (const text of texts) {
        if (text.length < 30)
            continue;
        for (const [cat, pats] of Object.entries(PATTERNS)) {
            if (pats.some(p => p.test(text))) {
                const title = text.slice(0, 80).replace(/["\n]/g, " ").trim();
                if (!seen.has(title)) {
                    seen.add(title);
                    out.push({ title, content: text.slice(0, 500), category: cat });
                }
                break;
            }
            if (out.length >= 3)
                break;
        }
        if (out.length >= 3)
            break;
    }
    return out;
}
// ==================== HELPERS ====================
function extractUserContent(msgs) {
    const out = [];
    for (const msg of msgs) {
        if (!msg || typeof msg !== "object")
            continue;
        const m = msg;
        if (m.role !== "user")
            continue;
        if (typeof m.content === "string")
            out.push(m.content);
        else if (Array.isArray(m.content))
            for (const b of m.content)
                if (b?.type === "text")
                    out.push(b.text);
    }
    return out;
}
const AUDIT_DIR = path.join(homedir(), ".shieldcortex", "audit");
const NOVELTY_CACHE_FILE = path.join(homedir(), ".shieldcortex", "openclaw-memory-cache.json");
const DEFAULT_NOVELTY_THRESHOLD = 0.88;
const DEFAULT_MAX_RECENT = 300;
const MIN_NOVELTY_CHARS = 40;
async function auditLog(entry) {
    try {
        await fs.mkdir(AUDIT_DIR, { recursive: true });
        await fs.appendFile(path.join(AUDIT_DIR, `realtime-${new Date().toISOString().slice(0, 10)}.jsonl`), JSON.stringify(entry) + "\n");
    }
    catch { }
}
function normalizeMemoryText(text) {
    return String(text || "")
        .toLowerCase()
        .replace(/[`"'\\]/g, " ")
        .replace(/https?:\/\/\S+/g, " ")
        .replace(/[^a-z0-9\s]/g, " ")
        .replace(/\s+/g, " ")
        .trim();
}
function hashToken(token) {
    return createHash("sha1").update(token).digest("hex").slice(0, 12);
}
function buildTokenHashes(normalized) {
    const words = normalized.split(" ").filter((w) => w.length >= 3);
    const set = new Set();
    for (let i = 0; i < words.length; i++) {
        set.add(hashToken(words[i]));
        if (i < words.length - 1)
            set.add(hashToken(`${words[i]}_${words[i + 1]}`));
    }
    return Array.from(set).slice(0, 200);
}
function jaccardSimilarity(a, b) {
    if (a.size === 0 || b.size === 0)
        return 0;
    let intersection = 0;
    for (const item of a) {
        if (b.has(item))
            intersection++;
    }
    const union = a.size + b.size - intersection;
    return union === 0 ? 0 : intersection / union;
}
function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
}
async function loadNoveltyCache(maxRecent) {
    try {
        const raw = JSON.parse(await fs.readFile(NOVELTY_CACHE_FILE, "utf-8"));
        if (!Array.isArray(raw))
            return [];
        return raw
            .filter((entry) => entry && typeof entry.hash === "string" && Array.isArray(entry.tokenHashes))
            .slice(0, maxRecent);
    }
    catch {
        return [];
    }
}
async function saveNoveltyCache(entries) {
    await fs.mkdir(path.dirname(NOVELTY_CACHE_FILE), { recursive: true });
    await fs.writeFile(NOVELTY_CACHE_FILE, JSON.stringify(entries, null, 2) + "\n", "utf-8");
}
function inspectNovelty(content, entries, threshold) {
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
async function createNoveltyGate(config) {
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
        inspect(content) {
            if (!enabled)
                return { allow: true, contentHash: null, tokenHashes: [] };
            return inspectNovelty(content, entries, threshold);
        },
        remember(memory, novelty) {
            if (!enabled || !novelty.contentHash || novelty.tokenHashes.length === 0)
                return;
            entries.unshift({
                hash: novelty.contentHash,
                tokenHashes: novelty.tokenHashes,
                title: String(memory.title || "").slice(0, 120),
                category: String(memory.category || "note"),
                createdAt: new Date().toISOString(),
            });
            if (entries.length > maxRecent)
                entries.length = maxRecent;
            dirty = true;
        },
        async flush() {
            if (!enabled || !dirty)
                return;
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
    /^\[(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s/, // Timestamped system events
    /^A subagent task/i,
    /subagent.*completed/i,
];
function isInternalContent(text) {
    return SKIP_PATTERNS.some(p => p.test(text.trim()));
}
function handleLlmInput(event, ctx) {
    // Fire and forget
    (async () => {
        try {
            // Only scan user content, skip system/boot/heartbeat prompts
            const userTexts = extractUserContent(event.historyMessages).slice(-5);
            const texts = [event.prompt, ...userTexts].filter(t => t && !isInternalContent(t));
            for (const text of texts) {
                if (!text || text.length < 10)
                    continue;
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
                        // Pass the local entry as-is; cloudSync strips the input preview/content
                        // before transmit (metadata-only egress). No raw LLM input leaves here.
                        .then(cfg => cloudSync(entry, cfg))
                        .catch(() => { });
                }
            }
        }
        catch (e) {
            console.error("[shieldcortex] llm_input error:", e instanceof Error ? e.message : String(e));
        }
    })();
}
// Skip text blocks that are ShieldCortex/OpenClaw tool-result pass-throughs
function isToolResultContent(text) {
    // ShieldCortex recall returns "Found N memories:" header
    if (/^Found \d+ memor(?:y|ies):/m.test(text))
        return true;
    // ShieldCortex get_context returns structured context blocks
    if (/^## (?:Architecture|Patterns|Preferences|Errors|Context)/m.test(text))
        return true;
    // OpenClaw tool-result wrapper markers
    if (/^\[tool_result\b/i.test(text.trim()))
        return true;
    if (/^<tool_result\b/i.test(text.trim()))
        return true;
    return false;
}
function handleLlmOutput(event, ctx) {
    // Fire and forget
    (async () => {
        try {
            const config = await loadConfig();
            if (!isAutoMemoryEnabled(config))
                return;
            const texts = event.assistantTexts
                .filter(t => t && t.length >= 30)
                .filter(t => !isToolResultContent(t));
            if (!texts.length)
                return;
            const memories = extractMemories(texts);
            if (!memories.length)
                return;
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
        }
        catch (e) {
            console.error("[shieldcortex] llm_output error:", e instanceof Error ? e.message : String(e));
        }
    })();
}
// ==================== PLUGIN EXPORT ====================
export default {
    id: PLUGIN_ID,
    name: "ShieldCortex Real-time Scanner",
    description: "Real-time defence scanning on LLM inputs with optional memory extraction from outputs",
    version: _version,
    configSchema: {
        parse(value) {
            return normaliseConfig(value);
        },
        uiHints: PLUGIN_CONFIG_UI_HINTS,
        jsonSchema: PLUGIN_CONFIG_JSON_SCHEMA,
    },
    register(api) {
        if (_registered)
            return;
        _registered = true;
        try {
            applyPluginConfigOverride(api);
            // --- Interceptor (lazy init) ---
            let interceptorReady = null;
            let interceptorInitAttempted = false;
            async function initInterceptor() {
                if (interceptorInitAttempted)
                    return interceptorReady;
                interceptorInitAttempted = true;
                try {
                    const scConfig = await loadConfig();
                    const rawInterceptorConfig = scConfig.interceptor;
                    const interceptorConfig = {
                        ...DEFAULT_INTERCEPTOR_CONFIG,
                        ...(rawInterceptorConfig && typeof rawInterceptorConfig === 'object' ? {
                            enabled: rawInterceptorConfig.enabled ?? DEFAULT_INTERCEPTOR_CONFIG.enabled,
                            severityActions: { ...DEFAULT_INTERCEPTOR_CONFIG.severityActions, ...rawInterceptorConfig.severityActions },
                            failurePolicy: { ...DEFAULT_INTERCEPTOR_CONFIG.failurePolicy, ...rawInterceptorConfig.failurePolicy },
                        } : {}),
                        logger: { info: api.logger?.info ?? console.log, warn: api.logger?.warn ?? console.warn },
                    };
                    if (!interceptorConfig.enabled)
                        return null;
                    // Dynamic import with string variable to prevent TypeScript from resolving
                    // at compile time — 'shieldcortex/defence' only exists at runtime when the
                    // package is installed globally, not during CI builds of the plugin itself.
                    let defenceMod;
                    try {
                        const defenceModPath = 'shieldcortex' + '/defence';
                        defenceMod = await import(/* webpackIgnore: true */ defenceModPath);
                    }
                    catch (importErr) {
                        // Stack overflow or missing module — interceptor can't load
                        api.logger?.warn?.(`[shieldcortex] Cannot load defence module: ${importErr instanceof Error ? importErr.message : importErr}`);
                        return null;
                    }
                    if (typeof defenceMod.runDefencePipeline !== 'function')
                        return null;
                    interceptorReady = createInterceptor(interceptorConfig, defenceMod.runDefencePipeline, {
                        onAuditEntry: (entry) => syncInterceptEvent(entry, {
                            cloudApiKey: scConfig.cloudApiKey ?? '',
                            cloudBaseUrl: scConfig.cloudBaseUrl ?? 'https://api.shieldcortex.ai',
                            cloudEnabled: scConfig.cloudEnabled ?? false,
                        }),
                    });
                    api.logger?.info?.('[shieldcortex] Interceptor active — watching: remember, mcp__memory__remember');
                    return interceptorReady;
                }
                catch (err) {
                    api.logger?.warn?.(`[shieldcortex] Interceptor init failed: ${err instanceof Error ? err.message : err}`);
                    return null;
                }
            }
            // Register before_tool_call with lazy-init wrapper
            api.registerHook('before_tool_call', async (context) => {
                const interceptor = await initInterceptor();
                if (!interceptor)
                    return;
                try {
                    await interceptor.handleToolCall(context);
                }
                catch (err) {
                    // Intentional blocks from the interceptor (ShieldCortex: ...) should propagate
                    if (err instanceof Error && err.message.startsWith('ShieldCortex:'))
                        throw err;
                    // Unexpected errors (DB crash, etc.) — log and allow the tool call through
                    api.logger?.warn?.(`[shieldcortex] Interceptor error (allowing tool call): ${err instanceof Error ? err.message : err}`);
                }
            }, {
                name: 'shieldcortex-intercept-tool',
                description: 'Active threat gating on tool calls',
            });
            // Try to register session_end for cache cleanup
            try {
                api.registerHook('session_end', () => { interceptorReady?.resetSession(); }, {
                    name: 'shieldcortex-session-cleanup',
                    description: 'Clear interceptor deny cache on session end',
                });
            }
            catch {
                // session_end may not be a supported hook — TTL safety net handles this
            }
            // Explicit capability registration (replaces legacy api.on)
            api.registerHook("llm_input", handleLlmInput, {
                name: "shieldcortex-scan-input",
                description: "Real-time threat scanning on LLM input",
            });
            api.registerHook("llm_output", handleLlmOutput, {
                name: "shieldcortex-scan-output",
                description: "Memory extraction from LLM output",
            });
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
                        text: `ShieldCortex v${_version}\n` +
                            `  Hooks: llm_input (scan), llm_output (memory)\n` +
                            `  Auto memory: ${autoMemory} | Dedupe: ${dedupe}\n` +
                            `  Cloud sync: ${cloud}`,
                    };
                },
            });
            api.logger.info(`[shieldcortex] v${_version} registered (llm_input + llm_output + before_tool_call + /shieldcortex-status)`);
        }
        catch (err) {
            // Plugin must never block channel startup — warn and bail gracefully
            const msg = err instanceof Error ? err.message : String(err);
            console.warn(`[shieldcortex] WARNING: Plugin failed to initialize: ${msg}`);
            console.warn('[shieldcortex] Real-time scanning is disabled. Channels will start normally.');
        }
    },
};
