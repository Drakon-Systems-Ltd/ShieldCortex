/**
 * ShieldCortex Real-time Scanning Plugin for OpenClaw v2026.3.22+
 *
 * Uses explicit capability registration (registerHook + registerCommand)
 * for llm_input/llm_output scanning and optional memory extraction.
 * All scanning operations are fire-and-forget.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import { existsSync, readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import { homedir } from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";
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
    // 2. Environment variable override
    if (process.env.SHIELDCORTEX_ROOT) {
        addRuntimeCandidate(candidates, process.env.SHIELDCORTEX_ROOT);
    }
    // 3. Walk up from current file location
    addAncestorCandidates(candidates, path.dirname(fileURLToPath(import.meta.url)));
    // 4. Find via shieldcortex binary
    try {
        const bin = execFileSync("which", ["shieldcortex"], {
            encoding: "utf-8",
            timeout: 3000,
        }).trim();
        if (bin)
            addAncestorCandidates(candidates, realpathSync(bin));
    }
    catch { }
    // 5. npm global root
    try {
        const npmRoot = execFileSync("npm", ["root", "-g"], {
            encoding: "utf-8",
            timeout: 3000,
        }).trim();
        if (npmRoot)
            addRuntimeCandidate(candidates, path.join(npmRoot, "shieldcortex"));
    }
    catch { }
    // 6. npm prefix
    try {
        const prefix = execFileSync("npm", ["config", "get", "prefix"], {
            encoding: "utf-8",
            timeout: 3000,
        }).trim();
        if (prefix)
            addRuntimeCandidate(candidates, path.join(prefix, "lib", "node_modules", "shieldcortex"));
    }
    catch { }
    // 7. Common global install paths
    for (const root of [
        "/usr/lib/node_modules/shieldcortex",
        "/usr/local/lib/node_modules/shieldcortex",
        "/opt/homebrew/lib/node_modules/shieldcortex",
        path.join(homedir(), ".npm-global", "lib", "node_modules", "shieldcortex"),
    ]) {
        addRuntimeCandidate(candidates, root);
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
let _configOverride = null;
let _version = "0.0.0";
try {
    for (const packageUrl of [
        new URL("./package.json", import.meta.url),
        new URL("../../package.json", import.meta.url),
    ]) {
        try {
            const pkg = JSON.parse(readFileSync(packageUrl, "utf-8"));
            if (typeof pkg.version === "string" && pkg.version.trim()) {
                _version = pkg.version;
                break;
            }
        }
        catch {
            // try the next candidate
        }
    }
}
catch { /* fallback */ }
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
    const runtimeConfig = typeof api.runtime?.config?.loadConfig === "function"
        ? api.runtime.config.loadConfig()
        : api.config;
    const pluginConfig = extractPluginConfig(runtimeConfig);
    if (Object.keys(pluginConfig).length === 0)
        return;
    _configOverride = {
        ...(_configOverride ?? {}),
        ...pluginConfig,
    };
    if (_config) {
        _config = { ..._config, ...pluginConfig };
    }
}
async function loadConfig() {
    if (_config)
        return _config;
    const shieldConfig = normaliseConfig(await (await getRuntime()).loadShieldConfig());
    _config = {
        ...shieldConfig,
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
async function cloudSync(threat) {
    const cfg = await loadConfig();
    if (!cfg.cloudApiKey)
        return;
    try {
        await fetch(`${cfg.cloudBaseUrl || "https://api.shieldcortex.ai"}/v1/threats`, {
            method: "POST",
            headers: { "Content-Type": "application/json", Authorization: `Bearer ${cfg.cloudApiKey}` },
            body: JSON.stringify(threat),
            signal: AbortSignal.timeout(5000),
        });
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
                    cloudSync({ ...entry, content: text.slice(0, 200) });
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
        applyPluginConfigOverride(api);
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
            aliases: ["sc-status"],
            description: "Show ShieldCortex real-time scanner status",
            async execute({ reply }) {
                const cfg = await loadConfig();
                const autoMemory = isAutoMemoryEnabled(cfg) ? "on" : "off";
                const dedupe = isAutoMemoryDedupeEnabled(cfg) ? "on" : "off";
                const cloud = cfg.cloudApiKey ? "configured" : "not configured";
                reply(`ShieldCortex v${_version}\n` +
                    `  Hooks: llm_input (scan), llm_output (memory)\n` +
                    `  Auto memory: ${autoMemory} | Dedupe: ${dedupe}\n` +
                    `  Cloud sync: ${cloud}`);
            },
        });
        api.logger.info(`[shieldcortex] v${_version} registered (llm_input + llm_output + /shieldcortex-status)`);
    },
};
