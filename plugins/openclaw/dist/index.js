/**
 * ShieldCortex Real-time Scanning Plugin for OpenClaw v2026.2.15+
 *
 * Hooks into llm_input/llm_output for real-time defence scanning
 * and optional memory extraction. All operations are fire-and-forget.
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
let _config = null;
let _version = "0.0.0";
try {
    const pkg = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf-8"));
    _version = pkg.version;
}
catch { /* fallback */ }
async function loadConfig() {
    if (_config)
        return _config;
    _config = await (await getRuntime()).loadShieldConfig();
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
// ==================== DEFENCE PIPELINE ====================
let _pipeline = null;
async function getPipeline() {
    if (_pipeline)
        return _pipeline;
    try {
        const mod = await import("shieldcortex/defence");
        _pipeline = mod.runDefencePipeline;
        return _pipeline;
    }
    catch {
        return null;
    }
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
        await fetch(`${cfg.cloudEndpoint || "https://api.shieldcortex.ai"}/v1/threats`, {
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
            const pipeline = await getPipeline();
            if (!pipeline)
                return;
            // Only scan user content, skip system/boot/heartbeat prompts
            const userTexts = extractUserContent(event.historyMessages).slice(-5);
            const texts = [event.prompt, ...userTexts].filter(t => t && !isInternalContent(t));
            for (const text of texts) {
                if (!text || text.length < 10)
                    continue;
                const result = pipeline(text, "llm_input", { type: "plugin", identifier: "openclaw-realtime", name: "openclaw-realtime", trust: "medium" });
                if (result && !result.allowed) {
                    console.warn(`[shieldcortex] ⚠️ Threat in LLM input: ${result.reason}`);
                    const entry = {
                        type: "threat", hook: "llm_input", sessionId: event.sessionId,
                        model: event.model, reason: result.reason,
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
    id: "shieldcortex-realtime",
    name: "ShieldCortex Real-time Scanner",
    description: "Real-time defence scanning on LLM inputs with optional memory extraction from outputs",
    version: _version,
    register(api) {
        api.on("llm_input", handleLlmInput);
        api.on("llm_output", handleLlmOutput);
        // Fire-and-forget: init database for local audit logging
        import("shieldcortex")
            .then((mod) => {
            mod.initDatabase();
            api.logger.info("[shieldcortex] Audit database initialized");
        })
            .catch((e) => api.logger.info("[shieldcortex] DB init deferred: " + (e instanceof Error ? e.message : String(e))));
        api.logger.info("[shieldcortex] Real-time scanning plugin registered (llm_input + llm_output)");
    },
};
