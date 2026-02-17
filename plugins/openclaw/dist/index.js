/**
 * ShieldCortex Real-time Scanning Plugin for OpenClaw v2026.2.15+
 *
 * Hooks into llm_input/llm_output for real-time defence scanning
 * and memory extraction. All operations are fire-and-forget.
 */
import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { homedir } from "node:os";
let _config = null;
async function loadConfig() {
    if (_config)
        return _config;
    try {
        _config = JSON.parse(await fs.readFile(path.join(homedir(), ".shieldcortex", "config.json"), "utf-8"));
    }
    catch {
        _config = {};
    }
    return _config;
}
// ==================== SERVER CMD ====================
let _serverCmd = null;
async function resolveServerCmd() {
    if (_serverCmd)
        return _serverCmd;
    const config = await loadConfig();
    if (config.binaryPath) {
        try {
            await fs.access(config.binaryPath);
            return (_serverCmd = config.binaryPath);
        }
        catch { }
    }
    try {
        const { execFileSync } = await import("node:child_process");
        const bin = execFileSync("which", ["shieldcortex"], { encoding: "utf-8", timeout: 3000 }).trim();
        if (bin)
            return (_serverCmd = bin);
    }
    catch { }
    return (_serverCmd = "npx -y shieldcortex");
}
// ==================== MCP HELPER ====================
function callCortex(tool, args = {}) {
    return resolveServerCmd().then(serverCmd => new Promise(resolve => {
        const cmdArgs = ["mcporter", "call", "--stdio", serverCmd, tool];
        for (const [k, v] of Object.entries(args))
            cmdArgs.push(`${k}:${String(v).replace(/'/g, "''")}`);
        execFile("npx", cmdArgs, { timeout: 15000, maxBuffer: 256 * 1024 }, (err, stdout) => {
            resolve(err ? null : stdout?.trim() || null);
        });
    }));
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
    architecture: [
        /\b(?:architecture|designed|structured)\b.*?(?:uses?|is|with)\b/i,
        /\b(?:decided?\s+to|going\s+with|chose)\b/i,
        /\b(?:set\s+up|configured|installed|deployed|migrated)\b/i,
        /\b(?:runs?\s+on|hosted\s+(?:on|at)|lives?\s+at|stored\s+(?:in|at))\b/i,
        /\b(?:API|endpoint|webhook|token|credential)\s+(?:is|at|for|uses?)\b/i,
        /\b(?:cron|scheduled|automated)\s+(?:job|task|to)\b/i,
    ],
    error: [
        /\b(?:fixed|resolved|solved)\s+(?:by|with|using)\b/i,
        /\b(?:solution|fix|root\s*cause)\s+(?:was|is)\b/i,
        /\b(?:bug|issue|error|broken|failing)\s+(?:in|with|because|due)\b/i,
        /\b(?:workaround|patched|hotfix)\b/i,
        /\bthe\s+(?:problem|issue)\s+(?:was|is|turned\s+out)\b/i,
    ],
    learning: [
        /\b(?:learned|discovered|turns?\s+out|figured\s+out|realized)\b/i,
        /\b(?:gotcha|caveat|heads?\s*up|watch\s+out|be\s+careful)\b/i,
        /\b(?:the\s+trick\s+is|key\s+thing|note\s+that)\b/i,
        /\b(?:doesn.t\s+work|won.t\s+work|can.t\s+be|not\s+supported)\b/i,
        /\b(?:needs?\s+to\s+be|must\s+be|has\s+to\s+be|requires?)\b/i,
    ],
    preference: [
        /\b(?:always|never|prefer|should\s+always)\b/i,
        /\b(?:michael\s+(?:wants?|likes?|prefers?|said|asked))\b/i,
        /\b(?:we\s+(?:use|prefer|go\s+with|stick\s+with))\b/i,
        /\b(?:don.t\s+use|avoid\s+using|instead\s+of)\b/i,
    ],
    context: [
        /\b(?:password|login|account|credentials?)\s+(?:is|are|for|in|at|stored)\b/i,
        /\b(?:1password|1P)\s+(?:item|vault|field)\b/i,
        /\b(?:script|command)\s+(?:is|at|for|to)\b/i,
        /\b(?:price|cost|budget|£|\$)\s*\d/i,
        /\b(?:birthday|anniversary|reminder)\b/i,
        /\b(?:contact|phone|email|address)\s+(?:is|for)\b/i,
    ],
    note: [
        /\b(?:important|remember|key\s+point)\s*:/i,
        /\b(?:summary|verdict|bottom\s+line|tldr|tl;dr)\s*:/i,
        /\b(?:status|result|outcome)\s*:/i,
        /\b(?:todo|action\s+item|next\s+step|follow\s*up)\b/i,
    ],
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
                    out.push({ title, content: text.slice(0, 1000), category: cat });
                }
                break;
            }
            if (out.length >= 5)
                break;
        }
        if (out.length >= 5)
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
                const result = pipeline(text, "llm_input", { type: "plugin", name: "openclaw-realtime", trust: "medium" });
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
function handleLlmOutput(event, ctx) {
    // Fire and forget
    (async () => {
        try {
            const texts = event.assistantTexts.filter(t => t && t.length >= 30);
            if (!texts.length)
                return;
            const memories = extractMemories(texts);
            if (!memories.length)
                return;
            let saved = 0;
            for (const mem of memories) {
                const r = await callCortex("remember", {
                    title: mem.title, content: mem.content, category: mem.category,
                    project: ctx.agentId || "openclaw", scope: "global",
                    importance: "normal", tags: "auto-extracted,realtime-plugin,llm-output",
                });
                if (r)
                    saved++;
            }
            if (saved) {
                console.log(`[shieldcortex] Extracted ${saved} memor${saved === 1 ? "y" : "ies"} from LLM output`);
                auditLog({ type: "memory", hook: "llm_output", sessionId: event.sessionId, count: saved, ts: new Date().toISOString() });
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
    description: "Real-time defence scanning on LLM inputs and memory extraction from outputs",
    version: "2.12.3",
    register(api) {
        api.on("llm_input", handleLlmInput);
        api.on("llm_output", handleLlmOutput);
        api.logger.info("[shieldcortex] Real-time scanning plugin registered (llm_input + llm_output)");
    },
};
