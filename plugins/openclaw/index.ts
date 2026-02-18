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

// ==================== TYPES (inline to avoid import issues) ====================

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
type PluginApi = {
  id: string; name: string; logger: { info: (m: string) => void };
  on: (hook: string, handler: (...args: any[]) => any) => void;
  [k: string]: any;
};

// ==================== CONFIG ====================

interface SCConfig { cloudApiKey?: string; cloudEndpoint?: string; binaryPath?: string }
let _config: SCConfig | null = null;

async function loadConfig(): Promise<SCConfig> {
  if (_config) return _config;
  try {
    _config = JSON.parse(await fs.readFile(path.join(homedir(), ".shieldcortex", "config.json"), "utf-8"));
  } catch { _config = {}; }
  return _config!;
}

// ==================== SERVER CMD ====================

let _serverCmd: string | null = null;
async function resolveServerCmd(): Promise<string> {
  if (_serverCmd) return _serverCmd;
  const config = await loadConfig();
  if (config.binaryPath) { try { await fs.access(config.binaryPath); return (_serverCmd = config.binaryPath); } catch {} }
  try {
    const { execFileSync } = await import("node:child_process");
    const bin = execFileSync("which", ["shieldcortex"], { encoding: "utf-8", timeout: 3000 }).trim();
    if (bin) return (_serverCmd = bin);
  } catch {}
  return (_serverCmd = "npx -y shieldcortex");
}

// ==================== MCP HELPER ====================

function callCortex(tool: string, args: Record<string, string> = {}): Promise<string | null> {
  return resolveServerCmd().then(serverCmd => new Promise(resolve => {
    const cmdArgs = ["mcporter", "call", "--stdio", serverCmd, tool];
    for (const [k, v] of Object.entries(args)) cmdArgs.push(`${k}:${String(v).replace(/'/g, "''")}`);
    execFile("npx", cmdArgs, { timeout: 15000, maxBuffer: 256 * 1024 }, (err, stdout) => {
      resolve(err ? null : stdout?.trim() || null);
    });
  }));
}

// ==================== DEFENCE PIPELINE ====================

let _pipeline: ((content: string, title: string, source: any, config?: any, project?: string) => any) | null = null;

async function getPipeline() {
  if (_pipeline) return _pipeline;
  try {
    // Initialize the database first — the pipeline's logAudit and persistEvent
    // functions require it, and the plugin runs outside the MCP server context
    // where initDatabase() would normally be called.
    try {
      const { initDatabase } = await import("shieldcortex");
      initDatabase();
    } catch {
      // Database init failed (e.g. better-sqlite3 not available) — pipeline
      // will still work, audit logging will gracefully return -1
    }
    const mod = await import("shieldcortex/defence");
    _pipeline = mod.runDefencePipeline;
    return _pipeline;
  } catch { return null; }
}

// ==================== CONTENT PATTERNS ====================

const PATTERNS: Record<string, RegExp[]> = {
  architecture: [/\b(?:architecture|designed|structured)\b.*?(?:uses?|is|with)\b/i, /\b(?:decided?\s+to|going\s+with|chose)\b/i],
  error: [/\b(?:fixed|resolved|solved)\s+(?:by|with|using)\b/i, /\b(?:solution|fix|root\s*cause)\s+(?:was|is)\b/i],
  learning: [/\b(?:learned|discovered|turns?\s+out|figured\s+out|realized)\b/i],
  preference: [/\b(?:always|never|prefer|should\s+always)\b/i],
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

async function auditLog(entry: Record<string, unknown>) {
  try {
    await fs.mkdir(AUDIT_DIR, { recursive: true });
    await fs.appendFile(
      path.join(AUDIT_DIR, `realtime-${new Date().toISOString().slice(0, 10)}.jsonl`),
      JSON.stringify(entry) + "\n",
    );
  } catch {}
}

async function cloudSync(threat: Record<string, unknown>) {
  const cfg = await loadConfig();
  if (!cfg.cloudApiKey) return;
  try {
    await fetch(`${cfg.cloudEndpoint || "https://api.shieldcortex.ai"}/v1/threats`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${cfg.cloudApiKey}` },
      body: JSON.stringify(threat),
      signal: AbortSignal.timeout(5000),
    });
  } catch {}
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

function handleLlmInput(event: LlmInputEvent, ctx: AgentCtx): void {
  // Fire and forget
  (async () => {
    try {
      const pipeline = await getPipeline();
      if (!pipeline) return;

      // Only scan user content, skip system/boot/heartbeat prompts
      const userTexts = extractUserContent(event.historyMessages).slice(-5);
      const texts = [event.prompt, ...userTexts].filter(t => t && !isInternalContent(t));
      for (const text of texts) {
        if (!text || text.length < 10) continue;
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
    } catch (e) {
      console.error("[shieldcortex] llm_input error:", e instanceof Error ? e.message : String(e));
    }
  })();
}

function handleLlmOutput(event: LlmOutputEvent, ctx: AgentCtx): void {
  // Fire and forget
  (async () => {
    try {
      const texts = event.assistantTexts.filter(t => t && t.length >= 30);
      if (!texts.length) return;
      const memories = extractMemories(texts);
      if (!memories.length) return;

      let saved = 0;
      for (const mem of memories) {
        const r = await callCortex("remember", {
          title: mem.title, content: mem.content, category: mem.category,
          project: ctx.agentId || "openclaw", scope: "global",
          importance: "normal", tags: "auto-extracted,realtime-plugin,llm-output",
        });
        if (r) saved++;
      }
      if (saved) {
        console.log(`[shieldcortex] Extracted ${saved} memor${saved === 1 ? "y" : "ies"} from LLM output`);
        auditLog({ type: "memory", hook: "llm_output", sessionId: event.sessionId, count: saved, ts: new Date().toISOString() });
      }
    } catch (e) {
      console.error("[shieldcortex] llm_output error:", e instanceof Error ? e.message : String(e));
    }
  })();
}

// ==================== PLUGIN EXPORT ====================

export default {
  id: "shieldcortex-realtime",
  name: "ShieldCortex Real-time Scanner",
  description: "Real-time defence scanning on LLM inputs and memory extraction from outputs",
  version: "2.11.0",

  register(api: PluginApi) {
    api.on("llm_input", handleLlmInput);
    api.on("llm_output", handleLlmOutput);
    api.logger.info("[shieldcortex] Real-time scanning plugin registered (llm_input + llm_output)");
  },
};
