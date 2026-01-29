/**
 * Cortex Memory Hook — Persistent brain-like memory for Clawdbot/Moltbot
 *
 * Integrates Claude Cortex MCP server via mcporter to provide:
 * - Auto-extraction of important session content on /new
 * - Context injection on agent bootstrap
 * - Keyword-triggered memory saves
 */
import { execFile } from "node:child_process";
import fs from "node:fs/promises";

// ==================== CORTEX MCP HELPER ====================

/**
 * Call a Claude Cortex MCP tool via mcporter
 * @param {string} tool - Tool name (e.g., "remember", "recall", "get_context")
 * @param {Record<string, string>} args - Tool arguments as key:value pairs
 * @returns {Promise<string|null>} Raw stdout or null on error
 */
function callCortex(tool, args = {}) {
  return new Promise((resolve) => {
    const cmdArgs = [
      "mcporter", "call", "--stdio",
      "npx -y claude-cortex",
      tool,
    ];
    for (const [key, value] of Object.entries(args)) {
      // Escape single quotes by doubling them (FTS5-safe)
      const safe = String(value).replace(/'/g, "''");
      cmdArgs.push(`${key}:${safe}`);
    }

    execFile("npx", cmdArgs, {
      timeout: 15000,
      maxBuffer: 1024 * 256,
    }, (err, stdout) => {
      if (err) {
        console.error(`[cortex-memory] mcporter error (${tool}):`, err.message);
        resolve(null);
        return;
      }
      resolve(stdout?.trim() || null);
    });
  });
}

// ==================== CONTENT EXTRACTION ====================

const PATTERNS = {
  architecture: [
    /\b(?:architecture|designed|structured|pattern|approach)\b.*?(?:uses?|is|with)\b/i,
    /\b(?:created|implemented|refactored|built|set up)\b/i,
    /\b(?:decided?\s+to|going\s+with|chose|opted?\s+for|using)\b/i,
  ],
  error: [
    /\b(?:fixed|resolved|solved)\s+(?:by|with|using)\b/i,
    /\b(?:the\s+)?(?:solution|fix|root\s*cause|bug)\s+(?:was|is)\b/i,
  ],
  learning: [
    /\b(?:learned|discovered|turns?\s+out|figured\s+out|realized)\b/i,
    /\b(?:TIL|today\s+I\s+learned)\b/i,
  ],
  preference: [
    /\b(?:always|never|prefer|don't\s+like|should\s+always)\b/i,
  ],
  note: [
    /\b(?:important|remember|key\s+point|crucial|note)\s*:/i,
  ],
};

/**
 * Extract high-salience content from session messages
 * @param {string[]} messages - Array of "role: content" strings
 * @returns {Array<{title: string, content: string, category: string}>}
 */
function extractMemories(messages) {
  const extracted = [];
  const seen = new Set();

  for (const msg of messages) {
    if (!msg.startsWith("assistant:")) continue;
    const text = msg.slice("assistant:".length).trim();
    if (text.length < 20) continue;

    for (const [category, patterns] of Object.entries(PATTERNS)) {
      for (const pattern of patterns) {
        if (pattern.test(text)) {
          const title = text.slice(0, 80).replace(/["\n]/g, " ").trim();
          if (seen.has(title)) break;
          seen.add(title);

          extracted.push({
            title,
            content: text.slice(0, 500),
            category,
          });
          break;
        }
      }
      if (extracted.length >= 5) break;
    }
    if (extracted.length >= 5) break;
  }

  return extracted;
}

// ==================== SESSION FILE READER ====================

/**
 * Read recent messages from a session JSONL file
 * @param {string} sessionFilePath
 * @returns {Promise<string[]>} Array of "role: content" strings
 */
async function getRecentMessages(sessionFilePath) {
  try {
    const content = await fs.readFile(sessionFilePath, "utf-8");
    const lines = content.trim().split("\n");
    const recentLines = lines.slice(-30);

    const messages = [];
    for (const line of recentLines) {
      try {
        const entry = JSON.parse(line);
        if (entry.type === "message" && entry.message) {
          const msg = entry.message;
          if ((msg.role === "user" || msg.role === "assistant") && msg.content) {
            const text = Array.isArray(msg.content)
              ? msg.content.find((c) => c.type === "text")?.text
              : msg.content;
            if (text && !text.startsWith("/")) {
              messages.push(`${msg.role}: ${text}`);
            }
          }
        }
      } catch {
        // Skip invalid lines
      }
    }
    return messages;
  } catch {
    return [];
  }
}

// ==================== EVENT HANDLERS ====================

/**
 * Handle command:new — extract memories from ending session
 */
async function onSessionEnd(event) {
  const context = event.context || {};
  const sessionEntry = context.previousSessionEntry || context.sessionEntry || {};
  const sessionFile = sessionEntry.sessionFile;

  if (!sessionFile) {
    console.log("[cortex-memory] No session file found, skipping extraction");
    return;
  }

  const messages = await getRecentMessages(sessionFile);
  if (messages.length === 0) {
    console.log("[cortex-memory] No messages to extract");
    return;
  }

  const memories = extractMemories(messages);
  if (memories.length === 0) {
    console.log("[cortex-memory] No high-salience content found");
    return;
  }

  let saved = 0;
  for (const mem of memories) {
    const result = await callCortex("remember", {
      title: mem.title,
      content: mem.content,
      category: mem.category,
      project: "clawdbot",
      scope: "global",
      importance: "high",
      tags: "auto-extracted,clawdbot-hook",
    });
    if (result) saved++;
  }

  console.log(`[cortex-memory] Saved ${saved}/${memories.length} memories from session`);
}

/**
 * Handle agent:bootstrap — inject past context into agent
 */
async function onBootstrap(event) {
  const context = event.context || {};
  if (!Array.isArray(context.bootstrapFiles)) return;

  const result = await callCortex("get_context", {
    query: "clawdbot session context",
    format: "summary",
  });

  if (!result || result.length < 20) {
    console.log("[cortex-memory] No context to inject");
    return;
  }

  context.bootstrapFiles.push({
    name: "CORTEX_MEMORY.md",
    content: `# Past Session Context (from Claude Cortex)\n\n${result}`,
  });

  console.log("[cortex-memory] Injected past context into bootstrap");
}

/**
 * Handle command events — check for keyword triggers
 */
async function onKeywordTrigger(event) {
  if (event.action === "new" || event.action === "stop") return;

  const context = event.context || {};
  const sessionEntry = context.sessionEntry || {};
  const lastMessage = context.lastUserMessage || sessionEntry.lastUserMessage;
  if (!lastMessage || typeof lastMessage !== "string") return;

  const lower = lastMessage.toLowerCase();
  const triggers = ["remember this", "don't forget", "dont forget"];
  const triggered = triggers.some((t) => lower.includes(t));
  if (!triggered) return;

  let content = lastMessage;
  for (const t of triggers) {
    const idx = lower.indexOf(t);
    if (idx !== -1) {
      content = lastMessage.slice(idx + t.length).replace(/^[:\s]+/, "").trim();
      break;
    }
  }

  if (content.length < 5) return;

  const title = content.slice(0, 80).replace(/["\n]/g, " ").trim();

  const result = await callCortex("remember", {
    title,
    content: content.slice(0, 500),
    category: "note",
    project: "clawdbot",
    scope: "global",
    importance: "critical",
    tags: "keyword-trigger,clawdbot-hook",
  });

  if (result) {
    event.messages.push(`Saved to Cortex memory: "${title}"`);
    console.log(`[cortex-memory] Keyword trigger saved: ${title}`);
  }
}

// ==================== MAIN HANDLER ====================

const cortexMemoryHandler = async (event) => {
  try {
    if (event.type === "command" && event.action === "new") {
      await onSessionEnd(event);
    } else if (event.type === "agent" && event.action === "bootstrap") {
      await onBootstrap(event);
    } else if (event.type === "command") {
      await onKeywordTrigger(event);
    }
  } catch (err) {
    console.error(
      "[cortex-memory] Error:",
      err instanceof Error ? err.message : String(err)
    );
  }
};

export default cortexMemoryHandler;
