/**
 * Cortex Memory Hook — Persistent brain-like memory for OpenClaw
 *
 * Integrates ShieldCortex MCP server via mcporter to provide:
 * - Auto-extraction of important session content on /new
 * - Context injection on agent bootstrap
 * - Keyword-triggered memory saves
 */
import { execFile } from "node:child_process";
import fs from "node:fs/promises";

// ==================== SERVER COMMAND RESOLUTION ====================

/**
 * Resolve the fastest way to invoke shieldcortex:
 * 1. ~/.shieldcortex/config.json "binaryPath" override
 * 2. Global install detected via `which shieldcortex`
 * 3. Fallback to `npx -y shieldcortex` (slow on ARM64)
 */
let _resolvedServerCmd = null;

async function resolveServerCmd() {
  if (_resolvedServerCmd) return _resolvedServerCmd;

  const path = await import("node:path");
  const { homedir } = await import("node:os");

  // 1. Check config for explicit binaryPath
  try {
    const configPath = path.join(homedir(), ".shieldcortex", "config.json");
    const config = JSON.parse(await fs.readFile(configPath, "utf-8"));
    if (config.binaryPath) {
      await fs.access(config.binaryPath);
      _resolvedServerCmd = config.binaryPath;
      console.log(`[cortex-memory] Using configured binary: ${config.binaryPath}`);
      return _resolvedServerCmd;
    }
  } catch { /* Config not found, no binaryPath, or path invalid */ }

  // 2. Try to find global install via `which`
  try {
    const { execFileSync } = await import("node:child_process");
    const bin = execFileSync("which", ["shieldcortex"], {
      encoding: "utf-8",
      timeout: 3000,
    }).trim();
    if (bin) {
      _resolvedServerCmd = bin;
      console.log(`[cortex-memory] Using global install: ${bin}`);
      return _resolvedServerCmd;
    }
  } catch { /* Not in PATH */ }

  // 3. Fall back to npx (slow but always works)
  _resolvedServerCmd = "npx -y shieldcortex";
  console.log("[cortex-memory] Falling back to npx -y shieldcortex (slow path)");
  return _resolvedServerCmd;
}

// ==================== CORTEX MCP HELPER ====================

/**
 * Call a ShieldCortex MCP tool via mcporter
 * @param {string} tool - Tool name (e.g., "remember", "recall", "get_context")
 * @param {Record<string, string>} args - Tool arguments as key:value pairs
 * @param {object} options - Options { retries: number, timeout: number }
 * @returns {Promise<string|null>} Raw stdout or null on error
 */
async function callCortex(tool, args = {}, options = { retries: 1, timeout: 15000 }) {
  const serverCmd = await resolveServerCmd();

  return new Promise((resolve) => {
    const cmdArgs = [
      "mcporter", "call", "--stdio",
      serverCmd,
      tool,
    ];
    for (const [key, value] of Object.entries(args)) {
      // Escape single quotes by doubling them (FTS5-safe)
      const safe = String(value).replace(/'/g, "''");
      cmdArgs.push(`${key}:${safe}`);
    }

    let attempts = 0;
    const maxAttempts = (options.retries || 0) + 1;

    function attempt() {
      attempts++;
      execFile("npx", cmdArgs, {
        timeout: options.timeout || 15000,
        maxBuffer: 1024 * 256,
      }, (err, stdout) => {
        if (err) {
          // Distinguish timeout from other errors
          const isTimeout = err.killed || err.code === "ETIMEDOUT" || err.signal === "SIGTERM";
          const errorType = isTimeout ? "TIMEOUT" : "ERROR";

          if (attempts < maxAttempts) {
            console.warn(`[cortex-memory] ${errorType} on ${tool} (attempt ${attempts}/${maxAttempts}), retrying...`);
            setTimeout(attempt, 1000); // 1s delay before retry
            return;
          }

          console.error(`[cortex-memory] ${errorType} on ${tool} after ${attempts} attempt(s):`, err.message);
          if (err.code) console.error(`[cortex-memory] Error code: ${err.code}`);
          resolve(null);
          return;
        }
        resolve(stdout?.trim() || null);
      });
    }

    attempt();
  });
}

// ==================== HOOK SCANNER ====================

/**
 * Scan installed OpenClaw hooks for potential threats
 * Uses ShieldCortex's scanSkill via mcporter
 * @returns {Promise<Array<{hookName: string, threat: string}>>}
 */
async function scanInstalledHooks() {
  const path = await import("node:path");
  const { homedir } = await import("node:os");

  const hooksDir = path.join(homedir(), ".openclaw", "hooks");
  const threats = [];

  try {
    const entries = await fs.readdir(hooksDir, { withFileTypes: true });

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;

      const hookDir = path.join(hooksDir, entry.name);

      // Check for HOOK.md
      const hookMdPath = path.join(hookDir, "HOOK.md");
      try {
        const hookContent = await fs.readFile(hookMdPath, "utf-8");
        const result = await callCortex("scan_skill", {
          content: hookContent,
          name: entry.name,
          format: "hook-md",
        });

        if (result && result.includes("unsafe")) {
          threats.push({ hookName: entry.name, threat: `HOOK.md flagged as unsafe` });
        }
      } catch { /* No HOOK.md, skip */ }

      // Check for handler.js
      const handlerPath = path.join(hookDir, "handler.js");
      try {
        const handlerContent = await fs.readFile(handlerPath, "utf-8");
        const result = await callCortex("scan_skill", {
          content: handlerContent,
          name: `${entry.name}/handler.js`,
          format: "hook-js",
        });

        if (result && result.includes("unsafe")) {
          threats.push({ hookName: entry.name, threat: `handler.js flagged as unsafe` });
        }
      } catch { /* No handler.js, skip */ }
    }
  } catch {
    // Hooks directory doesn't exist or is unreadable
  }

  return threats;
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
      project: "openclaw",
      scope: "global",
      importance: "high",
      tags: "auto-extracted,openclaw-hook",
    });
    if (result) saved++;
  }

  console.log(`[cortex-memory] Saved ${saved}/${memories.length} memories from session`);
  
  // Provide visible feedback to user
  if (saved > 0 && event.messages) {
    event.messages.push(`🧠 ShieldCortex: Saved ${saved} memor${saved === 1 ? 'y' : 'ies'} from this session`);
  }
}

/**
 * Handle command:stop — extract memories before session ends
 * This fires when user explicitly calls /stop
 */
async function onSessionStop(event) {
  const context = event.context || {};
  const sessionEntry = context.sessionEntry || {};
  const sessionFile = sessionEntry.sessionFile;

  if (!sessionFile) {
    console.log("[cortex-memory] No session file found for stop, skipping extraction");
    return;
  }

  const messages = await getRecentMessages(sessionFile);
  if (messages.length === 0) {
    console.log("[cortex-memory] No messages to extract on stop");
    return;
  }

  const memories = extractMemories(messages);
  if (memories.length === 0) {
    console.log("[cortex-memory] No high-salience content found on stop");
    return;
  }

  let saved = 0;
  for (const mem of memories) {
    const result = await callCortex("remember", {
      title: mem.title,
      content: mem.content,
      category: mem.category,
      project: "openclaw",
      scope: "global",
      importance: "high",
      tags: "auto-extracted,openclaw-hook,session-stop",
    });
    if (result) saved++;
  }

  console.log(`[cortex-memory] Saved ${saved}/${memories.length} memories on session stop`);
  
  // Provide visible feedback to user
  if (saved > 0 && event.messages) {
    event.messages.push(`🧠 ShieldCortex: Saved ${saved} memor${saved === 1 ? 'y' : 'ies'} before session end`);
  }
}

/**
 * Handle agent:bootstrap — inject past context into agent
 */
async function onBootstrap(event) {
  const context = event.context || {};
  if (!Array.isArray(context.bootstrapFiles)) return;

  const result = await callCortex("get_context", {
    query: "openclaw session context",
    format: "summary",
  });

  if (!result || result.length < 20) {
    console.log("[cortex-memory] No context to inject");
    return;
  }

  context.bootstrapFiles.push({
    name: "CORTEX_MEMORY.md",
    content: `# Past Session Context (from ShieldCortex)\n\n${result}`,
  });

  console.log("[cortex-memory] Injected past context into bootstrap");

  // Scan installed hooks for threats
  try {
    const threats = await scanInstalledHooks();
    if (threats.length > 0) {
      const warnings = threats.map(t => `- ${t.hookName}: ${t.threat}`).join("\n");
      context.bootstrapFiles.push({
        name: "SHIELDCORTEX_WARNINGS.md",
        content: `# ShieldCortex Security Warning\n\nThe following installed hooks have been flagged as potentially unsafe:\n\n${warnings}\n\nConsider running: \`npx shieldcortex scan-skills\` for a detailed report.`,
      });
      console.log(`[cortex-memory] WARNING: ${threats.length} hook(s) flagged as potentially unsafe`);
    }
  } catch (scanErr) {
    // Hook scanning is best-effort — never block bootstrap
    console.warn("[cortex-memory] Hook scan failed:", scanErr.message);
  }
}

/**
 * Keyword triggers with their categories and importance levels
 * Order matters: more specific triggers should come first
 */
const KEYWORD_TRIGGERS = [
  // Learning triggers
  { phrase: "lesson learned", category: "learning", importance: "high" },
  { phrase: "i learned", category: "learning", importance: "normal" },
  { phrase: "til:", category: "learning", importance: "normal" },
  { phrase: "today i learned", category: "learning", importance: "normal" },
  
  // Error/prevention triggers
  { phrase: "never again", category: "error", importance: "critical" },
  { phrase: "root cause was", category: "error", importance: "high" },
  { phrase: "the fix was", category: "error", importance: "high" },
  
  // Preference triggers
  { phrase: "always do", category: "preference", importance: "high" },
  { phrase: "never do", category: "preference", importance: "high" },
  { phrase: "i prefer", category: "preference", importance: "normal" },
  { phrase: "we should always", category: "preference", importance: "high" },
  
  // Architecture/decision triggers
  { phrase: "we decided", category: "architecture", importance: "high" },
  { phrase: "decision made", category: "architecture", importance: "high" },
  { phrase: "going with", category: "architecture", importance: "normal" },
  
  // Explicit memory triggers (highest priority - always critical)
  { phrase: "remember this", category: "note", importance: "critical" },
  { phrase: "don't forget", category: "note", importance: "critical" },
  { phrase: "dont forget", category: "note", importance: "critical" },
  { phrase: "this is important", category: "note", importance: "critical" },
  { phrase: "make a note", category: "note", importance: "critical" },
  { phrase: "for the record", category: "note", importance: "critical" },
  { phrase: "note to self", category: "note", importance: "critical" },
  { phrase: "important:", category: "note", importance: "critical" },
  { phrase: "key point:", category: "note", importance: "high" },
  { phrase: "crucial:", category: "note", importance: "critical" },
];

/**
 * Check message text for keyword triggers and save to memory
 * @param {string} messageText - The user's message text
 * @param {object} event - The event object for pushing response messages
 * @returns {Promise<boolean>} Whether a memory was saved
 */
async function checkAndSaveKeywordTrigger(messageText, event) {
  if (!messageText || typeof messageText !== "string") return false;

  const lower = messageText.toLowerCase();
  
  // Find the first matching trigger
  let matchedTrigger = null;
  let matchIdx = -1;
  
  for (const trigger of KEYWORD_TRIGGERS) {
    const idx = lower.indexOf(trigger.phrase);
    if (idx !== -1) {
      matchedTrigger = trigger;
      matchIdx = idx;
      break;
    }
  }
  
  if (!matchedTrigger) return false;

  // Extract content after the trigger phrase
  let content = messageText.slice(matchIdx + matchedTrigger.phrase.length).replace(/^[:\s]+/, "").trim();
  
  // If content is too short, use the whole message as context
  if (content.length < 5) {
    content = messageText;
  }

  const title = content.slice(0, 80).replace(/["\n]/g, " ").trim();

  const result = await callCortex("remember", {
    title,
    content: content.slice(0, 500),
    category: matchedTrigger.category,
    project: "openclaw",
    scope: "global",
    importance: matchedTrigger.importance,
    tags: `keyword-trigger,openclaw-hook,trigger:${matchedTrigger.phrase.replace(/\s+/g, "-")}`,
  });

  if (result) {
    if (event.messages) {
      event.messages.push(`✅ Saved to Cortex memory (${matchedTrigger.category}): "${title}"`);
    }
    console.log(`[cortex-memory] Keyword trigger "${matchedTrigger.phrase}" saved: ${title}`);
    return true;
  }
  return false;
}

/**
 * Handle message events — check for keyword triggers in user messages
 * This is the FIX: keyword triggers must work on message events, not just commands
 */
async function onMessageKeywordTrigger(event) {
  // Only process user messages
  if (event.role !== "user") return;

  // Get message content - handle both string and array formats
  let messageText = event.content;
  if (Array.isArray(messageText)) {
    const textBlock = messageText.find((c) => c.type === "text");
    messageText = textBlock?.text || "";
  }

  await checkAndSaveKeywordTrigger(messageText, event);
}

/**
 * Handle command events — check for keyword triggers (legacy/fallback)
 */
async function onKeywordTrigger(event) {
  if (event.action === "new" || event.action === "stop" || event.action === "clear" || event.action === "exit") return;

  const context = event.context || {};
  const sessionEntry = context.sessionEntry || {};
  const lastMessage = context.lastUserMessage || sessionEntry.lastUserMessage;
  
  await checkAndSaveKeywordTrigger(lastMessage, event);
}

// ==================== MAIN HANDLER ====================

const cortexMemoryHandler = async (event) => {
  try {
    if (event.type === "command" && event.action === "new") {
      await onSessionEnd(event);
    } else if (event.type === "command" && event.action === "stop") {
      await onSessionStop(event);
    } else if (event.type === "command" && (event.action === "clear" || event.action === "exit")) {
      // Also save on clear/exit - these also end the session context
      await onSessionStop(event);
    } else if (event.type === "agent" && event.action === "bootstrap") {
      await onBootstrap(event);
    } else if (event.type === "message") {
      // FIX: Check for keyword triggers on message events (not just commands)
      await onMessageKeywordTrigger(event);
    } else if (event.type === "command") {
      // Fallback: also check commands for keyword triggers (legacy support)
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
