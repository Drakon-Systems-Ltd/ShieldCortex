/**
 * Cortex Memory Hook — Persistent brain-like memory for OpenClaw
 *
 * Integrates ShieldCortex MCP server via mcporter to provide:
 * - Auto-extraction of important session content on /new
 * - Context injection on agent bootstrap
 * - Keyword-triggered memory saves
 */
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { createOpenClawRuntime } from "./runtime.mjs";

// ==================== SERVER COMMAND RESOLUTION ====================

let _autoMemoryNoticeShown = false;
const runtime = createOpenClawRuntime({ logPrefix: "[cortex-memory]" });
const loadShieldConfig = runtime.loadShieldConfig;
const callCortex = runtime.callCortex;

async function isOpenClawAutoMemoryEnabled() {
  const config = await loadShieldConfig();
  return runtime.isOpenClawAutoMemoryEnabled(config);
}

async function isProactiveRecallEnabled() {
  const config = await loadShieldConfig();
  return config?.proactiveRecall === true; // Default: false since v4.11.0 (opt-in)
}

// ==================== NOVELTY / DEDUPE GATE ====================

const NOVELTY_CACHE_FILE = path.join(homedir(), ".shieldcortex", "openclaw-memory-cache.json");
const DEFAULT_NOVELTY_THRESHOLD = 0.88;
const DEFAULT_MAX_RECENT = 300;
const MIN_NOVELTY_CHARS = 40;

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
    if (i < words.length - 1) {
      set.add(hashToken(`${words[i]}_${words[i + 1]}`));
    }
  }

  return Array.from(set).slice(0, 200);
}

function jaccardSimilarity(a, b) {
  if (a.size === 0 || b.size === 0) return 0;
  let intersection = 0;
  for (const item of a) {
    if (b.has(item)) intersection++;
  }
  const union = a.size + b.size - intersection;
  return union === 0 ? 0 : intersection / union;
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

async function getNoveltyConfig() {
  const config = await loadShieldConfig();
  const rawThreshold = Number(config?.openclawAutoMemoryNoveltyThreshold);
  const rawMaxRecent = Number(config?.openclawAutoMemoryMaxRecent);
  return {
    enabled: config?.openclawAutoMemoryDedupe !== false,
    threshold: Number.isFinite(rawThreshold)
      ? clamp(rawThreshold, 0.6, 0.99)
      : DEFAULT_NOVELTY_THRESHOLD,
    maxRecent: Number.isFinite(rawMaxRecent)
      ? Math.floor(clamp(rawMaxRecent, 50, 1000))
      : DEFAULT_MAX_RECENT,
  };
}

async function loadNoveltyCache(maxRecent) {
  try {
    const raw = JSON.parse(await fs.readFile(NOVELTY_CACHE_FILE, "utf-8"));
    if (!Array.isArray(raw)) return [];
    return raw
      .filter((entry) => entry && typeof entry.hash === "string" && Array.isArray(entry.tokenHashes))
      .slice(0, maxRecent);
  } catch {
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
    return { allow: true, normalized, contentHash: null, tokenHashes: [] };
  }

  const contentHash = createHash("sha256").update(normalized).digest("hex").slice(0, 24);
  if (entries.some((entry) => entry.hash === contentHash)) {
    return { allow: false, normalized, contentHash, tokenHashes: [], reason: "exact duplicate" };
  }

  const tokenHashes = buildTokenHashes(normalized);
  const currentSet = new Set(tokenHashes);
  let bestSimilarity = 0;

  for (const entry of entries) {
    const score = jaccardSimilarity(currentSet, new Set(entry.tokenHashes || []));
    if (score > bestSimilarity) bestSimilarity = score;
    if (score >= threshold) {
      return {
        allow: false,
        normalized,
        contentHash,
        tokenHashes,
        reason: `near duplicate (similarity ${score.toFixed(2)})`,
      };
    }
  }

  return { allow: true, normalized, contentHash, tokenHashes, bestSimilarity };
}

async function createNoveltyGate() {
  const cfg = await getNoveltyConfig();
  const entries = cfg.enabled ? await loadNoveltyCache(cfg.maxRecent) : [];
  let dirty = false;

  return {
    enabled: cfg.enabled,
    inspect(content) {
      if (!cfg.enabled) return { allow: true, reason: null };
      return inspectNovelty(content, entries, cfg.threshold);
    },
    remember(memory, novelty) {
      if (!cfg.enabled) return;
      if (!novelty?.contentHash || !Array.isArray(novelty?.tokenHashes)) return;
      entries.unshift({
        hash: novelty.contentHash,
        tokenHashes: novelty.tokenHashes,
        title: String(memory?.title || "").slice(0, 120),
        category: String(memory?.category || "note"),
        createdAt: new Date().toISOString(),
      });
      if (entries.length > cfg.maxRecent) entries.length = cfg.maxRecent;
      dirty = true;
    },
    async flush() {
      if (!cfg.enabled || !dirty) return;
      await saveNoveltyCache(entries);
    },
  };
}

// ==================== SHARED NOVELTY GATE ====================

/**
 * Process-level shared novelty gate for ALL save paths (session-end, session-stop, keyword triggers).
 * Avoids redundant disk round-trips and ensures cross-path deduplication.
 */
let _sharedNoveltyGate = null;

async function getSharedNoveltyGate() {
  if (!_sharedNoveltyGate) {
    _sharedNoveltyGate = await createNoveltyGate();
  }
  return _sharedNoveltyGate;
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

      // Skip self and internal hooks to avoid false positives
      if (entry.name === 'cortex-memory' || entry.name === 'internal') continue;

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
    /\b(?:I|we|you\s+should)\s+(?:always|never)\b/i,
    /\b(?:always\s+use|never\s+use|never\s+commit)\b/i,
    /\bprefer(?:\s+to)?\s+\w+/i,
    /\bshould\s+always\b/i,
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
  if (!(await isOpenClawAutoMemoryEnabled())) {
    if (!_autoMemoryNoticeShown) {
      console.log("[cortex-memory] Auto memory extraction disabled (set openclawAutoMemory=true to enable)");
      _autoMemoryNoticeShown = true;
    }
    return;
  }

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

  const noveltyGate = await getSharedNoveltyGate();
  let saved = 0;
  let skipped = 0;
  for (const mem of memories) {
    const novelty = noveltyGate.inspect(mem.content);
    if (!novelty.allow) {
      skipped++;
      continue;
    }

    const result = await callCortex("remember", {
      title: mem.title,
      content: mem.content,
      category: mem.category,
      project: "openclaw",
      scope: "global",
      importance: "high",
      tags: "auto-extracted,openclaw-hook",
      sourceType: "hook",
      sourceIdentifier: "openclaw-session-end",
      workspaceDir: context.workspaceDir || "",
    });
    if (result) {
      saved++;
      noveltyGate.remember(mem, novelty);
    }
  }
  await noveltyGate.flush();

  console.log(`[cortex-memory] Saved ${saved}/${memories.length} memories from session (${skipped} skipped as duplicates)`);

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
  if (!(await isOpenClawAutoMemoryEnabled())) {
    if (!_autoMemoryNoticeShown) {
      console.log("[cortex-memory] Auto memory extraction disabled (set openclawAutoMemory=true to enable)");
      _autoMemoryNoticeShown = true;
    }
    return;
  }

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

  const noveltyGate = await getSharedNoveltyGate();
  let saved = 0;
  let skipped = 0;
  for (const mem of memories) {
    const novelty = noveltyGate.inspect(mem.content);
    if (!novelty.allow) {
      skipped++;
      continue;
    }

    const result = await callCortex("remember", {
      title: mem.title,
      content: mem.content,
      category: mem.category,
      project: "openclaw",
      scope: "global",
      importance: "high",
      tags: "auto-extracted,openclaw-hook,session-stop",
      sourceType: "hook",
      sourceIdentifier: "openclaw-session-stop",
      workspaceDir: context.workspaceDir || "",
    });
    if (result) {
      saved++;
      noveltyGate.remember(mem, novelty);
    }
  }
  await noveltyGate.flush();

  console.log(`[cortex-memory] Saved ${saved}/${memories.length} memories on session stop (${skipped} skipped as duplicates)`);
  
  // Provide visible feedback to user
  if (saved > 0 && event.messages) {
    event.messages.push(`🧠 ShieldCortex: Saved ${saved} memor${saved === 1 ? 'y' : 'ies'} before session end`);
  }
}

/**
 * Handle agent:bootstrap — inject past context into agent
 *
 * NOTE: Context injection disabled as of v2026.2.26.
 * OpenClaw's native Memory Search now handles context recall at bootstrap.
 * The old get_context injection caused ~40x duplication of CORTEX_MEMORY.md
 * in the system prompt, eating the entire context window.
 * Hook remains active for keyword triggers + session-end auto-save.
 */
async function onBootstrap(event) {
  const context = event.context || {};
  if (!Array.isArray(context.bootstrapFiles)) return;

  const wsDir = context.workspaceDir || event?.workspaceDir || "/tmp";

  // Context injection removed — native OpenClaw Memory Search handles this now.

  // Scan installed hooks for threats (still useful)
  try {
    const threats = await scanInstalledHooks();
    if (threats.length > 0) {
      const warnings = threats.map(t => `- ${t.hookName}: ${t.threat}`).join("\n");
      context.bootstrapFiles.push({
        name: "SHIELDCORTEX_WARNINGS.md",
        path: path.join(wsDir, "SHIELDCORTEX_WARNINGS.md"),
        content: `# ShieldCortex Security Warning\n\nThe following installed hooks have been flagged as potentially unsafe:\n\n${warnings}\n\nConsider running: \`shieldcortex scan-skills\` for a detailed report.`,
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

  // Deduplicate via shared novelty gate (same gate used by session-end/stop extraction)
  const noveltyGate = await getSharedNoveltyGate();
  const novelty = noveltyGate.inspect(content.slice(0, 500));
  if (!novelty.allow) {
    console.log(`[cortex-memory] Keyword trigger skipped (duplicate): "${title}"`);
    return false;
  }

  const result = await callCortex("remember", {
    title,
    content: content.slice(0, 500),
    category: matchedTrigger.category,
    project: "openclaw",
    scope: "global",
    importance: matchedTrigger.importance,
    tags: `keyword-trigger,openclaw-hook,trigger:${matchedTrigger.phrase.replace(/\s+/g, "-")}`,
    sourceType: "hook",
    sourceIdentifier: `openclaw-keyword:${matchedTrigger.phrase.replace(/\s+/g, "-")}`,
  });

  if (result) {
    noveltyGate.remember({ content: content.slice(0, 500), title, category: matchedTrigger.category }, novelty);
    await noveltyGate.flush();
    if (event.messages) {
      event.messages.push(`✅ Saved to Cortex memory (${matchedTrigger.category}): "${title}"`);
    }
    console.log(`[cortex-memory] Keyword trigger "${matchedTrigger.phrase}" saved: ${title}`);
    return true;
  }
  return false;
}

/**
 * Proactive recall — query memory on every user message and surface relevant context
 */
async function proactiveRecall(event) {
  if (event.role !== "user") return;
  if (!(await isProactiveRecallEnabled())) return;

  let messageText = event.content;
  if (Array.isArray(messageText)) {
    const textBlock = messageText.find((c) => c.type === "text");
    messageText = textBlock?.text || "";
  }

  if (!messageText || messageText.length < 8) return;
  if (/^(yes|no|ok|sure|do it|go|send it|y|n|yep|nope)\s*[.!?]?\s*$/i.test(messageText.trim())) return;

  try {
    const result = await callCortex("recall", {
      query: messageText.slice(0, 200),
      limit: 5,
      project: "*",
    });

    if (result && typeof result === "string" && result.includes("Found") && !result.includes("Found 0")) {
      if (event.messages) {
        event.messages.push(`🧠 ${result}`);
      }
    }
  } catch {
    // Proactive recall is best-effort — never block message processing
  }
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

// ==================== SELF-CHECK & SELF-HEAL ====================

/**
 * One-shot self-check that runs on first bootstrap per process.
 * Detects legacy hook paths and attempts self-heal by copying files.
 * 
 * Safety: 
 * - _selfCheckDone flag prevents re-runs (no loops)
 * - All fs ops are sync-safe copies (no recursive watchers, no intervals)
 * - Fails silently on any error — never blocks bootstrap
 */
let _selfCheckDone = false;

async function selfCheckAndHeal(event) {
  if (_selfCheckDone) return;
  _selfCheckDone = true; // Set immediately to prevent re-entry

  try {
    const path = await import("node:path");
    const { homedir } = await import("node:os");
    const home = homedir();

    // Where am I running from?
    const myDir = path.dirname(new URL(import.meta.url).pathname);

    // Expected locations (newest first)
    const expectedDirs = [
      path.join(home, ".openclaw", "hooks", "internal", "cortex-memory"),
      path.join(home, ".openclaw", "hooks", "cortex-memory"),
    ];

    const isInExpectedLocation = expectedDirs.some(d => myDir.startsWith(d));

    if (isInExpectedLocation) {
      // Check for stale legacy copies that could cause confusion
      const legacyDirs = [
        path.join(home, ".clawdbot", "hooks", "cortex-memory"),
        path.join(home, ".clawdbot", "hooks", "internal", "cortex-memory"),
      ];

      // Only check real directories, not symlinks pointing back to .openclaw
      const clawdbotBase = path.join(home, ".clawdbot");
      let isSymlink = false;
      try {
        const stat = await fs.lstat(clawdbotBase);
        isSymlink = stat.isSymbolicLink();
      } catch { /* doesn't exist */ }

      if (!isSymlink) {
        for (const legacyDir of legacyDirs) {
          try {
            await fs.access(legacyDir);
            // Legacy dir exists and isn't a symlink — clean it up
            await fs.rm(legacyDir, { recursive: true });
            console.log(`[cortex-memory] Self-heal: removed stale legacy hook at ${legacyDir}`);
          } catch { /* doesn't exist — good */ }
        }
      }

      return; // All good
    }

    // We're running from an unexpected location — try to copy ourselves to the right place
    const targetDir = expectedDirs[0]; // prefer hooks/internal/cortex-memory
    const targetParent = path.dirname(targetDir);

    // Ensure parent exists
    await fs.mkdir(targetParent, { recursive: true });
    await fs.mkdir(targetDir, { recursive: true });

    // Copy our files to the expected location
    const filesToCopy = ["HOOK.md", "handler.ts"];
    let copiedCount = 0;

    for (const file of filesToCopy) {
      const src = path.join(myDir, file);
      const dest = path.join(targetDir, file);
      try {
        await fs.access(src);
        await fs.copyFile(src, dest);
        copiedCount++;
      } catch { /* source file missing — skip */ }
    }

    if (copiedCount > 0) {
      console.log(`[cortex-memory] Self-heal: copied ${copiedCount} file(s) to ${targetDir}`);
      console.log(`[cortex-memory] Hook will load from correct path on next restart`);

      // Inject a warning into bootstrap context so the agent knows
      if (event?.context?.bootstrapFiles && Array.isArray(event.context.bootstrapFiles)) {
        const wsDir = event?.context?.workspaceDir || event?.workspaceDir || "/tmp";
        event.context.bootstrapFiles.push({
          name: "SHIELDCORTEX_HOOK_MIGRATED.md",
          path: path.join(wsDir, "SHIELDCORTEX_HOOK_MIGRATED.md"),
          content: `# ShieldCortex Hook Self-Healed\n\nThe cortex-memory hook was running from an unexpected path (${myDir}).\nIt has been copied to ${targetDir}.\nA gateway restart will pick up the new location.\n\nNo action needed — this is informational.`,
        });
      }
    }
  } catch (err) {
    // Self-check must NEVER break the hook — fail silently
    console.warn("[cortex-memory] Self-check failed (non-fatal):", err instanceof Error ? err.message : String(err));
  }
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
      await selfCheckAndHeal(event);
      await onBootstrap(event);
    } else if (event.type === "message") {
      await proactiveRecall(event);
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
