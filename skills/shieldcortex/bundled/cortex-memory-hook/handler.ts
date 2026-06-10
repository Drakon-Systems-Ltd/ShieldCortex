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
import { fileURLToPath } from "node:url";
import { createOpenClawRuntime } from "./runtime.mjs";

// ==================== SERVER COMMAND RESOLUTION ====================

// Transcript line format shared by the producer (getRecentMessages builds
// `${role}: ${text}`) and the consumer (assistantConversationText filters on
// this prefix). Centralised so a format change can't silently break the filter.
const ASSISTANT_PREFIX = "assistant:";

// Process-global by design: these one-shot notice flags and the load-null
// cache live for the lifetime of the long-lived gateway process. A gateway
// restart is the intended upgrade boundary that resets them.
let _autoMemoryNoticeShown = false;
let _noExtractNoticeShown = false;
const runtime = createOpenClawRuntime({ logPrefix: "[cortex-memory]" });
const loadShieldConfig = runtime.loadShieldConfig;
const callCortex = runtime.callCortex;
// Pure chunker wrapper loader (resolves the local install's hardened
// extractor). Returns null when no local install is resolvable — in which
// case auto-capture is simply skipped (we do NOT regrow the old high-salience
// bespoke-extractor path). The wrapper imports nothing native; persistence
// still flows only through callCortex's mcporter shell-out.
const loadOpenClawExtract = runtime.loadOpenClawExtract;
// Resolves the ShieldCortex package root from the resolved server binary (no
// DB access). Used by selfCheckAndHeal to compare the running hook against the
// packaged source for staleness — warn-only, never re-copies from the gateway.
const resolvePackageRoot = runtime.resolvePackageRoot;

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
 * Parse the scan_skill verdict from its structured markdown output.
 *
 * The MCP `scan_skill` tool emits a fixed `**Safe:** Yes|No` field (see
 * server.ts). We parse THAT exact field rather than substring-matching the
 * whole report. The old `result.includes("unsafe")` was wrong twice over: the
 * report never even prints the literal word "unsafe" (the verdict field is
 * `**Safe:** No`), and any finding `description`/`matchedText` that merely
 * mentions "unsafe" would false-positive a clean file into a security warning.
 *
 * Returns true (unsafe), false (safe), or null (unparseable → indeterminate).
 * @param {string} result
 * @returns {boolean|null}
 */
function parseScanSkillUnsafe(result) {
  if (typeof result !== "string") return null;
  const m = result.match(/\*{0,2}Safe:\*{0,2}\s*(Yes|No)\b/i);
  if (!m) return null;
  return m[1].toLowerCase() === "no";
}

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

        if (parseScanSkillUnsafe(result) === true) {
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

        if (parseScanSkillUnsafe(result) === true) {
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
//
// Extraction is delegated to the hardened centralized chunker via the pure
// `openclaw-extract` wrapper (resolved through runtime.loadOpenClawExtract).
// The old bespoke regex extractor lived here and mislabelled categories,
// produced clause fragments, and minted high/critical-salience memories (the
// "salience wall"). It is intentionally gone — the chunker is now the single
// source of truth for extraction quality and taxonomy. Persistence below is
// uniformly importance:"normal" (0.5, capped well under the wall).

/**
 * Join transcript lines into conversation text, keeping ONLY assistant-authored
 * lines. getRecentMessages returns "role: content" strings for both user and
 * assistant turns; for the first ship we extract from assistant text only
 * (lowest-risk: don't mine user-typed prose). Returns "" if nothing qualifies.
 */
function assistantConversationText(messages: string[]): string {
  const parts: string[] = [];
  for (const msg of messages) {
    if (typeof msg !== "string" || !msg.startsWith(ASSISTANT_PREFIX)) continue;
    const text = msg.slice(ASSISTANT_PREFIX.length).trim();
    if (text.length > 0) parts.push(text);
  }
  return parts.join("\n");
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
              // Producer side of the transcript line format. The assistant
              // prefix is tied to ASSISTANT_PREFIX so the consumer
              // (assistantConversationText) filter can't silently drift.
              const prefix = msg.role === "assistant" ? ASSISTANT_PREFIX : `${msg.role}:`;
              messages.push(`${prefix} ${text}`);
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
 * Shared session-extraction routine for both /new (onSessionEnd) and
 * /stop|/clear|/exit (onSessionStop). They were ~95% identical; the only
 * differences are which sessionEntry to read, the persisted tags +
 * source-identifier, and the user-facing "done" message. Behaviour is
 * otherwise identical — gateway-safe persistence via callCortex only.
 *
 * @param {object} event
 * @param {{ sessionEntry: object, tags: string, sourceIdentifier: string, doneMessage: (n: number) => string }} opts
 */
async function runSessionExtraction(event, { sessionEntry, tags, sourceIdentifier, doneMessage }) {
  if (!(await isOpenClawAutoMemoryEnabled())) {
    if (!_autoMemoryNoticeShown) {
      console.log("[cortex-memory] Auto memory extraction disabled (set openclawAutoMemory=true to enable)");
      _autoMemoryNoticeShown = true;
    }
    return;
  }

  const context = event.context || {};
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

  const conversationText = assistantConversationText(messages);
  if (conversationText.length === 0) {
    console.log("[cortex-memory] No assistant content to extract");
    return;
  }

  const extract = await loadOpenClawExtract();
  if (!extract) {
    if (!_noExtractNoticeShown) {
      console.log("[cortex-memory] No resolvable local install — skipping auto-extraction (no fallback)");
      _noExtractNoticeShown = true;
    }
    return;
  }

  const memories = extract.extractSessionMemories(conversationText);
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
      memoryPurpose: mem.memoryPurpose,
      project: "openclaw",
      scope: "global",
      importance: "normal",
      tags,
      sourceType: "hook",
      sourceIdentifier,
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
    event.messages.push(doneMessage(saved));
  }
}

/**
 * Handle command:new — extract memories from ending session
 */
async function onSessionEnd(event) {
  const context = event.context || {};
  await runSessionExtraction(event, {
    sessionEntry: context.previousSessionEntry || context.sessionEntry || {},
    tags: "auto-extracted,openclaw-hook",
    sourceIdentifier: "openclaw-session-end",
    doneMessage: (n) =>
      `🧠 ShieldCortex: Saved ${n} memor${n === 1 ? "y" : "ies"} from this session`,
  });
}

/**
 * Handle command:stop — extract memories before session ends
 * This fires when user explicitly calls /stop
 */
async function onSessionStop(event) {
  const context = event.context || {};
  await runSessionExtraction(event, {
    sessionEntry: context.sessionEntry || {},
    tags: "auto-extracted,openclaw-hook,session-stop",
    sourceIdentifier: "openclaw-session-stop",
    doneMessage: (n) =>
      `🧠 ShieldCortex: Saved ${n} memor${n === 1 ? "y" : "ies"} before session end`,
  });
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
 * Keyword trigger phrases. Order matters: more specific triggers should come
 * first (the first match wins). Each entry carries the AUTHORITATIVE chunker
 * extractorType for its phrase — the trigger phrase is the classification
 * signal ("the fix was" → error-fix, "i prefer" → preference), so we pass it
 * straight into extractKeywordMemory rather than re-guessing from content
 * (which collapsed everything to `note`). Salience stays uniform across all
 * triggers (importance:"normal" → 0.5, capped well under the wall); the old
 * per-trigger category/importance fields are gone — they minted high/critical
 * salience and mislabelled categories.
 *
 * extractorType must be one of the chunker's keys (EXTRACTOR_TO_CATEGORY /
 * EXTRACTOR_TO_PURPOSE in extract-memorable-segments.mjs):
 *   decision | error-fix | learning | architecture | preference | important-note
 */
const KEYWORD_TRIGGERS = [
  // Learning triggers
  { phrase: "lesson learned", extractorType: "learning" },
  { phrase: "i learned", extractorType: "learning" },
  { phrase: "til:", extractorType: "learning" },
  { phrase: "today i learned", extractorType: "learning" },

  // Error/prevention triggers
  { phrase: "never again", extractorType: "error-fix" },
  { phrase: "root cause was", extractorType: "error-fix" },
  { phrase: "the fix was", extractorType: "error-fix" },

  // Preference triggers
  { phrase: "always do", extractorType: "preference" },
  { phrase: "never do", extractorType: "preference" },
  { phrase: "i prefer", extractorType: "preference" },
  { phrase: "we should always", extractorType: "preference" },

  // Architecture/decision triggers
  { phrase: "we decided", extractorType: "decision" },
  { phrase: "decision made", extractorType: "decision" },
  { phrase: "going with", extractorType: "decision" },

  // Explicit memory triggers (generic — important-note)
  { phrase: "remember this", extractorType: "important-note" },
  { phrase: "don't forget", extractorType: "important-note" },
  { phrase: "dont forget", extractorType: "important-note" },
  { phrase: "this is important", extractorType: "important-note" },
  { phrase: "make a note", extractorType: "important-note" },
  { phrase: "for the record", extractorType: "important-note" },
  { phrase: "note to self", extractorType: "important-note" },
  { phrase: "important:", extractorType: "important-note" },
  { phrase: "key point:", extractorType: "important-note" },
  { phrase: "crucial:", extractorType: "important-note" },
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

  // Route through the chunker wrapper: applies the rejection corpus (drops true
  // malformations) and derives category + memory_purpose from the chunker's
  // taxonomy. Explicit keyword intent BYPASSES the salience threshold (B8) —
  // the wrapper returns a memory for any non-malformed content.
  const extract = await loadOpenClawExtract();
  if (!extract) {
    if (!_noExtractNoticeShown) {
      console.log("[cortex-memory] No resolvable local install — skipping keyword capture (no fallback)");
      _noExtractNoticeShown = true;
    }
    return false;
  }

  // The trigger phrase carries the authoritative classification — pass its
  // extractorType so the wrapper pins category/purpose instead of re-guessing
  // from content (which collapsed typed triggers to `note`).
  const candidates = extract.extractKeywordMemory(content, matchedTrigger.extractorType);
  if (candidates.length === 0) {
    console.log(`[cortex-memory] Keyword trigger skipped (rejected as malformed): "${matchedTrigger.phrase}"`);
    return false;
  }
  const mem = candidates[0];

  // Deduplicate via shared novelty gate (same gate used by session-end/stop extraction)
  const noveltyGate = await getSharedNoveltyGate();
  const novelty = noveltyGate.inspect(mem.content);
  if (!novelty.allow) {
    console.log(`[cortex-memory] Keyword trigger skipped (duplicate): "${mem.title}"`);
    // M2: an EXPLICIT "remember this" must never be silently dropped — make the
    // dedup decision visible even though we skip the duplicate store.
    if (event.messages) {
      event.messages.push(`🧠 Already remembered.`);
    }
    return false;
  }

  const result = await callCortex("remember", {
    title: mem.title,
    content: mem.content,
    category: mem.category,
    memoryPurpose: mem.memoryPurpose,
    project: "openclaw",
    scope: "global",
    importance: "normal",
    tags: `keyword-trigger,openclaw-hook,trigger:${matchedTrigger.phrase.replace(/\s+/g, "-")}`,
    sourceType: "hook",
    sourceIdentifier: `openclaw-keyword:${matchedTrigger.phrase.replace(/\s+/g, "-")}`,
  });

  if (result) {
    noveltyGate.remember({ content: mem.content, title: mem.title, category: mem.category }, novelty);
    await noveltyGate.flush();
    if (event.messages) {
      event.messages.push(`✅ Saved to Cortex memory (${mem.category}): "${mem.title}"`);
    }
    console.log(`[cortex-memory] Keyword trigger "${matchedTrigger.phrase}" saved: ${mem.title}`);
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

    // Parse the structured `Found N memor(y|ies):` header (recall.ts) at the
    // START of the result, rather than substring-matching "Found" anywhere — a
    // recalled memory's own content can contain "Found" and the old
    // `!result.includes("Found 0")` clause was dead (empty = "No memories
    // found...", never "Found 0"). Surface only on N >= 1.
    const recallMatch = typeof result === "string" ? result.match(/^Found\s+(\d+)\s+memor/m) : null;
    if (recallMatch && Number(recallMatch[1]) >= 1) {
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

    // Where am I running from? Use fileURLToPath, not URL.pathname — the latter
    // does NOT decode percent-encoding, so an install path with spaces/special
    // chars would yield a path that fails every downstream fs read (staleness
    // comparison + self-heal copy below).
    const myDir = path.dirname(fileURLToPath(import.meta.url));

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

      // Task 6b: staleness signal. The hook is installed by file-copy, so a
      // package update can leave THIS running copy behind the packaged source
      // (e.g. an OpenClaw version-lag where the global package is newer than
      // the hook last copied into ~/.openclaw). Compare our running files
      // against the package's hooks/openclaw/cortex-memory source by content.
      //
      // WARN-ONLY by design — we do NOT re-copy from inside the long-lived
      // gateway. Re-copying would overwrite the very files this process is
      // executing from, racing any concurrently-bootstrapping agent's jiti
      // load. The real auto-refresh happens in the npm postinstall; the
      // user-invoked repair is `shieldcortex openclaw install` (also surfaced
      // by `shieldcortex doctor`). No DB, no persistence — pure fs reads.
      try {
        const root = await resolvePackageRoot();
        if (root) {
          const sourceDir = path.join(root, "hooks", "openclaw", "cortex-memory");
          const hookFiles = ["HOOK.md", "handler.ts", "runtime.mjs"];
          let stale = false;
          for (const file of hookFiles) {
            const srcPath = path.join(sourceDir, file);
            const minePath = path.join(myDir, file);
            try {
              const srcBuf = await fs.readFile(srcPath);
              const mineBuf = await fs.readFile(minePath);
              if (!srcBuf.equals(mineBuf)) { stale = true; break; }
            } catch {
              // Source file missing/unreadable (can't prove staleness for it)
              // or our own file unreadable — don't flip `stale` on a read error.
              // DELIBERATE ASYMMETRY with src/setup/openclaw.ts `hookFilesStale`,
              // which returns `true` (stale) on a read error so the doctor nags
              // on a broken install. Here we stay quiet: this runs inside the
              // long-lived gateway, where a transient read error must not emit a
              // spurious bootstrap "out of date" warning. Keep them divergent.
            }
          }
          if (stale) {
            console.warn(
              "[cortex-memory] Installed hook is OUT OF DATE — it differs from the " +
              "packaged version. Run `shieldcortex openclaw install` to refresh it " +
              "(then restart the gateway) so memory capture uses the latest logic."
            );
          }
        }
      } catch { /* staleness check is best-effort — never blocks bootstrap */ }

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
