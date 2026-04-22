# ShieldCortex — Hooks & Defaults Audit

**Date:** 2026-04-22
**Trigger:** Michael removed ShieldCortex from his three production agents (Tars, Friday, Jarvis) because they ran measurably better without it. Before we ship more patches on top of the current shape, audit what we actually install, what each piece costs, and which defaults to flip for v4.11.0.
**Scope:** Every on-install auto-behaviour. Claude Code hooks, OpenClaw plugin, CLAUDE.md injection, MCP registration. Does **not** cover defensive features that only fire on explicit CLI invocation (`scan`, `xray`, `env scan`, `consolidate`, `iron-dome activate`) — those pay no per-turn tax.

---

## 1. Inventory — what `shieldcortex install` / `quickstart` defaults to

| # | Auto-behaviour | Where it lives | On by default | Fires when |
|---|---|---|---|---|
| 1 | Claude Code `SessionStart` hook | `scripts/session-start-hook.mjs` | **Yes** | Fresh session start only (silent on resume/compact/clear since v4.10.5) |
| 2 | Claude Code `PreCompact` hook | `scripts/pre-compact-hook.mjs` | **Yes** | Before every context compaction |
| 3 | Claude Code `UserPromptSubmit` hook | `scripts/prompt-recall-hook.mjs` | **Yes** | Every user message |
| 4 | Claude Code `SessionEnd` hook | `scripts/session-end-hook.mjs` | No (actively removed by installer) | — crashed OpenClaw agents, disabled |
| 5 | Claude Code `Stop` hook | `scripts/stop-hook.mjs` | No (opt-in via `--stopHook`) | End of assistant turn |
| 6 | Static block in `~/.claude/CLAUDE.md` | `src/setup/claude-md.ts` | Yes (one-time) | Install; refreshed if signature drifts (v4.10.7) |
| 7 | MCP server registration in `~/.claude.json` | `src/setup/claude-md.ts` | Yes (one-time) | Install |
| 8 | OpenClaw `cortex-memory` hook | `hooks/openclaw/cortex-memory/` | Yes if OpenClaw detected | `agent:bootstrap`, `message`, `session:end`, `command` |
| 9 | OpenClaw `shieldcortex-realtime` plugin — `llm_input` | `plugins/openclaw/index.ts` | Yes if plugin installed | Every LLM input (fire-and-forget) |
| 10 | OpenClaw plugin — `llm_output` auto-extraction | `plugins/openclaw/index.ts` | **No** (opt-in via `openclawAutoMemory: true`) | Every LLM output (if enabled) |
| 11 | OpenClaw plugin — `before_tool_call` interceptor | `plugins/openclaw/interceptor.ts` | Yes if defence module loads | Every `remember` / `mcp__memory__remember` tool call |
| 12 | OpenClaw plugin — `session_end` cache cleanup | `plugins/openclaw/index.ts` | Yes | Session end |

---

## 2. Per-behaviour verdicts

Each row: what it does → what it costs → what it gains → honest verdict. Evidence from reading the scripts and from v4.10.4–v4.10.7 bug history.

### 2.1 SessionStart hook (prompt-recall-hook.mjs)

- **Cost per fire**: 200–500ms sync + 500–2000 tokens injected (preamble + up to 15 memories).
- **Fires**: fresh `source=startup` only. Resume/compact/clear are silent since v4.10.5.
- **Gains**: surfaces project context at session boot for humans who just opened the agent.
- **Failure history**: banner re-pasted every resume in v4.10.4 (catastrophic context pollution); broken entirely in v4.10.5 due to `scripts/lib` packaging miss. Fixed in v4.10.6+.
- **Honest verdict**: **Useful on human-initiated interactive sessions. Net-negative on agent-spawned sub-sessions** (which fire `startup` on every sub-agent boot, eating 2000 tokens per spawn). Fleet agents that spawn sub-agents hit this repeatedly. Token cost 500–2000 per spawn is the big number. Cannot distinguish "human opened Claude Code" from "parent agent spawned child agent" from the hook data.
- **Recommended default**: **Remain on**, but flip the **full preamble** (13-line instruction block) to off. Ship only the memory list, no prescriptive instructions. Consider: add a `sessionStart.onlyIfInteractive` flag that reads `process.stdin.isTTY` or an env signal from parent agent to skip sub-agent spawns.

### 2.2 PreCompact hook (pre-compact-hook.mjs)

- **Cost per fire**: 100–500ms sync + ~200 tokens of reminder text output to stdout every fire. Creates 0–5 memories.
- **Fires**: before every context compaction (4–8× per productive day).
- **Gains**: auto-extracts high-salience content before it's lost. Theoretically the most valuable hook.
- **Signal-to-noise** (from extraction thresholds, pattern rules):
  - Architecture-keyword threshold 0.28 ("created", "implemented", "refactored") catches all past-tense phrases. High false-positive rate on casual speech.
  - Estimated precision: ~1 valuable memory per 20 extractions in typical use (5%).
  - Over 4–8 compactions/day: 4–16 auto-memories/day, of which 0–2 are signal, 2–8 are noise.
- **Honest verdict**: **Net-negative under current thresholds**. The memory store fills with noise, which then hurts recall precision downstream (see §2.3). Auto-extraction is only worth it if the signal-to-noise ratio is much better than 5%. The PreCompact reminder output (200 tokens every compaction) also eats context.
- **Recommended default**: **Raise all category thresholds by +0.1** (architecture 0.28 → 0.38, error 0.30 → 0.40). Set `MAX_AUTO_MEMORIES = 2` (down from 5). Remove the stdout reminder text entirely — the memories themselves are the signal; telling the model about them is redundant noise. Or: flip to opt-in.

### 2.3 UserPromptSubmit hook — prompt-recall (prompt-recall-hook.mjs)

- **Cost per fire**: 200–500ms **synchronous** (blocks the model from starting) + 100–400 tokens injected via `hookSpecificOutput.additionalContext` per turn.
- **Fires**: every user message ≥8 characters. Skips trivial ("yes", "ok", "do it").
- **Gains**: injects up to 5 relevant memories before the model sees the prompt. Designed to reduce "I told you this yesterday" moments.
- **The fleet problem**: For a programmatic agent running 100+ turns in a work loop, 200–500ms per turn is **20–50 seconds of cumulative latency per long session**. If recall returns noise (see §2.2), you also pay tokens for irrelevant context.
- **Honest verdict**: **This is the main culprit for why the fleet runs better without ShieldCortex**. The per-turn tax is real and measurable. For a deep-work human session it might break even. For an agent loop doing fast iteration, it's pure drag. Low-quality auto-extracted memories (§2.2) compound the problem — the recall injects junk which pollutes context, which makes the model less accurate, which costs more turns to fix, which fires more recalls.
- **Recommended default**: **Flip to opt-in**. Ship disabled. Users with deep interactive sessions can enable via `config.proactiveRecall = true`. Keep the code — it's useful for the specific use case it was designed for. Don't keep the default.

### 2.4 SessionEnd hook

- Already removed from defaults (installer actively strips it out). Crashed OpenClaw agents when fired on already-terminated sessions.
- **Verdict**: correct status quo. No change.

### 2.5 Stop hook (stop-hook.mjs)

- Opt-in only. Exits with code 2 to block the stop and force a `remember` call.
- Known failure: fires on narrative keywords ("the bug was fixed by...") not just Claude's own decisions → false-positive forced writes.
- **Verdict**: leave as opt-in, fix the keyword detection before recommending it to anyone. Lowest priority.

### 2.6 CLAUDE.md static block (claude-md.ts)

- Rewritten in v4.10.7 to lead with automatic capture and frame manual tool calls as conditional. No per-turn cost.
- **Verdict**: already fixed. Ship as-is.

### 2.7 MCP server registration (~/.claude.json)

- One-time config write. Registers `memory` server pointing at `npx -y shieldcortex`.
- `npx -y` is slow on cold start (hits npm cache).
- **Verdict**: no per-turn cost. Leave on by default. Minor polish opportunity: prefer the installed global binary path over `npx -y` when detected. Not urgent.

### 2.8 OpenClaw cortex-memory hook (hooks/openclaw/cortex-memory/)

- **agent:bootstrap**: self-heal + hook-scan only. Former context-injection bloat removed in v2026.2.26 (used to 40× duplicate CORTEX_MEMORY.md).
- **message**: fires `proactiveRecall()` + keyword-trigger check on every message (same FTS query as §2.3, duplicated here for OpenClaw).
- **session:end**: no-op after SessionEnd hook removed.
- **Verdict**: the message-event recall is the same tax as §2.3 duplicated. If we flip §2.3 to opt-in, do the same here for consistency. The bootstrap scan is cheap and useful, keep it.

### 2.9 OpenClaw plugin — llm_input scan (plugins/openclaw/index.ts)

- **Cost per fire**: ~50ms **async** fire-and-forget. Doesn't block the model.
- **Gains**: real-time threat scan on every LLM input. Defensive value.
- **Verdict**: **Keep on by default**. Low cost, clear defensive value, async so doesn't pay latency tax. This is the good stuff.

### 2.10 OpenClaw plugin — llm_output auto-extraction

- Already opt-in (default false). 600–800ms async cost when enabled.
- **Verdict**: correct status quo. No change.

### 2.11 OpenClaw plugin — before_tool_call interceptor (interceptor.ts)

- **Cost per fire**: **1–5 seconds synchronous** when the defence pipeline runs. Blocks tool execution.
- **Fires**: every `remember` / `mcp__memory__remember` tool call (not all tool calls — only memory writes).
- **Gains**: genuine defensive value — stops poisoned memories from being written.
- **Risk**: 1–5s sync latency on legitimate memory writes. For a fleet agent that writes memories frequently, this is the **second-biggest cost after prompt-recall**. The deny-cache (2hr TTL) mitigates repeat hits but not first-fires.
- **Failure mode**: if defence module import fails, interceptor silently disables and allows everything — fail-open.
- **Honest verdict**: **Keep on by default but fix the latency**. The pipeline subprocess call (spawn + mcporter + binary lookup) is where the seconds go. Options: (a) only run the fast synchronous layers (input sanitisation, pattern detection, credential scan) synchronously, move semantic/behavioural layers to post-write audit; (b) cache compiled patterns in-process instead of spawning. Either cuts 1–5s to <100ms.
- **Recommended default**: **Keep on, but set `interceptor.severityActions.critical = 'log'`** by default (not `require_approval`). Preserve the defence (critical threats still deny via `failurePolicy`), drop the human-approval prompt by default. Users who want the block-and-prompt flow opt in.

### 2.12 OpenClaw plugin — session_end cleanup

- Cache cleanup only. <1ms.
- **Verdict**: no change.

---

## 3. Worst-case single-turn tax (current defaults)

For one user → assistant exchange where the model also calls one `remember` tool:

| Stage | Sync cost | Async cost | Tokens injected |
|---|---|---|---|
| UserPromptSubmit recall (§2.3) | **200–500ms** | — | 100–400 |
| OpenClaw message-event recall (§2.8) | — | background | 100–400 (duplicate) |
| llm_input scan (§2.9) | — | 50ms | 0 |
| Model generates response | (LLM) | — | — |
| llm_output extraction (§2.10, default off) | — | 0 | 0 |
| before_tool_call interceptor (§2.11) | **1–5s** (first fire) / <10ms (cache hit) | — | 0 |
| **Total sync** | **200ms–5.5s** | 50ms | 200–800 |

On a 100-turn fleet workload with occasional tool calls: **20–50s** cumulative latency plus **20k–80k tokens** of recall context — most of which, per §2.2, is noise.

---

## 4. On session start (current defaults, `source=startup`)

| Stage | Sync cost | Tokens injected |
|---|---|---|
| SessionStart hook (§2.1) | 200–500ms | **500–2000** |
| OpenClaw bootstrap self-heal + hook-scan (§2.8) | <50ms + async | 0–100 (only if threats found) |
| First-message prompt-recall (§2.3) | 200–500ms | 100–400 |
| **Total** | **400ms–1s** | **600–2500** |

For a fleet that spawns sub-agents frequently, each spawn pays this.

---

## 5. Proposed v4.11.0 default changes

Ranked by impact on the fleet-agent case. Each is independently shippable.

| Priority | Change | What it fixes | Breaking for existing users? |
|---|---|---|---|
| **P0** | `proactiveRecall` default: `true` → `false` | Main per-turn tax gone. Recall stays available as opt-in. | Yes — users expecting auto-recall lose it until they set the flag. Mitigate with CHANGELOG callout + one-time notice on `shieldcortex update`. |
| **P0** | Interceptor `severityActions.critical` default: `require_approval` → `log`; `high` → `warn` | Drops the 1–5s pipeline block on memory writes. `failurePolicy` still denies critical threats. | Yes — less aggressive. But defensive value preserved, UX improves. |
| **P1** | PreCompact: raise all category thresholds +0.1, drop `MAX_AUTO_MEMORIES` 5 → 2, remove stdout reminder text | Fewer noisy auto-memories → recall quality goes up for users who opt back into §2.3. | Mildly — less noise accumulates. |
| **P1** | SessionStart: full-preamble mode removed entirely; only memory list injected; 15 → 5 memories max | 500–2000 token preamble cost drops to 100–400. | Yes — users with `preamble: "full"` lose the instruction block. |
| **P2** | OpenClaw message-event recall follows §2.3 default (off by default) | Consistency, no duplicate recall tax. | Same as §2.3. |
| **P2** | Stop-hook keyword detection rewrite | Opt-in feature becomes less buggy. | No (opt-in). |
| **P3** | MCP server registration: prefer installed global binary over `npx -y` when detected | Faster cold starts. | No. |

### What stays on by default

- Defence pipeline at `runDefencePipeline()` call sites (scan, firewall, at memory write time) — the core product.
- Iron Dome action gates.
- Environment Firewall (`env scan`).
- X-Ray scanner (`xray`).
- OpenClaw `llm_input` scan (§2.9) — cheap + clear value.
- Tool call interceptor in non-blocking mode (§2.11 above).
- SessionStart hook for fresh `source=startup` only (§2.1) with stripped preamble.
- PreCompact extraction (§2.2) with tightened thresholds.
- CLAUDE.md block (§2.6) as rewritten in v4.10.7.

### What becomes opt-in

- `proactiveRecall` (was on, flip to off).
- Full SessionStart preamble (instruction block).
- Stop hook (already opt-in, stays).
- `openclawAutoMemory` (already opt-in, stays).

---

## 6. Risk & migration

v4.11.0 is the first release in the 4.10.x line that changes defaults in a user-visible way. To make this safe:

1. **CHANGELOG** leads with a "Default changes" section, not buried.
2. **One-time notice** on `shieldcortex update`: "v4.11.0 turned off auto-recall and relaxed interceptor approval prompts. See CHANGELOG. To restore previous behaviour: `shieldcortex config --proactive-recall true`."
3. **Config migration helper**: `shieldcortex config --restore-4.10-defaults` for users who preferred the old behaviour.
4. **Dashboard note**: surface the default change in the Trust Console home view for a release.

---

## 7. Closing

The product has two clean sides:

- **Defence pipeline** (scan, X-Ray, Iron Dome, Environment Firewall, credential leak detection, tool call interceptor when it's fast): **works, earns its cost, should stay on**.
- **Memory-injection-into-prompt side** (prompt-recall, SessionStart preamble, PreCompact auto-extract at current thresholds): **pays per-turn tax that fleet evidence shows is negative-EV at current defaults**.

v4.11.0 is the release that lines defaults up with reality. The memory side stays in the product for the use case it was designed for (deep interactive debugging sessions with long-lived context), but stops taxing the use case it wasn't (fast agent loops).

No rewrite. No deprecation. Just honest defaults.
