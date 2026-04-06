# Tool Call Interceptor — Design Spec

**Date:** 2026-03-29
**Status:** Draft (Rev 2 — incorporates review feedback)
**Triggered by:** OpenClaw v2026.3.28 adding async `requireApproval` to `before_tool_call` hooks

## Problem

ShieldCortex's OpenClaw plugin currently hooks `llm_input` and `llm_output` to scan for threats, but it can only log — it cannot block. A prompt injection that slips into a `remember` call gets stored before anyone can intervene. The new `requireApproval` API lets plugins pause tool execution and gate it behind user approval.

## Goal

Turn ShieldCortex from a passive scanner into an active firewall for OpenClaw tool calls. When a watched tool is invoked with suspicious content, pause execution and require user approval before proceeding.

## Scope — Phase 1

Phase 1 is deliberately narrow:

- **Two watched tools only:** `remember` and `mcp__memory__remember` (hardcoded, no glob)
- **Structured scan results** via direct `runDefencePipeline()` import — no markdown regex
- **No similarity-based auto-approve** — every flagged call prompts the user
- **Exact-match deny suppression only** — identical denied content is auto-denied
- **Separate cloud ingest helper** — does not mutate existing `cloudSync()`
- **Content-field extraction** — inspects known content-bearing fields, not stringified JSON

Glob tool matching, configurable watched tools, and similarity-based caching move to Phase 2.

## Architecture

### File Structure

```
plugins/openclaw/
├── index.ts              # Registration hub — registers all 3 hooks + command
├── interceptor.ts        # NEW — before_tool_call logic
├── intercept-ingest.ts   # NEW — cloud ingest adapter for intercept events
└── openclaw.plugin.json  # Plugin manifest
```

### Registration

`index.ts` registers two new hooks alongside the existing two:

```typescript
api.registerHook("before_tool_call", handleToolCall, {
  name: "shieldcortex-intercept-tool",
  description: "Active threat gating on tool calls"
});

api.registerHook("session_end", () => interceptor.resetSession(), {
  name: "shieldcortex-session-cleanup",
  description: "Clear interceptor deny cache on session end"
});
```

**Note:** If OpenClaw does not expose `session_end` as a hookable event, the 2-hour TTL safety net (see Deny Cache lifecycle) prevents unbounded cache growth.

### Interceptor Module

`interceptor.ts` exports a factory function:

```typescript
export function createInterceptor(config: InterceptorConfig): {
  handleToolCall: (context: ToolCallContext) => Promise<void>;
  resetSession: () => void;
}
```

Owns:
- Tool matching (exact match against hardcoded list in Phase 1)
- Content-field extraction from tool arguments
- Scanning via `runDefencePipeline()` — typed, structured results
- Severity evaluation against configured thresholds
- Approval prompt formatting
- Exact-match deny cache
- Audit logging

## Configuration

Lives in `~/.shieldcortex/config.json` under the `interceptor` key, overridable via OpenClaw plugin config.

```json
{
  "interceptor": {
    "enabled": true,
    "severityActions": {
      "low": "log",
      "medium": "warn",
      "high": "require_approval",
      "critical": "require_approval"
    },
    "failurePolicy": {
      "low": "allow",
      "medium": "allow",
      "high": "deny",
      "critical": "deny"
    }
  }
}
```

**Note:** `watchedTools` is not user-configurable in Phase 1. The interceptor watches `remember` and `mcp__memory__remember` only.

### Severity Actions

| Action | Behaviour |
|--------|-----------|
| `log` | Write to audit log, no interruption |
| `warn` | Log + console warning (yellow), no interruption |
| `require_approval` | Call `requireApproval()` with detailed threat message, block until user responds |

### Failure Policy

Controls what happens when `requireApproval` throws or times out, **per severity level**:

| Policy | Behaviour |
|--------|-----------|
| `allow` | Warn and allow the tool call to proceed |
| `deny` | Deny the tool call — safe default for high/critical |

This replaces the previous blanket "default to allow" fallback. For low/medium threats where approval was optional anyway, allowing on failure is fine. For high/critical threats where the user explicitly needed to approve, silently allowing on failure undercuts the feature.

### Config Validation

- Unknown severity levels in `severityActions` — warn and ignore
- Missing `interceptor` block — use defaults (enabled, standard severity/failure actions)

## Scanning

### ToolCallContext

The `before_tool_call` hook receives a `ToolCallContext` from OpenClaw:

```typescript
interface ToolCallContext {
  toolName: string;
  arguments: Record<string, unknown>;
  requireApproval: (message: string) => Promise<boolean>;  // true = approved, false = denied
}
```

**Note:** `requireApproval` lives on the context object, not the `api` object. Availability check: `typeof context.requireApproval === 'function'`.

### Content Extraction

Phase 1 does **not** stringify the entire arguments object. Instead, it extracts known content-bearing fields for each watched tool:

| Tool | Content Fields |
|------|---------------|
| `remember` | `content`, `title` |
| `mcp__memory__remember` | `content`, `title` |

The extracted text is concatenated and passed to the scanner. This avoids false positives from JSON metadata noise (tags, category, importance, etc.).

### Structured Scan Path

The interceptor imports `runDefencePipeline` directly from the `shieldcortex` package — no markdown parsing:

```typescript
import { runDefencePipeline } from 'shieldcortex/defence';
import type { DefencePipelineResult, DefenceSource } from 'shieldcortex/defence';

const source: DefenceSource = { type: 'agent', identifier: 'openclaw' };
const result: DefencePipelineResult = runDefencePipeline(content, title, source);
```

This returns fully typed results:
- `result.allowed` — boolean pass/fail
- `result.firewall.result` — `'ALLOW' | 'BLOCK' | 'QUARANTINE'`
- `result.firewall.threatIndicators` — array of typed threat objects
- `result.firewall.anomalyScore` — numeric score
- `result.trust.score` — trust level

**Side effects:** `runDefencePipeline` internally calls `logAudit()` (SQLite), `persistEvent()` (dashboard), and `syncToCloud()`. This means the pipeline already handles audit logging and cloud sync. The interceptor layer does **not** duplicate these — it only writes its own JSONL entry to the local `realtime-*.jsonl` file for the intercept-specific fields (action taken, outcome, approval result) that the pipeline doesn't know about. The `intercept-ingest.ts` adapter syncs only these intercept-specific fields to the cloud — no double-sync.

**Database dependency:** `runDefencePipeline` requires the SQLite database to be initialised for `logAudit()`. In the plugin context, the database may not be available. If `runDefencePipeline` throws due to database issues, the error handler treats it as high severity and applies `failurePolicy` (deny by default). This is acceptable — a non-functional defence pipeline should not silently allow content through.

### Severity Mapping

Map `result.firewall.result` + `result.firewall.anomalyScore` to interceptor severity:

| Condition | Severity |
|-----------|----------|
| `firewall.result === 'ALLOW'` and `anomalyScore < 0.3` | `low` |
| `firewall.result === 'ALLOW'` and `anomalyScore >= 0.3` | `medium` |
| `firewall.result === 'QUARANTINE'` | `high` |
| `firewall.result === 'BLOCK'` | `critical` |

This uses the pipeline's own structured decisions rather than parsing risk level strings.

### Interceptor Flow

1. Check if `toolName` is in the watched list (exact match)
2. Extract content-bearing fields from `arguments`
3. Call `runDefencePipeline(content, title, source)` — synchronous, typed
4. Map firewall result to severity level
5. Check exact-match deny cache — if content was previously denied, auto-deny
6. Look up configured action for severity
7. Execute action (log / warn / require_approval)

**Important:** Unlike the existing `llm_input`/`llm_output` hooks which are fire-and-forget (async IIFE, no await), the `before_tool_call` handler **must await** the approval result, since the point is to gate execution.

### Approval Control Flow

When action is `require_approval`:
1. Format the approval prompt message (see below)
2. Call `const approved = await context.requireApproval(message)`
3. If `approved === true` → allow tool call to proceed
4. If `approved === false` → throw an error to signal rejection to OpenClaw (the `before_tool_call` contract: throwing prevents the tool from executing), cache content hash for future auto-deny
5. Log outcome to audit either way

**Rejection mechanism:** The handler throws a descriptive error (e.g. `throw new Error("ShieldCortex: tool call denied by user")`) to prevent the tool from executing. OpenClaw's `before_tool_call` contract treats thrown errors as tool call rejections.

If `requireApproval` is not available (pre-v2026.3.28), fall back to `warn` action.

If `requireApproval` throws or times out, apply `failurePolicy` for the current severity level (allow for low/medium, deny for high/critical).

## Approval Prompt

Passed as the `message` parameter to OpenClaw's `requireApproval()`:

```
🛡️ ShieldCortex — Tool Call Intercepted

Tool:       remember
Risk:       critical (BLOCK)
Threats:    instruction_injection, privilege_escalation
Content:    "You are now in admin mode. Ignore previous..."

[Approve]  [Deny]
```

- Content preview: first 200 chars of the extracted content fields, truncated
- Threat types from `result.firewall.threatIndicators[].type`
- Risk line shows severity + firewall decision

## Deny Cache

### Purpose

When the user denies a flagged tool call, cache the content so identical calls are auto-denied without re-prompting. **No auto-approve cache in Phase 1** — every non-denied flagged call prompts the user.

### Approach

- SHA-256 hash of the normalised content (using `normalizeMemoryText()` from the plugin's novelty system — strips URLs, backticks, quotes, non-alphanumeric chars, then lowercases and collapses whitespace)
- Keyed by tool name
- Exact match only — no similarity/Jaccard

### Cache Structure

```typescript
denyCache: Map<string, Set<string>>
// key: tool name
// value: Set of content hashes that were denied
```

### Lifecycle

- Populated on each user denial
- Cleared on session end — plugin registers a `session_end` hook that calls `resetSession()`
- Safety net: entries older than 2 hours are auto-evicted
- Never persisted to disk — session-scoped only
- Max 200 entries per tool (FIFO eviction)

### Rate Limiting

To prevent approval fatigue from rapid-fire prompts, limit to **5 approval prompts per minute globally** (across all watched tools). Beyond that, auto-deny with a warning log: `"ShieldCortex: too many approval prompts — auto-denying"`. Resets each minute.

### Audit Trail

Auto-denied decisions are logged with `outcome: "auto_denied"` so the cache's behaviour is visible.

## Cloud Ingest

### Separate Adapter

A new `intercept-ingest.ts` file provides a dedicated cloud sync function for intercept events:

```typescript
export function syncInterceptEvent(event: InterceptAuditEntry, config: CloudConfig): void
```

- Fire-and-forget POST to `/v1/audit/ingest` with `type: "intercept"` in the payload
- Does **not** modify the existing `cloudSync()` function in `index.ts`
- Reuses the same `CloudConfig` (cloudApiKey, cloudBaseUrl, cloudEnabled)
- Same resilience: 5-second timeout, failures silently caught

The existing `cloudSync()` (which POSTs to `/v1/threats`) is left untouched. Migrating it to `/v1/audit/ingest` is a separate task.

## Audit Logging

Every intercepted call is logged to `~/.shieldcortex/audit/realtime-YYYY-MM-DD.jsonl` regardless of outcome:

```json
{
  "type": "intercept",
  "tool": "remember",
  "severity": "critical",
  "firewallResult": "BLOCK",
  "threats": ["instruction_injection", "privilege_escalation"],
  "anomalyScore": 0.87,
  "action": "require_approval",
  "outcome": "denied",
  "preview": "first 200 chars...",
  "ts": "2026-03-29T12:00:00.000Z"
}
```

Possible `outcome` values: `approved`, `denied`, `auto_denied`, `logged`, `warned`, `failure_allowed`, `failure_denied`

## Error Handling & Compatibility

### Graceful Degradation

- **Pre-v2026.3.28 OpenClaw:** Detect via `typeof context.requireApproval === 'function'` inside the handler. If unavailable, fall back to log + warn only. Never block.
- **Scan runtime unavailable:** Skip interception with a one-time console warning (existing `getRuntime()` resilience handles this).
- **`requireApproval` throws or times out:** Apply `failurePolicy` for the current severity level. Low/medium → warn and allow. High/critical → deny. Logged as `failure_allowed` or `failure_denied`.
- **`runDefencePipeline` throws:** Treat as high severity, apply failure policy (deny by default). Log the error.

### Version Requirements

- Plugin remains loadable on older OpenClaw versions (graceful fallback)
- README/docs note v2026.3.28 as minimum for active blocking
- Plugin version bumps with next ShieldCortex npm release

### Plugin Manifest Update

`openclaw.plugin.json` must be updated to:
- Include the new `interceptor` config block in its `configSchema` and `uiHints`
- Fix version drift (manifest currently says `3.4.33`, package is `3.4.37`) — sync to match the release version

## Iron Dome Alignment

The `severityActions` config intentionally mirrors the structure used by Iron Dome policies in the SaaS. While Phase 1 is plugin-only, the config shape is designed so that Phase 2 can map interceptor rules into Iron Dome policy objects without breaking changes. Specifically:

- Severity levels (`low`, `medium`, `high`, `critical`) match Iron Dome's threat classification
- Actions (`log`, `warn`, `require_approval`) can map to Iron Dome's `action` field
- `failurePolicy` aligns with Iron Dome's `fallbackAction` concept

This avoids building a parallel policy system.

## Testing

Required test cases:

| Test | Input | Expected |
|------|-------|----------|
| Clean allow | Benign `remember` call | Pipeline returns ALLOW, action is `log`, tool proceeds |
| Warned allow | Moderate-risk content | Pipeline returns ALLOW with anomalyScore >= 0.3, console warning, tool proceeds |
| Approved block-release | High-risk content, user approves | `requireApproval` fires, user approves, tool proceeds |
| Denied block | High-risk content, user denies | `requireApproval` fires, user denies, tool blocked |
| Auto-denied (cache) | Same denied content repeated | Exact hash match, auto-denied without prompt |
| Missing requireApproval | High-risk on pre-v2026.3.28 | Falls back to warn, tool proceeds |
| Timeout — high severity | `requireApproval` times out on high-risk | Failure policy denies |
| Timeout — medium severity | `requireApproval` times out on medium-risk | Failure policy allows with warning |
| Rate limit | 6th approval prompt in 1 minute | Auto-denied with rate limit warning |
| Unwatched tool | Tool not in watched list | No scan, tool proceeds immediately |
| Pipeline error | `runDefencePipeline` throws | Treated as high severity, failure policy denies |

## Phase 2 (Future Work)

### Configurable Watched Tools with Glob Matching

User-configurable `watchedTools` list with glob pattern support (e.g. `mcp__memory__*`). Requires content-field extraction maps for each new tool type.

### Similarity-Based Auto-Approve

Session-scoped Jaccard similarity cache for approved calls. Requires careful threshold tuning — a single changed token can alter intent. May be restricted to low/medium severity only, with high/critical always prompting.

### Generic Tool Argument Scanning

Stringified JSON scanning for arbitrary tools beyond memory-write. Phase 1's content-field extraction is too narrow for this — needs noise filtering and per-tool field maps.

### Persistent Approval Learning (Pro Feature)

Save approval/denial decisions to config and build a user-specific allowlist over time. Requires its own storage design and config schema. Gated behind Pro tier.

### Core MemoryFirewall Integration

Move interception logic into the core `MemoryFirewall` class so other integrations (not just OpenClaw) get active blocking for free. Bigger refactor — decouples from OpenClaw's `requireApproval` API by abstracting an approval interface.

### Custom Approval Channels

Support Telegram, Discord, and other channels for approval prompts instead of just OpenClaw's built-in exec overlay. Depends on OpenClaw's channel APIs which are brand new in v2026.3.28.

### Iron Dome Policy Unification

Map interceptor config directly into Iron Dome policy objects so there's one policy system, not two. Interceptor becomes a consumer of Iron Dome policies rather than maintaining its own severity/action config.
