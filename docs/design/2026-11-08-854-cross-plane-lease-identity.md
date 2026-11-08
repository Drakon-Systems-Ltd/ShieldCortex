# #854 — Own-session lease refusal across the hook and OpenClaw planes: design after re-inspecting OpenClaw 2026.11.x (design proposal, not approved implementation)

**Status:** design proposal for independent review. Nothing here is implemented, enabled or approved. It authorises no runtime change, no Guard configuration change and no release. #854 stays open; #554 is closed as its duplicate and its acceptance constraints and five rejected-design findings are binding inputs here (§3).

**Base:** ShieldCortex `main` at `4d7b3c0bf15144c332786e11b1affd5d3e4c6fc1` (8 Nov 2026). OpenClaw evidence is a static read of the **published npm tarballs** `openclaw@2026.10.4`, `2026.10.6`, `2026.11.1` and `2026.11.2` (the `latest` dist-tag on 8 Nov 2026), unpacked into disposable directories. Paths below are `package/dist/...` inside each tarball; chunk hashes in file names are per release. No live gateway, no live Guard state and no host process was inspected; nothing was executed.

**Lineage.** #856 (merged `68a446df`, 5.10.6) and #868 (5.10.7) made both planes derive one identity from one session id. The 17 Oct option (1′) design on #554 (a per-call `tool_use_id` binding consumed across planes) received two independent CHANGES REQUESTED verdicts with five findings; it is **not revived**. The withdrawn #552 pid-ancestry re-entry stays withdrawn. This document answers the question #854 left open: does OpenClaw now hand either plane a host-owned, non-replayable identity for the Claude CLI child, and if not, what is the smallest upstream contract that would.

---

## 0. One-paragraph summary

OpenClaw 2026.11.1/11.2 passes the plugin `before_tool_call` hook **exactly the same context fields as 2026.10.4/10.6**: OpenClaw's `sessionId`, `sessionKey`, `runId`, `toolCallId`; no Claude CLI session id, no child pid, no spawn token. But the static read also shows two facts the earlier rounds did not record. **(a)** For the `claude-cli` backend (`sessionMode: "always"`) OpenClaw **mints the Claude session id itself** before spawn (`crypto.randomUUID()` in `resolveSessionIdToSend`) and passes it as `--session-id`, or passes the stored id as `--resume`; so the gateway holds the exact string the Claude Code PreToolUse hook later hashes, in the same runtime module that builds the plugin context, for every turn including a fresh cron turn. It just does not put it on the context, in the child environment, or in the session store until the run commits. **(b)** After a turn commits, that id is persisted host-side as `SessionEntry.cliSessionIds["claude-cli"]`, and plugins can read it in-process through `api.runtime.agent.session.getSessionEntryAsync({ sessionKey, agentId })` (sync `getSessionEntry` in 10.4; async added by 11.1). The general case (first turn of a fresh session, which is every isolated cron turn and the 25 Oct incident) therefore **remains upstream-blocked**, and the minimal upstream contract is one optional field (§5). A **partial, host-owned, non-replayable** bridge for resumed turns (the long-lived main-session hits in the issue body) is implementable today without any OpenClaw change and without a per-call binding record (§4); it is proposed for review, not for implementation in this PR.

---

## 1. What each plane holds today (ShieldCortex `main@4d7b3c0b`)

| Plane | Identity used for the lease | Source |
|---|---|---|
| Claude Code PreToolUse command hook | `baseExtra.sessionKey` = `sc-` + HMAC(salt, `action-guard-session:<hook stdin session_id>`), else `ppid:<pid>`, or `null` (refuse) when a named id cannot be derived | `scripts/pre-tool-hook.mjs` L1310 (`sessionKeyFor`), L3338-3360 (`leaseSelf`, `evaluateToolCallLease(... { self: leaseSelf, holderPid })`) |
| OpenClaw plugin interceptor | `leaseIdentityFor(context.sessionId)` over the same formula and salt; `''` → `anon-pid-<pid>`; `null` → explicit `unknown` refusal | `plugins/openclaw/interceptor.ts` L2226 (`checkActionLease(toolName, args, context.sessionId)`), `plugins/openclaw/index.ts` L2848-2905 (`actionLeaseAdapters`), `src/defence/iron-dome/session-lease-identity.ts` |

Both planes agree **iff** they receive the same string. On the Claude CLI runtime they do not: the hook receives Claude's `session_id`, the plugin receives OpenClaw's `sessionId`. That is the residual #856 named and #854 tracks.

---

## 2. Static inspection of the published OpenClaw distributions

### 2.1 Plugin hook context: unchanged 2026.10.4 → 2026.11.2

`PluginHookToolContext` is field-for-field identical in all four releases:

```
agentId? sessionKey? sessionId? runId? abortSignal? trace? toolName
toolKind? toolInputKind? toolCallId? getSessionExtension? channelId? requester?
```

- 2026.10.4: `hook-runner-global-Jvv9WFUW.d.ts` L1388-1410 (and `PluginHookBeforeToolCallEvent` L1411).
- 2026.10.6: same shape (checked in the 10.6 `.d.ts`).
- 2026.11.1: `config-contracts-CUCiWyff.d.ts` L15036-15058; event L15059.
- 2026.11.2: `config-contracts-0_35lKDI.d.ts` L15037.

`requester` carries channel/sender facts (`PluginHookToolRequesterContext`), not harness identity. `getSessionExtension(namespace)` reads **plugin-owned** state only (`PluginSessionExtensionRegistration`, L26231), so it cannot surface a host-owned id a plugin never wrote.

### 2.2 How the context is built on the Claude CLI path: unchanged

`execute.runtime-CdXXiurs.mjs` (11.1) L1482 `createPluginToolPermissionHandler` → L1535-1557 `runBeforeToolCallHook({ toolName, params, toolCallId: request.toolCallId, ctx: { agentId, sessionKey: run.sessionKey, sessionId: run.sessionId, runId: run.runId, ... } })`. Every ctx field comes from `run` (the OpenClaw run params). Identical block in 10.4 (`execute.runtime-z4Gtl6lu.mjs` L1437-1440) and 11.2 (`execute.runtime-22Paxzlc.mjs` L1545-1548).

The native request arrives from the Anthropic extension: `extensions/anthropic/.setup/cli.runtime-DXQ4h1hv.mjs` L258 `toolUseId = request.tool_use_id`, L265-271 `turn.context.requestToolPermission({ toolName, toolInput, cwd, toolCallId: toolUseId })`; L293-297 `handleRequest` routes `can_use_tool` and `hook_callback`. The Claude `session_id` is **not** forwarded on this call.

### 2.3 OpenClaw knows the Claude session id before spawn — and keeps it to itself

- `cli-backend-C3TZcctF.mjs` L136-158, backend `claude-cli`: `sessionArgs: ["--session-id", "{sessionId}"]`, `resumeArgs: [..., "--resume", "{sessionId}"]`, `forkArg: "--fork-session"`, **`sessionMode: "always"`**.
- `helpers-Dfaf1azP.mjs` L131 `resolveSessionIdToSend`: `sessionId: mode === "none" ? undefined : mode === "existing" || existing ? existing : crypto.randomUUID()`. Same function in 10.4 (`helpers-B5i3L0yF.mjs` L123) and 11.2 (`helpers-Dlev7sb8.mjs` L131).
- `execute.runtime-CdXXiurs.mjs` L3199-3218 `executePreparedCliRun(context, cliSessionIdToUse)` → `{ sessionId: resolvedSessionId, isNew } = resolveSessionIdToSend(...)`; L3220 `useResume = Boolean(cliSessionIdToUse && resolvedSessionId && backend.resumeArgs ...)`; L3268 `resolvedArgs = useResume ? baseArgs.map(e => e.replaceAll("{sessionId}", resolvedSessionId)) : baseArgs`; `helpers-Dfaf1azP.mjs` L229 pushes `sessionArgs` with the minted id when not resuming; `cli-runtime-args-UumcGmHy.mjs` L72 does the same for the stdio transport (`context.useResume ? "--resume" : "--session-id"`). Identical in 10.6.

So the string the Claude Code hook will report as `session_id` exists as `resolvedSessionId` inside the gateway, in the same module whose L1535-1557 builds the plugin context, on **every** turn. Neither is wired to the other.

### 2.4 Where the id goes afterwards

- **Child environment:** `prepare.runtime-_N6IgijZ.mjs` L1644-1645 sets `OPENCLAW_MCP_TOKEN` (loopback grant) and `OPENCLAW_MCP_CLI_CAPTURE_KEY`; `prompt-context-xdi-Qrs5.mjs` L493 sets the capture key. Nothing session-identifying is exported. `OPENCLAW_TOOLS_MCP_AGENT_SESSION_KEY` is still only read, never set (as Tars found on 10.1/10.6; re-confirmed on 11.1/11.2).
- **Session store, post-run only:** `cli-session-jhqFA830.mjs` L26-31 `applyCliSessionBindingResult(entry, provider, meta)` and L38-81 `setCliSessionBinding` write `entry.cliSessionBindings[provider]` and `entry.cliSessionIds[provider]`; they are called from the result commit (`cli-session-store-BFq-GvXo.mjs` L137-139, `run-executor.runtime-BTWjkxjq.mjs` L452-457). The committed value is what Claude reported in its stream (`cli-live-session-registry-BgyS5Il2.mjs` L308-319 `pickCliSessionId` over `session_id`/`sessionId`/...). There is no pre-run persistence of the candidate id (`prepare.runtime` L1765-1812 only resolves reuse/invalidate; the search for any pre-run write of the candidate found none).
- **Store read API for plugins:** `config-contracts-CUCiWyff.d.ts` L65055-65056 `SessionEntry.cliSessionIds?: Record<string,string>`, `cliSessionBindings?: Record<string, CliSessionBinding>`; L50260 `api.runtime.agent.session.getSessionEntry` (sync, deprecated with removal in the first Jan 2027 stable) and L50262 `getSessionEntryAsync({ sessionKey, agentId?, readConsistency?: "latest" })`. 10.4 exposes only the sync form (`agent-harness-runtime-DZjstJNb.d.ts` L32323).

### 2.5 Other paths checked and ruled out

- **MCP bridge (`mcp__openclaw__exec` with native Bash disabled):** `mcp-http.handlers-CSYvjxKu.mjs` L72 `toolCallId = \`mcp-${crypto.randomUUID()}\``; MCP `_meta` is not read. The hook sees Claude's `tool_use_id`, the plugin sees `mcp-<uuid>`: no shared per-call id on this path, so even a repaired option (1′) could not cover it.
- **Native hook relay:** `native-hook-relay-B_V9WH_m.mjs` (new coverage in 11.1 relative to 10.4) registers `{ relayId, sessionId, sessionKey, runId, pid }` host-side (L129-131, L859) and maps `tool_use_id` → `toolCallId` (L140-149); the child reaches it via `openclaw hooks relay --relay-id` (`native-hook-relay-cli-COhWqE0G.mjs` L93). It is **Codex-only** (`listAgentToolResultMiddlewares("codex")`, Codex response codec throughout). It is the right *shape* of host-owned binding (process-instance registration, dead-pid reaping) and is cited in §5 as precedent; it does not exist for Claude.
- **Live session registry:** `cli-live-session-registry-BgyS5Il2.mjs` L1770-1777 keys the live Claude process by `{ backendId, agentId, sessionId, sessionKey }` (OpenClaw ids) and stores an opaque `generation`; no Claude id, no pid exposed to plugins (importers: `cli-runner-CgzdLWEN.mjs` only).

### 2.6 Verdict

| Question | Answer |
|---|---|
| Does 2026.11.1/11.2 hand the plugin a host-owned Claude-child identity? | **No.** Context unchanged since 10.4. |
| Does it hand the Claude child the OpenClaw session identity? | **No.** Child env unchanged. |
| Does any host-owned, non-replayable identity reach **both** planes for a **fresh** turn? | **No.** Upstream-blocked (§5). |
| Does one reach both planes for a **resumed** turn? | **Yes, indirectly:** the committed `cliSessionIds["claude-cli"]` is host-written, keyed by the host's own `sessionKey`, readable in-process by the plugin, and equal to the `--resume` id Claude reports to the hook when the binding is reused (§4). |

---

## 3. The #554 constraints, applied

Acceptance (from the #552 review, restated on #554): host-maintained binding of **this** child to the OpenClaw holder; not a shared gateway pid, not a caller-selected env string, not a nonce the agent can read and replay; "already gated" claims must bind exact scope + action with bounded, non-replayable authority; sibling B, forged, expired and missing bindings stay HELD; freeze first; never release before the operation; off for the interceptor-only, `evaluateAction` and host adapters.

The five rejected-design findings (TARSDrakon, 17 Oct, two lanes) and how any new design must stand against them:

| # | Finding against option (1′) | Why it bound | What a design must do instead |
|---|---|---|---|
| F1 | Consume is not atomic over the whole-file lease store; a stale snapshot can resurrect an old holder | Any per-call **record** written into the lease store and consumed later needs a commit protocol the store does not have | Have **no per-call record to consume**. Identity derivation adds nothing to the lease store. |
| F2 | `actionKey` undefined for Write/Edit (`extractCommand` → null) | A command-surface hash cannot describe file-tool actions | Do not hash actions. Nothing in §4/§5 depends on an action key. |
| F3 | The token (`tool_use_id`) is re-presentable: copied into both planes and written to an owner-writable file; nothing binds the process instance | A readable id that any sibling can **present** is not an identity | Use an identity that a caller cannot *present*: the hook plane's id is written into the hook's stdin by Claude Code, the plugin plane's id is read from host state keyed by the host's own `sessionKey`. Neither is a parameter of the tool call. |
| F4 | Either-order symmetry fails: hook-first in steady state returns HELD with no wait for a binding | Consume-on-held needs a bounded wait the hook does not have | With one identity on both planes, order is irrelevant: whichever plane acquires, the other re-enters through the existing same-holder path (`checkSessionLease`, `session-lease.ts` L159). |
| F5 | `actionKey` collisions (`config.json` vs `settings.json`) | Same as F2 | Same as F2. |

Both §4 and §5 are **identity selection**, the thing #856 already shipped for the same-id case. They introduce no binding record, no consumption, no action hash and no ordering assumption; F1-F5 do not arise. The remaining question for each is only: *is the selected identity host-owned, and can a sibling or the agent make a plane adopt someone else's?* That is answered per option below.

---

## 4. Option A (no OpenClaw change): committed-binding identity on the plugin plane for resumed `claude-cli` turns

### 4.1 Rule

In `actionLeaseAdapters` (`plugins/openclaw/index.ts` L2848), when the call is **scoped** (`scopeForToolCall(toolName, args) != null`) and the plugin can resolve the run's harness identity, the plugin leases as `leaseIdentityFor(harnessSessionId)` instead of `leaseIdentityFor(ctx.sessionId)`. Resolution order, first hit wins:

1. `ctx.harnessSessionId` when a future OpenClaw exposes it (§5). Not present today; listed so the shape is forward-compatible and the §5 field lands in one place.
2. `entry.cliSessionIds["claude-cli"]` from `api.runtime.agent.session.getSessionEntryAsync({ sessionKey: ctx.sessionKey, agentId: ctx.agentId, readConsistency: "latest" })` (fall back to the sync `getSessionEntry` where the async form is absent), **only if** `entry.sessionId === ctx.sessionId` (the store row is the live incarnation this run was built from) **and** the value is a nonblank string.
3. Otherwise `ctx.sessionId`, exactly as today.

Unscoped calls never read the store and never derive. Release uses the identity captured at acquire (the #856 `acquiredAs` WeakMap), unchanged.

### 4.2 What it covers and what it does not

- **Covers:** turn N≥2 of a session whose previous turn committed a Claude binding and whose current turn reuses it (`prepare.runtime` L1765-1812 → `mode: "reuse"`/`"reuse-with-drift"` → `--resume <id>`). Claude Code's hook then reports that same id. This is the long-lived main-session class in the #854 body (install, security-config, gateway-restart, npm-publish hits in a resumed chat session).
- **Does not cover:** the first turn of a fresh session (no committed binding yet; OpenClaw passes a freshly minted `--session-id` the plugin cannot see). Every isolated cron turn is in this class, including the 25 Oct `openclaw backup create --verify` incident. Also not covered: a turn where OpenClaw invalidates or forks the binding (`claudeCliInvalidatedReason`, `forkNextResume` → `--fork-session`): Claude runs under a new id, the store still holds the old one.
- **Behaviour in the uncovered cases:** the plugin derives a *stale* identity (this session's previous Claude id, or OpenClaw's id); the hook derives the live one; they differ; the second plane is refused — **today's behaviour, no downgrade.**

### 4.3 Against the acceptance constraints

- **Host-maintained, specific to this child's session:** the value is written only by OpenClaw's own commit path (§2.4) under the host's `sessionKey`, from the id OpenClaw passed to, and read back from, this session's Claude process. It is not chosen by the agent, not a shared pid, not an env string, not a nonce.
- **Not presentable:** a sibling session B cannot pass A's id to the plugin; the plugin never takes an identity from tool-call parameters. B's plugin plane reads B's own store row. B's hook plane reports B's own Claude `session_id`.
- **Sibling B HELD:** B's identities differ from A's on both planes; both refuse while A holds. Unchanged.
- **Forged / expired / missing:** a missing or blank `cliSessionIds["claude-cli"]`, a store row whose `sessionId` is not this run's `ctx.sessionId`, a read failure or a throw all fall to step 3 (strict identity, today's behaviour). There is nothing to expire because nothing is minted per call.
- **Freeze first; no early release; off elsewhere:** the freeze check and the held-branch order in `checkSessionLease` are untouched; nothing releases before the operation; the hook, `evaluateAction` and host adapters are untouched. Only the OpenClaw plugin's identity selection changes.

### 4.4 Residual risks to weigh in review (stated, not minimised)

1. **Trust in the host session store.** The store is same-uid writable (`~/.openclaw/agents/<agent>/sessions/...`). An agent process that rewrites its **own** row's `cliSessionIds["claude-cli"]` to a victim's Claude id, *and* gets Claude to run under that id, could make both of its planes carry the victim's identity. The second half is **pre-existing**: the hook plane has always trusted Claude Code's stdin `session_id`, and `claude --session-id <victim>` gives it to any same-uid process today. Option A does not create that capability; it extends the same trust to the plugin plane. The sessions store is **not** in the `security-config` write-shape set and this design does not propose adding it (reviewers may disagree; it is a separate scope question).
2. **Stale-id collision.** In an uncovered turn the plugin leases as this session's *previous* Claude id. That could equal another live session's identity only if another OpenClaw session is concurrently running Claude under that same id, which OpenClaw's fork-on-resume design avoids (`forkCliSessionBindings`, `--fork-session`). Assessed LOW; a fixture pins the refusal direction anyway (§4.5 e).
3. **Store read in the enforcement path.** One worker-backed read per **scoped** call (scoped calls are rare: install, security-config, npm-publish, gateway-restart). Cache per `(sessionKey, runId)` for the run. A read that is slow, fails or throws falls to step 3; it must never fail open to `''`/`anon-pid`.
4. **API lifetime.** Sync `getSessionEntry` is deprecated for removal in the first January 2027 stable release; the design uses the async form where present and sync only on dists that lack it.
5. **Derived keys in refusal text.** Unchanged from #856's residual list.

### 4.5 Synthetic regression plan (fixture-only; no live host; each test must fail with the rule removed)

Pure plugin/adapter tests with a fixture lease dir and a stubbed `api.runtime.agent.session`:

- (a) **Resumed turn, hook first:** hook holds `security-config` as `sc-HMAC(C1)`; plugin ctx `{ sessionId: O1, sessionKey: K1, agentId: A }`, store row `{ sessionId: O1, cliSessionIds: { "claude-cli": C1 } }`; plugin scoped `exec` → **allowed as same holder**, `acquired: false`, nothing released. Mutation: revert step 2 → HELD (the test fails).
- (b) **Resumed turn, plugin first:** plugin acquires as `sc-HMAC(C1)`; hook plane evaluates with `self = sc-HMAC(C1)` → same holder. Mutation as (a).
- (c) **Fresh turn:** store row has no `cliSessionIds` → plugin leases as `leaseIdentityFor(O1)`; hook as `sc-HMAC(C2)` → second plane HELD. Pins "no downgrade"; mutation: make step 2 return a guessed id → test fails because the refusal disappears.
- (d) **Sibling B:** store rows `{O1→C1}` and `{O2→C2}`; A holds; B's plugin and B's hook both HELD.
- (e) **Stale store row:** `entry.sessionId !== ctx.sessionId` → step 3; HELD against a hook holder under the live id. Mutation: drop the `entry.sessionId` guard → test fails.
- (f) **Read failure / throw / timeout:** stub rejects → step 3 (never `''`, never `anon-pid`), scoped call still gated; no fail-open.
- (g) **Unscoped call:** store stub asserts it was **never called**.
- (h) **Release parity:** acquire as `sc-HMAC(C1)` via the store path, salt lookup then fails → release still frees exactly that hold (extends the #856 r2 case).
- (i) **Freeze wins:** freeze set + matching committed id → FROZEN, not allowed.
- (j) **Old dist without `getSessionEntryAsync`:** sync `getSessionEntry` used; absent both → step 3.
- Existing `src/__tests__/session-lease-cross-plane-854.test.ts` (#854 r2 block) must stay green unchanged.

PR evidence required before any merge: the failing-then-passing run for (a)-(j), the two mutation runs quoted with counts, `npm run guard:precision -- --planes` unchanged, and the README feature grid untouched (no user-visible capability is added; the fix removes a false refusal).

---

## 5. Option B (upstream): the minimal OpenClaw API contract

Precisely one optional field on the existing tool-hook context, populated from a value OpenClaw already holds in the same module:

```ts
// PluginHookToolContext (config-contracts d.ts, L15036 in 2026.11.1)
/**
 * Session id of the CLI harness child executing this run, as passed on its
 * command line (`--session-id` or `--resume`). Present only on CLI-backend
 * runs. Host-minted; never taken from the tool call or the child.
 */
harnessSessionId?: string;
/** CLI backend id that owns `harnessSessionId`, e.g. "claude-cli". */
harnessBackendId?: string;
```

Population point: `execute.runtime` builds the plugin context at L1535-1557 from `run`; `executePreparedCliRun` (L3199) computes `resolvedSessionId` for the same run before spawn. Threading `resolvedSessionId` and `context.backendResolved.id` into the permission handler's ctx is a plumbing change inside one file plus the type. With it, ShieldCortex's step 1 in §4.1 fires on **every** turn, fresh or resumed, and `leaseIdentityFor` closes #854 for the Claude CLI runtime with no store read and none of the §4.4 residuals 1-4.

Alternatives, in order of preference if the field is refused:

- **B2.** Persist the pre-spawn binding (`setCliSessionBinding` before `executePreparedCliRun`, cleared on failure) so §4 step 2 covers fresh turns. Larger blast radius (store semantics around retries, forks and interrupted replacements, `shouldClearInterruptedCliSessionBinding`), so not preferred.
- **B3.** A Claude-side native hook relay with host registration, mirroring the Codex relay (`native-hook-relay-B_V9WH_m.mjs`: `{ relayId, sessionId, sessionKey, runId, pid }`, dead-pid reaping). Strongest binding (process-instance), largest change; it would also move Claude's native PreToolUse gate into `before_tool_call`, which changes who evaluates what and needs its own review.
- **Not proposed:** exporting the OpenClaw session id to the child environment (a caller-readable env string, exactly what #554 excludes), or forwarding MCP `_meta` (does not exist on the native path, and the MCP path's `toolCallId` is `mcp-<uuid>`).

The upstream request itself is **held** per the standing owner decision on #854 and is not filed by this document.

---

## 6. Recommendation

1. Review Option A as a bounded, forward-compatible identity-selection change on the plugin plane; if approved, implement it with the §4.5 fixtures and mutation evidence in a separate PR with FULL (Sol + Grok + Daybreak) review as runtime/security work. It fixes the resumed-session class now and is the exact code path the §5 field will feed.
2. Record the §5 contract as the one factual blocker for the fresh-turn class on #854; file it upstream only when the owner lifts the hold.
3. Keep #673/#875 (lease refusals must not raise approval cards) as the mitigation for the fresh-turn class in the meantime.

## 7. What was not done

No code was written or run; no tests were written; no OpenClaw host, gateway, Guard state, lease directory or session store was read; no upstream issue was filed; no owner was contacted. The Claude Code binary was not re-read this round: the claim that the PreToolUse hook reports the `--session-id`/`--resume` id as `session_id` rests on the 17 Oct read of Claude Code 2.1.299/2.1.301 and on the #552/#554 field evidence, and should be re-pinned in the implementation PR's fixtures by recording a real hook stdin sample from a throwaway session.
