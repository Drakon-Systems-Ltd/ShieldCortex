# #854 — Own-session lease refusal across the hook and OpenClaw planes: design after re-inspecting OpenClaw 2026.11.x (design proposal, not approved implementation)

**Status:** design proposal for independent review. Nothing here is implemented, enabled or approved. It authorises no runtime change, no Guard configuration change and no release. #854 stays open; #554 is closed as its duplicate and its acceptance constraints and five rejected-design findings are binding inputs here (§3).

**Round 2 (8 Nov 2026, after the independent panel's FIX verdict on the first draft).** Option A (§4) is **withdrawn as an implementation candidate**: the first draft claimed it met the #554 acceptance constraints and recommended implementing it; that claim and that recommendation are withdrawn (§4.3, §6). The §4.1 selection rule now requires host-owned evidence about the *current run's* backend and resume mode, which no published OpenClaw release supplies, so the rule is unreachable today. §5 distinguishes the *requested* harness id from the *effective* one and excludes fork turns. §4.5 separates positive regression fixtures from safety-invariant fixtures and adds backend-switch, retained-binding, fork, same-row-invalidation and forged-row cases. No runtime change and no upstream filing follow from this round.

**Round 3 (8 Nov 2026, after the second panel FIX at e8631174).** Wording and contract consistency only, four groups: (1) every uncovered case now reads strict `ctx.sessionId`, and leasing a historical Claude id is named as the forbidden downgrade the fixtures prevent, not as residual behaviour (§4.2, §4.4 items 2 and 6); (2) §4.1 step 1 requires `harnessBackendId === "claude-cli"` as well as a nonblank `harnessSessionId`, pinned by fixture (q); (3) §4.5 replaces the one-fixture-per-mutation rule with a per-mutation expected failing set, redefines fixture (n) on host-owned current-run evidence, and moves fixture (o) into a separate revival acceptance gate with its own mutation; (4) the "every turn" statements in §0 and §2.3 are qualified to non-fork turns and the `forkNextResume` cross-reference in §5 is corrected. Still no runtime change and no upstream filing.

**Base:** ShieldCortex `main` at `4d7b3c0bf15144c332786e11b1affd5d3e4c6fc1` (8 Nov 2026). OpenClaw evidence is a static read of the **published npm tarballs** `openclaw@2026.10.4`, `2026.10.6`, `2026.11.1` and `2026.11.2` (the `latest` dist-tag on 8 Nov 2026), unpacked into disposable directories. Paths below are `package/dist/...` inside each tarball; chunk hashes in file names are per release. No live gateway, no live Guard state and no host process was inspected; nothing was executed.

**Lineage.** #856 (merged `68a446df`, 5.10.6) and #868 (5.10.7) made both planes derive one identity from one session id. The 17 Oct option (1′) design on #554 (a per-call `tool_use_id` binding consumed across planes) received two independent CHANGES REQUESTED verdicts with five findings; it is **not revived**. The withdrawn #552 pid-ancestry re-entry stays withdrawn. This document answers the question #854 left open: does OpenClaw now hand either plane a host-owned, non-replayable identity for the Claude CLI child, and if not, what is the smallest upstream contract that would.

---

## 0. One-paragraph summary

OpenClaw 2026.11.1/11.2 passes the plugin `before_tool_call` hook **exactly the same context fields as 2026.10.4/10.6**: OpenClaw's `sessionId`, `sessionKey`, `runId`, `toolCallId`; no Claude CLI session id, no child pid, no spawn token. But the static read also shows two facts the earlier rounds did not record. **(a)** For the `claude-cli` backend (`sessionMode: "always"`) OpenClaw **mints the Claude session id itself** before spawn (`crypto.randomUUID()` in `resolveSessionIdToSend`) and passes it as `--session-id`, or passes the stored id as `--resume`; so the gateway holds the exact string the Claude Code PreToolUse hook later hashes, in the same runtime module that builds the plugin context, for every **non-fork** turn including a fresh cron turn (on a `--fork-session` turn it holds only the *requested* parent id before spawn and learns Claude's effective id from the stream afterwards, §5). It just does not put it on the context, in the child environment, or in the session store until the run commits. **(b)** After a turn commits, that id is persisted host-side as `SessionEntry.cliSessionIds["claude-cli"]`, and plugins can read it in-process through `api.runtime.agent.session.getSessionEntryAsync({ sessionKey, agentId })` (sync `getSessionEntry` in 10.4; async added by 11.1). The general case (first turn of a fresh session, which is every isolated cron turn and the 25 Oct incident) therefore **remains upstream-blocked**, and the minimal upstream contract is one optional field (§5). A partial bridge for resumed turns (the long-lived main-session hits in the issue body) can be *constructed* today from the committed binding without any OpenClaw change and without a per-call binding record (§4, Option A). Review found that it does **not** meet the #554 acceptance constraints: the binding it reads lives in a same-uid-writable store, the Claude id it matches is caller-selectable (`claude --session-id <id>`), and the selection rule cannot tell from `PluginHookToolContext` whether the current run is a `claude-cli` run that actually resumed that binding without forking. Option A is therefore kept as analysis and **withdrawn as an implementation candidate** until a trusted, process-bound identity for the current run is demonstrated (§4.3, §6). The §5 contract is the path, with its own fork-turn limitation stated there.

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

So the string the Claude Code hook will report as `session_id` exists as `resolvedSessionId` inside the gateway, in the same module whose L1535-1557 builds the plugin context, on every **non-fork** turn. On a fork turn (`--resume <id>` plus `forkArg` `--fork-session`) `resolvedSessionId` is only the *requested* parent id; Claude runs under a new id that OpenClaw learns from the stream after spawn (`pickCliSessionId`, §2.4), so the pre-spawn string and the hook's `session_id` differ (§5). Neither is wired to the other.

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
| Does one reach both planes for a **resumed** turn? | **A candidate exists, but it is not a trusted identity.** The committed `cliSessionIds["claude-cli"]` is written by the host's commit path, keyed by the host's own `sessionKey`, readable in-process by the plugin, and equal to the `--resume` id Claude reports to the hook *when* the current run is a `claude-cli` run that reused that binding without `--fork-session`. But the store is same-uid writable, the plugin cannot verify the current run's backend or resume mode from `PluginHookToolContext`, and the hook plane's id is caller-selectable. So **no** in the sense #554 requires (host-owned, bound to this child, non-replayable); see §4.3. |

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

## 4. Option A (no OpenClaw change): committed-binding identity on the plugin plane for resumed `claude-cli` turns — analysed, **withdrawn as an implementation candidate**

**Disposition.** Option A is retained in this document as analysis only. It is not recommended for implementation and its first-draft compliance claim is withdrawn (§4.3). It stays here because (i) its step 1 is the exact code path the §5 field would feed, (ii) its failure modes define the §4.5 fixtures, and (iii) the conditions under which it could be revisited are stated precisely (§4.1 steps 2a/2b, fixture (o)).

### 4.1 Rule

In `actionLeaseAdapters` (`plugins/openclaw/index.ts` L2848), when the call is **scoped** (`scopeForToolCall(toolName, args) != null`) and the plugin can resolve the run's harness identity, the plugin leases as `leaseIdentityFor(harnessSessionId)` instead of `leaseIdentityFor(ctx.sessionId)`. Resolution order, first hit wins:

1. `ctx.harnessSessionId` when a future OpenClaw exposes it (§5), and **only when both** `ctx.harnessSessionId` is a nonblank string **and** the host-owned current-run `ctx.harnessBackendId` is exactly `"claude-cli"`. A `harnessSessionId` presented with any other backend id, or with `harnessBackendId` absent, is not used: it names a child that no Claude Code hook evaluates on this run, so adopting it would be the same historical-id downgrade step 2 forbids. In that case the rule continues to step 2 and step 3. Neither field is present today; listed so the shape is forward-compatible and the §5 field lands in one place. Pinned by fixtures (p) and (q) (§4.5).
2. `entry.cliSessionIds["claude-cli"]` from `api.runtime.agent.session.getSessionEntryAsync({ sessionKey: ctx.sessionKey, agentId: ctx.agentId, readConsistency: "latest" })` (fall back to the sync `getSessionEntry` where the async form is absent), **only when all three of the following hold**, with (2a) and (2b) taken from host-owned evidence about the *current run* and never inferred from the store row:
   - **(2a) Current-run backend evidence.** The host asserts that *this run's* resolved backend is `claude-cli` (`context.backendResolved.id` inside `execute.runtime`, or the §5 `harnessBackendId`). `entry.sessionId === ctx.sessionId` proves only that the row belongs to this OpenClaw session; it says nothing about which backend this run spawned. A session that ran `claude-cli` on an earlier turn and another backend on this one still carries the old Claude id in its row.
   - **(2b) Current-run binding evidence.** The host asserts that this run was spawned with `--resume <id>` where `<id>` equals the stored value, **and not** with `--fork-session` (§4.2, §5). The plugin cannot observe `useResume`, the resolved args, `claudeCliInvalidatedReason` or `forkNextResume`; a stored value may be *retained* from an earlier turn that this run did not resume, or resumed under a fork that gives Claude a new id.
   - **(2c)** the row is the live incarnation (`entry.sessionId === ctx.sessionId`) and the value is a nonblank string.

   If (2a) or (2b) is unavailable, step 2 **must not fire**. On every published OpenClaw release inspected here (2026.10.4 → 2026.11.2) neither is available to a plugin, so step 2 is unreachable today and Option A reduces to step 1, i.e. to the §5 contract.
3. Otherwise `ctx.sessionId`, exactly as today (strict identity).

The first draft of this rule gated step 2 on (2c) alone. That would let a run whose backend has switched, or whose binding was invalidated, forked or otherwise not resumed, lease as a *historical* Claude identity and re-enter a hold held under that id with no corresponding Claude hook evaluation on this run. That defect, together with §4.3, is why Option A is withdrawn rather than recommended.

Unscoped calls never read the store and never derive. Release uses the identity captured at acquire (the #856 `acquiredAs` WeakMap), unchanged.

### 4.2 What it covers and what it does not

- **Covers:** turn N≥2 of a session whose previous turn committed a Claude binding and whose current turn reuses it (`prepare.runtime` L1765-1812 → `mode: "reuse"`/`"reuse-with-drift"` → `--resume <id>`). Claude Code's hook then reports that same id. This is the long-lived main-session class in the #854 body (install, security-config, gateway-restart, npm-publish hits in a resumed chat session).
- **Does not cover:** the first turn of a fresh session (no committed binding yet; OpenClaw passes a freshly minted `--session-id` the plugin cannot see). Every isolated cron turn is in this class, including the 25 Oct `openclaw backup create --verify` incident. Also not covered: a turn where OpenClaw invalidates or forks the binding (`claudeCliInvalidatedReason`, `forkNextResume` → `--fork-session`): Claude runs under a new id, the store still holds the old one. Also not covered: a **backend switch** (the session ran `claude-cli` earlier and runs another backend now): the row still holds the Claude id, no Claude hook runs on this turn, and without (2a) the plugin would adopt an identity no hook plane on this run can corroborate.
- **Behaviour in the uncovered cases:** step 2 must not fire (§4.1), so the plugin leases as `leaseIdentityFor(ctx.sessionId)`, strict identity, which is exactly what every published release does today (the plugin identity is always OpenClaw's `sessionId`); the hook derives Claude's live id; they differ; the second plane is refused. The plugin never leases as this session's *previous* Claude id in an uncovered turn: that would be the historical-id downgrade §4.1 forbids (the first draft's (2c)-only defect), and fixtures (k)-(n) pin its absence.

### 4.3 Against the acceptance constraints — where Option A fails (compliance claim withdrawn)

- **Host-maintained binding of *this* child: NOT MET.** The value is written by OpenClaw's commit path (§2.4), but it rests in `~/.openclaw/agents/<agent>/sessions/...`, a same-uid-writable store that the agent process can rewrite, and the id it names is a Claude `--session-id` that any same-uid process can choose when it launches `claude`. The constraint asks for a host-maintained binding of the process instance; a rewritable row plus a caller-selectable child id is neither. The hook plane's pre-existing trust in stdin `session_id` does not license extending the same trust to the plugin plane: that widens the exposure from one plane to both, which is exactly the outcome §4.4 item 1 describes. The first draft's statement that this constraint was met is withdrawn.
- **Not presentable: PARTIALLY MET.** A sibling cannot pass A's id as a tool-call parameter, and the plugin never reads an identity from tool-call arguments. But a same-uid process can write A's id into its own store row and launch Claude under it (§4.4 item 1). "Not a parameter" is not "not presentable".
- **Bound to the current run: NOT MET today.** Steps 2a/2b (§4.1) are the conditions under which the stored id would be known to describe *this* run; no published release lets a plugin establish them.
- **Sibling B HELD (honest siblings):** B's identities differ from A's on both planes; both refuse while A holds. Unchanged. This holds only for a sibling that does not rewrite its row.
- **Forged / expired / missing:** a missing or blank `cliSessionIds["claude-cli"]`, a store row whose `sessionId` is not this run's `ctx.sessionId`, a read failure or a throw all fall to step 3 (strict identity, today's behaviour). There is nothing to expire because nothing is minted per call. A **forged** row with a *matching* `sessionId` and a victim's Claude id is **not** caught by any rule that lets the store row stand in for (2a)/(2b) (the first draft's (2c)-only gate, or any revival that reads the evidence from the row): that is the disqualifying case. Under the revised rule it is HELD only because step 2 cannot fire without host-owned evidence; the revival acceptance gate (fixture (o) and mutation M-o, §4.5) pins exactly that.
- **Freeze first; no early release; off elsewhere:** the freeze check and the held-branch order in `checkSessionLease` are untouched; nothing releases before the operation; the hook, `evaluateAction` and host adapters are untouched. Only the OpenClaw plugin's identity selection would change.

**Result.** Option A does not satisfy the #554 acceptance constraints as they are written, and the first draft's claim that it did is withdrawn. It may be revisited only when (2a)/(2b) are available from host-owned evidence that the agent process cannot write, and fixture (o) is HELD.

### 4.4 Residual risks to weigh in review (stated, not minimised)

1. **Trust in the host session store — disqualifying, not residual (see §4.3).** The store is same-uid writable (`~/.openclaw/agents/<agent>/sessions/...`). An agent process that rewrites its **own** row's `cliSessionIds["claude-cli"]` to a victim's Claude id, *and* gets Claude to run under that id, makes both of its planes carry the victim's identity, so the lease check cannot distinguish it from the victim. The second half is pre-existing (the hook plane has always trusted Claude Code's stdin `session_id`, and `claude --session-id <victim>` gives it to any same-uid process today), but that does **not** justify extending the trust to a second enforcement plane; the first draft argued that it did, and that position is withdrawn. Whether the sessions store should join the `security-config` write-shape set is a separate scope question and remains open.
2. **Historical-id inheritance (prevented, not residual).** In an uncovered turn the plugin leases as `ctx.sessionId` (§4.1 step 3), never as this session's *previous* Claude id. Leasing a historical Claude id is a forbidden downgrade, not a fallback: it could re-enter a hold left by an earlier Claude process with no Claude hook evaluation on this run, and it could coincide with another live session's identity if OpenClaw were ever running Claude under that id concurrently (its fork-on-resume design, `forkCliSessionBindings` and `--fork-session`, makes that unlikely, but the rule does not rely on it). The prevented counterfactual is pinned by fixtures (k), (l), (m) and (n) (§4.5), whose mutations fire step 2 without (2a)/(2b) and must FAIL. Fixture (e) pins a different guard, the (2c) incarnation match, and is not the evidence for this item.
3. **Store read in the enforcement path.** One worker-backed read per **scoped** call (scoped calls are rare: install, security-config, npm-publish, gateway-restart). Cache per `(sessionKey, runId)` for the run. A read that is slow, fails or throws falls to step 3; it must never fail open to `''`/`anon-pid`.
4. **API lifetime.** Sync `getSessionEntry` is deprecated for removal in the first January 2027 stable release; the design uses the async form where present and sync only on dists that lack it.
5. **Derived keys in refusal text.** Unchanged from #856's residual list.
6. **Backend switch and retained binding (prevented, not residual).** The row's Claude id outlives the run that produced it: a later turn on another backend, a turn after invalidation, or a forked turn all still satisfy (2c). Under the §4.1 rule none of them inherits the historical id, because step 2 also requires (2a) and (2b) and otherwise falls to strict `ctx.sessionId`. The inheritance is the *mutation* that fixtures (k), (l), (m) and (n) exercise (step 2 firing on (2c) alone, or without (2b)), and each must FAIL under it; it is not a behaviour this design retains.

### 4.5 Synthetic regression plan for any future identity-selection implementation (fixture-only; no live host)

Kept for the §5-fed path (step 1) and for any revival of step 2 once (2a)/(2b) exist. Pure plugin/adapter tests with a fixture lease dir and a stubbed `api.runtime.agent.session` plus a stubbed current-run evidence source (`harnessBackendId`, requested id, fork flag). The first draft required *every* fixture to fail when the rule is removed; that requirement is withdrawn because it is impossible for cases whose purpose is to preserve today's behaviour. Fixtures are split into two classes with different mutation contracts, and each names its exact expected failure.

**Class P — positive regression.** Each must PASS with the rule and FAIL with the rule removed (steps 1/2 reverted to step 3). Removing the rule must fail *all* of Class P and *none* of Class I, and the revival-gate fixture (o) must still be HELD.

- (a) **Resumed turn, hook first:** hook holds `security-config` as `sc-HMAC(C1)`; plugin ctx `{ sessionId: O1, sessionKey: K1, agentId: A }`, current-run evidence `{ backend: "claude-cli", resumed: C1, fork: false }`, store row `{ sessionId: O1, cliSessionIds: { "claude-cli": C1 } }`; plugin scoped `exec` → allowed as same holder, `acquired: false`, nothing released. Expected failure without rule: HELD.
- (b) **Resumed turn, plugin first:** plugin acquires as `sc-HMAC(C1)`; hook plane evaluates with `self = sc-HMAC(C1)` → same holder. Expected failure without rule: hook HELD against a plugin holder under `leaseIdentityFor(O1)`.
- (h) **Release parity:** acquire as `sc-HMAC(C1)` via the derived path, salt lookup then fails → release still frees exactly that hold (extends the #856 r2 case). Expected failure without rule: the hold is acquired under `O1`, so the assertion on the released identity fails.
- (j) **Old dist without `getSessionEntryAsync`:** sync `getSessionEntry` used with the same evidence as (a) → allowed. Expected failure without rule: HELD. Absent both APIs → step 3 (this half belongs to Class I and is asserted there as (j′)).
- (p) **§5 field present:** ctx carries `harnessSessionId: C1, harnessBackendId: "claude-cli"`, store stub asserts it was never called, result as (a). Expected failure without rule: HELD.

**Class I — safety invariants.** Each must PASS both with and without the rule (they pin behaviour the rule must not change) and must FAIL against the unsafe mutation it names. One mutation can legitimately remove the guard that several fixtures depend on (M-k, step 2 firing on (2c) alone, also fails (l), (m) and (n)), so the contract is per mutation, not per fixture: each mutation has an **expected failing set**, listed after the fixtures, and a mutation run passes the evidence bar when exactly that set fails and every other fixture in both classes passes.

- (c) **Fresh turn:** store row has no `cliSessionIds`, evidence `{ backend: "claude-cli", resumed: null }` → plugin leases as `leaseIdentityFor(O1)`; hook as `sc-HMAC(C2)` → second plane HELD. Mutation M-c: step 2 returns a minted or guessed id → the refusal disappears → FAIL.
- (d) **Sibling B:** rows `{O1→C1}`, `{O2→C2}`; A holds; B's plugin and B's hook both HELD. Mutation M-d: derive the identity from a tool-call argument or caller-supplied field → B allowed → FAIL.
- (e) **Stale store row:** row `{ sessionId: O0, cliSessionIds: { "claude-cli": C1 } }` with `O0 !== ctx.sessionId`, current-run evidence `{ backend: "claude-cli", resumed: C1, fork: false }` (so (2a) and (2b) hold and only (2c) blocks) → step 3; HELD against a hook holder under `sc-HMAC(C1)`. Mutation M-e: drop the (2c) guard → allowed → FAIL.
- (f) **Read failure / throw / timeout:** stub rejects → step 3 (never `''`, never `anon-pid`), scoped call still gated. Mutation M-f: on throw fall to `''`/`anon-pid` → fail-open observed → FAIL.
- (g) **Unscoped call:** store stub and evidence stub assert they were never called. Mutation M-g: remove the scoped gate → stub called → FAIL.
- (i) **Freeze wins:** freeze set + matching derived id → FROZEN, not allowed. Mutation M-i: identity match evaluated before the freeze check → allowed → FAIL.
- (j′) **No store API at all:** both forms absent → step 3 → HELD against a hook holder. Mutation M-j′: treat a missing API as "trust the row cached from an earlier run" → FAIL.
- (k) **Backend switch (new):** row `{O1→C1}` from an earlier `claude-cli` turn; current-run evidence `{ backend: "codex" }` or absent; a hook holder exists as `sc-HMAC(C1)` (left by the earlier Claude process); plugin must lease as `leaseIdentityFor(O1)` → HELD. Mutation M-k: step 2 fires on (2c) alone → plugin re-enters as C1 with no Claude hook on this run → FAIL.
- (l) **Retained binding, not resumed this run (new):** row `{O1→C1}`; evidence `{ backend: "claude-cli", requested: C3 via --session-id, resumed: null }` (binding invalidated: `claudeCliInvalidatedReason` set) or evidence absent; plugin leases `O1`; hook reports C3 → HELD. Mutation M-l: step 2 fires without (2b) → plugin leases C1 → FAIL.
- (m) **Fork turn (new):** row `{O1→C1}`; evidence `{ backend: "claude-cli", requested: C1, fork: true }`; Claude reports C4. Plugin must not adopt C1 → strict → HELD; with the §5 field, `harnessSessionId` must be **absent** on this turn (§5). Mutation M-m: forward the requested id as effective → plugin leases C1 and can re-enter a hold under the parent's live Claude id → FAIL.
- (n) **Same-row invalidation (new):** row `{O1→C1}`, live incarnation, so (2c) holds; host-owned current-run evidence `{ backend: "claude-cli", resumed: null, invalidated: true }` (the host's `claudeCliInvalidatedReason` signal, which the plugin cannot observe itself (§4.1 2b) and therefore only ever receives as evidence); Claude runs under a fresh id C5. Two holder placements, each tried in both plane orders: (n-i) a hook holder under the live id `sc-HMAC(C5)` → the plugin leases `O1` → HELD; (n-ii) a stale hook holder under `sc-HMAC(C1)` left by the earlier Claude process → the plugin still leases `O1` → HELD. Mutation M-n: when the evidence reports `resumed: null`, treat the stored id as the resumed id (synthesise (2b) from the row) → the plugin leases C1 → (n-ii) is allowed → FAIL.
- (q) **§5 field under another backend (new):** ctx carries `harnessSessionId: C1` with `harnessBackendId: "codex"` (second variant: `harnessBackendId` absent); a hook holder exists as `sc-HMAC(C1)`; step 1 must not fire → strict → HELD. Mutation M-q: accept `harnessSessionId` without the backend check → the plugin leases C1 → FAIL.
- Existing `src/__tests__/session-lease-cross-plane-854.test.ts` (#854 r2 block) must stay green unchanged.

**Revival acceptance gate (outside Class I; the condition for ever re-enabling step 2).** Fixture (o), **forged store row:** the fixture "agent" writes row `{ sessionId: O1, cliSessionIds: { "claude-cli": C_victim } }` and a hook holder exists as `sc-HMAC(C_victim)`; no host-owned (2a)/(2b) evidence is supplied, so the store row is the only source available, as it is to a plugin today. Under the revised §4.1 rule the expected result is **HELD**: the row does not satisfy (2a)/(2b), step 2 does not fire, and the plugin leases strict `O1`. Mutation M-o: accept the store row as (2a)/(2b) evidence (row present and matching ⇒ assume a `claude-cli` run that resumed it without a fork) → the plugin re-enters as `C_victim` → FAIL. This is the impersonation the first draft's (2c)-only gate allowed and §4.3 calls disqualifying. Step 2 may be revived only when (o) is HELD *and* the (2a)/(2b) evidence that makes a positive case pass comes from host state the agent process cannot write; an implementation PR must quote (o)'s result and M-o's failure explicitly.

**Expected failing set per mutation** (the evidence bar for each mutation run: exactly this set fails, everything else in Class P, Class I and the gate passes):

| Mutation | What it removes or adds | Expected failing set |
|---|---|---|
| M-c | step 2 returns a minted or guessed id when the row has none | (c) |
| M-d | identity derived from a tool-call argument or caller-supplied field | (d) |
| M-e | (2c) incarnation guard dropped | (e) |
| M-f | read failure falls to `''`/`anon-pid` | (f) |
| M-g | scoped gate removed | (g) |
| M-i | identity match evaluated before the freeze check | (i) |
| M-j′ | missing store API treated as "trust the row cached from an earlier run" | (j′) |
| M-k | step 2 fires on (2c) alone | (k), (l), (m), (n), (o) |
| M-l | step 2 fires on (2a)+(2c), without (2b) | (l), (m), (n) |
| M-m | requested id forwarded as effective on a fork turn (`harnessSessionId` populated) | (m) |
| M-n | `resumed: null` overridden by the stored id | (l), (n) |
| M-q | `harnessSessionId` accepted without the `harnessBackendId === "claude-cli"` check | (q) |
| M-o | store row accepted as (2a)/(2b) evidence when host-owned evidence is absent | (o), plus the evidence-absent variants of (k) and (l) |

PR evidence required before any merge of an implementation: the failing-then-passing run for Class P; the rule-removed run quoted with counts (all P fail, all I pass); one run per named mutation (M-c, M-d, M-e, M-f, M-g, M-i, M-j′, M-k, M-l, M-m, M-n, M-q, and M-o for the revival gate) quoted with counts, each matching its expected failing set in the table above and nothing else; the result of (o) and the failure of M-o stated explicitly; `npm run guard:precision -- --planes` unchanged; and the README feature grid untouched (no user-visible capability is added; the fix removes a false refusal).

---

## 5. Option B (upstream): the minimal OpenClaw API contract

Precisely one optional field on the existing tool-hook context, populated from a value OpenClaw already holds in the same module:

```ts
// PluginHookToolContext (config-contracts d.ts, L15036 in 2026.11.1)
/**
 * Effective session id of the CLI harness child executing this run: the id
 * passed on its command line (`--session-id <id>`, or `--resume <id>` without
 * the backend's fork argument). Present only on CLI-backend runs and ABSENT
 * when the run was spawned with `--fork-session`, because the child then runs
 * under a new id the host learns only after spawn. Host-minted; never taken
 * from the tool call or the child.
 */
harnessSessionId?: string;
/** CLI backend id that owns `harnessSessionId`, e.g. "claude-cli". */
harnessBackendId?: string;
```

Population point: `execute.runtime` builds the plugin context at L1535-1557 from `run`; `executePreparedCliRun` (L3199) computes `resolvedSessionId` for the same run before spawn. Threading `resolvedSessionId` and `context.backendResolved.id` into the permission handler's ctx is a plumbing change inside one file plus the type.

**Requested vs effective id.** `resolvedSessionId` is the id OpenClaw *requests*. With `--session-id <id>`, or `--resume <id>` without the fork argument, Claude runs under that id and the PreToolUse hook reports it: requested == effective. With `--resume <id>` plus the backend's fork argument (`forkArg: "--fork-session"`, §2.3), which OpenClaw emits when its `forkNextResume` signal is set (a host-side signal the plugin cannot observe, §4.1 2b and §4.2), Claude resumes the transcript but runs under a **new** id that OpenClaw learns only from the stream after spawn (`pickCliSessionId`, §2.4): requested ≠ effective, and the plugin would lease as the parent's id. The contract is therefore: populate `harnessSessionId` **only** when the host can assert requested == effective (non-fork spawns); leave it **absent** on fork turns, where ShieldCortex falls to strict identity (today's behaviour, pinned by fixture (m)). Fork turns stay excluded until an effective-id propagation exists upstream (the host reading Claude's init `session_id` from the stream before the first `can_use_tool` and updating the context, or the B3 relay).

With that, step 1 in §4.1 fires on every **non-fork `claude-cli`** turn, fresh or resumed (the `harnessBackendId === "claude-cli"` check keeps a Codex or other CLI child's id out of the Claude hook plane's lease), with no store read and none of §4.4 items 1-4 and 6. What B does not change: the hook plane's own trust in stdin `session_id` (a same-uid process can still launch `claude --session-id <victim>`), so B gives the plugin plane a host-owned identity but is not yet a process-bound binding of the child; only B3 removes that remaining element. That residual is stated, not minimised, and is why B is described as the *minimal* contract rather than the complete one.

Alternatives, in order of preference if the field is refused:

- **B2.** Persist the pre-spawn binding (`setCliSessionBinding` before `executePreparedCliRun`, cleared on failure) so §4 step 2 covers fresh turns. Larger blast radius (store semantics around retries, forks and interrupted replacements, `shouldClearInterruptedCliSessionBinding`), so not preferred.
- **B3.** A Claude-side native hook relay with host registration, mirroring the Codex relay (`native-hook-relay-B_V9WH_m.mjs`: `{ relayId, sessionId, sessionKey, runId, pid }`, dead-pid reaping). Strongest binding (process-instance), largest change; it would also move Claude's native PreToolUse gate into `before_tool_call`, which changes who evaluates what and needs its own review.
- **Not proposed:** exporting the OpenClaw session id to the child environment (a caller-readable env string, exactly what #554 excludes), or forwarding MCP `_meta` (does not exist on the native path, and the MCP path's `toolCallId` is `mcp-<uuid>`).

The upstream request itself is **held** per the standing owner decision on #854 and is not filed by this document.

---

## 6. Recommendation

1. **Option A is withdrawn as an implementation candidate; do not implement it.** Its first-draft compliance claim is withdrawn (§4.3): the identity it selects is read from an agent-writable store and matched to a caller-selectable Claude id, and the selection rule cannot verify the current run's backend or resume mode (§4.1 2a/2b). It is retained as analysis because step 1 is the code path the §5 field would feed and its failure modes define the §4.5 fixtures. It may be revisited only when (2a)/(2b) are available from host-owned evidence the agent process cannot write and fixture (o) is HELD; any such revival is runtime/security work needing FULL (Sol + Grok + Daybreak) review and the §4.5 evidence.
2. Record the §5 contract, with the requested/effective distinction and the fork exclusion, as the one factual blocker for the Claude CLI runtime on #854; file it upstream only when the owner lifts the hold. Note on #854 that B3 (process-instance relay) is the only option that also removes the hook plane's trust in stdin `session_id`.
3. Keep #673/#875 (lease refusals must not raise approval cards) as the mitigation for **all** Claude CLI turns in the meantime, not only fresh ones, since no identity-selection change is recommended from this round.

## 7. What was not done

No code was written or run; no tests were written; no OpenClaw host, gateway, Guard state, lease directory or session store was read; no upstream issue was filed; no owner was contacted. The Claude Code binary was not re-read this round: the claim that the PreToolUse hook reports the `--session-id`/`--resume` id as `session_id` rests on the 17 Oct read of Claude Code 2.1.299/2.1.301 and on the #552/#554 field evidence, and should be re-pinned in the implementation PR's fixtures by recording a real hook stdin sample from a throwaway session.
