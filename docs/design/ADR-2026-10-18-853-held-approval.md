# ADR 2026-10-18: Held approval when nobody can be asked (#853)

Status: PROPOSED (design-first; no live-control change in this ADR or its first slice)
Issue: Drakon-Systems-Ltd/ShieldCortex#853, "never silently deny when there is no prompt surface"
Builds on: `ADR-2026-08-19-retry-control.md` (the #310 ADR) and `2026-08-19-310-retry-control.md` (DESIGN-310 v3-final).
That ADR is not edited. This one supersedes exactly one clause of it (§3) and restates the rest.

## 0. Context and evidence

The issue body reported about 60 `denied_no_prompt_surface` rows on clawdbot1, 15–18 Oct 2026.
That figure was a substring overcount. The confirmed breakdown (issue comment
[#issuecomment-6256267789](https://github.com/Drakon-Systems-Ltd/ShieldCortex/issues/853#issuecomment-6256267789),
read-only from the box's `realtime-2026-10-1[5-8].jsonl` audit files) is **34** true
`denied_no_prompt_surface` rows: all `origin: claude-code-hook` (openclaw-interceptor 0), all
`permissionMode: bypassPermissions` with `noPromptSurfaceReason` "bypassPermissions mode shows no
prompt", Bash 31 / Write 3, four distinct sessions, 19 on 16 Oct and 15 on 18 Oct. The breakdown
does not say what launched those sessions (cron, sub-agent or a worker), so this ADR does not claim
one. The owner's
requirement is to hold the action, send one plain card (What / Why / Who / outcome), tell the
agent the action is held, and report expiry as "nothing ran". Until that ships, Guard stays
advisory on every box.

What the repo says today (all CONFIRMED by reading the files named):

| Fact | Where |
|---|---|
| `denied_no_prompt_surface` is written only by the Claude Code hook, with `origin: 'claude-code-hook'` | `scripts/pre-tool-hook.mjs` `emitApprovalRequired` (~L2991) |
| The hook decides "no prompt surface" from `permission_mode` alone | `noPromptSurfaceReason` (~L442) |
| The OpenClaw interceptor's no-approver branch writes `failure_denied`, not DNP, and raises no card | `plugins/openclaw/interceptor.ts` ~L2406–2429 |
| OpenClaw holds back `requireApproval` from cron and heartbeat sessions on purpose ("recreates #112: the turn waits out the timeout on a decision nobody can give") | `plugins/openclaw/index.ts` `handleTypedBeforeToolCall`, `isTrustedAutomationSession` |
| OpenClaw sub-agent sessions (`agent:X:subagent:…`) do not match the cron or heartbeat regex, so they get the host card | same file, `HOST_CRON_SESSION` / `HOST_HEARTBEAT_SESSION` |
| The #310 waiter maps `allow-once → grantRetry`, `deny → recordDenySuppression`, and anything else (including expiry) to nothing. Expiry writes no row | `src/defence/iron-dome/dnp-retry-waiter.ts` |
| A #310 grant is spent only by a retry of the same canonical hash, AND-matched on `{cwd, tool}` | `retry-control.ts` `consumeRetryGrant`; hook consume ~L3466 |
| The agent-facing deny text is `terminalDecisionReason`. Before slice 1 it was static (a literal `<actionId>`) and the #853 notice went to stderr only; slice 1 puts the notice, with the real actionId, into `permissionDecisionReason` | `pre-tool-hook.mjs` `terminalDecisionReason`, `alertGuardOutcome`, `emitApprovalRequired` |
| `actionGuard.retryCards` defaults to false. Absent, junk and `"true"` all count as off | `normaliseRetryControlConfig`; pinned by `retry-card-copy-853.test.ts` |

Which plane produced the clawdbot1 rows: **CONFIRMED** the Claude Code hook in
`bypassPermissions` (34 of 34, per the comment above), which matches the repo fact that the hook
is the only writer of the outcome name. That classification half of R0 (§9) is done. So
**Plane A in `bypassPermissions` is the first target.** The interceptor's no-approver
`failure_denied` branch has the same silent-deny shape and stays in scope, but later: this
evidence shows no interceptor no-surface failures on clawdbot1 (the comment attributes that box's
interceptor refusals to the separate lease self-refusal, #854). The acceptance metric still
counts eligible interceptor rows once Plane B ships (§9).

## 1. Decision (summary)

1. **Two planes, two different meanings of "hold".** They are never merged, and neither reads the
   other's store.
   - **Plane A, the Claude Code hook (first; this is where all 34 clawdbot1 rows came from, in
     `bypassPermissions`).** It cannot pause. "Held" means *refused now, with a single
     operator decision pending that, on Approve, lets one retry of the exact same call through*.
     This is the #310 mechanism with new copy, a new outcome name and expiry reporting.
   - **Plane B, the OpenClaw interceptor (later; the clawdbot1 evidence shows no no-surface
     failures on this plane).** It can (LIKELY) pause: our own plugin header
     (`plugins/openclaw/index.ts`) says `before_tool_call` is awaited in-process. That is
     ShieldCortex's reading, not something verified against OpenClaw for an await of up to
     10 minutes, or for cron and sub-agent sessions specifically (see U3, U10). "Held" means *the tool call is suspended in the running turn until the operator
     answers or the card expires*. Approve runs that exact suspended call, once. Nothing spendable
     is ever written to disk.
2. **One card per held identity**, using a dedupe key per plane (§5). A second matching
   event while a card is live never raises a second card.
3. **Expiry and Deny are always reported** as "nothing ran", on the channel the card went to,
   using a follow-up notice with no buttons.
4. **Catastrophic tier: no hold, no card, no grant, on either plane.** Unchanged.
5. **Dark by default on both planes.** No default, posture or enforce setting changes here.

## 2. What is restated unchanged from the #310 ADR

- Clause 1: Claude Code PreToolUse never pauses. Plane A stays deterministic deny-now.
- Clause 3: a tap is not a TTY review. Nothing from a card ever mints or spends `reviewedScripts`. No `allow-always`.
- Clause 5: no silent new trust surface. This ADR, the dark launch and the soak gate are the process.
- Mint on operator intent, not on denial. A denial leaves a claim ticket, never a spendable record.
- Plane A's grant mechanics, nonce, single flock plane, deny-beats-approve, budget, prune precedence: all of DESIGN-310 §B1–B6 and the R3 binding rules 1–10, *except* the part of rule 10 named in §3.
- Webhooks and digests carry actionIds, never spendable tokens.
- Payload text (tool input, prompt text, `[cron:…]` envelopes) never mutes, triggers or scopes a card.
  `permission_mode` is different and is not neutral: `noPromptSurfaceReason` uses it, and only it,
  to decide between `ask` and `denied_no_prompt_surface`, and only a `denied_no_prompt_surface`
  denial can reach the card path. So `permission_mode` decides whether a call is card-eligible at
  all. It never mutes a card, never scopes a grant (that is `{tool, canonical cwd}` plus the hash),
  and plays no part in the dedupe key or the Who line.

## 3. Supersession: the interceptor exclusion, narrowed

The #310 ADR says: *"The OpenClaw interceptor is out for CARDS and for CONSUME … Anyone extending
this to the interceptor is writing a new ADR, not a patch."* This is that ADR.

**Superseded (cards only):** the interceptor MAY raise a held-approval card for its own
in-process hold (Plane B, §4.2).

**Retained, verbatim in effect (consume):** the interceptor never reads, writes or consumes
`retry-control.json`, the #118 approvals store, or any grant minted from a hook denial. The
#310 reason still holds: a hook-minted grant is bound to `{cwd, tool}` on the Claude Code plane
and means nothing on the gateway plane. Plane B needs no store, because it binds the decision to
the suspended call object itself, which is a stronger binding than any on-disk grant.

Why this model is safe enough to supersede on:
- No new spendable artefact exists. The approval resolves a promise held by the same gateway
  process for the same `before_tool_call` invocation. If the process dies, the promise dies, and
  nothing can be replayed later.
- The decision is meant to come back as the response to the `plugin.approval.request` the hold
  itself issued, so ShieldCortex authenticates nothing extra and trusts no new caller. This is
  UNVERIFIED for Plane B: the #310 waiter reaches that method through a separate
  `openclaw gateway call` CLI process (`dnp-retry-waiter.ts`), not from inside a running
  `before_tool_call`. Whether the in-process plugin API can place the request from there, and
  whether the response is bound to the requesting connection, must be confirmed against OpenClaw
  before slice 3 (U10). If it cannot, Plane B falls back to the waiter's transport and this
  paragraph is re-reviewed.
- The #112 failure (a turn waiting forever on nobody) is closed by a hard deadline: the card
  lifetime, after which the hold fails closed and expiry is reported.

## 4. Per-plane hold semantics

### 4.1 Plane A: Claude Code hook (held-for-retry)

Event order for a dangerous-tier call with no prompt surface. Steps 1–4 are the existing #310
order (suppression first, then digest and budget, then card):

1. Suppressed (a live operator Deny): the outcome stays `denied_no_prompt_surface`, no card. The agent is told the operator denied this recently.
2. Fingerprint upsert by `(hash, canonical cwd)`, as today.
3. Card eligibility: `retryCards === true` AND scopeable (cwd present) AND a launch claim is won (per-identity budget 1, epoch-pinned; global 3 per window) AND the waiter spawned and wrote `requesting`.
4. **Outcome naming (new):**
   - Eligible, with the card handed to the waiter: the outcome is **`held_for_retry`**.
   - A live claim already exists for this identity (a remint): the outcome is **`held_for_retry`** with `cardDedupedTo: <actionId of the live card>`. No new card.
   - Not eligible (cards off, budget exhausted, unscopeable, spawn failed, waiter `failed` within the poll window): the outcome stays **`denied_no_prompt_surface`**, with a `noCardReason`. These are the rows that "a card could not have held". The acceptance metric excludes them by reason, never by guessing.
5. The hook decision is still `deny`. Claude Code's contract is unchanged.
6. **Agent-facing text goes in `permissionDecisionReason`, not only stderr** (slice 1, done). It is
   the `retryCardAgentNotice` wording, carrying the real actionId: did NOT run, held for the
   operator, delivery not confirmed, retrying this SAME call within N minutes of the Approve runs
   it once, a retry before approval is refused again, and Deny or no answer means nothing runs.
   The static "an Approve-once card if raised" sentence is replaced whenever a card was handed
   off. When cards are on but none was raised, the reason says so with the `noCardReason` and the
   real actionId. When cards are off, the static text carries the real actionId instead of the
   `<actionId>` placeholder. The same notice is still printed to stderr. (See risk U1.)

"Approve runs the action" on Plane A means **the next retry of the identical call in the same
canonical cwd, within the grant TTL, runs once**. For a cron job, that is the next tick if the
interval is no longer than the TTL. If the interval is longer, the card already says so and points
at `approve --denial <id> --ttl` (existing #310 rule). The ADR does not claim more than this.

### 4.2 Plane B: OpenClaw interceptor (in-turn hold)

Applies when the session is host-classified automation: `isTrustedAutomationSession` (cron,
heartbeat), plus **sub-agent** sessions via a new host-shape classifier with the same tight-prefix
discipline (`agent:<id>:subagent:<tag>`). Interactive (main or direct) sessions keep the existing
host `requireApproval` card, byte-identical.

1. Broker `harden` and `pre_clear` keep their current precedence, ahead of any hold.
2. Rate limiter as today.
3. Dedupe check (§5). If a card is live for this key, the call is refused immediately with outcome `hold_deduped` and the message "already waiting on your answer for card <id>". No second card, and this call is not attached to the first card.
4. Otherwise, request one owner-channel card through the gateway approval request (`plugin.approval.request`, the method the #310 waiter calls; the in-process route is unverified, U10), with `allowedDecisions: ['allow-once','deny']` and `timeoutMs = HOLD_LIFETIME_MS` (default 10m; the 10-minute gateway ceiling is what our own comments in `retry-control.ts` and `openclaw-approval-channel.ts` say, not verified against OpenClaw here). The turn awaits it.
5. Mapping:
   - `allow-once` → **run that suspended call once** (return from `before_tool_call`). Outcome `approved`, `grantKind: 'hold'`.
   - `deny` → block. Outcome `hold_denied`.
   - `timeout` or `null` → block. Outcome `hold_expired`.
   - `cancelled` / turn aborted → block. Outcome `hold_cancelled`.
   - Transport error → block. Outcome `hold_unreachable` (§6).
   - Unknown decision string → block, with an `unrecognised decision` log line. Never guess.
6. The tool error returned to the agent says the action was held and what the operator decided,
   or that the card expired and nothing ran. It never says "failed" when the operator denied.
7. For these session kinds, `requireApproval` stays withheld. The host never draws a second
   card for the same call (the one-card rule).

The failure policy still governs **ineligible** Plane B calls: hold switch off, no owner channel
configured, or catastrophic. Those keep `failure_denied` with a `noCardReason`.

## 5. One-card dedupe key

| Plane | Key | Scope of "one" |
|---|---|---|
| A | `fingerprintId(hash, canonicalCwd)`, the #310 canonical identity (R3 rule 2) | One live card per identity per deny-epoch, plus the existing global 3 per digest window |
| B | `sha256("ocb\0" ‖ hashToolCall(tool,args) ‖ "\0" ‖ agentId ‖ "\0" ‖ sessionKind ‖ "\0" ‖ sessionBase)` where `sessionBase` is the host session key with any `:run:<n>` suffix removed | One live card per key in this gateway process |

Rules:
- `hash` is always the #118 canonical tool-call hash. Never a hash of redacted or display text.
- The keys never contain tool input that the agent could vary to dodge dedupe without changing the call itself: the hash covers the call, and the rest is host-supplied.
- Plane B keeps its dedupe set in memory only. A gateway restart forgets it, and that is safe because every hold it covered died with the process (risk U4 covers the operator's view).
- There is no cross-plane dedupe. The two planes gate different tool calls. An OpenClaw `exec` of `claude -p` is one call on Plane B, and every inner tool call is a separate call on Plane A.
- The global card budget (3 per digest window) applies to **both** planes, through the shared digest window start (#310 R3 rule 7). Plane B reads the window but writes no Plane A store. Its budget counter is in-process. A host-wide budget across planes is deferred, as risk U6.

## 6. Card channel and transport failure

There is no silent path. Every failure lands in exactly one of these rows and in the operator digest:

| Failure | Plane A | Plane B |
|---|---|---|
| Cards off / no channel configured | `denied_no_prompt_surface`, `noCardReason: cards_off \| no_channel`. Existing #331 digest page | `failure_denied`, `noCardReason`. `doctor` reports "this box cannot hold" |
| Spawn or transport fails before `requesting` | stays DNP, `noCardReason: card_spawn_failed`. Claim released (existing) | `hold_unreachable`, block now. #509 reach `unreached` |
| Transport fails after `requesting` (gateway call errors) | Row already `held_for_retry`. The waiter appends `retry_card_failed` (new) to `denials.jsonl`. The digest lists the actionId with `approve --denial` | `hold_unreachable` |
| Card delivered, gateway ack absent | Treated as delivered-unconfirmed. Copy never says "delivered" | same |
| Approve tapped, store refuses | existing `retry_grant_failed`, no ack | n/a (no store) |

The agent copy on both planes says "handed to the operator's card channel; delivery is not
confirmed". ShieldCortex has no end-to-end delivery receipt from Telegram or other channels
(CONFIRMED: the `gateway-notify-channel.ts` header says the seam has no fixed contract), so it
never claims one.

## 7. Grant lifecycle and expiry

**Plane A** (unchanged #310 state machine, plus two reported terminals):
`fingerprint → claimed(card live, epoch pinned) → granted(TTL from tap) → consumed`.
The other terminals are `expired-unanswered`, `granted-expired-unspent` and `revoked(by Deny)`.
- New: when the card expires unanswered, the waiter appends `retry_card_expired` and the digest says "card for <tool> (<actionId>) expired. Nothing ran."
- An unspent grant at TTL is reported by the existing sweeper (`formatUnspentExpiryNotice`). There is still no daemon, so the notice rides the next guard event or `approve` call. This is restated honestly, not dressed up.
- A Deny is reported (`retry_denied`, existing) with "nothing ran".

**Plane B:**
`held → approved(run once) | denied | expired | cancelled | unreachable`.
Every terminal except `approved` sends one follow-up notice with no buttons, of the form "ShieldCortex: <tool> for <who> — <denied|expired|cancelled>. Nothing ran." `approved` sends nothing extra, and the audit row is the record. The hold lifetime is
`min(HOLD_LIFETIME_MS, gateway ceiling)`. There is no extension and no re-raise for the same
held call.

Clocks (new rows only. The #310 table stands):

| Clock | Name | Default |
|---|---|---|
| Plane B hold lifetime | `openclaw.heldApprovals.holdLifetimeMs` | 10m, clamped 1–10m |
| Plane B dedupe entry | lives exactly as long as the hold | n/a |

## 8. Trust and origin binding

- **Who line.** Built only from host- or harness-supplied identity: Claude Code's `session_id` through the HMAC session tag, and OpenClaw's host session key and `agentId`. Never from tool input, prompt text or `[cron:…]` envelopes. Plane A never claims "cron" or "sub-agent", because the PreToolUse payload cannot tell them apart. Plane B names the kind only from the host-shape classifier. (The uncommitted slice follows this. Its tests assert that the raw session id is not echoed.)
- **Plane A origin binding:** unchanged. The grant is AND-matched on `{tool, canonical cwd}` with the exact hash. `sessionKey` is diagnostic only.
- **Plane B origin binding:** the in-memory suspended call. The decision is accepted only from the response to the request that this hold issued (request id equality). It is never accepted from any other caller or process.
- **Card authenticity:** Plane A uses the gateway-approver identity plus `claimNonce` (HMAC at rest, fd-passed). Plane B is intended to use the gateway-approver identity on the requesting connection (unverified, U10). Neither accepts a decision from a webhook, a chat message body or a CLI on another host.
- **Copy safety:** every card field passes the credential redactor (`buildApprovalCard`) and the line and hidden-character flattening. Secret-egress classes withhold the target. The outcome line is never truncated. (These are the uncommitted slice's rules. They are pinned by its tests.)
- **Catastrophic:** no card or hold path is reachable. A test asserts this per plane.

## 9. Rollout gates

| Gate | Requirement | Blocks |
|---|---|---|
| R0 | Classify the clawdbot1 15–18 Oct refusals by `origin` and `noPromptSurfaceReason` / failure-policy branch. **Done** (issue comment 6256267789: 34 DNP, all `claude-code-hook` / `bypassPermissions`, interceptor 0). Still open: confirm U10 (Plane B transport and await length) against OpenClaw, and U5 | Any Plane B code |
| R1 | Slice 1 (Plane A copy, the uncommitted work) merged with `retryCards` still false. Agent text in `permissionDecisionReason` (implemented in slice 1, pinned by the real-hook tests) | R2 |
| R2 | Slice 2: `held_for_retry` / `retry_card_expired` / `retry_card_failed` outcomes, plus every reader updated (`guard-readiness.ts` would-stop set, `session-guard.ts`, `dnp-digest.ts`, stop-hook summary, `cron-denial-audit-375`, webhook outcome header, `doctor`) | Soak A |
| Soak A | ≥3 days on a clawdbot1-class host, `retryCards: true`. Matrix: headless Claude Code sessions in `bypassPermissions` first (the 34-row clawdbot1 shape, Bash and Write), ≥3 distinct identities, a cron-launched and a sub-agent session if the host has them, empty origin, grant then newer DNP, budget exhaustion, deny, expiry, transport-down. **Pass:** zero `denied_no_prompt_surface` rows whose `noCardReason` is absent, exactly one card per identity per epoch, every expiry and deny reported | Plane A default flip (separate owner decision) |
| R3 | Slice 3: Plane B behind `openclaw.heldApprovals.enabled=false`, with the sub-agent classifier, the dedupe set and the follow-up notice | Soak B |
| Soak B | ≥3 days on clawdbot1. Same matrix on OpenClaw cron and sub-agent sessions, plus a gateway restart mid-hold and a turn timeout shorter than the hold. clawdbot1 showed zero interceptor no-surface rows for 15–18 Oct, so organic traffic may not exercise this; the matrix must be driven deliberately. **Pass:** zero `failure_denied` rows for eligible calls, one card per key, no double card (host plus owner) | Plane B default flip |
| E | Guard leaves advisory only after both soaks pass and the owner decides. #509 readiness rules unchanged | enforce on any box |

**No live-control change.** This ADR and slice 1 change no default, no posture, no `enforce`,
no `failurePolicy`, no `retryCards` value, and no interceptor behaviour. A test already pins
`retryCards` dark (`retry-card-copy-853.test.ts`).

## 10. Test plan (hook `bypassPermissions` first, then cron and sub-agent coverage)

Plane A tests lead, and every hook case runs with `permission_mode: 'bypassPermissions'` (the
real-hook harness default, `pre-tool-hook-retry-310.test.ts`), because that is the only shape the
clawdbot1 evidence shows. Session labels such as "cron tick" or "sub-agent" in those tests are
session ids only; the hook cannot tell launchers apart (§8).

Existing in the uncommitted slice:
- `src/defence/iron-dome/__tests__/retry-card-copy-853.test.ts` covers What/Why/Who/outcome for a Claude Code headless session, an OpenClaw cron and an OpenClaw sub-agent; a truncation order that never cuts the outcome line; secret-egress withholding; line-break and hidden-character flattening; the #310 fallback; `allow-once`/`deny` only; and `retryCards` dark.
- `src/__tests__/pre-tool-hook-retry-310.test.ts` covers a cron-tick and sub-agent hook payload through the real hook: the card leads with What/Why/Who, the raw session id is not echoed, and the JSON `permissionDecisionReason` carries the denial row's real actionId, "did NOT run", "held for the operator", "delivery is not confirmed", the retry-within-TTL wording and "nothing runs", and never `<actionId>`, "delivered" or "ran". Two more cases pin the reason when cards are on with no card channel (no-card reason plus real actionId) and when cards are off (real actionId replaces the placeholder). The catastrophic case asserts no held or no-card text.

Required before Soak A (slice 2), all in `bypassPermissions`:
0. Hook, headless worker session, Bash and Write each: DNP → `held_for_retry` → Approve → a retry of the identical call in the same cwd spends the grant once. A further retry is refused again.
1. Hook, cron tick: DNP → `held_for_retry` → Approve → **next tick's fresh session** spends the grant once. A third run is refused again.
2. Hook, sub-agent: same, with the retry from the same session.
3. Two holds for the same identity while the card is live: one card. Row 2 is `held_for_retry` with `cardDedupedTo`.
4. Card expires unanswered: a `retry_card_expired` row, and the digest says nothing ran.
5. Deny: `retry_denied`. A later retry is refused while suppression is live, and no new card.
6. Waiter transport fails after `requesting`: `retry_card_failed`, and the digest shows `--denial`.
7. Cards off or budget exhausted: `denied_no_prompt_surface` with `noCardReason`. These are excluded from the acceptance count only by that field.
8. `permissionDecisionReason` contains the real actionId, "did NOT run" and "not confirmed", and never contains "delivered" or "ran". (Pinned in slice 1 for cron and sub-agent payloads; slice 2 re-asserts it for the `held_for_retry` and `cardDedupedTo` rows.)
9. Catastrophic, under cron and sub-agent: no card, no row beyond the existing terminal one.
10. Every reader in R2 treats `held_for_retry` as a would-stop (a #509 readiness test).

Required before Soak B (slice 3):
11. OpenClaw cron session: hold → `allow-once` → the call runs exactly once. The host `requireApproval` is never offered.
12. OpenClaw sub-agent: same. The classifier rejects look-alikes (`direct:subagent`, whitespace, over 256 chars, an envelope in the prompt).
13. Hold → `deny`, `timeout`, `cancelled`, transport error: each blocks, writes its outcome, and sends one follow-up notice.
14. Dedupe: two cron runs of the same job with the same call give one card. The second is `hold_deduped`, and an Approve runs only the first.
15. A gateway restart mid-hold: no replay after restart, and a later tap on the stale card changes nothing.
16. A turn abort before the card answers gives `hold_cancelled`, and a later tap runs nothing.
17. A regression check that the interceptor never opens `retry-control.json` or the approvals dir (an fs spy).
18. Interactive OpenClaw sessions are byte-identical to today (golden).

## 11. Unresolved security risks (accepted for design, must be closed or re-accepted at the soak reviews)

- **U1: the agent may not see the held notice (Plane A). Narrowed by slice 1.** The notice is now in `permissionDecisionReason` with the real actionId, and the real-hook tests pin the JSON. What the tests cannot pin is Claude Code's side: that it passes `permissionDecisionReason` to the model on a `deny` (unverified, from memory: the hooks contract says it does). Whether hook stderr reaches the model on a JSON `deny` with exit 0 is still UNKNOWN, so stderr is kept only for the operator's terminal. Close at Soak A by reading a real headless transcript.
- **U2: Plane A "Approve runs it" depends on the agent retrying.** A cron job whose next tick is later than the TTL, or an agent that gives up (for example a one-shot `bypassPermissions` worker that exits after the refusal), never runs the approved action. Plane A is the plane implicated by all 34 observed rows, so this gap matters directly; the breakdown cannot tell which calls would have been retried. The card says "if retried", but the owner's acceptance wording ("Approve runs the action") is only met for Plane B. This needs owner sign-off.
- **U3: Plane B holds a live turn for up to 10 minutes.** An OpenClaw cron turn timeout shorter than the hold, or a host that serialises cron runs, can stall or kill the job. OpenClaw's cron turn budget, and whether it allows a `before_tool_call` await that long at all, is UNKNOWN to this codebase. Soak B must measure it. The fallback is `hold_cancelled` reported, with nothing run.
- **U4: stale cards after a gateway restart (Plane B).** The card can stay tappable in the owner's chat after the hold is dead. A tap does nothing, but the owner gets no "too late" reply unless the gateway reports one. Whether the gateway closes orphaned approval requests on restart is UNKNOWN.
- **U5: OpenClaw sub-agent routing is unverified.** Today sub-agents get the host card, and where the host shows it is UNKNOWN. Moving sub-agents to the owner channel assumes the host card was not reaching anyone. The R0 breakdown cannot settle this: it found zero interceptor no-surface rows on clawdbot1. It must be confirmed some other way before slice 3, or the change could replace a working card with a different one.
- **U6: no host-wide card budget across planes.** A box running both planes could send up to 3 cards per window per plane. A shared counter would need Plane B to write a Plane A store, which §3 forbids, so this is accepted as a 2× ceiling.
- **U7: one-tap social engineering.** The card's What line is agent-influenced (it is the redacted call). The redactor, flattening and secret-egress withholding reduce the risk but do not remove it. A carefully shaped command could read as benign in ≤256 characters. The broker `harden` path is the only model-side check, and it is off by default.
- **U8: delivery is unconfirmable.** No end-to-end receipt exists from the chat platform. "Exactly one card arrives" can be asserted only up to the gateway hand-off. Soak evidence is the owner's own count.
- **U9: same-user local processes.** Plane A's protection is the nonce and the TTY gate. A same-user process that can read the waiter's inherited fd, or the argv fallback where fd passing is unavailable, can mint a grant (the #310 accepted risk, restated).
- **U10: Plane B's transport is unverified.** That a plugin can place `plugin.approval.request` from inside an awaited `before_tool_call`, for a cron or sub-agent session, and receive the decision on that same request, is a design assumption taken from ShieldCortex's own comments and the #310 waiter (which uses a separate CLI process). None of it is confirmed against OpenClaw. Slice 3 is blocked until it is; if it fails, §3's safety argument is re-reviewed, not patched.
