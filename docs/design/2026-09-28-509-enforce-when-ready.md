# Action Guard: enforce when ready (#509)

Operator direction, 28 Sep 2026: *"Go and build the version that the false-positive rate is measured low and approvals reliably reach a human."*

This posture enforces only once three conditions hold. Two of them are **readiness proxies for operability**, measured on each install's own traffic. The third is **reviewed effectiveness evidence**, which is required by default and does not exist yet.

**What the proxies are not.** They are not the ADR-002 §5B bars, and passing them is not a §5B result. §5B's ≤ 2% is unintended blocking of *legitimate work* on frozen fixtures with a frozen denominator. §5B's ≥ 98% is *legitimate task completion* along the approval path. The proxies use a different denominator (every gated call) and a different event (a human answered). So the intervention rate is not a false-positive rate, and it is not a bound on one either, because false positives ÷ legitimate work can exceed would-stops ÷ all calls. The 2% and 98% thresholds are operability thresholds chosen for this posture.

This is not the ADR-002 §8 decision. Session taint (§2.2), the §2.4 effect decision and dangerous-tier narrowing are untouched. The verdicts are exactly the guard's verdicts; the posture only decides whether a dangerous-tier verdict is applied or recorded.

## The postures

| posture | config | dangerous tier | catastrophic tier and lease floor |
|---|---|---|---|
| Off (default) | `enabled: false` | not looked at | not looked at |
| Watch only | `enabled: true, enforce: false` | logged, runs | blocked |
| Enforce | `enabled: true, enforce: true` | approval or block | blocked |
| **Enforce when ready** | `enabled: true, enforce: true, readinessGate: true` | **shadow** (logged as `would_hold` / `would_block`, runs) until all three conditions hold, then approval or block | blocked, identically in shadow, enforcing and demoted states |

Set it with `shieldcortex config --action-guard-enforce-when-ready`, or pick it when `shieldcortex setup` asks. Non-interactive setup changes nothing; the default stays off. Setup marks none of the three choices as recommended. That waits on the operator's decision about the effectiveness condition.

`readinessGate` is a separate key rather than a new value of `enforce`, so every reader that does not know it (older hooks, the OpenClaw plugin, the policy lock schema) reads an enforcing guard. Not knowing the gate is the tighter reading.

**Scope today:** the gate is implemented on the Claude Code `PreToolUse` hook. The OpenClaw plugin ignores `readinessGate` and enforces from the start. A policy lock (`/etc/shieldcortex`) pins enforcement, so the gate is ignored on a locked host, and the setter refuses to turn it on there.

## The three conditions

The proxies are recomputed from the audit log (`~/.shieldcortex/audit/realtime-*.jsonl`; `SHIELDCORTEX_CONFIG_DIR/audit` is read too when that override is set). Constants live at the top of `src/defence/iron-dome/guard-readiness.ts`.

**1. Operational intervention rate (readiness proxy).** Over the last 14 days of real Claude Code hook calls: would-stops ÷ all counted calls ≤ 2%, with at least 500 calls spanning at least 7 days.

- A would-stop is any non-catastrophic `would_hold`, `would_block`, `asked`, `denied_no_prompt_surface`, `warned` or `auto_denied` row.
- It measures how often the guard would get in the way of this install's work. It does not say how many of those stops were wrong.
- Counted calls are rows with origin exactly `claude-code-hook`. Excluded: `gate_degraded` rows, `notify` rows, rows marked `synthetic`, session-lease refusals, and rows from any other origin (OpenClaw interceptor, canaries, proofs).
- Under this posture a benign allow writes a minimal tally row (no command text) so the denominator is every gated call. That is one extra audit row per tool call.

**2. Approval reachability (readiness proxy).** Over the last 30 days: of approval requests put to the configured human channel, ≥ 98% got a human answer (approve **or** deny) within 15 minutes, with at least 20 resolved requests, **and** at least one answered round-trip in the last 7 days. A human answering is not the task completing.

- **No configured human channel ⇒ not ready.** A channel is `actionGuard.notify` with `enabled: true` and either `openclaw: true` (the approval card) or an http(s) `webhookUrl`.
- **Promotion also needs a channel that can push a notice.** The OpenClaw card channel carries approvals only; it cannot deliver a plain demotion notice. So an install whose only channel is the card (`{enabled: true, openclaw: true}` with no `webhookUrl`) is never promoted, and readiness says why: add `--action-guard-notify-webhook <url>`. A demotion on a promoted install can therefore always reach the operator.
- A request is recorded when the hook sends it to the channel. The answer is recorded when a human approves or denies it (`shieldcortex approve` / `deny` in a terminal, or a tap on the OpenClaw card).
- **Each delivery is its own attempt.** The approval store mints a fresh correlation id every time it records a refusal, the request row carries it, and an answer counts only for the attempt it names. The same command asked ten times is ten attempts: one answer to the eleventh does not erase the ten that expired. An answer that names no attempt binds to nothing.
- Not a reach: an answer after 15 minutes, a card that expired, a request the channel did not accept, a denial for want of a prompt surface, and the hash-in-transcript fallback when the configured channel failed.
- On a quiet box, `shieldcortex guard test-approval` (terminal only) sends a clearly labelled synthetic request through the channel and records whether you answered. It never approves anything: it does not import the approval store, and its hash is 256 random bits. For a card you tap Approve or Deny; for a webhook you type the 6-digit code the message carries. Synthetic round-trips count toward reachability, because they test the same channel end to end.

**3. Effectiveness evidence.** Low intervention plus reachable approvals says the guard is tolerable to run. It says nothing about whether it stops attacks. So automatic promotion also needs independently reviewed effectiveness evidence (the effect-based red-team exam), pinned to the adapter + policy version in force.

- One constant and one config key: `EFFECTIVENESS_EVIDENCE_REQUIRED = true`, overridden only by `actionGuard.readinessRequireEffectivenessEvidence: false`. The operator's decision either way is a one-line change.
- Evidence is an entry in `REVIEWED_EFFECTIVENESS_EVIDENCE`, a registry in the source that changes only through code review. It is never read from a same-UID file an agent could write, and this module never attests it. An entry names the adapter and policy version, the reviewer, a reference to the exam, the review date (at most 90 days old) and the number of attack cases (at least 50, a proposed floor that the exam's own design should set).
- **The registry is empty.** With the default, an install stays in shadow. Once both proxies pass, `guard readiness`, `doctor` and the state file say exactly: *"operability proxies met; awaiting reviewed effectiveness evidence"*. Before then they list everything that is missing, the evidence included.

`shieldcortex guard readiness` and `shieldcortex doctor` show the posture, the current mode, the version pin, each proxy against its threshold and sample, the effectiveness condition, the last round-trip, and what is missing. Both are read-only: they never promote, demote or write readiness state.

## Evidence pinning and soundness

- Every evidence row the hook writes under this posture carries a `readinessPin`: the adapter (`claude-code-hook@<package version>`) and the policy (a digest of the guard's rule module as built). Only rows pinned to the version in force count. An upgrade or any rule change starts the evidence over. Rows from another version are shown as "not counted".
- The state file records the pin its mode was computed under. A cached mode from another version is not reused.
- Each input has a minimum sample and a freshness window: 500 calls over ≥ 7 days within 14 days; 20 resolved requests within 30 days plus a round-trip within 7 days; a review within 90 days.
- Missing, empty, unreadable or unparseable evidence never qualifies. A missing or empty audit is short of the sample. An evidence file that cannot be read makes the install not ready and says so.
- **Every complete line in the window is parsed and validated before any origin or type filter.** A line that is not a JSON object, or an evidence row (hook `intercept`, `approval_reach`, `readiness_transition`) without the fields readiness reads, is a malformed record, and any malformed record invalidates the measurement: not ready, with the count named. Only the last line of a file, and only when it has no trailing newline, is treated as an append still in flight and left for the next recompute. A version pin that cannot be determined is not ready.

## Promotion, demotion, hysteresis

- **Promote** as soon as all three conditions hold (announced on stderr, audited as a `readiness_transition` row).
- **Demote** to shadow when any condition has been failing for 1 hour continuously. One bad recompute does not flip it.
- **Re-promote** no sooner than 1 hour after a demotion.
- A demotion is a loosening, so it is loud: stderr, a `readiness_transition` row, a `notify` audit row, a notice on the configured webhook, and `shieldcortex doctor` **FAIL** until the install is enforcing again. Doctor also FAILs when a demotion is due on the hook's next call. The operator chose enforcement and is not getting it. Off and watch-only stay WARN, not FAIL (#516).
- Every promote and demote is also appended to the **durable transition record** (below), before the state file is rewritten.
- **Floors.** The catastrophic tier and the session-lease freeze return before the shadow branch in the hook, so they apply identically in shadow, enforcing and demoted states. The lease floor is tested end to end in all three states. The catastrophic floor is tested structurally (source order). A catastrophic command fixture could not be written into the suite, because the Action Guard refuses to write catastrophic command text into a file.

## Per-call cost and the cache

The hook reads `~/.shieldcortex/approvals/guard-readiness.json` and the transition record on each call. The cache may only **tighten**: a result younger than 10 minutes, computed under the version in force, is reused only when its mode matches the transition record. Older, missing, from another version, or disagreeing with the record, the hook recomputes from the audit (newest files first, 64 MB read budget, only lines that can matter are parsed), applies the hysteresis rule, and rewrites the file under a lock. If another process holds the lock, it answers from evidence without writing and never announces a transition twice. If the readiness module is missing from the build or throws, the hook **enforces**.

## Tamper direction

The audit log and the state file are same-UID files.

- **Inflating readiness** (forged answers, deleted would-stops) can only make the guard enforce, and with the default it cannot even do that: promotion needs reviewed effectiveness evidence, which lives in reviewed source, not in a file.
- **Deflating readiness** loosens, so it is never silent:
  - Forged would-block rows, deleted approval answers or a corrupted evidence line change the recomputed result. Within one TTL plus the 1-hour grace, that is a demotion with every signal above.
  - **The durable transition record** (`~/.shieldcortex/approvals/guard-readiness-transitions.jsonl`) is the authority for "was this install enforcing". It is append-only, separate from the rolling measurement window and the read budget, and never pruned, so a promotion made months ago is still remembered after the audit has rotated. `shieldcortex config --action-guard-enforce-when-ready` and `setup` start it with an `init` entry on a change of posture only; re-running the command cannot clear a recorded demotion.
  - **A forged cache cannot loosen.** A fresh cached `shadow` on an install the record says was promoted is not trusted. It is a tamper signal: recorded in the transition record and the audit (`readiness_tamper`), printed on stderr, and shown by `doctor` for 7 days. Readiness is recomputed from evidence. If the evidence is still ready, the install keeps enforcing. If it is not, the full demotion protocol runs at once (announced, audited, doctor FAIL): a forged cache's failure clock is not trusted either. Refreshing `computedAt` therefore extends nothing.
  - **A missing or unreadable record is unknown**, never "never ready". Unknown is treated as potentially demoted: unless the evidence promotes, or the state file or audit still show enforcing (then the normal grace applies), the hook announces a demotion whose reason names the lost record, and `doctor` FAILs. A corrupt record is moved aside (`.corrupt-<ms>`) and a new one started.
  - A deleted state file is not read as "shadow". The previous mode comes from the transition record; the state file and the audit's `readiness_transition` rows can only raise it to enforcing.
  - `shieldcortex config --action-guard-enforce-when-ready` is classified with `--action-guard-disable` / `--action-guard-advisory` (core evaluator, both WS2 fallback lists, Hermes). On an enforcing install an agent cannot switch it into this posture, which starts in shadow, without approval. From off or watch only it is a tightening and is not gated, because nothing enforces there.
  - The state file, its lock, its temp file and the transition record sit in the approval store's own directory, `~/.shieldcortex/approvals`, even when `SHIELDCORTEX_CONFIG_DIR` points elsewhere. The guard's existing `touch-approval-store` rule gates an agent writing any of them, on the core evaluator and on both WS2 fallback lists (the hook's and the OpenClaw interceptor's). A test extracts the rule from all three sources and matches it against all three paths; the #59 parity test keeps the lists in step.
- Readiness is always recomputed from evidence. The state file stores only the last mode, its pin, the failure clock and the demotion history. The transition record stores transitions and tamper reports, never readiness.

## Residuals

- A cached `enforcing` forged outside the tool surface is applied for up to one 10-minute TTL. That is a tightening.
- The same outside-the-tool-surface actor can shorten the demotion grace by editing `failingSince`, or trigger an immediate demotion by forging a disagreeing cache. Both demotions are loud.
- Deleting the whole audit log leaves no evidence either way; the install demotes loudly because the conditions cannot be met. Deleting the audit log, the state file **and** the transition record outside the tool surface is an unknown record: an announced demotion and a doctor FAIL, not a silent reset. What such an actor can still do is append a forged `init` or `demote` line to the record. That is not silent either: it is a demotion or a posture restart, and doctor shows the record's last entry. Through agent tool calls all three are gated (`touch-approval-store`, and a recursive delete by the dangerous tier).
- Rewriting an evidence row into a different, well-formed record type (for example changing its `type`) is indistinguishable from deleting it, and deletion is covered by the recompute, not detected as corruption.
- The demotion notice goes to the webhook. If the webhook is removed after promotion, readiness fails and the install demotes, but the notice can then only reach stderr, the audit and doctor.
- An OpenClaw card answer the waiter records after the store no longer holds the request (already answered elsewhere, expired) names no attempt, so it is not counted. This biases reachability low.
- In shadow mode the new flag, like `--action-guard-advisory`, is logged but not stopped: shadow does not enforce the dangerous tier.
- The audit directory itself is not path-protected against an agent. Protecting it would gate the hook's own audit writes, so it stays a disclosed residual. Tampering with it is covered by the loud-demotion rule, not prevented.
- On an interactive Claude Code session with a card channel, a human who answers the Claude Code dialog instead of the card leaves the card to expire, and that counts as not reached. This biases reachability low.
- #310 retry cards are not yet counted as reaches: a no-prompt-surface denial counts as not reached even when a retry card was raised.
- The OpenClaw plugin surface enforces from the start under this posture; its evidence does not feed the proxies.
- The policy pin digests the guard's rule module only. A change elsewhere that alters verdicts without touching that module (for example the script resolver) is covered by the adapter's package version, not by the policy digest.
- The catastrophic floor under shadow and demoted states is asserted by source order, not by driving a catastrophic command through the hook (see Floors).
- These are per-install operability proxies measured on live traffic. They are not a security evaluation. Nothing here claims the guard makes an install safe.
