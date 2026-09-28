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
- A request is recorded when the hook sends it to the channel. The answer is recorded when a human approves or denies it (`shieldcortex approve` / `deny` in a terminal, or a tap on the OpenClaw card).
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
- Missing, empty, unreadable or unparseable evidence never qualifies. A missing or empty audit is short of the sample. An evidence file that cannot be read, or a complete line that does not parse, makes the install not ready and says so. An append still in flight (no trailing newline) is left for the next recompute. A version pin that cannot be determined is not ready.

## Promotion, demotion, hysteresis

- **Promote** as soon as all three conditions hold (announced on stderr, audited as a `readiness_transition` row).
- **Demote** to shadow when any condition has been failing for 1 hour continuously. One bad recompute does not flip it.
- **Re-promote** no sooner than 1 hour after a demotion.
- A demotion is a loosening, so it is loud: stderr, a `readiness_transition` row, a `notify` audit row, a notice on the configured webhook, and `shieldcortex doctor` **FAIL** until the install is enforcing again. Doctor also FAILs when a demotion is due on the hook's next call. The operator chose enforcement and is not getting it. Off and watch-only stay WARN, not FAIL (#516).
- The OpenClaw card channel carries approvals only, so an openclaw-only install gets stderr, audit and doctor FAIL, but no pushed notice.
- **Floors.** The catastrophic tier and the session-lease freeze return before the shadow branch in the hook, so they apply identically in shadow, enforcing and demoted states. The lease floor is tested end to end in all three states. The catastrophic floor is tested structurally (source order). A catastrophic command fixture could not be written into the suite, because the Action Guard refuses to write catastrophic command text into a file.

## Per-call cost and the cache

The hook reads `~/.shieldcortex/approvals/guard-readiness.json` on each call. A result younger than 10 minutes, computed under the version in force, is reused. Older, missing or from another version, the hook recomputes from the audit (newest files first, 64 MB read budget, only lines that can matter are parsed), applies the hysteresis rule, and rewrites the file under a lock. If another process holds the lock, it answers from evidence without writing and never announces a transition twice. If the readiness module is missing from the build or throws, the hook **enforces**.

## Tamper direction

The audit log and the state file are same-UID files.

- **Inflating readiness** (forged answers, deleted would-stops) can only make the guard enforce, and with the default it cannot even do that: promotion needs reviewed effectiveness evidence, which lives in reviewed source, not in a file.
- **Deflating readiness** loosens, so it is never silent:
  - Forged would-block rows, deleted approval answers or a corrupted evidence line change the recomputed result. Within one TTL plus the 1-hour grace, that is a demotion with every signal above.
  - A deleted state file is not read as "shadow". The previous mode is taken from the audit's last `readiness_transition` row, and where the state and the audit disagree, enforcing wins.
  - The state file, its lock and its temp file sit in the approval store's own directory, `~/.shieldcortex/approvals`, even when `SHIELDCORTEX_CONFIG_DIR` points elsewhere. The guard's existing `touch-approval-store` rule gates an agent writing any of them, on the core evaluator and on both WS2 fallback lists (the hook's and the OpenClaw interceptor's). A test extracts the rule from all three sources and matches it against all three paths; the #59 parity test keeps the lists in step.
- Readiness is always recomputed from evidence. The state file stores only the last mode, its pin, the failure clock and the demotion history.

## Residuals

- A state file forged outside the tool surface (same UID, not through an agent tool call) holds its mode for at most one 10-minute TTL before evidence overrules it.
- The same outside-the-tool-surface actor can shorten the demotion grace by editing `failingSince`. The demotion is still loud.
- Deleting the whole audit log leaves no evidence either way. With the state file intact the install demotes (loudly) because the conditions cannot be met. Deleting **both** the audit log and the state file outside the tool surface resets the install to a fresh, never-ready shadow state with no demotion row. That is indistinguishable from a new install. Through agent tool calls both deletions are gated (the state file by `touch-approval-store`, a recursive delete in the state tree by the dangerous tier). Outside the tool surface this is not prevented.
- The audit directory itself is not path-protected against an agent. Protecting it would gate the hook's own audit writes, so it stays a disclosed residual. Tampering with it is covered by the loud-demotion rule, not prevented.
- On an interactive Claude Code session with a card channel, a human who answers the Claude Code dialog instead of the card leaves the card to expire, and that counts as not reached. This biases reachability low.
- #310 retry cards are not yet counted as reaches: a no-prompt-surface denial counts as not reached even when a retry card was raised.
- The OpenClaw plugin surface enforces from the start under this posture; its evidence does not feed the proxies.
- The policy pin digests the guard's rule module only. A change elsewhere that alters verdicts without touching that module (for example the script resolver) is covered by the adapter's package version, not by the policy digest.
- The catastrophic floor under shadow and demoted states is asserted by source order, not by driving a catastrophic command through the hook (see Floors).
- These are per-install operability proxies measured on live traffic. They are not a security evaluation. Nothing here claims the guard makes an install safe.
