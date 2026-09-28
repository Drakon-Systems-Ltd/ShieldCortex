# Action Guard: enforce when ready (#509)

Operator direction, 28 Sep 2026: *"Go and build the version that the false-positive rate is measured low and approvals reliably reach a human."*

Those two conditions are two of the ADR-002 §5B pre-registered bars: **≤ 2% unintended blocking of legitimate work** and **≥ 98% completion along the approval path**. This posture does not invent new bars. It makes each install measure those two on its own traffic and enforce only while both hold.

This is not the ADR-002 §8 decision. Session taint (§2.2), the §2.4 effect decision and dangerous-tier narrowing are untouched. The verdicts are exactly the guard's verdicts; the posture only decides whether a dangerous-tier verdict is applied or recorded.

## The postures

| posture | config | dangerous tier | catastrophic tier |
|---|---|---|---|
| Off (default) | `enabled: false` | not looked at | not looked at |
| Watch only | `enabled: true, enforce: false` | logged, runs | blocked |
| Enforce | `enabled: true, enforce: true` | approval or block | blocked |
| **Enforce when ready** | `enabled: true, enforce: true, readinessGate: true` | **shadow** (logged as `would_hold` / `would_block`, runs) until both bars hold, then approval or block | blocked |

Set it with `shieldcortex config --action-guard-enforce-when-ready`, or pick it when `shieldcortex setup` asks. Non-interactive setup changes nothing; the default stays off.

`readinessGate` is a separate key rather than a new value of `enforce`, so every reader that does not know it (older hooks, the OpenClaw plugin, the policy lock schema) reads an enforcing guard. Not knowing the gate is the tighter reading.

**Scope today:** the gate is implemented on the Claude Code `PreToolUse` hook. The OpenClaw plugin ignores `readinessGate` and enforces from the start. A policy lock (`/etc/shieldcortex`) pins enforcement, so the gate is ignored on a locked host, and the setter refuses to turn it on there.

## The two bars

Both are recomputed from the audit log (`~/.shieldcortex/audit/realtime-*.jsonl`; `SHIELDCORTEX_CONFIG_DIR/audit` is read too when that override is set). Constants live at the top of `src/defence/iron-dome/guard-readiness.ts`.

**FP bar.** Over the last 14 days of real Claude Code hook calls: stops ÷ all counted calls ≤ 2%, with at least 500 calls spanning at least 7 days.

- A stop is any non-catastrophic `would_hold`, `would_block`, `asked`, `denied_no_prompt_surface`, `warned`, or `require_approval`/`auto_denied` row.
- **Every stop counts as a possible false positive.** Some of them were right, so the measured rate is an upper bound on unintended blocking, not an estimate of it. This is deliberately conservative.
- Counted calls are rows with origin exactly `claude-code-hook`. Excluded: `gate_degraded` rows, `notify` rows, rows marked `synthetic`, session-lease refusals, and rows from any other origin (OpenClaw interceptor, canaries, proofs).
- Under this posture a benign allow writes a minimal tally row (no command text) so the denominator is every gated call. That is one extra audit row per tool call.

**Approval-reach bar.** Over the last 30 days: of approval requests put to the configured human channel, ≥ 98% got a human answer (approve **or** deny) within 15 minutes, with at least 20 resolved requests, **and** at least one answered round-trip in the last 7 days.

- **No configured human channel ⇒ not ready.** A channel is `actionGuard.notify` with `enabled: true` and either `openclaw: true` (the approval card) or an http(s) `webhookUrl`.
- A request is recorded when the hook sends it to the channel. The answer is recorded when a human approves or denies it (`shieldcortex approve` / `deny` in a terminal, or a tap on the OpenClaw card).
- Not a reach: an answer after 15 minutes, a card that expired, a request the channel did not accept, a denial for want of a prompt surface, and the hash-in-transcript fallback when the configured channel failed.
- On a quiet box, `shieldcortex guard test-approval` (terminal only) sends a clearly labelled synthetic request through the channel and records whether you answered. It never approves anything: it does not import the approval store, and its hash is 256 random bits. For a card you tap Approve or Deny; for a webhook you type the 6-digit code the message carries. Synthetic round-trips count toward the bar — they test the same channel end to end.

`shieldcortex guard readiness` and `shieldcortex doctor` show the posture, the current mode, each bar against its threshold and sample, the last round-trip, and what is missing.

## Promotion, demotion, hysteresis

- **Promote** as soon as both bars hold (announced on stderr, audited as a `readiness_transition` row).
- **Demote** to shadow when either bar has been failing for 1 hour continuously. One bad recompute does not flip it.
- **Re-promote** no sooner than 1 hour after a demotion.
- A demotion is a loosening, so it is loud: stderr, a `readiness_transition` row, a `notify` audit row, a notice on the configured webhook, and `shieldcortex doctor` **FAIL** until the install is enforcing again. The operator chose enforcement and is not getting it. Off and watch-only stay WARN, not FAIL (#516).
- The OpenClaw card channel carries approvals only, so an openclaw-only install gets stderr, audit and doctor FAIL, but no pushed notice.

## Per-call cost and the cache

The hook reads `~/.shieldcortex/approvals/guard-readiness.json` on each call. A result younger than 10 minutes is reused. Older or missing, the hook recomputes from the audit (newest files first, 64 MB read budget, only lines that can matter are parsed), applies the hysteresis rule, and rewrites the file under a lock. If another process holds the lock, it answers from evidence without writing and never announces a transition twice. If the readiness module is missing from the build or throws, the hook **enforces**.

## Tamper direction

The audit log and the state file are same-UID files.

- **Inflating readiness** (forged answers, deleted would-stops) makes the guard enforce. That only tightens.
- **Deflating readiness** loosens, so it is never silent:
  - Forged would-block rows or deleted approval answers change the recomputed bars. Within one TTL plus the 1-hour grace, that is a demotion with every signal above.
  - A deleted state file is not read as "shadow". The previous mode is taken from the audit's last `readiness_transition` row, and where the state and the audit disagree, enforcing wins.
  - The state file sits inside the approvals directory, so the guard's existing `touch-approval-store` rule gates an agent writing it, on the core evaluator and on both WS2 fallback lists (the #59 parity test keeps those in step).
- Readiness is always recomputed from evidence. The state file stores only the last mode, the failure clock and the demotion history.

## Residuals

- A state file forged outside the tool surface (same UID, not through an agent tool call) holds its mode for at most one 10-minute TTL before evidence overrules it.
- The same outside-the-tool-surface actor can shorten the demotion grace by editing `failingSince`. The demotion is still loud.
- Deleting the whole audit log leaves no evidence either way. With the state file intact the install demotes (loudly) because the bars cannot be met. Deleting **both** the audit log and the state file outside the tool surface resets the install to a fresh, never-proven shadow state with no demotion row — indistinguishable from a new install. Through agent tool calls both deletions are gated (the state file by `touch-approval-store`, a recursive delete in the state tree by the dangerous tier); outside the tool surface this is not prevented.
- The audit directory itself is not path-protected against an agent. Tampering with it is covered by the loud-demotion rule, not prevented.
- On an interactive Claude Code session with a card channel, a human who answers the Claude Code dialog instead of the card leaves the card to expire, and that counts as not reached. This biases the approval bar low (conservative).
- #310 retry cards are not yet counted as reaches: a no-prompt-surface denial counts as not reached even when a retry card was raised.
- The OpenClaw plugin surface enforces from the start under this posture; its evidence does not feed the bars.
- These are per-install engineering bars measured on live traffic. They are not a security evaluation and not a claim that the guard is safe by default.
