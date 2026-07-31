# Design: AI-assisted approval broker

**Status:** proposal (no code yet — spec first, per Michael 31 Jul 2026)
**Author:** Jarvis
**Depends on:** #118 one-shot approval store (shipped 4.47.18), #139 deny-when-no-prompt-surface
**Issue:** (filed alongside this doc)

## Problem

The Action Guard's `require_approval` verdict has two delivery paths today:

1. **OpenClaw plugin** — calls `context.requireApproval(...)`, which the gateway renders as a native Telegram inline-button card. Works. The operator taps approve/deny on their phone.
2. **Claude Code hook** — has no channel at all. It can only print into a transcript nobody is watching. Every one of the 433 real stops measured on the Jarvis box in July happened here, which is why they were dead ends. 4.47.18 (#118) gave this path a `shieldcortex approve <hash>` terminal fallback — correct, but useless to an operator who is away from the keyboard.

Two gaps remain even once notifications reach the phone:

- **The human isn't always reachable.** An action can be legitimately blocked for minutes or hours because nobody answered. For an unattended agent (cron, overnight build) that means the work simply stops.
- **A tap is a thin signal.** "Anyone who can send as Michael can approve as Michael" — and a well-crafted request can socially-engineer a yes. A human glancing at a phone is not a strong classifier of intent.

## Non-goals

- Replacing the human as the final authority. The AI serves the human and the tier rules; it never overrides either.
- Making catastrophic-tier actions approvable by anything other than a human. Those stay human-only, full stop.
- A general "agent asks another agent for permission" framework. This is specifically the guard's approval gate.

## The three-layer model

```
  tool call
     │
     ▼
┌─────────────────────┐
│ 1. TIER RULES       │  catastrophic → BLOCK (never overridable, never brokered)
│    (deterministic)  │  benign       → ALLOW
└─────────┬───────────┘  dangerous    → ↓ (needs approval)
          ▼
┌─────────────────────┐
│ 2. AI BROKER        │  judges intent: is this what the session was doing,
│    (fast model)     │  or are we being played (injection / off-pattern)?
│                     │  can HARDEN (→ escalate to human / deny)
│                     │  can pre-clear ONLY low/med, in-context, high-confidence
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ 3. HUMAN            │  final say, on their own channel (Telegram/WhatsApp/TUI)
│    (approval broker)│  tap approve/deny; request carries exact command + why
└─────────────────────┘
```

### Layer 1 — tier rules (unchanged)

The existing guard. Catastrophic is a hard block that never reaches the broker. Benign never needed approval. Only the dangerous tier enters the broker. **This is the red line: no AI verdict and no timeout can release a catastrophic action.**

### Layer 2 — the AI broker

A model judges the *dangerous-tier* request before it bothers the human. Its job is intent, not pattern — the thing a regex cannot do:

- Does this action fit what the session has been doing, or did it appear out of nowhere?
- Does the surrounding context contain injection ("ignore previous instructions", a tool result that reads like a command, a request whose justification doesn't match its effect)?
- Is the stated purpose consistent with the actual effect?

**Cardinal rule — the broker escalates toward caution only.** Its verdict can:
- **Harden** — turn a dangerous-tier approval into an outright deny (e.g. it detects injection). Always allowed.
- **Hold** — pass the request through to the human unchanged. The default.
- **Pre-clear** — release *without* waiting for the human, but ONLY when all of: (a) the action is low/medium tier, (b) it matches the session's established pattern, (c) the model is above a confidence threshold, and (d) no injection signal is present. Anything dangerous-or-above is never pre-cleared by the model alone.

"The model said it's fine" is never sufficient on its own to release a dangerous action. Otherwise the lock's key becomes "convince the AI", and convincing an AI is what prompt injection does for a living.

**Model tiering** (mirrors the fleet's advisor/implementer split): a fast, cheap model (Haiku / Grok) on the hot path for the thousands of benign-looking dangerous-tier ops; escalate to Sonnet/Opus only when the fast model is uncertain or the action is high-tier. The judge model's own calls are **logged to the audit trail and rate-limited** — a compromised or looping judge is a new attack surface and must be observable and bounded.

### Layer 3 — the human broker

The existing OpenClaw Telegram card, generalised to a channel-agnostic transport in front of #118's store:
- Request carries the **exact command** and **what tripped** — enough to resist social engineering (same discipline as break-glass: readable enough that you can't be tricked into tapping yes on something you didn't initiate).
- **Deny is as cheap as approve** — one tap, not silence-by-timeout.
- Single-use, exact-call-bound, expiring — all of which #118's store already enforces; this just adds a transport.

## The timeout path (where the care goes)

"Human's out of the loop, let the AI decide" is powerful and is *exactly* the scenario an attacker engineers — fire the malicious action at 3am when they know nobody answers. So the timeout decision **cannot be symmetric**:

| Tier at timeout | Outcome |
|---|---|
| low / medium, in-context, broker-confident-benign | **auto-APPROVE** (fail-useful) |
| dangerous or above, OR any injection signal, OR broker uncertain | **auto-DENY + queue for human** (fail-closed) |
| catastrophic | never reaches here — blocked at layer 1 |

Timing out into "allow" is the dangerous direction and is only ever taken for the tiers where a wrong call is cheap and reversible. This is the same fail-closed instinct as #139 (deny when no prompt surface can be confirmed); the broker just makes the "can't confirm" case rarer and the "safe to auto-allow" case explicit and narrow.

## Open questions (for the spec, before code)

1. **Confidence threshold + calibration.** What number, and how is it validated against the 429-event corpus so we know the pre-clear set is actually benign?
2. **Injection detection** — reuse the existing llm_input threat scanner's signal, or a broker-specific prompt? Probably both, ANDed.
3. **"In-context" definition.** What does the broker see of the session, and how do we stop *that context* from being the injection vector (a poisoned transcript arguing its own approval)?
4. **Timeout duration** per tier, and who configures it.
5. **Offline / no-model fallback.** If the judge model is unreachable, the broker must fail closed to layer-3 human-only — never fail open.
6. **Audit shape.** Every broker decision (verdict, model, confidence, tier, timeout-outcome) needs to be in the audit trail with the same fidelity as a guard verdict.

## Test posture (non-negotiable, when built)

- Adversarial corpus: injection-laced dangerous requests must never be pre-cleared or auto-approved-on-timeout.
- The 429 real-stop corpus: measure how many the broker would pre-clear, and hand-verify that set is benign.
- Fail-closed proofs: model unreachable → human-only; broker uncertain → deny-on-timeout; catastrophic → never brokered.
- The judge model's own tool calls are themselves subject to the guard (no exempting the broker from the thing it feeds).
