# ADR 2026-08-19 — Operator Retry Control for Headless Denials (#310)

Status: ACCEPTED (design v3-final; dual frontier review R3: 2× APPROVE_WITH_NITS, nits binding)
Supersedes: ADR 2026-08-16 clauses 2 ("OpenClaw cards deferred") and the terminal-DNP
no-affordance corollary. Restates unchanged: clause 1 (Claude CLI stays deterministic DNP —
PreToolUse never pauses), clause 3 (tap ≠ TTY review; nothing from a card ever mints/spends
reviewedScripts), clause 5 (no silent new trust surface — this ADR + dark launch + soak gate
IS the process).

## Decision
Mint on operator intent, not on denial. DNP remains terminal; a denial produces a
fingerprint (claim ticket), never a spendable record. Operator control surfaces:
1. OpenClaw card (budgeted, epoch-pinned, claimNonce-authenticated) → atomic one-shot
   scoped grant on Approve; windowed suppression on Deny.
2. TTY `shieldcortex approve --denial <actionId>` (isInteractive-gated) → same grant path.
Webhook alerts carry actionIds, never spendable tokens. Catastrophic tier: no path, ever.

Scope in this phase is the **Claude Code hook path only**. The OpenClaw interceptor
(`plugins/openclaw/interceptor.ts`) is out for CARDS *and* for CONSUME: its unattended path
never reads the #118 store today, and it must not be "helpfully" wired to the retry-control
store either — a grant minted from a hook denial has no origin binding that means anything on
that surface. Anyone extending this to the interceptor is writing a new ADR, not a patch.

## Rollout
Dark behind `actionGuard.retryCards=false`. Soak gate: ≥3 days on an Edith-class host,
deny/approve/timeout matrix across ≥3 cron identities, empty-origin, grant-then-newer-DNP,
budget-exhaustion. Default flips only after soak review against this ADR.

Full mechanism: DESIGN-310.md (v3-final) in this directory.
