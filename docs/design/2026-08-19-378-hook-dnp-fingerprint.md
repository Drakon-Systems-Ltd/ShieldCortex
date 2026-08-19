# #378 — Hook-lane DNP always leaves a fingerprint

## Problem (proven)

On clawdbot1, 272/313 denials in 14d are `origin: claude-code-hook` +
`denied_no_prompt_surface`. `shieldcortex approve` prints "No pending Action
Guard approvals." `approve --denial` is also empty.

Cause on `origin/main` (`c73ede9`): `scripts/pre-tool-hook.mjs`
`loadRetryControl()` returns null unless `actionGuard.retryCards === true`.
That gates the **entire** retry plane — fingerprint write, grant consume, and
cards — behind the soak switch. ADR-2026-08-19 said the opposite: denial
always leaves a fingerprint; cards stay dark.

#371 is not this bug. It is OpenClaw-native live-hold `{ requireApproval }`.
Claude Code PreToolUse cannot pause for a Telegram card. OpenClaw-spawned hook
sessions still DNP. That stays structural.

## Non-goals

- Live-hold / PreToolUse async pause
- Flipping `retryCards` default (Edith soak still owns that)
- Interceptor fingerprint/consume (ADR left interceptor out this phase)
- Catastrophic grant path
- Mint-on-DNP spendable pendings / #118 pending records for DNP

## Design

1. `loadRetryControl` loads the dist module whenever it is complete. It no
   longer returns null just because `retryCards !== true`.
2. Every dangerous-tier hook DNP records a fingerprint (same
   `recordDenialFingerprint` contract as today).
3. `consumeRetryGrant` always runs when the module loaded, so
   `shieldcortex approve --denial <actionId>` works with cards off.
4. `raiseRetryCard` / waiter / budget debit run only when
   `normaliseRetryControlConfig(...).retryCards === true`.
5. Catastrophic still never touches the retry plane.
6. Bare `shieldcortex approve` still lists #118 held calls only, but if any
   fingerprint rows exist it points at `approve --denial`. Looking never
   creates the store.

## Security invariants

- Nothing spendable is minted on denial.
- Cards remain strict-true `retryCards`.
- TTY gate on grant is unchanged.
- Grant scope `{cwd, tool}` AND-match unchanged.
- No `reviewedScripts` mint/spend.
- Payload / permission_mode never mute or arm this.
- Dist incomplete → null → same terminal DNP as today (fail closed on the
  retry plane, not on the denial).
