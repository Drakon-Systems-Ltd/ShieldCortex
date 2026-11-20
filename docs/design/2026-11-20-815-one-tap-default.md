# Design: one-tap approve, on by default when it can arm safely (#815)

Status: proposed. Docs only; nothing here is implemented by this change.
Refs #815. Owner decisions: ledger rows of 20 Nov 2026 (priority for the next release; ships on by default), recorded in the #815 comments of that date. Tars's measurement of 20 Nov (#815 comment 7038838939) supplies the host numbers used below.

This document states properties and invariants only. It contains no bypass recipe, no reproduction steps and no live host value.

## 1. Goal and non-goals

Goal: when the Guard holds or denies an action, the operator can answer from their phone with one tap, and the answer is as hard to forge as `shieldcortex approve --denial` in a terminal. It should work without setup effort on any host that can do it safely.

Non-goals:
- No change to what the Guard allows or blocks. This only changes who can give an answer, and where.
- No release of a held call. A tap writes the same scoped, short-lived retry grant the terminal command writes (retry-control, #310).
- No change to the always-block set. Catastrophic and self-protection-floor actions stay terminal-only.
- No change to OpenClaw hosts, which keep their native approval channel (#220).

## 2. What exists today (main at 4bb795e6)

- `approve-tap.ts` ships the endpoint half: `mintApproveTapNonce`, `verifyApproveTap`, `createApproveTapHandler`, `checkApproveTapArming` and the doctor row. Its header states nothing calls the mint from the Guard yet, so no tap completes end to end.
- Config is `actionGuard.approveTap`. `enabled` is true only for a strict `true`; absent means off.
- Arming already refuses when the agent's user can read the approve secret, when the secret is the webhook secret, on wrong mode or owner, and when no approver is set.
- The card is version 1: readable text, no nonce, no tap path.
- The bridge that relays cards to a chat is a host script, not product code.

## 3. Decisions

### D1. Arming contract (rows 283, 284)

The tap path has exactly three states, resolved in one place.

| State | Condition | Behaviour |
|---|---|---|
| Armed | Owner notify chat is configured AND an approver id is set AND the approve secret passes the existing arming check AND the key-holder is a different user from the agent | Cards carry Approve / Deny; the endpoint is live |
| Cannot arm | Any of the above is missing | Deny exactly as today. The card tells the operator to run `shieldcortex approve --denial <actionId>` in a terminal. Doctor WARNs and names the single missing item |
| Opted out | `actionGuard.approveTap.enabled: false` (strict `false`) | Same as cannot arm, and doctor reports it as a choice, not a fault |

Reason: the owner's rule is "on by default whenever it can arm safely, otherwise deny as today". Three explicit states make "never fail open" testable: the only state that adds a way to approve is Armed.

Decisions that follow:
- The default resolves in `approve-tap.ts` (`normaliseApproveTapConfig`): absent `enabled` becomes "auto", meaning on if and only if arming passes. Junk input still degrades to off. Reason: the existing total normaliser is the one place every caller already goes through.
- The smallest `tool-action-guard.ts` change is a call to the mint when a denial card is produced, guarded by the arming result. Nothing else in that file changes. Reason: that file is under the standing non-overlap rule and holds the Guard's decisions; it should only gain the call, never a policy edit.
- A host where the agent runs as the secret's owner stays "cannot arm". The stronger boundary there is the OS lock plus the terminal approve.

### D2. Mint and tap flow

1. The Guard produces a card for a denial and calls the mint with the action id, only when Armed.
2. The mint creates a single-use 128-bit nonce bound to the action id, the exact call digest and an expiry. The store keeps only the hash of the nonce.
3. The card carries the action id and nonce on its Approve button, and the digest and expiry beside it, inside the body the webhook secret already signs. The chat callback carries action id and nonce only.
4. The receiver (D3) accepts a tap only from the configured approver, then calls the loopback endpoint with a MAC made under the approve secret.
5. The endpoint verifies, spends the nonce first, then writes the retry grant. A concurrent second tap sees a spent nonce.

Invariants (all already enforced by the endpoint; the tests in D9 pin them for the new wiring):
- Single use. Bound to action id and exact call digest. Expiry between 30 seconds and 10 minutes.
- A different digest, a replay, an unknown action and a nonce from another action are refused with nothing written.
- A Deny, from either path, wins: a tapped Approve after a Deny stays denied.
- A denial with no recorded digest cannot be tapped.

### D3. Receiver contract

- Every card that needs a decision has Approve and Deny buttons. Deny is one tap and needs no nonce check beyond approver identity, because it only narrows.
- The receiver relays an Approve to the existing loopback endpoint and never talks to the Guard directly.
- A text-only fallback (receiver cannot send buttons, or the text exceeds the chat's length limit) must say plainly why there are no buttons and give the terminal command. Reason: a card with no buttons and no explanation looks like a broken tap.
- A reference receiver ships in the product repo, in a new directory (proposed `examples/notify-bridge/`), so a host does not have to invent one. It is an example: the script a given box actually runs is that box's owner and agent matter, and this repo does not edit it.
- The receiver never logs the nonce, the secret or the MAC.

### D4. Key-holder

- A separate OS user holds the approve secret and runs the receiver. The agent's user must not be able to read it.
- The secret is a different credential from `notify.webhookSecret`; arming already refuses the reverse.
- The file is mode 0600 and owned by the key-holder, with a private parent directory. Arming checks this from metadata only, and the endpoint re-checks on the open file before trusting a byte.
- Setup offers to create the key-holder and secret, showing the exact commands and asking before running anything that needs elevation. Setup never silently creates a user.
- Doctor checks, in order: notify chat set, approver set, secret present and well-formed, key-holder differs from agent, endpoint reachable on loopback. It stops at the first failure and says what to do. Doctor is warn-only.

### D5. One card per action

- One card per action id. A second denial with the same call digest inside the window attaches to the existing card instead of producing a new one.
- A retry of an action that already has a live grant produces no card (#1077, #1067).
- The dedupe key is action id first, call digest second, window equal to the nonce lifetime.

Reason: duplicate cards are the owner's second reported symptom, and each duplicate carries its own live nonce, which widens the set of outstanding approvals for one action.

### D6. Expiry and re-ask

- A tap on an expired or spent nonce gets an explicit reply: "expired, ask again", with a re-ask button. It is never a silent no-op.
- Re-ask re-runs the same action's card path and mints a new nonce only if the action is still in the denied state.
- Expired cards go into the existing expiry digest (#673), one line each.
- Tars measured 63 of 170 taps landing after a 60-second timeout on one runtime. The default nonce lifetime therefore stays at the existing ceiling; shortening it is a worse trade than a clear re-ask.

### D7. Wording

A card has three parts, in this order:
1. A plain first line: who wants to do what to which target, in a sentence.
2. The command, trimmed to a fixed character budget with an explicit "trimmed" marker.
3. The rule that fired, in words, with no raw signal id in the headline.

The total stays under the chat's message limit; the budget is applied before sending, not by the transport. A card never shows secrets that appear in a command. The card keeps the existing statement of the phone-as-security-boundary caveat.

### D8. #853 boundary

#853 (no-prompt sessions get one held card instead of a silent denial) is owned by #959. This design needs exactly one thing from it: when a held card is produced, it goes through the same card path and the same mint as a denial card, with one card per action. The held-card work is not built here, and nothing in this plan depends on how #959 implements the hold.

### D9. Tests and acceptance

Add-only unit tests per slice (listed in D10), each using disposable fixtures and no live host:
- Arming table: every state in D1, including each single missing precondition, yields Cannot arm and never Armed.
- Mint is called only when Armed; never for terminal-only signals.
- Dedupe: same action id and same digest in the window produce one card; a different digest produces a second.
- Expiry: late tap returns the re-ask reply and writes nothing.
- Deny beats an earlier or later Approve.
- Wording: the first line has no signal id; budget and trim marker hold at the limit; length limit is respected.
- Text-only fallback states why it has no buttons.

Host acceptance (a host, not CI): deny, tap, one retry passes; a replay and a different digest are refused; a Deny tap stays denied. This is run by the owner's own enable step on their box.

### D10. Slice plan

Order matters because of open peers (live state at 20 Nov 2026):

| Slice | Content | Files | Line ceiling | Must merge first |
|---|---|---|---|---|
| S1 | Auto default and arming states; reasons | `approve-tap.ts`, `tap-eligibility.ts` (if needed) and their tests | 250 | none |
| S2 | Card version 2: buttons, dedupe, wording, fallback text | `approval-card.ts`, `operator-notify.ts`, `webhook-notify-channel.ts` and tests | 350 | #1104 |
| S3 | Mint wiring from the Guard | `tool-action-guard.ts` (call only) and tests | 120 | S1, S2, and the non-overlap rule clearing |
| S4 | Doctor rows and setup offer | `src/cli/doctor.ts`, `src/setup/settings-hooks.ts` and tests | 300 | #959 |
| S5 | Expiry reply, re-ask, digest line | `approve-tap.ts`, `retry-control.ts` and tests | 250 | S2 |
| S6 | Reference receiver and enable runbook | new `examples/notify-bridge/`, new runbook | 300 | S2 |

S3 and S4 are the slices that touch files held by peers today (#1104 and #959 touch the card, notify, interceptor, hook and doctor files). S1 and S6 touch no file in an open PR at the time of writing and are the first candidates, but S1 alone cannot be exercised end to end until S3 lands, so it ships behind the existing off state until S3 merges.

### D11. Owner-only

These are not decided or done by any builder or reviewer:
- Applying live Guard config on any box (broker, approve tap, notify).
- Any default beyond the one in D1.
- ADR-002 defaults.
- Creating the key-holder user on any host.

## 4. Risks

- A phone is a security boundary. The card says so, and the approver id is inside the MAC, so a tap signed for one user cannot be replayed as another.
- Default-on could surprise a host that arms by accident. Mitigation: arming requires an owner chat, an approver id and a separate key-holder, all explicit; the strict opt-out remains.
- Dedupe could hide a genuinely new action. Mitigation: the key is the exact call digest, so a different call is a new card.

## 5. Open questions for the owner

1. Should the first slice after this merges be S1 or S6? S1 is the smaller change; S6 is what lets the owner try it.
2. Is a re-ask allowed unlimited times, or capped per action? This design proposes a cap of three per action per hour, but it is the owner's call.
