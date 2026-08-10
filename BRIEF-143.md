# Brief: finish #143 — a denial must reach the operator AS a denial

Worktree, branch `fix/143-operator-channel`, based on `origin/main` @ `ba6e97c`.
Deps installed. Commit locally, do NOT push.

**Correction to an earlier version of this brief: the approval-hash defect
(#183/#201) is ALREADY FIXED on main** — see `projectForHash` /
`EXEC_ADVISORY_KEYS` in `src/defence/iron-dome/action-approvals.ts`, commit
c725626. Do not touch it. Native OpenClaw approval cards also already shipped
(commit 6771901, `notify.openclaw=true`). Read both before starting so you are
working against reality and not against this document.

## Read first

1. `scripts/pre-tool-hook.mjs` — `loadNotify`, `pingOperator`,
   `emitApprovalRequired`, `noPromptSurfaceReason`, and the call site around
   line 892 marked `── operator-notify transport (#143) ──`.
2. `src/defence/iron-dome/operator-notify.ts`
3. `src/defence/iron-dome/notify-config.ts`
4. `src/defence/iron-dome/webhook-notify-channel.ts`
5. `src/defence/iron-dome/openclaw-approval-channel.ts`

## The defect

`pingOperator` runs on the shared path BEFORE `emitApprovalRequired` chooses
between `ask` and `deny`. So on a promptless box — `bypassPermissions`, which
is how every unattended agent and cron on this fleet runs — the operator
receives a notification worded as *"approve this?"* for an action that has
**already been refused and handed back to the agent as a denial**.

Two things are wrong with that, and the second is the one that cost real work:

1. The card's wording is false at the moment it arrives. Nothing is waiting on
   the operator; the action is already dead.
2. It never says a job just died, or which one. From issue #143, in my own
   words: *every `denied_no_prompt_surface` must emit on the operator's channel
   — what was denied, which rule, the approve hash, and which job it killed.*

Live cost, measured this morning across the fleet: 41 gated actions hard-denied
in one week with nobody told. Friday's nightly backup on 2 Aug is simply absent
from the backup repo. Edith saw `email_pickup.py` denied 15 consecutive times
over 7 hours, found only by reading the audit jsonl by hand.

## What to build

### 1. An event discriminator on the notification

In `operator-notify.ts`, add to `OperatorNotification`:

- `event: 'approval_requested' | 'denied_no_prompt_surface'` — default
  `'approval_requested'` at every existing construction site so no current
  behaviour changes.
- `deniedReason?: string` — the `noPromptSurfaceReason` text, e.g.
  `bypassPermissions mode shows no prompt`.
- `sessionId?: string` and `cwd?: string` — from the hook's `hookData`
  (`session_id`, `cwd`). This is how an operator identifies WHICH job died;
  without it the alert is unactionable.

`formatOperatorNotification` must render the two events differently. The denial
text states plainly that the action was BLOCKED and DID NOT RUN, gives the
reason, names the session/cwd, and still carries the approve command so the
retry can be authorised. Do not emit an Approve/Deny pair on a denial — there
is nothing left to deny.

### 2. Both channels carry it

- `webhook-notify-channel.ts`: derive `X-ShieldCortex-Event` from the
  discriminator instead of the hardcoded `approval_requested`, and include
  `event`, `deniedReason`, `sessionId`, `cwd` in the JSON body.
- `openclaw-approval-channel.ts`: on `denied_no_prompt_surface` this must NOT
  raise an interactive Approve/Deny card — there is no live decision to make
  and a card whose buttons change nothing trains the operator to ignore cards.
  Send it as a plain notification on the same channel instead. If the channel
  has no non-interactive send path, say so in your report and fall back to the
  webhook channel for this event rather than inventing a gateway call you have
  not verified exists.

### 3. The hook passes the truth

`emitApprovalRequired` already computes `noPromptSurfaceReason`. Restructure so
the notify call knows which branch it is on. Hard constraints:

- Notify stays BEST-EFFORT: never throws into the decision, never delays past
  its own bounded timeout, never changes the verdict.
- `emitDecision` output stays byte-identical to today for every existing case.
- No added latency on the allow path.
- The hook is one process per tool call — no persistent state, no background
  work that outlives the process except the existing detached waiter.

### 4. `notify.webhookSecret`

`createWebhookNotifyChannel` already accepts a `secret` and HMAC-signs the body
with it, but `NotifyConfig` has no field for one and `loadNotify` never passes
one — so the webhook channel can only ever send unauthenticated POSTs. Any
receiver worth pointing it at must reject unsigned requests.

Add `webhookSecret?: string` to `NotifyConfig`, normalise it the way the other
fields are normalised (reject non-strings, bound the length, treat unusable as
absent), and pass it through in `loadNotify`. Never log it, never include it in
an error message, never put it in an audit row.

## Non-negotiables

- **Zeroth law: ShieldCortex must never break the host.** Unsure whether a
  change could wedge the gateway or an agent? Take the smaller change and say
  so in the report.
- Do not touch tier rules, the broker's pre-clear set, `enforce`,
  `failurePolicy`, or the catastrophic hard-block. This work tells the operator
  things; it does not change verdicts.
- No opportunistic refactors. Smallest change that fully solves it.
- Comments explain WHY. Match the surrounding files' unusually high comment
  density and voice — that is deliberate house style, not accident.

## Tests

- `src/__tests__/prompt-surface-deny.test.ts`: a promptless-mode denial with a
  configured notify webhook delivers a payload whose `event` is
  `denied_no_prompt_surface`, naming the reason, session and cwd. Local
  throwaway HTTP server or injected fetch — no real network.
- `operator-notify.test.ts` / `webhook-notify-channel.test.ts`: new fields and
  header, and that the default event is unchanged for existing callers.
- `notify-config.test.ts` (create if absent): `webhookSecret` normalisation,
  including that a non-string or over-long value is dropped rather than
  accepted.
- **The property that matters most:** a notify channel that throws, hangs past
  its deadline, or returns 500 leaves the guard's decision completely
  unchanged. Pin it for both events.

## Before reporting done

Run and paste real output:
- `npx tsc --noEmit -p tsconfig.json`
- `npx jest src/__tests__/prompt-surface-deny.test.ts src/defence/iron-dome/__tests__`
- the full suite if it finishes in reasonable time

Report what you changed, what you verified WITH OUTPUT, what you did not do,
and anything you found that contradicts this brief. If the brief is wrong about
the code, say so rather than implementing something you can see is wrong — that
already happened once on this task.

Write the report to `REPORT-143.md`.
