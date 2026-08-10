# Report — #143: a denial must reach the operator AS a denial

Branch `fix/143-operator-channel`, worktree `/home/ubuntu/clawd/sc-wt-143`, based on
`ba6e97c`. Local commits only, nothing pushed.

```
bb0438f docs(#143): working notes — brief and completion report
667ce3c test(#143): the approve command a denial offers really does authorise the retry
2645322 test(#143): pin the denial event end to end, and that a broken channel changes nothing
96841dc feat(#143): a denial reaches the operator AS a denial
```

## Confirming the brief against the code before starting

Both corrections in the brief are accurate:

- The approval-hash defect (#183/#201) **is** already fixed on main —
  `projectForHash` / `EXEC_ADVISORY_KEYS` in `action-approvals.ts` (c725626). Not touched.
- Native OpenClaw approval cards **did** ship (6771901, `notify.openclaw=true`). Not touched
  except to make them refuse the new denial event.

The defect as described is real and was in the place described:
`scripts/pre-tool-hook.mjs:891` fired `pingOperator` before `emitApprovalRequired` chose
between `ask` and `deny`, so a promptless box got a card/POST worded "approval needed" for a
call the guard had already refused, with no session, no cwd, and no statement that anything
had died.

## What changed

### 1. `src/defence/iron-dome/operator-notify.ts` — the discriminator

- New `OperatorNotificationEvent = 'approval_requested' | 'denied_no_prompt_surface'`.
- `OperatorNotification` gains `event` (required), `deniedReason?`, `sessionId?`, `cwd?`.
  `RequestOperatorApprovalInput` gains the same four, all optional, `event` defaulting to
  `'approval_requested'` — so every caller that predates the discriminator produces a
  byte-identical notification.
- `deniedReason` is only carried on the denial event (a caller cannot accidentally tell an
  operator that a live hold was blocked). `sessionId` / `cwd` are carried on both; they are
  bounded to 500 chars and dropped when empty, because they arrive from the harness's JSON.
- `formatOperatorNotification` renders the two events differently. The denial reads
  `🛡️ ShieldCortex — BLOCKED: this action did NOT run`, adds `Blocked:` / `Session:` /
  `Cwd:` lines, and closes with "The agent has already been refused; this job did not do the
  work. / To authorise a RETRY, run in YOUR terminal: shieldcortex approve <hash>". No
  `[Approve]`/`[Deny]` pair. The approval wording is unchanged, byte for byte.
- An **unknown or missing** `event` renders as the approval wording. A stale dist degrading
  to today's text is safe; degrading to a false "this was blocked" is not.
- `fallbackHint` on a denial carries the approve half only.

### 2. `webhook-notify-channel.ts` — both channels carry it

- `X-ShieldCortex-Event` is derived from the discriminator instead of hardcoded, via an
  `eventOf()` that emits only the two known values.
- Body gains `event` (first key), plus `deniedReason` / `sessionId` / `cwd` where they apply.
- `denyCommand` is omitted on a denial — a receiver that renders these into chat would
  otherwise draw a Deny button on a dead request. This is safe because
  `denied_no_prompt_surface` is a **new** event: no existing receiver can depend on the shape
  of a body it has never been sent. The `approval_requested` body is unchanged but for the
  added `event` key.

### 3. `openclaw-approval-channel.ts` — and the honest gap

**Answering the brief's question directly: this channel has no non-interactive send path.**
Its only route is the detached waiter's one long-lived
`openclaw gateway call plugin.approval.request`, which is by definition an Approve/Deny card.
So, per the brief, it now refuses `denied_no_prompt_surface` outright — before spawning
anything — and the hook falls back to the webhook for that event.

Two things I did *not* do and why:

- I did not invent a gateway route. The repo's own corpus references
  `openclaw message send --channel <c> --target <t> --text "…"` as a real CLI shape
  (`payload-vs-action-89.test.ts:200`), and the `openclaw` binary is installed on this box —
  but I have not verified that route exists on the gateway build in use, and `NotifyConfig`
  has no channel/target fields to aim it with. Wiring it would mean inventing both a call and
  a config surface.
- I did not add those config fields. That is a design decision, not a bug fix.

**Consequence you should weigh:** on an install with `notify.openclaw:true` and **no**
`webhookUrl`, a promptless denial now reaches **no** channel, where before it raised a
(wrongly-worded) card. That card was not entirely inert — tapping Approve would have left a
one-shot approval in the #118 store that the retry could spend — so this is a real, if small,
reduction in what arrives on that one configuration. Everything else is unchanged, and the
hash-in-terminal floor is untouched. If you want that combination covered, the fix is a
verified non-interactive gateway send path plus `notify.openclawChannel`/`openclawTarget`;
say the word and I will do it as a separate change.

### 4. `notify-config.ts` — `webhookSecret`

`NotifyConfig.webhookSecret?: string`, normalised by a new exported `normaliseWebhookSecret`:
non-string → absent, empty/whitespace-only → absent, over 512 chars → absent (dropped, not
truncated — a silently truncated key produces a signature the receiver can never reproduce).
Trimmed, deliberately: config files collect trailing newlines and the receiver's copy is
invariably the trimmed literal. Kept independent of `webhookUrl` so a key configured before
the URL is not thrown away. `loadNotify` passes it into `createWebhookNotifyChannel`.

It is never logged, never in an error message, never in an audit row — pinned by a test that
greps the hook's stdout, stderr and the audit row for it. I also checked it cannot leave the
box by another route: `plugins/openclaw/cloud-sync.ts` and `src/cloud/config.ts` never read
or transmit the `notify` block.

### 5. `scripts/pre-tool-hook.mjs` — the hook passes the truth

The restructure is deliberately the smallest one that works: `pingOperator` is handed
`noPromptSurfaceReason(permissionMode)` — the same pure function `emitApprovalRequired`
evaluates a few lines later — plus `session_id` and `cwd` off `hookData`. Recomputing a pure
string is cheaper and far less fragile than restructuring the refusal path around the
notification, and it means the notify layer cannot alter the verdict even by accident:
`emitApprovalRequired` remains the sole owner of the decision and still derives it
independently from the permission mode alone.

`loadNotify` now returns `denialChannel` (the webhook, when configured) alongside the primary
`channel`. `pingOperator` picks exactly one — never both — so the "one channel per hold"
invariant that keeps the one-shot hash from being offered on two surfaces still holds.

Constraints honoured:

- **Best-effort:** unchanged try/catch, unchanged per-channel deadline, result used for a
  stderr breadcrumb only. Pinned by tests for both events.
- **`emitDecision` byte-identical:** not touched at all. The e2e tests compare the full
  decision object against a no-notify baseline run.
- **No added latency on the allow path:** the allow path exits before any of this. The denial
  path additionally short-circuits inside the card channel before its 4s receipt poll.
- **One process per tool call:** no new state, no new background work; the existing detached
  waiter is the only thing that outlives the process and is now never launched for a denial.
- Tier rules, the broker's pre-clear set, `enforce`, `failurePolicy` and the catastrophic
  hard-block: untouched.

## Verification — real output

### `npx tsc --noEmit -p tsconfig.json`

This config is **already red on `ba6e97c`** — it includes test files with long-standing type
errors (duplicate identifiers, `rootDir` violations from `benchmark/`, untyped `.mjs`
imports). It is not the build config; `tsconfig.build.json` is. I pinned that my change adds
nothing:

```
$ npx tsc --noEmit -p tsconfig.json 2>&1 > /tmp/tsc-after.txt; grep -cE "^[^ ]" /tmp/tsc-after.txt
173
$ git stash -q && npx tsc --noEmit -p tsconfig.json 2>&1 > /tmp/tsc-before.txt; grep -cE "^[^ ]" /tmp/tsc-before.txt
173
$ git stash pop -q; diff <(grep -E "^[^ ]" /tmp/tsc-before.txt) <(grep -E "^[^ ]" /tmp/tsc-after.txt) && echo "IDENTICAL to HEAD"
IDENTICAL to HEAD
```

The config the build actually uses is clean:

```
$ npx tsc --noEmit -p tsconfig.build.json; echo "exit=$?"
exit=0
```

### `jest src/__tests__/prompt-surface-deny.test.ts src/defence/iron-dome/__tests__`

```
    the operator is told a job died (#143)
      ✓ delivers a denied_no_prompt_surface event naming the reason, the session and the cwd (119 ms)
      ✓ signs the body with notify.webhookSecret, so the receiver can reject a forged POST (119 ms)
      ✓ never leaks the secret into stdout, stderr, or the audit row (121 ms)
      ✓ a prompting session still gets the approval event, unchanged (116 ms)
      ✓ the notification carries the SAME hash the denial reason offers for the retry (117 ms)
      ✓ the approve command it offers really does authorise the retry (188 ms)
      a promptless denial survives a broken channel
        ✓ a receiver returning 500 changes nothing (178 ms)
        ✓ a receiver that never responds is cut off at the deadline and changes nothing (740 ms)
        ✓ a refused connection changes nothing (166 ms)
      a live hold survives a broken channel
        ✓ a receiver returning 500 changes nothing (188 ms)
        ✓ a receiver that never responds is cut off at the deadline and changes nothing (744 ms)
        ✓ a refused connection changes nothing (165 ms)
```

```
Test Suites: 44 passed, 44 total
Tests:       1083 passed, 1083 total
```

(First attempt at that command showed 2 failures in `config-normalization.test.ts` — a fresh
worktree whose `node_modules/better-sqlite3` had no compiled binding, unrelated to this work.
Fixed with `cd node_modules/better-sqlite3 && npm run build-release`; that is now recorded in
my notes on this repo's test recipe.)

### Full suite

```
$ npm run build:ts && SHIELDCORTEX_SKIP_EMBEDDINGS=1 \
    node --experimental-vm-modules node_modules/jest/bin/jest.js --runInBand

Test Suites: 351 passed, 351 total
Tests:       7 skipped, 4039 passed, 4046 total
Snapshots:   0 total
Time:        248.822 s
Ran all test suites.
```

### The tests were verified failing-first, retroactively

I wrote the implementation before the tests, so I proved the tests actually bite: reverted
`src/` + `scripts/` to `ba6e97c`, kept the new test files, rebuilt `dist`, ran them.

```
      ✕ delivers a denied_no_prompt_surface event naming the reason, the session and the cwd
      ✕ signs the body with notify.webhookSecret, so the receiver can reject a forged POST
      ✕ a prompting session still gets the approval event, unchanged
      ✕ carries the denial event with the reason and WHICH JOB died
      ✕ states plainly that the action was blocked and did not run
      ✕ offers no Approve/Deny pair — there is nothing left to deny
      ✕ carries the denial event on the header and the body, with the reason and which job died (#143)
      ✕ reports not-delivered and never spawns the waiter
      ✕ accepts a plausible key and hands it through
      … 19 failed, 95 passed, 114 total
```

The best-effort pins ("a broken channel changes nothing") **passed** on the old tree, which is
exactly what they are for: they are regression pins on a property that already held and must
survive this change.

## Tests added

- `src/__tests__/prompt-surface-deny.test.ts` — a new `the operator is told a job died (#143)`
  block. Drives the **real** hook against the **real** dist and the **real** webhook channel
  over a throwaway `127.0.0.1` HTTP server (no fake channel, no network off-box), asserting
  the header, the HMAC signature, the body and the rendered text. Includes the
  broken-channel matrix (500 / never responds / refused connection) run for **both** events
  against a no-notify baseline decision.
- `operator-notify.test.ts` — denial wording; the default event for pre-discriminator
  callers; an unknown event degrading to the approval wording; a `deniedReason` ignored on
  the approval event; bounded session/cwd; and the whole adversarial best-effort battery
  re-run over both events.
- `webhook-notify-channel.test.ts` — header and body event for both, denial fields, the
  signature computed over the exact body sent, unsigned when no secret.
- `openclaw-approval-channel.test.ts` — a denial never becomes a card, never spawns the
  waiter, and costs no receipt-poll latency; live holds unaffected.
- `notify-config.test.ts` — `webhookSecret` normalisation, including non-string and over-long
  values being dropped rather than accepted.

## What I did not do

- **No non-interactive OpenClaw send path.** See §3. This is the one requirement I could not
  fully satisfy without inventing a gateway call, which the brief forbids.
- **`plugins/openclaw/gateway-notify-channel.ts` is unchanged.** It carries its own structural
  mirror of `OperatorNotification` (it cannot import across the plugin `rootDir`) and serves
  the plugin interceptor, not the hook. Denials on that surface are a separate change; the
  required field on the real interface does not break it, because the mirror is structural
  and method parameters are bivariant. Verified: all 19 plugin suites, 174 tests, pass.
- **No notify handling in `handleDegradedGuard`.** That path runs when `dist` is missing or
  the guard threw — the notify modules load from the same `dist`, so there is nothing to load.
  It denies with the same message as before; the audit row still records
  `denied_no_prompt_surface`. Flagging it because it is a genuine, pre-existing hole in the
  "every denial is reported" claim.
- **No docs.** `notify.webhookUrl`, `notify.openclaw` and now `notify.webhookSecret` appear in
  no README or `docs/` file — the whole `notify` config block has been undocumented since
  #143 landed. Adding a config reference is worth doing but is not this change.
- **No CHANGELOG entry, no version bump, no push.** Consistent with how 6771901 and 7c0e485
  were committed (CHANGELOG is written at release).

## Things worth knowing

- `BRIEF-143.md` and `REPORT-143.md` are committed as working notes. Drop them before any PR.
- `dist/` in this worktree has been rebuilt from this branch. The hook loads from `dist`, so
  anything exercising it locally is running the new code.
- The e2e suite's "has dist been built at all?" probe (copied from
  `pre-tool-hook-notify-143.test.ts`) only builds when dist files are **missing**, not when
  they are stale. If you edit `src/defence/iron-dome/*` and re-run only the hook tests
  without `npm run build:ts`, you will be testing the old dist. That trap predates this work;
  I am flagging it rather than fixing it here.
