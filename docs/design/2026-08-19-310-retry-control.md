# #310 — Operator Retry Control for Headless Denials (Design v3)

Date: 2026-08-19 · Author: TARS · Status: v3-FINAL — R3 verdicts: Grok 4.6 APPROVE_WITH_NITS · GPT-5.6 SOL Pro APPROVE_WITH_NITS (nits folded below)
(R1: both REQUEST_CHANGES → pivot to mint-on-intent. R2: both REQUEST_CHANGES on spec holes;
architecture endorsed by both. v3 closes the R2 blockers.)

## Core principle (unchanged from v2)

**Mint on operator intent, not on denial.** DNP stays terminal; nothing spendable exists
until a human acts. Cards are claim tickets; grants are atomic, scoped, one-shot.

## R2 blocker resolutions

### B1 (Grok) — deny-epoch, not remint-generation

v2's per-DNP generation bump broke the primary use case (same-session/looping retries would
stale-age the live card). v3:

- **`denyEpoch`** advances ONLY on operator Deny, claim expiry, or explicit clear — never on
  remint. Remints of the same hash+origin refresh `lastDeniedAt` only.
- A live launch-claim **pins the epoch**: the card remains valid for its lifetime even as the
  job keeps flapping. Tap authorises the retry it was drawn for.
- `grantRetry` fails closed if the epoch record is missing/unreadable (corrupt-store reset can
  never revalidate a stale card: fresh store ⇒ no claim record ⇒ claimNonce check fails first).

### B2 (Grok+SOL) — suppression is first-class and ordered

Order per DNP event: **suppression check → digest/budget accounting → card/mint.**
- Suppressed events never open the siren window, never burn card budget, still write
  fingerprints + audit (audit truth preserved).
- `grantRetry` refuses when suppressed (deny beats in-flight approve — a tap on a card that
  outlived a Deny is a no-op, audited `suppressed`).
- TTY `--denial` during suppression: refused by default; `--override-deny` exists with an
  explicit "you are overriding your own deny from <time>" confirmation. Cards never override.
- Honest naming: suppression is **windowed silence** (default = digest window). The docs say
  "deny silences this action for N minutes", never "deny is permanent".

### B3 (Grok+SOL) — origin binding: AND-match, fail closed, honestly sourced

- Capture source named: hook has HMAC `sessionKey` (from harness session_id) — that is ALL
  that exists today. There is **no cronId on PreToolUse** and the OpenClaw interceptor's
  unattended path never consults the #118 store. Scope: **hook path only** in this phase;
  interceptor cards are explicitly out (documented as hard a split as Hermes-cards).
- Known limitation, stated plainly: a NEW Claude session (next cron tick spawns one) gets a
  new sessionKey. Therefore the default grant scope is **`cwd + tool` AND-matched**, with
  sessionKey pinned additionally when the retry happens in-session. `cwd` comes from the
  harness payload (same trust as sessionKey), never from tool input.
- Empty scope (no cwd, no sessionKey) ⇒ **card grant refused** (`unscopeable`, audited,
  webhook says use TTY). TTY `--any-origin` remains, off by default, with the "ANY local
  process may spend this" confirm.
- `consumeApproval` for `grantKind:'retry'` takes a caller-computed origin argument from the
  hook's own context. AND-match every bound field. Live-hold consume branch byte-identical.

### B4 (Grok) — authenticated grant + single lock plane

- **`claimNonce`**: 256-bit nonce minted at launch-claim, passed only on waiter argv, never
  written to denials.jsonl/webhook/audit. `grantRetry(fingerprint, nonce)` requires it on the
  card path; `assertInteractive` gates the TTY path. A same-user process importing the library
  cannot mint (no nonce, no TTY).
- Waiter **never calls `approveRequest`** on the DNP path — new decision mapping:
  `allow-once → grantRetry(fingerprint, nonce)`, `deny → recordDenySuppression`,
  timeout/unknown → nothing. New `dnp-retry-waiter.ts`; `createOpenClawApprovalChannel` is
  not reused (its send() semantics are live-hold-only, per its own header).
- Invariant: **no `grantKind:'retry'` row without `approvedAt`** — grant is one locked write,
  never recordPending-then-approve. Double-tap idempotent (`already-granted`).
- **One lock plane**: fingerprint store, suppression, launch-claims, budget debits, and grants
  live in one `flock`-guarded store file (`retry-control.json` beside approvals; the existing
  approvals RMW+rename is last-writer-wins and stays live-hold-only). Launch-claim is atomic
  with the budget debit; failed spawn releases the slot.

### B5 (SOL) — denial-fingerprint store is first-class

`retry-control.json` holds `actionId → { hash, denyEpoch, lastDeniedAt, originScope: {cwd?,
sessionKey?}, tool, signals, redactedSurface, deniedAt, suppression?, claim?, grant? }`.
- TTL/prune: fingerprints prune with the pending-retention clock (60m rolling from last DNP);
  suppressions prune at window end; spent/expired grants prune at spend-TTL + 24h (audit tail).
- denials.jsonl stays #284-redacted (no hash) — the fingerprint store is the control record,
  permissioned like approvals (0600, owner-only).
- `shieldcortex approve --denial <actionId>` reads the fingerprint → same `grantRetry`. No
  hash reconstruction from redacted surfaces, no spendable token in any alert.

### B6 (both) — budgets and clocks, named and aligned

| Clock | Name | Default |
|---|---|---|
| Card lifetime | gateway ceiling | 10m |
| Grant spend TTL | `actionGuard.retryGrantTtlMs` | 10m from tap |
| Deny suppression | `actionGuard.denySuppressionMs` | = digest window |
| Card budget window | **shares the digest window start** (`dnpDigestWindowMs`) | 15m |
| Fingerprint retention | pending-retention clock | 60m rolling |

- Card budget: per-hash 1 (epoch-pinned claim) + global 3 per window. Suppressed events don't
  count. `budget_exhausted` appears on the **operator digest/webhook copy** with the actionIds
  that lost cards ("use `shieldcortex approve --denial <id>`"), not audit-only.
- Unspent-expiry sweeper: the hook runs an opportunistic prune+notify on every DNP event and
  on `shieldcortex approvals`/`approve` invocations (named trigger — no daemon; worst case the
  notice rides the next guard event, stated honestly in the ADR).

### Card copy (256-char budget, trust copy first)

Title ≤80: `SC retry? <tool> · <top-signal>` · Description: mandatory trust copy ("already
denied — approving authorises ONE retry, <ttl>m, scope <cwd-tail>") is never truncated; the
redacted surface fills the remainder and truncates last. Hash and full surface live in the
webhook alert + audit row (card = control, webhook = record). Secret-egress class: surface
withheld. If cron interval > spend TTL, card says so and points at `--denial` with `--ttl`.

## Unchanged invariants

- Claude CLI PreToolUse never pauses; catastrophic: no card, no grant, ever.
- Tap = one-invocation consent (gateway-approver identity); never mints/spends
  `reviewedScripts`; no allow-always.
- Payload/`permission_mode` never mute/trigger/scope anything.
- Live-hold #118/#143 flow byte-identical (regression-pinned).
- #331 siren untouched.

## ADR + rollout gate

New ADR file supersedes 2026-08-16 clauses 2 + terminal-DNP corollary; restates 1/3/5.
Ship dark behind `actionGuard.retryCards=false` default. Soak on Edith-class host ≥3 days:
deny/approve/timeout matrix across ≥3 cron identities + empty-origin + grant-then-newer-DNP +
budget-exhaustion cases. Flip default only after soak review.

## Test plan (R2 additions folded in)

Unit: epoch pinning (remint under live claim stays valid), deny-epoch advance rules,
suppression-first ordering, budget accounting excl. suppressed, claimNonce required,
assertInteractive TTY gate, no-retry-row-without-approvedAt, copy budget order, catastrophic-
never, unscopeable refusal.
Store: flock serialization (concurrent DNP + tap), corrupt-store fail-closed (no stale-card
revival), deny-beats-inflight-approve, double-tap idempotence, cross-origin spend refused,
cwd+tool AND-match, --any-origin TTY-only, live-hold byte-identical regression.
Races: approve-vs-remint, deny-vs-approve, two-waiter launch-claim, tap-after-prune.
Soak: as above.

## R3 nits — folded as binding implementation rules

1. **Prune precedence**: never prune a row with a live claim or unspent grant; fingerprint TTL
   yields to claim/grant terminality; spent/expired grants keep a spend-TTL+24h audit tail.
   tap-after-prune stays refuse.
2. **Canonical identity**: rows upsert by `(hash, originScope)`; `actionId` is a secondary
   alias index for `--denial`/webhook — epochs never split across actionIds of one identity.
3. **Spend predicate is `{cwd, tool}` ONLY** — sessionKey is recorded as diagnostic telemetry,
   never AND-matched (a new cron tick's fresh sessionKey must not fail-close the retry).
   `cwd` canonicalised (realpath, strip trailing slash) before match.
4. **claimNonce at rest**: store `HMAC(nonce)` in retry-control.json, never the raw nonce;
   nonce passes to the waiter via inherited fd where possible, argv fallback documented.
5. **Consume on the flock**: retry-grant consume is a locked RMW in the same plane;
   concurrent-consume race is in the test matrix; a live unspent grant blocks a second
   launch-claim (consume-before-card ordering).
6. **Post-grant regret**: operator Deny (card or TTY) revokes an unspent grant in the same
   locked write — deny always wins over an unspent approve.
7. **Window alignment**: card-budget window start := digest window start, read in the same
   handler — no independent first-event windows.
8. **Ack follows store**: waiter acks allow-once only after grantRetry returns ok;
   grant_failed → no ack, operator pointed at --denial.
9. **TTY gate**: use the live `isInteractive` symbol from approve.ts (not a new assert).
10. **Interceptor stays out of consume as well as cards** — stated in the ADR so the
    OpenClaw-native cron path is never "helpfully" wired to the #118 store in this phase.
