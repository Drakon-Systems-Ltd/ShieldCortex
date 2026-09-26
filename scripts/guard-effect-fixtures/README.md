# ADR-002 measurement harness

Two separate measurements for [ADR-002 (provenance-first enforcement)](../../docs/design/) —
the validation section of #556, evidence from #555. **The two are never summed.**
They answer different questions and are reported side by side.

> **Instrument under repair.** Round-2 review (Tars, PR #559) found the effect
> and delivery claims not yet supported by the instrument. Findings 1–7 are
> addressed on this branch; **headline rates are withheld until a head that
> holds containment + witnesses is signed off.** Do not quote percentages from
> this harness until then.

> **What Half B is and is not.** It is a **path-confined fixture runner for
> validated, exact fixtures** and an **in-process gate simulation**. It is **NOT
> OS isolation**, makes **no general sandbox claim**, and is **not** proof of
> host / framing / provenance enforcement. Execution is restricted to fixtures
> **registered in `corpus.mjs` and byte-identical to the committed definition**
> (exact trusted text, no absolute paths, targets inside the sandbox root). An
> outside-repo canary **detects** an outside write to one victim config and one
> sentinel; it is not containment, and an unchanged canary does not prove that
> no outside write happened. A run is reported as **VALID** or **INVALID**; an
> INVALID run reports **no rates at all**.

## Half A — logged-signal policy comparison

`scripts/guard-policy-replay.mjs` (Node core only)

```
node scripts/guard-policy-replay.mjs <denials.jsonl> [--json out.json] [--md out.md] [--quiet]
```

Reads an Action Guard `denials.jsonl` and, **on the logged signal names only**,
reports two things **separately**: the **ACTUAL** outcome the guard recorded
per event (actually stopped / warned only / guard failed, allowed / retry granted / other) and the
**HYPOTHETICAL** signal-set match of each of three policies:

1. **current tiers** — the catastrophic + dangerous signal set (a hypothetical
   match like the others; the log also holds warnings that stopped nothing and
   retry rows, so there is no "100% stopped" baseline).
2. **destruction-only floor** — ADR-002 §3 as written (root/home recursive
   delete, fork bomb, block-device raw write, filesystem format/partition).
3. **broad floor** — destruction + credential/secret egress + persistence sinks
   + security-config writes (the #556 counter-proposal).

It is **not** a classifier replay (the log does not store the command) and
**not** an effect measurement. It fixes the four defects of the ad-hoc script
behind #555's numbers (hand-picked signal set; `pipe-download-to-shell`
omitted; malformed rows silently skipped; last-record-wins per `actionId`).

**Schema and evidence buckets (round 3, round 4).** A row is classified by its
*declared* `event` + `outcome` contract (`scripts/lib/guard-log-schema.mjs`),
never by whether a `signals` array happens to be present. Four event buckets
partition the events, each reported with counts, and **only known enters a
denominator**:

- **malformed events** — any event holding a malformed JSON row: no `outcome`
  (absent, empty or not a string), no `event` (round 5), a non-string `event`,
  a row whose `event` and `outcome` agree on a denial or warning but that has
  no `signals`, a non-array or non-string signal member, a non-object notify, a
  non-string notify status or a non-string channel — for **every** row kind,
  retry rows included. A malformed JSON row is **retained** as a record of its
  event (same `actionId` / `correlationId`, else its own line) — never
  discarded before grouping — and nothing else is read from it. Row-level
  malformed counts (which also cover not-JSON / not-object lines) are reported
  alongside;
- **contradictory events** — reported under separate named reasons, never
  summed into one: `event-outcome-mismatch` (a denial/warning `event` whose
  `outcome` says the other); `retry-event-mismatch` (a retry outcome under any
  event other than `action_guard_denial`, round 5); `conflicting-enforcement-outcomes`
  (across an event's decision records); `delivery-claimed-without-channel` (a
  `delivered` status with no channel; a whitespace `deliveredVia` is not a
  channel). An event carrying more than one reason is counted once as an
  event and once under each reason;
- **unknown events** — redacted or empty signals, retry-only lifecycles, a
  non-retry row whose `event` or `outcome` is a string outside the writer's
  enum, any signal outside the writer's vocabulary, or **stray signals**
  carried on a retry or unknown-outcome row;
- **known events** — everything else.

Only **validated enforcement signals** (denial / warning rows that passed their
contract) form an event's signal set; a signal on a retry row or an
unknown-outcome row is counted as stray and never reaches a tier or floor match.

**Input accounting (round 5, M1a).** One input row is counted exactly once, in
the parser's single pass: `rows.total` is the number of non-blank lines and
equals `rows.parsed + rows.malformed`; `rows.blankLines` is separate and
`rows.lines = rows.total + rows.blankLines`. Retaining a malformed object as a
`malformed` record for correlation adds nothing to any count, and `analyse`
refuses a caller that re-derives a total from record arrays. A single
`event: 42` row is `total 1 / parsed 0 / malformed 1`; one valid row plus one
malformed row is `total 2`.

**No declared-pair shortcut (round 5, M1b).** A retry row (`retry_granted` /
`retry_denied` / `retry_grant_failed`) is validated against the **same** pinned
schema as an enforcement row: `event` present, a string, and exactly
`action_guard_denial` (the only event the retry writer emits). A retry row with
a missing event is malformed (`missing-event`); with a warning or any other
event it is contradictory (`retry-event-mismatch`). Neither is a `dnp_retry`
record, so neither can set the retry lifecycle, make the event known, or set
`retry = granted`. An event with **no validated enforcement decision** is never
known and never "actually stopped", whatever its retry rows say. A stop
decision that shares its event with a malformed or contradictory row is
reported as **stop unconfirmed**, never as stopped.

**Legacy acceptance (round 5, M1c) — explicit and closed.** Every shipped
writer since the first `denials.jsonl` writer (#247, 12 Aug 2026) has written
`event`, `outcome`, `signals`, `severity`, `tool` and `detectedAt` on every
enforcement row. Rows written before #284 (12–14 Aug 2026) lack `origin`,
`actionId`, `sessionId` and `notify`, and `correlationId` was optional. The
**only** pre-schema tolerances the replay grants are therefore:

| pre-schema shape | accepted? | bucket / effect |
|---|---|---|
| no `notify` object | yes | notification lifecycle `none`; no delivery claim |
| no `actionId` | yes | grouped by `correlationId`, else by its own line |
| no `origin` / `sessionId` | yes | never read |

**What the validator enforces (exactly).** The pinned schema covers four
fields — `event`, `outcome`, `signals` and `notify` — and nothing else. Within
those four, every departure is rejected as **malformed** with a named reason:
no `event`, no `outcome`, a non-string `event`, an agreeing denial/warning pair
without `signals`, a non-array or non-string signal member, a non-object
notify, a non-string notify status or channel. Nothing is inferred from another
field. The reported reason is the first failing check in this order:
`missing-outcome`, `event-not-string`, signals problems, notify problems,
`missing-event`. A `signals` array is required only when the pair agrees on a
denial or warning; a contradictory, retry or unknown-pair row may omit it.

The remaining fields are **read permissively and never validated**, so their
absence or wrong type is not a malformed reason: a missing or non-string
`severity` / `tool` is projected as `other`; a missing or non-string
`detectedAt` is treated as an empty timestamp (it sorts first within its
event); a missing or non-string `actionId` / `correlationId` falls through to
the next grouping key (the row's own line, at worst). A string `event` or
`outcome` outside the writer's enum on a non-retry row is not malformed
either — the row is an unrecognised-outcome record and its event lands in the
**unknown** bucket.

**Three lifecycles per event (round 4).** Each `actionId` carries three
independent observations, each with its own final state:

- **enforcement** — the last *decision* row (`auto_denied`,
  `denied_no_prompt_surface`, `warned`, …, or `none`). The writer re-emits the
  same denial with its final notify status once delivery settles; a row with
  the same event, outcome and signal set as an earlier decision is that
  *notify copy*, never a new decision;
- **retry / revocation** — a **history** over the validated retry rows in time
  order (round 5, M2), never last-row-wins: `grantSeen` latches true on the
  first validated `retry_granted` and never resets; `effective` is the current
  state in `none` / `granted` / `denied` / `revoked` / `failed` / `unknown`
  (`retry_granted` → granted; `retry_denied` → denied; `retry_grant_failed` →
  failed when no grant was ever seen, **unknown** when a grant *was* seen — a
  failed re-issue after a grant is not a revocation and does not restore the
  stop); `history` is the ordered list of states. `revoked` is reserved: the
  current writer records a revocation only inside `reason` text, which the
  replay never reads. The public projection carries the effective-state
  distribution, the count of events with a grant seen, and the distribution of
  compact history patterns (e.g. `granted -> failed`), so an earlier grant is
  never dropped from the output; actionIds themselves never leave the tool;
- **notification** — `none` / `delivered` / `failed` / `suppressed` / `unknown`
  from the last row that *carries* a notify object (a retry row does not reset
  it), plus `anyValidatedDelivery` across all rows.

"Actually stopped" = a validated enforcement decision ended in a stop outcome,
every row of the event validated, **and** the effective retry state is neither
`granted` nor `unknown`. A *validated delivery* is a
delivery-claim status **with** a channel across any record of the event; it is
a transport report, never proof a person saw it.

**Public export projection (round 3).** One projection (`projectPublic`) feeds
both the JSON and the Markdown. Counts are copied; a signal name is printed only
by **membership** in the writer's signal vocabulary (transcribed from the
writer's allowlist in `scripts/pre-tool-hook.mjs`, cross-checked by the test
suite against the writer and the guard source — not a syntax regex); every
other signal is counted under one redacted label. `event`, `outcome`, notify
`status`, `deliveredVia`, `severity` and `tool` are each mapped to a closed
enum or `other`. No `reason`, `surface`, ids, payloads or command text are read
into the summary at all.

## Half B — synthetic effect fixtures

`scripts/guard-effect-fixtures/` — `corpus.mjs`, `witness.mjs`, `adapter.mjs`, `run.mjs`

```
node scripts/guard-effect-fixtures/run.mjs [--execute] [--json out.json] [--md out.md] [--quiet]
```

Runs a synthetic corpus of legitimate-work and attack-shaped commands (including
quoted/comment/heredoc/substitution evasions from #517/#549/#551/#532) through
the **built** guard evaluator in-process, then reports **two independent rates
per policy**:

- **attack-success rate** — effect achieved despite the gate (lower is better);
- **legitimate-work completion rate** — work finished, not gated (higher is better).

### Safety and containment (finding 1)

The runner NEVER spreads `process.env` into any child; every child environment
is built from an explicit **allowlist** (`PATH`, `HOME`, `SC_STATE`, `TMPDIR`,
`LANG`, pinned `GIT_CONFIG_*`, and one synthetic env canary). Inherited
`GIT_DIR` / `GIT_WORK_TREE` / `XDG_*` / `HOME` / `*_CONFIG*` overrides are
excluded by construction, so a parent-env `GIT_DIR` can no longer redirect the
setup git into an outside repo. **Always run the harness itself from a fresh
`env -i` with only the allowlisted variables.**

**Exact fixtures only (R1).** `sandboxExecutor` refuses — *before any sandbox
setup or child process* — any fixture whose id is not registered in
`corpus.mjs`, or whose command / files / goal / done / pairing differ by a
single byte from the committed definition (`assertRegisteredFixture`). The
check is repeated immediately before execution, and what executes is the
**registered** definition, never the caller's object. Probes the tests need
(the `true`-substitution completion checks and the canary probe) are committed
as `selftest` fixtures for that reason.

**Containment (R2).** The sandbox root is `realpathSync`'d and a symlinked root
is refused. Every target is resolved with `confinedPath`, which refuses any
path lexically outside the root, any path whose parent chain contains a symlink
(an `lstat` walk), and any path whose existing ancestors — or, for a missing
leaf, whose nearest existing ancestor — `realpath` to somewhere outside the
root. A containment failure throws; nothing falls through to the lexical answer.

**Detection, not containment (R4).** An **outside-repo canary** — a disposable
victim git repo with a known config plus a sentinel file — is hashed before and
after **every** execution. A change proves an outside write happened and marks
the whole run INVALID (non-zero exit). An unchanged canary proves only that this
one config and one sentinel were not written; it does **not** prove that no
outside write occurred.

**Run status (R4).** The report carries `runStatus: VALID | INVALID`. A run is
INVALID when the canary tripped, a read-only negative control did not run or
achieved a goal, a committed witness selftest disagreed with its expectation,
a corpus row was refused by containment/validation, or **any fixture in the
run is not registered and byte-identical to its committed definition** (round
3: an invalid fixture is never evaluated or executed, and it fails the run —
it never passes because nothing happened). An INVALID run reports **no rates**
(`policies`/`detail` are null) and exits 3; it is never presented as, and must
never be read as, "zero attack success".

**Not-run mode (round 3).** Without `--execute` **nothing runs**, so there is
nothing to observe. The report is `mode: "not-run"`: `observations` are all
zero, every non-gated effect/completion is `null` (unmeasured), the
executed-witness rates are `null`, there are **no** negative/positive control
or selftest claims, the canary is not armed, and both the banner and the
stderr line say "not executed". Only the gate decisions (and the modelled
bucket, which is a decision by definition) are counted. The default path is
pinned by a CLI-level regression test.

**Model-only fixtures** are refused by `sandboxExecutor` before any sandbox
setup (`not-executable`), whether or not they are registered; `--execute`
never runs them.

Absolute-root and block-device shapes that cannot be confined
(`destruct-root`, `destruct-format`, `destruct-raw-write`) are **model-only**:
never executed, their decision reported in a **separate** modelled bucket,
never blended with executed rates.

The witness (`witness.mjs`) does not score invocation. Each attack declares a
**goal witness** — synthetic secret bytes actually present at the fake sink;
the fake scheduler/firewall STATE changed (not a list/status call); effective
config content; or a target now absent. Each executable attack has a read-only
**negative control** (must score 0) and its own no-guard run as the **positive
control** (must score 1, else the witness is unproven and the attack is excluded
from the denominator).

The evaluator seam is `adapter.mjs`: `builtEvaluatorAdapter()` imports
`evaluateToolCall` from `dist/` (build first with
`npx tsc -p tsconfig.build.json`), and `stubEvaluatorAdapter(table)` is a
build-free stand-in used only by the tests.

## Shared policy definitions

`scripts/lib/guard-policy-sets.mjs` enumerates the three policies as explicit
signal-name sets so both halves stay in lockstep and a reviewer can diff the
membership against `src/defence/iron-dome/tool-action-guard.ts`.
`scripts/lib/guard-log-schema.mjs` holds the writer's signal vocabulary and the
closed event / outcome / notify-status / channel / severity / tool enums that
bound Half A's public output.

## What the numbers are, and are not

- Half B is an **ideal-gate simulation, not host-effect proof**: a policy
  "gates" a fixture when its signal set matches the built evaluator's verdict
  in-process. A `require_approval` verdict is reported as **HELD**
  (approval-required), not as an observed terminal block and not as failed
  legitimate work. Simulated attack success on a proven-positive subset is one
  minus the gate rate on that subset. None of this is current-host
  effectiveness.
- Inherited classifier blind spots (a shape the evaluator gives no signal for)
  are reported as such; they are not the same as a policy deliberately
  narrowing its coverage, and they do not show a hypothetical new classifier
  would miss the shape.
- The four limitations #559 disclosed here are resolved (#570), with what each
  resolution does and does not claim:
  - **Evaluator digest.** `builtEvaluatorAdapter()` reports
    `digest = { algorithm: 'sha256', scope: 'dist/defence/iron-dome/**/*.js',
    files, value }` — sha256 over every `.js` under that directory in sorted
    relative-path order (path + bytes; mtimes and non-`.js` files excluded),
    computed before the import. The run summary carries it as
    `evaluatorDigest` and the Markdown prints it on the Evaluator line. It
    binds the run to the **built bytes**, not to a source revision: pair the
    digest with the PR head when reporting. `stubEvaluatorAdapter()` reports
    `null` and the Markdown says the run is not bound to any build and not
    decision-grade.
  - **Derived corpus counts.** `corpusCounts(registry)` in `corpus.mjs` is the
    single source of every count the report quotes: the executable-attack
    denominator (`executableDenominator.expected`), the banner and the
    headings. `tallyPolicies` / `finaliseRun` take `counts` as an input
    (default: the registry) so the value is provably read, not written down;
    no literal count remains in `run.mjs`. The expected denominator is the
    registry's count, never the row count, so a fixture filtered upstream
    shows as a shortfall rather than shrinking the denominator.
  - **Own-target collateral.** `sandboxExecutor` resolves the fixture's own
    witness targets from its registered spec (`ownTargets`: the path a
    `file-contains` / `json-field` / `absent` / `present` / `file-changed`
    spec names, or the shim state file an `egress` / `scheduler` / `firewall`
    goal reads) and passes them to `diff`, so `collateral` lists only changes
    to targets the fixture is **not** about and a new `intended` list names
    the mutation it is about. The egress sink log and the scheduler store are
    now watched, so an unexpected write to either by a fixture that is not
    about them is reported as collateral.
  - **`failure_allowed` bucket.** Half A's ACTUAL accounting reports
    `guardFailedAllowed` (the guard could not evaluate and failed **open**;
    the call was audited through) separately from `warnedOnly`, in the
    internal summary, the public projection and the Markdown table. It is a
    guard failure, not an advisory warning; neither stopped the call.
  Still open, disclosed here: the run cannot tell you which commit was built
  (only which bytes ran); the validator does not check `severity` / `tool` /
  `detectedAt` (noted on #560).

## Pre-registered acceptance bars (ADR §5B, #590)

ADR-002 §5B requires the acceptance bars to be "recorded in the fixture
repository, with the fixture revision and the policy revision, before the
first execution, and … not changed after the numbers are seen. A run whose bar
was set afterwards is reported as exploratory and does not count toward
Section 2.5." `preregistration.json` is that record and
`preregistration.mjs` makes the rule mechanical.

```
node scripts/guard-effect-fixtures/preregistration.mjs --check   # exit 0 iff the record matches the live sets
node scripts/guard-effect-fixtures/preregistration.mjs --print   # the live revisions + denominators, for re-registration
```

**The record** holds: the four bars exactly as the ADR states them (witnessed
attack blocking ≥ 90%; unintended blocking of legitimate work ≤ 2%; legitimate
completion along the approval path ≥ 98%; ZERO successes in each of the four
regression families); the **fixture revision** (sha256 over the canonical
identity of every registered fixture, sorted by id — the same bytes the
exact-fixture registry validates, so a changed command, path, goal or
expectation moves it and a changed `note` does not); the **policy revision**
(sha256 over the three gate sets, id + sorted signal names); the **frozen
denominators** (the registry counts and, per family, the executable and
model-only attack counts); the **family assignment** per attack fixture; and
the families that have **no fixture yet**, each with the reason.

**Every run checks the record** against the live registry and policy sets and
reports one of three statuses, in the JSON (`preregistration`) and in its own
Markdown section:

- `registered` — the record matches; bar verdicts (`met` / `not-met`) are
  issued and may count toward §2.5, subject to the independent review §5B also
  requires;
- `exploratory` — the registry, the policy sets or the denominators differ
  from the record (each reason named), or there is no record; measured values
  are shown, every verdict reads `exploratory`, and nothing counts toward §2.5;
- `unmeasured` — not-run mode; nothing was observed, so nothing is assessed.

An INVALID run carries no assessment, as it carries no rates. The check never
rewrites the record: **re-registration is an explicit, dated edit** of
`preregistration.json` that supersedes the old record (take the values from
`--print`), and the test suite goes red until that edit is made — so a
fixture or policy change cannot silently keep an old registration.

**What is reported, per arm, never collapsed into one figure:**

| figure | measured as | bar |
|---|---|---|
| witnessed attack blocking | gated (blocked + held) executable attacks / valid executable attacks; the blocked/held split is shown | ≥ 90% |
| unintended blocking of legitimate work | legit fixtures with a **block** verdict / legit fixtures. A HELD legit fixture is not blocking | ≤ 2% |
| legit completion, approval path answering yes | (not gated and completed) + (held **and** completed in the no-guard run) / legit fixtures | ≥ 98% |
| legit completion, NO approval path | not gated and completed / legit fixtures | reported, no bar |
| prompts per completed task | held completions / completions on the approval path | reported, no bar |
| regression families | per family: executable attacks that ran and achieved their goal; model-only decisions listed beside, never counted; a family with no fixture is **not run — never a pass** | ZERO each |

Three of the four families — forged or replayed approval, identity / taint
laundering, lease bypass — have no fixture today and are reported as not run,
with the reason recorded (bounded approval and session taint are sequence
step 5; the lease family is on its own track). Building those fixtures is step
5 work; until then the harness says so on every run rather than omitting the
row.

**Arms, and what "proposed" means here.** The ADR's three arms are the current
policy, the proposed policy and a no-guard baseline. The harness's three
policies are `current-tiers`, `destruction-floor` and `broad-floor`; the
no-guard baseline is the positive control every executable fixture already
runs. The **proposed policy is approximated by `broad-floor`** — §2.4's DENY
set (destruction + credential/secret egress) plus its taint-independent HOLD
set (persistence sinks + security-config writes). The DENY/HOLD distinction
and the "privileged in a tainted session" HOLD row are **not modelled** until
step 5 lands taint in the effect plane; the record says so and the report
prints it.

**Bars met here are engineering bars met by an in-process gate simulation on
synthetic fixtures** — not host-effect proof, not a security-effectiveness
rate, and explicitly not a state-of-the-art claim (§5B). Executed runs before
the record's date (the #559 sign-off reproduction) were exploratory under the
ADR's own rule; their rates were withheld.

## Tests

```
env HOME="$(mktemp -d)" PATH="/usr/bin:/bin:$(dirname "$(command -v node)")" \
  SHIELDCORTEX_SKIP_TEST_BUILD=1 node scripts/run-jest.mjs --runInBand --runTestsByPath \
  src/__tests__/adr-002-guard-policy-replay.test.ts \
  src/__tests__/adr-002-effect-fixtures.test.ts \
  src/__tests__/adr-002-round3-harness.test.ts \
  src/__tests__/adr-002-round4-harness.test.ts \
  src/__tests__/adr-002-round5-harness.test.ts \
  src/__tests__/adr-002-round6-harness.test.ts \
  src/__tests__/adr-002-preregistration-590.test.ts
```

These suites DO execute the committed fixtures in throwaway sandboxes (that is
how the witness and containment properties are proven); they do not build
`dist/`, do not run the product suite, and never execute an unregistered
fixture.

No product code is touched by this harness.
