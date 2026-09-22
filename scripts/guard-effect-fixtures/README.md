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
per event (actually stopped / warned only / retry granted / other) and the
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

- **malformed events** — any event holding a malformed JSON row: no outcome, a
  non-string `event`, a declared denial or warning with no `signals`, a
  non-array or non-string signal member, a non-string notify status or a
  non-string channel. A malformed JSON row is **retained** as a record of its
  event (same `actionId` / `correlationId`, else its own line) — never
  discarded before grouping — and nothing else is read from it. Row-level
  malformed counts (which also cover not-JSON / not-object lines) are reported
  alongside;
- **contradictory events** — event/outcome pair disagrees; conflicting
  enforcement outcomes across an event's decision records; a `delivered`
  status with no channel (a whitespace `deliveredVia` is not a channel);
- **unknown events** — redacted or empty signals, retry-only lifecycles, an
  outcome outside the writer's enum, any signal outside the writer's
  vocabulary, or **stray signals** carried on a retry or unknown-outcome row;
- **known events** — everything else.

Only **validated enforcement signals** (denial / warning rows that passed their
contract) form an event's signal set; a signal on a retry row or an
unknown-outcome row is counted as stray and never reaches a tier or floor match.

**Three lifecycles per event (round 4).** Each `actionId` carries three
independent observations, each with its own final state:

- **enforcement** — the last *decision* row (`auto_denied`,
  `denied_no_prompt_surface`, `warned`, …, or `none`). The writer re-emits the
  same denial with its final notify status once delivery settles; a row with
  the same event, outcome and signal set as an earlier decision is that
  *notify copy*, never a new decision;
- **retry / revocation** — `none` / `granted` / `denied` / `failed` /
  `revoked` from the retry rows alone. `revoked` is reserved: the current writer
  records a revocation only inside `reason` text, which the replay never reads;
- **notification** — `none` / `delivered` / `failed` / `suppressed` / `unknown`
  from the last row that *carries* a notify object (a retry row does not reset
  it), plus `anyValidatedDelivery` across all rows.

"Actually stopped" = the enforcement lifecycle ended in a stop outcome **and**
the retry lifecycle did not end in a grant. A *validated delivery* is a
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
- Known, undisclosed-by-default limitations: the evaluator id does not bind a
  dist/source hash; the expected corpus counts are hardcoded; `diff(before,
  after)` does not exclude the fixture's own target, so an intended mutation
  is also listed as collateral; `failure_allowed` events fall into the
  warned-only bucket. Resolve or disclose before any decision-grade use.

## Tests

```
env HOME="$(mktemp -d)" PATH="/usr/bin:/bin:$(dirname "$(command -v node)")" \
  SHIELDCORTEX_SKIP_TEST_BUILD=1 node scripts/run-jest.mjs --runInBand --runTestsByPath \
  src/__tests__/adr-002-guard-policy-replay.test.ts \
  src/__tests__/adr-002-effect-fixtures.test.ts \
  src/__tests__/adr-002-round3-harness.test.ts
```

These suites DO execute the committed fixtures in throwaway sandboxes (that is
how the witness and containment properties are proven); they do not build
`dist/`, do not run the product suite, and never execute an unregistered
fixture.

No product code is touched by this harness.
