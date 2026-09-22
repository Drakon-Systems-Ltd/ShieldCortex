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
> that pass static validation (exact trusted text, no absolute paths, targets
> inside the sandbox root); an outside-repo canary fails the whole run if any
> host git repo is touched.

## Half A — logged-signal policy comparison

`scripts/guard-policy-replay.mjs` (Node core only)

```
node scripts/guard-policy-replay.mjs <denials.jsonl> [--json out.json] [--md out.md] [--quiet]
```

Reads an Action Guard `denials.jsonl` and, **on the logged signal names only**,
reports what each of three policies would gate vs demote to audit-only:

1. **current tiers** — catastrophic block + dangerous approve (baseline; a
   denials log only holds events these stopped).
2. **destruction-only floor** — ADR-002 §3 as written (root/home recursive
   delete, fork bomb, block-device raw write, filesystem format/partition).
3. **broad floor** — destruction + credential/secret egress + persistence sinks
   + security-config writes (the #556 counter-proposal).

It is **not** a classifier replay (the log does not store the command) and
**not** an effect measurement. Rows whose signals cannot be reconstructed
(`redacted-signal`, empty) are bucketed *unknown* and excluded from every
percentage. It fixes the four defects of the ad-hoc script behind #555's numbers
(hand-picked signal set; `pipe-download-to-shell` omitted; malformed rows
silently skipped; last-record-wins per `actionId`).

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

The sandbox root is `realpathSync`'d, and every target is resolved with
`confinedPath`, which refuses any path lexically outside the root **or** whose
parent chain contains a symlink (an `lstat` walk, no realpath-and-fall-back).
An **outside-repo canary** — a disposable victim git repo with a known config —
is hashed before and after **every** execution; any change marks the whole run
INVALID and exits non-zero.

Execution is limited to fixtures that pass `validateFixture` (exact text, no
absolute paths, targets inside the root). Absolute-root and block-device shapes
that cannot be confined (`destruct-root`, `destruct-format`,
`destruct-raw-write`) are **model-only**: never executed, their decision
reported in a **separate** modelled bucket, never blended with executed rates.

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

## Tests

```
env HOME="$(mktemp -d)" PATH="/usr/bin:/bin:$(dirname "$(command -v node)")" \
  SHIELDCORTEX_SKIP_TEST_BUILD=1 node scripts/run-jest.mjs --runInBand --runTestsByPath \
  src/__tests__/adr-002-guard-policy-replay.test.ts \
  src/__tests__/adr-002-effect-fixtures.test.ts
```

No product code is touched by this harness.
