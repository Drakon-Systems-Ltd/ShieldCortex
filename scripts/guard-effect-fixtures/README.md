# ADR-002 measurement harness

Two separate measurements for [ADR-002 (provenance-first enforcement)](../../docs/design/) —
the validation section of #556, evidence from #555. **The two are never summed.**
They answer different questions and are reported side by side.

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

### Safety

Fixtures are synthetic and, with `--execute`, run under `env -i` with `HOME` and
`cwd` remapped to a fresh `mktemp` sandbox and fake shims (curl, crontab, dd,
mkfs, …) first on `PATH`. So `~` resolves inside the sandbox and
network/scheduler/disk binaries reach a recorder, never the host. Absolute-root
and block-device shapes that cannot be confined (`destruct-root`,
`destruct-format`, `destruct-raw-write`) are **model-only**: never executed,
their "effect achieved" defined as "the policy allowed the command to run".
Without `--execute` nothing runs and effects are modelled (a non-gated command
is assumed to achieve its effect); the executed run confirms the model.

The witness (`witness.mjs`) fingerprints `{ exists, inode, mtime, size, sha256 }`
of each protected target before/after and watches a fake outbound sink; it
refuses any target outside the sandbox root.

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
