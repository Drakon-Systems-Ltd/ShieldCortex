# P1 — Write-pipeline hot-path performance budget

Phase-1 definition-of-done item: *"Hot-path performance budget for the write
pipeline documented and measured."* This is that document.

## What the hot path is

Every durable memory write goes through `runDefencePipeline(content, title,
source)` **synchronously** before `store.ts:addMemory` inserts the row — the
6 sync layers (input sanitisation, pattern detection, structural, behavioural,
credential-leak) plus source trust scoring. The **semantic** layer is *not* on
this path: it runs only on the async / deep-scan path
(`runDefencePipelineWithVerify`), so the write hot path stays regex/heuristic
only and CPU-bound with no model load.

## Measured baseline (2026-07-20, v4.47.10 line, Apple Silicon, 2000 iterations/payload after warm-up)

| Payload | Length | mean | p50 | p95 | p99 |
|---|---|---|---|---|---|
| short note | 51 B | 0.145 ms | 0.114 ms | 0.225 ms | 0.79 ms |
| typical decision | 156 B | 0.150 ms | 0.122 ms | 0.223 ms | 0.43 ms |
| long doc | 1.76 KB | 0.490 ms | 0.448 ms | 0.649 ms | 1.62 ms |

The pipeline is **sub-millisecond** for typical content and scales roughly
linearly with length (the ReDoS-bounded patterns are the dominant cost). P1's
provenance work (WS3) adds one `defence_verdict` bind + a `BEFORE INSERT`
trigger that evaluates three `IS NULL` checks — nanosecond-scale, below the
measurement floor.

## Budget (ceiling)

For content up to **2 KB** (the 99th-percentile real write; larger content is
truncated to 10 KB by the anti-bloat cap and separately flagged `oversized`):

- **p95 ≤ 5 ms** — ~20× headroom over today's 0.22 ms, so a genuine regression
  is caught while normal variance is not.
- **mean ≤ 2 ms**.

Rationale for the ceiling, not a tighter one: the write path runs once per
`remember`/auto-capture, off any user-interactive loop (the OpenClaw fast loop
uses the async recall path, not this write path), so single-digit-ms is
imperceptible; a tight sub-ms CI gate would flake on shared runners.

## How it's enforced

- The measurement harness (`scratchpad/perf-measure.mjs` shape) can be run
  ad-hoc against `dist/defence/pipeline.js`.
- The standing guardrails that keep the path fast are the **ReDoS budgets**
  already in CI: `guard-bypasses-4475` and the residual-evasion timing tests
  cap individual patterns (<300 ms on 30 KB adversarial input), and the guard's
  4 KB fallback/oversize caps bound worst-case scanning. A pattern that blew the
  hot-path budget would first trip those ReDoS timing tests.
- The semantic/model cost is kept off this path by construction (async-only);
  regressing that (moving a model load onto the sync path) would be caught by
  the `scan-only-entry` import-graph test, which asserts the light write/scan
  entry pulls in no native/ML/DB/cloud modules.

## Revisit triggers

Re-measure and re-baseline if: a new synchronous layer is added to
`runDefencePipeline`; the semantic layer is moved onto the sync path; or the
anti-bloat content cap changes materially.
