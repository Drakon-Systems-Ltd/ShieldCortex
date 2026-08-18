# Track D — LongMemEval-S honesty harness (kickoff)

**Date:** 2026-08-18  
**Epic:** #347 · Issue: #351  
**Status:** kickoff (not a SOTA-ready gate)

## Goal

Publish an **honest** retrieval scorecard against LongMemEval-S (or a
statistically labeled subset). Numbers are **proof of measurement**, not a
claim that SC is Memory-SOTA.

Normative freeze: `docs/design/2026-08-17-memory-sota-program-r2-appendix.md`
— LME-S is anti-RAG-gravity / honesty, not the conjunction for "ready".

## Already in repo

| Asset | Role |
|---|---|
| `benchmark/longmemeval/` | harness (load/ingest/run/score) |
| `npm run bench:smoke` | toy fixture E2E |
| `SCORECARD.md` | auto-rendered; currently **toy only** |
| agentmemory 95.2% line | **reference only**, not comparable |

## Deliverables (this track)

1. **Dataset acquisition path** (not redistributed): documented command +
   private cache location under `~/.shieldcortex/benchmark/` or CI secret mount.
2. **Convertor** from upstream LongMemEval format → harness JSONL (`types.ts`).
3. **Full (or labeled subset) run** producing:
   - `SCORECARD.md` with caveats updated (toy vs full)
   - `report.json` artifact
4. **CI workflow (non-gating)** optional nightly / release artifact upload.
5. **Epic comment** with numbers + explicit non-claims.

## Non-goals

- Do not gate merges on R@5.
- Do not remove defence/plane/capture product gates in favour of R@k.
- Do not compare toy % to agentmemory full-corpus %.

## First executable steps

```bash
# 1) smoke (always)
npm run bench:smoke

# 2) obtain upstream dataset (operator machine; license-respecting)
#    see https://github.com/xiaowu0162/LongMemEval
# 3) convert → ~/.shieldcortex/benchmark/longmemeval-s.jsonl
# 4) npm run bench -- --dataset ~/.shieldcortex/benchmark/longmemeval-s.jsonl
```

## Exit criteria for "D done enough"

- [ ] Smoke green on main
- [ ] Convertor + documented fetch path
- [ ] At least one full or statistically labeled run checked into SCORECARD
      with honest headers
- [ ] #351 updated; epic #347 notes D status

## Parallelism

D runs **after** C merge is fine; does not block host enablement or A/B
contract work.


## First measured run (TARS, 2026-08-18)

| Field | Value |
|---|---|
| Dataset | LongMemEval-S **labeled subset-50** (seed=42) from `longmemeval_s_cleaned` HF |
| Convert | `convert-upstream.ts --limit 50 --seed 42` |
| Embeddings | **OFF** (`SHIELDCORTEX_SKIP_EMBEDDINGS=1`) |
| Defence | **ON** (blocked turns skipped) |
| Engines | rrf, legacy |

### Headline (subset-50, no embeddings)

| Engine | R@5 | R@10 | MRR | Duration |
|---|---|---|---|---|
| rrf | **4.00%** | 4.00% | 0.0400 | ~101s |
| legacy | **0.00%** | 0.00% | 0.0000 | ~100s |

### What this means (honesty)

- **Not** a full-S number. **Not** comparable to agentmemory 95.2%.
- Without embeddings, retrieval is FTS-only over large multi-session haystacks — weak by design.
- Defence-on ingest means some gold turns never enter the store (product-honest).
- Value of this run: harness + convert + fetch path **proven end-to-end** on real upstream data.
- Next measurement upgrade: subset-50 **with** embeddings, then optional full-500 (still non-gating).

Artifacts (host-local, not in git):
`~/.shieldcortex/benchmark/longmemeval/runs/subset50/{SCORECARD.md,report.json}`
