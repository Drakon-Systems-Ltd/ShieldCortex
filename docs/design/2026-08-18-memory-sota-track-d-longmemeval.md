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
