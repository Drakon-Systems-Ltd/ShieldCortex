# LongMemEval-S benchmark harness

Measures ShieldCortex's retrieval quality (R@5, R@10, MRR) on the public
[LongMemEval-S](https://arxiv.org/abs/2410.10813) dataset (Wu et al.,
ICLR 2025) — 500 questions across multi-session conversation histories.

## Quick start

```bash
# Smoke test (toy fixture, <1s, no embeddings)
npm run bench:smoke

# Full sweep with embeddings on (requires the dataset file)
npm run bench -- --dataset path/to/longmemeval-s.jsonl

# Just one engine
npm run bench -- --engine rrf
npm run bench -- --engine legacy
```

Output:

- `benchmark/longmemeval/SCORECARD.md` — human-readable comparison
- `benchmark/longmemeval/report.json` — full machine-readable report
  (per-question retrieved sessions, first-hit ranks, durations)

Both files are overwritten on every run.

## Getting the LongMemEval-S dataset

The dataset is published by the LongMemEval authors and is **not
redistributed from this repo** to respect their licensing terms. Get it
from the upstream release:

- Paper: <https://arxiv.org/abs/2410.10813>
- Code & data: <https://github.com/xiaowu0162/LongMemEval>

Convert their format to a JSONL where each line is one question with
the shape documented in `types.ts` (`question_id`, `question`,
`answer_session_ids`, `haystack_sessions`).

## What gets measured

For each question, for each engine (`rrf`, `legacy`):

1. Spin up a fresh in-memory SQLite DB.
2. Ingest every turn of every haystack session as a memory, tagging
   `metadata.session_id` so we can map retrieval back to source.
3. Run `searchMemoriesExplained` for the question text.
4. Map retrieved memory ids → session ids.
5. Score: did any retrieved memory in top-k come from a
   `answer_session_ids` session?

R@k is binary per question (hit/no-hit). MRR is reciprocal of the
first-hit position (or 0 if no hit).

## Honest reporting

Per the v4.15 plan, we publish whatever numbers we get — no
selective reporting. If RRF underperforms legacy on the real dataset,
v4.15 still ships RRF as opt-in (`SHIELDCORTEX_RANKER=rrf`) with
legacy as the default until we tune. The CI workflow uploads
`SCORECARD.md` to the release artifacts so the audit trail is
public-by-default.

## What this is not

- Not a generation benchmark — we measure *retrieval*, not whether the
  agent answered correctly.
- Not a substitute for production telemetry. Real query distributions
  diverge from the academic dataset.
- Not gated CI — the workflow is a transparency tool, not a regression
  gate. Per-PR perf checks belong in the unit-test suite.

## Track D — full / labeled LongMemEval-S (honesty)

Dataset is **not** in git. Fetch the cleaned S release, convert if needed, run:

```bash
# 1) download (HF; ~respect upstream license)
npm run bench:fetch-s
# → ~/.shieldcortex/benchmark/longmemeval/longmemeval_s_cleaned.json

# 2) convert official → harness JSONL (optional if using load.ts upstream support)
npm run bench:convert --   --in ~/.shieldcortex/benchmark/longmemeval/longmemeval_s_cleaned.json   --out ~/.shieldcortex/benchmark/longmemeval/longmemeval-s.jsonl

# labeled subset (deterministic, cite as subset not full-S)
npm run bench:convert --   --in ~/.shieldcortex/benchmark/longmemeval/longmemeval_s_cleaned.json   --out ~/.shieldcortex/benchmark/longmemeval/longmemeval-s-subset50.jsonl   --limit 50 --seed 42

# 3) measure (writes SCORECARD.md + report.json)
npm run bench -- --dataset ~/.shieldcortex/benchmark/longmemeval/longmemeval-s.jsonl
# or embeddings-off smoke-scale:
SHIELDCORTEX_SKIP_EMBEDDINGS=1 npm run bench -- --dataset ~/.shieldcortex/benchmark/longmemeval/longmemeval-s-subset50.jsonl
```

**Honesty rules**

- Toy fixture ≠ LongMemEval-S.
- Subset-50 must be labeled **subset** in SCORECARD / epic comments.
- agentmemory 95.2% is reference-only, different corpus run.
- Not a merge gate.
