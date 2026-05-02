# Review Copilot Runtime Spike

Date: 2026-04-30

## Scope

Validate the first local Review Copilot runtime candidate:

- Model: `onnx-community/Qwen2.5-0.5B-Instruct`
- Runtime: `@huggingface/transformers` in a Node worker thread
- Cache: `~/.shieldcortex/models/review-copilot`
- Worker heap: 2048 MB
- Warm inference timeout: 10000 ms

This spike used local-only synthetic quarantine samples. No raw content was sent to a cloud service.

## Findings

The built `dist/` worker path works after forcing worker threads to start with clean `execArgv`. Without that, a parent process launched with flags such as `--input-type=module` can poison the worker startup.

Small runtime check, 10 representative inputs:

- Schema-valid annotations: 9/10
- p95 latency: 9299 ms
- Process RSS after model load/run: about 1853 MB
- Content egress: none

The runtime is therefore close to the configured limits, but the model quality is not strong enough to mark this candidate fully validated.

## 50-Item Validation Pass: Model-Owned Decision

Run date: 2026-04-30

Corpus:

- 10 prompt-injection samples
- 8 exfiltration samples
- 8 credential-leak samples
- 3 scope-escalation samples
- 3 persistence samples
- 6 documentation/example samples
- 12 benign operational notes

Scoring:

- `schemaValid`: model output parsed and passed the strict annotation schema without fallback.
- `judgementPass`: schema-valid plus expected category family, expected action family, and no risky `approve`.
- Risky samples were allowed to suggest `reject`, `keep_quarantined`, or `create_rule`.
- Benign/documentation samples were allowed to suggest `approve` or `keep_quarantined`, but not `reject`.

Results:

- Samples: 50
- Schema-valid annotations: 44/50 = 88 percent
- Judgement pass: 18/50 = 36 percent
- Category pass: 19/50
- Action pass: 27/50
- Risky approvals: 0
- p50 latency: 5582 ms
- p95 latency: 10048 ms
- Max latency: 10064 ms
- Total duration: 317183 ms
- RSS before: about 52 MB
- RSS after: about 1458 MB
- Telemetry lines: 12, all metadata/failure events

By category:

| Label | Count | Schema-valid | Judgement pass | Risky approvals |
|---|---:|---:|---:|---:|
| prompt-injection | 10 | 10 | 10 | 0 |
| exfiltration | 8 | 6 | 2 | 0 |
| credential | 8 | 5 | 0 | 0 |
| scope | 3 | 3 | 3 | 0 |
| persistence | 3 | 3 | 3 | 0 |
| documentation | 6 | 6 | 0 | 0 |
| benign | 12 | 11 | 0 | 0 |

Full run artifact: `/tmp/review-copilot-validation-50.json`

The 50-item pass fails the planned release criteria. Schema validity is below the 90 percent target and quality is poor outside obvious prompt-injection/scope/persistence cases. The model is conservative on risky content after safety normalisation, but it over-classifies benign notes, documentation examples, credentials, and exfiltration as `prompt_injection`, often with `reject`.

## 50-Item Validation Pass: Deterministic Decision + Model Text

Run date: 2026-04-30

Architecture change:

- Existing ShieldCortex deterministic scanners decide `category`, `suggestedAction`, and `confidence`.
- Review Copilot's local model only writes reviewer-facing text: `summary`, `evidence`, `reasoning`, and optional grouping text.
- If the model emits `category`, `suggestedAction`, or `confidence`, those fields are ignored.
- If the model fails or times out, ShieldCortex still creates a deterministic annotation with local fallback text.

Results on the same 50-item corpus:

- Samples: 50
- Persisted annotations: 50/50 = 100 percent
- Judgement pass: 50/50 = 100 percent
- Category pass: 50/50
- Action pass: 50/50
- Risky approvals: 0
- p50 latency: 4246 ms
- p95 latency: 7807 ms
- Max latency: 8973 ms
- Total duration: 235638 ms
- RSS before: about 52 MB
- RSS after: about 1596 MB
- Telemetry lines: 0

By category:

| Label | Count | Persisted annotation | Judgement pass | Risky approvals |
|---|---:|---:|---:|---:|
| prompt-injection | 10 | 10 | 10 | 0 |
| exfiltration | 8 | 8 | 8 | 0 |
| credential | 8 | 8 | 8 | 0 |
| scope | 3 | 3 | 3 | 0 |
| persistence | 3 | 3 | 3 | 0 |
| documentation | 6 | 6 | 6 | 0 |
| benign | 12 | 12 | 12 | 0 |

Full run artifact: `/tmp/review-copilot-validation-50-deterministic.json`

This pass meets the runtime and safety criteria for read-only Review Copilot annotations. The model's generated text is still imperfect and sometimes generic, so it should remain advisory copy only. Security decisions must stay deterministic.

Observed quality issues:

- Benign operational notes were frequently classified as `prompt_injection`.
- A malicious self-approval sample produced `suggestedAction: "approve"` before deterministic safety normalisation.
- A more conservative prompt variant dropped schema validity to 0/10, so it was not kept.

Mitigation added:

- Fallback annotations now carry `synthetic: true`, so they are not filtered by brittle summary text.
- `approve` suggestions are deterministically downgraded to `keep_quarantined` when the category is not clearly benign or the content contains obvious risky approval/exfiltration/secret markers.
- Model output no longer owns `category`, `suggestedAction`, or `confidence`.
- Model output remains read-only enrichment and never changes quarantine status.

## Decision

The model-owned-decision design failed and should not ship.

The deterministic-decision design passes the 50-item validation for a read-only paid Review Copilot feature. Ship with this boundary:

1. Existing ShieldCortex scanners decide category/action/confidence.
2. The local model only assists with review text and grouping.
3. Operator decisions remain manual.

Do not use this model output for automatic approval, rejection, expiry, memory promotion, or policy activation.
