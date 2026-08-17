### VERDICT
CHANGES_REQUESTED

### BLOCKERS
1. Compact rehydrate is underspecified on **live eligibility**: R2-2 allows re-inject of pinned start-pack content hashes after compact/prompt-reset, but does not require a re-check that those rows are still admitted (not forgotten, quarantine, RESTRICTED, trust-dropped, or scope-moved). Hash replay without a live gate can resurrect revoked memory into the prompt bus.

2. Compact rehydrate vs **session cumulative budget / hash-ring accounting** is undefined. Coding hosts compact often; “re-inject pinned hashes” with no rule for cumulative tokens (1500/2000), whether rehydrate is budget-neutral, and whether hash-ring suppress still applies, re-opens a multi-compact 40×-class failure mode — the exact disaster Inject v2 exists to prevent.

3. Host native-inject contract still has a hole: `coexist_dedup` is a first-class P0 option (R2-3) with **no algorithm** (what counts as dup: hash, normalized text, source_id; who wins; does native stay in system prompt). That is enough rope to ship dual-bus again. P0 must either drop `coexist_dedup` or specify it; bound OC/Claude defaults should be normative (`sc_only` or `disable_native_inject` only), not soft recommendation.

### NITS
1. Dual authority is declared (appendix/§16 win) but parent §6 still shows pack fields with `why` and pre-fold deliverables. Collapse/strike conflicting body text before coding so implementers cannot grep the wrong schema.

2. `memory.plane=dual_legacy` still reads like a supported product mode in §5; mark it deprecated/time-boxed migration escape, consistent with “dual-plane = defect.”

3. Start-pack selection under pressure: pin-first vs rank-only when over row/token budget is unspecified; define pin priority + stable exclusion.

4. P0 exact-hash dedup only: paraphrase/salience stuffing can still fill top-k (listed adversarially, not mitigated). Accept as known P0 limit or add a cheap diversity/source cap.

5. Empty-brain doctor: define N (days), and whether “only low-trust junk admitted” is warn vs fail (green-wash case is named but not normative).

6. Trust floor “medium | source_attested” left to impl spike — publish enum + default floor in A-min one-pager before B lands.

7. Hermes host contract remains “if any”; A-min table should explicitly say unsupported / MCP-only limitations rather than implied parity.

8. Title is still model-visible and instruction-shaped; cap length and keep envelope language explicit that title+fact are untrusted data.

9. §8 “ranker PR must show LME delta” mildly tensions D-as-non-gating; rephrase as honesty artifact, not merge gate for B/C.

10. Capture path when scope keys missing (host/agent/project) is clear for inject (deny) but not for L1/L2 writes — fail closed consistently.

### FIRST CUT
Confirm appendix order: **Prelude empty-brain RCA (no feature code) → B start-only inject v2 (ceilings, scope, hash ring, compact rehydrate once specified, host contract) → C distill fail-closed; A-min parallel with B; D harness parallel non-gating.** Defer A2, turn inject, full import (A-min+), A1 projections until B+C prove value, fleet shared brain, RRF-as-product-gate, custom embedders.

### ONE-LINE SUMMARY
Program direction and cut are right, but freeze cannot lift until rehydrate eligibility + multi-compact budget semantics and a non-hand-wavy native-bus contract are nailed as design law.
