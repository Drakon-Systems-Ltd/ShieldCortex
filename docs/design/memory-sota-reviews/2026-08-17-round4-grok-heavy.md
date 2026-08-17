### VERDICT
APPROVE_WITH_NITS

### BLOCKERS
none

### NITS
1. Parent §0–§15 / §13 still show open cut-menu, pack `why`, A2-as-option, absolute single-plane wording. Freeze surface already wins; SUPERSEDED scrub before first B PR remains mandatory hygiene (R3), not optional polish.
2. “A-min parallel with B” is slightly loose: host-contract choice (`disable_native_inject` | `sc_only`), inject scope keys, and provenance needed for eligibility are **B-gating**; plane one-pager / drift doctor / plane flag can stay true-parallel. State that split once so ∥ is not read as “B can ship inject without contract.”
3. Rehydrate may shrink the pinned pack when live eligibility drops → host `extraSystemPromptHash` can change mid-session; host-contract note should say “expected, not session reset.”
4. `project` (and missing-project deny) semantics are still thin — A-min policy one-pager must define per-host project key and deny-by-default when absent (no implicit global).
5. Trust floor enums “align at first B PR” is fine; add freeze gloss: map to existing SC trust types only — no parallel enum.
6. Empty-brain doctor `N days` has no default band (e.g. 7d) — pick a coded default at A-min/B doctor spike.
7. Post-C `memory.capture=distill` “when provider configured” needs a one-line definition of configured (else unset behavior races with legacy regex).
8. Hermes row still “if any” — A-min host table should be explicit (`sc_only` / `disable_native_inject` / `mcp_sidecar_no_inject`) so parity is not forgotten.
9. §11 metrics still not cleanly split product SLOs vs D honesty (R1-9); cosmetic but grep-risky.

### FIRST CUT
Confirm: prelude empty-brain RCA (no feature code) → B (start-only inject v2 + hash-ring/rehydrate law + host contract on critical path) → C (distill fail-closed); A-min parallel with B (B-gating subset first); D LongMemEval-S harness parallel, non-gating. Defer A2, coexist_dedup, turn inject default, Full P0, fleet shared brain, RRF-as-product-gate, custom embedders.

### ONE-LINE SUMMARY
Freeze surface is coherent and prior blockers are folded — approve with nits; lift coding freeze only after dual-lane clear + Michael cut pick + RCA prelude, with parent superseded text scrubbed before first B PR.
