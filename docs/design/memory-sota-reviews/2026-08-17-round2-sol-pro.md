### VERDICT
CHANGES_REQUESTED

### BLOCKERS
1. Dual authority: §5–§7, §9, §13 still contradict §16 (pack still has instruction-shaped `why`/`title`; plane still “choose A1/A2/A3”; cut menu pre-consensus). Freeze needs one normative surface — either rewrite those sections to match §16 or an explicit “§16 wins on conflict” banner plus corrected deliverable/acceptance bullets in the track sections implementers will copy.

2. Track B session-start selection seed is unspecified. Hybrid top-k needs a query or a non-query policy (e.g. scope-bound pins + salience/recency working set, stable sort already named). Without this, B defaults to dump-shaped “best memories” and re-opens bootstrap/risk ambiguity.

3. A-min scope disagrees inside §16: §16.4 P0 ship includes defended import path; §16.6 A-min is policy + doctor drift + plane flag + provenance only. Pick one cut boundary (recommend: A-min = policy/flag/provenance/doctor drift + host-contract notes; defended import-once as A-min+ or immediate follow, not silent scope creep).

4. Cut-time security knobs for B still open as rules, not vibes: inject trust-floor (numeric or enum), and what “RESTRICTED unless session cleared” means (who clears, persistence, audit). Same class of hole R1-2 fixed for token caps.

### NITS
1. Default post-C `memory.capture` (`regex` vs `distill`) not chosen; say default + doctor posture when unset.
2. MCP `get_context` has adversarial “dump” but no budget/hash parity with inject packs — side-car honesty gap.
3. Provenance backfill for pre-existing rows (null vs `source_kind=legacy_unknown`) unspecified.
4. L1 salience cap “proposal ≤0.7” should be normative or explicitly cut-time.
5. §3 “single plane” vs dual_legacy flag still reads absolute; one sentence that dual_legacy is temporary defect mode would align thesis with flags.
6. Host-contract appendix (OC/Claude/Hermes: stop writing what, which hooks own capture/inject) is required by R1-7 but not a checklist deliverable under A-min.
7. Re-enable criteria for OC `agent:bootstrap` should be a named gate (adversarial suite green + start-only + hash ring) not only “carefully.”
8. Metric “>0 memories / 7d” can green-wash junk; tie to non-quarantine + capture_layer/quality bar already hinted in adversarial doctor case.

### RESIDUAL RISKS
- RCA prelude finds intake/defence FP/host-aim breakage: B+C polish an empty or hostile path until a non-feature intake fix lands (prelude correctly blocks assumption, not the calendar).
- Start-only + session-end distill means facts appear next session — UX still loses to always-on native until turn inject (deferred) or mid-session L2 pins.
- Exact-hash dedup only: paraphrase 40× and salience stuffing remain until near-dup/rank defences (listed, not designed).
- Deny-by-default scope fails closed to “no inject” if host_id/agent_id/project missing — correct, but looks like empty brain; doctor must distinguish mis-scope vs empty store.
- Distill confused-deputy / billing footguns if host OAuth route is broader than intended; fail-closed matrix helps, provider allowlist still implementer-dependent.
- D parallel can still drag attention into RAG gravity despite §16.6/§16.8; keep D non-gating in issue templates and CI.
- A3-leaning without import in the same cut leaves dual-plane doctor noisy and native SoT intact — security-theatre residual until import or write-target decision (R1-10) lands.
- Shared DB historical rows lacking scope keys: migration/defaulting errors → cross-agent spray or mass deny.

### FIRST CUT
Confirm: RCA prelude (no feature code) → B (start-only inject v2) → C (distill fail-closed), A-min in parallel with B, D harness parallel non-gating. Defer A2, turn inject, Full P0, fleet shared brain, RRF-as-product-gate. Do not start B implementation until blockers 1–4 are folded into the normative text (not only another review appendix).

### ONE-LINE SUMMARY
§16 absorbed the Round-1 security/product holes, but freeze should not lift until body/§16 are single-sourced, session-start pack selection and A-min/import boundaries are pinned, and B trust/RESTRICTED rules are as hard as the token ceilings.
