### VERDICT
CHANGES_REQUESTED

### BLOCKERS
1. Normative clash inside the freeze layer: §16.2 hash-ring says never re-inject identical content for the whole session, while R2-2 requires post-compact/prompt-reset rehydrate of pinned start-pack hashes. Write one rule that wins: hash-ring suppresses duplicates except rehydrate of session-pinned start-pack hashes after compact/reset; first inject charges cumulative unique budget once; rehydrate does not re-charge and must not rewrite preamble identity (stable `extraSystemPromptHash`).

### NITS
1. Parent §6/§9/§13 still show live pack `why`, open cut menu, and open plane pick; appendix says it overrides, but linear readers will re-litigate. Stamp those sections SUPERSEDED or scrub before coding.
2. Host-contract (`sc_only` / `disable_native_inject`) is on the B critical path, not optional A-min parallel work; say B cannot default-on without a recorded per-host choice.
3. Lock trust floor enum (`medium`, `source_attested`, etc.) in the design pack before B merge; “align at impl spike” invites cross-PR drift.
4. Empty-brain doctor acceptance should cover green-wash: bound + auto-on + only quarantine/junk/below-floor rows is fail, not “has rows.”
5. Start-pack assembly: state whether pins are reserved slots or just rank inputs, and that budget trim always runs after rank (pin stuffing).
6. `chars/4` token accounting: document CJK/undercount as known P0 limit; hard char cap stays authoritative.
7. Michael still must record native-writable + cut pick at freeze; modes exist, decision does not.

### FIRST CUT
Confirm appendix order: empty-brain RCA prelude (no feature code) → B start-only inject v2 (ceilings, scope deny-by-default, compact rehydrate, host contract) → C fail-closed distill; A-min in parallel with B (policy, plane flag, drift/empty-brain doctor, provenance, host-contract table); D LongMemEval-S harness parallel and non-gating. Defer A2, turn inject default, full import product, fleet shared brain, RRF-as-product-gate.

### ONE-LINE SUMMARY
Design is almost freeze-ready after R1/R2 folds, but coding must not start until hash-ring vs compact-rehydrate vs cumulative budget is one explicit normative rule.
