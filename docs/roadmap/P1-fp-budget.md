# P1 — False-positive budget for the newly-enforcing tiers

Phase-1 definition-of-done item: *"A documented false-positive budget for the
newly-enforcing tiers."* This is that document.

P1 moved two paths from advisory to enforced-by-default. Enforcement that
over-fires is a real cost, so each tier ships with (a) a recoverable or
opt-down escape hatch and (b) a CI-enforced regression bed that turns "no
false-positive regression" into a build gate rather than a hope.

## Tier 1 — Action Guard `dangerous` (WS1, enforce-by-default)

**FP shape:** a legitimate dangerous-looking op is gated when it shouldn't be
(a quoted command in a doc, a `web_fetch` URL that mentions `rm`, `git commit
-m "remove the rm call"`).

**Escape hatches (opt-down, never silent-allow):**
- `actionGuard.enforce: false` → advisory (warn, no gate). Catastrophic still blocks.
- `actionGuard.autoApprove: [...]` → per-operation allowlist for unattended agents.
- `failurePolicy` → per-severity verdict when a decision can't be obtained.
- Attended surfaces get an approval prompt; only headless + no-approver fails closed.

**Budget = the must-ALLOW fixtures.** The FP rate is held at zero *against a
curated corpus* by the regression suites, each of which pairs every must-BLOCK
case with a must-ALLOW sibling; a new over-block flips a fixture and fails CI:
- `fp-tune-71-73`, `fp-precision-88-89`, `guard-tune-91-89` — field-reported FP classes.
- `span-classifier-84` — the general mention-vs-intent model (quoted data / URL
  spans are not intent); this is the structural FP-reducer that replaced the
  per-incident carve-outs.
- `guard-bypasses-4475` must-still-allow siblings.

**Ceiling:** zero must-ALLOW fixture may flip. New field FPs are added to the
corpus with their fix in the same PR (the standing pattern across #71–#96).
There is no numeric production-rate target yet — the corpus is the proxy; a
telemetry-based rate is the natural follow-on (audit-mined allowlist, #84 rec #5).

## Tier 2 — Memory write quarantine (WS3/WS4, block/quarantine-by-default)

**FP shape:** a benign memory is held (quarantined) instead of stored — e.g. a
legitimate note that trips a pattern, or a sub-agent write in the 0.5–0.7 trust
band held for parent approval.

**Why the FP cost is bounded — holds are RECOVERABLE, not lost:**
- A false quarantine is **reviewable and re-admittable**: approving a held
  QUARANTINE item re-enters the sanctioned funnel (`addMemory`) and re-scans,
  so an approved item is stored with a real verdict. Nothing benign is
  destroyed — the write-path FP is a review-queue item, not data loss.
- A BLOCK is held (WS4) rather than dropped, so even a hard-blocked
  false-positive is forensically recoverable at review (auto-rejected by
  default so poison isn't laundered, but visible).
- The sub-agent trust band is the only *new* auto-hold; it is deliberately
  narrow (0.5–0.7) and single-sourced (`resolveDisposition`) so both runtimes
  apply it identically.

**Budget:** the group-A proof suite (`claims-proof` claims 1, 1a) pins that
benign writes store with real provenance and only poisoning/low-trust writes are
held — across *both* runtimes. A regression that started holding benign content
would flip claim 1's store assertion. Quarantine has a 7-day auto-expire so a
mistaken hold self-clears if never reviewed.

## Summary

| Tier | Enforced default | Opt-down / recovery | FP gate |
|---|---|---|---|
| Action Guard `dangerous` | require-approval / fail-closed unattended | `enforce:false`, `autoApprove`, `failurePolicy` | must-ALLOW fixtures (zero flips) |
| Memory write | hold (quarantine) high-confidence poison + sub-agent band | review→re-admit; 7-day auto-expire | `claims-proof` group A |
