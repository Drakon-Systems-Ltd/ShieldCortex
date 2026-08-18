# A/B residuals after C merge

**Date:** 2026-08-18 · Epic #347

## A-min (done on #352)
- empty-brain doctor
- plane policy doc
- inject pack library + session-start wiring

## B residuals (host work, not more library)
1. **TARS:** inject contract already set (`sc_only`, hostId=tars).
2. **OpenClaw hosts (CASE):** set when ready:
```json
{
  "memory": {
    "inject": {
      "mode": "start",
      "nativeContract": "sc_only",
      "hostId": "case",
      "agentId": "openclaw-primary"
    }
  }
}
```
3. Prove one session: capture → rows → next session inject pack ≤ budget.
4. Do **not** enable inject without `nativeContract` (doctor fails).

## Out of this residual
- A2 multi-master
- coexist_dedup
- turn-by-turn inject default
