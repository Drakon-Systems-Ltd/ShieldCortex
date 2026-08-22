# A/B residuals after C merge — superseded in part by 2026-08-22 fold

**Date:** 2026-08-18 · Epic #347  
**Fold:** 2026-08-22 — for Track A remaining work, **`2026-08-22-memory-sota-track-a-residual.md` is authoritative.**

## A-min (done on #352 / #381)

- empty-brain doctor
- plane policy doc (see folded `2026-08-17-memory-plane-policy-amin.md`)
- inject pack library + session-start wiring
- signed `--memory-inject-contract`

## B residuals (host work, not more library)

1. **TARS:** inject contract already set (`sc_only`, hostId=tars). **Still required:** prove native is actually off the bus (paper contract risk — #348 T1).
2. **OpenClaw hosts (CASE):** set when ready via **signed CLI**, not hand-edit:

```bash
shieldcortex config --memory-inject-contract sc_only
# plus hostId/agentId via supported signed config path when available
```

Illustrative shape (do not hand-edit signed config as the happy path):

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

## Track A residuals (open — #348)

Do **not** treat A-min as Track A complete. Full residual plan, Opus blockers (B1–B4), and tickets T1–T3:

→ **`docs/design/2026-08-22-memory-sota-track-a-residual.md`**

Minimum open set:

- [ ] Host contract enforcement proof (native off bus)
- [ ] `memory.plane` signed CLI + enum teeth + `planeSetAt`
- [ ] Dual-plane drift doctor (≠ empty-brain)
- [ ] Attestation ≠ trust harden + scope gate not data-derived
- [ ] Position on GuardedMemoryBridge / Markdown SoT side-car APIs
- [ ] Defended import-once (A3) after the above

## Out of this residual

- A2 multi-master
- coexist_dedup
- turn-by-turn inject default
- False close of #348
