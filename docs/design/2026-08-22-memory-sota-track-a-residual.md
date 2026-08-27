# Memory SOTA Track A residual plan — triple-review fold

**Status:** Normative for remaining #348 work  
**Date:** 2026-08-22  
**Parent issue:** #348 (Track A — P0 Bridge) · Epic #347  
**Reviews:** Grok 4.6 + GPT 5.6 SOL Pro + Claude Opus (2026-08-22)  
**Issue comment:** https://github.com/Drakon-Systems-Ltd/ShieldCortex/issues/348#issuecomment-5379236612  
**Supersedes on conflict:** soft wording in `2026-08-18-memory-sota-ab-residuals.md` and any “A-min = Track A done” reading of #352

## Verdict summary

| Reviewer | Verdict |
|---|---|
| Grok 4.6 | APPROVE_WITH_NITS |
| GPT 5.6 SOL Pro | APPROVE_WITH_NITS |
| Claude Opus | REQUEST_CHANGES |

**Consensus:** A-min ≠ Track A done. **Do not close #348.** Remaining work is required. Proceed only under the locks below. Opus blockers must be folded into the plan (this document) before import-product coding.

## What A-min shipped (keep)

- Plane policy one-pager (`2026-08-17-memory-plane-policy-amin.md`)
- Doctor empty-brain / missing-contract checks
- Inject v2 gated on `nativeContract` (`sc_only` \| `disable_native_inject`)
- Signed CLI: `shieldcortex config --memory-inject-contract …` (#381)
- Provenance columns on new writes (`source_kind`, `capture_layer`, `host_id`, `agent_id`)

## What is still dual-plane risk (live defect)

1. **Paper contracts** — config can say `sc_only` while OpenClaw Memory Search / `MEMORY.md` / STM promotion still own the cognitive bus.
2. **No dual-plane drift doctor** — empty-brain ≠ drift; can green-wash when SC has junk/legacy while native is the real brain.
3. **No defended native → SC import product.**
4. **`memory.plane` has no teeth** — stored string, default `dual_legacy`, weak/no enum lock, no signed write path (hand-edit foot-gun).
5. **Attestation ≠ trust hole** — `source_attested` must not bypass inject trust floor for non-pin rows.
6. **Scope gate self-disable** — `requireScope` derived from “no scoped rows exist” is not a gate.
7. **SC side-car APIs** — `ShieldCortexGuardedMemoryBridge` / Markdown backends still document dual-plane “external store + SC audit” doctrine; Track A must take a position.

## Locked residual rules

1. **A-min stays shipped; #348 stays open** until import + drift doctor + host stop-SoT proof land.
2. **A3-leaning only.** A2 / bidirectional multi-master / continuous mirror **forbidden**. `coexist_dedup` **forbidden**.
3. **A1 projections** only after one bound host soaks with SC as the automatic bus — never as a sync substitute in P0.
4. **`sc_only` / `disable_native_inject` are bus laws, not labels.** If native still owns recall or promotion while contract is set → doctor **FAIL**.
5. **Import = full defence chokepoint only** (same pipeline as remember admit path). Never raw INSERT, defence-off flag, scan-only admit, or `updateMemory` overwrite of higher-trust SC.
6. **Native import is not `source_attested`.** Trust from pipeline + ceiling. SC-wins. No LWW merge. No silent overwrite.
7. **Re-import is idempotent skip, not sync.** Session-start must not import. One-shot then archive (or explicit operator re-import under same laws).
8. **`dual_legacy` = deprecated time-boxed defect**, not steady product mode. Target after T1–T3 on a host: `import_only`, then `sc_canonical` when bus law is proven.
9. **Hermes:** honest sidecar (`mcp_sidecar_no_inject`) **or** `sc_only` — never both / never fake canonicity without inject surface.
10. **Turn inject stays off** for this cut. Export/pretty projection out of P0.
11. **Attestation ≠ trust.** `source_attested` records channel identity; must not bypass inject trust floor for non-pin rows.
12. **Deny-by-default scope is config**, not data-derived from an unscoped legacy/shared DB.
13. **SC must not manufacture a second SoT** via library bridges that write only to native MD under `import_only` / `sc_canonical`.

## Opus blockers (fold before import product code)

### B1 — Split attestation from trust *(CRITICAL, small)*

- Stop `source_attested` acting as a trust-floor bypass for non-pin rows in inject eligibility.
- Escape only if: `source_attested AND pinned AND trust >= floor` (or equivalent explicit pin law).
- Clamp import salience ≤ 0.7 at the boundary.
- Do not admit `defence_verdict = 'unverified'` legacy rows into inject packs.
- Tests: import row at trust 0.4 must not appear in start pack; salience 1.0 payload lands ≤ 0.7; never-scanned legacy must not inject.

### B2 — `memory.plane` teeth *(HIGH, small)*

- Signed CLI: `shieldcortex config --memory-plane <sc_canonical|dual_legacy|import_only>` on the same `mutateRawConfig` discipline as inject contract.
- Validate closed enum at write path.
- Reject illegal plane × contract combos (see plane policy doc).
- Persist `planeSetAt` (or equivalent) for time-box / drift escalation.
- Update A-min one-pager: **stop prescribing hand-edits** of signed config.

### B3 — Drift doctor + scope self-disable *(CRITICAL, medium)*

- Implement dual-plane **drift** detector distinct from empty-brain.
- Primary signal: native-artifact recency/growth vs SC durable-admit recency under activity.
- Count “injectable” with real inject eligibility, not a weaker doctor predicate.
- Report unscoped-excluded counts; `warn: cannot determine` when telemetry absent — never silent PASS.
- Replace data-derived `requireScope` off-switch with **explicit config defaulting to deny**.
- Tests: host with many admitted rows, native touched yesterday, zero durable admits in 7d → **FAIL** on `import_only`/`sc_canonical`; unscoped shared DB injects nothing and says so.

### B4 — Position on SC side-car dual-plane APIs *(HIGH)*

Track A must choose one and document it:

| Option | Meaning |
|---|---|
| **Deprecate** | Mark `ShieldCortexGuardedMemoryBridge` / pure-Markdown SoT backends as legacy; doctor warns when used under bound inject |
| **Rewire** | Bridge writes SC `memories` (defended) and optionally projects outward |
| **Doctor-fail** | Under `import_only`/`sc_canonical`, using external-only save path is a doctor **FAIL** |

Silence is not a position. Default recommendation: **deprecate + doctor-fail under sc_canonical/import_only**; rewire is a later ticket if product needs the bridge.

## Sequencing (do not reorder casually)

```
B1 attestation/trust harden  ─┐
B2 plane signed CLI          ─┼─ can parallel
B3 drift doctor + scope gate ─┘
        │
        ▼
T1 Host contract enforcement proof (native off the bus)
        │
        ▼
T2 memory.plane law + drift doctor productized (if not fully in B2/B3)
        │
        ▼
T3 Defended import-once (A3)
        │
        ▼
Default flip dual_legacy → import_only on hosts with contract+import path
        │
        ▼
Optional A1 projection after soak (not P0 gate)
```

**Do not** land T3 before B1–B3 and T1. Import into a dual-bus host recreates two writers.

## Child issues

| Ticket | Issue |
|---|---|
| T1 Host contract enforcement | #393 |
| T2 Plane teeth + drift doctor | #394 |
| T3 Defended import-once | #395 |

## Ticket specs

### T1 — Host contract enforcement proof · **#393**

**Goal:** `sc_only` / `disable_native_inject` actually remove native automatic memory from the bus.

**Hosts:** OpenClaw (TARS, CASE, …), Claude Code, Hermes (honest sidecar vs contract — pick one).

**Acceptance:**
- With contract set, native Memory Search / session-start native preamble does not own automatic durable context.
- Doctor **FAIL** if native still owns bus while contract claims otherwise.
- Tests: contract on → native tool/path dark for SoT; contract off → no SC pack claim of canonicity.
- No `coexist_dedup`.

### T2 — Plane runtime + dual-plane drift doctor · **#394**

**Goal:** `memory.plane` is law; drift is visible and fail-closed where required.

**Acceptance:**
- Closed enum validation; signed CLI write; `planeSetAt`.
- Illegal combos doctor-fail (see plane policy).
- Drift check distinct from empty-brain; fail/warn matrix:
  - `dual_legacy` + activity bypassing SC → **WARN** (time-boxed)
  - `import_only` / `sc_canonical` + native SoT growth or native bus → **FAIL**
  - telemetry missing → **WARN cannot determine**, not PASS
- FP fixtures documented (operator scratchpad vs agent SoT).

### T3 — Defended import-once (A3) · **#395**

**Goal:** Native MD / host memory files → SC only through full defence.

**Acceptance:**
- CLI/API import → chunk → full defence pipeline → admit path only.
- Provenance: `source_kind=native_import`, origin host/path, batch id, `content_hash`, defence verdict stored.
- Trust ceiling; never auto `source_attested` from file presence.
- SC-wins: higher-trust SC preserved; exact hash → idempotent no-op; no silent UPDATE overwrite.
- Dry-run default or explicit apply flag; per-row disposition.
- Adversarial suite: poison MD, higher-trust preserve, pipeline-down fail-closed, unscoped reject, salience clamp.
- After success, native is archive; T2 goes red if native keeps growing as SoT.

## Out of this residual (still)

- A2 multi-master / bidir sync / continuous mirror
- `coexist_dedup`
- Turn-by-turn inject default
- Fleet shared-brain (G) as plane shortcut
- Claiming SOTA from LongMemEval alone
- Hermes-native SoT writer as first-class brain

## Exit criteria for closing #348

All must be true:

1. B1–B4 folded into code or explicit accepted deferral issues with links  
2. T1 proven on at least one live bound host (TARS or CASE)  
3. T2 green in CI + doctor matrix tests  
4. T3 green with adversarial suite  
5. No doctor PASS while durable agent truth lives only on native under `import_only`/`sc_canonical`  
6. Independent review on the implementation PR(s) clears CRITICAL/HIGH  

Until then: **keep #348 open. No false close.**

## Implementation status (2026-08-22)

| Item | Status |
|---|---|
| B1 attestation≠trust + salience + unverified | **Landed** (this PR) |
| B2 signed `--memory-plane` + planeSetAt | **Landed** (this PR) |
| B3 drift doctor + scope not data-derived | **Landed**; deepened by #394 — real `isInjectEligible` counting, runtime-aware native SoT scan, gaps say cannot-determine |
| B4 side-car API position | **Deferred** — no dedicated doctor check yet; do not claim doctor-fail for GuardedMemoryBridge |
| T1 #393 host contract enforcement | **Initial** doctor proof (`checkMemoryHostContract`) — deepen per-host disable of Memory Search |
| T2 #394 | **Landed** — fail/warn matrix, FP fixtures (`doctor-plane-drift-394.test.ts`), real inject-eligibility counting, illegal plane × bus combos, telemetry cannot-determine. Residual: no `dual_legacy`-after-import escalation (needs T3), no export-back-to-native flag check (no such flag exists yet) |
| T3 #395 | **Not started** (blocked) |

---

## Related program fold (2026-08-24)

Post-Edith SOTA memory + defence + work-not-frustration: `2026-08-24-memory-sota-defence-work-not-frustration.md`. Track A residual locks unchanged; Phase 0 doors/lanes may run in parallel with T1 but **T3 import still waits on T1 + B1–B3**.
