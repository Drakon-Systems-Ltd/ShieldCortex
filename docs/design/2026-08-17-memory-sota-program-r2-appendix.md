# Memory SOTA — Round-2 appendix (normative addendum)

**Parent:** `docs/design/2026-08-17-memory-sota-program.md`  
**Authority:** This appendix + parent §16 **override** parent §0–§15 on conflict.  
**Date:** 2026-08-17 · Design only · No implementation

## Round-2 review results

| Lane | Model | Verdict |
|---|---|---|
| Heavy | grok-4.20-multi-agent-0309 | CHANGES_REQUESTED (folded here) |
| SOL Pro | gpt-5.6-sol-pro | CHANGES_REQUESTED (folded here) |
| Grok 4.6 | grok-4.6 | Incomplete run (infra) |

## Corrections to parent doc (treat as already decided)

1. **Pack schema:** `{id, title, fact, source_ids, trust, age, tokens, content_hash}` — **no why/rationale field**
2. **Inject mode default:** `start` (not `both`). Mode values: `off | start | turn | both`
3. **A2 bidirectional sync:** **out of P0**
4. **P0 plane:** A3-leaning + doctor drift; A1 optional after B+C
5. **LME-S:** honesty scorecard only — not Memory-SOTA-ready gate
6. **First cut:** B → C + A-min + D parallel

## R2 blockers → design law

### R2-1 Dual authority
Parent §16/this appendix win. Implementers must not copy pre-fold schemas from §6 if they conflict.

### R2-2 Compaction / prompt reset
**Rehydrate on compact:** after host compact or prompt-reset, allow re-inject of the **pinned start-pack content hashes only** (not free reprint of arbitrary rows). Turn inject remains off by default.

### R2-3 Native in-context memory still on bus
**Host contract (A-min):** when `memory.inject != off`, per host choose:
- `disable_native_inject`
- `coexist_dedup`
- `sc_only`

**Default recommendation for bound OpenClaw / Claude Code:** `sc_only` or `disable_native_inject`.

### R2-4 Session-start selection seed
**Non-query working set:** scope-bound pins + high salience/recency → hybrid rank, stable sort (rank desc, id asc). Optional task query only if host supplies one. No dump-all.

### R2-5 A-min boundary
**A-min includes:**
- plane policy one-pager (A3-leaning; A2 forbidden)
- `memory.plane` flag + doctor dual-plane drift
- empty-brain doctor (bound + auto-on + zero durable writes over N days with activity)
- provenance on **new** writes; legacy → `source_kind=legacy_unknown`
- host-contract table (OpenClaw / Claude Code / Hermes)
- native-writable decision recorded

**A-min does not include:** full import product (that is **A-min+**).

### R2-6 Trust / RESTRICTED
P0 inject never includes `quarantine` or `RESTRICTED`.  
Trust floor: `trust >= medium` or `source_attested` pins (enum aligned at impl spike).  
No session-clear escape hatch in P0.

### R2-7 get_context parity
MCP `get_context` uses same budgets, envelope, scope, and no-quarantine rules as inject packs.

### R2-8 Token accounting
P0: **chars/4** with char hard cap `tokens*4`. Document in tests.

## Inject ceilings (repeat of §16.2 — absolute maxima)

| Pack | Default tokens | Default rows | Max/row | Hard max tokens | Hard max rows |
|---|---|---|---|---|---|
| Session-start | 600 | 6 | 100 | 800 | 8 |
| Turn (off default) | 200 | 2 | 100 | 300 | 3 |
| Session cumulative | 1500 | — | — | 2000 | — |

## Distill fail-closed (repeat)

Outage/error/invalid schema → **skip + audit + doctor**.  
No silent regex fallback.  
`regex` only if explicitly configured degraded mode.  
L1 salience cap **0.7**. L2 pins may use higher.

## First cut (confirmed)

1. Prelude: empty-brain RCA (no feature code)
2. **B** Inject v2 start-only (+ compact rehydrate + scope + host contract)
3. **C** Capture distill fail-closed
4. **A-min** in parallel with B
5. **D** LongMemEval harness parallel, non-gating

## Round-3 gate

Need ≥2 frontier lanes **APPROVE** or **APPROVE_WITH_NITS** with **blockers: none** before freeze lifts for coding.
