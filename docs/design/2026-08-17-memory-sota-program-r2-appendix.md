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

## Freeze lift gate

Need ≥2 frontier lanes **APPROVE** or **APPROVE_WITH_NITS** with **blockers: none** before freeze lifts for coding.

---

## Round-3 fold (2026-08-17) — freeze surface

| Lane | Verdict |
|---|---|
| Heavy | CHANGES_REQUESTED → folded |
| SOL Pro | CHANGES_REQUESTED → folded |
| Grok 4.6 | APPROVE_WITH_NITS |

### Single hash-ring + rehydrate law (wins)

1. Session maintains a **pinned start-pack** (ordered ids + content hashes) chosen at session open.
2. **Content hash preimage** = `id + newline + title + newline + fact` only (exclude age/trust/tokens so rehydrate identity is stable).
3. **Hash ring** suppresses re-inject of any content hash already delivered **except** rehydrate case (4).
4. **Rehydrate:** on host-signaled compact or prompt-reset only, re-deliver the pinned start-pack rows that **still pass live eligibility** (not deleted/forgotten, not quarantine, not RESTRICTED, trust floor still met, scope still matches).
5. Rehydrate is **budget-neutral** for the 1500/2000 cumulative unique session budget (already charged on first inject). Hard per-pack ceilings still apply to the serialized envelope.
6. If the host **cannot signal compact**, P0 = **no rehydrate** (not silent reprint).
7. Serialized envelope (wrapper + fields) counts toward token/char caps, not bare fact alone.
8. Char accounting: **chars/4** with hard char cap `tokens*4` (CJK undercount accepted P0 limit).

### Native inject contract (P0 law)

When `memory.inject != off` on a bound host, recorded choice must be exactly one of:
- `disable_native_inject`
- `sc_only`

**`coexist_dedup` is out of P0** (no algorithm → dual-bus rope).
**Illegal:** enable SC inject without a recorded per-host choice.
Host contract is on the **B critical path**, not optional paperwork.

### Unscoped rows

Rows missing `host_id` / `agent_id` / `project` are **not injectable**. Doctor reports excluded count. No implicit "all hosts" backfill.

### Pins under budget pressure

Pins are **rank inputs with priority**, not infinite reserved slots. Assembly: candidate set → rank → **pin-priority stable trim** until all ceilings hold. Pin stuffing cannot exceed hard maxima.

### Capture default after C

Default `memory.capture=distill` when provider configured (fail-closed skip).
`regex` only if explicitly configured. Unset must not silently mean legacy regex forever after C ships.

### Trust floor (P0)

Inject only if:
- not quarantine, not RESTRICTED, and
- (`trust >= medium` OR `source_attested` pin)

Exact enum names aligned to existing SC trust types at first B PR — must be in the PR description.

### Empty-brain doctor

Fail when bound + auto-on + (zero durable admitted rows OR only quarantine/junk/below-floor rows) over N days with activity. Green-wash = fail.

### Editorial before first B PR

Scrub or mark SUPERSEDED any parent pack/`why` / open A2 / open cut-menu lines so grep cannot revive them. This appendix § Round-3 + parent §16 are the freeze surface.

### First cut (unchanged)

Prelude RCA → **B** (with host contract) → **C**; **A-min** parallel with B; **D** parallel non-gating.

### Prior gate (satisfied by Round-4)

Target dual APPROVE / APPROVE_WITH_NITS, blockers none, on this full freeze surface.

---

## Round-4 result (2026-08-17) — design freeze CLEAR

| Lane | Verdict | Blockers |
|---|---|---|
| Heavy | **APPROVE_WITH_NITS** | none |
| SOL Pro | **APPROVE_WITH_NITS** | none |
| Grok 4.6 | **APPROVE_WITH_NITS** | none |

**Design freeze for coding may lift after Michael selects first cut.**

Remaining items are **nits / pre-B checklist**, not freeze-lifters:
- SUPERSEDED scrub of parent greppable contradictions before first B PR
- Split A-min parallel vs **B-gating** host-contract
- Doctor N default band (suggest **7 days**)
- Post-C unset capture = distill skip (not legacy regex)
- Candidate pool cap before rank; rehydrate drops ineligible without backfill
- Hermes row = MCP side-car / no inject if applicable
- Title length cap inside per-row budget
- Rehydrate uses frozen snapshot fields + live eligibility drop

### Operator decision still required

1. First cut pick (recommended: **1+2** = B then C + A-min + D parallel)
2. Native-writable post-bridge (yes/no)
3. Per-host inject contract when enabling B (`disable_native_inject` | `sc_only`)

## 2026-08-22 triple-review fold (Track A residual)

Grok 4.6 + GPT 5.6 SOL Pro + Claude Opus reviewed issue **#348**.

- **Authoritative residual plan:** [`2026-08-22-memory-sota-track-a-residual.md`](./2026-08-22-memory-sota-track-a-residual.md)
- **Plane policy (folded):** [`2026-08-17-memory-plane-policy-amin.md`](./2026-08-17-memory-plane-policy-amin.md)
- **Consensus:** A-min ≠ Track A done; A2/`coexist_dedup` forbidden; A3-leaning; Opus blockers B1–B4 before import product code.
- **Do not close #348** until residual exit criteria are met.
