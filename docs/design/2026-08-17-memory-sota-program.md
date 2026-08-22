# ShieldCortex Memory SOTA Program

**Status:** Design (Round-1 frontier reviews folded) / no implementation until first cut is chosen  
**Date:** 2026-08-17  
**Anchor:** main `@e6e5b6a` (post #340/#343/#344/#345)  
**Owner:** TARS (program) · Michael (cut selection)  
**Related:** `SCOPE.md`, `docs/agent-trap-gap-analysis.md`, `benchmark/longmemeval/`, OpenClaw cortex-memory hook  

**GitHub:** Epic [#347](https://github.com/Drakon-Systems-Ltd/ShieldCortex/issues/347) · A [#348](https://github.com/Drakon-Systems-Ltd/ShieldCortex/issues/348) · B [#349](https://github.com/Drakon-Systems-Ltd/ShieldCortex/issues/349) · C [#350](https://github.com/Drakon-Systems-Ltd/ShieldCortex/issues/350) · D [#351](https://github.com/Drakon-Systems-Ltd/ShieldCortex/issues/351) · Design PR [#346](https://github.com/Drakon-Systems-Ltd/ShieldCortex/pull/346)

---

## 0. One-line thesis

> For **bound** agents with a writable integration surface, ShieldCortex is the **defended canonical durable memory plane**: model-grade capture, defence on every write, automatic **brief fact** recall (never instructions), proven ranking. Native files are **projection, untrusted import, or explicit legacy** — not a competing brain. MCP-only / unbound hosts stay honest side-cars with doctor limitations (not fake canonicity).

Defence-on-the-memory-path remains the moat. Utility must stop losing to sticky notes. Side-car-forever is security theatre.

---

## 1. Problem statement (adversarial)

### What is strong today
- Write-path **6-layer defence**, quarantine, credential-leak block
- Recall ACL / RESTRICTED isolation intent
- Store architecture: FTS5 + embeddings + graph + salience/decay + Dream Mode
- MCP surface: `remember` / `recall` / `forget` / `get_context`
- Iron Dome (action) is improving faster than brain UX

### What is weak today
| Failure | Evidence |
|---|---|
| **Empty brain** | Live host example: `openclawAutoMemory: true` + `proactiveRecall: true` + **0 rows** in `memories.db` while `defence_audit` has activity |
| **Dual-plane surrender** | OpenClaw bootstrap inject **disabled** (v2026.2.26) after ~40× `CORTEX_MEMORY.md` duplication — session-start ceded to native Memory Search |
| **Capture is not cognition** | Regex/keyword extractors, max ~5, salience capped at 0.6 |
| **Recall is opt-in load** | Agent must call tools or hope proactive recall hits; native is always-in-context |
| **Unproven retrieval** | LongMemEval **toy** (5 Q); agentmemory 95% @500 cited as **not comparable**; RRF still cautious/opt-in in places |
| **Doc/default contradiction** | README “auto off to respect native” vs postinstall/hook “on by default” |
| **Security theatre risk** | Defended empty vault while agent reads undefended native markdown |

### Blunt scorecard (baseline)
| Area | Score |
|---|---|
| Architecture ambition | 8/10 |
| Write-path defence | 8.5/10 |
| Always-on usefulness | 3/10 |
| Capture intelligence | 3.5/10 |
| Retrieval proven quality | 4/10 |
| Integration coherence | 3/10 |
| Fleet memory | 2/10 |
| **As SOTA agent memory** | **~4/10** |

---

## 2. Non-goals (hard)

1. **Not** generic document RAG / vector DB product  
2. **Not** disabling defence to “feel faster”  
3. **Not** unbounded bootstrap dumps (no return of 40× class)  
4. **Not** replacing host EDR / OS security  
5. **Not** coding implementation until Michael picks **first cut**

---

## 3. Success definition (program-level)

A host is **Memory-SOTA ready** when **all** hold:

1. **Single plane:** for bound agents, SC is canonical durable store; native MD is export/view or import source — not a competing brain  
2. **Automatic:** core recall does not depend on the model choosing `recall`  
3. **Brief:** injected pack is ranked top-k, token-budgeted, content-hashed, non-duplicating across turns  
4. **Quality capture:** durable writes are model-distilled (or explicit user pin), not regex-only  
5. **Defence on path:** every durable write still passes the pipeline; no fast-path skip  
6. **Proof (product):** poison/recall-loop + inject budget/hash-ring + empty-brain doctor green in CI. **Proof (honesty, parallel):** LongMemEval-S scorecard exists and is labeled — it is **not** the conjunction that defines Memory-SOTA-ready  
7. **Doctor:** bound + auto-on + zero writes/recalls over N days is a **fail**, not a silent green  
8. **Fleet-ready path:** per-agent scope design accepted (implementation may trail P0)

---

## 4. Program structure

```
Epic: Memory SOTA
├── Track A — P0 Bridge (native ↔ SC single plane)
├── Track B — P0 Inject v2 (always-on, budgeted, non-duplicating)
├── Track C — P0 Capture distill (LLM-grade write quality)
├── Track D — P0 LongMemEval-S (proof, not toy)
├── Track E — P1 Retrieval defaults (RRF hybrid default, explain cards)
├── Track F — P1 Trust completion (SCOPE P1–P2 memory faces)
└── Track G — P2 Fleet boundaries (SCOPE P4)
```

**This epic’s committed design slice:** Tracks **A–D** (P0).  
E–G are sequenced, not abandoned.

---

## 5. Track A — P0 Bridge (native ↔ SC)

### Goal
End dual-brain. Agent and human have one truth.

### Design options (choose at cut time)
| Option | Shape | Risk |
|---|---|---|
| **A1 Canonical SC** | SC is SoT; `MEMORY.md` / OC memory files are **generated projections** (read-mostly) | Breaks workflows that hand-edit MD as SoT |
| **A2 Bidirectional sync** | Import native → SC (defended); export SC → MD snapshot | Merge conflicts; need LWW or SC-wins rules |
| **A3 SC-primary + import-once** | One-shot migrate native → SC; MD becomes archive | Migration pain; least ongoing complexity |

### Deliverables (design → later impl)
- [ ] Plane policy doc: canonical rules, conflict, project key  
- [ ] Import path: native MD / OC memory search index → `remember` via full defence  
- [ ] Export path: SC → stable markdown projection (optional)  
- [ ] Doctor check: dual-plane drift detector  
- [ ] Feature flag: `memory.plane = sc_canonical | dual_legacy | import_only`

### Acceptance
- Bound host cannot accumulate durable “agent truth” only outside SC without doctor warning  
- Import never bypasses defence pipeline  
- No silent overwrite of higher-trust SC rows by lower-trust native import

### Non-goals for A
- Full multi-master CRDT  
- Cloud-only memory

---


### Status 2026-08-22 (triple review)

A-min shipped (#352/#381). Full Track A **not** done. Residual plan + Opus blockers:

→ [`2026-08-22-memory-sota-track-a-residual.md`](./2026-08-22-memory-sota-track-a-residual.md)

Do not close #348 on A-min alone.

## 6. Track B — P0 Inject v2 (session-start + turn recall)

### Goal
Fix the 40× disaster **without** ceding the cognitive bus to native.

### Failure we must not repeat
OpenClaw bootstrap pushed full CORTEX_MEMORY-class content repeatedly → context death → inject disabled.

### Inject v2 principles
1. **Budget first:** hard token / char / row caps (config + absolute ceiling)  
2. **Hash ring:** never re-inject identical content within session window  
3. **Ranked pack:** hybrid ranker top-k only; no dump of “all project memories”  
4. **Data envelope:** every block wrapped as untrusted data (existing recall-defence)  
5. **Stable hash of preamble:** `extraSystemPromptHash` must not thrash session binding  
6. **Turn vs start:** session-start pack ≠ every-turn pack (turn is thinner)

### Surfaces
| Host | Surface |
|---|---|
| OpenClaw | `agent:bootstrap` + proactive message hook (re-enable carefully) |
| Claude Code | SessionStart + UserPromptSubmit (`prompt-recall-hook`) |
| Hermes | Plugin bootstrap / memory inject path (if any) — design parity |
| MCP-only hosts | Cannot force inject — document limitation; improve `get_context` |

### Deliverables
- [ ] Inject pack schema (versioned): `{id, title, why, trust, age, tokens}`  
- [ ] Budget config: `memory.inject.*`  
- [ ] Dedup store: per-session content hashes  
- [ ] Adversarial tests: no 40×; poison row cannot become tool instruction  
- [ ] Kill switch: `memory.inject = off | start | turn | both`

### Acceptance
- Synthetic 1000-row store injects ≤ budget every time  
- Repeated bootstrap does not grow prompt  
- Poison fixture recalled → data envelope only; tool-gate still independent

---

## 7. Track C — P0 Capture distill

### Goal
Stop storing medium-confidence regex shards as if they were judgment.

### Layers
| Layer | Role |
|---|---|
| **L0 Regex/heuristic** | Candidate discovery only (current extractors) |
| **L1 Distill** | LLM (local or host) turns candidates + transcript window → 0–N structured memories |
| **L2 Explicit** | User “remember this” / pin / MCP `remember` (highest trust) |
| **L3 Defence** | Unchanged pipeline on final content |

### Constraints
- Distill **output** still goes through defence — model can emit injection  
- Salience: L1 not auto-1.0; L2 can be critical  
- Cost: batch at session-end / pre-compact, not every token  
- Offline: L0-only fallback must remain (degraded mode, doctor warns)

### Deliverables
- [ ] Distill prompt + schema (`title`, `content`, `purpose`, `category`, `entities`)  
- [ ] Provider policy: prefer local/host OAuth routes; no surprise API bills  
- [ ] Cap policy: replace “5 regex shards” with “≤N distilled facts + pins”  
- [ ] Eval set: human-rated capture quality (precision/recall of “should have remembered”)  
- [ ] Flag: `memory.capture = regex | distill | distill_required`

### Acceptance
- On fixed transcript fixtures, distilled set beats regex F1  
- Zero defence bypass  
- Distill failure fails closed to L0 or skip with audit — never unreviewed raw dump of whole transcript into memories

---

## 8. Track D — P0 LongMemEval-S proof

### Goal
Replace vanity toy metrics with a real retrieval scorecard.

### Current state
- Toy fixture: 5 questions; RRF R@5 80% vs legacy 60%  
- agentmemory 95.2% @ full LongMemEval-S is **reference only**, not our number  
- Embeddings optional; missing model → FTS-only

### Deliverables
- [ ] Dataset acquisition path (documented license + local cache; not committed if restricted)  
- [ ] Harness: full LongMemEval-S (or agreed subset with statistical honesty)  
- [ ] Engines: `legacy`, `rrf` (and later graph-heavy)  
- [ ] CI job: scheduled or manual `workflow_dispatch` (full suite may be too heavy every PR)  
- [ ] SCORECARD.md regenerated with **comparable** caveats removed when full run exists  
- [ ] Target thresholds (proposal — confirm at cut): R@5 ≥ internal baseline + documented gap to agentmemory

### Acceptance
- One command produces full scorecard on a clean machine  
- Numbers labeled with corpus id, date, engine, embedding on/off  
- PR that changes ranker must show scorecard delta or justify skip

### Non-goals for D
- Training custom embedders in P0  
- Claiming SOTA before full corpus run

---

## 9. Sequencing & first-cut menu

**No coding until Michael picks one cut.**

| Cut | Tracks | Why pick it | Dependency risk |
|---|---|---|---|
| **Cut 0 — Truth** | A only (policy + doctor drift) | Cheapest; stops lying about dual brain | Low utility alone |
| **Cut 1 — Feel it** | B Inject v2 | User feels SC every session | Needs content or still empty |
| **Cut 2 — Fill it** | C Capture distill | Stops empty/noisy store | Needs inject or tools to surface |
| **Cut 3 — Prove it** | D LongMemEval-S | Stops marketing on toy | Parallelizable |
| **Cut 1+2** | B+C | Recommended product pair | Medium |
| **Cut Full P0** | A+B+C+D | Program integrity | Highest coordination |

**Recommended default if forced:** **Cut 1+2** (Inject v2 + Capture distill), with **A policy stub** (no full sync yet) and **D harness kickoff in parallel**.

Rationale: empty store + no inject = permanent loss to native. Bridge without fill is bureaucracy. Proof without product is vanity.

---

## 10. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Reintroduce 40× context death | Budget + hash ring + adversarial tests before OC bootstrap on |
| Distill API cost | Local/host OAuth only; batch; opt-in flag; doctor cost note |
| Dual-write races | SC-wins or import-only until sync proven |
| Defence FP on good memories | Separate capture FP budget; quarantine review UX |
| Ranker churn breaks agents | Feature flag; scorecard gate |
| Fleet contamination | No shared default brain until Track G |
| Scope creep into RAG product | Non-goals enforced in review |

---

## 11. Metrics (program dashboard)

| Metric | Baseline (example host) | Target |
|---|---|---|
| Durable memories (bound host, 7d) | 0 | >0 with quality bar |
| Recall inject events / active session | low/none | ≥1 start pack when store non-empty |
| % writes via defence pipeline | high when used | 100% durable |
| LongMemEval-S R@5 | unmeasured (toy only) | measured + published honestly |
| Dual-plane drift warnings | none | doctor detects |
| Poison-recall loop tests | partial | CI green |

---

## 12. Review protocol (frontier eyes)

Before any implementation PR:

1. **Design pack** = this doc + epic body + child issue texts  
2. **Independent reviews** (minimum):
   - Grok Heavy multi-agent **or** Grok 4.6 adversarial  
   - ChatGPT SOL Pro (`gpt-5.6-sol-pro`)  
   - Claude Opus/Sonnet when OAuth available (coding-limit may block Terminal Claude)  
3. **Loop rule:** any **blocker** → revise doc/issues → re-review until dual (or triple) **APPROVE / APPROVE_WITH_NITS** with empty blockers  
4. **No self-approve** by implementer  
5. **No code** until Michael selects cut + reviews clear for that cut’s design

### Review questions (every model must answer)
1. Is the single-plane thesis correct, or should SC stay a secure side-car forever?  
2. Safest inject v2 budget defaults?  
3. Distill: local-only vs host-model — what fails closed?  
4. First cut recommendation and what to explicitly defer  
5. Missing adversarial cases  
6. What would make this program accidentally become generic RAG?

---

## 13. Open decisions (Michael)

1. **First cut:** 0 / 1 / 2 / 3 / 1+2 / Full P0  
2. **Plane policy:** A1 / A2 / A3  
3. **Distill provider preference**  
4. **Whether OpenClaw native memory remains user-visible write target** after bridge  
5. **LongMemEval-S data handling** (license / private cache)

---

## 14. Exit criteria for “program design done”

- [x] This doc on a branch / PR (docs only)  
- [ ] GitHub epic + child issues A–D  
- [ ] ≥2 frontier independent reviews filed  
- [ ] Blockers resolved or explicitly accepted  
- [ ] Michael picks first cut  
- **Then** implementation may start — not before

---

## 15. References (in-repo)

- `SCOPE.md` — organism model, P0–P4 gaps  
- `hooks/openclaw/cortex-memory/HOOK.md` — bootstrap disable note  
- `benchmark/longmemeval/SCORECARD.md` — toy caveat  
- `scripts/lib/extract-memorable-segments.mjs` — regex capture  
- `scripts/lib/save-memory.mjs` — defence-on-write  
- `src/memory/ranker/` — RRF hybrid  
- `docs/agent-trap-gap-analysis.md` — environment/trap adjacency  

---

*Program opened 2026-08-17. Implementation frozen until first-cut selection + review clear.*


---

## 16. Round-1 frontier review (2026-08-17)

Independent reviews (no code). Full texts: `docs/design/memory-sota-reviews/`.

| Lane | Model | Verdict |
|---|---|---|
| Heavy | `grok-4.20-multi-agent-0309` | **CHANGES_REQUESTED** |
| SOL Pro | `gpt-5.6-sol-pro` | **CHANGES_REQUESTED** |
| Grok | `grok-4.6` | **CHANGES_REQUESTED** |

**Consensus first cut:** **1+2** (B then C) + **thin A** + **D parallel / non-gating**.  
**Consensus order:** **B > C > A > D**.  
**Consensus anti-pattern:** side-car forever · Full P0 first · LME-S as definition of SOTA · A2 multi-master in P0.

### 16.1 Blockers absorbed into design (must be true before freeze lifts)

| ID | Blocker | Design resolution |
|---|---|---|
| R1-1 | Empty-brain may be write-path/FP/quarantine/host-aim — not only “dumb capture” | **Prelude RCA** required before Cut 1+2 freezes: one-page why `defence_audit` moves and `memories` does not (per host class). Track C cannot assume intake works. |
| R1-2 | Inject budgets were qualitative | **Hard ceilings in code** (config may only lower). See §16.2. Default mode **`start` only**, not `both`. |
| R1-3 | Shared DB cross-host inject is P0 contamination | Inject/query default scope includes **host + agent_id + project** (deny-by-default if missing). Fleet Track G is deeper sharing — not “no scope until G”. |
| R1-4 | Pack field `why` is instruction-shaped | Inject pack = **fact / source_ids / trust / age / tokens / content_hash** only. No rationale-to-model field. |
| R1-5 | Distill “L0 or skip” is ambiguous | Fail closed = **skip + audit + doctor**. L0 only under explicit `memory.capture=regex` degraded mode — never silent fallback. Distill is tool-less, schema-bound, adversarial input. |
| R1-6 | LongMemEval-S in SOTA-ready conjunction = RAG gravity | LME-S is **honesty scorecard (Track D)**, not a gate for “Memory-SOTA-ready”. Product gates: poison-loop, budget/hash, empty-brain doctor, no-bootstrap-explosion. |
| R1-7 | Single-plane absolute vs dual_legacy / open A pick | Thesis is **directional for bound agents**. P0 plane policy: **A3 import-once + doctor drift** (or explicit best-effort canonical). **A2 out of P0**. A1 projections after B/C prove SC is worth SoT. Requires **host contract** notes (what OC/Claude/Hermes stop writing). |
| R1-8 | Provenance missing on durable rows | Every durable row: `source_kind`, `source_id`, `agent_id`, `host_id`, `content_hash`, `defence_verdict`, `capture_layer` (L0/L1/L2). |
| R1-9 | Success metrics conflicted with 1+2 cut | Metrics split: **product SLOs** (B/C/A-min) vs **retrieval honesty** (D). |
| R1-10 | Open decision “native remains writable” is A-input | Escalated to **cut-time blocker decision**, not soft preference. |

### 16.2 Inject v2 numeric defaults (Round-1 consensus band)

Absolute ceilings are **coded maxima**; config may only go lower.

| Pack | Default tokens | Default rows | Max tokens/row | Hard max tokens | Hard max rows |
|---|---|---|---|---|---|
| Session-start | **600** | **6** | **100** | **800** | **8** |
| Turn (off by default) | 200 | 2 | 100 | 300 | 3 |
| Session cumulative unique inject | **1500** | — | — | **2000** | — |

Other rules:
- Default mode: **`start`** until adversarial suite green one release; then optional `turn`
- Hash ring: **whole session**; start pack **pinned at session open** (stable sort: rank desc, id asc)
- Never inject quarantine / RESTRICTED (unless session cleared) / below trust threshold
- Empty store → inject **nothing** (no placeholder essays)
- Near-dup: exact hash in P0; optional normalized/near-dup later (explicit adversarial case)

### 16.3 Distill fail-closed matrix

| Condition | Behaviour |
|---|---|
| Provider error / timeout / invalid schema | **No L1 write**; audit; doctor degraded |
| Defence fail / uncertain on L1 output | **Quarantine**, not partial commit |
| `memory.capture=distill` outage | Skip L1; **do not** silent L0 |
| `memory.capture=regex` | Explicit degraded mode only |
| `memory.capture=distill_required` outage | Skip + doctor **fail** quality SLO (not dump transcript) |
| Transcript tries to instruct distill | Schema reject / defence; treat as adversarial |
| Billing | Default **no cloud call**; local/host OAuth only if configured |

L1 salience cap proposal: **≤0.7**; **1.0 reserved for L2 pins** (pins still reviewable if poison).

### 16.4 Plane policy (P0)

| Step | Policy |
|---|---|
| Now | Document dual-plane as **defect**, not feature |
| P0 ship | **A3-leaning:** defended import path + doctor drift; native writes treated untrusted if still allowed |
| After B+C prove value | A1 projections (“GENERATED — do not edit”) optional |
| Out of P0 | **A2 bidirectional multi-master** |
| Always | SC-wins on trust; import never skips defence; no silent overwrite of higher-trust SC |

### 16.5 Empty-brain RCA prelude (before Cut 1+2 implementation)

Must answer on at least one live bound host + one clean fixture host:
1. Are hooks actually invoking `save-memory` / MCP `remember`?
2. Are writes dying in defence (block vs quarantine vs pipeline unavailable)?
3. Project-key / path miss?
4. Host writing native memory only?
5. Dedup swallowing everything?

Output: short RCA appendix in this folder + issue comment on #347. **No feature code in prelude.**

### 16.6 Revised first-cut recommendation (post Round-1)

**Ship:** Cut **1+2** = Track **B** (start-only inject v2) → Track **C** (distill + fail-closed)  
**With:** Track **A-min** (policy + doctor drift + plane flag + provenance fields)  
**Parallel:** Track **D** harness (non-gating honesty)  
**Defer:** A2, turn inject, Full P0, fleet shared brain, RRF hard cutover as product gate, custom embedders, generic doc connectors

### 16.7 Extra adversarial cases added to suite list

Poison title/purpose · paraphrase 40× · start+turn double inject · unstable preamble hash · distill confused deputy · native import poison · quarantine exfil via titles · proactive capture→inject loop · cross-host shared DB spray · MCP `get_context` dump · ranking poison crowding top-k · salience stuffing · session-id churn reprint · doctor green-wash (only junk/quarantine) · defence FP empty brain · embedder-off keyword poison

### 16.8 Anti-RAG gravity clause

Any proposal whose primary beneficiary is **open-domain doc QA**, unbounded corpus connectors, or R@k without defence/plane/capture SLOs is **out of program** unless explicitly rechartered. LongMemEval informs ranker quality; it does not redefine the product.

### 16.9 Round-2 review gate

Re-review this doc (§16 included) with the same frontier lanes. Freeze lifts for a cut only when:
- ≥2 lanes **APPROVE** or **APPROVE_WITH_NITS**
- **BLOCKERS: none** on all lanes (or Michael explicitly accepts a residual blocker in writing)

---

---

## Normative addendum

**Round-2 fold:** see [`2026-08-17-memory-sota-program-r2-appendix.md`](./2026-08-17-memory-sota-program-r2-appendix.md). That appendix **overrides** §0–§15 on conflict with pack schema, plane policy, inject ceilings, A-min boundary, compact rehydrate, and host native-inject contract.
