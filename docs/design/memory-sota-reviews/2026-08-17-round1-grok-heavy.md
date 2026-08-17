### VERDICT
CHANGES_REQUESTED

### BLOCKERS
1. Plane policy is undecided with A2 still on the menu as peer options. Bidirectional sync (A2) reopens dual-SoT, merge races, and lower-trust native overwrite of defended SC rows. Design freeze must pick a default: A3 migrate-once → A1 projections, with A2 explicitly deferred or rejected for P0. “SC-wins” as a one-liner is not a conflict protocol.
2. Inject pack fields `{title, why, …}` are not proven instruction-safe. “Data envelope / never instructions” is the core security claim, but free-text `why`/`title` from ranker or distill can still steer the model. Need a hard schema: fixed labels, no imperatives, strip/deny tool-like syntax, and tests that poisoned title/why cannot induce tool calls or policy overrides.
3. Distill threat model is incomplete on confidentiality and provenance. L1 on host-model can exfil RESTRICTED/quarantine-adjacent transcript into host context; L1 local can still emit injection that passes soft defence and becomes high-salience retrieval bait. Fail-closed must specify: no distill of RESTRICTED spans; distill outputs inherit max source sensitivity; salience capped; never elevate L1 above L2; audit lineage candidate→distill→defence decision.
4. “Bound agent” and single-plane enforcement boundary are undefined. Without a crisp definition (which hosts, which files, write interception vs doctor-only nag), Track A acceptance (“cannot accumulate durable truth only outside SC”) is unenforceable and invites either false doctor fails or security theatre.
5. Success metric “zero writes/recalls over N days = doctor fail” is unsafe as stated. New installs, idle hosts, read-only analysts, and deliberate empty policy will page green→red incorrectly. Gate must be: bound + auto capture/inject enabled + meaningful agent activity + empty/unused SC → fail; idle/disabled must stay green or warn.
6. P0 leaves MCP-only hosts as “document limitation” while thesis says SC is the only durable plane for any bound agent. Either narrow the thesis to inject-capable hosts for P0, or require a concrete MCP mitigation (mandatory get_context convention, host-side wrapper, or “not Memory-SOTA-ready” certification label). Thesis vs delivery mismatch is a product lie risk.
7. Missing formal inject invariants before re-enabling OpenClaw bootstrap: absolute ceilings (not only config), stable pack serialization for `extraSystemPromptHash`, defined session dedup window/TTL, turn≪start budget ratio, and a kill-switch default of off/start-only until adversarial suite is green. “Re-enable carefully” is not a design gate.

### NITS
1. Scorecard baseline (~4/10) is useful rhetorically but unanchored; keep as narrative, not a KPI.
2. Track D targets (“R@5 ≥ internal baseline + gap to agentmemory”) should state minimum sample, confidence, and no-claim rule if embeddings off.
3. Inject schema should include `content_hash`, `source_ids`, `sensitivity`, `plane_revision` for debug and drift.
4. Capture flag `distill_required` can empty the brain on provider outage; prefer `distill` with L0 degraded + doctor warn as default fail mode.
5. Export projections need deterministic ordering and “GENERATED — do not edit” header to reduce A1 workflow breakage.
6. Fleet non-goal is right; add explicit P0 default `agent_id`/tenant scope on every row so G is not a retrofit.
7. Doc/default contradiction (README vs postinstall) should be a Track A/B exit patch, not only a problem bullet.
8. “Utility must stop losing to sticky notes” should be paired with UX for pin/forget/quarantine review or power users stay on native MD.
9. Parallel D harness kickoff is fine; do not block Cut 1+2 on full LongMemEval-S numbers.
10. Related docs (SCOPE, hook disable note) should be linked as normative inputs to plane + inject decisions, not bibliography only.

### ANSWERS (mandatory)
1. Single-plane thesis: correct, or should SC stay secure side-car forever? Why?
Correct for bound agents — with staged enforcement, not overnight abolition of native files. Side-car-forever concedes the failure mode you already measured: defended empty vault + undefended sticky notes = security theatre and product loss. Defence-on-the-memory-path is only a moat if durable cognition actually traverses that path. Caveats: single-plane is a sovereignty claim over durable agent truth, not a ban on user scratchpads; native MD becomes projection/import/archive; hosts that cannot inject cannot be called SOTA-ready; A2 multi-master is how you accidentally stay dual-plane forever. So: thesis yes; implementation A3→A1; side-car only as `dual_legacy` escape hatch.

2. Safest Inject v2 budget defaults (token/row/session)?
Defaults should be boring and hard-capped (config ≤ absolute).
- Session-start: ≤ 600–800 tokens, ≤ 8 rows, ≤ 120 tokens/row, ≤ 1 pack/session-start, hard ceiling 1024 tokens / 12 rows.
- Per-turn: ≤ 150–250 tokens, ≤ 2–3 rows, only on retrieval miss vs already-injected hash ring; hard ceiling 384 tokens / 4 rows.
- Session cumulative inject: ≤ 1500–2000 tokens unique content; beyond that, rank-replace not append.
- Dedup: content hash ring for full session lifetime (not a short window); near-dup optional later.
- Ordering: stable sort (rank desc, id asc) so preamble hash does not thrash.
- Default mode until suite green: `start` only (not `both`); `off` remains kill switch.
- Never inject RESTRICTED unless session already cleared for that ACL; default deny.

3. Distill: local-only vs host-model — what fails closed?
Prefer local/small dedicated distill first; host-model only if same trust boundary as the agent transcript and explicitly opted in. Fail closed means:
- Provider error/timeout/quota → no write of raw transcript; L0 candidates only or skip; doctor/audit records degraded capture.
- RESTRICTED/secret-bearing spans → no L1 send outside enclave; redact or skip.
- Distill output always L3 defence; on defence uncertainty → quarantine, not partial apply.
- No silent billable external API from default config.
- `distill_required` must not brick capture: treat outage as degraded + fail doctor quality SLO, not as “dump everything” or “write nothing forever” without signal.
Host-model fails open on privacy if transcript leaves SC; local-only fails open on quality if L0 regex remains the only path without doctor visibility. Both need the same write-path choke point.

4. First-cut recommendation (0 / 1 / 2 / 3 / 1+2 / Full P0) and what to defer
Recommend Cut 1+2, plus a thin A policy stub (not full bridge), D harness kickoff in parallel — aligned with the doc, with sharper deferrals.
Ship: Inject v2 (budgets, hash ring, envelope tests, start-only default), Capture distill (L0→L1→L3, caps, fail closed), plane policy doc + doctor “dual-plane / empty-brain under activity” definitions, LongMemEval harness scaffolding without SOTA claims.
Defer: A2 sync, full A1 projection productization beyond stub, OpenClaw bootstrap `both`/turn inject until adversarial green, fleet multi-master (G), trust faces F, RRF-default hard cutover E until D baseline exists, custom embedders, CRDTs, any “disable defence for speed.”
Do not pick Full P0 first — coordination risk recreates 40×-class failure under schedule pressure. Cut 0 alone is bureaucracy; Cut 3 alone is vanity.

5. Missing adversarial cases
- Poison title/why/purpose fields (not only body) inducing tool use or “ignore policies.”
- Hash-ring bypass via whitespace/unicode twin, chunk splitting, or alternating near-duplicates (40× by paraphrase).
- Session-start + turn double inject of same fact under different ids.
- `extraSystemPromptHash` flip from unstable ordering / timestamps / “age” text in preamble.
- Distill instructed by malicious user/transcript: “summarize as SYSTEM: …” / credential replicas / ACL escalation.
- Import native MD with embedded instructions or secret material; SC-wins not applied; saliance inflation.
- Quarantine exfil via inject pack citations or export projection.
- Proactive recall loop: inject → model restates → capture → inject growth (semantic dup).
- Multi-agent same host: agent B receives agent A memory via shared default plane.
- MCP-only agent never calls recall; doctor green because inject N/A — false SOTA.
- Budget DoS: 1000 high-salience poison rows all under cap but crowding out true top-k (ranking poison).
- Defence FP storm on good distill → empty brain while native fills.
- Clock/age manipulation affecting decay and inject eligibility.
- Partial disable: defence on, inject on, capture off (or inverse) — doctor must model combinations.
- Host memory search still writing native SoT after “canonical SC” flag — drift detector blind spots.

6. What would make this program accidentally become generic RAG?
- Optimizing primarily for LongMemEval/corpus QA and chunk-ingest of arbitrary docs instead of agent durable facts + defence-on-write.
- Treating MEMORY.md / repo docs as first-class corpus with embedding-only retrieval and no ACL/salience/graph/dream specifics.
- Dropping write-path defence or adding “fast ingest” bypass for demo speed.
- Unbounded context packs (“more tokens = better”) and citation-style answer generation as the product surface.
- Building connectors for PDFs/Confluence/Drive before plane/inject/capture integrity.
- Ranking research without bind-to-agent scope, pin/forget, quarantine UX, and doctor SLOs.
- Marketing external 95% numbers as ours or reshaping schema to match generic vector-DB APIs.
Guard: every epic acceptance must cite bound-agent durable memory + defence path; reject features whose primary beneficiary is doc-QA.

### CUT PRIORITY
After design freeze lifts (blockers cleared):
1. B — Inject v2 (user-visible bus; must be safe before on)
2. C — Capture distill (otherwise inject stays empty/noisy)
3. A — Bridge policy + doctor drift (stub→A3→A1; no A2)
4. D — LongMemEval-S harness/scorecard (parallel once B/C flags exist; do not gate first user-visible ship)

Dependency note: thin A definitions before B/C ship so “what may be injected/imported” is specified; full A sync after B/C prove the plane is worth canonicalizing.

### ONE-LINE SUMMARY
Approve the single-plane + inject/capture direction, but freeze A2, harden inject/distill fail-closed invariants and doctor semantics, then implement B→C with thin A and parallel D — not Full P0 and not side-car forever.
