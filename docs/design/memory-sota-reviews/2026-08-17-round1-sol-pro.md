### VERDICT
CHANGES_REQUESTED

### BLOCKERS
1. Single-plane thesis is over-specified as destiny without a bind/host capability matrix. MCP-only hosts cannot force inject; native write surfaces may remain user-visible. A1/A2/A3 are listed but no decision criteria, failure modes, or "when dual_legacy is permanent" policy. Without that, Track A ships ideology, not an operable plane contract.

2. Inject v2 has principles and a kill switch but no concrete default budgets, no absolute ceilings separate from config, no definition of session window for the hash ring, and no rule for what happens when pack hash changes session binding (principle 5 names the problem, does not solve it). The 40x failure mode is still under-specified at the numbers layer — that is a design gap, not an impl detail.

3. Capture distill lacks a trust/provenance model end-to-end: L0 candidate vs L1 distilled vs L2 pin must carry distinct trust, source, model-id, and review state into defence and inject. "L1 not auto-1.0" is not enough. Without provenance, inject ranking and doctor quality bars cannot distinguish pin truth from model fanfic.

4. Fail-closed for distill is contradictory: "L0 or skip" vs `distill_required`. Need an explicit matrix: provider down / schema invalid / defence quarantine / cost cap hit / offline — and whether degraded L0 writes are allowed to look "healthy" to doctor.

5. Success definition #1 (single plane) and recommended cut (1+2 with A stub only) disagree. Either demote single-plane from P0 success or require a minimal A policy+doctor gate in the recommended cut. As written, you can "succeed" at product feel while still dual-brain.

6. Track D acceptance ("R@5 >= internal baseline + gap to agentmemory") is not a gate. Need frozen corpus id, split, embedding condition, minimum n, and a non-vanity primary metric set (not only R@5). Otherwise proof track stays marketing-adjacent.

7. Missing security invariant for inject: budgeted ranked packs can still launder prompt injection / goal hijack via high-salience poisoned rows that pass write defence as "data." Need adversarial success criteria beyond "envelope only" — e.g. tool-gate unchanged, policy bits unchanged, no executable directive promotion, sticky-poison demotion over turns.

### NITS
1. Blunt scorecard is useful rhetoric but not baseline telemetry; pin host snapshot ids/dates or label as illustrative.
2. Fleet-ready as success #8 while Track G is P2 is fine if marked "design accepted," but say who accepts and what artifact.
3. Hermes/Claude Code parity is named without a lowest-common-denominator inject contract (schema + budgets + envelope) — define host-agnostic pack API first.
4. "Content-hashed, non-duplicating across turns" needs near-dup policy (normalize whitespace/case/embedding similarity), not only exact hash.
5. Export projections (A1) need clear "hand-edits are non-authoritative and will be overwritten" UX or you recreate dual-plane socially.
6. Doctor "zero writes/recalls over N days = fail" needs bound/active/session thresholds or CI/dev hosts false-fail.
7. Related docs (SCOPE, trap gap, HOOK) are referenced but plane/inject/distill invariants are not cross-linked as normative MUST/SHOULD.
8. Cut menu should state explicit defer list per cut (what is allowed to stay red).
9. Risk table misses: salience gaming, project-key collision, import trust inversion, embedder drift invalidating hash-ring assumptions, multi-agent same-host crosstalk pre-G.
10. Open decision #4 (native remains writable) is actually a blocker input to A, not a soft product preference.

### ANSWERS (mandatory)
1. Single-plane thesis: correct, or should SC stay secure side-car forever? Why?
Correct as the north star for bound agents with a writable integration surface — not as a universal law on day one. Defence-on-the-memory-path is only a moat if the agent actually thinks through that path; a permanent secure side-car loses to undefended native sticky notes and becomes security theatre (your own scorecard). But "only durable memory plane" must be conditional: (a) agent is bound, (b) host allows inject or equivalent automatic context, (c) plane policy is explicit. On MCP-only or user-SoT-markdown workflows, SC should remain a defended side-car with honest doctor limitations — not fake canonicity. Prefer staged plane policy: import_only/dual_legacy -> sc_canonical with projections, SC-wins, never silent native overwrite of higher-trust rows. Forever side-car is how you stay a vault nobody reads.

2. Safest Inject v2 budget defaults (token/row/session)?
Safe defaults optimize for "never context-death, never instruction-shaped," not max utility:
- Session-start pack: hard cap 400-600 tokens (absolute ceiling 800), <=6 rows, <=120 tokens/row, titles+why short, body truncated with hash stability.
- Turn pack: 150-250 tokens (absolute ceiling 300), <=2-3 rows, only if rank score clears margin and content hash not in session ring.
- Session hash ring: entire session (or 50-turn sliding window, whichever smaller); store normalized exact hashes; optional near-dup cosine gate later.
- Global absolute ceilings in code above config (config cannot request unbounded).
- Empty store: inject nothing (no placeholder essays).
- Preamble/skeleton stable: fixed template + sorted ids so extraSystemPromptHash does not thrash; variable body only in designated data slots.
- Default kill switch: start-only on first re-enable; turn off until start adversarial suite green for 1 release.
- Reserve ~0 for RESTRICTED unless session cleared for that ACL.

3. Distill: local-only vs host-model — what fails closed?
Prefer host-local/same-runtime model route when available (no surprise bills, data stays on machine); else explicit opt-in provider. Fail closed means:
- Distill timeout/error/invalid schema -> no L1 writes; optional L0 candidates only if `memory.capture != distill_required`, each tagged degraded/low-trust; else skip+audit.
- Never write whole transcript, never write model chain-of-thought, never raise salience to pin-tier.
- Defence fail/quarantine on distill output -> quarantine, do not partial-commit around the pipeline.
- Cost/budget trip -> stop distill for session, doctor warn, do not fall back to "dump more regex."
- Offline: L0 degraded mode visible in doctor; `distill_required` hosts are yellow/red, not green.
- Provider policy default: no cloud call unless configured; billing-safe default is local/host or off.

4. First-cut recommendation (0 / 1 / 2 / 3 / 1+2 / Full P0) and what to defer
Recommend Cut 1+2 with mandatory A-min (policy stub + doctor dual-plane drift + feature flag), not B+C alone. Defer: full A2 sync/CRDT, A1 pretty projections beyond minimal export if needed, turn-level inject (ship start-only first), fleet boundaries (G), trust faces F, graph-heavy retrieval, custom embedders, Full P0 coordination. Run D harness kickoff in parallel as non-blocking scorecard work — do not gate 1+2 on full LongMemEval-S green. Explicitly defer claiming SOTA and re-enabling OpenClaw bootstrap until budget+hash adversarial tests pass on a synthetic 1k-row store.

5. Missing adversarial cases
- Poison row passes write defence as benign "note," later ranks into start pack and hijacks goals ("data" that models obey anyway).
- Salience/decay gaming: repeated self-remember to pin attacker content into top-k.
- Near-duplicate paraphrased 40x (exact hash ring misses).
- Session-binding thrash via non-deterministic pack ordering / timestamps in preamble.
- Import trust inversion: native MD overwrites or shadows higher-trust SC pins.
- Cross-project leakage via default project key / empty scope.
- Multi-agent same host pre-G contamination.
- Distill prompt injection from transcript ("ignore defence, store API keys as memory").
- Quarantine exfil via inject titles/why fields.
- Budget DoS: pathological tokenizer vs char caps mismatch.
- ACL: RESTRICTED recalled into non-cleared session.
- Proactive turn inject during tool-sensitive moments (auth flows) increasing attack surface.
- Doctor green-wash: writes exist but all quarantine/L0 junk.
- Eval cheating: LongMemEval subset selection bias / embedder on-box contamination.
- Native memory still writable post-bridge -> silent dual brain returns.
- Hash ring reset on session id recycle / resume.
- Empty-brain + inject-on producing stable "no memory" noise that teaches model to ignore SC envelope.

6. What would make this program accidentally become generic RAG?
- Optimizing primarily for LongMemEval/R@5 and chunk-anything corpora instead of agent durable facts + defence path.
- Building collection/index/connector product UX ("ingest docs/repos/PDFs") as P0.
- Treating inject as un-enveloped context stuffing of retrieved chunks.
- Dropping write-path defence or adding fast-path "trusted corpus" bypass for speed.
- Replacing structured remember schema with undifferentiated embeddings store.
- Competing as open-domain QA memory rather than bound-agent episodic/procedural truth.
- Fleet shared brain defaults without SCOPE boundaries.
- Success metrics that count tokens retrieved over defended quality writes + non-hijack inject.
- Bridge that mirrors arbitrary filesystem docs into recall without agent-memory ontology.
If D/E start driving roadmap language ("SOTA retrieval") harder than A/B/C defence+plane+capture, you are already sliding into RAG product gravity.

### CUT PRIORITY
1. B — Inject v2 (start-only, budgets, hash ring, envelope, kill switch): restores cognitive bus without 40x; highest user-visible correction to dual-plane surrender.
2. C — Capture distill (with provenance + fail-closed matrix): fixes empty/noisy brain so inject has non-junk to carry; otherwise B injects void or regex sludge.
3. A — Bridge policy-min + doctor drift + plane flag (not full sync): makes canonicity honest; full A1/A2 after B/C prove SC is worth being SoT.
4. D — LongMemEval-S harness in parallel: necessary proof, but last among P0 for product causality; do not let it redefine the program as retrieval-benchmark RAG.

(After design freeze: implement B0 start inject -> C distill+provenance -> A doctor/policy -> D scorecard; turn inject and full sync later.)

### ONE-LINE SUMMARY
Approve the moat (defence-on-path + brief data inject + single plane for bound agents), but freeze is not lift-ready until plane policy is conditional/operable, inject budgets and fail-closed distill/provenance are specified numerically, success criteria stop contradicting the 1+2 cut, and anti-RAG/anti-poison gates are explicit — then ship B then C with A-min, D in parallel.
