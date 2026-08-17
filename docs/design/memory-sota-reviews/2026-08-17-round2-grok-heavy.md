### VERDICT
CHANGES_REQUESTED

### BLOCKERS
1. Inject v2 still has no policy for context compaction / prompt reset. Start-only + whole-session hash ring + start pack pinned at open means after compact the model loses the pack and will not see it again unless it calls tools. Real hosts (OpenClaw, Claude Code) compact. Before B freezes: specify re-pin/rehydrate on compact (preferred), or bounded post-compact turn inject, or an explicit P0 limitation with acceptance that mid-session recall is tool-dependent until turn ships.

2. Bound-host contract covers native writes (A3 / untrusted import) but not the native in-context memory path. If OC Memory Search (or equivalent) still always-injects while SC inject v2 is on, you get dual-plane on the cognitive bus, burned budget, and another path to thrash/duplication. Before B + A-min freeze: per host, state whether native memory inject/search-in-context is disabled, coexist-with-dedup, or replaced when `memory.inject` is not `off`.

### NITS
1. §5 still offers A1/A2/A3 at cut time and §13 still lists A2; §16 forbids A2 in P0 and locks A3-leaning. Make §16 authoritative; close A2 in open decisions; mark A1 as post-proof optional.

2. A-min scope is ambiguous on one-shot defended import. Say explicitly: A-min = policy + plane flag + doctor drift + provenance schema (+ optional import tool or not). “A3-leaning” without a defined import slice is just labeling the defect.

3. Inject “trust threshold” and “session cleared” for RESTRICTED are unnamed. Give P0 defaults (or “no RESTRICTED ever in P0 inject”).

4. §11 metrics table still mixes product SLOs and D honesty; label rows per R1-9.

5. MCP `get_context` needs the same budget / envelope / scope / no-quarantine rules as inject packs (adversarial list mentions dump; deliverables do not).

6. Token accounting method undefined (tokenizer vs chars/4). Pick one for ceilings and tests.

7. Pack schema in §6 still shows `why`; §16.1 R1-4 removed it. Fix the parent section so implementers do not reintroduce instruction-shaped fields.

### RESIDUAL RISKS
- Empty-brain RCA finds intake/defence/FP/hook failure: C cannot fill a broken write path; cut may become “fix intake → then B/C”.
- Start-only: facts written mid-session stay invisible until next session (worsened if blocker 1 is accepted as limitation).
- Exact-hash dedup only: paraphrase / near-dup 40× and salience stuffing can still crowd top-k.
- Ranking poison and title-only exfil remain until suite is red/green in CI.
- Distill local/host quality variance; `distill_required` outages fail quality SLO and can re-empty the brain operationally.
- Plane policy is social + doctor: hosts can keep writing native; drift warnings without enforcement become noise.
- Provenance on new rows only leaves legacy rows half-trusted until backfill rules exist.
- D parallel can still create RAG-gravity PR pressure if scorecard theater outruns product SLOs (anti-RAG clause helps, does not bind reviewers).
- Shared DB mis-scope (missing agent_id/project) fail-closed may yield empty inject and look like “SC is useless”.

### FIRST CUT
Confirm: B → C + A-min + D parallel, with empty-brain RCA prelude before feature code.  
Defer: A2, A1 projections until B/C prove value, turn inject until start suite is green one release (unless compact rehydrate forces a thin turn/compact hook), RRF hard cutover as product gate, fleet shared brain, custom embedders, generic doc connectors.  
Order remains B before C only if RCA shows intake can accept L1/L2 writes; if RCA shows write-path death, insert intake fix ahead of C (B can still ship against fixtures).

### ONE-LINE SUMMARY
Round-1 fold is mostly solid and the cut is right, but freeze should not lift until inject defines post-compact rehydrate and bound hosts define what happens to native in-context memory when SC inject is on.
