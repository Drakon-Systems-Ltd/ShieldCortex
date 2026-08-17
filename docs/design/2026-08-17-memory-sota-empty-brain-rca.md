# Empty-brain RCA (TARS host) — Memory SOTA prelude

**Date:** 2026-08-17  
**Host:** TARS (`~/.shieldcortex`)  
**Cut:** 1+2 prelude (no feature code in this document)

## Snapshot

| Signal | Value |
|---|---|
| `openclawAutoMemory` | `true` |
| `proactiveRecall` | `true` |
| `memories` rows | **0** |
| `quarantine` rows | **0** |
| `defence_audit` rows | 27 |
| `hook_invocations` | 22 — **all** `prompt-recall` |
| `session_events` | 162 (prompts captured) |
| OpenClaw hook install | `~/.openclaw/hooks/cortex-memory` present |

## What defence_audit is doing

Every recent `defence_audit` row is:

- `source_type: cli`
- `source_identifier: shieldcortex-scan` or `shieldcortex-audit`
- `operation: write` (pipeline exercise / scan path)
- `memory_id: null`

**Conclusion:** defence activity is **scan/audit**, not durable memory admission. ALLOW on those rows does **not** insert into `memories`.

## What hooks are doing

| Hook | Evidence |
|---|---|
| `prompt-recall` | Fires often; notes always `zero-yield:no-candidates` |
| Capture hooks (`session-end` / `stop` / `pre-compact` / OC cortex-memory extract) | **No** `hook_invocations` rows for save/extract on this host |
| OC bootstrap inject | Explicitly **disabled** in handler (post ~40× CORTEX_MEMORY disaster) — native Memory Search owns bus |

**Conclusion:** recall path is live and correctly empty (no candidates). **Capture path is not producing durable rows** on this host despite `openclawAutoMemory=true`.

## Root causes (ordered)

1. **No durable writes attempted into `memories`**  
   Empty store + empty quarantine + no save-oriented hook telemetry ⇒ intake never completed a `saveAutoExtractedMemory` / MCP `remember` success path here.

2. **Dual-plane / bus surrender**  
   OpenClaw bootstrap inject contributes nothing to system prompt; session cognition stays on native memory. SC is not the bus even when config flags are on.

3. **Capture is regex/session-file dependent and host-coupled**  
   OC handler skips when no session file / no assistant content / no resolvable local install / no high-salience regex hits. Claude-side extract hooks may not be the primary agent loop on TARS (Hermes-primary). Result: flags on, brain empty.

4. **Hermes path is defence-on-native-memory, not SC store fill**  
   Hermes plugin guards `on_memory_write` / recall context; it does not by itself populate `memories.db` as the canonical plane.

5. **Not primary:** defence FP storm  
   Quarantine is empty; audit ALLOW rows are scans. Distill/C is still needed for quality, but **will not fix an un-aimed write path alone**.

## Implications for cut 1+2

| Track | Implication |
|---|---|
| **B Inject v2** | Must handle empty store (inject nothing). Value appears after C/A fill. Still required to reclaim bus safely with host contract `sc_only`. |
| **C Capture distill** | Must target **actual agent loops on this host** (Claude hooks + OC + explicit remember), not only OC session-end regex. Fail-closed; also add capture hook telemetry so empty-brain is diagnosable. |
| **A-min** | Doctor must fail: bound + auto-on + 0 admitted memories over N days **with** activity (session_events / hook_invocations / defence_audit). Distinguish green-wash. |
| **D** | Parallel honesty only. |

## Fix order (implementation)

1. Doctor empty-brain + plane flags (A-min)  
2. Inject pack library + session-start path (B) + host contract config  
3. Capture path that can write on Hermes/Claude/OC with telemetry (C)  
4. LongMemEval harness scaffold (D)

## One-line RCA

**Flags are on; scan defence runs; prompt-recall runs empty; nothing is admitting rows into `memories` because capture is not on the live agent write path and bootstrap inject was surrendered to native.**
