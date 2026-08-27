# Memory plane policy (A-min + 2026-08-22 fold) — Memory SOTA

**Status:** Normative for cut 1+2 **and** remaining Track A (#348)  
**Date:** 2026-08-17 · **Folded:** 2026-08-22 (Grok + SOL + Opus)  
**Parent:** `docs/design/2026-08-17-memory-sota-program-r2-appendix.md`  
**Residual plan:** `docs/design/2026-08-22-memory-sota-track-a-residual.md`

## Plane flag

`memory.plane` in `~/.shieldcortex/config.json`:

| Value | Meaning |
|---|---|
| `dual_legacy` | **Deprecated defect mode** — native + SC both may hold truth. Time-boxed migration escape only. Doctor **WARN**s when activity bypasses SC. Not a steady product state. |
| `import_only` | **A3-leaning default target after import path exists** — native may be imported via full defence; not multi-master; native is archive/untrusted I/O after import. |
| `sc_canonical` | SC is defended SoT; native MD is projection/archive/untrusted import only. Requires **proven** host bus law (`sc_only` / `disable_native_inject` actually enforced). |

**P0 default today:** `dual_legacy` (honest about residual dual-plane).  
**Target after T1–T3 on a host:** `import_only`, then `sc_canonical` when bus ownership is proven.

**A2 bidirectional multi-master is out of P0.** Continuous native↔SC mirror is A2 — **reject**.  
**`coexist_dedup` is out of P0.**

### Signed write (required — Opus B2)

Do **not** hand-edit signed config for plane.

```bash
shieldcortex config --memory-plane dual_legacy|import_only|sc_canonical
```

Same `mutateRawConfig` / re-sign discipline as `--memory-inject-contract`. Persist `planeSetAt` (ISO timestamp) alongside the value for time-box and drift escalation.

Until that CLI ships, treat plane changes as **operator-mediated signed writes only** — never document raw JSON surgery as the happy path.

## Inject (B-gating)

```json
{
  "memory": {
    "plane": "dual_legacy",
    "planeSetAt": "2026-08-22T00:00:00.000Z",
    "inject": {
      "mode": "start",
      "nativeContract": "sc_only",
      "hostId": "tars",
      "agentId": "hermes-primary"
    }
  }
}
```

| Field | Law |
|---|---|
| `mode` | `off` \| `start` \| `turn` \| `both` — default **start**; turn/both not default for this cut |
| `nativeContract` | **Required** if mode ≠ off: only `sc_only` or `disable_native_inject` |
| `hostId` / `agentId` | Scope keys for eligibility when columns exist |

### Contract meanings (bus laws, not labels)

| Contract | Law |
|---|---|
| `disable_native_inject` | Host native recall/inject **off**. SC start-pack is the only automatic memory on the bus. |
| `sc_only` | Same bus rule **plus** native MD treated as non-brain (archive/view/untrusted I/O). |
| *(illegal)* | `coexist_dedup`, missing contract with inject on, garbage strings |

If config claims `sc_only` / `disable_native_inject` but native Memory Search / session-start native preamble / STM→MEMORY.md promotion still owns automatic durable context → **doctor FAIL** (paper contract).

### Illegal combos (doctor FAIL)

- `inject.mode ≠ off` without legal `nativeContract`
- `plane=sc_canonical` + native automatic memory still on the bus
- `plane=sc_canonical` + inject off or turn-only (no automatic start bus); honest sidecar posture is valid only with `dual_legacy`
- `plane=import_only` or `sc_canonical` + bidirectional/export-back-to-native-as-SoT flags
- `plane=dual_legacy` after import-once completed **and** grace elapsed on that host (warn first, then fail next release window)
- Any plane + SC library path that writes durable agent truth **only** to native MD under `import_only`/`sc_canonical` without SC store admit
- Import path marking native files `source_attested` solely because they existed on disk

## Host contract (bound agents)

| Host | Capture | Inject | Must stop when contract set |
|---|---|---|---|
| OpenClaw | cortex-memory hook when `openclawAutoMemory` | inject v2 only with contract | Native Memory Search owning session-start; MEMORY.md / dream-STM as SoT; historical bootstrap dump |
| Claude Code | stop / session-end / pre-compact / session-start | session-start → inject pack v2 | Native memory preamble as automatic brain |
| Hermes | plugin / MCP remember | **Either** honest `mcp_sidecar_no_inject` **or** `sc_only` — never both / never fake inject parity | Hermes-native files as SoT if claiming sc_only |
| CASE | same as OpenClaw | `sc_only` + hostId/agentId | Shared DB spray; dual automatic inject |

## Empty-brain doctor (shipped)

Fail when bound (auto-memory or proactive or inject start/both) **and** 7d activity **and** zero admitted memories (or green-wash only).

**Not sufficient alone** — see drift doctor.

## Dual-plane drift doctor (required residual)

Distinct check from empty-brain. Signals (normative intent):

1. Native memory artifact mtime/size/entry growth under session activity while SC durable admits ≈ 0 or ≪ native delta  
2. Native automatic bus still active while `nativeContract` claims otherwise  
3. Injectable count using **real** inject eligibility (not a weaker predicate); unscoped-excluded count reported  
4. Telemetry missing → `warn: cannot determine`, never silent PASS  

| Plane | Drift severity |
|---|---|
| `dual_legacy` | WARN (time-boxed defect) |
| `import_only` / `sc_canonical` | FAIL |

### Shipped shape (#394 T2)

`checkMemoryPlaneDrift` (evidence) → `evaluatePlaneDrift`
(`src/memory/plane-drift.ts`, pure decision), same split as the host-contract
proof. Signal order is **positive evidence before gaps**: a native brain doctor
can see growing is a decided defect even when the SC side is only partly
countable; only when no signal fires do the gaps speak, and a gap is
`cannot determine` (WARN on every plane), never PASS.

Signal 3 uses the shared `selectInjectCandidates` + `isInjectEligible` path from
`scripts/lib/inject-pack.mjs` — the exact deterministic top-64 window, row
shape, and predicate both start emitters use. Doctor reports eligibility
unknown when a session project is required but unavailable; it never presents
a project-agnostic upper bound as an exact positive. A bound SC bus (legal
`nativeContract` + start-capable mode) holding durable rows that the real gate
admits **none** of is drift: the store looks healthy by row count and delivers
nothing. With a signed honest `mcp_sidecar_no_inject` posture and inject explicitly off,
native bus/SoT/activity are expected and the drift check reports that posture
as healthy. `import_only`/`sc_canonical` plus sidecar is contradictory and
fails; a copied/unsigned posture string gets no exemption.

`requireScope` is read from the same config keys the runtime reads and defaults
to deny. It is never derived from the data; an unscoped store reports
`unscoped_excluded=N` and refuses to PASS.

### FP fixtures — operator scratchpad vs agent SoT

Drift counts only what a host actually loads as its agent brain. The FP column
is the reason each acceptance test exists (`doctor-plane-drift-394.test.ts`).

| Artifact | Drift? | Why |
|---|---|---|
| `<oc workspace>/MEMORY.md`, `memory.md` | **yes when non-empty** | OpenClaw loads non-empty bootstrap memory; a zero-byte bootstrap contains no memory and is ignored as drift |
| `<oc workspace>/memory/*` | **yes** | the workspace memory store |
| `<oc workspace-\<agentId\>>/…` | **yes** | per-agent brains, enumerated with the host contract's own workspace resolver |
| `~/.claude/memory/*`, `~/.claude/projects/<key>/memory/*` | **yes** | Claude's memory-tool store |
| `~/.hermes/MEMORY.md`, `~/.hermes/memories/*`, profile stores | **yes** | Hermes native store |
| `~/MEMORY.md`, `~/notes/…`, a stray `.md` in a workspace | **no** | operator scratchpad — no host loads it as a brain |
| `CLAUDE.md` / `AGENTS.md` preambles | **no** | project instructions, graded by the host-contract check (#393). Developers edit them constantly; drift is memory growth, not instruction edits |

Native **bus** state is reported only when PROVEN on (shared reader:
`resolveOpenClawMemorySearchState`, `parseHermesMemoryBlock`). Unknown bus
belongs to the host-contract check, which already caps at unknown and fails
there — drift is not a second host-contract parser.

## Import law (A3 — when T3 lands)

- Single chokepoint: parse → **full** defence pipeline → admit only on allow  
- `source_kind=native_import`; never auto `source_attested` from file presence  
- Trust ceiling; salience clamp ≤ 0.7  
- SC-wins; idempotent on `content_hash`; no silent overwrite of higher-trust SC  
- Scope required (host/agent/project) or reject  
- Dry-run or explicit apply; per-row disposition  
- Forbidden: continuous reimport mirror (A2), session-start import, defence-off flag  

## Attestation ≠ trust (Opus B1)

`source_attested` is channel identity, not content trustworthiness.  
Inject eligibility must **not** let attestation bypass the trust floor for non-pin rows.  
Pins remain explicit operator/high-trust law.

## Scope gate (Opus B3)

Deny-by-default scope is an **explicit config decision**.  
A gate that turns itself off because the DB has no scoped rows yet is **not** a gate (legacy/shared DB foot-gun).

## SC side-car APIs (Opus B4)

Under `import_only` / `sc_canonical`, library bridges that write defended facts **only** to external native stores are a Track A defect surface.  
Position until rewire: **deprecate + doctor-fail when used as agent SoT path**; do not expand their use.

## Native MD writable?

**Cut default:** native files may remain writable as **untrusted I/O**, not competing SoT.  
SC wins on trust for durable agent facts once `import_only` / `sc_canonical`.  
Hand-edits to projection/archive files are non-authoritative.

## Staged rollout and backout

1. Ship the shared candidate selector and doctor first; run doctor while the host remains `dual_legacy` and inspect candidate/native evidence without claiming canonicity.
2. Prove the bound runtime's automatic start bus and native-memory switches, then move that host to `import_only` with a signed CLI write. Soak before any canonical claim.
3. Move to `sc_canonical` only after start-pack delivery, recursive native-store scans, profile switches, and telemetry are all attestable and green.
4. Back out with a signed `--memory-plane dual_legacy` write. If the host cannot support automatic inject, declare the signed `mcp_sidecar_no_inject` posture instead; never hand-edit the posture string or signature.

## Related

- Residual tickets & sequencing: `2026-08-22-memory-sota-track-a-residual.md`  
- Program thesis: `2026-08-17-memory-sota-program.md` §5  
- R2 appendix: `2026-08-17-memory-sota-program-r2-appendix.md`
