# Memory plane policy (A-min) — Memory SOTA

**Status:** Normative for cut 1+2  
**Date:** 2026-08-17  
**Parent:** `docs/design/2026-08-17-memory-sota-program-r2-appendix.md`

## Plane flag

`memory.plane` in `~/.shieldcortex/config.json`:

| Value | Meaning |
|---|---|
| `dual_legacy` | **Defect mode** — native + SC both may hold truth. Doctor warns when activity bypasses SC. |
| `sc_canonical` | SC is defended SoT; native MD is projection/archive/untrusted import only. |
| `import_only` | A3-leaning: native may be imported via defence; not multi-master. |

P0 default remains `dual_legacy` until host contract + inject ship; target is `sc_canonical`.

**A2 bidirectional multi-master is out of P0.**

## Inject (B-gating)

```json
{
  "memory": {
    "plane": "dual_legacy",
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
| `mode` | `off` \| `start` \| `turn` \| `both` — default **start** |
| `nativeContract` | **Required** if mode ≠ off: only `sc_only` or `disable_native_inject` |
| `hostId` / `agentId` | Scope keys for eligibility when columns exist |

Illegal: inject enabled without `nativeContract`.

## Host contract (bound agents)

| Host | Capture | Inject | Notes |
|---|---|---|---|
| OpenClaw | cortex-memory hook when `openclawAutoMemory` | bootstrap uses inject v2 only with contract; native Memory Search must not own bus when contract=`sc_only` | Historical bootstrap dump disabled |
| Claude Code | stop / session-end / pre-compact / session-start | session-start → inject pack v2 | |
| Hermes | plugin memory provider / MCP remember | MCP `get_context` budget parity; often **mcp_sidecar_no_inject** | Honest side-car if no inject surface |

## Empty-brain doctor

Fail when bound (auto-memory or proactive or inject start/both) **and** 7d activity **and** zero admitted memories (or green-wash only).

## Native MD writable?

**Cut default:** native files remain writable as **untrusted I/O**, not competing SoT. SC wins on trust for durable agent facts once `sc_canonical`.
