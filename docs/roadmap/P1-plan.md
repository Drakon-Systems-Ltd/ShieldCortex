# P1 — Trust the Brain: enforce the write & action paths

Implementation plan for **Phase 1** of [`SCOPE.md`](../../SCOPE.md). Baseline: **v4.45.2**, 2026-07-01.

## Objective

Move the two state-mutating paths — **memory writes** and **tool actions** — up the maturity
ladder from *advisory / fail-open* to **enforced-by-default and proven**. After P1, "ShieldCortex
protects what the agent stores and does" is a CI-enforced fact, not a marketing line.

**Phase definition of done**
- Every workstream ships with a firing entry in `src/__tests__/claims-proof.test.ts` (1:1 with any claim it lets us make).
- No enforcement path fails *open*: a scan/gate error on a dangerous action or a high-confidence poisoning write results in **deny/quarantine**, never silent-allow.
- Hot-path performance budget for the write pipeline documented and measured.
- A documented false-positive budget for the newly-enforcing tiers.

## Current state (grounded)

| Surface | Today | Anchor |
|---------|-------|--------|
| Action guard | Only `catastrophic` → `block`; `sensitive`/`dangerous` "route through" confirmation/advisory | `src/defence/iron-dome/tool-action-guard.ts` (tiers `benign\|sensitive\|dangerous\|catastrophic`, catastrophic→`verdict('block',…)`) |
| Iron Dome config | Profile-based `blockedOperations` lists; no single enforce-by-tier default | `src/defence/iron-dome/config.ts:54` `DEFAULT_IRON_DOME_CONFIG` |
| Memory write | Single funnel exists but provenance is not a hard invariant; direct inserts possible | `src/memory/store.ts:546` (`INSERT INTO memories …`); bypass example `src/cli/doctor.ts:287` |
| Quarantine | Core pipeline blocks high-confidence poisoning (proven, claim 1); per-runtime capture consistency not guaranteed | `src/defence/pipeline.ts`, `src/defence/quarantine/` |
| Proof suite | Groups A–E, `it('claim N …')` | `src/__tests__/claims-proof.test.ts` |

Proven already (don't rebuild): claim 1 (write-path block/quarantine), 5 (credential-leak block), 6 (skill-threat block at write), 10 (catastrophic action block), 12 (provenance ledger). P1 hardens the *posture around* these, it does not re-implement them.

## Workstreams

### WS1 — Action Guard: promote `dangerous` to enforce-by-default
**Problem.** Only `catastrophic` blocks out of the box. A `dangerous` op (e.g. broad `rm`, unscoped network exfil surface, package install) is advisory/confirmation — i.e. can proceed.
**Change.** `dangerous` defaults to **block-or-require-approval** (never silent-allow). Enforce is the default posture; config may opt an operation *down* to advisory, not the reverse. Keep the explicit allow/approve path (confirmation-gate) for legitimate dangerous actions.
**Files.** `tool-action-guard.ts`, `config.ts`, `gateway.ts`, `action-gate.ts`, `confirmation-gate.ts`.
**Done.** New claim in group **C**: fire a representative `dangerous` op → assert gated (blocked or approval-required), and assert a benign op is untouched (precision).

### WS2 — Runtime gates fail **closed** (kill advisory-fail-open)
**Problem.** When a gate can't scan (missing auth, exception, timeout) it may silently no-op — "looks live, is a no-op." This is exactly the Hermes gate bug (401 → fail-open → scanned nothing).
**Change.** On the enforcement path, an inability to scan a `dangerous`/`catastrophic` action **fails closed** (deny + surface + audit `gate_degraded`). Distinguish "scanned & allowed" from "couldn't scan." Applies across OpenClaw plugin + Hermes plugin + Claude Code hook wiring.
**Files.** OpenClaw extension action wiring, Hermes plugin gate (`sc_client`), `gateway.ts`.
**Done.** Integration test: simulate scan failure on a dangerous action → asserted **denied**, `gate_degraded` audit row emitted. No path returns allow-on-error.

### WS3 — Provenance invariant: no durable write without source + trust + verdict
**Problem.** The guarded pipeline tags writes, but nothing *guarantees* every row does — a direct insert can bypass provenance.
**Change.** (a) `store.ts` is the single sanctioned write funnel; (b) schema `NOT NULL`/`CHECK` on provenance columns (`source`, `capture_method`, defence disposition/verdict) + migration; (c) a guard that rejects an un-tagged write; (d) audit and remove/redirect any bypassing callers.
**Files.** `src/memory/store.ts`, `src/memory/save-filter.ts`, `src/database/schema.sql` (+ migration in `migrations.ts`), `pipeline.ts`.
**Done.** New claim in group **A**: a durable write lacking provenance is **rejected**; every accepted row carries source + trust + verdict.

### WS4 — Quarantine blocks-by-default across all runtimes
**Problem.** Core blocks high-confidence poisoning, but per-runtime auto-capture (Claude Code / OpenClaw / Hermes) must apply the same default disposition, not advisory pass-through.
**Change.** One verdict→disposition mapping shared by all capture paths: high-confidence poisoning ⇒ block/quarantine everywhere; consistent default; loud on degrade.
**Files.** `pipeline.ts`, `src/defence/quarantine/`, per-runtime capture wiring.
**Done.** Extend claim 1 to assert the block holds via each runtime's auto-capture entry, not just the direct pipeline call.

## Sequencing

WS3 (provenance invariant) and WS1 (dangerous→enforce) are independent and can land in parallel.
WS2 (fail-closed) depends on WS1's enforce semantics being defined. WS4 depends on WS3's single
disposition mapping. Suggested order: **WS1 + WS3 → WS2 → WS4**, each merged only with its proof entry.

## Cross-cutting definition of done
- **Perf budget:** measure added latency on the write hot path; document a ceiling; fail CI if exceeded.
- **False-positive budget:** track over-blocks on the newly-enforcing `dangerous` tier; publish the rate; provide the opt-down escape hatch.
- **Proof suite 1:1:** every new public claim gets a firing test in the same PR. Update `docs/CLAIMS-PROOF.md`.

## Risks & mitigations
- **Over-blocking legit actions** → confirmation/approve path + per-op opt-down + FP budget.
- **Migration on live DBs** (provenance NOT NULL) → backfill existing rows with an `unknown`/`legacy` provenance tag before applying the constraint.
- **Runtime divergence** → single shared disposition mapping (WS4) so the three runtimes can't drift.

## Issue map
- Epic: **P1 — Trust the brain** (tracking)
- WS1 → *Action Guard: dangerous → enforce-by-default*
- WS2 → *Runtime gates fail closed (no advisory-fail-open)*
- WS3 → *Provenance invariant on every durable write*
- WS4 → *Quarantine blocks-by-default across runtimes*
