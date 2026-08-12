# ShieldCortex — Scope & Phased Roadmap

*A second brain with a defence system built in.*

Status anchor: **v4.47.39** · 2026-08-12 · claims proven: **12/12** (`docs/CLAIMS-PROOF.md`)

---

## 1. Thesis — why "built in" is the whole game

Bolt-on memory is a commodity: every RAG stack stores and recalls. Bolt-on security is
just a scanner someone runs and forgets. ShieldCortex's moat is that **the defence lives
*on* the memory data path** — because memory is the liability nobody else treats as one:

- **Poison persists.** A bad memory written once silently re-influences every future
  decision. There is no "log out and back in" — the corruption is durable.
- **Memory hoards secrets & PII.** Capture is automatic; without a filter it will store
  credentials, tokens, and personal data verbatim, forever.
- **It's an unaudited black box.** "Why did the agent do that?" has no answer unless every
  read/write/decision is recorded and tamper-evident.

A second brain you cannot trust is worse than no brain. So defence is not a feature bolted
beside the memory — it *is* what makes the memory usable in production.

---

## 1a. The zeroth law — never break the host

Standing directive (Michael, 2026-07-02): **ShieldCortex must never break the OpenClaw
gateway or the agent it protects.** A protection layer that can take down its own host is
worse than none. Concretely:

- **No implicit gateway restarts.** `restartOpenClawGateway()` is the single choke point:
  it refuses under any test runner (`JEST_WORKER_ID` / `NODE_ENV=test`), and in any
  non-interactive session unless `SHIELDCORTEX_ALLOW_GATEWAY_RESTART=1` is set —
  deliberate automation only (e.g. a fleet-upgrade runbook that has checked for in-flight
  work). A restart kills every in-flight agent turn on the host, frequently including the
  agent that ran the install. A human at a TTY keeps the normal setup behaviour.
- **Tests never touch live services** (PR #64) — guard plus regression tests pin it.
- **The realtime plugin fails open.** A plugin crash or scan timeout degrades to
  advisory/no-op; it must never stall or kill the gateway.
- **Hooks stay bounded.** Claude Code hooks run with canonical timeouts (doctor verifies);
  a hung hook must never wedge an agent turn.
- **Enforcement must not strand unattended agents.** Fail-closed changes (P1/WS1) ship
  only after the fleet autoApprove audit, so no legitimate unattended job starts failing
  on upgrade.

Violations of this section are release-blockers regardless of what else a change delivers.

---

## 2. The one-organism model

Two systems sharing one data path. The brain thinks; the immune system guards every surface
where thought meets the outside world.

### The brain (cognition) — *mostly built*
`capture` (auto, hook-driven) → `structure` (typed memories, knowledge graph, salience/decay)
→ `recall` (semantic + graph, project-scoped) → `consolidate` (dedup / merge / contradiction)
→ `lifecycle` (decay, compaction/VACUUM, retention).

### The immune system (defence) — five guard pillars + a ledger

(Memory, Recall/ACL, Iron Dome, Environment Firewall, Overseer — plus Forensics, which is
the cross-cutting ledger rather than a sixth guard.)
Each pillar guards a distinct surface. The project already names them; this scope matures
them, it does not invent them.

| Pillar | Guards the… | Protects against | Today |
|--------|-------------|------------------|-------|
| 🧠 **Memory** | write path (what it *stores*) | poisoning, injection-into-memory, secret/PII capture | block/quarantine + credential-leak proven; advisory paths remain |
| 🔓 **Recall / ACL** | read path (what it *releases*) | leaking RESTRICTED / low-trust memory to the agent or dashboard | RESTRICTED isolation + own-only proven |
| 🛡️ **Iron Dome** | action path (what it *does*) | catastrophic/irreversible tool calls | catastrophic hard-block proven; broader classes advisory |
| 🌐 **Environment Firewall** | input path (what it *sees*) | hidden-web / tool-response injection | detection proven; **enforce off by default** |
| 👁️ **Overseer** | approval path (what the *human* approves) | social-engineering the operator into approving | signals detected; **advisory, never blocks** |
| 🧾 **Forensics** | the record (cross-cutting) | "no answer to what happened" | read/write/delete ledger w/ per-row content hashes; **not yet chained** |

**"Built in" means:** every write passes the Memory pillar before it becomes *trusted*;
every recall is surfaced as *data, never instructions*; every action is gated; every one of
those events lands in the ledger. You cannot get the brain without the immune system — the
same way a biological brain is inseparable from its blood-brain barrier.

---

## 3. Where we are — P0 (today)

Honest baseline. The pillars are **not** greenfield — all six exist and **12/12 public
defensive claims are proven by firing adversarial tests** (not "code runs" — real block /
redaction / quarantine asserted). See `docs/CLAIMS-PROOF.md`.

**Proven and live today:** 6-layer write-path pipeline (block/quarantine, nothing silently
dropped) · pattern + semantic + behavioural injection detection · credential-leak block at
write (25+ patterns) · skill-threat block at write time · contradiction detection · RESTRICTED
recall isolation + own-only ACL · dashboard never emits RESTRICTED · Iron Dome catastrophic
hard-block · Environment Firewall injection detection · provenance ledger (read/write/delete +
content hash). Runtimes: Claude Code hooks, OpenClaw plugin, Hermes plugin, MCP, API, dashboard.

**The honest gaps** (what P1–P4 exist to close):
1. **Enforcement is mixed.** Environment Firewall and Overseer run *advisory / fail-open* by
   default. Advisory-fail-open is indistinguishable from no protection when it matters — it
   "looks live, is a no-op." (This is the exact bug that bit the Hermes gate.)
2. **The ledger is per-row-hashed, not tamper-*evident*.** No hash-chain, no signing, no
   compliance-grade export. A ledger you can edit is a diary, not evidence.
3. **No erasure / retention story.** No GDPR right-to-be-forgotten workflow spanning memory +
   graph + ledger; capture/audit rows grow unbounded (only VACUUM reclaims space).
4. **No cross-agent trust model.** A fleet sharing memory has no per-agent scoping or
   contamination boundary. (The EDITH `workspace ↔ canonical` project-key collision was a
   preview of this class of problem.)

---

## 4. The maturity axis

Existence is not the metric. Every defence must climb the same ladder, and the roadmap is the
act of moving each pillar up it:

> **present → advisory → enforced-by-default → proven (1:1 claim) → hardened**

A pillar is only "done" for a release when it is *enforced by default* (or has a deliberate,
documented reason not to be) **and** has a firing adversarial test in the proof suite.

---

## 5. Phased roadmap

### P1 — Trust the brain: harden the write & action paths
*Goal: the two paths that mutate state (memory writes, tool actions) are enforced, not hoped.*
- Provenance stamped on **every** memory at write — source, trust tier, scan verdict — no
  un-tagged rows reach durable memory.
- Quarantine that **blocks by default** for high-confidence poisoning (not advisory pass-through).
- Iron Dome action gate: promote the **high** severity class (not just catastrophic) from
  advisory → enforce-by-default, with an explicit allow/approve path.
- **Definition of done:** new proof-suite entries asserting enforce-by-default behaviour;
  fail-open removed from these paths; perf budget on the write hot path documented.

### P2 — Close the loops: read & approval paths
*Goal: memory can't be turned into an instruction, and the human can't be socially engineered
through the agent.*
- Recall-as-data isolation hardening: an adversarial test proving a poisoned memory, when
  recalled, **cannot** re-fire as an instruction (memory-borne injection loop).
- Environment Firewall: **enforce-by-default** with a safe rollout (redact-before-model),
  false-positive budget, and an escape hatch.
- Overseer Guard: from advisory report → **raise-the-approval-bar** integration (high-risk
  manipulation signals force a stricter confirmation, not just a note).
- **Definition of done:** loop-closure and enforce tests in the proof suite; documented
  false-positive rate.

### P3 — Compliance-grade forensics
*Goal: the ledger is evidence, and the brain can forget on request.*
- **Tamper-evident ledger:** append-only + hash-chained (each row commits the previous) +
  optional signing; verification command that detects any edit.
- **Exportable** audit (JSON/CSV) for diligence/compliance, building on the existing export.
- **GDPR erasure workflow:** right-to-be-forgotten that spans memory + graph + embeddings and
  leaves a tombstone in the ledger (erased, provably, without breaking the chain).
- Retention policy on capture/audit rows (bounded growth, not just reactive VACUUM).
- **Definition of done:** chain-verification + erasure proven in the suite; a customer can run
  one command and get a signed audit export.

### P4 — Fleet memory with trust boundaries
*Goal: many agents, one trustworthy brain, zero cross-contamination.*
- Per-agent scoping + provenance so a shared brain never leaks or blends one agent's memory
  into another's decisions.
- RESTRICTED / ACL semantics that hold **across** agents, not just within one.
- Project-key discipline as a first-class guard (the EDITH collision, auto-detected and safely
  repaired).
- **Definition of done:** a cross-agent contamination attack is fired and blocked in the suite.

---

## 6. Non-goals (what ShieldCortex is *not*)

- **Not a document-RAG / vector-search product.** Store-and-recall is commodity; the value is
  agent-native capture + the defence on the path.
- **Not host security / EDR / antivirus.** Iron Dome guards *agent cognition and actions*, not
  the operating system.
- **Not a replacement for the model's own safety.** It is the *integrity layer around* agent
  memory and action — the part the model provider does not give you.

---

## 7. The discipline (definition of done, for everything)

1. **Provably enforced, not advisory-that-fails-open.** A defence that fails open is a bug, not
   a feature. Every enforcement claim gets a firing adversarial test.
2. **Proof suite stays 1:1 with the public claims.** If the README/SKILL says it, `claims-proof`
   fires the attack and asserts the block. New claim ⇒ new test, same PR.
3. **Hot-path performance budget.** Defence on every write/recall must be cheap enough that no
   one is tempted to disable it. Measure it.
4. **False-positive budget.** Over-blocking legitimate memory/actions destroys trust and gets
   the guard turned off. Track and bound it.

---

## 8. Highest-leverage next build

**P1 — flip the advisory/fail-open paths to enforce-by-default (starting with the Iron Dome
high-severity action class and quarantine-blocks-by-default).**

Rationale: it converts the single biggest credibility gap — "looks protected, actually a
no-op" — into a fact, and it builds directly on a surface that is already 12/12 proven, so it
is high-leverage and low-greenfield. It is also the most defensible marketing claim ("enforced,
not advisory") and the one competitors can't cheaply copy.
