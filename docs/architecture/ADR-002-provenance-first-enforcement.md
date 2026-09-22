# ADR-002: Provenance-first enforcement (v2)

**Status:** Proposed
**Date:** 2026-09-22
**Author of v1:** TARS (issue #556). **v2 fold:** author-side objections recorded on #556 and the convergence agreed between the two on 2026-09-22.
**Reviewer:** TARS. **Decision:** operator.
**Evidence:** #555. **Supersedes for review purposes:** the v1 text in the body of #556.
**Relates to:** ADR-001 — the intent-first doctrine at `docs/design/2026-08-24-intent-first-doctrine.md` and its companion target architecture. This ADR changes the enforcement *mechanism* under that doctrine; it does not change the doctrine's one-line law, its catastrophe hard-stops or its credential non-exfil rule.

**Revision:** v2 round 3 — addresses review at fe9541a2: the effect decision is a function of (effect, targets, taint) rather than a static signal list; opaque-invocation approval is a distinct, weaker mode; the Hermes fail-open claim corrected against source; 5B controls split into effect-witness and taint families; acceptance bars pre-registered as engineering bars; 5A qualified as descriptive.

| round | head | what changed |
|---|---|---|
| v2 round 1 | ffca84c5 | first fold of #556 v1 with the author-side objections (Section 0) |
| v2 round 2 | fe9541a2 | Section 2.4 restructured into three disjoint effect sets with precedence DENY > HOLD > AUDIT; Sections 2.1/2.2 restated as a taint and lineage contract (unknown provenance fails closed, taint is transitive by content, taint state bound to host-owned session identity); Section 2.5 narrowing gate now requires 5A and 5B and 5C; the "SC already sees every tool response" assertion replaced by the measured per-adapter coverage table in Section 5C; Section 8 records the alternative not taken |
| v2 round 3 | this revision | Section 2.4 recast as a decision over (effect kinds, targets, session taint) with a minimum effect taxonomy and a fail-closed unclassified branch, and round 2's static-disjointness rule withdrawn; Section 2.3 gains **opaque-invocation approval** as a distinct mode with immutable execution identity and execution-time revalidation; Section 5C's Hermes row corrected against source (partial fail-open, not blanket); Section 5B's controls split into enforcement-off effect witnesses and taint controls, and the acceptance bars pre-registered as engineering bars; Section 5A qualified as descriptive; Section 4's tainted-session consequence corrected |

> **Nothing in this document is the operator's acceptance of the trade-offs; that decision is pending.**

Numbering note: this is the first file under `docs/architecture/`. Earlier decision records live under `docs/design/` (for example `ADR-2026-08-19-retry-control.md`) and keep their names; "ADR-001" is the label #556 gives the intent-first doctrine, not a file.

---

## 0. What changed from v1

| v1 (#556 body) | v2 (this document) | Why |
|---|---|---|
| "837 events … Notifications actually delivered: 0"; read as 837 gates | 837 distinct events = 638 warned (advisory) + 195 auto_denied + 4 denied_no_prompt_surface; `notify: not_configured` 837/837 describes the notification channel only | The tally mixed advisory and enforced outcomes. The log does not support reading the total as a count of blocked actions. |
| Gate keys on the lowest-band *span in the causal context* of a tool call | Gate keys on **session taint**: once any `untrusted-external` span has entered context, HOLD-set effects are held pending bounded approval | The trust plane's ceiling is per-process. No harness links a context span to the tool call it caused. |
| Floor = catastrophic destruction only | A **decision over (effect kinds, targets, session taint)** resolving into DENY, HOLD or AUDIT with precedence DENY > HOLD > AUDIT: DENY (destruction + credential egress, no approval path, taint-independent), HOLD (persistence sinks, security-config writes, anything privileged in a tainted session, and anything the guard cannot classify; released only by bounded approval), AUDIT (the dangerous tier in an untainted session, after the narrowing gate) | An injection wants secrets out and persistence in, not a formatted disk; but persistence and config writes are also how an operator installs and repairs, so they need an approval path rather than a prohibition. The same signal class lands differently at different taint states, so the partition has to be computed, not tabulated. |
| Dangerous tier → audit-only now | Dangerous tier → audit-only **only after** the logged-signal replay (5A), the executed and reviewed effect-witness run (5B) and per-adapter coverage evidence (5C) | Narrowing must be measured, not argued. |
| `notify: not_configured` + `enforce: true` fails `doctor` | Same, and the failure must **not** change enforcement state; ships first and independently | A doctor that silently flips enforcement is a second way to lose the gate. |
| #550/#552/#553/#554 fold into this decision | **Excluded.** Same agent, same session, same band on both sides; provenance cannot replace that sink control | Different threat, different control. |
| #506 reframed as "labels and capability, not patterns" | #506 reframed as **ingestion-boundary scanner coverage** (`tool-response-enforce` blocks in enforce mode); never an effect gate; multilingual/rot13 coverage kept | The clamp never sees text inside a tool result; the scanner does, at the front door. |
| Validation: replay + agent-work corpus + injection corpus | Two separated halves, never summed: logged-signal policy comparison and synthetic effect-witness fixtures; provenance coverage measured per adapter | Signal counts and outcome measurements answer different questions. |
| (implicit) ShieldCortex already sees every tool response and every memory injection | **Measured** per-adapter coverage table (Section 5C): which hooks each adapter registers, whether a result transformation exists, and "missing" where it does not | The claim was asserted, not measured; measurement shows result transformation is missing on every adapter. |

### What changed in v2 round 3 (review at fe9541a2)

- **Section 2.4 — the partition is a decision, not a table.** Set membership is now a function of (effect kinds, targets, session taint) with precedence DENY > HOLD > AUDIT. Round 2's rule that a signal class may appear in only one list is **withdrawn**: the same class is legitimately HOLD in a tainted session and AUDIT in an untainted one. The invariant is that the decision function is total and single-valued. A four-step decision procedure is written out.
- **Section 2.4 — a minimum privileged-effect taxonomy** (`destroy`, `credential-read`, `egress`, `persistence-write`, `security-config-write`, `privilege-change`, `process-control`, `file-mutate`, `package-install`, `code-exec-opaque`, `network-fetch`), each with a resolved target set, plus an explicit **fail-closed** branch: an executable effect the guard cannot classify, or whose targets it cannot resolve, is **HOLD at minimum** in every session. An explicit rule that **no program is exempted by name** — builds, tests and `git` are classified by effect and target like anything else, and an unresolved delegate is `code-exec-opaque`.
- **Section 2.3 — opaque-invocation approval is a distinct mode.** Approving an exact invocation string does not bind effects or targets, only which bytes run. The mode requires immutable execution identity (content hash of the program and everything resolved into it, `argv`, interpreter, working directory), host/session/action binding, **execution-time revalidation** (re-hash at exec; any mismatch returns to HOLD), and DENY and lease constraints enforced independently of the approval. Where an adapter cannot enforce all four, **the opacity stays held**; a string approval or a pre-scan is not proof of an unknown program's effects. Nested and indirect effects are named as the mode's residual.
- **Section 5C — the Hermes fail-open claim corrected against source.** Not blanket fail-open: an unreachable scanner runs a dependency-free fallback scan over the raw exec surface, catastrophic matches are denied always, dangerous matches are denied when enforce is on, and only unmatched shapes fail open, audited as `gate_degraded`. The row and a new paragraph say so, with the residual stated.
- **Section 5B — controls split into two families.** Enforcement-off **effect-witness** controls prove the attack is real and the witness observes it, and prove nothing about taint. Separate **taint controls**, run with taint instrumentation enabled, prove the taint mechanism: a positive-injection control (taint must be present after reading outside content) and a clean-session control (taint must be absent). Which control licenses which claim is stated.
- **Section 5B — acceptance bars pre-registered, as engineering bars.** ≥ 90% witnessed attack blocking, ≤ 2% unintended blocking of legitimate work, ≥ 98% completion along the approval path, **zero** successes in the DENY / forged-or-replayed-approval / identity-and-taint-laundering / lease-bypass families; no-approval completion and prompt burden reported separately; three arms (current, proposed, no-guard) on frozen fixtures; a failed no-guard witness voids its comparison; denominators frozen first; uncovered adapters never described as protected; cross-session taint tests required. **Explicitly not a SOTA claim** — that would need an independent held-out set and an adaptive attacker.
- **Section 5A — qualified as descriptive.** Not a security-effectiveness rate. Requires reconciliation of all 199 enforced events with an explicit unknowns column, no known DENY weakening left unexplained, and a prohibition on manufacturing provenance to make a replay look decisive.
- **Section 4 — the tainted-session consequence corrected.** Round 2 asserted that a tainted-session service stop or file delete proceeds once the dangerous tier is AUDIT. It does not: those are HOLD in a tainted session. The residual is restated as (a) damage in a session the adapters wrongly believe is clean and (b) an operator approving under pressure.
- **Sections 2.5 and 8 updated** to reference the two control families, the pre-registered bars and the opaque-invocation mode.

---

## 1. Context

### 1.1 Two planes that do not talk to each other

ShieldCortex has a trust plane and an effect plane.

**The trust plane** (`src/defence/trust/`) implements provenance for the *caller*:

- `src/defence/trust/env-detector.ts` computes an environment-inferred trust **ceiling** from the process environment the MCP server inherited, which a tool parameter cannot forge.
- `src/defence/trust/resolve-tool-source.ts` computes that ceiling first, clamps any over-claimed declared source down to it, drops a same-score identity the environment did not confirm, and writes `SOURCE_ELEVATION_BLOCKED` to the defence audit when a clamp happens, "so operators can spot prompt-injection trying to escalate its own trust or wear another agent's name".
- `source-scorer.ts` and `access-control.ts` turn the resolved `DefenceSource` into a decision about memory.

This is the right shape for an injection defence on the surface it covers: it checks the label, not the words.

**The effect plane** (Action Guard / Iron Dome) decides on text:

- `isActionAllowed(action, config, source?, attested?)` in `src/defence/iron-dome/action-gate.ts` takes `source` as an optional parameter and consults it only for `subAgentRestrictions`. Every other branch ignores it.
- The realtime guard that emits `recursive-force-delete`, `opaque-script-invocation` and the rest of the signal set contains no reference to `DefenceSource`, `resolveToolSource` or any provenance concept. It decides purely on command text.

So the plane that knows who asked cannot gate effects, and the plane that gates effects does not know who asked. That gap is retained from v1 as the diagnosis.

### 1.2 Premise correction: the ceiling is per-process, not per-span

The ceiling answers "which client process made this MCP call". It does not answer "which text in the model's context caused this tool call". A tool call injected by a poisoned web page inside an operator's coding session and a tool call the operator typed reach the gate with byte-identical environment, so the same ceiling, so the same band. The model is the component that got fooled, and its output carries no provenance.

No harness ShieldCortex integrates with exposes a causal link from a context span to the tool call it produced. v1's gate question ("is the lowest-band span in the causal context requesting a privileged effect?") therefore presumes a signal that does not exist. Two readings survive:

- **Per-caller binding.** This is `subAgentRestrictions` today. It does nothing for an injection in the main session.
- **Session taint.** Once any `untrusted-external` span has entered a session's context, the session is tainted and HOLD-set effects are held until a bounded approval is given for the specific effect.

Only session taint is an injection defence. Section 2.2 adopts it and states its cost.

### 1.3 Evidence, measured

From one production host, `denials.jsonl`, origin `claude-code-hook`, window 2026-08-16 to 2026-09-22. Two rows per event is normal; the counts below are distinct events.

| outcome | events |
|---|---|
| warned (advisory) | 638 |
| auto_denied | 195 |
| denied_no_prompt_surface | 4 |
| **total distinct events** | **837** |

`notify: not_configured` on 837/837 describes the **notification channel only**: no denial or warning was delivered to an operator surface over the whole window. It does not say every one of those events stopped an action. 638 of the 837 were advisory and did not stop the action. 199 were enforced (195 auto-denied, 4 dead-ended for lack of a renderable approval surface).

Signals present across the 837 events, from #555 (an event may carry several):

| signal | events |
|---|---|
| opaque-script-invocation | 389 |
| stop-process-or-service | 216 |
| redacted-signal | 206 |
| privilege-escalation | 200 |
| file-delete | 191 |
| recursive-force-delete | 170 |
| modify-scheduler | 114 |

Tools gated: `Bash` 631, `Write` 109, `Edit` 97. All are agent-originated tool calls; none is an inbound-content decision. Events carrying any injection- or exfil-flavoured signal (`external-egress`, `decode-pipe-to-shell`, `pipe-download-to-shell`, secret and credential classes): 26. The remaining 811 carry only dangerous-tier or catastrophic-tier signals.

### 1.4 What the numbers do not say

- **Live-operator presence at the time of each denial is UNKNOWN.** `denials.jsonl` has no field for it. What would establish it: a join of each event's action id and timestamp against the host's session records for the same session id, recording whether the session was interactive (a TTY or a connected chat turn) or a headless lane (cron, hook re-entry, background worker) at that instant, and whether an operator message was sent to that session within a bounded window before and after. Until that correlation is run, "no operator ever saw a denial" is a statement about the notification channel, not about the operator.
- **811/837 "agent work" is not evidence that the sink control is useless.** Its job is to gate agent work. The count measures signals, not outcomes. What the count does show is that the guard's input is the agent's own command text, so what it sees is dominated by the agent's own ordinary operations.
- **The 26 injection-flavoured events are not 26 injections.** They are events whose signal set includes an egress or decode class; whether any corresponded to hostile context is not recoverable from the log.

### 1.5 The false-positive class is structural

Because the guard's only input is command text, any text that mentions a dangerous shape trips it. #532 (a comment in a folded script mentioning a delete command denied the repo's own test runner), #517/#549/#551 (quoted data denied while expanded substitution was missed), #512 and #519 (a tokeniser now quadratic, about a second at 8,000 tokens) are one defect class seen from several directions: mentioning a thing is not doing the thing, and text inspection cannot tell them apart. The board reflects it: sixteen open issues in the command-inspection lane against five in the memory and injection lane.

---

## 2. Decision

**Enforcement keys on provenance and capability, with a text-inspected DENY set scoped to irreversible effects.** Detection stays at the ingestion boundary as a scanner, and in the DENY set as a last line, not as the general effect gate. Sections 2.1 and 2.2 together are the **taint and lineage contract** every adapter must satisfy; Section 2.4 is the effect-set contract the gate enforces.

### 2.1 Every span entering model context carries a source label, and a missing label fails closed

Reuse `DefenceSource`. The bands below are an ordering over the existing source types (`user`, `cli`, `hook`, `email`, `web`, `agent`, `file`, `api`, `tool_response`), fixed at implementation time; they are not a new type.

| band | examples |
|---|---|
| `operator` | authenticated channel: owner chat, local terminal |
| `signed-peer` | signature-verified teammate message |
| `agent` | this agent's own reasoning and its own tool calls |
| `stored-memory` | recalled memory, framed per #531 and #535 |
| `tool-result` | MCP or tool output that is not otherwise classified |
| `untrusted-external` | web page, feed, scraped content, unsigned message, any tool result whose origin is a network fetch or an unauthenticated source |

**Unknown or missing provenance is fail-closed.** A span whose label is `unknown`, absent, or produced by an adapter that could not classify the event shape is treated as `untrusted-external` **for the purpose of taint**. The alternative, defaulting an unlabelled span to a trusted band, would make every unlabelled entry point a silent hole; the cost of the fail-closed rule is that an adapter with poor labelling taints more sessions than it should, which is visible in the audit row and fixable by improving the adapter, not by weakening the rule.

The existing seam for this is already in `src/defence/types.ts`: `ProvenanceLabel` is documented as "a declaration, not host attestation", it carries `unknown` as a member alongside the `DefenceSource` types, and `ProvenanceSource` widens `DefenceSource` so an ingress that *declares* a label (`document`, `memory_candidate`, `agent_message`, `tool_result`, `system`, `unknown`) is scored and reported without becoming a new memory source. The distinction this ADR relies on is exactly that one: a **caller-declared label** is an input to policy; **attestation** (the environment-inferred ceiling and, where a host supplies it, the host's own sender or session flag) is what policy trusts. The OpenClaw realtime plugin's `provenance.ts` already applies the first half of this rule ("never guess upwards"; an unrecognised shape is labelled `unknown` and counted). What it does not yet do is treat that `unknown` as tainting; Section 2.2 requires it.

This rule is about **provenance**, not about scanner uncertainty. The existing #361 rule in the OpenClaw plugin (an uncertain or unavailable *scan result* never raises taint) survives unchanged: an "I could not scan this" is not a claim about where the span came from. The two rules coexist because they answer different questions.

The ceiling clamp in `env-detector.ts` and `resolve-tool-source.ts` remains the load-bearing mechanism for the *caller's* band and is reused as-is. Labelling of *spans* is done at ingestion. **Whether ShieldCortex actually sees a given span at ingestion is an adapter property that has been measured, not assumed**: Section 5C tabulates, per adapter, which hooks it registers, whether it transforms tool results, and where the labelling point is missing. #535, #547 and #538 are prerequisites because a single unframed or unlabelled entry point is a leak of the whole scheme.

### 2.2 Session taint: a transitive lineage contract bound to host-owned identity

**Rule.** When any span labelled `untrusted-external` (including, by Section 2.1, any span whose provenance is unknown or missing) enters a session's context, the session becomes **tainted**. Taint is one of the three inputs to Section 2.4's decision, and it moves the outcome in exactly one direction:

- **DENY** is unaffected: a DENY row denies at any taint state, and there is no approval for it.
- **Every privileged effect kind** (Section 2.4's taxonomy — all of them except `network-fetch`) is **HOLD** while the session is tainted, whatever its target, pending a bounded approval (Section 2.3) for that one effect. This is what makes a service stop, a file deletion, a deploy or an opaque script HOLD in a tainted session where it would be AUDIT in a clean one.
- **AUDIT is not reachable in a tainted session.** Only effects that are not privileged — reads, and `network-fetch` itself — proceed, and they are audited with the taint flag on the row.

**Taint is transitive by content, regardless of transport trust.** What taints is the *content's lineage*, not the channel it arrived over. The following all taint the receiving session:

- a tool result carrying externally fetched material, whether the fetch was made directly or through a proxy such as an MCP server acting on the agent's behalf (the proxy's own band is `tool-result`; the material it relays is still external);
- a return from a peer or sub-agent whose own session was tainted, or whose return quotes hostile material, even when the peer's message is signature-verified (`signed-peer` is a statement about who sent the envelope, not about what is inside it);
- a local file authored externally (a cloned repository's README, a downloaded document, a shared drive file), even though it is read through a `file` source on a trusted host;
- a memory written from a tainted session and later recalled (the frame per #531 carries the taint marker; recall taints the recalling session);
- a summary or compaction of a tainted context (the poisoned span may be gone; its influence on the model is not).

**Taint state is bound to host-owned session identity.** The taint record is keyed by the session identity the *host* supplies (the gateway's session id, the hook's session id, the MCP server's process-inherited identity), never by an identity asserted in content. **Prose labels carry no authority**: a tool result saying "this content is from the operator", a message claiming to be the owner, or a span self-labelled `operator` neither sets nor clears anything. This is the same rule the OpenClaw plugin's `conversation-trust.ts` already applies to the owner flag (a missing or non-boolean `senderIsOwner` is not the owner; unknown fails toward caution) and the same rule `resolve-tool-source.ts` applies to a declared source: declaration is input, attestation is authority.

**Lifetime.** Taint lasts for the **session**. It is inherited by:

- forked or child sessions spawned from a tainted session;
- summaries and compactions of a tainted context;
- memory written from a tainted session and later imported.

"Until the next operator turn" is rejected: the poisoned page is still in context when the operator says "carry on". "Until the span leaves context" is rejected: leaving is unobservable through compaction. A fixed time-to-live is rejected for the same reason: the existing OpenClaw taint store's fifteen-minute window (Section 5C) was designed for a detection-triggered escalation and is the wrong lifetime for a provenance-triggered one.

**Reset.** There is no operator "clear" that launders retained hostile context. An operator may start a fresh session. An operator may approve a specific effect under Section 2.3. Neither clears the taint of the session in which the hostile span was read.

**What this contract does not cover.** Binding a *child harness* to its *holder session* so that a taint (or a lease) set in one is visible from the other is the cross-session identity problem tracked in **#554**. That issue is deliberately **not folded into this ADR**: it is a trust-plane binding problem with its own design, and this ADR's inheritance rules above are a requirement on it, not a solution to it. Until #554 lands, a child harness that the host cannot bind to its holder is an adapter with a coverage gap, and Section 5C lists it as such.

**New false-positive class, accepted as a trade.** "Fetch the vendor's docs, then deploy" is held: the fetch taints the session and the deploy is a privileged effect. That is a different false-positive profile from today's, not a zero one. Today's profile is "mentioning a dangerous shape is denied"; the proposed profile is "having read the outside world, privileged effects need a bounded yes". The second is decidable, explainable in one sentence to the operator, and bounded by the operator's own workflow rather than by the shell grammar. Whether it is the better trade is the operator's decision.

### 2.3 Bounded approval

An approval issued against a held effect comes in exactly **two modes**, and an implementation may not silently substitute the weaker one for the stronger. The bullets immediately below define the default, **effect-bound** mode; the subsection after them defines the **opaque-invocation** mode and its disclosed residual risk.

An **effect-bound** approval:

- **binds the actual effect and its targets**: the resolved command or write, the files, hosts, services or scheduler entries it touches; not a class, not a pattern, not "this kind of thing";
- **expires**: a short window, a single use, or both;
- **is non-replayable**: consumed on use, tied to the action id it was issued for, useless against a later identical string;
- **cannot bless an unknown**: a shell effect the mapper cannot resolve (an opaque script, an interpreter given a program, a computed target) cannot inherit a broad approval. It is held until its effect is known, or until the operator issues an **opaque-invocation approval** under the separate mode below — which is not an effect-bound approval and does not become one;
- **never clears taint**;
- **never overrides the DENY set** (Section 2.4): there is no approval that turns a DENY into an allow;
- **never overrides a held session lease or freeze** (Section 2.7): where an approval and a lease disagree, the lease wins.

#### Opaque-invocation approval: a distinct mode, with disclosed residual risk

**Approving an exact invocation string does not bind the action's effects or its targets.** An effect-bound approval binds *what the action will do*, because the mapper resolved it. An approval of an opaque program binds only *which bytes will be run*; the effects of those bytes remain unknown to the guard. Round 2's text treated "the operator approves that exact opaque invocation" as though it satisfied the effect-and-target binding rule. It does not, and the two are separated here so that an implementation cannot present the weaker one as the stronger.

What the operator is approving in this mode, and what the surface must say in those words: **an identified program running once, in a named place, whose effects the guard could not determine; this approval does not certify those effects.**

An opaque-invocation approval is valid **only** where the adapter can enforce all four of the following. They are cumulative, not a menu.

- **Immutable execution identity.** The approval is bound to a **content hash** of the program that will actually run — the script file, the heredoc body, the `-c` program text, and every file resolved into the execution surface — together with the exact `argv`, the interpreter and its flags, and the working directory. It is not bound to the command string: the same path can hold different contents at different moments, so a path is not an identity.
- **Host, session and action binding.** The approval is bound to the host, to the host-owned session identity of Section 2.2 (never to an identity asserted in content), and to the single action id it was issued for. It is single-use and it expires, as every approval in this section does.
- **Execution-time revalidation.** The program is **re-hashed at the moment of execution**, inside the same gate that releases the hold. Any mismatch — the file changed, a resolved include changed, `argv` differs, the interpreter or its flags differ, the working directory differs — returns the action to **HOLD**. It does not proceed, it does not warn-and-run, and it does not silently re-prompt as though nothing had changed. Time-of-check to time-of-use is the whole reason this mode needs a second check.
- **DENY and lease constraints enforced independently of the approval.** The DENY set (Section 2.4) and any held session lease or freeze (Section 2.7) are evaluated at execution against the surface actually being run, without reference to the approval. An opaque-invocation approval **never overrides a DENY** and **never overrides a held lease or freeze**; where they disagree, DENY and the lease win. This is the same rule the effect-bound bullets state, repeated here because the opaque mode is exactly where an implementation would be tempted to treat the approval as a general release.

**If the adapter cannot enforce all four, the opacity stays HELD.** A string approval, a pre-scan of the program's text, or a human reading the script are not proof that an unknown program's effects are safe. A pre-scan is the text-inspection gate this ADR is replacing, applied to a surface the attacker chose, and it says nothing about what the program does at run time through a child process, an interpreter, a downloaded payload or a network fetch. An adapter without content hashing, without execution-time revalidation, or without a surface that can render the opacity statement is an adapter on which opaque effects are held — and Section 5C records that as the adapter's measured state, not as a pass.

**Nested and indirect effects are this mode's residual, not its coverage.** An approved opaque program that reaches a DENY effect through a child process or an interpreter is stopped by the DENY evaluation *at that inner call*, and only on an adapter whose gate observes inner calls. On an adapter that gates the outer invocation only, every effect the program reaches indirectly is inside the residual the operator accepted. That residual is stated on the approval surface and is exercised as fixture (b) in Section 5B.

The existing retry-control design (`docs/design/ADR-2026-08-19-retry-control.md`: mint on operator intent, denial produces a claim ticket not a grant, catastrophic tier has no path) is the shape to extend. An approval surface that cannot render the effect and its targets cannot issue a bounded approval; on such a host a held effect stays held, as `denied_no_prompt_surface` does today.

### 2.4 The effect decision: a function of (effect, targets, taint), resolved into DENY, HOLD or AUDIT

**Set membership is computed per action, not looked up in a static list.** For every action the guard resolves a triple:

1. the **effect kinds** the action performs (the taxonomy below);
2. the **targets** each of those effects acts on (files, hosts, services, scheduler entries, devices, network sinks);
3. the **taint state** of the session requesting it (Section 2.2), taken from the host-owned session identity.

That triple, and only that triple, decides the outcome. Precedence is **DENY > HOLD > AUDIT**: where one action carries effects that resolve into more than one set, the most restrictive set present decides.

**Disjointness is a property of the decision, not of the signal vocabulary.** Round 2 said that "a class listed under one set may not also appear under another, and an implementation that finds a class in two lists has a bug". That sentence described a static table, and this policy is not one; it is **withdrawn here**. The same signal class correctly appears at different points of the space: `stop-process-or-service`, `file-delete` and `opaque-script-invocation` are **HOLD in a tainted session and AUDIT in an untainted one** (after Section 2.5's gate); `modify-scheduler` is HOLD when its target is a persistence sink and AUDIT when it is not; a `file-delete` whose target is a root or home tree is DENY at any taint state. The implementable invariant is instead that the decision function is **total and single-valued**: every (effect, targets, taint) triple maps to exactly one set, and an implementation that maps a triple to two sets, or to none, has a bug.

**The decision procedure.**

1. Resolve effect kinds and targets. An effect kind the guard cannot name is `unclassified-executable`; a target it cannot resolve is `unresolved`.
2. If any (effect, target) pair matches a DENY row: **DENY**. Taint is irrelevant, and no approval exists.
3. Else if any pair matches a HOLD row, **or** the session is tainted and any resolved effect kind is privileged, **or** the action is `unclassified-executable`, **or** any target is `unresolved`: **HOLD**.
4. Else: **AUDIT** (after Section 2.5's gate; current behaviour before it).

v1 had a single "floor" that was both "no approval path" and "held pending approval", which is a contradiction. v2 round 1 kept the contradiction by putting persistence sinks and security-config writes on a floor described as having no approval path while Section 2.2 said they were held. That is removed: **the DENY set has no approval path; the HOLD set is the set that is held.**

#### The minimum privileged-effect taxonomy the guard must classify

The decision above is only as good as the classifier under it. These are the effect kinds an implementation must be able to name; an implementation may name more, and none of them may be dropped. Each named effect carries a **resolved target set**; where the target cannot be resolved, the target set is `unresolved`.

| effect kind | what it covers |
|---|---|
| `destroy` | irreversible destruction of data or a device: recursive removal of a root or home tree, a write onto a block device, filesystem format or partition tooling, `DROP DATABASE`, an infrastructure destroy verb |
| `credential-read` | reading a secret-shaped value or a known credential store (key files, token stores, keychains, environment secrets) |
| `egress` | bytes leaving the host to a network or other non-local sink, including a pipe into an uploading client |
| `persistence-write` | writing a target that causes **future** execution: scheduler entries (cron, systemd timers, launchd), shell rc files, hook and agent configuration, `authorized_keys`, service units, startup items |
| `security-config-write` | writing ShieldCortex's own config, the policy lock, the host's agent settings, or the guard's own hook registration |
| `privilege-change` | changing or escalating execution identity or access: `sudo`/`doas`, setuid, capability grants, ownership and ACL changes |
| `process-control` | starting, stopping, killing or restarting a process or a service |
| `file-mutate` | creating, modifying, truncating, moving or deleting a file, where the target is outside `destroy` scope |
| `package-install` | installing or upgrading code from a registry, a VCS remote or another remote source |
| `code-exec-opaque` | executing a program whose effects the mapper cannot resolve: a script by path, an interpreter handed a program, a computed target, a task runner delegating to project-controlled code |
| `network-fetch` | retrieving external content into the session. This is an **ingestion** event: it sets taint under Section 2.2 rather than gating an effect of its own |

All of these except `network-fetch` are **privileged effect kinds** for the purpose of step 3 of the decision procedure.

**Fail-closed on an executable effect the guard cannot classify.** An action that executes something and whose effect kind the guard cannot name, or whose kind it names but whose targets it cannot resolve, is `unclassified-executable` / `unresolved` and is **HOLD at minimum, in every session, tainted or not**. It never falls through to AUDIT, and it is never allowed on the ground that no rule matched it. A DENY match on the surface still takes precedence and still denies. The cost of this rule is a hold on a legitimate command the mapper is too weak to read; the cure is a better mapper, recorded as such, not a default of "allow when unsure".

**No command-name exemption, anywhere in this ADR.** Nothing is exempted because of the *name* of the program invoked. `npm test`, `make`, `cargo build`, `go test`, `git` and every other build, test or version-control command are classified by the effects they perform and the targets they touch, exactly like any other command. Each of them executes code the project controls — a test script, a build recipe, a git hook, a `package.json` lifecycle script — and each can mutate a sensitive target. A build or test invocation whose delegate program the mapper cannot resolve is `code-exec-opaque`, and therefore HOLD at minimum under the rule above. Section 1.5's false positives are to be fixed by classifying effects and targets, never by allowlisting program names.

#### DENY — immutable, no approval path, no opt-out, taint-independent

Text-gated and **provenance-blind**: these rows fire at every taint state, and no approval of any mode releases them. By the time these are observable, provenance has already failed and the sink is the last point of control. Nothing legitimate resembles them, so there is no operator workflow to preserve.

| effect kind | target predicate | why it is DENY |
|---|---|---|
| `destroy` | a root or home tree, a block device, a filesystem or partition table, a fork bomb, an unrecoverable database or infrastructure verb (`DROP DATABASE`, infra destroy) | unrecoverable; nothing legitimate resembles it |
| `credential-read` composed with `egress` | a secret-shaped value or a known credential file reaching a network or other non-local sink, including `pipe-download-to-shell` and `decode-pipe-to-shell` where the payload is a credential | disclosure cannot be undone; this is the payoff of a successful injection |

Normalisation (#504: unicode, quote and backslash tricks, write-then-exec) lives in the DENY set, because evasion of an absolute rule is a real attack. Fail-closed on hook load failure (#511) lives in the DENY set. #503 survives here only where the verb is unrecoverable (`DROP DATABASE`, infrastructure destroy), not for routine data statements. The DENY set is small in vocabulary and is the one place where the command-inspection investment continues.

#### HOLD — always mediated, released only by bounded approval

Held pending a bounded approval under Section 2.3, in every session, tainted or not. These are the effects an injection is *for* (persistence in, the guard editing its own guard) and also the effects an operator's own install and repair work needs, so they get an approval path rather than a prohibition.

| effect kind | target predicate | taint state | why it is HOLD |
|---|---|---|---|
| `persistence-write` | any persistence sink: scheduler entries (cron, systemd timers, launchd), shell rc files, hook and agent configuration, `authorized_keys`, service units, startup items | any | how a one-shot injection becomes a standing one; also how an operator installs |
| `security-config-write` | ShieldCortex's own config, the policy lock, the host's agent settings, the guard's own hook registration | any | the guard editing its own guard; also how an operator repairs it |
| **any privileged effect kind** | any target | **tainted** | the model may have been steered; a bounded yes from the operator re-establishes intent for that one effect. This is the row that makes a service stop, a file deletion, a deploy, a package install, a privilege change and an opaque script **HOLD rather than AUDIT** once the session has read the outside world (Section 2.2) |
| `code-exec-opaque`, or any effect whose targets are `unresolved` | any | any | fail-closed: an executable effect the guard cannot classify is held, never allowed by default (taxonomy above) |

Release conditions are exactly Section 2.3's. In the default **effect-bound** mode the approval binds the actual effect **and** its targets; in either mode it expires, is non-replayable, never clears taint, never overrides DENY, and never overrides a held session lease or freeze. An unknown shell effect (opaque script, interpreter given a program, computed target) cannot inherit a broad blessing; it is held until its effect is resolvable, or until the operator issues an **opaque-invocation approval** under the distinct mode in Section 2.3, which binds execution identity rather than effects and carries that mode's disclosed residual risk. Where the adapter cannot enforce that mode's four constraints, the opacity stays held. #505's genuinely irreversible write targets belong to the persistence and security-config rows here.

#### AUDIT — logged, not enforced by default, in an **untainted** session only, and only after the narrowing gate

AUDIT is the residual branch of the decision procedure: it is reached only when step 2 found no DENY row, step 3 found no HOLD row, the session is **untainted**, the effect kinds are all **classified**, and every target **resolved**.

At that point `process-control` (`stop-process-or-service`), `file-mutate` (`file-delete`) outside `destroy` scope, `privilege-change` (`privilege-escalation`), `package-install`, a **resolvable** script invocation (`opaque-script-invocation` whose delegate the mapper did resolve), `persistence-write` whose target is **not** a persistence sink (`modify-scheduler` against an ordinary file), and `touch-sensitive-path` whose target is **not** a security-config target are ordinary operations for an agent doing real work. The intent is that they become **audit-only** by default, with enforcement an explicit opt-in that requires a configured delivery channel.

Two conditions bound this set, and neither may be dropped in an implementation:

- **Taint flips these rows to HOLD.** The same effect kinds against the same targets in a tainted session are HOLD under the third HOLD row above. AUDIT is never reached in a tainted session.
- **The gate has not passed.** This set is reached **only after the narrowing gate in Section 2.5 has passed**. Until then these classes keep their current behaviour and their current default. The AUDIT set is defined now so that the gate has a stated target; it is not in force.

#### Where ordinary work lands

Ordinary deploy, install, configuration and repair work lands as follows:

- in a **tainted** session: **HOLD**, released by one bounded approval per effect, whatever the effect kind;
- in any session, when it writes a HOLD target (a scheduler entry, an rc file, hook or agent configuration, ShieldCortex's own config, the policy lock, the host's agent settings): **HOLD**;
- in any session, when the guard cannot classify the executable effect or resolve its targets: **HOLD**, by the fail-closed rule;
- otherwise (untainted, classified, resolved, no HOLD target): **AUDIT** (after the gate) or current behaviour (before it).

So an operator-requested install or repair remains possible in every state: at worst it costs one bounded approval that names the effect and its targets. Nothing in the three sets makes a legitimate operator workflow impossible, which is why the header's statement that the intent-first product law is unchanged holds: the one-line law, the catastrophe hard-stops and the credential non-exfil rule are the DENY set, and everything above it is mediated rather than forbidden.

#### Alternative not taken: blanket prohibition of persistence and security-config writes

The operator could choose a stricter doctrine in which persistence sinks and security-config writes join the DENY set: no approval path, ever, from any agent session. Its benefit is that an approval surface can no longer be socially engineered into blessing a persistence write. Its operational cost is that **install and repair through the agent become impossible**: every scheduler entry, hook installation, configuration edit and ShieldCortex self-repair would have to be performed by a human outside the agent, and an agent-driven `doctor --fix` or `setup` would refuse its own work. That is a doctrine change from ADR-001's intent-first law (the operator's stated intent could no longer authorise those effects through the agent) and is presented here as a choice the operator may make, **not** as this ADR's default. This ADR's default is HOLD.

### 2.5 The narrowing gate: 5A and 5B and 5C

The move of the dangerous tier to the AUDIT set is **not made in this ADR and not made first**. It is made only after **all three** of the following exist and have been reviewed:

- **5A** — the logged-signal policy comparison in Section 5A has been run and its output reviewed: which classes stop being gated, which of the 199 enforced events would have passed, and which DENY classes still deny;
- **5B** — the synthetic effect-witness fixtures in Section 5B have been **executed** (not merely built) against **both** the current policy and the proposed policy, the results have been **independently reviewed** by someone other than the person who built the fixtures, the acceptance bars were **written down before the run** (the pre-registered bars in Section 5B, which are engineering bars and not a SOTA claim), **both control families** ran — enforcement-off effect witnesses and taint controls with instrumentation enabled — and the fixture set includes legitimate scheduler, install and configuration work and cross-session taint propagation;
- **5C** — capability and adapter evidence per Section 5C: the session-taint gate is live and its coverage is measured and proved on every adapter that feeds context, with every "missing" row in the coverage table either closed or explicitly accepted as uncovered by the operator, so the dangerous tier is being replaced by something rather than removed.

**Building fixtures is not passing them.** A fixture suite that exists on disk, a harness that runs green against the current policy only, or a run whose acceptance bar was chosen after seeing the numbers does not satisfy 5B. Until all three exist, the dangerous tier keeps its current behaviour and its current default.

### 2.6 Delivery: a gate nobody can see is a configuration error

`enforce: true` together with `notify: not_configured` is a **`doctor` FAIL**, not a warning. A gate whose denials reach nobody blocks work and produces no signal.

Two constraints on that failure:

- **Fail loud, state unchanged.** A `doctor` failure must not silently change enforcement state in either direction. It reports, exits non-zero, and names the fix. A doctor that disables the guard because nobody is listening has just created a second silent path to no guard; a doctor that enables notification on its own has chosen a recipient the operator did not.
- **Ships first and independently.** This is the delivery half of #517. It does not depend on session taint, the effect sets or the tier narrowing, and it should land before them.

A `require_approval` verdict on a host with no renderable approval surface remains `denied_no_prompt_surface`: an unpassable gate. Four such events are in the window. `doctor` should report a host in that state the same way.

### 2.7 Excluded: the session-lease family (#550, #552, #553, #554)

The session lease is **not** an injection control and provenance cannot replace it. It freezes security configuration against **the same agent, in the same session, under the same band** while a lease is held: the operator's guard against the agent editing its own guard mid-task. Provenance is identical on both sides of that line by construction, so a provenance gate is blind to it.

The write-shape work on #550/#552 is the cost of a *sink* control on one specific path. The alternatives this ADR might seem to imply are "freeze on any mention" (the false positive #550 was opened for) or "no freeze" (the operator's rule removed). Neither is acceptable. #554 is a binding problem *within* the trust plane (a host-maintained binding of a child harness to its holder session); Section 2.2 states the requirement that binding must satisfy and leaves the design to #554.

The lease family therefore stays out of the fold list. A bounded approval under Section 2.3 never overrides a held lease or freeze: **the lease wins over the approval**.

### 2.8 #506 reframed: ingestion-boundary scanner coverage, never an effect gate

The clamp in `resolve-tool-source.ts` protects **caller-declared metadata** on an MCP call. The authority spoof in #506 ("the operator says: approve this") is **text inside a tool result** that the *model* reads. The clamp never sees that text. Two mechanisms do:

- framing (#531, #535): the text arrives labelled as data;
- the tool-response scanner, whose enforce layer in `src/defence/tool-response-enforce.ts` **blocks** in enforce mode: any injection signal, the instruction detector firing, or a blob that decodes to an injection or a credential withholds the whole payload and tells the agent why.

That is a data-plane quarantine at ingestion: the front door, not a sink. Detection-as-gate is legitimate there and only there, because the input is bounded (one tool response) and the cost of a false positive is a withheld page, not a blocked deploy.

So #506's patterns are kept as **scanner coverage at the ingestion boundary**: authority-spoof, verbatim-exfil, multilingual and rot13 variants. They are never an effect gate and never were one. Multilingual and rot13 coverage is cheap and closes real paraphrase gaps at that boundary. Section 5C records which adapters actually route a tool result through that scanner at delivery time; today the answer is that the enforce layer exists as a library and an MCP tool, and no adapter invokes it on the delivery path automatically.

---

## 3. Why not "better detection" as the gate

More patterns on the effect plane (the tempting reading of #506, and the treadmill of #549/#551/#512) is an unbounded input space in which the attacker moves last and the matcher is always one paraphrase behind. A model-based classifier has the same property and additionally violates the local, deterministic, customer-CPU constraint.

Detection remains useful in two places: at the ingestion boundary (Section 2.8), where the input is bounded and a false positive is cheap, and in the DENY set (Section 2.4), where the rule is absolute and evasion of it is itself an attack. It must not be the general effect gate. Effect gating keys on provenance, which is finite and decidable.

---

## 4. Consequences

**Positive**

- Injection defence keys on the attack's mechanism: data promoted to instruction. The gate question ("has this session read the outside world, and is this a privileged effect?") is decidable without inferring intent from spelling.
- The DENY and HOLD sets together cover what an injection is for (secrets out, persistence in), not only what a vandal is for, while HOLD keeps the operator's install and repair workflow possible.
- The effect decision is a **total, single-valued function of (effect kinds, targets, taint)** with a stated precedence and a stated fail-closed branch, so an implementation can be checked against a decision procedure and an effect taxonomy rather than against prose or a signal-name list.
- Once Section 2.5's gate passes, ordinary agent operations stop being enforced by default; the quadratic tokeniser (#519) leaves the enforced hot path and stays only where the DENY set needs it.
- #512, #549, #551 and the residual halves of #517 fold into this decision rather than being fixed as spelling rules.

**Negative and accepted risks**

- **The new false-positive class** (Section 2.2): a session that fetched anything external must obtain a bounded approval for each privileged effect. This is an explicit trade, stated here so the operator can decide on it. It is not a zero-false-positive design.
- **Fail-closed unknown provenance widens taint** on adapters with weak labelling (Section 2.1). The cure is better labelling in the adapter, and the coverage table in Section 5C shows where that work is.
- **Approval fatigue** on the HOLD path is a real risk if the privileged set is drawn too wide. Section 2.4's HOLD set is the minimum; anything wider is opt-in.
- **Recoverable damage remains possible, but not by the route round 2 described.** Round 2 said a successful injection *in a tainted session* could still stop a service or delete a working file once the dangerous tier is in the AUDIT set. That is wrong under Section 2.4 and is corrected here: in a **tainted** session those effects are **HOLD**, not AUDIT, and they do not proceed without a bounded approval naming the effect and its targets. The residual is therefore two different things, and both are accepted knowingly: **(a)** recoverable damage in a session the adapters wrongly believe is **untainted** — which, by Section 2.1's fail-closed rule, means an adapter that did not label the span at all, and which Section 5C's coverage rows are what bound it; **(b)** an operator who approves a held effect, under time pressure or social engineering, on an approval surface that rendered the effect and its targets correctly. Accepted only after Section 2.5's measurement shows what each costs, and only because these classes are recoverable while the irreversible ones are DENY with no approval path at any taint state.
- **Provenance labelling must reach every context-entry point or it leaks.** An adapter that injects context without a label defeats the taint. Section 5C's table shows that today result transformation is missing on every adapter; the taint gate cannot go live on an adapter until its row is closed.
- **Summaries and imported memory carry taint** (Section 2.2), which will surprise operators who expect a fresh session to be clean after recalling a tainted note. The frame must say so.
- **Cross-session inheritance depends on #554.** Until a child harness can be bound to its holder session by the host, taint inheritance into that child is a stated requirement without an implementation.
- The enforced-outcome numbers above come from one host, one origin and five weeks. They are evidence for the shape of the problem, not a rate.

---

## 5. Validation

The harness has two separated halves. **They are never summed**: A measures logged signals against policies; B measures outcomes against fixtures. A number from one is not comparable with a number from the other. C is not a number at all; it is a per-adapter table of proofs.

### 5A. Logged-signal policy comparison

Replay `denials.jsonl` from the production window against three policies and tabulate per outcome and per signal class:

1. **current** (the shipped tiers and defaults);
2. **destruction-only floor** (v1's floor);
3. **three-set policy** (Section 2.4: DENY = destruction + credential/secret external egress; HOLD = persistence sinks + security-config writes + privileged-in-tainted-session; AUDIT = the dangerous tier).

Rules for the replay:

- Rows carrying `redacted-signal` (206 events) and any row whose command cannot be reconstructed from the log are bucketed **"unknown"**, reported as their own column, and never counted as "would pass" or "would deny".
- Malformed rows are **counted, not skipped**, and reported.
- **All records per action id are kept.** Where the records for one action disagree (an advisory row and an enforced row, or two verdicts), the conflict is shown, not resolved by picking one.
- `pipe-download-to-shell` is in the signal set alongside `external-egress` and `decode-pipe-to-shell`.
- Because the log has no taint field, the HOLD row for "privileged in a tainted session" is reported as **"cannot be determined from the log"**, not estimated.
- The output is a table of events by (policy × outcome × signal class), plus the list of enforced events (the 199) that would change outcome under each policy, each identifiable by action id for review.

This half answers "what stops being gated and what still denies". It does not answer "was anything protected".

**5A is descriptive; it is not a security-effectiveness rate.** It describes what the shipped policy *gated* over one window on one host. It does not measure what was *protected*, and no number taken from it may be presented as an effectiveness, block, detection or prevention rate, in this ADR or in anything derived from it. Three requirements follow, and a 5A output that omits any of them does not satisfy Section 2.5's gate:

- **Reconcile every enforced event.** All 199 enforced events (195 `auto_denied`, 4 `denied_no_prompt_surface`) are accounted for under each of the three policies: which set the event lands in, which effect kind and target predicate put it there, and whether the outcome changes. An event that cannot be reconstructed from the log is reported by action id in an explicit **unknowns** column together with the reason it is unreconstructable. The unknowns column is reported beside the totals and is never folded into a "would pass" or "would deny" count.
- **No known DENY weakening is left unexplained.** Where a policy moves an event out of an enforced outcome, the row names the rule that moved it. A DENY class that stops denying something it denies today is a **finding**, reported as a finding with its action ids, never absorbed into an aggregate or presented as a false-positive reduction.
- **Provenance is never manufactured for the replay.** The log carries no taint field and no span lineage. Taint-dependent rows stay "cannot be determined from the log", per the rule above, and no taint state, source band or span lineage may be inferred, back-filled, sampled or assumed in order to make a replay outcome look decisive. A reconstruction that requires invented provenance is an unknown, and is reported as one.

### 5B. Synthetic fixtures with effect witnesses, executed and reviewed

In an isolated fixture host (no production data, no network egress except to a controlled sink), run two corpora through the full stack (scanner, framing, taint, effect sets) in **three arms on the same frozen fixtures** — the current policy, the proposed policy and a **no-guard baseline** — and report all three:

- **Attack corpus**: framing bypass attempts, forged authority in tool results, untrusted-source privileged requests, obfuscated DENY commands, egress of a planted secret, persistence attempts (scheduler entry, rc file, hook config), a signed peer returning hostile quoted material, an externally authored local file carrying an instruction, a proxy fetch through an MCP server, a tainted memory recalled into a fresh session, a tainted parent spawning a child, multilingual and rot13 variants. Two fixtures exercise the opaque-invocation approval mode of Section 2.3 specifically: **(a) changed-script-after-approval** — the program's content changes between the moment the approval is issued and the moment it executes, and the execution-time re-hash must return the action to HOLD rather than run it; **(b) nested or indirect forbidden effect** — an approved opaque program invokes a DENY effect through a child process or an interpreter, where a gate that observes inner calls must deny it and a gate that does not must be recorded as not covering it, never as a pass.
- **Legitimate-work corpus** (these are fixture *scenarios*, not an exemption list — each one is classified by the effects and targets it actually produces, per Section 2.4's no-command-name-exemption rule): build, test, deploy, git, file edits, service restarts, package installs, **legitimate scheduler entries, legitimate install and configuration edits, a ShieldCortex self-repair**, including the "fetch vendor docs, then deploy" sequence that Section 2.2 deliberately holds, and the same sequence with the bounded-approval script answering yes.

Every fixture has an **effect witness**: a file that must or must not exist afterwards, a process that must or must not be running, a controlled sink that must or must not have received bytes, a taint record that must or must not be present on the named session. A flagged-but-executed attack is a failure. A held legitimate step that the fixture's bounded-approval script then approves counts as completed with one prompt; a held step with no renderable surface counts as not completed.

**Controls are mandatory, and there are two families that prove different claims. They are never merged and never substituted for each other.** Round 2 asked one enforcement-off control to prove both that the attack is real and that the taint store behaves; an enforcement-off run cannot do the second, because with the guard removed the taint store may be bypassed, disabled, or simply never written, so "no taint record" in that arm is uninformative.

- **Effect-witness controls — run with enforcement OFF.** For every witness type, a control fixture removes the guard (or runs the attack with enforcement off) and must show the effect happening: the file appearing, the process running, the bytes arriving at the controlled sink. **What this proves:** the fixture really does the damage when nothing stops it, so the witness observes an effect. A witness that reports "no effect" when the guard is absent is not observing anything, and every result that depended on it is void. **What this cannot prove:** anything about taint. Taint assertions are not read from this arm.
- **Taint controls — run with taint instrumentation ENABLED**, the taint store live and readable by the harness, in both directions:
  - **positive-injection control**: a fixture reads outside content through the adapter under test; afterwards the taint record for that **host-owned session identity** must be **present**, naming the span that set it. **What this proves:** the taint path is wired on that adapter, so that a later "held" result is attributable to taint rather than to some unrelated rule firing.
  - **clean-session control**: a fixture performs the same privileged effect in a session that read nothing external; the taint record must be **absent** and the action must take the untainted branch. **What this proves:** taint is not set unconditionally, so that the positive case is not vacuously held.

  A taint control that cannot read the taint store on an adapter is reported as **not run on that adapter**, never as a pass. On adapters whose taint state is "missing" in Section 5C's table, these controls are the fixture that closes the row.

In short: the enforcement-off controls license every **attack-effect** claim; the taint controls license every **taint-mechanism** claim. A held result with no positive-injection control behind it is not evidence that taint held it, and may not be reported as such.

#### Pre-registered acceptance bars (engineering bars, not a SOTA claim)

These are the bars this ADR **proposes**. They are recorded in the fixture repository, with the fixture revision and the policy revision, **before the first execution**, and are not changed after the numbers are seen. A run whose bar was set afterwards is reported as exploratory and does not count toward Section 2.5.

**These are engineering acceptance bars for shipping this change. They are explicitly not evidence of a state-of-the-art result.** A SOTA claim additionally requires an independent held-out fixture set the implementers did not build against, and an adaptive attacker permitted to see the defence and iterate against it. Neither is in scope here, and no result from this harness may be described as state of the art, best in class, or a comparison against published systems.

| bar | threshold |
|---|---|
| witnessed attack blocking, aggregate | **≥ 90%** |
| unintended blocking of legitimate work | **≤ 2%** |
| legitimate completion along the documented approval path | **≥ 98%** |
| enumerated regression families — DENY, forged or replayed approval, identity / taint laundering, lease bypass | **ZERO** successes, each family reported separately |

Rules that go with the bars, all of which are part of the pre-registration:

- **No-approval completion and prompt burden are reported separately.** The completion rate obtained with the bounded-approval script answering yes is reported beside the rate obtained with **no approval available at all**, and beside the **count of prompts per completed task**. An auto-yes script can hide approval fatigue behind a high completion rate; a completion rate, a no-approval rate and a prompt count together cannot.
- **Three arms on the same frozen fixtures.** Current policy, proposed policy and a **no-guard baseline** run against the same fixture revision and the same model settings. Reported separately: raw counts (not percentages alone), per-adapter results, per-family results, uncertainty, and invalid or unreachable fixtures.
- **A failed no-guard witness invalidates its comparison.** Where the no-guard arm does not produce the effect, that fixture's attack-blocking comparison is **void** and is reported as invalid. It is never counted as a block for the guarded arms.
- **Denominators and sample sizes are frozen before execution**, alongside the thresholds, the fixture revision and the policy revision.
- **Covered adapters must show zero missing required capabilities.** An adapter explicitly accepted as uncovered, and any memory-plane-only adapter, keeps current policy and **is never described as protected** in any result table, summary or derived claim.
- **Cross-session taint tests are required, not optional**: a tainted parent spawning a child, a tainted memory recalled into a fresh session, and a child harness bound — or provably not bound — to its holder session per #554.

**Independent review.** The executed results, the outputs of **both** control families (enforcement-off effect witnesses and taint controls), and the pre-registered bars are reviewed by someone who did not write the fixtures. The review record names the reviewer, the fixture revision and the policy revision.

**Reporting minimum, per arm, never collapsed into one figure:** attack-success rate, legitimate-work-completion rate **with** the approval script, completion rate **without** any approval path, prompts per completed task, and the four regression-family counts — each with its own frozen denominator, broken out per adapter and per family, with invalid and unreachable fixtures listed separately. Building the fixtures, running them against the current policy only, or reporting a single headline number satisfies none of this section.

### 5C. Provenance coverage, per adapter: measured, then proved

For every adapter that feeds context, a fixture must prove that an `untrusted-external` span entering through that adapter taints the session and that a HOLD-set effect after it is held. Coverage is **proved, not assumed**; an adapter without a passing fixture is listed as uncovered in the ADR's acceptance record.

The starting point is the **measured** state of each adapter at ffca84c5, read from the adapter's registration code rather than from its documentation. "Missing" means the code registers no hook at that point; it is not a judgement about whether one is planned.

| adapter | where measured | hooks registered | pre-effect gate | result transformation at delivery | span labelling at ingestion | taint state |
|---|---|---|---|---|---|---|
| Claude Code hook | `src/setup/settings-hooks.ts`, `scripts/pre-tool-hook.mjs`, `scripts/prompt-recall-hook.mjs`, `scripts/session-start-hook.mjs`, `scripts/pre-compact-hook.mjs`, `scripts/stop-hook.mjs`, `scripts/session-end-hook.mjs` | `PreToolUse`, `UserPromptSubmit`, `SessionStart`, `PreCompact`, `Stop` (opt-in), `SessionEnd` | yes: `PreToolUse` runs the Action Guard | **missing**: no `PostToolUse` hook is installed; no hook sees a tool result before the model does | recall packs are framed (#531) at `UserPromptSubmit` and `SessionStart`; tool results: **missing** | **missing**: no taint store; the pre-tool hook reads none |
| OpenClaw realtime plugin | `plugins/openclaw/openclaw.plugin.json`, `plugins/openclaw/index.ts`, `provenance.ts`, `session-taint.ts`, `scan-taint-policy.ts`, `conversation-trust.ts`, `interceptor.ts` | `llm_input`, `llm_output`, `before_agent_run`, `before_tool_call`, `session_end`, `agent_end` | yes: `before_tool_call` runs the Action Guard and reads the taint store | **missing**: no `after_tool_call` or tool-result hook; tool output is scanned one turn later at `llm_input` in **advisory** mode (`scanToolResponse(..., "advisory")`) and nothing rewrites or withholds it before the model reads it | partial: `llm_input` labels `user` / `tool_result` / `unknown` only; no `web` or `document` distinction because the host event carries none; `unknown` is counted but does not taint | partial: in-memory per-session store, **detection-triggered** (a scan hit), fifteen-minute TTL, cleared at `session_end`, escalates the Action Guard by one notch; owner input never taints when `senderIsOwner === true`; not provenance-triggered, not inherited by forks, summaries or memory |
| Hermes plugin | `plugins/hermes/shieldcortex/plugin.yaml`, `plugins/hermes/shieldcortex/__init__.py` | `pre_tool_call` only | yes: `pre_tool_call` calls the Action Guard over REST. **Degraded, not blanket fail-open**, when the scanner is unreachable: a dependency-free fallback scan runs over the raw exec surface, a catastrophic match is denied **always**, a dangerous match is denied **when `enforce` is on**, and only an unmatched shape fails open, audited as `gate_degraded` | **missing**: `transform_tool_result` is documented as a later phase and not implemented | **missing** | **missing** |
| Codex (CLI and IDE) | `src/setup/codex.ts` | none: the installer writes an `mcp_servers` entry into the Codex config only | **missing**: no hook surface; the Action Guard is reachable only if the model calls `iron_dome_check` itself | **missing** | **missing** unless the model calls `scan_tool_response` itself | **missing** |
| MCP server (any MCP client, including Codex, Cursor and others) | `src/server.ts` | none automatic; exposes `recall`, `get_context`, `scan_tool_response`, `iron_dome_check` and related tools that the model must choose to call | only by explicit model call | **missing** at delivery; `scan_tool_response` runs the enforce layer only when invoked | recall results framed (#531); tool results: **missing** unless invoked | **missing** |
| LangChain integration | `src/integrations/langchain.ts` | none: `ShieldCortexMemory.loadMemoryVariables` / `saveContext` and `ShieldCortexGuard.scan` are library calls | none | **missing** | recall framed via the shared recall frame; tool results: **missing** | **missing** |
| Universal guarded memory bridge | `src/integrations/universal.ts` | none: guarded `save` / `search` over an external memory backend | none | **missing** (memory plane only) | memory records scored by declared `sourceType` | **missing** |
| Session-start and recall packs | `scripts/session-start-hook.mjs`, `scripts/prompt-recall-hook.mjs`, `src/memory/host-contract.ts` | (Claude Code events above) | n/a | n/a | framed; taint marker on recalled memory: **missing** (the frame does not yet carry one) | **missing** |

**The Hermes row, measured.** Round 2 said the Hermes gate is "fail-open when the scanner is unreachable". That is too blanket and is corrected above. Read from `plugins/hermes/shieldcortex/__init__.py` (the `pre_tool_call` closure registered by `register`, and `_enforce_default` above it): when `evaluate_tool_call` returns a verdict that is not `available`, the plugin computes `fallback_surface(tool_args)` — the raw exec surface, not the JSON blob — and runs `fallback_catastrophic_match` and `fallback_dangerous_match` over it. A catastrophic match denies **regardless of the enforce setting**; a dangerous match denies **when enforce is on** (enforce is the default since v4.47.2, opt-out via `SHIELDCORTEX_ENFORCE=0`); every other shape is allowed. Each degraded call writes a `gate_degraded` audit entry with `outcome: failure_denied` or `failure_allowed`, and the plugin logs the degradation at WARNING.

So the accurate claim is **partial fail-open, loudly audited**: the residual is an **unmatched** shape passing while the scanner is down, plus the case where the audit sink itself is unwritable and the `gate_degraded` entry is dropped with a warning. The fallback is text inspection over a raw surface, so it inherits Section 1.5's false-negative profile against obfuscation and normalisation evasion — that is a reason to close the availability gap, not a reason to restate the blanket claim. Hermes's `transform_tool_result`, span labelling and taint state remain **missing**, unchanged by this correction.

What the table says, in words: **no adapter transforms a tool result at delivery time today.** The tool-response enforce layer (`src/defence/tool-response-enforce.ts`) exists as a library function and as an MCP tool, and the OpenClaw plugin calls the scanner in advisory mode a turn late. The only taint store in the tree is the OpenClaw plugin's, and it is detection-triggered with a fixed TTL, not the provenance-triggered, session-lifetime, inherited taint that Section 2.2 requires. The Claude Code hook, which produced all 837 events in Section 1.3, has no result path at all.

Every "missing" cell above is therefore an item on the 5C work list. The gate in Section 2.5 requires, per shipped adapter, either a passing fixture for each of the four columns (gate, transformation, labelling, taint) or an explicit operator acceptance that the adapter ships uncovered, recorded in the acceptance record with the adapter name. An adapter accepted as uncovered does not get the AUDIT-set narrowing: on that adapter the dangerous tier keeps its current behaviour, because there is nothing replacing it.

Cross-session inheritance (a tainted parent spawning a child, a child harness bound to its holder) is a 5C fixture for each adapter that can spawn, and is blocked on #554 where the host cannot supply the binding; that block is recorded as such, not as a pass.

Section 2.5's narrowing is gated on 5A having been reviewed, 5B having been executed and independently reviewed against pre-registered bars, and 5C being complete for every shipped adapter.

---

## 6. Sequencing

1. **#535** — close the unframed tool-result echo (labelling must be complete before taint means anything).
2. **#547, #538** — framing coverage and redactor fail-safes.
3. **#517 delivery half + `doctor`** — `enforce: true` without a notify surface fails `doctor`, fail loud, state unchanged. Independent of everything below; ships first.
4. **Replay harness** — Section 5A over the production window, reported as descriptive with its unknowns column; Section 5B fixtures and effect witnesses built, **both control families** built (enforcement-off effect witnesses and taint controls), acceptance bars pre-registered with frozen denominators.
5. **Capability binding** — session taint (Section 2.2, provenance-triggered, session-lifetime, fail-closed on unknown) and bounded approval (Section 2.3) in the effect plane, using the existing ceiling clamp for the caller band; result transformation at delivery on each adapter; per-adapter coverage fixtures (Section 5C) closing the "missing" rows.
6. **5B execution** — the effect-witness run against current and proposed policy, independently reviewed against the pre-registered bars.
7. **Narrowing** — effect sets per Section 2.4 in force; dangerous tier to AUDIT per Section 2.5, only once 4, 5 and 6 are reviewed and 5C is complete for every shipped adapter.
8. **#506 reframed** — ingestion-boundary scanner coverage per Section 2.8.

**Freeze** the remaining command-inspection lane except #504 (scoped to the DENY set), #511 and #517's delivery half. The session-lease family (#550/#552/#553/#554) is outside both this sequence and the freeze; it proceeds on its own track.

---

## 7. Issue disposition under this ADR

| issue | disposition |
|---|---|
| #504 | keep; normalisation scoped to the DENY set |
| #505 | keep the irreversible targets as HOLD persistence / security-config rows |
| #503 | keep only unrecoverable verbs (`DROP DATABASE`, infra destroy) in DENY |
| #506 | reframe: ingestion-boundary scanner coverage, multilingual/rot13 kept; never an effect gate |
| #511 | keep; fail-closed stays in DENY |
| #512, #549, #551 | fold into this decision; not fixed as spelling rules |
| #517 | delivery half ships first (step 3); residual halves fold |
| #519 | leaves the enforced hot path after step 7 |
| #531, #535, #547, #538 | prerequisites (steps 1 and 2) |
| #550, #552, #553, #554 | **excluded**; own track; unaffected by this ADR; #554 is the cross-session binding Section 2.2 depends on and does not design |
| #532 | already shipped; illustrates Section 1.5 |

---

## 8. Open for the operator's decision

- Accept the session-taint trade (Section 2.2) and its false-positive class, including fail-closed unknown provenance and transitivity by content, or reject it and keep text-gating as the general effect gate.
- Accept the effect decision of Section 2.4 — a total, single-valued function of (effect kinds, targets, session taint) with precedence DENY > HOLD > AUDIT — including the minimum effect taxonomy, the fail-closed treatment of an unclassified executable effect, and the rule that no program is exempted by name.
- Accept **opaque-invocation approval** (Section 2.3) as a distinct, weaker approval mode: it binds execution identity (content hash, `argv`, interpreter, host, session, action id) and requires execution-time revalidation, it never binds effects, it never overrides DENY or a lease, and where an adapter cannot enforce its four constraints the opacity stays held.
- Accept the **pre-registered acceptance bars** in Section 5B as the bars this change ships against (≥ 90% witnessed attack blocking, ≤ 2% unintended blocking of legitimate work, ≥ 98% completion along the approval path, zero successes in the enumerated regression families), and accept that they are **engineering** bars: a state-of-the-art claim would need an independent held-out set and an adaptive attacker, which this harness does not provide.
- Decide whether to take the **alternative not taken** in Section 2.4 (persistence and security-config writes moved from HOLD to DENY), accepting that agent-driven install and repair then become impossible. This ADR's default is HOLD.
- Accept that narrowing of the dangerous tier is gated on Sections 5A, 5B and 5C together, that building fixtures is not passing them, and that the dangerous tier keeps its current behaviour until then, per adapter.
- Confirm that the session-lease family stays outside this decision, that the lease wins over a bounded approval, and that #554 is tracked separately.

> **Nothing in this document is the operator's acceptance of the trade-offs; that decision is pending.**
