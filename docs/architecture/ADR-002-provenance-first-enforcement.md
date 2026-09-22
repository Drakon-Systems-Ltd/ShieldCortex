# ADR-002: Provenance-first enforcement (v2)

**Status:** Proposed
**Date:** 2026-09-22
**Author of v1:** TARS (issue #556). **v2 fold:** author-side objections recorded on #556 and the convergence agreed between the two on 2026-09-22.
**Reviewer:** TARS. **Decision:** operator.
**Evidence:** #555. **Supersedes for review purposes:** the v1 text in the body of #556.
**Relates to:** ADR-001 — the intent-first doctrine at `docs/design/2026-08-24-intent-first-doctrine.md` and its companion target architecture. This ADR changes the enforcement *mechanism* under that doctrine; it does not change the doctrine's one-line law, its catastrophe hard-stops or its credential non-exfil rule.

**Revision:** v2 round 2 — addresses review at ffca84c5: disjoint DENY/HOLD/AUDIT, fail-closed unknown provenance + transitive taint, 5B required, measured adapter coverage.

| round | head | what changed |
|---|---|---|
| v2 round 1 | ffca84c5 | first fold of #556 v1 with the author-side objections (Section 0) |
| v2 round 2 | this revision | Section 2.4 restructured into three disjoint effect sets with precedence DENY > HOLD > AUDIT; Sections 2.1/2.2 restated as a taint and lineage contract (unknown provenance fails closed, taint is transitive by content, taint state bound to host-owned session identity); Section 2.5 narrowing gate now requires 5A and 5B and 5C; the "SC already sees every tool response" assertion replaced by the measured per-adapter coverage table in Section 5C; Section 8 records the alternative not taken |

> **Nothing in this document is the operator's acceptance of the trade-offs; that decision is pending.**

Numbering note: this is the first file under `docs/architecture/`. Earlier decision records live under `docs/design/` (for example `ADR-2026-08-19-retry-control.md`) and keep their names; "ADR-001" is the label #556 gives the intent-first doctrine, not a file.

---

## 0. What changed from v1

| v1 (#556 body) | v2 (this document) | Why |
|---|---|---|
| "837 events … Notifications actually delivered: 0"; read as 837 gates | 837 distinct events = 638 warned (advisory) + 195 auto_denied + 4 denied_no_prompt_surface; `notify: not_configured` 837/837 describes the notification channel only | The tally mixed advisory and enforced outcomes. The log does not support reading the total as a count of blocked actions. |
| Gate keys on the lowest-band *span in the causal context* of a tool call | Gate keys on **session taint**: once any `untrusted-external` span has entered context, HOLD-set effects are held pending bounded approval | The trust plane's ceiling is per-process. No harness links a context span to the tool call it caused. |
| Floor = catastrophic destruction only | Three **disjoint** effect sets, precedence DENY > HOLD > AUDIT: DENY (destruction + credential egress, no approval path), HOLD (persistence sinks, security-config writes, anything privileged in a tainted session; released only by bounded approval), AUDIT (the dangerous tier, after the narrowing gate) | An injection wants secrets out and persistence in, not a formatted disk; but persistence and config writes are also how an operator installs and repairs, so they need an approval path rather than a prohibition. |
| Dangerous tier → audit-only now | Dangerous tier → audit-only **only after** the logged-signal replay (5A), the executed and reviewed effect-witness run (5B) and per-adapter coverage evidence (5C) | Narrowing must be measured, not argued. |
| `notify: not_configured` + `enforce: true` fails `doctor` | Same, and the failure must **not** change enforcement state; ships first and independently | A doctor that silently flips enforcement is a second way to lose the gate. |
| #550/#552/#553/#554 fold into this decision | **Excluded.** Same agent, same session, same band on both sides; provenance cannot replace that sink control | Different threat, different control. |
| #506 reframed as "labels and capability, not patterns" | #506 reframed as **ingestion-boundary scanner coverage** (`tool-response-enforce` blocks in enforce mode); never an effect gate; multilingual/rot13 coverage kept | The clamp never sees text inside a tool result; the scanner does, at the front door. |
| Validation: replay + agent-work corpus + injection corpus | Two separated halves, never summed: logged-signal policy comparison and synthetic effect-witness fixtures; provenance coverage measured per adapter | Signal counts and outcome measurements answer different questions. |
| (implicit) ShieldCortex already sees every tool response and every memory injection | **Measured** per-adapter coverage table (Section 5C): which hooks each adapter registers, whether a result transformation exists, and "missing" where it does not | The claim was asserted, not measured; measurement shows result transformation is missing on every adapter. |

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

**Rule.** When any span labelled `untrusted-external` (including, by Section 2.1, any span whose provenance is unknown or missing) enters a session's context, the session becomes **tainted**. While tainted, every HOLD-set effect (Section 2.4, which includes any privileged effect requested in a tainted session) is **held** pending a bounded approval (Section 2.3). DENY-set effects are denied regardless of taint. AUDIT-set effects proceed and are audited with the taint flag on the row.

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

An approval issued against a held effect:

- **binds the actual effect and its targets**: the resolved command or write, the files, hosts, services or scheduler entries it touches; not a class, not a pattern, not "this kind of thing";
- **expires**: a short window, a single use, or both;
- **is non-replayable**: consumed on use, tied to the action id it was issued for, useless against a later identical string;
- **cannot bless an unknown**: a shell effect the mapper cannot resolve (an opaque script, an interpreter given a program, a computed target) cannot inherit a broad approval; it is held until its effect is known or the operator approves that exact opaque invocation with the opacity stated;
- **never clears taint**;
- **never overrides the DENY set** (Section 2.4): there is no approval that turns a DENY into an allow;
- **never overrides a held session lease or freeze** (Section 2.7): where an approval and a lease disagree, the lease wins.

The existing retry-control design (`docs/design/ADR-2026-08-19-retry-control.md`: mint on operator intent, denial produces a claim ticket not a grant, catastrophic tier has no path) is the shape to extend. An approval surface that cannot render the effect and its targets cannot issue a bounded approval; on such a host a held effect stays held, as `denied_no_prompt_surface` does today.

### 2.4 Three disjoint effect sets: DENY, HOLD, AUDIT

Every effect class the guard can name belongs to **exactly one** of the three sets below. Where a single action carries effects from more than one set, precedence is **DENY > HOLD > AUDIT**: the most restrictive set present decides the outcome. The sets are disjoint by construction; a class listed under one may not also appear under another, and an implementation that finds a class in two lists has a bug, not a policy choice.

v1 had a single "floor" that was both "no approval path" and "held pending approval", which is a contradiction. v2 round 1 kept the contradiction by putting persistence sinks and security-config writes on a floor described as having no approval path while Section 2.2 said they were held. That is removed: **the DENY set has no approval path; the HOLD set is the set that is held.**

#### DENY — immutable, no approval path, no opt-out

Text-gated, provenance-blind, always enforced. By the time these are observable, provenance has already failed and the sink is the last point of control. Nothing legitimate resembles them, so there is no operator workflow to preserve.

| class | examples | why it is DENY |
|---|---|---|
| catastrophic destruction | `rm -rf /` and equivalents against root or home, fork bomb, `dd` onto a block device, filesystem format or partition tooling | unrecoverable; nothing legitimate resembles them |
| credential and secret **external** egress | a secret-shaped value or a known credential file leaving over the network; `pipe-download-to-shell` and `decode-pipe-to-shell` where the payload is a credential | disclosure cannot be undone; this is the payoff of a successful injection |

Normalisation (#504: unicode, quote and backslash tricks, write-then-exec) lives in the DENY set, because evasion of an absolute rule is a real attack. Fail-closed on hook load failure (#511) lives in the DENY set. #503 survives here only where the verb is unrecoverable (`DROP DATABASE`, infrastructure destroy), not for routine data statements. The DENY set is small in vocabulary and is the one place where the command-inspection investment continues.

#### HOLD — always mediated, released only by bounded approval

Held pending a bounded approval under Section 2.3, in every session, tainted or not. These are the effects an injection is *for* (persistence in, the guard editing its own guard) and also the effects an operator's own install and repair work needs, so they get an approval path rather than a prohibition.

| class | examples | why it is HOLD |
|---|---|---|
| persistence sinks | scheduler entries (cron, systemd timers, launchd), shell rc files, hook and agent configuration, `authorized_keys` | how a one-shot injection becomes a standing one; also how an operator installs |
| security-config writes | ShieldCortex's own config, the policy lock, the host's agent settings | the guard editing its own guard; also how an operator repairs it |
| **any privileged effect requested in a tainted session** | a deploy, a service restart, a package install, a file delete, a privilege escalation, an opaque script, when the session has read the outside world (Section 2.2) | the model may have been steered; a bounded yes from the operator re-establishes intent for that one effect |

Release conditions are exactly Section 2.3's: the approval binds the actual effect **and** its targets, expires, is non-replayable, never clears taint, never overrides DENY, and never overrides a held session lease or freeze. An unknown shell effect (opaque script, interpreter given a program, computed target) cannot inherit a broad blessing; it is held until its effect is resolvable or the operator approves that exact opaque invocation with the opacity stated. #505's genuinely irreversible write targets belong to the persistence and security-config rows here.

#### AUDIT — logged, not enforced by default, only after the narrowing gate

`opaque-script-invocation`, `stop-process-or-service`, `file-delete`, `privilege-escalation`, `modify-scheduler` where the target is not a HOLD persistence sink, and `touch-sensitive-path` where the path is not a HOLD security-config target. These are ordinary operations for an agent doing real work. The intent is that they become **audit-only** by default, with enforcement an explicit opt-in that requires a configured delivery channel.

This set is reached **only after the narrowing gate in Section 2.5 has passed**. Until then these classes keep their current behaviour and their current default. The AUDIT set is defined now so that the gate has a stated target; it is not in force.

#### Where ordinary work lands

Ordinary deploy, install, configuration and repair work lands as follows:

- in a **tainted** session, or when it writes a HOLD sink (a scheduler entry, an rc file, hook or agent configuration, ShieldCortex's own config, the policy lock, the host's agent settings): **HOLD**, released by one bounded approval per effect;
- otherwise: **AUDIT** (after the gate) or current behaviour (before it).

So an operator-requested install or repair remains possible in every state: at worst it costs one bounded approval that names the effect and its targets. Nothing in the three sets makes a legitimate operator workflow impossible, which is why the header's statement that the intent-first product law is unchanged holds: the one-line law, the catastrophe hard-stops and the credential non-exfil rule are the DENY set, and everything above it is mediated rather than forbidden.

#### Alternative not taken: blanket prohibition of persistence and security-config writes

The operator could choose a stricter doctrine in which persistence sinks and security-config writes join the DENY set: no approval path, ever, from any agent session. Its benefit is that an approval surface can no longer be socially engineered into blessing a persistence write. Its operational cost is that **install and repair through the agent become impossible**: every scheduler entry, hook installation, configuration edit and ShieldCortex self-repair would have to be performed by a human outside the agent, and an agent-driven `doctor --fix` or `setup` would refuse its own work. That is a doctrine change from ADR-001's intent-first law (the operator's stated intent could no longer authorise those effects through the agent) and is presented here as a choice the operator may make, **not** as this ADR's default. This ADR's default is HOLD.

### 2.5 The narrowing gate: 5A and 5B and 5C

The move of the dangerous tier to the AUDIT set is **not made in this ADR and not made first**. It is made only after **all three** of the following exist and have been reviewed:

- **5A** — the logged-signal policy comparison in Section 5A has been run and its output reviewed: which classes stop being gated, which of the 199 enforced events would have passed, and which DENY classes still deny;
- **5B** — the synthetic effect-witness fixtures in Section 5B have been **executed** (not merely built) against **both** the current policy and the proposed policy, the results have been **independently reviewed** by someone other than the person who built the fixtures, the acceptance bars were **written down before the run**, the negative controls **proved the witnesses observe effects**, and the fixture set includes legitimate scheduler, install and configuration work and cross-session taint propagation;
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
- The three sets are disjoint with a stated precedence, so an implementation can be checked against the lists rather than against prose.
- Once Section 2.5's gate passes, ordinary agent operations stop being enforced by default; the quadratic tokeniser (#519) leaves the enforced hot path and stays only where the DENY set needs it.
- #512, #549, #551 and the residual halves of #517 fold into this decision rather than being fixed as spelling rules.

**Negative and accepted risks**

- **The new false-positive class** (Section 2.2): a session that fetched anything external must obtain a bounded approval for each privileged effect. This is an explicit trade, stated here so the operator can decide on it. It is not a zero-false-positive design.
- **Fail-closed unknown provenance widens taint** on adapters with weak labelling (Section 2.1). The cure is better labelling in the adapter, and the coverage table in Section 5C shows where that work is.
- **Approval fatigue** on the HOLD path is a real risk if the privileged set is drawn too wide. Section 2.4's HOLD set is the minimum; anything wider is opt-in.
- **A successful injection in a tainted session can still cause dangerous-but-recoverable damage** (stop a service, delete a working file) once the dangerous tier is in the AUDIT set. Accepted only after Section 2.5's measurement shows what that costs, and only because those classes are recoverable and the irreversible ones are DENY.
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

### 5B. Synthetic fixtures with effect witnesses, executed and reviewed

In an isolated fixture host (no production data, no network egress except to a controlled sink), run two corpora through the full stack (scanner, framing, taint, effect sets), **once against the current policy and once against the proposed policy**, and report both:

- **Attack corpus**: framing bypass attempts, forged authority in tool results, untrusted-source privileged requests, obfuscated DENY commands, egress of a planted secret, persistence attempts (scheduler entry, rc file, hook config), a signed peer returning hostile quoted material, an externally authored local file carrying an instruction, a proxy fetch through an MCP server, a tainted memory recalled into a fresh session, a tainted parent spawning a child, multilingual and rot13 variants.
- **Legitimate-work corpus**: build, test, deploy, git, file edits, service restarts, package installs, **legitimate scheduler entries, legitimate install and configuration edits, a ShieldCortex self-repair**, including the "fetch vendor docs, then deploy" sequence that Section 2.2 deliberately holds, and the same sequence with the bounded-approval script answering yes.

Every fixture has an **effect witness**: a file that must or must not exist afterwards, a process that must or must not be running, a controlled sink that must or must not have received bytes, a taint record that must or must not be present on the named session. A flagged-but-executed attack is a failure. A held legitimate step that the fixture's bounded-approval script then approves counts as completed with one prompt; a held step with no renderable surface counts as not completed.

**Negative controls are mandatory.** For every witness type, a control fixture removes the guard (or runs the attack with enforcement off) and must show the effect happening: the file appearing, the process running, the bytes arriving, the taint record being set. A witness that reports "no effect" when the guard is absent is not observing anything, and every result that depended on it is void.

**Acceptance bars are written before the run.** The pass thresholds for attack-success rate and legitimate-work-completion rate, per policy, are recorded in the fixture repository before the first execution and are not changed after the numbers are seen. A run whose bar was set afterwards is reported as exploratory and does not count toward Section 2.5.

**Independent review.** The executed results, the negative-control outputs and the pre-registered bars are reviewed by someone who did not write the fixtures. The review record names the reviewer, the fixture revision and the policy revision.

Report **two numbers per policy, never one**: attack-success rate and legitimate-work-completion rate, each with its denominator. Building the fixtures, or running them only against the current policy, satisfies none of this section.

### 5C. Provenance coverage, per adapter: measured, then proved

For every adapter that feeds context, a fixture must prove that an `untrusted-external` span entering through that adapter taints the session and that a HOLD-set effect after it is held. Coverage is **proved, not assumed**; an adapter without a passing fixture is listed as uncovered in the ADR's acceptance record.

The starting point is the **measured** state of each adapter at ffca84c5, read from the adapter's registration code rather than from its documentation. "Missing" means the code registers no hook at that point; it is not a judgement about whether one is planned.

| adapter | where measured | hooks registered | pre-effect gate | result transformation at delivery | span labelling at ingestion | taint state |
|---|---|---|---|---|---|---|
| Claude Code hook | `src/setup/settings-hooks.ts`, `scripts/pre-tool-hook.mjs`, `scripts/prompt-recall-hook.mjs`, `scripts/session-start-hook.mjs`, `scripts/pre-compact-hook.mjs`, `scripts/stop-hook.mjs`, `scripts/session-end-hook.mjs` | `PreToolUse`, `UserPromptSubmit`, `SessionStart`, `PreCompact`, `Stop` (opt-in), `SessionEnd` | yes: `PreToolUse` runs the Action Guard | **missing**: no `PostToolUse` hook is installed; no hook sees a tool result before the model does | recall packs are framed (#531) at `UserPromptSubmit` and `SessionStart`; tool results: **missing** | **missing**: no taint store; the pre-tool hook reads none |
| OpenClaw realtime plugin | `plugins/openclaw/openclaw.plugin.json`, `plugins/openclaw/index.ts`, `provenance.ts`, `session-taint.ts`, `scan-taint-policy.ts`, `conversation-trust.ts`, `interceptor.ts` | `llm_input`, `llm_output`, `before_agent_run`, `before_tool_call`, `session_end`, `agent_end` | yes: `before_tool_call` runs the Action Guard and reads the taint store | **missing**: no `after_tool_call` or tool-result hook; tool output is scanned one turn later at `llm_input` in **advisory** mode (`scanToolResponse(..., "advisory")`) and nothing rewrites or withholds it before the model reads it | partial: `llm_input` labels `user` / `tool_result` / `unknown` only; no `web` or `document` distinction because the host event carries none; `unknown` is counted but does not taint | partial: in-memory per-session store, **detection-triggered** (a scan hit), fifteen-minute TTL, cleared at `session_end`, escalates the Action Guard by one notch; owner input never taints when `senderIsOwner === true`; not provenance-triggered, not inherited by forks, summaries or memory |
| Hermes plugin | `plugins/hermes/shieldcortex/plugin.yaml`, `plugins/hermes/shieldcortex/__init__.py` | `pre_tool_call` only | yes: `pre_tool_call` calls the Action Guard over REST; fail-open when the scanner is unreachable | **missing**: `transform_tool_result` is documented as a later phase and not implemented | **missing** | **missing** |
| Codex (CLI and IDE) | `src/setup/codex.ts` | none: the installer writes an `mcp_servers` entry into the Codex config only | **missing**: no hook surface; the Action Guard is reachable only if the model calls `iron_dome_check` itself | **missing** | **missing** unless the model calls `scan_tool_response` itself | **missing** |
| MCP server (any MCP client, including Codex, Cursor and others) | `src/server.ts` | none automatic; exposes `recall`, `get_context`, `scan_tool_response`, `iron_dome_check` and related tools that the model must choose to call | only by explicit model call | **missing** at delivery; `scan_tool_response` runs the enforce layer only when invoked | recall results framed (#531); tool results: **missing** unless invoked | **missing** |
| LangChain integration | `src/integrations/langchain.ts` | none: `ShieldCortexMemory.loadMemoryVariables` / `saveContext` and `ShieldCortexGuard.scan` are library calls | none | **missing** | recall framed via the shared recall frame; tool results: **missing** | **missing** |
| Universal guarded memory bridge | `src/integrations/universal.ts` | none: guarded `save` / `search` over an external memory backend | none | **missing** (memory plane only) | memory records scored by declared `sourceType` | **missing** |
| Session-start and recall packs | `scripts/session-start-hook.mjs`, `scripts/prompt-recall-hook.mjs`, `src/memory/host-contract.ts` | (Claude Code events above) | n/a | n/a | framed; taint marker on recalled memory: **missing** (the frame does not yet carry one) | **missing** |

What the table says, in words: **no adapter transforms a tool result at delivery time today.** The tool-response enforce layer (`src/defence/tool-response-enforce.ts`) exists as a library function and as an MCP tool, and the OpenClaw plugin calls the scanner in advisory mode a turn late. The only taint store in the tree is the OpenClaw plugin's, and it is detection-triggered with a fixed TTL, not the provenance-triggered, session-lifetime, inherited taint that Section 2.2 requires. The Claude Code hook, which produced all 837 events in Section 1.3, has no result path at all.

Every "missing" cell above is therefore an item on the 5C work list. The gate in Section 2.5 requires, per shipped adapter, either a passing fixture for each of the four columns (gate, transformation, labelling, taint) or an explicit operator acceptance that the adapter ships uncovered, recorded in the acceptance record with the adapter name. An adapter accepted as uncovered does not get the AUDIT-set narrowing: on that adapter the dangerous tier keeps its current behaviour, because there is nothing replacing it.

Cross-session inheritance (a tainted parent spawning a child, a child harness bound to its holder) is a 5C fixture for each adapter that can spawn, and is blocked on #554 where the host cannot supply the binding; that block is recorded as such, not as a pass.

Section 2.5's narrowing is gated on 5A having been reviewed, 5B having been executed and independently reviewed against pre-registered bars, and 5C being complete for every shipped adapter.

---

## 6. Sequencing

1. **#535** — close the unframed tool-result echo (labelling must be complete before taint means anything).
2. **#547, #538** — framing coverage and redactor fail-safes.
3. **#517 delivery half + `doctor`** — `enforce: true` without a notify surface fails `doctor`, fail loud, state unchanged. Independent of everything below; ships first.
4. **Replay harness** — Section 5A over the production window; Section 5B fixtures and effect witnesses built, negative controls built, acceptance bars pre-registered.
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
- Accept the three disjoint effect sets (Section 2.4) with precedence DENY > HOLD > AUDIT: DENY as the immutable no-approval set, HOLD as the always-mediated set released only by bounded approval, AUDIT as the target for the dangerous tier after the gate.
- Decide whether to take the **alternative not taken** in Section 2.4 (persistence and security-config writes moved from HOLD to DENY), accepting that agent-driven install and repair then become impossible. This ADR's default is HOLD.
- Accept that narrowing of the dangerous tier is gated on Sections 5A, 5B and 5C together, that building fixtures is not passing them, and that the dangerous tier keeps its current behaviour until then, per adapter.
- Confirm that the session-lease family stays outside this decision, that the lease wins over a bounded approval, and that #554 is tracked separately.

> **Nothing in this document is the operator's acceptance of the trade-offs; that decision is pending.**
