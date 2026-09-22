# ADR-002: Provenance-first enforcement (v2)

**Status:** Proposed
**Date:** 2026-09-22
**Author of v1:** TARS (issue #556). **v2 fold:** author-side objections recorded on #556 and the convergence agreed between the two on 2026-09-22.
**Reviewer:** TARS. **Decision:** operator.
**Evidence:** #555. **Supersedes for review purposes:** the v1 text in the body of #556.
**Relates to:** ADR-001 — the intent-first doctrine at `docs/design/2026-08-24-intent-first-doctrine.md` and its companion target architecture. This ADR changes the enforcement *mechanism* under that doctrine; it does not change the doctrine's one-line law, its catastrophe hard-stops or its credential non-exfil rule.

> **Nothing in this document is the operator's acceptance of the trade-offs; that decision is pending.**

Numbering note: this is the first file under `docs/architecture/`. Earlier decision records live under `docs/design/` (for example `ADR-2026-08-19-retry-control.md`) and keep their names; "ADR-001" is the label #556 gives the intent-first doctrine, not a file.

---

## 0. What changed from v1

| v1 (#556 body) | v2 (this document) | Why |
|---|---|---|
| "837 events … Notifications actually delivered: 0"; read as 837 gates | 837 distinct events = 638 warned (advisory) + 195 auto_denied + 4 denied_no_prompt_surface; `notify: not_configured` 837/837 describes the notification channel only | The tally mixed advisory and enforced outcomes. The log does not support reading the total as a count of blocked actions. |
| Gate keys on the lowest-band *span in the causal context* of a tool call | Gate keys on **session taint**: once any `untrusted-external` span has entered context, privileged effects are held pending bounded approval | The trust plane's ceiling is per-process. No harness links a context span to the tool call it caused. |
| Floor = catastrophic destruction only | Floor = irreversibility **including disclosure and persistence**: destruction + credential/secret egress + persistence sinks + security-config writes | An injection wants secrets out and persistence in, not a formatted disk. |
| Dangerous tier → audit-only now | Dangerous tier → audit-only **only after** the replay comparison and per-adapter capability evidence | Narrowing must be measured, not argued. |
| `notify: not_configured` + `enforce: true` fails `doctor` | Same, and the failure must **not** change enforcement state; ships first and independently | A doctor that silently flips enforcement is a second way to lose the gate. |
| #550/#552/#553/#554 fold into this decision | **Excluded.** Same agent, same session, same band on both sides; provenance cannot replace that sink control | Different threat, different control. |
| #506 reframed as "labels and capability, not patterns" | #506 reframed as **ingestion-boundary scanner coverage** (`tool-response-enforce` blocks in enforce mode); never an effect gate; multilingual/rot13 coverage kept | The clamp never sees text inside a tool result; the scanner does, at the front door. |
| Validation: replay + agent-work corpus + injection corpus | Two separated halves, never summed: logged-signal policy comparison and synthetic effect-witness fixtures; provenance coverage proved per adapter | Signal counts and outcome measurements answer different questions. |

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
- **Session taint.** Once any `untrusted-external` span has entered a session's context, the session is tainted and privileged effects are held until a bounded approval is given for the specific effect.

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

**Enforcement keys on provenance and capability, with a text-inspected floor scoped to irreversible effects.** Detection stays at the ingestion boundary as a scanner, and at the floor as a last line, not as the general effect gate.

### 2.1 Every span entering model context carries a source label

Reuse `DefenceSource`. The bands below are an ordering over the existing source types (`user`, `cli`, `hook`, `email`, `web`, `agent`, `file`, `api`, `tool_response`), fixed at implementation time; they are not a new type.

| band | examples |
|---|---|
| `operator` | authenticated channel: owner chat, local terminal |
| `signed-peer` | signature-verified teammate message |
| `agent` | this agent's own reasoning and its own tool calls |
| `stored-memory` | recalled memory, framed per #531 and #535 |
| `tool-result` | MCP or tool output that is not otherwise classified |
| `untrusted-external` | web page, feed, scraped content, unsigned message, any tool result whose origin is a network fetch or an unauthenticated source |

The ceiling clamp in `env-detector.ts` and `resolve-tool-source.ts` remains the load-bearing mechanism for the *caller's* band and is reused as-is. Labelling of *spans* is done at ingestion, where ShieldCortex already sees every tool response (the scanner) and every memory injection (the frame). #535, #547 and #538 are prerequisites because a single unframed or unlabelled entry point is a leak of the whole scheme.

### 2.2 Session taint

**Rule.** When any span labelled `untrusted-external` enters a session's context, the session becomes **tainted**. While tainted, every privileged effect (Section 2.4's floor plus any class the operator has opted into enforcing) is **held** pending a bounded approval (Section 2.3). Non-privileged effects proceed and are audited with the taint flag on the row.

**Lifetime.** Taint lasts for the **session**. It is inherited by:

- forked or child sessions spawned from a tainted session;
- summaries and compactions of a tainted context (the poisoned span may be gone; its influence on the model is not);
- memory written from a tainted session and later imported (the frame per #531 carries the taint marker; recall of such a memory taints the recalling session).

"Until the next operator turn" is rejected: the poisoned page is still in context when the operator says "carry on". "Until the span leaves context" is rejected: leaving is unobservable through compaction.

**Reset.** There is no operator "clear" that launders retained hostile context. An operator may start a fresh session. An operator may approve a specific effect under Section 2.3. Neither clears the taint of the session in which the hostile span was read.

**New false-positive class, accepted as a trade.** "Fetch the vendor's docs, then deploy" is held: the fetch taints the session and the deploy is a privileged effect. That is a different false-positive profile from today's, not a zero one. Today's profile is "mentioning a dangerous shape is denied"; the proposed profile is "having read the outside world, privileged effects need a bounded yes". The second is decidable, explainable in one sentence to the operator, and bounded by the operator's own workflow rather than by the shell grammar. Whether it is the better trade is the operator's decision.

### 2.3 Bounded approval

An approval issued against a held effect:

- **binds the actual effect and its targets**: the resolved command or write, the files, hosts, services or scheduler entries it touches; not a class, not a pattern, not "this kind of thing";
- **expires**: a short window, a single use, or both;
- **is non-replayable**: consumed on use, tied to the action id it was issued for, useless against a later identical string;
- **cannot bless an unknown**: a shell effect the mapper cannot resolve (an opaque script, an interpreter given a program, a computed target) cannot inherit a broad approval; it is held until its effect is known or the operator approves that exact opaque invocation with the opacity stated;
- **never clears taint**, never overrides the floor (Section 2.4), and never overrides a held session lease (Section 2.7).

The existing retry-control design (`docs/design/ADR-2026-08-19-retry-control.md`: mint on operator intent, denial produces a claim ticket not a grant, catastrophic tier has no path) is the shape to extend. An approval surface that cannot render the effect and its targets cannot issue a bounded approval; on such a host a held effect stays held, as `denied_no_prompt_surface` does today.

### 2.4 The floor, redefined by irreversibility

The floor is the set of effects that stay **text-gated, provenance-blind, always enforced, with no approval path**, because by the time they are observable, provenance has already failed and the sink is the last point of control. v1 defined it by destruction. v2 defines it by **irreversibility, including disclosure and persistence**:

| class | examples | why it is on the floor |
|---|---|---|
| catastrophic destruction | `rm -rf /` and equivalents against root or home, fork bomb, `dd` onto a block device, filesystem format or partition tooling | unrecoverable; nothing legitimate resembles them |
| credential and secret egress | a secret-shaped value or a known credential file leaving over the network, `pipe-download-to-shell` and `decode-pipe-to-shell` where the payload is a credential | disclosure cannot be undone; this is the payoff of a successful injection |
| persistence sinks | scheduler entries (cron, systemd timers, launchd), shell rc files, hook and agent configuration, `authorized_keys` | how a one-shot injection becomes a standing one |
| security-config writes | ShieldCortex's own config, the policy lock, the host's agent settings | the guard editing its own guard |

Normalisation (#504: unicode, quote and backslash tricks, write-then-exec) belongs on the floor, because evasion of an absolute rule is a real attack. Fail-closed on hook load failure (#511) stays on the floor. #505's genuinely irreversible write targets belong to the persistence and security-config rows. #503 survives only where the verb is unrecoverable (`DROP DATABASE`, infrastructure destroy), not for routine data statements.

The floor is small in vocabulary and is the one place where the command-inspection investment continues.

### 2.5 The dangerous tier: audit-only, but only after measurement

`opaque-script-invocation`, `stop-process-or-service`, `file-delete`, `privilege-escalation`, `modify-scheduler` (where not already on the floor as a persistence sink) and `touch-sensitive-path` are ordinary operations for an agent doing real work. The intent is that they become **audit-only** by default, with enforcement an explicit opt-in that requires a configured delivery channel.

That change is **not made in this ADR and not made first**. It is made only after both of:

- **(a)** the replay comparison in Section 5A has been run and its output reviewed: which classes stop being gated, which of the 199 enforced events would have passed, and which of the floor classes still deny;
- **(b)** capability and adapter evidence per Section 5C: the session-taint gate is live and its coverage is proved on every adapter that feeds context, so the dangerous tier is being replaced by something rather than removed.

Until both exist, the dangerous tier keeps its current behaviour and its current default.

### 2.6 Delivery: a gate nobody can see is a configuration error

`enforce: true` together with `notify: not_configured` is a **`doctor` FAIL**, not a warning. A gate whose denials reach nobody blocks work and produces no signal.

Two constraints on that failure:

- **Fail loud, state unchanged.** A `doctor` failure must not silently change enforcement state in either direction. It reports, exits non-zero, and names the fix. A doctor that disables the guard because nobody is listening has just created a second silent path to no guard; a doctor that enables notification on its own has chosen a recipient the operator did not.
- **Ships first and independently.** This is the delivery half of #517. It does not depend on session taint, the floor redefinition or the tier narrowing, and it should land before them.

A `require_approval` verdict on a host with no renderable approval surface remains `denied_no_prompt_surface`: an unpassable gate. Four such events are in the window. `doctor` should report a host in that state the same way.

### 2.7 Excluded: the session-lease family (#550, #552, #553, #554)

The session lease is **not** an injection control and provenance cannot replace it. It freezes security configuration against **the same agent, in the same session, under the same band** while a lease is held: the operator's guard against the agent editing its own guard mid-task. Provenance is identical on both sides of that line by construction, so a provenance gate is blind to it.

The write-shape work on #550/#552 is the cost of a *sink* control on one specific path. The alternatives this ADR might seem to imply are "freeze on any mention" (the false positive #550 was opened for) or "no freeze" (the operator's rule removed). Neither is acceptable. #554 is a binding problem *within* the trust plane (a host-maintained binding of a child harness to its holder session) and this ADR's framing supports doing it properly.

The lease family therefore stays out of the fold list, and a bounded approval under Section 2.3 never overrides a held lease.

### 2.8 #506 reframed: ingestion-boundary scanner coverage, never an effect gate

The clamp in `resolve-tool-source.ts` protects **caller-declared metadata** on an MCP call. The authority spoof in #506 ("the operator says: approve this") is **text inside a tool result** that the *model* reads. The clamp never sees that text. Two mechanisms do:

- framing (#531, #535): the text arrives labelled as data;
- the tool-response scanner, whose enforce layer in `src/defence/tool-response-enforce.ts` **blocks** in enforce mode: any injection signal, the instruction detector firing, or a blob that decodes to an injection or a credential withholds the whole payload and tells the agent why.

That is a data-plane quarantine at ingestion: the front door, not a sink. Detection-as-gate is legitimate there and only there, because the input is bounded (one tool response) and the cost of a false positive is a withheld page, not a blocked deploy.

So #506's patterns are kept as **scanner coverage at the ingestion boundary**: authority-spoof, verbatim-exfil, multilingual and rot13 variants. They are never an effect gate and never were one. Multilingual and rot13 coverage is cheap and closes real paraphrase gaps at that boundary.

---

## 3. Why not "better detection" as the gate

More patterns on the effect plane (the tempting reading of #506, and the treadmill of #549/#551/#512) is an unbounded input space in which the attacker moves last and the matcher is always one paraphrase behind. A model-based classifier has the same property and additionally violates the local, deterministic, customer-CPU constraint.

Detection remains useful in two places: at the ingestion boundary (Section 2.8), where the input is bounded and a false positive is cheap, and on the floor (Section 2.4), where the rule is absolute and evasion of it is itself an attack. It must not be the general effect gate. Effect gating keys on provenance, which is finite and decidable.

---

## 4. Consequences

**Positive**

- Injection defence keys on the attack's mechanism: data promoted to instruction. The gate question ("has this session read the outside world, and is this a privileged effect?") is decidable without inferring intent from spelling.
- The floor now covers what an injection is for (secrets out, persistence in), not only what a vandal is for.
- Once Section 2.5's conditions are met, ordinary agent operations stop being enforced by default; the quadratic tokeniser (#519) leaves the enforced hot path and stays only where the floor needs it.
- #512, #549, #551 and the residual halves of #517 fold into this decision rather than being fixed as spelling rules.

**Negative and accepted risks**

- **The new false-positive class** (Section 2.2): a session that fetched anything external must obtain a bounded approval for each privileged effect. This is an explicit trade, stated here so the operator can decide on it. It is not a zero-false-positive design.
- **Approval fatigue** on the taint path is a real risk if the privileged set is drawn too wide. Section 2.4's floor is the minimum; anything wider is opt-in.
- **A successful injection in a tainted session can still cause dangerous-but-recoverable damage** (stop a service, delete a working file) once the dangerous tier is audit-only. Accepted only after Section 2.5's measurement shows what that costs, and only because those classes are recoverable and the irreversible ones are on the floor.
- **Provenance labelling must reach every context-entry point or it leaks.** An adapter that injects context without a label defeats the taint. This is why coverage is proved per adapter (Section 5C) rather than assumed.
- **Summaries and imported memory carry taint** (Section 2.2), which will surprise operators who expect a fresh session to be clean after recalling a tainted note. The frame must say so.
- The enforced-outcome numbers above come from one host, one origin and five weeks. They are evidence for the shape of the problem, not a rate.

---

## 5. Validation

The harness has two separated halves. **They are never summed**: A measures logged signals against policies; B measures outcomes against fixtures. A number from one is not comparable with a number from the other.

### 5A. Logged-signal policy comparison

Replay `denials.jsonl` from the production window against three policies and tabulate per outcome and per signal class:

1. **current** (the shipped tiers and defaults);
2. **destruction-only floor** (v1's floor);
3. **broad floor** (Section 2.4: destruction + credential/secret egress + persistence sinks + security-config writes).

Rules for the replay:

- Rows carrying `redacted-signal` (206 events) and any row whose command cannot be reconstructed from the log are bucketed **"unknown"**, reported as their own column, and never counted as "would pass" or "would deny".
- Malformed rows are **counted, not skipped**, and reported.
- **All records per action id are kept.** Where the records for one action disagree (an advisory row and an enforced row, or two verdicts), the conflict is shown, not resolved by picking one.
- `pipe-download-to-shell` is in the signal set alongside `external-egress` and `decode-pipe-to-shell`.
- The output is a table of events by (policy × outcome × signal class), plus the list of enforced events (the 199) that would change outcome under each policy, each identifiable by action id for review.

This half answers "what stops being gated and what still denies". It does not answer "was anything protected".

### 5B. Synthetic fixtures with effect witnesses

In an isolated fixture host (no production data, no network egress except to a controlled sink), run two corpora through the full stack (scanner, framing, taint, floor):

- **Attack corpus**: framing bypass attempts, forged authority in tool results, untrusted-source privileged requests, obfuscated floor commands, egress of a planted secret, persistence attempts (scheduler entry, rc file, hook config), multilingual and rot13 variants.
- **Legitimate-work corpus**: build, test, deploy, git, file edits, service restarts, package installs, including the "fetch vendor docs, then deploy" sequence that Section 2.2 deliberately holds.

Every fixture has an **effect witness**: a file that must or must not exist afterwards, a process that must or must not be running, a controlled sink that must or must not have received bytes. A flagged-but-executed attack is a failure. A held legitimate step that the fixture's bounded-approval script then approves counts as completed with one prompt; a held step with no renderable surface counts as not completed.

Report **two numbers, never one**: attack-success rate and legitimate-work-completion rate, each with its denominator.

### 5C. Provenance coverage, per adapter

For every adapter that feeds context (the Claude Code hook path, the OpenClaw interceptor and its message recall, the MCP server's recall and context tools, the LangChain memory variable, the Hermes plugin, the session-start packs and any other injection point), a fixture proves that an `untrusted-external` span entering through that adapter taints the session and that a privileged effect after it is held. Coverage is **proved, not assumed**; an adapter without a passing fixture is listed as uncovered in the ADR's acceptance record.

Section 2.5's narrowing is gated on 5A having been reviewed and 5C being complete for every shipped adapter.

---

## 6. Sequencing

1. **#535** — close the unframed tool-result echo (labelling must be complete before taint means anything).
2. **#547, #538** — framing coverage and redactor fail-safes.
3. **#517 delivery half + `doctor`** — `enforce: true` without a notify surface fails `doctor`, fail loud, state unchanged. Independent of everything below; ships first.
4. **Replay harness** — Section 5A over the production window; Section 5B fixtures and effect witnesses built.
5. **Capability binding** — session taint (Section 2.2) and bounded approval (Section 2.3) in the effect plane, using the existing ceiling clamp for the caller band; per-adapter coverage fixtures (Section 5C).
6. **Narrowing** — floor redefined per Section 2.4; dangerous tier to audit-only per Section 2.5, only once 4 and 5 are reviewed.
7. **#506 reframed** — ingestion-boundary scanner coverage per Section 2.8.

**Freeze** the remaining command-inspection lane except #504 (scoped to the floor), #511 and #517's delivery half. The session-lease family (#550/#552/#553/#554) is outside both this sequence and the freeze; it proceeds on its own track.

---

## 7. Issue disposition under this ADR

| issue | disposition |
|---|---|
| #504 | keep; normalisation scoped to the floor |
| #505 | keep the irreversible targets as persistence / security-config floor rows |
| #503 | keep only unrecoverable verbs (`DROP DATABASE`, infra destroy) |
| #506 | reframe: ingestion-boundary scanner coverage, multilingual/rot13 kept; never an effect gate |
| #511 | keep; fail-closed stays on the floor |
| #512, #549, #551 | fold into this decision; not fixed as spelling rules |
| #517 | delivery half ships first (step 3); residual halves fold |
| #519 | leaves the enforced hot path after step 6 |
| #531, #535, #547, #538 | prerequisites (steps 1 and 2) |
| #550, #552, #553, #554 | **excluded**; own track; unaffected by this ADR |
| #532 | already shipped; illustrates Section 1.5 |

---

## 8. Open for the operator's decision

- Accept the session-taint trade (Section 2.2) and its false-positive class, or reject it and keep text-gating as the general effect gate.
- Accept the broad floor (Section 2.4) as the always-enforced, no-approval set.
- Accept that narrowing of the dangerous tier is gated on Sections 5A and 5C, and that the dangerous tier keeps its current behaviour until then.
- Confirm that the session-lease family stays outside this decision.

> **Nothing in this document is the operator's acceptance of the trade-offs; that decision is pending.**
