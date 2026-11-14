# ADR-002 v3 (proposed amendment): align with the 20 Oct design contract; build the command model first

**Status:** Proposed (v3). **Not accepted.** The accepted text is still [ADR-002 v2 round 3](./ADR-002-provenance-first-enforcement.md) (operator decision 2026-09-29). Nothing in this document is in force, and this change switches nothing on or off: no default, no posture and no entry on the always-block list changes with it.
**Date:** 2026-11-12
**Author:** Jarvis (builder lane, epic #1065 Phase 0), from the build plan recorded on #1065.
**Decision:** operator. The six questions in Section 7 need an owner answer before any of them takes effect.
**Tracker:** #556. **Build epic:** #1065. **Parent:** #875 (outcome 2: routine work never trips the guard).

This is a separate file on purpose. Editing the accepted ADR in place would either make an accepted record look demoted or make a proposal look accepted. If the owner accepts v3, its text is folded into ADR-002 in the change that records the decision, and this file is removed.

---

## 1. Why amend

ADR-002's diagnosis still holds. The false positives are structural (v2 §1.5): the guard reads text, and text that mentions a thing is not a command that does it. About twenty open issues are that one defect seen from different sides. The principle that follows also holds: decide on **effect and target**, never on spelling, and exempt no program by name (v2 §2.4).

Three things have changed since 29 Sep.

### 1.1 A later owner decision contradicts three of v2's rules

On 20 Oct the owner accepted a four-principle design contract for Action Guard, recorded on #875 with the words that those principles "take precedence where current behaviour differs". They are:

1. **Fixed catastrophic list; everything else logs.** A short published always-block list: disk or tree wipe, git force push or history rewrite, secret exfiltration, payments or money movement, disabling the guard itself. Nothing outside that list is gated by default. It is logged, never asked.
2. **Approvals hold and resume** (#853): where a gate does apply, the action is held, one card reaches the owner, and approval runs the held action.
3. **One switch per box** for the hook, the OpenClaw plugin and Hermes together.
4. **Trust by situation.** An owner-present interactive terminal is log-only. Headless paths are where principles 1 and 2 apply.

Its non-goals: no new detectors, no new tiers, no new config keys beyond what the one switch needs.

Set beside v2:

| Topic | ADR-002 v2 (accepted 29 Sep) | 20 Oct contract (#875) |
|---|---|---|
| Default for anything not on the block list | HOLD if opaque, unclassified or unresolved, in every session (§2.4) | logged, never asked |
| Tainted session | every privileged effect is HOLD (§2.2, §2.4) | no new tiers, no new detectors |
| Block list | destruction, and credential read composed with egress (§2.4 DENY) | adds force push and history rewrite, payments, disabling the guard |
| Persistence and guard-config writes | HOLD in every session (§2.4) | disabling the guard is on the block list; the rest logs |
| Owner at the keyboard | no exemption | log-only (principle 4; re-confirmed by the owner on 8 Nov, #967) |
| Dangerous tier to audit-only | only after 5A and 5B and 5C (§2.5) | already the posture: advisory on every box until hold-and-resume ships |

v2 and the contract cannot both be the target. v3 proposes that the contract wins, as its own text says, and that v2's machinery is kept where the contract is silent.

### 1.2 The taint gate as written would hold nearly everything

This is reasoning, not a measurement. v2's taint is session-long, has no clear, and is set by any web page, unsigned message, cloned repository file or recalled memory (§2.2). A working agent session reads one of those within minutes. Nearly every session is then tainted, and under v2 every privileged effect in it becomes a hold. That is the outcome the owner rejected on 20 Oct ("working against the harness").

### 1.3 The taint gate cannot be built on the main adapter today

Checked on `main` at `7da096fb`:

- The Claude Code setup registers no tool-result hook, so there is nowhere to set taint from a result (v2 §5C already records this as missing).
- `session-taint-lineage.ts` is imported only by `src/defence/index.ts` and its own test, and its header says it is not wired.
- The #556 tracker has shown the second half of v2's step 5 as not started since 27 Sep.

### 1.4 v2 has no plan for the part that generates the issues

v2 says the cure for a misread command is "a better mapper", and its sequence (§6) never builds one. The classifier is one file of 9,691 lines: regular-expression tables over text, plus strip, mask and escape passes. Each open parsing issue is one of those passes guessing wrong, and the long review chains (#552, #882, #964) were all spelling chases inside it.

---

## 2. What v3 keeps from v2

- The effect decision is a **total, single-valued function** (§2.4). v3 changes its inputs and its outcomes, not that property.
- **No command-name exemption** (§2.4). Build, test and version-control commands are classified by what they do.
- The **minimum effect taxonomy** (§2.4) as the vocabulary the mapper must be able to name.
- A small, **text-gated always-block list with normalisation** as the one place pattern work continues (§2.4 DENY, #504).
- The **session-lease family stays excluded** (§2.7).
- **Measurement discipline**: 5A is descriptive, 5B is executed and independently reviewed against bars written down first, and building fixtures is not passing them (§2.5, §5).
- Bounded approval (§2.3) as the design for a held action. Its delivery is hold-and-resume, built once, in #853.
- §2.6 (a gate nobody can see is a configuration error) and §2.8 (#506 as ingestion-boundary scanner coverage).

---

## 3. What v3 changes

### 3.1 Decision inputs

`decide(effects, targets, situation, taint, posture)`.

- **situation** is new: owner-present interactive terminal, or headless. It carries principle 4.
- **posture** is the box's one switch (principle 3): advisory, or enforce where the owner has opted the box in.
- **taint** stays an input, as an audit flag first (3.4).

### 3.2 Three outcomes, mapped to the contract

| Outcome | When | Replaces in v2 |
|---|---|---|
| **BLOCK** | the action matches the fixed published list, at any situation, taint or posture | DENY |
| **LOG** | everything else, by default | AUDIT, and most of HOLD |
| **HOLD** | only where the owner has opted a box into enforce, delivered by hold-and-resume (#853); and the guard's own state, which is already held today under advisory posture | HOLD |

Precedence is BLOCK > HOLD > LOG. HOLD is no longer a default path.

### 3.3 Unclassified or unresolved commands

v2: HOLD at minimum, in every session. v3: **logged with an `unresolved` marker by default; held only under enforce.**

One rule does not move: **no relief by spelling.** Where the command model is unsure, the answer is `unresolved` and today's treatment of that command stands. An unsure parse never becomes a reason to relax a verdict.

### 3.4 Taint ships as an audit flag first

Session taint is wired as a flag on audit rows. It gates nothing. Promoting a narrow set to HOLD in a tainted headless session (candidates: persistence writes; a credential read followed by any egress; running content fetched in the same session) is a later owner decision, taken on measured numbers from the flag.

### 3.5 The always-block list

v2's DENY set, plus the three items the contract adds: git force push or history rewrite, payments or money movement, disabling the guard itself. **Changing the published list is an owner decision.** Until it is recorded, the list in force is the one `main` enforces today.

Open scoping questions that the owner answer must settle, because the folded issues hold cases on both sides (none of them is a fixture in the corpus yet):

- whether a lease-protected force push to a non-default branch is on the list or logged (#512 calls it routine);
- what counts as "disabling the guard" beyond the switch itself: a write to the guard's config or hook registration is the proposed boundary; a read of those files is not (#927, #874).

### 3.6 What the narrowing gate now governs

The dangerous tier is already advisory as posture. v2 §2.5's gate (5A and 5B and 5C) is kept and re-pointed: it now governs **whether enforce may become a default again**, on any box or for any tier.

### 3.7 Sequencing: the command model comes first

v2 §6 is replaced by the phases of epic #1065:

| Phase | What | Verdict change |
|---|---|---|
| 0 | Freeze the corpus: every folded issue becomes named fixtures with expected effects, targets and decision; cases that fail today are marked known-gap. This document. **Not complete:** at this change 1 of the 20 epic lines (#519) has a fixture and the other nineteen are not authored; see [ADR-002-frozen-corpus.md](./ADR-002-frozen-corpus.md). | none |
| 1 | One single-pass lexer and argv tree: statements, words marked executable or data, redirects, heredocs tagged by language, substitutions, normalisation of executable words. Shadow mode. Linear time, proven by a growth ratio. | none |
| 2 | An effect and target mapper on that model replaces the dangerous-tier substring rules. Quoted prose and written file content are data. Reading a config file is not writing it. Hook and OpenClaw interceptor share one classifier. | false positives in the frozen corpus stop; zero movement in the miss corpus and the block list |
| 3 | The always-block list runs on normalised executable words. Write-content rows made linear. Residuals documented in `docs/`. | misses in the frozen corpus stop; the false-positive corpus does not move |
| 4 | One decision function; taint as an audit flag; re-run 5A and execute 5B against the pre-registered bars; a one-page go-live decision for the owner. | none by default |

Rules for every phase: tests and fixtures run in CI or an isolated evaluator, never on a live guarded host; fixtures name dangerous shapes by signal or compose them at runtime; review findings end fixed, dropped with a reason, or carried, and open no new issues.

---

## 4. Consequences

- **Routine work stops tripping the guard for a structural reason**, not because another spelling was excused. That is the purpose of Phases 1 and 2.
- **Less is held by default than v2 intended.** An opaque script, a persistence write or a privileged effect in a session that has read the outside world is logged, not held, unless the box is in enforce. v2 accepted the false-positive cost of holding those; v3 accepts the opposite risk, on the owner's 20 Oct decision. The block list and the audit log are what stand between an injection and a non-listed effect until hold-and-resume and the measured taint set exist.
- **The block list becomes the security boundary that matters most**, so Phase 3 (normalisation, inline-program output routed into a shell, sends to a bare host) carries more weight than it did under v2, and needs a non-author security reviewer in addition to the usual panel.
- **Taint evidence arrives before a taint gate**, which lets the eventual gate be sized from data instead of from the argument in 1.2.
- **`tool-action-guard.ts` must get smaller.** The epic's closing condition includes it.
- The frozen corpus is what is meant to make any of this reviewable: each phase reports a moved list against it, and a move that is not in the corpus is a defect in the change. It cannot do that yet. At this change it holds 1 of the 20 epic lines, and no phase can report a moved list against lines that have no fixture.

---

## 5. What v3 does not decide

- Hold-and-resume itself (#853), card delivery (#815), owner-present detection (#923) and session-lease identity (#854). They belong to #875 and keep their owners.
- Any new detector. Where a folded issue records a shape the guard has no signal for and the contract's list does not name (for example the reverse-shell case in #1005), v3 records it as a block-list scoping question for the owner, not as work to start.
- Skill-scanner speed (#1002, #1040) and the release blocker (#1060).

---

## 6. Validation

Unchanged in kind from v2 §5; changed in what it is for.

- **5A** (logged-signal replay) is re-run after Phase 2 and reported as descriptive.
- **5B** (effect-witness fixtures, three arms) is executed in Phase 4 against the bars v2 pre-registered: at least 90% of witnessed attacks blocked, at most 2% unintended blocking of legitimate work, at least 98% completion along the approval path, zero successes in the enumerated regression families. Denominators are frozen before the run.
- **5C** (per-adapter coverage) is reported for the taint **flag**: present on rows in the positive-injection control, absent in the clean control.
- The **frozen corpus** (`src/defence/iron-dome/__tests__/fixtures/adr002/`, index in [ADR-002-frozen-corpus.md](./ADR-002-frozen-corpus.md)) is the intended per-phase regression bar. At this change it covers 1 of the 20 epic lines (#519, a cost fixture measured by an opt-in report and not asserted in the default suite), so it is not yet a bar for Phases 2 to 4.

---

## 7. Owner decisions needed

Items 2, 3, 4 and 6 change answers the owner gave on 29 Sep and touch Guard defaults. They are owner-only. Phases 0 to 2 do not depend on the answers.

1. Accept that the 20 Oct contract supersedes v2 where they differ (Section 1.1), and that ADR-002 is amended to say so.
2. Accept the three outcomes of Section 3.2: BLOCK on the fixed list, LOG by default, HOLD only under enforce and for the guard's own state.
3. Accept the always-block list of Section 3.5, and answer its two scoping questions (lease-protected force push to a non-default branch; what counts as disabling the guard).
4. Accept that unclassified or unresolved commands are logged with a marker by default rather than held (Section 3.3).
5. Accept that taint ships as an audit flag first, and that promoting any set to a hold is a later decision taken on measured numbers (Section 3.4).
6. Accept that v2 §2.5's gate now governs whether enforce may become a default again (Section 3.6).

The one-line form, for a digest: "ADR-002 v3: align with your 20 Oct rules (block list plus log, taint as a log flag first), and build the parser before anything else. OK?"

**Decision record:** none yet. This section is where the answer is recorded.
