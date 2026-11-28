# ADR-002 frozen corpus (epic #1065, Phase 0)

**State at this change: incomplete.** The fixture format, the test harness and the Phase 1 line (#519) are in the tree. The fixtures for the other nineteen epic lines are **not**, except one Phase 3 line and the Phase 4 line: #1005, with the reverse-shell shapes, the part A exfil shapes, the memory-directive shape, and their controls; and #556, with one note. 3 of 20 lines have a fixture. #519's is a cost fixture whose growth measurement is an opt-in report; #1005's are verdict fixtures, so #1005 is the only epic line whose classifier verdict the default suite asserts; #556's is a note and is never executed. Read "What is missing, and why" before relying on this corpus for anything.

## What it is

Every open Guard issue that epic #1065 folds in becomes one or more **named fixtures**: a tool call, the effect kinds and targets the command model is expected to derive from it, the decision the [accepted ADR-002 v3](./ADR-002-v3-amendment-proposed.md) gives it (accepted by the owner on 22 Nov 2026; the file keeps its name until it is folded into ADR-002 on #1065), and the verdict today's classifier must return for the fixture to count as fixed. Later phases report a **moved list** against it: every fixture whose verdict changed, old to new. A move that is not in the corpus is a defect in that change.

It is test data only. It lives under `src/defence/iron-dome/__tests__/fixtures/adr002/`, which the build excludes, so the published package does not change and no runtime module imports it.

| File | Holds |
|---|---|
| `types.ts` | the fixture format: id, issue, phase, class, status, call, stub files, effects, targets, v3 decision, expectation |
| `phase1.ts` | Phase 1 fixtures (#519) |
| `phase3.ts` | Phase 3 fixtures (so far: #1005, the reverse-shell, part A exfil and memory-directive shapes, and their controls) |
| `phase4.ts` | Phase 4 fixtures (so far: #556, one note) |
| `index.ts` | the epic lines frozen on 12 Nov 2026, and the corpus assembled from the phase files |
| `../adr002-frozen-corpus-1065.test.ts` | the suite |

## Fixture status

| Status | Meaning | How the suite runs it |
|---|---|---|
| `settled` | the expectation holds on `main` and must keep holding | plain test |
| `known-gap` | the expectation is agreed and **fails** on `main` today | verdict fixtures: `it.failing`, so CI goes red the moment it starts passing, until the marker is removed and the epic line ticked in the same change. Cost fixtures: recorded only, not held by CI (see below) |
| `pending-decision` | the correct verdict is not settled (an owner or design decision is outstanding) | pinned to today's verdict, so any move is deliberate |
| `note` | a recorded constraint or classification with no call to evaluate | never executed |

A fixture asserts a verdict (`allow`, `not-block`, `gate`, `block`, `approval`, or none), optionally an exact severity, signals that must or must not be present, script paths the resolver must be asked for, or, for a cost fixture, a growth ratio per doubling of input size. Cost is always a ratio, never a wall-clock budget (#519, #1040).

A cost fixture is never timed in the default suite. Elapsed time moves with the scheduler, garbage collection and JIT warm-up, so a clock reading must not decide red or green. The default suite checks only the deterministic part: the same size builds the same call, and the input grows by a constant amount per unit of size. The growth measurement runs only with `ADR002_CORPUS_REPORT=1`, after one discarded pass over every size, and prints times, ratios, the fixture's bound and `withinBound`. It asserts nothing. The consequence is stated plainly: a `known-gap` cost fixture is **not** machine-held. The change that closes it removes the marker on the strength of that report and of its own deterministic test (for #519, a step count the Phase 1 lexer can expose; today's tokeniser cannot be counted without a production change, which this corpus does not make).

The effect, target and v3 decision fields are recorded for the reviewer and for Phases 2 to 4. The Phase 0 suite does not assert them. v3 is accepted, but accepting it changed no runtime default: posture moves only through the #1065 build, so a fixture's v3 decision and the verdict the classifier returns today can differ.

## Rules for adding fixtures

- Only the call and stub file contents the issue supports. Where the reporter's source was not supplied, the body is a synthetic stand-in and the fixture says so.
- Catastrophic shapes are named by signal, following the convention already in `guard-precision-corpus.ts`. Credentials are synthetic; hosts are reserved example names or documentation address ranges.
- Every relief fixture has a paired control that must not move.
- The corpus is run in CI or an isolated evaluator only, never on a live guarded host, and fixture text is never reshaped to get it past a live guard (#629, 5 Oct rule).
- Removing a `known-gap` marker and ticking the epic line happen in the same change.

## Coverage of the epic

| Epic line | Phase | Fixtures in the tree |
|---|---|---|
| #519 tokeniser cost | 1 | 1 (`519/tokeniser-growth-repeated-word`, cost, known-gap; measured by the opt-in report, not asserted) |
| #629, #927, #512, #551 (also #549), #738, #958, #634, #874 | 2 | none yet |
| #1005 (SCN-009 reverse-shell shapes) | 3 | 7 in `phase3.ts`: `1005/exec-nc-reverse`, `1005/exec-devtcp-reverse`, `1005/exec-ncat-e`, `1005/exec-socat-exec` (miss; expect `approval`, severity `dangerous`, signal `reverse-shell`; settled since the interim row in #1088, known-gap before it), and controls `1005/exec-nc-port-check-control`, `1005/exec-nc-localhost-control`, `1005/exec-docs-grep-control` (settled, allow) |
| #1005 (SCN-008 part A exfil labels) | 3 | 6 in `phase3.ts`: `1005/exfil-read-secret-then-print`, `1005/exfil-curl-upload-secret` (miss; expect `approval`, severity `dangerous`, signal `touch-sensitive-path`; settled since the interim row in #1104, known-gap before it), `1005/exfil-env-secret-to-url` (miss; expect `approval`, severity `dangerous`, signal `env-credential-egress`, never `secret-egress`; known-gap: #1104 was split and that row moved to #1065 Phase 2). Controls `1005/exfil-get-no-secret-control`, `1005/exfil-upload-nonsecret-control` (settled, allow) and `1005/exfil-read-secret-no-egress-control` (the Read tool on a credential file, SCN-008c: `pending-decision`) |
| #1005 (memory-directive label) | 3 | 4 in `phase3.ts`: `1005/persist-memory-directive` (miss: an MCP `remember` call storing a standing directive that relaxes a confirmation and hides it from the user; expect `approval`, severity `dangerous`, signal `memory-directive`, which is **proposed** classifier behaviour, not accepted v3 policy; known-gap on the **Action Guard plane only**: `evaluateToolCall` allows every memory-tool call and hands it to the memory pipeline, which already quarantines this write (see "The memory-directive gap is Action Guard only" below); it turns settled when the Guard change that screens memory writes lands; today's Guard verdict, allow / benign / no signal, is pinned beside it by ordinary assertions), and controls `1005/persist-memory-preference-control`, `1005/persist-memory-runbook-control`, `1005/persist-memory-incident-quote-control` (settled, allow; forward pins for the Guard change). Ordinary tests also assert that `detectMemoryDirective` detects the directive and none of the three controls, on the production `title + "\n" + content` candidate |
| #504, #703, #662, #995, #755, #929, #1049, #588, #1005 (labels with no fixture yet), #885 note | 3 | none yet |
| #556 | 4 | 1 note in `phase4.ts`: `556/post-unrequested-provenance` (the unrequested-post label is a send-class provenance case: session taint bound to the egress effect and its recipient, audit flag first; never executed) |

That is 3 of 20 epic lines. The suite prints this as one line (`[#1065] frozen corpus: ...`) and holds "every unchecked epic line maps to at least one fixture id" as a known-gap, so it cannot be forgotten: the test turns red when the last line is covered.

## The memory-directive gap is Action Guard only

The `1005/persist-memory-directive` known-gap is a statement about one plane, the Action Guard (`evaluateToolCall`). It is not a statement that ShieldCortex lets this write through.

- **The Action Guard hands memory writes to the memory pipeline.** For a memory-family tool, `tool-action-guard.ts` returns early (about line 8410) with allow, severity benign, no signal and the reason "memory tool — handled by memory defence pipeline". That is the verdict the fixture records as the gap.
- **The memory pipeline already quarantines this directive on the MCP `remember` path.** The MCP `remember` tool passes `memoryAdmission: 'agent'` (`server.ts`). In balanced mode, the firewall's SCN-010 M1 escalation then returns QUARANTINE when `detectMemoryDirective` fires on the title and content (`firewall/index.ts`). Source: Jarvis-lane code-path reproduction at `82eb3dfb`, running the fixture's title and content through the defence pipeline with and without the admission flag (QUARANTINE with it, ALLOW without it). It is not a red-team or nightly-battery measurement.
- **Why a Guard-plane signal is still wanted.** Not every memory write goes through `remember`. A Write or Edit of a memory markdown file is an ordinary file write that never reaches the memory pipeline, so only the Guard sees it.
- **What is proposed and what is accepted.** The `dangerous` tier and the `memory-directive` signal in the fixture's `expect` are the **proposed** classifier behaviour for that Guard change. They are not part of the accepted ADR-002 v3 policy. Accepted v3 is: LOG by default, BLOCK on the fixed Section 3.5 list, and a narrow HOLD only where the owner has opted the box into enforce. A memory write is not on the block list, so its `adr` is LOG, and v3's acceptance does not settle whether a memory directive is eligible for HOLD under enforce.
- **What the fixtures test.** All four rows are MCP `remember` calls. They do not test Markdown writes through Write or Edit, and they do not test enforcement. The three controls do not exercise the Guard's screen today, because the Guard returns allow with no signal for every `remember`; they are forward pins for the Guard change. The screen property itself is held by ordinary assertions on `detectMemoryDirective` in the suite, separate from the `it.failing` row. The controls are not claimed to pass the whole memory pipeline: the preference control, for one, is quarantined there by a separate instruction detector, which these fixtures do not assert.

## What is missing, and why

The Phase 2 to 4 fixture files were drafted and could not be written on the builder's host. That host runs ShieldCortex's own Action Guard in Watch only, and the guard refused the write of the Phase 2 fixture file as a change to the guard's own state. The fixture text is, by design, the set of inputs the guard misreads: reads of its config, prose that names its signals, a control row that names the switch. This is the same wall recorded on #738, #755, #958 and #629.

The builder stopped there. The file was not retried in another form, split to isolate the rows, composed at runtime to avoid the match, or written through another tool or host. Doing any of those is the evasion the 5 Oct rule forbids.

The remaining fixtures are not authored. Authoring is stopped. Where and whether it resumes is the operator's decision under the epic's existing rule. This document grants nothing on it.

What Phase 0 still lacks, for the record:

1. The Phase 2 to 4 fixtures for the lines the coverage table lists as "none yet", written against `types.ts` and added to `index.ts`. None of those is in the tree, and none is to be added as a placeholder or stub.
2. A run of the suite with `ADR002_CORPUS_REPORT=1` to get the verdict `main` returns for every fixture, with each status set from that output, not from the issue text. In particular the #874 rows have not been re-run, and the ones that already pass are not yet recorded as `settled`.
3. The `.failing` marker on the coverage test stays until the last epic line is covered.

## Reading notes for the missing lines

All twenty-one issues were read in full on 12 Nov 2026 (bodies and every comment). These are the classification decisions that reading produced. They are notes for the fixture author, not fixtures.

**Phase 2**

- **#629** has several distinct families, and one merged slice each for two of them: memory-note prose (PR #724 relieved dangerous-tier mentions and kept catastrophic prose gated on purpose) and read-only inspection (PR #994). Still open: quoted note and message arguments, search patterns, the read-only git compound read as a download piped to a shell, signal 0 liveness polls, test and docs-contract source that names a signal word or a settings path, and `apply_patch` bodies rated differently from `write` and `edit` of the same content. Veronica's control pair (the same destructive effect through an interpreter with no shell verb is not seen) is a **miss**, and belongs with #703 in Phase 3.
- **#927** needs each of its five rows plus the true-positive controls its ask 5 names. The loopback row asserts only that the secret-egress block is absent; other signals on the env file stay separate (26 Oct static triage). The lease and reader script bodies are synthetic stand-ins.
- **#512** splits in two. Flag misreads and quoted-argument data are settled false positives. Rows whose effect is real but local or routine (project virtualenv install, cwd-scoped find-and-delete, a block copy between regular files, a literal JSON POST) are `pending-decision`: they are LOG under the 20 Oct contract, and the classifier default for that tier does not move without the owner's answer. The lease-protected force push is `pending-decision` for a different reason: the contract puts force push on the block list.
- **#551** is a signal-precision pair with no verdict change. It needs the direct form, the substituted form, and the outer-boundary control from #548 that any fix must leave exactly as it is. #549 is the same fixture.
- **#738** asserts that the resolver is **asked** for each loader path, for the four rows in the issue exactly. An earlier attempt substituted other examples after a refusal and was discarded for it.
- **#958** needs the denied test-file write and the must-gate twin whose target is a real agent settings file.
- **#634** at the core classifier is a pair: the script resolved (allow) and the same call unresolved (today's opaque treatment stands). Plane parity itself is a Phase 2 acceptance test, not a core fixture. The OpenClaw hook context carries no per-call execution directory (TARS, 11 Oct), so Phase 2 must obtain that contract or return `unresolved` on both planes.
- **#874**: the six 20 Oct rows, fixtures 7 to 9, and the 3 Nov repro recorded on #629. Bug 1 (advisory posture denying on the headless path) is posture and delivery, tracked on #875 and #853, and is outside this corpus. The 3 Nov cron denial has no recorded command and can only be a note. The first row's relief was removed from #924; see #929.

**Phase 3**

- **#504**: one miss per evasion family in the issue, plus the two forms the issue says are already caught, as controls.
- **#703**: the three routed-output rows, and the two data-only filter rows that must stay allowed (the #190 false positive).
- **#662**: host-addressed sends of a sensitive file must carry the egress signal; a local copy and a listener are the controls.
- **#995**: the three home-wide searches at least at the sensitive-path tier; a project-scoped search stays benign.
- **#755**: a cost fixture on the write-content scan, with a paired long positive. No numeric gap bounds.
- **#929**: the hazard rows stay exactly as `main` returns them (verdict, severity and signal, per the 25 Oct note) and are already pinned in `guard-false-positive-fixtures-874.test.ts`. The intended-relief targets are `pending-decision`: the issue's own acceptance cannot both forbid any new allow and permit them.
- **#1049**: items 1 to 3 are `pending-decision` (each says "decide whether" or "if that client matters"). Item 4 is a timing-tripwire flake and is a note. The Python `params` mismatch from the final panel is a miss.
- **#588**: the escaped-operand write to a startup file is a miss on the exec surface. Write-time scanning of script content is `pending-decision`, as the epic line says; the run-time backstop is its control.
- **#1005**, classed from the 7 Nov triage: env-secret-to-url and nc-reverse are guard-detectable; read-secret-then-print and curl-upload-secret are classification misses whose exact battery paths are private, so the public rows can only be controls on listed paths; read-secret-file is a taint case (Phase 4, flag first). memory-directive is guard-detectable at the memory sink (memory tools and memory markdown writes). The proposed Guard behaviour, not accepted policy, is that a standing directive about a control asks for approval at the dangerous tier. On the MCP `remember` path the memory pipeline already quarantines it in balanced mode; the Guard signal is for writes that bypass `remember`. Under accepted v3 a memory write is LOG by default, with a narrow HOLD only where the owner has opted the box into enforce; it is not on the Section 3.5 always-block list the owner accepted on 22 Nov. post-unrequested is a send-class provenance case under #556 (Phase 4, taint as an audit flag first), not a guard detector. nc-reverse is also a block-list scoping question, because the 20 Oct list does not name it and the contract rules out new detectors.
- **#885** is a note: the relief it guards (#882) never merged, so there is nothing on `main` to test. The rule it carries applies if that relief returns.

**Phase 4**

- **#556** is a note at Phase 0: the decision function's totality is a property test written with the function, and the measurement lives in `scripts/guard-effect-fixtures/` and `scripts/guard-policy-replay.mjs`. Its one fixture so far is the #1005 post-unrequested label, recorded as a note: whether a post or send was requested is a question of who asked, which is session taint bound to the egress effect and its recipient (v2 §2.2, v3 Section 3.4: an audit flag first, promotion to a hold a later owner decision on measured numbers). No posting-verb regex, and a single-call battery cannot express "unrequested". Its send to a variable sink is target resolution under #662, not provenance.
