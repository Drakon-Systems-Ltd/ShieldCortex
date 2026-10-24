# Design: always-deny for execution of agent-authored native code (#907)

**Status:** Design only. No source change in this branch.
**Issue:** #907 (raised by Michael, 23 Oct 2026). **Author:** TARS (improvement loop).
**Relates to:** ADR-002 (`docs/architecture/ADR-002-provenance-first-enforcement.md`) — this
is one DENY row and two HOLD rows under that ADR's effect decision, plus a provenance store.
ADR-002's §2.2 taint store is **not wired** (`session-taint-lineage.ts` says so); this design
does not depend on it for any floor row and does not claim it (§4, Q1). ADR-001's intent-first
law, catastrophe hard-stops and credential non-exfil rule are unchanged.

> **Invariant up front (ADR-002 / M1).** The Guard is **OFF by default**. Everything below is a
> rule that applies *only when the Guard is enabled*. Nothing here turns the Guard on, changes
> its default posture, or changes who it is on for. The **floor** (rows A/C/D) is held to "never
> fires on routine work": it fires only on directly-written native bytes, never on a compiler's
> output. The issue's compile-then-run case is **not** in the floor; it is row B, whose verdict
> is owner question Q1 (AUDIT recommended — and AUDIT is **not** a door). The **unknown door**
> (row J) is a new HOLD on routine work in one place, stated plainly rather than hidden: a native
> binary at a project-local path whose production the guard did not observe — a pre-existing
> `./target/debug/app`, a build driver's output — is held (§4.2, §9).

> **Round-3 note (last fold under the cap).** Round 2 (Astra, Grok) returned CHANGES REQUESTED.
> This revision **removes or narrows** claims rather than adding coverage. The moves, each stated
> once and referenced elsewhere:
> 1. **Rule H** (§3.1): install-root location never certifies non-agent authorship by itself.
>    Relief at an install root is reached only through a **complete** per-session record of
>    write-family targets inside install roots; a write into an install root that cannot be
>    durably recorded is held instead of proceeding unrecorded. Loss, eviction and overflow of
>    those records are made impossible by construction or fail to the door.
> 2. **Rule P** (§3.1): a record is **intent**; a header at exec proves **format**, not
>    authorship. A record counts as the producer of the current bytes only if the file's content
>    identity changed after the recorded call. An unproved record — a failed write, a metadata-only
>    `chmod`, a failed compile — is treated as **no record**. An unproved compile label can no
>    longer weaken the floor.
> 3. **Build drivers are demoted** (§3.4): only a recognised compiler with a literal, resolvable
>    `-o` output gets compile lineage. `cargo`/`go test`/`make`/`npm run build`/`pip install`
>    outputs are **unsupported-output**: a later exec of them is row J, not row B.
> 4. **"Not in the ledger"** means unknown **only for a native image at a non-install path** (§3.1).
> 5. **Taint (B′)** is not wired; B′ HOLD is not a PR 1 result (§4, Q1).
> 6. **Hermes** coverage is stated per inspected surface and per `enforce` (§6).
> 7. §10 residuals now state the **actual** verdict (several were wrong-direction in round 2).

---

## 1. What #907 asks for, and the one honest tension in it

The issue wants "agent-authored native code reaches the CPU" to be a hard-denied
effect. It lists four shapes:

1. write a compiled binary / object file / raw bytes, then execute it;
2. compile code the agent just generated (`cc`/`gcc`/`clang`/`rustc`/`go build`/`zig`…)
   and run the output;
3. interpreter escape hatches that execute native code (ctypes / cffi / `mmap` with
   execute permission, Node native addons, `dlopen`/`LD_PRELOAD` of a just-written `.so`);
4. generate code at runtime and execute it from writable memory.

Shapes 1, 3 and 4 have **few routine developer analogues** *in the directly-written form*.
Nobody hand-writes an ELF or Mach-O and runs it, or `LD_PRELOAD`s a `.so` they produced **by
hand** (not by a compiler), as part of ordinary work. Executable-memory shapes (shape 4) do have
benign analogues — JIT, FFI and test code — and §4.2 counts them as false-positive surface. A
`.so`/`.node` that a **guard-observed compiler** produced is shape 2, not shape 1/3 (§2).

Shape 2 is the tension. **Compiling source the agent just wrote and running the output is both
the attack path and the single most common thing a coding agent does.** The guard cannot tell a
Rowhammer proof-of-concept's source from a legitimate helper's source by reading the content.

**Therefore an honest always-deny floor cannot include shape 2 without blocking routine
compile-and-test.** Shape 2 is row B, whose verdict is owner question Q1 (AUDIT recommended,
HOLD or DENY the alternatives). AUDIT is a logged, unenforced verdict — not a door. This is
stated plainly rather than papered over with an allowlist of command names, which ADR-002 §2.4
forbids.

---

## 2. Effect class and signal names

New effect kind added to ADR-002 §2.4's taxonomy (the taxonomy says "an implementation
may name more"):

| effect kind | what it covers |
|---|---|
| `native-exec-of-agent-artifact` | executing, loading, or mapping-as-executable a native artifact whose current bytes the guard has **evidence the agent produced in this session by a write-family call** (Rule P, §3.1), and which did **not** come from a guard-observed compile — or mapping just-written bytes as executable memory (text-decidable). **DENY floor.** |

and one signal that is **not** the floor:

| signal | what it covers | tier |
|---|---|---|
| `exec-of-agent-compiled-artifact` | the agent ran a recognised compiler with a literal, resolvable `-o` output (§3.4), Rule P shows that compile produced the current bytes, and the **agent** then runs or loads that output (shape 2, including a compiled `.so`/`.node` loaded via `dlopen`/`require` when the load is visible) | Q1: AUDIT recommended, or HOLD, or DENY |

**The compile-lineage boundary.** For the same bytes at the same path, the only thing that
separates floor (row A/C) from row B is whether Rule P names a **compiled-output** record or an
**agent-written** record as the producer. An unproved compile record is no record (Rule P), so a
failed compile over directly-written native bytes leaves the write record as the producer and the
floor still fires. Row C carries the same rule, so the two cannot disagree.

Signal vocabulary (kebab-case, mirrors `opaque-script-invocation`, `write-content-catastrophic`):

- `native-exec-of-agent-artifact` — umbrella signal on the floor verdict.
- `exec-agent-written-native-bytes` — shape 1 (row A).
- `map-exec-agent-written-memory` — shape 4 and the `mmap`/`mprotect` + execute and
  ctypes/cffi-call-into-buffer forms of shape 3 (row D). **Decidable from inspected body text
  only** — see §6 for which surface each plane actually inspects.
- `load-agent-written-native-object` — shape 3 loader form (row C).
- `exec-of-agent-compiled-artifact` — shape 2 (row B).
- `unclassified-executable` — ADR-002's own name for the unknown-provenance door (row J);
  reused, not new vocabulary.

These names are added to `SAFE_SIGNALS` in `scripts/pre-tool-hook.mjs`,
`SAFE_ACTION_GUARD_SIGNALS` in `src/defence/iron-dome/operator-notify.ts`, and
`SAFE_SUMMARY_SIGNALS` in `scripts/stop-hook.mjs`. Hermes carries bounded string signals
(`sc_client.py`) and OpenClaw has no separate signal table, so there are no further tables to edit.

---

## 3. Provenance data model (content-free, bounded, cross-call)

### 3.1 The agent-artifact ledger, Rule P, Rule H, and the total classifier

A per-session record of the write-family and compile calls the guard saw. It is the typed host
fact the ledger-dependent rows read; it is **not** derivable from command text (invariant 5).

```
AgentArtifactLedger (keyed by host-owned sessionKey)
  general: Array<{                 // JSON file, FIFO-bounded
    pathHash: string               // HMAC(salt, canonical-abs-path), NOT the path
    kind:     'agent-written' | 'compiled-output'
    preId:    ContentId | 'absent' // content identity of the path at the pre-gate
    at:       number               // ms, ordering + FIFO eviction only
  }>
  pins: <sessionDir>/pin/<pathHash>.<seq>   // one create-once file per record whose
                                            // target is inside an install root (Rule H);
                                            // body = { kind, preId, at }; never evicted
ContentId = { dev, ino, size, mtimeMs }     // stat fields; ctime deliberately excluded so a
                                            // metadata-only chmod/chown does not count
```

**Rule P — production evidence (the one rule for "did this record produce these bytes").**
The pre-gate sees a call's **intent**, not its completion (§3.4). A header read at exec proves
the bytes are a native **format**; it does not prove who wrote them. So a record is evidence that
the recorded call produced the current bytes only if the path's current `ContentId` **differs**
from the record's `preId`. For a path with several records (newest first, per-path window of 4),
the **producer** is the newest record whose `preId` differs from the current `ContentId`. If no
record in the window qualifies — the write failed, was refused by another gate, was a
metadata-only `chmod`, or the compile never produced — the path has **no producer**, which is
treated **exactly as no record**. Consequences:

- a failed write against an existing native file leaves its `preId` equal to the old file's
  identity → unproved → the old bytes are not attributed to the agent (round-2 B2 example 1);
- a failed compile over directly-written native bytes leaves the compile record unproved → the
  older write record is the producer → floor, not row B (round-2 B2 example 2);
- `chmod`/`chown` on existing native bytes changes ctime only → unproved (round-2 B2 example 3).

What Rule P does **not** prove: that the recorded call, rather than a later **unrecorded** writer
in the same session, made the change. A change after a recorded intent is attributed to that
record. That is a classification limit, listed in §10 with its actual verdict.

**Rule H — install-root relief requires complete install-root history (the one rule for
"location").** `isInstalledBinaryPath` (`tool-action-guard.ts:4813`) is a path-string test:
`INSTALLED_BIN_DIR_RE` plus "extensionless". It covers user-writable roots (`~/.local/bin`,
`~/.cargo/bin`, `node_modules/.bin`, …), and its own rationale (`:4790-4797`) concedes files can be
planted there. **Location alone never certifies non-agent authorship.** Relief is justified only
by a positive completeness fact about this session's writes into those roots:

1. Every write-family call whose resolved target is inside an install root is recorded as a
   **pin**: a create-once file (`O_CREAT|O_EXCL`) named by `pathHash` and a sequence number. Pins
   are never FIFO-evicted and never read-modify-written, so the general store's
   last-writer-wins race, corrupt-as-empty read and cap eviction cannot drop one.
2. The pin is persisted **before** the write call is let through. If it cannot be persisted —
   no session key, unwritable store, pin cap reached (proposed 256 per session) — the write call
   itself is **held** (row J) instead of proceeding unrecorded.
3. At exec, if the session's pin directory cannot be listed, install-root relief is withdrawn
   for that session: a no-producer native image at an install root is state 3 (door).

Under Rule H, an install-root native image with no producing record is state 2 only because the
guard positively knows no recognised write-family call in this session produced it. The rule's
limits — unrecorded exec-surface creators, cross-session/TTL, widenable holds on non-enforcing
hosts — are §10 residuals with their real verdict (allow), not covered cases.

**The total classifier.** For an exec/load target the guard resolves to a path `p` (§3.4, §5):

| step | condition | state | rows |
|---|---|---|---|
| 0 | `p`'s header is not a native image (script/text), or `p` cannot be read | **outside this design** — current behaviour (including the existing opaque-script audit) | — |
| 1 | native image; Rule P producer is `agent-written` | **1 — agent-produced** | A / C (floor) |
| 1c | native image; Rule P producer is `compiled-output` | **1c — compile-lineage subtype** | B |
| 2 | native image; no producer; `p` passes `isInstalledBinaryPath`; Rule H history complete | **2 — install-root, no session write** | F/G: current behaviour |
| 3 | native image; no producer; any other case (non-install path, or Rule H incomplete) | **3 — unknown** | J (door) |

So the three authorship states are 1 / 2 / 3, with 1c as the compile-lineage subtype of an
observed producer. **"Not in the ledger" has exactly one meaning: for a native image at a
non-install path (or at an install root without complete history) it is unknown → row J.** For a
non-native target it means nothing to this design: the target is outside the classifier and
keeps current behaviour. There is no sentence elsewhere in this document that overrides this table.

- **Content-free in audit (invariant 4).** The ledger stores **hashes of paths** and stat
  identities, never path text and never file contents. A denial's audit row names the *effect*
  and the *signal*, and at most a `fmtSpan`-bounded fragment of the **command** the operator can
  already see. The ledger never reaches an audit row.
- **Keyed by host-owned session identity.** The key is `sessionKeyFor(id)` — the HMAC the hook,
  `session-guard.ts` and `stop-hook.mjs` already compute from the host's `session_id`.
  `hookSessionExtras` sets `namedIdentityUnresolved` only for a *non-empty unresolved* id, so the
  new code treats an **absent** key the same as an unresolved one: no ledger. With no ledger,
  every native image at a non-install path is state 3, and every install-root write is held
  under Rule H step 2.
- **Bounded — new bounds, not inherited lease-store constants.** The store mechanism (flat JSON,
  atomic tmp+rename, `0o600`, TTL) mirrors `session-lease-store.ts`; the layout (one directory per
  `sessionKey`) and caps do not. New constants in the pure core: general entries per session
  (proposed 512), per-path window (4), pins per session (256), max distinct sessions, TTL measured
  from the session's last ledger activity.
- **Loss of a general record fails toward the door, by the classifier, with no tombstone
  needed.** A general record covers only non-install targets (install-root targets are pins).
  If it is evicted, lost to a race, or read as corrupt-empty, its path has no producer and is a
  native image at a non-install path → state 3 → row J. It can neither manufacture a DENY (no
  producer remains) nor reach state 2 (wrong location). The round-2 tombstone ring and its
  "install-path backstop" assertion are **removed**: Rule H replaces them.

### 3.2 Where it lives and how a separate-process hook shares it

Flat files, not SQLite, under `~/.shieldcortex/` (honouring `SHIELDCORTEX_*`): the Claude Code
hook has no DB on its hot path, and a store one plane cannot read is a plane that silently does
not bind. Each hook invocation is a **separate process** reading the same per-session directory.
The general JSON is best-effort last-writer-wins between concurrent calls; by §3.1 a lost general
record lands in row J. Pins are create-once files and have no read-modify-write race.

### 3.3 Two split cores (same discipline as `session-taint-lineage.ts` + `session-lease-store.ts`)

- **Pure core** `src/defence/iron-dome/agent-artifact-provenance.ts`: record/query/evict
  arithmetic, hashing, Rule P producer selection, Rule H completeness, the total classifier,
  caps, native-header classification over injected bytes. No I/O, injected clock.
- **fs layer** `src/defence/iron-dome/agent-artifact-store.ts`: the one entry point both
  planes call; atomic writes, create-once pins, stat, TTL, corrupt-as-empty for the general file.

### 3.4 Capture point — forced by there being no PostToolUse hook

**Measured fact.** No enforcement adapter registers a post-tool completion hook.
`src/setup/settings-hooks.ts` registers `PreToolUse`, `SessionStart`, `UserPromptSubmit`,
`PreCompact` by default; OpenClaw registers `before_tool_call` plus `session_end`, `agent_end`,
`llm_input`, `llm_output`, `before_agent_run`, but no `after_tool_call`; Hermes registers
`pre_tool_call` only. So recording happens at the pre-gate of the write/compile call, and the
record is **intent**. Completion is reconciled later, at the exec that matters, by Rule P's
content-identity comparison — not by any completion observation, which no adapter has.

Capture rules:

- **Any write-family tool call** (`WRITE_TOOLS`, `tool-action-guard.ts:133`) whose target path
  resolves → stat the target for `preId`, then record `agent-written` (a pin if the target is
  inside an install root, else a general entry), **regardless of extension or content**. The
  native-vs-source distinction is made at exec by the header read; whether the call changed the
  bytes is decided at exec by Rule P. The old `isScriptLikeWritePath` /
  `writeContentLooksExecutable` predicates (script suffix / shebang only) are not used for this.
- **A recognised compiler with a literal, resolvable output.** Supported output-resolution
  contract, and nothing wider: the program position (read with `detectScriptInvocations` /
  `tokeniseStatement` / `commandBaseName`, no new regex family) is one of `cc`, `gcc`, `g++`,
  `c++`, `clang`, `clang++`, `zig cc`, `nvcc`, `ghc`, `rustc`, `go build`, **and** the statement
  carries a literal `-o <path>` / `-o<path>` operand that resolves against the call's cwd →
  record `compiled-output` for that path with its `preId`. This is not a command-name exemption:
  nothing is allowed by name; the name only says where to look for the output operand.
- **Unsupported output — honest result.** A compiler with no literal `-o` (`cc foo.c` → `a.out`),
  and every build driver (`make`, `cmake`, `ninja`, `node-gyp`, `cargo`, `go test`, `go run`,
  `npm run build`, `pip install`), records **nothing**: PR 1 cannot name their output path. The
  outer invocation keeps current behaviour (the driver binary is an installed tool; its children
  are unseen, ADR-002 §2.3 outer-gate limitation). A **later, separate** agent exec of their
  output that the guard resolves to a native image at a non-install path is **state 3 → row J
  (HOLD)** — not row B. Build-output-directory awareness is Q3 / PR 2.

**Exec-surface creation paths that are NOT recorded.** These create a file through the exec
family (Bash/shell), not a `WRITE_TOOLS` call, so no record is minted:

1. shell redirection and here-docs to a file;
2. `dd`, `printf`, `tee`, `base64 -d`, `xxd -r` writing bytes to a path;
3. `curl`/`wget`/`fetch` downloading a file;
4. an interpreter writing a file inline;
5. a build driver or package lifecycle child (see "Unsupported output");
6. **same-command write-and-exec** (a redirect then an exec of the same file, or a compile then
   an exec of its output, in one Bash call): the pre-gate runs before the file exists, so there
   is no header to read.

The verdict each actually gets is in §10. In short: if the file is created at a non-install path
and a **later, separate** call execs it as a native image, it is row J; if it is created inside an
install root, or execed in the same call, it keeps **current behaviour (allow)**.

Recording is done by the **caller** (hook/interceptor), not inside `evaluateToolCall`, preserving
that function's purity — the same split as the injected `resolveScriptSource`.

---

## 4. Decision table

`A` = the artifact being executed/loaded/mapped; "state" is the §3.1 classifier. There is **no
taint column**: no PR 1 adapter supplies the ADR-002 taint fact (see B′).

| # | Case | State / signal | Verdict | Rationale |
|---|---|---|---|---|
| A | Exec of a native image whose Rule P producer is an `agent-written` record | 1 / `exec-agent-written-native-bytes` | **DENY (floor)** | shape 1; the guard observed the agent's write change these bytes and no compile produced them |
| C | `dlopen`/`LD_PRELOAD`/`DYLD_INSERT_LIBRARIES`/`require` of a native object (resolved target) whose producer is `agent-written` | 1 / `load-agent-written-native-object` | **DENY (floor)** | shape 3 loader form; a compiled object is row B |
| D | Inspected program body maps written/just-generated bytes as executable memory (`mmap` PROT_EXEC, `mprotect` +X, ctypes/cffi call into a buffer) | `map-exec-agent-written-memory` | **DENY (floor)** | shape 4; text-decidable **from the body the plane inspects** (§6); needs no ledger; a body the plane does not inspect is current behaviour (§10) |
| B | Agent runs/loads a native image whose producer is a `compiled-output` record (§3.4 supported contract) | 1c / `exec-of-agent-compiled-artifact` | **Q1** (AUDIT recommended; HOLD; DENY) | shape 2; routine compile-test |
| B′ | Same as B in a session ADR-002 would call tainted | — | **Not a PR 1 row.** | the ADR §2.2 taint store is not wired (`session-taint-lineage.ts:16-17`); no PR 1 adapter can tell B from B′ (Q1 note) |
| E | The build output the agent compiled, run from the user/cli **band** | band-attested, **not** human-attested (Q2) | **no new gate; current behaviour** | the band is process identity; it never relieves a floor match (floor DENY takes precedence regardless of band) |
| F | Installed tool (`git`, `node`, `python`, system `cc`) — native image at an install root, no producer, Rule H complete | 2 | **no new gate; current behaviour** | non-false-positive in the issue; relief by Rule H, not by absence |
| G | `node_modules/.bin/<tool>` (the only package-tree arm `INSTALLED_BIN_DIR_RE` has) — native, no producer, Rule H complete | 2 | **no new gate; current behaviour** | a wheel entry point or `.venv/bin` tool is **not** in the regex: if native it is state 3 (row J); if a script it is outside the classifier |
| H | Interpreter running an existing script | outside the classifier (the script is not a native image) | **current behaviour** | an interpreted script is not a native artifact; only row D's body match can apply to it. Installed-interpreter location says nothing about the script's provenance |
| I | Build tool writes a declared build output, run from the user/cli band | band-attested (Q2/Q3) | **no new gate; current behaviour** | row E generalised — subject to Q2/Q3 |
| J | Native image, no producer, not state 2: non-install path; or install root with Rule H incomplete; or no session key; also a write-family call into an install root that cannot be pinned (Rule H step 2) | 3 / `unclassified-executable` | **HOLD (door)** | ADR-002 §2.4 fail-closed rule for an executable effect of unknown provenance |

**Precedence** is ADR-002's DENY > HOLD > AUDIT. A floor row denies at any taint state with no
approval path, on the terminal branch (`TERMINAL_BLOCK_SEVERITIES`, the doorless branch in
`pre-tool-hook.mjs:3307`). The floor is not a text pattern for A/C: it requires a Rule P producer
plus a native header.

**"ALLOW" is not a fourth decision tier.** ADR-002 §2.4's decision set is DENY / HOLD / AUDIT.
Rows E–I are "no new gate — the call keeps its existing behaviour", not a new verdict.

**Three-valued mapping, scoped to the core decision contract.** In the pure evaluator with a
ledger view and a header reader supplied: state 1 → DENY; state 1c → Q1; state 2 → current
behaviour; state 3 → the existing `require_approval` door, never a fabricated catastrophic.
Where an **adapter** cannot supply those inputs or cannot enforce the door, the outcome is that
adapter's, listed next to the acceptance rows in §6 and §9 — the core contract does not claim it.

### 4.1 Rows needing a typed host fact rather than text (invariant 5)

- **A, C** — need the **ledger** (Rule P producer), a **stat** of the target (current
  `ContentId`), and a **header read**. Neither header nor record alone suffices: header alone
  would deny installed `git`; a record alone is only intent.
- **D** — text-decidable from the body the plane inspects; no ledger.
- **B** — Rule P producer of kind `compiled-output`.
- **E/I** — DefenceSource band (`resolve-tool-source.ts` / `env-detector.ts`). The band is
  process identity: `env-detector.ts` labels a direct Claude Code / Codex CLI `type: cli`, and
  ADR-002 §1.2 says an operator's request and an injected model's request in one session share
  the band. It is **band-attested, not human-attested** (Q2). "Declared build output" needs a
  build-config fact (Q3).

### 4.2 False-positive surface (what the non-FP bar does and does not cover)

What the design **does not** gate (benign controls in §8): installed tools at install roots with
complete Rule H history; non-native targets (scripts, data files); outer build-driver invocations;
a supported compile followed by an exec of its output under Q1 = AUDIT.

What the design **does** gate on routine work, stated so "no false positives on pre-existing
tools" cannot be read as covering it:

- **Row J holds pre-existing project-local native binaries** (yesterday's `./target/debug/app`, a
  vendored `./bin/tool`) and **build-driver outputs** (`cargo build && ./target/debug/x`, a
  `node-gyp` `.node` loaded by a visible `require`) when a later, separate agent call execs them.
  Today those are an opaque-script **allow** at the sensitive tier (`tool-action-guard.ts:7318-7325`);
  under this design they are `require_approval`. When the Guard is enabled it enforces by default
  (`pre-tool-hook.mjs:79`), so this is a real trip on routine work — the priced cost of ADR-002's
  "unknown executable is HOLD" rule. It is not claimed as met by the non-FP bar (§9).
- **Row D can match benign executable-memory shapes** (JIT, FFI, test code); the §8 row-D fixture
  is itself benign no-op bytes. No benign row-D control is claimed; this surface is unmeasured.
- **Row A fires on placed, not authored, native bytes**: a write-family `cp`/`mv` of an existing
  binary to a non-install path, then an exec of it, has an `agent-written` producer. Rare in
  routine work, unmeasured.
- **Row B** under Q1 = HOLD is one bounded approval per compile-then-run chain.

Measurement, within its real limits:

- `scripts/guard-policy-replay.mjs` compares **signal sets** over logged events and
  `scripts/replay-guard-corpus.mts` replays **truncated STOP-event previews**;
  `guard-effect-fixtures/README.md` says its log carries no command. None of them can reconstruct
  authorship, content identity, compile completion or taint, and **none is a corpus of allowed
  calls with commands**. So the replay cannot measure this design's flip rate, and it cannot list
  which allowed events carried write/compile/exec shapes. That scope is **unknown** until a
  suitable allowed-call corpus exists; none is claimed here.
- the `guard-effect-fixtures` harness is an **in-process simulation** (its own README), not
  proof of host enforcement;
- `guard-precision-corpus.ts` gets the benign compile-and-test rows so a regression that
  floor-denies a supported compile output fails CI.

Acceptance bar, pre-registered and narrowed to the control set: **zero** §8 benign controls hit
the **floor**; the three directly-written shapes (A/C/D) denied with a plain-English reason on the
planes listed in §9. Row J holding project-local binaries is **expected**, not a pass of the non-FP
bar.

---

## 5. Surfaces to change (every file and call site)

**PR 1 (the floor + ledger + door, Claude Code hook and OpenClaw):**

- `src/defence/iron-dome/agent-artifact-provenance.ts` **(new, pure core)** — §3.3.
- `src/defence/iron-dome/agent-artifact-store.ts` **(new, fs layer)** — §3.3.
- `src/defence/iron-dome/tool-action-guard.ts`:
  - new `ToolGuardOptions` members, injected per call by the caller, never throwing:
    - `artifactView?: AgentArtifactView` — the caller has **already bound** the session: it is the
      loaded ledger for this call's `sessionKey` (general entries + pin listing + a
      `pinsReadable` flag), or `null` when there is no key. The pure evaluator never derives a
      key and never receives one; a key asserted in content cannot reach it.
    - `statPath?: (absPath) => ContentId | null` and `readFileHeader?: (absPath) => Uint8Array | null`.
    - `cwd?: string` — the call's working directory, already validated by the caller
      (hook: `pre-tool-hook.mjs:540-549` rules; OpenClaw: `toolCallCwd(context)`).
  - **Canonicalisation:** a program-position or loader-target token containing `/` is resolved
    against `cwd`, `~` expanded, and the parent directory `realpath`ed; the basename is kept
    (so a symlink target is what the header read sees). **Bare names are not resolved through
    PATH** in PR 1 — a bare-name exec of a planted binary is a §10 residual.
  - **Missing-input precedence:** if `artifactView` is `undefined` (an adapter that does not
    wire it — Hermes API in PR 1, any older caller) the native classifier **does not run** and
    the call keeps today's behaviour; this is adapter non-coverage, recorded in §6/§9, not an
    allow claim. If `artifactView` is `null` (no session key) the classifier runs with no
    producers and Rule H incomplete. If `statPath` or `readFileHeader` returns `null` for the
    target, the target is outside the classifier (step 0).
  - new classifier `classifyNativeExec(execSurface, view, statPath, readFileHeader, cwd)` built on
    `detectScriptInvocations` / `tokeniseStatement` / `commandBaseName` / `EXEC_WRAPPER` /
    `SCRIPT_INTERPRETER` / `isInstalledBinaryPath` and the existing body-fold regions — no new
    regex family.
  - wire into `evaluateToolCall`: A/C/D on the terminal branch (block, terminal severity —
    **not** added to `GUARD_SELF_PROTECTION_SIGNALS`); J on `require_approval`; B at Q1's tier.
- `scripts/pre-tool-hook.mjs`:
  - at the write/compile pre-gate, stat the target and call the store's record entry points
    keyed by `baseExtra.sessionKey`; when `namedIdentityUnresolved` **or** the key is absent,
    record nothing and apply Rule H step 2 to install-root targets;
  - build `artifactView` for this call's key and inject it with `statPath`, `readFileHeader`
    and `cwd` into the 4th `evaluateToolCall` argument beside `resolveScriptSource`;
  - add the signal names to `SAFE_SIGNALS`;
  - **non-widenable floor vs widenable door.** Floor rows exit at the
    `TERMINAL_BLOCK_SEVERITIES` branch (`:3307`) before the `autoApprove`, shadow and
    `enforce:false` advisory widenings. Row J (and Rule H's held install-root write) is an
    ordinary `require_approval` and **is** widenable: on an advisory, shadow or
    standing-`autoApprove` host it warns or auto-approves, and Rule H's guarantee does not hold
    there (§10).
- `plugins/openclaw/interceptor.ts` — the action-evaluator call at `:2169-2176` (the 3rd
  `createInterceptor` argument, `index.ts` ~4811, not `runDefencePipeline`). The interceptor
  derives the key from `context.sessionId` with the same host-owned keying it already uses for
  its stores, builds `artifactView`, and passes it with `statPath`, `readFileHeader` and
  `cwd: toolCallCwd(context)`. Writes/compiles are recorded in the same `before_tool_call` path.
  Existing OpenClaw detection-taint escalation (`:2182-2218`, `session-taint.ts:156-167`) is
  untouched: it raises a `sensitive` verdict to `require_approval` and a `dangerous` one to
  `block` for a bounded window after a scan hit, and fails soft. It is **not** ADR-002 provenance
  taint and is not claimed as B′.
- `src/api/visualization-server.ts` (`POST /api/v1/action-guard`, `:566-577`) accepts `tool` +
  `args` only and calls `evaluateToolCall` with **no options** (no resolver, no view). PR 1
  extends it to accept the host-owned session id and forward it; it does **not** hold the store
  (PR 2).
- `plugins/hermes/shieldcortex/sc_client.py` — forward the session id; add a text-only
  `fallback_native_exec_memory_match` (row D shape) to the outage path, wired like
  `fallback_catastrophic_match` (unconditional when it matches). It reads only
  `fallback_surface(args)` (§6).
- `plugins/hermes/shieldcortex/policy.py` + `__init__.py` — thread the session id and the new
  fallback flag. No change to the unmatched-outage `None` path or to `enforce` handling.
- Tests: `src/defence/iron-dome/__tests__/native-exec-of-agent-artifact-907.test.ts` (pure core:
  Rule P, Rule H, total classifier), the §8 rows, and benign rows in `guard-precision-corpus.ts`.
  **Adapter-fixture obligation (implementation, not simulation):** at least one multi-call test
  per wired adapter that drives the **real** hook process (`pre-tool-hook.mjs` as a subprocess)
  and the real OpenClaw interceptor across separate calls against real files under a test-pinned
  home, covering write → exec (A), failed-write → exec (Rule P), and install-root write → exec
  (Rule H). The `guard-effect-fixtures` simulation does not discharge this.

**PR 2 (Hermes API-up store + build-output awareness):** server-side store and view so A/C/B/J
evaluate on the Hermes **API-up** path; cross-plane parity tests; Q3 build-output-directory
awareness. PR 2 does **not** close the Hermes outage case: an unavailable server cannot supply its
store.

**Separate prerequisite (not PR 1 or PR 2):** ADR-002 taint wiring. Until it lands, B′ does not
exist as a verdict (§4, Q1).

**PR 3 (separate issue — doctor shared-host warning, issue item 4):** §7.
**PR 4 (separate issue — egress tightening, issue item 5).**

---

## 6. Cross-plane behaviour (invariant 4)

Coverage is stated **per inspected surface and per posture**. "Inline body" = program text
present in the tool call's own arguments; "file body" = the contents of a script the call runs.

| plane | A / C | D | B / J |
|---|---|---|---|
| Claude Code hook | PR 1: **block**, any posture (terminal) | PR 1: **block**, any posture, for inline bodies and file bodies the hook folds (`resolveScriptSource`, within `MAX_SCRIPT_BYTES`/`MAX_FOLDED_BYTES`); an unfolded or over-cap body keeps current behaviour | PR 1: `require_approval` → ask; **widenable** by advisory/shadow/`autoApprove` |
| OpenClaw interceptor | PR 1: **block** (terminal) | PR 1: as hook (it injects `resolveScriptSource` too) | PR 1: same posture limits as the hook |
| Hermes, API up | **not covered in PR 1** (the API evaluates with no view); PR 2: `block` | PR 1: **inline body only** — the API passes no script resolver, so a file body is not read → **block** on a match | PR 2. Then `require_approval` → **block when `enforce`** (default on) or a self-protection signal is present; with `SHIELDCORTEX_ENFORCE=0` it returns `None` → **allow** (`policy.py:124-127`). The new signals are not self-protection signals |
| Hermes, outage | **not covered** — unmatched → `None` → **allow** (`policy.py:77`) | **inline text only, within `fallback_surface`**: the selected keys (`command`, `code`, `script`, …; **not** a write tool's `content`), joined and truncated to 4096 chars (`sc_client.py:131-157`). A match blocks unconditionally. A **file body** (write-then-run) and a body beyond the cap are **not covered → allow** | not covered → **allow** |

**The honest Hermes statement.** Hermes has no approval prompt and no door for an unmatched
outage shape; ADR-002 records its outage behaviour as "partial fail-open, loudly audited". On
outage this design adds exactly one thing: an inline-text row-D match within the fallback surface.
It does **not** make the write-then-run form of row D outage-safe, and it does not give A/C/B/J any
outage coverage. On API-up, Hermes A/C/B/J arrive with PR 2; row D API-up is inline text only.

---

## 7. Doctor shared-host check (outline — separate PR 3)

Issue item 4. Modelled on `checkStaleShieldCortexCopies` in `src/cli/doctor.ts`
(`CheckResult`, `warn` status). Outline:

- **Name/label:** `Code-execution host isolation`.
- **Fires when:** the Guard is enabled *and* a code-executing agent session shares a host
  or kernel with secrets it should not reach — detected from host facts already available
  (container markers under `/proc`/cgroup, presence of credential stores on the same
  mount, sibling agent sessions on the same kernel).
- **Verdict:** `warn` (never `fail` — it is advisory; hardware-flaw attacks cross container
  boundaries, so a container is not isolation). Recommends separate VMs/machines or
  disposable sandboxes for code-executing agents.
- **Honest scope line in the message:** this narrows one attack path; it does not fix the
  hardware flaw and a shared CPU remains a shared CPU.

---

## 8. Test plan (GitHub CI; benign fixtures only)

Fixtures run in CI via Jest + the `guard-effect-fixtures` harness (an in-process simulation) plus
the §5 adapter-fixture obligation. Exploit rows are described by *shape*; benign fixtures are real
files. Fixtures write under the test-pinned home, never `$HOME/.shieldcortex`, and avoid
`os.tmpdir()` for watch-adjacent paths. Expected columns are **Claude hook + OpenClaw** unless a
row says otherwise.

**Acceptance rows from #907:**

- **(a) agent writes and runs a compiled binary** → a write tool **creates** a new file (`preId`
  absent) whose bytes carry a native magic header (a tiny benign committed stub), then a separate
  call execs it → **DENY** `exec-agent-written-native-bytes`. (A `chmod` alone is not this
  fixture — Rule P makes it unproved.)
- **(b) compile-then-run across two calls** → call 1 writes `helper.c` and runs
  `cc helper.c -o helper`; call 2 runs `./helper` → `exec-of-agent-compiled-artifact` at **Q1's
  verdict** — **not** DENY (§9). No taint variant: B′ is not a PR 1 row.
- **(c) LD_PRELOAD of a just-written library** → a write tool creates `libx.so` (no compile), then
  a command sets the preload variable to it and runs a program → **DENY**
  `load-agent-written-native-object`.
- **(d) Python mapping executable memory** → the `mmap` PROT_EXEC / `mprotect` +X /
  ctypes-call-into-buffer *shape* with benign no-op bytes, as (i) an inline `-c`/heredoc body and
  (ii) a written script then run → **DENY** on the hook and OpenClaw for both. Hermes: (i) only,
  API-up and outage (outage only within 4096 chars of the fallback surface); (ii) is **not**
  covered on Hermes and is asserted as **allow** on the outage path so the gap is visible.

**Rule P / Rule H controls:**

- failed write against an existing native file (simulated by recording, then not changing the
  file) → exec → **row J** at a non-install path, **current behaviour** at an install root — never DENY;
- `chmod +x` (write-family) of an existing native file → same as above;
- direct write of native bytes, then a supported compile to the same path that does not change the
  file → exec → **DENY** (compile record unproved; write record is producer);
- supported compile that does change the file → exec → **row B**;
- write-family call creating a native file inside `~/.local/bin` (test-pinned home) → exec →
  **DENY** (pinned producer), and the same after filling the general store past its cap → still
  **DENY** (pins are not evicted);
- install-root write with the store made unwritable → the **write call** is **row J**;
- pin directory unreadable at exec → install-root native with no producer → **row J**;
- general record evicted / store corrupt → non-install native exec → **row J**, not DENY, not allow;
- unresolved or absent session id → non-install native exec → **row J**; install-root write held;
- cross-process: a record made by one hook process is visible to the exec check in another.

**Benign controls (must not hit the floor):**

- installed `git`, `node`, `python` running a pre-existing script (F, H);
- `node_modules/.bin/<tool>` not written by the agent (G);
- the user/cli band running a compiled output (E — band-attested, Q2);
- a data file written then read (`INERT_WRITE_TARGET`);
- **build drivers**: `cargo test`, `go test`, `make check`, `npm run build` of a native addon,
  `pip install` of an extension — the **outer** call keeps **current behaviour**; a **following
  separate** agent exec of the output, where the guard resolves it, is **row J (HOLD)**, asserted
  as such. These controls prove "never floor"; they do **not** prove "not gated";
- a **supported** compile (`cc x.c -o x`) then a separate exec → **row B**, never floor.

---

## 9. What PR 1 delivers against each #907 acceptance criterion

| #907 acceptance | met by PR 1? |
|---|---|
| Fixture: agent writes+runs a compiled binary → denied, plain reason | **Yes on Claude Code hook and OpenClaw.** Hermes: **No** in PR 1 (API-up is PR 2; outage never) |
| Fixture: compile-then-run across two calls → **denied** | **No.** Row B at Q1's verdict (AUDIT recommended). Not met by design |
| Fixture: LD_PRELOAD of a just-written library → denied | **Yes on Claude Code hook and OpenClaw.** Hermes: **No** in PR 1 |
| Fixture: Python mapping executable memory → denied | **Yes on Claude Code hook and OpenClaw** (inline and folded file body, within scan caps). Hermes: **inline body only** (API-up and outage, outage within 4096 chars); write-then-run file body **not met** on Hermes |
| No false positives on installed/pre-existing tools | **Partly.** Met for installed tools at install roots (Rule H complete), non-native targets, and outer build-driver invocations: none hits the floor or the door. **Not met** for pre-existing **project-local** native binaries and build-driver outputs: those are held at row J (§4.2). Not a measured production rate |
| Doctor reports the shared-host risk | **No — separate PR 3** |

So PR 1 meets the three directly-written DENY fixtures **on the Claude Code hook and OpenClaw
only**, with Hermes limited to inline row D. It does not meet compile-then-run → denied, the
Hermes A/C rows, the Hermes file-body row D, the non-FP bar for project-local binaries, or the
doctor row. §1, §4.2, §11 and the invariant box say the same thing.

---

## 10. Residual risks and open owner questions

### Owner questions (numbered, recommended option first)

1. **Default verdict for row B.** Options: (a) AUDIT — record, do not block; (b) HOLD — one
   bounded approval per compile-then-run chain; (c) DENY — floor it too. **Recommend (a)** for
   PR 1 so supported compile-and-test does not trip the Guard. **What ADR-002 actually says:** an
   executable effect the mapper cannot resolve is `unclassified-executable` / `code-exec-opaque`,
   **HOLD at minimum in every session** (§2.4), and the move of any class **toward AUDIT** is
   gated on §2.5 (5A + 5B + 5C), which has not passed. So (b) HOLD is the ADR-consistent position
   **now**; (a) AUDIT is a **conscious owner departure** from it, justified only by M1. (c) is
   rejected unless the owner accepts blocking routine builds. **Taint note (fact, not a new
   option):** ADR-002 allows AUDIT only in an *untainted* session, and no PR 1 adapter can
   establish "untainted" — the §2.2 store is not wired, the Claude hook and Hermes read no taint,
   and OpenClaw's detection-triggered taint is a different contract that fails soft. Unknown
   taint is not clean. So choosing (a) for PR 1 means AUDIT **regardless of taint**, a further
   departure the owner is accepting, until taint wiring lands. (OpenClaw's existing escalation
   would still raise a `sensitive` AUDIT row to `require_approval` inside its bounded window.)
2. **Operator-vs-agent discriminator for rows E/I.** The band is process identity, not a human
   fact. Options: (a) keep E/I on the band, labelled "band-attested, not human-attested", with
   floor DENY precedence independent of band; (b) require a per-action host-attested human fact;
   (c) drop E/I. **Recommend (a)** for PR 1; (b) is the long-term fact.
3. **"Declared build output" definition (rows E/I).** Recommend the band for PR 1 and build-dir
   awareness in PR 2.
4. **Hermes outage floor coverage.** Recommend accepting, as a documented residual, that on
   outage A/C/B/J and file-body row D **allow** (§6); the only outage addition is inline-text row
   D. PR 2's store does not fix the outage case.
5. **Native-image detection fidelity.** Magic-byte reads catch ELF/Mach-O/PE. Recommend treating
   a NUL-bearing target with a Rule P `agent-written` producer as a native image even without a
   known magic number.

### Residuals (static coverage deductions — not attacks executed in this review)

Each line states the **actual** verdict. "Classification limit" = the evidence is misread;
"observation limit" = the call is never seen.

- **Unrecorded exec-surface creators (§3.4 items 1–4)** — observation limit. Created at a
  non-install path and execed by a later separate call → **row J**. Created **inside an install
  root** → state 2 → **current behaviour (allow)**; Rule H covers write-family calls only.
- **Same-command write-and-exec** (redirect-then-exec or compile-then-exec in one Bash call) —
  observation limit. The pre-gate runs before the file exists: no header, no producer, no row
  fires → **current behaviour (allow)** (today's opaque-script audit at the sensitive tier). Not
  "one approval"; nothing is held. Row D catches it only when an exec-memory shape is in the
  inspected inline body.
- **Unrecorded writer after a recorded intent** — classification limit of Rule P. A failed
  recorded write followed by an unrecorded write of native bytes → attributed to the record →
  **DENY** (bytes are still agent-delivered). A failed supported compile followed by an
  unrecorded native write → attributed to the compile → **row B (Q1 verdict)**, i.e. a
  directly-written binary can escape the floor this way. Not benign over-gating.
- **Same-UID `ContentId` forgery** (restoring `mtime`/`size` after a write) can make a producing
  write look unproved → **row J** at a non-install path, **allow** at an install root.
- **Unsupported build outputs** — by design (§3.4): a later separate exec → **row J (HOLD)**;
  same-call or child exec → **allow**.
- **Build-recipe / package-lifecycle / native-loader child exec** not seen as a tool call —
  ADR-002's outer-gate limitation → **allow**.
- **Loads inside an inspected-only-by-name program** (a `require` inside a test runner, an
  import of an extension) are not resolved as load targets → **allow**.
- **Bare-name PATH exec** is not resolved in PR 1 → **allow** (current behaviour).
- **Rule H on non-enforcing hosts** — on advisory, shadow or `autoApprove` hosts the held
  install-root write is widened to warn/approve and proceeds **unrecorded**; its later exec is
  state 2 → **allow**. An install-root write released by a genuine approval also proceeds
  unrecorded; the approval is the authority.
- **Cross-session / TTL** — a native file written into an install root in session S1 and execed in
  S2, or after S1's directory expired, has no pin in the executing session → **allow**.
- **Row D bounded inspection** — a body beyond `MAX_SCRIPT_BYTES`/`MAX_FOLDED_BYTES`, NUL-bearing,
  or unresolved is folded as **opaque** (`tool-action-guard.ts:5118-5119`) → **allow** at the
  sensitive tier (`:7318-7325`), not fail-closed. On Hermes, a body outside the fallback surface
  or beyond 4096 chars is unmatched → **allow** (`policy.py:77`).
- **Compile-to-native is row B, not the floor (Q1)** — it carries the harmful effect the floor
  seeks to reduce; the accepted M1 trade.
- **Same-UID evasion** — direct mutation or deletion of the ledger/pins, hard-link aliases, file
  replacement after inspection, symlink/rename/second-interpreter indirection — the same residual
  the self-protection floor documents.
- **Scope honesty (issue "Context").** This narrows the "agent-authored native code reaches the
  CPU" path. It does **not** stop hardware flaws and does not isolate a shared CPU. The doctor
  warning (PR 3) and egress tightening (PR 4) are the complementary, separate controls.

---

## 11. PR ordering summary

1. **PR 1** — effect class + floor DENY (A/C/D) + ledger (pure core, fs store, Rule P, Rule H,
   total classifier, Claude hook + OpenClaw wiring) + door (J) + row B at Q1's verdict + Hermes
   session-id forwarding and inline-text row-D outage fallback + §8 tests + adapter fixtures.
   **Meets** the three directly-written DENY fixtures on the Claude Code hook and OpenClaw, and
   inline row D on Hermes. **Does not meet** compile-then-run → denied, Hermes A/C, Hermes
   file-body row D, the non-FP bar for project-local native binaries (held at row J), or the
   doctor row.
2. **PR 2** — Hermes API-up store (A/C/B/J on Hermes when the API is up; outage unchanged);
   cross-plane parity; build-output-dir awareness (Q3).
3. **Separate prerequisite** — ADR-002 taint wiring; until then B′ is not a verdict.
4. **PR 3** *(separate issue)* — doctor `Code-execution host isolation` warning (issue item 4).
5. **PR 4** *(separate issue)* — egress allow-listing for code-executing sessions (issue item 5).
