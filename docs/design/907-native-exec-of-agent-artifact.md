# Design: always-deny for execution of agent-authored native code (#907)

**Status:** Design only. No source change in this branch.
**Issue:** #907 (raised by Michael, 23 Oct 2026). **Author:** TARS (improvement loop).
**Relates to:** ADR-002 (`docs/architecture/ADR-002-provenance-first-enforcement.md`) — this
is one DENY row and one HOLD row under that ADR's effect decision, plus the
provenance store the ADR's §2.2 taint contract already assumes. ADR-001's
intent-first law, catastrophe hard-stops and credential non-exfil rule are
unchanged.

> **Invariant up front (ADR-002 / M1).** The Guard is **OFF by default**. Everything
> below is a rule that applies *only when the Guard is enabled*. Nothing here turns
> the Guard on, changes its default posture, or changes who it is on for. "Routine
> work never trips the Guard" is a hard constraint on the decision table in §4, not
> an aspiration — and §4 is explicit that an *honest* always-deny floor cannot cover
> the issue's compile-then-run case without blocking routine coding work, so that
> case is a door (HOLD), not the floor, and the floor is narrowed to the cases with
> no routine analogue.

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

Shapes 1, 3 and 4 have **no routine developer analogue**. Nobody hand-writes an ELF
or Mach-O and runs it, remaps a freshly written buffer as executable, or `LD_PRELOAD`s
a `.so` they just produced by hand, as part of ordinary work. These are the floor.

Shape 2 is the tension the design has to be honest about. **Compiling source the agent
just wrote and running the output is both the attack path and the single most common
thing a coding agent does.** `gcc foo.c -o foo && ./foo`, `cargo build && cargo run`,
`go build ./... && ./app`, `npm run build && node dist/app.js` — where the agent
authored `foo.c`/the Rust/the Go in this same session — are routine. The guard cannot
tell a Rowhammer proof-of-concept's source from a legitimate helper's source by reading
the content; both are "native code the agent wrote, compiled, and ran."

**Therefore an honest always-deny floor cannot include shape 2 without blocking routine
compile-and-test.** Per the issue's own M1 framing and ADR-002's three-valued discipline,
shape 2 is handled as a *door* (HOLD → the existing brokerable dangerous approval), not as
the floor, and the default for shape 2 in an **untainted** session is an open owner
question (§10, Q1). This is stated plainly rather than papered over with an allowlist of
command names, which ADR-002 §2.4 forbids.

---

## 2. Effect class and signal names

New effect kind added to ADR-002 §2.4's taxonomy (the taxonomy says "an implementation
may name more"):

| effect kind | what it covers |
|---|---|
| `native-exec-of-agent-artifact` | executing, loading, or mapping-as-executable a native artifact the **agent created or modified in this session**, where the artifact did **not** come from a guard-observed compile of agent-authored *source* — i.e. directly-written native bytes, a `dlopen`/`LD_PRELOAD` of an agent-written shared object, or mapping agent-written bytes as executable memory. **DENY floor.** |

and one signal that is **not** the floor:

| signal | what it covers | tier |
|---|---|---|
| `exec-of-agent-compiled-artifact` | agent wrote *source*, the guard observed a compile of that source into an output, and the **agent** then runs that output within the session (shape 2) | HOLD (door), or AUDIT in an untainted session — see §4 and Q1 |

Signal vocabulary (kebab-case, mirrors `opaque-script-invocation`, `write-content-catastrophic`):

- `native-exec-of-agent-artifact` — umbrella signal on the floor verdict.
- `exec-agent-written-native-bytes` — shape 1 (an agent-written file whose on-disk
  bytes are a native image: ELF / Mach-O / PE / a raw-byte blob with no reviewable source).
- `map-exec-agent-written-memory` — shape 4 and the `mmap`/`mprotect` + execute and
  ctypes/cffi-call-into-buffer forms of shape 3. **Decidable from program body text.**
- `load-agent-written-native-object` — `dlopen`/`LD_PRELOAD`/`DYLD_INSERT_LIBRARIES`
  of an agent-written `.so`/`.dylib`/`.node`.
- `exec-of-agent-compiled-artifact` — shape 2 (door, not floor).

These names must be added to `SAFE_SIGNALS` in `scripts/pre-tool-hook.mjs` (and the
Hermes/OpenClaw equivalents) so audit rows show the signal instead of `redacted-signal`.

---

## 3. Provenance data model (content-free, bounded, cross-call, cross-plane)

### 3.1 The agent-artifact ledger

A per-session record of what the agent wrote and what those writes produced. It is the
typed host fact that §4's ledger-dependent rows read; it is **not** derivable from command
text (invariant 5).

```
AgentArtifactLedger (keyed by host-owned sessionKey)
  entries: Array<{
    pathHash:   string   // HMAC(salt, canonical-abs-path), NOT the path
    kind:       'written-native' | 'written-source' | 'compiled-output'
    srcHashes?: string[] // for compiled-output: pathHashes of the source inputs
    at:         number   // ms, for FIFO eviction only
  }>
```

- **Content-free in audit (invariant 4).** The ledger stores **hashes of paths**, never
  path text and never file contents. A denial's audit row names the *effect* and the
  *signal*, and at most a `fmtSpan`-bounded fragment of the **command** the operator can
  already see — exactly as the self-protection floor does today. The ledger itself never
  reaches an audit row. This mirrors the rule that `secret-egress` contributes no span.
- **Keyed by host-owned session identity (invariant 4).** The key is `sessionKeyFor(id)`
  — the same HMAC the hook, `session-guard.ts` and `stop-hook.mjs` already compute from
  the host's `session_id`. A content-asserted identity is refused, exactly as
  `session-taint-lineage.ts` refuses one. A call whose session id cannot be derived
  (`namedIdentityUnresolved`) gets **no ledger**, so every artifact read is *unknown*
  provenance → the door, never allow.
- **Bounded (invariant 4).** Caps mirror `session-lease-store.ts`: a max entry count per
  session (proposed 512), a max distinct sessions, a per-file byte cap on the hashed input,
  and a TTL. All are constants in the pure core.
- **Eviction fails toward *unknown*, not *allow* (invariant 4).** When the cap is hit the
  oldest entry is dropped. A later exec of an evicted path is then *not found in the
  ledger* → provenance unknown → three-valued **door** (`require_approval`), never a clean
  allow. The floor (`native-exec-of-agent-artifact`) is only asserted on a **positive**
  ledger match; an eviction can only *weaken* to the door, which is the fail-closed
  direction. (Contrast: the floor never fires on an absent ledger, so eviction cannot
  manufacture a DENY either — it manufactures a HOLD.)

### 3.2 Where it lives and how a separate-process hook shares it

Follows `session-lease-store.ts` exactly: **flat JSON, not SQLite**, under
`~/.shieldcortex/` (honouring `SHIELDCORTEX_*`), atomic tmp+rename at `0o600`, corrupt
read as empty, TTL discipline. Rationale is identical: the Claude Code hook has no DB on
its hot path, and a store one plane cannot read is a plane that silently does not bind.

Cross-process sharing is the same mechanism the lease store relies on: each hook
invocation is a **separate process** that reads and writes the same per-session file keyed
by `sessionKey`. Concurrency is **best-effort between honest sessions**, stated as a
decision not a surprise (same wording as the lease store): two writes can race
last-writer-wins. That is acceptable because a lost *write* record only weakens a later
exec to the door (fail-closed), and the floor cases (§4 rows A/C/D) do not depend on a
prior write record at all — they read the artifact's **on-disk bytes** at exec time.

### 3.3 Two split cores (same discipline as `session-taint-lineage.ts` + `session-lease-store.ts`)

- **Pure core** `src/defence/iron-dome/agent-artifact-provenance.ts`: record/query/evict
  arithmetic, hashing, the compile-lineage edge, caps. No I/O, no clock except injected,
  no host. Unit-testable like `session-taint-lineage.ts`.
- **fs layer** `src/defence/iron-dome/agent-artifact-store.ts`: the one entry point both
  planes call, atomic writes, TTL, corrupt-as-empty. Modelled on `session-lease-store.ts`.

### 3.4 Capture point — forced by there being no PostToolUse hook

**Measured fact:** there is no post-execution hook on any plane. `src/setup/settings-hooks.ts`
registers `PreToolUse`, `UserPromptSubmit`, `Stop`, `SessionEnd`, `PreCompact` — **no
`PostToolUse`**. OpenClaw registers `before_tool_call` only (no `after_tool_call`). Hermes
`__init__.py` registers `pre_tool_call` only; its docstring marks `transform_tool_result`
as future phase 2.

Consequence: provenance is recorded at the **pre-gate of the write/compile call itself**,
because the guard already sees that call before it runs:

- A write/create/edit/`mkdir`/`mv`/`cp` tool call (`WRITE_TOOLS` already recognises these)
  whose target path is script-like or whose content looks executable
  (`isScriptLikeWritePath`, `writeContentLooksExecutable` — both already exist) → record
  `written-source` or `written-native`.
- A compiler invocation in the exec surface (`gcc`/`clang`/`cc`/`rustc`/`go build`/`zig`/
  `ghc`/`nvcc`…) whose `-o`/output target is resolvable → record `compiled-output` with
  `srcHashes` linking the source inputs. Program position is read with the existing
  `detectScriptInvocations` / `tokeniseStatement` / `commandBaseName` machinery; **no new
  regex family** (invariant 5). Compilers are added as a recognised command class the same
  way the installer family is.

Recording is done by the **caller** (hook/interceptor), not inside `evaluateToolCall`,
preserving that function's purity — the same split as the injected `resolveScriptSource`.
The pure guard receives a **reader** (see §5).

---

## 4. Decision table

Let `A` = the artifact being executed/loaded/mapped. Columns: provenance (from ledger +
on-disk bytes), who runs it (DefenceSource band), session taint (ADR-002 §2.2).

| # | Case | Provenance signal | Taint | Verdict | Rationale |
|---|---|---|---|---|---|
| A | Agent-written file whose on-disk bytes are a native image (ELF/Mach-O/PE/raw blob), executed — with no guard-observed source→compile lineage | `exec-agent-written-native-bytes` | any | **DENY (floor)** | shape 1; no routine analogue — nobody hand-writes a binary and runs it |
| C | `dlopen`/`LD_PRELOAD`/`DYLD_INSERT_LIBRARIES`/Node `.node` addon load of an agent-written object | `load-agent-written-native-object` | any | **DENY (floor)** | shape 3 (loader form); no routine analogue |
| D | Program body maps agent-written/just-generated bytes as executable memory (`mmap` PROT_EXEC, `mprotect` +X on a writable buffer, ctypes/cffi call into a written buffer) | `map-exec-agent-written-memory` | any | **DENY (floor)** | shape 4; **text-decidable** from the program body the guard already folds |
| B | Agent wrote *source*, guard observed its compile, **agent** runs the output this session | `exec-of-agent-compiled-artifact` | untainted | **AUDIT by default** (owner Q1: or HOLD, or DENY) | shape 2; routine compile-test — floor-denying this breaks M1 |
| B′ | Same as B | `exec-of-agent-compiled-artifact` | tainted | **HOLD** | ADR-002 §2.2 already holds every privileged effect in a tainted session; native-exec only sharpens the reason |
| E | **Operator** (user/cli band) runs the build output the agent compiled | — | any | **ALLOW** | the issue's "when the user, not the agent, runs it"; intent re-established by band |
| F | Pre-existing installed tool executed (`git`, `node`, `python`, system `cc`) with no agent-written artifact on its execution surface | not in ledger | untainted | **ALLOW** | explicit non-false-positive in the issue |
| G | Package-manager install tree executed (`node_modules/.bin/*`, a wheel's entry point) not authored by the agent | not in ledger | untainted | **ALLOW** | install trees are not agent-authored |
| H | Interpreter running an **existing** (not agent-written) script | not in ledger | untainted | **ALLOW** | existing behaviour; no provenance match |
| I | Build tool writes the project's **declared build output** and the **operator** runs it | — | any | **ALLOW** | row E generalised to build systems |
| J | Agent-written artifact exec where ledger evicted / session id unresolved / provenance otherwise unknown | `unclassified-executable`-adjacent | any | **HOLD (door)** | three-valued unknown → existing brokerable dangerous door, never a fake catastrophic (invariant 3) |

**Precedence** is ADR-002's DENY > HOLD > AUDIT. A floor row (A/C/D) denies at any taint
state with no approval path, exactly like the catastrophic tier (`TERMINAL_BLOCK_SEVERITIES`,
the doorless branch in `pre-tool-hook.mjs`). The floor is **provenance-blind only in the
sense that taint does not matter** — it still requires a positive artifact match; it is not
a text pattern.

**Three-valued mapping (invariant 3):** proven-executed-native-of-agent-artifact → DENY
(rows A/C/D); proven-data / proven-operator-run / not-in-ledger-and-untainted → ALLOW
(rows E–I); unknown (row J) → the existing dangerous `require_approval` door, **never** a
fabricated catastrophic.

### 4.1 Rows needing a typed host fact rather than text (invariant 5)

- **A, C** — "is this path an agent-written artifact" needs the **ledger** (host fact);
  "are the on-disk bytes a native image" needs a **magic-byte read of the file header**
  (host fact) at the hook boundary, injected like `resolveScriptSource`. Neither is
  decidable from the command string.
- **D** — **text-decidable** from the program body the guard already folds; no host fact
  needed. This is why row D is the one floor row Hermes' text-only outage fallback can keep
  (§6).
- **B/B′** — the source→compile→run lineage is a ledger fact (the compile edge recorded in
  §3.4).
- **E/I** — "did the operator or the agent run this" is the **DefenceSource band** (host
  fact, already resolved by `resolve-tool-source.ts` / `env-detector.ts`); "is the target
  the declared build output" needs project build config (host fact), see Q3.

### 4.2 False-positive surface and how it is measured

The false-positive surface is **row B in an untainted session** — the agent compiling and
running its own source. Under the recommended default (B = AUDIT) the surface is **zero
blocked routine builds**: B audits, never blocks. If the owner chooses B = HOLD (Q1), the
surface is "one bounded approval per distinct compile-then-run chain," bounded by the
operator's own workflow, not by shell grammar.

Measurement reuses the existing machinery, not a new one:

- the §5A logged-signal replay (`scripts/guard-policy-replay.mjs` /
  `scripts/replay-guard-corpus.mts`): run the proposed classifier over the recorded
  corpus and report how many real allowed events would flip to DENY (must be 0 for the
  floor) or to HOLD/AUDIT;
- the `guard-effect-fixtures` harness (§5B), with the benign controls below executed
  against both current and proposed policy and independently reviewed;
- `guard-precision-corpus.ts` gets the benign compile-and-test rows added so a regression
  that floor-denies a routine build fails CI.

The floor's acceptance bar, pre-registered: **zero** benign-control rows denied; **100%**
of the four exploit-shaped fixtures denied with a plain-English reason.

---

## 5. Surfaces to change (every file and call site)

**PR 1 (the floor + ledger + three-valued door):**

- `src/defence/iron-dome/agent-artifact-provenance.ts` **(new, pure core)** — ledger
  record/query/evict, path hashing, compile-lineage edge, native-image magic-byte
  classifier helper (operates on an injected header read, stays pure), caps.
- `src/defence/iron-dome/agent-artifact-store.ts` **(new, fs layer)** — per-session flat
  JSON, atomic tmp+rename `0o600`, TTL, corrupt-as-empty; one entry point each for
  *record-write*, *record-compile*, *query*.
- `src/defence/iron-dome/tool-action-guard.ts`:
  - new `ToolGuardOptions` members (injected, caller-supplied, never throwing):
    `agentArtifactLedger?: (sessionKey) => LedgerView` (read) and
    `readFileHeader?: (path) => Uint8Array | null` (magic-byte read for rows A/C).
  - new classifier `classifyNativeExec(execSurface, ledger, headerReader)` returning the
    §2 signals; built on `detectScriptInvocations` / `tokeniseStatement` /
    `commandBaseName` / `EXEC_WRAPPER` / `SCRIPT_INTERPRETER` and the existing body-fold
    regions — **no new regex family**.
  - wire into `evaluateToolCall`: floor rows A/C/D land on the catastrophic/terminal branch
    (block, doorless); row J lands on the `require_approval` branch; row B emits the
    `exec-of-agent-compiled-artifact` signal at AUDIT/HOLD per Q1.
  - extend `GUARD_SELF_PROTECTION_SIGNALS`? **No** — this is a separate floor; but mirror
    its "enforced in every posture" standing for rows A/C/D by rating them at a terminal
    severity (`TERMINAL_BLOCK_SEVERITIES`).
- `scripts/pre-tool-hook.mjs`:
  - at the write/compile pre-gate, call the store's record entry points keyed by
    `baseExtra.sessionKey` (skip when `namedIdentityUnresolved`);
  - inject `agentArtifactLedger` + `readFileHeader` into the `evaluateToolCall` options
    object (4th arg) alongside `resolveScriptSource`;
  - add the new signal names to `SAFE_SIGNALS`.
- `plugins/openclaw/interceptor.ts` — same injection via the defence module
  (`runDefencePipeline`); record writes/compiles in the `before_tool_call` path.
- `plugins/openclaw/provenance.ts` / `session-taint.ts` — no behaviour change required,
  but the agent-write record is a natural provenance input; noted, not required for PR 1.
- `src/api/visualization-server.ts` (`POST /api/v1/action-guard`) — accept the host-owned
  session id and hold the store server-side so Hermes shares it (§6).
- `plugins/hermes/shieldcortex/sc_client.py` — forward session id to the API; add a
  **text-only** `fallback_native_exec_memory_match` (row D) for the outage path, analogous
  to `fallback_catastrophic_match`. Rows A/C cannot be served by the outage fallback (no
  ledger, no header read) → they fall to the dangerous door, which is the fail-closed
  direction.
- `plugins/hermes/shieldcortex/policy.py` + `__init__.py` — thread the session id through
  `pre_tool_call`.
- Tests: `src/defence/iron-dome/__tests__/native-exec-of-agent-artifact-907.test.ts`
  (pure core + classifier), an enforcement-surface-parity fixture so all three planes agree
  on the floor, and benign rows added to `guard-precision-corpus.ts`.

**PR 2 (plane parity + store wiring):** finish Hermes/API server-side store so row B/J
ledger logic (not just the text-decidable floor) holds under Hermes; cross-plane parity
tests.

**PR 3 (separate follow-up issue — doctor shared-host warning, issue item 4):** see §7.

**PR 4 (separate follow-up issue — egress tightening, issue item 5):** allow-list egress
destinations for code-executing sessions. Out of scope for the first PR; filed separately.

---

## 6. Cross-plane behaviour (invariant 4)

| plane | capture | floor (A/C/D) | door (B/J) |
|---|---|---|---|
| Claude Code hook | pre-gate record keyed by `sessionKey` | full (ledger + header read) | full |
| OpenClaw interceptor | pre-gate record via defence module | full | full |
| Hermes (API up) | API holds store | full | full |
| Hermes (outage fallback) | none | **row D only** (text-decidable); A/C → dangerous door | → dangerous door |

The honest statement, in the ADR-002 style: on the Hermes outage path the ledger-dependent
floor rows (A/C) degrade to the brokerable door, not to allow, and row D (text-decidable)
still denies. §5C-style coverage must record Hermes-outage as "floor partial, fails toward
door," not as a pass.

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

All fixtures run in CI via the existing Jest + `guard-effect-fixtures` harness. **Payload
literals are not needed** — the exploit rows are described by *shape*; benign fixtures are
real files. Remembering the repo's CI gotchas: fixtures write under the test-pinned home,
never `$HOME/.shieldcortex`, and avoid `os.tmpdir()` for any watch-adjacent path.

**Acceptance rows from #907:**

- **(a) agent writes and runs a compiled binary** → fixture: a write tool records a file
  whose bytes carry a native-image magic header (a tiny benign ELF/Mach-O stub committed as
  a fixture, or a `chmod +x` of agent-written bytes), then an exec of that path →
  `exec-agent-written-native-bytes` → **DENY**, plain-English reason.
- **(b) compile-then-run across two calls** → call 1: agent writes `helper.c` (benign
  "hello") and runs `cc helper.c -o helper` (records `compiled-output` linked to the
  source); call 2: agent runs `./helper` → `exec-of-agent-compiled-artifact` → **HOLD in a
  tainted session / AUDIT (or Q1 verdict) untainted**. Proves cross-call linkage via the
  store.
- **(c) LD_PRELOAD of a just-written library** → agent writes `libx.so` (benign), then a
  command sets the preload env and runs any program → `load-agent-written-native-object`
  → **DENY**.
- **(d) Python mapping executable memory** → a program body containing the `mmap`
  PROT_EXEC / `mprotect` +X / ctypes-call-into-buffer *shape* (benign no-op bytes) folded
  from a write-then-run or a `-c`/heredoc → `map-exec-agent-written-memory` → **DENY**.
  This row needs no ledger and is the Hermes-outage-safe one.

**Benign controls (must all ALLOW / not trip the floor):**

- running installed `git`, `node`, `python` on a **pre-existing** (not agent-written)
  script (row F/H);
- `node_modules/.bin/<tool>` and a pip console-script entry point not authored by the
  agent (row G);
- the **operator** (user/cli band) running the build output the agent compiled (row E);
- a build tool writing the declared build output, operator-run (row I);
- an agent writing a **data** file (`.json`/`.md`/`.csv`) and a later command reading it
  (must not be mistaken for a native artifact — reuses `INERT_WRITE_TARGET`);
- the full benign compile-and-test flow in a **tainted** session is HOLD (expected), proving
  the floor did not escalate it to DENY.

**Store/eviction controls:**

- evict-then-exec → the previously-recorded path is gone → row J door, **not** allow and
  **not** a floor DENY (proves eviction fails toward *unknown*);
- unresolved session id → no ledger → row J door;
- cross-process: write recorded in process 1 is visible to the exec check in process 2
  (two separate hook invocations against the same store file).

---

## 9. What PR 1 delivers against each #907 acceptance criterion

| #907 acceptance | met by PR 1? |
|---|---|
| Fixture: agent writes+runs a compiled binary → denied, plain reason | **Yes** (row A) |
| Fixture: compile-then-run across two calls | **Yes**, as HOLD/AUDIT (door), with DENY gated on owner Q1 |
| Fixture: LD_PRELOAD of a just-written library → denied | **Yes** (row C) |
| Fixture: Python mapping executable memory → denied | **Yes** (row D) |
| No false positives on installed/pre-existing tools | **Yes** (rows E–I + benign controls + corpus) |
| Doctor reports the shared-host risk | **No — separate PR 3** (issue item 4), by design |

So PR 1 meets every acceptance row **except the doctor shared-host report**, which the
issue itself lists as a distinct deliverable (item 4) and which §5/§7 split out as a
follow-up. The egress tightening (item 5) is likewise a separate follow-up (PR 4). Stated
honestly so PR 1 is not claimed to close the whole issue.

---

## 10. Residual risks and open owner questions

Each numbered, with a recommended option.

1. **Default verdict for shape 2 (row B) in an *untainted* session.** Options: (a) AUDIT —
   record, do not block; (b) HOLD — one bounded approval per compile-then-run chain; (c)
   DENY — floor it too. **Recommend (a) AUDIT** for the first PR: it satisfies M1 ("routine
   work never trips the Guard"), keeps the false-positive surface at zero blocked builds,
   and still produces the signal and the audit trail the owner needs to decide later. (b)
   is the ADR-002-consistent tightening once the §2.5 narrowing gate is met. (c) is rejected
   as dishonest against M1 unless the owner explicitly accepts blocking routine builds.
2. **Native-image detection fidelity.** Magic-byte reads catch ELF/Mach-O/PE; a raw-shellcode
   blob with no recognisable header is caught only when it reaches row D's exec-memory shape.
   Recommend: treat an agent-written file that is executed directly *and* is non-text (NUL
   bytes, as `foldScriptSources` already detects) as `exec-agent-written-native-bytes` even
   without a known magic number — fail toward the floor for direct exec of agent-written
   binary blobs.
3. **"Declared build output" definition (rows E/I).** Needs a project build-config fact to
   know the build dir. Recommend: for PR 1, rely on the **band** (operator-run → allow)
   rather than the build-dir fact, and defer build-dir awareness to PR 2 so PR 1 ships
   without a new config surface.
4. **Hermes outage floor coverage.** Rows A/C degrade to the door on the text-only fallback.
   Recommend accepting this (fail-closed to a door, never to allow) for PR 1 and closing it
   in PR 2 with server-side store wiring; record it as a measured coverage gap, not a pass.
5. **Interpreter escape hatches beyond mmap/ctypes/dlopen** (e.g. a Node native addon built
   and `require`d in one session). Recommend: `require`/`import` of an agent-written `.node`
   is row C (`load-agent-written-native-object`); anything the fold cannot resolve is row J
   (door), never a silent allow.
6. **Scope honesty (issue "Context").** This narrows the "agent-authored native code reaches
   the CPU" path. It does **not** stop hardware flaws, does not isolate a shared CPU, and a
   determined same-UID process can still evade the classifier (symlink, rename, a second
   interpreter) — the same residual the self-protection floor documents. The doctor warning
   (PR 3) and egress tightening (PR 4) are the complementary, separate controls.

---

## 11. PR ordering summary

1. **PR 1** — effect class + floor DENY (rows A/C/D) + agent-artifact ledger (pure core,
   fs store, Claude + OpenClaw wiring) + three-valued door (rows B/J) + Hermes session-id
   forwarding and text-only row-D fallback + full test plan + benign corpus. Closes every
   #907 acceptance row except the doctor report.
2. **PR 2** — Hermes/API server-side store so the ledger-dependent floor and door hold under
   Hermes; cross-plane parity; build-output-dir awareness (Q3).
3. **PR 3** *(separate issue)* — doctor `Code-execution host isolation` warning (issue item 4).
4. **PR 4** *(separate issue)* — egress allow-listing for code-executing sessions (issue item 5).
