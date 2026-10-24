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

> **Round-2 note (review fold).** Round 1 (Astra `gpt-6-astra-900k`, Grok `grok-4.7`)
> returned CHANGES REQUESTED. This revision folds every blocker. The three design
> decisions that moved are called out where they land: (1) the ledger records a
> write-family target **regardless of extension or content** — the native-vs-source
> distinction is made at *exec time* by a header read, not at *write time* by the
> old script-path/executable-content predicates, which do not recognise native bytes
> (§3.1, §3.4); (2) "not found in the ledger" has **one** meaning — unknown provenance
> → the existing brokerable door, never ALLOW; the ALLOW rows fire on a **positive**
> pre-existing/installed signal, not on absence (§3.1, §4); (3) on a Hermes outage the
> ledger-dependent floor rows A/C **fail open (allow) for unmatched shapes** — this is
> ADR-002 §own documented partial fail-open, not a door; the earlier "fall to a door"
> claim was wrong and is removed (§6, Q4).

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

Shapes 1, 3 and 4 have **no routine developer analogue** *in the directly-written form*.
Nobody hand-writes an ELF or Mach-O and runs it, remaps a freshly written buffer as
executable, or `LD_PRELOAD`s a `.so` they produced **by hand** (not by a compiler), as
part of ordinary work. Those directly-written forms are the floor. The qualifier
matters: a `.so`/`.node` that a **guard-observed compiler/build driver produced** from
agent source is shape 2, not shape 1/3 — it carries compile lineage and is a door, not
the floor (this is the round-1 B3 contradiction, resolved in §2 and row C of §4).

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
| `native-exec-of-agent-artifact` | executing, loading, or mapping-as-executable a native artifact the **agent created or modified in this session**, where the artifact did **not** come from a guard-observed compile/build of agent-authored *source* — i.e. directly-written native bytes, a `dlopen`/`LD_PRELOAD` of an agent-**written** (not compiler-produced) shared object, or mapping agent-written bytes as executable memory. **DENY floor.** |

and one signal that is **not** the floor:

| signal | what it covers | tier |
|---|---|---|
| `exec-of-agent-compiled-artifact` | agent wrote *source*, the guard observed a compile/build of that source into an output, and the **agent** then runs or loads that output within the session (shape 2, **including a built `.node`/`.so` loaded via `require`/`dlopen`**) | HOLD (door), or AUDIT in an untainted session — see §4 and Q1 |

**The compile-lineage boundary (round-1 B3).** The *only* thing that separates a floor DENY
(row A/C) from the shape-2 door (row B) for the **same bytes at the same path** is whether
the guard **observed a compile/build** that produced them. A `.so`/`.node` the agent wrote
byte-for-byte with a write tool and never compiled is the floor; a `.so`/`.node` a
guard-observed `cc`/`rustc`/`node-gyp`/`cargo` produced from agent source is the door. Row C
in §4 carries this exception explicitly, identically to the effect-kind definition above, so
the two cannot disagree.

Signal vocabulary (kebab-case, mirrors `opaque-script-invocation`, `write-content-catastrophic`):

- `native-exec-of-agent-artifact` — umbrella signal on the floor verdict.
- `exec-agent-written-native-bytes` — shape 1 (an agent-written file whose on-disk
  bytes are a native image: ELF / Mach-O / PE / a raw-byte blob with no reviewable source,
  **and with no observed compile lineage**).
- `map-exec-agent-written-memory` — shape 4 and the `mmap`/`mprotect` + execute and
  ctypes/cffi-call-into-buffer forms of shape 3. **Decidable from program body text.**
- `load-agent-written-native-object` — `dlopen`/`LD_PRELOAD`/`DYLD_INSERT_LIBRARIES`/
  `require` of an agent-**written** `.so`/`.dylib`/`.node` **with no observed compile lineage**.
- `exec-of-agent-compiled-artifact` — shape 2 (door, not floor).
- `unclassified-executable` — ADR-002's own name for the unknown-provenance door (row J);
  reused here, not a new vocabulary.

These names must be added to the signal allowlists so audit rows show the signal instead of
`redacted-signal`. The concrete destinations (round-1 N4): `SAFE_SIGNALS` in
`scripts/pre-tool-hook.mjs` (hook deny/ask rows), `SAFE_ACTION_GUARD_SIGNALS` in
`src/defence/iron-dome/operator-notify.ts` (the shared notification mirror), and
`SAFE_SUMMARY_SIGNALS` in `scripts/stop-hook.mjs` (stop-summary). Hermes carries bounded
string signals already (`sc_client.py`), not a SAFE-signal table, and OpenClaw has no
separate signal table — so "Hermes/OpenClaw equivalents" is **not** a set of tables to edit;
those planes surface the signal through their existing bounded-string paths.

---

## 3. Provenance data model (content-free, bounded, cross-call, cross-plane)

### 3.1 The agent-artifact ledger — three provenance states, not two

A per-session record of what the agent wrote and what those writes produced. It is the
typed host fact that §4's ledger-dependent rows read; it is **not** derivable from command
text (invariant 5).

```
AgentArtifactLedger (keyed by host-owned sessionKey)
  entries: Array<{
    pathHash:   string   // HMAC(salt, canonical-abs-path), NOT the path
    kind:       'agent-written' | 'compiled-output'
    srcHashes?: string[] // for compiled-output: pathHashes of the source inputs
    at:         number   // ms, for FIFO eviction only
  }>
  tombstones: Array<string>   // pathHashes evicted/overflowed — see "Eviction" below
```

**Round-1 B1/B2: three distinct provenance states, not an absent-vs-present binary.**
A path at exec time is classified into exactly one of:

1. **Positively agent-authored.** A `pathHash` match of `kind: 'agent-written'` (recorded by
   §3.4's write-family capture) **and** a header read (§4.1) that says the on-disk bytes are
   a native image, **and** no `compiled-output` lineage for that path → **floor (rows A/C).**
2. **Positively pre-existing / not-agent.** The path is affirmatively recognised as a
   non-agent artifact by a **positive** host signal — it sits in a recognised install root
   (`isInstalledBinaryPath` / `INSTALLED_BIN_DIR_RE`, which already covers `/usr/bin`,
   Homebrew/Cellar, `~/.cargo/bin`, `node_modules/.bin`, …), or is a package-tree entry
   point, or is a system path — **and** carries no `agent-written` record → **no floor, no
   door; current behaviour (rows F/G/H).** This is a positive "known clean" signal, never
   mere absence from the ledger.
3. **Unknown.** Everything else: a native-image header at a non-install, non-system path with
   no `agent-written` record and no recognised-pre-existing signal (e.g. an evicted agent
   write, a file created through an unrecorded exec-surface path in §3.4, a race that lost the
   write record) → **HOLD (door), row J.** Unknown is the fail-closed default and is **never**
   ALLOW.

This is the round-1 correction: "proven non-agent/pre-existing", "positively agent-authored"
and "unknown" are three states established by three different positive signals. The floor
fires only on state 1; ALLOW (current behaviour) is reached only on state 2's positive
signal; state 3 is the door. "Not in the ledger" is **not** itself an ALLOW reason anywhere.

- **Content-free in audit (invariant 4).** The ledger stores **hashes of paths**, never
  path text and never file contents. A denial's audit row names the *effect* and the
  *signal*, and at most a `fmtSpan`-bounded fragment of the **command** the operator can
  already see — exactly as the self-protection floor does today. The ledger itself never
  reaches an audit row. This mirrors the rule that `secret-egress` contributes no span.
- **Keyed by host-owned session identity (invariant 4).** The key is `sessionKeyFor(id)`
  — the same HMAC the hook, `session-guard.ts` and `stop-hook.mjs` already compute from
  the host's `session_id`. A content-asserted identity is refused, exactly as
  `session-taint-lineage.ts` refuses one. A call whose session id cannot be derived
  (`namedIdentityUnresolved`, **or an absent key** — `hookSessionExtras` only sets
  `namedIdentityUnresolved` for a *non-empty unresolved* id, so the new code must also treat
  an **absent** `sessionKey` as "no ledger") gets **no ledger**: every artifact read is then
  state 3 (unknown) → the door, never allow.
- **Bounded — these are NEW bounds, not inherited lease-store constants (round-1 N1).**
  The **store mechanism** (flat JSON, atomic tmp+rename, `0o600`, corrupt-as-empty, TTL)
  mirrors `session-lease-store.ts`. The **caps do not**: the lease store's own bounds are a
  TTL and best-effort last-writer-wins concurrency, keyed by a shared `leases/leases.json`
  by scope — it defines no max-entry/max-session/per-file cap and is not a per-session file.
  This store is a **deliberate new layout** (one file per `sessionKey`) with its **own**
  bounds, stated here as new constants in the pure core: a max entry count per session
  (proposed 512), a max distinct sessions, a max tombstone count, a per-file byte cap on the
  hashed input, and a TTL. None of these is "a constant the lease store already has."
- **Eviction fails toward *unknown*, with a tombstone so it cannot silently become ALLOW
  (round-1 B1).** When the entry cap is hit the oldest `agent-written`/`compiled-output`
  entry is dropped **and its `pathHash` is pushed onto the bounded `tombstones` ring.** A
  later exec of an evicted path then matches a tombstone → state 3 (unknown) → **door**, not
  a clean allow. If the tombstone ring itself overflows, the state-2 install-location
  discriminator is the backstop: an evicted agent artifact lives at a **project-local /
  non-install** path, so it fails the positive pre-existing test and still lands in state 3
  (door), never state 2 (allow). The floor (`native-exec-of-agent-artifact`) is asserted only
  on a **positive state-1 match**; an eviction can only *weaken* to the door — it can neither
  manufacture a DENY (no state-1 record remains) nor a silent allow (tombstone + install-path
  backstop keep it in state 3). This is the single, consistent eviction rule required by both
  reviewers.

### 3.2 Where it lives and how a separate-process hook shares it

Store **mechanism** follows `session-lease-store.ts`: **flat JSON, not SQLite**, under
`~/.shieldcortex/` (honouring `SHIELDCORTEX_*`), atomic tmp+rename at `0o600`, corrupt
read as empty, TTL discipline. **Layout differs** (§3.1 N1): one file per `sessionKey`, not
a single scope-keyed `leases.json`. Rationale for the mechanism is identical: the Claude
Code hook has no DB on its hot path, and a store one plane cannot read is a plane that
silently does not bind.

Cross-process sharing is the same mechanism the lease store relies on: each hook
invocation is a **separate process** that reads and writes the same per-session file keyed
by `sessionKey`. Concurrency is **best-effort between honest sessions**, stated as a
decision not a surprise: two writes can race last-writer-wins.

**What a lost write record does (round-1 B1/B2 — corrected from the earlier draft).** A lost
`agent-written` record does **not** leave the floor rows free to read on-disk bytes "without
the ledger." Rows A and C need **both** the authorship record **and** the header read (§4.1);
row D needs **neither** (it is text-decidable). So a lost record for an A/C candidate means
the path is no longer state-1 agent-authored; with a native header at a non-install path it
becomes **state 3 (unknown) → door** (via the tombstone/install-path discriminator above),
**never a silent allow and never a floor DENY.** The earlier claim that "floor cases A/C/D do
not depend on a prior write record — they read on-disk bytes at exec time" was wrong for A/C
and is removed; it holds only for D.

### 3.3 Two split cores (same discipline as `session-taint-lineage.ts` + `session-lease-store.ts`)

- **Pure core** `src/defence/iron-dome/agent-artifact-provenance.ts`: record/query/evict
  arithmetic, hashing, the compile-lineage edge, the three-state classifier, caps,
  tombstones. No I/O, no clock except injected, no host. Unit-testable like
  `session-taint-lineage.ts`.
- **fs layer** `src/defence/iron-dome/agent-artifact-store.ts`: the one entry point both
  planes call, atomic writes, TTL, corrupt-as-empty. Modelled on `session-lease-store.ts`.

### 3.4 Capture point — forced by there being no PostToolUse hook

**Measured fact (round-1 N2, corrected).** There is no **post-tool completion** hook on any
enforcement adapter. `src/setup/settings-hooks.ts` registers `PreToolUse`, `SessionStart`,
`UserPromptSubmit`, `PreCompact` by default (`SessionEnd` is explicitly removed from defaults;
`Stop` is opt-in per ADR-002's adapter table) — **no `PostToolUse`.** OpenClaw registers
`before_tool_call`, plus `session_end`, `agent_end`, `llm_input`, `llm_output`,
`before_agent_run` — but **no `after_tool_call`.** Hermes `__init__.py` registers
`pre_tool_call` only; its docstring marks `transform_tool_result` as future phase 2. The
observation this design depends on is narrow and true: **no registered post-tool completion
hook on these enforcement adapters** — not "the host ecosystem cannot support one."

Consequence: provenance is recorded at the **pre-gate of the write/compile call itself**,
because the guard already sees that call before it runs. **This records INTENT, not completion
(round-1 B2 / smaller item):** the pre-tool hook fires before the tool runs, so a write/compile
that then fails, is refused by another gate, or never executes still leaves a record. This is
a deliberately accepted limit, bounded as follows:

- **For the floor (A/C):** the record alone never denies — the **exec-time header read** is the
  second required fact. A failed write leaves no native bytes (or leaves the old file); the
  header read governs, so an intent record for a write that did not land cannot by itself
  manufacture a floor DENY. Direction: fail-safe.
- **For the door (B):** a `compiled-output` label minted for a compile that then failed, or a
  path whose bytes are later replaced, can mis-label lineage. Direction is toward the **door**
  (benign over-gating), never a silent allow. Listed as a residual in §10.

Capture rules:

- **Any write-family tool call** (`WRITE_TOOLS` already recognises write/edit/create/`mkdir`/
  `mv`/`cp`/`chmod`/…) whose target path resolves → record `agent-written` for that path
  **regardless of extension or content.** This is the round-1 B1 fix: the old
  `isScriptLikeWritePath` / `writeContentLooksExecutable` predicates recognise script suffixes
  and a shebang **only** — not `.so`/`.o`/`.node`/`.dylib`/extensionless images or ELF/Mach-O/PE
  magic — so they cannot record a native artifact. The native-vs-source distinction is **not**
  made here; it is made at exec time by the header read (§4.1). Recording every write-tool
  target as `agent-written` is cheap (a path hash) and is what lets the exec-time header read
  decide floor-vs-door honestly.
- **A compile/build-delegate invocation in the exec surface** whose output target is resolvable
  → record `compiled-output` with `srcHashes` linking the source inputs. The recognised class
  is the compilers (`gcc`/`clang`/`cc`/`rustc`/`go build`/`zig`/`ghc`/`nvcc`…) **and the build
  drivers that delegate to them** (`make`/`cmake`/`ninja`/`node-gyp`/`cargo`/`go`), added as a
  recognised command class the same way the installer family (`PACKAGE_INSTALLERS`) is. Program
  position is read with the existing `detectScriptInvocations` / `tokeniseStatement` /
  `commandBaseName` machinery; **no new regex family** (invariant 5). This is **not** a
  command-name *exemption* (ADR-002 §2.4 forbids those): these commands are not allowlisted to
  ALLOW — they are recognised to attach **compile lineage** so their output lands on the **door**
  (row B) rather than being mistaken for a directly-written native artifact (floor). Classifying
  a build driver's output as shape 2 is what keeps `cargo test` / `go test` / `make check` /
  `npm run build` of a native addon / `pip install` of an extension out of the floor.

**Exec-surface creation paths that are NOT recorded (explicit residuals, round-1 B1/N7).**
These create or deliver a file through the **exec family** (Bash/shell), not a `WRITE_TOOLS`
call, so no `agent-written` record is minted. At a later exec, each lands in **state 3
(unknown) → door** if it has a native header at a non-install path, or is simply not seen as an
artifact at all:

1. shell redirection (`> file`, `>> file`), here-docs to a file;
2. `dd`, `printf`, `tee`, `base64 -d`, `xxd -r` writing bytes to a path;
3. `curl`/`wget`/`fetch` downloading a file;
4. an interpreter writing a file inline (`python -c 'open(...).write(...)'`, `node -e`);
5. a build driver or package lifecycle whose **child** exec is never seen as a tool call
   (`make` running a recipe, a wheel's `postinstall`) — the outer call is recorded as
   `compiled-output` only when its own `-o`/output is resolvable; outputs produced by an
   unresolved child are not;
6. **same-command write-and-exec** (`> f; ./f` or `gcc x.c -o x && ./x` in one Bash call): the
   pre-gate fires before the file exists, so the header read misses; one approval releases both
   halves. Governed by Q1's compile-then-run default for the compile form; the raw-bytes form is
   caught only when its bytes are **inline** and text-decidable (row D) — otherwise a residual.

None of these is claimed as covered by the floor. They are enumerated in §10 as residuals, with
the door (state 3) as the fail-closed catch for the native-header-at-non-install-path subset.

Recording is done by the **caller** (hook/interceptor), not inside `evaluateToolCall`,
preserving that function's purity — the same split as the injected `resolveScriptSource`.
The pure guard receives a **reader** (see §5).

---

## 4. Decision table

Let `A` = the artifact being executed/loaded/mapped. Columns: provenance state (from the
three-state classifier of §3.1, i.e. ledger + on-disk header + install-location signal), who
runs it (DefenceSource band), session taint (ADR-002 §2.2).

| # | Case | Provenance signal | Taint | Verdict | Rationale |
|---|---|---|---|---|---|
| A | State-1 agent-authored file whose on-disk bytes are a native image (ELF/Mach-O/PE/raw blob), executed — **no guard-observed compile lineage** | `exec-agent-written-native-bytes` | any | **DENY (floor)** | shape 1; no routine analogue — nobody hand-writes a binary and runs it |
| C | `dlopen`/`LD_PRELOAD`/`DYLD_INSERT_LIBRARIES`/`require` of a state-1 agent-**written** object **with no guard-observed compile lineage** | `load-agent-written-native-object` | any | **DENY (floor)** | shape 3 (loader form); a built `.node`/`.so` is row B, not here (round-1 B3) |
| D | Program body maps agent-written/just-generated bytes as executable memory (`mmap` PROT_EXEC, `mprotect` +X on a writable buffer, ctypes/cffi call into a written buffer) | `map-exec-agent-written-memory` | any | **DENY (floor)** | shape 4; **text-decidable** from the program body the guard already folds; needs no ledger |
| B | Agent wrote *source*, guard observed its compile/build (compiler **or** build driver), **agent** runs or loads the output this session | `exec-of-agent-compiled-artifact` | untainted | **AUDIT by default** (owner Q1: or HOLD, or DENY) | shape 2; routine compile-test — floor-denying this breaks M1 |
| B′ | Same as B | `exec-of-agent-compiled-artifact` | tainted | **HOLD** | ADR-002 §2.2 already holds every privileged effect in a tainted session; native-exec only sharpens the reason |
| E | **Operator** (user/cli band) runs the build output the agent compiled | positive band signal | any | **no floor/door; current behaviour** | the issue's "when the user, not the agent, runs it" — subject to Q2's band caveat |
| F | State-2 pre-existing installed tool executed (`git`, `node`, `python`, system `cc`), recognised install root, no `agent-written` record | positive install-root signal | untainted | **no floor/door; current behaviour** | explicit non-false-positive in the issue; ALLOW on a positive signal, not on absence |
| G | State-2 package-manager install tree (`node_modules/.bin/*`, a wheel's entry point), recognised, not agent-authored | positive package-tree signal | untainted | **no floor/door; current behaviour** | install trees are not agent-authored |
| H | Interpreter running an **existing** (not agent-written, no `agent-written` record) script | no provenance match | untainted | **no floor/door; current behaviour** | existing behaviour; no provenance match |
| I | Build tool writes the project's **declared build output** and the **operator** runs it | positive band signal | any | **no floor/door; current behaviour** | row E generalised to build systems — subject to Q2/Q3 |
| J | State-3 unknown: agent-written-exec where ledger evicted (tombstoned) / session id absent or unresolved / native header at a non-install path with no recognised-pre-existing signal / an unrecorded exec-surface creation (§3.4) | `unclassified-executable` | any | **HOLD (door)** | three-valued unknown → existing brokerable dangerous door, never ALLOW and never a fake catastrophic (invariant 3) |

**Precedence** is ADR-002's DENY > HOLD > AUDIT. A floor row (A/C/D) denies at any taint
state with no approval path, exactly like the catastrophic tier (`TERMINAL_BLOCK_SEVERITIES`,
the doorless branch in `pre-tool-hook.mjs`). The floor is **provenance-blind only in the
sense that taint does not matter** — it still requires a positive state-1 artifact match plus
the exec-time header read (A/C) or a text-decidable body (D); it is not a text pattern.

**"ALLOW" is not a fourth decision tier (round-1 N4 / Grok#4).** ADR-002 §2.4's decision set is
**DENY / HOLD / AUDIT only.** Rows E–I are therefore **not** a new ALLOW verdict: they are
"**no floor match, no door — the call keeps its existing behaviour (no new gate),**" i.e. the
pre-AUDIT baseline this design does not touch. Not blocking installed tools and package-manager
bins (invariant 2) needs no new tier; it is the absence of a match. The floor adds a DENY row,
the door adds/uses a HOLD row, shape 2 lands in AUDIT (Q1) — that is the whole of what this
design adds to the three-valued decision.

**Three-valued mapping (invariant 3):** state-1 native-of-agent-artifact → DENY (rows A/C/D);
state-2 positive-pre-existing / operator-run → current behaviour (rows E–I, unchanged); state-3
unknown (row J) → the existing dangerous `require_approval` door, **never** a fabricated
catastrophic and **never** a silent allow. There is no path from "not in the ledger" to a clean
allow.

### 4.1 Rows needing a typed host fact rather than text (invariant 5)

- **A, C** — need **both** host facts: the **ledger** (is this path a state-1 `agent-written`
  artifact, with no `compiled-output` lineage) **and** a **magic-byte read of the file header**
  (are the on-disk bytes a native image), injected like `resolveScriptSource` at the hook
  boundary. **Neither alone suffices**, and neither is decidable from the command string.
  Header-alone would be wrong twice: it would miss authorship (denying installed `git`/`node`,
  whose headers are ELF) and it would make the ledger pointless. The ledger is **necessary** for
  the agent-authored half; the header is **necessary** for the native-image half. A lost ledger
  record for an A/C candidate → state 3 (door), per §3.2.
- **D** — **text-decidable** from the program body the guard already folds; **no host fact
  needed and no ledger needed.** This is why row D is the one floor row Hermes' text-only outage
  fallback can keep (§6).
- **B/B′** — the source→compile→run lineage is a ledger fact (the compile edge recorded in
  §3.4).
- **E/I** — "did the operator or the agent run this" is the **DefenceSource band** (host
  fact, resolved by `resolve-tool-source.ts` / `env-detector.ts`). **Round-1 B5 caveat (Q2):**
  that band is *process* identity — `env-detector.ts` labels a direct Claude Code / Codex CLI as
  `type: cli`, and ADR-002 §1.2 states an operator's tool request and a prompt-injected model's
  request **inside the same session share the same band**. So the band does **not** by itself
  prove a *human*, rather than the agent, ran the output. "is the target the declared build
  output" needs project build config (host fact), see Q3. Both are owner questions, not facts
  PR 1 can assert; see Q2/Q3.

### 4.2 False-positive surface and how it is measured

The false-positive surface is **row B in an untainted session** — the agent compiling/building
and running its own source. Under the recommended default (B = AUDIT) that surface audits and
does not block. The honest scope of the "no blocked builds" claim (round-1 B3): this holds for
the flows the control set in §8 actually exercises — a compiler build-and-run, a build-driver
build-and-run (`cargo test`, `go test`, `make check`, `npm` native-addon build, `pip` extension
build), and a built `.node` loaded via `require`. It is **not** a measured false-positive *rate*
over production traffic, and it does not claim "zero blocked builds" for build shapes outside
that control set. If the owner chooses B = HOLD (Q1), the surface is "one bounded approval per
distinct compile-then-run chain."

Measurement reuses existing machinery, within its real limits (round-1 N5):

- the §5A logged-signal replay (`scripts/guard-policy-replay.mjs` /
  `scripts/replay-guard-corpus.mts`) is a **signal-set / STOP-event** comparison over truncated
  previews — it **cannot** reconstruct the new facts (artifact bytes, authorship, compile
  completion, taint) from existing logs. Taint-dependent and artifact-dependent rows stay
  "cannot be determined from the log" (ADR-002 §5A rule: provenance is never manufactured for
  the replay). What the replay **can** report is which recorded allowed events carry a
  write/compile/exec command shape at all — a scoping signal, not a flip rate.
- the `guard-effect-fixtures` harness (§5B) is an **in-process simulation** (per its own README),
  not proof of host/provenance enforcement; the benign controls below are executed against both
  current and proposed policy and independently reviewed;
- `guard-precision-corpus.ts` gets the benign compile-and-test **and build-driver** rows added
  so a regression that floor-denies a routine build fails CI.

The floor's acceptance bar, pre-registered and **narrowed to the control set**: **zero**
benign-control rows (§8) denied; the **three directly-written floor shapes** (A/C/D) denied with
a plain-English reason. Shape 2 (compile-then-run) is **not** in the floor's DENY bar — it is the
door (§9, Q1).

---

## 5. Surfaces to change (every file and call site)

**PR 1 (the floor + ledger + three-valued door):**

- `src/defence/iron-dome/agent-artifact-provenance.ts` **(new, pure core)** — ledger
  record/query/evict, path hashing, compile-lineage edge, the three-state classifier,
  native-image magic-byte classifier helper (operates on an injected header read, stays pure),
  caps, tombstones.
- `src/defence/iron-dome/agent-artifact-store.ts` **(new, fs layer)** — per-session flat
  JSON, atomic tmp+rename `0o600`, TTL, corrupt-as-empty; one entry point each for
  *record-write*, *record-compile*, *query*.
- `src/defence/iron-dome/tool-action-guard.ts`:
  - new `ToolGuardOptions` members (injected, caller-supplied, never throwing):
    `agentArtifactLedger?: (sessionKey) => LedgerView` (read) and
    `readFileHeader?: (path) => Uint8Array | null` (magic-byte read for rows A/C). These add a
    ledger reader and a header reader; they are **not** an attested-actor input — the actor
    question (E/I) stays the DefenceSource band and its Q2 limit.
  - new classifier `classifyNativeExec(execSurface, ledger, headerReader)` returning the
    §2 signals and the three §3.1 states; built on `detectScriptInvocations` /
    `tokeniseStatement` / `commandBaseName` / `EXEC_WRAPPER` / `SCRIPT_INTERPRETER` /
    `isInstalledBinaryPath` and the existing body-fold regions — **no new regex family**.
  - wire into `evaluateToolCall`: floor rows A/C/D land on the catastrophic/terminal branch
    (block, doorless); row J lands on the `require_approval` branch; row B emits the
    `exec-of-agent-compiled-artifact` signal at AUDIT/HOLD per Q1.
  - **do not** extend `GUARD_SELF_PROTECTION_SIGNALS` — this is a separate floor; but mirror
    its "enforced in every posture" standing for rows A/C/D by rating them at a terminal
    severity (`TERMINAL_BLOCK_SEVERITIES`).
- `scripts/pre-tool-hook.mjs`:
  - at the write/compile pre-gate, call the store's record entry points keyed by
    `baseExtra.sessionKey`; **skip when `namedIdentityUnresolved` OR when `sessionKey` is
    absent** (round-1 N-item: an absent key is not flagged `namedIdentityUnresolved`);
  - inject `agentArtifactLedger` + `readFileHeader` into the `evaluateToolCall` options
    object (4th arg) alongside `resolveScriptSource`;
  - add the new signal names to `SAFE_SIGNALS`;
  - **non-widenable floor vs widenable door (round-1 B4).** Floor rows A/C/D are rated terminal,
    so they exit at the `TERMINAL_BLOCK_SEVERITIES` branch **before** the `autoApprove`, shadow
    (enforce-when-ready) and `enforce:false` advisory widenings — those three cannot turn a floor
    DENY into an allow/warn. Row J is an ordinary `require_approval` and **is** subject to those
    widenings: on an advisory, shadow, or standing-`autoApprove` Claude host, an unknown-exec
    (row J) can be warned or auto-approved exactly as any dangerous verdict can. This is the
    honest limit — row J's door is as widenable as the dangerous tier it reuses; it is not a
    new non-widenable semantics.
- `plugins/openclaw/interceptor.ts` — inject via the **action-evaluator** seam, not
  `runDefencePipeline` (round-1 N3): the evaluator is a distinct `createInterceptor` option
  (`index.ts` ~4811, the 3rd arg's `evaluateToolCall`) called directly at `interceptor.ts` ~2169;
  `runDefencePipeline` is the separate content/memory pipeline. Record writes/compiles in the
  `before_tool_call` path. The injected inputs still need session key, caller cwd, PATH
  resolution and the header reader spelled out at that seam.
- `plugins/openclaw/provenance.ts` / `session-taint.ts` — no behaviour change required for
  PR 1; the agent-write record is a natural provenance input, noted not required.
- `src/api/visualization-server.ts` (`POST /api/v1/action-guard`) — **today accepts `tool` +
  `args` only**, with no resolver or state options. PR 1 extends it to accept the host-owned
  session id and forward it; holding the store server-side so Hermes shares it is **PR 2**
  (§6, cross-plane table). Forwarding an id alone is not full provenance.
- `plugins/hermes/shieldcortex/sc_client.py` — forward session id to the API; add a
  **text-only** `fallback_native_exec_memory_match` (row D) for the outage path, analogous
  to `fallback_catastrophic_match`. **Rows A/C cannot be served by the outage fallback** (no
  ledger, no header read) and, per `policy.py`, an unmatched outage shape **fails open (allow)**,
  not to a door — see §6 and Q4. This PR does **not** change that fail-open contract.
- `plugins/hermes/shieldcortex/policy.py` + `__init__.py` — thread the session id through
  `pre_tool_call`. No change to the unavailable→None(allow) path for unmatched shapes.
- Tests: `src/defence/iron-dome/__tests__/native-exec-of-agent-artifact-907.test.ts`
  (pure core + classifier + three-state + tombstone eviction), an enforcement-surface-parity
  fixture, and the benign + build-driver rows added to `guard-precision-corpus.ts`.

**PR 2 (plane parity + store wiring):** finish Hermes/API **server-side store** so row B/J
ledger logic (not just the text-decidable floor) holds under Hermes; cross-plane parity tests.
Note this does **not** close the Hermes-**outage** gap: an unavailable server cannot supply its
store (round-1 B4), so A/C outage behaviour is the §6/Q4 residual regardless of PR 2.

**PR 3 (separate follow-up issue — doctor shared-host warning, issue item 4):** see §7.

**PR 4 (separate follow-up issue — egress tightening, issue item 5):** allow-list egress
destinations for code-executing sessions. Out of scope for the first PR; filed separately.

---

## 6. Cross-plane behaviour (invariant 4)

| plane | capture | floor (A/C/D) | door (B/J) |
|---|---|---|---|
| Claude Code hook | pre-gate record keyed by `sessionKey` | full (ledger + header read) | full; row J is widenable (autoApprove/shadow/advisory), floor is not |
| OpenClaw interceptor | pre-gate record via action-evaluator seam | full | full (same posture limits as the hook) |
| Hermes (API up) | PR 2: API holds store | full (PR 2) | B/J via `require_approval`→**block** (Hermes has no card); PR 1 forwards id only |
| Hermes (outage fallback) | none | **row D only** (text-decidable); **A/C unmatched → fail open (allow)** | B/J unmatched → **fail open (allow)** |

**The honest Hermes statement, in the ADR-002 style (round-1 B4).** On the Hermes outage path
`policy.py` returns `None` (allow) for any shape the text fallback does not match, and Hermes
has **no approval prompt** — so there is **no door on this plane for an unmatched shape.** The
ledger-dependent floor rows A/C are unmatched text shapes, so on an outage they **fail open
(allow)**, not to a door. Only row D (text-decidable) denies on outage, and only the
catastrophic fallback denies unconditionally; a dangerous match denies when `enforce` is on.
This is ADR-002 §own documented behaviour ("partial fail-open, loudly audited" — the Hermes row
of the §5C adapter table), recorded here as a **measured residual**, not a pass. The earlier
draft's "A/C fall to the dangerous door" / "brokerable door, not to allow" on outage was
**incorrect against `policy.py`** and is removed.

**API-up wording corrected.** When the API is up, `policy.py` maps `require_approval` to a
**block** (fail-closed, stricter than a door, because Hermes has no approval card) — not to an
approval prompt. So "door = full" was the wrong word for the API-up Hermes cell; it is
"require_approval → block." §5C-style coverage records Hermes-outage as "floor partial (row D
only), A/C fail open," never as a pass.

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

All fixtures run in CI via the existing Jest + `guard-effect-fixtures` harness (an in-process
simulation — round-1 N5). **Payload literals are not needed** — the exploit rows are described
by *shape*; benign fixtures are real files. Remembering the repo's CI gotchas: fixtures write
under the test-pinned home, never `$HOME/.shieldcortex`, and avoid `os.tmpdir()` for any
watch-adjacent path.

**Acceptance rows from #907 (the three directly-written shapes are DENY; compile-then-run is the
door):**

- **(a) agent writes and runs a compiled binary** → fixture: a write tool records a file
  whose bytes carry a native-image magic header (a tiny benign ELF/Mach-O stub committed as
  a fixture, or a `chmod +x` of agent-written bytes), then an exec of that path →
  `exec-agent-written-native-bytes` → **DENY**, plain-English reason.
- **(b) compile-then-run across two calls** → call 1: agent writes `helper.c` (benign
  "hello") and runs `cc helper.c -o helper` (records `compiled-output` linked to the
  source); call 2: agent runs `./helper` → `exec-of-agent-compiled-artifact` → **HOLD in a
  tainted session / AUDIT (or Q1 verdict) untainted** — **NOT a DENY** (see §9). Proves
  cross-call linkage via the store.
- **(c) LD_PRELOAD of a just-written library** → agent **writes** `libx.so` byte-for-byte
  (benign, no compile observed), then a command sets the preload env and runs any program →
  `load-agent-written-native-object` → **DENY**.
- **(d) Python mapping executable memory** → a program body containing the `mmap`
  PROT_EXEC / `mprotect` +X / ctypes-call-into-buffer *shape* (benign no-op bytes) folded
  from a write-then-run or a `-c`/heredoc → `map-exec-agent-written-memory` → **DENY**.
  This row needs no ledger and is the Hermes-outage-safe one.

**Benign controls (must all keep current behaviour / not trip the floor):**

- running installed `git`, `node`, `python` on a **pre-existing** (not agent-written)
  script (rows F/H — state-2 positive install-root/no-record signal);
- `node_modules/.bin/<tool>` and a pip console-script entry point not authored by the
  agent (row G);
- the **operator** (user/cli band) running the build output the agent compiled (row E — with the
  Q2 band caveat noted, this is "band says cli", not a proven human);
- a build tool writing the declared build output, operator-run (row I);
- an agent writing a **data** file (`.json`/`.md`/`.csv`) and a later command reading it
  (must not be mistaken for a native artifact — reuses `INERT_WRITE_TARGET`);
- **build-driver flows the floor must not deny (round-1 B3):** `cargo test`, `go test`,
  `make check`, an `npm run build` of a native addon, and a `pip install` of an extension — each
  as the agent running the outer command, with a following agent exec/load of the output. All
  must resolve to **row B (door/AUDIT per Q1)** via the compile-lineage record, **never floor**;
- a **built** `.node` addon `require`d in the same session → **row B** (compile lineage), not
  floor row C (this is the round-1 B3 scenario-D fix, asserted as a control);
- the full benign compile-and-test flow in a **tainted** session is HOLD (expected), proving
  the floor did not escalate it to DENY.

**Store/eviction/unknown controls:**

- evict-then-exec → the previously-recorded path is tombstoned → **row J door**, **not** allow
  and **not** a floor DENY (proves eviction fails toward *unknown*);
- unresolved **or absent** session id → no ledger → row J door;
- a native-header file at a **non-install project-local** path with no record (state 3) → row J
  door, not allow (proves "not in ledger" is never ALLOW);
- a native-header file in a **recognised install root** with no record (state 2) → current
  behaviour, not a door (proves installed tools are not floor-denied or door-held);
- cross-process: write recorded in process 1 is visible to the exec check in process 2
  (two separate hook invocations against the same store file).

---

## 9. What PR 1 delivers against each #907 acceptance criterion

| #907 acceptance | met by PR 1? |
|---|---|
| Fixture: agent writes+runs a compiled binary → denied, plain reason | **Yes** (row A) |
| Fixture: compile-then-run across two calls → **denied** | **No — consciously narrowed to HOLD/AUDIT (door), pending owner Q1.** Floor-denying this would block routine compile-and-test (M1); the issue's DENY is not met by design, not by omission |
| Fixture: LD_PRELOAD of a just-written library → denied | **Yes** (row C) |
| Fixture: Python mapping executable memory → denied | **Yes** (row D) |
| No false positives on installed/pre-existing tools | **Yes, for the §8 control set** (rows E–I + the data-file, build-driver, built-addon and state-2/3 controls); not a measured production false-positive rate |
| Doctor reports the shared-host risk | **No — separate PR 3** (issue item 4), by design |

So PR 1 meets the three directly-written DENY fixtures (a, c, d) and the installed-tool
non-false-positive bar **for the control set**. It does **not** meet the issue's "compile-then-run
→ denied" row: that row is **consciously narrowed** to the door, pending the owner's Q1 decision,
because an honest floor cannot deny it without blocking routine builds. The doctor report (item 4)
and egress tightening (item 5) are separate deliverables (PR 3 / PR 4). This is stated so PR 1 is
not claimed to close the whole issue, and so §9, §10-Q1, §11 and the summary all say the same
thing about the compile-then-run row (round-1 B7).

---

## 10. Residual risks and open owner questions

### Owner questions (numbered, recommended option first)

1. **Default verdict for shape 2 (row B) in an *untainted* session.** Options: (a) AUDIT —
   record, do not block; (b) HOLD — one bounded approval per compile-then-run chain; (c)
   DENY — floor it too. **Recommend (a) AUDIT** for the first PR: it satisfies M1 ("routine
   work never trips the Guard"), keeps the control-set false-positive surface at no blocked
   builds, and still produces the signal and the audit trail the owner needs to decide later.
   (b) is the ADR-002-consistent tightening **only after** the §2.5 narrowing gate (5A+5B+5C)
   is met — it is not an ADR-sequenced default now, and HOLD is not "a later tightening of an
   AUDIT default" in ADR-002's own text (round-1 B6/Grok#3). (c) is rejected as dishonest
   against M1 unless the owner explicitly accepts blocking routine builds. **ADR note:**
   ADR-002 §2.4 holds an `unclassified-executable`/`unresolved` effect at **HOLD minimum in
   every session**; a compiled binary whose effects the mapper cannot resolve is such an effect.
   Recommending AUDIT for row B is therefore a **conscious owner departure** from ADR-002's
   HOLD-minimum for this one well-provenanced shape, justified by M1 — it is labelled as a
   departure here, not presented as already ADR-consistent.
2. **Operator-vs-agent discriminator for rows E/I (round-1 B5).** The DefenceSource band is
   *process* identity; ADR-002 §1.2 says an operator request and an injected-model request in
   the same session share it, so `type: cli` does **not** prove a human ran the output. Options:
   (a) keep rows E/I on the band but **label them "band-attested, not human-attested"** and do
   not treat the band as a provenance *exception* that overrides the floor — the floor (A/C/D)
   keeps DENY precedence regardless of band; (b) require a genuine per-action host-attested
   human-execution fact before E/I relieve anything; (c) drop E/I from guarded tool calls
   entirely. **Recommend (a)** for PR 1: E/I are "no new gate" rows (current behaviour), and the
   floor's DENY precedence is independent of band, so a mislabelled band cannot grant the agent a
   floor exemption. (b) is the correct long-term fact and is deferred to the actor-attestation
   work. This also means row E/I never *weaken* the floor — they only describe where no floor
   match exists.
3. **"Declared build output" definition (rows E/I).** Needs a project build-config fact to
   know the build dir. Recommend: for PR 1, rely on the **band** (operator-run, with the Q2
   caveat) rather than the build-dir fact, and defer build-dir awareness to PR 2 so PR 1 ships
   without a new config surface.
4. **Hermes outage floor coverage (round-1 B4).** On the text-only fallback, rows A/C are
   unmatched shapes and `policy.py` **fails open (allow)** for them; Hermes has no approval
   prompt, so there is **no door** on this plane for an unmatched shape. Recommend **accepting
   this as a documented residual** for PR 1 (ADR-002 already documents Hermes partial fail-open),
   recording it as a measured coverage gap, **not** closing it with a claim of a door that the
   plane does not have. PR 2's server-side store does **not** fix the *outage* case — an
   unavailable server cannot supply its store. The honest first-PR change is: row D denies on
   outage via the new text matcher; A/C do not, and that is the residual.
5. **Native-image detection fidelity.** Magic-byte reads catch ELF/Mach-O/PE; a raw-shellcode
   blob with no recognisable header is caught only when it reaches row D's exec-memory shape.
   Recommend: treat a state-1 agent-written file that is executed directly *and* is non-text (NUL
   bytes, as `foldScriptSources` already detects at exec) as `exec-agent-written-native-bytes`
   even without a known magic number — fail toward the floor for direct exec of agent-written
   binary blobs.

### Residuals (static coverage deductions — not attacks executed in this review)

- **Unrecorded exec-surface creation (§3.4):** shell redirection, `dd`/`printf`/`tee`/`base64
  -d`, downloads (`curl`/`wget`), interpreter inline file writes, and unsupported write schemas —
  no `agent-written` record; caught only as state-3 **door** when a native header sits at a
  non-install path, else not seen as an artifact.
- **Same-command write-and-exec / compile-and-exec** in one Bash call (`> f; ./f`,
  `gcc x.c -o x && ./x`): the pre-gate fires before the file exists; one approval releases both
  halves; governed by Q1 for the compile form, text-decidable (row D) only for inline-bytes.
- **Pre-gate records intent, not completion:** a `compiled-output` label for a compile that then
  failed, or a path whose bytes are later overwritten by an unrecorded writer, can mis-label
  lineage — direction is toward the **door** (benign over-gating) for row B, and the exec-time
  header read governs the floor, so neither direction is a silent allow (§3.4).
- **Build-recipe / package-lifecycle / native-loader child exec** not observed as a tool call —
  ADR-002 §210's outer-gate limitation; an inner call a build recipe or loader makes is outside
  the gate on adapters that observe the outer invocation only.
- **Bare-PATH execution and extensionless install-root relief** inherited from
  `detectScriptInvocations` / `isInstalledBinaryPath` — a later-modified target inside such a
  tree is a state-2 path by location, so a genuine agent modification of a file *inside* an
  install root is a residual (positive pre-existing signal can mask an agent write there).
- **Bounded parsing / folding limits:** a body beyond the `MAX_SCRIPT_BYTES` / `MAX_FOLDED_BYTES`
  scan cap, a truncated Hermes fallback surface (4096-char cap), or a raw fallback body that is
  absent — row D may miss; such a miss is unknown, not allow-by-design.
- **Compile-to-native remains an intentional door (Q1), not a floor** — it carries the same
  harmful effect the floor seeks to reduce; this is the accepted M1 trade, not a covered case.
- **Same-UID evasion:** direct mutation of the same-UID-writable ledger, hard-link aliases, file
  replacement after inspection, a symlink/rename/second-interpreter indirection, and identity of
  files across session/TTL boundaries — the same residual the self-protection floor documents.
  Not all of these are "determined same-UID evasion": several (redirection, build recipes) are
  ordinary tool paths and are listed above as such.
- **Scope honesty (issue "Context").** This narrows the "agent-authored native code reaches the
  CPU" path. It does **not** stop hardware flaws, does not isolate a shared CPU. The doctor
  warning (PR 3) and egress tightening (PR 4) are the complementary, separate controls.

---

## 11. PR ordering summary

1. **PR 1** — effect class + floor DENY (rows A/C/D) + agent-artifact ledger (pure core,
   fs store, three-state classifier, tombstones, Claude + OpenClaw wiring) + three-valued door
   (rows B/J) + Hermes session-id forwarding and text-only row-D fallback + the §8 test plan +
   benign/build-driver corpus. **Meets the three directly-written DENY fixtures (a, c, d) and the
   installed-tool non-false-positive bar for the control set.** Does **not** meet the issue's
   "compile-then-run → denied" row (consciously narrowed to the door, pending Q1), the doctor
   report (PR 3), or egress tightening (PR 4).
2. **PR 2** — Hermes/API **server-side** store so the ledger-dependent floor and door hold under
   Hermes **when the API is up** (the outage case stays the §6/Q4 residual); cross-plane parity;
   build-output-dir awareness (Q3).
3. **PR 3** *(separate issue)* — doctor `Code-execution host isolation` warning (issue item 4).
4. **PR 4** *(separate issue)* — egress allow-listing for code-executing sessions (issue item 5).
