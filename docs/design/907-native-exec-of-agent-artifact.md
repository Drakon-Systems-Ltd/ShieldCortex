# Design: always-deny for execution of agent-authored native code (#907)

**Status:** Design only. No source change in this branch.
**Issue:** #907 (raised by Michael, 23 Oct 2026). **Author:** TARS (improvement loop).
**Relates to:** ADR-002 (`docs/architecture/ADR-002-provenance-first-enforcement.md`) — this
is one DENY effect (floor rows A/C/D), one HOLD row (door row J) and one row whose verdict is
owner question Q1 (row B), under that ADR's effect decision, plus a provenance store.
ADR-002's §2.2 taint store is **not wired** (`session-taint-lineage.ts` says so); this design
does not depend on it for any floor row and does not claim it (§4, Q1). ADR-001's intent-first
law, catastrophe hard-stops and credential non-exfil rule are unchanged.

> **Invariant up front (ADR-002 / M1).** The Guard is **OFF by default**. Everything below is a
> rule that applies *only when the Guard is enabled*. Nothing here turns the Guard on, changes
> its default posture, or changes who it is on for. The **floor** (rows A/C/D) is held to a
> narrowed bar: **no §8 benign control hits it** (§4.2 lists the benign surface it can still
> match — JIT/FFI/test bodies for D, placed binaries for A — unmeasured). A/C fire only where
> Rule P names a unique `agent-written` producer from complete session history (§3.1); a
> compiler's output with a unique `compiled-output` producer is never floor. Incomplete or
> ambiguous history is the door, never the floor. The issue's compile-then-run case is **not** in
> the floor; it is row B, whose verdict is owner question Q1 (AUDIT recommended — and AUDIT is
> **not** a door). The **unknown door** (row J) is a new HOLD on routine work, stated plainly
> rather than hidden: a native binary at a project-local path whose production the guard did not
> observe — a pre-existing `./target/debug/app`, a build driver's output — is held; and in a
> session whose history is incomplete, every resolved native exec is held (§4.2, §9).

> **Round-3 note (last fold under the cap).** Round 2 (Astra, Grok) returned CHANGES REQUESTED.
> This revision **removes or narrows** claims rather than adding coverage. The moves, each stated
> once and referenced elsewhere:
> 1. **Rule H** (§3.1): install-root location never certifies non-agent authorship by itself.
>    Relief at an install root is reached only through **complete** per-session history (as
>    redefined in round 4, below).
> 2. **Rule P** (§3.1): a record is **intent**; a header at exec proves **format**, not
>    authorship. A record counts as the producer of the current bytes only if the file's content
>    identity changed after the recorded call. An unproved record — a failed write, a metadata-only
>    `chmod`, a failed compile — names no producer. An unproved compile label can no longer weaken
>    the floor.
> 3. **Build drivers are demoted** (§3.4): only a recognised compiler with a literal, resolvable
>    `-o` output gets compile lineage. `cargo`/`go test`/`make`/`npm run build`/`pip install`
>    outputs are **unsupported-output**: a later exec of them is row J, not row B.
> 4. **"No producer"** for a native image means unknown (row J) at a non-install path, and at an
>    install root whenever history is incomplete; the §3.1 classifier table is the rule.
> 5. **Taint (B′)** is not wired; B′ HOLD is not a PR 1 result (§4, Q1).
> 6. **Hermes** coverage is stated per inspected surface and per `enforce` (§6).
> 7. §10 residuals now state the **actual** verdict (several were wrong-direction in round 2).

> **Round-4 note (final fold).** Round 3 (Astra, Grok) converged on one defect: Rule P read only a
> per-path window of 4 records, so a still-stored producing record could fall outside it while
> Rule H certified "complete" history. Astra added a second: the best-effort general JSON store
> could lose a newer record and leave an older one to be misread as the producer. The fix
> **removes** mechanism:
> 1. **One record store** (§3.1): the FIFO general JSON file, its last-writer-wins race, its
>    corrupt-as-empty read and the per-path window are gone. Every record — install root or not —
>    is a create-once file. Nothing is evicted, nothing is rewritten.
> 2. **Rule P reads every record for the path.** There is no window.
> 3. **One completeness test** (§3.1, "complete history") covers listing, per-record readability,
>    in-flight publication, the cap and unresolved targets. Incomplete or ambiguous history names
>    **no** producer and is state 3 (row J): never a compile exemption, never a floor DENY.
> 4. **One canonicaliser** for record and query (§3.4); compiler names that are two tokens are
>    dropped; cwd and stat failure contracts are stated (§5).

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
**agent-written** record as the producer. An unproved compile record names no producer (Rule P),
so a failed compile over directly-written native bytes leaves the write record as the producer and
the floor still fires. Where history cannot name a unique producer (incomplete, or two records of
different kinds that Rule P cannot order), neither applies: state 3, row J. Row C carries the same
rule, so the two cannot disagree.

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
  <sessionDir>/rec/<pathHash>.<at>.<rand>   // ONE create-once file per record, for every
                                            // target (install root or not); never evicted,
                                            // never rewritten
    body = { kind:  'agent-written' | 'compiled-output'
             preId: ContentId | 'absent' | 'unknown'   // identity at the pre-gate (§5)
             at:    number }                // ms, ordering only
  <sessionDir>/rec/unresolved.<at>.<rand>   // a write-family call carried a path argument
                                            // that could not be canonicalised (§3.4)
  pathHash  = HMAC(salt, canonicalTarget(token, cwd, home))   // §3.4; NOT the path
ContentId = { dev, ino, size, mtimeMs }     // stat fields; ctime deliberately excluded so a
                                            // metadata-only chmod/chown does not count
```

**Publication.** A record is written to a temp entry `<pathHash>.<at>.<rand>.tmp` opened
`O_CREAT|O_EXCL`, its body written, then renamed to its final unique name. The recorded call is
released only **after** the rename returns. If any step fails, the call is **held** (row J)
rather than proceeding unrecorded. With no session key nothing is recorded and nothing is held:
every native exec is already state 3 (see "Keyed by host-owned session identity").

**Complete history.** For an exec target `p`, the session's history is **complete for `p`** iff
all of:

1. the session's `rec/` directory lists (a not-found directory — a session that has recorded
   nothing — is complete and empty; any other listing error is incomplete);
2. no entry is named `unresolved.*`, and every entry name parses as the scheme above;
3. the entry count is below the cap (proposed 4096 per session) — at the cap, further calls
   proceed **unrecorded**, so a full directory is incomplete by definition;
4. every entry for `p`'s `pathHash` is a final (not `.tmp`) entry that reads, parses, and has a
   `preId` other than `'unknown'`.

Any failure makes history incomplete for `p` — an unreadable, unparseable, truncated or
still-being-published record withdraws relief exactly as an unlistable directory does. Failures 1–3
are session-wide; failure 4 is scoped to `p`.

**Rule P — production evidence (the one rule for "did this record produce these bytes").**
The pre-gate sees a call's **intent**, not its completion (§3.4). A header read at exec proves
the bytes are a native **format**; it does not prove who wrote them. So a record is evidence that
the recorded call produced the current bytes only if the path's current `ContentId` **differs**
from the record's `preId`. Rule P runs only on complete history and reads **every** record for
`p` — there is no window. The **candidate** is the newest record (by `at`) whose `preId` differs
from the current `ContentId`. It is the **producer** only if it is **unique**: no other record for
`p` has the same `preId` and a different `kind`. (Two records pre-gated against the same identity
are two intents whose effect order the pre-gate cannot see — parallel calls, or a failed write
followed by a compile; Rule P does not guess which landed last.) Outcomes:

- unique candidate → **producer** (state 1 or 1c);
- no candidate — every record's `preId` equals the current identity: the write failed, was
  refused by another gate, was a metadata-only `chmod`, or the compile never produced → **no
  producer** (state 2 or 3 by location);
- candidate not unique, or history incomplete → **ambiguous** → state 3. Ambiguous history is
  never a compile exemption and never a floor DENY.

Consequences, with complete history:

- a failed write against an existing native file leaves its `preId` equal to the old file's
  identity → unproved → the old bytes are not attributed to the agent (round-2 B2 example 1);
- a failed compile over directly-written native bytes leaves the compile record unproved → the
  older write record is the producer → floor, not row B (round-2 B2 example 2);
- `chmod`/`chown` on existing native bytes changes ctime only → unproved (round-2 B2 example 3);
- a producing write followed by any number of metadata-only or failed calls to the same path:
  the later records all carry the produced identity as `preId`, the producing record is still
  read (no window) and is the unique candidate → producer (round-3 B1);
- a failed write followed by a real compile to the same path (both `preId` = the old identity,
  different kinds) → ambiguous → row J, not DENY and not row B (round-3 B2 example B, without
  needing any loss).

What Rule P does **not** prove: that the recorded call, rather than a later **unrecorded** writer
in the same session, made the change. A change after a recorded intent is attributed to that
record. That is a classification limit, listed in §10 with its actual verdict.

**Rule H — install-root relief requires complete history (the one rule for "location").**
`isInstalledBinaryPath` (`tool-action-guard.ts:4813`) is a path-string test:
`INSTALLED_BIN_DIR_RE` plus "extensionless". It covers user-writable roots (`~/.local/bin`,
`~/.cargo/bin`, `node_modules/.bin`, …), and its own rationale (`:4790-4797`) concedes files can be
planted there. **Location alone never certifies non-agent authorship.** An install-root native
image with no producer is state 2 only when history is complete for `p`. Then the sentence "no
recognised write-family or supported-compile call in this session changed `p`'s bytes" is true of
the records the classifier actually read: every record for `p` was read, none has a `preId`
differing from `p`'s current identity, and no recognised call was let through without a published
record (publication failure holds the call; the cap and unresolved targets make history
incomplete). The rule's limits — unrecorded exec-surface creators, cross-session/TTL, holds
widened on non-enforcing hosts or released by approval — are §10 residuals with their real
verdict, not covered cases.

**The total classifier.** For an exec/load target the guard resolves to a path `p` (§3.4, §5):

| step | condition | state | rows |
|---|---|---|---|
| 0 | `p`'s header is not a native image (script/text); or `p`'s header cannot be read **and** history is complete for `p` with no record for `p` | **outside this design** — current behaviour (including the existing opaque-script audit) | — |
| 1 | native image; history complete for `p`; Rule P producer (unique) is `agent-written` | **1 — agent-produced** | A / C (floor) |
| 1c | native image; history complete for `p`; Rule P producer (unique) is `compiled-output` | **1c — compile-lineage subtype** | B |
| 2 | native image; history complete for `p`; no candidate; `p` passes `isInstalledBinaryPath` | **2 — install-root, no session write** | F/G: current behaviour |
| 3 | any other case: native image at a non-install path with no producer; history incomplete; candidate not unique; current identity unknown (`statPath` → `null`); no session key; header unreadable for a `p` that has a record or whose history is incomplete | **3 — unknown** | J (door) |

So the three authorship states are 1 / 2 / 3, with 1c as the compile-lineage subtype of an
observed producer. **"No producer" for a native image means unknown → row J, except at an install
root with complete history (state 2).** For a non-native target it means nothing to this design:
the target is outside the classifier and keeps current behaviour (row D's body match still
applies to inspected script bodies, §4). There is no sentence elsewhere in this document that
overrides this table.

- **Content-free in audit (invariant 4).** The ledger stores **hashes of paths** and stat
  identities, never path text and never file contents. A denial's audit row names the *effect*
  and the *signal*, and at most a `fmtSpan`-bounded fragment of the **command** the operator can
  already see. The ledger never reaches an audit row.
- **Keyed by host-owned session identity.** The key is `sessionKeyFor(id)` — the HMAC the hook,
  `session-guard.ts` and `stop-hook.mjs` already compute from the host's `session_id`.
  `hookSessionExtras` sets `namedIdentityUnresolved` only for a *non-empty unresolved* id, so the
  new code treats an **absent** key the same as an unresolved one: no ledger. With no ledger,
  history is never complete, so every native image (install root or not) is state 3; nothing is
  recorded and no write is held for want of a store.
- **Bounded — new bounds, not inherited lease-store constants.** Temp-then-rename, `0o600` and
  TTL mirror `session-lease-store.ts`; its single read-modify-write JSON file, corrupt-as-empty
  read and last-writer-wins race (`session-lease-store.ts:19-30`, `:109-128`) are **not**
  borrowed. New constants in the pure core: records per session (proposed 4096), max distinct
  sessions, TTL measured from the session's last ledger activity. TTL expiry renames the whole
  session directory away before deleting it, so a reader sees all of a session's records or none.
- **Loss cannot be partial except by same-UID tampering.** No record is evicted, rewritten or
  merged, so the round-3 B2 shapes (a race or corrupt read dropping a newer record and leaving an
  older one) have no mechanism. A record that cannot be published holds its call; a damaged
  record makes history incomplete (state 3); a full store makes history incomplete. Deletion of
  individual record files by a same-UID process is the §10 same-UID residual. The round-2
  tombstone ring and the round-3 general JSON store are **removed**.

### 3.2 Where it lives and how a separate-process hook shares it

Flat files, not SQLite, under `~/.shieldcortex/` (honouring `SHIELDCORTEX_*`): the Claude Code
hook has no DB on its hot path, and a store one plane cannot read is a plane that silently does
not bind. Each hook invocation is a **separate process** reading the same per-session directory.
Records are create-once files with unique names, so concurrent calls cannot overwrite each other;
a record still being published is a `.tmp` entry and makes history incomplete for its path until
the rename lands. Pre-gate order is not effect order for parallel calls; Rule P's uniqueness test
(§3.1) is what keeps that from naming a producer.

### 3.3 Two split cores (same discipline as `session-taint-lineage.ts` + `session-lease-store.ts`)

- **Pure core** `src/defence/iron-dome/agent-artifact-provenance.ts`: record/query/TTL
  arithmetic, hashing, `canonicalTarget` (§3.4), the complete-history test, Rule P producer
  selection, the total classifier, caps, native-header classification over injected bytes. No
  I/O, injected clock.
- **fs layer** `src/defence/iron-dome/agent-artifact-store.ts`: the one entry point both
  planes call; create-once record publication, listing, stat, TTL. No corrupt-as-empty read: a
  record that does not parse is reported to the core as damaged, never dropped.

### 3.4 Capture point — forced by there being no PostToolUse hook

**Measured fact.** No enforcement adapter registers a post-tool completion hook.
`src/setup/settings-hooks.ts` registers `PreToolUse`, `SessionStart`, `UserPromptSubmit`,
`PreCompact` by default; OpenClaw registers `before_tool_call` plus `session_end`, `agent_end`,
`llm_input`, `llm_output`, `before_agent_run`, but no `after_tool_call`; Hermes registers
`pre_tool_call` only. So recording happens at the pre-gate of the write/compile call, and the
record is **intent**. Completion is reconciled later, at the exec that matters, by Rule P's
content-identity comparison — not by any completion observation, which no adapter has.

**One canonicaliser for record and query.** `canonicalTarget(token, cwd, home)` in the pure core
(with an injected `realpath`) is the only function that turns a path token into the string
`pathHash` is computed over. Capture (write targets, compile `-o` operands) and query (exec and
loader targets) both call it; there is no second resolver. Rules:

- a token that is empty, contains NUL, or exceeds 4096 chars is **unresolvable**;
- `~/` is expanded against `home`; an absolute token is kept; a relative token is resolved
  against `cwd` **only** if `cwd` is a nonempty absolute string without NUL and at most 4096
  chars — otherwise the token is **unresolvable**. There is deliberately **no** `process.cwd()`
  fallback (unlike the hook's `scriptResolutionBase`, `pre-tool-hook.mjs:547-551`, and OpenClaw's
  `createScriptSourceResolver`, `interceptor.ts:1484-1490`): a guessed base would give record and
  query different hashes;
- the result is lexically normalised; the longest existing ancestor of the parent directory is
  `realpath`ed and the remaining components appended; the basename is kept (so a symlinked
  final component is what the header read sees). A `realpath` failure other than not-found is
  **unresolvable**.

At capture, an unresolvable path argument publishes an `unresolved.*` record (history incomplete
for the session). A write-family call with **no** path argument (`extractPath`,
`tool-action-guard.ts:482`, returns empty — e.g. an MCP `create_issue`) is not a file write and
records nothing. At query, an unresolvable exec/loader token is not classified: current
behaviour, the same residual as a bare name (§10).

Capture rules:

- **Any write-family tool call** (`WRITE_TOOLS`, `tool-action-guard.ts:133`) with a path
  argument → `canonicalTarget` it, stat it for `preId` (§5 contract), then publish an
  `agent-written` record, **regardless of extension, content or location**. The
  native-vs-source distinction is made at exec by the header read; whether the call changed the
  bytes is decided at exec by Rule P. The old `isScriptLikeWritePath` /
  `writeContentLooksExecutable` predicates (script suffix / shebang only) are not used for this.
- **A recognised compiler with a literal, resolvable output.** Supported output-resolution
  contract, and nothing wider: the program position's `commandBaseName` (read with
  `detectScriptInvocations` / `tokeniseStatement` / `commandBaseName`, no new regex family) is
  exactly one of `cc`, `gcc`, `g++`, `c++`, `clang`, `clang++`, `nvcc`, `ghc`, `rustc`, **and** the
  statement carries a literal `-o <path>` / `-o<path>` operand that `canonicalTarget` resolves →
  publish `compiled-output` for that path with its `preId`. `go build` and `zig cc` are **not**
  supported: `commandBaseName` (`tool-action-guard.ts:4864-4866`) yields one segment (`go`,
  `zig`), and PR 1 adds no subcommand matching; their outputs are unsupported-output below. This
  is not a command-name exemption: nothing is allowed by name; the name only says where to look
  for the output operand.
- **Unsupported output — honest result.** A compiler with no literal `-o` (`cc foo.c` → `a.out`),
  `go build`, `zig cc`, and every build driver (`make`, `cmake`, `ninja`, `node-gyp`, `cargo`,
  `go test`, `go run`, `npm run build`, `pip install`), records **nothing**: PR 1 cannot name
  their output path. The
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
   an exec of its output, in one Bash call): the pre-gate runs before the call does. If the target
   is **initially absent** there is no header to read. If it **already exists**, the pre-gate
   classifies the **old** file — its old header against its existing history — and that verdict
   applies to the whole call before the replacement runs.

The verdict each actually gets is in §10. In short, for a path with **no surviving record** in
the session: if the file is created at a non-install path and a **later, separate** call execs it
as a native image, it is row J; if it is created inside an install root, or created and execed in
one call with the target initially absent, it keeps **current behaviour (allow)**. Where an older
record for the path survives, Rule P may attribute the change to it (§10).

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
| F | Installed tool (`git`, `node`, `python`, system `cc`) — native image at an install root, no producer, history complete | 2 | **no new gate; current behaviour** | non-false-positive in the issue; relief by Rule H, not by absence |
| G | `node_modules/.bin/<tool>` (the only package-tree arm `INSTALLED_BIN_DIR_RE` has) — native, no producer, history complete | 2 | **no new gate; current behaviour** | a wheel entry point or `.venv/bin` tool is **not** in the regex: if native it is state 3 (row J); if a script it is outside the classifier |
| H | Interpreter running an existing script | outside the classifier (the script is not a native image) | **current behaviour** | an interpreted script is not a native artifact; only row D's body match can apply to it. Installed-interpreter location says nothing about the script's provenance |
| I | Build tool writes a declared build output, run from the user/cli band | band-attested (Q2/Q3) | **no new gate; current behaviour** | row E generalised — subject to Q2/Q3 |
| J | State 3 (§3.1 table): no producer at a non-install path; incomplete history; non-unique candidate; unknown current identity; no session key. Also a recognised write-family or supported-compile call whose record cannot be published (§3.1 "Publication") | 3 / `unclassified-executable` | **HOLD (door)** | ADR-002 §2.4 fail-closed rule for an executable effect of unknown provenance |

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
complete history; non-native targets (scripts, data files) except where row D matches an
inspected body; outer build-driver invocations; a supported compile followed by an exec of its
output under Q1 = AUDIT, when Rule P names it uniquely.

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
- **Incomplete history holds what it would otherwise relieve.** A session that reaches the record
  cap (4096), or records an `unresolved.*` target (e.g. a relative write path on an OpenClaw call
  with no usable cwd), holds every later resolved native exec in that session at row J —
  including a spelt install-root path such as `node_modules/.bin/<tool>`. A failed or
  ambiguous chain (failed write then compile to the same path) is row J rather than row B.
- **A broken store holds writes.** With a session key but an unwritable store, every recognised
  write-family or supported-compile call with a path is held (row J). That is a loud failure
  mode, not routine work, and it is the price of never letting a call through unrecorded.

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
      listing of this call's `sessionKey` record directory as the store read it — each entry's
      name and either its parsed body or a `damaged` marker, plus a `listable` flag — or `null`
      when there is no key. The core applies the §3.1 complete-history test to it; the caller
      never pre-filters damaged entries out. The pure evaluator never derives a key and never
      receives one; a key asserted in content cannot reach it.
    - `statPath?: (absPath) => ContentId | 'absent' | null` — `'absent'` **only** when `lstat`
      of the final component fails with not-found (`ENOENT`/`ENOTDIR`); `null` for every other
      failure (`EACCES`, `EIO`, `ELOOP`, …). An I/O error is never reported as absent.
    - `readFileHeader?: (absPath) => Uint8Array | null`.
    - `cwd?: string` — the call's raw working directory, **unvalidated**; `canonicalTarget`
      (§3.4) validates it. Hook: the payload `cwd`, passed without the `process.cwd()` fallback.
      OpenClaw: `toolCallCwd(context)` (`interceptor.ts:1581-1588`), which returns the first
      nonempty string or `undefined` and applies no absolute/NUL/length check of its own.
  - **Capture-side stat:** a `preId` from `statPath` is a `ContentId` or `'absent'`; `null` is
    recorded as `'unknown'`, which makes history incomplete for that path (§3.1 item 4). The
    record is still published, so the call is not lost.
  - **Canonicalisation:** `canonicalTarget` (§3.4), the same function the capture side uses. A
    program-position or loader-target token containing `/` or starting `~/` is resolved; **bare
    names are not resolved through PATH** in PR 1 — a bare-name exec of a planted binary is a §10
    residual.
  - **Missing-input precedence:** if `artifactView` is `undefined` (an adapter that does not
    wire it — Hermes API in PR 1, any older caller), or `statPath` / `readFileHeader` is
    `undefined`, the native classifier **does not run** and the call keeps today's behaviour;
    this is adapter non-coverage, recorded in §6/§9, not an allow claim. If `artifactView` is
    `null` (no session key) history is never complete → state 3 for every native image. For the
    resolved target: `readFileHeader` → `null` is step 0 only when history is complete for the
    path and holds no record for it (otherwise state 3); a native header with `statPath` → `null` is state 3 (current
    identity unknown); `statPath` → `'absent'` at exec is step 0 (nothing to execute).
  - new classifier `classifyNativeExec(execSurface, view, statPath, readFileHeader, cwd)` built on
    `detectScriptInvocations` / `tokeniseStatement` / `commandBaseName` / `EXEC_WRAPPER` /
    `SCRIPT_INTERPRETER` / `isInstalledBinaryPath` and the existing body-fold regions — no new
    regex family.
  - wire into `evaluateToolCall`: A/C/D on the terminal branch (block, terminal severity —
    **not** added to `GUARD_SELF_PROTECTION_SIGNALS`); J on `require_approval`; B at Q1's tier.
- `scripts/pre-tool-hook.mjs`:
  - at the write/compile pre-gate, canonicalise and stat the target and publish a record keyed
    by `baseExtra.sessionKey`, holding the call (row J) if publication fails; when
    `namedIdentityUnresolved` **or** the key is absent, record nothing and hold nothing (every
    native exec in that session is state 3);
  - build `artifactView` for this call's key and inject it with `statPath`, `readFileHeader`
    and `cwd` into the 4th `evaluateToolCall` argument beside `resolveScriptSource`;
  - add the signal names to `SAFE_SIGNALS`;
  - **non-widenable floor vs widenable door.** Floor rows exit at the
    `TERMINAL_BLOCK_SEVERITIES` branch (`:3307`) before the `autoApprove`, shadow and
    `enforce:false` advisory widenings. Row J (and a call held for an unpublishable record) is an
    ordinary `require_approval` and **is** widenable: on an advisory, shadow or
    standing-`autoApprove` host it warns or auto-approves, and the complete-history guarantee
    does not hold there (§10).
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
  home, covering write → exec (A), failed-write → exec (Rule P), install-root write → exec
  (Rule H), and producing write → four `chmod` calls → exec (no window). The
  `guard-effect-fixtures` simulation does not discharge this.

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

**Rule P / complete-history controls** (each states its initial state; "no prior record" means
the session holds no record for the path before the control's first call):

- failed write against an existing native file, no prior record (simulated by recording, then
  not changing the file) → exec → **row J** at a non-install path, **current behaviour** at an
  install root — never DENY;
- `chmod +x` (write-family) of an existing native file, no prior record → same as above;
- direct write of native bytes, then a supported compile to the same path that does not change the
  file → exec → **DENY** (compile record unproved; write record is producer);
- supported compile that does change the file, no prior record → exec → **row B**;
- failed write against an existing file, then a supported compile that changes it (same `preId`,
  different kinds) → exec → **row J**, not DENY, not row B;
- **window exhaustion** — a write-family call **creates** a native file, then four or more
  write-family calls to the same path that do not change its identity (`chmod`/`chown`, and
  separately failed writes) → exec → **DENY**, at a non-install path **and** inside
  `~/.local/bin` (test-pinned home) — never state 2;
- write-family call creating a native file inside `~/.local/bin` → exec → **DENY**;
- **retained-old-plus-lost-new** — an older record survives and the newer record for the same
  path is (i) made unreadable, (ii) truncated to an unparseable body, (iii) left as a `.tmp`
  entry → exec → **row J** in each case, never DENY and never row B; (iv) never published because
  the store was made unwritable → the newer **call** is **row J** (held), so its bytes never land
  unrecorded;
- record directory at the cap with an older producing record retained, then a further write to
  the same path (unrecorded) → exec → **row J**, at a non-install path and at an install root;
- `unresolved.*` record present → install-root native with no producer → **row J**;
- record directory unlistable at exec → install-root native with no producer → **row J**;
- capture-side `statPath` → `null` (`preId` `'unknown'`) → exec of that path → **row J**;
- record and query spell the same file differently (relative vs absolute, `~/`, a symlinked
  parent) → one `pathHash` → same verdict as the plain spelling;
- relative write target with no usable cwd → `unresolved.*` record, not `process.cwd()`;
- unresolved or absent session id → native exec, non-install **and** install root → **row J**;
  writes are not held;
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
- a **supported** compile (`cc x.c -o x`, output path initially absent, no prior record) then a
  separate exec → **row B**, never floor.

---

## 9. What PR 1 delivers against each #907 acceptance criterion

| #907 acceptance | met by PR 1? |
|---|---|
| Fixture: agent writes+runs a compiled binary → denied, plain reason | **Yes on Claude Code hook and OpenClaw.** Hermes: **No** in PR 1 (API-up is PR 2; outage never) |
| Fixture: compile-then-run across two calls → **denied** | **No.** Row B at Q1's verdict (AUDIT recommended). Not met by design |
| Fixture: LD_PRELOAD of a just-written library → denied | **Yes on Claude Code hook and OpenClaw.** Hermes: **No** in PR 1 |
| Fixture: Python mapping executable memory → denied | **Yes on Claude Code hook and OpenClaw** (inline and folded file body, within scan caps). Hermes: **inline body only** (API-up and outage, outage within 4096 chars); write-then-run file body **not met** on Hermes |
| No false positives on installed/pre-existing tools | **Partly.** Met for installed tools at install roots with complete history and outer build-driver invocations: neither hits the floor or the door. Non-native targets are outside the A/C/B/J classifier, but row D's body match still applies to an inspected script body, and that benign surface is unmeasured (§4.2). **Not met** for pre-existing **project-local** native binaries and build-driver outputs (held at row J), nor for any resolved native exec in a session whose history is incomplete (§4.2). Not a measured production rate |
| Doctor reports the shared-host risk | **No — separate PR 3** |

So PR 1 meets the three directly-written DENY fixtures **on the Claude Code hook and OpenClaw
only**, with Hermes limited to inline row D. Rows A and C are met **when session history is
complete for the path** (§3.1); with incomplete or ambiguous history the same fixtures are held at
row J instead — door, not floor, and not allow. It does not meet compile-then-run → denied, the
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

- **Unrecorded exec-surface creators (§3.4 items 1–4)** — observation limit. With **no surviving
  record** for the path: created at a non-install path and execed by a later separate call →
  **row J**; created **inside an install root** → state 2 → **current behaviour (allow)** — the
  complete-history test covers recognised write-family and compile calls only. With a surviving
  record, see "Unrecorded writer after a recorded intent".
- **Same-command write-and-exec** (redirect-then-exec or compile-then-exec in one Bash call) —
  observation limit. With the target **initially absent** and no other matching row: no header,
  no producer → **current behaviour (allow)** (today's opaque-script audit at the sensitive
  tier); nothing is held. With the target **already present**, the pre-gate classifies the old
  file against its history, and that verdict (A/C DENY, B, J, or current behaviour) applies to
  the whole call before the replacement runs. Row D catches it only when an exec-memory shape is
  in the inspected inline body.
- **Unrecorded writer after a recorded intent** — classification limit of Rule P. A failed
  recorded write followed by an unrecorded write of native bytes → attributed to the record →
  **DENY** (bytes are still agent-delivered). A failed supported compile followed by an
  unrecorded native write → attributed to the compile → **row B (Q1 verdict)**, i.e. a
  directly-written binary can escape the floor this way. Not benign over-gating.
- **Held call released unrecorded** — a call held because its record could not be published
  proceeds unrecorded if a human approves it, or if an advisory/shadow/`autoApprove` host widens
  the hold. History is then incomplete without the guard knowing: a later exec at that path may
  be state 2 (allow) at an install root, or attributed to an older surviving record (A/C DENY or
  row B). The approval or the widening posture is the authority.
- **Parallel calls to one path with different `preId`s** — Rule P orders records by pre-gate
  time; the uniqueness test catches two intents against the **same** identity, not interleavings
  where a stale-`preId` call lands after a newer one. Misattribution between `agent-written` and
  `compiled-output` is possible in that interleaving (an agent issuing a write and a compile to
  the same output path in parallel). Not observed in routine work; unmeasured.
- **Same-UID `ContentId` forgery** (restoring `mtime`/`size` after a write) can make a producing
  write look unproved → **row J** at a non-install path, **allow** at an install root.
- **Unsupported build outputs** — by design (§3.4): a later separate exec → **row J (HOLD)**;
  same-call or child exec → **allow**.
- **Build-recipe / package-lifecycle / native-loader child exec** not seen as a tool call —
  ADR-002's outer-gate limitation → **allow**.
- **Loads inside an inspected-only-by-name program** (a `require` inside a test runner, an
  import of an extension) are not resolved as load targets → **allow**.
- **Bare-name PATH exec** is not resolved in PR 1 → **allow** (current behaviour). Likewise a
  relative exec/loader token when the call has no usable cwd (`canonicalTarget` refuses it,
  §3.4) → **allow**.
- **Cross-session / TTL** — a native file written into an install root in session S1 and execed in
  S2, or after S1's directory expired, has no record in the executing session → **allow**.
- **Row D bounded inspection** — a body beyond `MAX_SCRIPT_BYTES`/`MAX_FOLDED_BYTES`, NUL-bearing,
  or unresolved is folded as **opaque** (`tool-action-guard.ts:5118-5119`) → **allow** at the
  sensitive tier (`:7318-7325`), not fail-closed. On Hermes, a body outside the fallback surface
  or beyond 4096 chars is unmatched → **allow** (`policy.py:77`).
- **Compile-to-native is row B, not the floor (Q1)** — it carries the harmful effect the floor
  seeks to reduce; the accepted M1 trade.
- **Same-UID evasion** — direct mutation or deletion of individual record files (which can leave
  an older record to be read as the producer), hard-link aliases, file
  replacement after inspection, symlink/rename/second-interpreter indirection — the same residual
  the self-protection floor documents.
- **Scope honesty (issue "Context").** This narrows the "agent-authored native code reaches the
  CPU" path. It does **not** stop hardware flaws and does not isolate a shared CPU. The doctor
  warning (PR 3) and egress tightening (PR 4) are the complementary, separate controls.

---

## 11. PR ordering summary

1. **PR 1** — effect class + floor DENY (A/C/D) + ledger (pure core, create-once record store,
   one canonicaliser, complete-history test, Rule P, Rule H, total classifier, Claude hook +
   OpenClaw wiring) + door (J) + row B at Q1's verdict + Hermes
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
