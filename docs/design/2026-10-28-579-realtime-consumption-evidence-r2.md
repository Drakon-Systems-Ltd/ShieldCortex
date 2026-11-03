# #579 — Durable realtime consumption evidence, round 2 (design proposal, not approved implementation)

**Status:** design proposal for independent review. The proposed feature is not implemented or approved; the future executable plan is unrun. Separate bounded design-model checks are recorded below. It authorises no code change, no retention, no compression, no deletion, no archive and no database rebuild, migration or modification. **Disk reclaimed by this design: zero bytes.** #579 stays open.

**Base:** `main` at `cbe011ef9cecb3f27babf638ef156fc5bcb450a9` (28 Oct 2026). Every line citation below is to that commit. Source reading only; see §10 for what was not run.

**Lineage.** Slice 1A (strict cursor, hold at an unreadable listed file) merged as #741/#742 and is unchanged here. The round-1 Slice 1B design (12 Oct 2026, at `d28ab590`) received two independent CHANGES REQUESTED verdicts. The earlier discarded candidate (compress in place, delete by age) stays discarded and is not revived. This round answers every finding from both reviews and re-derives the design from current `main`.

---

## 0. One-paragraph summary

The realtime ledger (`src/threat-graph/realtime-ledger.ts`) is the only reader that advances a cursor over `~/.shieldcortex/audit/realtime-YYYY-MM-DD.jsonl`. This design adds one observation table, `realtime_file_evidence`, inserted/upserted **only inside the ledger's existing apply transaction** (initialization may invalidate imported rows before collection), recording for each file the SHA-256 of the exact byte prefix whose lines the ledger decided, the `(dev, ino)` of the descriptor those bytes came through, the directory identity it was listed from, and sticky non-affirmative states for oversize, held, changed, replaced and unverifiable files. Evidence is bound to the current graph generation by SQLite triggers that fire for any code version, and to the current **database incarnation** by a stamp that dump recovery inherently resets (`PRAGMA user_version`, which `.dump` does not carry; observed in §5.2). The read path keeps today's **stat-before-open** oversize decision so the floor policy is unchanged. Nothing reads the table in production. The one affirmative state means only "the ledger committed decisions for exactly these bytes, in this graph generation and database incarnation". It is **not** cleanup permission, and it says nothing about stop-hook recovery evidence, other readers, writers still holding descriptors, or days that are no longer on disk.

---

## 1. Findings from round 1 and how this round answers them

| Finding (reviewer) | Round-2 answer | Section |
|---|---|---|
| Open-before-size turns a stat-able, unreadable oversize file from a floor into a hold (Grok B1, Astra F2) | Follow-`stat` preflight kept exactly as today; oversize decided before any `open`; oversize rows carry NULL identity | §5.3 |
| Recompute can promote an unidentified file; `empty_observed` falls through (Grok B2) | First-match precedence; recompute unreachable unless identity, directory and prefix checks all passed; `empty_observed` is not resumable | §5.5 |
| Directory sample missing on batch-cut and hold commit paths; `ino` coerced through Number (Grok R1) | Second sample taken on every return that can commit, `bigint` → decimal text; missing or different sample ⇒ no evidence rows | §5.4 |
| Short read, `EAGAIN`, non-regular file treated as EOF (Grok R2, Astra N2) | Bounded read loop; `EINTR` retried; any other error ⇒ `unavailable` hold; non-regular ⇒ hold; growth past the cap during the read ⇒ decision point D1 | §5.3 |
| Resume-row recheck needs a column list and must not abort fresh reads (Grok R2) | Exact column list; recheck only when `startLine > 0` | §5.6 |
| Dump-recovery invalidation is neither legacy-safe nor crash-complete (Astra F1) | Evidence incarnation stamp in `user_version`; rows carry it; zero header ⇒ UNKNOWN, followed by mandatory atomic invalidation before initialization; covers pre-1B recovery and interruption without a recovery post-step | §5.2 |
| Verifier claims exceed its inputs (Astra N1, Grok "defer verify") | 1B-verify removed from the implementable slice; contract for a future classifier written down as spec only | §5.10 |
| "At most 64 MB" not enforced (Astra N2) | Stated honestly; bounded-read decision D1 | §5.3, §8 |
| Directory endpoint equality is not a pin (Astra N3) | Wording changed to "endpoint observation"; prefix check also binds `dir_dev/dir_ino` | §5.4, §5.5 |
| "Consumed" vs "decided" wording; "no reader" overstated (Astra N4) | Vocabulary fixed in §3; degraded rows described as having no durable recovery reader | §3 |
| `nlink > 1` not in identity (Grok residual) | Folded into `identityOk` | §5.3 |
| Migration must guard an absent `threat_graph_state`; keep trigger DDL out of the broad reconcile block (Astra) | Own guarded block; canonical schema creates triggers after the table | §5.1 |
| `guard-readiness.ts` third `appendRow` caller (Grok) | Noted in the writer inventory | §2.3 |

---

## 2. Source map at `cbe011ef`

### 2.1 Ledger and projector

| Fact | Citation |
|---|---|
| Plain grammar, consumed-file sentinel, strict cursor classifier | `src/threat-graph/realtime-plane.ts:24`, `:27`, `:42-54` |
| Filesystem seam `readdir/stat/readFile` (path-based, follows symlinks, utf-8 string) | `realtime-plane.ts:57-67` |
| `readPlainRealtimeFile`: follow-`stat` → oversize without opening → `readFileSync` → typed `unavailable` | `realtime-plane.ts:83-102` (stat `:91-95`, oversize `:96`, read `:97-101`) |
| Collector: `readdir` failure silent; pre-cursor names skipped; sentinel skip; oversize floor + continue; unavailable → hold + return; tail excluded; batch cut | `realtime-ledger.ts:118-165` (`:129-132`, `:137`, `:139`, `:142-146`, `:147-153`, `:155-158`, `:161`) |
| Barrier check (hold at D ⇒ nothing at or after D commits) | `realtime-ledger.ts:177-183`, `:224-227` |
| State row `INSERT OR IGNORE`; raw cursor read; malformed halt before listing | `realtime-ledger.ts:202-204`, `:209-212` |
| No pending and no floor → early return, **no transaction** | `realtime-ledger.ts:223` |
| Apply: raw compare-and-set; per-line decisions; `rt:<file>:<line>` node identity; eviction; floor outranks position; cursor write; `BEGIN IMMEDIATE` | `realtime-ledger.ts:230-304` (`:233-235`, `:241-257`, `:264`, `:295-296`, `:299-301`, `:302`, `:304`) |
| Realtime dir honours `SHIELDCORTEX_AUDIT_DIR` untrimmed | `src/threat-graph/shared.ts:64-67` |
| `PROJECTOR_VERSION = 6` | `src/threat-graph/projector.ts:85` |
| `clearGraph`: deletes edges/nodes/source_risk, resets `last_rt_cursor = ''`, stamps version, one `immediate` transaction | `projector.ts:493-510` |
| Rebuild: snapshot → `clearGraph` → audit replay → realtime loop until `processed === 0` | `projector.ts:517-578` (`:541`, `:573-578`) |
| Lease: version mismatch → `clearGraph`; one realtime call per run | `projector.ts:689-699`, `:716-718` |
| Only production writers of `last_rt_cursor` | `realtime-ledger.ts:302`, `projector.ts:506` |

### 2.2 Database initialisation paths that must agree

| Path | Citation | Effect on a new table/trigger |
|---|---|---|
| Fresh DB: `runMigrations` returns early (no `memories` table), then canonical schema | `src/database/migrations.ts:79-86`; `src/database/init.ts:1206-1209` | created by schema |
| Upgraded DB: migrations, then canonical schema (`IF NOT EXISTS`) on every open | `init.ts:1206-1209` | created by schema; guarded migration is belt-and-braces |
| Bundled/inline fallback when `schema.sql` is absent | `init.ts:956-967`; `src/database/inline-schema.ts:227` (state table) | must mirror DDL exactly |
| Dump recovery (startup path, and `repairDatabase` only after its `REINDEX`/`VACUUM` recheck still fails) | `init.ts:781-812`; callers `:1099-1101`, `:1371-1381` (the `repairDatabase` dump branch starts at `:1371`; the successful in-place return at `:1353` is not dump recovery, see N15) | rows reimported from a possibly partial DB; `.dump` emits data before triggers (§5.2) |
| Backup restore (file copy) | `init.ts:238-240` (`copyFileSync`) | header preserved (§5.2) |
| Repair "recreated" / fresh | `init.ts:1383-1399` | empty table |
| Read-only inspection opens | `init.ts:160-163` | never create, never write |
| Existing note that a `.dump`-restored database keeps tables but not `user_version` | `migrations.ts:1058-1059` | the property §5.2 relies on |

### 2.3 Production realtime writers (none fsync; none coordinate)

Unchanged from the round-1 inventory at the same paths: OpenClaw plugin `auditLog` and its bundled twin, OpenClaw interceptor and its bundled twin, `scripts/pre-tool-hook.mjs` (no-follow append, `nlink` check), `scripts/stop-hook.mjs` summary append (`:397-399`), `src/defence/iron-dome/session-guard.ts`, `guard-readiness.ts` (`appendRow` has three callers, not two), Hermes `plugins/hermes/shieldcortex/__init__.py` (Python text append, fixed `~`). Directory resolution differs between writers (trimmed override, untrimmed override, config dir, fixed home). **Consequence:** evidence must be bound to the directory the ledger actually listed, never to a bare filename.

### 2.4 Production realtime readers

Only the ledger advances a cursor. The others are reader-visible horizons that ledger evidence says nothing about: stop-hook collection (`scripts/stop-hook.mjs:523-536`, `O_NOFOLLOW`, `nlink` check; the per-session index is explicitly best-effort, `:653`), `/api/v1/intercepts` (`src/api/routes/admin.ts:166`, last 14 files), sessions route (`src/api/routes/memories.ts:202`), OpenClaw self-check (`src/setup/openclaw-selfcheck.ts:695`, loose name match, newest two), guard-readiness evidence (`guard-readiness.ts:793`, date window, up to three directories).

---

## 3. Vocabulary (fixes round-1 ambiguity)

- **Decided** — the ledger iterated a 0x0A-terminated line inside its apply transaction and took one of three decisions: project (`type:"threat"`), ignore (any other type), or record-and-skip (malformed JSON). `realtime-ledger.ts:237-257`.
- **Consumed (status)** — every line in `bytes[0, covered_bytes)` was decided and `covered_bytes == observed_bytes > 0` with no unterminated tail and no batch cut. A status name, defined in §5.5; nothing more.
- **Projected** — a threat row became an `rt:` event node. Projected nodes can later be **evicted** (`shared.ts:180`). Consumption is not graph retention.
- **Preserved** — kept somewhere a reader can recover it from. The ledger preserves nothing it ignores. Guard outcomes, summaries, fingerprints and degraded intercept rows are **decided and ignored** by the ledger; the only durable recovery reader for guard outcomes is the stop hook over plain files plus a best-effort index. `/api/v1/intercepts` can display degraded rows inside its 14-file window, so "no reader" is wrong; "no durable recovery reader" is right.
- **UNKNOWN** — absence of an affirmative row, or any non-affirmative status, or an incarnation/generation mismatch. UNKNOWN always means preserve.

---

## 4. Safety invariants (each has executable tests in §7)

- **I1 Never false-affirmative.** No row reaches `consumed` for a file that is unconsumed, partially read, oversize-skipped, held, changed in place, replaced, symlinked, multi-linked, non-regular, read through a descriptor that does not match the listed name, or resumed from a prefix the evidence did not itself re-hash.
- **I2 Projection-neutral.** With the feature present, nodes, edges, cursor, floors, holds, halts, tail exclusion and error strings are byte-identical to today for every regular-file fixture. The only permitted projection change is the non-regular hold (§5.3) and, if D1 is accepted, a file that grows past the cap *during* the read.
- **I3 Transaction coupling.** Evidence inserts/upserts commit in the same `BEGIN IMMEDIATE` as the cursor write, after the raw compare-and-set; a failed CAS, a failed resume-row recheck, or a thrown apply writes no evidence. Earlier initialization invalidation (§5.2) is separate and is not rolled back by an apply failure.
- **I4 Generation binding.** Any reset of the graph (`clearGraph` from any code version, hand-run `UPDATE ... last_rt_cursor = ''`, loss or recreation of the state row) deletes all evidence atomically with the reset.
- **I5 Incarnation binding.** Evidence written in one database incarnation is never trusted in another. Dump recovery (new or pre-1B code), interrupted recovery, and a fresh file all start a new incarnation. A consistent backup snapshot copied byte-for-byte preserves logical graph/cursor/evidence continuity; arbitrary copies are not certified. In-place REINDEX/VACUUM preserves continuity, not proof of completeness after corruption (§5.9).
- **I6 Stat-before-open.** The oversize decision is taken from the following `stat` exactly as today, before any `open`; a stat-able, unopenable oversize file floors and never holds; a within-cap file whose open or read fails holds exactly as today (stage `read`).
- **I7 Directory binding.** Rows are written only when the directory identity sampled before listing equals the identity sampled on the committing return path; both stored as decimal text from `bigint` stats; the prefix check compares them too.
- **I8 Skip evidence persists.** Oversize files get a sticky `skipped_oversize` row in the run that commits the floor (a floor always commits, `:223`); a held file never gains an affirmative row and, when earlier progress commits, gets a sticky `held` row if it has none; absence of a row is UNKNOWN. No stored state ever promotes a skipped or held file.

---

## 5. Specification

### 5.1 Schema

Identical DDL in `src/database/schema.sql` (after `threat_graph_state`, `:292-305`), `src/database/inline-schema.ts` (after the state table, `:227`), and as an idempotent guarded block in `runMigrations` placed **outside** the broad reconcile block at `migrations.ts:895-925` so a missing `threat_graph_state` cannot abort unrelated reconciliation. The migration block runs only when `threat_graph_state` exists; on databases where it does not, the canonical schema creates the table and then the triggers.

```sql
-- #579: per-file realtime ledger consumption evidence. OBSERVATION ONLY.
-- Never cleanup permission. Cleared by triggers on every graph reset, and
-- untrusted (then purged) whenever `incarnation` differs from the database's
-- evidence incarnation (PRAGMA user_version; see realtime-ledger.ts).
CREATE TABLE IF NOT EXISTS realtime_file_evidence (
  name TEXT PRIMARY KEY
    CHECK (name GLOB 'realtime-[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9].jsonl'),
  incarnation INTEGER NOT NULL,                 -- PRAGMA user_version at commit
  status TEXT NOT NULL CHECK (status IN (
    'consumed','partial','empty_observed',
    'skipped_oversize','held','changed','unverified_prefix','unverified_identity')),
  dir_dev TEXT, dir_ino TEXT,                   -- stat(dir, bigint) as decimal text
  dev TEXT, ino TEXT,                           -- fstat(fd, bigint) as decimal text
  observed_bytes INTEGER NOT NULL DEFAULT 0,    -- bytes read, or stat size when oversize
  covered_lines INTEGER NOT NULL DEFAULT 0,     -- last committed line of this file
  covered_bytes INTEGER NOT NULL DEFAULT 0,     -- offset just past that line's 0x0A
  covered_sha256 TEXT,                          -- sha256(bytes[0, covered_bytes)); NULL unless consumed/partial
  malformed_lines INTEGER NOT NULL DEFAULT 0,
  projector_version INTEGER NOT NULL,
  observed_at TEXT NOT NULL,
  CHECK (status NOT IN ('consumed','partial')
         OR (dev IS NOT NULL AND ino IS NOT NULL AND dir_dev IS NOT NULL
             AND dir_ino IS NOT NULL AND covered_sha256 IS NOT NULL))
);
CREATE TRIGGER IF NOT EXISTS rt_evidence_clear_on_reset
  AFTER UPDATE OF last_rt_cursor ON threat_graph_state WHEN NEW.last_rt_cursor = ''
  BEGIN DELETE FROM realtime_file_evidence; END;
CREATE TRIGGER IF NOT EXISTS rt_evidence_clear_on_state_insert
  AFTER INSERT ON threat_graph_state
  BEGIN DELETE FROM realtime_file_evidence; END;
CREATE TRIGGER IF NOT EXISTS rt_evidence_clear_on_state_delete
  AFTER DELETE ON threat_graph_state
  BEGIN DELETE FROM realtime_file_evidence; END;
```

Changes from round 1: identity columns are nullable so a non-affirmative row never requires an `open` (I6); the table-level CHECK makes the affirmative statuses the only ones that demand full identity (I1); `incarnation` and `held` are new. `CREATE TRIGGER IF NOT EXISTS` does not repair a drifted trigger, so the three DDL copies must be the same statement text; §7 S3 pins that.

Why triggers rather than a delete in `clearGraph` alone: an older installed build, or hand-run SQL, resets the cursor without knowing the table exists. The ledger never writes `''`, so `WHEN NEW.last_rt_cursor = ''` matches only resets. New-code `clearGraph` may add an explicit `DELETE` in its transaction (redundant; documents intent). `INSERT OR IGNORE` on an existing state row (`realtime-ledger.ts:202`, `projector.ts:149`) does not fire the insert trigger, so normal ticks do not clear evidence.

### 5.2 Evidence incarnation (answers Astra F1)

**Problem.** A dump-recovered database can carry evidence rows and a state row from a partially recovered graph. In new code a `DELETE` after `freshDb.exec(dumpOutput)` is a separate step that a crash can skip, and a **pre-1B build** performing the recovery has no such step at all. The triggers do not help: `.dump` emits each table's `INSERT`s before any `CREATE TRIGGER` and wraps the whole import in one transaction, so no trigger fires during import. Observed on this host with SQLite 3.45.1 against an in-memory fixture: `CREATE TABLE s …; INSERT INTO s …; CREATE TABLE e …; INSERT INTO e …; CREATE TRIGGER t …; COMMIT;`.

**Mechanism.** Use a header reset that recovery performs by construction, plus mandatory atomic invalidation at evidence-aware initialization; never rely on an optional recovery post-step. `sqlite3 .dump` emits schema and data only; it does **not** emit `PRAGMA user_version` (observed on this host: a database with `user_version = 12345` dumps with only `PRAGMA foreign_keys=OFF;`). The repository already relies on this (`migrations.ts:1058-1059`: "a `.dump`-restored database keeps tables, not `user_version`"). Nothing in `src/`, `scripts/` or the OpenClaw plugin sets `user_version` or `application_id` today (grep at `cbe011ef`). So:

1. **Reservation and timing.** Reserve `PRAGMA user_version` for evidence. Fresh initialization leaves it zero until the first ledger **run**, not the first apply commit. At each run's start, after `assertNotInTransaction` and before evidence use or listing, call `ensureEvidenceIncarnation(db)`. Initialization is separate from apply; a no-progress run can initialize. Read-only classifiers never initialize.
2. **Deterministic initialization boundary.** Under one `BEGIN IMMEDIATE`, read the header. At zero, unconditionally `DELETE FROM realtime_file_evidence` **before** setting `PRAGMA user_version = 1`, then commit both together. §5.1 must have created the table first. Failure of either operation rolls back and stops the run before collection/apply; never continue with a usable header. Valid non-zero positive signed-31-bit markers remain unchanged; invalid/unreadable markers fail closed. Racing initializers serialize: the second sees the committed marker and does not clear newly written evidence. No randomness or globally unique identifier is claimed. Reusing marker 1, even if imported rows carry 1, is safe because no imported row survives the transaction making the header usable. Never cache evidence across initialization; collect snapshots afterwards.
3. **Stamping.** Every evidence upsert carries the run's marker. Apply re-reads the header; a different value aborts before projection/evidence writes, like a failed CAS. Marker equality alone is not global identity proof: safety also requires rule 2. Live file replacement/concurrent restore is unsupported, not certified by this protocol.
4. **Trust rule.** Prefix checks and future affirmative classification require a valid **non-zero** current header and `row.incarnation == current user_version`. At zero every row is UNKNOWN, including an imported row stamped zero. Read-only classifiers return UNKNOWN without initialization. Mismatched rows are UNKNOWN.
5. **Mismatch hygiene.** Each committing apply, after cursor write, deletes rows whose incarnation differs from the marker. This is hygiene, distinct from mandatory rule 2. Present wrong-incarnation rows are not treated as absent before apply: P5 (or earlier sticky precedence) still applies.

**Lifecycle table (contract; implementation not run).**

| Event | Header | Old rows |
|---|---|---|
| Fresh database | zero → 1 on first ledger run | none |
| Ordinary reopen, restart, WAL checkpoint | unchanged | same-incarnation eligibility only |
| Consistent backup snapshot restored by file copy | copied with snapshot | continuity preserved; arbitrary/concurrent copies not certified |
| Completed new-code dump recovery | new file zero → 1 on first ledger run | UNKNOWN at zero; all deleted before initialization commits |
| New-code recovery interrupted after import | already zero | same; no recovery post-step required |
| Pre-1B dump recovery, including interruption after import | already zero | same on first evidence-aware run, even if older code advanced cursor |
| Recreation/fresh create | zero, empty table | none |
| In-place REINDEX/VACUUM repair | unchanged | continuity preserved, not proof of completeness after corruption (§5.9) |
| Graph reset by any build | unchanged | deleted by trigger (I4) |
| Downgrade to pre-1B | unchanged | rows persist; triggers fire; no evidence consumer in that build |
| Imported marker equals assigned 1 | zero → 1 | deterministically deleted before assignment; no collision exception |
| Failure during initialization | rollback to zero or both operations committed | never committed usable marker with imported rows retained |

Optional new-code post-import deletion is redundant. **Mandatory rule 2 belongs to evidence-aware initialization**, not the recovering code. This contract authorizes no actual repair, import, restore or database operation.

### 5.3 Read path (`realtime-plane.ts`): stat-before-open, bounded fd read, identity

Order, preserving today's outcome precedence:

1. **Follow-`stat`** the path exactly as `:91-95`. Failure ⇒ `unavailable stage:'stat'` with the same sanitised code (a dangling symlink still fails here, as the 1A suite asserts).
2. **Oversize from that stat,** `:96`, **before any open.** Return `{kind:'oversize', size}`; the ledger floors and continues as today. No descriptor is opened, so a stat-able but unopenable oversize file floors and never holds (I6). The evidence row for it is `skipped_oversize` with NULL identity and NULL hash.
3. `lstat` the path (identity sample `l`: regular, symlink, dev, ino, nlink; `bigint`). Failure here is **not** a new hold: treat as `identityOk = false` and continue to open, so projection is unchanged.
4. `open(path, O_RDONLY | O_NONBLOCK)` (follows symlinks exactly as `readFileSync` did). Failure ⇒ `unavailable stage:'read'`, the same stage today's `readFileSync` failure reports, with the sanitised code.
5. `fstat(fd, {bigint:true})`. If not a regular file ⇒ close and return `unavailable stage:'read' code:'OTHER'`. **Deliberate narrow change:** today a FIFO or device name could block the worker or be projected; it now holds, is never marked consumed, and is reported.
6. **Bounded read loop.** Read into a buffer until a 0-length read. Retry `EINTR`. `EAGAIN`/`EWOULDBLOCK` or any other error ⇒ close, `unavailable stage:'read'`. If total bytes read would exceed `maxBytes` (the file grew past the cap between the stat and the read), apply **decision D1**:
   - **D1 recommended:** stop reading, close, return `{kind:'oversize', size: <bytes observed so far or current fstat size>}`. The ledger floors it. This matches invariant 6 ("files larger than maxFileBytes are skipped") and bounds memory. It changes projection only in the race window where today's unbounded `readFileSync` would have read the grown file.
   - **D1 alternative:** read to EOF unbounded, as today. Memory bound is then not established, exactly as today.
   The panel chooses; this document recommends the bounded form.
7. Close the descriptor on every path (`try/finally`).
8. `content = buf.toString('utf8')`; identical to `readFileSync(path, 'utf-8')` for the same bytes, so projection strings are unchanged (I2). Line end offsets come from scanning `buf` for 0x0A.
9. `identityOk = l.ok && l.isFile && !l.isSymlink && l.nlink === 1n && l.dev === f.dev && l.ino === f.ino && f.isFile() && f.nlink === 1n && countNewlines(buf) === content.split('\n').length - 1`. A false flag never changes projection; it only forces `unverified_identity` (§5.5).

Outcome type gains optional `identity` and `bytes` fields on `ok`, and `size` stays on `oversize`. The `RealtimePlaneFs` seam becomes `readdir/stat/lstat/open/fstat/read/close` (test-owned injection, no environment or global switch). The 1A suites that count seam calls need a mechanical rename; their behavioural assertions must not change.

### 5.4 Directory endpoint samples (answers Grok R1, Astra N3)

- Before `readdir`: `dirId0 = stat(dir, {bigint:true})` → `(dev, ino)` as decimal text. Failure ⇒ no evidence this run; projection unchanged.
- On **every** return of `collectPending` that can lead to a commit — loop end, batch cut (`:161`), hold with earlier pending or an earlier floor (`:152`) — take `dirId1` the same way.
- Evidence rows are written only when both samples exist and are equal. Projection commits regardless.
- This is an **endpoint observation, not a pin**: an A→B→A swap between the two samples, or a swap between a sample and a file open, is not excluded. Pinning a directory across a destructive sequence remains gate G2.

### 5.5 Observations and first-match transition precedence (answers Grok B2)

`collectPending` additionally returns one observation per file it stat'd this run: `{name, kind: 'oversize'|'held'|'read', size?, identity?, identityOk, observedBytes, startLine, lineEnds[], hasTail, batchCut, malformedDelta}`. For `kind:'read'` with `startLine = k > 0` it also computes `prefixCheck`:

`prefixCheck = 'ok'` iff a row `R` exists **and all of**: `R.incarnation == current`; `R.status ∈ {consumed, partial}`; `R.dir_dev/dir_ino == dirId0`; `R.dev/ino == fd identity`; `R.covered_lines == k`; `R.covered_bytes <= observedBytes`; `R.covered_bytes == 0 || buf[R.covered_bytes - 1] == 0x0A`; the number of 0x0A in `buf[0, R.covered_bytes)` equals `k`; `sha256(buf[0, R.covered_bytes)) == R.covered_sha256`. Otherwise `'no_row'` when `R` is absent, else `'mismatch'`. The hash is incremental (`update` to `covered_bytes`, `copy().digest()` to compare, then continue to the new cut).

**Precedence, first match wins, evaluated per file inside the committing apply:**

| # | Condition | Write |
|---|---|---|
| P0 | run-level: malformed cursor (already halted), or `dirId0`/`dirId1` missing or different, or `user_version` changed since run start | **no evidence rows at all** |
| P1 | `kind = 'oversize'` | upsert `skipped_oversize`; identity NULL; hash NULL; `observed_bytes = size` |
| P2 | `kind = 'held'` (the file the run held at, when earlier progress commits) | insert `held` only if no row exists; otherwise leave the row untouched |
| P3 | `identityOk = false` (any `startLine`) | upsert `unverified_identity`; hash NULL |
| P4 | `startLine > 0` and existing status is sticky (`skipped_oversize`, `held`, `changed`, `unverified_prefix`, `unverified_identity`) | leave the row untouched |
| P5 | `startLine > 0` and `prefixCheck != 'ok'` | `unverified_prefix` if no row, else `changed` (this includes a previous `empty_observed`, or a row from another incarnation) |
| P6 | recompute: `identityOk`, directory equal, and (`startLine = 0` or `prefixCheck = 'ok'`) | `observedBytes == 0` ⇒ `empty_observed`; `covered_bytes == observedBytes > 0 && !hasTail && !batchCut` ⇒ `consumed`; otherwise `partial`. `covered_lines` = last committed line of this file (or `k` if none was added), `covered_bytes` = its end offset (always on 0x0A), `covered_sha256 = sha256(buf[0, covered_bytes))`, `malformed_lines` = previous + delta (reset on `startLine = 0`) |

No other path reaches a write. A fresh read (`startLine = 0`) replaces any earlier row because the file really is being decided again from byte 0 in this generation and incarnation (after a reset the triggers already cleared it). `malformed_lines > 0` may sit on a `consumed` row but is never affirmative for any future classifier (a torn write from a concurrent writer looks exactly like malformed JSON).

**Unavailable at `startLine` with no earlier progress** writes nothing because `:223` returns before the transaction. The 1A hold re-observes the file every run; absence stays UNKNOWN. This is the accepted limit of "unreadable" evidence (I8): the only stored record of a hold comes from a run that also committed earlier work.

### 5.6 Apply-transaction coupling (I3)

Inside the existing `apply` (`:230-303`), in order:

1. Existing raw CAS `current !== startCursor` ⇒ return; **no writes**.
2. Re-read `user_version`; `!= run incarnation` ⇒ return; no writes.
3. Only when `startLine > 0` for the cursor file: re-read its row and compare `(exists, status, incarnation, dev, ino, covered_lines, covered_bytes, covered_sha256)` with the collect-time snapshot (not `observed_at`, not `malformed_lines`). Any difference ⇒ return before any projection write, exactly like a failed CAS. A `startLine = 0` run is never aborted for a missing row.
4. Existing projection loop, eviction, floor and cursor write, unchanged (`:237-302`).
5. If P0 does not apply: upsert evidence rows per §5.5, then the incarnation purge (§5.2 rule 5).

All of it is one `BEGIN IMMEDIATE` (`:304`). A throw anywhere rolls back cursor and evidence together. Every committing run changes the cursor (pending lines advance it; a floor is always greater than the start), so the raw CAS also guarantees the rows read at collect time are current. The one ABA is through `''`, which requires a reset, which deletes all rows; a stale `''` run that then commits writes rows for bytes it really decided from offset 0 into the post-reset graph. That is truthful. The pre-existing duplicate-projection race is unchanged.

### 5.7 Generation binding (I4)

Covered by the three triggers (§5.1) plus an optional explicit `DELETE` in new-code `clearGraph`. Rebuild (`projector.ts:541`, `:573-578`) and the lease version bump (`:698`) both pass through `clearGraph`. After a reset, rows reappear only for files actually re-read from byte 0 in the new generation; files absent at replay get no row (UNKNOWN). **No `PROJECTOR_VERSION` change:** a bump auto-runs `clearGraph` and replays only files present, which is the issue's rebuild hazard (C5) and must not be triggered by this slice.

### 5.8 Persistent skip evidence (I8)

- Oversize: `skipped_oversize` is written in the same run that commits the floor, because a floor forces the transaction (`:223`). Sticky by P4. A later fresh read (only after a reset) can replace it truthfully.
- Held: `held` is written (if no row) when a hold coincides with earlier committed progress. Sticky by P4. When the file becomes readable the cursor is still before or inside it, so it is decided from `startLine` and P5/P6 apply; a `held` row with `startLine > 0` stays `held` (P4), which is conservative.
- Unreadable without earlier progress: not stored (see §5.5). Absence is UNKNOWN by construction, and I1 forbids any path from promoting it.

### 5.9 Missing history and recovery limits (G5; stated, not solved)

- A day file absent before the directory is listed is never observed: no row, UNKNOWN, undetected.
- A day file restored behind the cursor is skipped by `:137` and never re-decided until a reset. Evidence never drives replay.
- A reset followed by replay (rebuild or version bump) re-creates evidence only for files present. Days no longer on disk vanish from the graph and from evidence; this is the rebuild hazard from the issue's third comment and is **unchanged**.
- Evicted `rt:` nodes do not invalidate evidence; consumption is not graph retention.
- Partial database corruption that loses graph rows without a recovery is undetectable by this design.

### 5.10 Future classifier contract (spec only; not in the implementable slice)

Any later read-only verifier must first require `status === 'consumed'`, `malformed_lines === 0` (missing, invalid or non-zero ⇒ UNKNOWN), a valid non-zero header matching the row, and positive complete coverage (`covered_bytes === observed_bytes > 0`). These are necessary, not sufficient: it must also read `cursor`, `user_version` and the row in one read transaction; probe the **named** file in the **recorded** directory (`dir_dev/dir_ino` compared first); open with `O_NOFOLLOW`, `fstat`, re-hash exactly `covered_bytes` through a bounded loop with its own independent size limit (never an allocation sized by the row), then `fstat`/`lstat` again; then re-read `cursor`, `user_version` and the row and require all three unchanged. Malformed cursor ⇒ every file `UNKNOWN_PLANE`. Any missing, inconsistent or mismatched input ⇒ UNKNOWN. The only affirmative code means: "the ledger committed decisions for exactly these bytes in this generation and incarnation, and a bounded read just now reproduced the digest with no detected endpoint change". It is point-in-time, excludes no writer holding a descriptor, and is not cleanup permission.

---

## 6. Acceptance matrix against the issue

Legend: ✔ addressed as evidence input only; — not addressed; gate names: **G1** writer coordination/retirement, **G2** directory pin, representations, durable publish, dry-run parity, **G3** compressed-reader ports and decompression budgets, **G4** deletion policy incl. stop-hook recovery, #654, no-durable-reader rows, rebuild visibility, **G5** missing/restored history.

| # | Requirement | 1A (merged) | This design | Gate |
|---|---|---|---|---|
| B1 | Late appends during rollover, compression, verification | — | — (growth detected later as non-affirmative, not prevented) | G1 |
| B2 | Re-check source identity before removal, or coordinate writer | — | supplies `(dev,ino)` + digest + dir identity; no removal guard | G1 |
| B3 | Loop short writes; fsync before publish | n/a | n/a; no writer changed, none fsyncs | G1/G2 |
| B4 | Pin `audit/` across the async operation | — | endpoint observation only (§5.4) | G2 |
| B5 | Delete/compress only after the projector consumed the day | — | ✔ exact-byte evidence, never cursor order; insufficient alone (B8, C2, rebuild) | G4 |
| B6 | Shared strict cursor parsing; malformed ⇒ unknown, skip plane | done | classifier contract reuses it (§5.10) | retention code must call it |
| B7 | Skipped days stay protected | hold | ✔ sticky `skipped_oversize`/`held`; absence is UNKNOWN; incarnation/generation mismatch is UNKNOWN | pre-listing absence: G5 |
| B8 | Unsummarised guard outcomes survive deletion | preserved by doing nothing | — (decided and ignored by the ledger) | G4 + #654 |
| B9 | Decompression budgets charge actual bytes | n/a | n/a | G3 |
| B10 | Executable gz/plain contract for every reader | ledger plain only | — | G2/G3 |
| B11 | Open/disappearance errors retry the other representation; never corruption-advance | hold | — (single representation) | G2/G3 |
| B12 | Dry run matches execute incl. existing `.gz` | n/a | n/a (no actions) | G2 |
| B13 | Skipped audit plane must not arm a 24 h throttle | n/a | n/a (no worker hook; `shieldcortex maintain` does not touch audit) | kept as requirement |
| C1 | Affirmative evidence for the exact stable file | — | ✔ digest + identity + incarnation; "stable" is point-in-time | G1 |
| C2 | Durable reader-supported home for guard outcomes and dedup evidence | — | — | G4 + #654 |
| C3 | Coordinated retirement or locking against writers | — | — | G1 |
| C4 | Pinned dir + source identity; archive verified before removal | — | identity primitives only | G1/G2 |
| C5 | Unknown/malformed ⇒ preserve; rebuild must not drop days | halt | reset clears evidence; rebuild hazard unchanged | G4/G5 |
| C6 | Degraded rows with no durable recovery reader are evidence | preserved | — (never covered by `consumed`) | G4 |
| C7 | Do not copy the tarball workaround | — | nothing archives | — |

---

## 7. Executable test plan (future artefacts; none written or run)

**Placement and rules.** Jest files under `src/__tests__/`, run by CI on macOS and Ubuntu (Node 22.14.0 and 24) through `npm test` (`scripts/run-jest.mjs`, which also runs `build:ts`). Targeted local runs: `nice -n19 ionice -c3 npm test -- src/__tests__/<file>`; full suites only through `fleet-remote-test` or CI. Temp directories and `initDatabase(':memory:')` or a temp file DB as in `threat-graph-lease-jsonl.test.ts` and `realtime-ledger-barrier-579.test.ts`. Faults injected only through the extended `RealtimePlaneFs` seam and `beforeApply`; **no environment or global test switch**. Permission fixtures are skipped when `process.getuid() === 0`; every permission case also has a deterministic seam variant so root CI still exercises the branch. All fixture content is synthetic.

### 7.1 `realtime-evidence-transition-579.test.ts` — pure transition function (I1)

| Id | Case | Expect |
|---|---|---|
| T1 | each precedence row P1–P6 with a minimal observation | exactly the status in §5.5; table-driven over every `(prev status × observation kind × startLine)` cell |
| T2 | `identityOk = false` with `startLine = 0` and with `prefixCheck = 'ok'` | `unverified_identity`; never `consumed` |
| T3 | previous `empty_observed`, `startLine > 0` | `changed` |
| T4 | previous sticky status, `startLine > 0`, prefix would be `ok` | row untouched |
| T5 | prefix row from another incarnation, otherwise matching | `prefixCheck = 'mismatch'` ⇒ `changed` |
| T6 | prefix row with different `dir_dev/dir_ino` | `mismatch` |
| T7 | `covered_bytes == observedBytes` but `hasTail` or `batchCut` true | `partial` |
| T8 | `malformedDelta > 0` on a complete file | `consumed` with `malformed_lines > 0` (non-affirmative for any classifier) |

### 7.2 `realtime-plane-reader-579.test.ts` (extend) — read path (I2, I6)

| Id | Case | Expect |
|---|---|---|
| R1 | seam: `stat.size > cap`, `open` throws | `oversize`; `open` **not called**; error/floor text identical to 1A T1; a later readable file still projects |
| R2 | seam: `stat.size <= cap`, `open` throws `EACCES` | `unavailable stage:'read' code:'EACCES'`, hold, identical to today |
| R3 | dangling symlink (real temp dir) | fails at `stat`, same code as the 1A barrier suite asserts |
| R4 | seam: `fstat` not regular | `unavailable stage:'read' code:'OTHER'`, hold, nothing consumed |
| R5 | seam: `read` throws `EAGAIN`; `read` throws `EINTR` once then succeeds | hold; success with identical content |
| R6 | D1: seam grows the file past the cap mid-read | recommended: `oversize` floor; alternative: full read (whichever the panel chooses is pinned) |
| R7 | UTF-8 edge bytes (invalid sequences adjacent to 0x0A, BOM, CRLF, lone surrogates) | `content === fs.readFileSync(p,'utf-8')`; newline-count equality; `lineEnds` correct |
| R8 | descriptor closed on every path (seam counts `open`/`close`) | equal counts after each outcome kind |
| R9 | regular file with `nlink = 2` (hard link in temp dir) | projection unchanged; `identityOk = false` |

### 7.3 `realtime-evidence-ledger-579.test.ts` — ledger integration (I1–I3, I7, I8)

| Id | Case | Expect |
|---|---|---|
| L1 | fresh file, three terminated lines (threat, non-threat, malformed) | `consumed`, `covered_lines 3`, `covered_bytes == size`, digest = sha256(file), `malformed_lines 1`; nodes/cursor/errors byte-identical to a run without evidence (golden comparison of `threat_nodes`, `threat_edges`, state) |
| L2 | same-inode same-length in-place rewrite after L1, then a committing run on a later file | row unchanged (historical); no promotion; projection unchanged |
| L3 | append to a consumed cursor file, next run | prefix `ok`, chain verifies, `consumed` with new digest; one-shot digest of the whole file equals the chained one |
| L4 | unterminated tail | `partial`, tail excluded; after completion ⇒ `consumed` |
| L5 | `batchSize` cut mid-file, then next run | `partial(k)` ⇒ `consumed`; digest equals one-shot |
| L6 | prefix rewritten same length between runs plus one new line | `changed` (sticky); projection identical to today |
| L7 | rename-over replacement of the cursor file (new inode) | `changed`; projection identical to today |
| L8 | pre-existing cursor `D:k` with no rows (simulated upgrade) | D ⇒ `unverified_prefix`; earlier files no row; later files genuine |
| L9 | oversize file (small `maxFileBytes`) | `skipped_oversize`, NULL identity; floor/cursor/errors identical to 1A T1 |
| L10 | unreadable listed D after earlier progress | earlier rows written; D ⇒ `held`; later files no row; projection identical to 1A barrier suite |
| L11 | unreadable D with no earlier progress | no **apply** transaction, projection/cursor writes or evidence upserts. With initialized header and existing state: zero data writes. At header zero: separate initialization clears imported evidence and sets marker even with no progress; assert those writes only. Account for state-row setup separately. |
| L12 | D becomes readable after L10 | decided from `startLine`; `held` stays if `startLine > 0` (P4); fresh read replaces it if `startLine = 0` |
| L13 | empty file and tail-only file in a committing run | `empty_observed`, `partial(0)` |
| L14 | symlinked `realtime-D.jsonl` → regular file | projection unchanged; `unverified_identity` |
| L15 | directory identity differs between samples (seam) on loop end, batch cut and hold paths | projection commits; **no rows** on all three paths |
| L16 | `bigint` directory/file ids above 2⁵³ (seam) | stored decimal text exact; comparison by text |
| L17 | stale CAS via `beforeApply` | no node/edge/cursor/evidence write |
| L18 | resume row changed between collect and apply (seam mutates the row in `beforeApply`) | no write at all; a `startLine = 0` run with no row is **not** aborted |
| L19 | throw inside apply after projection (seam) | rollback: cursor and evidence unchanged |
| L20 | malformed cursor | 1A halt unchanged; no filesystem call; no evidence write |
| L21 | `rebuildThreatGraph` after rows exist, one file moved away first | all old rows gone; present files re-evidenced from byte 0; moved file no row |
| L22 | lease path with `projector_version = PROJECTOR_VERSION - 1` | evidence cleared then re-derived from present files only |

### 7.4 `realtime-evidence-schema-579.test.ts` — schema parity and triggers (I4)

| Id | Case | Expect |
|---|---|---|
| S1 | raw `UPDATE threat_graph_state SET last_rt_cursor = ''` | rows deleted (older-build reset simulation) |
| S2 | `DELETE FROM threat_graph_state`; then `INSERT OR IGNORE` | rows deleted by both triggers; a subsequent `INSERT OR IGNORE` on the existing row deletes nothing |
| S3 | apply `schema.sql`, `getInlineSchema()`, and migrations-then-schema on a pre-table fixture DB | table and three triggers present; `sqlite_master.sql` text identical across all three |
| S4 | migrations on a fixture DB **without** `threat_graph_state` | no throw; unrelated reconciliation still runs; canonical schema then creates table and triggers |
| S5 | CHECK constraints | `consumed` with NULL `dev` rejected; bad `name` rejected; unknown status rejected |

### 7.5 `realtime-evidence-incarnation-579.test.ts` — incarnation lifecycle (I5)

| Id | Case | Expect |
|---|---|---|
| N1 | fresh `initDatabase` | `user_version = 0` until the first ledger run; non-zero afterwards; stable across reopen |
| N2 | `PRAGMA user_version = N` inside a transaction that throws | value unchanged after rollback |
| N3 | two connections race on `0` | both end with the same value; no row ever carries a value other than the final one after one committing run each |
| N4 | simulated recovery: copy schema and all rows (including state and evidence) into a new file via `ATTACH` + `INSERT … SELECT`, leave `user_version = 0`, reopen | all rows UNKNOWN at zero; initialization deletes imported rows before setting marker 1, preserving cursor/graph. Resume with `startLine > 0` now has **no row** ⇒ `unverified_prefix`; earlier cursor-skipped files have no row |
| N5 | same as N4 but using the real `sqlite3 .dump` + import when the CLI is present (`skip` otherwise) | identical result |
| N6 | N4 variant omitting some `threat_nodes` rows (partial recovery) | identical result; nothing re-trusts the old rows |
| N7 | interruption: stop after the import step of a simulated new-code recovery, reopen without any post-step | identical result |
| N8a | dump-recovery entry paths: startup corrupt-DB recovery (`init.ts:1099`, straight to dump), and `repairDatabase()` on a fixture whose integrity check still fails after `REINDEX`/`VACUUM` so the `:1371` dump branch runs | identical to N7/N11 result |
| N8b | `repairDatabase()` on a fixture whose integrity check fails but passes after `REINDEX`/`VACUUM` (returns `repaired` at `init.ts:1353`, no dump) | identical to N15: marker, graph, cursor and evidence unchanged; no invalidation; no completeness claim |
| N9 | backup restore by `copyFileSync` of a healthy file | same `user_version`; rows trusted; resume chain continues |
| N10 | downgrade simulation: run a reset through raw SQL with the table present | triggers fire; `user_version` untouched |
| N11 | forced collision: imported consumed row stamped 1, retained cursor, omitted graph rows, header zero; completed/interrupted import and pre-1B recovery without a post-step | UNKNOWN before initialization; after assignment of 1, imported rows absent. Resume ⇒ unverified_prefix, never chained consumed; earlier files absent. No probability assumption. |
| N12 | failure after deletion or marker assignment before commit; retry and successful control | rollback leaves zero header and untrusted imported rows; retry clears them. Success commits marker 1 with no imported rows. |
| N13 | valid non-zero header, present consumed/partial row of another incarnation, otherwise matching prefix | mismatch ⇒ changed (P5). Missing-row control ⇒ unverified_prefix. Wrong-incarnation sticky control follows P4, remains UNKNOWN and may be removed by hygiene. |
| N14 | read-only classifier, zero header, row stamped zero or 1 | UNKNOWN, no writes or initialization |
| N15 | in-place REINDEX/VACUUM on healthy synthetic fixture | marker and logical graph/cursor/evidence unchanged; no completeness claim for corruption |

### 7.6 Future classifier tests (spec only)

A later classifier must test a malformed but newline-terminated row with otherwise matching consumed status, coverage, cursor, incarnation, identity and digest: UNKNOWN because `malformed_lines === 1`. The valid-line control with `malformed_lines === 0` may be affirmative only if every other predicate holds. Missing/negative/non-integer counts, zero/mismatched headers and non-consumed statuses require separate UNKNOWN controls. No verifier implementation is included here.

### 7.7 Regression

`threat-graph-lease-jsonl.test.ts`, `realtime-ledger-barrier-579.test.ts`, `realtime-plane-cursor-579.test.ts`, `realtime-plane-reader-579.test.ts` and all `threat-graph-*` suites must stay green with only mechanical seam-name updates. L1's golden comparison is the executable form of I2.

---

## 8. What stays unresolved (honest list)

| Item | Why this design does not solve it | Gate |
|---|---|---|
| Writer coordination and retirement: held append descriptors, rollover late writes, bundled and Hermes writers that know no protocol, no fsync anywhere | evidence is historical; a writer can append after any observation | G1 |
| Directory identity across a destructive sequence | endpoint observation only; no `openat`-style pin | G2 |
| Compression, gzip/plain representations, durable publish-then-verify, dry-run parity | no actions, no representation state machine | G2/G3 |
| Reader ports for compressed files; decompression budgets by actual bytes | plain-only; R2–R6 untouched | G3 |
| Stop-hook recovery: unsummarised guard outcomes, summary dedup, positional fingerprints (#654), degraded rows with no durable recovery reader | decided and ignored by the ledger; only the best-effort session index protects them today | G4 |
| Reader horizons (14-file API windows, 2-file self-check, readiness windows) | deleting a consumed file still changes what they show | G4 |
| Rebuild visibility of archived days; restored pre-cursor history; files absent before listing | no row = UNKNOWN; nothing detects or replays them | G5 |
| Worker throttle semantics for a skipped plane | no worker hook exists; requirement recorded | later |
| Memory bound of the ledger read | D1 decision; today unbounded | panel |
| Same-inode same-length rewrite after the cursor leaves a file | row goes stale until a future classifier re-hashes; status is history, not current truth | accepted |

**Decision points for the panel:** D1 bounded read ⇒ oversize floor (recommended) versus status-quo unbounded read; D2 include the optional `held` row (recommended) or drop it; D3 optional explicit `DELETE` in `clearGraph` and in new-code `attemptDumpRecovery` (recommended as documentation of intent, never relied on).

**When preserving the data is the only safe result:** every file whose row is absent or non-affirmative; and, while G1 and G4 are unresolved, every file at all. Today that is every file. This design changes no retention outcome.

---

## 9. Implementation brief (only if separately authorised; not authorised by this document)

Title: `feat(threat-graph): record exact-byte realtime consumption evidence (#579 Slice 1B r2, no retention)`.

1. `src/database/schema.sql`, `src/database/inline-schema.ts`, `src/database/migrations.ts` (own guarded block): §5.1 DDL and the `user_version` reservation comment.
2. `src/threat-graph/realtime-plane.ts`: §5.3 read path and extended seam; stat-before-open preserved.
3. `src/threat-graph/realtime-ledger.ts`: `ensureEvidenceIncarnation`; directory samples on every commit path; observations and `prefixCheck`; §5.6 apply ordering; evidence upsert and incarnation purge. No change to CAS, floor, hold, halt, tail or projection.
4. `src/threat-graph/realtime-evidence.ts`: pure transition function only. **No probe, no classifier, no CLI, no doctor row, no worker hook.**
5. `src/threat-graph/projector.ts` `clearGraph`: optional explicit `DELETE` (D3). No `PROJECTOR_VERSION` change.
6. Tests §7.1–7.5; seam renames in the 1A suites; one paragraph in `docs/design/2026-08-11-threat-graph.md` beside the Slice 1A paragraph stating "observation only; not cleanup permission".

PR promise: "The realtime ledger records, in the same transaction as its cursor, the SHA-256, descriptor identity and directory identity of the exact bytes it decided from each realtime file, stamped with the database's evidence incarnation, with sticky non-affirmative states for oversize, held, changed, replaced or unverifiable files. Evidence is cleared on every graph reset and distrusted after dump/reimport or recreation, with imported evidence atomically invalidated before zero-header initialization. Consistent snapshot file-copy restore and in-place REINDEX/VACUUM preserve continuity, not proof of graph completeness. Nothing reads it in production, no audit file is compressed or deleted, zero disk reduction; #579 stays open."

---

## 10. Original authoring-pass checks and refusals

**NOT RUN:** build, typecheck, lint, Jest, fixtures, CLI/API/worker, live audit or database reads, compression, rename, unlink, replay, rebuild, migration, any write to a ShieldCortex database. Every behaviour above is derived from source at `cbe011ef`. The two SQLite observations in §5.2 were made against **in-memory** fixtures with the host's `sqlite3 3.45.1`, with no file created and no ShieldCortex code involved.

**Refusal recorded:** one shell command in this pass ended with a recursive force delete of a scratch directory and was denied by the host Action Guard (`Catastrophic-tier … [recursive-force-delete]`). The delete was not retried in any form; the fixture was re-done in memory so no directory existed to remove. No read or write of this document or of repository files was refused.

**Writes this pass:** this document only, on a documentation branch. No source, schema, test, guard, config or database change.

## 11. Documentation repair verification

The repair replaces probabilistic marker safety with mandatory atomic invalidation at zero-header initialization, adds the malformed-count classifier predicate, and reconciles initialization-on-run, missing-row/wrong-incarnation test oracles and recovery categories. All unresolved G1–G5 gates and D1–D3 decisions remain; no implementation or operational action is authorized.

A bounded Python SQLite `:memory:` model (no ShieldCortex code or file database) retained cursor/evidence, omitted graph rows and forced imported marker 1 to equal the assigned marker. Commit left header 1 and zero imported rows. Rollback after deletion and after marker assignment each restored header zero and one untrusted imported row; cursor stayed unchanged. These three checks passed; they are not lifecycle integration tests or proof of an implementation. Documentation diff whitespace check passed. No build/full suite was needed for this design-only edit; CI and independent exact-head review remain gates.
