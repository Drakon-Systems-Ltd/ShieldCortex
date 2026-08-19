# #375 — Cron Discovery + Denial Honesty for Scheduled Jobs (Design v2)

Date: 2026-08-19 · Author: TARS · Status: v3-FINAL
(R1: both REQUEST_CHANGES → simpler converged shape. R2: Grok APPROVE_WITH_NITS,
SOL REQUEST_CHANGES — both independently naming the SAME two holes, closed here:
cron_run_logs joins the honesty probe; the nearest-run fallback is deleted.)

## Problems (proven live on Edith, 2026-08-19)

**P1 — Discovery blindness.** `allowlist scan` (#309) reads OpenClaw crons from
`~/.openclaw/cron/jobs.json`. OpenClaw migrated the store to SQLite
(`~/.openclaw/state/openclaw.sqlite`, table `cron_jobs`; Edith: 63 rows, JSON
deleted, only `.bak`/`.migrated` remain). Scan discovers zero gateway cron
scripts; every new cron script silently breaks on first run.

**P2 — Status dishonesty.** A guard denial inside a cron turn does not fail the
turn; OpenClaw records `last_run_status: ok`. Two Edith crons were dead 2+
weeks with green status. ShieldCortex cannot rewrite OpenClaw status; it CAN
correlate denials to cron runs and surface the lie.

## Non-goals
- No writes to any OpenClaw store (SQL read-only; note: WAL/shm files may
  appear on open — we claim no SQL writes, not zero filesystem side effects).
- No auto-pinning; discovery feeds the existing #309 TTY per-item review flow.
  No `--yes` batch pin for the first sqlite backfill (per-item only).
- No new notification channel; #369 handles real-time.
- No hook-lane (Match B) attribution in v1: denials do not carry a reliable
  join key for it. Deferred behind a denial-time join key (tiny ADR if wanted).
  Do NOT un-redact #284 surfaces to get one.
- Correlation stays OUT of the guard hot path (CLI/doctor only).

## Design

### Shared: one RO sqlite helper + one honesty enum
`src/cli/openclaw-cron-store.ts`:
- `openCronStore(dbPath)` → better-sqlite3 `new Database(path, { readonly:
  true, fileMustExist: true })` — the exact pattern doctor already uses.
  No node:sqlite, no sqlite3 binary spawn, no RW branch anywhere.
- `probeCronSource(path)` → shared status enum for BOTH scan and doctor:
  `ok | absent | unreadable | schema_mismatch`.
  - File missing → `absent`.
  - Open failure / query failure → `unreadable`.
  - Table `cron_jobs` missing → `absent` (SOL blocker 2: the store simply is
    not this shape — but see the visibility rule below).
  - Table present, required columns missing (PRAGMA table_info vs required
    set) → `schema_mismatch`.
  - The probe covers BOTH load-bearing tables: `cron_jobs` (required:
    job_id, name, enabled, payload_message, trigger_script, job_json) AND
    `cron_run_logs` (required: job_id, session_key, run_at_ms, status —
    R2 shared blocker: run logs are the silent-source-of-truth and MUST be in
    the honesty enum; their failure is cannot-look → WARN, never
    silentCount=0 PASS). `cron_jobs` ok + `cron_run_logs` missing/mismatched
    → correlation status is the failing status; P1 discovery may still use
    cron_jobs.
- `isIncomplete(status)` = `unreadable || schema_mismatch` → scan exit 1;
  doctor renders WARN (Grok blocker 1: cannot-look is never INFO/pass).
- Visibility rule: if `~/.openclaw/` exists (dir or openclaw.json) and BOTH
  cron sources (JSON + DB) are `absent`, scan reports the pair as a visible
  line and exits 1 (incomplete): an OpenClaw host with no readable cron source
  is "we could not look", not "all clear". A host with no `~/.openclaw` at all
  stays empty-ok (fresh host).

### P1 — Discovery (allowlist-scan.ts)
- New source `openclaw-cron-db`, path `~/.openclaw/state/openclaw.sqlite`
  (injectable `openclawDbPath` for tests; real HOME never read under test).
- Query (bounded, columns guarded by the probe):
  `SELECT job_id, name, enabled, payload_message, trigger_script, job_json
  FROM cron_jobs` — ALL rows; `enabled` filtered in JS with truthiness
  coercion (see implementation rules), never in SQL.
- Extraction: existing `extractScriptPaths` on `payload_message` and
  `trigger_script`; `job_json` is parsed and WALKED structurally (every string
  leaf through `extractScriptPaths`) — no stringify sweep (SOL nit).
- Union with legacy JSON source if that file still exists (mid-migration
  hosts). `.bak`/`.migrated` files are never read as live, and never treated
  as proof the store is absent.
- `CronSourceReport` gains the DB entry on day one, included in the broken-
  sources accounting (Grok nit).

### P2 — Correlation (`src/cli/cron-denial-audit.ts`, CLI-side, not defence/)
- `correlateCronDenials({ home, openclawDbPath, denialsPath, windowMs = 7d })`:
  - Read `denials.jsonl` (cap 4 MiB tail; unreadable file → status
    `unreadable` → WARN, never pass; absent → clean pass).
  - Dedupe denial rows by `actionId` (each denial writes 2 lines: outcome +
    notify-status).
  - **Match A only**: denial `sessionKey` matching
    `^agent:[A-Za-z0-9_-]+:cron:([0-9a-f-]{36}):run:` → jobId by exact token.
    Anything else → counted `unattributed` (shown as a count line, no guessing).
  - For each attributed denial, find its run row in `cron_run_logs`
    (`WHERE job_id = ? AND run_at_ms BETWEEN ? AND ?` — SQL-bounded window)
    by session_key EXACT match only. The denial sessionKey IS the run's
    session_key in Match A — there is nothing to approximate. NO
    nearest-run fallback (R2 shared blocker: that was a guess; a wide window
    can glue a denial to an unrelated ok run and print a green lie).
  - `silent` = the exactly-matched run row's `status = 'ok'`. No matching
    row → `unconfirmed` (counted + WARN line "N denial(s) could not be
    matched to a run row"), never silent=true and never silent=false-pass.
  - Output: `{ jobId, name, enabled, denialCount, lastDenialTs, silentCount,
    pinnablePaths }` where `pinnablePaths` come from THAT JOB's discovered
    script paths (P1 extraction) — never from a denial surface (Grok rule).
- Doctor check `CRON` (WARN, never --fix, never auto-pass):
  - Attributed silent denials → WARN: "N scheduled job(s) had guard denials in
    the last 7 days while their runs reported ok", per-job lines, and
    `shieldcortex allowlist add <path>` per pinnable path.
  - Sources unreadable/schema_mismatch → WARN "could not correlate cron
    denials (<status>)".
  - Nothing denied + sources ok → PASS.
- `allowlist scan`: attributed-denied scripts sort FIRST in the review list,
  flagged "guard-denied in the last 7 days (job: <name>)".

## Security invariants
- No SQL writes to OpenClaw stores; readonly+fileMustExist only.
- No denial surface reconstruction; correlation uses actionId/sessionKey/
  timestamps only; doctor lines never print command bodies.
- Discovery → pin path unchanged: TTY per-item review only.
- Path extraction: existing conservative regex only; no shell parsing.
- `cron-denial-audit` lives under `src/cli/`; importing it from the guard hot
  path is forbidden (test asserts no import from defence/iron-dome runtime
  modules beyond types).

## Test plan
- Helper: probe matrix — absent file / unreadable (chmod 000) / missing table
  → absent / missing column → schema_mismatch / ok — for BOTH cron_jobs and
  cron_run_logs required-column sets. isIncomplete truth table.
- P2 fail-closed: cron_jobs ok + cron_run_logs missing → doctor WARN
  cannot-correlate (NOT pass, NOT silentCount=0); same for run-log query
  failure mid-correlation.
- No-row case: attributed denial with no exact session_key run row →
  unconfirmed count + WARN, silentCount unchanged.
- P1: fixture DB (better-sqlite3 in-test): payload_message, trigger_script,
  job_json leaf paths discovered with `openclaw-cron-db` label; disabled jobs
  excluded; JSON+DB union; `.bak`/`.migrated` ignored; ~/.openclaw present +
  both sources absent → visible + exit 1; no ~/.openclaw → empty-ok; corrupt
  DB → exit 1.
- P2: fixture denials + cron tables: Match A attributes exact job; malformed/
  foreign sessionKeys → unattributed count; actionId dedupe (2 lines = 1
  denial); silent keyed off run-log row status (fixture where job
  last_run_status differs from the attributed run's status); window bound
  respected; unreadable denials.jsonl → WARN; absent → pass; pinnablePaths
  only from job extraction; scan orders denied-first.
- Doctor: WARN rendering for silent denials incl. add-commands; WARN on
  cannot-look; PASS when clean; never listed as fixable.
- Regression: existing #309 scan suite untouched and green.

### R2 nits folded as implementation rules
- Do not existsSync-gate on `~/.openclaw` presence: probe the two source
  paths directly; EACCES on either = `unreadable` (visible), not absent.
- First-backfill guard: `scan --yes` is refused while ANY `openclaw-cron-db`
  path is still unpinned (per-item review only for the initial sqlite wave).
- Coerce `enabled` in-process (JS truthiness on the selected column), so a
  store with textual '1'/'true' cannot empty-ok a live store via `WHERE
  enabled = 1` type mismatch — select all rows, filter in JS.

## Rollout
Additive CLI/doctor surface; no config gate. Next patch release; Edith (63-job
store) is the live validation host.
