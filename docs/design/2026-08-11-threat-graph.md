# The Threat Graph — a security event graph that closes ShieldCortex's learning loops

*2026-08-11. Design for making the graph subsystem a defence asset. Builds on the
2026-08-11 graph audit (six-agent workflow: extraction, storage, consumers, defence
signals, two adversarial verifications) and revised against a four-lens adversarial
design review (red-team, codebase-accuracy, systems-feasibility, completeness — 45
findings, all folded in below). Companion to
`2026-08-10-conversation-taint-escalation.md`, whose escalation philosophy this
design generalises.*

## The question

ShieldCortex has a knowledge graph (`entities` / `triples` / `memory_entities`)
and a defence pipeline. Today they do not talk to each other, and neither one
learns. Can the graph become the substrate that makes ShieldCortex a *learning*
security system — without becoming a *trainable* one?

## What the audit established

Three findings shape everything below.

**1. The memory knowledge graph cannot carry security reasoning as built.**
Extraction is regex + word lists (`src/graph/extract.ts`); the dominant edge is
all-pairs `related_to` co-occurrence; confidence is a flat 0.8 that no code path
ever varies; junk entities (`AbortError`, `path/to/server.js`) are minted freely
and entrenched by co-occurrence edges; Levenshtein-≤2 resolution silently merges
distinct identities (`server.ts` ↔ `server.js`). It is a co-occurrence index
with a graph-shaped API. Useful as a recall signal (0.3 RRF weight) — unusable
as a reasoning substrate.

**2. The defence pipeline consumes zero graph data and learns from nothing.**
Confirmed by grep: no defence module reads `entities`/`triples`. "Behavioural
Scoring — anomaly detection over time" (`firewall/anomaly-scorer.ts`) is a pure
per-content function with no history, no baseline, no temporal component.
Operator quarantine decisions are terminal writes — `recordOperatorDecision`
(`judge/telemetry.ts:49`) has **zero call sites**. Approving item N does nothing
for identical item N+1. Session taint is a 15-minute in-memory Map that dies
with the gateway process.

**3. The system already owns a near-perfect event source.** `defence_audit`
(`schema.sql:233-252`) records, for every memory-write pipeline run *including
ALLOW*: source tuple, trust score, verdict, operation, threat indicators,
blocked patterns, anomaly score, fragmentation score, content hash (write-path
rows), timestamp. It is append-only in operation, bounded by retention (90-day
age purge plus a size-pressure valve), with lifetime counters preserved in
`audit_aggregates`. Two honest caveats the design must carry: the
**tool-response scanner audits threats only** (clean tool-response scans leave
no row — `tool-response-scanner.ts:271-273`), and **conversation scans in the
OpenClaw gateway currently produce no `defence_audit` rows at all** — the
plugin is deliberately DB-free and writes a JSONL realtime audit instead
(`plugins/openclaw/index.ts:794-807, 872-886`). The design treats that JSONL
as a second ledger rather than pretending the gap doesn't exist.

The conclusion: **do not graph the prose — graph the security events.** The
intelligence lives in a new event graph projected from the audit ledgers; the
memory knowledge graph's job shrinks to what regex extraction can honestly
support (a recall index), later gaining provenance columns so the threat graph
can police it.

## Why this matters now (the landscape)

Memory poisoning is OWASP ASI06 in the Agentic Top 10 (2026). The research
frontier has moved to attacks *on graph memory itself*: ShadowMerge
(arXiv:2605.09033) poisons graph-based agent memory via relation-channel
conflicts; Oracle Poisoning (arXiv:2605.09822) corrupts knowledge graphs to
weaponise agent reasoning. The defences that literature calls for — relation
provenance, writer authority, conflict resolution, trust-aware retrieval
(MemGuard arXiv:2605.28009, Selection Integrity arXiv:2606.12290) — are
precisely what a memory security product should own. Meanwhile the memory-
quality SOTA (Zep/Graphiti, arXiv:2501.13956) is temporal knowledge graphs:
every edge carries when it became true, when it stopped, and where it came
from. The security literature and the memory literature independently demand
the same three properties: **typed edges, provenance, time.** Nobody ships
"graph memory security" today. This design claims it — with the limits stated
plainly, because a security product that overclaims is worse than none.

## First principles (non-negotiable invariants)

These keep a *learning* security system from becoming a *trainable* one. Every
mechanism below must satisfy all of them.

1. **The ledgers are truth; the graph is a derived view.** The threat graph is
   a deterministic projection of `defence_audit` + the realtime JSONL +
   operator decision rows. It can be dropped and rebuilt from the ledgers —
   **within the retention window** (purged history survives only as
   aggregates; see Retention). Determinism is *logical*: two projections of
   the same ledger rows produce identical canonical dumps (nodes ordered by
   `(kind, key)`, edges by `(src_key, predicate, dst_key)`, all columns
   compared except surrogate ids), not identical database files. All projected
   timestamps derive from ledger-row timestamps, never wall clock.
2. **Additive-tightening only, with one audited exception.** Graph-derived
   signals may lower trust, raise severity, or escalate a verdict — never
   automatically raise trust, lower severity, or downgrade a verdict. The
   exception is invariant 3's operator actions (allowances, disputes), which
   are human-authored, narrow, expiring, and ledger-recorded.
3. **Operators are the only loosening force, and they loosen narrowly.** An
   operator decision produces a scoped, expiring effect (an allowance on one
   source × pattern pair; a risk reset on one source), never a global
   threshold change. Every operator action lands an audit row, so replay
   reproduces it.
4. **The hot path reads O(1) precomputed values only, and can never be harmed
   by them.** The sync pipeline and Action Guard never traverse the graph.
   The single permitted hot-path read (`source_risk` by primary key) is
   guarded and exception-isolated: any failure yields modifier 0. A graph
   failure must never surface as a scan failure — stated as a hard rule
   because the pipeline itself is fail-closed, and an unguarded read would
   convert a stale WAL checkpoint into blocked scans (see Loop 2).
5. **Node identity is class-typed, and only one class is trusted.** Three
   identity classes, handled differently everywhere they are consumed:
   - *System vocabulary* (built-in pattern ids, verdict values, indicator
     names): trusted identity. Safe to key on, cluster on, alert on.
   - *Caller-attested* (source tuples, session ids): *claimed* identity.
     `source_identifier` is caller-supplied free text
     (`source-scorer.ts:43`); a malicious local process can claim any name —
     including a victim's. Risk keyed on this class is therefore both an
     attacker self-burn and a **griefing primitive** (burn a legitimate
     agent's name), and every consumer must treat it accordingly (see Loop 2's
     attestation gate and the per-source accrual cap).
   - *Content-derived* (`entity_ref` bridges, labels): untrusted. Bridged by
     numeric id; the referenced memory-graph entity inherits that graph's
     junk-minting and fuzzy-merge weaknesses, so `entity_ref` links are
     low-confidence signals, never sole triggers. Labels are display-only,
     capped at 256 chars, control-char-stripped, and never matched on.
   Custom patterns (user-authorable, `src/defence/custom-patterns`) are keyed
   under a `custom:` namespace and treated as caller-attested, not system,
   identity.
6. **Bounded everything, with numbers.** Distinct source nodes ≤ 5,000
   (overflow routes to a bucketed `source:overflow` node and raises a
   notable event — a spike in new-source minting is itself an
   identity-rotation signal). Event nodes ≤ 50,000; edges ≤ 200,000; evidence
   arrays ≤ 20 audit ids (FIFO, newest kept). At cap: oldest non-campaign
   event nodes are evicted first, their contribution rolled into the
   corresponding aggregate edges *before* deletion; aggregate edges and
   allowances are never evicted; every breach is recorded in
   `threat_graph_state.last_error` and surfaced by the doctor check (the
   4.47.38 cap-eviction autopsy is the cautionary tale: at-cap behaviour is
   specified here, not improvised later). Campaign alerts have their own
   budget (see Loop 4). Risk decays with a half-life so no source is tainted
   forever — and an idle-row sweep guarantees the decay actually happens
   (see Loop 1).

## Architecture

```text
                     SYNC HOT PATH (unchanged, pure)
  scan → sanitise → trust → firewall → sensitivity → … → verdict
             │  (guarded O(1) read: source_risk row — Loop 2)  │
             │                                                 ▼
             │                              defence_audit  ◄── TRUTH (ledger 1)
             │        gateway conversation scans → realtime JSONL (ledger 2)
             │                                                 │
  ═══════════╪══════════════ async boundary ═══════════════════╪══════════
             │                                                 ▼
             │                                       ┌──────────────────┐
             │                                       │  Graph Projector │  worker light tick,
             │                                       │  (deterministic) │  both profiles,
             │                                       └────────┬─────────┘  leased single-writer
             │                                                ▼
             │                                          THREAT GRAPH
             │                                threat_nodes / threat_edges
             │                                                │
             │                      ┌─────────────┬───────────┴───────┬─────────────┐
             │                      ▼             ▼                   ▼             ▼
             │                source_risk    campaign           allowances     baselines
             │                (O(1) table)   detection          (operator)     (per source)
             └──────────────────────┘        (async job)             │
                                                                     ▼
                                                            quarantine disposition
                                                            + Review Copilot
```

The projector is the only writer of graph rows (`writer='projector'`), except
operator actions (`writer='operator'`). Nothing in the hot path writes graph
tables. Nothing in the hot path reads them except the guarded `source_risk`
lookup, and only when the feature is enabled.

## Data model

New tables, deliberately **separate** from `entities`/`triples`. The memory
graph is built from attacker-influenced content, fuzzy-merged, and pruned when
memories die. The threat graph is built from system verdicts, never fuzzy-
merged, and retention-managed like audit. Mixing them in one table would
recreate the ShadowMerge problem inside our own defence layer. Bridging happens
by id, one direction only (threat graph → memory graph).

```sql
-- Threat graph: nodes. Identity = (kind, key); see invariant 5 for the
-- three identity classes and their trust levels.
CREATE TABLE IF NOT EXISTS threat_nodes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL CHECK(kind IN
    ('source','session','pattern','indicator','event','campaign','operator','entity_ref')),
  key TEXT NOT NULL,           -- 'agent:jarvis>researcher' (caller-attested),
                               -- 'pattern:credential_exfil' (system),
                               -- 'pattern:custom:<id>' (caller-attested),
                               -- 'event:audit:81234' / 'event:rt:<file>:<line>',
                               -- 'entity_ref:1042' (content-derived)
  label TEXT,                  -- display only: capped 256, sanitised, never matched on
  attrs TEXT NOT NULL DEFAULT '{}',  -- JSON: counters, baseline stats, verdict, decision,
                                     -- project of origin (events), risk exponent sum (sources)
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  UNIQUE(kind, key)
);
CREATE INDEX IF NOT EXISTS idx_threat_nodes_kind ON threat_nodes(kind);
CREATE INDEX IF NOT EXISTS idx_threat_nodes_last_seen ON threat_nodes(last_seen);

-- Threat graph: edges. Closed predicate vocabulary (CHECK, not free text —
-- the free-text predicate column on `triples` is a mistake we do not repeat).
CREATE TABLE IF NOT EXISTS threat_edges (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  src INTEGER NOT NULL REFERENCES threat_nodes(id) ON DELETE CASCADE,
  predicate TEXT NOT NULL CHECK(predicate IN
    ('triggered',      -- source → pattern         (aggregate, counted)
     'observed_in',    -- pattern → session        (aggregate, counted)
     'from_source',    -- event → source
     'in_session',     -- event → session
     'matched',        -- event → pattern
     'mentions',       -- event → entity_ref       (bridge, low-confidence)
     'decided',        -- event(decision) → event(scan); quarantine id in attrs
     'allows',         -- source → pattern         (operator allowance, TTL'd)
     'part_of',        -- event → campaign
     'conflicts_with'  -- event(conflict) → entity_ref; triple ids in attrs
    )),
  dst INTEGER NOT NULL REFERENCES threat_nodes(id) ON DELETE CASCADE,
  count INTEGER NOT NULL DEFAULT 1,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  valid_to TEXT,                              -- NULL = open; set on allowance expiry/revocation
  writer TEXT NOT NULL CHECK(writer IN ('projector','operator','backfill')),
  confidence REAL NOT NULL DEFAULT 1.0,
  evidence TEXT NOT NULL DEFAULT '[]',        -- JSON array of ledger refs, cap 20, FIFO
  UNIQUE(src, predicate, dst)
);
CREATE INDEX IF NOT EXISTS idx_threat_edges_src ON threat_edges(src);
CREATE INDEX IF NOT EXISTS idx_threat_edges_dst ON threat_edges(dst);
CREATE INDEX IF NOT EXISTS idx_threat_edges_pred ON threat_edges(predicate);

-- Projector checkpoint + single-writer lease. Two cursors: one per ledger.
CREATE TABLE IF NOT EXISTS threat_graph_state (
  id INTEGER PRIMARY KEY CHECK(id = 1),
  last_audit_id INTEGER NOT NULL DEFAULT 0,     -- defence_audit cursor
  last_rt_cursor TEXT NOT NULL DEFAULT '',      -- realtime JSONL cursor: '<file>:<line>'
  projector_version INTEGER NOT NULL DEFAULT 1, -- bump ⇒ full rebuild on next run
  lease_expires_at TEXT,                        -- single-writer lease (see Write paths)
  last_run_at TEXT,
  last_error TEXT
);

-- Hot-path read surface: ONE row per source, precomputed async. The sync
-- pipeline reads this by primary key or not at all. No JSON — the hot path
-- must not parse.
CREATE TABLE IF NOT EXISTS source_risk (
  source_key TEXT PRIMARY KEY,        -- '<source_type>:<source_identifier>', length-capped
  risk REAL NOT NULL DEFAULT 0.0,     -- [0,1], decayed (idle sweep keeps it current)
  attested INTEGER NOT NULL DEFAULT 0,-- 1 = identity was env-inferred or strictSourceMode
  block_count_28d INTEGER NOT NULL DEFAULT 0,
  quarantine_count_28d INTEGER NOT NULL DEFAULT 0,
  scan_count_28d INTEGER NOT NULL DEFAULT 0,    -- write-path scans only; see Loop 1 caveat
  updated_at TEXT NOT NULL
);
```

### Schema placement and migrations

The schema lives in three places and all three must move together (the
inline-schema header says exactly this): new tables go into
`src/database/schema.sql` **and** `src/database/inline-schema.ts` (plain
`CREATE TABLE IF NOT EXISTS` suffices — idempotent). Phase E's
`ALTER TABLE triples ADD COLUMN` is *not* idempotent and therefore ships as a
guarded entry in `src/database/migrations.ts` (`PRAGMA table_info` check, per
that file's own rules) plus matching columns in both schema definitions for
fresh installs. The `operation='review'` value needs no schema change (the
column has no CHECK constraint — verified across all three definitions) but
does need the `AuditOperation` union extended (`src/defence/types.ts:181`) and
that column's already-stale comment refreshed.

### Two-tier volume control

Every write-path scan lands an audit row; a busy fleet produces thousands a
day. The projection is two-tier:

- **Aggregate edges** for the bulk: an ALLOW scan updates counters on the
  `source` node and, if a pattern fired at warning level, increments the
  `source —triggered→ pattern` edge. No event node. Bounded by
  |sources| × |patterns| — with |patterns| ≈ 100 (built-ins + indicators +
  ≤50 custom) and |sources| hard-capped at 5,000 (invariant 6), the worst
  case is bounded and the realistic case (50–200 stable sources) is tiny.
- **Event nodes** only for *notable* events: verdict ∈ {BLOCK, QUARANTINE},
  anomaly score above threshold, scans flagged as tainted-session, operator
  decisions, conflict detections, and cap/mint-rate breaches. Keyed
  `event:audit:<id>` (or `event:rt:<file>:<line>` for the JSONL ledger) so
  they are joinable back to their ledger and deduplicated on replay.
  One deliberate exclusion: audit rows whose `threat_indicators` contain
  `pipeline_error` (the fail-closed handler's own BLOCK rows,
  `pipeline.ts:316-332`) carry **zero risk weight** — otherwise a wedged
  install (native-binding failure, DB corruption) would sit in a loop
  inflating every source's risk with self-inflicted blocks.

### Projection mechanics

The projector processes ledger rows in order, in batches of 500, inside a
**`BEGIN IMMEDIATE`** transaction (better-sqlite3's `.immediate()` variant —
the deferred default would hit `SQLITE_BUSY_SNAPSHOT` on lock upgrade against
concurrent scan writes, and `busy_timeout` does not apply to snapshot
invalidation). The cursor is **re-read inside the transaction** and the batch
range derived from that read, making each batch an atomic claim-and-advance:
even if a second projector instance runs (see Write paths), it processes a
disjoint range or no-ops. A crash mid-batch discards the uncommitted WAL
frames — cursor and partial work vanish together, and the batch re-runs
cleanly. That atomic claim, not per-rule idempotency, is what makes replay
safe; event-node dedup on ledger keys is a second belt for the rebuild path.

`shieldcortex threat-graph rebuild` (subcommand of the existing `graph` CLI
family, no name collision) drops the graph tables and replays both ledgers
from zero — which is also the **backfill**: on first ship, the graph populates
from every retained audit row. Bumping `projector_version` forces the same
rebuild on the next worker pass, which is how projection-logic upgrades roll
out without migration scripts.

## Write paths

**Ledger-only ingestion.** The projector consumes the two ledgers; nothing
else writes graph rows. Anything wanting representation in the threat graph
must first land a ledger row — a single choke point, inheriting audit's
tamper-evidence and retention machinery. Three gaps to close:

1. **Operator decisions.** Wire the dead `recordOperatorDecision` export: on
   quarantine approve/reject (`quarantine/review.ts:97-142`), write a
   `defence_audit` row with `operation='review'`, source
   `operator:<reviewed_by>`, and the decision + quarantine id in a structured
   `reason` payload. One subtlety the projector must handle: approval
   *already* produces a second row — `promoteApprovedQuarantineRow` re-scans
   at `{type:'user', identifier:'approved'}` (trust 0.9, `review.ts:56-83`),
   landing an ALLOW row. The projector pairs the two via the quarantine id so
   one approval is one decision event, not two independent events, and
   `user:approved` accrues no spurious aggregate credit.
2. **Conversation scans (corrected from first draft).** The gateway's
   `llm_input` path runs the tool-response scanner *in-process with no
   database* — by design (`plugins/openclaw/index.ts:794-797`); its audit
   write is gated on `isDatabaseInitialized()` and never fires there.
   Detections currently reach only the console, the in-memory taint store,
   and the realtime JSONL (`~/.shieldcortex/audit/realtime-YYYY-MM-DD.jsonl`).
   **The JSONL becomes the projector's second ledger** — it is already
   append-only and already written; the projector tails it with its own
   cursor (`last_rt_cursor`). Two fields must be added to the JSONL rows at
   the gateway: the session id and the session-taint state at scan time
   (the gateway owns both; the projector cannot reconstruct taint from
   outside). Projection rules account for the thinner row shape: realtime
   rows carry fixed trust 0.5, no fragmentation score, threats-only (no
   clean-scan rows).
3. **Denominator honesty.** Because the tool-response scanner and the
   realtime path audit threats only, `scan_count_28d` exists only for
   write-path sources. Rate-based baselines ("block rate jumped") apply to
   write-path sources alone; threats-only sources get absolute counts, not
   rates. Stated here so nobody divides by a denominator that doesn't exist.

**Projector hosting (corrected from first draft).** The medium tick runs only
under the `'full'` worker profile (`brain-worker.ts:193-199`); MCP-profile
installs — the *most common* install class — would never run it. The
audit-retention code solved this exact problem already and says so in its
comment (`brain-worker.ts:293-297`): run in the **light tick on both
profiles**, self-throttled to its own cadence (default: every 5 minutes of
tick traffic, i.e. effectively every light tick on full profile, every tick
on mcp profile). There is no task-registration abstraction — "hosting" means
an inline guarded block in `lightTick()`, same as the audit purge.

Multiple worker processes can coexist (MCP servers, dashboard, `shieldcortex
worker`, service — nothing enforces a singleton). Correctness under that
reality comes from the **lease**: a projector run first attempts an atomic
compare-and-set on `threat_graph_state.lease_expires_at` inside
`BEGIN IMMEDIATE`; losers no-op until the lease lapses. Combined with
claim-and-advance batches, N processes yield exactly-once projection without
requiring any particular one to be alive — no dashboard dependency, no
double-counting.

**Gateway risk read (new-connection honesty).** The interceptor consulting
`source_risk` at session start would be the gateway's *first-ever* database
access — `initDatabase` is heavyweight (migrations, lock files, pragmas) and
must not run inside the OpenClaw gateway. If Phase D wants this read, it uses
a dedicated read-only helper (`new Database(path, {readonly: true,
fileMustExist: true})`, no init path) with the same guard-and-default-0
contract as the pipeline read, or it asks the local API. Named here so the
trade-off is a decision, not an accident.

## Read paths (the four loops)

### Loop 1 — Per-source history (what "behavioural" honestly means here)

The projector maintains per-source stats on the `source` node's `attrs`
(counts, anomaly mean/variance — incremental, O(1) per row) and distils a
risk score into `source_risk`.

**Risk model.** Exponentially decayed severity sum, normalised to [0, 1]:

```text
risk(t) = 1 - exp( -Σᵢ wᵢ · 2^(-(t - tᵢ)/H) )
```

`wᵢ`: BLOCK 1.0, QUARANTINE 0.5, high-anomaly ALLOW 0.1, `pipeline_error`
rows 0.0. `H` = half-life, default 14 days, configurable. The raw exponent
sum and its reference timestamp live in the source node's `attrs`; the
projector runs an **idle-row sweep** every pass — recomputing decay for *all*
`source_risk` rows (bounded by the 5,000-source cap, trivially cheap) — so a
source that misbehaved and went quiet actually heals on schedule rather than
freezing at peak risk. Accrual is **rate-capped per source** (weight sum
counted per rolling 24 h capped at 2.0): this bounds how fast anyone —
including an attacker burning a *victim's* name — can move a source's risk,
and makes a poisoning campaign take days, not seconds.

**What this is and is not.** This is a decayed penalty ledger of *caught*
events. It is honest per-source memory — repeat offenders stay expensive, and
"this source's block count jumped against its 28-day history" is a projector
fact. It is **not** anomaly detection of successful evasion: a clean ALLOW
accrues nothing, so an attacker who evades the pipeline accrues no risk *by
construction*. The graph never claims to catch what the scanners missed; it
makes what the scanners caught compound. Marketing language must say
"per-source threat history and escalation", not "detects novel attacks over
time". (Weighting the *shape* of ALLOW traffic would be genuine anomaly
detection — and a trainable surface this design deliberately excludes; if
that trade is ever wanted, it gets its own design doc.)

### Loop 2 — Trust scoring enrichment (the only sync touch)

```text
effective_trust = base_trust - min(risk × RISK_TRUST_SCALE, RISK_TRUST_CAP)
```

`RISK_TRUST_SCALE = 0.3`, `RISK_TRUST_CAP = 0.3`. With risk ≤ 1 the cap
cannot currently bind — it is deliberate belt-and-braces so SCALE can be
raised later without silently widening the maximum penalty. A fully-burned
source loses at most 0.3 trust: enough to push a 0.9 agent into the
quarantine band, not enough to make anyone an enemy.

**Placement and failure isolation (hard requirements).** The read lives in
`pipeline.ts` immediately after `scoreSource` — *not* inside
`source-scorer.ts`, which stays pure so the `shieldcortex/scan` entry keeps
its zero-DB import graph (enforced by `scan-only-entry.test.ts`). It is gated
on `isDatabaseInitialized()`, uses a module-cached prepared statement, and is
wrapped in its own try/catch that yields modifier 0 on *any* error. This is
invariant 4 made concrete: the pipeline's outer catch is fail-closed
(`pipeline.ts:311-357`), so an unguarded `SQLITE_BUSY` during a WAL-truncate
checkpoint would otherwise stall a scan 10 s and then BLOCK it — a graph
feature must never be able to do that.

**The spoofed-victim problem (red-team blocker, resolved by gating).** Source
identity is caller-attested (invariant 5). An attacker can emit deliberate
BLOCKs under a *victim's* name — `agent:jarvis` — and additive-only risk
would then depress the real Jarvis's trust with no remediation path. Three
controls close this:

1. **Attestation gate.** The modifier applies only when `source_risk.attested
   = 1` — identity was env-inferred (`env-detector`) or the deployment runs
   `strictSourceMode`. For unattested identities the risk score exists but is
   **annotation-only forever** (shown in audit rows, dashboards, Review
   Copilot — never subtracted from trust). Spoofing a victim's name can then
   embarrass a dashboard, not quarantine the victim's writes.
2. **Accrual rate cap** (Loop 1) — burning a name takes a sustained campaign,
   which is itself a loud, clusterable event stream.
3. **Operator dispute.** `shieldcortex threat-graph reset-source <key>`
   zeroes a source's risk. It is invariant 3's loosening: human-authored,
   single-source, and recorded as an `operation='review'` audit row so
   replay reproduces it. This is the remediation path additive-only systems
   otherwise lack.

Config: `threatGraph.trustModifier: 'off' | 'advisory' | 'enforce'`, default
`advisory` — computed and recorded, not applied. Recording uses a dedicated
nullable `risk_modifier REAL` column on `defence_audit` (routine migration) —
**not** an entry in `threat_indicators`, which is a `string[]` that every
consumer including the cloud ingest parses as such; changing its element
shape would break the dashboard and SaaS shim (the snake_case lesson).
Promotion to default-enforce only on advisory telemetry evidence (we have
never measured our false-positive rate — #182; ghost-risk false positives
from a stale sweep would poison exactly this telemetry, which is why the
idle sweep is mandatory, not optional).

### Loop 3 — Operator allowances (narrow, honest about how narrow)

**Granularity honesty first:** an allowance is keyed (source, pattern), and a
pattern id is a *detector class*, not a payload. "The operator approved this
detector's firings from this source" — that is the true scope, and the doc
and UI must never claim "exactly the content you approved". The controls
below keep that scope from becoming a tunnel.

Allowance creation — ALL conditions required:

- **N = 3 qualifying approvals** of the same (source, pattern) pair within 30
  days, where qualifying means: on **≥ 3 distinct days**, with **materially
  different content hashes** (near-dup approvals count once), and
  **individually reviewed** — bulk `approveQuarantineItemsBySource` approvals
  (`review.ts:195-202`) never count toward allowances; bulk approval is
  triage, not three independent judgements. (This closes the one-click
  approve-farm the red team found.)
- Result: `source —allows→ pattern`, `writer='operator'`,
  `valid_to = now + 30d`.

Allowance consumption:

- **Annotation** (always on): Review Copilot shows allowance state
  *neutrally* — including an explicit divergence warning when the new item's
  content is dissimilar from the approved exemplars, so the annotation
  informs rather than nudges the next approval.
- **Auto-release** (`threatGraph.autoRelease`, default **false**): releases a
  QUARANTINE-severity item only when (a) **every** detection in its complete
  set (`blocked_patterns` ∪ `threat_indicators`) is an active allowance for
  the source, **and (b) its title+content exactly matches an approved
  exemplar** (SHA-256 of title+content — the implementation is exact, not
  fuzzy; any byte change misses and the item stays quarantined). Novel
  payloads tripping the same detector still quarantine. **BLOCK verdicts are
  never auto-released** — the check keys on the resolved verdict, never on the
  shared `quarantine` disposition action. Auto-releases are capped per source
  per day (one row per released item), and every one lands its own
  `auto_release` audit row for after-the-fact review. Implementation notes:
  the exemplar hash binds the title (hashing content alone would admit an
  unreviewed attacker-controlled title on approved content); the detection set
  is the union, not `blocked_patterns` alone (credential/privilege/restricted
  detections surface only as indicators).

Revocation with memory: rejecting an item from an allowed pair sets
`valid_to = now` immediately (one strike) — and the strike is *remembered*:
re-earning a revoked pair requires 2× the approvals over 2× the window, and a
second revocation disables auto-release for that pair permanently
(annotation-only). Without this, one-strike is trivially re-farmed. Noted
honestly: revocation fires *after* an auto-released item was admitted — the
near-dup requirement is what keeps that window to payloads the operator has
effectively already seen; the audit row is what makes it recoverable.

### Loop 4 — Durable taint + campaign detection

**Durable taint.** The 15-minute in-memory taint stays as designed. The graph
adds cross-process, cross-day memory as an *emergent property* of loops 1+2:
gateway detections land in the JSONL ledger (write path 2) → risk rises →
the next session's effective trust is lower (attested sources, enforce mode).
No new mechanism. The optional gateway session-start risk read is a Phase D
decision with the connection caveats already stated.

**Campaign detection** — an async job in the projector's tick family
(self-throttled to ~daily, same pattern as audit retention; also on-demand
via CLI/MCP). Implementation: **JS union-find over one windowed edge query**
(recursive-CTE components in SQLite are painful and slow; union-find over
50k window events × ~4 edges resolves in milliseconds). A component qualifies
when it links events across ≥2 sources or ≥2 sessions. Pivot-quality rules —
without which the feature ships as noise and gets turned off:

- A pattern node whose in-window degree exceeds 10 distinct sources is a
  *hub*, excluded as a connector (everyone trips `credential_exfil`;
  co-tripping it is not a campaign). Equivalently: pivots are
  rarity-weighted, and a component must link through at least one rare
  signal.
- `entity_ref`-only linkage is low-confidence (invariant 5): flagged, scored
  lower, never sole grounds for an alert — attacker text can both
  manufacture shared entities and (via the fuzzy-merge boundary) prevent
  sharing, so entity links corroborate, they don't convict.
- **Alert budget:** campaign alerts coalesce into one digest per run, with a
  per-week cap; campaign-node creation is rate-limited. Alert flooding is an
  operator-attention DoS and a webhook amplification vector; "bounded
  everything" includes alert volume.

**What campaign detection is:** clustering of *caught* events — attribution
("these blocks across three sessions are one actor"), not discovery of quiet
campaigns. A campaign of successful sub-threshold ALLOWs mints no event nodes
and does not cluster (same honesty as Loop 1). What it genuinely adds over
today's fragmentation detector — which is already cross-source *within* its
24 h window but source-blind and window-bound (`temporal-analyzer.ts:28-44`
carries no source column) — is attribution, arbitrary horizons, and coverage
of scan events that never became memories. The flat table stays for the sync
path.

## Policing the memory graph (Phase E — the ShadowMerge defence)

`triples` gains provenance — the temporal-KG convergence point applied
defensively (guarded migration + both schema files, per Schema placement):

```sql
ALTER TABLE triples ADD COLUMN valid_from TEXT;      -- NULL = created_at
ALTER TABLE triples ADD COLUMN valid_to TEXT;        -- NULL = open
ALTER TABLE triples ADD COLUMN writer_source TEXT;   -- source tuple of the memory write
ALTER TABLE triples ADD COLUMN writer_trust REAL;    -- trust at write time, capped (below)
```

(Also: vary `confidence` by extraction rule — verb-pattern 0.8, co-occurrence
0.3 — so consumers can finally discriminate. These columns are absent from
`SyncedGraphTripleRecord`; Phase E explicitly decides drift-vs-SaaS-schema —
see Cloud egress.)

The projector then detects **relation-channel conflicts**: a new edge
(A, p, B) on a single-valued predicate (`uses`, `depends_on`, `configures`,
`replaces` — never `related_to`, which asserts nothing) contradicting an
existing open edge (A, p, C), C ≠ B, across a writer-trust margin (0.3).

**Resolution is symmetric — the red team's first-mover finding reshaped this.**
The first draft auto-suspended the lower-trust newcomer and protected the
established edge. That rule is weaponisable: poison one memory past a naive
operator (admitted at `user:approved`, trust 0.9 — `review.ts:78-82`) and the
poisoned edge becomes the protected incumbent; every later legitimate
correction from an ordinary agent auto-suspends. Trust at write time does not
equal correctness, and recency does not equal attack. So:

- A conflict mints a `conflict` event node and a quarantine-review item
  citing **both** edges with their full provenance (writer, trust, time,
  source memories). **Neither edge is auto-suspended.** Both carry a
  `disputed` flag in the interim, which consumers may down-weight but must
  not treat as invalidation.
- The operator resolves: keep one, keep both (genuinely multi-valued), or
  reject both. The resolution is an `operation='review'` audit row — replay
  reproduces it.
- `writer_trust` is *capped at 0.7* for conflict purposes unless the writing
  source was attested (invariant 5's classes again), and
  quarantine-approved provenance (`user:approved`) is **disqualified from
  counting as the higher-trust side** — approval admits content, it does not
  crown facts.

Escalation stays additive (a conflict can only add review load, never
auto-delete), and the griefing ceiling is bounded: spamming conflicts costs
the attacker memory writes that are themselves scanned, rate-limited (20
writes/min/source), and now clustered by Loop 4.

To my knowledge no shipping product does write-time relation-conflict
detection on agent memory. It is the one research-adjacent piece here, gated
last for exactly that reason.

## Cross-cutting concerns

**Project scoping.** The threat graph is deliberately **global** — sources
span projects and an attacker is an attacker everywhere; cross-project
correlation is the point. Event nodes retain the audit row's `project` in
`attrs`; the query tool takes an optional project filter. (Memories stay
project-scoped; this changes nothing there.)

**Cloud egress.** `threat_nodes`, `threat_edges`, `source_risk`, and
`threat_graph_state` are **local-only, excluded from cloud sync** in this
design — `graph-sync.ts` envelopes are not extended. Two audit-field
additions do egress via the existing metadata-only `/v1/audit/ingest`:
`risk_modifier` (a number) and the session id/taint flags on realtime rows.
Both are metadata, no content — named here explicitly because the v4.29.0
realtime-egress episode taught us that new data classes leaving the machine
must be declared, never discovered. An Enterprise fleet-level threat graph
(same projector over Postgres, cross-device) is the obvious
ShieldCortex-internal extension, out of scope here; per the locked posture,
the local threat graph is free like everything else local.

**Emergency stop.** The new MCP tool ships wrapped exactly like its siblings
— `withKillSwitchGuard('graph', withResponseScan(...))` (`server.ts:742-776`)
— so it goes quiet during an emergency stop and its output is
injection-scanned. The projector *continues* during an emergency stop — a
deliberate decision, stated: it reads ledgers and writes derived tables,
takes no actions, and stopping it would blind the operator's post-incident
view precisely when it matters.

**Doctor.** `shieldcortex doctor` gains a threat-graph check: projector lag
(`max(defence_audit.id) − last_audit_id` plus JSONL cursor age) against a
staleness threshold, `last_error` surfaced, WARN when `source_risk` rows are
older than the sweep budget. Invariant 4's "stale means no modifier" is
fail-safe but *invisible* by construction — the doctor check is what makes a
dead projector a finding instead of a silent regression (the #200/#222
lesson: a check that can only report success is not a check).

**Retention.** Event nodes whose ledger rows age out are deleted by a graph
retention step in the projector tick (same transaction discipline), their
contribution rolled into aggregate edges first — mirroring
`audit_aggregates`, which itself preserves only five global counters and
cannot reconstruct per-source history (which is precisely why the graph does
its own rollup rather than leaning on audit's). Dangling evidence ids
referencing purged audit rows are acceptable — ledger joins are best-effort
forensics, not integrity constraints. Consequence for invariant 1, stated
plainly: a from-zero rebuild after a purge yields *less* risk than the
incrementally-maintained graph (purged events vanish; rebuild grants risk
amnesty beyond the intended half-life). Rebuild therefore seeds each source's
exponent sum from the graph's own pre-purge rollup when present, and the
canonical-dump equivalence test runs within the retention window.

**MCP tool surface (Phase A).** One tool, `threat_graph`, with
`{view: 'sources'|'source'|'campaigns'|'events', key?, project?, since?,
limit?}` — hard row cap (200) and byte cap (256 KB) with an explicit
truncation marker. The unbounded-output bug being fixed in `graph_query`
(Phase 0) does not get reintroduced by its successor.

**Config surface** (all under `threatGraph` in `~/.shieldcortex/config.json`,
following the `actionGuard` block pattern):

| Key | Default | Phase | Meaning |
| --- | --- | --- | --- |
| `enabled` | `true` | A | projector runs; graph populates |
| `trustModifier` | `'advisory'` | B | `off` / `advisory` / `enforce` (enforce requires attested identity per Loop 2). Top-level `strictSourceMode: true` also attests every resolution. |
| `halfLifeDays` | `14` | B | risk decay half-life (constant for now; wired as `halfLifeMs` override) |
| `autoRelease` | `false` | C | allowance auto-release: admit a would-be-quarantined item whose every detection is an active (source,pattern) allowance and whose content near-duplicates an approved exemplar. Per-source per-day capped; fails closed; each release lands a reviewable `auto_release` audit row. |
| `campaignAlerts` | `'digest'` | D | `off` / `digest` / `each` (each still budget-capped) |

Batch size, caps, rate limits are constants, not config — fewer knobs on a
security surface.

## What this design deliberately does NOT do

- **No auto-adjusting detection thresholds.** Outcome-trained thresholds are
  a poisoning vector. Every learning effect is tightening (risk),
  operator-authored (allowances, disputes, conflict resolutions), or
  advisory. Statistical threshold tuning, if ever wanted, ships as a report
  to the operator, never a live control loop.
- **No claim of detecting successful evasion.** Loops 1 and 4 compound and
  attribute what the scanners *caught*. Stated three times in this doc
  because it will be tempting to market otherwise.
- **No LLM or embedding calls anywhere in this design.** The event graph is
  projected from typed data.
- **No graph database dependency.** SQLite at this scale (thousands of
  nodes, bounded by invariant 6) with JS union-find where needed. The audit
  showed our graph problems are emission bugs and data quality, not engine
  limits. Local-first, zero external services, stays a selling point.
- **No hot-path traversal, ever.** A future feature that seems to need it
  gets a new precomputed column instead.
- **No fleet/cloud graph in this phase** (see Cloud egress).

## Honest limits

- **Source identity is claimed, not proven.** Everything keyed on source
  tuples inherits that (invariant 5). The attestation gate confines the
  *enforcement* consequences to identities the system inferred itself; the
  spoofing residue is dashboard noise plus operator-resettable risk, and a
  local attacker with process control has already won bigger prizes.
- **Identity rotation resets per-source risk.** Mitigated, not solved: the
  source-cap overflow bucket and the new-source mint-rate event make bulk
  rotation loud, and campaign detection can link rotated identities through
  shared patterns — but a patient, fully-randomised, sub-threshold attacker
  looks like background noise to this and every behavioural system.
- **The graph learns only where scanning happens and only what scanning
  catches.** Dropped hooks, the OpenClaw consent gate, threats-only audit
  paths, and successful evasions all leave holes. The graph makes several of
  them *visible* (flatlined counters, missing denominators — surfaced by
  doctor) but cannot fill them.
- **Advisory soak is mandatory.** False-positive rate is unmeasured (#182).
  Nothing here moves from advisory to enforce without fleet telemetry, and
  the telemetry is only trustworthy because the idle sweep keeps risk fresh.

## Implementation phases

Phase 0 is the audit's bug-fix list and precedes everything (emission dedup
in `graph_query`, the `'project'`-stopword triple drop, junk-entity filters,
`prepare()` hoisting, `LOWER(name)` index defeat, file-type fuzzy-merge). It
ships independently as a patch release.

| Phase | Scope | Depends on |
| --- | --- | --- |
| **A** | Schema (three-file placement) + projector (light tick, both profiles, lease) + JSONL cursor + rebuild/backfill CLI + `threat_graph` MCP tool (capped, guarded) + doctor check. Dashboard: read-only sources/events table only — the CIC threat-graph view gets its own design pass | Phase 0 |
| **B** | `source_risk` + idle sweep + attestation flag + `risk_modifier` audit column + trust modifier (advisory) + reset-source CLI | A |
| **C** | Operator loop: `operation='review'` rows (+ `AuditOperation` union), decision events with approval/re-admission pairing, allowances (distinctness rules, near-dup exemplar matching, strike memory), Review Copilot annotations | A |
| **D** | Campaign detection (union-find, pivot rules, digest budget) + gateway JSONL session/taint fields + optional gateway session-start risk read (read-only helper) | A, B |
| **E** | `triples` provenance (guarded migration) + per-rule confidence + symmetric conflict detection + `writer_trust` caps | A; Phase 0 extractor fixes |

Each phase is independently shippable; A alone turns retained audit history
into a queryable threat graph on day one.

**Testing.** Projector determinism = canonical-dump equality across replays
(not file bytes). Crash-safety: terminate mid-batch, restart, dump-diff.
Lease: two concurrent projectors, assert disjoint batch ranges and no
double-counted aggregates. Volume: synthetic 100k-row replay within caps and
time budget. Hot path: fault-injection on the `source_risk` read (locked DB,
missing table, corrupt row) must yield modifier 0 and an unblocked scan —
this test is the enforcement of invariant 4. All ordinary unit tests: decay
takes `now` as a parameter, no network, no LLM.

## Phase B implementation notes (pre-B architecture audit, 2026-08-11)

A four-lens audit of the shipped Phase A stack pinned these decisions so B is
built on facts, not the doc's assumptions. They amend the sections above.

1. **Attestation must be plumbed — it does not exist in the ledger.**
   `resolveToolSource` computes the inferred/declared/clamped metadata and
   discards it before the pipeline runs; no audit column records it, and a
   cleanly-declared source leaves no trace. B therefore ships: (a)
   `resolveToolSource` returns `{ source, attested }` — attested is
   deliberately NOT a field on `DefenceSource`, which is caller-suppliable
   through scan-only/SDK surfaces and would let integrators self-attest;
   (b) a nullable `source_attested INTEGER` guarded-ALTER on `defence_audit`
   (alongside `risk_modifier` — two ALTERs); (c) an explicit egress
   declaration for both new columns (the v4.29.0 rule). The projector reads
   attestation per-row from the ledger — never from live config, which would
   break replay determinism.
2. **`strictSourceMode` is currently unwired** — defined in `DefenceConfig`,
   consumed nowhere on the live tool path. B must wire it into
   `resolveToolSource` (strict ⇒ every resolution attested) before
   implementing the doc's attested definition, or that half is silently
   always-false.
3. **Rebuild seeding.** `clearGraph()` now clears `source_risk` too (ghost
   risk keyed to a dead projection must not survive a rebuild). Because a
   replay over a retention-purged ledger yields lower sums, B's rebuild path
   snapshots `{source_key → exponent sum, ref_ts}` from source-node attrs
   before clearing and re-seeds after replay, with a test asserting
   rebuild-after-purge never lowers a source's risk below its decayed
   pre-rebuild value. The raw sum lives in source-node `attrs`
   (ledger-time-normalised — it is replay state and sits inside the
   canonicalDump determinism contract); decayed output lives in
   `source_risk` (wall-clock-relative, outside the contract).
4. **28-day windowed counters need a query path.** They cannot come from the
   graph (ALLOW rows mint no events) or from monotonic counters. B adds a
   guarded composite index `idx_audit_source_ident_ts ON defence_audit
   (source_type, source_identifier, timestamp)` and computes the window in
   the idle sweep with one range query per pass.
5. **Hot-path read mechanics.** The pipeline's `source_risk` lookup uses the
   shared `sourceKey()` helper (`threat-graph/keys.ts`, deliberately DB-free
   so pipeline code can import it) — identical normalisation to the
   projector or long identifiers silently read no row. The prepared
   statement is cached **keyed on the Database instance** (init.ts closes
   and reopens the handle on recovery; a naive once-cache would throw into
   the fail-to-zero guard and silently disable the modifier until restart —
   the exact invisible-off state invariant 4 warns about). Overflow-bucket
   sources have no per-key risk row and read modifier 0 by construction.
6. **`operation='review'` rows** (reset-source, Phase C decisions) are
   excluded from counters and risk accrual when B rewrites the projector's
   SELECT — operator actions are not scans.
7. **Custom-pattern identity**: B's pipeline diff adds `custom:<id>` to
   `blocked_patterns` when local custom patterns fire (today they land only
   in free-text reason, invisible to the graph). Cloud-synced patterns keyed
   `custom:<category>` need a SaaS payload change — tracked for Phase C prep.
8. **Realtime rows accrue no risk in B** (no verdict field; pooled
   unattested identities are enforcement-inert anyway) — weights for
   conversation detections are decided in Phase D with campaign detection.

## Phase D — implementation notes (2026-08-12 review)

Campaign detection landed after a three-lens review. Deviations and deferrals,
pinned so they are decisions not surprises:

- **Hub exclusion applies to ALL three axes, not just patterns.** The spec
  named pattern hubs; the review found that source and session pivots with no
  cap collapse pooled/non-attributable identities into giant false campaigns —
  in particular `conversation:<hook>` (every conversation detection on a hook)
  and the `overflow` bucket. A pivot linking ≥ `hubThreshold` (10) distinct
  counterparties, or a pooled source key (`overflow` / `conversation:*`), is
  excluded as a connector. The boundary is inclusive (`≥`). Consequence:
  conversation events do not currently form cross-session campaigns — the
  realtime rows carry no cross-session actor identity, and the design's honest
  limits already concede that. The session/taint plumbing is forward-ready.
- **Alert budget is DEFERRED — Phase D is detection-only.** The digest +
  per-week cap and the `threatGraph.campaignAlerts` config key are not wired;
  nothing emits alerts, so there is no flooding surface. Any future
  dashboard/webhook consumer of campaign nodes MUST land the per-week cap +
  digest first. Campaign truncation past the per-run cap is recorded in
  `last_error` and ranked by breadth (not oldest-anchored) so a real campaign
  is never silently dropped for noise.
- **Determinism.** Campaign nodes + `part_of` edges are a wall-clock-relative
  derived layer (like `source_risk`), recomputed each throttled run and
  EXCLUDED from the canonicalDump contract. Detection runs in the lease runner,
  never in `projectToCompletion`/`rebuildThreatGraph`. `clearGraph` resets the
  throttle so a rebuild re-mints on the next tick. `PROJECTOR_VERSION` → 4 for
  the realtime `tainted` attr.

## Phase B — known limits and pre-enforce items (2026-08-12 review)

The B implementation was adversarially reviewed (3 lenses). Two majors were
fixed and are now the design of record: **risk accrues only from attested
rows** (an unattested spoof under a victim's name can never enter the sum the
enforced modifier consumes — the earlier "read gate only" was insufficient),
and the **rate window tumbles forward only** (a descending-timestamp burst,
e.g. a backward clock step, no longer re-arms the cap). The operator reset is
**ledger-reproducible**: it writes a structured `risk_reset` review row the
projector consumes on replay, so a rebuild reproduces the dispute. These
carry a `PROJECTOR_VERSION` bump (1 → 2), so A→B upgrades rebuild and backfill
risk from retained history.

Deferred, tracked here so they are decisions not surprises:

- **Enforce-mode × sub-agent hold band.** Subtracting the modifier can move a
  clean-content score into or through the [0.5, 0.7) sub-agent quarantine
  band non-monotonically (a larger penalty can land *below* the band). This is
  inert under the `advisory` default (modifier recorded, not applied). Before
  promoting any deployment to `enforce`, decide the intended interaction —
  most likely: an enforce-applied modifier marks the source at-least-quarantine
  at the disposition layer regardless of the resulting score. Do not promote
  to enforce until this is resolved and the advisory soak has FP data (#182).
- **>200-char identifier collision.** Two distinct identifiers sharing a
  200-char prefix collide onto one source node (merged risk sum; counters and
  attestation from the last-projected full id). Bounded and rare (deep agent
  hierarchies); accepted for B. A later phase can disambiguate by appending a
  short hash of the full identifier when length exceeds the cap.
- **Cold-start honesty.** On A→B upgrade the rebuild backfills the enforcement
  sum only from rows carrying `source_attested = 1`; historical rows predating
  the attestation plumbing (NULL) contribute counters but not enforced risk.
  Enforced risk therefore builds forward from attested writes — the annotation
  counters still reflect full history.

## Open questions

1. **Half-life and accrual-cap defaults** (14 d / 2.0-per-24 h) — shapes are
   right, numbers are guesses; advisory telemetry decides.
2. **Allowance thresholds** (3 approvals / 3 days / 30-day TTL / 2× re-earn) —
   same treatment.
3. **CIC threat-graph view** — the most CIC-shaped data the product has;
   deliberately deferred to its own design pass against the
   dashboard-cleanup work.
4. **Does recall ranking consult `disputed` flags after Phase E?** Attractive
   (down-weight memories whose edges are under dispute), but it couples
   recall to defence state — decide after E ships and the dispute workflow
   has real usage.
