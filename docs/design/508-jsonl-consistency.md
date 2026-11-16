# #508 JSONL consistency design repair (proposal only)

Refs #508; never closes it. Responds to TARS review [13 October](https://github.com/Drakon-Systems-Ltd/ShieldCortex/issues/508#issuecomment-6139083060).
Source baseline: freshly fetched origin/main `56fcc32d`. No implementation approval,
public capability change, runtime safety claim, or executed acceptance tests.
Memory-row authenticity acceptance remains **OPEN in #508**. Chaining defence_audit
is not memory authenticity. #579 retention freeze: NO REBUILD / NO AUDIT DELETION
on this box. No migration, repair, pruning or rewriting existing audit records.

## 1. Writer and delivery contract

Source citations below are paths and exact lines at the baseline above. Inventory
contains **eight append sites**, including the newer session-guard digest mirror:

| Source | Delivery boundary |
|---|---|
| scripts/pre-tool-hook.mjs:3228 | standalone Node hook |
| scripts/stop-hook.mjs:864 | standalone Node summary hook |
| plugins/openclaw/interceptor.ts:1501 | OpenClaw plugin bundle |
| plugins/openclaw/index.ts:2631 | second OpenClaw bundle append |
| plugins/hermes/shieldcortex/__init__.py:93–95 | Python degraded-gate writer, not sc_client.py |
| src/defence/iron-dome/session-guard.ts:230 | TypeScript session guard |
| src/defence/iron-dome/session-guard.ts:429 | TypeScript digest realtime mirror |
| src/defence/iron-dome/guard-readiness.ts:671 | TypeScript readiness writer |

Future implementation must route these through one versioned contract: TS shared
module, standalone distributable ESM helper included alongside both packaged hooks,
and bundled copy for both OpenClaw paths. Python requires a native implementation
of the identical contract; importing the Node source is not a deployment strategy.
Packaging inclusion and installed-bundle parity remain UNKNOWN until implementation
validation. package.json:186,188 presently lists the standalone hooks.

Planned exclusions: zero of these eight sites. Present design-only change leaves
all eight unchanged; no claimed new coverage. Any unavailable helper/version skew,
canonicalization failure or lock timeout emits explicitly unchained coverage with
reason when the existing safe append permits it, otherwise preserves audit-write
failure reporting. Never replace no-follow/identity checks with ordinary append.
Keep side-stream session-guard index receipts distinct from realtime mirrors.
Additional writer completeness beyond the searched src/plugins/scripts tree is UNKNOWN.

## 2. Exact hash and shared-vector contract

Payload P is the complete stored JSON object excluding only the reserved `chain`
member; reject caller-supplied chain. Preserve top-level binding seq and every other
stored field. Normalize optional undefined object properties by omission BEFORE
storage, as current JSON serialization does; array undefined becomes null. Reject
nonfinite numbers, bigint, cycles and unsupported objects, rather than silently
coercing them. Canonicalize the normalized stored object, not the caller object.

Use canonicalJson rules (src/defence/ledger/canonical.ts:15–25,47–77): UTF-16
key ordering, JSON string escaping, UTF-8 bytes, finite IEEE-754 doubles with
ECMAScript shortest-roundtrip formatting, negative zero as 0. Python must implement
these rules, not use its default dumps numeric/key ordering. Reject duplicate keys
and lone surrogates in chain-bearing input; do not Unicode-normalize strings.

chain = {v:1, day, segment, seq, prev, predecessor, h}; day is UTC YYYY-MM-DD,
segment is random 128-bit lowercase hex, seq is a safe nonnegative integer starting
at zero per segment, prev is 64 lowercase hex. predecessor is null or
{day,segment,seq,h}. h = SHA256(UTF8("sc-jsonl-v1\n" + canonicalJson({payload:P,
v:1,day,segment,seq,prev,predecessor}))). Thus metadata and payload are covered;
chain.seq never substitutes for payload.seq. Genesis uses 64 zeroes and null
predecessor; a linked new segment uses predecessor.h as prev.

One future checked-in language-neutral JSON vector manifest is normative: each
case contains input JSON, normalized payload, exact canonical UTF-8 hex, full hash
preimage hex, expected lowercase SHA256, or expected rejection reason. Both Python
and Node consume the same manifest, including standalone/bundled artifacts. Cases:
key permutation, nested arrays, optional fields, payload seq, -0, 1e-7/1e21,
non-ASCII and supplementary keys, escaping, surrogate rejection, safe-integer
limits, metadata changes and malformed values. Independently checked expected
bytes/hashes are required; generating expectations with the implementation under
test is insufficient. Vectors are specified, NOT created or run in this docs PR.

## 3. Genesis, restart and day boundaries

Under the shared directory lock, sample UTC day once; event timestamp stays payload
metadata. Append to that chosen day even if the clock crosses midnight afterwards.
For same-day restart recover last complete valid chained row within bounded tail
read (1 MiB maximum); continue its segment only when the remaining suffix is empty.
Unchained suffix starts a new segment with an explicit coverage break. Lookup the
nearest earlier retained eligible day within the verifier budgets below; do not
assume yesterday exists. Record exact predecessor identity, not only a digest.
Legacy-only/missing/inaccessible predecessor means unanchored genesis plus explicit
reason, never proof of tampering. First-ever genesis is indistinguishable from lost
history without an external anchor. Retained predecessor mismatch is inconsistent;
missing predecessor is incomplete. Restart after budget exhaustion is unanchored.

Never truncate a torn tail or insert a newline to repair it. Decline chained append
to that file and report sink unavailable; any existing fallback that appends there
is unprotected and cannot regain verified status. No rewrite/reordering: consumers'
file/line identities must remain stable. Whole-record tail truncation may leave a
consistent observed prefix; torn partial records are separately reported incomplete.

## 4. Mixed coverage and CLI outcomes

Proposed ledger verify --jsonl combines DB and JSONL; --jsonl-only isolates JSONL.
Report counts and file/line ranges for chained, unchained, torn, restarted/unanchored,
skipped and unavailable records. Segment consistency is separate from scan coverage.
Never label a whole mixed file verified because one segment matches. No data is
unavailable coverage, not proof that no events occurred. Text and JSON always say:
“Internal consistency only, NOT authenticity or completeness. Whole-chain rewriting,
whole-record tail truncation and unchained data are not authenticated or excluded.”

Exit 1 if any observed inconsistency; else 2 if incomplete/unavailable/unchained
coverage or scan limits; else 0 for fully scanned selected consistent chains, still
subject to the limits statement. Combined mode uses that precedence across both
planes; include each plane's independent result. Unsupported chain version =
unavailable, not a successful legacy verification. Memory-row authenticity remains
outside both results and OPEN in #508.

## 5. Lock ownership, races and failures

Exclusive create on a fixed no-follow lock path; owner record binds random token,
host/boot identity, PID, process-start identity and namespace. Bound acquisition
wait to 250 ms. Check lock file identity and token before release. Age alone NEVER
permits stealing; PID absence in another namespace is not proof of death. Default
v1 performs NO automatic stale-lock reaping: timeout gives explicit unchained
fallback or sink failure, not a competing chained writer. Any future recovery
requires a separately reviewed atomic ownership protocol, not check-then-unlink.
No assertion of “cannot fork”: verifier detects duplicate segment sequence,
competing successors, and predecessor/hash disagreement among observed rows.
Non-cooperating writers remain visible as unchained or malformed coverage.

## 6. Bounded read-only verification and proposed acceptance

Allow only exact realtime-YYYY-MM-DD.jsonl names under one selected audit directory.
Reject symlink directory components; hold verified directory identity. Open regular
files with no-follow/nonblocking semantics, then fstat and compare identity with
selection metadata. Refuse FIFO/device/socket/directory inputs before any read.
Never follow links or read outside the selected plane. Unsupported platform safety
primitives => unavailable, not permissive fallback. Detect identity/size/mtime changes
and report unstable/incomplete; never claim snapshot consistency during concurrent
writes. No locks, repairs, config changes, DB writes or audit mutation by verifier.

Default hard bounds: 366 files, 16 MiB/file, 64 MiB total including predecessor reads,
1 MiB/line, 100,000 lines, 5 seconds monotonic scan budget, 64 nesting levels.
Stop before exceeding any budget and report exact limit plus examined/unexamined
coverage. No implicit unbounded override. Inaccessible predecessors remain incomplete.

Implementation acceptance, NOT RUN: changed outcome and deleted middle row;
retained day-link mismatch versus missing predecessor; genesis/restart and legacy
mixed suffix; whole-record truncation versus partial torn tail; actual multiprocess
writers, timeout, competing recovery attempts (neither steals), midnight rollover;
shared Python/Node/bundle vectors; unavailable helper and canonicalization rejection;
symlink/FIFO/device/oversize/identity-race bounds; unchanged existing consumers and
file/line identities; read-only verifier and combined exit precedence. Tests are
not applicable to this design-only milestone; implementation proof remains UNKNOWN.

## Single findings disposition checklist

- [x] Fixed in proposed design: eight-site inventory and delivery boundaries (§1).
- [x] Fixed in proposed design: canonical stored payload and shared vectors (§2).
- [x] Fixed in proposed design: restart/daylink/legacy/torn-tail semantics (§3).
- [x] Fixed in proposed design: explicit partial coverage and no authenticity (§4).
- [x] Fixed in proposed design: no age-only stealing; ownership/fork limits (§5).
- [x] Fixed in proposed design: bounded no-follow read-only verification (§6).
- [ ] Carried to rolling #1075 AFTER merge only: implementation evidence for these
  six design contracts, bundle parity and complete writer discovery. No carry write
  is claimed by this draft. Memory authenticity remains OPEN in #508, no new issue.
