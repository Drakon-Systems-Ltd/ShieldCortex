# Dashboard v2 — second-model review of the BUILT result (13 Sep 2026)

Reviewers: Grok 4.6 (fetched branch from GitHub; graph.ts paths handler and MemoryGraph JSX not fully read) and GPT-6 Astra (inline source: graph.ts, transforms.ts, read-guard diff, final report, §13/§14). Consolidated by Jarvis with one own finding. Items are numbered for the fix round; each must be closed with code + test or explicitly disclosed in §14.

## A. Blocking

1. **`/api/graph/paths` + `useGraphPath` — no project scope** (GPT A1, Grok A2, Jarvis). Route ignores `project`; hook never sends it; query key omits it. Endpoint resolution, BFS hops and `sourceMemories` titles cross projects. Fix: accept `?project=`; scope endpoint resolution (incl. self-path), every traversal candidate and the source-memory lookup with the same `memory_entities→memories.project` rule; hook passes project and includes it in the key; clear selection on scope change; route test with an out-of-scope bridge entity.
2. **Neighbourhood focal bypasses scope** (GPT A2, Grok B). Focal lookup is unconditional; an out-of-project focal's name/aliases and edges appear. Fix: when `project` is set, 404 a focal with no in-scope memory. `/entities/:id/triples` and `/triples` also ignore project — add optional `?project=` with the both-endpoints rule (additive).
3. **Boundedness/parsing gaps** (GPT A3, Grok C). `:id` via `parseInt` accepts `12junk`; `/entities/:id/triples` has no LIMIT or deterministic tie-break; `neighboursOf.all()` materialises every candidate before the cap; BFS bounds depth (4) but not breadth/work; a non-string `project` (array) silently drops the filter. Fix: one strict positive safe-integer id parser for every `:id`/`fromId`/`toId`; SQL LIMIT + `ORDER BY … , t.id DESC` on the triples listing; LIMIT in `neighboursOf`; BFS visit budget with a `truncated: true` flag in the response; 400 on malformed supplied `project`. `boundedInt` comment overclaims (negatives clamp to min, they do not fall back to default) — align comment and add value-asserting tests.
4. **Path mode cannot draw a path through an omitted entity** (GPT A4). Path mode only highlights within the filtered/capped overview set. Fix: build the path subgraph from the `/paths` response itself (`entityId`, `predicate`, `direction` per hop), merge it into `graphData` with preserved positions, so every hop is always on the canvas.
5. **Overview false reassurance** (GPT A5, Grok B). Loading/failed queues render "Nothing pending. All queues are clear"; loading audit renders "No gated operations recorded"; write-firewall pill is `permissive → warn else ok` and ignores `tampered`; "enforced (permissive)" wording; FirstRunGuide receives `?? 0` on failed fetch; licence/update errors never become `unavailable`. Fix: derive every row/text/colour from the query status (`pending` / `unavailable` / `stale (refetch failed)` / confirmed) via one helper; `tampered` is never green; label permissive honestly.
6. **"Show memories" toggle lies in Map** (Grok A1). Defaults true but Map never draws memories. Fix: hidden/disabled in Map with copy "double-click an entity to see its memories", default off; enabled in Focus.

## B. Should-fix

7. **`deepRedactRestrictedContent`** (GPT B). (a) Date passthrough: normalise to `new Date(value.getTime())` so decorated Dates / subclasses with custom `toJSON` cannot carry data; test decorated, subclassed and invalid Dates. (b) **Pre-existing aliasing bypass:** `seen.has(value) → return value` returns the ORIGINAL unredacted object on its second occurrence (`{a: restricted, b: restricted}` exposes `b`). Replace the WeakSet with a WeakMap original→sanitised copy; add the regression test. (c) Map/Set/Buffer/typed arrays: define handling explicitly (Map/Set → plain array/object then redacted; Buffer/typed arrays passed through) with a test.
8. **Drawer without Focus** (Grok C, GPT): selecting a node shows an empty related/memories section until Focus. Fetch depth-1 neighbourhood with `includeMemories` on select so the drawer is useful immediately.
9. **Truncation notice** blames min-mentions when type chips hid nodes — split "hidden by type" vs "below threshold" (Grok B).
10. **Overview graph preview** skips `computeDefaultMinMentions` (minMentions=1, limit 150) — apply the same rule (Grok B).
11. **`.pulse-cyan` / `.pulse-coral` still loop** in globals.css — remove; nothing loops (Grok B, brief §5).
12. **Missing §6.3/§7 items** (Grok B): right-click / long-press context menu (focus, path from here, hide type, copy id); memory created-date range filter in Focus; conversation-scanning row on the Overview protection tile. Implement or disclose in §14 with reason.
13. **Legacy contract note**: neighbourhood now caps all neighbours (default 50) — document in CHANGELOG as a behaviour change with the `limit` param (Grok B).

## C. Claims not supported (fix the record)

14. Final report and PR body say **16** tests in `graph-v2-routes.test.ts`; the file has **11** `it(...)`. Correct both, and re-state every number after the fix round from a fresh run.
15. Second builder (steps 5–7) ran on **claude-sonnet-5** after a pool fallback, not Fable; record in the final report.

## D. Verdicts
Grok: APPROVE_WITH_CHANGES. GPT-6: APPROVE_WITH_CHANGES (5 blocking). Jarvis: same — nothing here contradicts the design; all are scoping, honesty and hardening gaps.

## E. Fix-round status (13 Sep 2026, Fable 5.1)

Commits on `feat/dashboard-v2-ux` above `d0214880`: `8ba93ca8` (items 1–3), `19c45cc2` (4, 6, 8–12), `eda53d0b` (5), `7f41183e` (7), and the docs commit carrying this section (13–15). Verification numbers: `dashboard-v2-final-report.md` → *Fix round (review)*.

| # | Status | Where |
|---|---|---|
| 1 | **FIXED** `8ba93ca8` | `/paths` scoped end-to-end (route + `useGraphPath` + query key); selection/focus/path cleared on scope change; route test with an out-of-scope bridge entity |
| 2 | **FIXED** `8ba93ca8` | out-of-scope focal → 404; optional `?project=` (both-endpoints rule) on `/entities/:id/triples` and `/triples` |
| 3 | **FIXED** `8ba93ca8` | `parseId` for every `:id`/`fromId`/`toId`; `LIMIT` + `ORDER BY created_at DESC, id DESC` on entity triples; SQL `LIMIT` in `neighboursOf` with a separate honest `COUNT`; BFS visit budget (2000) + fan-out cap (500) + `truncated`; malformed `project` → 400; `boundedInt` comment aligned + value-asserting tests |
| 4 | **FIXED** `19c45cc2` | `buildPathData` merges every hop (hops now carry real `entityType`/`memoryCount`/`confidence`/`disputed`) into the Map data with preserved positions |
| 5 | **FIXED** `eda53d0b` | `lib/query-status.ts` (pending / unavailable / stale / confirmed) drives every row, count and pill; `tampered` never green; permissive labelled advisory; FirstRunGuide gated on confirmed data; licence/update errors → unavailable; 12 unit tests |
| 6 | **FIXED** `19c45cc2` | default off; Map copy "double-click an entity to see its memories"; toggle only in Focus |
| 7 | **FIXED** `7f41183e` | Date normalisation; WeakMap original→copy (aliasing bypass closed); explicit Map/Set/binary handling; 4 regression tests |
| 8 | **FIXED** `19c45cc2` | depth-1 `includeMemories` fetch on select; drawer shows loading/unavailable instead of "Focus this entity" |
| 9 | **FIXED** `19c45cc2` | `hiddenBreakdown` splits "hidden by type" from "below min mentions" |
| 10 | **FIXED** `19c45cc2` | preview shares the 400-entity payload and applies `computeDefaultMinMentions` |
| 11 | **FIXED** `19c45cc2` | `.pulse-cyan`/`.pulse-coral`/`pulseGlow` removed (no usages) |
| 12 | **FIXED** (context menu `19c45cc2`; conversation-scanning row `eda53d0b`) / **DISCLOSED** (date-range filter → brief §14.a-10; scanning-row derivation → §14.a-11) | |
| 13 | **FIXED** (docs commit) | CHANGELOG *Changed*: neighbourhood cap with `limit`, plus the other legacy-route hardening |
| 14 | **FIXED** (docs commit) | final report corrected (11 at `d0214880`, 21 now) with fresh numbers from a clean run; PR #491 body **not** edited — external write outside this round's authorisation (see final report → *Not done*) |
| 15 | **FIXED** (docs commit) | final report records the steps 5–7 builder ran on `claude-sonnet-5` after a pool fallback |

Also fixed outside the 15 items, because the full root suite had to be green to push: `src/__tests__/upgrading-5-notice.test.ts` asserted the CHANGELOG Unreleased section still read "(none yet)" — already failing at `d0214880` (brief §14.a-14).
