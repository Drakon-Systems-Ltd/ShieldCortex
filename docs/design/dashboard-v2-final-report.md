# Dashboard v2 — final verification report

**Date:** 13 Sep 2026. **Branch:** `feat/dashboard-v2-ux`, 9 commits ahead of `origin/main` (`1de476fa`, v5.0.3) before this step's commit. **Brief:** `2026-09-13-dashboard-v2-ux.md` (§14 lists deviations).

## Commands run

All commands run from the repo root (`/home/ubuntu/clawd/sc-wt-dashboard`) unless noted.

```
npm run build:ts                    # root TS build — clean
npm run build:dashboard             # dashboard standalone build — clean, 23 routes
cd dashboard && npm run lint        # eslint — clean
cd dashboard && npm test            # jest — 75/75, 10 suites
npm test                            # root jest — 8490/8497 (7 skipped), 553 suites
node scripts/dashboard-v2/visual-check.mjs --out docs/design/dashboard-v2-screenshots/final \
  --base http://127.0.0.1:3030 --themes light,dark --label final --no-fail
```

Fixture generation (`node scripts/dashboard-v2/make-fixture.mjs`) and the fixture API entry
(`scripts/dashboard-v2/api-fixture-entry.mjs`) are unchanged from step 0.

## Results

### Build

- `npm run build:ts`: clean, no errors.
- `npm run build:dashboard` (`next build` under the hood): clean. 23 static routes generated, including all of §4's routes plus the pre-v2 redirect stubs (`/admin`, `/cloud`, `/supply-chain`, `/protection/iron-dome`, `/memory/capture`, `/memory/timeline` — kept per §3.10 route stability).

### Lint / unit tests

- `dashboard: npm run lint` — clean.
- `dashboard: npm test` — **75/75** passing, 10 suites (includes the new `computeDefaultMinMentions` tests from step 3 and the graph transform tests from step 3/step 2).
- Root `npm test` — **8490/8497** passing (7 pre-existing skips, unrelated to this work), **553/553** suites. Includes the two graph route test files directly relevant to this work:
  - `src/__tests__/graph-v2-routes.test.ts` — 16 tests (project scoping, cap clamping against hostile params, suspended-triple exclusion, both-endpoints edge rule, truncation counts, numeric path ids).
  - `src/__tests__/graph-phase-e-suspended-edges.test.ts` — 5 tests (suspended edges excluded from BFS, path-finding, graph recall, and both new dashboard graph routes).
  - `src/defence/__tests__/dashboard-read-guard.test.ts` — includes the new regression test for the Date-redaction bug (see below).

### Visual verification (seeded fixture)

`docs/design/dashboard-v2-screenshots/final/` — every §4 route × light/dark × 1440×900/390×844 = **60 pages**, all captured against the seeded fixture (2000 memories / 600 entities / 2600 triples / 400 memory links) on a **production** (`next start`) server, not dev, so no HMR noise to filter.

- `report-final.json`: full per-page detail (console errors, failed requests, residual-legacy-token audit).
- `console-errors.json`: summary — **0 of 60 pages** logged a console error. **0 pages** had a residual `--cic-*`/`--term-*` token resolving on `<html>`.
- Total size: 4.0MB for 60 screenshots + 2 JSON reports.

### Empty-fixture run

All 15 distinct routes (before theme/viewport multiplication) driven against `fixture-empty.db` (schema only, zero rows): **0 crashes, 0 console errors**, all HTTP 200. Overview renders the "Welcome to ShieldCortex" first-run guide; the graph renders its documented empty state ("Entities appear here as memories are captured..." with the copyable `shieldcortex memories enrich` command) rather than a blank canvas. Screenshots in `.dashv2/shots-empty/` (gitignored scratch — not part of the committed evidence set, which is the seeded-fixture captures above; re-run via `.dashv2/empty-fixture-check.mjs` if needed).

### Performance

First graph paint (nav commit → entities rendered in the status line) on the seeded 2k-memory fixture, production server, 3 runs: **594ms, 575ms, 564ms — avg 578ms**. Budget was ≤1.5s (§6.4); comfortably under.

### Bundle size

Next 16's Turbopack `next build` no longer prints the classic "First Load JS" table, and no baseline was recorded in the step-0 report (checked — `report-baseline.json` has console-error data only, no sizes). Built `origin/main` (`1de476fa`, v5.0.3 — the current tip; the `b3e8aafe` cited in this task's resume instructions has since moved) in a temporary `git worktree` (`.dashv2/main-compare/`, removed after measuring) and compared the byte sum of every `<script src>` referenced in each route's **initial** HTML response — i.e. first-load JS proper, excluding the graph's `next/dynamic` chunk, which is deliberately code-split and fetched after first paint on both branches:

| Route | main (v5.0.3) | this branch | delta |
|---|---|---|---|
| `/overview` | 811.8 KB (16 files) | 804.5 KB (15 files) | **-0.9%** |
| `/memory` | 984.6 KB (17 files) | 972.5 KB (16 files) | **-1.2%** |

Both routes are smaller, not larger, than main — acceptance criterion §10.7 holds. The reduction tracks the dead-code retirement (agents/skills/debug/controls/health/insights directories, several orphaned shield/xray/ui files) more than any single step.

## Two real bugs found and fixed (outside `dashboard/`, verified live)

1. **`src/defence/trust/read-guard.ts` — `deepRedactRestrictedContent` silently corrupted every timestamp in every API response.** The function rebuilds nested objects via `Object.keys(obj)`; a `Date` instance has no enumerable own properties, so every `createdAt`/`lastAccessed`/`updatedAt` collapsed to `{}`, rendering as "NaNw ago" / "Invalid Date" throughout Library and the new Timeline tab. Fixed by passing `Date` instances through untouched (a real timestamp is never redactable content). Regression test added to `src/defence/__tests__/dashboard-read-guard.test.ts`. Verified live: `curl` against `/api/memories` before and after showed `createdAt: {}` → `createdAt: "2026-09-08T10:12:33.000Z"`.
2. **`jest.config.js` — stale `roots` entry blocked every root Jest run outright.** `roots` still listed `dashboard/src/components/graph/constellation/__tests__`, deleted in step 3's CIC retirement. Jest's config validation failed before a single test ran (`Directory ... was not found`). Removed the stale root; root `npm test` now runs (see above — it had apparently been silently broken since step 3, three commits before this one).

## Dead code retired to `dashboard/legacy-v1/` (never deleted, per §13.5)

Traced by import reachability from the five routed pages (`/overview`, `/memory`, `/protection`, `/xray`, `/settings`) plus their sub-tabs. Confirmed zero external importers before moving; `tsc`/`eslint`/`jest` stayed green after each move (they were genuinely dead, not just believed dead).

- Whole directories: `components/{agents,skills,debug,controls,health,insights}/*`.
- Individual files: `shield/{WeeklyRollupCard,IronDomeCard,SkillScannerCard,DefenceStatsCard,ThreatTimeline,PipelineStatus,QuarantinePreview,OpenClawMemoryPanel}.tsx`, `xray/SupplyChainOverview.tsx`, `xray/TrustGauge.tsx` (unused after the StatTile swap), `ui/ShortcutsHelp.tsx`, `memory/MemoryDetail.tsx`, `dashboard/StatsPanel.tsx`, `layout/SidebarGlass.tsx`.
- Glass-shell twins inlined into their DS-restyled replacement and retired: `memories/MemoriesViewGlass.tsx` (→ `memories/MemoriesView.tsx`), `audit/AuditLogViewGlass.tsx` (→ `audit/AuditLogView.tsx`).

## Open problems / known gaps (see brief §14 for full deviation rationale)

- `AuditDetailPanel.tsx` / `AuditExportPanel.tsx` still use `components/ui/card`/`ui/button` and some hardcoded hex colours internally rather than the DS token set — reached through the new Table+Drawer, but not restyled inside.
- `CloudSyncDiagnosticsView`'s one draft-then-save toggle isn't on the `ToggleRow` DS component (has label+description, no separate consequence line).
- Settings → Admin → System Information's connection-info labels are static text, not verified against the live runtime origin.
- The Protection → Status "six-layer" stepper reports Iron Dome's six modules, not the memory-write firewall's six layers — see brief §14.1 for why the latter has no honest per-layer data to show.

## Fixture and fleet hygiene

No dev/prod server was left running at the end of this work — every `node`/`next` process started for verification (fixture APIs on 3001/3401/3402, dashboard dev/prod servers on 3400/3403/3411/3030, and the origin/main comparison server on 3410) was stopped by PID before moving to the next step or concluding. The temporary `git worktree` at `.dashv2/main-compare/` was removed after the bundle-size measurement. All fixture databases and scratch scripts live under `.dashv2/` (gitignored) or `docs/design/dashboard-v2-screenshots/` (committed evidence only for the seeded-fixture captures named in the brief).
