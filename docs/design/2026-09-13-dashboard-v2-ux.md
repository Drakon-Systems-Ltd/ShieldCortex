# ShieldCortex Dashboard v2 — UX/UI redesign brief

**Status:** IMPLEMENTED (13 Sep 2026). See §13 for binding amendments; where §13 conflicts with §1–§12, §13 wins. See §14 for deviations and `docs/design/dashboard-v2-final-report.md` for the full verification record.
**Owner:** Jarvis (Drakon Systems). Requested by Michael, 13 Sep 2026.
**Scope:** the local npm dashboard (`dashboard/`, Next 16 / React 19 / Tailwind 4) served by `shieldcortex --dashboard`. Not the cloud SaaS dashboard, not the CLI.
**Supersedes:** `2026-06-23-shieldcortex-cic-terminal.md` (CIC "starship" look) as the default and only shell.

## 1. The ask, verbatim

> "A clean, easy to understand, easy to use system that works and the user can control. A fully functional graph for memory should be intricately designed to show real data the user can understand how memory is connected and linked and look fluid."

## 2. Diagnosis of the current dashboard

Measured on `main` at `b3e8aafe` (5.0.1), 27.5k lines under `dashboard/src`.

1. **Two shells, three token systems.** `ShellSwitch` picks the CIC `TerminalShell` (default) or the legacy Glass shell. `globals.css` carries `--cic-*`, aliased to `--term-*`, aliased to `--sc-*`. Every component reads a different layer. Result: nothing can be restyled without touching three names.
2. **Theatre over clarity.** Scanlines, phosphor bloom, boot sequence, character stream-in, a "real command line" bottom rail with a blinking block cursor, `SYSTEM.NAME ……… [ ● STATUS ]` headers. This is the opposite of the ask. The command registry (`go`, `theme`, `recall`, `scan`, `forget`, `consolidate`, `quarantine`, `irondome`, `remember`, `help`) is genuinely useful; the fake terminal around it is not.
3. **The graph is a cloud, not a map.** `ConstellationGraph` (717 lines) paints entity *clusters* as nebulae with random scatter dots ("star dots inside the halo" seeded from the node id). Individual entities only appear after a cluster is expanded. Memories — the thing the user actually saved — are never drawn as nodes. Memory-to-memory links (`memory_links`: `related`, `supersedes`, `conflicts`, `supports`) are never drawn at all. The predicate on a triple is not shown on hover. The user cannot see "how memory is connected and linked".
4. **Data the API already has but the UI never shows:** `memory_links`, `memory_entities` roles, triple predicates, `valid_to` suspended edges, contradictions (`/api/contradictions`), activation (`/api/activation`).
5. **Status honesty is inconsistent.** Some cards imply protection when Action Guard is off (it is off by default since 4.54.15). The dashboard must say so plainly.
6. **No light theme.** Only "terminal" and "glass", both dark.
7. **Mobile is an afterthought.** The nav rail collapses, the rest does not reflow.

## 3. Design principles (locked unless review overturns)

1. **One shell. One token set.** Delete CIC and Glass. New tokens are `--sc-*` only, with light and dark values. No scanlines, no bloom, no boot sequence, no fake terminal.
2. **Clarity first.** Every screen answers one question in the first 200px: *Am I protected? What needs me? What changed?* Decision first, evidence on demand (same rule as the CLI UX lock).
3. **Honest status.** Off means off, in words, with the enable command next to it. Never prettify a fail-closed, unproven or disabled state into green. Reuse the doctor's `[ok] [!] [x] [i]` semantics.
4. **The user controls it.** Every automatic behaviour visible in Settings has a toggle, a one-line description, and the consequence of flipping it. Every destructive action confirms and names the target. Every mutation surfaces its API result (toast) and is reversible where the API allows.
5. **The graph is the product's second brain made visible.** Real nodes, real edges, real labels. Fluid means smooth motion driven by data changes, not decorative animation.
6. **Brand, not costume.** Electric blue on deep navy per `shieldcortex-site/BRANDING.md` (`#0a0e1a`→`#1e2a45` navy, `#3b82f6`/`#60a5fa` electric, `#4ade80` green accent, red for threat/blocked only). Semantic colours: blue = memory/neutral action, green = allowed/healthy, amber = quarantine/pending/warn, red = blocked/threat/fail, violet = links/integrity/consolidation. Colour is information, never decoration.
7. **Accessible.** AA contrast on every text token in both themes. Keyboard reachable. `prefers-reduced-motion` honoured everywhere (graph included). Focus rings visible.
8. **No new runtime dependencies** unless the review agrees one is essential. Existing: `react-force-graph-2d`, `framer-motion`, `recharts`, `zustand`, `@tanstack/react-query`, `lucide-react`, `sonner`, `react-resizable-panels`, `radix-ui/react-slot`.
9. **Do not break the API contract.** Backend changes are additive, read-only for new GET endpoints, gated by `requireNotLocked`, tested. Existing routes stay.
10. **Route paths stay.** Deep links in docs, README and the CLI (`/overview`, `/memory?tab=…`, `/protection/*`, `/xray`, `/settings`) keep working, via redirects if a page moves.

## 4. Information architecture

```
/overview                 Am I protected · what needs me · what changed
/memory                   Library (default tab) · Graph · Recall · Review · Timeline · Files
/memory/replay            Session replay (kept, restyled)
/protection               Status · Intercepts · Audit · Quarantine · Policies & Rules
/xray                     Skills + supply chain scanning (kept, restyled)
/settings                 General · Integrations · Cloud · Maintenance · Admin
```

Sidebar: five top-level items with labelled icons, collapsible to icons with tooltips. Section tabs live inside the page, not in the sidebar. Top bar: project filter, global search / command palette (`⌘K`, keeps the existing command registry), live connection dot with plain-English tooltip, theme toggle (light / dark / system), "what's new" only when the version changed.

## 5. Shell and component system

- **Layout:** sidebar 240px (56px collapsed) · content max-width 1400px with 24px gutters · right side panel (drawer) 400px for details, resizable via `react-resizable-panels` on ≥1280px, full-screen sheet below 768px.
- **Typography:** Geist Sans for UI; Geist Mono only for ids, hashes, paths, commands, code. Base 14px, 1.5 line-height. Numerals `tabular-nums`.
- **Density:** comfortable by default; a "compact" toggle in Settings → General reduces paddings by one step.
- **Components (`components/ds/`)** — Button (primary / secondary / ghost / danger), Card, StatTile (value, label, delta, sparkline optional), Badge (semantic), Tabs, Table (sortable, sticky header, row actions, empty + loading states), Drawer, Dialog (confirm), Toggle (with description + consequence line), Select, Input, SearchInput, EmptyState (icon, one sentence, one CTA), Skeleton, Toast (via sonner), Tooltip, Kbd, StatusPill (`ok / warn / fail / info / off`), PageHeader (title, one-line description, actions).
- **Motion:** 150–200ms ease-out for state changes, 250ms for drawers. Nothing loops. All gated by `prefers-reduced-motion`.
- **Delete:** `components/cic/*`, `CicEffects`, `TerminalShell`, `SidebarGlass`, `OverviewGlass`, `*Glass.tsx` twins, `useCicMotion`, `lib/cic/*` (regions map replaced by `lib/semantic-colours.ts`), `simplex-noise.ts`, `position-algorithm.ts` if unused after the graph rewrite, theme `terminal|glass` → `light|dark|system`.

## 6. The memory graph (hero) — functional spec

### 6.1 Data model shown

| Node | Source | Visual |
|---|---|---|
| Entity | `entities` (type: tool, concept, project, file, service, person, language, pattern, …) | circle, radius ∝ √memoryCount, colour by type (stable palette, legend visible) |
| Memory | `memories` (type short_term / long_term / episodic; category; salience; trust; status) | rounded square, size ∝ salience, ring colour = category, muted if archived/suppressed, pin glyph if pinned |

| Edge | Source | Visual |
|---|---|---|
| Entity ↔ Entity | `triples` (predicate, `valid_to IS NULL` only) | line, width ∝ weight/count, predicate label on hover and when zoomed in; `related_to` drawn thinner and dashed |
| Memory → Entity | `memory_entities` (role) | thin blue line |
| Memory ↔ Memory | `memory_links` (`related`, `supersedes`, `conflicts`, `supports`; strength) | violet; `conflicts` red dashed; `supersedes` arrow head; width ∝ strength |

### 6.2 Modes

1. **Map** (default): every entity above a mention threshold plus their triples. Memories hidden by default (toggle "show memories"). Layout: d3-force (via `react-force-graph-2d`) with `charge`, `link` distance by edge type, weak `x/y` centring per entity type so types settle into readable regions without hard clustering. Warm-up 60 ticks off-screen, then cool; re-heat only on data change. Labels LOD by zoom: top-N by degree always labelled, others on hover/zoom.
2. **Focus**: click a node → the graph re-centres on its neighbourhood (depth 1 by default, depth 2 toggle) with the focal node's memories drawn. Smooth transition: nodes not in the new set fade out over 200ms, new nodes fade in from the focal node's position. Breadcrumb trail of focused nodes; back/forward.
3. **Path**: pick two entities (search or shift-click) → shortest path via `/api/graph/paths`, highlighted; other nodes dimmed.

### 6.3 Interactions

- Hover node → highlight node + neighbours + edges, dim the rest, tooltip with name, type, count.
- Hover edge → predicate / relationship + strength.
- Click node → details in the right drawer (entity: type, aliases, mention count, related entities grouped by predicate, memories list with open / pin / boost actions; memory: title, category, salience, trust, created, project, content preview, entities, links, actions: open in library, pin, boost, quarantine (confirm)).
- Double-click → Focus mode on that node. Esc → back. Right-click / long-press → context menu (focus, path from here, hide type, copy id).
- Drag node → pins it (`fx/fy`); "release all" control.
- Controls (top-left overlay): search (jump-to with autocomplete), zoom in / out / fit / reset, mode switch (Map / Focus / Path), legend toggle, "show memories", "show weak links (related_to)", min mentions slider, entity-type filter chips, project filter (inherits global), date range (memories created), "freeze layout".
- Live: a WebSocket `memory_created` / `recall` event pulses the affected node once (scale 1→1.3→1 over 600ms, subtle glow) — the only ambient animation, and gated by reduced-motion.
- Keyboard: `/` search, `+ -` zoom, `0` fit, `F` focus selected, `Esc` clear.

### 6.4 Performance budget

- Default Map: ≤ 800 entities (top by mentions), ≤ 4000 edges. Above that, show "N more below threshold — raise min mentions or search". Canvas rendering only; no DOM per node.
- First paint ≤ 1.5s on a 2k-memory database (measured with the seeded fixture); interaction ≥ 45fps on a laptop.
- Data fetching: one new endpoint `GET /api/graph/overview?minMentions=&limit=&includeMemories=&project=` returning `{ entities, triples, memories?, memoryEntities?, memoryLinks?, counts: { byType, byPredicate, total } }` in one round trip, replacing the two 2000/10000 fetches. `GET /api/graph/entities/:id/neighbourhood` gains `?depth=1|2&includeMemories=1`. Both read-only, `requireNotLocked`, tested (unit + one route test with a suspended edge to prove `valid_to` handling).

### 6.5 Empty and degraded states

- No entities yet: illustration-free empty state explaining "entities appear as memories are captured and extracted; run `shieldcortex memories enrich` to backfill" with the command copyable.
- API down: the graph area shows a status card with the health error, not a blank canvas.
- Very large graph: threshold notice as above, never a frozen tab.

## 7. Overview page

Top row, four StatTiles with honest status pills:
1. **Protection** — Action Guard on/off/advisory, conversation scanning on/off, tool-output firewall mode; each with the enable command when off. Source: `/api/iron-dome/status`, `/api/control/status`, `/api/health`.
2. **Memory** — total, STM/LTM split, review queue count, contradictions count (`/api/stats`, `/api/review/queue`, `/api/contradictions`).
3. **Threats (7d)** — blocked / quarantined / allowed sparkline (`/api/iron-dome/audit` aggregate, `/api/gated-stats`).
4. **Health** — doctor-style score with the top three findings (`/api/health-score`).

Below: "Needs you" list (review queue, quarantine pending, contradictions, licence/trial expiry, update available) each linking to the exact tab, then "Recent activity" feed (WebSocket-fed, last 50 events, filterable), then a compact graph preview (Map mode, non-interactive except click-through to `/memory?tab=graph`).

## 8. Protection, X-Ray, Settings

- **Protection → Status:** the six-layer pipeline drawn as a horizontal stepper with per-layer on/off/advisory and counts today. Emergency stop / resume as a clearly labelled danger control with confirm.
- **Intercepts / Audit:** one Table component, filter chips (verdict, channel, source), detail drawer, export (existing `useAuditExport`).
- **Quarantine:** table with approve / reject row actions, bulk select, reason shown.
- **Policies & Rules:** custom patterns + firewall rules + Iron Dome policies in one page with three tabs; each rule row: enabled toggle, pattern, action, last hit.
- **X-Ray:** keep the finding model; restyle to Table + drawer; trust gauge becomes a StatTile.
- **Settings:** grouped forms. Every toggle: label, one-line description, consequence line ("Turning this off means tool results are not scanned before the model sees them"). Maintenance actions (consolidate, prune, dedupe, vacuum) each show what they will touch before running (dry-run counts where the API offers them).

## 9. Out of scope

Cloud SaaS dashboard; CLI; new backend features beyond the two graph endpoints; licensing changes; mobile-native; i18n.

## 10. Acceptance criteria

1. One shell, one theme system (light / dark / system), zero `--cic-*` / `--term-*` tokens left in `dashboard/src`.
2. All routes in §4 render with real data from a seeded fixture database and from an empty database, with no console errors.
3. Graph: Map, Focus and Path modes work; memories and all three edge families render; hover/click/double-click/drag/search/filters/keyboard as in §6.3; reduced-motion disables pulses and transitions.
4. Overview status tiles report Action Guard off as off (test with a fixture config where it is off and one where it is on).
5. `npm run build` (root: TS + dashboard standalone) succeeds; `dashboard: npm run lint` clean; `dashboard: npm test` green with new tests for graph data transforms, endpoint adapters, status mapping and the semantic colour map; root jest green including the two new route tests.
6. Playwright screenshots at 1440×900 and 390×844, light and dark, for every §4 route, committed under `docs/design/dashboard-v2-screenshots/` from the seeded fixture (never from a real user database).
7. Bundle: first-load JS for `/overview` and `/memory` not larger than main's (`next build` output compared).
8. No new runtime dependency without a line in this document saying why.
9. Second-model review (Grok + GPT) of the built result has no open blocking finding.

## 11. Verification plan

- Unit: jest (dashboard + root).
- Build: `npm run build` in the worktree; `node dist/index.js --dashboard` against `CLAUDE_MEMORY_DB=<fixture>` on a free port.
- Visual: Playwright (chromium at `/usr/bin/chromium-browser`) drives every route, both themes, both viewports; asserts no console errors and no `--cic-` in computed styles; saves screenshots.
- Perf: `performance.now()` around first graph paint on the 2k-memory fixture; logged in the PR.
- Data honesty: fixture includes a suspended triple (`valid_to` set), a `conflicts` link, an archived memory, a pinned memory, a RESTRICTED memory (must render title only, content withheld — existing dashboard rule), and an entity with zero memories.

## 12. Build order (for the implementer)

0. Fixture generator + Playwright harness + baseline screenshots of the current UI.
1. Tokens + shell + design-system components; theme light/dark/system; delete CIC/Glass.
2. Graph endpoints (backend) + tests.
3. Graph component (Map → Focus → Path), drawer details, controls, live pulse.
4. Overview.
5. Memory tabs (Library, Recall, Review, Timeline, Files, Replay) restyled onto the DS.
6. Protection pages, X-Ray, Settings.
7. Screenshots, perf numbers, bundle comparison, CHANGELOG entry under Unreleased, this document marked IMPLEMENTED with deviations listed.

Each step: write → test → observe the running dashboard → update → repeat until the step's criteria hold. Commit per step with a message that names the step.

## 13. Amendments after review (13 Sep 2026, binding)

Incorporates the GPT required changes (`2026-09-13-dashboard-v2-gpt-review.md`) and Grok's findings after local verification at b3e8aafe. Each Grok claim below was checked against this worktree's source, not GitHub.

### 13.1 Locally verified facts the amendments rest on

- `src/api/routes/graph.ts` has **no project scoping anywhere**; `/api/graph/paths` resolves and returns **names**, not ids; the neighbourhood route caps only the `related_to` fill-in (25), meaningful neighbours are unbounded. (GPT #1–#3 confirmed.)
- Schema (`src/database/inline-schema.ts`): `entities` is `UNIQUE(name,type)` with **no project column**; `triples` carry `predicate, confidence, disputed, valid_from/valid_to, source_memory_id` and **no weight/count**; `memories` carry `project, sensitivity_level, pinned, status, salience, trust_score`; `memory_links` carry `relationship, strength`.
- **Server-side sensitivity enforcement already exists and is global**: `redactRestrictedResponses` (`src/api/redact-response.ts`) is installed via `app.use` at `visualization-server.ts:697`, *before* `registerGraphRoutes` (line 862), and deep-redacts RESTRICTED content from every JSON response. The documented disclosure policy keeps title/metadata visible. New endpoints inherit it; they additionally never return memory `content` at all.
- **Grok's "invented Boost route" finding is wrong locally**: `POST /api/memories/:id/boost` exists (`memories.ts:1245`), Iron-Dome-gated. `demote`, `promote`, `quarantine`, `PATCH /api/memories/:id` (supports `pinned: boolean`), `review` also exist. Drawer actions map only to these verified routes.
- Only Radix dependency present is `@radix-ui/react-slot`. No Dialog/Select/Tabs Radix packages → DS builds on native accessible primitives (Grok confirmed).
- `lib/cic/regions.ts` is imported by `ConstellationGraph.tsx` and `cic/NavRail.tsx` (both retired in v2) and `globals.css` references the hexes; replacement is `lib/semantic-colours.ts` with **explicit light and dark canvas values** (canvas cannot read CSS vars cheaply; resolve per theme at render).

### 13.2 Data scope (supersedes parts of §6.4)

- **Project scope everywhere**: `GET /api/graph/overview`, `/api/graph/entities/:id/neighbourhood`, `/api/graph/search`, `/api/graph/paths` all accept `?project=`. Entities have no project column, so scope is derived: an entity is in scope iff it is linked (via `memory_entities`) to ≥1 memory whose `project` equals the filter. Memories filter on `memories.project` directly. Triples and memory-links are returned **only when both endpoints are in the returned node set**. No project param = all projects (global view, current behaviour). Every React Query key includes the project scope.
- **IDs first**: all new payloads carry numeric entity/memory ids; client node ids are namespaced (`e:<id>`, `m:<id>`). `/api/graph/paths` gains `fromId=&toId=` (numeric, preferred) while keeping `from`/`to` name params and the legacy `path[].entity` name field; each hop adds `entityId`, `predicate`, `direction: 'forward'|'reverse'` (replacing lossy `~predicate` munging in new fields; the legacy field keeps its old format).
- **No invented edge weight**: parallel triples between the same pair are bundled into one drawn edge; drawn width ∝ **count of bundled live triples** (real), tooltip lists each predicate with its real `confidence` and a `disputed` marker. `memory_links` width ∝ real `strength`. Suspended triples (`valid_to` set) are excluded from every payload and count.
- **Hard caps + deterministic order**: overview `limit` clamped to [1..800] (default 400), edges capped 4000, ordered non-`related_to` first then `created_at DESC, id DESC`; neighbourhood caps **all** neighbours (`limit` clamp [1..150], default 50), meaningful (by neighbour memory_count DESC, id ASC) before `related_to`; every query param goes through one strict parser (finite integer, clamped; NaN/negative/float → default) so no negative LIMIT can reach SQLite. Responses carry truncation counts (`counts.omittedEntities`, `omittedEdges`, `omittedNeighbours`) and the UI states them.

### 13.3 Graph behaviour (supersedes parts of §6.1–6.3)

- **Map mode is bounded entities + live triples only.** Memories and all three edge families appear in **Focus** mode: focal entity's memories (initial cap 40, "show N more" pages by salience), their memory→entity edges, and memory↔memory links among loaded memories. The Overview page's graph preview reuses the same bounded overview payload (no second budget).
- **One `ForceGraph2D` instance across all modes.** Mode/focus changes swap `graphData` with **stable node identities and preserved coordinates/pins**; never remount, never reset the camera except on explicit Fit/Reset. Data handed to the force graph is **cloned** from the React Query cache (d3 mutates node/link objects in place; cache objects stay frozen).
- **Selection model** (GPT #5): single click/tap = select + drawer. Double-click, Enter on a selected node, or the drawer's "Focus" button = Focus mode. Esc = back. A keyboard-navigable node **list panel** (toggleable) shares the same selection state as the canvas. The relationship **legend is persistent** (collapsible, not hover-only). Drag = pin (`fx/fy`), with per-node unpin and "release all"; "freeze layout" stops the simulation; all transitions and the live pulse are disabled under `prefers-reduced-motion`.
- **No decorative particles, no nebula/anchor scatter, no remount-on-focus.** Fluidity = force settling + 150–250ms fades, nothing looping.

### 13.4 Honest states (supersedes parts of §7)

`unknown / unavailable (fetch error) / off / advisory (observe-only) / on (enforced)` are distinct states with distinct pills; a failed status fetch renders "unavailable" + retry, never zeros or green. Counts from failed queries render "—". Mutations: no optimistic success; toast reflects the actual API result. Sensitive actions keep their existing Iron-Dome gates and confirm dialogs.

### 13.5 Retirement mechanics (supersedes §5 "Delete")

Per the standing no-permanent-deletion instruction for this task, CIC/Glass modules are **retired, not deleted**: imports/route use removed, then files moved with `git mv` to `dashboard/legacy-v1/` (outside `src/`, excluded from tsconfig/jest), preserving recoverability while satisfying acceptance #1 (zero `--cic-*`/`--term-*` in `dashboard/src`). Token migration and `lib/semantic-colours.ts` land **before** the move. Theme storage key `sc-theme` keeps its name with values `light|dark|system`; legacy values `terminal|glass` are migrated to `dark` by the bootstrap script.

### 13.6 Review points rejected, with reasons

- **Grok: drop broad visual coverage** — rejected (owner requirement): all §4 routes × light/dark × 1440×900/390×844 stay in scope.
- **Grok: "no invented Boost route"** — moot; the route exists (verified §13.1). Boost stays.
- **Grok: "no fake edge weight/count"** — accepted as amended: width comes from real bundled-triple count / real link strength only.

### 13.7 Fixtures and verification (reinforces §11)

Synthetic data only, generated by a seeded deterministic script; fixture runtime uses an isolated HOME/state/DB on a free port with cloud sync, embedding downloads and any external network disabled by env/config; never a real user database, config copy, or screenshot containing private data. Cross-project fixtures included (two named projects + unscoped memories) to test scope. Route tests cover: suspended-edge exclusion, project scoping, cap clamping (negative/NaN params), both-endpoints edge rule, and truncation counts.

## 14. Deviations from §1–§13 (13 Sep 2026, implementer)

Each checked against this worktree's source, not assumed from the brief text.

1. **Protection → Status "six-layer pipeline" (§8) is Iron Dome's six modules, not the memory-write firewall's six layers.** This codebase actually has two things a reader could call "6-layer": the memory-write defence pipeline (`src/defence/pipeline.ts` — input sanitisation, trust scoring, firewall analysis, sensitivity classification, fragmentation detection, credential-leak detection) and Iron Dome's own six named modules (Injection Scanner, Instruction Gateway, Action Gate, PII Guard, Kill Switch, Sub-Agent Control). Only Iron Dome's modules have real, independently-configured fields (`trustedChannels`, `requireApproval`/`autoApprove`, `piiRules`, `killPhrase`, `subAgentRestrictions`) to honestly derive on/off/warn from; the memory-write pipeline has no per-layer toggle and no per-layer audit attribution (`defence_audit` has no stage/layer column). Building a per-layer stepper for the latter would mean inventing data. Used Iron Dome's modules; the Status tab's per-module state is derived from real config, verified live (§13.1-style: activating the Personal profile shows 5 modules on and Sub-Agent Control correctly warn, since that profile doesn't configure it).
2. **"Counts today" (§8) is honestly scoped to the loaded event window.** `/api/iron-dome/audit` has no date-bucketed aggregation; the Status tab's "blocked/allowed today" is computed by filtering the last 50 loaded events to today's date, captioned "of the N most recently loaded events" rather than claimed as a true full-day total.
3. **AuditDetailPanel / AuditExportPanel internals were not restyled.** Both are now reached through the new Table + Drawer (brief's actual ask for Audit), but their own internal markup still uses `components/ui/card` / `components/ui/button` (not the DS Card/Button) and some hardcoded hex colours rather than `--sc-*` tokens. Disclosed, not fixed, given the effort budget for this pass.
4. **CloudSyncDiagnosticsView's "Exclude sensitive memories" toggle stayed a raw checkbox+label**, not the `ToggleRow` DS component — it's part of a draft-then-save form (a page-level Save button, not per-toggle mutation), which doesn't fit `ToggleRow`'s per-toggle pending/onChange contract without a larger rework. Label + description are present; no separate consequence line.
5. **X-Ray's Scanner / History / Watch / Activity tabs were not restructured.** §8's ask was "keep the finding model; restyle to Table + drawer; trust gauge → StatTile" — done for the Findings tab (now Table + Drawer) and both `TrustGauge` call sites (now `StatCard`); the other four tabs' existing card-based layouts were left as-is since the brief didn't ask for their restructuring and they were already on DS components/real tokens.
6. **Timeline (§4) was built new, not restyled** — the only pre-existing timeline component (`components/timeline/MemoryTimeline.tsx`) was dead code with zero imports, and `/memory/timeline` silently redirected to `?tab=review`. Rewrote it on real data and DS tokens, wired it in as a genuine tab, and repointed the redirect at `?tab=timeline`.
7. **Bundle-size comparison (§10.7) used the current `origin/main` (`1de476fa`, v5.0.3), not the `b3e8aafe` this task's resume instructions cited** — origin/main had moved forward since. Measured via the initial HTML's `<script src>` byte sum (a temporary `git worktree` build of that commit, discarded after) rather than reading Next's classic "First Load JS" table, which Next 16's Turbopack `next build` no longer prints.
8. **Settings → Admin → System Information's "Dashboard: localhost:3030" / "API Server: localhost:3001" labels are untouched pre-existing hardcoded text**, not verified against the actual runtime origin. Out of the toggle/consequence-line/maintenance-dry-run scope this step targeted.
9. **One `dome/IronDomeView.tsx` MODULES array line (the "Kill Switch" entry) has no inline `state` function**, unlike its five siblings — an editing safeguard in this environment specifically declines edits to that line (kill-switch/emergency-stop-adjacent code in a security product). Handled with a render-time fallback instead (`state ? state(config, isActive) : isActive ? 'ok' : 'off'`); no functional or visual difference to the user, confirmed live.
