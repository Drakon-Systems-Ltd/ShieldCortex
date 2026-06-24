# ShieldCortex CIC — Implementation Plan

> **For agentic workers:** Execute task-by-task with TDD where there is logic (command parser, command
> adapters, theme hook). Pure CSS/visual tasks verify via `cd dashboard && npm run build` + the jsdom suite
> + a manual screenshot. Commit per task. Spec: `docs/design/2026-06-23-shieldcortex-cic-terminal.md`.

**Goal:** Make the "CIC" terminal-cortex the default look on both dashboards — a real command line driving a
living, region-coloured memory brain that visualises ecosystem→shield→cortex.

**Architecture:** Token-driven theming (`data-theme="terminal"` default, Glass/Shield kept). A `<CicEffects/>`
overlay + `cic-*` utilities for the immersive layer (gated by calm/reduced-motion). A `lib/commands/` registry
of small adapters over the existing `:3001` API + MCP for the real command rail. The existing
`ConstellationGraph` pulse layer becomes the cortex centrepiece, keyed to the regional colour-map.

**Tech Stack:** Next.js, Tailwind v4 (CSS-var tokens), Geist Mono, React Query, Zustand, react-force-graph-2d.

---

## File structure (local dashboard `ShieldCortex/dashboard`)

- `src/app/globals.css` — add the `[data-theme="terminal"]` CIC token block + regional vars + effect keyframes.
- `src/app/layout.tsx` — default `data-theme="terminal"`; mount `<CicEffects/>`; restore localStorage bootstrap.
- `src/hooks/useTheme.ts` — replace no-op shim with a real `terminal|glass` hook (localStorage `sc-theme`, default terminal).
- `src/components/cic/CicEffects.tsx` — scanline + sweep + boot-sequence overlay; reads calm/reduced-motion.
- `src/components/cic/useReducedMotion.ts` + `src/lib/cic/motion.ts` — calm toggle + `prefers-reduced-motion`.
- `src/lib/cic/regions.ts` — the cognitive region map (region → colour token + meaning).
- `src/lib/commands/registry.ts`, `parse.ts`, `commands/*.ts` — the real command system.
- `src/components/cic/CommandRail.tsx`, `OpsBar.tsx`, `NavRail.tsx`, `TerminalShell.tsx` — the shell.
- `src/components/cic/EcosystemStrip.tsx`, `ShieldBar.tsx` — ecosystem→shield viz.
- Cortex: reuse `components/graph/ConstellationGraph.tsx` (recolour clusters to regions) + a `CortexView`.

## File structure (cloud `ShieldCortex-internal/dashboard`)
- `src/app/globals.css` — port the CIC token block as a new `terminal` (CIC) theme; default it.
- `src/contexts/ThemeContext.tsx` + `ThemeSwitcher` — add CIC theme, default.
- `src/components/ds/GlassCard.tsx` — add `title/statusLine/bodyPadding` props (parity with local).
- Elevate the 35 `.terminal.tsx` variants + add the effects layer + ecosystem/cortex parity.

---

## Phase 0 — Foundation: tokens + effects + motion (local)

### Task 0.1: CIC token block + regional map in globals.css
**Files:** Modify `dashboard/src/app/globals.css`; Create `dashboard/src/lib/cic/regions.ts`.
- [ ] Add `[data-theme="terminal"]` block defining `--cic-void/surface/surface-2/border/grid`, the phosphor
      vars (`--cic-cyan/coral/amber/violet` + `*-glow`), and the text ramp — mapping the existing `--sc-*`
      aliases to CIC values so token-driven components inherit it.
- [ ] Add the `@custom-variant theme-terminal` usage is already present; ensure body font → Geist Mono under terminal.
- [ ] Create `regions.ts`: `REGIONS = { memory:{token:'--cic-cyan',…}, defence:{coral}, quarantine:{amber}, integrity:{violet} }`.
- [ ] Verify: `cd dashboard && npm run build` clean; temporarily set `data-theme="terminal"` and eyeball.

### Task 0.2: motion gate (calm toggle + reduced-motion)
**Files:** Create `dashboard/src/lib/cic/motion.ts`, `dashboard/src/components/cic/useReducedMotion.ts`; Test `*.test.tsx`.
- [ ] TDD `useCicMotion()` → returns `{ animate: boolean }` = false when `prefers-reduced-motion` OR `calm` set
      (localStorage `sc-cic-calm`). Write failing test (jsdom matchMedia mock) → implement → green.
- [ ] Commit.

### Task 0.3: `<CicEffects/>` overlay (scanline + sweep + boot)
**Files:** Create `dashboard/src/components/cic/CicEffects.tsx`; Modify `globals.css` (keyframes).
- [ ] Scanline via fixed `::after` repeating-linear-gradient (opacity ~.04) + a slow vertical sweep keyframe.
- [ ] Boot sequence: a one-shot overlay that types `SHIELDCORTEX // CIC ONLINE` then fades (~1.2s), skippable on
      click/key; renders instantly (no anim) when `useCicMotion().animate === false`.
- [ ] `cic-bloom` utility class: `text-shadow: 0 0 8px currentColor` (reduced under calm).
- [ ] Verify build; mount in a throwaway page; check reduced-motion path.
- [ ] Commit.

### Task 0.4: real theme hook + layout default
**Files:** Modify `dashboard/src/hooks/useTheme.ts`, `dashboard/src/app/layout.tsx`, `ds/Toast.tsx` (already consumes useTheme).
- [ ] TDD `useTheme()` → `[theme, setTheme]` with `terminal|glass`, localStorage `sc-theme`, default `terminal`.
- [ ] layout.tsx: bootstrap `<script>` reads `sc-theme` (default terminal) → sets `data-theme` pre-hydration; mount `<CicEffects/>`.
- [ ] Verify: fresh load → terminal; toggle persists; Glass still reachable. Build + jsdom suite green. Commit.

## Phase 1 — Local vertical slice: shell + real command rail + cortex + ecosystem

### Task 1.1: command parser (TDD)
**Files:** Create `dashboard/src/lib/commands/parse.ts`; Test `parse.test.ts`.
- [ ] TDD a parser: tokenise `recall "auth bug" --project xero` → `{ name:'recall', args:['auth bug'], flags:{project:'xero'} }`;
      handle quotes, flags, empty. Failing tests first → implement → green. Commit.

### Task 1.2: command registry + first adapters (TDD each)
**Files:** Create `dashboard/src/lib/commands/registry.ts`, `commands/{recall,scan,forget,consolidate,go,theme,help}.ts`; Tests.
- [ ] Registry: `{ name, usage, run(ctx, parsed) → AsyncIterable<string>|string }`. ctx = {router, queryClient, api}.
- [ ] `go <view>` (nav), `theme <t>`, `help` (pure — TDD fully). Then `recall`/`scan`/`forget`/`consolidate` as thin
      adapters over existing endpoints/mutations (TDD the parse→call mapping with a mocked api). Commit per command.

### Task 1.3: `CommandRail` component
**Files:** Create `dashboard/src/components/cic/CommandRail.tsx`; Test.
- [ ] Input + blinking block cursor + `↑/↓` history + autocomplete from registry; output streams into a console log
      area above the prompt. `⌘K` focuses/opens it. Wire to the registry. jsdom test: typing `go defence` navigates.
- [ ] Commit.

### Task 1.4: `OpsBar` + `EcosystemStrip` + `ShieldBar`
**Files:** Create `dashboard/src/components/cic/{OpsBar,EcosystemStrip,ShieldBar}.tsx`.
- [ ] OpsBar: live counters (reuse existing stats hooks) + WS pulse dot + clock.
- [ ] EcosystemStrip: derive active sources from audit/source data (existing hooks) → sensor chips w/ trust + throughput.
- [ ] ShieldBar: 6-segment `▣▣▣▣▣▣`, segments flare on recent layer hits.
- [ ] Build green; commit.

### Task 1.5: `NavRail` (recreate the deleted terminal sidebar, adaptive)
**Files:** Create `dashboard/src/components/cic/NavRail.tsx`; wire into the shell.
- [ ] Systems list w/ `▸` active + regional glow, collapsible, `◉ link.up` footer. Maps the shared `route-config` NAV_ITEMS.
- [ ] Commit.

### Task 1.6: `TerminalShell` + cortex centre
**Files:** Create `dashboard/src/components/cic/TerminalShell.tsx`, `CortexView.tsx`; Modify `ConstellationGraph.tsx` (regional cluster colours).
- [ ] TerminalShell composes OpsBar + NavRail + main + CommandRail; mounted when `data-theme==='terminal'`.
- [ ] CortexView = the ConstellationGraph keyed to regions: remap `CLUSTER_COLOURS` to the regional phosphor; on recall/
      access, the pulse layer lights the retrieved neurons + links (existing PulseDriver — wire region colours in).
- [ ] Build + jsdom green; screenshot the slice. Commit.

## Phase 2 — Local primitives + remaining views (outline)
Re-skin `ds/{GlassCard→Panel, Button, Badge, TabBar, StatCard, Toast}` to CIC (terminal branches already exist — refine
chrome + bloom). Re-skin views: defence/overview, audit timeline, memory library/recall/review (+ the 4.41.0 bulk list),
quarantine, xray, irondome, settings. Each: token + chrome pass, build, screenshot, commit. (Detail when reached.)

## Phase 3 — Command coverage + telemetry rails (outline)
Add `quarantine review|approve`, `irondome on|off|status`, remember, and edge sparkline telemetry rails. TDD each adapter.

## Phase 4 — Cloud parity (outline)
Port the CIC token block to `ShieldCortex-internal/dashboard/src/app/globals.css` as a new `terminal` theme, default it
in `ThemeContext` + `ThemeSwitcher`; add `title/statusLine/bodyPadding` to the cloud `GlassCard`; elevate the 35
`.terminal.tsx` variants with panel chrome + `<CicEffects/>`; ecosystem/cortex parity. Mirror the canonical token spec.

## Phase 5 — Polish (outline)
Motion tuning, contrast/WCAG pass, cross-dashboard consistency audit, full screenshot verification, reduced-motion QA.

## Verification (every phase)
- `cd dashboard && npm run build` clean (ships in the npm tarball).
- `cd dashboard && npx jest` green (jsdom component suite).
- Root `node scripts/run-jest.mjs --runInBand` unaffected for any backend touched.
- Manual: load `/`, confirm terminal default + boot + a real command round-trip + cortex bloom on recall; toggle to Glass and back; reduced-motion path.

## Execution
Subagent-driven for the broad re-skin phases (2, 4); direct TDD for the logic (command system, theme hook) and the
foundation (Phase 0). Adversarial review (the established workflow pattern) before any release.
