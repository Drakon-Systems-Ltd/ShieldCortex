# Living Constellation — Knowledge Graph Redesign

**Status:** Approved by user (2026-05-20) during brainstorming. Ready for implementation planning.
**Scope:** Public repo, `dashboard/src/components/graph/*` + supporting hooks.
**Owner:** ShieldCortex dashboard.

---

## 1. Problem

The current knowledge graph (`ConstellationGraph.tsx`, 527 lines, `react-force-graph-2d` based) renders the user's memory entities but is reported as "hard to control, no flow, no organic feel, no pulse on connections, no centre — feels weak."

Concrete causes confirmed in code:

| Symptom | Cause |
|---|---|
| No centre | `d3Force('center').strength(0.05)` — barely any pull; no node is pinned. |
| No flow / freezes | `cooldownTicks={300}` — simulation runs 300 ticks then halts cold. |
| Connections don't glow | Links use the library's default static line. No `linkCanvasObject`, no `linkDirectionalParticles`. |
| Pan/zoom feels jumpy | Default wheel-zoom, no smooth zoom-to-selection, no double-click-fit. |
| Drag fights the simulation | Drag-release does not set `fx`/`fy`; the simulation springs the node back. |

Data that exists but is unused for the "alive" feel:

- **Per-entity** (`GraphEntity` in `useGraphData.ts:9-19`): `memoryCount` only. `salience` and `created_at` are **per-memory** on `LinkedMemory` (line 52-60), not per-entity — the formulas in this spec use `memoryCount` plus the runtime `edgeCount` derived from the loaded links.
- **Event stream:** `/ws/events` WebSocket on the visualization server (`visualization-server.ts:734`).
- **Polling fallback:** the existing `/api/memories?mode=recent` query (handled in `src/api/routes/memories.ts:278`) — used by the dashboard already, no new endpoint required.

---

## 2. Goals & Non-Goals

### Goals

1. Give the graph a visually obvious **centre** that is stable on load and user-overridable.
2. Make the graph **breathe** continuously without consuming meaningful CPU when idle.
3. Make **connections glow and flow** in a way driven by real data (creation events, recall events, edge weight).
4. Smooth **pan/zoom** and add **drag-to-pin** so direct manipulation feels intentional.
5. Allow a user (or always-on dashboard operator) to dial intensity down via a single config setting.
6. Refactor the 527-line monolith into 6 small, independently testable modules as part of the work.

### Non-Goals (deferred — user explicitly declined in brainstorming)

- Search-and-fly-to-node camera animation. Existing search stays text-only.
- Keyboard arrow navigation across neighbours.
- "Focus mode" that dims unrelated nodes.
- Smooth interpolated re-layout on filter toggles.
- Migration to WebGL / `@react-three/fiber` for the knowledge graph (kept for `HolographicGrid` only).
- Custom canvas rewrite that drops `react-force-graph-2d`.

---

## 3. Design Decisions (locked during brainstorming)

| Decision | Choice | Rationale |
|---|---|---|
| Visual direction | **Living Constellation** | Dark space, warm "sun" centre, satellites drifting, soft halos breathing, light particles flowing along edges. Extends the existing constellation aesthetic — no aesthetic rewrite. |
| Centre concept | **Auto-anchored Sun + Click-to-orbit** | Default = strongest entity (`salience × edgeCount`), pinned at `(0,0)`. Click any node → smoothly becomes the new centre. Double-click empty space → reset to default. |
| Pulse triggers | **All three layers** | Always-on breathing (salience-modulated sine) + spike on `memory.created` + warmer glow on `memory.accessed`. |
| Control polish | **Pan/zoom + drag-to-pin only** | User explicitly declined search/keyboard/filter polish. |
| Motion intensity | **Moderate default** | 3s breath, steady particle flow. Configurable via `graph.intensity ∈ {subtle, moderate, strong}` in browser `localStorage` (`shieldcortex.graph.intensity`). Server-side sync deferred — see §10. |
| Implementation strategy | **Extend `react-force-graph-2d`** | Use built-in extension points (`linkCanvasObject`, `linkDirectionalParticles`, `nodeCanvasObject`, `fx`/`fy`, custom `d3Force`, `cooldownTicks=Infinity`, `onNodeClick`, `onNodeDragEnd`). No new rendering stack. |

---

## 4. Architecture

### 4.1 Module layout

```text
dashboard/src/components/graph/
├── ConstellationGraph.tsx          (slim wirer, ~150 lines)
└── constellation/
    ├── anchor.ts                   (pure)
    ├── pulse.ts                    (pure, frame-driven class)
    ├── renderLinks.ts              (pure canvas drawer)
    ├── renderNodes.ts              (pure canvas drawer)
    ├── controls.ts                 (force-graph ref wiring)
    └── intensity.ts                (pure config map)
dashboard/src/hooks/
└── useGraphPulse.ts                (network: /ws/events + polling fallback)
```

### 4.2 Contracts

| Module | Type | Responsibility | Depends on |
|---|---|---|---|
| `anchor.ts` | pure functions | `pickAnchor(nodes, links): nodeId \| null`; `applyAnchor(graph, anchorId, opts)`: set `fx`/`fy`, animate transition | none (no React, no DOM) |
| `pulse.ts` | class `PulseDriver` | tracks per-node `energy: Map<nodeId, number>`; `onFrame(t)` modulates breathing + decays spikes; `dispatch({type, entityId})` injects spikes | `intensity.ts` |
| `renderLinks.ts` | pure function `(ctx, link, globalScale, pulseEnergy)` | gradient stroke with additive blend; α scaled by edge weight × max(src,dst) energy | none |
| `renderNodes.ts` | pure function `(ctx, node, globalScale, pulseEnergy, isAnchor, isSelected, opts?)` | sun ring, halo, cluster glow, breathing radius modulation. `opts._paintHook?: (info: {nodeId, radius, energy}) => void` is an optional test-only callback invoked once per paint with the computed values — used by the integration test (§7) to inspect render output without reading the canvas. | none |
| `controls.ts` | `wireControls(forceGraphRef, opts)` | pan/zoom polish, drag-to-pin via `onNodeDragEnd`, double-click-fit, shift-click-unpin | `react-force-graph-2d` ref |
| `intensity.ts` | exported `INTENSITY` const | maps `subtle\|moderate\|strong` → `{breathPeriod, breathAmp, particleCap, decayCreate, decayRecall}` | none |
| `useGraphPulse.ts` | React hook | subscribes `/ws/events`; falls back to polling `GET /api/memories?mode=recent` every 10s; dispatches into `PulseDriver` | `PulseDriver` (passed in) |

**`ConstellationGraph.tsx`** is the only file that imports React, owns force-graph state, and wires the modules together. Pure modules never import React or DOM globals.

### 4.3 Data flow

```text
┌─────────────────┐                       ┌──────────────────┐
│  useFullGraph   │── nodes, links ─────▶ │ ConstellationGraph│
│  (existing)     │   clusters            │  (slim wirer)    │
└─────────────────┘                       └──────────────────┘
                                                  │
        ┌─────────────────────────────────────────┼──────────────────────────────┐
        ▼                                         ▼                              ▼
   anchor.ts                              PulseDriver                       controls.ts
   pickAnchor()                           - breathing                       - smooth zoom
   applyAnchor() ──┐                      - create/recall spikes            - drag-to-pin
                   │                      - energy decay
                   │                              ▲
                   │                              │
                   │                       useGraphPulse
                   │                       /ws/events ─────────────┐
                   │                                                │ fallback
                   │                       /api/memories?mode=recent┘ (10s poll)
                   │
                   ▼
   force-graph: fx/fy set on anchor node, simulation idles at α=0.003
                                                  │
                          ┌───────────────────────┴───────────────────────┐
                          ▼                                               ▼
                   renderNodes(ctx, node, e)                    renderLinks(ctx, link, e)
                   – radius += e × breathAmp                    – additive gradient stroke
                   – halo opacity ∝ e                           – α ∝ edgeWeight × maxEnergy
                                                                – linkDirectionalParticles ∝
                                                                   top-N edges by energy
```

---

## 5. Runtime Behaviour

### 5.1 Anchor (the Sun)

- On `useFullGraph` data ready, `anchor.ts → pickAnchor(nodes, links)` returns the node maximising `memoryCount × edgeCount`, where `edgeCount` is computed from the loaded `links` array (count of links where node is source or target). Ties broken by entity `name` (alphabetical) for determinism. `salience` is not used here — it's a per-memory field, not per-entity. Pure, deterministic, cached in component state.
- `applyAnchor(graph, anchorId)` sets `node.fx = 0, node.fy = 0` on that node. Centre force strength is bumped from `0.05` → `0.12` so satellites pull inward visibly.
- **Click-to-orbit:** `onNodeClick(node)` releases the previous anchor (`fx = null, fy = null` with a 600ms tween from current position to the new anchor's `(0,0)` using cubic ease). `forceGraph.centerAt(0, 0, 600)` re-centres the camera in lockstep.
- **Reset:** double-click on empty canvas releases current pin and re-applies the default `pickAnchor` result; `zoomToFit(600, 80)`.
- **Cache invalidation:** `pickAnchor` cache is invalidated only when node count changes or when the top-ranked node's `memoryCount × edgeCount` delta exceeds 5% — so the sun does not flicker between siblings on every minor data refresh.

### 5.2 PulseDriver (the heartbeat)

A single `PulseDriver` instance owns `nodeEnergy: Map<nodeId, number>` (0..1). It is driven by `react-force-graph-2d`'s `onRenderFramePre` hook. Each frame:

1. **Layer C — breathing** (always-on, for every visible node):
   `energy += sin(t / period + phase) × amplitude`
   where `period` and `amplitude` come from `INTENSITY[level]` and `phase = hash(nodeId)` so nodes breathe out of sync.
2. **Layer A — create spike** (on `dispatch({type: 'memory.created', entityId})`):
   `nodeEnergy[entityId] = 1.0`, then decays each frame: `energy *= INTENSITY[level].decayCreate` (≈2s tail at moderate).
3. **Layer B — recall glow** (on `dispatch({type: 'memory.accessed', entityId})`):
   Warmer-coloured spike (e.g. `#fb923c` vs `#7dd3fc`), faster decay (`× decayRecall` ≈1s tail at moderate).

Energy is exposed via `getEnergy(nodeId): number` and read by:

- `renderNodes.ts` — modulates radius and halo opacity.
- `renderLinks.ts` — modulates edge α; the top-`particleCap` edges by `max(srcEnergy, dstEnergy)` get `linkDirectionalParticles` set. Ties are broken in favour of edges adjacent to the current anchor (so the sun always has visible flow even when no events are firing). Energy is the single ranking signal — `GraphLink` carries no `weight` field, and energy already encodes salience-modulated breathing plus create/recall spikes.

### 5.3 Intensity config

```ts
// constellation/intensity.ts
export type IntensityLevel = 'subtle' | 'moderate' | 'strong';

export const INTENSITY: Record<IntensityLevel, {
  breathPeriod: number;   // ms
  breathAmp: number;      // fraction of base radius
  particleCap: number;    // global cap on active particle edges
  decayCreate: number;    // per-frame multiplier
  decayRecall: number;
}> = {
  subtle:   { breathPeriod: 6000, breathAmp: 0.03, particleCap: 20,  decayCreate: 0.98, decayRecall: 0.96 },
  moderate: { breathPeriod: 3000, breathAmp: 0.08, particleCap: 60,  decayCreate: 0.96, decayRecall: 0.93 },
  strong:   { breathPeriod: 1600, breathAmp: 0.14, particleCap: 120, decayCreate: 0.94, decayRecall: 0.90 },
};
```

Persisted **per-browser in `localStorage` under the key `shieldcortex.graph.intensity`**, default `"moderate"` on absent/invalid value. Dashboard Settings exposes a 3-radio selector that writes the same key. Server-side sync (folding `graph.intensity` into `~/.shieldcortex/config.json` and surfacing it through a settings endpoint) is **explicitly out of scope** for this iteration — see §10. There is no general-purpose settings write endpoint on the visualization server today (only domain-specific ones like `/api/iron-dome/config`), and adding one would broaden scope beyond the visual fix.

### 5.4 Visual primitives

- **Sun (anchor) node** — larger ring + always-on halo at `1.5×` standard amplitude. Yellow-warm fill (`#fde68a`) regardless of cluster colour. A small pin glyph on hover indicates "anchored — click another to move."
- **Satellites** — existing node colours + cluster halos preserved. Radius is `baseRadius × (1 + energy × breathAmp)`.
- **Link glow** — `linkCanvasObject` paints a gradient stroke from source colour → target colour, drawn with `ctx.globalCompositeOperation = 'lighter'` for additive blending. Stroke width = `1.0 + max(srcEnergy, dstEnergy) × 0.8`; alpha = `0.35 + 0.6 × max(srcEnergy, dstEnergy)`. (No `edgeWeight` field exists on links — energy is the sole modulation signal.)
- **Flowing particles** — `linkDirectionalParticles` enabled on the top-N edges ranked by `max(srcEnergy, dstEnergy)`, tie-broken in favour of edges adjacent to the current anchor, where N = `INTENSITY[level].particleCap`. Library handles per-edge particle render; speed = `linkDirectionalParticleSpeed = 0.006` (moderate).
- **Cluster halos** — unchanged from current code; the existing `renderNodes` cluster-halo block is preserved verbatim and called before the new sun/breathing rendering.

### 5.5 Controls

| Interaction | Behaviour |
|---|---|
| Wheel zoom | Existing library behaviour; add `enableZoomInteraction` already on. Add wheel debounce (50ms) to smooth coarse trackpads. |
| Drag node | While dragging: library default. **On drag-end:** set `node.fx = node.x, node.fy = node.y` permanently — pin it in place. A small grey pin glyph renders next to pinned nodes. |
| Shift-click pinned node | Releases the pin (`fx = fy = null`); node rejoins the simulation. |
| Double-click empty canvas | Releases current click-anchor (if any), re-applies default sun via `pickAnchor`, `zoomToFit(600, 80)`. |
| Double-click node | Smooth `centerAt(node.x, node.y, 600)` + `zoom(2, 600)`. Does not change the anchor. |
| Click node | Selects + makes it the new anchor (click-to-orbit). Existing `selectedEntity` state in `UnifiedGraph` still drives the side panel. |

`cooldownTicks` is set to `Infinity` and `d3VelocityDecay` tuned (~0.6) so the simulation idles at very low alpha; `d3AlphaTarget(0.003)` keeps the graph gently moving without consuming meaningful CPU.

---

## 6. Performance Budget

- Idle CPU: <1% on a settled 200-node graph (current code freezes after `cooldownTicks` so its idle CPU is 0%; we are explicitly trading this for "alive" feel, but the target stays well under 5%).
- Particle render is capped via `INTENSITY[level].particleCap`. On a 500-node graph at `moderate`, ~60 particle edges, not 500.
- Breathing modulation skips nodes outside the rendered viewport (force-graph's existing render culling for labels — extend the same check).
- `prefers-reduced-motion: reduce` short-circuits all timed animation: no breathing, no particles, instant click-to-orbit (no tween), instant zoom. Graph still works, just quiet.
- Worst-case test: 1000 nodes, 3000 edges, `strong` intensity → must stay above 30fps on a 2021 M1 baseline. If not, particle cap is the first dial to lower.

---

## 7. Testing Strategy

### Unit (pure modules — Jest)

- `anchor.ts`:
  - 10 fixture graphs (empty, single-node, single-cluster, multi-cluster, ties, identical-salience-different-degree, deleted-node) → `pickAnchor` returns expected node or `null`.
  - `applyAnchor` sets `fx`/`fy` on exactly one node and clears on the previous anchor.
- `pulse.ts`:
  - Breathing — feed `t = 0..6000` ms across 10 nodes with distinct phases; assert per-node energy curves are sinusoidal and out of phase.
  - Create spike — `dispatch('memory.created', 'n1')`; assert `energy[n1] = 1.0`, decays to <0.05 within 2s at moderate.
  - Recall glow — `dispatch('memory.accessed', 'n1')`; assert faster decay.
  - Cap enforcement — feed 1000 spikes; assert active-energy set never exceeds `particleCap` for particle assignment.
- `intensity.ts`:
  - Each level produces the documented values; loader falls back to `moderate` on missing/invalid config.

### Integration (React Testing Library)

- Mount `ConstellationGraph` with a 20-node mock. Pass a test-only `_paintHook` (the `renderNodes` opts callback declared in §4.2) that records every `{nodeId, radius, energy}` tuple. Dispatch a synthetic `memory.created` for one entity via the `PulseDriver` ref. After one animation frame, assert the recorded radius for that entity strictly increased and its energy spiked to ~1.0. No canvas pixel-reading required.
- Existing graph tests must remain green.

### Manual

- Dev-only "pulse debug" panel (gated on `localStorage.SHIELDCORTEX_DEBUG_PULSE = '1'`) with two inputs (entityId + button per event type) to fire `memory.created` / `memory.accessed` for any entity. Not shipped in the production bundle.

---

## 8. Error Handling

- `/ws/events` not connected → `useGraphPulse` falls back to polling `GET /api/memories?mode=recent` every 10s (the existing endpoint at `src/api/routes/memories.ts:278`). Rows newer than the last seen `created_at` become synthetic `memory.created` events. Graph never blocks on the network.
- WS reconnect → resume; no stale-event replay (polling fallback fills any gap during disconnect).
- `pickAnchor` returns `null` (empty graph) → no `fx`/`fy` applied; existing empty-state UI renders unchanged.
- `graph.intensity` missing or invalid → fall back to `moderate` with one `console.warn`.
- `prefers-reduced-motion: reduce` → all animations short-circuit (see §6). This is treated as a first-class success path, not an error.

---

## 9. Out of Scope (Explicit)

Captured to prevent scope creep during planning/implementation:

- Search-and-fly-to-node camera animation.
- Keyboard arrow navigation across neighbours.
- "Focus mode" that dims unrelated nodes.
- Smooth interpolated re-layout on filter toggles.
- Migration of the knowledge graph to WebGL / `@react-three/fiber`.
- Custom canvas rewrite (dropping `react-force-graph-2d`).
- Changes to `useFullGraph`, the API graph endpoint, or the underlying data shape.
- Mobile / touch interaction redesign.
- Server-side persistence of `graph.intensity` (folding it into `~/.shieldcortex/config.json` and adding/extending a settings write endpoint). Intensity is per-browser in `localStorage` only this iteration.

---

## 10. File / Module Manifest

### New

- `dashboard/src/components/graph/constellation/anchor.ts`
- `dashboard/src/components/graph/constellation/pulse.ts`
- `dashboard/src/components/graph/constellation/renderLinks.ts`
- `dashboard/src/components/graph/constellation/renderNodes.ts`
- `dashboard/src/components/graph/constellation/controls.ts`
- `dashboard/src/components/graph/constellation/intensity.ts`
- `dashboard/src/hooks/useGraphPulse.ts`
- `dashboard/src/components/graph/__tests__/anchor.test.ts`
- `dashboard/src/components/graph/__tests__/pulse.test.ts`
- `dashboard/src/components/graph/__tests__/intensity.test.ts`
- `dashboard/src/components/graph/__tests__/constellation-integration.test.tsx`

### Modified

- `dashboard/src/components/graph/ConstellationGraph.tsx` — reduced from 527 lines to ~150 lines; becomes a wirer.
- `dashboard/src/components/graph/UnifiedGraph.tsx` — small change to pass `intensity` prop down (read from config).
- `dashboard/src/components/settings/SettingsView.tsx` — add `graph.intensity` 3-radio selector that reads/writes `localStorage['shieldcortex.graph.intensity']` and fires a `storage`/`CustomEvent` so a live graph picks up the change without reload.

### Unchanged

- `dashboard/src/hooks/useGraphData.ts` — no API or shape changes.
- `src/api/visualization-server.ts` — no new endpoints; reuses existing `/ws/events` and `GET /api/memories?mode=recent`.
- `dashboard/src/components/graph/GraphFilterPanel.tsx`, `LocalGraph.tsx`, `KnowledgeGraph.tsx`, `OntologyGraph.tsx` — untouched.

---

## 11. Open Questions

None at spec time. All design choices were resolved during brainstorming.
