# Graph Interactivity & Visual Improvements

**Date:** 2026-03-23
**Component:** `dashboard/src/components/graph/UnifiedGraph.tsx`

## Context

The Graph tab's Map mode renders nodes on tight pre-positioned ellipses (250×180 / 360×255) pinned with `fx`/`fy`, causing the graph to cluster in the top-left corner rather than filling the viewport. The Bloom mode uses a single-pass SVG Gaussian blur that looks flat. Neither mode supports node dragging or filtering.

## Changes

### 1. Map Mode — Full Viewport Layout

**Problem:** Nodes are pinned to fixed positions on small ellipses at origin. No `zoomToFit()` call. Graph appears as a small cluster in one corner.

**Fix:**
- Remove `fx`/`fy` constraints from positioned nodes — let d3 force simulation position them naturally
- Enable charge force: `fg.d3Force('charge')?.strength(-120)` (was `0`)
- Add `zoomToFit(400, 60)` call after warmup ticks complete
- Keep focal node loosely centred with a mild centering force
- Link distance stays predicate-aware (120px meaningful, 160px ambient)

**File:** `UnifiedGraph.tsx` — `graphData` memo (lines ~405–492) and force config effect (lines ~494–504)

### 2. Map Mode — Node Dragging

**Problem:** Nodes can't be dragged. `react-force-graph-2d` supports drag natively but it's ineffective when nodes have `fx`/`fy` pins.

**Fix:**
- With `fx`/`fy` removed (step 1), built-in drag works automatically
- Add `onNodeDragEnd` handler to fix node at dropped position (`node.fx = node.x; node.fy = node.y`) so it stays where the user places it
- Add `enableNodeDrag={true}` prop (default, but explicit for clarity)

**File:** `UnifiedGraph.tsx` — `<ForceGraph2D>` props (lines ~1524–1540)

### 3. Bloom Mode — Enhanced Glow

**Problem:** Single-pass `feGaussianBlur` with `stdDeviation="14"` looks flat. Only the focal node has a glow halo.

**Fix:**
- Dual-radius blur: blur at `stdDeviation="6"` and `stdDeviation="18"`, blended via `<feBlend mode="screen">`
- Apply per-node coloured halos (not just focal) — small glow circle behind each node coloured by entity type
- Add radial gradient background centred on focal node for depth
- Increase feColorMatrix alpha multiplier from 18 to 22 for richer bloom

**File:** `UnifiedGraph.tsx` — SVG `<defs>` filter (lines ~1353–1365) and node rendering (lines ~1410–1500)

### 4. Bloom Mode — Node Dragging

**Problem:** Nodes are positioned along computed petal branches. No drag interaction exists.

**Fix:**
- Add `onMouseDown` per node that sets a `draggingNodeId` ref
- On `mousemove` (existing handler), if `draggingNodeId` is set, update that node's position in bloom layout state
- On `mouseUp`, clear `draggingNodeId` and persist final position
- Change cursor to `grab`/`grabbing` on node hover/drag
- Dragged nodes detach from their petal branch and stay at the dropped position

**File:** `UnifiedGraph.tsx` — bloom node `<g>` elements (lines ~1440–1500), new state for overridden positions

### 5. Collapsible Filter Sidebar (Both Modes)

**Problem:** No way to filter nodes by entity type or relationship type.

**Implementation:**
- New component `GraphFilterPanel.tsx` in `dashboard/src/components/graph/`
- State: `visibleEntityTypes: Set<string>` (all enabled by default), `visiblePredicates: Set<string>` (all enabled by default), `isOpen: boolean`
- Collapsed state: small filter icon button at top-right
- Expanded state: 220px panel on right edge with:
  - **Entity Types** section — checkbox per type with colour dot (person, concept, tool, language, file, service, pattern)
  - **Relationships** section — checkbox per predicate type found in current neighbourhood
  - **Reset filters** button
- Filters applied in `graphData` memo — filter nodes and links before rendering
- Entity types and predicates derived dynamically from current `neighbourhood` data
- Panel positioned `absolute right-4 top-4` with `backdrop-blur-sm` and dark semi-transparent background
- Animate open/close with CSS transition on width

**Files:**
- New: `dashboard/src/components/graph/GraphFilterPanel.tsx`
- Modified: `UnifiedGraph.tsx` — filter state, pass to memo, render panel in both Map and Bloom containers

### 6. Filter Integration with Graph Data

**How filters flow:**
1. `GraphFilterPanel` calls `onToggleEntityType(type)` / `onToggleRelationship(predicate)` callbacks
2. `UnifiedGraph` holds the filter state sets
3. `graphData` memo filters: nodes where `entityType` is in `visibleEntityTypes`, links where both endpoints pass AND `predicate` is in `visiblePredicates`
4. Bloom layout memo recomputes with filtered nodes
5. Focal node is never filtered out

## Files to Modify

| File | Change |
|------|--------|
| `dashboard/src/components/graph/UnifiedGraph.tsx` | Remove fx/fy pins, enable charge, add zoomToFit, add drag handlers, enhance bloom SVG filter, integrate filter state |
| `dashboard/src/components/graph/GraphFilterPanel.tsx` | **New** — collapsible filter sidebar component |

## Verification

1. Open dashboard at localhost:3030, navigate to Graph tab
2. **Map mode**: nodes should spread across full viewport, not cluster in corner. Drag a node — it should stay where dropped. Toggle entity types in filter panel — nodes and their links should appear/disappear.
3. **Bloom mode**: each node should have a coloured glow halo. Background should have a subtle radial gradient. Drag a node off its petal. Filter panel should work identically to Map mode.
4. **Read mode**: filter panel should not appear (text-only mode, no spatial filtering needed)
5. **Navigation**: clicking a node to re-centre should still work in both modes. Filter state should persist across navigation.
