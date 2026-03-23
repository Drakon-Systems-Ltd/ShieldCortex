# Graph Interactivity & Visual Improvements — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Graph tab's Map and Bloom modes fill the viewport, support node dragging, and add a collapsible filter sidebar for entity types and relationship predicates.

**Architecture:** Extract filter panel into a standalone component (`GraphFilterPanel.tsx`). Filter state lives in `UnifiedGraph` and flows into the existing `graphData`/`bloomLayout` memos. Map mode unlocks d3 forces for natural layout. Bloom mode adds per-node drag state overrides.

**Tech Stack:** React, react-force-graph-2d, SVG, Tailwind CSS, lucide-react icons

**Spec:** `docs/superpowers/specs/2026-03-23-graph-interactivity-design.md`

---

### Task 1: Create GraphFilterPanel Component

**Files:**
- Create: `dashboard/src/components/graph/GraphFilterPanel.tsx`

- [ ] **Step 1: Create the filter panel component**

```tsx
// dashboard/src/components/graph/GraphFilterPanel.tsx
'use client';

import { useState } from 'react';
import { Filter, X } from 'lucide-react';

const ENTITY_COLORS: Record<string, string> = {
  tool: '#22d3ee',
  person: '#34d399',
  concept: '#f59e0b',
  language: '#a78bfa',
  file: '#64748b',
  service: '#f472b6',
  pattern: '#fb923c',
};

interface GraphFilterPanelProps {
  entityTypes: string[];
  predicates: string[];
  visibleEntityTypes: Set<string>;
  visiblePredicates: Set<string>;
  onToggleEntityType: (type: string) => void;
  onToggleRelationship: (predicate: string) => void;
  onReset: () => void;
}

export default function GraphFilterPanel({
  entityTypes,
  predicates,
  visibleEntityTypes,
  visiblePredicates,
  onToggleEntityType,
  onToggleRelationship,
  onReset,
}: GraphFilterPanelProps) {
  const [isOpen, setIsOpen] = useState(false);

  if (!isOpen) {
    return (
      <button
        onClick={() => setIsOpen(true)}
        className="flex items-center gap-1.5 rounded-xl border border-slate-800 bg-slate-950/80 px-3 py-1.5 text-[11px] text-slate-400 backdrop-blur-sm transition-colors hover:border-slate-700 hover:text-slate-300"
      >
        <Filter size={13} />
        Filters
      </button>
    );
  }

  return (
    <div className="w-[220px] rounded-2xl border border-slate-800 bg-slate-950/90 p-4 backdrop-blur-sm">
      <div className="mb-3 flex items-center justify-between">
        <span className="text-[10px] uppercase tracking-[0.2em] text-slate-500">Filters</span>
        <button onClick={() => setIsOpen(false)} className="text-slate-500 hover:text-slate-300">
          <X size={14} />
        </button>
      </div>

      {/* Entity types */}
      <div className="mb-3">
        <div className="mb-2 text-[10px] uppercase tracking-[0.15em] text-slate-600">Entity Types</div>
        <div className="flex flex-col gap-1.5">
          {entityTypes.map((type) => {
            const active = visibleEntityTypes.has(type);
            return (
              <label
                key={type}
                className={`flex cursor-pointer items-center gap-2 text-xs ${active ? 'text-slate-300' : 'text-slate-600 line-through'}`}
                onClick={() => onToggleEntityType(type)}
              >
                <span
                  className={`flex h-3.5 w-3.5 items-center justify-center rounded-sm border ${
                    active
                      ? 'border-cyan-400/60 bg-cyan-400/15 text-[9px] text-cyan-400'
                      : 'border-slate-700'
                  }`}
                >
                  {active && '✓'}
                </span>
                <span
                  className="h-2 w-2 rounded-full"
                  style={{ background: active ? (ENTITY_COLORS[type] ?? '#94a3b8') : '#475569' }}
                />
                {type}
              </label>
            );
          })}
        </div>
      </div>

      {/* Relationships */}
      <div className="mb-3">
        <div className="mb-2 text-[10px] uppercase tracking-[0.15em] text-slate-600">Relationships</div>
        <div className="flex flex-col gap-1.5">
          {predicates.map((pred) => {
            const active = visiblePredicates.has(pred);
            return (
              <label
                key={pred}
                className={`flex cursor-pointer items-center gap-2 text-xs ${active ? 'text-slate-300' : 'text-slate-600 line-through'}`}
                onClick={() => onToggleRelationship(pred)}
              >
                <span
                  className={`flex h-3.5 w-3.5 items-center justify-center rounded-sm border ${
                    active
                      ? 'border-cyan-400/60 bg-cyan-400/15 text-[9px] text-cyan-400'
                      : 'border-slate-700'
                  }`}
                >
                  {active && '✓'}
                </span>
                {pred.replace(/_/g, ' ')}
              </label>
            );
          })}
        </div>
      </div>

      <div className="border-t border-slate-800 pt-2.5">
        <button
          onClick={onReset}
          className="w-full rounded-lg border border-slate-700 bg-transparent px-3 py-1.5 text-[11px] text-slate-400 transition-colors hover:border-slate-600 hover:text-slate-300"
        >
          Reset filters
        </button>
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd dashboard && npx next build --no-lint 2>&1 | tail -5` (or just check for TS errors: `npx tsc --noEmit`)

- [ ] **Step 3: Commit**

```bash
git add dashboard/src/components/graph/GraphFilterPanel.tsx
git commit -m "feat(graph): add collapsible filter sidebar component"
```

---

### Task 2: Add Filter State and Wire Up Panel in UnifiedGraph

**Files:**
- Modify: `dashboard/src/components/graph/UnifiedGraph.tsx`

- [ ] **Step 1: Add filter state and derived lists**

After the existing state declarations (line ~196, after `searchTimerRef`), add:

```tsx
// Filter state
const [visibleEntityTypes, setVisibleEntityTypes] = useState<Set<string>>(new Set());
const [visiblePredicates, setVisiblePredicates] = useState<Set<string>>(new Set());
const [filtersInitialised, setFiltersInitialised] = useState(false);
```

Add a `useEffect` to initialise filters from neighbourhood data (all visible by default, re-initialise when focal changes):

```tsx
useEffect(() => {
  if (!neighbourhood) return;
  const types = new Set<string>();
  types.add(neighbourhood.focal.type);
  neighbourhood.neighbours.forEach((n) => types.add(n.type));
  const preds = new Set<string>();
  neighbourhood.triples.forEach((t) => preds.add(t.predicate));
  setVisibleEntityTypes(types);
  setVisiblePredicates(preds);
  setFiltersInitialised(true);
}, [neighbourhood]);
```

Add toggle/reset callbacks:

```tsx
const handleToggleEntityType = useCallback((type: string) => {
  setVisibleEntityTypes((prev) => {
    const next = new Set(prev);
    if (next.has(type)) next.delete(type);
    else next.add(type);
    return next;
  });
}, []);

const handleToggleRelationship = useCallback((predicate: string) => {
  setVisiblePredicates((prev) => {
    const next = new Set(prev);
    if (next.has(predicate)) next.delete(predicate);
    else next.add(predicate);
    return next;
  });
}, []);

const handleResetFilters = useCallback(() => {
  if (!neighbourhood) return;
  const types = new Set<string>();
  types.add(neighbourhood.focal.type);
  neighbourhood.neighbours.forEach((n) => types.add(n.type));
  const preds = new Set<string>();
  neighbourhood.triples.forEach((t) => preds.add(t.predicate));
  setVisibleEntityTypes(types);
  setVisiblePredicates(preds);
}, [neighbourhood]);
```

Derive entity type and predicate lists for the panel:

```tsx
const availableEntityTypes = useMemo(() => {
  if (!neighbourhood) return [];
  const types = new Set<string>();
  types.add(neighbourhood.focal.type);
  neighbourhood.neighbours.forEach((n) => types.add(n.type));
  return [...types].sort();
}, [neighbourhood]);

const availablePredicates = useMemo(() => {
  if (!neighbourhood) return [];
  const preds = new Set<string>();
  neighbourhood.triples.forEach((t) => preds.add(t.predicate));
  return [...preds].sort();
}, [neighbourhood]);
```

- [ ] **Step 2: Add filter to graphData memo**

In the `graphData` useMemo (line ~492), add `visibleEntityTypes` and `visiblePredicates` to the dependency array. Before `return { nodes, links: uniqueLinks }`, filter:

```tsx
const filteredNodes = nodes.filter(
  (n) => n.isFocal || visibleEntityTypes.has(n.entityType),
);
const visibleNodeIds = new Set(filteredNodes.map((n) => n.id));
const filteredLinks = uniqueLinks.filter(
  (l) =>
    visibleNodeIds.has(l.source as unknown as number) &&
    visibleNodeIds.has(l.target as unknown as number) &&
    visiblePredicates.has(l.predicate),
);
return { nodes: filteredNodes, links: filteredLinks };
```

Update the dependency array from `[displayMode, neighbourhood]` to `[displayMode, neighbourhood, visibleEntityTypes, visiblePredicates]`.

- [ ] **Step 3: Render the filter panel in Map and Bloom containers**

Add import at top of file:

```tsx
import GraphFilterPanel from './GraphFilterPanel';
```

In the **Map mode** container (the `<div ref={containerRef} className="flex-1 min-h-0 relative">` block around line ~1506), add after the info box div:

```tsx
<div className="absolute right-4 top-4 z-20">
  <GraphFilterPanel
    entityTypes={availableEntityTypes}
    predicates={availablePredicates}
    visibleEntityTypes={visibleEntityTypes}
    visiblePredicates={visiblePredicates}
    onToggleEntityType={handleToggleEntityType}
    onToggleRelationship={handleToggleRelationship}
    onReset={handleResetFilters}
  />
</div>
```

In the **Bloom mode** container (around line ~1320 where the top-right controls are), replace the existing `<div className="absolute right-4 top-4 z-20 flex items-center gap-2">` block to include the filter panel:

```tsx
<div className="absolute right-4 top-4 z-20 flex items-start gap-2">
  <GraphFilterPanel
    entityTypes={availableEntityTypes}
    predicates={availablePredicates}
    visibleEntityTypes={visibleEntityTypes}
    visiblePredicates={visiblePredicates}
    onToggleEntityType={handleToggleEntityType}
    onToggleRelationship={handleToggleRelationship}
    onReset={handleResetFilters}
  />
  <div className="flex items-center gap-2">
    <div className="rounded-full border border-slate-800 bg-slate-950/70 px-3 py-1 text-[11px] text-slate-400">
      Wheel to zoom • drag to pan
    </div>
    <button
      onClick={() => setBloomViewport({ scale: 1, offsetX: 0, offsetY: 0 })}
      className="rounded-full border border-slate-700 bg-slate-950/70 px-3 py-1 text-[11px] text-slate-300 transition-colors hover:border-slate-600 hover:text-white"
    >
      Reset view
    </button>
  </div>
</div>
```

- [ ] **Step 4: Verify dashboard builds**

Run: `cd dashboard && npx tsc --noEmit`

- [ ] **Step 5: Commit**

```bash
git add dashboard/src/components/graph/UnifiedGraph.tsx
git commit -m "feat(graph): wire filter state and sidebar into Map and Bloom modes"
```

---

### Task 3: Fix Map Mode — Full Viewport Layout and Dragging

**Files:**
- Modify: `dashboard/src/components/graph/UnifiedGraph.tsx`

- [ ] **Step 1: Remove fx/fy pins from non-focal nodes**

In the `graphData` useMemo, in the `setNode` function (lines ~405–420), remove the `fx` and `fy` assignments:

Change:
```tsx
const setNode = (item: typeof prioritizedNeighbours[number], x: number, y: number) => {
  const ratio = item.entity.memoryCount / maxCount;
  positionedNodes.set(item.entity.id, {
    id: item.entity.id,
    name: item.entity.name,
    entityType: item.entity.type,
    memoryCount: item.entity.memoryCount,
    isFocal: false,
    val: 7 + Math.pow(ratio, 0.6) * 14,
    x,
    y,
    fx: x,
    fy: y,
    labelDirection: Math.abs(x) < 40 ? 'center' : (x > 0 ? 'right' : 'left'),
  });
};
```

To:
```tsx
const setNode = (item: typeof prioritizedNeighbours[number], x: number, y: number) => {
  const ratio = item.entity.memoryCount / maxCount;
  positionedNodes.set(item.entity.id, {
    id: item.entity.id,
    name: item.entity.name,
    entityType: item.entity.type,
    memoryCount: item.entity.memoryCount,
    isFocal: false,
    val: 7 + Math.pow(ratio, 0.6) * 14,
    x,
    y,
    labelDirection: Math.abs(x) < 40 ? 'center' : (x > 0 ? 'right' : 'left'),
  });
};
```

Keep the focal node `fx: 0, fy: 0` to anchor the centre.

- [ ] **Step 2: Enable charge force and add zoomToFit**

In the force config `useEffect` (lines ~494–504), change:

```tsx
useEffect(() => {
  const fg = graphRef.current;
  if (!fg || graphData.nodes.length === 0) return;

  fg.d3Force('charge')?.strength(0);
  fg.d3Force('center', null);
  fg.d3Force('link')?.distance((link: GraphLink) => {
    return link.predicate === 'related_to' ? 160 : 120;
  });
}, [graphData]);
```

To:
```tsx
useEffect(() => {
  const fg = graphRef.current;
  if (!fg || graphData.nodes.length === 0) return;

  fg.d3Force('charge')?.strength(-120);
  fg.d3Force('center', null);
  fg.d3Force('link')?.distance((link: GraphLink) => {
    return link.predicate === 'related_to' ? 160 : 120;
  });

  // Auto-fit after simulation settles
  setTimeout(() => fg.zoomToFit(400, 60), 500);
}, [graphData]);
```

- [ ] **Step 3: Add drag-end handler and explicit drag prop**

Add a callback before the `<ForceGraph2D>` render:

```tsx
const handleNodeDragEnd = useCallback((node: GraphNode) => {
  // Pin node at dropped position
  node.fx = (node as unknown as { x: number }).x;
  node.fy = (node as unknown as { y: number }).y;
}, []);
```

On the `<ForceGraph2D>` component (lines ~1524–1540), add props:

```tsx
enableNodeDrag={true}
onNodeDragEnd={handleNodeDragEnd}
```

- [ ] **Step 4: Verify dashboard builds**

Run: `cd dashboard && npx tsc --noEmit`

- [ ] **Step 5: Commit**

```bash
git add dashboard/src/components/graph/UnifiedGraph.tsx
git commit -m "feat(graph): unlock Map layout — charge repulsion, zoomToFit, node drag"
```

---

### Task 4: Enhance Bloom Mode Glow

**Files:**
- Modify: `dashboard/src/components/graph/UnifiedGraph.tsx`

- [ ] **Step 1: Replace the SVG bloom filter**

In the SVG `<defs>` section (lines ~1353–1365), replace the existing filter:

```xml
<filter id="bloom-glow" x="-40%" y="-40%" width="180%" height="180%">
  <feGaussianBlur stdDeviation="14" result="blur" />
  <feColorMatrix
    in="blur"
    type="matrix"
    values="1 0 0 0 0
            0 1 0 0 0
            0 0 1 0 0
            0 0 0 18 -8"
  />
</filter>
```

With:

```xml
<filter id="bloom-glow" x="-50%" y="-50%" width="200%" height="200%">
  <feGaussianBlur stdDeviation="18" in="SourceGraphic" result="blur1" />
  <feGaussianBlur stdDeviation="6" in="SourceGraphic" result="blur2" />
  <feBlend in="blur1" in2="blur2" mode="screen" result="combined" />
  <feColorMatrix
    in="combined"
    type="matrix"
    values="1 0 0 0 0
            0 1 0 0 0
            0 0 1 0 0
            0 0 0 22 -9"
  />
</filter>
<radialGradient id="bloom-bg-grad" cx="50%" cy="72%">
  <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.06" />
  <stop offset="40%" stopColor="#22d3ee" stopOpacity="0.02" />
  <stop offset="100%" stopColor="#020617" stopOpacity="0" />
</radialGradient>
```

- [ ] **Step 2: Add background gradient rect and per-node halos**

After the `<defs>` block, before the existing `<g>` transform group, add:

```xml
<rect x="0" y="0" width={bloomLayout.width} height={bloomLayout.height} fill="url(#bloom-bg-grad)" />
```

In the bloom node rendering section (where each node `<circle>` is drawn, around lines ~1440–1470), add a glow circle behind each node:

Before each node circle, add:
```tsx
<circle
  cx={node.x}
  cy={node.y}
  r={node.radius + 8}
  fill={ENTITY_COLORS[node.entityType] ?? DEFAULT_COLOR}
  opacity={0.07}
  filter="url(#bloom-glow)"
/>
```

- [ ] **Step 3: Verify the SVG renders without errors**

Run: `cd dashboard && npx tsc --noEmit`

- [ ] **Step 4: Commit**

```bash
git add dashboard/src/components/graph/UnifiedGraph.tsx
git commit -m "feat(graph): dual-radius bloom glow with per-node halos"
```

---

### Task 5: Add Bloom Mode Node Dragging

**Files:**
- Modify: `dashboard/src/components/graph/UnifiedGraph.tsx`

- [ ] **Step 1: Add bloom drag state**

Add a ref and state for tracking dragged node positions. Near the existing `bloomDragRef` (line ~179):

```tsx
const bloomNodeDragRef = useRef<{ nodeId: number; startX: number; startY: number } | null>(null);
const [bloomNodeOverrides, setBloomNodeOverrides] = useState<Map<number, { x: number; y: number }>>(new Map());
```

Clear overrides when focal changes:

```tsx
useEffect(() => {
  setBloomNodeOverrides(new Map());
}, [focalId]);
```

- [ ] **Step 2: Add bloom node drag handlers**

```tsx
const handleBloomNodeMouseDown = useCallback((e: MouseEvent, nodeId: number) => {
  e.stopPropagation();
  const svg = (e.target as SVGElement).closest('svg');
  if (!svg) return;
  const pt = svg.createSVGPoint();
  pt.x = e.clientX;
  pt.y = e.clientY;
  const svgPt = pt.matrixTransform(svg.getScreenCTM()?.inverse());
  bloomNodeDragRef.current = { nodeId, startX: svgPt.x, startY: svgPt.y };
}, []);

const handleBloomNodeMouseMove = useCallback((e: MouseEvent) => {
  const drag = bloomNodeDragRef.current;
  if (!drag) return;
  const svg = (e.target as SVGElement).closest('svg');
  if (!svg) return;
  const pt = svg.createSVGPoint();
  pt.x = e.clientX;
  pt.y = e.clientY;
  const svgPt = pt.matrixTransform(svg.getScreenCTM()?.inverse());
  setBloomNodeOverrides((prev) => {
    const next = new Map(prev);
    next.set(drag.nodeId, { x: svgPt.x, y: svgPt.y });
    return next;
  });
}, []);

const handleBloomNodeMouseUp = useCallback(() => {
  bloomNodeDragRef.current = null;
}, []);
```

- [ ] **Step 3: Apply overrides in bloom node rendering**

In the bloom node rendering loop, before using `node.x` and `node.y`, check for overrides:

```tsx
const pos = bloomNodeOverrides.get(node.id) ?? { x: node.x, y: node.y };
```

Use `pos.x` and `pos.y` instead of `node.x` and `node.y` for the node circle, glow circle, label, and badge positions.

Add `onMouseDown` to the node `<g>` element:

```tsx
<g
  onMouseDown={(e) => handleBloomNodeMouseDown(e, node.id)}
  style={{ cursor: bloomNodeDragRef.current?.nodeId === node.id ? 'grabbing' : 'grab' }}
>
```

Wire `handleBloomNodeMouseMove` and `handleBloomNodeMouseUp` into the SVG's existing mouse handlers (combine with pan handlers — node drag takes priority when `bloomNodeDragRef.current` is set).

In the existing `handleBloomMouseMove`, add at the top:
```tsx
if (bloomNodeDragRef.current) {
  handleBloomNodeMouseMove(e);
  return;
}
```

In `endBloomDrag`, add:
```tsx
bloomNodeDragRef.current = null;
```

- [ ] **Step 4: Verify dashboard builds**

Run: `cd dashboard && npx tsc --noEmit`

- [ ] **Step 5: Commit**

```bash
git add dashboard/src/components/graph/UnifiedGraph.tsx
git commit -m "feat(graph): drag nodes in Bloom mode"
```

---

### Task 6: Apply Filters to Bloom Layout

**Files:**
- Modify: `dashboard/src/components/graph/UnifiedGraph.tsx`

- [ ] **Step 1: Filter bloom nodes**

In the `bloomLayout` useMemo (around lines ~700–858), add `visibleEntityTypes` and `visiblePredicates` to the dependency array. Filter the neighbours before grouping into branches:

At the start of the memo, after the early return check, filter neighbours:

```tsx
const filteredNeighbours = neighbourhood.neighbours.filter(
  (n) => visibleEntityTypes.has(n.type),
);
```

Use `filteredNeighbours` instead of `neighbourhood.neighbours` for the branch grouping logic.

For cross-links, filter by visible predicates:

```tsx
const filteredTriples = neighbourhood.triples.filter(
  (t) => visiblePredicates.has(t.predicate),
);
```

- [ ] **Step 2: Verify dashboard builds**

Run: `cd dashboard && npx tsc --noEmit`

- [ ] **Step 3: Commit**

```bash
git add dashboard/src/components/graph/UnifiedGraph.tsx
git commit -m "feat(graph): apply entity/relationship filters to Bloom layout"
```

---

### Task 7: Manual Verification and Final Commit

- [ ] **Step 1: Build the dashboard**

```bash
cd dashboard && npm run build
```

- [ ] **Step 2: Start the dashboard and API**

```bash
# Terminal 1 — API server
npm run dev:api

# Terminal 2 — Dashboard
cd dashboard && npm run dev
```

- [ ] **Step 3: Verify Map mode**

Open http://localhost:3030, navigate to Graph tab, select Map mode:
- Nodes should spread across the full viewport (not clustered top-left)
- Drag a node — it should stay where dropped
- Open filter panel — toggle entity types and relationship types
- Filtered nodes and their links should disappear/reappear
- Click a node to navigate — graph should re-centre

- [ ] **Step 4: Verify Bloom mode**

Switch to Bloom mode:
- Each node should have a coloured glow halo matching its entity type
- Background should have a subtle radial gradient
- Drag a node off its petal — it should stay at dropped position
- Filter panel should work identically to Map mode
- Zoom and pan should still work

- [ ] **Step 5: Verify Read mode**

Switch to Read mode:
- Filter panel should NOT appear
- Text layout should be unaffected

- [ ] **Step 6: Build the standalone dashboard bundle**

```bash
npm run build:dashboard
```

- [ ] **Step 7: Commit and push**

```bash
git add -A
git commit -m "feat(graph): interactive map, enhanced bloom, and filter sidebar"
```
