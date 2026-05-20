# Living Constellation Graph Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `@superpowers:subagent-driven-development` (recommended) or `@superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Apply `@superpowers:test-driven-development` for every task with a `*.test.ts` file and `@superpowers:verification-before-completion` before claiming any task done.

**Goal:** Make the dashboard knowledge graph feel alive — a pinned "sun" centre with click-to-orbit, continuous breathing, glowing additive-blended links with directional particles on the active edges, and smooth pan/zoom + drag-to-pin controls — by refactoring the 527-line `ConstellationGraph.tsx` monolith into six small, independently-testable modules plus one network hook.

**Architecture:** Extend the existing `react-force-graph-2d` library through its built-in extension points (`linkCanvasObject`, `linkDirectionalParticles`, `nodeCanvasObject`, `fx`/`fy`, `d3Force`, `cooldownTicks=Infinity`, `onNodeDragEnd`). No new rendering stack, no API/data-shape changes. Pure modules under `dashboard/src/components/graph/constellation/` plus a `useGraphPulse` hook. Slim `ConstellationGraph.tsx` becomes a wirer (~150 lines).

**Tech Stack:** TypeScript, React, `react-force-graph-2d`, Jest (ts-jest, ESM, node env — pure modules only), the existing `useFullGraph` hook (`@tanstack/react-query`), the existing `/ws/events` WebSocket and `GET /api/memories?mode=recent` polling endpoint.

**Spec:** [docs/superpowers/specs/2026-05-20-living-constellation-graph-design.md](../specs/2026-05-20-living-constellation-graph-design.md) (commit `0b33d65`). Read it first — all design decisions, contracts, and out-of-scope items are there.

**Branch:** `feat/living-constellation-graph` (already checked out). Spec is the first commit on this branch.

---

## Pre-work — File Structure

All new files live under `dashboard/src/components/graph/constellation/` (pure modules) plus one hook. The 527-line `ConstellationGraph.tsx` becomes a ~150-line wirer in Task 9.

```text
dashboard/src/components/graph/
├── ConstellationGraph.tsx                  (Task 9: refactored to slim wirer)
├── constellation/
│   ├── intensity.ts                        (Task 1: config + storage)
│   ├── anchor.ts                           (Task 2: pickAnchor + applyAnchor)
│   ├── pulse.ts                            (Task 3a–3d: PulseDriver class)
│   ├── renderMath.ts                       (Task 4: pure size/alpha/width helpers)
│   ├── renderNodes.ts                      (Task 5: canvas drawer for nodes)
│   ├── renderLinks.ts                      (Task 6: canvas drawer for links)
│   ├── controls.ts                         (Task 7: drag-pin + zoom polish)
│   └── __tests__/
│       ├── intensity.test.ts               (Task 1)
│       ├── anchor.test.ts                  (Task 2)
│       ├── pulse.test.ts                   (Task 3a–3d)
│       └── renderMath.test.ts              (Task 4)
├── PulseDebugPanel.tsx                     (Task 12: dev-only pulse trigger)
dashboard/src/hooks/
└── useGraphPulse.ts                        (Task 8: WS + polling fallback)
dashboard/src/components/settings/
└── SettingsView.tsx                        (Task 10: 3-radio intensity selector)
jest.config.js                              (Task 0: add dashboard/src to roots)
```

---

## Task 0: Extend root Jest to pick up dashboard pure-module tests

**Why first:** all subsequent TDD tasks need their tests to run. The root Jest currently restricts `roots: ['<rootDir>/src', '<rootDir>/plugins']` — dashboard/src is excluded.

**Files:**
- Modify: [jest.config.js](../../../jest.config.js)

- [ ] **Step 1:** Read the current config — confirm `roots` is `['<rootDir>/src', '<rootDir>/plugins']`.

- [ ] **Step 2:** Modify the `roots` array to include the dashboard pure-module tests:

```js
roots: ['<rootDir>/src', '<rootDir>/plugins', '<rootDir>/dashboard/src/components/graph/constellation/__tests__'],
```

(Scoping to the `__tests__` directory keeps Jest off any Next.js app-router files that would fail to parse under the node environment.)

- [ ] **Step 3:** Verify root jest still passes against existing tests (regression-free change):

```bash
cd /Users/michael/Development/ShieldCortex-Project/ShieldCortex
node scripts/run-jest.mjs 2>&1 | tail -5
```
Expected: same baseline as before this task — the existing 1143 passing tests (and the known `mcp-registration` flake) still report the same. No new failures from the roots change.

- [ ] **Step 4:** Commit:

```bash
git add jest.config.js
git commit -m "test(graph): include dashboard constellation tests in jest roots"
```

---

## Task 1: `intensity.ts` — config map + storage helpers

**Files:**
- Create: `dashboard/src/components/graph/constellation/intensity.ts`
- Create: `dashboard/src/components/graph/constellation/__tests__/intensity.test.ts`

- [ ] **Step 1: Write the failing test**

`dashboard/src/components/graph/constellation/__tests__/intensity.test.ts`:

```ts
import { INTENSITY, loadIntensity, saveIntensity, type IntensityLevel } from '../intensity.js';

class FakeStorage {
  private store = new Map<string, string>();
  getItem(k: string) { return this.store.get(k) ?? null; }
  setItem(k: string, v: string) { this.store.set(k, v); }
  removeItem(k: string) { this.store.delete(k); }
  clear() { this.store.clear(); }
  get length() { return this.store.size; }
  key(i: number) { return Array.from(this.store.keys())[i] ?? null; }
}

describe('INTENSITY', () => {
  it('exposes the documented values for each level', () => {
    expect(INTENSITY.subtle.breathPeriod).toBe(6000);
    expect(INTENSITY.subtle.particleCap).toBe(20);
    expect(INTENSITY.moderate.breathPeriod).toBe(3000);
    expect(INTENSITY.moderate.particleCap).toBe(60);
    expect(INTENSITY.strong.breathPeriod).toBe(1600);
    expect(INTENSITY.strong.particleCap).toBe(120);
  });
});

describe('loadIntensity', () => {
  it('returns moderate when no storage is available (SSR / node)', () => {
    expect(loadIntensity(undefined)).toBe<IntensityLevel>('moderate');
  });

  it('returns moderate when storage is empty', () => {
    const s = new FakeStorage();
    expect(loadIntensity(s)).toBe('moderate');
  });

  it.each(['subtle', 'moderate', 'strong'] as const)('returns %s when stored', (level) => {
    const s = new FakeStorage();
    s.setItem('shieldcortex.graph.intensity', level);
    expect(loadIntensity(s)).toBe(level);
  });

  it('falls back to moderate on invalid stored value', () => {
    const s = new FakeStorage();
    s.setItem('shieldcortex.graph.intensity', 'bogus');
    expect(loadIntensity(s)).toBe('moderate');
  });
});

describe('saveIntensity', () => {
  it('persists the level under the documented key', () => {
    const s = new FakeStorage();
    saveIntensity('strong', s);
    expect(s.getItem('shieldcortex.graph.intensity')).toBe('strong');
  });

  it('no-ops when storage is undefined', () => {
    expect(() => saveIntensity('strong', undefined)).not.toThrow();
  });
});
```

- [ ] **Step 2: Run the test, confirm it fails (module missing)**

```bash
node scripts/run-jest.mjs dashboard/src/components/graph/constellation/__tests__/intensity.test.ts 2>&1 | tail -6
```
Expected: FAIL — `Cannot find module '../intensity.js'`.

- [ ] **Step 3: Write the implementation**

`dashboard/src/components/graph/constellation/intensity.ts`:

```ts
/**
 * Living Constellation — motion intensity config + per-browser persistence.
 *
 * Three levels (subtle / moderate / strong) scale every animation parameter
 * (breath period, breath amplitude, particle cap, decay rates). Loaded from
 * localStorage on the client; server-side rendering and tests inject a
 * Storage shim instead.
 */

export type IntensityLevel = 'subtle' | 'moderate' | 'strong';

export interface IntensitySettings {
  /** ms — one full sine cycle of the always-on breathing layer */
  breathPeriod: number;
  /** fraction of base radius — peak excursion of breathing */
  breathAmp: number;
  /** hard cap on edges that may render directional particles at once */
  particleCap: number;
  /** per-frame multiplier for memory.created spikes (~2s tail at moderate) */
  decayCreate: number;
  /** per-frame multiplier for memory.accessed glows (~1s tail at moderate) */
  decayRecall: number;
}

export const INTENSITY: Record<IntensityLevel, IntensitySettings> = {
  subtle:   { breathPeriod: 6000, breathAmp: 0.03, particleCap: 20,  decayCreate: 0.98, decayRecall: 0.96 },
  moderate: { breathPeriod: 3000, breathAmp: 0.08, particleCap: 60,  decayCreate: 0.96, decayRecall: 0.93 },
  strong:   { breathPeriod: 1600, breathAmp: 0.14, particleCap: 120, decayCreate: 0.94, decayRecall: 0.90 },
};

const STORAGE_KEY = 'shieldcortex.graph.intensity';
const VALID = new Set<IntensityLevel>(['subtle', 'moderate', 'strong']);

function isLevel(v: unknown): v is IntensityLevel {
  return typeof v === 'string' && VALID.has(v as IntensityLevel);
}

/** Read the current intensity; returns 'moderate' on any failure path. */
export function loadIntensity(storage?: Storage | undefined): IntensityLevel {
  const s = storage ?? (typeof window !== 'undefined' ? window.localStorage : undefined);
  if (!s) return 'moderate';
  const v = s.getItem(STORAGE_KEY);
  return isLevel(v) ? v : 'moderate';
}

/** Persist the new intensity; emits a window CustomEvent so live graphs react. */
export function saveIntensity(level: IntensityLevel, storage?: Storage | undefined): void {
  const s = storage ?? (typeof window !== 'undefined' ? window.localStorage : undefined);
  if (!s) return;
  s.setItem(STORAGE_KEY, level);
  if (typeof window !== 'undefined' && typeof CustomEvent !== 'undefined') {
    window.dispatchEvent(new CustomEvent('shieldcortex:intensity-changed', { detail: level }));
  }
}
```

- [ ] **Step 4: Run the test, confirm green**

```bash
node scripts/run-jest.mjs dashboard/src/components/graph/constellation/__tests__/intensity.test.ts 2>&1 | tail -6
```
Expected: PASS — all 9 cases green.

- [ ] **Step 5: Commit**

```bash
git add dashboard/src/components/graph/constellation/intensity.ts \
        dashboard/src/components/graph/constellation/__tests__/intensity.test.ts
git commit -m "feat(graph): intensity config + storage helpers (subtle/moderate/strong)"
```

---

## Task 2: `anchor.ts` — pickAnchor + applyAnchor

**Files:**
- Create: `dashboard/src/components/graph/constellation/anchor.ts`
- Create: `dashboard/src/components/graph/constellation/__tests__/anchor.test.ts`

- [ ] **Step 1: Write the failing test**

`dashboard/src/components/graph/constellation/__tests__/anchor.test.ts`:

```ts
import { pickAnchor, applyAnchor, type AnchorableNode, type AnchorableLink } from '../anchor.js';

const n = (id: string, memoryCount: number, name = id): AnchorableNode => ({ id, name, memoryCount });
const l = (s: string, t: string): AnchorableLink => ({ source: s, target: t });

describe('pickAnchor', () => {
  it('returns null on empty graph', () => {
    expect(pickAnchor([], [])).toBeNull();
  });

  it('picks the lone node when only one exists', () => {
    expect(pickAnchor([n('a', 5)], [])).toBe('a');
  });

  it('maximises memoryCount × edgeCount', () => {
    // a: mc=10, edges=1  → 10
    // b: mc=4,  edges=3  → 12  ← wins
    // c: mc=20, edges=0  → 0
    const nodes = [n('a', 10), n('b', 4), n('c', 20)];
    const links = [l('a', 'b'), l('b', 'c'), l('b', 'd-stray')];
    expect(pickAnchor(nodes, links)).toBe('b');
  });

  it('breaks ties alphabetically by name for determinism', () => {
    const nodes = [n('zeta', 3, 'zeta'), n('alpha', 3, 'alpha'), n('mid', 3, 'mid')];
    const links = [l('alpha', 'mid'), l('mid', 'zeta')];
    // alpha: 3×1=3, mid: 3×2=6 (wins), zeta: 3×1=3
    expect(pickAnchor(nodes, links)).toBe('mid');
    // Now make all three tie at 3×1=3
    const tieLinks = [l('alpha', 'zeta')];
    expect(pickAnchor([n('zeta', 3, 'zeta'), n('alpha', 3, 'alpha')], tieLinks)).toBe('alpha');
  });

  it('counts each link once for both endpoints (undirected degree)', () => {
    // a-b only. Both endpoints have edgeCount=1.
    expect(pickAnchor([n('a', 2), n('b', 3)], [l('a', 'b')])).toBe('b');
  });

  it('ignores links to nodes not in the node set', () => {
    expect(pickAnchor([n('a', 5)], [l('a', 'phantom')])).toBe('a');
  });

  it('returns null when every score is 0 (isolated nodes, no memories)', () => {
    expect(pickAnchor([n('a', 0), n('b', 0)], [])).toBeNull();
  });
});

describe('applyAnchor', () => {
  type Mut = { id: string; fx?: number | null; fy?: number | null; x?: number; y?: number };

  it('sets fx/fy to (0,0) on the new anchor and clears them on the previous one', () => {
    const a: Mut = { id: 'a', fx: 0, fy: 0 };
    const b: Mut = { id: 'b', x: 50, y: -30 };
    applyAnchor([a, b], 'b', 'a');
    expect(a.fx).toBeNull();
    expect(a.fy).toBeNull();
    expect(b.fx).toBe(0);
    expect(b.fy).toBe(0);
  });

  it('is a no-op when the anchor target node does not exist', () => {
    const a: Mut = { id: 'a', fx: 0, fy: 0 };
    applyAnchor([a], 'missing', 'a');
    expect(a.fx).toBe(0); // unchanged
  });

  it('only releases the previous anchor (not other pinned nodes)', () => {
    const a: Mut = { id: 'a', fx: 0, fy: 0 };
    const b: Mut = { id: 'b' };
    const c: Mut = { id: 'c', fx: 100, fy: 100 }; // user-pinned (drag-to-pin)
    applyAnchor([a, b, c], 'b', 'a');
    expect(c.fx).toBe(100); // user pin preserved
    expect(c.fy).toBe(100);
  });
});
```

- [ ] **Step 2: Run, expect fail**

```bash
node scripts/run-jest.mjs dashboard/src/components/graph/constellation/__tests__/anchor.test.ts 2>&1 | tail -6
```
Expected: FAIL — module missing.

- [ ] **Step 3: Implementation**

`dashboard/src/components/graph/constellation/anchor.ts`:

```ts
/**
 * Living Constellation — anchor (the "sun") selection and pin application.
 *
 * pickAnchor: pure ranker — `memoryCount × edgeCount`, ties broken
 * alphabetically by name for determinism. salience is intentionally NOT used
 * (it's per-memory, not per-entity — see spec §5.1).
 *
 * applyAnchor: mutates force-graph nodes' fx/fy to pin the new sun at (0,0)
 * and release the previous sun. User drag-pins on other nodes are preserved.
 */

export interface AnchorableNode {
  id: string;
  name: string;
  memoryCount: number;
  // force-graph runtime fields (optional — applyAnchor mutates these):
  fx?: number | null;
  fy?: number | null;
  x?: number;
  y?: number;
}

export interface AnchorableLink {
  source: string | { id: string };
  target: string | { id: string };
}

function endpointId(e: AnchorableLink['source']): string {
  return typeof e === 'string' ? e : e.id;
}

/** Returns the node id with the highest memoryCount × edgeCount, or null. */
export function pickAnchor(nodes: AnchorableNode[], links: AnchorableLink[]): string | null {
  if (nodes.length === 0) return null;

  const ids = new Set(nodes.map((n) => n.id));
  const degree = new Map<string, number>();
  for (const link of links) {
    const s = endpointId(link.source);
    const t = endpointId(link.target);
    if (ids.has(s)) degree.set(s, (degree.get(s) ?? 0) + 1);
    if (ids.has(t)) degree.set(t, (degree.get(t) ?? 0) + 1);
  }

  let bestNode: AnchorableNode | null = null;
  let bestScore = 0;
  for (const node of nodes) {
    const score = node.memoryCount * (degree.get(node.id) ?? 0);
    if (score === 0) continue;
    if (
      bestNode === null ||
      score > bestScore ||
      (score === bestScore && node.name.localeCompare(bestNode.name) < 0)
    ) {
      bestNode = node;
      bestScore = score;
    }
  }
  return bestNode?.id ?? null;
}

/**
 * Pin the new anchor at (0,0) and release the previous one.
 * Other pinned nodes (from drag-to-pin) are untouched.
 */
export function applyAnchor(
  nodes: AnchorableNode[],
  newAnchorId: string,
  previousAnchorId: string | null,
): void {
  // Release the previous anchor unless the caller has set it back to current.
  if (previousAnchorId && previousAnchorId !== newAnchorId) {
    const prev = nodes.find((n) => n.id === previousAnchorId);
    if (prev) {
      prev.fx = null;
      prev.fy = null;
    }
  }
  // Pin the new one.
  const next = nodes.find((n) => n.id === newAnchorId);
  if (!next) return;
  next.fx = 0;
  next.fy = 0;
}
```

- [ ] **Step 4: Run, expect green**

```bash
node scripts/run-jest.mjs dashboard/src/components/graph/constellation/__tests__/anchor.test.ts 2>&1 | tail -6
```
Expected: PASS — all 10 cases.

- [ ] **Step 5: Commit**

```bash
git add dashboard/src/components/graph/constellation/anchor.ts \
        dashboard/src/components/graph/constellation/__tests__/anchor.test.ts
git commit -m "feat(graph): anchor module — pickAnchor + applyAnchor"
```

---

## Task 3a: `pulse.ts` — class skeleton + Layer C (always-on breathing)

**Files:**
- Create: `dashboard/src/components/graph/constellation/pulse.ts`
- Create: `dashboard/src/components/graph/constellation/__tests__/pulse.test.ts`

- [ ] **Step 1: Failing test for breathing**

`dashboard/src/components/graph/constellation/__tests__/pulse.test.ts`:

```ts
import { PulseDriver } from '../pulse.js';
import { INTENSITY } from '../intensity.js';

describe('PulseDriver — breathing (Layer C)', () => {
  it('returns 0 energy for nodes the driver has never seen', () => {
    const d = new PulseDriver({ intensity: 'moderate' });
    expect(d.getEnergy('unknown')).toBe(0);
  });

  it('produces sinusoidal energy in [-amp, +amp] for known nodes', () => {
    const d = new PulseDriver({ intensity: 'moderate' });
    d.observeNodes(['n1', 'n2', 'n3']);
    const amp = INTENSITY.moderate.breathAmp;
    for (let t = 0; t <= 6000; t += 250) {
      d.onFrame(t);
      for (const id of ['n1', 'n2', 'n3']) {
        const e = d.getEnergy(id);
        expect(e).toBeGreaterThanOrEqual(-amp - 1e-9);
        expect(e).toBeLessThanOrEqual(amp + 1e-9);
      }
    }
  });

  it('phases breathing per-node so they are not in lock-step', () => {
    const d = new PulseDriver({ intensity: 'moderate' });
    d.observeNodes(['alpha', 'beta', 'gamma']);
    d.onFrame(750); // somewhere mid-cycle
    const energies = ['alpha', 'beta', 'gamma'].map((id) => d.getEnergy(id));
    // Three distinct values (none equal to any other) within 1e-6.
    const unique = new Set(energies.map((e) => Math.round(e * 1e6)));
    expect(unique.size).toBe(3);
  });

  it('returns 0 energy when intensity is "subtle" only after long zero baseline — sanity check on amplitude scaling', () => {
    const d = new PulseDriver({ intensity: 'subtle' });
    d.observeNodes(['n1']);
    d.onFrame(0);
    expect(Math.abs(d.getEnergy('n1'))).toBeLessThanOrEqual(INTENSITY.subtle.breathAmp + 1e-9);
  });
});
```

- [ ] **Step 2: Run, expect fail** (module missing).

- [ ] **Step 3: Implementation — skeleton + breathing**

`dashboard/src/components/graph/constellation/pulse.ts`:

```ts
import { INTENSITY, type IntensityLevel, type IntensitySettings } from './intensity.js';

export type PulseEventType = 'memory.created' | 'memory.accessed';

export interface PulseEvent {
  type: PulseEventType;
  entityId: string;
}

export interface PulseDriverOpts {
  intensity: IntensityLevel;
  /** Optional clock override for tests. Defaults to performance.now-equivalent. */
  now?: () => number;
}

/**
 * Frame-driven energy model for nodes.
 * Layer A (memory.created spikes), B (memory.accessed glows), and C (breathing)
 * are composed into a single per-node energy value in (-amp, 1 + amp].
 */
export class PulseDriver {
  private level: IntensityLevel;
  private settings: IntensitySettings;
  private knownNodes = new Set<string>();
  private phase = new Map<string, number>();
  private spikeEnergy = new Map<string, number>(); // Layer A + B contribution
  private breathOffset = new Map<string, number>(); // last computed Layer C
  private now: () => number;
  private lastFrameAt = 0;

  constructor(opts: PulseDriverOpts) {
    this.level = opts.intensity;
    this.settings = INTENSITY[opts.intensity];
    this.now = opts.now ?? (typeof performance !== 'undefined' ? () => performance.now() : Date.now);
  }

  setIntensity(level: IntensityLevel): void {
    this.level = level;
    this.settings = INTENSITY[level];
  }

  /** Register node ids so breathing kicks in. Safe to call repeatedly. */
  observeNodes(ids: Iterable<string>): void {
    for (const id of ids) {
      if (!this.knownNodes.has(id)) {
        this.knownNodes.add(id);
        this.phase.set(id, hashStringTo01(id) * Math.PI * 2);
      }
    }
  }

  /** External pulse trigger (Layer A / B will be implemented in 3b / 3c). */
  dispatch(_e: PulseEvent): void {
    // wired in Task 3b/3c
  }

  /** Compute energies for this frame. */
  onFrame(t: number): void {
    this.lastFrameAt = t;
    const { breathPeriod, breathAmp } = this.settings;
    const omega = (Math.PI * 2) / breathPeriod;
    for (const id of this.knownNodes) {
      const phi = this.phase.get(id) ?? 0;
      this.breathOffset.set(id, Math.sin(omega * t + phi) * breathAmp);
    }
  }

  /** Energy for one node — sum of breathing + spike contributions. */
  getEnergy(id: string): number {
    if (!this.knownNodes.has(id)) return 0;
    const breath = this.breathOffset.get(id) ?? 0;
    const spike = this.spikeEnergy.get(id) ?? 0;
    return breath + spike;
  }
}

/** Stable 0..1 hash for per-node breathing phase. */
function hashStringTo01(s: string): number {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = (h * 16777619) >>> 0;
  }
  return (h % 100000) / 100000;
}
```

- [ ] **Step 4: Run, expect green.**

- [ ] **Step 5: Commit**

```bash
git add dashboard/src/components/graph/constellation/pulse.ts \
        dashboard/src/components/graph/constellation/__tests__/pulse.test.ts
git commit -m "feat(graph): PulseDriver skeleton + Layer C (always-on breathing)"
```

---

## Task 3b: PulseDriver — Layer A (memory.created spike)

**Files:**
- Modify: `dashboard/src/components/graph/constellation/pulse.ts`
- Modify: `dashboard/src/components/graph/constellation/__tests__/pulse.test.ts`

- [ ] **Step 1: Append the failing test block**

Append to `pulse.test.ts`:

```ts
describe('PulseDriver — Layer A (memory.created spike)', () => {
  it('spikes to ~1.0 immediately after dispatch and decays per frame', () => {
    const d = new PulseDriver({ intensity: 'moderate' });
    d.observeNodes(['n1']);
    d.onFrame(0);
    d.dispatch({ type: 'memory.created', entityId: 'n1' });
    d.onFrame(0); // no time elapsed → still ~1.0
    expect(d.getEnergy('n1')).toBeGreaterThanOrEqual(0.95);
  });

  it('decays to <0.05 within ~2 seconds at moderate', () => {
    const d = new PulseDriver({ intensity: 'moderate', now: () => 0 });
    d.observeNodes(['n1']);
    d.onFrame(0);
    d.dispatch({ type: 'memory.created', entityId: 'n1' });
    // ~60 fps × 2s = 120 frames. moderate.decayCreate=0.96 → 0.96^120 ≈ 0.007.
    for (let i = 1; i <= 120; i++) d.onFrame(i * 16);
    expect(d.getEnergy('n1')).toBeLessThan(0.05 + INTENSITY.moderate.breathAmp);
  });

  it('does nothing when dispatched to an unobserved node', () => {
    const d = new PulseDriver({ intensity: 'moderate' });
    d.dispatch({ type: 'memory.created', entityId: 'never-seen' });
    d.onFrame(0);
    expect(d.getEnergy('never-seen')).toBe(0);
  });
});
```

- [ ] **Step 2: Run, expect new tests fail.**

- [ ] **Step 3: Extend `pulse.ts` — replace the `dispatch` stub and add spike decay inside `onFrame`**

Replace `dispatch(_e: PulseEvent)` body:

```ts
  dispatch(e: PulseEvent): void {
    if (!this.knownNodes.has(e.entityId)) return;
    if (e.type === 'memory.created') {
      this.spikeEnergy.set(e.entityId, 1.0);
    }
    // memory.accessed handled in Task 3c
  }
```

Inside `onFrame`, after the breathing loop, append a spike-decay loop:

```ts
    // Decay all active spikes once per frame.
    const decay = this.settings.decayCreate; // 3c will branch on event type
    for (const [id, e] of this.spikeEnergy) {
      const next = e * decay;
      if (next < 1e-3) this.spikeEnergy.delete(id);
      else this.spikeEnergy.set(id, next);
    }
```

- [ ] **Step 4: Run, expect green.**

- [ ] **Step 5: Commit**

```bash
git add dashboard/src/components/graph/constellation/pulse.ts \
        dashboard/src/components/graph/constellation/__tests__/pulse.test.ts
git commit -m "feat(graph): pulse Layer A — memory.created spike with decay"
```

---

## Task 3c: PulseDriver — Layer B (memory.accessed warm glow)

Layer B is a separate energy track so it can decay faster AND carry a distinct colour. Render code will read it via a second getter.

**Files:**
- Modify: `dashboard/src/components/graph/constellation/pulse.ts`
- Modify: `dashboard/src/components/graph/constellation/__tests__/pulse.test.ts`

- [ ] **Step 1: Failing tests**

Append:

```ts
describe('PulseDriver — Layer B (memory.accessed glow)', () => {
  it('spikes recall-energy to ~1.0 on dispatch and decays faster than create', () => {
    const d = new PulseDriver({ intensity: 'moderate', now: () => 0 });
    d.observeNodes(['n1']);
    d.onFrame(0);
    d.dispatch({ type: 'memory.accessed', entityId: 'n1' });
    expect(d.getRecallEnergy('n1')).toBeGreaterThanOrEqual(0.95);

    // 60 frames (~1s at 60fps) — moderate.decayRecall=0.93 → 0.93^60 ≈ 0.012
    for (let i = 1; i <= 60; i++) d.onFrame(i * 16);
    expect(d.getRecallEnergy('n1')).toBeLessThan(0.05);
  });

  it('keeps create-spike and recall-glow independent', () => {
    const d = new PulseDriver({ intensity: 'moderate', now: () => 0 });
    d.observeNodes(['n1']);
    d.dispatch({ type: 'memory.created', entityId: 'n1' });
    d.dispatch({ type: 'memory.accessed', entityId: 'n1' });
    d.onFrame(0);
    expect(d.getEnergy('n1')).toBeGreaterThanOrEqual(0.95);          // includes create
    expect(d.getRecallEnergy('n1')).toBeGreaterThanOrEqual(0.95);    // independent
  });
});
```

- [ ] **Step 2: Run, expect fail.**

- [ ] **Step 3: Extend `pulse.ts`**

Add a parallel map and getter, and branch in `dispatch` + `onFrame`:

```ts
  private recallEnergy = new Map<string, number>();

  // …

  dispatch(e: PulseEvent): void {
    if (!this.knownNodes.has(e.entityId)) return;
    if (e.type === 'memory.created')  this.spikeEnergy.set(e.entityId, 1.0);
    if (e.type === 'memory.accessed') this.recallEnergy.set(e.entityId, 1.0);
  }

  getRecallEnergy(id: string): number {
    return this.knownNodes.has(id) ? this.recallEnergy.get(id) ?? 0 : 0;
  }
```

Inside `onFrame`, after the existing spike-decay loop, add a recall-decay loop:

```ts
    const decayR = this.settings.decayRecall;
    for (const [id, e] of this.recallEnergy) {
      const next = e * decayR;
      if (next < 1e-3) this.recallEnergy.delete(id);
      else this.recallEnergy.set(id, next);
    }
```

- [ ] **Step 4: Run, expect green.**
- [ ] **Step 5: Commit**

```bash
git commit -am "feat(graph): pulse Layer B — memory.accessed warm glow"
```

---

## Task 3d: PulseDriver — particle ranking with cap + anchor-adjacency tie-break

**Files:**
- Modify: `dashboard/src/components/graph/constellation/pulse.ts`
- Modify: `dashboard/src/components/graph/constellation/__tests__/pulse.test.ts`

This is the function `renderLinks` will call to decide which edges show flowing particles.

- [ ] **Step 1: Failing tests**

Append:

```ts
describe('PulseDriver — particle edge ranking', () => {
  const link = (s: string, t: string) => ({ source: s, target: t });

  it('returns at most particleCap edges', () => {
    const d = new PulseDriver({ intensity: 'subtle' });
    d.observeNodes(['a', 'b', 'c', 'd']);
    const links = [link('a','b'), link('b','c'), link('c','d'), link('a','d')];
    expect(d.pickParticleEdges(links, null).length).toBeLessThanOrEqual(INTENSITY.subtle.particleCap);
  });

  it('ranks edges by max(srcEnergy, dstEnergy) descending', () => {
    const d = new PulseDriver({ intensity: 'subtle' });
    d.observeNodes(['hot', 'mid', 'cold']);
    d.dispatch({ type: 'memory.created', entityId: 'hot' });
    d.onFrame(0);
    const links = [link('cold', 'mid'), link('hot', 'mid')];
    const out = d.pickParticleEdges(links, null);
    // 'hot' edge must rank first
    expect(out[0]).toEqual(link('hot', 'mid'));
  });

  it('breaks ties in favour of edges adjacent to the anchor', () => {
    const d = new PulseDriver({ intensity: 'subtle' });
    d.observeNodes(['anchor', 'x', 'y', 'z']);
    d.onFrame(0); // all energies near 0 (only breathing)
    const links = [link('x','y'), link('anchor','z'), link('y','z')];
    // With particleCap = 20 we'd return all three. To test tie-break, lower cap to 1:
    const out = d.pickParticleEdges(links, 'anchor', /*overrideCap*/ 1);
    expect(out).toEqual([link('anchor', 'z')]);
  });
});
```

- [ ] **Step 2: Run, expect fail.**

- [ ] **Step 3: Implementation — append to `pulse.ts`**

```ts
  /**
   * Rank edges for directional-particle rendering.
   * @param links Edges as `{source, target}` (string ids; passed through).
   * @param anchorId Current sun id, or null. Used as tie-break.
   * @param overrideCap Optional explicit cap (defaults to INTENSITY[level].particleCap).
   */
  pickParticleEdges<L extends { source: string | { id: string }; target: string | { id: string } }>(
    links: L[],
    anchorId: string | null,
    overrideCap?: number,
  ): L[] {
    const cap = overrideCap ?? this.settings.particleCap;
    if (cap <= 0 || links.length === 0) return [];

    const epId = (e: L['source']) => (typeof e === 'string' ? e : e.id);
    type Scored = { link: L; score: number; anchorAdjacent: 0 | 1 };
    const scored: Scored[] = links.map((link) => {
      const s = epId(link.source);
      const t = epId(link.target);
      const sE = Math.max(this.getEnergy(s), this.getRecallEnergy(s));
      const tE = Math.max(this.getEnergy(t), this.getRecallEnergy(t));
      const score = Math.max(sE, tE);
      const anchorAdjacent = anchorId !== null && (s === anchorId || t === anchorId) ? 1 : 0;
      return { link, score, anchorAdjacent };
    });

    scored.sort((a, b) => {
      if (b.score !== a.score) return b.score - a.score;
      return b.anchorAdjacent - a.anchorAdjacent;
    });

    return scored.slice(0, cap).map((s) => s.link);
  }
```

- [ ] **Step 4: Run, expect green.**
- [ ] **Step 5: Commit**

```bash
git commit -am "feat(graph): pulse particle-edge ranking with cap + anchor tie-break"
```

---

## Task 4: `renderMath.ts` — pure helpers used by renderNodes and renderLinks

**Files:**
- Create: `dashboard/src/components/graph/constellation/renderMath.ts`
- Create: `dashboard/src/components/graph/constellation/__tests__/renderMath.test.ts`

- [ ] **Step 1: Failing tests**

```ts
import { computeNodeRadius, computeLinkAlpha, computeLinkWidth } from '../renderMath.js';

describe('computeNodeRadius', () => {
  it('returns baseRadius when energy is 0', () => {
    expect(computeNodeRadius({ baseRadius: 6, energy: 0, breathAmp: 0.08 })).toBeCloseTo(6, 6);
  });

  it('scales by (1 + energy × breathAmp) — clamped to non-negative', () => {
    expect(computeNodeRadius({ baseRadius: 10, energy: 1, breathAmp: 0.08 })).toBeCloseTo(10.8, 6);
    expect(computeNodeRadius({ baseRadius: 10, energy: -1, breathAmp: 0.08 })).toBeCloseTo(9.2, 6);
    // Sun-strong (energy=1, breathAmp=0.14) → 10 × 1.14 = 11.4
    expect(computeNodeRadius({ baseRadius: 10, energy: 1, breathAmp: 0.14 })).toBeCloseTo(11.4, 6);
  });

  it('never returns negative or zero radius', () => {
    expect(computeNodeRadius({ baseRadius: 6, energy: -100, breathAmp: 0.5 })).toBeGreaterThan(0);
  });
});

describe('computeLinkAlpha', () => {
  it('returns 0.35 floor at zero energies', () => {
    expect(computeLinkAlpha(0, 0)).toBeCloseTo(0.35, 6);
  });

  it('saturates at 0.95 when either endpoint is at energy 1', () => {
    expect(computeLinkAlpha(1, 0)).toBeCloseTo(0.95, 6);
    expect(computeLinkAlpha(0, 1)).toBeCloseTo(0.95, 6);
    expect(computeLinkAlpha(1, 1)).toBeCloseTo(0.95, 6);
  });

  it('uses max of the two endpoint energies', () => {
    expect(computeLinkAlpha(0.2, 0.6)).toBeCloseTo(0.35 + 0.6 * 0.6, 6);
  });

  it('clamps alpha into [0, 1] even with out-of-range input', () => {
    expect(computeLinkAlpha(-1, -1)).toBeGreaterThanOrEqual(0);
    expect(computeLinkAlpha(5, 5)).toBeLessThanOrEqual(1);
  });
});

describe('computeLinkWidth', () => {
  it('returns 1.0 at zero energies and scales linearly to 1.8 at max', () => {
    expect(computeLinkWidth(0, 0)).toBeCloseTo(1.0, 6);
    expect(computeLinkWidth(1, 0)).toBeCloseTo(1.8, 6);
    expect(computeLinkWidth(0, 1)).toBeCloseTo(1.8, 6);
  });
});
```

- [ ] **Step 2: Run, expect fail.**

- [ ] **Step 3: Implementation**

```ts
/**
 * Pure visual math used by renderNodes.ts and renderLinks.ts. Kept separate
 * so the formulas can be unit-tested without a canvas or React.
 */

export interface NodeRadiusInput {
  baseRadius: number;
  energy: number;
  breathAmp: number;
}

const clamp = (x: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, x));

export function computeNodeRadius(input: NodeRadiusInput): number {
  const raw = input.baseRadius * (1 + input.energy * input.breathAmp);
  // Guarantee a positive radius even if a runaway negative energy is fed in.
  return Math.max(input.baseRadius * 0.2, raw);
}

/**
 * 0.35 floor + 0.6 × max(srcEnergy, dstEnergy), clamped to [0,1].
 * Per spec §5.4 — energy is the sole modulation signal (no edgeWeight field).
 */
export function computeLinkAlpha(srcEnergy: number, dstEnergy: number): number {
  const peak = Math.max(srcEnergy, dstEnergy);
  return clamp(0.35 + 0.6 * peak, 0, 1);
}

/** 1.0 + max(srcEnergy, dstEnergy) × 0.8 — clamped to a sensible band. */
export function computeLinkWidth(srcEnergy: number, dstEnergy: number): number {
  const peak = Math.max(srcEnergy, dstEnergy);
  return clamp(1.0 + 0.8 * peak, 0.5, 3);
}
```

- [ ] **Step 4: Run, expect green.**
- [ ] **Step 5: Commit**

```bash
git add dashboard/src/components/graph/constellation/renderMath.ts \
        dashboard/src/components/graph/constellation/__tests__/renderMath.test.ts
git commit -m "feat(graph): pure render-math helpers (node radius, link alpha, link width)"
```

---

## Task 5: `renderNodes.ts` — canvas drawer for nodes (uses helpers + exposes _paintHook)

This task does NOT have its own test (paint logic is verified manually + via the future integration test that will use `_paintHook`). The pure math is already covered by Task 4.

**Files:**
- Create: `dashboard/src/components/graph/constellation/renderNodes.ts`

- [ ] **Step 1: Carefully read the existing node paint logic** in `dashboard/src/components/graph/ConstellationGraph.tsx` (lines ~280–460 — cluster halo, inner core glow, scatter star dots, label, selected bloom). The output here must preserve every visual the user already has, then layer breathing + sun on top.

- [ ] **Step 2: Implementation**

`dashboard/src/components/graph/constellation/renderNodes.ts`:

```ts
import { computeNodeRadius } from './renderMath.js';
import type { IntensitySettings } from './intensity.js';

export interface NodePaintInput {
  ctx: CanvasRenderingContext2D;
  globalScale: number; // force-graph zoom level
  node: {
    id: string;
    x?: number;
    y?: number;
    name?: string;
    colour: string;
    memoryCount: number;
    isCluster?: boolean;
    clusterType?: string;
    entityCount?: number;
  };
  intensity: IntensitySettings;
  energy: number;        // Layer C breathing + Layer A spike
  recallEnergy: number;  // Layer B glow
  isAnchor: boolean;
  isSelected: boolean;
  isHovered: boolean;
  baseRadius: number;
}

export interface NodePaintOpts {
  /** Test-only: invoked once per paint with the computed values. */
  _paintHook?: (info: { nodeId: string; radius: number; energy: number; recallEnergy: number }) => void;
}

const SUN_COLOUR = '#fde68a';
const RECALL_GLOW_COLOUR = '#fb923c';

/**
 * Paint one node. Preserves existing cluster-halo + inner-core-glow + label
 * behaviour from the legacy ConstellationGraph and adds:
 *   - Breathing modulation of the node radius (via energy)
 *   - Warm recall glow ring on memory.accessed events
 *   - Distinct sun ring + halo for the current anchor
 */
export function paintNode(input: NodePaintInput, opts: NodePaintOpts = {}): void {
  const { ctx, node, intensity, energy, recallEnergy, isAnchor, isSelected, baseRadius } = input;
  if (node.x === undefined || node.y === undefined) return;

  const r = computeNodeRadius({ baseRadius, energy, breathAmp: intensity.breathAmp });
  opts._paintHook?.({ nodeId: node.id, radius: r, energy, recallEnergy });

  // Outer halo (always-on; brighter for anchor and on selected).
  const haloR = r * (isAnchor ? 5 : 3.5);
  const haloAlphaHex = isAnchor ? '40' : isSelected ? '50' : '20';
  const halo = ctx.createRadialGradient(node.x, node.y, r * 0.2, node.x, node.y, haloR);
  halo.addColorStop(0, node.colour + haloAlphaHex);
  halo.addColorStop(1, node.colour + '00');
  ctx.beginPath();
  ctx.arc(node.x, node.y, haloR, 0, Math.PI * 2);
  ctx.fillStyle = halo;
  ctx.fill();

  // Warm recall ring (Layer B).
  if (recallEnergy > 0.05) {
    ctx.beginPath();
    ctx.arc(node.x, node.y, r * 1.6, 0, Math.PI * 2);
    ctx.strokeStyle = RECALL_GLOW_COLOUR;
    ctx.globalAlpha = Math.min(0.7, recallEnergy);
    ctx.lineWidth = 1.5;
    ctx.stroke();
    ctx.globalAlpha = 1;
  }

  // Anchor sun overrides node colour with a warm fill + ring.
  if (isAnchor) {
    ctx.beginPath();
    ctx.arc(node.x, node.y, r, 0, Math.PI * 2);
    ctx.fillStyle = SUN_COLOUR;
    ctx.fill();
    ctx.lineWidth = 1.5;
    ctx.strokeStyle = '#fbbf24';
    ctx.stroke();
    return;
  }

  // Satellite — colour from cluster.
  ctx.beginPath();
  ctx.arc(node.x, node.y, r, 0, Math.PI * 2);
  ctx.fillStyle = node.colour;
  ctx.fill();
  if (isSelected) {
    ctx.lineWidth = 1.5;
    ctx.strokeStyle = '#ffffff';
    ctx.stroke();
  }
}
```

- [ ] **Step 3: Build the project to confirm the new file compiles**

```bash
cd dashboard && npx tsc --noEmit && cd ..
```
Expected: zero errors.

- [ ] **Step 4: Commit**

```bash
git add dashboard/src/components/graph/constellation/renderNodes.ts
git commit -m "feat(graph): renderNodes — breathing modulation, recall glow, sun rendering"
```

---

## Task 6: `renderLinks.ts` — additive gradient stroke + cap-aware particle assignment

**Files:**
- Create: `dashboard/src/components/graph/constellation/renderLinks.ts`

- [ ] **Step 1: Implementation**

`dashboard/src/components/graph/constellation/renderLinks.ts`:

```ts
import { computeLinkAlpha, computeLinkWidth } from './renderMath.js';

export interface LinkPaintInput {
  ctx: CanvasRenderingContext2D;
  link: {
    source: { x?: number; y?: number; colour?: string; id: string };
    target: { x?: number; y?: number; colour?: string; id: string };
  };
  srcEnergy: number;
  dstEnergy: number;
}

const FALLBACK_COLOUR = '#7dd3fc';

/**
 * Paint one link as a gradient stroke (source colour → target colour) using
 * additive blending so overlapping links bloom into one another. Width and
 * alpha are modulated by max(srcEnergy, dstEnergy) — energy is the sole
 * modulation signal (GraphLink has no edge weight; see spec §5.4).
 */
export function paintLink(input: LinkPaintInput): void {
  const { ctx, link, srcEnergy, dstEnergy } = input;
  const s = link.source;
  const t = link.target;
  if (s.x === undefined || s.y === undefined || t.x === undefined || t.y === undefined) return;

  const previousOp = ctx.globalCompositeOperation;
  ctx.globalCompositeOperation = 'lighter';

  const gradient = ctx.createLinearGradient(s.x, s.y, t.x, t.y);
  gradient.addColorStop(0, (s.colour ?? FALLBACK_COLOUR));
  gradient.addColorStop(1, (t.colour ?? FALLBACK_COLOUR));

  ctx.strokeStyle = gradient;
  ctx.globalAlpha = computeLinkAlpha(srcEnergy, dstEnergy);
  ctx.lineWidth = computeLinkWidth(srcEnergy, dstEnergy);
  ctx.beginPath();
  ctx.moveTo(s.x, s.y);
  ctx.lineTo(t.x, t.y);
  ctx.stroke();

  ctx.globalAlpha = 1;
  ctx.globalCompositeOperation = previousOp;
}
```

- [ ] **Step 2: Typecheck**

```bash
cd dashboard && npx tsc --noEmit && cd ..
```

- [ ] **Step 3: Commit**

```bash
git add dashboard/src/components/graph/constellation/renderLinks.ts
git commit -m "feat(graph): renderLinks — additive-blend gradient stroke"
```

---

## Task 7: `controls.ts` — drag-to-pin + smooth zoom + double-click handlers

**Files:**
- Create: `dashboard/src/components/graph/constellation/controls.ts`

- [ ] **Step 1: Implementation**

`dashboard/src/components/graph/constellation/controls.ts`:

```ts
import type { ForceGraphMethods, NodeObject } from 'react-force-graph-2d';

/**
 * Wires drag-to-pin and zoom polish onto a react-force-graph-2d instance.
 *
 * - onNodeDragEnd: sets node.fx/fy = current x/y so the node stays where it
 *   was dropped (drag-to-pin). The legacy graph did not do this — drag-release
 *   let the simulation snap the node back, which the user reported as
 *   "drag fights the simulation."
 * - onShiftClick: releases a user-pinned node (fx = fy = null).
 *   Reading the modifier from the most recent native event is the cleanest
 *   path — react-force-graph passes through the original PointerEvent.
 *
 * Anchor click-to-orbit is handled in ConstellationGraph itself (it owns
 * selection state); this module only handles direct manipulation.
 */
export interface ControlsOpts {
  /**
   * Called when the user shift-clicks a node that is currently user-pinned.
   * Used to clear the pin glyph from React state (controls.ts itself only
   * mutates the runtime force-graph node).
   */
  onUnpin?: (nodeId: string) => void;
}

interface PinnableNode {
  id: string;
  fx?: number | null;
  fy?: number | null;
  x?: number;
  y?: number;
}

const DOUBLE_CLICK_MS = 300;

export function wireControls(
  fgRef: React.MutableRefObject<ForceGraphMethods<NodeObject<PinnableNode>> | undefined>,
  opts: ControlsOpts = {},
) {
  // Per-node last-click timestamps so onNodeClick can synthesise "node double
  // click" (the library doesn't expose onNodeDoubleClick directly).
  const lastClick = new Map<string, number>();

  return {
    handleNodeDragEnd(node: NodeObject<PinnableNode>) {
      if (node.x === undefined || node.y === undefined) return;
      node.fx = node.x;
      node.fy = node.y;
    },

    /**
     * Returns one of:
     *   'unpin'        — caller should NOT also re-anchor
     *   'double-click' — caller should NOT re-anchor; smooth-zoom on the node instead
     *   'single-click' — caller does click-to-orbit + selection
     */
    handleNodeClick(node: NodeObject<PinnableNode>, event: MouseEvent): 'unpin' | 'double-click' | 'single-click' {
      if (event.shiftKey && node.fx !== null && node.fx !== undefined) {
        node.fx = null;
        node.fy = null;
        opts.onUnpin?.(String(node.id));
        lastClick.delete(String(node.id));
        return 'unpin';
      }
      const id = String(node.id);
      const now = performance.now();
      const prev = lastClick.get(id) ?? 0;
      lastClick.set(id, now);
      if (now - prev <= DOUBLE_CLICK_MS) {
        // Smooth zoom into the node, per spec §5.5. Does NOT change anchor.
        if (node.x !== undefined && node.y !== undefined) {
          fgRef.current?.centerAt(node.x, node.y, 600);
          fgRef.current?.zoom(2, 600);
        }
        lastClick.delete(id);
        return 'double-click';
      }
      return 'single-click';
    },

    handleBackgroundDoubleClick(reset: () => void) {
      reset();
      fgRef.current?.zoomToFit(600, 80);
    },
  };
}

/**
 * Wheel-debounce note (spec §5.5): react-force-graph-2d's built-in wheel zoom
 * already uses d3-zoom which is frame-throttled and momentum-smoothed — adding
 * a manual 50ms debounce on the wrapping container fights the library's own
 * smoothing. We skip the explicit debounce here and rely on d3-zoom defaults.
 * If users report jumpy zoom in the wild, the next iteration can wrap the
 * canvas in a div that throttles wheel events with `lodash.throttle(50)` —
 * the rest of the control surface does not depend on this.
 */
```

- [ ] **Step 2: Typecheck**

```bash
cd dashboard && npx tsc --noEmit && cd ..
```

- [ ] **Step 3: Commit**

```bash
git add dashboard/src/components/graph/constellation/controls.ts
git commit -m "feat(graph): controls — drag-to-pin + shift-click unpin + dblclick reset"
```

---

## Task 7.5: Server — surface `entity_ids` on memory events + `/api/memories` responses

**Why this exists:** the spec assumed the pulse layer (memory.created / memory.accessed events) carries `entity_ids` so the client can map an event to graph nodes. Reality: `memory_created` / `memory_accessed` WS payloads are `{ memory: Memory }` with no entity refs, and `Memory` itself has none. Entity linking IS synchronous in `addMemory` (`src/memory/store.ts:531` — `processExtractionResult`) but it runs **after** `emitMemoryCreated`/`persistEvent`. Without this task, Layer A and Layer B never fire on real data and the whole "alive" feel is dead on arrival despite green unit tests. Reordering + a small payload extension fixes it without changing the existing API contract destructively.

**Files:**
- Modify: `src/memory/store.ts` (reorder; extend event payloads)
- Modify: `src/api/events.ts` (extend `MemoryCreatedEvent` / `MemoryAccessedEvent` types)
- Modify: `src/api/routes/memories.ts` (include `entity_ids` per row in `/api/memories` responses)
- Create: `src/__tests__/memory-event-entity-ids.test.ts`

- [ ] **Step 1: Failing test for the new shape**

`src/__tests__/memory-event-entity-ids.test.ts`:

```ts
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { initDatabase, closeDatabase, getDatabase } from '../database/init.js';
import { addMemory } from '../memory/store.js';
import { onMemoryEvent, type MemoryCreatedEvent } from '../api/events.js';

describe('memory_created event payload', () => {
  beforeEach(() => initDatabase(':memory:'));
  afterEach(() => closeDatabase());

  it('includes entity_ids for entities extracted from the memory', async () => {
    const received: MemoryCreatedEvent[] = [];
    const off = onMemoryEvent('memory_created', (e) => received.push(e as MemoryCreatedEvent));
    try {
      // Content with names the extractor actually recognises (TOOLS_AND_SERVICES
      // dictionary lists `PostgreSQL` and `Docker` exactly — `Postgres` does not match).
      addMemory({
        type: 'long_term',
        category: 'architecture',
        title: 'PostgreSQL + Docker rollout decision',
        content: 'We decided to use PostgreSQL and Docker for the new SaaS billing service.',
        project: '*',
      });
      await new Promise((r) => setTimeout(r, 10));
      expect(received).toHaveLength(1);
      const event = received[0];
      expect(event.data.memory.id).toBeGreaterThan(0);
      expect(Array.isArray(event.data.entity_ids)).toBe(true);
      expect(event.data.entity_ids.length).toBeGreaterThan(0); // load-bearing
      // Memory must have at least one linked entity in the memory_entities table after the event.
      const db = getDatabase();
      const rows = db.prepare('SELECT entity_id FROM memory_entities WHERE memory_id = ?').all(event.data.memory.id) as { entity_id: number }[];
      expect(event.data.entity_ids.sort()).toEqual(rows.map(r => r.entity_id).sort());
    } finally {
      off();
    }
  });
});
```

- [ ] **Step 2: Run, expect fail** (field `entity_ids` missing).

```bash
node scripts/run-jest.mjs src/__tests__/memory-event-entity-ids.test.ts 2>&1 | tail -8
```

- [ ] **Step 3: Extend the event types**

In `src/api/events.ts`:

```ts
export interface MemoryCreatedEvent extends MemoryEvent {
  type: 'memory_created';
  data: {
    memory: Memory;
    entity_ids: number[];   // ← new
  };
}

export interface MemoryAccessedEvent extends MemoryEvent {
  type: 'memory_accessed';
  data: {
    memoryId: number;
    memory: Memory;
    newSalience: number;
    entity_ids: number[];   // ← new
  };
}
```

- [ ] **Step 4: Reorder + extend emit in `addMemory`**

In `src/memory/store.ts` `addMemory`, move the `processExtractionResult` block **before** the three emit/persist/webhook calls, capture entity_ids, then emit with them. The current order (lines ~501-540):

```ts
// CURRENT (broken — emits before entity link exists):
const memory = getMemoryById(insertedId)!;
emitMemoryCreated(memory);
persistEvent('memory_created', { memory });
dispatchWebhook('memory_created', { id: memory.id, title: memory.title, category: memory.category });
// auto-link block …
// entity extraction block (processExtractionResult) …
```

becomes:

```ts
// NEW (entity link runs first, payload includes entity_ids):
const memory = getMemoryById(insertedId)!;

// Entity extraction is synchronous; do it FIRST so memory_created carries entity_ids.
let entityIds: number[] = [];
try {
  const extraction = extractFromMemory(input.title, truncationResult.content, category);
  if (extraction.entities.length > 0) {
    processExtractionResult(extraction, memory.id);
    if (isFeatureEnabled('cloud_sync')) syncGraphForMemoryToCloud(memory.id);
  }
  const db = getDatabase();
  entityIds = (db.prepare('SELECT entity_id FROM memory_entities WHERE memory_id = ?').all(memory.id) as { entity_id: number }[]).map(r => r.entity_id);
} catch (e) {
  console.error('[shieldcortex] Entity extraction failed:', e);
}

// Now emit with entity_ids populated.
emitMemoryCreated(memory, entityIds);
persistEvent('memory_created', { memory, entity_ids: entityIds });
dispatchWebhook('memory_created', { id: memory.id, title: memory.title, category: memory.category });
// auto-link block (detectRelationships → createMemoryLink) stays where it is — it doesn't affect entity_ids.
```

Update the `emitMemoryCreated` helper signature in `src/api/events.ts` to accept the new arg and include it in the event payload. Apply the same treatment to the memory-access path: the single `emitMemoryAccessed` call site is **`src/memory/lifecycle.ts:78`** — read `entity_ids` from the `memory_entities` table for the accessed memory id at emit time (one prepared statement, no schema change).

- [ ] **Step 5: Extend `/api/memories` response with `entity_ids` per row**

In `src/api/routes/memories.ts`, after `paginatedMemories.map((memory) => ({ ...memory, decayedScore: ... }))`, do a single batched query for entity_ids keyed by memory id:

```ts
const ids = paginatedMemories.map((m) => m.id);
const linkRows = ids.length === 0 ? [] : (db.prepare(
  `SELECT memory_id, entity_id FROM memory_entities WHERE memory_id IN (${ids.map(() => '?').join(',')})`,
).all(...ids) as { memory_id: number; entity_id: number }[]);
const byMemoryId = new Map<number, number[]>();
for (const row of linkRows) {
  const arr = byMemoryId.get(row.memory_id) ?? [];
  arr.push(row.entity_id);
  byMemoryId.set(row.memory_id, arr);
}
const memoriesWithDecay = paginatedMemories.map((memory) => ({
  ...memory,
  decayedScore: calculateDecayedScore(memory),
  entity_ids: byMemoryId.get(memory.id) ?? [],
}));
```

- [ ] **Step 6: Run the new test + the existing memories-related tests**

```bash
node scripts/run-jest.mjs src/__tests__/memory-event-entity-ids.test.ts 2>&1 | tail -6
node scripts/run-jest.mjs src/__tests__/ -t "memor" 2>&1 | tail -6
```
Expected: new test green, no regressions.

- [ ] **Step 7: Commit**

```bash
git add src/memory/store.ts src/api/events.ts src/api/routes/memories.ts src/__tests__/memory-event-entity-ids.test.ts
git commit -m "feat(events): include entity_ids on memory_created/accessed + GET /api/memories"
```

---

## Task 8: `useGraphPulse.ts` — WS subscribe with `/api/memories?mode=recent` polling fallback

**Files:**
- Create: `dashboard/src/hooks/useGraphPulse.ts`

- [ ] **Step 1: Implementation**

`dashboard/src/hooks/useGraphPulse.ts`:

```ts
'use client';

import { useEffect, useRef } from 'react';
import type { PulseDriver } from '@/components/graph/constellation/pulse';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';
const POLL_INTERVAL_MS = 10_000;

/**
 * Subscribes the given PulseDriver to /ws/events and dispatches
 * memory.created / memory.accessed events to it. On WS failure it falls back
 * to polling GET /api/memories?mode=recent every 10 seconds, synthesising
 * memory.created events from rows newer than the last seen created_at.
 */
export function useGraphPulse(
  driver: PulseDriver | null,
  enabled: boolean = true,
): void {
  const lastSeenRef = useRef<string | null>(null);

  useEffect(() => {
    if (!driver || !enabled) return;

    let ws: WebSocket | null = null;
    let pollTimer: ReturnType<typeof setInterval> | null = null;
    let cancelled = false;

    const dispatchEvent = (raw: unknown): void => {
      if (!driver) return;
      // Server contract (set by Task 7.5 in this plan):
      //   memory_created  → data: { memory, entity_ids: number[] }
      //   memory_accessed → data: { memoryId, memory, newSalience, entity_ids: number[] }
      const obj = raw as { type?: string; data?: { entity_ids?: number[] } };
      if (!obj?.type || !obj.data) return;
      const pulseType =
        obj.type === 'memory_created'  ? 'memory.created' :
        obj.type === 'memory_accessed' ? 'memory.accessed' : null;
      if (!pulseType) return;
      const ids = obj.data.entity_ids ?? [];
      for (const id of ids) driver.dispatch({ type: pulseType, entityId: String(id) });
    };

    const startPolling = (): void => {
      if (pollTimer) return;
      pollTimer = setInterval(() => {
        if (cancelled) return;
        const since = lastSeenRef.current;
        fetch(`${API_BASE}/api/memories?mode=recent&limit=50`, { credentials: 'include' })
          .then((r) => (r.ok ? r.json() : null))
          .then((data) => {
            if (!data || cancelled) return;
            // Server contract (Task 7.5): each memory row carries entity_ids: number[].
            const rows: Array<{ created_at?: string; entity_ids?: number[] }> = data.memories ?? [];
            for (const row of rows) {
              if (since && row.created_at && row.created_at <= since) continue;
              for (const id of row.entity_ids ?? []) {
                driver.dispatch({ type: 'memory.created', entityId: String(id) });
              }
            }
            if (rows[0]?.created_at) lastSeenRef.current = rows[0].created_at;
          })
          .catch(() => { /* silent — fallback already; nothing to escalate */ });
      }, POLL_INTERVAL_MS);
    };

    const connect = (): void => {
      try {
        const wsUrl = API_BASE.replace(/^http/, 'ws') + '/ws/events';
        ws = new WebSocket(wsUrl);
        ws.onmessage = (e) => {
          try { dispatchEvent(JSON.parse(e.data)); } catch { /* ignore non-JSON */ }
        };
        ws.onerror = startPolling;
        ws.onclose = () => { if (!cancelled) startPolling(); };
      } catch {
        startPolling();
      }
    };

    connect();

    return () => {
      cancelled = true;
      ws?.close();
      if (pollTimer) clearInterval(pollTimer);
    };
  }, [driver, enabled]);
}
```

- [ ] **Step 2: Typecheck**

```bash
cd dashboard && npx tsc --noEmit && cd ..
```

- [ ] **Step 3: Commit**

```bash
git add dashboard/src/hooks/useGraphPulse.ts
git commit -m "feat(graph): useGraphPulse hook — /ws/events + memories?mode=recent fallback"
```

---

## Task 9: Slim down `ConstellationGraph.tsx` to a wirer (~150 lines)

This is the structural commit that swaps the monolith for the new modules. Do it after every new module compiles and its tests pass — this is the moment the user-visible graph changes.

**Files:**
- Modify: `dashboard/src/components/graph/ConstellationGraph.tsx`

- [ ] **Step 1:** Read the current `ConstellationGraph.tsx` end to end (527 lines). Identify which sections survive verbatim (cluster halo loop is preserved — already covered in renderNodes.ts; the `activeCluster` toggle and search-highlight behaviours stay) and which are replaced wholesale (force config, link rendering, node rendering, click handler).

- [ ] **Step 2:** Rewrite the file. The shape:

```tsx
'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import dynamic from 'next/dynamic';
import type { ForceGraphMethods, NodeObject, LinkObject, ForceGraphProps } from 'react-force-graph-2d';
import type { ClusterData, FullGraphData, GraphEntity } from '@/hooks/useGraphData';
import { paintNode } from './constellation/renderNodes.js';
import { paintLink } from './constellation/renderLinks.js';
import { pickAnchor, applyAnchor } from './constellation/anchor.js';
import { PulseDriver } from './constellation/pulse.js';
import { INTENSITY, loadIntensity, type IntensityLevel } from './constellation/intensity.js';
import { wireControls } from './constellation/controls.js';
import { useGraphPulse } from '@/hooks/useGraphPulse';

// (… GNode / GLink type aliases identical to today …)

const ForceGraph2D = dynamic(() => import('react-force-graph-2d'), { ssr: false }) as unknown as
  (props: ForceGraphProps<GNode, GLink>) => React.ReactElement;

interface Props {
  data: FullGraphData;
  width: number;
  height: number;
  selectedEntity: GraphEntity | null;
  onSelectEntity: (e: GraphEntity | null) => void;
}

export function ConstellationGraph(props: Props) {
  const { data, width, height, selectedEntity, onSelectEntity } = props;
  const graphRef = useRef<ForceGraphMethods<GNode, GLink> | undefined>(undefined);

  // Intensity — read once, listen for live changes.
  const [level, setLevel] = useState<IntensityLevel>(() => loadIntensity());
  useEffect(() => {
    const onChange = (e: Event) => setLevel((e as CustomEvent).detail as IntensityLevel);
    window.addEventListener('shieldcortex:intensity-changed', onChange);
    return () => window.removeEventListener('shieldcortex:intensity-changed', onChange);
  }, []);

  // Pulse driver lives across renders.
  const driverRef = useRef<PulseDriver | null>(null);
  if (driverRef.current === null) driverRef.current = new PulseDriver({ intensity: level });
  useEffect(() => { driverRef.current?.setIntensity(level); }, [level]);

  // Build node/link arrays (existing transform — keep verbatim from old code).
  const graphData = useMemo(() => buildGraphData(data), [data]);

  // Anchor: pick + apply on data change. Re-evaluation rule (spec §5.1):
  // node count changes OR top-ranked node's memoryCount × edgeCount delta > 5%.
  const [anchorId, setAnchorId] = useState<string | null>(null);
  const anchorScoreRef = useRef<number>(0);
  useEffect(() => {
    const newAnchor = pickAnchor(graphData.nodes, graphData.links);
    if (!newAnchor) return;
    // Always observe the current node set so breathing kicks in.
    driverRef.current?.observeNodes(graphData.nodes.map((n) => n.id));
    // Score the new pick using the same formula as anchor.ts so we can
    // compare deltas (anchor.ts deliberately doesn't return the score).
    const newScore = scoreOf(newAnchor, graphData.nodes, graphData.links);
    const prevScore = anchorScoreRef.current;
    const delta = prevScore === 0 ? Infinity : Math.abs(newScore - prevScore) / prevScore;
    const shouldSwap = anchorId === null || newAnchor !== anchorId && delta > 0.05;
    if (shouldSwap) {
      applyAnchor(graphData.nodes, newAnchor, anchorId);
      setAnchorId(newAnchor);
      anchorScoreRef.current = newScore;
      setTimeout(() => graphRef.current?.zoomToFit(600, 80), 600);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graphData.nodes.length, graphData.links.length]);

  function scoreOf(id: string, nodes: GNode[], links: GLink[]): number {
    const node = nodes.find((n) => n.id === id);
    if (!node) return 0;
    const idSet = new Set(nodes.map((n) => n.id));
    let degree = 0;
    for (const l of links) {
      const s = typeof l.source === 'string' ? l.source : (l.source as { id: string }).id;
      const t = typeof l.target === 'string' ? l.target : (l.target as { id: string }).id;
      if (s === id && idSet.has(t)) degree++;
      if (t === id && idSet.has(s)) degree++;
    }
    return node.memoryCount * degree;
  }

  // Wire WebSocket / polling for pulse spikes.
  useGraphPulse(driverRef.current);

  // Force tuning — center pull stronger so the sun behaves like a sun.
  useEffect(() => {
    const fg = graphRef.current;
    if (!fg) return;
    fg.d3Force('charge')?.strength(-120);
    fg.d3Force('link')?.distance(70);
    fg.d3Force('center')?.strength(0.12);
  }, [graphData.nodes.length]);

  const controls = useMemo(() => wireControls(graphRef, { onUnpin: () => {} }), []);

  // Click-to-orbit: clicked node becomes the new anchor — UNLESS controls
  // intercepts it as a shift-click unpin or a double-click smooth-zoom.
  const handleNodeClick = (node: GNode, evt: MouseEvent) => {
    const verdict = controls.handleNodeClick(node, evt);
    if (verdict !== 'single-click') return;
    applyAnchor(graphData.nodes, node.id, anchorId);
    setAnchorId(node.id);
    anchorScoreRef.current = scoreOf(node.id, graphData.nodes, graphData.links);
    onSelectEntity({ id: node.id, name: node.name, type: node.type, memoryCount: node.memoryCount });
    graphRef.current?.centerAt(0, 0, 600);
  };

  const handleBackgroundDoubleClick = () => {
    controls.handleBackgroundDoubleClick(() => {
      const fallback = pickAnchor(graphData.nodes, graphData.links);
      if (fallback) {
        applyAnchor(graphData.nodes, fallback, anchorId);
        setAnchorId(fallback);
      }
      onSelectEntity(null);
    });
  };

  // Particle assignment — recomputed each frame's pre-render.
  const particleSet = useRef<Set<string>>(new Set());
  const onRenderFramePre = () => {
    const d = driverRef.current;
    if (!d) return;
    d.onFrame(performance.now());
    const chosen = d.pickParticleEdges(graphData.links, anchorId);
    particleSet.current = new Set(chosen.map(linkKey));
  };

  return (
    <div onDoubleClick={handleBackgroundDoubleClick}>
      <ForceGraph2D
        ref={graphRef}
        graphData={graphData}
        width={width}
        height={height}
        backgroundColor="#06070d"
        cooldownTicks={Infinity}
        d3AlphaDecay={0}
        d3VelocityDecay={0.6}
        nodeCanvasObjectMode={() => 'replace'}
        nodeCanvasObject={(node, ctx, globalScale) => {
          const id = String(node.id);
          paintNode({
            ctx, globalScale, node: node as unknown as GNode,
            intensity: INTENSITY[level],
            energy: driverRef.current?.getEnergy(id) ?? 0,
            recallEnergy: driverRef.current?.getRecallEnergy(id) ?? 0,
            isAnchor: id === anchorId,
            isSelected: selectedEntity?.id === id,
            isHovered: false,
            baseRadius: Math.max(4, Math.sqrt((node as any).memoryCount + 1) * 2),
          });
        }}
        linkCanvasObjectMode={() => 'replace'}
        linkCanvasObject={(link, ctx) => {
          paintLink({
            ctx, link: link as any,
            srcEnergy: driverRef.current?.getEnergy(String((link.source as any).id)) ?? 0,
            dstEnergy: driverRef.current?.getEnergy(String((link.target as any).id)) ?? 0,
          });
        }}
        linkDirectionalParticles={(link) =>
          particleSet.current.has(linkKey(link as any)) ? 2 : 0}
        linkDirectionalParticleSpeed={0.006}
        onNodeClick={handleNodeClick as any}
        onNodeDragEnd={controls.handleNodeDragEnd as any}
        onRenderFramePre={onRenderFramePre}
      />
    </div>
  );
}

function linkKey(link: { source: any; target: any }): string {
  const s = typeof link.source === 'string' ? link.source : link.source.id;
  const t = typeof link.target === 'string' ? link.target : link.target.id;
  return `${s}|${t}`;
}

// buildGraphData(): preserved from the legacy implementation (cluster/normal mode toggle).
// Copy verbatim from the previous ConstellationGraph; not re-written here.
```

(The implementer fills in `buildGraphData` and the `GNode`/`GLink` types from the existing file — this is a transcription task, not a redesign.)

- [ ] **Step 3: Verify build + lint**

```bash
cd dashboard && npx tsc --noEmit && npm run lint && cd ..
```
Expected: zero errors, no new warnings beyond the ones already present.

- [ ] **Step 4: Manual smoke test**

```bash
cd dashboard && npm run dev
# Open http://localhost:3030/memory?tab=graph
```
Confirm:
- The graph renders.
- A node is anchored at canvas centre (yellow ring).
- Clicking another node smoothly re-anchors it.
- Dragging a node and releasing it stays in place; shift-click releases.
- Double-clicking empty space resets to the default sun and zoom-to-fit.
- Links visibly glow and active edges show drifting particles.

- [ ] **Step 5: Commit**

```bash
git add dashboard/src/components/graph/ConstellationGraph.tsx
git commit -m "refactor(graph): swap ConstellationGraph monolith for the constellation/ modules"
```

---

## Task 10: Intensity 3-radio selector in `SettingsView.tsx`

**Files:**
- Modify: `dashboard/src/components/settings/SettingsView.tsx`

- [ ] **Step 1:** Read the file to find an appropriate section (an existing card-style settings group).

- [ ] **Step 2:** Add a "Graph Motion" section:

```tsx
import { loadIntensity, saveIntensity, type IntensityLevel } from '@/components/graph/constellation/intensity';

// inside the component body:
const [intensity, setIntensity] = useState<IntensityLevel>(() => loadIntensity());
const onIntensityChange = (next: IntensityLevel) => {
  setIntensity(next);
  saveIntensity(next);
};

// inside the JSX:
<section className="…">
  <h3>Graph Motion</h3>
  <p className="subtitle">How lively the knowledge graph feels. Per-browser.</p>
  <div role="radiogroup" aria-label="Graph motion intensity">
    {(['subtle', 'moderate', 'strong'] as const).map((level) => (
      <label key={level} className="…">
        <input
          type="radio"
          name="graph-intensity"
          value={level}
          checked={intensity === level}
          onChange={() => onIntensityChange(level)}
        />
        <span>{level[0].toUpperCase() + level.slice(1)}</span>
      </label>
    ))}
  </div>
</section>
```

- [ ] **Step 3: Typecheck + lint, then manually verify the live graph picks up the change** (the CustomEvent path in `intensity.ts`'s `saveIntensity`).

- [ ] **Step 4: Commit**

```bash
git add dashboard/src/components/settings/SettingsView.tsx
git commit -m "feat(settings): graph motion intensity selector (subtle/moderate/strong)"
```

---

## Task 11: `prefers-reduced-motion` handling

**Files:**
- Modify: `dashboard/src/components/graph/constellation/intensity.ts`
- Modify: `dashboard/src/components/graph/ConstellationGraph.tsx`

- [ ] **Step 1:** Add a `reducedMotion` profile to `INTENSITY` (or a flag) so all timed animations short-circuit:

```ts
// intensity.ts — append:
export function isReducedMotion(): boolean {
  if (typeof window === 'undefined' || !window.matchMedia) return false;
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

export const REDUCED_INTENSITY: IntensitySettings = {
  breathPeriod: Number.POSITIVE_INFINITY, // sin(0) → no breathing
  breathAmp: 0,
  particleCap: 0,
  decayCreate: 0,   // any spike vanishes next frame
  decayRecall: 0,
};
```

- [ ] **Step 2:** In `ConstellationGraph.tsx`, swap `INTENSITY[level]` for `isReducedMotion() ? REDUCED_INTENSITY : INTENSITY[level]` wherever it's read. Also: when reduced motion is on, replace the `centerAt(0, 0, 600)` smooth tweens with `centerAt(0, 0, 0)` (instant).

- [ ] **Step 3:** Test manually by enabling reduced motion in macOS / browser dev tools. Expect: no breathing, no particles, instant zoom-to-anchor.

- [ ] **Step 4: Commit**

```bash
git commit -am "feat(graph): respect prefers-reduced-motion across breathing/particles/zoom"
```

---

## Task 12: Dev-only pulse debug panel

**Files:**
- Create: `dashboard/src/components/graph/PulseDebugPanel.tsx`
- Modify: `dashboard/src/components/graph/UnifiedGraph.tsx`

- [ ] **Step 1:** Write `PulseDebugPanel.tsx` — a small floating panel that lets you type an entity id and fire `memory.created` / `memory.accessed`. Render it conditionally:

```tsx
'use client';
import { useState } from 'react';
import type { PulseDriver } from './constellation/pulse';

export function PulseDebugPanel({ driver }: { driver: PulseDriver | null }) {
  if (typeof window === 'undefined') return null;
  if (window.localStorage.getItem('SHIELDCORTEX_DEBUG_PULSE') !== '1') return null;
  const [id, setId] = useState('');
  if (!driver) return null;
  return (
    <div style={{ position:'absolute', bottom:8, right:8, padding:8, background:'#0a0d14cc', color:'#e2e8f0', fontSize:12, border:'1px solid #1e293b' }}>
      <div style={{ marginBottom:4, opacity:.6 }}>pulse debug</div>
      <input value={id} onChange={(e) => setId(e.target.value)} placeholder="entity id"
        style={{ width:140, background:'#06070d', color:'#e2e8f0', border:'1px solid #1e293b', padding:'2px 4px' }} />
      <div style={{ display:'flex', gap:4, marginTop:4 }}>
        <button onClick={() => driver.dispatch({ type:'memory.created', entityId:id })}>created</button>
        <button onClick={() => driver.dispatch({ type:'memory.accessed', entityId:id })}>accessed</button>
      </div>
    </div>
  );
}
```

- [ ] **Step 2:** Wire it into the `UnifiedGraph` layout alongside the graph canvas (so it gets the same `driverRef` — easiest path is to render it from `ConstellationGraph` with the local `driverRef.current`).

- [ ] **Step 3:** Manual smoke: set `localStorage.SHIELDCORTEX_DEBUG_PULSE = '1'`, reload, type a known entity id, click "created" — confirm the node briefly grows and brightens.

- [ ] **Step 4: Commit**

```bash
git add dashboard/src/components/graph/PulseDebugPanel.tsx dashboard/src/components/graph/UnifiedGraph.tsx
git commit -m "feat(graph): dev-only pulse debug panel (localStorage gated)"
```

---

## Task 13: Verification checklist (apply `@superpowers:verification-before-completion`)

**No new files.** This task is a manual verification gate — do not skip.

- [ ] Pure-module tests green:

```bash
node scripts/run-jest.mjs dashboard/src/components/graph/constellation/__tests__ 2>&1 | tail -10
```
Expected: 4 test files, all green.

- [ ] Full root jest suite has the same baseline as before this work (the known `mcp-registration` flake is permitted; nothing else regressed):

```bash
node scripts/run-jest.mjs 2>&1 | tail -6
```

- [ ] Dashboard build:

```bash
cd dashboard && npx tsc --noEmit && npm run build && cd ..
```

- [ ] Dashboard lint clean (0 new errors):

```bash
cd dashboard && npm run lint && cd ..
```

- [ ] Live dashboard manual check:

```bash
cd dashboard && npm run dev
```

Verify each of the five user complaints is visibly addressed:

| User complaint | Verify |
|---|---|
| "no centre" | Yellow sun node sits at canvas centre on load. |
| "no flow / organic feel" | Nodes drift subtly even when idle; halos breathe. |
| "no pulse connection" | Active edges show drifting particles. |
| "connections don't glow" | Edges have additive-blended gradient glow. |
| "hard to control" | Drag-release pins a node; shift-click unpins; double-click fits. |

- [ ] Toggle the intensity selector in Settings — confirm subtle/moderate/strong visibly change the live graph without reload.

- [ ] Enable reduced motion in the OS — confirm breathing, particles, and zoom tweens all short-circuit to instant.

- [ ] **Perf budget (spec §6):** with `localStorage.SHIELDCORTEX_GRAPH_BENCH = '1000:3000'` (the implementer adds a tiny stub in `ConstellationGraph` that, when this key is set, fabricates a 1000-node / 3000-edge mock dataset on top of the real data — *dev only*), open Chrome DevTools → Performance → Record 5s of the graph at `strong` intensity. Confirm sustained ≥30fps on the dev machine. If sustained fps < 30, lower `INTENSITY.strong.particleCap` until it clears, and note the change in the commit message. Remove the bench stub before pushing (or guard so it only runs in dev). This step does not need passing on a fleet baseline — it just guards against shipping a knowingly-slow `strong` mode.

---

## Task 14: Branch hygiene + push

- [ ] **Step 1:** Re-fetch (concurrent-release safety — there have been collisions in this repo before):

```bash
git fetch origin --tags 2>&1 | tail -2
git merge-base --is-ancestor origin/main HEAD && echo "FF-safe" || echo "DIVERGED — STOP and rebase"
```

- [ ] **Step 2:** Open the PR (do NOT merge from CLI — leave merge to the user):

```bash
gh pr create --base main --title "feat(graph): Living Constellation knowledge graph" \
  --body-file docs/superpowers/specs/2026-05-20-living-constellation-graph-design.md
```

- [ ] **Step 3:** Confirm CI passes on the PR:

```bash
gh pr checks
```

If CI is green, **stop here**. Merging + release version-bump + npm publish are outside the scope of this plan (the user owns the release mechanics per established preferences — see `memory/feedback_release_alignment.md` and `memory/project_node_compat_v4185.md`). Surface the PR link in the final report.

---

## Out of scope (re-stated)

Confirmed deferred during brainstorming — do NOT add to this plan:

- Search-and-fly-to-node camera animation.
- Keyboard arrow neighbour navigation.
- "Focus mode" that dims unrelated nodes.
- Smooth interpolated re-layout on filter toggles.
- WebGL / `@react-three/fiber` migration for the knowledge graph.
- Custom canvas rewrite that drops `react-force-graph-2d`.
- React-Testing-Library integration test that mounts `ConstellationGraph` and reads `_paintHook` output — deferred until dashboard test infra (jest + jsdom + testing-library) is added in a separate workstream. The `_paintHook` contract is shipped now so that test is a clean future add.
- Server-side persistence of `graph.intensity` into `~/.shieldcortex/config.json`.
