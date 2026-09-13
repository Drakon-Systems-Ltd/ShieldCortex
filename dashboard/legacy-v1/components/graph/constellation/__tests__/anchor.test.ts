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
    const links = [l('a', 'b'), l('b', 'd-other'), l('b', 'd-stray')];
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

  it('falls back to memoryCount alone when no node has any edges (alpha tie-break)', () => {
    expect(pickAnchor([n('zeta', 5, 'zeta'), n('alpha', 5, 'alpha')], [])).toBe('alpha');
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
