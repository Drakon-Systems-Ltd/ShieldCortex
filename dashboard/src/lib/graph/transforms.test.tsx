import {
  buildFocusData,
  buildMapData,
  linkTooltip,
  linkWidth,
  withPreservedPositions,
  type NeighbourhoodPayload,
  type OverviewPayload,
} from './transforms';

const overview: OverviewPayload = {
  entities: [
    { id: 1, name: 'alpha', type: 'tool', memoryCount: 10 },
    { id: 2, name: 'beta', type: 'concept', memoryCount: 5 },
    { id: 3, name: 'gamma', type: 'tool', memoryCount: 2 },
  ],
  triples: [
    { id: 11, subjectId: 1, objectId: 2, predicate: 'uses', confidence: 0.9, disputed: false },
    { id: 12, subjectId: 2, objectId: 1, predicate: 'configures', confidence: 0.7, disputed: true },
    { id: 13, subjectId: 1, objectId: 3, predicate: 'related_to', confidence: 0.5, disputed: false },
    { id: 14, subjectId: 2, objectId: 99, predicate: 'uses', confidence: 0.8, disputed: false },
  ],
  counts: { byType: {}, byPredicate: {}, totalEntities: 3, totalEdges: 4, omittedEntities: 0, omittedEdges: 0 },
};

describe('buildMapData', () => {
  it('namespaces ids, bundles parallel triples into one link with real per-predicate data', () => {
    const data = buildMapData(overview);
    expect(data.nodes.map((n) => n.id)).toEqual(['e:1', 'e:2', 'e:3']);
    // 1↔2 has two triples in opposite directions → ONE drawn link, two entries.
    const bundle = data.links.find((l) => l.id === 'e:1|e:2');
    expect(bundle?.triples).toHaveLength(2);
    expect(bundle?.triples?.map((t) => t.predicate).sort()).toEqual(['configures', 'uses']);
    expect(bundle?.triples?.find((t) => t.predicate === 'configures')).toMatchObject({ disputed: true, direction: 'reverse' });
    expect(bundle?.weakOnly).toBe(false);
    // Edge to entity 99 (not in the node set) is dropped: both endpoints rule.
    expect(data.links).toHaveLength(2);
  });

  it('marks related_to-only bundles weak and can drop them', () => {
    const all = buildMapData(overview);
    expect(all.links.find((l) => l.id === 'e:1|e:3')?.weakOnly).toBe(true);
    const strong = buildMapData(overview, { hideWeakLinks: true });
    expect(strong.links.map((l) => l.id)).toEqual(['e:1|e:2']);
  });

  it('applies type and min-mention filters, dropping stranded links with the nodes', () => {
    const noTools = buildMapData(overview, { hiddenTypes: new Set(['tool']) });
    expect(noTools.nodes.map((n) => n.label)).toEqual(['beta']);
    expect(noTools.links).toHaveLength(0);
    const min5 = buildMapData(overview, { minMentions: 5 });
    expect(min5.nodes.map((n) => n.label).sort()).toEqual(['alpha', 'beta']);
  });
});

const nbhd: NeighbourhoodPayload = {
  focal: { id: 1, name: 'alpha', type: 'tool', memoryCount: 10 },
  neighbours: [{ id: 2, name: 'beta', type: 'concept', memoryCount: 5, depth: 1 }],
  triples: [{ id: 11, subject_id: 1, object_id: 2, predicate: 'uses', confidence: 0.9, disputed: false }],
  memories: [
    { id: 7, title: 'note A', type: 'long_term', category: 'error', salience: 0.8, trust_score: 1, status: 'active', pinned: 1, project: null, created_at: '2026-08-01 00:00:00' },
    { id: 8, title: 'note B', type: 'short_term', category: 'note', salience: 0.3, trust_score: 1, status: 'archived', pinned: 0, project: 'atlas', created_at: '2026-08-02 00:00:00' },
  ],
  memoryEntities: [
    { memory_id: 7, entity_id: 1, role: 'subject' },
    { memory_id: 8, entity_id: 1, role: 'mention' },
    { memory_id: 7, entity_id: 42, role: 'mention' }, // entity 42 not loaded → dropped
  ],
  memoryLinks: [
    { id: 91, source_id: 7, target_id: 8, relationship: 'conflicts', strength: 0.9 },
    { id: 92, source_id: 7, target_id: 999, relationship: 'supports', strength: 0.5 }, // 999 not loaded → dropped
  ],
  counts: { totalNeighbours: 1, omittedNeighbours: 0, totalEdges: 1, omittedEdges: 0, totalMemories: 2, omittedMemories: 0 },
};

describe('buildFocusData', () => {
  it('renders all three edge families with endpoint checks', () => {
    const data = buildFocusData(nbhd, true);
    expect(data.nodes.map((n) => n.id).sort()).toEqual(['e:1', 'e:2', 'm:7', 'm:8']);
    expect(data.nodes.find((n) => n.id === 'e:1')?.isFocal).toBe(true);
    const kinds = data.links.map((l) => l.kind).sort();
    expect(kinds).toEqual(['memory-entity', 'memory-entity', 'memory-link', 'triple']);
    expect(data.links.find((l) => l.kind === 'memory-link')).toMatchObject({ relationship: 'conflicts', strength: 0.9 });
  });

  it('hides memories and their edges when showMemories is off', () => {
    const data = buildFocusData(nbhd, false);
    expect(data.nodes).toHaveLength(2);
    expect(data.links.every((l) => l.kind === 'triple')).toBe(true);
  });
});

describe('withPreservedPositions', () => {
  it('clones nodes (cache safety) while carrying x/y/pins over by id', () => {
    const base = buildMapData(overview);
    const prev = [{ ...base.nodes[0], x: 10, y: 20, fx: 10, fy: 20 }];
    const next = withPreservedPositions(base, prev);
    expect(next.nodes[0]).toMatchObject({ x: 10, y: 20, fx: 10, fy: 20 });
    expect(next.nodes[0]).not.toBe(base.nodes[0]); // fresh clone, cache untouched
    expect(base.nodes[0].x).toBeUndefined();
    expect(next.nodes[1].x).toBeUndefined();
  });
});

describe('link width and tooltip honesty', () => {
  it('width grows with the REAL bundled count / strength, never invented weight', () => {
    const data = buildMapData(overview);
    const two = data.links.find((l) => l.id === 'e:1|e:2')!;
    const one = data.links.find((l) => l.id === 'e:1|e:3')!;
    expect(linkWidth(two)).toBeGreaterThan(linkWidth(one));
  });

  it('tooltip lists each predicate with confidence and dispute, oriented correctly', () => {
    const data = buildMapData(overview);
    const two = data.links.find((l) => l.id === 'e:1|e:2')!;
    const text = linkTooltip(two, (id) => (id === 'e:1' ? 'alpha' : 'beta'));
    expect(text).toContain('alpha uses beta (90%)');
    expect(text).toContain('beta configures alpha (70%, disputed)');
  });
});
