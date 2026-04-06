'use client';

import { useQuery } from '@tanstack/react-query';
import { authFetch } from '@/lib/auth';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

// ── Types ──────────────────────────────────────────────────

export interface GraphEntity {
  id: string;
  name: string;
  type: string;
  memoryCount: number;
}

export interface GraphNode extends GraphEntity {
  isFocal?: boolean;
}

export interface GraphLink {
  source: string;
  target: string;
  predicate: string;
}

interface Triple {
  id: number;
  subject_id: number;
  object_id: number;
  predicate: string;
  subject_name: string;
  subject_type: string;
  object_name: string;
  object_type: string;
}

interface RawEntity {
  id: number;
  name: string;
  type: string;
  memoryCount: number;
}

interface NeighbourhoodResponse {
  focal: RawEntity;
  neighbours: RawEntity[];
  triples: Triple[];
  totalConnections: number;
}

export interface LinkedMemory {
  id: number;
  title: string;
  type: string;
  category: string;
  salience: number;
  created_at: string;
}

export interface NeighbourhoodData {
  nodes: GraphNode[];
  links: GraphLink[];
  focal: GraphNode;
  totalConnections: number;
}

// ── Hooks ──────────────────────────────────────────────────

export function useGraphEntities() {
  return useQuery<GraphEntity[]>({
    queryKey: ['graph', 'entities'],
    queryFn: async () => {
      const res = await authFetch(`${API_BASE}/api/graph/entities?limit=30`);
      if (!res.ok) throw new Error('Failed to fetch entities');
      const data = await res.json();
      const entities = (data.entities || []) as RawEntity[];
      return entities
        .map((e) => ({
          id: String(e.id),
          name: e.name,
          type: e.type,
          memoryCount: e.memoryCount,
        }))
        .sort((a, b) => b.memoryCount - a.memoryCount);
    },
    staleTime: 30_000,
  });
}

export function useEntityNeighbourhood(entityId: string | null) {
  return useQuery<NeighbourhoodData | null>({
    queryKey: ['graph', 'neighbourhood', entityId],
    queryFn: async () => {
      if (!entityId) return null;
      const res = await authFetch(`${API_BASE}/api/graph/entities/${entityId}/neighbourhood`);
      if (!res.ok) throw new Error('Failed to fetch neighbourhood');
      const data = (await res.json()) as NeighbourhoodResponse;

      const focal: GraphNode = {
        id: String(data.focal.id),
        name: data.focal.name,
        type: data.focal.type,
        memoryCount: data.focal.memoryCount,
        isFocal: true,
      };

      const nodeMap = new Map<string, GraphNode>();
      nodeMap.set(focal.id, focal);

      for (const n of data.neighbours) {
        nodeMap.set(String(n.id), {
          id: String(n.id),
          name: n.name,
          type: n.type,
          memoryCount: n.memoryCount,
        });
      }

      const links: GraphLink[] = data.triples.map((t) => ({
        source: String(t.subject_id),
        target: String(t.object_id),
        predicate: t.predicate,
      }));

      return {
        nodes: Array.from(nodeMap.values()),
        links,
        focal,
        totalConnections: data.totalConnections,
      };
    },
    enabled: entityId !== null,
    staleTime: 15_000,
  });
}

export function useEntityMemories(entityId: string | null) {
  return useQuery<LinkedMemory[]>({
    queryKey: ['graph', 'memories', entityId],
    queryFn: async () => {
      if (!entityId) return [];
      const res = await authFetch(`${API_BASE}/api/graph/entities/${entityId}/memories`);
      if (!res.ok) throw new Error('Failed to fetch memories');
      const data = await res.json();
      return (data.memories || []) as LinkedMemory[];
    },
    enabled: entityId !== null,
    staleTime: 15_000,
  });
}

// ── Full graph (all entities + triples for constellation view) ──

export interface ClusterData {
  type: string;
  entities: GraphEntity[];
  colour: string;
}

export interface FullGraphData {
  entities: GraphEntity[];
  triples: { source: string; target: string; predicate: string }[];
  clusters: ClusterData[];
  totalConnections: number;
}

const CLUSTER_COLOURS: Record<string, string> = {
  tool: '#00e5cc',
  concept: '#ff4d4d',
  project: '#f59e0b',
  file: '#5a6480',
  service: '#a78bfa',
  person: '#34d399',
  language: '#a78bfa',
  pattern: '#fb923c',
};

export function useFullGraph() {
  return useQuery<FullGraphData>({
    queryKey: ['graph', 'full'],
    queryFn: async () => {
      // Fetch all entities and triples in parallel
      const [entRes, triRes] = await Promise.all([
        authFetch(`${API_BASE}/api/graph/entities?limit=2000`),
        authFetch(`${API_BASE}/api/graph/triples?limit=10000`),
      ]);
      if (!entRes.ok || !triRes.ok) throw new Error('Failed to fetch graph data');
      const [entData, triData] = await Promise.all([entRes.json(), triRes.json()]);

      const entities: GraphEntity[] = ((entData.entities || []) as RawEntity[]).map((e) => ({
        id: String(e.id),
        name: e.name,
        type: e.type,
        memoryCount: e.memoryCount ?? (e as unknown as Record<string, unknown>).memory_count as number ?? 0,
      }));

      const triples = ((triData.triples || []) as Triple[]).map((t) => ({
        source: String(t.subject_id),
        target: String(t.object_id),
        predicate: t.predicate,
      }));

      // Group into clusters by type
      const typeMap = new Map<string, GraphEntity[]>();
      for (const e of entities) {
        const list = typeMap.get(e.type) || [];
        list.push(e);
        typeMap.set(e.type, list);
      }
      const clusters: ClusterData[] = Array.from(typeMap.entries())
        .map(([type, ents]) => ({
          type,
          entities: ents.sort((a, b) => b.memoryCount - a.memoryCount),
          colour: CLUSTER_COLOURS[type] || '#8892b0',
        }))
        .sort((a, b) => b.entities.length - a.entities.length);

      return { entities, triples, clusters, totalConnections: triples.length };
    },
    staleTime: 60_000,
  });
}

export function useGraphSearch(query: string) {
  return useQuery<GraphEntity[]>({
    queryKey: ['graph', 'search', query],
    queryFn: async () => {
      const res = await authFetch(
        `${API_BASE}/api/graph/search?q=${encodeURIComponent(query)}&limit=8`,
      );
      if (!res.ok) throw new Error('Search failed');
      const data = await res.json();
      return ((data.entities || []) as RawEntity[]).map((e) => ({
        id: String(e.id),
        name: e.name,
        type: e.type,
        memoryCount: e.memoryCount,
      }));
    },
    enabled: query.trim().length > 0,
    staleTime: 10_000,
  });
}
