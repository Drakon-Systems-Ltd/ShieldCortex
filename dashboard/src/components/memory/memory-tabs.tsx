import { Clock, Database, FileText, GitBranch, PlayCircle, Search } from 'lucide-react';
import type { TabItem } from '@/components/ds/TabBar';
import { visibleTabs } from '@/components/layout/hidden-routes';

/**
 * One tab bar for the Memory section, shared by /memory and /memory/replay so
 * Replay is reachable from Memory (it had no inbound link). Replay keeps its
 * own route; every other tab is a `?tab=` of /memory.
 */
export const MEMORY_TAB_DEFS: TabItem[] = [
  { id: 'library', label: 'Library', icon: <Database size={14} /> },
  { id: 'graph', label: 'Graph', icon: <GitBranch size={14} /> },
  { id: 'recall', label: 'Recall', icon: <Search size={14} /> },
  { id: 'review', label: 'Review' },
  { id: 'timeline', label: 'Timeline', icon: <Clock size={14} /> },
  { id: 'replay', label: 'Replay', icon: <PlayCircle size={14} /> },
  { id: 'files', label: 'Files', icon: <FileText size={14} /> },
];

export function memoryTabHref(id: string): string {
  if (id === 'replay') return '/memory/replay';
  return id === 'library' ? '/memory' : `/memory?tab=${id}`;
}

/** Memory tabs minus hidden ones, with optional per-tab counts. */
export function memoryTabs(counts: Partial<Record<string, number | undefined>> = {}): TabItem[] {
  return visibleTabs('/memory', MEMORY_TAB_DEFS).map((t) => ({ ...t, count: counts[t.id] }));
}
