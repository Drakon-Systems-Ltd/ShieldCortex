import { ScanSearch, ShieldAlert } from 'lucide-react';
import type { TabItem } from '@/components/ds/TabBar';
import { visibleTabs } from '@/components/layout/hidden-routes';

/**
 * One tab bar for the Protection section, shared by /protection and /xray so
 * the skill & package scanner sits under Protection (Opus design §2) while
 * /xray keeps its own route. Every other tab is a `?tab=` of /protection.
 * Labels follow the plain-word glossary (Opus §3); ids are unchanged so old
 * deep links still land.
 */
export const PROTECTION_TAB_DEFS: TabItem[] = [
  { id: 'status', label: 'Protection level', icon: <ShieldAlert size={14} /> },
  { id: 'intercepts', label: 'Activity' },
  { id: 'audit', label: 'Memory checks' },
  { id: 'quarantine', label: 'Held back' },
  { id: 'policies', label: 'Rules' },
  { id: 'scanner', label: 'Skill & package scanner', icon: <ScanSearch size={14} /> },
];

export function protectionTabHref(id: string): string {
  if (id === 'scanner') return '/xray';
  return id === 'status' ? '/protection' : `/protection?tab=${id}`;
}

/** Protection tabs minus hidden ones, with optional per-tab counts. */
export function protectionTabs(counts: Partial<Record<string, number | undefined>> = {}): TabItem[] {
  return visibleTabs('/protection', PROTECTION_TAB_DEFS).map((t) => ({ ...t, count: counts[t.id] }));
}
