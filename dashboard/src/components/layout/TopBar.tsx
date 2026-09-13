'use client';

import { useState } from 'react';
import { Search } from 'lucide-react';
import { useProjects } from '@/hooks/useMemories';
import { useDashboardStore } from '@/lib/store';
import { useWebSocketStatus } from '@/components/MemoryWebSocketProvider';
import { ThemeToggle } from '@/components/ds/ThemeToggle';
import { Kbd } from '@/components/ds/Kbd';
import { CommandPalette } from '@/components/ds/CommandPalette';
import { cn } from '@/lib/utils';

interface ProjectInfo {
  project: string | null;
  memory_count?: number;
}

/**
 * v2 top bar: project filter · global search / command palette (⌘K) · live
 * connection dot with a plain-English tooltip · theme toggle.
 */
export function TopBar() {
  const { data: projects } = useProjects();
  const { projectFilter, setProjectFilter } = useDashboardStore();
  const { isConnected, connectionFailed } = useWebSocketStatus();
  const [paletteOpen, setPaletteOpen] = useState(false);

  const raw: ProjectInfo[] = Array.isArray(projects)
    ? (projects as ProjectInfo[])
    : Array.isArray((projects as { projects?: ProjectInfo[] })?.projects)
      ? (projects as { projects: ProjectInfo[] }).projects
      : [];
  const projectList = raw
    .filter((p): p is ProjectInfo & { project: string } => typeof p.project === 'string' && p.project.length > 0)
    .sort((a, b) => (b.memory_count ?? 0) - (a.memory_count ?? 0) || a.project.localeCompare(b.project));

  const connectionLabel = isConnected
    ? 'Live: connected to the local ShieldCortex API — updates stream in as they happen'
    : connectionFailed
      ? 'Not connected: the local ShieldCortex API is unreachable, data may be stale'
      : 'Connecting to the local ShieldCortex API…';

  return (
    <header className="flex h-14 shrink-0 items-center gap-3 border-b border-[var(--sc-border)] bg-[var(--sc-surface)] px-4">
      <label className="flex items-center gap-2 text-xs text-[var(--sc-text-muted)]">
        <span className="hidden sm:inline">Project</span>
        <select
          value={projectFilter ?? ''}
          onChange={(e) => setProjectFilter(e.target.value === '' ? null : e.target.value)}
          aria-label="Filter dashboard by project"
          className="h-8 max-w-44 rounded-md border border-[var(--sc-border)] bg-[var(--sc-surface)] px-2 text-xs text-[var(--sc-text)] focus-visible:outline-2 focus-visible:outline-[var(--sc-focus)]"
        >
          <option value="">All projects</option>
          {projectList.map((p) => (
            <option key={p.project} value={p.project}>
              {p.project}
              {typeof p.memory_count === 'number' ? ` (${p.memory_count})` : ''}
            </option>
          ))}
        </select>
      </label>

      <button
        type="button"
        onClick={() => setPaletteOpen(true)}
        aria-label="Open search and command palette"
        className="flex h-8 min-w-0 flex-1 max-w-md items-center gap-2 rounded-md border border-[var(--sc-border)] bg-[var(--sc-surface-2)] px-3 text-left text-xs text-[var(--sc-text-muted)] transition-colors hover:border-[var(--sc-border-strong)] focus-visible:outline-2 focus-visible:outline-[var(--sc-focus)]"
      >
        <Search size={13} aria-hidden />
        <span className="flex-1 truncate">Search or run a command…</span>
        <Kbd>⌘K</Kbd>
      </button>

      <div className="ml-auto flex items-center gap-2">
        <span className="flex items-center gap-1.5 text-xs text-[var(--sc-text-muted)]" title={connectionLabel}>
          <span
            aria-hidden
            className={cn(
              'inline-block h-2 w-2 rounded-full',
              isConnected ? 'bg-[var(--sc-ok)]' : connectionFailed ? 'bg-[var(--sc-danger)]' : 'bg-[var(--sc-warn)]',
            )}
          />
          <span className="sr-only">{connectionLabel}</span>
          <span className="hidden md:inline">{isConnected ? 'Live' : connectionFailed ? 'Offline' : 'Connecting'}</span>
        </span>
        <ThemeToggle />
      </div>

      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} />
    </header>
  );
}
