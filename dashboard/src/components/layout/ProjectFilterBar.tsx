'use client';

import { Filter } from 'lucide-react';
import { useProjects } from '@/hooks/useMemories';
import { useDashboardStore } from '@/lib/store';

interface ProjectInfo {
  project: string | null;
  memory_count?: number;
  label?: string;
}

/**
 * Persistent project filter bar shown above every dashboard view. The shield,
 * audit, quarantine, review, and insights views all read `projectFilter` from
 * `useDashboardStore` and re-query when it changes — this is the missing UI
 * affordance to actually set it.
 *
 * "All projects" maps to `null` (no filter).
 */
export function ProjectFilterBar() {
  const { data: projects } = useProjects();
  const { projectFilter, setProjectFilter } = useDashboardStore();

  const projectListRaw: ProjectInfo[] = Array.isArray(projects)
    ? (projects as ProjectInfo[])
    : Array.isArray((projects as { projects?: ProjectInfo[] })?.projects)
      ? (projects as { projects: ProjectInfo[] }).projects
      : [];
  // The /api/projects endpoint includes a synthetic { project: null } "All
  // Projects" row at the top with the global count. Drop it — we render our
  // own "All projects" option, and a `null` value would break the controlled
  // <select>.
  const projectList = projectListRaw.filter((p): p is ProjectInfo & { project: string } => typeof p.project === 'string' && p.project.length > 0);
  const totalCount = projectListRaw.find((p) => p.project === null)?.memory_count
    ?? projectList.reduce((sum, p) => sum + (p.memory_count ?? 0), 0);

  return (
    <div className="flex items-center gap-2 border-b border-[var(--sc-border)] bg-[var(--sc-bg-surface)]/40 px-4 py-2 backdrop-blur-sm">
      <Filter size={13} className="text-[var(--sc-text-muted)]" />
      <label htmlFor="project-filter" className="text-xs uppercase tracking-[0.14em] text-[var(--sc-text-muted)]">
        Project
      </label>
      <select
        id="project-filter"
        value={projectFilter ?? ''}
        onChange={(e) => setProjectFilter(e.target.value === '' ? null : e.target.value)}
        className="rounded-md border border-[var(--sc-border)] bg-[var(--sc-bg-deep)] px-2 py-1 text-xs text-[var(--sc-text-primary)] focus:outline-none focus:ring-1 focus:ring-[var(--sc-cyan)]"
        aria-label="Filter dashboard by project"
      >
        <option value="">All projects{totalCount ? ` (${totalCount})` : ''}</option>
        {projectList
          .slice()
          .sort((a, b) => (b.memory_count ?? 0) - (a.memory_count ?? 0) || a.project.localeCompare(b.project))
          .map((p) => (
            <option key={p.project} value={p.project}>
              {p.project}{typeof p.memory_count === 'number' ? ` (${p.memory_count})` : ''}
            </option>
          ))}
      </select>
      {projectFilter && (
        <button
          type="button"
          onClick={() => setProjectFilter(null)}
          className="text-[11px] text-[var(--sc-text-muted)] hover:text-[var(--sc-text-primary)] underline"
        >
          Clear
        </button>
      )}
    </div>
  );
}
