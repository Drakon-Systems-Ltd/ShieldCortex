'use client';

import { useProjects } from '@/hooks/useMemories';
import { useDashboardStore } from '@/lib/store';

interface ProjectInfo {
  project: string | null;
  memory_count?: number;
  label?: string;
}

export function ProjectFilterBar() {
  const { data: projects } = useProjects();
  const { projectFilter, setProjectFilter } = useDashboardStore();

  const projectListRaw: ProjectInfo[] = Array.isArray(projects)
    ? (projects as ProjectInfo[])
    : Array.isArray((projects as { projects?: ProjectInfo[] })?.projects)
      ? (projects as { projects: ProjectInfo[] }).projects
      : [];
  const projectList = projectListRaw.filter((p): p is ProjectInfo & { project: string } => typeof p.project === 'string' && p.project.length > 0);
  const totalCount = projectListRaw.find((p) => p.project === null)?.memory_count
    ?? projectList.reduce((sum, p) => sum + (p.memory_count ?? 0), 0);

  return (
    <div className="flex items-center gap-3 border-b border-[var(--term-border)] bg-[var(--term-surface)] px-4 py-1.5 font-mono text-xs">
      <span className="text-[var(--term-text-muted)]">project</span>
      <span className="text-[var(--term-text-muted)]" aria-hidden>=</span>
      <select
        id="project-filter"
        value={projectFilter ?? ''}
        onChange={(e) => setProjectFilter(e.target.value === '' ? null : e.target.value)}
        className="rounded-sm border border-[var(--term-border)] bg-[var(--term-surface-2)] px-2 py-0.5 text-xs text-[var(--term-text)] font-mono focus:outline-none focus:border-[var(--term-electric)]"
        aria-label="Filter dashboard by project"
      >
        <option value="">*{totalCount ? ` (${totalCount})` : ''}</option>
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
          className="text-[var(--term-text-muted)] hover:text-[var(--term-text)] underline"
        >
          clear
        </button>
      )}
    </div>
  );
}
