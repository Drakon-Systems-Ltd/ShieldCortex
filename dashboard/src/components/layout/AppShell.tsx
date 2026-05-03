import { Sidebar } from '@/components/layout/Sidebar';
import { ProjectFilterBar } from '@/components/layout/ProjectFilterBar';

export function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-dvh w-full overflow-hidden bg-[var(--sc-bg-deep)] text-[var(--sc-text-primary)]">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <ProjectFilterBar />
        <main className="min-w-0 flex-1 overflow-auto">{children}</main>
      </div>
    </div>
  );
}
