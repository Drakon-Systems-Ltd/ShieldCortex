import { Sidebar } from '@/components/layout/Sidebar';
import { ProjectFilterBar } from '@/components/layout/ProjectFilterBar';
import { DailyMomentBar } from '@/components/layout/DailyMomentBar';
import { MemoryWebSocketProvider } from '@/components/MemoryWebSocketProvider';

export function AppShell({ children }: { children: React.ReactNode }) {
  return (
    // One authenticated WebSocket for the whole dashboard, scoped here so it
    // never opens on bare/auth routes outside the (dashboard) group.
    <MemoryWebSocketProvider>
      <div className="flex h-dvh w-full overflow-hidden bg-[var(--sc-bg-deep)] text-[var(--sc-text-primary)]">
        <Sidebar />
        <div className="flex min-w-0 flex-1 flex-col">
          <DailyMomentBar />
          <ProjectFilterBar />
          <main className="min-w-0 flex-1 overflow-auto">{children}</main>
        </div>
      </div>
    </MemoryWebSocketProvider>
  );
}
