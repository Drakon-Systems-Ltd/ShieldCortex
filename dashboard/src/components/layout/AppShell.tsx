import { MemoryWebSocketProvider } from '@/components/MemoryWebSocketProvider';
import { ShellSwitch } from '@/components/layout/ShellSwitch';

export function AppShell({ children }: { children: React.ReactNode }) {
  return (
    // One authenticated WebSocket for the whole dashboard, scoped here so it
    // never opens on bare/auth routes outside the (dashboard) group. ShellSwitch
    // renders the CIC terminal console (default) or the legacy Glass shell.
    <MemoryWebSocketProvider>
      <ShellSwitch>{children}</ShellSwitch>
    </MemoryWebSocketProvider>
  );
}
