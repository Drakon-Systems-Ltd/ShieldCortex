'use client';

import { useEffect, useState } from 'react';
import { useTheme } from '@/hooks/useTheme';
import { Sidebar } from '@/components/layout/Sidebar';
import { DailyMomentBar } from '@/components/layout/DailyMomentBar';
import { ProjectFilterBar } from '@/components/layout/ProjectFilterBar';
import { TerminalShell } from '@/components/cic/TerminalShell';

/**
 * Chooses the shell by theme: the CIC TerminalShell (default) or the legacy Glass
 * shell. A mounted-gate keeps the first client render equal to the SSR output (the
 * terminal default) so there is no hydration mismatch; a glass user swaps after mount.
 */
export function ShellSwitch({ children }: { children: React.ReactNode }) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const [theme] = useTheme();
  const effective = mounted ? theme : 'terminal';

  if (effective === 'terminal') {
    return <TerminalShell>{children}</TerminalShell>;
  }

  return (
    <div className="flex h-dvh w-full overflow-hidden bg-[var(--sc-bg-deep)] text-[var(--sc-text-primary)]">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <DailyMomentBar />
        <ProjectFilterBar />
        <main className="min-w-0 flex-1 overflow-auto">{children}</main>
      </div>
    </div>
  );
}
