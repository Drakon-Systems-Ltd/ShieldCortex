'use client';

import { OpsBar } from './OpsBar';
import { NavRail } from './NavRail';
import { CommandRail } from './CommandRail';

/**
 * The CIC console shell: ops bar across the top, nav rail down the left, the
 * active view in the centre, and the real command rail anchored at the bottom —
 * the bridge of a starship whose computer is a brain.
 */
export function TerminalShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-dvh w-full flex-col overflow-hidden bg-[var(--cic-void)] text-[var(--cic-text)]">
      <OpsBar />
      <div className="flex min-h-0 flex-1">
        <NavRail />
        <main className="min-w-0 flex-1 overflow-auto">{children}</main>
      </div>
      <CommandRail />
    </div>
  );
}
