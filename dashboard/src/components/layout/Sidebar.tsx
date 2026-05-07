'use client';

/**
 * Theme-routing Sidebar wrapper.
 *
 * Both variants render simultaneously into the DOM; CSS picks which is
 * visible via the `theme-terminal:` / `theme-glass:` custom variants. This
 * sidesteps SSR hydration mismatches — the server emits both subtrees, the
 * inline bootstrap script in `app/layout.tsx` sets `<html data-theme>`
 * before React hydrates, and only one subtree is ever painted.
 */

import { SidebarTerminal } from './SidebarTerminal';
import { SidebarGlass } from './SidebarGlass';

export function Sidebar() {
  return (
    <>
      <div className="contents theme-glass:hidden">
        <SidebarTerminal />
      </div>
      <div className="hidden theme-glass:contents">
        <SidebarGlass />
      </div>
    </>
  );
}
