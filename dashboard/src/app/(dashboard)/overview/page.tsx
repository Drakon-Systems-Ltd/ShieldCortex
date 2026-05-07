'use client';

/**
 * Theme-routing wrapper for the overview page.
 *
 * Both variants render simultaneously into the DOM and visibility is
 * controlled by CSS via `theme-glass:` / `theme-terminal:` Tailwind variants
 * defined in globals.css. The inline bootstrap script in app/layout.tsx
 * sets `<html data-theme>` before React hydrates so only one subtree paints.
 */

import { OverviewTerminal } from './OverviewTerminal';
import { OverviewGlass } from './OverviewGlass';

export default function OverviewPage() {
  return (
    <>
      <div className="contents theme-glass:hidden">
        <OverviewTerminal />
      </div>
      <div className="hidden theme-glass:contents">
        <OverviewGlass />
      </div>
    </>
  );
}
