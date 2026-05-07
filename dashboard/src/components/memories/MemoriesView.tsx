'use client';

import { MemoriesViewTerminal } from './MemoriesViewTerminal';
import { MemoriesViewGlass } from './MemoriesViewGlass';

export function MemoriesView() {
  return (
    <>
      <div className="contents theme-glass:hidden">
        <MemoriesViewTerminal />
      </div>
      <div className="hidden theme-glass:contents">
        <MemoriesViewGlass />
      </div>
    </>
  );
}
