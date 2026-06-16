'use client';

// The dashboard is glass-only (the Terminal theme was removed in the 2026-06
// cleanup); this wrapper now simply renders the glass sidebar.
import { SidebarGlass } from './SidebarGlass';

export function Sidebar() {
  return <SidebarGlass />;
}
