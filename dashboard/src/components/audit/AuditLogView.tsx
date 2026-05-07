'use client';

import { AuditLogViewTerminal } from './AuditLogViewTerminal';
import { AuditLogViewGlass } from './AuditLogViewGlass';

export function AuditLogView() {
  return (
    <>
      <div className="contents theme-glass:hidden">
        <AuditLogViewTerminal />
      </div>
      <div className="hidden theme-glass:contents">
        <AuditLogViewGlass />
      </div>
    </>
  );
}
