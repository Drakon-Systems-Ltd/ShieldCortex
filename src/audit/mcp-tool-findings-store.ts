import type { AutoCheckLedgerRow } from './mcp-tools-autocheck.js';

interface FindingsDb {
  prepare(sql: string): { run(...params: unknown[]): unknown };
}

/**
 * Persist one automatic-check ledger row, in full, to `mcp_tool_findings` (#925).
 * defence_audit keeps only a truncated `reason`; this table keeps the structured
 * finding (source, severity, every tool/field/indicator) and the untruncated
 * detail, so a pending alert survives long names or many tools.
 */
export function recordAutoCheckRow(db: FindingsDb, row: AutoCheckLedgerRow, auditId: number | null): void {
  db.prepare(
    `INSERT INTO mcp_tool_findings (audit_id, server_name, kind, alert_kind, source, severity, finding_json, detail, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    auditId !== null && auditId > 0 ? auditId : null,
    row.server,
    row.kind,
    row.finding?.alertKind ?? null,
    row.finding?.source ?? null,
    row.finding?.severity ?? null,
    row.finding ? JSON.stringify(row.finding) : null,
    row.detail,
    new Date().toISOString(),
  );
}
