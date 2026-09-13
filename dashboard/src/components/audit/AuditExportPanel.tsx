'use client';

import { useState } from 'react';
import { Download, FileJson, FileText } from 'lucide-react';
import { useAuditExport } from '@/hooks/useAuditExport';

function ExportForm() {
  const exportAudit = useAuditExport();
  const [format, setFormat] = useState<'json' | 'csv'>('json');

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <Download size={16} className="text-[var(--sc-ok)]" />
        <h3 className="text-sm font-medium text-[var(--sc-text)]">Export Audit Logs</h3>
      </div>

      <div className="flex items-center gap-3">
        <div className="flex rounded-lg overflow-hidden border border-[var(--sc-border)]">
          <button
            onClick={() => setFormat('json')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs transition-colors ${
              format === 'json' ? 'bg-[var(--sc-ok)]/20 text-[var(--sc-ok)]' : 'bg-[var(--sc-surface-2)] text-[var(--sc-text-dim)] hover:text-[var(--sc-text)]'
            }`}
          >
            <FileJson size={12} /> JSON
          </button>
          <button
            onClick={() => setFormat('csv')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs transition-colors ${
              format === 'csv' ? 'bg-[var(--sc-ok)]/20 text-[var(--sc-ok)]' : 'bg-[var(--sc-surface-2)] text-[var(--sc-text-dim)] hover:text-[var(--sc-text)]'
            }`}
          >
            <FileText size={12} /> CSV
          </button>
        </div>

        <button
          onClick={() => exportAudit.mutate({ format })}
          disabled={exportAudit.isPending}
          className="flex items-center gap-1.5 px-4 py-1.5 text-xs bg-[var(--sc-ok)] text-[var(--sc-text)] rounded-lg hover:bg-[var(--sc-ok)] disabled:opacity-50 transition-colors"
        >
          <Download size={12} />
          {exportAudit.isPending ? 'Exporting...' : 'Export'}
        </button>
      </div>

      {exportAudit.error && <p className="text-xs text-[var(--sc-danger)]">{(exportAudit.error as Error).message}</p>}
      {exportAudit.isSuccess && <p className="text-xs text-[var(--sc-ok)]">Export downloaded successfully.</p>}
    </div>
  );
}

export function AuditExportPanel() {
  return (
    <div className="bg-[var(--sc-surface)] border border-[var(--sc-border)] rounded-xl p-4">
      <ExportForm />
    </div>
  );
}
