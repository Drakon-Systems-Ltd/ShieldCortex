'use client';

import { useState } from 'react';
import { Download, FileJson, FileText } from 'lucide-react';
import { ProFeatureGate } from '../shield/ProFeatureGate';
import { useAuditExport } from '@/hooks/useAuditExport';

function ExportForm() {
  const exportAudit = useAuditExport();
  const [format, setFormat] = useState<'json' | 'csv'>('json');

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <Download size={16} className="text-[var(--sc-cyan)]" />
        <h3 className="text-sm font-medium text-[var(--sc-text-primary)]">Export Audit Logs</h3>
      </div>

      <div className="flex items-center gap-3">
        <div className="flex rounded-lg overflow-hidden border border-[var(--sc-border)]">
          <button
            onClick={() => setFormat('json')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs transition-colors ${
              format === 'json' ? 'bg-[var(--sc-cyan)]/20 text-[var(--sc-cyan)]' : 'bg-[var(--sc-bg-elevated)] text-[var(--sc-text-secondary)] hover:text-[var(--sc-text-primary)]'
            }`}
          >
            <FileJson size={12} /> JSON
          </button>
          <button
            onClick={() => setFormat('csv')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs transition-colors ${
              format === 'csv' ? 'bg-[var(--sc-cyan)]/20 text-[var(--sc-cyan)]' : 'bg-[var(--sc-bg-elevated)] text-[var(--sc-text-secondary)] hover:text-[var(--sc-text-primary)]'
            }`}
          >
            <FileText size={12} /> CSV
          </button>
        </div>

        <button
          onClick={() => exportAudit.mutate({ format })}
          disabled={exportAudit.isPending}
          className="flex items-center gap-1.5 px-4 py-1.5 text-xs bg-[var(--sc-cyan)] text-[var(--sc-text-primary)] rounded-lg hover:bg-[var(--sc-cyan)] disabled:opacity-50 transition-colors"
        >
          <Download size={12} />
          {exportAudit.isPending ? 'Exporting...' : 'Export'}
        </button>
      </div>

      {exportAudit.error && <p className="text-xs text-[var(--sc-coral)]">{(exportAudit.error as Error).message}</p>}
      {exportAudit.isSuccess && <p className="text-xs text-[var(--sc-cyan)]">Export downloaded successfully.</p>}
    </div>
  );
}

export function AuditExportPanel() {
  return (
    <div className="bg-[var(--sc-bg-surface)] border border-[var(--sc-border)] rounded-xl p-4">
      <ProFeatureGate feature="audit_export" label="Export your full audit trail as JSON or CSV for compliance reporting.">
        <ExportForm />
      </ProFeatureGate>
    </div>
  );
}
