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
        <Download size={16} className="text-cyan-400" />
        <h3 className="text-sm font-medium text-slate-200">Export Audit Logs</h3>
      </div>

      <div className="flex items-center gap-3">
        <div className="flex rounded-lg overflow-hidden border border-slate-700">
          <button
            onClick={() => setFormat('json')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs transition-colors ${
              format === 'json' ? 'bg-cyan-600/20 text-cyan-400' : 'bg-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileJson size={12} /> JSON
          </button>
          <button
            onClick={() => setFormat('csv')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs transition-colors ${
              format === 'csv' ? 'bg-cyan-600/20 text-cyan-400' : 'bg-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileText size={12} /> CSV
          </button>
        </div>

        <button
          onClick={() => exportAudit.mutate({ format })}
          disabled={exportAudit.isPending}
          className="flex items-center gap-1.5 px-4 py-1.5 text-xs bg-cyan-600 text-white rounded-lg hover:bg-cyan-500 disabled:opacity-50 transition-colors"
        >
          <Download size={12} />
          {exportAudit.isPending ? 'Exporting...' : 'Export'}
        </button>
      </div>

      {exportAudit.error && <p className="text-xs text-red-400">{(exportAudit.error as Error).message}</p>}
      {exportAudit.isSuccess && <p className="text-xs text-green-400">Export downloaded successfully.</p>}
    </div>
  );
}

export function AuditExportPanel() {
  return (
    <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4">
      <ProFeatureGate feature="audit_export" label="Export your full audit trail as JSON or CSV for compliance reporting.">
        <ExportForm />
      </ProFeatureGate>
    </div>
  );
}
