'use client';

import { useState } from 'react';
import { useQuarantine, useApproveQuarantine, useRejectQuarantine, QuarantineItem } from '@/hooks/useDefence';
import { useDashboardStore } from '@/lib/store';
import { AlertTriangle, Check, X } from 'lucide-react';

function ConfirmationDialog({
  action,
  item,
  onConfirm,
  onCancel,
}: {
  action: 'approve' | 'reject';
  item: QuarantineItem;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const [input, setInput] = useState('');
  const isValid = input.trim().toLowerCase() === 'yes';

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-slate-900 border border-slate-700 rounded-xl p-6 max-w-md w-full mx-4">
        <h3 className="text-sm font-semibold text-white mb-2">
          {action === 'approve' ? 'Approve' : 'Reject'} quarantined item?
        </h3>
        <p className="text-xs text-slate-400 mb-1">
          <strong>{item.title || 'Untitled'}</strong>
        </p>
        <p className="text-xs text-slate-500 mb-4">
          {action === 'approve'
            ? 'This will store the memory in the database.'
            : 'This will permanently discard the memory.'}
        </p>

        <div className="mb-4">
          <label className="text-xs text-slate-400 block mb-1">
            Type <strong className="text-white">YES</strong> to confirm:
          </label>
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            className="w-full bg-slate-800 border border-slate-700 text-white text-sm rounded-lg px-3 py-2 focus:ring-cyan-500 focus:border-cyan-500"
            autoFocus
            onKeyDown={(e) => {
              if (e.key === 'Enter' && isValid) onConfirm();
              if (e.key === 'Escape') onCancel();
            }}
          />
        </div>

        <div className="flex gap-2 justify-end">
          <button
            onClick={onCancel}
            className="px-3 py-1.5 text-xs text-slate-400 hover:text-white transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            disabled={!isValid}
            className={`px-3 py-1.5 text-xs rounded-lg transition-colors ${
              isValid
                ? action === 'approve'
                  ? 'bg-green-600 text-white hover:bg-green-500'
                  : 'bg-red-600 text-white hover:bg-red-500'
                : 'bg-slate-700 text-slate-500 cursor-not-allowed'
            }`}
          >
            {action === 'approve' ? 'Approve' : 'Reject'}
          </button>
        </div>
      </div>
    </div>
  );
}

export function QuarantineView() {
  const { projectFilter } = useDashboardStore();
  const [statusFilter, setStatusFilter] = useState<string>('pending');
  const { data, isLoading } = useQuarantine(statusFilter, 100, projectFilter || undefined);
  const approveMutation = useApproveQuarantine();
  const rejectMutation = useRejectQuarantine();

  const [confirmAction, setConfirmAction] = useState<{
    action: 'approve' | 'reject';
    item: QuarantineItem;
  } | null>(null);

  const items = data?.items ?? [];

  const handleConfirm = () => {
    if (!confirmAction) return;
    if (confirmAction.action === 'approve') {
      approveMutation.mutate(confirmAction.item.id);
    } else {
      rejectMutation.mutate({ id: confirmAction.item.id });
    }
    setConfirmAction(null);
  };

  return (
    <div className="h-full flex flex-col overflow-hidden">
      {/* Confirmation dialog */}
      {confirmAction && (
        <ConfirmationDialog
          action={confirmAction.action}
          item={confirmAction.item}
          onConfirm={handleConfirm}
          onCancel={() => setConfirmAction(null)}
        />
      )}

      {/* Header */}
      <div className="p-4 border-b border-slate-800 shrink-0">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">Quarantine Review</h2>
          <div className="flex gap-1 bg-slate-800 rounded-lg p-0.5">
            {['pending', 'approved', 'rejected'].map((status) => (
              <button
                key={status}
                onClick={() => setStatusFilter(status)}
                className={`px-3 py-1 text-xs rounded-md transition-colors capitalize ${
                  statusFilter === status ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-white'
                }`}
              >
                {status}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Items */}
      <div className="flex-1 overflow-y-auto p-4">
        {isLoading ? (
          <div className="flex items-center justify-center h-32">
            <div className="text-xs text-slate-500 animate-pulse">Loading quarantine items...</div>
          </div>
        ) : items.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-32 text-slate-500">
            <AlertTriangle size={24} className="mb-2 text-slate-600" />
            <span className="text-xs">No {statusFilter} items</span>
          </div>
        ) : (
          <div className="space-y-3">
            {items.map((item) => {
              const indicators = (() => {
                try { return JSON.parse(item.threat_indicators); } catch { return []; }
              })();

              return (
                <div
                  key={item.id}
                  className="bg-slate-900 border border-slate-800 rounded-xl p-4"
                >
                  <div className="flex items-start justify-between mb-2">
                    <div>
                      <h4 className="text-sm font-medium text-white">
                        {item.title || 'Untitled'}
                      </h4>
                      <div className="text-[10px] text-slate-500 mt-0.5">
                        {item.source_type} &middot; {new Date(item.created_at).toLocaleString()}
                        {item.anomaly_score > 0 && (
                          <span className={`ml-2 ${item.anomaly_score > 0.5 ? 'text-red-400' : 'text-yellow-400'}`}>
                            Anomaly: {item.anomaly_score.toFixed(2)}
                          </span>
                        )}
                      </div>
                    </div>
                    <span className="text-[10px] text-red-400 bg-red-400/10 px-2 py-0.5 rounded">
                      {item.reason?.slice(0, 50) || 'Threat detected'}
                    </span>
                  </div>

                  {/* Content preview */}
                  <div className="bg-slate-800/50 rounded-lg p-3 mb-3 text-xs text-slate-300 max-h-24 overflow-y-auto whitespace-pre-wrap">
                    {item.content?.slice(0, 500) || 'No content'}
                  </div>

                  {/* Threat indicators */}
                  {indicators.length > 0 && (
                    <div className="flex gap-1 mb-3 flex-wrap">
                      {indicators.map((ind: string, i: number) => (
                        <span key={i} className="text-[9px] text-yellow-400 bg-yellow-400/10 px-1.5 py-0.5 rounded">
                          {ind}
                        </span>
                      ))}
                    </div>
                  )}

                  {/* Actions (only for pending) */}
                  {item.status === 'pending' && (
                    <div className="flex gap-2">
                      <button
                        onClick={() => setConfirmAction({ action: 'approve', item })}
                        className="flex items-center gap-1 px-3 py-1.5 text-xs bg-green-600/10 text-green-400 rounded-lg hover:bg-green-600/20 transition-colors"
                      >
                        <Check size={12} /> Approve
                      </button>
                      <button
                        onClick={() => setConfirmAction({ action: 'reject', item })}
                        className="flex items-center gap-1 px-3 py-1.5 text-xs bg-red-600/10 text-red-400 rounded-lg hover:bg-red-600/20 transition-colors"
                      >
                        <X size={12} /> Reject
                      </button>
                    </div>
                  )}

                  {/* Review info (for reviewed items) */}
                  {item.reviewed_at && (
                    <div className="text-[10px] text-slate-500">
                      {item.status === 'approved' ? 'Approved' : 'Rejected'} by {item.reviewed_by} at {new Date(item.reviewed_at).toLocaleString()}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
