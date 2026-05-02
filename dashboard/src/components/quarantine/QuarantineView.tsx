'use client';

import { useState } from 'react';
import {
  useQuarantine,
  useApproveQuarantine,
  useRejectQuarantine,
  useBulkApproveQuarantine,
  useBulkRejectQuarantine,
  useReviewCopilotStatus,
  useAnnotateQuarantine,
  useAnnotatePendingQuarantine,
  QuarantineItem,
  ReviewAnnotation,
} from '@/hooks/useDefence';
import { useDashboardStore } from '@/lib/store';
import { AlertTriangle, Bot, Check, Loader2, Sparkles, Tags, Wand2, X, CheckSquare, Square, MinusSquare } from 'lucide-react';
import { ProFeatureGate } from '@/components/shield/ProFeatureGate';

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
  const isMemoryFile = item.source_type === 'memory_file';

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-[var(--sc-bg-surface)] border border-[var(--sc-border)] rounded-xl p-6 max-w-md w-full mx-4">
        <h3 className="text-sm font-semibold text-[var(--sc-text-primary)] mb-2">
          {action === 'approve' ? 'Approve' : 'Reject'} quarantined item?
        </h3>
        <p className="text-xs text-[var(--sc-text-secondary)] mb-1">
          <strong>{item.title || 'Untitled'}</strong>
        </p>
        <p className="text-xs text-[var(--sc-text-muted)] mb-4">
          {action === 'approve'
            ? isMemoryFile
              ? 'This will mark the memory-file finding as reviewed. The source file is not modified.'
              : 'This will approve the item and promote it into memory.'
            : isMemoryFile
              ? 'This will dismiss the memory-file finding. The source file is not deleted or edited.'
              : 'This will permanently discard the memory.'}
        </p>

        <div className="mb-4">
          <label className="text-xs text-[var(--sc-text-secondary)] block mb-1">
            Type <strong className="text-[var(--sc-text-primary)]">YES</strong> to confirm:
          </label>
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            className="w-full bg-[var(--sc-bg-elevated)] border border-[var(--sc-border)] text-[var(--sc-text-primary)] text-sm rounded-lg px-3 py-2 focus:ring-[var(--sc-cyan)] focus:border-[var(--sc-cyan)]"
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
            className="px-3 py-1.5 text-xs text-[var(--sc-text-secondary)] hover:text-[var(--sc-text-primary)] transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            disabled={!isValid}
            className={`px-3 py-1.5 text-xs rounded-lg transition-colors ${
              isValid
                ? action === 'approve'
                  ? 'bg-[var(--sc-cyan)] text-[var(--sc-text-primary)] hover:bg-[var(--sc-cyan-mid)]'
                  : 'bg-[var(--sc-coral)] text-[var(--sc-text-primary)] hover:bg-[var(--sc-coral-mid)]'
                : 'bg-[var(--sc-bg-elevated)] text-[var(--sc-text-muted)] cursor-not-allowed'
            }`}
          >
            {action === 'approve' && isMemoryFile ? 'Mark reviewed' : action === 'approve' ? 'Approve' : 'Reject'}
          </button>
        </div>
      </div>
    </div>
  );
}

function actionTone(action: ReviewAnnotation['suggestedAction']): string {
  if (action === 'approve') return 'text-[var(--sc-cyan)] bg-[var(--sc-cyan)]/10 border-[var(--sc-cyan)]/25';
  if (action === 'reject') return 'text-[var(--sc-coral)] bg-[var(--sc-coral)]/10 border-[var(--sc-coral)]/25';
  if (action === 'create_rule') return 'text-[var(--sc-amber)] bg-[var(--sc-amber)]/10 border-[var(--sc-amber)]/25';
  return 'text-[var(--sc-text-secondary)] bg-[var(--sc-surface-interactive)] border-[var(--sc-border)]';
}

function categoryLabel(category: string): string {
  return category.replace(/_/g, ' ');
}

function LocalAiQuarantineAnnotation({ annotation }: { annotation: ReviewAnnotation }) {
  return (
    <div className="mb-3 rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-elevated)]/70 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="inline-flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.16em] text-[var(--sc-cyan)]">
          <Bot size={12} /> Local AI Explainer
        </span>
        <span className="rounded border border-[var(--sc-border)] px-2 py-0.5 text-[10px] uppercase tracking-[0.12em] text-[var(--sc-text-secondary)]">
          {categoryLabel(annotation.category)}
        </span>
        <span className={`rounded border px-2 py-0.5 text-[10px] uppercase tracking-[0.12em] ${actionTone(annotation.suggestedAction)}`}>
          {annotation.suggestedAction.replace(/_/g, ' ')}
        </span>
        <span className="text-[10px] text-[var(--sc-text-muted)]">
          {Math.round(annotation.confidence * 100)}% confidence
        </span>
        {annotation.similarGroupKey && (
          <span className="inline-flex items-center gap-1 text-[10px] text-[var(--sc-text-muted)]">
            <Tags size={11} /> {annotation.similarGroupKey}
          </span>
        )}
      </div>
      <p className="mt-2 text-xs leading-5 text-[var(--sc-text-primary)]">{annotation.summary}</p>
      <p className="mt-1 text-[11px] leading-5 text-[var(--sc-text-secondary)]">{annotation.reasoning}</p>
      {annotation.evidence.length > 0 && (
        <div className="mt-2 space-y-1.5">
          {annotation.evidence.map((entry, index) => (
            <div key={`${entry.snippet}-${index}`} className="rounded border border-[var(--sc-border)] bg-[var(--sc-bg-surface)] px-2 py-1.5">
              <div className="text-[10px] text-[var(--sc-text-muted)]">{entry.reason}</div>
              <div className="mt-0.5 text-[11px] text-[var(--sc-text-primary)] break-words">&quot;{entry.snippet}&quot;</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function QuarantineView() {
  const { projectFilter } = useDashboardStore();
  const [statusFilter, setStatusFilter] = useState<string>('pending');
  const { data, isLoading } = useQuarantine(statusFilter, 100, projectFilter || undefined);
  const { data: copilotStatus } = useReviewCopilotStatus();
  const approveMutation = useApproveQuarantine();
  const rejectMutation = useRejectQuarantine();
  const bulkApproveMutation = useBulkApproveQuarantine();
  const bulkRejectMutation = useBulkRejectQuarantine();
  const annotateMutation = useAnnotateQuarantine();
  const annotatePendingMutation = useAnnotatePendingQuarantine();

  const [confirmAction, setConfirmAction] = useState<{
    action: 'approve' | 'reject';
    item: QuarantineItem;
  } | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const [bulkConfirm, setBulkConfirm] = useState<'approve' | 'reject' | null>(null);
  const mutationError =
    (approveMutation.error as Error | null)?.message ||
    (rejectMutation.error as Error | null)?.message ||
    (bulkApproveMutation.error as Error | null)?.message ||
    (bulkRejectMutation.error as Error | null)?.message ||
    (annotateMutation.error as Error | null)?.message ||
    (annotatePendingMutation.error as Error | null)?.message ||
    null;

  const items = data?.items ?? [];
  const pendingItems = items.filter(i => i.status === 'pending');
  const annotatedItems = items.filter(i => i.annotation);
  const needsAiReviewItems = pendingItems.filter(i => !i.annotation);
  const selectedItems = pendingItems.filter(i => selectedIds.has(i.id));
  const selectedMemoryFileCount = selectedItems.filter(i => i.source_type === 'memory_file').length;
  const annotationGroups = (() => {
    const groups = new Map<string, number>();
    for (const item of annotatedItems) {
      const key = item.annotation?.similarGroupKey;
      if (!key) continue;
      groups.set(key, (groups.get(key) ?? 0) + 1);
    }
    return [...groups.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3);
  })();
  const allSelected = pendingItems.length > 0 && pendingItems.every(i => selectedIds.has(i.id));
  const someSelected = pendingItems.some(i => selectedIds.has(i.id));
  const copilotBusy = annotateMutation.isPending || annotatePendingMutation.isPending;
  const canAnnotate = Boolean(copilotStatus?.enabled && copilotStatus.featureEnabled && copilotStatus.modelCached);

  const toggleSelect = (id: number) => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleSelectAll = () => {
    if (allSelected) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(pendingItems.map(i => i.id)));
    }
  };

  const handleConfirm = () => {
    if (!confirmAction) return;
    if (confirmAction.action === 'approve') {
      approveMutation.mutate(confirmAction.item.id);
    } else {
      rejectMutation.mutate({ id: confirmAction.item.id });
    }
    setConfirmAction(null);
  };

  const handleBulkConfirm = () => {
    if (!bulkConfirm || selectedIds.size === 0) return;
    const ids = Array.from(selectedIds);
    if (bulkConfirm === 'approve') {
      bulkApproveMutation.mutate(ids);
    } else {
      bulkRejectMutation.mutate(ids);
    }
    setSelectedIds(new Set());
    setBulkConfirm(null);
  };

  const handleAnnotatePending = () => {
    annotatePendingMutation.mutate({
      limit: Math.min(Math.max(needsAiReviewItems.length, 1), 100),
      project: projectFilter || undefined,
    });
  };

  return (
    <div className="space-y-6">
      {/* Confirmation dialog */}
      {confirmAction && (
        <ConfirmationDialog
          action={confirmAction.action}
          item={confirmAction.item}
          onConfirm={handleConfirm}
          onCancel={() => setConfirmAction(null)}
        />
      )}

      {/* Bulk confirmation dialog */}
      {bulkConfirm && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-[var(--sc-bg-surface)] border border-[var(--sc-border)] rounded-xl p-6 max-w-md w-full mx-4">
            <h3 className="text-sm font-semibold text-[var(--sc-text-primary)] mb-2">
              {bulkConfirm === 'approve' ? 'Approve' : 'Reject'} {selectedIds.size} item{selectedIds.size !== 1 ? 's' : ''}?
            </h3>
            <p className="text-xs text-[var(--sc-text-secondary)] mb-4">
              {bulkConfirm === 'approve'
                ? selectedMemoryFileCount > 0
                  ? 'Memory-file findings will be marked reviewed without editing files. Other selected items will be promoted into memory.'
                  : 'This will approve all selected items and promote them into memory.'
                : selectedMemoryFileCount > 0
                  ? 'Memory-file findings will be dismissed without editing files. Other selected memories will be discarded.'
                  : 'This will permanently discard all selected memories.'}
            </p>
            <div className="flex gap-2 justify-end">
              <button
                onClick={() => setBulkConfirm(null)}
                className="px-3 py-1.5 text-xs text-[var(--sc-text-secondary)] hover:text-[var(--sc-text-primary)] transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleBulkConfirm}
                className={`px-3 py-1.5 text-xs rounded-lg transition-colors ${
                  bulkConfirm === 'approve'
                    ? 'bg-[var(--sc-cyan)] text-[var(--sc-text-primary)] hover:bg-[var(--sc-cyan-mid)]'
                    : 'bg-[var(--sc-coral)] text-[var(--sc-text-primary)] hover:bg-[var(--sc-coral-mid)]'
                }`}
              >
                {bulkConfirm === 'approve' ? 'Approve' : 'Reject'} {selectedIds.size} item{selectedIds.size !== 1 ? 's' : ''}
              </button>
            </div>
          </div>
        </div>
      )}

      <ProFeatureGate feature="local_ai_explainer" label="Use a local model to explain and group quarantined items without sending content to the cloud.">
        <div className="glass-card p-5">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="flex items-center gap-2 text-sm font-semibold text-[var(--sc-text-primary)]">
                  <Sparkles size={16} className="text-[var(--sc-cyan)]" />
                  Local AI Explainer
                </h3>
                <span className={`rounded border px-2 py-0.5 text-[10px] uppercase tracking-[0.12em] ${
                  copilotStatus?.enabled
                    ? 'border-[var(--sc-cyan)]/25 bg-[var(--sc-cyan)]/10 text-[var(--sc-cyan)]'
                    : 'border-[var(--sc-border)] bg-[var(--sc-surface-interactive)] text-[var(--sc-text-muted)]'
                }`}>
                  {copilotStatus?.enabled ? 'enabled' : 'disabled'}
                </span>
                <span className={`rounded border px-2 py-0.5 text-[10px] uppercase tracking-[0.12em] ${
                  copilotStatus?.modelCached
                    ? 'border-[var(--sc-cyan)]/25 bg-[var(--sc-cyan)]/10 text-[var(--sc-cyan)]'
                    : 'border-[var(--sc-border)] bg-[var(--sc-surface-interactive)] text-[var(--sc-text-muted)]'
                }`}>
                  {copilotStatus?.modelCached ? 'model cached' : 'model not cached'}
                </span>
              </div>
              <div className="mt-2 text-xs leading-5 text-[var(--sc-text-secondary)]">
                {!copilotStatus?.enabled
                  ? 'Enable from the CLI first: shieldcortex review-copilot enable'
                  : !copilotStatus.modelCached
                    ? 'Download the local model first: shieldcortex review-copilot download-model'
                    : 'Explain unreviewed quarantine items locally; approve and reject decisions stay manual.'}
              </div>
              <div className="mt-2 flex flex-wrap gap-2 text-[10px] text-[var(--sc-text-muted)]">
                <span className={needsAiReviewItems.length > 0 ? 'text-[var(--sc-amber)]' : ''}>
                  {needsAiReviewItems.length} need explanation
                </span>
                <span>{annotatedItems.length} explained in this view</span>
                {annotationGroups.map(([key, count]) => (
                  <span key={key} className="inline-flex items-center gap-1">
                    <Tags size={11} /> {key}: {count}
                  </span>
                ))}
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              <button
                onClick={handleAnnotatePending}
                disabled={!canAnnotate || copilotBusy || needsAiReviewItems.length === 0}
                className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--sc-cyan)]/10 px-3 py-1.5 text-xs font-semibold text-[var(--sc-cyan)] transition-colors hover:bg-[var(--sc-cyan)]/20 disabled:pointer-events-none disabled:opacity-45"
              >
                {annotatePendingMutation.isPending ? <Loader2 size={13} className="animate-spin" /> : <Wand2 size={13} />}
                Explain all
              </button>
            </div>
          </div>
        </div>
      </ProFeatureGate>

      {/* Filters and bulk actions */}
      <div className="glass-card p-5">
        <div className="flex items-center justify-between">
          <div className="flex gap-1 bg-[var(--sc-bg-elevated)] rounded-lg p-0.5">
            {['pending', 'approved', 'rejected'].map((status) => (
              <button
                key={status}
                onClick={() => { setStatusFilter(status); setSelectedIds(new Set()); }}
                className={`px-3 py-1 text-xs rounded-md transition-colors capitalize ${
                  statusFilter === status ? 'bg-[var(--sc-cyan)] text-[var(--sc-text-primary)]' : 'text-[var(--sc-text-secondary)] hover:text-[var(--sc-text-primary)]'
                }`}
              >
                {status}
              </button>
            ))}
          </div>
        </div>

        {/* Bulk action bar */}
        {statusFilter === 'pending' && pendingItems.length > 0 && (
          <div className="flex items-center gap-3 mt-3">
            <button
              onClick={toggleSelectAll}
              className="flex items-center gap-1.5 text-xs text-[var(--sc-text-secondary)] hover:text-[var(--sc-text-primary)] transition-colors"
            >
              {allSelected ? <CheckSquare size={14} className="text-[var(--sc-cyan)]" /> : someSelected ? <MinusSquare size={14} className="text-[var(--sc-cyan)]" /> : <Square size={14} />}
              {allSelected ? 'Deselect all' : 'Select all'}
            </button>
            {someSelected && (
              <>
                <span className="text-xs text-[var(--sc-text-muted)]">{selectedIds.size} selected</span>
                <button
                  onClick={() => setBulkConfirm('approve')}
                  className="flex items-center gap-1 px-2.5 py-1 text-xs bg-[var(--sc-cyan)]/10 text-[var(--sc-cyan)] rounded-lg hover:bg-[var(--sc-cyan)]/20 transition-colors"
                >
                  <Check size={12} /> Approve
                </button>
                <button
                  onClick={() => setBulkConfirm('reject')}
                  className="flex items-center gap-1 px-2.5 py-1 text-xs bg-[var(--sc-coral)]/10 text-[var(--sc-coral)] rounded-lg hover:bg-[var(--sc-coral)]/20 transition-colors"
                >
                  <X size={12} /> Reject
                </button>
              </>
            )}
          </div>
        )}
      </div>

      {mutationError && (
        <div className="glass-card p-5 border-[var(--sc-coral)]/30 bg-[var(--sc-coral)]/10 text-sm text-[var(--sc-coral)]">
          {mutationError}
        </div>
      )}

      {/* Items */}
      <div>
        {isLoading ? (
          <div className="glass-card p-5 flex items-center justify-center h-32">
            <div className="text-xs text-[var(--sc-text-muted)] animate-pulse">Loading quarantine items...</div>
          </div>
        ) : items.length === 0 ? (
          <div className="glass-card p-5 flex flex-col items-center justify-center h-32 text-[var(--sc-text-muted)]">
            <AlertTriangle size={24} className="mb-2 text-[var(--sc-text-muted)]" />
            <span className="text-xs">No {statusFilter} items</span>
          </div>
        ) : (
          <div className="space-y-3">
            {items.map((item) => {
              const indicators = (() => {
                try { return JSON.parse(item.threat_indicators); } catch { return []; }
              })();
              const isMemoryFile = item.source_type === 'memory_file';

              return (
                <div
                  key={item.id}
                  className={`glass-card p-5 ${
                    selectedIds.has(item.id)
                      ? 'border-[var(--sc-cyan)]/50'
                      : item.status === 'pending' && !item.annotation
                        ? 'border-[var(--sc-amber)]/35'
                        : ''
                  }`}
                >
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex items-start gap-2.5">
                      {item.status === 'pending' && (
                        <button
                          onClick={() => toggleSelect(item.id)}
                          className="mt-0.5 text-[var(--sc-text-muted)] hover:text-[var(--sc-cyan)] transition-colors shrink-0"
                        >
                          {selectedIds.has(item.id) ? <CheckSquare size={14} className="text-[var(--sc-cyan)]" /> : <Square size={14} />}
                        </button>
                      )}
                      <div>
                        <div className="flex flex-wrap items-center gap-2">
                          <h4 className="text-sm font-medium text-[var(--sc-text-primary)]">
                            {item.title || 'Untitled'}
                          </h4>
                          {item.status === 'pending' && !item.annotation && (
                            <span className="inline-flex items-center gap-1 rounded border border-[var(--sc-amber)]/25 bg-[var(--sc-amber)]/10 px-2 py-0.5 text-[9px] font-semibold uppercase tracking-[0.12em] text-[var(--sc-amber)]">
                              <Bot size={10} /> Needs explanation
                            </span>
                          )}
                        </div>
                        <div className="text-[10px] text-[var(--sc-text-muted)] mt-0.5">
                          {item.source_type} &middot; {new Date(item.created_at).toLocaleString()}
                          {item.anomaly_score > 0 && (
                            <span className={`ml-2 ${item.anomaly_score > 0.5 ? 'text-[var(--sc-coral)]' : 'text-[var(--sc-amber)]'}`}>
                              Anomaly: {item.anomaly_score.toFixed(2)}
                            </span>
                          )}
                        </div>
                        {isMemoryFile && (
                          <div className="mt-1 break-all font-mono text-[10px] text-[var(--sc-text-muted)]">
                            {item.source_identifier}
                          </div>
                        )}
                      </div>
                    </div>
                    <span className="text-[10px] text-[var(--sc-coral)] bg-[var(--sc-coral)]/10 px-2 py-0.5 rounded">
                      {item.reason?.slice(0, 50) || 'Threat detected'}
                    </span>
                  </div>

                  {/* Content preview */}
                  <div className="bg-[var(--sc-bg-elevated)] rounded-lg p-3 mb-3 text-xs text-[var(--sc-text-primary)] whitespace-pre-wrap break-words">
                    {item.content?.slice(0, 500) || 'No content'}
                  </div>

                  {/* Threat indicators */}
                  {indicators.length > 0 && (
                    <div className="flex gap-1 mb-3 flex-wrap">
                      {indicators.map((ind: string, i: number) => (
                        <span key={i} className="text-[9px] text-[var(--sc-amber)] bg-[var(--sc-amber)]/10 px-1.5 py-0.5 rounded">
                          {ind}
                        </span>
                      ))}
                    </div>
                  )}

                  {item.annotation && <LocalAiQuarantineAnnotation annotation={item.annotation} />}

                  {/* Actions (only for pending) */}
                  {item.status === 'pending' && (
                    <div className="flex flex-wrap gap-2">
                      <button
                        onClick={() => annotateMutation.mutate(item.id)}
                        disabled={!canAnnotate || annotateMutation.isPending || annotatePendingMutation.isPending}
                        className="flex items-center gap-1 px-3 py-1.5 text-xs bg-[var(--sc-bg-elevated)] text-[var(--sc-text-secondary)] border border-[var(--sc-border)] rounded-lg hover:text-[var(--sc-cyan)] transition-colors disabled:pointer-events-none disabled:opacity-45"
                      >
                        {annotateMutation.isPending ? <Loader2 size={12} className="animate-spin" /> : <Wand2 size={12} />}
                        {item.annotation ? 'Re-explain' : 'Explain'}
                      </button>
                      <button
                        onClick={() => setConfirmAction({ action: 'approve', item })}
                        disabled={approveMutation.isPending || bulkApproveMutation.isPending}
                        className="flex items-center gap-1 px-3 py-1.5 text-xs bg-[var(--sc-cyan)]/10 text-[var(--sc-cyan)] rounded-lg hover:bg-[var(--sc-cyan)]/20 transition-colors"
                      >
                        <Check size={12} /> {isMemoryFile ? 'Mark reviewed' : 'Approve'}
                      </button>
                      <button
                        onClick={() => setConfirmAction({ action: 'reject', item })}
                        disabled={rejectMutation.isPending || bulkRejectMutation.isPending}
                        className="flex items-center gap-1 px-3 py-1.5 text-xs bg-[var(--sc-coral)]/10 text-[var(--sc-coral)] rounded-lg hover:bg-[var(--sc-coral)]/20 transition-colors"
                      >
                        <X size={12} /> Reject
                      </button>
                    </div>
                  )}

                  {/* Review info (for reviewed items) */}
                  {item.reviewed_at && (
                    <div className="text-[10px] text-[var(--sc-text-muted)]">
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
