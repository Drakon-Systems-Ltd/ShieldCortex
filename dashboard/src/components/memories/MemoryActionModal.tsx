'use client';

import { useEffect, useMemo, useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import {
  ArrowUpCircle,
  Database,
  ExternalLink,
  FileScan,
  ShieldAlert,
  Sparkles,
  Trash2,
  X,
} from 'lucide-react';
import { toast } from 'sonner';
import { Badge, riskVariant } from '@/components/ds/Badge';
import { Button } from '@/components/ds/Button';
import { LocalAiExplanationPanel, type ExplainAction } from '@/components/local-ai/LocalAiExplanationPanel';
import { buildEditorUrl } from '@/lib/editor-url';

// Memories sometimes carry a file path in `source` (e.g. memory_file scans,
// agent skill scans). Show "Open in editor" when the heuristic matches.
function detectFilePath(source: string | null | undefined): string | null {
  if (!source) return null;
  const trimmed = source.trim();
  if (!trimmed.includes('/')) return null;
  if (!/\.[A-Za-z0-9]{1,8}$/.test(trimmed)) return null;
  return trimmed;
}
import { authFetch, readApiError } from '@/lib/auth';
import {
  useAccessMemory,
  useDeleteMemory,
  usePromoteMemory,
  useQuarantineMemory,
} from '@/hooks/useMemories';
import { useLocalAiExplain } from '@/hooks/useLocalAiExplainer';
import type { Memory } from '@/types/memory';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

interface MemoryScanResult {
  allowed: boolean;
  firewall: {
    result: 'ALLOW' | 'BLOCK' | 'QUARANTINE';
    reason: string;
    threatIndicators: string[];
    anomalyScore: number;
    blockedPatterns: string[];
  };
  sensitivity: {
    level: string;
    confidence: number;
    detectedPatterns: string[];
    redactionRequired: boolean;
  };
  trust: {
    score: number;
  };
}

interface MemoryActionModalProps {
  memory: Memory;
  onClose: () => void;
}

function formatDate(value?: string | null): string {
  if (!value) return 'Not set';
  return new Date(value).toLocaleString();
}

function percent(value: number | undefined): string {
  return `${Math.round((value ?? 0) * 100)}%`;
}

async function scanMemory(memory: Memory): Promise<MemoryScanResult> {
  const response = await authFetch(`${API_BASE}/api/v1/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      title: memory.title,
      content: `Title: ${memory.title}\n\nContent:\n${memory.content}`,
      source: {
        type: 'api',
        identifier: `dashboard:memory:${memory.id}`,
      },
    }),
  });

  if (!response.ok) throw new Error(await readApiError(response, 'Failed to scan memory'));
  return response.json();
}

function ScanResultPanel({ result }: { result: MemoryScanResult }) {
  const risk = result.firewall.result === 'ALLOW' ? 'SAFE' : result.firewall.result;
  const indicators = result.firewall.threatIndicators ?? [];

  return (
    <div className="rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/70 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant={riskVariant(risk)}>{risk}</Badge>
        <Badge variant="muted">anomaly {result.firewall.anomalyScore.toFixed(2)}</Badge>
        <Badge variant="muted">trust {result.trust.score.toFixed(2)}</Badge>
        <Badge variant={result.sensitivity.redactionRequired ? 'amber' : 'muted'}>
          {result.sensitivity.level}
        </Badge>
      </div>
      <p className="mt-3 text-sm text-[var(--sc-text-primary)]">{result.firewall.reason}</p>
      {indicators.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {indicators.map((indicator) => (
            <span
              key={indicator}
              className="rounded bg-[var(--sc-bg-elevated)] px-2 py-1 text-[11px] text-[var(--sc-text-secondary)]"
            >
              {indicator}
            </span>
          ))}
        </div>
      )}
      {result.firewall.blockedPatterns.length > 0 && (
        <div className="mt-3 rounded border border-[var(--sc-coral)]/30 bg-[var(--sc-coral)]/10 p-2 text-xs text-[var(--sc-coral)]">
          {result.firewall.blockedPatterns.join(', ')}
        </div>
      )}
    </div>
  );
}

export function MemoryActionModal({ memory, onClose }: MemoryActionModalProps) {
  const [confirmAction, setConfirmAction] = useState<'delete' | 'quarantine' | null>(null);

  const accessMemory = useAccessMemory();
  const promoteMemory = usePromoteMemory();
  const deleteMemory = useDeleteMemory();
  const quarantineMemory = useQuarantineMemory();
  const explainMutation = useLocalAiExplain();
  const scanMutation = useMutation({ mutationFn: () => scanMemory(memory) });

  const tags = useMemo(() => memory.tags ?? [], [memory.tags]);
  const busy =
    accessMemory.isPending ||
    promoteMemory.isPending ||
    deleteMemory.isPending ||
    quarantineMemory.isPending ||
    explainMutation.isPending ||
    scanMutation.isPending;

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [onClose]);

  const handleScan = () => {
    setConfirmAction(null);
    scanMutation.mutate(undefined, {
      onSuccess: (result) => {
        if (result.firewall.result === 'ALLOW') {
          toast.success('Memory scan passed');
        } else {
          toast.warning(`Memory scan returned ${result.firewall.result.toLowerCase()}`);
        }
      },
      onError: (error) => toast.error(error instanceof Error ? error.message : 'Memory scan failed'),
    });
  };

  const handleExplain = () => {
    setConfirmAction(null);
    explainMutation.mutate(
      {
        kind: 'memory',
        title: memory.title,
        content: memory.content,
        project: memory.project,
        source: `${memory.sourceKind ?? 'user'}${memory.source ? `:${memory.source}` : ''}`,
        signals: [
          memory.category,
          memory.type,
          memory.status ?? 'active',
          memory.sensitivityLevel ?? 'INTERNAL',
          ...tags,
        ],
        metadata: {
          id: memory.id,
          uuid: memory.uuid,
          trustScore: memory.trustScore,
          salience: memory.salience,
          decayedScore: memory.decayedScore,
          captureMethod: memory.captureMethod,
          accessCount: memory.accessCount,
          cloudExcluded: memory.cloudExcluded,
        },
      },
      {
        onSuccess: (result) => {
          toast.success(result.explanation.synthetic ? 'Fallback explanation generated' : 'Local explanation generated');
        },
        onError: (error) => toast.error(error instanceof Error ? error.message : 'Local explanation failed'),
      },
    );
  };

  const handleReinforce = () => {
    setConfirmAction(null);
    accessMemory.mutate(memory.id, {
      onSuccess: () => toast.success('Memory reinforced'),
      onError: (error) => toast.error(error instanceof Error ? error.message : 'Failed to reinforce memory'),
    });
  };

  const handlePromote = () => {
    setConfirmAction(null);
    promoteMemory.mutate(memory.id, {
      onSuccess: () => toast.success('Memory promoted to long-term'),
      onError: (error) => toast.error(error instanceof Error ? error.message : 'Failed to promote memory'),
    });
  };

  const handleQuarantine = () => {
    quarantineMemory.mutate(
      { id: memory.id, reason: 'Quarantined from memory detail modal' },
      {
        onSuccess: () => {
          toast.warning('Memory moved to quarantine');
          onClose();
        },
        onError: (error) => toast.error(error instanceof Error ? error.message : 'Failed to quarantine memory'),
      },
    );
  };

  const handleDelete = () => {
    deleteMemory.mutate(memory.id, {
      onSuccess: () => {
        toast.success('Memory deleted');
        onClose();
      },
      onError: (error) => toast.error(error instanceof Error ? error.message : 'Failed to delete memory'),
    });
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-labelledby="memory-detail-title"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div className="flex max-h-[90vh] w-full max-w-3xl flex-col overflow-hidden rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-surface)] shadow-2xl">
        <div className="flex items-start justify-between gap-4 border-b border-[var(--sc-border)] p-5">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="cyan">{memory.category}</Badge>
              <Badge variant="muted">{memory.type.replace('_', '-')}</Badge>
              <Badge variant={memory.status && memory.status !== 'active' ? 'amber' : 'safe'}>
                {memory.status ?? 'active'}
              </Badge>
            </div>
            <h2 id="memory-detail-title" className="mt-3 text-lg font-semibold text-[var(--sc-text-primary)]">
              {memory.title}
            </h2>
            <p className="mt-1 text-sm text-[var(--sc-text-secondary)]">{memory.project || 'Global memory'}</p>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-2 text-[var(--sc-text-muted)] transition-colors hover:bg-[var(--sc-bg-elevated)] hover:text-[var(--sc-text-primary)]"
            aria-label="Close memory detail"
            type="button"
          >
            <X size={18} />
          </button>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto p-5">
          <div className="grid gap-4 lg:grid-cols-[1.5fr_1fr]">
            <div className="space-y-4">
              <section>
                <h3 className="text-xs font-semibold uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">Content</h3>
                <pre className="mt-2 max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/70 p-3 font-sans text-sm leading-6 text-[var(--sc-text-primary)]">
                  {memory.content}
                </pre>
              </section>

              {explainMutation.data?.explanation && (
                <LocalAiExplanationPanel
                  explanation={explainMutation.data.explanation}
                  actions={(() => {
                    const filePath = detectFilePath(memory.source);
                    if (!filePath) return [];
                    const actions: ExplainAction[] = [
                      {
                        key: 'open',
                        label: 'Open in editor',
                        icon: <ExternalLink size={13} />,
                        variant: 'outline',
                        onClick: () => {
                          const url = buildEditorUrl(filePath);
                          if (url) window.location.href = url;
                        },
                      },
                    ];
                    return actions;
                  })()}
                />
              )}

              {explainMutation.error && (
                <div className="rounded-lg border border-[var(--sc-coral)]/30 bg-[var(--sc-coral)]/10 p-3 text-sm text-[var(--sc-coral)]">
                  {explainMutation.error instanceof Error ? explainMutation.error.message : 'Local explanation failed'}
                </div>
              )}

              {scanMutation.data && <ScanResultPanel result={scanMutation.data} />}

              {scanMutation.error && (
                <div className="rounded-lg border border-[var(--sc-coral)]/30 bg-[var(--sc-coral)]/10 p-3 text-sm text-[var(--sc-coral)]">
                  {scanMutation.error instanceof Error ? scanMutation.error.message : 'Memory scan failed'}
                </div>
              )}
            </div>

            <div className="space-y-4">
              <section className="rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/50 p-3">
                <h3 className="text-xs font-semibold uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">Health</h3>
                <div className="mt-3 grid grid-cols-2 gap-3 text-sm">
                  <div>
                    <div className="text-[var(--sc-text-muted)]">Salience</div>
                    <div className="font-semibold text-[var(--sc-text-primary)]">{percent(memory.salience)}</div>
                  </div>
                  <div>
                    <div className="text-[var(--sc-text-muted)]">Decay</div>
                    <div className="font-semibold text-[var(--sc-text-primary)]">{percent(memory.decayedScore ?? memory.salience)}</div>
                  </div>
                  <div>
                    <div className="text-[var(--sc-text-muted)]">Trust</div>
                    <div className="font-semibold text-[var(--sc-text-primary)]">{(memory.trustScore ?? 1).toFixed(2)}</div>
                  </div>
                  <div>
                    <div className="text-[var(--sc-text-muted)]">Accesses</div>
                    <div className="font-semibold text-[var(--sc-text-primary)]">{memory.accessCount}</div>
                  </div>
                </div>
              </section>

              <section className="rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/50 p-3">
                <h3 className="text-xs font-semibold uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">Provenance</h3>
                <dl className="mt-3 space-y-2 text-sm">
                  <div className="flex justify-between gap-3">
                    <dt className="text-[var(--sc-text-muted)]">Source</dt>
                    <dd className="text-right text-[var(--sc-text-primary)]">{memory.sourceKind || 'user'}</dd>
                  </div>
                  <div className="flex justify-between gap-3">
                    <dt className="text-[var(--sc-text-muted)]">Capture</dt>
                    <dd className="text-right text-[var(--sc-text-primary)]">{memory.captureMethod || 'manual'}</dd>
                  </div>
                  <div className="flex justify-between gap-3">
                    <dt className="text-[var(--sc-text-muted)]">Created</dt>
                    <dd className="text-right text-[var(--sc-text-primary)]">{formatDate(memory.createdAt)}</dd>
                  </div>
                  <div className="flex justify-between gap-3">
                    <dt className="text-[var(--sc-text-muted)]">Updated</dt>
                    <dd className="text-right text-[var(--sc-text-primary)]">{formatDate(memory.updatedAt)}</dd>
                  </div>
                  <div className="flex justify-between gap-3">
                    <dt className="text-[var(--sc-text-muted)]">Sensitivity</dt>
                    <dd className="text-right text-[var(--sc-text-primary)]">{memory.sensitivityLevel || 'INTERNAL'}</dd>
                  </div>
                  <div className="flex justify-between gap-3">
                    <dt className="text-[var(--sc-text-muted)]">Cloud</dt>
                    <dd className="text-right text-[var(--sc-text-primary)]">{memory.cloudExcluded ? 'Excluded' : 'Eligible'}</dd>
                  </div>
                </dl>
              </section>

              {tags.length > 0 && (
                <section className="rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/50 p-3">
                  <h3 className="text-xs font-semibold uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">Tags</h3>
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {tags.map((tag) => (
                      <span key={tag} className="rounded bg-[var(--sc-bg-elevated)] px-2 py-1 text-xs text-[var(--sc-text-secondary)]">
                        {tag}
                      </span>
                    ))}
                  </div>
                </section>
              )}
            </div>
          </div>
        </div>

        <div className="border-t border-[var(--sc-border)] p-4">
          {confirmAction && (
            <div className="mb-3 rounded-lg border border-[var(--sc-coral)]/30 bg-[var(--sc-coral)]/10 p-3">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <p className="text-sm text-[var(--sc-coral)]">
                  {confirmAction === 'delete'
                    ? 'Delete this memory permanently?'
                    : 'Move this memory to quarantine for manual review?'}
                </p>
                <div className="flex gap-2">
                  <Button size="sm" variant="outline" onClick={() => setConfirmAction(null)} disabled={busy}>
                    Cancel
                  </Button>
                  <Button
                    size="sm"
                    variant="coral"
                    onClick={confirmAction === 'delete' ? handleDelete : handleQuarantine}
                    disabled={busy}
                  >
                    {confirmAction === 'delete' ? 'Delete' : 'Quarantine'}
                  </Button>
                </div>
              </div>
            </div>
          )}

          <div className="flex flex-wrap justify-end gap-2">
            <Button variant="outline" size="sm" onClick={handleExplain} disabled={busy} pulse={explainMutation.isPending}>
              <Sparkles size={14} />
              {explainMutation.isPending ? 'Explaining' : 'Explain'}
            </Button>
            <Button variant="outline" size="sm" onClick={handleScan} disabled={busy}>
              <FileScan size={14} />
              {scanMutation.isPending ? 'Scanning' : 'Scan'}
            </Button>
            <Button variant="outline" size="sm" onClick={handleReinforce} disabled={busy}>
              <Database size={14} />
              {accessMemory.isPending ? 'Reinforcing' : 'Reinforce'}
            </Button>
            {memory.type === 'short_term' && (
              <Button variant="outline" size="sm" onClick={handlePromote} disabled={busy}>
                <ArrowUpCircle size={14} />
                {promoteMemory.isPending ? 'Promoting' : 'Promote'}
              </Button>
            )}
            <Button
              variant="outline"
              size="sm"
              onClick={() => setConfirmAction(confirmAction === 'quarantine' ? null : 'quarantine')}
              disabled={busy}
            >
              <ShieldAlert size={14} />
              Quarantine
            </Button>
            <Button
              variant="coral"
              size="sm"
              onClick={() => setConfirmAction(confirmAction === 'delete' ? null : 'delete')}
              disabled={busy}
            >
              <Trash2 size={14} />
              Delete
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
