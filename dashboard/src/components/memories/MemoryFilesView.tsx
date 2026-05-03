'use client';

import { useState } from 'react';
import { AlertTriangle, CheckCircle2, Clock, ExternalLink, FileText, Loader2, ScanLine, Sparkles } from 'lucide-react';
import { toast } from 'sonner';
import { Badge, riskVariant } from '@/components/ds/Badge';
import { Button } from '@/components/ds/Button';
import { GlassCard } from '@/components/ds/GlassCard';
import { LocalAiExplanationPanel, type ExplainAction } from '@/components/local-ai/LocalAiExplanationPanel';
import { ProFeatureGate } from '@/components/shield/ProFeatureGate';
import { useLocalAiExplain, type LocalAiExplanation } from '@/hooks/useLocalAiExplainer';
import { useMemoryFileScan, type MemoryFileScanRecord } from '@/hooks/useMemoryFiles';
import { buildEditorUrl } from '@/lib/editor-url';

function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

function formatDate(value: string | null): string {
  if (!value) return 'Unknown';
  return new Date(value).toLocaleString();
}

function fileName(path: string): string {
  return path.split(/[\\/]/).filter(Boolean).pop() ?? path;
}

function isFlagged(file: MemoryFileScanRecord): boolean {
  return file.risk !== 'SAFE' && file.risk !== 'LOW';
}

function buildExplainContent(file: MemoryFileScanRecord): string {
  const evidence = file.evidence
    .map((entry) => `${entry.reason}: ${entry.snippet}`)
    .join('\n');
  const findings = file.findings
    .map((finding) => `${finding.severity.toUpperCase()}: ${finding.title} - ${finding.description}`)
    .join('\n');

  return [
    `Path: ${file.path}`,
    `Source: ${file.source}`,
    `Risk: ${file.risk}`,
    `Firewall result: ${file.firewallResult}`,
    `Scan reason: ${file.reason}`,
    file.threatIndicators.length ? `Threat indicators: ${file.threatIndicators.join(', ')}` : '',
    evidence ? `Evidence:\n${evidence}` : '',
    findings ? `Findings:\n${findings}` : '',
    file.contentExcerpt ? `Content excerpt:\n${file.contentExcerpt}` : 'Content excerpt: empty file',
  ].filter(Boolean).join('\n\n');
}

function MemoryFileCard({
  file,
  isActive,
  explaining,
  explanation,
  explainError,
  onExplain,
}: {
  file: MemoryFileScanRecord;
  isActive: boolean;
  explaining: boolean;
  explanation?: LocalAiExplanation;
  explainError: unknown;
  onExplain: (file: MemoryFileScanRecord) => void;
}) {
  const flagged = isFlagged(file);
  const badgeVariant = riskVariant(file.risk);
  const cardSeverity = file.risk.toLowerCase() as 'critical' | 'high' | 'medium' | 'low' | 'safe';

  return (
    <GlassCard
      className={`p-4 ${flagged ? '' : 'opacity-80'}`}
      severity={flagged ? cardSeverity : undefined}
    >
      <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant={badgeVariant} dot={flagged}>{file.risk}</Badge>
            <Badge variant={file.firewallResult === 'ALLOW' ? 'muted' : 'amber'}>
              {file.firewallResult}
            </Badge>
            <Badge variant="muted">{file.source}</Badge>
          </div>
          <div className="mt-3 flex min-w-0 items-start gap-2">
            <FileText size={16} className="mt-0.5 shrink-0 text-[var(--sc-cyan)]" />
            <div className="min-w-0">
              <h3 className="truncate text-sm font-semibold text-[var(--sc-text-primary)]">
                {fileName(file.path)}
              </h3>
              <p className="mt-1 break-all text-xs text-[var(--sc-text-muted)]">{file.path}</p>
            </div>
          </div>
        </div>

        <div className="flex shrink-0 flex-wrap items-center gap-2 text-xs text-[var(--sc-text-muted)]">
          <span>{formatBytes(file.sizeBytes)}</span>
          <span className="inline-flex items-center gap-1">
            <Clock size={12} />
            {formatDate(file.modifiedAt)}
          </span>
          <Button variant="outline" size="sm" onClick={() => onExplain(file)} disabled={explaining}>
            {explaining ? <Loader2 size={13} className="animate-spin" /> : <Sparkles size={13} />}
            {explaining ? 'Explaining' : 'Explain'}
          </Button>
        </div>
      </div>

      <p className="mt-4 text-sm leading-6 text-[var(--sc-text-secondary)]">{file.reason}</p>

      {file.threatIndicators.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {file.threatIndicators.map((indicator) => (
            <span
              key={indicator}
              className="rounded bg-[var(--sc-bg-elevated)] px-2 py-1 text-[11px] text-[var(--sc-text-secondary)]"
            >
              {indicator}
            </span>
          ))}
        </div>
      )}

      {file.evidence.length > 0 && (
        <div className="mt-4 space-y-2 border-t border-[var(--sc-border)] pt-3">
          {file.evidence.map((entry, index) => (
            <div key={`${entry.reason}-${index}`} className="text-xs leading-5">
              <div className="font-semibold text-[var(--sc-text-primary)]">{entry.reason}</div>
              <div className="mt-0.5 break-words text-[var(--sc-text-secondary)]">&quot;{entry.snippet}&quot;</div>
            </div>
          ))}
        </div>
      )}

      {isActive && (
        <div className="mt-4 space-y-3">
          {explanation && (
            <LocalAiExplanationPanel
              explanation={explanation}
              actions={file.path
                ? [{
                  key: 'open',
                  label: 'Open in editor',
                  icon: <ExternalLink size={13} />,
                  variant: 'outline',
                  onClick: () => {
                    const url = buildEditorUrl(file.path);
                    if (url) window.location.href = url;
                  },
                } satisfies ExplainAction]
                : []}
            />
          )}
          {Boolean(explainError) && (
            <div className="rounded-lg border border-[var(--sc-coral)]/30 bg-[var(--sc-coral)]/10 p-3 text-sm text-[var(--sc-coral)]">
              {explainError instanceof Error ? explainError.message : 'Local explanation failed'}
            </div>
          )}
        </div>
      )}
    </GlassCard>
  );
}

export function MemoryFilesView() {
  const scanMutation = useMemoryFileScan();
  const explainMutation = useLocalAiExplain();
  const [activeFileId, setActiveFileId] = useState<string | null>(null);

  const data = scanMutation.data;
  const files = data?.files ?? [];

  const handleScan = () => {
    scanMutation.mutate(undefined, {
      onSuccess: (result) => {
        if (result.summary.flagged > 0) {
          const queued = result.quarantine.created + result.quarantine.updated;
          toast.warning(
            `${result.summary.flagged} memory file${result.summary.flagged === 1 ? '' : 's'} flagged` +
            (queued > 0 ? `, ${queued} queued for review` : '')
          );
        } else {
          toast.success('Memory file scan passed');
        }
      },
      onError: (error) => toast.error(error instanceof Error ? error.message : 'Memory file scan failed'),
    });
  };

  const handleExplain = (file: MemoryFileScanRecord) => {
    setActiveFileId(file.id);
    explainMutation.mutate(
      {
        kind: 'memory_file',
        title: fileName(file.path),
        content: buildExplainContent(file),
        source: `memory-file:${file.path}`,
        signals: [
          file.risk,
          file.firewallResult,
          file.source,
          ...file.threatIndicators,
          ...file.findings.map((finding) => finding.severity),
        ],
        metadata: {
          id: file.id,
          path: file.path,
          source: file.source,
          sizeBytes: file.sizeBytes,
          modifiedAt: file.modifiedAt,
          risk: file.risk,
          firewallResult: file.firewallResult,
          findingCount: file.findings.length,
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

  return (
    <ProFeatureGate feature="memory_file_scan" label="Scan persistent agent memory files for poisoned instructions and credential leaks.">
      <div className="space-y-4">
        <GlassCard className="p-5">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <div className="flex items-center gap-2">
                <ScanLine size={17} className="text-[var(--sc-cyan)]" />
                <h2 className="text-base font-semibold text-[var(--sc-text-primary)]">Memory Files</h2>
              </div>
              {data && (
                <p className="mt-1 text-xs text-[var(--sc-text-muted)]">
                  Scanned {formatDate(data.scannedAt)}
                </p>
              )}
            </div>

            <Button variant="cyan" size="sm" onClick={handleScan} disabled={scanMutation.isPending}>
              {scanMutation.isPending ? <Loader2 size={14} className="animate-spin" /> : <ScanLine size={14} />}
              {scanMutation.isPending ? 'Scanning' : 'Scan Memory Files'}
            </Button>
          </div>

          {data && (
            <div className="mt-5 grid grid-cols-2 gap-3 md:grid-cols-5">
              <div className="rounded-lg bg-[var(--sc-bg-deep)]/60 p-3">
                <div className="text-[10px] uppercase tracking-[0.16em] text-[var(--sc-text-muted)]">Total</div>
                <div className="mt-1 text-xl font-semibold text-[var(--sc-text-primary)]">{data.summary.total}</div>
              </div>
              <div className="rounded-lg bg-[var(--sc-bg-deep)]/60 p-3">
                <div className="text-[10px] uppercase tracking-[0.16em] text-[var(--sc-text-muted)]">Safe</div>
                <div className="mt-1 flex items-center gap-2 text-xl font-semibold text-[var(--sc-cyan)]">
                  <CheckCircle2 size={16} />
                  {data.summary.safe}
                </div>
              </div>
              <div className="rounded-lg bg-[var(--sc-bg-deep)]/60 p-3">
                <div className="text-[10px] uppercase tracking-[0.16em] text-[var(--sc-text-muted)]">Flagged</div>
                <div className="mt-1 flex items-center gap-2 text-xl font-semibold text-[var(--sc-amber)]">
                  <AlertTriangle size={16} />
                  {data.summary.flagged}
                </div>
              </div>
              <div className="rounded-lg bg-[var(--sc-bg-deep)]/60 p-3">
                <div className="text-[10px] uppercase tracking-[0.16em] text-[var(--sc-text-muted)]">High</div>
                <div className="mt-1 text-xl font-semibold text-[var(--sc-coral-mid)]">{data.summary.high}</div>
              </div>
              <div className="rounded-lg bg-[var(--sc-bg-deep)]/60 p-3">
                <div className="text-[10px] uppercase tracking-[0.16em] text-[var(--sc-text-muted)]">Critical</div>
                <div className="mt-1 text-xl font-semibold text-[var(--sc-coral)]">{data.summary.critical}</div>
              </div>
            </div>
          )}

          {data && data.quarantine.created + data.quarantine.updated > 0 && (
            <div className="mt-4 rounded-lg border border-[var(--sc-amber)]/25 bg-[var(--sc-amber)]/10 px-3 py-2 text-xs text-[var(--sc-amber)]">
              {data.quarantine.created + data.quarantine.updated} flagged file{data.quarantine.created + data.quarantine.updated === 1 ? '' : 's'} queued in Quarantine for manual review.
            </div>
          )}
        </GlassCard>

        {scanMutation.error && (
          <GlassCard className="border-[var(--sc-coral)]/30 p-4">
            <p className="text-sm text-[var(--sc-coral)]">
              {scanMutation.error instanceof Error ? scanMutation.error.message : 'Memory file scan failed'}
            </p>
          </GlassCard>
        )}

        {data && files.length === 0 && (
          <GlassCard className="p-8 text-center">
            <CheckCircle2 size={24} className="mx-auto text-[var(--sc-cyan)]" />
            <p className="mt-3 text-sm text-[var(--sc-text-secondary)]">No memory files found.</p>
          </GlassCard>
        )}

        {files.length > 0 && (
          <div className="grid grid-cols-1 gap-3">
            {files.map((file) => (
              <MemoryFileCard
                key={file.id}
                file={file}
                isActive={activeFileId === file.id}
                explaining={activeFileId === file.id && explainMutation.isPending}
                explanation={activeFileId === file.id ? explainMutation.data?.explanation : undefined}
                explainError={activeFileId === file.id ? explainMutation.error : null}
                onExplain={handleExplain}
              />
            ))}
          </div>
        )}
      </div>
    </ProFeatureGate>
  );
}
