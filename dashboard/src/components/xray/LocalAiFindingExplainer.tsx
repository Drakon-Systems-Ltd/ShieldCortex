'use client';

import { ExternalLink, ShieldAlert, ShieldCheck, ShieldX, Sparkles } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ds/Button';
import { LocalAiExplanationPanel, type ExplainAction } from '@/components/local-ai/LocalAiExplanationPanel';
import { useLocalAiExplain } from '@/hooks/useLocalAiExplainer';
import { useQuarantineFinding, useUpdateFindingStatus } from '@/hooks/useXRayFindings';
import { buildEditorUrl } from '@/lib/editor-url';

export interface ExplainableXRayFinding {
  id?: string;
  severity: string;
  category: string;
  title: string;
  description: string;
  file?: string;
  line?: number;
  evidence?: string;
  status?: string;
  detectedAt?: string;
  guidance?: {
    whatItMeans?: string;
    whatToDo?: string;
    falsePositiveNote?: string;
    urgency?: string;
  };
  systemFile?: boolean;
}

function buildFindingContent(finding: ExplainableXRayFinding): string {
  return [
    `Title: ${finding.title}`,
    `Description: ${finding.description}`,
    finding.file ? `File: ${finding.line ? `${finding.file}:${finding.line}` : finding.file}` : '',
    finding.evidence ? `Evidence: ${finding.evidence}` : '',
    finding.guidance?.whatItMeans ? `Scanner meaning: ${finding.guidance.whatItMeans}` : '',
    finding.guidance?.whatToDo ? `Scanner guidance: ${finding.guidance.whatToDo}` : '',
    finding.guidance?.falsePositiveNote ? `False positive note: ${finding.guidance.falsePositiveNote}` : '',
  ].filter(Boolean).join('\n');
}

export function LocalAiFindingExplainer({ finding }: { finding: ExplainableXRayFinding }) {
  const explainMutation = useLocalAiExplain();
  const updateStatus = useUpdateFindingStatus();
  const quarantine = useQuarantineFinding();

  const handleExplain = () => {
    explainMutation.mutate(
      {
        kind: 'xray_finding',
        title: finding.title,
        content: buildFindingContent(finding),
        source: finding.file ? `xray:${finding.file}` : 'xray',
        signals: [
          finding.severity,
          finding.category,
          finding.status ?? '',
          finding.guidance?.urgency ?? '',
          finding.systemFile ? 'system-file' : '',
        ].filter(Boolean),
        metadata: {
          id: finding.id,
          file: finding.file,
          line: finding.line,
          severity: finding.severity,
          category: finding.category,
          status: finding.status,
          detectedAt: finding.detectedAt,
          systemFile: finding.systemFile,
          guidance: finding.guidance,
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

  const buildActions = (): ExplainAction[] => {
    const actions: ExplainAction[] = [];

    if (finding.file) {
      const url = buildEditorUrl(finding.file, finding.line);
      actions.push({
        key: 'open',
        label: 'Open in editor',
        icon: <ExternalLink size={13} />,
        variant: 'outline',
        onClick: () => {
          if (url) window.location.href = url;
        },
      });
    }

    // The status/quarantine actions all need a finding id to call the API.
    if (!finding.id) return actions;

    const id = finding.id;
    const isPending = updateStatus.isPending || quarantine.isPending;

    actions.push({
      key: 'reviewed',
      label: 'Mark reviewed',
      icon: <ShieldCheck size={13} />,
      variant: 'outline',
      pending: updateStatus.isPending && updateStatus.variables?.status === 'reviewed',
      disabled: isPending,
      onClick: () => {
        updateStatus.mutate({ id, status: 'reviewed' }, {
          onSuccess: () => toast.success('Marked as reviewed'),
          onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to mark reviewed'),
        });
      },
    });

    actions.push({
      key: 'dismiss',
      label: 'Dismiss',
      icon: <ShieldX size={13} />,
      variant: 'ghost',
      pending: updateStatus.isPending && updateStatus.variables?.status === 'ignored',
      disabled: isPending,
      onClick: () => {
        updateStatus.mutate({ id, status: 'ignored' }, {
          onSuccess: () => toast.success('Finding dismissed'),
          onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to dismiss'),
        });
      },
    });

    actions.push({
      key: 'quarantine',
      label: 'Quarantine file',
      icon: <ShieldAlert size={13} />,
      variant: 'coral',
      pending: quarantine.isPending,
      disabled: isPending,
      onClick: () => {
        quarantine.mutate({ id }, {
          onSuccess: () => toast.success('File quarantined'),
          onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to quarantine'),
        });
      },
    });

    return actions;
  };

  return (
    <div className="mt-3 space-y-3">
      <Button variant="outline" size="sm" onClick={handleExplain} disabled={explainMutation.isPending}>
        <Sparkles size={13} />
        {explainMutation.isPending ? 'Explaining' : 'Explain'}
      </Button>

      {explainMutation.data?.explanation && (
        <LocalAiExplanationPanel
          explanation={explainMutation.data.explanation}
          actions={buildActions()}
        />
      )}

      {explainMutation.error && (
        <div className="rounded-lg border border-[var(--sc-coral)]/30 bg-[var(--sc-coral)]/10 p-3 text-sm text-[var(--sc-coral)]">
          {explainMutation.error instanceof Error ? explainMutation.error.message : 'Local explanation failed'}
        </div>
      )}
    </div>
  );
}
