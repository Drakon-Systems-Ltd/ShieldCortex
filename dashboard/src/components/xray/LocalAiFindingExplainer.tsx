'use client';

import { Sparkles } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ds/Button';
import { LocalAiExplanationPanel } from '@/components/local-ai/LocalAiExplanationPanel';
import { useLocalAiExplain } from '@/hooks/useLocalAiExplainer';

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

  return (
    <div className="mt-3 space-y-3">
      <Button variant="outline" size="sm" onClick={handleExplain} disabled={explainMutation.isPending}>
        <Sparkles size={13} />
        {explainMutation.isPending ? 'Explaining' : 'Explain'}
      </Button>

      {explainMutation.data?.explanation && (
        <LocalAiExplanationPanel explanation={explainMutation.data.explanation} />
      )}

      {explainMutation.error && (
        <div className="rounded-lg border border-[var(--sc-coral)]/30 bg-[var(--sc-coral)]/10 p-3 text-sm text-[var(--sc-coral)]">
          {explainMutation.error instanceof Error ? explainMutation.error.message : 'Local explanation failed'}
        </div>
      )}
    </div>
  );
}
