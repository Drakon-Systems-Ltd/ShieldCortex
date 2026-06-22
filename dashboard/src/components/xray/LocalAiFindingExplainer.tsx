'use client';

import { useState } from 'react';
import { Check, ExternalLink, ShieldAlert, ShieldCheck, ShieldX, Sparkles } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ds/Button';
import { LocalAiExplanationPanel, type ExplainAction } from '@/components/local-ai/LocalAiExplanationPanel';
import { useLocalAiExplain } from '@/hooks/useLocalAiExplainer';
import { useQuarantineFinding, useUpdateFindingStatus, useXRayFindingsList } from '@/hooks/useXRayFindings';
import { buildEditorUrl } from '@/lib/editor-url';

// Stable identity match used by the backend findings store (see
// `findingDedupeKey` in src/xray/findings-store.ts). Re-implemented here so
// the History/Scanner views can resolve a persisted id even when the rendered
// finding came from a stored scan blob (which doesn't carry ids).
function findingMatchKey(category: string, title: string, file?: string, line?: number): string {
  return `${category}|${title}|${file ?? ''}|${line ?? ''}`;
}

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

export function LocalAiFindingExplainer({ finding, target }: { finding: ExplainableXRayFinding; target?: string }) {
  const explainMutation = useLocalAiExplain();
  const updateStatus = useUpdateFindingStatus();
  const quarantine = useQuarantineFinding();
  // Track which actions completed so the buttons can show a permanent "done"
  // state — the API call succeeds and the toast flashes, but the underlying
  // finding card on Scanner/History tabs renders from a result blob that
  // doesn't refetch, so the user can't otherwise tell the action stuck.
  const [completed, setCompleted] = useState<Set<string>>(new Set());
  const markCompleted = (key: string) => setCompleted((prev) => {
    const next = new Set(prev);
    next.add(key);
    return next;
  });

  // If the rendered finding has no id (Scanner/History tabs render from
  // result blobs that don't carry persisted ids), look the id up by stable
  // identity against the findings table. The lookup only fires when an
  // explanation has already been generated AND we have a target to scope to.
  const needsLookup = !finding.id && Boolean(target) && Boolean(explainMutation.data);
  const findingsLookup = useXRayFindingsList(needsLookup ? { target, limit: 200 } : undefined);
  const resolvedId = (() => {
    if (finding.id) return finding.id;
    if (!findingsLookup.data?.findings) return undefined;
    const wantKey = findingMatchKey(finding.category, finding.title, finding.file, finding.line);
    type Persisted = { id: string; category: string; title: string; file?: string; line?: number };
    const match = (findingsLookup.data.findings as Persisted[]).find(
      (f) => findingMatchKey(f.category, f.title, f.file, f.line) === wantKey,
    );
    return match?.id;
  })();

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

    // The status/quarantine actions need a persisted finding id. Use the
    // rendered finding's id when present (Findings tab) or the lookup result
    // (Scanner/History tabs).
    if (!resolvedId) {
      // While the lookup is in flight, surface a disabled placeholder so users
      // know more buttons are coming. If the lookup finished and still no id,
      // we just stop after Open in editor.
      if (needsLookup && findingsLookup.isLoading) {
        actions.push({
          key: 'lookup',
          label: 'Loading actions',
          variant: 'outline',
          disabled: true,
          pending: true,
          onClick: () => undefined,
        });
      }
      return actions;
    }

    const id = resolvedId;
    const isPending = updateStatus.isPending || quarantine.isPending;

    const reviewedDone = completed.has('reviewed');
    actions.push({
      key: 'reviewed',
      label: reviewedDone ? 'Reviewed' : 'Mark reviewed',
      icon: reviewedDone ? <Check size={13} /> : <ShieldCheck size={13} />,
      variant: reviewedDone ? 'cyan' : 'outline',
      pending: updateStatus.isPending && updateStatus.variables?.status === 'reviewed',
      disabled: isPending || reviewedDone,
      onClick: () => {
        updateStatus.mutate({ id, status: 'reviewed' }, {
          onSuccess: () => {
            markCompleted('reviewed');
            toast.success('Marked as reviewed');
          },
          onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to mark reviewed'),
        });
      },
    });

    const dismissDone = completed.has('dismiss');
    actions.push({
      key: 'dismiss',
      label: dismissDone ? 'Dismissed' : 'Dismiss',
      icon: dismissDone ? <Check size={13} /> : <ShieldX size={13} />,
      variant: dismissDone ? 'cyan' : 'ghost',
      pending: updateStatus.isPending && updateStatus.variables?.status === 'ignored',
      disabled: isPending || dismissDone,
      onClick: () => {
        updateStatus.mutate({ id, status: 'ignored' }, {
          onSuccess: () => {
            markCompleted('dismiss');
            toast.success('Finding dismissed');
          },
          onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to dismiss'),
        });
      },
    });

    const quarantineDone = completed.has('quarantine');
    actions.push({
      key: 'quarantine',
      label: quarantineDone ? 'Quarantined' : 'Quarantine file',
      icon: quarantineDone ? <Check size={13} /> : <ShieldAlert size={13} />,
      variant: quarantineDone ? 'cyan' : 'coral',
      pending: quarantine.isPending,
      disabled: isPending || quarantineDone,
      onClick: () => {
        quarantine.mutate({ id }, {
          onSuccess: () => {
            markCompleted('quarantine');
            toast.success('File quarantined');
          },
          onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to quarantine'),
        });
      },
    });

    return actions;
  };

  return (
    <div className="mt-3 space-y-3">
      <Button
        variant="outline"
        size="sm"
        onClick={handleExplain}
        disabled={explainMutation.isPending}
        pulse={explainMutation.isPending}
      >
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
        <ExplainerError message={explainMutation.error instanceof Error ? explainMutation.error.message : 'Local explanation failed'} />
      )}
    </div>
  );
}

/**
 * Render an explainer failure. When the failure is the opt-in/disabled state
 * (rather than a genuine error) show HOW to turn it on — the explainer is
 * off by default and the bare "disabled" message left users with a dead-end.
 */
function ExplainerError({ message }: { message: string }) {
  const lower = message.toLowerCase();
  const isOptIn = lower.includes('disabled') || lower.includes('not cached') || lower.includes('not enabled');

  if (!isOptIn) {
    return (
      <div className="rounded-lg border border-[var(--sc-coral)]/30 bg-[var(--sc-coral)]/10 p-3 text-sm text-[var(--sc-coral)]">
        {message}
      </div>
    );
  }

  return (
    <div className="space-y-2 rounded-lg border border-[var(--sc-border)] bg-[var(--sc-surface)]/40 p-3 text-sm text-[var(--sc-text-secondary)]">
      <p className="font-medium text-[var(--sc-text-primary)]">{message}</p>
      <p>The Local AI Explainer is opt-in. Enable it from a terminal:</p>
      <pre className="overflow-x-auto rounded bg-black/30 p-2 text-xs text-[var(--sc-text-primary)]">shieldcortex review-copilot enable --accept-download</pre>
      <p className="text-xs text-[var(--sc-text-muted)]">
        Runs a small local model (Qwen2.5-0.5B) on this machine — nothing leaves your device. Requires a Pro licence.
      </p>
    </div>
  );
}
