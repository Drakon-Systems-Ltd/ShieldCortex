'use client';

import { Badge } from '@/components/ds/Badge';
import type { LocalAiExplanation } from '@/hooks/useLocalAiExplainer';

interface LocalAiExplanationPanelProps {
  explanation: LocalAiExplanation;
}

export function LocalAiExplanationPanel({ explanation }: LocalAiExplanationPanelProps) {
  return (
    <div className="rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/70 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant={explanation.synthetic ? 'amber' : 'cyan'}>
          {explanation.synthetic ? 'Fallback' : 'Local AI'}
        </Badge>
        <Badge variant="muted">{Math.round(explanation.confidence * 100)}% confidence</Badge>
      </div>

      <p className="mt-3 text-sm font-semibold text-[var(--sc-text-primary)]">{explanation.summary}</p>
      <p className="mt-1 text-sm leading-6 text-[var(--sc-text-secondary)]">{explanation.whyItMatters}</p>

      {explanation.riskSignals.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {explanation.riskSignals.map((signal) => (
            <span
              key={signal}
              className="rounded bg-[var(--sc-bg-elevated)] px-2 py-1 text-[11px] text-[var(--sc-text-secondary)]"
            >
              {signal}
            </span>
          ))}
        </div>
      )}

      {explanation.evidence.length > 0 && (
        <div className="mt-3 space-y-2">
          {explanation.evidence.map((entry, index) => (
            <div key={`${entry.snippet}-${index}`} className="rounded border border-[var(--sc-border)] bg-[var(--sc-bg-surface)] px-2 py-1.5">
              <div className="text-[10px] uppercase tracking-[0.14em] text-[var(--sc-text-muted)]">{entry.reason}</div>
              <div className="mt-1 break-words text-xs text-[var(--sc-text-primary)]">"{entry.snippet}"</div>
            </div>
          ))}
        </div>
      )}

      {explanation.nextSteps.length > 0 && (
        <div className="mt-3 border-t border-[var(--sc-border)] pt-3">
          <div className="text-[10px] font-semibold uppercase tracking-[0.16em] text-[var(--sc-text-muted)]">Next steps</div>
          <div className="mt-2 space-y-1">
            {explanation.nextSteps.map((step) => (
              <div key={step} className="text-xs leading-5 text-[var(--sc-text-secondary)]">
                {step}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
