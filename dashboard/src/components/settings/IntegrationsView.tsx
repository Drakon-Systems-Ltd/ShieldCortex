'use client';

import { toast } from 'sonner';
import { GlassCard } from '@/components/ds/GlassCard';
import { ToggleRow } from '@/components/ds/ToggleRow';
import { Skeleton } from '@/components/ds/Skeleton';
import {
  useIntegrationsConfig,
  useUpdateIntegrationsConfig,
  type IntegrationsConfigUpdate,
} from '@/hooks/useIntegrationsConfig';

export function IntegrationsView() {
  const { data, isLoading, error } = useIntegrationsConfig();
  const update = useUpdateIntegrationsConfig();

  const submit = (patch: IntegrationsConfigUpdate, label: string) => {
    update.mutate(patch, {
      onSuccess: () => toast.success(label),
      onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to update toggle'),
    });
  };

  if (isLoading) {
    return (
      <GlassCard className="p-6 space-y-4">
        <Skeleton className="h-16 w-full" />
        <Skeleton className="h-16 w-full" />
      </GlassCard>
    );
  }

  if (error || !data) {
    return (
      <GlassCard className="p-6">
        <p className="text-sm text-[var(--sc-coral)]">
          Failed to load integration toggles: {error instanceof Error ? error.message : 'Unknown error'}
        </p>
      </GlassCard>
    );
  }

  const isPending = update.isPending;
  const pendingKey = isPending ? Object.keys(update.variables ?? {})[0] : undefined;

  return (
    <div className="space-y-4">
      <GlassCard className="p-6">
        <h3 className="text-lg font-semibold text-[var(--sc-text-primary)]">Integrations</h3>
        <p className="mt-1 text-sm text-[var(--sc-text-secondary)]">
          Both toggles are off by default. They were turned off in v4.11.0 after fleet evidence
          showed they hurt fast agent loops; turn them on if you run interactive sessions or want
          richer memory capture.
        </p>

        <div className="mt-5 space-y-3">
          <ToggleRow
            label="OpenClaw Auto-Memory"
            description="Extract memories from OpenClaw LLM output (decisions, fixes, learnings, preferences). Off by default — turn on for interactive sessions, leave off for fast agent loops."
            checked={data.openclawAutoMemory}
            pending={pendingKey === 'openclawAutoMemory'}
            disabled={isPending && pendingKey !== 'openclawAutoMemory'}
            docsUrl="https://shieldcortex.ai/docs/integrations#openclaw-auto-memory"
            onChange={(next) =>
              submit(
                { openclawAutoMemory: next },
                next ? 'OpenClaw auto-memory enabled' : 'OpenClaw auto-memory disabled',
              )
            }
          />

          <ToggleRow
            label="Proactive Recall"
            description="Inject relevant SC memory into every prompt. Adds 200–500ms latency and 100–400 tokens per turn. Net-negative for fast agent loops; useful for deep interactive sessions."
            checked={data.proactiveRecall}
            pending={pendingKey === 'proactiveRecall'}
            disabled={isPending && pendingKey !== 'proactiveRecall'}
            docsUrl="https://shieldcortex.ai/docs/integrations#proactive-recall"
            onChange={(next) =>
              submit(
                { proactiveRecall: next },
                next ? 'Proactive recall enabled' : 'Proactive recall disabled',
              )
            }
          />
        </div>

        <p className="mt-5 text-[11px] text-[var(--sc-text-muted)]">
          You can also toggle these via the CLI: <code className="font-mono">shieldcortex config --openclaw-auto-memory true|false</code> ·{' '}
          <code className="font-mono">shieldcortex config --proactive-recall true|false</code>
        </p>
      </GlassCard>
    </div>
  );
}
