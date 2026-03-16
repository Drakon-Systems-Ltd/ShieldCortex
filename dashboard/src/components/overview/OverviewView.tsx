'use client';

import { useCallback, useMemo } from 'react';
import { AlertTriangle, ArrowRight, CheckCircle2, Clock3, Database, FileSearch, GitBranch, Lock, Shield, Sparkles } from 'lucide-react';
import { useDashboardStore } from '@/lib/store';
import { TIER_BG, TIER_LABELS, TIER_COLOURS, type GatedFeature } from '@/lib/license';
import type { LicenseStatus } from '@/hooks/useLicense';
import { useLicenseStatus } from '@/hooks/useLicense';
import { useAuditStats, useQuarantine } from '@/hooks/useDefence';
import { useContradictions, useQuality } from '@/hooks/useMemories';
import type { MemoryStats } from '@/types/memory';
import { KnowledgeMapPanel } from '@/components/insights/KnowledgeMapPanel';
import { QualityPanel } from '@/components/insights/QualityPanel';

interface OverviewViewProps {
  stats?: MemoryStats;
  selectedProject?: string | null;
}

type ViewMode = ReturnType<typeof useDashboardStore.getState>['viewMode'];

interface ActionCard {
  title: string;
  detail: string;
  tone: 'critical' | 'warning' | 'healthy';
  cta: string;
  onClick: () => void;
}

interface WorkflowCard {
  feature?: GatedFeature;
  title: string;
  detail: string;
  cta: string;
  target: ViewMode;
}

function StatCard({
  label,
  value,
  detail,
  tone = 'default',
}: {
  label: string;
  value: string;
  detail: string;
  tone?: 'default' | 'danger' | 'warning' | 'success';
}) {
  const toneClass =
    tone === 'danger'
      ? 'border-red-500/30 bg-red-500/5'
      : tone === 'warning'
        ? 'border-amber-500/30 bg-amber-500/5'
        : tone === 'success'
          ? 'border-emerald-500/30 bg-emerald-500/5'
          : 'border-slate-800 bg-slate-900/70';

  return (
    <div className={`rounded-xl border p-4 ${toneClass}`}>
      <div className="text-xs uppercase tracking-[0.18em] text-slate-500">{label}</div>
      <div className="mt-2 text-2xl font-semibold text-white">{value}</div>
      <div className="mt-1 text-sm text-slate-400">{detail}</div>
    </div>
  );
}

function ActionRow({ action }: { action: ActionCard }) {
  const toneClass =
    action.tone === 'critical'
      ? 'border-red-500/30 bg-red-500/8'
      : action.tone === 'warning'
        ? 'border-amber-500/30 bg-amber-500/8'
        : 'border-emerald-500/30 bg-emerald-500/8';

  const icon =
    action.tone === 'critical'
      ? <AlertTriangle size={16} className="text-red-400 shrink-0" />
      : action.tone === 'warning'
        ? <Clock3 size={16} className="text-amber-400 shrink-0" />
        : <CheckCircle2 size={16} className="text-emerald-400 shrink-0" />;

  return (
    <button
      onClick={action.onClick}
      className={`w-full rounded-xl border p-4 text-left transition-colors hover:border-slate-500/60 hover:bg-slate-800/60 ${toneClass}`}
    >
      <div className="flex items-start gap-3">
        {icon}
        <div className="flex-1">
          <div className="text-sm font-medium text-white">{action.title}</div>
          <div className="mt-1 text-sm text-slate-400">{action.detail}</div>
          <div className="mt-3 inline-flex items-center gap-1 text-xs font-medium text-cyan-300">
            {action.cta}
            <ArrowRight size={12} />
          </div>
        </div>
      </div>
    </button>
  );
}

function WorkflowCard({ card, license, onOpen }: { card: WorkflowCard; license?: LicenseStatus; onOpen: (target: ViewMode) => void }) {
  const featureInfo = card.feature ? license?.features.find((item) => item.feature === card.feature) : null;
  const locked = featureInfo ? !featureInfo.enabled : false;
  const requiredTier = featureInfo?.requiredTier ?? 'pro';

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-sm font-medium text-white">{card.title}</div>
          <div className="mt-1 text-sm text-slate-400">{card.detail}</div>
        </div>
        {locked ? (
          <span className={`inline-flex items-center gap-1 rounded-full px-2 py-1 text-[10px] font-semibold ${TIER_BG[requiredTier]} ${TIER_COLOURS[requiredTier]}`}>
            <Lock size={10} />
            {TIER_LABELS[requiredTier]}
          </span>
        ) : (
          <span className="rounded-full bg-emerald-500/10 px-2 py-1 text-[10px] font-semibold text-emerald-300">
            Ready
          </span>
        )}
      </div>
      <div className="mt-4 flex items-center justify-between">
        <button
          onClick={() => onOpen(card.target)}
          className="inline-flex items-center gap-1 rounded-lg border border-slate-700 px-3 py-2 text-xs font-medium text-slate-200 transition-colors hover:border-slate-500 hover:bg-slate-800"
        >
          {locked ? `See ${TIER_LABELS[requiredTier]} workflow` : card.cta}
          <ArrowRight size={12} />
        </button>
        {locked && (
          <a
            href="https://shieldcortex.ai/pricing"
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-cyan-300 hover:text-cyan-200"
          >
            Upgrade
          </a>
        )}
      </div>
    </div>
  );
}

export function OverviewView({ stats, selectedProject }: OverviewViewProps) {
  const {
    setViewMode,
    setCategoryFilter,
    setTypeFilter,
    setSelectedMemory,
    setReviewFocus,
  } = useDashboardStore();
  const { data: auditStats } = useAuditStats('24h', selectedProject || undefined);
  const { data: quarantineData } = useQuarantine('pending', 10, selectedProject || undefined);
  const { data: quality } = useQuality(selectedProject || undefined);
  const { data: contradictionsData } = useContradictions(selectedProject || undefined);
  const { data: license } = useLicenseStatus();

  const totalMemories = stats?.total ?? 0;
  const healthyCount = stats?.decayDistribution?.healthy ?? 0;
  const fadingCount = stats?.decayDistribution?.fading ?? 0;
  const criticalCount = stats?.decayDistribution?.critical ?? 0;
  const healthPercent = stats?.decayDistribution
    ? Math.round((healthyCount / Math.max(1, totalMemories)) * 100)
    : null;
  const contradictionCount = contradictionsData?.count ?? contradictionsData?.contradictions.length ?? 0;
  const pendingQuarantine = quarantineData?.total ?? 0;
  const blockedCount = auditStats?.blockedCount ?? 0;
  const duplicateCount = quality?.duplicates.count ?? 0;
  const staleCount = quality?.stale.count ?? 0;
  const neverAccessedCount = quality?.neverAccessed.count ?? 0;

  const thinCategories = useMemo(
    () =>
      Object.entries(stats?.byCategory ?? {})
        .filter(([, count]) => count < 3)
        .sort((a, b) => a[1] - b[1]),
    [stats?.byCategory],
  );

  const openView = useCallback((target: ViewMode) => {
    setSelectedMemory(null);
    setViewMode(target);
  }, [setSelectedMemory, setViewMode]);

  const openReview = useCallback((focus: 'lowTrust' | 'noisyAutoExtracted' | 'stale' | 'neverUsed' | 'projectless' | 'duplicates' | 'contradictions') => {
    setSelectedMemory(null);
    setReviewFocus(focus);
    setViewMode('review');
  }, [setReviewFocus, setSelectedMemory, setViewMode]);

  const openMemories = useCallback((filters?: { category?: string | null; type?: string | null }) => {
    setCategoryFilter(filters?.category ?? null);
    setTypeFilter(filters?.type ?? null);
    setSelectedMemory(null);
    setViewMode('memories');
  }, [setCategoryFilter, setSelectedMemory, setTypeFilter, setViewMode]);

  const urgentActions = useMemo<ActionCard[]>(() => {
    const actions: ActionCard[] = [];

    if (pendingQuarantine > 0) {
      actions.push({
        title: `${pendingQuarantine} item${pendingQuarantine === 1 ? '' : 's'} waiting in quarantine`,
        detail: 'Review blocked or quarantined writes before they pile up into silent operator debt.',
        tone: pendingQuarantine > 10 ? 'critical' : 'warning',
        cta: 'Open review queue',
        onClick: () => {
          setReviewFocus(null);
          openView('quarantine');
        },
      });
    }

    if (contradictionCount > 0) {
      actions.push({
        title: `${contradictionCount} contradiction${contradictionCount === 1 ? '' : 's'} in memory`,
        detail: 'Conflicting facts reduce recall trust and are worth resolving before they become reinforced.',
        tone: contradictionCount > 5 ? 'critical' : 'warning',
        cta: 'Resolve contradictions',
        onClick: () => openReview('contradictions'),
      });
    }

    if (staleCount > 0 || neverAccessedCount > 0 || duplicateCount > 0) {
      actions.push({
        title: 'Memory cleanup work is available',
        detail: `${staleCount} stale, ${duplicateCount} duplicate, ${neverAccessedCount} never-accessed memories are reducing signal quality.`,
        tone: staleCount + duplicateCount > 10 ? 'warning' : 'healthy',
        cta: duplicateCount > 0 ? 'Merge duplicates' : staleCount > 0 ? 'Review stale memories' : 'Review unused memories',
        onClick: () => openReview(duplicateCount > 0 ? 'duplicates' : staleCount > 0 ? 'stale' : 'neverUsed'),
      });
    }

    if (thinCategories.length > 0) {
      const [category, count] = thinCategories[0];
      actions.push({
        title: 'Knowledge coverage is thin in at least one category',
        detail: `${category} only has ${count} memor${count === 1 ? 'y' : 'ies'} right now, which makes recall brittle in that area.`,
        tone: 'warning',
        cta: 'Browse category coverage',
        onClick: () => openMemories({ category }),
      });
    }

    if (actions.length === 0) {
      actions.push({
        title: 'No urgent trust issues right now',
        detail: 'Memory health, quarantine, and contradiction signals all look stable. This is a good time to explore the graph or recent audit activity.',
        tone: 'healthy',
        cta: 'Open graph view',
        onClick: () => openView('graph'),
      });
    }

    return actions.slice(0, 4);
  }, [pendingQuarantine, contradictionCount, staleCount, neverAccessedCount, duplicateCount, thinCategories, openMemories, openReview, openView, setReviewFocus]);

  const freeWorkflows = [
    {
      title: 'Debug recall behavior',
      detail: 'Run a query, inspect ranking factors, and compare expected memories against the returned set.',
      cta: 'Open Recall',
      target: 'recall' as const,
    },
    {
      title: 'Clean low-signal memory',
      detail: 'Find stale, contradictory, low-trust, and never-used memories before they degrade recall quality.',
      cta: 'Open Review',
      target: 'review' as const,
    },
    {
      title: 'Explore the knowledge map',
      detail: 'Use the graph to understand entity coverage and jump from concepts back to source memories.',
      cta: 'Open Graph',
      target: 'graph' as const,
    },
  ];

  const proWorkflows: WorkflowCard[] = [
    {
      feature: 'audit_export',
      title: 'Incident export',
      detail: 'Turn audit history into a reviewable export for incidents, customer proof, or compliance evidence.',
      cta: 'Open Audit export',
      target: 'audit',
    },
    {
      feature: 'custom_firewall_rules',
      title: 'Custom defence controls',
      detail: 'Add project-specific allow, block, and quarantine rules instead of relying only on generic patterns.',
      cta: 'Open Security controls',
      target: 'shield',
    },
    {
      feature: 'skill_scanner_deep',
      title: 'Deep skill review',
      detail: 'Move from file-by-file scanning to richer skill analysis when reviewing custom agent instructions.',
      cta: 'Open Skills',
      target: 'skills',
    },
  ];

  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mx-auto max-w-7xl space-y-6">
        <section className="rounded-2xl border border-slate-800 bg-gradient-to-br from-slate-950 via-slate-900 to-cyan-950/20 p-6">
          <div className="flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
            <div className="max-w-3xl">
              <div className="inline-flex items-center gap-2 rounded-full border border-cyan-500/20 bg-cyan-500/10 px-3 py-1 text-xs font-medium text-cyan-300">
                <Shield size={12} />
                Trust Console
              </div>
              <h2 className="mt-4 text-3xl font-semibold text-white">One place to see whether your memory system is actually healthy.</h2>
              <p className="mt-3 text-sm leading-6 text-slate-400">
                {selectedProject
                  ? `Project scope: ${selectedProject}. This view pulls memory quality, threat pressure, review queue, and graph coverage into one operational surface.`
                  : 'Workspace scope: all projects. This view pulls memory quality, threat pressure, review queue, and graph coverage into one operational surface.'}
              </p>
            </div>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:w-[480px]">
              <StatCard
                label="Memory Base"
                value={String(totalMemories)}
                detail={`${stats?.averageSalience ? `${Math.round(stats.averageSalience * 100)}% avg salience` : 'No salience data yet'}`}
              />
              <StatCard
                label="Healthy"
                value={healthPercent === null ? '—' : `${healthPercent}%`}
                detail={`${healthyCount} healthy · ${fadingCount} fading · ${criticalCount} critical`}
                tone={healthPercent !== null && healthPercent < 50 ? 'warning' : 'success'}
              />
              <StatCard
                label="Queue"
                value={String(pendingQuarantine)}
                detail="Pending quarantine review"
                tone={pendingQuarantine > 0 ? 'warning' : 'success'}
              />
              <StatCard
                label="Blocked"
                value={String(blockedCount)}
                detail="Blocked operations in the last 24h"
                tone={blockedCount > 0 ? 'danger' : 'success'}
              />
            </div>
          </div>
        </section>

        <section className="grid grid-cols-1 gap-6 xl:grid-cols-[1.15fr_0.85fr]">
          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-semibold text-white">Urgent actions</h3>
                <p className="mt-1 text-sm text-slate-400">These are the quickest wins for trust, safety, or recall quality.</p>
              </div>
              <span className="rounded-full bg-slate-800 px-2.5 py-1 text-xs text-slate-400">
                {urgentActions.length} active
              </span>
            </div>
            <div className="mt-4 grid grid-cols-1 gap-3">
              {urgentActions.map((action) => (
                <ActionRow key={action.title} action={action} />
              ))}
            </div>
          </div>

          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
            <h3 className="text-lg font-semibold text-white">Operator snapshot</h3>
            <p className="mt-1 text-sm text-slate-400">A compact read of the things that most often turn into recall or trust problems.</p>
            <div className="mt-4 space-y-3">
              <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
                <div className="text-sm font-medium text-white">Memory hygiene</div>
                <div className="mt-2 grid grid-cols-3 gap-3 text-sm">
                  <div>
                    <div className="text-xl font-semibold text-white">{duplicateCount}</div>
                    <div className="text-slate-500">duplicates</div>
                  </div>
                  <div>
                    <div className="text-xl font-semibold text-white">{staleCount}</div>
                    <div className="text-slate-500">stale</div>
                  </div>
                  <div>
                    <div className="text-xl font-semibold text-white">{neverAccessedCount}</div>
                    <div className="text-slate-500">never used</div>
                  </div>
                </div>
              </div>
              <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
                <div className="text-sm font-medium text-white">Knowledge coverage</div>
                <div className="mt-2 text-sm text-slate-400">
                  {thinCategories.length > 0 ? (
                    <>
                      Thin categories:
                      {' '}
                      {thinCategories.slice(0, 3).map(([category, count]) => `${category} (${count})`).join(' · ')}
                    </>
                  ) : (
                    'No obviously thin categories right now.'
                  )}
                </div>
                <button
                  onClick={() => openView('graph')}
                  className="mt-3 inline-flex items-center gap-1 text-xs font-medium text-cyan-300"
                >
                  Open graph coverage
                  <ArrowRight size={12} />
                </button>
              </div>
              <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
                <div className="text-sm font-medium text-white">Free vs Pro value</div>
                <div className="mt-2 text-sm text-slate-400">
                  Free gives visibility and cleanup. Pro adds stronger audit workflows, custom policy controls, and deeper skill review.
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="grid grid-cols-1 gap-6 xl:grid-cols-[1fr_1fr]">
          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-semibold text-white">Knowledge coverage</h3>
                <p className="mt-1 text-sm text-slate-400">Thin categories are usually where recall feels random or incomplete.</p>
              </div>
              <button
                onClick={() => openView('graph')}
                className="inline-flex items-center gap-1 rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-200 hover:border-slate-500 hover:bg-slate-800"
              >
                <GitBranch size={12} />
                Open graph
              </button>
            </div>
            <div className="mt-4">
              {stats ? (
                <KnowledgeMapPanel
                  stats={stats}
                  onNavigate={({ category }) => openMemories({ category: category ?? null })}
                />
              ) : (
                <div className="rounded-lg bg-slate-950/70 p-4 text-sm text-slate-500">No category data available yet.</div>
              )}
            </div>
          </div>

          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-semibold text-white">Memory cleanup</h3>
                <p className="mt-1 text-sm text-slate-400">The fastest way to improve recall is usually removing ambiguity and dead weight.</p>
              </div>
              <button
                onClick={() => openView('memories')}
                className="inline-flex items-center gap-1 rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-200 hover:border-slate-500 hover:bg-slate-800"
              >
                <Database size={12} />
                Open memories
              </button>
            </div>
            <div className="mt-4">
              <QualityPanel project={selectedProject || undefined} />
            </div>
          </div>
        </section>

        <section className="grid grid-cols-1 gap-6 xl:grid-cols-[0.9fr_1.1fr]">
          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
            <div className="flex items-center gap-2">
              <Sparkles size={16} className="text-cyan-400" />
              <h3 className="text-lg font-semibold text-white">Free workflows</h3>
            </div>
            <p className="mt-1 text-sm text-slate-400">These are the core jobs the free dashboard should do well every day.</p>
            <div className="mt-4 space-y-3">
              {freeWorkflows.map((workflow) => (
                <div key={workflow.title} className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
                  <div className="text-sm font-medium text-white">{workflow.title}</div>
                  <div className="mt-1 text-sm text-slate-400">{workflow.detail}</div>
                  <button
                    onClick={() => openView(workflow.target)}
                    className="mt-3 inline-flex items-center gap-1 text-xs font-medium text-cyan-300"
                  >
                    {workflow.cta}
                    <ArrowRight size={12} />
                  </button>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileSearch size={16} className="text-violet-400" />
                <h3 className="text-lg font-semibold text-white">Pro workflows</h3>
              </div>
              <span className={`rounded-full px-2.5 py-1 text-xs font-medium ${TIER_BG[license?.tier ?? 'free']} ${TIER_COLOURS[license?.tier ?? 'free']}`}>
                {TIER_LABELS[license?.tier ?? 'free']}
              </span>
            </div>
            <p className="mt-1 text-sm text-slate-400">Paid value should save operator time, not just expose more settings.</p>
            <div className="mt-4 grid grid-cols-1 gap-3 lg:grid-cols-3">
              {proWorkflows.map((workflow) => (
                <WorkflowCard key={workflow.title} card={workflow} license={license} onOpen={openView} />
              ))}
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
