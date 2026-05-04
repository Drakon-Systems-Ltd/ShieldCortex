'use client';

import { useState } from 'react';
import { Brain, Cloud, ShieldAlert, SlidersHorizontal } from 'lucide-react';
import { useDashboardStore } from '@/lib/store';
import { PipelineStatus } from './PipelineStatus';
import { QuarantinePreview } from './QuarantinePreview';
import { ThreatTimeline } from './ThreatTimeline';
import { DefenceStatsCard } from './DefenceStatsCard';
import HealthScore from '../health/HealthScore';
import { CloudUpsellCard } from './CloudUpsellCard';
import { CloudSyncStatus } from './CloudSyncStatus';
import { SkillScannerCard } from './SkillScannerCard';
import { IronDomeCard } from './IronDomeCard';
import { OpenClawMemoryPanel } from './OpenClawMemoryPanel';
import { LicenseStatusCard } from './LicenseStatusCard';
import { CustomFirewallRulesPanel } from './CustomFirewallRulesPanel';
import { WeeklyRollupCard } from './WeeklyRollupCard';

export function ShieldOverview() {
  const [timeRange, setTimeRange] = useState<'24h' | '7d' | '30d'>('24h');
  const setViewMode = useDashboardStore((state) => state.setViewMode);

  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mx-auto max-w-7xl space-y-6">
        <section className="rounded-2xl border border-[var(--sc-border)] bg-gradient-to-br from-[var(--sc-bg-deep)] via-[var(--sc-bg-surface)] to-cyan-950/15 p-6">
          <div className="flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
            <div className="max-w-3xl">
              <div className="inline-flex items-center gap-2 rounded-full border border-[var(--sc-cyan)]/20 bg-[var(--sc-cyan)]/10 px-3 py-1 text-xs uppercase tracking-[0.18em] text-[var(--sc-cyan)]">
                <ShieldAlert size={12} />
                Defence workspace
              </div>
              <h2 className="mt-4 text-3xl font-semibold text-[var(--sc-text-primary)]">See what is being blocked, what needs review, and what needs tuning.</h2>
              <p className="mt-2 text-sm leading-6 text-[var(--sc-text-secondary)]">
                Shield should help you answer three questions quickly: what is happening now, what needs a decision, and where should policy change next.
              </p>
            </div>
            <div className="flex gap-1 self-start rounded-lg bg-[var(--sc-bg-elevated)] p-0.5">
              {(['24h', '7d', '30d'] as const).map((range) => (
                <button
                  key={range}
                  onClick={() => setTimeRange(range)}
                  className={`px-3 py-1 text-xs rounded-md transition-colors ${
                    timeRange === range
                      ? 'bg-[var(--sc-cyan)] text-[var(--sc-text-primary)]'
                      : 'text-[var(--sc-text-secondary)] hover:text-[var(--sc-text-primary)]'
                  }`}
                >
                  {range}
                </button>
              ))}
            </div>
          </div>
        </section>

        {/* Weekly story — the "you got value" moment */}
        <WeeklyRollupCard />

        <section className="grid grid-cols-1 gap-6 xl:grid-cols-[1.05fr_0.95fr]">
          <div className="space-y-4">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">
                <ShieldAlert size={12} />
                Act Now
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <button
                  onClick={() => setViewMode('quarantine')}
                  className="rounded-full border border-[var(--sc-amber)]/20 bg-[var(--sc-amber)]/10 px-3 py-1 text-xs font-medium text-[var(--sc-amber)] transition-colors hover:bg-[var(--sc-amber)]/15"
                >
                  Review quarantine
                </button>
                <button
                  onClick={() => setViewMode('audit')}
                  className="rounded-full border border-[var(--sc-border)] bg-[var(--sc-bg-surface)] px-3 py-1 text-xs font-medium text-[var(--sc-text-primary)] transition-colors hover:border-[var(--sc-cyan)]/30 hover:text-[var(--sc-text-primary)]"
                >
                  Open audit
                </button>
              </div>
            </div>
            <div className="grid grid-cols-1 gap-4">
              <QuarantinePreview />
              <ThreatTimeline timeRange={timeRange} />
            </div>
          </div>

          <div className="space-y-4">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">
                <Cloud size={12} />
                System Status
              </div>
              <button
                onClick={() => setViewMode('cloud')}
                className="rounded-full border border-[var(--sc-border)] bg-[var(--sc-bg-surface)] px-3 py-1 text-xs font-medium text-[var(--sc-text-primary)] transition-colors hover:border-[var(--sc-cyan)]/30 hover:text-[var(--sc-text-primary)]"
              >
                Open cloud
              </button>
            </div>
            <div className="grid grid-cols-1 gap-4">
              <CloudSyncStatus />
              <LicenseStatusCard />
            </div>
          </div>
        </section>

        <section className="grid grid-cols-1 gap-6 xl:grid-cols-[1.05fr_0.95fr]">
          <div className="space-y-4">
            <div className="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">
              <SlidersHorizontal size={12} />
              Tune Defence
            </div>
            <div className="grid grid-cols-1 gap-4">
              <PipelineStatus timeRange={timeRange} />
              <DefenceStatsCard timeRange={timeRange} />
            </div>
          </div>

          <div className="space-y-4">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">
                <Brain size={12} />
                Memory Pressure
              </div>
              <button
                onClick={() => setViewMode('brain')}
                className="rounded-full border border-[var(--sc-border)] bg-[var(--sc-bg-surface)] px-3 py-1 text-xs font-medium text-[var(--sc-text-primary)] transition-colors hover:border-[var(--sc-cyan)]/30 hover:text-[var(--sc-text-primary)]"
              >
                Open brain
              </button>
            </div>
            <div className="space-y-4">
              <HealthScore />
              <OpenClawMemoryPanel />
            </div>
          </div>
        </section>

        <section className="grid grid-cols-1 gap-6 xl:grid-cols-[1fr_1fr]">
          <details className="group rounded-2xl border border-[var(--sc-border)] bg-[var(--sc-bg-surface)] p-5">
            <summary className="flex cursor-pointer list-none items-center justify-between">
              <div>
                <h3 className="text-lg font-semibold text-[var(--sc-text-primary)]">Advanced review</h3>
                <p className="mt-1 text-sm text-[var(--sc-text-secondary)]">Use these when you are inspecting instructions, hardening policies, or debugging low-level behaviour.</p>
              </div>
              <span className="text-xs text-[var(--sc-text-secondary)] group-open:text-[var(--sc-cyan)]">Expand</span>
            </summary>
            <div className="mt-4 space-y-4">
              <SkillScannerCard />
              <IronDomeCard />
            </div>
          </details>

          <details className="group rounded-2xl border border-[var(--sc-border)] bg-[var(--sc-bg-surface)] p-5">
            <summary className="flex cursor-pointer list-none items-center justify-between">
              <div>
                <h3 className="text-lg font-semibold text-[var(--sc-text-primary)]">Policy controls</h3>
                <p className="mt-1 text-sm text-[var(--sc-text-secondary)]">Custom firewall rules are powerful, but they are not the first thing most operators need every day.</p>
              </div>
              <span className="text-xs text-[var(--sc-text-secondary)] group-open:text-[var(--sc-cyan)]">Expand</span>
            </summary>
            <div className="mt-4">
              <CustomFirewallRulesPanel />
            </div>
          </details>
        </section>

        <div>
          {/* Cloud upsell — hidden when already configured */}
          <CloudUpsellCard />
        </div>
      </div>
    </div>
  );
}
