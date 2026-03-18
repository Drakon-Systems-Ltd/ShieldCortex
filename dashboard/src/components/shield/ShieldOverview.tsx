'use client';

import { useState } from 'react';
import { Brain, Cloud, ShieldAlert, SlidersHorizontal } from 'lucide-react';
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

export function ShieldOverview() {
  const [timeRange, setTimeRange] = useState<'24h' | '7d' | '30d'>('24h');

  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mx-auto max-w-7xl space-y-6">
        <section className="rounded-2xl border border-slate-800 bg-gradient-to-br from-slate-950 via-slate-900 to-cyan-950/15 p-6">
          <div className="flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
            <div className="max-w-3xl">
              <div className="inline-flex items-center gap-2 rounded-full border border-cyan-500/20 bg-cyan-500/10 px-3 py-1 text-xs uppercase tracking-[0.18em] text-cyan-300">
                <ShieldAlert size={12} />
                Defence workspace
              </div>
              <h2 className="mt-4 text-3xl font-semibold text-white">See what is being blocked, what needs review, and what needs tuning.</h2>
              <p className="mt-2 text-sm leading-6 text-slate-400">
                Shield should help you answer three questions quickly: what is happening now, what needs a decision, and where should policy change next.
              </p>
            </div>
            <div className="flex gap-1 self-start rounded-lg bg-slate-800 p-0.5">
              {(['24h', '7d', '30d'] as const).map((range) => (
                <button
                  key={range}
                  onClick={() => setTimeRange(range)}
                  className={`px-3 py-1 text-xs rounded-md transition-colors ${
                    timeRange === range
                      ? 'bg-cyan-600 text-white'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  {range}
                </button>
              ))}
            </div>
          </div>
        </section>

        <section className="grid grid-cols-1 gap-6 xl:grid-cols-[1.05fr_0.95fr]">
          <div className="space-y-4">
            <div className="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-slate-500">
              <ShieldAlert size={12} />
              Act Now
            </div>
            <div className="grid grid-cols-1 gap-4">
              <QuarantinePreview />
              <ThreatTimeline timeRange={timeRange} />
            </div>
          </div>

          <div className="space-y-4">
            <div className="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-slate-500">
              <Cloud size={12} />
              System Status
            </div>
            <div className="grid grid-cols-1 gap-4">
              <CloudSyncStatus />
              <LicenseStatusCard />
            </div>
          </div>
        </section>

        <section className="grid grid-cols-1 gap-6 xl:grid-cols-[1.05fr_0.95fr]">
          <div className="space-y-4">
            <div className="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-slate-500">
              <SlidersHorizontal size={12} />
              Tune Defence
            </div>
            <div className="grid grid-cols-1 gap-4">
              <PipelineStatus timeRange={timeRange} />
              <DefenceStatsCard timeRange={timeRange} />
            </div>
          </div>

          <div className="space-y-4">
            <div className="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-slate-500">
              <Brain size={12} />
              Memory Pressure
            </div>
            <div className="space-y-4">
              <HealthScore />
              <OpenClawMemoryPanel />
            </div>
          </div>
        </section>

        <section className="grid grid-cols-1 gap-6 xl:grid-cols-[1fr_1fr]">
          <details className="group rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
            <summary className="flex cursor-pointer list-none items-center justify-between">
              <div>
                <h3 className="text-lg font-semibold text-white">Advanced review</h3>
                <p className="mt-1 text-sm text-slate-400">Use these when you are inspecting instructions, hardening policies, or debugging low-level behaviour.</p>
              </div>
              <span className="text-xs text-slate-400 group-open:text-cyan-300">Expand</span>
            </summary>
            <div className="mt-4 space-y-4">
              <SkillScannerCard />
              <IronDomeCard />
            </div>
          </details>

          <details className="group rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
            <summary className="flex cursor-pointer list-none items-center justify-between">
              <div>
                <h3 className="text-lg font-semibold text-white">Policy controls</h3>
                <p className="mt-1 text-sm text-slate-400">Custom firewall rules are powerful, but they are not the first thing most operators need every day.</p>
              </div>
              <span className="text-xs text-slate-400 group-open:text-cyan-300">Expand</span>
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
