'use client';

import { useMemo } from 'react';
import { Brain, ShieldAlert, ShieldCheck, Sparkles, TrendingUp } from 'lucide-react';
import { GlassCard } from '@/components/ds/GlassCard';
import { CardError } from '@/components/ds/CardError';
import { useDigest, useDigestTimeline, type TimelineDay } from '@/hooks/useDigest';
import { useDashboardStore } from '@/lib/store';

function pctChange(current: number, previous: number): { label: string; positive: boolean | null } {
  if (previous === 0 && current === 0) return { label: 'no change', positive: null };
  if (previous === 0) return { label: 'first activity', positive: true };
  const pct = Math.round(((current - previous) / previous) * 100);
  if (pct === 0) return { label: 'flat vs prior week', positive: null };
  return {
    label: `${pct > 0 ? '+' : ''}${pct}% vs prior week`,
    positive: pct > 0,
  };
}

function findBiggestDay(timeline: TimelineDay[]): TimelineDay | null {
  if (!timeline.length) return null;
  let best = timeline[0];
  let bestActivity = best.scanned + best.captured + best.recalled;
  for (const day of timeline) {
    const activity = day.scanned + day.captured + day.recalled;
    if (activity > bestActivity) {
      best = day;
      bestActivity = activity;
    }
  }
  return bestActivity > 0 ? best : null;
}

function Sparkline({ values, max }: { values: number[]; max: number }) {
  if (max === 0) {
    return (
      <div className="flex h-8 items-end gap-0.5">
        {values.map((_, i) => (
          <div key={i} className="flex-1 rounded-t bg-[var(--sc-border)]/30" style={{ height: '4%' }} />
        ))}
      </div>
    );
  }
  return (
    <div className="flex h-8 items-end gap-0.5">
      {values.map((v, i) => {
        const pct = Math.max(4, Math.round((v / max) * 100));
        return (
          <div
            key={i}
            className="flex-1 rounded-t bg-[var(--sc-cyan)]/40 transition-all hover:bg-[var(--sc-cyan)]"
            style={{ height: `${pct}%` }}
            title={`${v} on day ${i + 1}`}
          />
        );
      })}
    </div>
  );
}

function formatDayShort(date: string): string {
  // date is YYYY-MM-DD
  const d = new Date(`${date}T00:00:00Z`);
  return d.toLocaleDateString(undefined, { weekday: 'short', month: 'short', day: 'numeric' });
}

/**
 * The "your week with ShieldCortex" rollup. Shows the seven-day story:
 * total volume + change vs prior week, biggest day, top blocked patterns,
 * top captured memories. The headline numbers come from /api/digest?window=7d
 * and the sparkline from /api/digest/timeline?days=7.
 *
 * This is the dashboard equivalent of the Cloudflare weekly email.
 */
export function WeeklyRollupCard() {
  const { projectFilter } = useDashboardStore();
  const { data: digest, isLoading: digestLoading, isError: digestError, refetch: refetchDigest } = useDigest('7d', projectFilter);
  const { data: timeline, isLoading: timelineLoading, isError: timelineError } = useDigestTimeline(7, projectFilter);

  const sparklineValues = useMemo(() => timeline?.timeline.map((d) => d.scanned) ?? [], [timeline]);
  const sparklineMax = useMemo(() => Math.max(0, ...sparklineValues), [sparklineValues]);

  const biggestDay = useMemo(() => (timeline ? findBiggestDay(timeline.timeline) : null), [timeline]);

  if (digestLoading || timelineLoading) {
    return (
      <GlassCard className="p-5">
        <div className="text-xs text-[var(--sc-text-muted)]">Loading weekly rollup…</div>
      </GlassCard>
    );
  }

  if (digestError || timelineError) {
    return (
      <GlassCard className="p-5">
        <CardError inline message="Weekly rollup unavailable" onRetry={() => refetchDigest()} />
      </GlassCard>
    );
  }

  if (!digest) return null;

  const c = digest.current;
  const p = digest.previous;
  const noActivity = c.scanned === 0 && c.memoriesCaptured === 0 && c.memoriesRecalled === 0;

  const scanChange = pctChange(c.scanned, p.scanned);
  const blockChange = pctChange(c.blocked + c.quarantined, p.blocked + p.quarantined);
  const captureChange = pctChange(c.memoriesCaptured, p.memoriesCaptured);
  const recallChange = pctChange(c.memoriesRecalled, p.memoriesRecalled);

  return (
    <GlassCard className="p-5">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h3 className="text-lg font-semibold text-[var(--sc-text-primary)]">Your week with ShieldCortex</h3>
          <p className="mt-0.5 text-xs text-[var(--sc-text-muted)]">
            Last 7 days{projectFilter ? ` · ${projectFilter}` : ' · all projects'}
          </p>
        </div>
        <TrendingUp size={16} className="text-[var(--sc-cyan)]" />
      </div>

      {noActivity ? (
        <div className="mt-4 rounded-lg border border-dashed border-[var(--sc-border)] p-6 text-center">
          <p className="text-sm text-[var(--sc-text-secondary)]">
            No activity in the last 7 days yet. Use Claude Code or your agent and the rollup will fill in.
          </p>
        </div>
      ) : (
        <>
          {/* Headline metrics */}
          <div className="mt-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
            <RollupStat
              icon={<ShieldCheck size={14} />}
              label="Scanned"
              value={c.scanned}
              change={scanChange}
            />
            <RollupStat
              icon={<ShieldAlert size={14} />}
              label="Blocked + Quarantined"
              value={c.blocked + c.quarantined}
              change={blockChange}
              tone="coral"
            />
            <RollupStat
              icon={<Sparkles size={14} />}
              label="Memories captured"
              value={c.memoriesCaptured}
              change={captureChange}
              tone="cyan"
            />
            <RollupStat
              icon={<Brain size={14} />}
              label="Memories recalled"
              value={c.memoriesRecalled}
              change={recallChange}
            />
          </div>

          {/* Sparkline */}
          <div className="mt-5">
            <div className="mb-1 flex items-center justify-between text-[10px] uppercase tracking-[0.14em] text-[var(--sc-text-muted)]">
              <span>Daily scans</span>
              {biggestDay && (
                <span className="text-[var(--sc-cyan)]">
                  Busiest: {formatDayShort(biggestDay.date)} ({(biggestDay.scanned + biggestDay.captured + biggestDay.recalled).toLocaleString()} events)
                </span>
              )}
            </div>
            <Sparkline values={sparklineValues} max={sparklineMax} />
            <div className="mt-1 flex justify-between text-[9px] text-[var(--sc-text-muted)]">
              {timeline?.timeline.map((d, i) => (
                <span key={d.date} className={i % 2 === 0 ? '' : 'opacity-0 sm:opacity-100'}>
                  {new Date(`${d.date}T00:00:00Z`).toLocaleDateString(undefined, { weekday: 'narrow' })}
                </span>
              ))}
            </div>
          </div>

          {/* Top patterns */}
          {digest.topThreatPatterns.length > 0 && (
            <div className="mt-5">
              <div className="mb-2 text-[10px] uppercase tracking-[0.14em] text-[var(--sc-text-muted)]">
                Most blocked patterns this week
              </div>
              <div className="flex flex-wrap gap-2">
                {digest.topThreatPatterns.map((p) => (
                  <span
                    key={p.pattern}
                    className="inline-flex items-center gap-1.5 rounded-full border border-[var(--sc-coral)]/20 bg-[var(--sc-coral)]/10 px-2.5 py-1 text-xs text-[var(--sc-coral)]"
                  >
                    <span className="font-mono">{p.pattern}</span>
                    <span className="text-[10px] opacity-70">{p.count}×</span>
                  </span>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </GlassCard>
  );
}

function RollupStat({
  icon,
  label,
  value,
  change,
  tone,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
  change: { label: string; positive: boolean | null };
  tone?: 'default' | 'coral' | 'cyan';
}) {
  const valueClass =
    tone === 'coral'
      ? 'text-[var(--sc-coral)]'
      : tone === 'cyan'
        ? 'text-[var(--sc-cyan)]'
        : 'text-[var(--sc-text-primary)]';
  const changeClass =
    change.positive === true
      ? 'text-[var(--sc-cyan)]'
      : change.positive === false
        ? 'text-[var(--sc-text-muted)]'
        : 'text-[var(--sc-text-muted)]';
  return (
    <div className="rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/40 p-3">
      <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-[0.12em] text-[var(--sc-text-muted)]">
        <span className={valueClass}>{icon}</span>
        {label}
      </div>
      <div className={`mt-1 font-mono text-2xl font-semibold ${valueClass}`}>{value.toLocaleString()}</div>
      <div className={`mt-0.5 text-[10px] ${changeClass}`}>{change.label}</div>
    </div>
  );
}
