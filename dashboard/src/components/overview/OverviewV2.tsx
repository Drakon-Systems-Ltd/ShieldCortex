'use client';

import { useCallback, useMemo, useState } from 'react';
import Link from 'next/link';
import dynamic from 'next/dynamic';
import { ArrowRight, Activity, Database, HeartPulse, Shield } from 'lucide-react';
import { PageHeader } from '@/components/ds/PageHeader';
import { StatusPill, type StatusPillState } from '@/components/ds/StatusPill';
import { CopyableCommand } from '@/components/ds/EmptyState';
import { FirstRunGuide } from '@/components/overview/FirstRunGuide';
import { CloudUpsellCard } from '@/components/shield/CloudUpsellCard';
import { useWebSocketEvent, useWebSocketStatus } from '@/components/MemoryWebSocketProvider';
import { useContradictions, useStats, useCheckForUpdates } from '@/hooks/useMemories';
import { useReviewQueue } from '@/hooks/useReviewQueue';
import { useAuditStats, useQuarantine, useDefenceConfig } from '@/hooks/useDefence';
import { useIronDomeStatus, useControlStatus } from '@/hooks/useIronDome';
import { useHealthScore } from '@/hooks/useHealthScore';
import { useLicenseStatus } from '@/hooks/useLicense';
import { useXRayStatus } from '@/hooks/useXRay';
import { useDashboardStore } from '@/lib/store';
import {
  combineStatus,
  countText,
  firewallPill,
  guardPill,
  operationsPill,
  queryStatus,
  scanningPill,
} from '@/lib/query-status';
import { cn } from '@/lib/utils';

const MemoryGraph = dynamic(() => import('@/components/graph/MemoryGraph'), {
  ssr: false,
  loading: () => (
    <div className="flex h-[240px] items-center justify-center text-sm text-[var(--sc-text-muted)]">
      Loading graph preview…
    </div>
  ),
});

interface FeedEvent {
  key: number;
  ts: string;
  group: 'memory' | 'defence' | 'system';
  label: string;
  detail?: string;
}

const FEED_FILTERS = ['all', 'memory', 'defence', 'system'] as const;

/**
 * WS event type → feed group + human label. Types come from the server's
 * MemoryEventType union (src/api/events.ts); decay/worker ticks are noise,
 * not activity, and are deliberately absent.
 */
const FEED_LABELS: Record<string, { group: FeedEvent['group']; label: string }> = {
  memory_created: { group: 'memory', label: 'Memory created' },
  memory_updated: { group: 'memory', label: 'Memory updated' },
  memory_deleted: { group: 'memory', label: 'Memory removed' },
  memory_accessed: { group: 'memory', label: 'Memory recalled' },
  link_discovered: { group: 'memory', label: 'Link discovered' },
  consolidation_complete: { group: 'memory', label: 'Consolidation complete' },
  defence_event: { group: 'defence', label: 'Defence event' },
  xray_detection: { group: 'defence', label: 'X-Ray detection' },
  kill_switch_activated: { group: 'defence', label: 'Emergency stop engaged' },
  kill_switch_deactivated: { group: 'defence', label: 'Emergency stop cleared' },
  update_started: { group: 'system', label: 'Upgrade started' },
  update_complete: { group: 'system', label: 'Upgrade complete' },
  update_failed: { group: 'system', label: 'Upgrade failed' },
  server_restarting: { group: 'system', label: 'API briefly unavailable' },
  session_started: { group: 'system', label: 'Session started' },
  session_ended: { group: 'system', label: 'Session ended' },
};

let feedKey = 0;

function toFeedEvent(msg: unknown): FeedEvent | null {
  const e = msg as { type?: string; timestamp?: string; data?: Record<string, unknown> };
  if (!e?.type) return null;
  const known = FEED_LABELS[e.type];
  if (!known) return null;
  const detail =
    typeof e.data?.title === 'string' ? (e.data.title as string)
    : typeof e.data?.action === 'string' ? (e.data.action as string)
    : typeof e.data?.file === 'string' ? (e.data.file as string)
    : undefined;
  return {
    key: ++feedKey,
    ts: e.timestamp ?? new Date().toISOString(),
    group: known.group,
    label: known.label,
    detail,
  };
}

export function OverviewV2() {
  const project = useDashboardStore((s) => s.projectFilter);

  const stats = useStats(project ?? undefined);
  const review = useReviewQueue(project);
  const contradictions = useContradictions();
  const audit7d = useAuditStats('7d', project ?? undefined);
  const quarantine = useQuarantine('pending', 1, project ?? undefined);
  const ironDome = useIronDomeStatus();
  const control = useControlStatus();
  const defence = useDefenceConfig();
  const health = useHealthScore();
  const license = useLicenseStatus();
  const xray = useXRayStatus();
  const update = useCheckForUpdates(true);
  const { isConnected } = useWebSocketStatus();

  // ── Every row/count/pill derives from query status via one helper
  //    (§13.4, review item 5): pending / unavailable / stale / confirmed. ──
  const st = {
    stats: queryStatus(stats),
    review: queryStatus(review),
    contradictions: queryStatus(contradictions),
    audit: queryStatus(audit7d),
    quarantine: queryStatus(quarantine),
    ironDome: queryStatus(ironDome),
    control: queryStatus(control),
    defence: queryStatus(defence),
    health: queryStatus(health),
    license: queryStatus(license),
    xray: queryStatus(xray),
    update: queryStatus(update),
  };
  const guard = guardPill(st.ironDome, ironDome.data?.enabled);
  const scanning = scanningPill(st.ironDome, ironDome.data?.enabled);
  const operations = operationsPill(st.control, control.data);
  const firewall = firewallPill(st.defence, defence.data);

  // ── Needs-you list ───────────────────────────────────────
  const needsYou = useMemo(() => {
    const items: { label: string; detail: string; href: string }[] = [];
    const unavailable: string[] = [];
    const pending: string[] = [];
    const stale: string[] = [];
    const note = (name: string, status: ReturnType<typeof queryStatus>) => {
      if (status === 'unavailable') unavailable.push(name);
      else if (status === 'pending') pending.push(name);
      else if (status === 'stale') stale.push(name);
    };

    note('quarantine', st.quarantine);
    if (st.quarantine !== 'unavailable' && (quarantine.data?.total ?? 0) > 0) {
      items.push({
        label: `${quarantine.data!.total} quarantined item${quarantine.data!.total === 1 ? '' : 's'} pending`,
        detail: 'Approve or reject blocked writes and file findings.',
        href: '/protection?tab=quarantine',
      });
    }

    note('contradictions', st.contradictions);
    if (st.contradictions !== 'unavailable' && (contradictions.data?.count ?? 0) > 0) {
      items.push({
        label: `${contradictions.data!.count} contradiction${contradictions.data!.count === 1 ? '' : 's'} detected`,
        detail: 'Conflicting facts reduce recall trust.',
        href: '/memory?tab=review',
      });
    }

    note('review queue', st.review);
    if (st.review !== 'unavailable') {
      const dupes = review.data?.summary?.duplicates ?? 0;
      const stale = review.data?.summary?.stale ?? 0;
      if (dupes + stale > 0) {
        items.push({
          label: 'Review queue has cleanup work',
          detail: `${stale.toLocaleString()} stale, ${dupes.toLocaleString()} duplicate.`,
          href: '/memory?tab=review',
        });
      }
    }

    // Licence / update-check failures are reported as unavailable too (review
    // item 5) — a failed check is not "nothing to do".
    note('licence', st.license);
    const trial = license.data?.trial as { daysRemaining?: number } | null | undefined;
    if (trial?.daysRemaining !== undefined && trial.daysRemaining <= 7) {
      items.push({
        label: `Trial ends in ${trial.daysRemaining} day${trial.daysRemaining === 1 ? '' : 's'}`,
        detail: 'Features fall back to Free when it lapses.',
        href: '/settings?tab=licence',
      });
    }

    note('update check', st.update);
    if (update.data?.updateAvailable) {
      items.push({
        label: `Newer version available — v${update.data.latestVersion}`,
        detail: `Running v${update.data.runningVersion ?? update.data.currentVersion}.`,
        href: '/settings?tab=admin',
      });
    }

    return { items, unavailable, pending, stale };
  }, [st.quarantine, st.contradictions, st.review, st.license, st.update, quarantine.data, contradictions.data, review.data, license.data, update.data]);

  // ── Activity feed (WS-fed, last 50, filterable) ──────────
  const [feed, setFeed] = useState<FeedEvent[]>([]);
  const [feedFilter, setFeedFilter] = useState<(typeof FEED_FILTERS)[number]>('all');
  useWebSocketEvent(
    useCallback((msg: unknown) => {
      const ev = toFeedEvent(msg);
      if (ev) setFeed((prev) => [ev, ...prev].slice(0, 50));
    }, []),
  );
  const visibleFeed = feedFilter === 'all' ? feed : feed.filter((e) => e.group === feedFilter);

  // ── Health tile: three weakest components ────────────────
  const weakest = useMemo(() => {
    if (!health.data) return [];
    return Object.values(health.data.components).sort((a, b) => a.score - b.score).slice(0, 3);
  }, [health.data]);

  // The first-run guide only shows once ALL three of its inputs are confirmed
  // (never on a failed fetch defaulted to 0 — review item 5).
  const firstRunStatus = combineStatus(st.stats, st.xray, st.audit);

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-7xl space-y-5 p-6">
        <PageHeader
          eyebrow="ShieldCortex"
          title="Overview"
          subtitle="Protection, memory and health at a glance — every number is live or marked unavailable."
        />

        <FirstRunGuide
          ready={firstRunStatus === 'confirmed'}
          memoryCount={stats.data?.total ?? 0}
          scanCount={xray.data?.summary?.scans ?? 0}
          blockedCount={audit7d.data?.blockedCount ?? 0}
        />

        {/* ── Four status tiles ── */}
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
          <Tile icon={<Shield size={15} aria-hidden />} title="Protection" href="/protection">
            <TileRow label="Action Guard" pill={guard.state} pillText={guard.text}
              onRetry={ironDome.isError ? () => ironDome.refetch() : undefined} />
            {guard.state === 'off' && <CopyableCommand command="shieldcortex iron-dome activate" />}
            <TileRow label="Conversation scanning" pill={scanning.state} pillText={scanning.text}
              onRetry={ironDome.isError ? () => ironDome.refetch() : undefined} />
            <TileRow label="Operations" pill={operations.state} pillText={operations.text}
              onRetry={control.isError ? () => control.refetch() : undefined} />
            <TileRow label="Write firewall" pill={firewall.state} pillText={firewall.text}
              onRetry={defence.isError ? () => defence.refetch() : undefined} />
          </Tile>

          <Tile icon={<Database size={15} aria-hidden />} title="Memory" href="/memory">
            <BigNumber value={countText(stats.data?.total, st.stats)} label="stored memories" />
            <div className="grid grid-cols-3 gap-2 text-center text-[11px] text-[var(--sc-text-muted)]">
              <div><div className="text-sm font-semibold tabular-nums text-[var(--sc-text)]">{countText(stats.data?.shortTerm, st.stats)}</div>short-term</div>
              <div><div className="text-sm font-semibold tabular-nums text-[var(--sc-text)]">{countText(stats.data?.longTerm, st.stats)}</div>long-term</div>
              <div><div className="text-sm font-semibold tabular-nums text-[var(--sc-text)]">{countText(contradictions.data?.count, st.contradictions)}</div>contradictions</div>
            </div>
            {st.stats === 'unavailable' && <TileRow label="Stats" pill="unavailable" pillText="unavailable" onRetry={() => stats.refetch()} />}
            {st.stats === 'stale' && <TileRow label="Stats" pill="warn" pillText="stale (refetch failed)" onRetry={() => stats.refetch()} />}
          </Tile>

          <Tile icon={<Activity size={15} aria-hidden />} title="Threats (7d)" href="/protection?tab=audit">
            <div className="grid grid-cols-3 gap-2 text-center text-[11px] text-[var(--sc-text-muted)]">
              <div><div className="text-lg font-semibold tabular-nums text-[var(--sc-danger)]">{countText(audit7d.data?.blockedCount, st.audit)}</div>blocked</div>
              <div><div className="text-lg font-semibold tabular-nums text-[var(--sc-warn)]">{countText(audit7d.data?.quarantinedCount, st.audit)}</div>quarantined</div>
              <div><div className="text-lg font-semibold tabular-nums text-[var(--sc-text)]">{countText(audit7d.data?.allowedCount, st.audit)}</div>allowed</div>
            </div>
            {st.audit === 'unavailable' ? (
              <TileRow label="Audit" pill="unavailable" pillText="unavailable" onRetry={() => audit7d.refetch()} />
            ) : st.audit === 'pending' ? (
              <p className="text-[11px] italic text-[var(--sc-text-muted)]">Checking the audit log…</p>
            ) : (
              <p className="text-[11px] text-[var(--sc-text-muted)]">
                {(audit7d.data?.totalOperations ?? 0) === 0 ? 'No gated operations recorded this week.' : `${audit7d.data!.totalOperations.toLocaleString()} gated operations this week.`}
                {st.audit === 'stale' && <span className="italic text-[var(--sc-warn)]"> Last known — refetch failed.</span>}
              </p>
            )}
          </Tile>

          <Tile icon={<HeartPulse size={15} aria-hidden />} title="Health" href="/memory?tab=review">
            {st.health === 'unavailable' ? (
              <TileRow label="Score" pill="unavailable" pillText="unavailable" onRetry={() => health.refetch()} />
            ) : (
              <>
                <BigNumber value={health.data ? `${health.data.overall}%` : '…'} label="memory health score" />
                {st.health === 'stale' && <TileRow label="Score" pill="warn" pillText="stale (refetch failed)" onRetry={() => health.refetch()} />}
                <ul className="space-y-1 text-[11px] text-[var(--sc-text-muted)]">
                  {weakest.map((c) => (
                    <li key={c.label} className="flex items-center justify-between gap-2">
                      <span className="truncate" title={c.detail}>{c.label}</span>
                      <span className={cn('tabular-nums font-medium', c.score >= 80 ? 'text-[var(--sc-ok)]' : c.score >= 50 ? 'text-[var(--sc-warn)]' : 'text-[var(--sc-danger)]')}>{c.score}</span>
                    </li>
                  ))}
                </ul>
              </>
            )}
          </Tile>
        </div>

        {/* ── Needs you + Activity ── */}
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <section className="rounded-lg border border-[var(--sc-border)] bg-[var(--sc-surface)] p-4 shadow-[var(--sc-shadow-card)]">
            <h3 className="text-sm font-semibold text-[var(--sc-text)]">Needs you</h3>
            <div className="mt-3 space-y-2">
              {needsYou.items.length === 0 && needsYou.pending.length > 0 && (
                <p className="text-sm italic text-[var(--sc-text-muted)]">Checking {needsYou.pending.join(', ')}…</p>
              )}
              {needsYou.items.length === 0 && needsYou.pending.length === 0 && needsYou.unavailable.length === 0 && (
                <p className="text-sm text-[var(--sc-text-muted)]">
                  Nothing pending. All queues are clear.
                  {needsYou.stale.length > 0 && <span className="italic text-[var(--sc-warn)]"> ({needsYou.stale.join(', ')}: last known — refetch failed.)</span>}
                </p>
              )}
              {needsYou.items.map((item) => (
                <Link key={item.label} href={item.href}
                  className="group flex items-start justify-between gap-3 rounded-md border border-[var(--sc-border)] px-3 py-2 transition-colors hover:border-[var(--sc-border-strong)]">
                  <div>
                    <p className="text-sm text-[var(--sc-text)]">{item.label}</p>
                    <p className="text-xs text-[var(--sc-text-muted)]">{item.detail}</p>
                  </div>
                  <ArrowRight size={14} aria-hidden className="mt-1 shrink-0 text-[var(--sc-text-muted)] transition-transform group-hover:translate-x-0.5" />
                </Link>
              ))}
              {needsYou.unavailable.map((src) => (
                <p key={src} className="text-xs italic text-[var(--sc-warn)]">{src} status unavailable — this list may be incomplete.</p>
              ))}
              {needsYou.items.length > 0 && needsYou.stale.map((src) => (
                <p key={`stale-${src}`} className="text-xs italic text-[var(--sc-warn)]">{src}: last known — refetch failed.</p>
              ))}
            </div>
          </section>

          <section className="rounded-lg border border-[var(--sc-border)] bg-[var(--sc-surface)] p-4 shadow-[var(--sc-shadow-card)]">
            <div className="flex items-center justify-between gap-2">
              <h3 className="text-sm font-semibold text-[var(--sc-text)]">Recent activity</h3>
              <div className="flex gap-1">
                {FEED_FILTERS.map((f) => (
                  <button key={f} type="button" aria-pressed={feedFilter === f} onClick={() => setFeedFilter(f)}
                    className={cn('rounded-full border px-2 py-0.5 text-[11px] capitalize',
                      feedFilter === f ? 'border-[var(--sc-primary)] text-[var(--sc-primary)]' : 'border-[var(--sc-border)] text-[var(--sc-text-muted)] hover:border-[var(--sc-border-strong)]')}>
                    {f}
                  </button>
                ))}
              </div>
            </div>
            <div className="mt-3 max-h-64 space-y-1 overflow-y-auto">
              {visibleFeed.length === 0 ? (
                <p className="text-sm text-[var(--sc-text-muted)]">
                  {isConnected
                    ? 'Live events appear here as they happen — nothing yet this session.'
                    : 'Event stream disconnected — activity cannot be shown live.'}
                </p>
              ) : (
                visibleFeed.map((e) => (
                  <div key={e.key} className="flex items-baseline gap-2 text-xs">
                    <span className="shrink-0 tabular-nums text-[var(--sc-text-muted)]">{e.ts.slice(11, 19)}</span>
                    <span className={cn('shrink-0 rounded-full px-1.5 text-[10px]',
                      e.group === 'defence' ? 'bg-[var(--sc-warn-soft)] text-[var(--sc-warn)]' : 'bg-[var(--sc-surface-2)] text-[var(--sc-text-muted)]')}>{e.group}</span>
                    <span className="text-[var(--sc-text)]">{e.label}</span>
                    {e.detail && <span className="truncate text-[var(--sc-text-muted)]">{e.detail}</span>}
                  </div>
                ))
              )}
            </div>
          </section>
        </div>

        {/* ── Graph preview (Map mode, click-through) ── */}
        <section className="rounded-lg border border-[var(--sc-border)] bg-[var(--sc-surface)] p-4 shadow-[var(--sc-shadow-card)]">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-[var(--sc-text)]">Knowledge graph</h3>
            <Link href="/memory?tab=graph" className="flex items-center gap-1 text-xs text-[var(--sc-primary)] hover:underline">
              Open the graph <ArrowRight size={12} aria-hidden />
            </Link>
          </div>
          <div className="mt-3">
            <MemoryGraph preview />
          </div>
        </section>

        <CloudUpsellCard />
      </div>
    </div>
  );
}

function Tile({ icon, title, href, children }: { icon: React.ReactNode; title: string; href: string; children: React.ReactNode }) {
  return (
    <section className="flex flex-col gap-2.5 rounded-lg border border-[var(--sc-border)] bg-[var(--sc-surface)] p-4 shadow-[var(--sc-shadow-card)]">
      <Link href={href} className="flex items-center gap-1.5 text-sm font-semibold text-[var(--sc-text)] hover:text-[var(--sc-primary)]">
        <span className="text-[var(--sc-text-muted)]">{icon}</span>
        {title}
      </Link>
      {children}
    </section>
  );
}

function TileRow({ label, pill, pillText, onRetry }: { label: string; pill: StatusPillState; pillText: string; onRetry?: () => void }) {
  return (
    <div className="flex items-center justify-between gap-2 text-xs text-[var(--sc-text-dim)]">
      <span>{label}</span>
      <span className="flex items-center gap-1.5">
        <StatusPill state={pill}>{pillText}</StatusPill>
        {onRetry && (
          <button type="button" onClick={onRetry} className="text-[11px] text-[var(--sc-primary)] hover:underline">retry</button>
        )}
      </span>
    </div>
  );
}

function BigNumber({ value, label }: { value: string; label: string }) {
  return (
    <div>
      <div className="text-2xl font-semibold tabular-nums text-[var(--sc-text)]">{value}</div>
      <div className="text-[11px] text-[var(--sc-text-muted)]">{label}</div>
    </div>
  );
}
