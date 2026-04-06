'use client';

import Link from 'next/link';
import { ArrowRight, Bot, Radar, ShieldAlert, Sparkles, TimerReset } from 'lucide-react';
import { useAuditStats, useQuarantine } from '@/hooks/useDefence';
import { useIronDomeStatus } from '@/hooks/useIronDome';
import { useInterceptorEvents } from '@/hooks/useInterceptorEvents';
import { useLicenseStatus } from '@/hooks/useLicense';
import { useXRayActivity, useXRayHistory, useXRayStatus, useXRayWatchSessions } from '@/hooks/useXRay';

function formatDate(value: string | null | undefined): string {
  if (!value) return '—';
  return new Date(value).toLocaleString();
}

const CARD = 'glass-card';
const PILL = 'rounded-full border border-[var(--sc-border)] bg-[var(--sc-surface-interactive)] px-3 py-1 text-xs font-medium text-[var(--sc-text-secondary)]';

export function SupplyChainOverview() {
  const { data: xrayStatus } = useXRayStatus();
  const { data: history } = useXRayHistory();
  const { data: activity } = useXRayActivity(6);
  const { data: watchSessions } = useXRayWatchSessions(4, { state: 'all' });
  const { data: ironDome } = useIronDomeStatus();
  const { data: quarantine } = useQuarantine('pending', 4);
  const { data: auditStats } = useAuditStats('24h');
  const { data: intercepts } = useInterceptorEvents({ limit: 10 });
  const { data: license } = useLicenseStatus();

  const latestScan = history?.entries?.[0];
  const watchRoots = watchSessions?.entries ?? [];
  const pendingItems = quarantine?.items ?? [];
  const recentActivity = activity?.entries ?? [];

  return (
    <div className="min-h-full overflow-y-auto bg-[radial-gradient(circle_at_top_left,_rgba(240,142,94,0.22),_transparent_34%),radial-gradient(circle_at_top_right,_rgba(51,110,108,0.14),_transparent_28%),linear-gradient(180deg,_#f8f2ea_0%,_#f4ede4_38%,_#efe7dc_100%)] text-[var(--sc-text-primary)]">
      <div className="mx-auto flex max-w-7xl flex-col gap-6 px-6 py-8">
        <section className="overflow-hidden rounded-[36px] border border-[var(--sc-border)]/70 bg-[linear-gradient(135deg,#fff7ef_0%,#fff2de_54%,#f6ebdf_100%)] px-8 py-8 shadow-[0_40px_120px_rgba(77,42,20,0.12)]">
          <div className="grid gap-8 lg:grid-cols-[minmax(0,1.2fr)_340px]">
            <div>
              <div className="inline-flex items-center gap-2 rounded-full border border-[var(--sc-coral)] bg-[var(--sc-card-bg)] px-3 py-1 text-xs font-semibold uppercase tracking-[0.18em] text-[var(--sc-coral)]">
                <Sparkles size={12} />
                ShieldCortex Supply Chain
              </div>
              <h1 className="mt-5 max-w-3xl text-4xl font-semibold tracking-[-0.04em] text-[var(--sc-text-primary)] md:text-5xl">
                Scan files, folders, and packages before they become a problem.
              </h1>
              <p className="mt-4 max-w-2xl text-base leading-7 text-[var(--sc-text-secondary)]">
                Start with one clear job: check something suspicious. Keep the serious controls close by, but don&apos;t make them the first thing a human has to decode.
              </p>

              <div className="mt-6 flex flex-wrap gap-3">
                <Link
                  href="/supply-chain/xray"
                  className="inline-flex items-center gap-2 rounded-full bg-[#c85f34] px-5 py-3 text-sm font-semibold text-white shadow-[0_18px_40px_rgba(200,95,52,0.28)] transition-transform hover:-translate-y-0.5 hover:bg-[#b85129]"
                >
                  Scan a file, folder, or package
                  <ArrowRight size={14} />
                </Link>
                <Link href="/protection/quarantine" className={`${PILL} hover:bg-[var(--sc-bg-elevated)]`}>
                  Review quarantine queue
                </Link>
                <Link href="/protection/iron-dome" className={`${PILL} hover:bg-[var(--sc-bg-elevated)]`}>
                  Open Iron Dome
                </Link>
              </div>

              <div className="mt-8 grid gap-4 md:grid-cols-3">
                <div className={`${CARD} p-4`}>
                  <div className="text-xs uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">Recent scans</div>
                  <div className="mt-2 text-3xl font-semibold text-[var(--sc-text-primary)]">{xrayStatus?.summary.scans ?? history?.entries?.length ?? 0}</div>
                  <div className="mt-1 text-sm text-[var(--sc-text-secondary)]">Manual checks you can reopen and inspect.</div>
                </div>
                <div className={`${CARD} p-4`}>
                  <div className="text-xs uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">Active watch roots</div>
                  <div className="mt-2 text-3xl font-semibold text-[var(--sc-cyan)]">{xrayStatus?.summary.activeWatchRoots ?? 0}</div>
                  <div className="mt-1 text-sm text-[var(--sc-text-secondary)]">Background protection currently watching folders.</div>
                </div>
                <div className={`${CARD} p-4`}>
                  <div className="text-xs uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">Quarantine waiting</div>
                  <div className="mt-2 text-3xl font-semibold text-[var(--sc-amber)]">{quarantine?.total ?? 0}</div>
                  <div className="mt-1 text-sm text-[var(--sc-text-secondary)]">Items that still need a human approve or reject decision.</div>
                </div>
              </div>
            </div>

            <div className={`${CARD} p-5`}>
              <div className="text-xs uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">What happens here</div>
              <div className="mt-4 space-y-4">
                <div className="rounded-2xl bg-[var(--sc-bg-elevated)] px-4 py-4">
                  <div className="text-sm font-semibold text-[var(--sc-text-primary)]">1. Scan something</div>
                  <div className="mt-1 text-sm leading-6 text-[var(--sc-text-secondary)]">Paste a local path or package name, then run one clear check.</div>
                </div>
                <div className="rounded-2xl bg-[var(--sc-bg-elevated)] px-4 py-4">
                  <div className="text-sm font-semibold text-[var(--sc-text-primary)]">2. Turn on automatic protection</div>
                  <div className="mt-1 text-sm leading-6 text-[var(--sc-text-secondary)]">Watch roots and preinstall checks keep scanning after you leave the page.</div>
                </div>
                <div className="rounded-2xl bg-[var(--sc-bg-elevated)] px-4 py-4">
                  <div className="text-sm font-semibold text-[var(--sc-text-primary)]">3. Review anything risky</div>
                  <div className="mt-1 text-sm leading-6 text-[var(--sc-text-secondary)]">Quarantine, Iron Dome, approvals, and audit logs stay close by when you actually need them.</div>
                </div>
              </div>
            </div>
          </div>
        </section>

        <div className="grid gap-6 xl:grid-cols-[minmax(0,1.2fr)_minmax(320px,0.8fr)]">
          <section className={`${CARD} p-6`}>
            <div className="flex items-center justify-between gap-3">
              <div>
                <div className="text-xs uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">Automatic Protection</div>
                <h2 className="mt-2 text-2xl font-semibold tracking-[-0.03em] text-[var(--sc-text-primary)]">Background scanning that makes sense</h2>
              </div>
              <Link href="/supply-chain/xray" className={`${PILL} hover:bg-[var(--sc-bg-elevated)]`}>
                Configure in X-Ray
              </Link>
            </div>

            <div className="mt-5 grid gap-4 md:grid-cols-2">
              <div className="rounded-[24px] bg-[#fff5ec] p-5">
                <div className="flex items-center gap-2 text-sm font-semibold text-[var(--sc-text-primary)]">
                  <Radar size={16} className="text-[#c85f34]" />
                  Watch mode
                </div>
                <p className="mt-2 text-sm leading-6 text-[var(--sc-text-secondary)]">
                  {xrayStatus?.summary.activeWatchRoots
                    ? `${xrayStatus.summary.activeWatchRoots} folder${xrayStatus.summary.activeWatchRoots === 1 ? '' : 's'} actively watched right now.`
                    : 'No folder is currently being watched.'}
                </p>
                <div className="mt-3 flex flex-wrap gap-2 text-xs text-[var(--sc-text-secondary)]">
                  <span className={PILL}>{xrayStatus?.summary.activeWatchRoots ?? 0} active</span>
                  <span className={PILL}>{xrayStatus?.summary.staleWatchRoots ?? 0} stale</span>
                  <span className={PILL}>{xrayStatus?.summary.watchSessions ?? 0} recent sessions</span>
                </div>
              </div>

              <div className="rounded-[24px] bg-[#eef6f3] p-5">
                <div className="flex items-center gap-2 text-sm font-semibold text-[var(--sc-text-primary)]">
                  <Bot size={16} className="text-[var(--sc-cyan)]" />
                  Install-time protection
                </div>
                <p className="mt-2 text-sm leading-6 text-[var(--sc-text-secondary)]">
                  Preinstall checks are wired into the same event stream, so risky install scripts show up alongside watch detections and manual scans.
                </p>
                <div className="mt-3 text-xs text-[var(--sc-text-secondary)]">
                  Recent automatic activity: {recentActivity.filter((entry) => entry.kind !== 'scan').length}
                </div>
              </div>
            </div>

            <div className="mt-6">
              <div className="text-xs uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">Watch Roots</div>
              <div className="mt-3 grid gap-3">
                {watchRoots.length === 0 ? (
                  <div className="rounded-[22px] bg-[var(--sc-bg-elevated)] px-4 py-4 text-sm text-[var(--sc-text-secondary)]">
                    No watch roots yet. Start one from X-Ray and it will appear here.
                  </div>
                ) : (
                  watchRoots.map((session) => (
                    <div key={session.id} className="rounded-[22px] border border-[var(--sc-border)] bg-[var(--sc-bg-elevated)] px-4 py-4">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <div className="truncate text-sm font-semibold text-[var(--sc-text-primary)]">{session.root}</div>
                          <div className="mt-1 text-xs text-[var(--sc-text-muted)]">
                            Started {formatDate(session.startedAt)} · Last heartbeat {formatDate(session.lastHeartbeatAt)}
                          </div>
                          <div className="mt-2 text-sm text-[var(--sc-text-secondary)]">{session.lastEventSummary ?? 'No detections yet'}</div>
                        </div>
                        <div className="flex flex-col items-end gap-2">
                          <span className={`${PILL} capitalize`}>{session.state}</span>
                          <span className={`${PILL}`}>{session.highestRiskLevel}</span>
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </section>

          <section className={`${CARD} p-6`}>
            <div className="text-xs uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">Safety Controls</div>
            <h2 className="mt-2 text-2xl font-semibold tracking-[-0.03em] text-[var(--sc-text-primary)]">Don’t lose the useful stuff</h2>

            <div className="mt-5 space-y-3">
              <Link href="/protection/iron-dome" className="block rounded-[22px] bg-[var(--sc-bg-elevated)] px-4 py-4 transition-colors hover:bg-[var(--sc-bg-elevated)]">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="text-sm font-semibold text-[var(--sc-text-primary)]">Iron Dome</div>
                    <div className="mt-1 text-sm text-[var(--sc-text-secondary)]">Profiles, kill switch, and emergency protection controls.</div>
                  </div>
                  <span className={`${PILL}`}>{ironDome?.enabled ? 'Active' : 'Inactive'}</span>
                </div>
              </Link>

              <Link href="/protection/quarantine" className="block rounded-[22px] bg-[var(--sc-bg-elevated)] px-4 py-4 transition-colors hover:bg-[var(--sc-bg-elevated)]">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="text-sm font-semibold text-[var(--sc-text-primary)]">Quarantine queue</div>
                    <div className="mt-1 text-sm text-[var(--sc-text-secondary)]">Approve or reject risky items instead of letting them pile up.</div>
                  </div>
                  <span className={`${PILL}`}>{quarantine?.total ?? 0} waiting</span>
                </div>
              </Link>

              <Link href="/protection/intercepts" className="block rounded-[22px] bg-[var(--sc-bg-elevated)] px-4 py-4 transition-colors hover:bg-[var(--sc-bg-elevated)]">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="text-sm font-semibold text-[var(--sc-text-primary)]">Live approvals</div>
                    <div className="mt-1 text-sm text-[var(--sc-text-secondary)]">Tool-call approvals and denies stay available when you need them.</div>
                  </div>
                  <span className={`${PILL}`}>{intercepts?.summary.total ?? 0} events</span>
                </div>
              </Link>
            </div>

            <div className="mt-6 rounded-[24px] bg-[#2f241f] px-5 py-5 text-[var(--sc-text-primary)]">
              <div className="text-xs uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">Review Queue</div>
              <div className="mt-3 space-y-3">
                {pendingItems.length === 0 ? (
                  <div className="text-sm text-[var(--sc-text-muted)]">Nothing is waiting for approval right now.</div>
                ) : (
                  pendingItems.map((item) => (
                    <div key={item.id} className="rounded-2xl border border-[var(--sc-border)] bg-[var(--sc-surface-interactive)] px-4 py-3">
                      <div className="text-sm font-medium text-white">{item.title || 'Untitled item'}</div>
                      <div className="mt-1 line-clamp-2 text-sm text-[var(--sc-text-muted)]">{item.reason}</div>
                    </div>
                  ))
                )}
              </div>
              <Link
                href="/protection/quarantine"
                className="mt-4 inline-flex items-center gap-2 rounded-full bg-[var(--sc-bg-elevated)] px-4 py-2 text-sm font-semibold text-[var(--sc-text-primary)] transition-colors hover:bg-[var(--sc-bg-elevated)]"
              >
                Open approve / reject queue
                <ArrowRight size={14} />
              </Link>
            </div>
          </section>
        </div>

        <div className="grid gap-6 xl:grid-cols-[minmax(0,0.95fr)_minmax(0,1.05fr)]">
          <section className={`${CARD} p-6`}>
            <div className="text-xs uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">Recent Activity</div>
            <div className="mt-4 space-y-3">
              {recentActivity.length === 0 ? (
                <div className="rounded-[22px] bg-[var(--sc-bg-elevated)] px-4 py-4 text-sm text-[var(--sc-text-secondary)]">No recent activity yet.</div>
              ) : (
                recentActivity.map((entry) => (
                  <div key={entry.id} className="rounded-[22px] border border-[var(--sc-border)] bg-[var(--sc-bg-elevated)] px-4 py-4">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 text-sm font-semibold capitalize text-[var(--sc-text-primary)]">
                          <TimerReset size={14} className="text-[#c85f34]" />
                          {entry.kind}
                        </div>
                        <div className="mt-1 truncate text-sm text-[var(--sc-text-secondary)]">{entry.target}</div>
                        <div className="mt-1 text-xs text-[var(--sc-text-muted)]">{entry.summary}</div>
                      </div>
                      <span className={`${PILL}`}>{entry.riskLevel}</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </section>

          <section className={`${CARD} p-6`}>
            <div className="text-xs uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">Latest Result</div>
            {!latestScan ? (
              <div className="mt-4 rounded-[22px] bg-[var(--sc-bg-elevated)] px-4 py-4 text-sm text-[var(--sc-text-secondary)]">Run a scan from X-Ray and the latest result will show up here.</div>
            ) : (
              <div className="mt-4 rounded-[24px] bg-[linear-gradient(135deg,#fef7ef_0%,#f7efe7_100%)] px-5 py-5">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="truncate text-lg font-semibold text-[var(--sc-text-primary)]">{latestScan.target}</div>
                    <div className="mt-1 text-sm text-[var(--sc-text-secondary)]">{formatDate(latestScan.scannedAt)}</div>
                  </div>
                  <span className={`${PILL}`}>{latestScan.riskLevel}</span>
                </div>
                <div className="mt-4 grid gap-3 sm:grid-cols-3">
                  <div className="rounded-2xl bg-[var(--sc-bg-elevated)] px-4 py-3 text-sm text-[var(--sc-text-secondary)]">
                    <div className="text-xs uppercase tracking-[0.16em] text-[var(--sc-text-muted)]">Score</div>
                    <div className="mt-1 text-xl font-semibold text-[var(--sc-text-primary)]">{latestScan.trustScore}</div>
                  </div>
                  <div className="rounded-2xl bg-[var(--sc-bg-elevated)] px-4 py-3 text-sm text-[var(--sc-text-secondary)]">
                    <div className="text-xs uppercase tracking-[0.16em] text-[var(--sc-text-muted)]">Findings</div>
                    <div className="mt-1 text-xl font-semibold text-[var(--sc-text-primary)]">{latestScan.findingCount}</div>
                  </div>
                  <div className="rounded-2xl bg-[var(--sc-bg-elevated)] px-4 py-3 text-sm text-[var(--sc-text-secondary)]">
                    <div className="text-xs uppercase tracking-[0.16em] text-[var(--sc-text-muted)]">Mode</div>
                    <div className="mt-1 text-xl font-semibold text-[var(--sc-text-primary)]">{latestScan.deepScan ? 'Deep' : 'Standard'}</div>
                  </div>
                </div>
                <Link
                  href="/supply-chain/xray"
                  className="mt-5 inline-flex items-center gap-2 rounded-full bg-[#c85f34] px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-[#b85129]"
                >
                  Open full X-Ray detail
                  <ArrowRight size={14} />
                </Link>
              </div>
            )}

            <div className="mt-6 text-xs uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">Current plan</div>
            <div className="mt-3 flex flex-wrap gap-2 text-xs text-[var(--sc-text-secondary)]">
              <span className={PILL}>Licence: {license?.tier ?? 'free'}</span>
              <span className={PILL}>Iron Dome: {ironDome?.enabled ? 'active' : 'inactive'}</span>
              <span className={PILL}>Blocked 24h: {auditStats?.blockedCount ?? 0}</span>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
