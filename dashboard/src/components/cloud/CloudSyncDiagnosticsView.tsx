'use client';

import { useState } from 'react';
import { AlertTriangle, CheckCircle2, Clock3, Cloud, Database, GitBranch, KeyRound, RefreshCw, Server, ShieldAlert } from 'lucide-react';
import { useCloudProjects, useCloudStatus, useUpdateCloudConfig, type CloudConfig } from '@/hooks/useCloudStatus';
import { useCloudSyncStatus, type CloudSyncStatus } from '@/hooks/useCloudSyncStatus';
import { useLicenseStatus } from '@/hooks/useLicense';
import { TIER_BG, TIER_COLOURS, TIER_LABELS } from '@/lib/license';

function formatTimeAgo(isoString: string): string {
  const diff = Date.now() - new Date(isoString).getTime();
  const seconds = Math.max(0, Math.floor(diff / 1000));

  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function formatTimeUntil(isoString: string): string {
  const diff = new Date(isoString).getTime() - Date.now();
  const seconds = Math.max(0, Math.floor(diff / 1000));

  if (seconds < 60) return `in ${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `in ${minutes}m`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `in ${hours}h`;
  const days = Math.floor(hours / 24);
  return `in ${days}d`;
}

function isCloudSyncStale(lastSyncAt: string | null): boolean {
  return lastSyncAt ? Date.now() - new Date(lastSyncAt).getTime() > 24 * 60 * 60 * 1000 : false;
}

function StatusBanner() {
  const { data: sync, isLoading } = useCloudSyncStatus();
  const { data: license } = useLicenseStatus();

  if (isLoading || !sync) return null;

  let tone = 'border-slate-700 bg-slate-900/70 text-slate-200';
  let title = 'Cloud sync disabled';
  let detail = 'Enable cloud sync and activate a Team licence to start replicating local data.';
  let Icon = Cloud;
  const stale = isCloudSyncStale(sync.lastSyncAt);
  const replicationPending = sync.queue.byKind.memory.pending + sync.queue.byKind.graph.pending;
  const replicationFailed = sync.queue.byKind.memory.failed + sync.queue.byKind.graph.failed;
  const auxiliaryFailed =
    sync.queue.byKind.audit.failed +
    sync.queue.byKind.quarantine.failed +
    sync.queue.byKind.unknown.failed;

  if (sync.enabled && sync.apiKeySet && !sync.featureEnabled) {
    tone = 'border-amber-500/30 bg-amber-500/10 text-amber-200';
    title = 'Cloud configured but licence locked';
    detail = `Cloud sync requires the ${TIER_LABELS[sync.requiredTier]} tier. Current tier: ${TIER_LABELS[license?.tier ?? 'free']}.`;
    Icon = KeyRound;
  } else if (sync.enabled && sync.apiKeySet && replicationPending > 0 && replicationFailed > 0) {
    tone = 'border-red-500/30 bg-red-500/10 text-red-200';
    title = 'Cloud sync needs attention';
    detail = sync.queue.lastError ?? 'One or more queued sync jobs are failing.';
    Icon = ShieldAlert;
  } else if (sync.enabled && sync.apiKeySet && replicationFailed > 0) {
    tone = stale ? 'border-red-500/30 bg-red-500/10 text-red-200' : 'border-amber-500/30 bg-amber-500/10 text-amber-200';
    title = stale ? 'Cloud sync has unresolved failures' : 'Cloud sync healthy, with failed history';
    detail = sync.queue.lastError
      ? `${sync.queue.lastError}${sync.queue.latestFailureAt ? ` Last failure ${formatTimeAgo(sync.queue.latestFailureAt)}.` : ''}`
      : `${replicationFailed} failed replication job${replicationFailed === 1 ? '' : 's'} remain in queue history.`;
    Icon = stale ? ShieldAlert : AlertTriangle;
  } else if (sync.enabled && sync.apiKeySet && replicationPending > 0) {
    tone = 'border-amber-500/30 bg-amber-500/10 text-amber-200';
    title = 'Cloud sync is catching up';
    detail = sync.queue.nextRetryAt
      ? `Next retry ${formatTimeUntil(sync.queue.nextRetryAt)}.`
      : 'Queued jobs are waiting to flush.';
    Icon = RefreshCw;
  } else if (sync.enabled && sync.apiKeySet) {
    tone = 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200';
    title = 'Cloud sync healthy';
    detail = sync.lastSyncAt ? `Last successful sync ${formatTimeAgo(sync.lastSyncAt)}.` : 'Connected and ready to sync.';
    if (auxiliaryFailed > 0) {
      detail += ` Auxiliary audit/quarantine history: ${auxiliaryFailed} failed job${auxiliaryFailed === 1 ? '' : 's'}.`;
    }
    Icon = CheckCircle2;
  }

  return (
    <div className={`rounded-2xl border p-4 ${tone}`}>
      <div className="flex items-start gap-3">
        <Icon size={18} className="mt-0.5 shrink-0" />
        <div>
          <h2 className="text-sm font-semibold">{title}</h2>
          <p className="mt-1 text-sm opacity-90">{detail}</p>
        </div>
      </div>
    </div>
  );
}

function StatCard({
  label,
  value,
  detail,
  icon: Icon,
}: {
  label: string;
  value: string | number;
  detail: string;
  icon: typeof Server;
}) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4">
      <div className="flex items-center justify-between">
        <span className="text-xs uppercase tracking-[0.2em] text-slate-500">{label}</span>
        <Icon size={15} className="text-slate-500" />
      </div>
      <div className="mt-2 text-2xl font-semibold text-white">{value}</div>
      <div className="mt-1 text-xs text-slate-400">{detail}</div>
    </div>
  );
}

function QueueKindCard({
  label,
  pending,
  failed,
  synced,
}: {
  label: string;
  pending: number;
  failed: number;
  synced: number;
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
      <div className="text-sm font-medium text-white">{label}</div>
      <div className="mt-3 grid grid-cols-3 gap-2 text-xs">
        <div>
          <div className="text-slate-500">Pending</div>
          <div className="mt-1 font-semibold text-amber-300">{pending}</div>
        </div>
        <div>
          <div className="text-slate-500">Failed</div>
          <div className="mt-1 font-semibold text-red-300">{failed}</div>
        </div>
        <div>
          <div className="text-slate-500">Synced</div>
          <div className="mt-1 font-semibold text-emerald-300">{synced}</div>
        </div>
      </div>
    </div>
  );
}

function SyncControlsCard() {
  const { data: cloudConfig } = useCloudStatus();
  const { data: projectsData } = useCloudProjects();
  const updateCloudConfig = useUpdateCloudConfig();
  const [draftControls, setDraftControls] = useState<{
    projectMode: 'all' | 'include' | 'exclude';
    projects: string[];
    contentMode: 'full' | 'metadata';
    excludeSensitive: boolean;
  } | null>(null);

  const projects = projectsData?.projects ?? [];
  const controls = draftControls ?? cloudConfig?.syncControls ?? {
    projectMode: 'all' as const,
    projects: [],
    contentMode: 'full' as const,
    excludeSensitive: false,
  };

  function toggleProject(project: string) {
    setDraftControls((current) => {
      const base = current ?? controls;
      const projects = base.projects.includes(project)
        ? base.projects.filter((entry) => entry !== project)
        : [...base.projects, project].sort((a, b) => a.localeCompare(b));

      return {
        ...base,
        projects,
      };
    });
  }

  async function saveControls() {
    await updateCloudConfig.mutateAsync({
      cloudSyncProjectMode: controls.projectMode,
      cloudSyncProjects: controls.projects,
      cloudSyncContentMode: controls.contentMode,
      cloudSyncExcludeSensitive: controls.excludeSensitive,
    });
    setDraftControls(null);
  }

  return (
    <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-white">Sync Controls</h2>
          <p className="mt-1 text-sm text-slate-400">
            Decide what leaves this device before it hits the cloud replica.
          </p>
        </div>
        <button
          type="button"
          onClick={() => void saveControls()}
          disabled={updateCloudConfig.isPending}
          className="rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-3 py-2 text-sm font-medium text-cyan-200 transition hover:bg-cyan-500/20 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {updateCloudConfig.isPending ? 'Saving...' : 'Save controls'}
        </button>
      </div>

      <div className="mt-5 grid gap-4">
        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
          <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Content mode</div>
          <div className="mt-3 grid gap-2 md:grid-cols-2">
            <label className={`rounded-lg border p-3 text-sm ${controls.contentMode === 'full' ? 'border-cyan-500/40 bg-cyan-500/10 text-cyan-100' : 'border-slate-800 text-slate-300'}`}>
              <input
                type="radio"
                className="mr-2"
                checked={controls.contentMode === 'full'}
                onChange={() => setDraftControls((current) => ({ ...(current ?? controls), contentMode: 'full' }))}
              />
              Full content
              <div className="mt-1 text-xs text-slate-400">Titles and memory bodies replicate to cloud.</div>
            </label>
            <label className={`rounded-lg border p-3 text-sm ${controls.contentMode === 'metadata' ? 'border-cyan-500/40 bg-cyan-500/10 text-cyan-100' : 'border-slate-800 text-slate-300'}`}>
              <input
                type="radio"
                className="mr-2"
                checked={controls.contentMode === 'metadata'}
                onChange={() => setDraftControls((current) => ({ ...(current ?? controls), contentMode: 'metadata' }))}
              />
              Metadata only
              <div className="mt-1 text-xs text-slate-400">Projects, tags, salience, and graph remain; body content is redacted.</div>
            </label>
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
          <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Project scope</div>
          <div className="mt-3 flex flex-wrap gap-2">
            {(['all', 'include', 'exclude'] as const).map((mode) => (
              <button
                key={mode}
                type="button"
                onClick={() => setDraftControls((current) => ({ ...(current ?? controls), projectMode: mode }))}
                className={`rounded-full border px-3 py-1.5 text-xs font-medium uppercase tracking-wide ${
                  controls.projectMode === mode
                    ? 'border-cyan-500/40 bg-cyan-500/10 text-cyan-100'
                    : 'border-slate-700 bg-slate-900/60 text-slate-300'
                }`}
              >
                {mode}
              </button>
            ))}
          </div>
          <p className="mt-3 text-xs text-slate-400">
            {controls.projectMode === 'all'
              ? 'All local projects are eligible for sync.'
              : controls.projectMode === 'include'
                ? 'Only the selected projects will sync.'
                : 'Selected projects stay local-only.'}
          </p>
          <div className="mt-3 max-h-48 overflow-y-auto rounded-lg border border-slate-800 bg-slate-900/40 p-3">
            {projects.length === 0 ? (
              <div className="text-xs text-slate-500">No named projects found in local memory yet.</div>
            ) : (
              <div className="flex flex-wrap gap-2">
                {projects.map((project) => {
                  const selected = controls.projects.includes(project.project);
                  return (
                    <button
                      key={project.project}
                      type="button"
                      onClick={() => toggleProject(project.project)}
                      className={`rounded-full border px-3 py-1.5 text-xs ${
                        selected
                          ? 'border-cyan-500/40 bg-cyan-500/10 text-cyan-100'
                          : 'border-slate-700 bg-slate-950/60 text-slate-300'
                      }`}
                    >
                      {project.project} <span className="text-slate-500">({project.count})</span>
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        <label className="flex items-start gap-3 rounded-xl border border-slate-800 bg-slate-950/60 p-4 text-sm text-slate-200">
          <input
            type="checkbox"
            className="mt-0.5"
            checked={controls.excludeSensitive}
            onChange={(event) =>
              setDraftControls((current) => ({
                ...(current ?? controls),
                excludeSensitive: event.target.checked,
              }))
            }
          />
          <div>
            <div className="font-medium text-white">Exclude sensitive memories</div>
            <div className="mt-1 text-xs text-slate-400">
              Skip memories whose sensitivity level is higher than INTERNAL when syncing to cloud.
            </div>
          </div>
        </label>

        {updateCloudConfig.isError && (
          <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-200">
            {(updateCloudConfig.error as Error).message}
          </div>
        )}
      </div>
    </section>
  );
}

function CompactPolicySummary({
  sync,
  cloudConfig,
}: {
  sync: CloudSyncStatus;
  cloudConfig: CloudConfig;
}) {
  return (
    <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
      <h2 className="text-lg font-semibold text-white">Current policy</h2>
      <p className="mt-1 text-sm text-slate-400">
        The snapshot below is the current cloud posture. Edit it in Sync Controls when you need to change what leaves this device.
      </p>
      <div className="mt-4 grid gap-3 md:grid-cols-2">
        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
          <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Sync scope</div>
          <div className="mt-2 text-sm font-medium text-white">{sync.controls.projectMode}</div>
          <div className="mt-1 text-xs text-slate-400">{sync.controls.projects.length} selected project{sync.controls.projects.length === 1 ? '' : 's'}</div>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
          <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Content mode</div>
          <div className="mt-2 text-sm font-medium text-white">{sync.controls.contentMode === 'metadata' ? 'Metadata only' : 'Full content'}</div>
          <div className="mt-1 text-xs text-slate-400">Sensitive filter {sync.controls.excludeSensitive ? 'enabled' : 'off'}</div>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
          <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Cloud endpoint</div>
          <div className="mt-2 text-sm font-medium text-white">{sync.baseUrl}</div>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
          <div className="text-xs uppercase tracking-[0.2em] text-slate-500">OpenClaw complement</div>
          <div className="mt-2 grid grid-cols-2 gap-2 text-xs text-slate-300">
            <span>Auto-memory: {cloudConfig.openclawMemory.autoMemory ? 'On' : 'Off'}</span>
            <span>Dedupe: {cloudConfig.openclawMemory.dedupe ? 'On' : 'Off'}</span>
            <span>Novelty: {cloudConfig.openclawMemory.noveltyThreshold}</span>
            <span>Recent window: {cloudConfig.openclawMemory.maxRecent}</span>
          </div>
        </div>
      </div>
    </section>
  );
}

export function CloudSyncDiagnosticsView() {
  const { data: sync, isLoading: syncLoading } = useCloudSyncStatus();
  const { data: cloudConfig, isLoading: configLoading } = useCloudStatus();
  const { data: license, isLoading: licenseLoading } = useLicenseStatus();

  if (syncLoading || configLoading || licenseLoading || !sync || !cloudConfig || !license) {
    return (
      <div className="h-full overflow-y-auto p-6">
        <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 text-sm text-slate-400">
          Loading cloud diagnostics...
        </div>
      </div>
    );
  }

  const tier = license.tier;
  const memoryQueue = sync.queue.byKind.memory;
  const graphQueue = sync.queue.byKind.graph;
  const replicationFailed = memoryQueue.failed + graphQueue.failed;
  const auxiliaryFailed =
    sync.queue.byKind.audit.failed +
    sync.queue.byKind.quarantine.failed +
    sync.queue.byKind.unknown.failed;
  const lastSyncLabel = sync.lastSyncAt ? formatTimeAgo(sync.lastSyncAt) : 'Never';
  const replicationHealth = replicationFailed > 0
    ? 'Needs review'
    : memoryQueue.pending + graphQueue.pending > 0
      ? 'Catching up'
      : 'Healthy';

  return (
    <div className="h-full overflow-y-auto bg-slate-950">
      <div className="mx-auto flex max-w-7xl flex-col gap-6 p-6">
        <div className="flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
          <div>
            <h1 className="text-2xl font-semibold text-white">Cloud Diagnostics</h1>
            <p className="mt-1 text-sm text-slate-400">
              See whether replication is healthy first. Then tune policy and inspect the deeper transport details only when you actually need them.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className={`rounded-full px-2.5 py-1 font-medium ${TIER_BG[tier]} ${TIER_COLOURS[tier]}`}>
              {TIER_LABELS[tier]}
            </span>
            <span className="rounded-full border border-slate-700 bg-slate-900/70 px-2.5 py-1 text-slate-300">
              Last sync: {lastSyncLabel}
            </span>
          </div>
        </div>

        <StatusBanner />

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-5">
          <StatCard
            label="Replication"
            value={replicationHealth}
            detail={`${replicationFailed} failed · ${memoryQueue.pending + graphQueue.pending} pending`}
            icon={RefreshCw}
          />
          <StatCard
            label="Device"
            value={sync.device.name}
            detail={`${sync.device.platform} · ${sync.device.id.slice(0, 12)}`}
            icon={Server}
          />
          <StatCard
            label="Cloud Target"
            value={new URL(sync.baseUrl).host}
            detail={sync.enabled ? 'Configured target' : 'Disabled in config'}
            icon={Cloud}
          />
          <StatCard
            label="Memory Queue"
            value={memoryQueue.pending}
            detail={`${memoryQueue.failed} failed · ${memoryQueue.synced} synced`}
            icon={Database}
          />
          <StatCard
            label="Graph Queue"
            value={graphQueue.pending}
            detail={`${graphQueue.failed} failed · ${graphQueue.synced} synced`}
            icon={GitBranch}
          />
        </div>

        <div className="grid grid-cols-1 gap-6 xl:grid-cols-[1.35fr_0.95fr]">
          <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
            <div className="flex items-center justify-between gap-3">
              <div>
                <h2 className="text-lg font-semibold text-white">Replication</h2>
                <p className="mt-1 text-sm text-slate-400">
                  Focus on memory and graph first. Audit and quarantine transport history is still available, but it should not dominate the page when replication itself is healthy.
                </p>
              </div>
            </div>

            <div className="mt-5 grid grid-cols-1 gap-3 md:grid-cols-2">
              <QueueKindCard label="Memory" {...memoryQueue} />
              <QueueKindCard label="Graph" {...graphQueue} />
            </div>

            <details className="mt-5 rounded-xl border border-slate-800 bg-slate-950/30 p-4">
              <summary className="cursor-pointer list-none text-sm font-medium text-slate-200">
                Advanced transport signals
              </summary>
              <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2">
                <QueueKindCard label="Audit" {...sync.queue.byKind.audit} />
                <QueueKindCard label="Quarantine" {...sync.queue.byKind.quarantine} />
              </div>
              <div className="mt-4 overflow-hidden rounded-xl border border-slate-800">
                <table className="min-w-full divide-y divide-slate-800 text-sm">
                  <thead className="bg-slate-950/70 text-slate-400">
                    <tr>
                      <th className="px-4 py-3 text-left font-medium">Signal</th>
                      <th className="px-4 py-3 text-left font-medium">Current value</th>
                      <th className="px-4 py-3 text-left font-medium">Why it matters</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 bg-slate-900/40 text-slate-200">
                    <tr>
                      <td className="px-4 py-3">Oldest queued job</td>
                      <td className="px-4 py-3">{sync.queue.oldestPendingAt ? formatTimeAgo(sync.queue.oldestPendingAt) : 'None queued'}</td>
                      <td className="px-4 py-3 text-slate-400">If this stays old while pending grows, the local worker is falling behind.</td>
                    </tr>
                    <tr>
                      <td className="px-4 py-3">Next retry</td>
                      <td className="px-4 py-3">{sync.queue.nextRetryAt ? formatTimeUntil(sync.queue.nextRetryAt) : 'Idle'}</td>
                      <td className="px-4 py-3 text-slate-400">Confirms whether failures are retrying normally or the queue is stuck.</td>
                    </tr>
                    <tr>
                      <td className="px-4 py-3">Failed jobs in history</td>
                      <td className="px-4 py-3">{replicationFailed}</td>
                      <td className="px-4 py-3 text-slate-400">These are retained replication dead-letter records for memory and graph sync.</td>
                    </tr>
                    <tr>
                      <td className="px-4 py-3">Auxiliary failed history</td>
                      <td className="px-4 py-3">{auxiliaryFailed}</td>
                      <td className="px-4 py-3 text-slate-400">Audit and quarantine retry history is shown here for debugging, but it does not mean memory replication is currently blocked.</td>
                    </tr>
                    <tr>
                      <td className="px-4 py-3">Latest memory sync</td>
                      <td className="px-4 py-3">{sync.lastSyncAt ? formatTimeAgo(sync.lastSyncAt) : 'Not recorded'}</td>
                      <td className="px-4 py-3 text-slate-400">This is the best quick indicator for whether cloud replication is actually current.</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </details>
          </section>

          <div className="flex flex-col gap-6">
            <SyncControlsCard />
            <CompactPolicySummary sync={sync} cloudConfig={cloudConfig} />

            <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
              <h2 className="text-lg font-semibold text-white">Last actionable error</h2>
              <div className="mt-4 rounded-xl border border-slate-800 bg-slate-950/60 p-4">
                {sync.queue.lastError ? (
                  <>
                    <div className={`flex items-center gap-2 text-sm font-medium ${sync.queue.pending > 0 ? 'text-red-300' : 'text-amber-300'}`}>
                      <AlertTriangle size={16} />
                      {sync.queue.lastErrorKind ? `${sync.queue.lastErrorKind} queue` : 'Unknown queue'}
                    </div>
                    <p className="mt-2 text-sm text-slate-300">{sync.queue.lastError}</p>
                    {sync.queue.latestFailureAt && (
                      <div className="mt-2 text-xs text-slate-500">
                        Recorded {formatTimeAgo(sync.queue.latestFailureAt)}
                      </div>
                    )}
                    {sync.queue.nextRetryAt && (
                      <div className="mt-3 inline-flex items-center gap-1 rounded-full bg-slate-900 px-2 py-1 text-xs text-slate-400">
                        <Clock3 size={12} />
                        Retry {formatTimeUntil(sync.queue.nextRetryAt)}
                      </div>
                    )}
                  </>
                ) : (
                  <div className="flex items-center gap-2 text-sm text-emerald-300">
                    <CheckCircle2 size={16} />
                    No recent sync errors recorded.
                  </div>
                )}
              </div>
            </section>
          </div>
        </div>
      </div>
    </div>
  );
}
