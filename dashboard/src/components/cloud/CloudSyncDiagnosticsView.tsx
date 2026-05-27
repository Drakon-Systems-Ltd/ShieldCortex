'use client';

import { useState } from 'react';
import { AlertTriangle, CheckCircle2, Clock3, Cloud, Database, GitBranch, KeyRound, RefreshCw, Server, ShieldAlert } from 'lucide-react';
import { useCloudProjects, useCloudStatus, useUpdateCloudConfig, type CloudConfig } from '@/hooks/useCloudStatus';
import { useClearFailedSync, useCloudSyncStatus, type CloudSyncStatus } from '@/hooks/useCloudSyncStatus';
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

function StatusBanner() {
  const { data: sync, isLoading } = useCloudSyncStatus();
  const { data: license } = useLicenseStatus();

  if (isLoading || !sync) return null;

  let tone = 'border-[var(--sc-border)] bg-[var(--sc-bg-surface)]/70 text-[var(--sc-text-primary)]';
  let title = 'Cloud sync disabled';
  let detail = 'Enable cloud sync and activate a Team licence to start replicating local data.';
  let Icon = Cloud;
  const replicationPending = sync.queue.byKind.memory.pending + sync.queue.byKind.graph.pending;
  const replicationFailed = sync.queue.byKind.memory.failed + sync.queue.byKind.graph.failed;
  const auxiliaryFailed =
    sync.queue.byKind.audit.failed +
    sync.queue.byKind.quarantine.failed +
    sync.queue.byKind.unknown.failed;

  if (sync.enabled && sync.apiKeySet && !sync.featureEnabled) {
    tone = 'border-[var(--sc-amber)]/30 bg-[var(--sc-amber)]/10 text-[var(--sc-amber)]';
    title = 'Cloud configured but licence locked';
    detail = `Cloud sync requires the ${TIER_LABELS[sync.requiredTier]} tier. Current tier: ${TIER_LABELS[license?.tier ?? 'free']}.`;
    Icon = KeyRound;
  } else if (sync.enabled && sync.apiKeySet && replicationPending > 0 && replicationFailed > 0) {
    tone = 'border-[var(--sc-coral)]/30 bg-[var(--sc-coral)]/10 text-[var(--sc-coral)]';
    title = 'Cloud sync needs attention';
    detail = sync.queue.lastError ?? 'One or more queued sync jobs are failing.';
    Icon = ShieldAlert;
  } else if (sync.enabled && sync.apiKeySet && replicationFailed > 0) {
    tone = 'border-[var(--sc-amber)]/30 bg-[var(--sc-amber)]/10 text-[var(--sc-amber)]';
    title = `${replicationFailed} failed sync job${replicationFailed === 1 ? '' : 's'} need clearing`;
    detail = sync.queue.lastError
      ? `${sync.queue.lastError}${sync.queue.latestFailureAt ? ` Last failure ${formatTimeAgo(sync.queue.latestFailureAt)}.` : ''}`
      : `These items exhausted retries and won't sync automatically. Clear them or investigate the cause.`;
    Icon = AlertTriangle;
  } else if (sync.enabled && sync.apiKeySet && replicationPending > 0) {
    tone = 'border-[var(--sc-amber)]/30 bg-[var(--sc-amber)]/10 text-[var(--sc-amber)]';
    title = 'Cloud sync is catching up';
    detail = sync.queue.nextRetryAt
      ? `Next retry ${formatTimeUntil(sync.queue.nextRetryAt)}.`
      : 'Queued jobs are waiting to flush.';
    Icon = RefreshCw;
  } else if (sync.enabled && sync.apiKeySet) {
    tone = 'border-[var(--sc-cyan)]/30 bg-[var(--sc-cyan)]/10 text-[var(--sc-cyan)]';
    title = 'Cloud sync healthy';
    detail = sync.lastSyncAt ? `Last successful sync ${formatTimeAgo(sync.lastSyncAt)}.` : 'Connected and ready to sync.';
    if (auxiliaryFailed > 0) {
      detail += ` Auxiliary audit/quarantine history: ${auxiliaryFailed} failed job${auxiliaryFailed === 1 ? '' : 's'}.`;
    }
    Icon = CheckCircle2;
  }

  const showClearInBanner = replicationFailed > 0 && replicationPending === 0;

  return (
    <div className={`rounded-2xl border p-4 ${tone}`}>
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-3">
          <Icon size={18} className="mt-0.5 shrink-0" />
          <div>
            <h2 className="text-sm font-semibold">{title}</h2>
            <p className="mt-1 text-sm opacity-90">{detail}</p>
          </div>
        </div>
        {showClearInBanner && <ClearFailedButton />}
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
    <div className="glass-card p-4">
      <div className="flex items-center justify-between">
        <span className="text-xs uppercase tracking-[0.2em] text-[var(--sc-text-muted)]">{label}</span>
        <Icon size={15} className="text-[var(--sc-text-muted)]" />
      </div>
      <div className="mt-2 text-2xl font-semibold text-[var(--sc-text-primary)]">{value}</div>
      <div className="mt-1 text-xs text-[var(--sc-text-secondary)]">{detail}</div>
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
    <div className="rounded-xl border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/60 p-3">
      <div className="text-sm font-medium text-[var(--sc-text-primary)]">{label}</div>
      <div className="mt-3 grid grid-cols-3 gap-2 text-xs">
        <div>
          <div className="text-[var(--sc-text-muted)]">Pending</div>
          <div className="mt-1 font-semibold text-[var(--sc-amber)]">{pending}</div>
        </div>
        <div>
          <div className="text-[var(--sc-text-muted)]">Failed</div>
          <div className="mt-1 font-semibold text-[var(--sc-coral)]">{failed}</div>
        </div>
        <div>
          <div className="text-[var(--sc-text-muted)]">Synced</div>
          <div className="mt-1 font-semibold text-[var(--sc-cyan)]">{synced}</div>
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
  const showProjectSelection = controls.projectMode !== 'all';

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

  const [saveStatus, setSaveStatus] = useState<'idle' | 'saved' | 'error'>('idle');

  async function saveControls() {
    try {
      await updateCloudConfig.mutateAsync({
        cloudSyncProjectMode: controls.projectMode,
        cloudSyncProjects: controls.projects,
        cloudSyncContentMode: controls.contentMode,
        cloudSyncExcludeSensitive: controls.excludeSensitive,
      });
      setDraftControls(null);
      setSaveStatus('saved');
      setTimeout(() => setSaveStatus('idle'), 2000);
    } catch {
      setSaveStatus('error');
      setTimeout(() => setSaveStatus('idle'), 3000);
    }
  }

  return (
    <div className="glass-card-strong p-5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-[var(--sc-text-primary)]">Sync Controls</h2>
          <p className="mt-1 text-sm text-[var(--sc-text-secondary)]">
            Decide what leaves this device before it hits the cloud replica.
          </p>
        </div>
        <button
          type="button"
          onClick={() => void saveControls()}
          disabled={updateCloudConfig.isPending}
          className={`rounded-lg border px-3 py-2 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-50 ${
            saveStatus === 'saved'
              ? 'border-[var(--sc-cyan)]/50 bg-[var(--sc-cyan)]/20 text-[var(--sc-cyan)]'
              : saveStatus === 'error'
                ? 'border-[var(--sc-coral)]/50 bg-[var(--sc-coral)]/20 text-[var(--sc-coral)]'
                : 'border-[var(--sc-cyan)]/30 bg-[var(--sc-cyan)]/10 text-[var(--sc-cyan)] hover:bg-[var(--sc-cyan)]/20'
          }`}
        >
          {updateCloudConfig.isPending ? 'Saving...' : saveStatus === 'saved' ? '✓ Saved' : saveStatus === 'error' ? 'Failed to save' : 'Save controls'}
        </button>
      </div>

      <div className="mt-5 grid gap-4">
        <div className="rounded-xl border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/60 p-4">
          <div className="text-xs uppercase tracking-[0.2em] text-[var(--sc-text-muted)]">Content mode</div>
          <div className="mt-2 flex flex-wrap gap-2 text-[11px] text-[var(--sc-text-secondary)]">
            <span className="rounded-full border border-[var(--sc-border)] bg-[var(--sc-bg-surface)]/60 px-2.5 py-1">
              {controls.contentMode === 'metadata' ? 'Metadata only' : 'Full content'}
            </span>
            <span className="rounded-full border border-[var(--sc-border)] bg-[var(--sc-bg-surface)]/60 px-2.5 py-1">
              Sensitive filter {controls.excludeSensitive ? 'on' : 'off'}
            </span>
          </div>
          <div className="mt-3 grid gap-2 md:grid-cols-2">
            <label className={`rounded-lg border p-3 text-sm ${controls.contentMode === 'full' ? 'border-[var(--sc-cyan)]/40 bg-[var(--sc-cyan)]/10 text-[var(--sc-cyan)]' : 'border-[var(--sc-border)] text-[var(--sc-text-primary)]'}`}>
              <input
                type="radio"
                className="mr-2"
                checked={controls.contentMode === 'full'}
                onChange={() => setDraftControls((current) => ({ ...(current ?? controls), contentMode: 'full' }))}
              />
              Full content
              <div className="mt-1 text-xs text-[var(--sc-text-secondary)]">Titles and memory bodies replicate to cloud.</div>
            </label>
            <label className={`rounded-lg border p-3 text-sm ${controls.contentMode === 'metadata' ? 'border-[var(--sc-cyan)]/40 bg-[var(--sc-cyan)]/10 text-[var(--sc-cyan)]' : 'border-[var(--sc-border)] text-[var(--sc-text-primary)]'}`}>
              <input
                type="radio"
                className="mr-2"
                checked={controls.contentMode === 'metadata'}
                onChange={() => setDraftControls((current) => ({ ...(current ?? controls), contentMode: 'metadata' }))}
              />
              Metadata only
              <div className="mt-1 text-xs text-[var(--sc-text-secondary)]">Projects, tags, salience, and graph remain; body content is redacted.</div>
            </label>
          </div>
        </div>

        <div className="rounded-xl border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/60 p-4">
          <div className="text-xs uppercase tracking-[0.2em] text-[var(--sc-text-muted)]">Project scope</div>
          <div className="mt-3 flex flex-wrap gap-2">
            {(['all', 'include', 'exclude'] as const).map((mode) => (
              <button
                key={mode}
                type="button"
                onClick={() => setDraftControls((current) => ({ ...(current ?? controls), projectMode: mode }))}
                className={`rounded-full border px-3 py-1.5 text-xs font-medium uppercase tracking-wide ${
                  controls.projectMode === mode
                    ? 'border-[var(--sc-cyan)]/40 bg-[var(--sc-cyan)]/10 text-[var(--sc-cyan)]'
                    : 'border-[var(--sc-border)] bg-[var(--sc-bg-surface)]/60 text-[var(--sc-text-primary)]'
                }`}
              >
                {mode}
              </button>
            ))}
          </div>
          <p className="mt-3 text-xs text-[var(--sc-text-secondary)]">
            {controls.projectMode === 'all'
              ? 'All local projects are eligible for sync.'
              : controls.projectMode === 'include'
                ? 'Only the selected projects will sync.'
                : 'Selected projects stay local-only.'}
          </p>
          {showProjectSelection && (
            <details className="mt-3 rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-surface)]/40 p-3">
              <summary className="cursor-pointer list-none text-sm font-medium text-[var(--sc-text-primary)]">
                Choose projects {controls.projects.length > 0 ? `(${controls.projects.length} selected)` : ''}
              </summary>
              <div className="mt-3 max-h-48 overflow-y-auto">
                {projects.length === 0 ? (
                  <div className="text-xs text-[var(--sc-text-muted)]">No named projects found in local memory yet.</div>
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
                              ? 'border-[var(--sc-cyan)]/40 bg-[var(--sc-cyan)]/10 text-[var(--sc-cyan)]'
                              : 'border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/60 text-[var(--sc-text-primary)]'
                          }`}
                        >
                          {project.project} <span className="text-[var(--sc-text-muted)]">({project.count})</span>
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>
            </details>
          )}
        </div>

        <label className="flex items-start gap-3 rounded-xl border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/60 p-4 text-sm text-[var(--sc-text-primary)]">
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
            <div className="font-medium text-[var(--sc-text-primary)]">Exclude sensitive memories</div>
            <div className="mt-1 text-xs text-[var(--sc-text-secondary)]">
              Skip memories whose sensitivity level is higher than INTERNAL when syncing to cloud.
            </div>
          </div>
        </label>

        {updateCloudConfig.isError && (
          <div className="rounded-xl border border-[var(--sc-coral)]/30 bg-[var(--sc-coral)]/10 p-3 text-sm text-[var(--sc-coral)]">
            {(updateCloudConfig.error as Error).message}
          </div>
        )}
      </div>
    </div>
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
    <div className="glass-card-strong p-5">
      <h2 className="text-lg font-semibold text-[var(--sc-text-primary)]">Current policy</h2>
      <p className="mt-1 text-sm text-[var(--sc-text-secondary)]">
        The snapshot below is the current cloud posture. Edit it in Sync Controls when you need to change what leaves this device.
      </p>
      <div className="mt-4 grid gap-3 md:grid-cols-2">
        <div className="rounded-xl border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/60 p-4">
          <div className="text-xs uppercase tracking-[0.2em] text-[var(--sc-text-muted)]">Sync scope</div>
          <div className="mt-2 text-sm font-medium text-[var(--sc-text-primary)]">{sync.controls.projectMode}</div>
          <div className="mt-1 text-xs text-[var(--sc-text-secondary)]">{sync.controls.projects.length} selected project{sync.controls.projects.length === 1 ? '' : 's'}</div>
        </div>
        <div className="rounded-xl border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/60 p-4">
          <div className="text-xs uppercase tracking-[0.2em] text-[var(--sc-text-muted)]">Content mode</div>
          <div className="mt-2 text-sm font-medium text-[var(--sc-text-primary)]">{sync.controls.contentMode === 'metadata' ? 'Metadata only' : 'Full content'}</div>
          <div className="mt-1 text-xs text-[var(--sc-text-secondary)]">Sensitive filter {sync.controls.excludeSensitive ? 'enabled' : 'off'}</div>
        </div>
        <div className="rounded-xl border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/60 p-4">
          <div className="text-xs uppercase tracking-[0.2em] text-[var(--sc-text-muted)]">Cloud endpoint</div>
          <div className="mt-2 text-sm font-medium text-[var(--sc-text-primary)]">{sync.baseUrl}</div>
        </div>
        <div className="rounded-xl border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/60 p-4">
          <div className="text-xs uppercase tracking-[0.2em] text-[var(--sc-text-muted)]">OpenClaw complement</div>
          <div className="mt-2 grid grid-cols-2 gap-2 text-xs text-[var(--sc-text-primary)]">
            <span>Auto-memory: {cloudConfig.openclawMemory.autoMemory ? 'On' : 'Off'}</span>
            <span>Dedupe: {cloudConfig.openclawMemory.dedupe ? 'On' : 'Off'}</span>
            <span>Novelty: {cloudConfig.openclawMemory.noveltyThreshold}</span>
            <span>Recent window: {cloudConfig.openclawMemory.maxRecent}</span>
          </div>
        </div>
      </div>
    </div>
  );
}

function ClearFailedButton() {
  const clearFailed = useClearFailedSync();
  return (
    <button
      type="button"
      onClick={() => clearFailed.mutate()}
      disabled={clearFailed.isPending}
      className="shrink-0 rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-elevated)]/50 px-3 py-1.5 text-xs text-[var(--sc-text-secondary)] transition hover:border-[var(--sc-text-muted)] hover:text-[var(--sc-text-primary)] disabled:opacity-50"
    >
      {clearFailed.isPending ? 'Clearing...' : clearFailed.isSuccess ? `Cleared ${clearFailed.data?.cleared ?? 0}` : 'Clear failed'}
    </button>
  );
}

export function CloudSyncDiagnosticsView() {
  const { data: sync, isLoading: syncLoading, refetch: refreshSync, isFetching: syncRefreshing } = useCloudSyncStatus();
  const { data: cloudConfig, isLoading: configLoading } = useCloudStatus();
  const { data: license, isLoading: licenseLoading } = useLicenseStatus();

  if (syncLoading || configLoading || licenseLoading || !sync || !cloudConfig || !license) {
    return (
      <div className="space-y-6">
        <div className="glass-card p-6 text-sm text-[var(--sc-text-secondary)]">
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
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className={`rounded-full px-2.5 py-1 font-medium ${TIER_BG[tier]} ${TIER_COLOURS[tier]}`}>
          {TIER_LABELS[tier]}
        </span>
        <span className="rounded-full border border-[var(--sc-border)] bg-[var(--sc-bg-surface)]/70 px-2.5 py-1 text-[var(--sc-text-primary)]">
          Last sync: {lastSyncLabel}
        </span>
        <button
          type="button"
          onClick={() => void refreshSync()}
          disabled={syncRefreshing}
          className="rounded-full border border-[var(--sc-border)] bg-[var(--sc-bg-surface)]/70 px-2.5 py-1 text-[var(--sc-text-muted)] transition hover:text-[var(--sc-text-primary)] disabled:opacity-50"
          title="Refresh sync status"
        >
          <RefreshCw size={12} className={syncRefreshing ? 'animate-spin' : ''} />
        </button>
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
        <div className="glass-card p-5">
          <div className="flex items-start justify-between gap-3">
            <div>
              <h2 className="text-lg font-semibold text-[var(--sc-text-primary)]">Replication</h2>
              <p className="mt-1 text-sm text-[var(--sc-text-secondary)]">
                Memory and graph sync queues. Items are synced to your cloud replica automatically.
              </p>
            </div>
            {replicationFailed > 0 && <ClearFailedButton />}
          </div>

          <div className="mt-5 grid grid-cols-1 gap-3 md:grid-cols-2">
            <QueueKindCard label="Memory" {...memoryQueue} />
            <QueueKindCard label="Graph" {...graphQueue} />
          </div>

          <details className="mt-5 rounded-xl border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/30 p-4">
            <summary className="cursor-pointer list-none text-sm font-medium text-[var(--sc-text-primary)]">
              Advanced transport signals
            </summary>
            <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2">
              <QueueKindCard label="Audit" {...sync.queue.byKind.audit} />
              <QueueKindCard label="Quarantine" {...sync.queue.byKind.quarantine} />
            </div>
            <div className="mt-4 overflow-hidden rounded-xl border border-[var(--sc-border)]">
              <table className="min-w-full divide-y divide-[var(--sc-border)] text-sm">
                <thead className="bg-[var(--sc-bg-deep)]/70 text-[var(--sc-text-secondary)]">
                  <tr>
                    <th className="px-4 py-3 text-left font-medium">Signal</th>
                    <th className="px-4 py-3 text-left font-medium">Current value</th>
                    <th className="px-4 py-3 text-left font-medium">Why it matters</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--sc-border)] bg-[var(--sc-bg-surface)]/40 text-[var(--sc-text-primary)]">
                  <tr>
                    <td className="px-4 py-3">Oldest queued job</td>
                    <td className="px-4 py-3">{sync.queue.oldestPendingAt ? formatTimeAgo(sync.queue.oldestPendingAt) : 'None queued'}</td>
                    <td className="px-4 py-3 text-[var(--sc-text-secondary)]">If this stays old while pending grows, the local worker is falling behind.</td>
                  </tr>
                  <tr>
                    <td className="px-4 py-3">Next retry</td>
                    <td className="px-4 py-3">{sync.queue.nextRetryAt ? formatTimeUntil(sync.queue.nextRetryAt) : 'Idle'}</td>
                    <td className="px-4 py-3 text-[var(--sc-text-secondary)]">Confirms whether failures are retrying normally or the queue is stuck.</td>
                  </tr>
                  <tr>
                    <td className="px-4 py-3">Failed jobs in history</td>
                    <td className="px-4 py-3">{replicationFailed}</td>
                    <td className="px-4 py-3 text-[var(--sc-text-secondary)]">These are retained replication dead-letter records for memory and graph sync.</td>
                  </tr>
                  <tr>
                    <td className="px-4 py-3">Auxiliary failed history</td>
                    <td className="px-4 py-3">{auxiliaryFailed}</td>
                    <td className="px-4 py-3 text-[var(--sc-text-secondary)]">Audit and quarantine retry history is shown here for debugging, but it does not mean memory replication is currently blocked.</td>
                  </tr>
                  <tr>
                    <td className="px-4 py-3">Latest memory sync</td>
                    <td className="px-4 py-3">{sync.lastSyncAt ? formatTimeAgo(sync.lastSyncAt) : 'Not recorded'}</td>
                    <td className="px-4 py-3 text-[var(--sc-text-secondary)]">This is the best quick indicator for whether cloud replication is actually current.</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </details>
        </div>

        <div className="flex flex-col gap-6">
          <SyncControlsCard />
          <CompactPolicySummary sync={sync} cloudConfig={cloudConfig} />

          <div className="glass-card-strong p-5">
            <h2 className="text-lg font-semibold text-[var(--sc-text-primary)]">Last actionable error</h2>
            <div className="mt-4 rounded-xl border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/60 p-4">
              {sync.queue.lastError ? (
                <>
                  <div className={`flex items-center gap-2 text-sm font-medium ${sync.queue.pending > 0 ? 'text-[var(--sc-coral)]' : 'text-[var(--sc-amber)]'}`}>
                    <AlertTriangle size={16} />
                    {sync.queue.lastErrorKind ? `${sync.queue.lastErrorKind} queue` : 'Unknown queue'}
                  </div>
                  <p className="mt-2 text-sm text-[var(--sc-text-primary)]">{sync.queue.lastError}</p>
                  {sync.queue.latestFailureAt && (
                    <div className="mt-2 text-xs text-[var(--sc-text-muted)]">
                      Recorded {formatTimeAgo(sync.queue.latestFailureAt)}
                    </div>
                  )}
                  {sync.queue.nextRetryAt && (
                    <div className="mt-3 inline-flex items-center gap-1 rounded-full bg-[var(--sc-bg-surface)] px-2 py-1 text-xs text-[var(--sc-text-secondary)]">
                      <Clock3 size={12} />
                      Retry {formatTimeUntil(sync.queue.nextRetryAt)}
                    </div>
                  )}
                </>
              ) : (
                <div className="flex items-center gap-2 text-sm text-[var(--sc-cyan)]">
                  <CheckCircle2 size={16} />
                  No recent sync errors recorded.
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
