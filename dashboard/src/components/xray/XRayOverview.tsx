'use client';

import { useMemo, useState } from 'react';
import {
  Activity,
  ArrowRight,
  Eye,
  FileSearch,
  FolderSearch,
  Lock,
  Radar,
  ScanSearch,
} from 'lucide-react';
import { toast } from 'sonner';
import { FeatureLockedError } from '@/lib/auth';
import { useMemoryWebSocket } from '@/lib/websocket';
import { GlassCard } from '@/components/ds/GlassCard';
import { Badge, riskVariant } from '@/components/ds/Badge';
import { Button } from '@/components/ds/Button';
import { PageHeader } from '@/components/ds/PageHeader';
import { StatCard } from '@/components/ds/StatCard';
import { TrustGauge } from '@/components/xray/TrustGauge';
import { FindingActions } from '@/components/xray/FindingActions';
import { LocalAiFindingExplainer } from '@/components/xray/LocalAiFindingExplainer';
import {
  useXRayActivity,
  useXRayHistory,
  useXRayHistoryEntry,
  usePickXRayTarget,
  useXRayScan,
  useXRayStatus,
  useXRayWatchSessions,
  useActiveWatchers,
  useStartWatch,
  useStopWatch,
} from '@/hooks/useXRay';
import { useXRayFindingsStats, useXRayFindingsList } from '@/hooks/useXRayFindings';

function formatDate(value: string | null | undefined): string {
  if (!value) return '\u2014';
  return new Date(value).toLocaleString();
}

type XRayTab = 'scanner' | 'history' | 'watch' | 'activity' | 'findings';

interface PersistedFinding {
  id: string;
  severity: string;
  category: string;
  title: string;
  description: string;
  file?: string;
  line?: number;
  evidence?: string;
  status: string;
  detectedAt: string;
}

export function XRayOverview() {
  const [tab, setTab] = useState<XRayTab>('scanner');
  const [target, setTarget] = useState('');
  const [deep, setDeep] = useState(false);
  const [selectedHistoryId, setSelectedHistoryId] = useState<string | null>(null);
  const [historyRisk, setHistoryRisk] = useState<'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE'>('ALL');
  const [historyTargetType, setHistoryTargetType] = useState<'all' | 'npm' | 'file' | 'dir'>('all');
  const [historyDepth, setHistoryDepth] = useState<'all' | 'true' | 'false'>('all');
  const [historySearch, setHistorySearch] = useState('');
  const [activityKind, setActivityKind] = useState<'all' | 'scan' | 'watch' | 'preinstall'>('all');
  const [watchState, setWatchState] = useState<'all' | 'active' | 'stale' | 'ended'>('all');
  const [watchTarget, setWatchTarget] = useState('');
  const [watchDeep, setWatchDeep] = useState(false);
  const [findingsFilter, setFindingsFilter] = useState<string>('new');

  const { data: historyData } = useXRayHistory({
    risk: historyRisk,
    targetType: historyTargetType,
    deep: historyDepth,
    search: historySearch,
  });
  const { data: activityData } = useXRayActivity(8, { kind: activityKind });
  const { data: watchSessionsData } = useXRayWatchSessions(8, { state: watchState });
  const { data: statusData } = useXRayStatus();
  const { data: findingsStats } = useXRayFindingsStats();
  const { data: findingsData } = useXRayFindingsList({ status: findingsFilter === 'all' ? undefined : findingsFilter });

  const historyEntries = useMemo(() => historyData?.entries ?? [], [historyData?.entries]);
  const activityEntries = activityData?.entries ?? [];
  const watchSessions = watchSessionsData?.entries ?? [];
  const scanMutation = useXRayScan();
  const pickTargetMutation = usePickXRayTarget();
  const effectiveHistoryId = selectedHistoryId ?? (historyEntries.length > 0 ? historyEntries[0].id : null);
  const detailQuery = useXRayHistoryEntry(effectiveHistoryId);
  const { data: activeWatchersData } = useActiveWatchers();
  const startWatchMutation = useStartWatch();
  const stopWatchMutation = useStopWatch();
  const activeWatchers = activeWatchersData?.watchers ?? [];

  const latestResult = scanMutation.data?.result;
  const persistedFindings = scanMutation.data?.persistedFindings ?? [];
  const latestError = scanMutation.error;
  const isFeatureLocked = latestError instanceof FeatureLockedError;

  useMemoryWebSocket({
    onMessage: (event) => {
      if (event.type === 'xray_detection') {
        const d = event.data as { summary?: string; riskLevel?: string };
        toast.warning(d.summary || 'X-Ray detection', {
          description: `Risk: ${d.riskLevel || 'unknown'}`,
          duration: 8000,
        });
      }
    },
  });

  const selectedHistory = detailQuery.data?.entry ?? historyEntries.find((e) => e.id === effectiveHistoryId) ?? null;
  const visibleResult = latestResult ?? selectedHistory?.result ?? null;

  const summary = useMemo(() => ({
    total: historyEntries.length,
    avgScore: historyEntries.length
      ? Math.round(historyEntries.reduce((sum, e) => sum + e.trustScore, 0) / historyEntries.length)
      : null,
  }), [historyEntries]);

  const capabilities = statusData?.capabilities;
  const statusSummary = statusData?.summary;

  const tabs = [
    { id: 'scanner', label: 'Scanner', icon: <ScanSearch size={14} /> },
    { id: 'history', label: 'History', count: summary.total },
    { id: 'watch', label: 'Watch', count: statusSummary?.activeWatchRoots ?? 0 },
    { id: 'activity', label: 'Activity' },
    { id: 'findings', label: 'Findings', count: findingsStats?.new ?? 0 },
  ];

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-7xl space-y-6 p-6">
        <PageHeader
          eyebrow="Supply Chain Security"
          title="X-Ray Scanner"
          subtitle="Scan packages, files, and directories for hidden risk signals."
          tabs={tabs}
          activeTab={tab}
          onTabChange={(id) => setTab(id as XRayTab)}
          actions={
            <div className="flex items-center gap-3">
              <Badge variant={capabilities?.deepScan ? 'cyan' : 'muted'} dot>
                Deep scan {capabilities?.deepScan ? 'enabled' : 'gated'}
              </Badge>
            </div>
          }
        />

        {/* Stats row */}
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <StatCard label="Total Scans" value={statusSummary?.scans ?? 0} icon={ScanSearch} accent="cyan" />
          <StatCard label="High Risk" value={statusSummary?.highRiskScans ?? 0} icon={Activity} accent="coral" />
          <StatCard label="Watch Roots" value={statusSummary?.activeWatchRoots ?? 0} icon={Eye} accent="cyan" />
          <StatCard label="Avg Trust" value={summary.avgScore ?? '\u2014'} icon={FileSearch} accent={summary.avgScore && summary.avgScore >= 70 ? 'cyan' : 'amber'} />
        </div>

        {/* Scanner tab */}
        {tab === 'scanner' && (
          <div className="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
            {/* Scan form + results */}
            <div className="space-y-6">
              <GlassCard strong className="p-6">
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    if (!target.trim()) return;
                    scanMutation.mutate({ target: target.trim(), deep });
                  }}
                >
                  <label className="text-sm font-semibold text-[var(--sc-text-primary)]">
                    What do you want to scan?
                  </label>
                  <input
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    placeholder="Package name, file path, or directory..."
                    className="mt-3 w-full rounded-xl border border-[var(--sc-border)] bg-[var(--sc-bg-elevated)] px-4 py-3 text-sm text-[var(--sc-text-primary)] placeholder:text-[var(--sc-text-muted)] focus-ring-cyan"
                  />
                  <div className="mt-4 flex flex-wrap items-center gap-3">
                    <button
                      type="button"
                      onClick={() => pickTargetMutation.mutate('file', {
                        onSuccess: (r) => { if (r.path) setTarget(r.path); },
                      })}
                      className="inline-flex items-center gap-2 rounded-xl border border-[var(--sc-border)] bg-[var(--sc-surface-interactive)] px-4 py-2.5 text-sm font-medium text-[var(--sc-text-secondary)] transition-all hover:bg-[var(--sc-surface-interactive-hover)] hover:text-[var(--sc-text-primary)]"
                    >
                      <FileSearch size={14} /> Browse file
                    </button>
                    <button
                      type="button"
                      onClick={() => pickTargetMutation.mutate('folder', {
                        onSuccess: (r) => { if (r.path) setTarget(r.path); },
                      })}
                      className="inline-flex items-center gap-2 rounded-xl border border-[var(--sc-border)] bg-[var(--sc-surface-interactive)] px-4 py-2.5 text-sm font-medium text-[var(--sc-text-secondary)] transition-all hover:bg-[var(--sc-surface-interactive-hover)] hover:text-[var(--sc-text-primary)]"
                    >
                      <FolderSearch size={14} /> Browse folder
                    </button>
                    <label className="inline-flex items-center gap-2 rounded-xl border border-[var(--sc-border)] bg-[var(--sc-surface-interactive)] px-3 py-2.5 text-sm text-[var(--sc-text-secondary)]">
                      <input
                        type="checkbox"
                        checked={deep}
                        onChange={(e) => setDeep(e.target.checked)}
                        className="h-4 w-4 rounded border-[var(--sc-border)] accent-[var(--sc-cyan)]"
                      />
                      Deep scan
                      {!capabilities?.deepScan && <Lock size={12} className="text-[var(--sc-coral)]" />}
                    </label>
                    <Button type="submit" variant="coral" glow disabled={scanMutation.isPending || !target.trim()}>
                      {scanMutation.isPending ? 'Scanning\u2026' : 'Run Scan'}
                      <ArrowRight size={14} />
                    </Button>
                  </div>
                  <p className="mt-3 text-xs text-[var(--sc-text-muted)]">
                    Native macOS picker via local API, or paste a path / package name directly.
                  </p>
                </form>

                {pickTargetMutation.isError && (
                  <div className="mt-3 rounded-xl border border-[var(--sc-coral)]/20 bg-[var(--sc-coral)]/5 px-4 py-3 text-sm text-[var(--sc-coral)]">
                    {pickTargetMutation.error instanceof Error ? pickTargetMutation.error.message : 'Failed to open native picker'}
                  </div>
                )}

                {latestError && (
                  <div className={`mt-4 rounded-xl px-4 py-3 text-sm ${
                    isFeatureLocked
                      ? 'border border-[var(--sc-amber)]/20 bg-[var(--sc-amber)]/5 text-[var(--sc-amber)]'
                      : 'border border-[var(--sc-coral)]/20 bg-[var(--sc-coral)]/5 text-[var(--sc-coral)]'
                  }`}>
                    {latestError.message}
                  </div>
                )}
              </GlassCard>

              {/* Scan result */}
              <GlassCard className={`p-6 ${scanMutation.isPending ? 'scan-sweep' : ''}`}>
                <div className="flex items-center justify-between gap-3">
                  <h3 className="text-lg font-semibold text-[var(--sc-text-primary)]">Scan Result</h3>
                  <div className="flex gap-2">
                    <Badge variant="muted">{summary.total} scans</Badge>
                    <Badge variant="muted">Avg {summary.avgScore ?? '\u2014'}</Badge>
                  </div>
                </div>

                {!visibleResult ? (
                  <div className="mt-5 rounded-xl bg-[var(--sc-bg-elevated)] px-5 py-8 text-center text-sm text-[var(--sc-text-muted)]">
                    Run a scan or select one from history to see results here.
                  </div>
                ) : (
                  <div className="mt-5 space-y-4">
                    {/* Result header */}
                    <div className="flex items-start gap-6">
                      <TrustGauge score={visibleResult.trustScore} size={120} />
                      <div className="flex-1">
                        <div className="flex flex-wrap items-center gap-3">
                          <h4 className="text-lg font-semibold text-[var(--sc-text-primary)]">{visibleResult.target}</h4>
                          <Badge variant={riskVariant(visibleResult.riskLevel)}>{visibleResult.riskLevel}</Badge>
                        </div>
                        <div className="mt-2 flex flex-wrap gap-2">
                          <Badge variant="muted">{visibleResult.filesScanned} files</Badge>
                          <Badge variant="muted">{visibleResult.deepScan ? 'Deep' : 'Standard'}</Badge>
                          <Badge variant="muted">{formatDate(visibleResult.scannedAt)}</Badge>
                        </div>
                      </div>
                    </div>

                    {/* Findings */}
                    <div className="space-y-3">
                      {visibleResult.findings.length === 0 ? (
                        <div className="rounded-xl border border-[var(--sc-cyan)]/20 bg-[var(--sc-cyan)]/5 px-4 py-4 text-sm text-[var(--sc-cyan)]">
                          No findings detected. This target looks clean.
                        </div>
                      ) : (
                        visibleResult.findings.map((finding, i) => (
                          <GlassCard key={`${finding.title}-${i}`} severity={finding.severity as 'critical' | 'high' | 'medium' | 'low'} className="p-4">
                            <div className="flex flex-wrap items-center gap-2">
                              <Badge variant={riskVariant(finding.severity)}>{finding.severity}</Badge>
                              <Badge variant="muted">{finding.category}</Badge>
                            </div>
                            <p className="mt-2 text-sm font-semibold text-[var(--sc-text-primary)]">{finding.title}</p>
                            <p className="mt-1 text-sm text-[var(--sc-text-secondary)]">{finding.description}</p>
                            {(finding.file || finding.evidence) && (
                              <div className="mt-2 space-y-0.5 font-mono text-xs text-[var(--sc-text-muted)]">
                                {finding.file && <div>File: {finding.line ? `${finding.file}:${finding.line}` : finding.file}</div>}
                                {finding.evidence && <div>Evidence: {finding.evidence}</div>}
                              </div>
                            )}
                            <LocalAiFindingExplainer
                              finding={{
                                ...finding,
                                id: persistedFindings[i]?.id,
                                status: persistedFindings[i]?.status,
                              }}
                            />
                            {persistedFindings[i] && (
                              <div className="mt-3 border-t border-[var(--sc-border)] pt-3">
                                <FindingActions
                                  findingId={persistedFindings[i].id}
                                  status={persistedFindings[i].status}
                                  hasFile={!!finding.file}
                                  compact
                                />
                              </div>
                            )}
                          </GlassCard>
                        ))
                      )}
                    </div>
                  </div>
                )}
              </GlassCard>
            </div>

            {/* Right sidebar — capabilities & quick links */}
            <div className="space-y-4">
              <GlassCard strong className="p-5">
                <h4 className="text-xs font-semibold uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">
                  Capabilities
                </h4>
                <div className="mt-4 space-y-3">
                  {[
                    { label: 'Local scan', enabled: capabilities?.localScan ?? true },
                    { label: 'Watch mode', enabled: capabilities?.watchMode ?? true },
                    { label: 'Preinstall hook', enabled: capabilities?.preinstallHook ?? false },
                    { label: 'npm inspection', enabled: capabilities?.npmInspection ?? false },
                    { label: 'Deep scan', enabled: capabilities?.deepScan ?? false },
                  ].map((cap) => (
                    <div key={cap.label} className="flex items-center justify-between rounded-lg bg-[var(--sc-bg-elevated)] px-3 py-2">
                      <span className="text-sm text-[var(--sc-text-secondary)]">{cap.label}</span>
                      <Badge variant={cap.enabled ? 'cyan' : 'muted'} dot>{cap.enabled ? 'On' : 'Off'}</Badge>
                    </div>
                  ))}
                </div>
              </GlassCard>

              <GlassCard strong className="p-5">
                <h4 className="text-xs font-semibold uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">
                  Quick stats
                </h4>
                <div className="mt-4 space-y-3">
                  <div className="flex items-center justify-between rounded-lg bg-[var(--sc-bg-elevated)] px-3 py-2">
                    <span className="text-sm text-[var(--sc-text-secondary)]">Watch roots</span>
                    <span className="text-sm font-semibold text-[var(--sc-text-primary)]">{statusSummary?.activeWatchRoots ?? 0} active</span>
                  </div>
                  <div className="flex items-center justify-between rounded-lg bg-[var(--sc-bg-elevated)] px-3 py-2">
                    <span className="text-sm text-[var(--sc-text-secondary)]">Stale roots</span>
                    <span className="text-sm font-semibold text-[var(--sc-amber)]">{statusSummary?.staleWatchRoots ?? 0}</span>
                  </div>
                  <div className="flex items-center justify-between rounded-lg bg-[var(--sc-bg-elevated)] px-3 py-2">
                    <span className="text-sm text-[var(--sc-text-secondary)]">Blocked events</span>
                    <span className="text-sm font-semibold text-[var(--sc-coral)]">{statusSummary?.blockedEvents ?? 0}</span>
                  </div>
                </div>
              </GlassCard>
            </div>
          </div>
        )}

        {/* History tab */}
        {tab === 'history' && (
          <div className="space-y-4">
            {/* Filters */}
            <GlassCard className="p-4">
              <div className="grid gap-3 lg:grid-cols-[1fr_auto_auto]">
                <input
                  value={historySearch}
                  onChange={(e) => setHistorySearch(e.target.value)}
                  placeholder="Filter by file, folder, or package..."
                  className="rounded-xl border border-[var(--sc-border)] bg-[var(--sc-bg-elevated)] px-4 py-2.5 text-sm text-[var(--sc-text-primary)] placeholder:text-[var(--sc-text-muted)] focus-ring-cyan"
                />
                <select
                  value={historyRisk}
                  onChange={(e) => setHistoryRisk(e.target.value as typeof historyRisk)}
                  className="rounded-xl border border-[var(--sc-border)] bg-[var(--sc-bg-elevated)] px-4 py-2.5 text-sm text-[var(--sc-text-primary)]"
                >
                  <option value="ALL">All risk</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                  <option value="SAFE">Safe</option>
                </select>
                <select
                  value={historyTargetType}
                  onChange={(e) => setHistoryTargetType(e.target.value as typeof historyTargetType)}
                  className="rounded-xl border border-[var(--sc-border)] bg-[var(--sc-bg-elevated)] px-4 py-2.5 text-sm text-[var(--sc-text-primary)]"
                >
                  <option value="all">All targets</option>
                  <option value="file">Files</option>
                  <option value="dir">Directories</option>
                  <option value="npm">Packages</option>
                </select>
              </div>
              <div className="mt-3 flex gap-2">
                {(['all', 'true', 'false'] as const).map((v) => (
                  <button
                    key={v}
                    onClick={() => setHistoryDepth(v)}
                    className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-all ${
                      historyDepth === v
                        ? 'bg-[var(--sc-coral)] text-white'
                        : 'bg-[var(--sc-surface-interactive)] text-[var(--sc-text-muted)] hover:text-[var(--sc-text-secondary)]'
                    }`}
                  >
                    {v === 'all' ? 'All scans' : v === 'true' ? 'Deep only' : 'Standard only'}
                  </button>
                ))}
              </div>
            </GlassCard>

            {/* History list + detail */}
            <div className="grid gap-6 xl:grid-cols-[0.45fr_0.55fr]">
              <div className="space-y-3">
                {historyEntries.length === 0 ? (
                  <GlassCard className="p-5 text-center text-sm text-[var(--sc-text-muted)]">
                    No matching scan history yet.
                  </GlassCard>
                ) : (
                  historyEntries.map((entry) => (
                    <GlassCard
                      key={entry.id}
                      hover
                      selected={effectiveHistoryId === entry.id}
                      onClick={() => {
                        setSelectedHistoryId(entry.id);
                        setTarget(entry.target);
                        setDeep(entry.deepScan);
                      }}
                      className="p-4"
                    >
                      <div className="truncate text-sm font-semibold text-[var(--sc-text-primary)]">{entry.target}</div>
                      <div className="mt-1 text-xs text-[var(--sc-text-muted)]">{formatDate(entry.scannedAt)}</div>
                      <div className="mt-2 flex flex-wrap gap-2">
                        <Badge variant={riskVariant(entry.riskLevel)}>{entry.riskLevel}</Badge>
                        <Badge variant="muted">Score {entry.trustScore}</Badge>
                        <Badge variant="muted">{entry.findingCount} findings</Badge>
                      </div>
                    </GlassCard>
                  ))
                )}
              </div>

              {/* Detail panel */}
              {visibleResult ? (
                <GlassCard strong className="p-6">
                  <div className="flex items-start gap-5">
                    <TrustGauge score={visibleResult.trustScore} size={100} />
                    <div className="flex-1">
                      <h4 className="text-lg font-semibold text-[var(--sc-text-primary)]">{visibleResult.target}</h4>
                      <div className="mt-2 flex flex-wrap gap-2">
                        <Badge variant={riskVariant(visibleResult.riskLevel)}>{visibleResult.riskLevel}</Badge>
                        <Badge variant="muted">{visibleResult.filesScanned} files</Badge>
                        <Badge variant="muted">{visibleResult.deepScan ? 'Deep' : 'Standard'}</Badge>
                      </div>
                    </div>
                  </div>
                  <div className="mt-5 space-y-3">
                    {visibleResult.findings.length === 0 ? (
                      <div className="rounded-xl border border-[var(--sc-cyan)]/20 bg-[var(--sc-cyan)]/5 px-4 py-3 text-sm text-[var(--sc-cyan)]">
                        Clean — no findings.
                      </div>
                    ) : (
                      visibleResult.findings.map((f, i) => (
                        <GlassCard key={`${f.title}-${i}`} severity={f.severity as 'critical' | 'high' | 'medium' | 'low'} className="p-3">
                          <div className="flex items-center gap-2">
                            <Badge variant={riskVariant(f.severity)}>{f.severity}</Badge>
                            <span className="text-sm font-medium text-[var(--sc-text-primary)]">{f.title}</span>
                          </div>
                          <p className="mt-1 text-xs text-[var(--sc-text-secondary)]">{f.description}</p>
                          <LocalAiFindingExplainer finding={f} />
                        </GlassCard>
                      ))
                    )}
                  </div>
                </GlassCard>
              ) : (
                <GlassCard className="flex items-center justify-center p-8 text-sm text-[var(--sc-text-muted)]">
                  Select a scan from the list to view details.
                </GlassCard>
              )}
            </div>
          </div>
        )}

        {/* Watch tab */}
        {tab === 'watch' && (
          <div className="space-y-6">
            {/* Start new watch */}
            <GlassCard strong className="p-6">
              <h3 className="text-lg font-semibold text-[var(--sc-text-primary)]">Start Watching</h3>
              <p className="mt-1 text-sm text-[var(--sc-text-muted)]">
                Monitor a directory for file changes and automatically scan for threats in real-time.
              </p>
              <form
                className="mt-4 flex flex-wrap items-end gap-3"
                onSubmit={(e) => {
                  e.preventDefault();
                  if (!watchTarget.trim()) return;
                  startWatchMutation.mutate({ target: watchTarget.trim(), deep: watchDeep });
                }}
              >
                <div className="flex-1">
                  <input
                    value={watchTarget}
                    onChange={(e) => setWatchTarget(e.target.value)}
                    placeholder="Directory path, e.g. /Users/michael/Development/project"
                    className="w-full rounded-xl border border-[var(--sc-border)] bg-[var(--sc-bg-elevated)] px-4 py-3 text-sm text-[var(--sc-text-primary)] placeholder:text-[var(--sc-text-muted)] focus-ring-cyan"
                  />
                </div>
                <button
                  type="button"
                  onClick={() => pickTargetMutation.mutate('folder', {
                    onSuccess: (r) => { if (r.path) setWatchTarget(r.path); },
                  })}
                  className="inline-flex items-center gap-2 rounded-xl border border-[var(--sc-border)] bg-[var(--sc-surface-interactive)] px-4 py-3 text-sm font-medium text-[var(--sc-text-secondary)] transition-all hover:bg-[var(--sc-surface-interactive-hover)] hover:text-[var(--sc-text-primary)]"
                >
                  <FolderSearch size={14} /> Browse
                </button>
                <label className="inline-flex items-center gap-2 rounded-xl border border-[var(--sc-border)] bg-[var(--sc-surface-interactive)] px-3 py-3 text-sm text-[var(--sc-text-secondary)]">
                  <input
                    type="checkbox"
                    checked={watchDeep}
                    onChange={(e) => setWatchDeep(e.target.checked)}
                    className="h-4 w-4 rounded accent-[var(--sc-cyan)]"
                  />
                  Deep
                </label>
                <Button type="submit" variant="cyan" disabled={startWatchMutation.isPending || !watchTarget.trim()}>
                  {startWatchMutation.isPending ? 'Starting\u2026' : 'Start Watch'}
                  <Eye size={14} />
                </Button>
              </form>
              {startWatchMutation.isSuccess && (
                <p className="mt-3 text-sm text-[var(--sc-cyan)]">
                  Watching {startWatchMutation.data.root}
                </p>
              )}
              {startWatchMutation.isError && (
                <p className="mt-3 text-sm text-[var(--sc-coral)]">
                  {startWatchMutation.error instanceof Error ? startWatchMutation.error.message : 'Failed to start watch'}
                </p>
              )}
            </GlassCard>

            {/* Active watchers from this API server */}
            {activeWatchers.length > 0 && (
              <div>
                <h4 className="mb-3 text-sm font-semibold uppercase tracking-wider text-[var(--sc-text-muted)]">Active Watchers (This Session)</h4>
                <div className="grid gap-3 lg:grid-cols-2">
                  {activeWatchers.map((w) => (
                    <GlassCard key={w.root} className="flex items-center justify-between p-4">
                      <div className="min-w-0">
                        <p className="truncate text-sm font-semibold text-[var(--sc-text-primary)]">{w.root}</p>
                        <p className="text-xs text-[var(--sc-text-muted)]">PID {w.pid}</p>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant="cyan" dot pulse>Watching</Badge>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => stopWatchMutation.mutate(w.root)}
                          disabled={stopWatchMutation.isPending}
                        >
                          Stop
                        </Button>
                      </div>
                    </GlassCard>
                  ))}
                </div>
              </div>
            )}

            {/* Filter + session history */}
            <div className="flex items-center justify-between gap-3">
              <h4 className="text-sm font-semibold uppercase tracking-wider text-[var(--sc-text-muted)]">Session History</h4>
              <div className="flex gap-2">
                {(['all', 'active', 'stale', 'ended'] as const).map((s) => (
                  <button
                    key={s}
                    onClick={() => setWatchState(s)}
                    className={`rounded-lg px-3 py-1.5 text-xs font-medium capitalize transition-all ${
                      watchState === s
                        ? 'bg-[var(--sc-coral)] text-white'
                        : 'bg-[var(--sc-surface-interactive)] text-[var(--sc-text-muted)] hover:text-[var(--sc-text-secondary)]'
                    }`}
                  >
                    {s}
                  </button>
                ))}
              </div>
            </div>

            {watchSessions.length === 0 ? (
              <GlassCard className="p-8 text-center text-sm text-[var(--sc-text-muted)]">
                No watch sessions recorded yet. Start a watcher above or use <code className="font-mono text-[var(--sc-cyan)]">shieldcortex xray --watch ./src</code> from the CLI.
              </GlassCard>
            ) : (
              <div className="grid gap-4 lg:grid-cols-2">
                {watchSessions.map((session) => (
                  <GlassCard key={session.id} className="p-5">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <p className="truncate text-sm font-semibold text-[var(--sc-text-primary)]">{session.root}</p>
                        <p className="mt-1 text-xs text-[var(--sc-text-muted)]">Started {formatDate(session.startedAt)}</p>
                      </div>
                      <Badge
                        variant={session.state === 'active' ? 'cyan' : session.state === 'stale' ? 'amber' : 'muted'}
                        dot
                        pulse={session.state === 'active'}
                      >
                        {session.state}
                      </Badge>
                    </div>
                    <p className="mt-2 text-sm text-[var(--sc-text-secondary)]">{session.lastEventSummary ?? 'No detections yet'}</p>
                    <div className="mt-3 flex flex-wrap gap-2">
                      <Badge variant="muted">{session.changesDetected} changes</Badge>
                      <Badge variant="muted">{session.findingsDetected} findings</Badge>
                      <Badge variant={riskVariant(session.highestRiskLevel)}>{session.highestRiskLevel}</Badge>
                    </div>
                  </GlassCard>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Activity tab */}
        {tab === 'activity' && (
          <div className="space-y-4">
            <div className="flex gap-2">
              {(['all', 'scan', 'watch', 'preinstall'] as const).map((k) => (
                <button
                  key={k}
                  onClick={() => setActivityKind(k)}
                  className={`rounded-lg px-3 py-1.5 text-xs font-medium capitalize transition-all ${
                    activityKind === k
                      ? 'bg-[var(--sc-coral)] text-white'
                      : 'bg-[var(--sc-surface-interactive)] text-[var(--sc-text-muted)] hover:text-[var(--sc-text-secondary)]'
                  }`}
                >
                  {k === 'all' ? 'All activity' : k}
                </button>
              ))}
            </div>

            {activityEntries.length === 0 ? (
              <GlassCard className="p-8 text-center text-sm text-[var(--sc-text-muted)]">
                No matching automatic events yet.
              </GlassCard>
            ) : (
              <div className="space-y-3">
                {activityEntries.map((entry) => (
                  <GlassCard key={entry.id} className="p-4">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <Radar size={14} className="shrink-0 text-[var(--sc-coral)]" />
                          <span className="text-sm font-semibold capitalize text-[var(--sc-text-primary)]">{entry.kind}</span>
                        </div>
                        <p className="mt-1 truncate text-sm text-[var(--sc-text-secondary)]">{entry.target}</p>
                        <p className="mt-1 text-xs text-[var(--sc-text-muted)]">{entry.summary}</p>
                      </div>
                      <Badge
                        variant={
                          entry.status === 'pass' ? 'safe'
                            : entry.status === 'blocked' ? 'critical'
                              : entry.status === 'warn' ? 'medium'
                                : 'amber'
                        }
                      >
                        {entry.status}
                      </Badge>
                    </div>
                  </GlassCard>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Findings tab */}
        {tab === 'findings' && (
          <div className="space-y-4">
            {/* Stats summary */}
            {findingsStats && (
              <div className="flex flex-wrap gap-2">
                <Badge variant="coral">{findingsStats.new} new</Badge>
                <Badge variant="muted">{findingsStats.reviewed} reviewed</Badge>
                <Badge variant="cyan">{findingsStats.resolved} resolved</Badge>
                <Badge variant="amber">{findingsStats.quarantined} quarantined</Badge>
                <Badge variant="muted">{findingsStats.ignored} ignored</Badge>
                <Badge variant="muted">{findingsStats.total} total</Badge>
              </div>
            )}

            {/* Status filter bar */}
            <div className="flex flex-wrap gap-2">
              {([
                { key: 'new', label: 'Needs attention', accent: true },
                { key: 'reviewed', label: 'Reviewed', accent: false },
                { key: 'resolved', label: 'Resolved', accent: false },
                { key: 'ignored', label: 'Ignored', accent: false },
                { key: 'quarantined', label: 'Quarantined', accent: false },
                { key: 'all', label: 'Everything', accent: false },
              ] as const).map(({ key, label, accent }) => (
                <button
                  key={key}
                  onClick={() => setFindingsFilter(key)}
                  className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-all ${
                    findingsFilter === key
                      ? accent ? 'bg-[var(--sc-coral)] text-white' : 'bg-[var(--sc-cyan)] text-[var(--sc-bg-deep)]'
                      : 'bg-[var(--sc-surface-interactive)] text-[var(--sc-text-muted)] hover:text-[var(--sc-text-secondary)]'
                  }`}
                >
                  {label}
                  {key === 'new' && findingsStats && findingsStats.new > 0 && (
                    <span className="ml-1.5 rounded-full bg-white/20 px-1.5 py-0.5 text-[10px] font-bold">
                      {findingsStats.new}
                    </span>
                  )}
                </button>
              ))}
            </div>

            {/* Findings list */}
            {!findingsData?.findings || findingsData.findings.length === 0 ? (
              <GlassCard className="p-8 text-center">
                <p className="text-sm text-[var(--sc-text-primary)]">
                  {findingsFilter === 'new' ? 'All clear — no findings need attention' : `No ${findingsFilter === 'all' ? '' : findingsFilter + ' '}findings`}
                </p>
                <p className="mt-1 text-xs text-[var(--sc-text-muted)]">
                  {findingsFilter === 'new'
                    ? 'Run an X-Ray scan or start a watcher to monitor for threats.'
                    : 'Findings move here when you take action on them.'}
                </p>
              </GlassCard>
            ) : (
              <div className="space-y-3">
                {(findingsData.findings as (PersistedFinding & { guidance?: { whatItMeans: string; whatToDo: string; falsePositiveNote: string; urgency: string }; systemFile?: boolean })[]).map((finding) => (
                  <GlassCard
                    key={finding.id}
                    severity={finding.severity as 'critical' | 'high' | 'medium' | 'low'}
                    className="p-5"
                  >
                    {/* Header row */}
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge variant={riskVariant(finding.severity)}>{finding.severity}</Badge>
                      <Badge variant="muted">{finding.category}</Badge>
                      {finding.systemFile && (
                        <Badge variant="muted">System file — likely safe</Badge>
                      )}
                      {finding.guidance?.urgency === 'usually-safe' && !finding.systemFile && (
                        <Badge variant="cyan">Usually safe</Badge>
                      )}
                      {finding.guidance?.urgency === 'act-now' && (
                        <Badge variant="critical" dot pulse>Act now</Badge>
                      )}
                    </div>

                    {/* Title */}
                    <p className="mt-3 text-sm font-semibold text-[var(--sc-text-primary)]">{finding.title}</p>

                    {/* Guidance — the human-readable explanation */}
                    {finding.guidance && (
                      <div className="mt-3 space-y-3 rounded-xl bg-[var(--sc-bg-elevated)] p-4">
                        <div>
                          <p className="text-[11px] font-semibold uppercase tracking-wider text-[var(--sc-text-muted)]">What this means</p>
                          <p className="mt-1 text-sm leading-relaxed text-[var(--sc-text-secondary)]">{finding.guidance.whatItMeans}</p>
                        </div>
                        <div>
                          <p className="text-[11px] font-semibold uppercase tracking-wider text-[var(--sc-cyan)]">What to do</p>
                          <p className="mt-1 text-sm leading-relaxed text-[var(--sc-text-secondary)]">{finding.guidance.whatToDo}</p>
                        </div>
                        <div>
                          <p className="text-[11px] font-semibold uppercase tracking-wider text-[var(--sc-text-muted)]">False positive?</p>
                          <p className="mt-1 text-xs leading-relaxed text-[var(--sc-text-muted)]">{finding.guidance.falsePositiveNote}</p>
                        </div>
                      </div>
                    )}

                    {/* File + evidence */}
                    {(finding.file || finding.evidence) && (
                      <div className="mt-3 space-y-0.5 font-mono text-xs text-[var(--sc-text-muted)]">
                        {finding.file && (
                          <div>File: {finding.line ? `${finding.file}:${finding.line}` : finding.file}</div>
                        )}
                        {finding.evidence && <div>Evidence: {finding.evidence}</div>}
                      </div>
                    )}

                    <LocalAiFindingExplainer finding={finding} />

                    {/* Timestamp */}
                    <div className="mt-2 text-xs text-[var(--sc-text-muted)]">
                      {formatDate(finding.detectedAt)}
                    </div>

                    {/* Actions */}
                    <div className="mt-3 border-t border-[var(--sc-border)] pt-3">
                      <FindingActions
                        findingId={finding.id}
                        status={finding.status}
                        hasFile={!!finding.file}
                        compact
                      />
                    </div>
                  </GlassCard>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
