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
  ShieldCheck,
} from 'lucide-react';
import { toast } from 'sonner';
import { FeatureLockedError } from '@/lib/auth';
import { useWebSocketEvent } from '@/components/MemoryWebSocketProvider';
import { GlassCard } from '@/components/ds/GlassCard';
import { Badge, riskVariant } from '@/components/ds/Badge';
import { Button } from '@/components/ds/Button';
import { CardError } from '@/components/ds/CardError';
import { Drawer } from '@/components/ds/Drawer';
import { PageHeader } from '@/components/ds/PageHeader';
import { StatCard } from '@/components/ds/StatCard';
import { Table, type Column } from '@/components/ds/Table';
import { FindingActions } from '@/components/xray/FindingActions';
import { LocalAiFindingExplainer } from '@/components/xray/LocalAiFindingExplainer';

/** Trust score accent (brief §8: trust gauge -> StatTile — a plain number
 *  fits the rest of the dashboard's decision-first stat tiles better than a
 *  bespoke circular gauge). */
function trustAccent(score: number): 'coral' | 'amber' | 'cyan' {
  if (score <= 50) return 'coral';
  if (score <= 75) return 'amber';
  return 'cyan';
}
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

type FindingRow = PersistedFinding & {
  guidance?: { whatItMeans: string; whatToDo: string; falsePositiveNote: string; urgency: string };
  systemFile?: boolean;
};

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
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);

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
  const {
    data: findingsData,
    isLoading: findingsLoading,
    isError: findingsError,
    error: findingsErrorObj,
    refetch: refetchFindings,
  } = useXRayFindingsList({ status: findingsFilter === 'all' ? undefined : findingsFilter });

  const findings = useMemo(() => (findingsData?.findings as FindingRow[] | undefined) ?? [], [findingsData]);
  const selectedFinding = findings.find((f) => f.id === selectedFindingId) ?? null;
  const findingColumns: Column<FindingRow>[] = useMemo(
    () => [
      {
        key: 'severity',
        header: 'Severity',
        cell: (f) => <Badge variant={riskVariant(f.severity)}>{f.severity}</Badge>,
        sortValue: (f) => f.severity,
      },
      { key: 'title', header: 'Finding', cell: (f) => <span className="text-[var(--sc-text)]">{f.title}</span>, sortValue: (f) => f.title },
      { key: 'category', header: 'Category', cell: (f) => f.category, sortValue: (f) => f.category },
      {
        key: 'file',
        header: 'File',
        cell: (f) => (f.file ? <span className="font-mono text-xs">{f.line ? `${f.file}:${f.line}` : f.file}</span> : '—'),
        className: 'max-w-xs truncate',
      },
      {
        key: 'detectedAt',
        header: 'Detected',
        cell: (f) => formatDate(f.detectedAt),
        sortValue: (f) => new Date(f.detectedAt).getTime(),
        className: 'whitespace-nowrap text-[var(--sc-text-dim)]',
      },
    ],
    [],
  );

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

  useWebSocketEvent((event) => {
    if (event.type === 'xray_detection') {
      const d = event.data as { summary?: string; riskLevel?: string };
      toast.warning(d.summary || 'X-Ray detection', {
        description: `Risk: ${d.riskLevel || 'unknown'}`,
        duration: 8000,
      });
    }
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
                  <label className="text-sm font-semibold text-[var(--sc-text)]">
                    What do you want to scan?
                  </label>
                  <input
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    placeholder="Package name, file path, or directory..."
                    className="mt-3 w-full rounded-xl border border-[var(--sc-border)] bg-[var(--sc-surface-2)] px-4 py-3 text-sm text-[var(--sc-text)] placeholder:text-[var(--sc-text-muted)] focus-ring-cyan"
                  />
                  <div className="mt-4 flex flex-wrap items-center gap-3">
                    <button
                      type="button"
                      onClick={() => pickTargetMutation.mutate('file', {
                        onSuccess: (r) => { if (r.path) setTarget(r.path); },
                      })}
                      className="inline-flex items-center gap-2 rounded-xl border border-[var(--sc-border)] bg-[var(--sc-surface-interactive)] px-4 py-2.5 text-sm font-medium text-[var(--sc-text-dim)] transition-all hover:bg-[var(--sc-surface-interactive-hover)] hover:text-[var(--sc-text)]"
                    >
                      <FileSearch size={14} /> Browse file
                    </button>
                    <button
                      type="button"
                      onClick={() => pickTargetMutation.mutate('folder', {
                        onSuccess: (r) => { if (r.path) setTarget(r.path); },
                      })}
                      className="inline-flex items-center gap-2 rounded-xl border border-[var(--sc-border)] bg-[var(--sc-surface-interactive)] px-4 py-2.5 text-sm font-medium text-[var(--sc-text-dim)] transition-all hover:bg-[var(--sc-surface-interactive-hover)] hover:text-[var(--sc-text)]"
                    >
                      <FolderSearch size={14} /> Browse folder
                    </button>
                    <label className="inline-flex items-center gap-2 rounded-xl border border-[var(--sc-border)] bg-[var(--sc-surface-interactive)] px-3 py-2.5 text-sm text-[var(--sc-text-dim)]">
                      <input
                        type="checkbox"
                        checked={deep}
                        onChange={(e) => setDeep(e.target.checked)}
                        className="h-4 w-4 rounded border-[var(--sc-border)] accent-[var(--sc-ok)]"
                      />
                      Deep scan
                      {!capabilities?.deepScan && <Lock size={12} className="text-[var(--sc-danger)]" />}
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
                  <div className="mt-3 rounded-xl border border-[var(--sc-danger)]/20 bg-[var(--sc-danger)]/5 px-4 py-3 text-sm text-[var(--sc-danger)]">
                    {pickTargetMutation.error instanceof Error ? pickTargetMutation.error.message : 'Failed to open native picker'}
                  </div>
                )}

                {latestError && (
                  <div className={`mt-4 rounded-xl px-4 py-3 text-sm ${
                    isFeatureLocked
                      ? 'border border-[var(--sc-amber)]/20 bg-[var(--sc-amber)]/5 text-[var(--sc-amber)]'
                      : 'border border-[var(--sc-danger)]/20 bg-[var(--sc-danger)]/5 text-[var(--sc-danger)]'
                  }`}>
                    {latestError.message}
                  </div>
                )}
              </GlassCard>

              {/* Scan result */}
              <GlassCard className={`p-6 ${scanMutation.isPending ? 'scan-sweep' : ''}`}>
                <div className="flex items-center justify-between gap-3">
                  <h3 className="text-lg font-semibold text-[var(--sc-text)]">Scan Result</h3>
                  <div className="flex gap-2">
                    <Badge variant="muted">{summary.total} scans</Badge>
                    <Badge variant="muted">Avg {summary.avgScore ?? '\u2014'}</Badge>
                  </div>
                </div>

                {!visibleResult ? (
                  <div className="mt-5 rounded-xl bg-[var(--sc-surface-2)] px-5 py-8 text-center text-sm text-[var(--sc-text-muted)]">
                    Run a scan or select one from history to see results here.
                  </div>
                ) : (
                  <div className="mt-5 space-y-4">
                    {/* Result header */}
                    <div className="flex items-start gap-4">
                      <StatCard
                        label="Trust score"
                        value={visibleResult.trustScore}
                        icon={ShieldCheck}
                        accent={trustAccent(visibleResult.trustScore)}
                        className="w-32 shrink-0"
                      />
                      <div className="flex-1 min-w-0">
                        <div className="flex flex-wrap items-center gap-3">
                          <h4 className="min-w-0 break-words text-lg font-semibold text-[var(--sc-text)]">{visibleResult.target}</h4>
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
                        <div className="rounded-xl border border-[var(--sc-ok)]/20 bg-[var(--sc-ok)]/5 px-4 py-4 text-sm text-[var(--sc-ok)]">
                          No findings detected. This target looks clean.
                        </div>
                      ) : (
                        visibleResult.findings.map((finding, i) => (
                          <GlassCard key={`${finding.title}-${i}`} severity={finding.severity as 'critical' | 'high' | 'medium' | 'low'} className="p-4">
                            <div className="flex flex-wrap items-center gap-2">
                              <Badge variant={riskVariant(finding.severity)}>{finding.severity}</Badge>
                              <Badge variant="muted">{finding.category}</Badge>
                            </div>
                            <p className="mt-2 text-sm font-semibold text-[var(--sc-text)]">{finding.title}</p>
                            <p className="mt-1 text-sm text-[var(--sc-text-dim)]">{finding.description}</p>
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
                              target={visibleResult.target}
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
                    <div key={cap.label} className="flex items-center justify-between rounded-lg bg-[var(--sc-surface-2)] px-3 py-2">
                      <span className="text-sm text-[var(--sc-text-dim)]">{cap.label}</span>
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
                  <div className="flex items-center justify-between rounded-lg bg-[var(--sc-surface-2)] px-3 py-2">
                    <span className="text-sm text-[var(--sc-text-dim)]">Watch roots</span>
                    <span className="text-sm font-semibold text-[var(--sc-text)]">{statusSummary?.activeWatchRoots ?? 0} active</span>
                  </div>
                  <div className="flex items-center justify-between rounded-lg bg-[var(--sc-surface-2)] px-3 py-2">
                    <span className="text-sm text-[var(--sc-text-dim)]">Stale roots</span>
                    <span className="text-sm font-semibold text-[var(--sc-amber)]">{statusSummary?.staleWatchRoots ?? 0}</span>
                  </div>
                  <div className="flex items-center justify-between rounded-lg bg-[var(--sc-surface-2)] px-3 py-2">
                    <span className="text-sm text-[var(--sc-text-dim)]">Blocked events</span>
                    <span className="text-sm font-semibold text-[var(--sc-danger)]">{statusSummary?.blockedEvents ?? 0}</span>
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
                  className="rounded-xl border border-[var(--sc-border)] bg-[var(--sc-surface-2)] px-4 py-2.5 text-sm text-[var(--sc-text)] placeholder:text-[var(--sc-text-muted)] focus-ring-cyan"
                />
                <select
                  value={historyRisk}
                  onChange={(e) => setHistoryRisk(e.target.value as typeof historyRisk)}
                  className="rounded-xl border border-[var(--sc-border)] bg-[var(--sc-surface-2)] px-4 py-2.5 text-sm text-[var(--sc-text)]"
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
                  className="rounded-xl border border-[var(--sc-border)] bg-[var(--sc-surface-2)] px-4 py-2.5 text-sm text-[var(--sc-text)]"
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
                        ? 'bg-[var(--sc-danger)] text-white'
                        : 'bg-[var(--sc-surface-interactive)] text-[var(--sc-text-muted)] hover:text-[var(--sc-text-dim)]'
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
                      <div className="truncate text-sm font-semibold text-[var(--sc-text)]">{entry.target}</div>
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
                  <div className="flex items-start gap-4">
                    <StatCard
                      label="Trust score"
                      value={visibleResult.trustScore}
                      icon={ShieldCheck}
                      accent={trustAccent(visibleResult.trustScore)}
                      className="w-32 shrink-0"
                    />
                    <div className="flex-1 min-w-0">
                      <h4 className="break-words text-lg font-semibold text-[var(--sc-text)]">{visibleResult.target}</h4>
                      <div className="mt-2 flex flex-wrap gap-2">
                        <Badge variant={riskVariant(visibleResult.riskLevel)}>{visibleResult.riskLevel}</Badge>
                        <Badge variant="muted">{visibleResult.filesScanned} files</Badge>
                        <Badge variant="muted">{visibleResult.deepScan ? 'Deep' : 'Standard'}</Badge>
                      </div>
                    </div>
                  </div>
                  <div className="mt-5 space-y-3">
                    {visibleResult.findings.length === 0 ? (
                      <div className="rounded-xl border border-[var(--sc-ok)]/20 bg-[var(--sc-ok)]/5 px-4 py-3 text-sm text-[var(--sc-ok)]">
                        Clean — no findings.
                      </div>
                    ) : (
                      visibleResult.findings.map((f, i) => (
                        <GlassCard key={`${f.title}-${i}`} severity={f.severity as 'critical' | 'high' | 'medium' | 'low'} className="p-3">
                          <div className="flex items-center gap-2">
                            <Badge variant={riskVariant(f.severity)}>{f.severity}</Badge>
                            <span className="text-sm font-medium text-[var(--sc-text)]">{f.title}</span>
                          </div>
                          <p className="mt-1 text-xs text-[var(--sc-text-dim)]">{f.description}</p>
                          <LocalAiFindingExplainer finding={f} target={visibleResult.target} />
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
              <h3 className="text-lg font-semibold text-[var(--sc-text)]">Start Watching</h3>
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
                    className="w-full rounded-xl border border-[var(--sc-border)] bg-[var(--sc-surface-2)] px-4 py-3 text-sm text-[var(--sc-text)] placeholder:text-[var(--sc-text-muted)] focus-ring-cyan"
                  />
                </div>
                <button
                  type="button"
                  onClick={() => pickTargetMutation.mutate('folder', {
                    onSuccess: (r) => { if (r.path) setWatchTarget(r.path); },
                  })}
                  className="inline-flex items-center gap-2 rounded-xl border border-[var(--sc-border)] bg-[var(--sc-surface-interactive)] px-4 py-3 text-sm font-medium text-[var(--sc-text-dim)] transition-all hover:bg-[var(--sc-surface-interactive-hover)] hover:text-[var(--sc-text)]"
                >
                  <FolderSearch size={14} /> Browse
                </button>
                <label className="inline-flex items-center gap-2 rounded-xl border border-[var(--sc-border)] bg-[var(--sc-surface-interactive)] px-3 py-3 text-sm text-[var(--sc-text-dim)]">
                  <input
                    type="checkbox"
                    checked={watchDeep}
                    onChange={(e) => setWatchDeep(e.target.checked)}
                    className="h-4 w-4 rounded accent-[var(--sc-ok)]"
                  />
                  Deep
                </label>
                <Button type="submit" variant="cyan" disabled={startWatchMutation.isPending || !watchTarget.trim()}>
                  {startWatchMutation.isPending ? 'Starting\u2026' : 'Start Watch'}
                  <Eye size={14} />
                </Button>
              </form>
              {startWatchMutation.isSuccess && (
                <p className="mt-3 text-sm text-[var(--sc-ok)]">
                  Watching {startWatchMutation.data.root}
                </p>
              )}
              {startWatchMutation.isError && (
                <p className="mt-3 text-sm text-[var(--sc-danger)]">
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
                        <p className="truncate text-sm font-semibold text-[var(--sc-text)]">{w.root}</p>
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
                        ? 'bg-[var(--sc-danger)] text-white'
                        : 'bg-[var(--sc-surface-interactive)] text-[var(--sc-text-muted)] hover:text-[var(--sc-text-dim)]'
                    }`}
                  >
                    {s}
                  </button>
                ))}
              </div>
            </div>

            {watchSessions.length === 0 ? (
              <GlassCard className="p-8 text-center text-sm text-[var(--sc-text-muted)]">
                No watch sessions recorded yet. Start a watcher above or use <code className="font-mono text-[var(--sc-ok)]">shieldcortex xray --watch ./src</code> from the CLI.
              </GlassCard>
            ) : (
              <div className="grid gap-4 lg:grid-cols-2">
                {watchSessions.map((session) => (
                  <GlassCard key={session.id} className="p-5">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <p className="truncate text-sm font-semibold text-[var(--sc-text)]">{session.root}</p>
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
                    <p className="mt-2 text-sm text-[var(--sc-text-dim)]">{session.lastEventSummary ?? 'No detections yet'}</p>
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
                      ? 'bg-[var(--sc-danger)] text-white'
                      : 'bg-[var(--sc-surface-interactive)] text-[var(--sc-text-muted)] hover:text-[var(--sc-text-dim)]'
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
                          <Radar size={14} className="shrink-0 text-[var(--sc-danger)]" />
                          <span className="text-sm font-semibold capitalize text-[var(--sc-text)]">{entry.kind}</span>
                        </div>
                        <p className="mt-1 truncate text-sm text-[var(--sc-text-dim)]">{entry.target}</p>
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
                      ? accent ? 'bg-[var(--sc-danger)] text-white' : 'bg-[var(--sc-ok)] text-[var(--sc-bg)]'
                      : 'bg-[var(--sc-surface-interactive)] text-[var(--sc-text-muted)] hover:text-[var(--sc-text-dim)]'
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

            {/* Findings: one Table, click a row for the full guidance/
                evidence/explainer/actions in a drawer (brief §8). */}
            {findingsError ? (
              <CardError
                message={`Failed to load findings: ${findingsErrorObj instanceof Error ? findingsErrorObj.message : 'fetch failed'}`}
                onRetry={() => refetchFindings()}
              />
            ) : (
              <Table
                columns={findingColumns}
                rows={findings}
                rowKey={(f) => f.id}
                onRowClick={(f) => setSelectedFindingId(f.id)}
                selectedKey={selectedFindingId}
                loading={findingsLoading}
                emptyMessage={
                  findingsFilter === 'new'
                    ? 'All clear — no findings need attention. Run an X-Ray scan or start a watcher to monitor for threats.'
                    : `No ${findingsFilter === 'all' ? '' : findingsFilter + ' '}findings — they move here when you take action on them.`
                }
                initialSort={{ key: 'detectedAt', dir: 'desc' }}
              />
            )}

            <Drawer open={selectedFinding !== null} onClose={() => setSelectedFindingId(null)} title={selectedFinding?.title} modal={false}>
              {selectedFinding && (
                <div className="space-y-4 text-sm">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge variant={riskVariant(selectedFinding.severity)}>{selectedFinding.severity}</Badge>
                    <Badge variant="muted">{selectedFinding.category}</Badge>
                    {selectedFinding.systemFile && <Badge variant="muted">System file — likely safe</Badge>}
                    {selectedFinding.guidance?.urgency === 'usually-safe' && !selectedFinding.systemFile && (
                      <Badge variant="cyan">Usually safe</Badge>
                    )}
                    {selectedFinding.guidance?.urgency === 'act-now' && (
                      <Badge variant="critical" dot pulse>Act now</Badge>
                    )}
                  </div>

                  {selectedFinding.guidance && (
                    <div className="space-y-3 rounded-xl bg-[var(--sc-surface-2)] p-4">
                      <div>
                        <p className="text-[11px] font-semibold uppercase tracking-wider text-[var(--sc-text-muted)]">What this means</p>
                        <p className="mt-1 text-sm leading-relaxed text-[var(--sc-text-dim)]">{selectedFinding.guidance.whatItMeans}</p>
                      </div>
                      <div>
                        <p className="text-[11px] font-semibold uppercase tracking-wider text-[var(--sc-ok)]">What to do</p>
                        <p className="mt-1 text-sm leading-relaxed text-[var(--sc-text-dim)]">{selectedFinding.guidance.whatToDo}</p>
                      </div>
                      <div>
                        <p className="text-[11px] font-semibold uppercase tracking-wider text-[var(--sc-text-muted)]">False positive?</p>
                        <p className="mt-1 text-xs leading-relaxed text-[var(--sc-text-muted)]">{selectedFinding.guidance.falsePositiveNote}</p>
                      </div>
                    </div>
                  )}

                  {(selectedFinding.file || selectedFinding.evidence) && (
                    <div className="space-y-0.5 font-mono text-xs text-[var(--sc-text-muted)]">
                      {selectedFinding.file && (
                        <div>File: {selectedFinding.line ? `${selectedFinding.file}:${selectedFinding.line}` : selectedFinding.file}</div>
                      )}
                      {selectedFinding.evidence && <div>Evidence: {selectedFinding.evidence}</div>}
                    </div>
                  )}

                  <LocalAiFindingExplainer finding={selectedFinding} />

                  <div className="text-xs text-[var(--sc-text-muted)]">{formatDate(selectedFinding.detectedAt)}</div>

                  <div className="border-t border-[var(--sc-border)] pt-3">
                    <FindingActions
                      findingId={selectedFinding.id}
                      status={selectedFinding.status}
                      hasFile={!!selectedFinding.file}
                      compact
                    />
                  </div>
                </div>
              )}
            </Drawer>
          </div>
        )}
      </div>
    </div>
  );
}
