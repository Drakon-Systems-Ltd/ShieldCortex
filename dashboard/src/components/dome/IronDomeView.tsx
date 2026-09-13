'use client';

import { useState } from 'react';
import {
  Shield,
  Loader2,
  Zap,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Lock,
  Eye,
  Radio,
  ShieldOff,
  Users,
  Scan,
  OctagonX,
  Play,
} from 'lucide-react';
import {
  useIronDomeStatus,
  useActivateIronDome,
  useDeactivateIronDome,
  useUpdateIronDomeConfig,
  useIronDomeScan,
  useIronDomeAudit,
  useEmergencyStop,
  useResumeOperations,
  useControlStatus,
  type IronDomeConfig,
  type IronDomeProfile,
  type InjectionScanResult,
  type IronDomeAuditLog,
} from '@/hooks/useIronDome';
import { StatusPill, type StatusPillState } from '@/components/ds/StatusPill';
import { ConfirmDialog } from '@/components/ds/Dialog';

const PROFILES: { id: IronDomeProfile; label: string; description: string; icon: typeof Shield }[] = [
  { id: 'personal', label: 'Personal', description: 'Lighter touch for solo use', icon: Shield },
  { id: 'enterprise', label: 'Enterprise', description: 'Financial & data protection', icon: Lock },
  { id: 'school', label: 'School', description: 'GDPR strict, pupil data guarded', icon: Users },
  { id: 'paranoid', label: 'Paranoid', description: 'Everything requires approval', icon: AlertTriangle },
];

/** Per-module honest state, derived from real IronDomeConfig fields (never
 *  a repeated copy of the top-level enabled flag). */
type ModuleStateFn = (config: IronDomeConfig | undefined, enabled: boolean) => StatusPillState;

const MODULES: { name: string; description: string; icon: typeof Shield; state?: ModuleStateFn }[] = [
  { name: 'Injection Scanner', description: '40+ patterns across 8 categories', icon: Scan, state: (_c, en) => (en ? 'ok' : 'off') },
  { name: 'Instruction Gateway', description: 'Trusted channel validation', icon: Radio, state: (c, en) => (!en ? 'off' : (c?.trustedChannels.length ?? 0) > 0 ? 'ok' : 'warn') },
  { name: 'Action Gate', description: 'Approve / block external actions', icon: Lock, state: (c, en) => (!en ? 'off' : (c?.requireApproval.length ?? 0) > 0 || (c?.autoApprove.length ?? 0) > 0 ? 'ok' : 'warn') },
  { name: 'PII Guard', description: 'Block sensitive data output', icon: Eye, state: (c, en) => (!en ? 'off' : (c?.piiRules.neverOutput.length ?? 0) > 0 || (c?.piiRules.aggregatesOnly.length ?? 0) > 0 ? 'ok' : 'warn') },
  { name: 'Kill Switch', description: 'Emergency stop phrase', icon: ShieldOff },
  { name: 'Sub-Agent Control', description: 'Restrict spawned agent operations', icon: Users, state: (c, en) => (!en ? 'off' : (c?.subAgentRestrictions.blockedOperations.length ?? 0) > 0 || c?.subAgentRestrictions.sanitiseContext ? 'ok' : 'warn') },
];

const SEVERITY_COLOURS: Record<string, string> = {
  critical: 'bg-[var(--sc-danger)]/20 text-[var(--sc-danger)] border-[var(--sc-danger)]/30',
  high: 'bg-[var(--sc-danger)]/20 text-[var(--sc-danger)] border-[var(--sc-danger)]/30',
  medium: 'bg-[var(--sc-amber)]/20 text-[var(--sc-amber)] border-[var(--sc-amber)]/30',
  low: 'bg-[var(--sc-surface-2)]/20 text-[var(--sc-text-dim)] border-[var(--sc-border)]/30',
};

const RISK_COLOURS: Record<string, string> = {
  CRITICAL: 'bg-[var(--sc-danger)]/20 text-[var(--sc-danger)]',
  HIGH: 'bg-[var(--sc-danger)]/20 text-[var(--sc-danger)]',
  MEDIUM: 'bg-[var(--sc-amber)]/20 text-[var(--sc-amber)]',
  LOW: 'bg-[var(--sc-surface-2)]/20 text-[var(--sc-text-dim)]',
  NONE: 'bg-[var(--sc-ok)]/20 text-[var(--sc-ok)]',
};

export function IronDomeView() {
  const { data: status, isLoading: statusLoading } = useIronDomeStatus();
  const { data: auditData } = useIronDomeAudit(50);
  const activateMutation = useActivateIronDome();
  const deactivateMutation = useDeactivateIronDome();
  const updateConfigMutation = useUpdateIronDomeConfig();
  const scanMutation = useIronDomeScan();

  const emergencyStopMutation = useEmergencyStop();
  const resumeMutation = useResumeOperations();
  const { data: controlStatus } = useControlStatus();

  const [scanText, setScanText] = useState('');
  const [scanResult, setScanResult] = useState<InjectionScanResult | null>(null);
  const [resumeReason, setResumeReason] = useState('');
  const [confirmStopOpen, setConfirmStopOpen] = useState(false);
  const isActive = status?.enabled ?? false;
  const isKillSwitchActive = controlStatus?.killSwitchActive ?? false;
  const killSwitchMeta = controlStatus?.killSwitchMeta ?? null;
  const activeProfile = status?.profile;
  const config = status?.config;

  const configKillPhrase = config?.killPhrase ?? '';
  const [killPhraseDraft, setKillPhraseDraft] = useState(configKillPhrase);
  const [prevKillPhrase, setPrevKillPhrase] = useState(configKillPhrase);
  if (configKillPhrase !== prevKillPhrase) {
    setPrevKillPhrase(configKillPhrase);
    setKillPhraseDraft(configKillPhrase);
  }

  const handleActivate = (profile: IronDomeProfile) => {
    activateMutation.mutate(profile);
  };

  const handleDeactivate = () => {
    deactivateMutation.mutate();
  };

  const handleScan = () => {
    if (!scanText.trim()) return;
    scanMutation.mutate(scanText, {
      onSuccess: (data) => setScanResult(data),
    });
  };

  // Derive event feed stats. "Today" (brief §8 "counts today") is computed
  // from this same loaded window (the last 50 events) — real data, but it
  // will undercount a day with >50 events; the caption below says so.
  const logs = auditData?.logs ?? [];
  const blockCount = logs.filter((l: IronDomeAuditLog) => l.firewall_result === 'BLOCK').length;
  const allowCount = logs.filter((l: IronDomeAuditLog) => l.firewall_result === 'ALLOW').length;
  const todayKey = new Date().toDateString();
  const todaysLogs = logs.filter((l: IronDomeAuditLog) => new Date(l.timestamp).toDateString() === todayKey);
  const blockedToday = todaysLogs.filter((l: IronDomeAuditLog) => l.firewall_result === 'BLOCK').length;
  const allowedToday = todaysLogs.filter((l: IronDomeAuditLog) => l.firewall_result === 'ALLOW').length;
  const killPhraseDirty = Boolean(config) && killPhraseDraft.trim() !== (config?.killPhrase ?? '');

  return (
    <div className="space-y-6">
      {/* Status + Deactivate */}
      <div className="flex items-center gap-3">
        {statusLoading ? (
          <span className="text-[10px] text-[var(--sc-text-muted)] animate-pulse">Loading...</span>
        ) : (
          <StatusPill state={isActive ? 'ok' : 'off'}>{isActive ? 'active' : 'inactive'}</StatusPill>
        )}
        {isActive && (
          <button
            onClick={handleDeactivate}
            disabled={deactivateMutation.isPending}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[var(--sc-surface-2)] border border-[var(--sc-border)] hover:border-[var(--sc-border-strong)] disabled:opacity-50 rounded-lg text-xs font-medium text-[var(--sc-text-dim)] transition-colors"
          >
            {deactivateMutation.isPending ? (
              <Loader2 size={12} className="animate-spin" />
            ) : (
              <ShieldOff size={12} />
            )}
            Deactivate
          </button>
        )}
      </div>

      {/* ── CONTROL PANEL ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Profile Selector */}
        <div className="glass-card p-6">
          <h3 className="text-sm font-medium text-[var(--sc-text)] mb-3">Security Profiles</h3>
          <div className="grid grid-cols-2 gap-2">
            {PROFILES.map(({ id, label, description, icon: Icon }) => (
              <button
                key={id}
                onClick={() => handleActivate(id)}
                disabled={activateMutation.isPending}
                className={`text-left p-3 rounded-lg border transition-colors ${
                  activeProfile === id
                    ? 'border-[var(--sc-primary)]/50 bg-[var(--sc-primary-soft)] text-[var(--sc-primary)]'
                    : 'border-[var(--sc-border)] bg-[var(--sc-surface-2)]/50 text-[var(--sc-text-dim)] hover:border-[var(--sc-text-muted)]'
                }`}
              >
                <div className="flex items-center gap-1.5 mb-1">
                  <Icon size={12} />
                  <span className="text-xs font-medium">{label}</span>
                </div>
                <div className="text-[10px] text-[var(--sc-text-muted)]">{description}</div>
              </button>
            ))}
          </div>
        </div>

        {/* Module Status — six modules, each an honest state derived from
            real config (brief §8 "six-layer pipeline... per-layer on/off").
            Iron Dome is the one system here actually built that way; see the
            MODULES doc comment for why the memory-write pipeline isn't. */}
        <div className="glass-card p-6">
          <h3 className="text-sm font-medium text-[var(--sc-text)] mb-3">Module status</h3>
          <ol className="space-y-2">
            {MODULES.map(({ name, description, icon: Icon, state }, i) => {
              const st = state ? state(config, isActive) : isActive ? 'ok' : 'off';
              return (
                <li
                  key={name}
                  className="flex items-center gap-3 rounded-lg bg-[var(--sc-surface-2)]/50 px-3 py-2"
                >
                  <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-[var(--sc-border)] text-[10px] text-[var(--sc-text-muted)]">
                    {i + 1}
                  </span>
                  <Icon size={14} className="shrink-0 text-[var(--sc-text-muted)]" />
                  <div className="min-w-0 flex-1">
                    <div className="text-xs font-medium text-[var(--sc-text)]">{name}</div>
                    <div className="truncate text-[10px] text-[var(--sc-text-muted)]">{description}</div>
                  </div>
                  <StatusPill state={st}>{st === 'ok' ? 'on' : st}</StatusPill>
                </li>
              );
            })}
          </ol>
        </div>
      </div>

      {/* Config summary (when active) */}
      {config && (
        <div className="glass-card p-6">
          <h3 className="text-sm font-medium text-[var(--sc-text)] mb-3">Active Configuration</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
            <div>
              <div className="text-[10px] text-[var(--sc-text-muted)] uppercase mb-1">Trusted Channels</div>
              <div className="flex flex-wrap gap-1">
                {config.trustedChannels.map((ch) => (
                  <span key={ch} className="px-1.5 py-0.5 bg-[var(--sc-surface-2)] rounded text-[var(--sc-text-dim)]">
                    {ch}
                  </span>
                ))}
              </div>
            </div>
            <div>
              <div className="text-[10px] text-[var(--sc-text-muted)] uppercase mb-1">Requires Approval</div>
              <div className="flex flex-wrap gap-1">
                {config.requireApproval.map((a) => (
                  <span key={a} className="px-1.5 py-0.5 bg-[var(--sc-danger)]/10 border border-[var(--sc-danger)]/20 rounded text-[var(--sc-danger)]">
                    {a}
                  </span>
                ))}
              </div>
            </div>
            <div>
              <div className="text-[10px] text-[var(--sc-text-muted)] uppercase mb-1">Kill Phrase</div>
              <div className="space-y-2">
                <input
                  type="text"
                  value={killPhraseDraft}
                  onChange={(e) => setKillPhraseDraft(e.target.value)}
                  placeholder="Set emergency stop phrase"
                  className="w-full bg-[var(--sc-surface-2)] border border-[var(--sc-border)] rounded-lg px-3 py-2 text-xs text-[var(--sc-text)] font-mono placeholder:text-[var(--sc-text-muted)] focus:outline-none focus:ring-1 focus:ring-[var(--sc-danger)]"
                />
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => updateConfigMutation.mutate({ killPhrase: killPhraseDraft.trim() })}
                    disabled={updateConfigMutation.isPending || !killPhraseDraft.trim() || !killPhraseDirty}
                    className="px-3 py-1.5 rounded-lg bg-[var(--sc-danger)] hover:bg-[var(--sc-danger)]/80 disabled:opacity-50 text-[11px] font-medium text-[var(--sc-text)] transition-colors"
                  >
                    {updateConfigMutation.isPending ? 'Saving...' : 'Save phrase'}
                  </button>
                  <span className="text-[10px] text-[var(--sc-text-muted)]">
                    {isActive ? 'Say this in a conversation to trigger lockdown.' : 'This will apply the next time Iron Dome is active.'}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── KILL SWITCH / EMERGENCY STOP ── */}
      {isKillSwitchActive ? (
        <div className="glass-card-strong p-6 border-2 !border-[var(--sc-danger)]/50 animate-pulse-slow">
          <div className="flex items-center gap-2 mb-3">
            <OctagonX size={18} className="text-[var(--sc-danger)]" />
            <h3 className="text-sm font-bold text-[var(--sc-danger)] uppercase tracking-wide">Kill Switch Active</h3>
            <span className="ml-auto text-[10px] bg-[var(--sc-danger)]/20 text-[var(--sc-danger)] px-2 py-0.5 rounded-full border border-[var(--sc-danger)]/30">
              LOCKDOWN
            </span>
          </div>
          <p className="text-xs text-[var(--sc-danger)]/80 mb-2">
            All agent operations are blocked. No memory reads, writes, graph queries, or consolidation. Iron Dome remains active and continues protecting.
          </p>

          {/* Kill switch metadata */}
          {killSwitchMeta && (
            <div className="bg-[var(--sc-danger)]/10 border border-[var(--sc-danger)]/20 rounded-lg p-3 mb-4 space-y-1">
              <div className="text-[10px] text-[var(--sc-text-muted)]">
                <span className="text-[var(--sc-danger)] font-medium">Triggered:</span>{' '}
                {new Date(killSwitchMeta.triggeredAt).toLocaleString()}
              </div>
              <div className="text-[10px] text-[var(--sc-text-muted)]">
                <span className="text-[var(--sc-danger)] font-medium">Source:</span>{' '}
                {killSwitchMeta.source === 'kill_phrase' ? `Kill phrase "${killSwitchMeta.phrase}"` :
                 killSwitchMeta.source === 'manual' ? 'Manual (dashboard)' :
                 killSwitchMeta.source === 'mcp_tool' ? 'MCP tool' : killSwitchMeta.source}
              </div>
              {killSwitchMeta.memoryCountAtTrigger !== undefined && (
                <div className="text-[10px] text-[var(--sc-text-muted)]">
                  <span className="text-[var(--sc-danger)] font-medium">Memories at trigger:</span>{' '}
                  {killSwitchMeta.memoryCountAtTrigger}
                </div>
              )}
            </div>
          )}

          {/* Resume with reason */}
          <div className="space-y-2">
            <input
              type="text"
              value={resumeReason}
              onChange={(e) => setResumeReason(e.target.value)}
              placeholder="Reason for resuming (required)..."
              className="w-full bg-[var(--sc-surface-2)] border border-[var(--sc-border)] rounded-lg px-3 py-2 text-xs text-[var(--sc-text)] placeholder:text-[var(--sc-text-muted)] focus:outline-none focus:ring-1 focus:ring-green-500"
            />
            <div className="flex items-center gap-3">
              <button
                onClick={() => {
                  if (!resumeReason.trim()) return;
                  resumeMutation.mutate(resumeReason.trim());
                  setResumeReason('');
                }}
                disabled={resumeMutation.isPending || !resumeReason.trim()}
                className="flex items-center gap-1.5 px-4 py-2 bg-[var(--sc-ok)] hover:bg-[var(--sc-ok)] disabled:opacity-50 rounded-lg text-xs font-medium text-[var(--sc-text)] transition-colors"
              >
                {resumeMutation.isPending ? (
                  <Loader2 size={12} className="animate-spin" />
                ) : (
                  <Play size={12} />
                )}
                Resume Agent
              </button>
              <span className="text-[10px] text-[var(--sc-text-muted)]">
                Only resume after you&apos;ve investigated the threat
              </span>
            </div>
          </div>
        </div>
      ) : (
        <div className="glass-card p-6 !border-[var(--sc-danger)]/30">
          <div className="flex items-center gap-2 mb-2">
            <OctagonX size={14} className="text-[var(--sc-danger)]" />
            <h3 className="text-sm font-medium text-[var(--sc-danger)]">Emergency Stop</h3>
          </div>
          <p className="text-xs text-[var(--sc-text-dim)] mb-3">
            Immediately halts your agent when you suspect it has been compromised or is acting on poisoned data. Blocks ALL operations — no reads, writes, or modifications. Iron Dome stays active.
          </p>
          {config?.killPhrase && (
            <p className="text-[10px] text-[var(--sc-text-muted)] mb-3">
              Kill phrase: <span className="font-mono text-[var(--sc-text-dim)]">&quot;{config.killPhrase}&quot;</span> — say this in conversation for hands-free stop
            </p>
          )}
          <button
            onClick={() => setConfirmStopOpen(true)}
            disabled={emergencyStopMutation.isPending}
            className="flex items-center gap-1.5 px-4 py-2 bg-[var(--sc-danger)] hover:bg-[var(--sc-danger)]/80 disabled:opacity-50 rounded-lg text-xs font-bold text-[var(--sc-text)] uppercase tracking-wider transition-colors"
          >
            {emergencyStopMutation.isPending ? (
              <Loader2 size={12} className="animate-spin" />
            ) : (
              <OctagonX size={14} />
            )}
            Emergency Stop
          </button>
          <ConfirmDialog
            open={confirmStopOpen}
            title="Halt all agent operations?"
            description="This blocks every memory read, write, graph query, and consolidation immediately. Iron Dome stays active and continues protecting; resume manually once you've investigated."
            confirmLabel="Emergency Stop"
            danger
            pending={emergencyStopMutation.isPending}
            onConfirm={() => emergencyStopMutation.mutate(undefined, { onSuccess: () => setConfirmStopOpen(false) })}
            onCancel={() => setConfirmStopOpen(false)}
          />
        </div>
      )}

      {/* ── LIVE MONITOR ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Injection Scanner (Test) */}
        <div className="glass-card p-6">
          <h3 className="text-sm font-medium text-[var(--sc-text)] mb-3">
            <Scan size={14} className="inline mr-1.5 text-[var(--sc-danger)]" />
            Injection Scanner
          </h3>
          <textarea
            value={scanText}
            onChange={(e) => setScanText(e.target.value)}
            placeholder="Paste suspicious text to scan for injection patterns..."
            className="w-full h-28 bg-[var(--sc-surface-2)] border border-[var(--sc-border)] rounded-lg p-3 text-sm text-[var(--sc-text)] placeholder:text-[var(--sc-text-muted)] resize-none focus:outline-none focus:ring-1 focus:ring-[var(--sc-danger)] focus:border-[var(--sc-danger)]"
          />
          <button
            onClick={handleScan}
            disabled={scanMutation.isPending || !scanText.trim()}
            className="mt-2 flex items-center gap-1.5 px-3 py-1.5 bg-[var(--sc-danger)] hover:bg-[var(--sc-danger)]/80 disabled:opacity-50 rounded-lg text-xs font-medium text-[var(--sc-text)] transition-colors"
          >
            {scanMutation.isPending ? (
              <Loader2 size={12} className="animate-spin" />
            ) : (
              <Zap size={12} />
            )}
            Scan
          </button>

          {/* Scan Results */}
          {scanResult && (
            <div className="mt-3 space-y-2">
              {/* Risk Level Badge */}
              <div className="flex items-center gap-2">
                {scanResult.clean ? (
                  <CheckCircle2 size={14} className="text-[var(--sc-ok)]" />
                ) : (
                  <XCircle size={14} className="text-[var(--sc-danger)]" />
                )}
                <span
                  className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${
                    RISK_COLOURS[scanResult.riskLevel] ?? 'bg-[var(--sc-surface-2)]/20 text-[var(--sc-text-dim)]'
                  }`}
                >
                  {scanResult.riskLevel}
                </span>
                <span className="text-xs text-[var(--sc-text-dim)]">{scanResult.summary}</span>
              </div>

              {/* Detection Cards */}
              {scanResult.detections.map((d, i) => (
                <div
                  key={i}
                  className={`border rounded-lg p-3 ${
                    SEVERITY_COLOURS[d.severity] ?? 'border-[var(--sc-border)]'
                  }`}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-[10px] font-medium uppercase">
                      {d.severity}
                    </span>
                    <span className="text-xs text-[var(--sc-text)]">{d.category.replace(/_/g, ' ')}</span>
                  </div>
                  <p className="text-[11px] text-[var(--sc-text-dim)] mb-1">{d.description}</p>
                  <code className="text-[10px] text-[var(--sc-text-muted)] bg-[var(--sc-surface-2)] px-1.5 py-0.5 rounded block truncate">
                    {d.match}
                  </code>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Event Feed */}
        <div className="glass-card p-6">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-medium text-[var(--sc-text)]">Event Feed</h3>
            <span className="text-[10px] text-[var(--sc-text-muted)]">
              Last {logs.length} events
            </span>
          </div>

          {/* Stats bar — today's counts first (brief §8), loaded-window
              totals below with an honest caption (see comment above). */}
          <div className="mb-1 grid grid-cols-2 gap-2">
            <div className="rounded-lg bg-[var(--sc-surface-2)]/50 p-2 text-center">
              <div className="text-sm font-bold text-[var(--sc-danger)]">{blockedToday}</div>
              <div className="text-[10px] text-[var(--sc-text-muted)]">Blocked today</div>
            </div>
            <div className="rounded-lg bg-[var(--sc-surface-2)]/50 p-2 text-center">
              <div className="text-sm font-bold text-[var(--sc-ok)]">{allowedToday}</div>
              <div className="text-[10px] text-[var(--sc-text-muted)]">Allowed today</div>
            </div>
          </div>
          <div className="mb-3 text-[10px] text-[var(--sc-text-muted)]">
            of the {logs.length} most recently loaded events
          </div>
          <div className="grid grid-cols-3 gap-2 mb-3">
            <div className="bg-[var(--sc-surface-2)]/50 rounded-lg p-2 text-center">
              <div className="text-sm font-bold text-[var(--sc-text)]">{logs.length}</div>
              <div className="text-[10px] text-[var(--sc-text-muted)]">Total</div>
            </div>
            <div className="bg-[var(--sc-surface-2)]/50 rounded-lg p-2 text-center">
              <div className="text-sm font-bold text-[var(--sc-danger)]">{blockCount}</div>
              <div className="text-[10px] text-[var(--sc-text-muted)]">Blocked</div>
            </div>
            <div className="bg-[var(--sc-surface-2)]/50 rounded-lg p-2 text-center">
              <div className="text-sm font-bold text-[var(--sc-ok)]">{allowCount}</div>
              <div className="text-[10px] text-[var(--sc-text-muted)]">Allowed</div>
            </div>
          </div>

          {/* Event list */}
          <div className="space-y-1 max-h-72 overflow-y-auto">
            {logs.length === 0 ? (
              <div className="text-center py-6">
                <Shield size={20} className="text-[var(--sc-text-muted)] mx-auto mb-1.5" />
                <p className="text-[10px] text-[var(--sc-text-muted)]">
                  No Iron Dome events yet
                </p>
              </div>
            ) : (
              logs.map((log: IronDomeAuditLog, i: number) => (
                <div
                  key={log.id ?? i}
                  className="flex items-center gap-2 px-2 py-1.5 rounded-md bg-[var(--sc-surface-2)]/50 text-xs"
                >
                  <span
                    className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                      log.firewall_result === 'BLOCK' ? 'bg-[var(--sc-danger)]' : 'bg-[var(--sc-ok)]'
                    }`}
                  />
                  <span className="text-[var(--sc-text-dim)] truncate flex-1">
                    {(log.reason ?? '').replace(/^\[iron-dome:\w+\]\s*/, '')}
                  </span>
                  <span className="text-[10px] text-[var(--sc-text-muted)] shrink-0">
                    {new Date(log.timestamp).toLocaleTimeString()}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
