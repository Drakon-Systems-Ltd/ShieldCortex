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
  type IronDomeProfile,
  type InjectionScanResult,
  type IronDomeAuditLog,
} from '@/hooks/useIronDome';
import { CustomPatternsPanel } from './CustomPatternsPanel';
import { CustomPoliciesPanel } from './CustomPoliciesPanel';

const PROFILES: { id: IronDomeProfile; label: string; description: string; icon: typeof Shield }[] = [
  { id: 'personal', label: 'Personal', description: 'Lighter touch for solo use', icon: Shield },
  { id: 'enterprise', label: 'Enterprise', description: 'Financial & data protection', icon: Lock },
  { id: 'school', label: 'School', description: 'GDPR strict, pupil data guarded', icon: Users },
  { id: 'paranoid', label: 'Paranoid', description: 'Everything requires approval', icon: AlertTriangle },
];

const MODULES = [
  { name: 'Injection Scanner', description: '40+ patterns across 8 categories', icon: Scan },
  { name: 'Instruction Gateway', description: 'Trusted channel validation', icon: Radio },
  { name: 'Action Gate', description: 'Approve / block external actions', icon: Lock },
  { name: 'PII Guard', description: 'Block sensitive data output', icon: Eye },
  { name: 'Kill Switch', description: 'Emergency stop phrase', icon: ShieldOff },
  { name: 'Sub-Agent Control', description: 'Restrict spawned agent operations', icon: Users },
];

const SEVERITY_COLOURS: Record<string, string> = {
  critical: 'bg-[var(--sc-coral)]/20 text-[var(--sc-coral)] border-[var(--sc-coral)]/30',
  high: 'bg-[var(--sc-coral)]/20 text-[var(--sc-coral)] border-[var(--sc-coral)]/30',
  medium: 'bg-[var(--sc-amber)]/20 text-[var(--sc-amber)] border-[var(--sc-amber)]/30',
  low: 'bg-[var(--sc-bg-elevated)]/20 text-[var(--sc-text-secondary)] border-[var(--sc-border)]/30',
};

const RISK_COLOURS: Record<string, string> = {
  CRITICAL: 'bg-[var(--sc-coral)]/20 text-[var(--sc-coral)]',
  HIGH: 'bg-[var(--sc-coral)]/20 text-[var(--sc-coral)]',
  MEDIUM: 'bg-[var(--sc-amber)]/20 text-[var(--sc-amber)]',
  LOW: 'bg-[var(--sc-bg-elevated)]/20 text-[var(--sc-text-secondary)]',
  NONE: 'bg-[var(--sc-cyan)]/20 text-[var(--sc-cyan)]',
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

  // Derive event feed stats
  const logs = auditData?.logs ?? [];
  const blockCount = logs.filter((l: IronDomeAuditLog) => l.firewall_result === 'BLOCK').length;
  const allowCount = logs.filter((l: IronDomeAuditLog) => l.firewall_result === 'ALLOW').length;
  const killPhraseDirty = Boolean(config) && killPhraseDraft.trim() !== (config?.killPhrase ?? '');

  return (
    <div className="space-y-6">
      {/* Status + Deactivate */}
      <div className="flex items-center gap-3">
        {statusLoading ? (
          <span className="text-[10px] text-[var(--sc-text-muted)] animate-pulse">Loading...</span>
        ) : (
          <span
            className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${
              isActive
                ? 'bg-[var(--sc-coral)]/20 text-[var(--sc-coral)] border border-[var(--sc-coral)]/30'
                : 'bg-[var(--sc-bg-elevated)]/50 text-[var(--sc-text-muted)]'
            }`}
          >
            {isActive ? 'ACTIVE' : 'INACTIVE'}
          </span>
        )}
        {isActive && (
          <button
            onClick={handleDeactivate}
            disabled={deactivateMutation.isPending}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[var(--sc-coral)]/10 border border-[var(--sc-coral)]/30 hover:bg-[var(--sc-coral)]/20 disabled:opacity-50 rounded-lg text-xs font-medium text-[var(--sc-coral)] transition-colors"
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
          <h3 className="text-sm font-medium text-[var(--sc-text-primary)] mb-3">Security Profiles</h3>
          <div className="grid grid-cols-2 gap-2">
            {PROFILES.map(({ id, label, description, icon: Icon }) => (
              <button
                key={id}
                onClick={() => handleActivate(id)}
                disabled={activateMutation.isPending}
                className={`text-left p-3 rounded-lg border transition-colors ${
                  activeProfile === id
                    ? 'border-[var(--sc-coral)]/50 bg-[var(--sc-coral)]/10 text-[var(--sc-coral)]'
                    : 'border-[var(--sc-border)] bg-[var(--sc-bg-elevated)]/50 text-[var(--sc-text-secondary)] hover:border-[var(--sc-text-muted)]'
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

        {/* Module Status */}
        <div className="glass-card p-6">
          <h3 className="text-sm font-medium text-[var(--sc-text-primary)] mb-3">Module Status</h3>
          <div className="space-y-2">
            {MODULES.map(({ name, description, icon: Icon }) => (
              <div
                key={name}
                className="flex items-center gap-3 px-3 py-2 rounded-lg bg-[var(--sc-bg-elevated)]/50"
              >
                <Icon size={14} className={isActive ? 'text-[var(--sc-coral)]' : 'text-[var(--sc-text-muted)]'} />
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-medium text-[var(--sc-text-primary)]">{name}</div>
                  <div className="text-[10px] text-[var(--sc-text-muted)] truncate">{description}</div>
                </div>
                <span
                  className={`w-2 h-2 rounded-full ${
                    isActive ? 'bg-[var(--sc-coral)]' : 'bg-[var(--sc-text-muted)]'
                  }`}
                />
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Config summary (when active) */}
      {config && (
        <div className="glass-card p-6">
          <h3 className="text-sm font-medium text-[var(--sc-text-primary)] mb-3">Active Configuration</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
            <div>
              <div className="text-[10px] text-[var(--sc-text-muted)] uppercase mb-1">Trusted Channels</div>
              <div className="flex flex-wrap gap-1">
                {config.trustedChannels.map((ch) => (
                  <span key={ch} className="px-1.5 py-0.5 bg-[var(--sc-bg-elevated)] rounded text-[var(--sc-text-secondary)]">
                    {ch}
                  </span>
                ))}
              </div>
            </div>
            <div>
              <div className="text-[10px] text-[var(--sc-text-muted)] uppercase mb-1">Requires Approval</div>
              <div className="flex flex-wrap gap-1">
                {config.requireApproval.map((a) => (
                  <span key={a} className="px-1.5 py-0.5 bg-[var(--sc-coral)]/10 border border-[var(--sc-coral)]/20 rounded text-[var(--sc-coral)]">
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
                  className="w-full bg-[var(--sc-bg-elevated)] border border-[var(--sc-border)] rounded-lg px-3 py-2 text-xs text-[var(--sc-text-primary)] font-mono placeholder:text-[var(--sc-text-muted)] focus:outline-none focus:ring-1 focus:ring-[var(--sc-coral)]"
                />
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => updateConfigMutation.mutate({ killPhrase: killPhraseDraft.trim() })}
                    disabled={updateConfigMutation.isPending || !killPhraseDraft.trim() || !killPhraseDirty}
                    className="px-3 py-1.5 rounded-lg bg-[var(--sc-coral)] hover:bg-[var(--sc-coral)]/80 disabled:opacity-50 text-[11px] font-medium text-[var(--sc-text-primary)] transition-colors"
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
        <div className="glass-card-strong p-6 border-2 !border-[var(--sc-coral)]/50 animate-pulse-slow">
          <div className="flex items-center gap-2 mb-3">
            <OctagonX size={18} className="text-[var(--sc-coral)]" />
            <h3 className="text-sm font-bold text-[var(--sc-coral)] uppercase tracking-wide">Kill Switch Active</h3>
            <span className="ml-auto text-[10px] bg-[var(--sc-coral)]/20 text-[var(--sc-coral)] px-2 py-0.5 rounded-full border border-[var(--sc-coral)]/30">
              LOCKDOWN
            </span>
          </div>
          <p className="text-xs text-[var(--sc-coral)]/80 mb-2">
            All agent operations are blocked. No memory reads, writes, graph queries, or consolidation. Iron Dome remains active and continues protecting.
          </p>

          {/* Kill switch metadata */}
          {killSwitchMeta && (
            <div className="bg-[var(--sc-coral)]/10 border border-[var(--sc-coral)]/20 rounded-lg p-3 mb-4 space-y-1">
              <div className="text-[10px] text-[var(--sc-text-muted)]">
                <span className="text-[var(--sc-coral)] font-medium">Triggered:</span>{' '}
                {new Date(killSwitchMeta.triggeredAt).toLocaleString()}
              </div>
              <div className="text-[10px] text-[var(--sc-text-muted)]">
                <span className="text-[var(--sc-coral)] font-medium">Source:</span>{' '}
                {killSwitchMeta.source === 'kill_phrase' ? `Kill phrase "${killSwitchMeta.phrase}"` :
                 killSwitchMeta.source === 'manual' ? 'Manual (dashboard)' :
                 killSwitchMeta.source === 'mcp_tool' ? 'MCP tool' : killSwitchMeta.source}
              </div>
              {killSwitchMeta.memoryCountAtTrigger !== undefined && (
                <div className="text-[10px] text-[var(--sc-text-muted)]">
                  <span className="text-[var(--sc-coral)] font-medium">Memories at trigger:</span>{' '}
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
              className="w-full bg-[var(--sc-bg-elevated)] border border-[var(--sc-border)] rounded-lg px-3 py-2 text-xs text-[var(--sc-text-primary)] placeholder:text-[var(--sc-text-muted)] focus:outline-none focus:ring-1 focus:ring-green-500"
            />
            <div className="flex items-center gap-3">
              <button
                onClick={() => {
                  if (!resumeReason.trim()) return;
                  resumeMutation.mutate(resumeReason.trim());
                  setResumeReason('');
                }}
                disabled={resumeMutation.isPending || !resumeReason.trim()}
                className="flex items-center gap-1.5 px-4 py-2 bg-[var(--sc-cyan)] hover:bg-[var(--sc-cyan-mid)] disabled:opacity-50 rounded-lg text-xs font-medium text-[var(--sc-text-primary)] transition-colors"
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
        <div className="glass-card p-6 !border-[var(--sc-coral)]/30">
          <div className="flex items-center gap-2 mb-2">
            <OctagonX size={14} className="text-[var(--sc-coral)]" />
            <h3 className="text-sm font-medium text-[var(--sc-coral)]">Emergency Stop</h3>
          </div>
          <p className="text-xs text-[var(--sc-text-secondary)] mb-3">
            Immediately halts your agent when you suspect it has been compromised or is acting on poisoned data. Blocks ALL operations — no reads, writes, or modifications. Iron Dome stays active.
          </p>
          {config?.killPhrase && (
            <p className="text-[10px] text-[var(--sc-text-muted)] mb-3">
              Kill phrase: <span className="font-mono text-[var(--sc-text-secondary)]">&quot;{config.killPhrase}&quot;</span> — say this in conversation for hands-free stop
            </p>
          )}
          <button
            onClick={() => emergencyStopMutation.mutate()}
            disabled={emergencyStopMutation.isPending}
            className="flex items-center gap-1.5 px-4 py-2 bg-[var(--sc-coral)] hover:bg-[var(--sc-coral)]/80 disabled:opacity-50 rounded-lg text-xs font-bold text-[var(--sc-text-primary)] uppercase tracking-wider transition-colors"
          >
            {emergencyStopMutation.isPending ? (
              <Loader2 size={12} className="animate-spin" />
            ) : (
              <OctagonX size={14} />
            )}
            Emergency Stop
          </button>
        </div>
      )}

      {/* ── LIVE MONITOR ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Injection Scanner (Test) */}
        <div className="glass-card p-6">
          <h3 className="text-sm font-medium text-[var(--sc-text-primary)] mb-3">
            <Scan size={14} className="inline mr-1.5 text-[var(--sc-coral)]" />
            Injection Scanner
          </h3>
          <textarea
            value={scanText}
            onChange={(e) => setScanText(e.target.value)}
            placeholder="Paste suspicious text to scan for injection patterns..."
            className="w-full h-28 bg-[var(--sc-bg-elevated)] border border-[var(--sc-border)] rounded-lg p-3 text-sm text-[var(--sc-text-primary)] placeholder:text-[var(--sc-text-muted)] resize-none focus:outline-none focus:ring-1 focus:ring-[var(--sc-coral)] focus:border-[var(--sc-coral)]"
          />
          <button
            onClick={handleScan}
            disabled={scanMutation.isPending || !scanText.trim()}
            className="mt-2 flex items-center gap-1.5 px-3 py-1.5 bg-[var(--sc-coral)] hover:bg-[var(--sc-coral)]/80 disabled:opacity-50 rounded-lg text-xs font-medium text-[var(--sc-text-primary)] transition-colors"
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
                  <CheckCircle2 size={14} className="text-[var(--sc-cyan)]" />
                ) : (
                  <XCircle size={14} className="text-[var(--sc-coral)]" />
                )}
                <span
                  className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${
                    RISK_COLOURS[scanResult.riskLevel] ?? 'bg-[var(--sc-bg-elevated)]/20 text-[var(--sc-text-secondary)]'
                  }`}
                >
                  {scanResult.riskLevel}
                </span>
                <span className="text-xs text-[var(--sc-text-secondary)]">{scanResult.summary}</span>
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
                    <span className="text-xs text-[var(--sc-text-primary)]">{d.category.replace(/_/g, ' ')}</span>
                  </div>
                  <p className="text-[11px] text-[var(--sc-text-secondary)] mb-1">{d.description}</p>
                  <code className="text-[10px] text-[var(--sc-text-muted)] bg-[var(--sc-bg-elevated)] px-1.5 py-0.5 rounded block truncate">
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
            <h3 className="text-sm font-medium text-[var(--sc-text-primary)]">Event Feed</h3>
            <span className="text-[10px] text-[var(--sc-text-muted)]">
              Last {logs.length} events
            </span>
          </div>

          {/* Stats bar */}
          <div className="grid grid-cols-3 gap-2 mb-3">
            <div className="bg-[var(--sc-bg-elevated)]/50 rounded-lg p-2 text-center">
              <div className="text-sm font-bold text-[var(--sc-text-primary)]">{logs.length}</div>
              <div className="text-[10px] text-[var(--sc-text-muted)]">Total</div>
            </div>
            <div className="bg-[var(--sc-bg-elevated)]/50 rounded-lg p-2 text-center">
              <div className="text-sm font-bold text-[var(--sc-coral)]">{blockCount}</div>
              <div className="text-[10px] text-[var(--sc-text-muted)]">Blocked</div>
            </div>
            <div className="bg-[var(--sc-bg-elevated)]/50 rounded-lg p-2 text-center">
              <div className="text-sm font-bold text-[var(--sc-cyan)]">{allowCount}</div>
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
                  className="flex items-center gap-2 px-2 py-1.5 rounded-md bg-[var(--sc-bg-elevated)]/50 text-xs"
                >
                  <span
                    className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                      log.firewall_result === 'BLOCK' ? 'bg-[var(--sc-coral)]' : 'bg-[var(--sc-cyan)]'
                    }`}
                  />
                  <span className="text-[var(--sc-text-secondary)] truncate flex-1">
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

      {/* Pro: Custom injection patterns */}
      <CustomPatternsPanel />

      {/* Pro: Custom Iron Dome policies */}
      <CustomPoliciesPanel />
    </div>
  );
}
