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
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-slate-500/20 text-slate-400 border-slate-500/30',
};

const RISK_COLOURS: Record<string, string> = {
  CRITICAL: 'bg-red-500/20 text-red-400',
  HIGH: 'bg-orange-500/20 text-orange-400',
  MEDIUM: 'bg-yellow-500/20 text-yellow-400',
  LOW: 'bg-slate-500/20 text-slate-400',
  NONE: 'bg-green-500/20 text-green-400',
};

export function IronDomeView() {
  const { data: status, isLoading: statusLoading } = useIronDomeStatus();
  const { data: auditData } = useIronDomeAudit(50);
  const activateMutation = useActivateIronDome();
  const deactivateMutation = useDeactivateIronDome();
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

  return (
    <div className="h-full overflow-y-auto p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <Zap size={20} className="text-red-400" />
          <h2 className="text-lg font-semibold text-white">Iron Dome</h2>
          {statusLoading ? (
            <span className="text-[10px] text-slate-500 animate-pulse">Loading...</span>
          ) : (
            <span
              className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${
                isActive
                  ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                  : 'bg-slate-700/50 text-slate-500'
              }`}
            >
              {isActive ? 'ACTIVE' : 'INACTIVE'}
            </span>
          )}
        </div>
        {isActive && (
          <button
            onClick={handleDeactivate}
            disabled={deactivateMutation.isPending}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-red-500/10 border border-red-500/30 hover:bg-red-500/20 disabled:opacity-50 rounded-lg text-xs font-medium text-red-400 transition-colors"
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
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
        {/* Profile Selector */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <h3 className="text-sm font-medium text-slate-300 mb-3">Security Profiles</h3>
          <div className="grid grid-cols-2 gap-2">
            {PROFILES.map(({ id, label, description, icon: Icon }) => (
              <button
                key={id}
                onClick={() => handleActivate(id)}
                disabled={activateMutation.isPending}
                className={`text-left p-3 rounded-lg border transition-colors ${
                  activeProfile === id
                    ? 'border-red-500/50 bg-red-500/10 text-red-400'
                    : 'border-slate-700 bg-slate-800/50 text-slate-400 hover:border-slate-600'
                }`}
              >
                <div className="flex items-center gap-1.5 mb-1">
                  <Icon size={12} />
                  <span className="text-xs font-medium">{label}</span>
                </div>
                <div className="text-[10px] text-slate-500">{description}</div>
              </button>
            ))}
          </div>
        </div>

        {/* Module Status */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <h3 className="text-sm font-medium text-slate-300 mb-3">Module Status</h3>
          <div className="space-y-2">
            {MODULES.map(({ name, description, icon: Icon }) => (
              <div
                key={name}
                className="flex items-center gap-3 px-3 py-2 rounded-lg bg-slate-800/50"
              >
                <Icon size={14} className={isActive ? 'text-red-400' : 'text-slate-600'} />
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-medium text-slate-300">{name}</div>
                  <div className="text-[10px] text-slate-500 truncate">{description}</div>
                </div>
                <span
                  className={`w-2 h-2 rounded-full ${
                    isActive ? 'bg-red-400' : 'bg-slate-600'
                  }`}
                />
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Config summary (when active) */}
      {isActive && config && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 mb-6">
          <h3 className="text-sm font-medium text-slate-300 mb-3">Active Configuration</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
            <div>
              <div className="text-[10px] text-slate-500 uppercase mb-1">Trusted Channels</div>
              <div className="flex flex-wrap gap-1">
                {config.trustedChannels.map((ch) => (
                  <span key={ch} className="px-1.5 py-0.5 bg-slate-800 rounded text-slate-400">
                    {ch}
                  </span>
                ))}
              </div>
            </div>
            <div>
              <div className="text-[10px] text-slate-500 uppercase mb-1">Requires Approval</div>
              <div className="flex flex-wrap gap-1">
                {config.requireApproval.map((a) => (
                  <span key={a} className="px-1.5 py-0.5 bg-red-500/10 border border-red-500/20 rounded text-red-400">
                    {a}
                  </span>
                ))}
              </div>
            </div>
            <div>
              <div className="text-[10px] text-slate-500 uppercase mb-1">Kill Phrase</div>
              <span className="px-1.5 py-0.5 bg-slate-800 rounded text-slate-400 font-mono">
                {config.killPhrase}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* ── KILL SWITCH / EMERGENCY STOP ── */}
      {isKillSwitchActive ? (
        <div className="bg-red-950/50 border-2 border-red-500/50 rounded-xl p-5 mb-6 animate-pulse-slow">
          <div className="flex items-center gap-2 mb-3">
            <OctagonX size={18} className="text-red-400" />
            <h3 className="text-sm font-bold text-red-400 uppercase tracking-wide">Kill Switch Active</h3>
            <span className="ml-auto text-[10px] bg-red-500/20 text-red-400 px-2 py-0.5 rounded-full border border-red-500/30">
              LOCKDOWN
            </span>
          </div>
          <p className="text-xs text-red-300/80 mb-2">
            All agent operations are blocked. No memory reads, writes, graph queries, or consolidation. Iron Dome remains active and continues protecting.
          </p>

          {/* Kill switch metadata */}
          {killSwitchMeta && (
            <div className="bg-red-950/30 border border-red-500/20 rounded-lg p-3 mb-4 space-y-1">
              <div className="text-[10px] text-slate-500">
                <span className="text-red-400 font-medium">Triggered:</span>{' '}
                {new Date(killSwitchMeta.triggeredAt).toLocaleString()}
              </div>
              <div className="text-[10px] text-slate-500">
                <span className="text-red-400 font-medium">Source:</span>{' '}
                {killSwitchMeta.source === 'kill_phrase' ? `Kill phrase "${killSwitchMeta.phrase}"` :
                 killSwitchMeta.source === 'manual' ? 'Manual (dashboard)' :
                 killSwitchMeta.source === 'mcp_tool' ? 'MCP tool' : killSwitchMeta.source}
              </div>
              {killSwitchMeta.memoryCountAtTrigger !== undefined && (
                <div className="text-[10px] text-slate-500">
                  <span className="text-red-400 font-medium">Memories at trigger:</span>{' '}
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
              className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white placeholder:text-slate-500 focus:outline-none focus:ring-1 focus:ring-green-500"
            />
            <div className="flex items-center gap-3">
              <button
                onClick={() => {
                  if (!resumeReason.trim()) return;
                  resumeMutation.mutate(resumeReason.trim());
                  setResumeReason('');
                }}
                disabled={resumeMutation.isPending || !resumeReason.trim()}
                className="flex items-center gap-1.5 px-4 py-2 bg-green-600 hover:bg-green-500 disabled:opacity-50 rounded-lg text-xs font-medium text-white transition-colors"
              >
                {resumeMutation.isPending ? (
                  <Loader2 size={12} className="animate-spin" />
                ) : (
                  <Play size={12} />
                )}
                Resume Agent
              </button>
              <span className="text-[10px] text-slate-500">
                Only resume after you&apos;ve investigated the threat
              </span>
            </div>
          </div>
        </div>
      ) : (
        <div className="bg-slate-900 border border-orange-500/30 rounded-xl p-4 mb-6">
          <div className="flex items-center gap-2 mb-2">
            <OctagonX size={14} className="text-orange-400" />
            <h3 className="text-sm font-medium text-orange-300">Emergency Stop</h3>
          </div>
          <p className="text-xs text-slate-400 mb-3">
            Immediately halts your agent when you suspect it has been compromised or is acting on poisoned data. Blocks ALL operations — no reads, writes, or modifications. Iron Dome stays active.
          </p>
          {config?.killPhrase && (
            <p className="text-[10px] text-slate-500 mb-3">
              Kill phrase: <span className="font-mono text-slate-400">&quot;{config.killPhrase}&quot;</span> — say this in conversation for hands-free stop
            </p>
          )}
          <button
            onClick={() => emergencyStopMutation.mutate()}
            disabled={emergencyStopMutation.isPending}
            className="flex items-center gap-1.5 px-4 py-2 bg-red-600 hover:bg-red-500 disabled:opacity-50 rounded-lg text-xs font-bold text-white uppercase tracking-wider transition-colors"
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
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <h3 className="text-sm font-medium text-slate-300 mb-3">
            <Scan size={14} className="inline mr-1.5 text-red-400" />
            Injection Scanner
          </h3>
          <textarea
            value={scanText}
            onChange={(e) => setScanText(e.target.value)}
            placeholder="Paste suspicious text to scan for injection patterns..."
            className="w-full h-28 bg-slate-800 border border-slate-700 rounded-lg p-3 text-sm text-white placeholder:text-slate-500 resize-none focus:outline-none focus:ring-1 focus:ring-red-500 focus:border-red-500"
          />
          <button
            onClick={handleScan}
            disabled={scanMutation.isPending || !scanText.trim()}
            className="mt-2 flex items-center gap-1.5 px-3 py-1.5 bg-red-600 hover:bg-red-500 disabled:opacity-50 rounded-lg text-xs font-medium text-white transition-colors"
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
                  <CheckCircle2 size={14} className="text-green-400" />
                ) : (
                  <XCircle size={14} className="text-red-400" />
                )}
                <span
                  className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${
                    RISK_COLOURS[scanResult.riskLevel] ?? 'bg-slate-500/20 text-slate-400'
                  }`}
                >
                  {scanResult.riskLevel}
                </span>
                <span className="text-xs text-slate-400">{scanResult.summary}</span>
              </div>

              {/* Detection Cards */}
              {scanResult.detections.map((d, i) => (
                <div
                  key={i}
                  className={`border rounded-lg p-3 ${
                    SEVERITY_COLOURS[d.severity] ?? 'border-slate-700'
                  }`}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-[10px] font-medium uppercase">
                      {d.severity}
                    </span>
                    <span className="text-xs text-slate-300">{d.category.replace(/_/g, ' ')}</span>
                  </div>
                  <p className="text-[11px] text-slate-400 mb-1">{d.description}</p>
                  <code className="text-[10px] text-slate-500 bg-slate-800 px-1.5 py-0.5 rounded block truncate">
                    {d.match}
                  </code>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Event Feed */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-medium text-slate-300">Event Feed</h3>
            <span className="text-[10px] text-slate-500">
              Last {logs.length} events
            </span>
          </div>

          {/* Stats bar */}
          <div className="grid grid-cols-3 gap-2 mb-3">
            <div className="bg-slate-800/50 rounded-lg p-2 text-center">
              <div className="text-sm font-bold text-slate-300">{logs.length}</div>
              <div className="text-[10px] text-slate-500">Total</div>
            </div>
            <div className="bg-slate-800/50 rounded-lg p-2 text-center">
              <div className="text-sm font-bold text-red-400">{blockCount}</div>
              <div className="text-[10px] text-slate-500">Blocked</div>
            </div>
            <div className="bg-slate-800/50 rounded-lg p-2 text-center">
              <div className="text-sm font-bold text-green-400">{allowCount}</div>
              <div className="text-[10px] text-slate-500">Allowed</div>
            </div>
          </div>

          {/* Event list */}
          <div className="space-y-1 max-h-72 overflow-y-auto">
            {logs.length === 0 ? (
              <div className="text-center py-6">
                <Shield size={20} className="text-slate-600 mx-auto mb-1.5" />
                <p className="text-[10px] text-slate-500">
                  No Iron Dome events yet
                </p>
              </div>
            ) : (
              logs.map((log: IronDomeAuditLog, i: number) => (
                <div
                  key={log.id ?? i}
                  className="flex items-center gap-2 px-2 py-1.5 rounded-md bg-slate-800/50 text-xs"
                >
                  <span
                    className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                      log.firewall_result === 'BLOCK' ? 'bg-red-400' : 'bg-green-400'
                    }`}
                  />
                  <span className="text-slate-400 truncate flex-1">
                    {(log.reason ?? '').replace(/^\[iron-dome:\w+\]\s*/, '')}
                  </span>
                  <span className="text-[10px] text-slate-600 shrink-0">
                    {new Date(log.timestamp).toLocaleTimeString()}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Pro: Custom injection patterns */}
      <div className="mt-4">
        <CustomPatternsPanel />
      </div>

      {/* Pro: Custom Iron Dome policies */}
      <div className="mt-4">
        <CustomPoliciesPanel />
      </div>
    </div>
  );
}
