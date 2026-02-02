'use client';

import { useAgentOperations } from '@/hooks/useAgents';

interface Props {
  identifier: string;
}

const resultColors: Record<string, string> = {
  BLOCK: 'text-red-400 bg-red-500/10',
  QUARANTINE: 'text-yellow-400 bg-yellow-500/10',
};

export function FlaggedOperations({ identifier }: Props) {
  const { data, isLoading } = useAgentOperations(identifier, {
    firewallResult: 'BLOCK',
    limit: 20,
  });

  // Also fetch quarantined
  const { data: quarantined } = useAgentOperations(identifier, {
    firewallResult: 'QUARANTINE',
    limit: 20,
  });

  const entries = [
    ...(data?.entries ?? []),
    ...(quarantined?.entries ?? []),
  ].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

  if (isLoading) {
    return <div className="text-slate-500 text-xs">Loading...</div>;
  }

  if (entries.length === 0) {
    return <div className="text-slate-500 text-xs">No flagged operations.</div>;
  }

  return (
    <div className="space-y-1 max-h-60 overflow-y-auto">
      {entries.map((entry) => {
        let threats: string[] = [];
        try {
          threats = JSON.parse(entry.threat_indicators);
        } catch { /* ignore */ }

        return (
          <div
            key={entry.id}
            className="px-2 py-1.5 rounded bg-slate-800/50 border border-slate-800"
          >
            <div className="flex items-center justify-between">
              <span className={`px-1 py-0.5 rounded text-[10px] font-medium ${resultColors[entry.firewall_result] ?? 'text-slate-400'}`}>
                {entry.firewall_result}
              </span>
              <span className="text-[10px] text-slate-500">
                {new Date(entry.timestamp).toLocaleString([], {
                  month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
                })}
              </span>
            </div>
            {entry.reason && (
              <p className="text-[11px] text-slate-400 mt-0.5 truncate">{entry.reason}</p>
            )}
            {threats.length > 0 && (
              <div className="flex gap-1 mt-1 flex-wrap">
                {threats.map((t, i) => (
                  <span key={i} className="px-1 py-0.5 rounded text-[9px] bg-red-500/10 text-red-400">
                    {t}
                  </span>
                ))}
              </div>
            )}
            <div className="flex gap-3 mt-1 text-[10px] text-slate-500">
              <span>Trust: {entry.trust_score.toFixed(2)}</span>
              <span>Anomaly: {entry.anomaly_score.toFixed(2)}</span>
              {entry.pipeline_duration_ms !== null && <span>{entry.pipeline_duration_ms}ms</span>}
            </div>
          </div>
        );
      })}
    </div>
  );
}
