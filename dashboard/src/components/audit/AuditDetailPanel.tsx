'use client';

import { useState, useCallback } from 'react';
import { AuditEntry } from '@/hooks/useDefence';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

interface AuditDetailPanelProps {
  entry: AuditEntry;
  onClose: () => void;
  onViewMemory?: (memoryId: number) => void;
}

const RESULT_CONFIG: Record<string, { color: string; bg: string; label: string }> = {
  ALLOW: { color: '#22C55E', bg: 'rgba(34, 197, 94, 0.15)', label: 'Allowed' },
  BLOCK: { color: '#EF4444', bg: 'rgba(239, 68, 68, 0.15)', label: 'Blocked' },
  QUARANTINE: { color: '#EAB308', bg: 'rgba(234, 179, 8, 0.15)', label: 'Quarantined' },
};

const SENSITIVITY_CONFIG: Record<string, { color: string; bg: string }> = {
  PUBLIC: { color: '#94a3b8', bg: 'rgba(148, 163, 184, 0.15)' },
  INTERNAL: { color: '#60a5fa', bg: 'rgba(96, 165, 250, 0.15)' },
  CONFIDENTIAL: { color: '#f59e0b', bg: 'rgba(245, 158, 11, 0.15)' },
  RESTRICTED: { color: '#ef4444', bg: 'rgba(239, 68, 68, 0.15)' },
};

const THREAT_CONFIG: Record<string, { color: string; bg: string }> = {
  instruction_injection: { color: '#ef4444', bg: 'rgba(239, 68, 68, 0.15)' },
  privilege_escalation: { color: '#ef4444', bg: 'rgba(239, 68, 68, 0.15)' },
  credential_leak: { color: '#ef4444', bg: 'rgba(239, 68, 68, 0.15)' },
  encoding_obfuscation: { color: '#f59e0b', bg: 'rgba(245, 158, 11, 0.15)' },
  fragmented_payload: { color: '#f59e0b', bg: 'rgba(245, 158, 11, 0.15)' },
  external_url: { color: '#f59e0b', bg: 'rgba(245, 158, 11, 0.15)' },
  pipeline_error: { color: '#94a3b8', bg: 'rgba(148, 163, 184, 0.15)' },
};

function parseThreatIndicators(raw: string): string[] {
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function parseBlockedPatterns(raw: string): string[] {
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function getTrustColor(score: number): string {
  if (score >= 0.7) return '#22C55E';
  if (score >= 0.4) return '#EAB308';
  return '#EF4444';
}

function getAnomalyColor(score: number): string {
  if (score > 0.5) return '#EF4444';
  if (score > 0.2) return '#EAB308';
  return '#94a3b8';
}

export function AuditDetailPanel({ entry, onClose, onViewMemory }: AuditDetailPanelProps) {
  const [copied, setCopied] = useState(false);

  const resultConfig = RESULT_CONFIG[entry.firewall_result] || RESULT_CONFIG.ALLOW;
  const sensitivityConfig = SENSITIVITY_CONFIG[entry.sensitivity_level] || SENSITIVITY_CONFIG.PUBLIC;
  const threats = parseThreatIndicators(entry.threat_indicators);
  const blockedPatterns = parseBlockedPatterns(entry.blocked_patterns);

  const handleCopyJson = useCallback(() => {
    const json = JSON.stringify(entry, null, 2);
    navigator.clipboard.writeText(json).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }, [entry]);

  return (
    <Card className="bg-slate-900 border-slate-700 h-full overflow-auto">
      <CardHeader className="border-b border-slate-700 pb-3">
        <div className="flex items-start justify-between gap-2">
          {/* Result badge */}
          <div className="flex items-center gap-3">
            <span
              className="px-2.5 py-1 rounded-md text-xs font-bold"
              style={{ backgroundColor: resultConfig.bg, color: resultConfig.color }}
            >
              {resultConfig.label}
            </span>
            <span
              className="px-2 py-0.5 rounded text-[10px] font-medium"
              style={{ backgroundColor: sensitivityConfig.bg, color: sensitivityConfig.color }}
            >
              {entry.sensitivity_level}
            </span>
          </div>
          <Button
            variant="ghost"
            size="sm"
            onClick={onClose}
            className="text-slate-400 hover:text-white -mt-1"
          >
            ✕
          </Button>
        </div>
        <div className="text-xs text-slate-400 mt-2">
          {new Date(entry.timestamp).toLocaleString()}
        </div>
        {entry.project && (
          <div className="text-[10px] text-slate-500 mt-1">
            Project: {entry.project}
          </div>
        )}
      </CardHeader>

      <CardContent className="p-4 space-y-4">
        {/* Source */}
        <div>
          <h4 className="text-xs font-medium text-slate-400 mb-2">Source</h4>
          <div className="bg-slate-800 rounded-lg p-3">
            <div className="flex items-center gap-2 mb-1">
              <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-cyan-500/10 text-cyan-400">
                {entry.source_type}
              </span>
            </div>
            {entry.source_identifier && (
              <div className="text-xs text-slate-300 mt-1 font-mono break-all">
                {entry.source_identifier}
              </div>
            )}
          </div>
        </div>

        {/* Scores */}
        <div>
          <h4 className="text-xs font-medium text-slate-400 mb-2">Scores</h4>
          <div className="grid grid-cols-2 gap-2">
            {/* Trust */}
            <div className="bg-slate-800 rounded-lg p-3">
              <div className="text-[10px] text-slate-500">Trust</div>
              <div className="text-lg font-bold" style={{ color: getTrustColor(entry.trust_score) }}>
                {(entry.trust_score * 100).toFixed(0)}%
              </div>
              <div className="mt-1 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full transition-all"
                  style={{
                    width: `${entry.trust_score * 100}%`,
                    backgroundColor: getTrustColor(entry.trust_score),
                  }}
                />
              </div>
            </div>

            {/* Anomaly */}
            <div className="bg-slate-800 rounded-lg p-3">
              <div className="text-[10px] text-slate-500">Anomaly</div>
              <div className="text-lg font-bold" style={{ color: getAnomalyColor(entry.anomaly_score) }}>
                {(entry.anomaly_score * 100).toFixed(0)}%
              </div>
              <div className="mt-1 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full transition-all"
                  style={{
                    width: `${entry.anomaly_score * 100}%`,
                    backgroundColor: getAnomalyColor(entry.anomaly_score),
                  }}
                />
              </div>
            </div>

            {/* Fragmentation */}
            {entry.fragmentation_score !== null && (
              <div className="bg-slate-800 rounded-lg p-3">
                <div className="text-[10px] text-slate-500">Fragmentation</div>
                <div className="text-lg font-bold text-slate-300">
                  {(entry.fragmentation_score * 100).toFixed(0)}%
                </div>
                <div className="mt-1 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full bg-purple-500 transition-all"
                    style={{ width: `${entry.fragmentation_score * 100}%` }}
                  />
                </div>
              </div>
            )}

            {/* Pipeline Duration */}
            {entry.pipeline_duration_ms !== null && (
              <div className="bg-slate-800 rounded-lg p-3">
                <div className="text-[10px] text-slate-500">Pipeline</div>
                <div className="text-lg font-bold text-slate-300">
                  {entry.pipeline_duration_ms}ms
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Threat Indicators */}
        <div>
          <h4 className="text-xs font-medium text-slate-400 mb-2">Threat Indicators</h4>
          {threats.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {threats.map((threat, i) => {
                const config = THREAT_CONFIG[threat] || { color: '#94a3b8', bg: 'rgba(148, 163, 184, 0.15)' };
                return (
                  <span
                    key={i}
                    className="px-2 py-1 rounded text-[11px] font-medium"
                    style={{ backgroundColor: config.bg, color: config.color }}
                  >
                    {threat.replace(/_/g, ' ')}
                  </span>
                );
              })}
            </div>
          ) : (
            <div className="text-xs text-slate-600">No threats detected</div>
          )}
        </div>

        {/* Blocked Patterns */}
        {blockedPatterns.length > 0 && (
          <div>
            <h4 className="text-xs font-medium text-slate-400 mb-2">Blocked Patterns</h4>
            <div className="bg-slate-800 rounded-lg p-3 max-h-32 overflow-y-auto">
              {blockedPatterns.map((pattern, i) => (
                <div key={i} className="text-[11px] text-slate-300 font-mono break-all mb-1 last:mb-0">
                  {pattern}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Reason */}
        {entry.reason && (
          <div>
            <h4 className="text-xs font-medium text-slate-400 mb-2">Reason</h4>
            <div className="bg-slate-800 rounded-lg p-3">
              <p className="text-xs text-slate-300 whitespace-pre-wrap leading-relaxed">
                {entry.reason}
              </p>
            </div>
          </div>
        )}

        {/* Actions */}
        <div className="flex gap-2 pt-2">
          {entry.memory_id && onViewMemory && (
            <Button
              variant="default"
              size="sm"
              onClick={() => onViewMemory(entry.memory_id!)}
              className="flex-1 bg-blue-600 hover:bg-blue-700"
            >
              View Memory
            </Button>
          )}
          <Button
            variant="outline"
            size="sm"
            onClick={handleCopyJson}
            className={`flex-1 border-slate-700 transition-all ${
              copied ? 'bg-green-600/20 text-green-400 border-green-600/50' : 'text-slate-300 hover:text-white'
            }`}
          >
            {copied ? 'Copied' : 'Copy JSON'}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
