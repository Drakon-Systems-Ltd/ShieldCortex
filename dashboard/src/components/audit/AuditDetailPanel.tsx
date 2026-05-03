'use client';

import { useState, useCallback } from 'react';
import { AuditEntry } from '@/hooks/useDefence';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { LocalAiExplanationPanel, type ExplainAction } from '@/components/local-ai/LocalAiExplanationPanel';
import { useLocalAiExplain } from '@/hooks/useLocalAiExplainer';
import { buildEditorUrl } from '@/lib/editor-url';
import { ExternalLink, Loader2, Sparkles } from 'lucide-react';

// Audit entries don't have a dedicated `file` field. Some `source_identifier`
// values *are* file paths (memory-file scans, agent skill scans). Heuristic:
// looks like a path if it contains a slash and a file extension.
function detectFilePath(source: string | null | undefined): string | null {
  if (!source) return null;
  const trimmed = source.trim();
  if (!trimmed.includes('/')) return null;
  if (!/\.[A-Za-z0-9]{1,8}(?::\d+)?$/.test(trimmed)) return null;
  return trimmed;
}

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

function buildAuditExplainContent(entry: AuditEntry, threats: string[], blockedPatterns: string[]): string {
  return [
    `Audit ID: ${entry.id}`,
    `Result: ${entry.firewall_result}`,
    `Source: ${entry.source_type}:${entry.source_identifier}`,
    entry.project ? `Project: ${entry.project}` : '',
    `Trust score: ${entry.trust_score}`,
    `Anomaly score: ${entry.anomaly_score}`,
    `Sensitivity: ${entry.sensitivity_level}`,
    entry.fragmentation_score !== null ? `Fragmentation score: ${entry.fragmentation_score}` : '',
    threats.length ? `Threat indicators: ${threats.join(', ')}` : '',
    blockedPatterns.length ? `Blocked patterns:\n${blockedPatterns.join('\n')}` : '',
    entry.reason ? `Reason:\n${entry.reason}` : '',
  ].filter(Boolean).join('\n\n');
}

export function AuditDetailPanel({ entry, onClose, onViewMemory }: AuditDetailPanelProps) {
  const [copied, setCopied] = useState(false);
  const explainMutation = useLocalAiExplain();

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

  const handleExplain = useCallback(() => {
    explainMutation.mutate({
      kind: 'audit_event',
      title: `${entry.firewall_result} audit event`,
      content: buildAuditExplainContent(entry, threats, blockedPatterns),
      project: entry.project,
      source: `${entry.source_type}:${entry.source_identifier}`,
      signals: [
        entry.firewall_result,
        entry.sensitivity_level,
        ...threats,
      ],
      metadata: {
        auditId: entry.id,
        memoryId: entry.memory_id,
        trustScore: entry.trust_score,
        anomalyScore: entry.anomaly_score,
        pipelineDurationMs: entry.pipeline_duration_ms,
      },
    });
  }, [blockedPatterns, entry, explainMutation, threats]);

  return (
    <Card className="bg-[var(--sc-bg-surface)] border-[var(--sc-border)] overflow-hidden">
      <CardHeader className="border-b border-[var(--sc-border)] pb-3">
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
            className="text-[var(--sc-text-secondary)] hover:text-white -mt-1"
          >
            ✕
          </Button>
        </div>
        <div className="text-xs text-[var(--sc-text-secondary)] mt-2">
          {new Date(entry.timestamp).toLocaleString()}
        </div>
        {entry.project && (
          <div className="text-[10px] text-[var(--sc-text-muted)] mt-1">
            Project: {entry.project}
          </div>
        )}
      </CardHeader>

      <CardContent className="p-4 space-y-4">
        {/* Source */}
        <div>
          <h4 className="text-xs font-medium text-[var(--sc-text-secondary)] mb-2">Source</h4>
          <div className="bg-[var(--sc-bg-elevated)] rounded-lg p-3">
            <div className="flex items-center gap-2 mb-1">
              <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-[var(--sc-cyan)]/10 text-[var(--sc-cyan)]">
                {entry.source_type}
              </span>
            </div>
            {entry.source_identifier && (
              <div className="text-xs text-[var(--sc-text-primary)] mt-1 font-mono break-all">
                {entry.source_identifier}
              </div>
            )}
          </div>
        </div>

        {/* Scores */}
        <div>
          <h4 className="text-xs font-medium text-[var(--sc-text-secondary)] mb-2">Scores</h4>
          <div className="grid grid-cols-2 gap-2">
            {/* Trust */}
            <div className="bg-[var(--sc-bg-elevated)] rounded-lg p-3">
              <div className="text-[10px] text-[var(--sc-text-muted)]">Trust</div>
              <div className="text-lg font-bold" style={{ color: getTrustColor(entry.trust_score) }}>
                {(entry.trust_score * 100).toFixed(0)}%
              </div>
              <div className="mt-1 h-1.5 bg-[var(--sc-bg-elevated)] rounded-full overflow-hidden">
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
            <div className="bg-[var(--sc-bg-elevated)] rounded-lg p-3">
              <div className="text-[10px] text-[var(--sc-text-muted)]">Anomaly</div>
              <div className="text-lg font-bold" style={{ color: getAnomalyColor(entry.anomaly_score) }}>
                {(entry.anomaly_score * 100).toFixed(0)}%
              </div>
              <div className="mt-1 h-1.5 bg-[var(--sc-bg-elevated)] rounded-full overflow-hidden">
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
              <div className="bg-[var(--sc-bg-elevated)] rounded-lg p-3">
                <div className="text-[10px] text-[var(--sc-text-muted)]">Fragmentation</div>
                <div className="text-lg font-bold text-[var(--sc-text-primary)]">
                  {(entry.fragmentation_score * 100).toFixed(0)}%
                </div>
                <div className="mt-1 h-1.5 bg-[var(--sc-bg-elevated)] rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full bg-purple-500 transition-all"
                    style={{ width: `${entry.fragmentation_score * 100}%` }}
                  />
                </div>
              </div>
            )}

            {/* Pipeline Duration */}
            {entry.pipeline_duration_ms !== null && (
              <div className="bg-[var(--sc-bg-elevated)] rounded-lg p-3">
                <div className="text-[10px] text-[var(--sc-text-muted)]">Pipeline</div>
                <div className="text-lg font-bold text-[var(--sc-text-primary)]">
                  {entry.pipeline_duration_ms}ms
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Threat Indicators */}
        <div>
          <h4 className="text-xs font-medium text-[var(--sc-text-secondary)] mb-2">Threat Indicators</h4>
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
            <div className="text-xs text-[var(--sc-text-muted)]">No threats detected</div>
          )}
        </div>

        {/* Blocked Patterns */}
        {blockedPatterns.length > 0 && (
          <div>
            <h4 className="text-xs font-medium text-[var(--sc-text-secondary)] mb-2">Blocked Patterns</h4>
            <div className="bg-[var(--sc-bg-elevated)] rounded-lg p-3 max-h-32 overflow-y-auto">
              {blockedPatterns.map((pattern, i) => (
                <div key={i} className="text-[11px] text-[var(--sc-text-primary)] font-mono break-all mb-1 last:mb-0">
                  {pattern}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Reason */}
        {entry.reason && (
          <div>
            <h4 className="text-xs font-medium text-[var(--sc-text-secondary)] mb-2">Reason</h4>
            <div className="bg-[var(--sc-bg-elevated)] rounded-lg p-3">
              <p className="text-xs text-[var(--sc-text-primary)] whitespace-pre-wrap leading-relaxed">
                {entry.reason}
              </p>
            </div>
          </div>
        )}

        {explainMutation.data?.explanation && (
          <LocalAiExplanationPanel
            explanation={explainMutation.data.explanation}
            actions={(() => {
              const filePath = detectFilePath(entry.source_identifier);
              if (!filePath) return [];
              const actions: ExplainAction[] = [
                {
                  key: 'open',
                  label: 'Open in editor',
                  icon: <ExternalLink size={13} />,
                  variant: 'outline',
                  onClick: () => {
                    const url = buildEditorUrl(filePath.replace(/:\d+$/, ''),
                      Number(filePath.match(/:(\d+)$/)?.[1]) || undefined);
                    if (url) window.location.href = url;
                  },
                },
              ];
              return actions;
            })()}
          />
        )}

        {explainMutation.error && (
          <div className="rounded-lg border border-[var(--sc-coral)]/30 bg-[var(--sc-coral)]/10 p-3 text-xs text-[var(--sc-coral)]">
            {explainMutation.error instanceof Error ? explainMutation.error.message : 'Local explanation failed'}
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
            onClick={handleExplain}
            disabled={explainMutation.isPending}
            className={`flex-1 border-[var(--sc-border)] text-[var(--sc-text-primary)] hover:text-white ${explainMutation.isPending ? 'glow-cyan-pulse' : ''}`}
          >
            {explainMutation.isPending ? <Loader2 size={13} className="mr-1 animate-spin" /> : <Sparkles size={13} className="mr-1" />}
            Explain
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={handleCopyJson}
            className={`flex-1 border-[var(--sc-border)] transition-all ${
              copied ? 'bg-[var(--sc-cyan)]/20 text-[var(--sc-cyan)] border-[var(--sc-cyan)]/50' : 'text-[var(--sc-text-primary)] hover:text-white'
            }`}
          >
            {copied ? 'Copied' : 'Copy JSON'}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
