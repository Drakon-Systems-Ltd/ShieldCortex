'use client';

import { useMemo, useState } from 'react';
import { Activity, AlertTriangle, CheckCircle2, Clock3, ShieldAlert } from 'lucide-react';
import { useInterceptorEvents } from '@/hooks/useInterceptorEvents';

const SEVERITY_STYLES: Record<string, string> = {
  critical: 'border-[var(--sc-coral)]/30 bg-[var(--sc-coral)]/10 text-[var(--sc-coral)]',
  high: 'border-[var(--sc-coral)]/30 bg-[var(--sc-coral)]/10 text-[var(--sc-coral)]',
  medium: 'border-[var(--sc-amber)]/30 bg-[var(--sc-amber)]/10 text-[var(--sc-amber)]',
  low: 'border-[var(--sc-border)] bg-[var(--sc-bg-elevated)]/80 text-[var(--sc-text-primary)]',
};

const OUTCOME_STYLES: Record<string, string> = {
  approved: 'bg-[var(--sc-cyan)]/10 text-[var(--sc-cyan)]',
  denied: 'bg-[var(--sc-amber)]/10 text-[var(--sc-amber)]',
  auto_denied: 'bg-[var(--sc-coral)]/10 text-[var(--sc-coral)]',
  warned: 'bg-[var(--sc-amber)]/10 text-[var(--sc-amber)]',
  logged: 'bg-[var(--sc-bg-elevated)] text-[var(--sc-text-primary)]',
  failure_allowed: 'bg-[var(--sc-cyan)]/10 text-[var(--sc-cyan)]',
  failure_denied: 'bg-[var(--sc-coral)]/10 text-[var(--sc-coral)]',
};

export function InterceptorEventsView() {
  const [severity, setSeverity] = useState<string>('');
  const [outcome, setOutcome] = useState<string>('');
  const [tool, setTool] = useState<string>('');

  const { data, isLoading } = useInterceptorEvents({
    limit: 100,
    severity: severity || undefined,
    outcome: outcome || undefined,
    tool: tool || undefined,
  });

  const entries = data?.entries ?? [];
  const summary = data?.summary;

  const toolOptions = useMemo(
    () => (summary?.topTools ?? []).map((item) => item.tool),
    [summary?.topTools]
  );

  return (
    <div className="space-y-6">
      <div className="glass-card p-6">
        <div className="grid gap-3 md:grid-cols-4">
          <div className="rounded-xl border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/60 p-4">
            <div className="flex items-center gap-2 text-[10px] uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">
              <Activity size={12} />
              Total
            </div>
            <div className="mt-2 text-xl font-semibold text-[var(--sc-text-primary)]">{summary?.total ?? 0}</div>
          </div>
          <div className="rounded-xl border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/60 p-4">
            <div className="flex items-center gap-2 text-[10px] uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">
              <CheckCircle2 size={12} />
              Approved
            </div>
            <div className="mt-2 text-xl font-semibold text-[var(--sc-cyan)]">{summary?.approved ?? 0}</div>
          </div>
          <div className="rounded-xl border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/60 p-4">
            <div className="flex items-center gap-2 text-[10px] uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">
              <AlertTriangle size={12} />
              Denied
            </div>
            <div className="mt-2 text-xl font-semibold text-[var(--sc-amber)]">{summary?.denied ?? 0}</div>
          </div>
          <div className="rounded-xl border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/60 p-4">
            <div className="flex items-center gap-2 text-[10px] uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">
              <ShieldAlert size={12} />
              Failures
            </div>
            <div className="mt-2 text-xl font-semibold text-[var(--sc-coral)]">{summary?.failures ?? 0}</div>
          </div>
        </div>

        <div className="mt-4 flex flex-wrap gap-2">
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-elevated)] px-3 py-1.5 text-xs text-[var(--sc-text-primary)]"
          >
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select
            value={outcome}
            onChange={(e) => setOutcome(e.target.value)}
            className="rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-elevated)] px-3 py-1.5 text-xs text-[var(--sc-text-primary)]"
          >
            <option value="">All outcomes</option>
            <option value="approved">Approved</option>
            <option value="denied">Denied</option>
            <option value="auto_denied">Auto denied</option>
            <option value="warned">Warned</option>
            <option value="logged">Logged</option>
            <option value="failure_allowed">Failure allowed</option>
            <option value="failure_denied">Failure denied</option>
          </select>
          <select
            value={tool}
            onChange={(e) => setTool(e.target.value)}
            className="rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-elevated)] px-3 py-1.5 text-xs text-[var(--sc-text-primary)]"
          >
            <option value="">Top tools</option>
            {toolOptions.map((item) => (
              <option key={item} value={item}>{item}</option>
            ))}
          </select>
        </div>
      </div>

      <div className="glass-card-strong p-5 overflow-hidden">
        {isLoading ? (
          <div className="flex h-32 items-center justify-center text-sm text-[var(--sc-text-secondary)]">Loading interceptor events…</div>
        ) : entries.length === 0 ? (
          <div className="flex h-32 items-center justify-center text-sm text-[var(--sc-text-secondary)]">No interceptor events found for the current filters.</div>
        ) : (
          <div className="divide-y divide-[var(--sc-border)]">
            {entries.map((entry, index) => (
              <div key={`${entry.ts}-${entry.tool}-${index}`} className="grid gap-4 px-5 py-4 lg:grid-cols-[220px_minmax(0,1fr)_220px]">
                <div className="space-y-2">
                  <div className="flex items-center gap-2 text-xs text-[var(--sc-text-muted)]">
                    <Clock3 size={12} />
                    {new Date(entry.ts).toLocaleString()}
                  </div>
                  <div className="text-sm font-medium text-[var(--sc-text-primary)]">{entry.tool}</div>
                  <div className={`inline-flex rounded-full border px-2.5 py-1 text-[11px] ${SEVERITY_STYLES[entry.severity] ?? SEVERITY_STYLES.low}`}>
                    {entry.severity.toUpperCase()}
                  </div>
                </div>

                <div className="min-w-0">
                  <div className="text-xs uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">Preview</div>
                  <p className="mt-2 line-clamp-4 text-sm leading-6 text-[var(--sc-text-primary)]">
                    {entry.preview || 'No preview captured.'}
                  </p>
                  <div className="mt-3 flex flex-wrap gap-2">
                    {(entry.threats ?? []).map((threat) => (
                      <span key={threat} className="rounded-full border border-[var(--sc-border)] bg-[var(--sc-bg-elevated)] px-2.5 py-1 text-[11px] text-[var(--sc-text-primary)]">
                        {threat}
                      </span>
                    ))}
                    {(!entry.threats || entry.threats.length === 0) && (
                      <span className="rounded-full border border-[var(--sc-border)] bg-[var(--sc-bg-elevated)] px-2.5 py-1 text-[11px] text-[var(--sc-text-secondary)]">
                        No explicit threat tags
                      </span>
                    )}
                  </div>
                </div>

                <div className="space-y-3">
                  <div>
                    <div className="text-[10px] uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">Outcome</div>
                    <div className={`mt-1 inline-flex rounded-full px-2.5 py-1 text-[11px] ${OUTCOME_STYLES[entry.outcome] ?? OUTCOME_STYLES.logged}`}>
                      {entry.outcome.replace(/_/g, ' ')}
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">Firewall</div>
                    <div className="mt-1 text-sm text-[var(--sc-text-primary)]">{entry.firewallResult}</div>
                  </div>
                  <div>
                    <div className="text-[10px] uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">Action</div>
                    <div className="mt-1 text-sm text-[var(--sc-text-primary)]">{entry.action}</div>
                  </div>
                  <div>
                    <div className="text-[10px] uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">Anomaly score</div>
                    <div className="mt-1 text-sm text-[var(--sc-text-primary)]">{entry.anomalyScore.toFixed(2)}</div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
