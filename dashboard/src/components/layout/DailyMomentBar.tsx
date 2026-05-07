'use client';

import { useState } from 'react';
import { Activity, ArrowDown, ArrowUp, Brain, Minus, ShieldAlert, ShieldCheck, Sparkles } from 'lucide-react';
import { useDigest, type DigestMoment, type DigestWindow } from '@/hooks/useDigest';
import { useDashboardStore } from '@/lib/store';

const WINDOWS: Array<{ id: DigestWindow; label: string }> = [
  { id: '24h', label: '24h' },
  { id: '7d', label: '7d' },
  { id: '30d', label: '30d' },
];

function DeltaPill({ value }: { value: number | undefined }) {
  if (value === undefined) return null;
  if (value === 0) {
    return (
      <span className="inline-flex items-center gap-0.5 text-[10px] text-[var(--sc-text-muted)]">
        <Minus size={9} /> 0
      </span>
    );
  }
  const positive = value > 0;
  const Icon = positive ? ArrowUp : ArrowDown;
  return (
    <span
      className={`inline-flex items-center gap-0.5 text-[10px] ${
        positive ? 'text-[var(--sc-cyan)]' : 'text-[var(--sc-text-muted)]'
      }`}
    >
      <Icon size={9} />
      {positive ? '+' : ''}{value}
    </span>
  );
}

function StatChip({
  icon,
  label,
  value,
  delta,
  tone,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
  delta?: number;
  tone?: 'default' | 'coral' | 'cyan';
}) {
  const toneClass =
    tone === 'coral'
      ? 'text-[var(--sc-coral)]'
      : tone === 'cyan'
        ? 'text-[var(--sc-cyan)]'
        : 'text-[var(--sc-text-primary)]';
  return (
    <div className="flex items-center gap-2">
      <span className={toneClass}>{icon}</span>
      <span className="text-[10px] uppercase tracking-[0.12em] text-[var(--sc-text-muted)]">{label}</span>
      <span className={`font-mono text-sm font-semibold ${toneClass}`}>{value.toLocaleString()}</span>
      <DeltaPill value={delta} />
    </div>
  );
}

function MomentRow({ moment }: { moment: DigestMoment }) {
  const Icon =
    moment.kind === 'block' || moment.kind === 'quarantine'
      ? ShieldAlert
      : moment.kind === 'capture'
        ? Sparkles
        : Brain;
  const tone =
    moment.kind === 'block' ? 'text-[var(--sc-coral)]' :
    moment.kind === 'quarantine' ? 'text-[var(--sc-amber)]' :
    moment.kind === 'capture' ? 'text-[var(--sc-cyan)]' :
    'text-[var(--sc-text-secondary)]';
  return (
    <li className="flex items-start gap-2 rounded border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/40 p-2">
      <Icon size={14} className={`mt-0.5 ${tone}`} />
      <div className="min-w-0 flex-1">
        <div className="text-xs font-medium text-[var(--sc-text-primary)] truncate">{moment.title}</div>
        <div className="mt-0.5 text-[10px] text-[var(--sc-text-muted)] truncate">{moment.detail}</div>
      </div>
      <span className="shrink-0 text-[10px] text-[var(--sc-text-muted)]">
        {new Date(moment.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
      </span>
    </li>
  );
}

/**
 * The "Cloudflare email" moment, in-app.
 *
 * One dense row that answers "did ShieldCortex earn its keep?" at a glance:
 * scans / blocks / captures / recalls in the chosen window, with delta vs the
 * previous equivalent window. Click to expand the top moments feed.
 */
export function DailyMomentBar() {
  const [window, setWindow] = useState<DigestWindow>('24h');
  const [expanded, setExpanded] = useState(false);
  const { projectFilter } = useDashboardStore();
  const { data, isLoading } = useDigest(window, projectFilter);

  if (isLoading || !data) {
    return (
      <div className="flex items-center gap-3 border-b border-[var(--sc-border)] bg-[var(--sc-bg-surface)]/30 px-4 py-2 text-[11px] text-[var(--sc-text-muted)]">
        <Activity size={12} className="animate-pulse" /> Loading activity…
      </div>
    );
  }

  const c = data.current;
  const d = data.delta;
  const noActivity = c.scanned === 0 && c.memoriesCaptured === 0 && c.memoriesRecalled === 0;

  return (
    <div className="border-b border-[var(--term-border)] bg-[var(--term-surface)] font-mono">
      {/* Headline row */}
      <div
        className="flex flex-wrap items-center gap-x-5 gap-y-2 px-4 py-2 cursor-pointer hover:bg-[var(--term-surface-2)] transition-colors"
        onClick={() => setExpanded((v) => !v)}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') setExpanded((v) => !v); }}
        aria-expanded={expanded}
        aria-label={`${data.windowLabel} ShieldCortex activity. Click to ${expanded ? 'collapse' : 'expand'} top moments.`}
      >
        <span className="text-[10px] uppercase tracking-[0.14em] text-[var(--sc-text-muted)]">{data.windowLabel}</span>

        {noActivity ? (
          <span className="text-xs text-[var(--sc-text-muted)]">
            No activity yet — ShieldCortex captures and protects in the background.
          </span>
        ) : (
          <>
            <StatChip icon={<ShieldCheck size={13} />} label="Scanned" value={c.scanned} delta={d.scanned} />
            <StatChip icon={<ShieldAlert size={13} />} label="Blocked" value={c.blocked + c.quarantined} delta={(d.blocked ?? 0) + (d.quarantined ?? 0)} tone="coral" />
            <StatChip icon={<Sparkles size={13} />} label="Captured" value={c.memoriesCaptured} delta={d.memoriesCaptured} tone="cyan" />
            <StatChip icon={<Brain size={13} />} label="Recalled" value={c.memoriesRecalled} delta={d.memoriesRecalled} />
          </>
        )}

        <div className="ml-auto flex items-center gap-1">
          {WINDOWS.map((w) => (
            <button
              key={w.id}
              type="button"
              onClick={(e) => { e.stopPropagation(); setWindow(w.id); }}
              className={`px-1.5 py-0.5 text-[11px] font-mono transition-colors ${
                w.id === window
                  ? 'text-[var(--term-electric-fg)]'
                  : 'text-[var(--term-text-muted)] hover:text-[var(--term-text)]'
              }`}
            >
              [{w.label}]
            </button>
          ))}
        </div>
      </div>

      {/* Expanded panel: top moments + threat patterns */}
      {expanded && !noActivity && (
        <div className="border-t border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/50 px-4 py-3">
          <div className="grid gap-3 md:grid-cols-2">
            <div>
              <div className="mb-2 text-[10px] uppercase tracking-[0.14em] text-[var(--sc-text-muted)]">
                Top moments
              </div>
              {data.topMoments.length === 0 ? (
                <div className="text-xs text-[var(--sc-text-muted)]">Nothing notable to surface in this window.</div>
              ) : (
                <ul className="space-y-1.5">
                  {data.topMoments.map((m, i) => <MomentRow key={`${m.kind}-${i}-${m.timestamp}`} moment={m} />)}
                </ul>
              )}
            </div>
            <div>
              <div className="mb-2 text-[10px] uppercase tracking-[0.14em] text-[var(--sc-text-muted)]">
                Top threat patterns
              </div>
              {data.topThreatPatterns.length === 0 ? (
                <div className="text-xs text-[var(--sc-text-muted)]">No threat patterns triggered.</div>
              ) : (
                <ul className="space-y-1">
                  {data.topThreatPatterns.map((p) => (
                    <li
                      key={p.pattern}
                      className="flex items-center justify-between rounded border border-[var(--sc-border)] bg-[var(--sc-bg-surface)]/50 px-2 py-1 text-xs"
                    >
                      <span className="font-mono text-[var(--sc-text-primary)] truncate">{p.pattern}</span>
                      <span className="font-mono text-[var(--sc-text-muted)]">{p.count}×</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
