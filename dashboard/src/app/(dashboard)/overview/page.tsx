'use client';

import { useMemo } from 'react';
import Link from 'next/link';
import {
  AlertTriangle,
  CheckCircle2,
  Clock3,
  Database,
  FileText,
  ScanSearch,
  Shield,
  ShieldAlert,
} from 'lucide-react';
import { GlassCard } from '@/components/ds/GlassCard';
import { StatCard } from '@/components/ds/StatCard';
import { Badge } from '@/components/ds/Badge';
import { Button } from '@/components/ds/Button';
import { PageHeader } from '@/components/ds/PageHeader';
import { useStats } from '@/hooks/useMemories';
import { useAuditStats, useQuarantine } from '@/hooks/useDefence';
import { useContradictions, useQuality } from '@/hooks/useMemories';
import { useLicenseStatus } from '@/hooks/useLicense';
import { useXRayStatus } from '@/hooks/useXRay';
import { TIER_LABELS } from '@/lib/license';

export default function OverviewPage() {
  const { data: stats } = useStats();
  const { data: auditStats } = useAuditStats('24h');
  const { data: quarantineData } = useQuarantine('pending', 10);
  const { data: memoryFileQuarantineData } = useQuarantine('pending', 1, undefined, 'memory_file');
  const { data: quality } = useQuality();
  const { data: contradictionsData } = useContradictions();
  const { data: license } = useLicenseStatus();
  const { data: xrayStatus } = useXRayStatus();

  const totalMemories = stats?.total ?? 0;
  const healthyCount = stats?.decayDistribution?.healthy ?? 0;
  const fadingCount = stats?.decayDistribution?.fading ?? 0;
  const criticalCount = stats?.decayDistribution?.critical ?? 0;
  const healthPercent = stats?.decayDistribution
    ? Math.round((healthyCount / Math.max(1, totalMemories)) * 100)
    : 0;
  const contradictionCount = contradictionsData?.count ?? contradictionsData?.contradictions?.length ?? 0;
  const pendingQuarantine = quarantineData?.total ?? 0;
  const pendingMemoryFileFindings = memoryFileQuarantineData?.total ?? 0;
  const pendingMemoryWriteQuarantine = Math.max(0, pendingQuarantine - pendingMemoryFileFindings);
  const blockedCount = auditStats?.blockedCount ?? 0;
  const duplicateCount = quality?.duplicates?.count ?? 0;
  const staleCount = quality?.stale?.count ?? 0;
  const neverAccessedCount = quality?.neverAccessed?.count ?? 0;
  const totalXRayScans = xrayStatus?.summary?.scans ?? 0;

  const urgentItems = useMemo(() => {
    const items: { title: string; detail: string; severity: 'critical' | 'high' | 'medium' | 'low' | 'safe'; href: string; cta: string }[] = [];

    if (pendingMemoryFileFindings > 0) {
      items.push({
        title: `${pendingMemoryFileFindings} memory file finding${pendingMemoryFileFindings === 1 ? '' : 's'} need review`,
        detail: 'These are scanned agent memory files, not stored ShieldCortex memories.',
        severity: pendingMemoryFileFindings > 10 ? 'critical' : 'medium',
        href: '/protection?tab=quarantine',
        cta: 'Review files',
      });
    }

    if (pendingMemoryWriteQuarantine > 0) {
      items.push({
        title: `${pendingMemoryWriteQuarantine} memory write${pendingMemoryWriteQuarantine === 1 ? '' : 's'} in quarantine`,
        detail: 'Review blocked writes before they become silent operator debt.',
        severity: pendingMemoryWriteQuarantine > 10 ? 'critical' : 'medium',
        href: '/protection?tab=quarantine',
        cta: 'Review writes',
      });
    }

    if (contradictionCount > 0) {
      items.push({
        title: `${contradictionCount} contradiction${contradictionCount === 1 ? '' : 's'} detected`,
        detail: 'Conflicting facts reduce recall trust.',
        severity: contradictionCount > 5 ? 'high' : 'medium',
        href: '/memory?tab=review',
        cta: 'Resolve',
      });
    }

    if (blockedCount > 0) {
      items.push({
        title: `${blockedCount} blocked operation${blockedCount === 1 ? '' : 's'} (24h)`,
        detail: 'Defence pipeline blocked suspicious writes.',
        severity: 'high',
        href: '/protection?tab=audit',
        cta: 'View audit',
      });
    }

    if (staleCount + duplicateCount > 0) {
      items.push({
        title: 'Memory cleanup available',
        detail: `${staleCount} stale, ${duplicateCount} duplicate, ${neverAccessedCount} unused memories.`,
        severity: 'low',
        href: '/memory?tab=review',
        cta: 'Clean up',
      });
    }

    return items.slice(0, 4);
  }, [pendingMemoryFileFindings, pendingMemoryWriteQuarantine, contradictionCount, blockedCount, staleCount, duplicateCount, neverAccessedCount]);

  const tier = license?.tier ?? 'free';

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-7xl space-y-6 p-6">
        <PageHeader
          eyebrow="command-centre"
          title="overview"
          subtitle="Stored-memory health, memory-file findings, threat pressure, operational status."
        />

        {/* Two-column terminal window grid: memory + protection stats */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <GlassCard
            title="memory.stats"
            bodyPadding={false}
            statusLine={`healthy=${healthyCount} · fading=${fadingCount} · critical=${criticalCount}`}
          >
            <StatCard label="stored.total" value={totalMemories.toLocaleString()} icon={Database} accent="cyan" />
            <StatCard label="health.percent" value={`${healthPercent}%`} icon={Shield} accent={healthPercent >= 80 ? 'cyan' : healthPercent >= 50 ? 'amber' : 'coral'} />
            <StatCard label="quality.duplicates" value={duplicateCount.toLocaleString()} icon={Database} accent="muted" />
            <StatCard label="quality.stale" value={staleCount.toLocaleString()} icon={Clock3} accent="muted" />
            <StatCard label="quality.unused" value={neverAccessedCount.toLocaleString()} icon={Database} accent="muted" />
          </GlassCard>

          <GlassCard
            title="protection.stats"
            bodyPadding={false}
            statusLine={`window=24h · blocked=${blockedCount} · pending=${pendingQuarantine}`}
          >
            <StatCard label="threats.blocked" value={blockedCount.toLocaleString()} icon={ShieldAlert} accent={blockedCount > 0 ? 'coral' : 'muted'} />
            <StatCard label="memory.file.flags" value={pendingMemoryFileFindings.toLocaleString()} icon={FileText} accent={pendingMemoryFileFindings > 0 ? 'amber' : 'muted'} />
            <StatCard label="quarantine.pending" value={pendingMemoryWriteQuarantine.toLocaleString()} icon={AlertTriangle} accent={pendingMemoryWriteQuarantine > 0 ? 'amber' : 'muted'} />
            <StatCard label="contradictions" value={contradictionCount.toLocaleString()} icon={AlertTriangle} accent={contradictionCount > 0 ? 'coral' : 'muted'} />
            <StatCard label="xray.scans" value={totalXRayScans.toLocaleString()} icon={ScanSearch} accent="cyan" />
          </GlassCard>
        </div>

        {/* Health gauge + Urgent actions */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <GlassCard title="memory.health" statusLine="decay distribution across stored memories">
            <div className="flex items-center justify-center py-2">
              <div className="relative h-36 w-36">
                <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90" aria-hidden>
                  <circle cx="50" cy="50" r="42" fill="none" stroke="var(--term-surface-2)" strokeWidth="6" />
                  <circle
                    cx="50" cy="50" r="42" fill="none"
                    stroke="var(--term-neon)"
                    strokeWidth="6"
                    strokeDasharray={`${healthPercent * 2.64} 264`}
                    strokeLinecap="butt"
                  />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center font-mono">
                  <span className="text-2xl text-[var(--term-text)] tabular-nums">{healthPercent}%</span>
                  <span className="text-[10px] text-[var(--term-text-muted)] uppercase tracking-wider">healthy</span>
                </div>
              </div>
            </div>
            <div className="mt-2 grid grid-cols-3 gap-3 text-center font-mono text-xs">
              <div>
                <div className="text-base text-[var(--term-neon-fg)] tabular-nums">{healthyCount}</div>
                <div className="text-[10px] text-[var(--term-text-muted)] uppercase tracking-wider">healthy</div>
              </div>
              <div>
                <div className="text-base text-[var(--term-warn)] tabular-nums">{fadingCount}</div>
                <div className="text-[10px] text-[var(--term-text-muted)] uppercase tracking-wider">fading</div>
              </div>
              <div>
                <div className="text-base text-[var(--term-danger)] tabular-nums">{criticalCount}</div>
                <div className="text-[10px] text-[var(--term-text-muted)] uppercase tracking-wider">critical</div>
              </div>
            </div>
          </GlassCard>

          <GlassCard
            title="alerts.urgent"
            bodyPadding={false}
            statusLine={urgentItems.length === 0 ? 'no urgent items' : `${urgentItems.length} active`}
          >
            {urgentItems.length === 0 ? (
              <div className="flex items-center gap-3 px-4 py-6">
                <CheckCircle2 size={16} className="shrink-0 text-[var(--term-neon-fg)]" aria-hidden />
                <div className="font-mono text-sm">
                  <p className="text-[var(--term-text)]"><span className="text-[var(--term-neon-fg)]">[OK]</span> all clear</p>
                  <p className="text-xs text-[var(--term-text-muted)] mt-0.5"># no urgent issues right now</p>
                </div>
              </div>
            ) : (
              <ul>
                {urgentItems.map((item) => {
                  const sevLabel =
                    item.severity === 'critical' || item.severity === 'high' ? 'critical'
                    : item.severity === 'medium' ? 'medium'
                    : 'safe';
                  return (
                    <li key={item.title}>
                      <Link
                        href={item.href}
                        className="group flex items-start gap-3 px-4 py-3 border-b border-[var(--term-border)] last:border-0 transition-colors hover:bg-[var(--term-surface-2)] font-mono"
                      >
                        <Badge variant={sevLabel} className="mt-0.5 shrink-0">
                          {sevLabel}
                        </Badge>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm text-[var(--term-text)] truncate">{item.title}</p>
                          <p className="mt-0.5 text-xs text-[var(--term-text-muted)] truncate"># {item.detail}</p>
                        </div>
                        <span className="shrink-0 self-center text-xs text-[var(--term-electric-fg)] opacity-0 group-hover:opacity-100">
                          {item.cta} →
                        </span>
                      </Link>
                    </li>
                  );
                })}
              </ul>
            )}
          </GlassCard>
        </div>

        {/* Quick actions — terminal command list */}
        <GlassCard title="quick.actions" bodyPadding={false}>
          <ul className="font-mono text-sm">
            {[
              { href: '/xray', cmd: 'shieldcortex xray', desc: 'inspect packages and files for hidden risk', icon: ScanSearch, accent: 'text-[var(--term-electric-fg)]' },
              { href: '/protection?tab=quarantine', cmd: 'shieldcortex quarantine review', desc: `${pendingQuarantine} item${pendingQuarantine === 1 ? '' : 's'} pending`, icon: AlertTriangle, accent: 'text-[var(--term-warn)]' },
              { href: '/memory?tab=recall', cmd: 'shieldcortex recall debug', desc: 'test queries and inspect ranking factors', icon: Database, accent: 'text-[var(--term-electric-fg)]' },
              { href: '/protection?tab=dome', cmd: 'shieldcortex iron-dome status', desc: 'kill switch and behaviour gates', icon: ShieldAlert, accent: 'text-[var(--term-danger)]' },
            ].map(({ href, cmd, desc, icon: Icon, accent }) => (
              <li key={href} className="border-b border-[var(--term-border)] last:border-0">
                <Link
                  href={href}
                  className="flex items-center gap-3 px-4 py-2.5 hover:bg-[var(--term-surface-2)] transition-colors"
                >
                  <Icon size={14} className={`shrink-0 ${accent}`} aria-hidden />
                  <span className="text-[var(--term-electric-fg)]">$</span>
                  <span className="text-[var(--term-text)] truncate">{cmd}</span>
                  <span className="ml-auto truncate text-[var(--term-text-muted)] text-xs"># {desc}</span>
                </Link>
              </li>
            ))}
          </ul>
        </GlassCard>

        {/* Licence */}
        <GlassCard title="licence" statusLine={`tier=${tier}`}>
          <div className="flex items-center justify-between font-mono">
            <div>
              <p className="text-sm text-[var(--term-text)]">
                <span className="text-[var(--term-text-muted)]">tier</span>
                <span className="text-[var(--term-text-muted)] mx-2">=</span>
                <span className="text-[var(--term-electric-fg)]">{TIER_LABELS[tier]}</span>
              </p>
              <p className="mt-1 text-xs text-[var(--term-text-muted)]"># current tier and feature access</p>
            </div>
            <Badge variant={tier === 'pro' ? 'cyan' : tier === 'team' ? 'coral' : 'muted'}>
              {TIER_LABELS[tier]}
            </Badge>
          </div>
          {tier === 'free' && (
            <div className="mt-4 flex items-center gap-4 border border-[var(--term-border)] bg-[var(--term-surface-2)] p-3 rounded-md font-mono text-sm">
              <div className="flex-1">
                <p className="text-[var(--term-text)]">unlock deep scanning, custom policies, and audit exports</p>
                <p className="mt-1 text-xs text-[var(--term-text-muted)]"># pro starts at £29/mo · 10K cloud scans · 90-day retention</p>
              </div>
              <a href="https://shieldcortex.ai/pricing" target="_blank" rel="noopener noreferrer">
                <Button variant="coral" size="sm">upgrade</Button>
              </a>
            </div>
          )}
        </GlassCard>
      </div>
    </div>
  );
}
