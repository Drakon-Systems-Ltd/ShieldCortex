'use client';

import { useMemo } from 'react';
import Link from 'next/link';
import {
  AlertTriangle,
  ArrowRight,
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

export function OverviewGlass() {
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
        detail: 'These are scanned agent memory files, not stored ShieldCortex memories. Review or dismiss them without editing files.',
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

  const quarantineDetail = pendingMemoryFileFindings > 0 && pendingMemoryWriteQuarantine > 0
    ? `${pendingMemoryFileFindings} file finding${pendingMemoryFileFindings === 1 ? '' : 's'}, ${pendingMemoryWriteQuarantine} write${pendingMemoryWriteQuarantine === 1 ? '' : 's'} pending.`
    : pendingMemoryFileFindings > 0
      ? `${pendingMemoryFileFindings} memory-file finding${pendingMemoryFileFindings === 1 ? '' : 's'} pending.`
      : `${pendingQuarantine} item${pendingQuarantine === 1 ? '' : 's'} pending review.`;

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-7xl space-y-6 p-6">
        {/* Header */}
        <PageHeader
          eyebrow="ShieldCortex"
          title="Command Centre"
          subtitle="Stored-memory health, memory-file findings, threat pressure, and operational status at a glance."
        />

        {/* Stats row */}
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
          <StatCard
            label="Stored Memories"
            value={totalMemories.toLocaleString()}
            icon={Database}
            accent="cyan"
            trend={healthPercent > 0 ? { value: healthPercent, label: 'healthy' } : undefined}
          />
          <StatCard
            label="Memory Files Flagged"
            value={pendingMemoryFileFindings.toLocaleString()}
            icon={FileText}
            accent={pendingMemoryFileFindings > 0 ? 'amber' : 'muted'}
          />
          <StatCard
            label="Threats Blocked"
            value={blockedCount.toLocaleString()}
            icon={ShieldAlert}
            accent={blockedCount > 0 ? 'coral' : 'muted'}
          />
          <StatCard
            label="X-Ray Scans"
            value={totalXRayScans.toLocaleString()}
            icon={ScanSearch}
            accent="cyan"
          />
          <StatCard
            label="Health Score"
            value={`${healthPercent}%`}
            icon={Shield}
            accent={healthPercent >= 80 ? 'cyan' : healthPercent >= 50 ? 'amber' : 'coral'}
          />
        </div>

        {/* Health gauge + Urgent actions */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-[1fr_1fr]">
          {/* Health breakdown */}
          <GlassCard className="p-6">
            <h3 className="text-lg font-semibold text-[var(--sc-text-primary)]">Stored Memory Health</h3>
            <p className="mt-1 text-sm text-[var(--sc-text-muted)]">
              Decay distribution across ShieldCortex stored memories.
            </p>

            <div className="mt-6 flex items-center justify-center">
              <div className="relative h-40 w-40">
                <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
                  <circle cx="50" cy="50" r="42" fill="none" stroke="var(--sc-bg-elevated)" strokeWidth="8" />
                  <circle
                    cx="50" cy="50" r="42" fill="none"
                    stroke="var(--sc-cyan)"
                    strokeWidth="8"
                    strokeDasharray={`${healthPercent * 2.64} 264`}
                    strokeLinecap="round"
                    className="transition-all duration-1000"
                  />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className="text-3xl font-bold text-[var(--sc-text-primary)]">{healthPercent}%</span>
                  <span className="text-xs text-[var(--sc-text-muted)]">healthy</span>
                </div>
              </div>
            </div>

            <div className="mt-6 grid grid-cols-3 gap-3 text-center">
              <div>
                <div className="text-lg font-semibold text-[var(--sc-cyan)]">{healthyCount}</div>
                <div className="text-xs text-[var(--sc-text-muted)]">Healthy</div>
              </div>
              <div>
                <div className="text-lg font-semibold text-[var(--sc-amber)]">{fadingCount}</div>
                <div className="text-xs text-[var(--sc-text-muted)]">Fading</div>
              </div>
              <div>
                <div className="text-lg font-semibold text-[var(--sc-coral)]">{criticalCount}</div>
                <div className="text-xs text-[var(--sc-text-muted)]">Critical</div>
              </div>
            </div>
          </GlassCard>

          {/* Urgent actions */}
          <GlassCard className="p-6">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold text-[var(--sc-text-primary)]">Urgent Actions</h3>
              {urgentItems.length > 0 && (
                <Badge variant="coral" dot pulse>{urgentItems.length} active</Badge>
              )}
            </div>
            <p className="mt-1 text-sm text-[var(--sc-text-muted)]">
              Quickest wins for trust, safety, and recall quality.
            </p>

            <div className="mt-4 space-y-3">
              {urgentItems.length === 0 ? (
                <div className="flex items-center gap-3 rounded-xl bg-[var(--sc-bg-elevated)] p-4">
                  <CheckCircle2 size={18} className="shrink-0 text-[var(--sc-cyan)]" />
                  <div>
                    <p className="text-sm font-medium text-[var(--sc-text-primary)]">All clear</p>
                    <p className="text-xs text-[var(--sc-text-muted)]">No urgent issues right now. Memory health looks stable.</p>
                  </div>
                </div>
              ) : (
                urgentItems.map((item) => (
                  <Link
                    key={item.title}
                    href={item.href}
                    className="group flex items-start gap-3 rounded-xl bg-[var(--sc-bg-elevated)] p-4 transition-all hover:bg-[var(--sc-surface-interactive-hover)]"
                  >
                    {item.severity === 'critical' || item.severity === 'high' ? (
                      <AlertTriangle size={16} className="mt-0.5 shrink-0 text-[var(--sc-coral)]" />
                    ) : item.severity === 'medium' ? (
                      <Clock3 size={16} className="mt-0.5 shrink-0 text-[var(--sc-amber)]" />
                    ) : (
                      <CheckCircle2 size={16} className="mt-0.5 shrink-0 text-[var(--sc-cyan)]" />
                    )}
                    <div className="flex-1">
                      <p className="text-sm font-medium text-[var(--sc-text-primary)]">{item.title}</p>
                      <p className="mt-0.5 text-xs text-[var(--sc-text-muted)]">{item.detail}</p>
                    </div>
                    <span className="flex shrink-0 items-center gap-1 text-xs font-medium text-[var(--sc-cyan)] opacity-0 transition-opacity group-hover:opacity-100">
                      {item.cta} <ArrowRight size={12} />
                    </span>
                  </Link>
                ))
              )}
            </div>
          </GlassCard>
        </div>

        {/* Quick actions */}
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <Link href="/xray">
            <GlassCard hover className="p-5">
              <ScanSearch size={20} className="text-[var(--sc-cyan)]" />
              <p className="mt-3 text-sm font-semibold text-[var(--sc-text-primary)]">Run X-Ray Scan</p>
              <p className="mt-1 text-xs text-[var(--sc-text-muted)]">Inspect packages and files for hidden risk.</p>
            </GlassCard>
          </Link>
          <Link href="/protection?tab=quarantine">
            <GlassCard hover className="p-5">
              <AlertTriangle size={20} className="text-[var(--sc-amber)]" />
              <p className="mt-3 text-sm font-semibold text-[var(--sc-text-primary)]">Review Quarantine</p>
              <p className="mt-1 text-xs text-[var(--sc-text-muted)]">{quarantineDetail}</p>
            </GlassCard>
          </Link>
          <Link href="/memory?tab=recall">
            <GlassCard hover className="p-5">
              <Database size={20} className="text-[var(--sc-cyan)]" />
              <p className="mt-3 text-sm font-semibold text-[var(--sc-text-primary)]">Debug Recall</p>
              <p className="mt-1 text-xs text-[var(--sc-text-muted)]">Test queries and inspect ranking factors.</p>
            </GlassCard>
          </Link>
          <Link href="/protection?tab=dome">
            <GlassCard hover className="p-5">
              <ShieldAlert size={20} className="text-[var(--sc-coral)]" />
              <p className="mt-3 text-sm font-semibold text-[var(--sc-text-primary)]">Iron Dome</p>
              <p className="mt-1 text-xs text-[var(--sc-text-muted)]">Kill switch and behaviour gates.</p>
            </GlassCard>
          </Link>
        </div>

        {/* Licence status */}
        <GlassCard className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-lg font-semibold text-[var(--sc-text-primary)]">Licence</h3>
              <p className="mt-1 text-sm text-[var(--sc-text-muted)]">
                Current tier and feature access.
              </p>
            </div>
            <Badge variant={license?.tier === 'pro' ? 'cyan' : license?.tier === 'team' ? 'coral' : 'muted'}>
              {TIER_LABELS[license?.tier ?? 'free']}
            </Badge>
          </div>
          {license?.tier === 'free' && (
            <div className="mt-4 flex items-center gap-4 rounded-xl bg-gradient-to-r from-[var(--sc-coral)]/5 to-[var(--sc-cyan)]/5 p-4">
              <div className="flex-1">
                <p className="text-sm font-medium text-[var(--sc-text-primary)]">Unlock deep scanning, custom policies, and audit exports</p>
                <p className="mt-1 text-xs text-[var(--sc-text-muted)]">Pro starts at £29/mo with 10K cloud scans and 90-day retention.</p>
              </div>
              <a href="https://shieldcortex.ai/pricing" target="_blank" rel="noopener noreferrer">
                <Button variant="coral" size="sm" glow>Upgrade</Button>
              </a>
            </div>
          )}
        </GlassCard>
      </div>
    </div>
  );
}
