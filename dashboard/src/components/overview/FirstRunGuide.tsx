'use client';

import { Sparkles, Terminal, Database, ScanSearch } from 'lucide-react';
import { GlassCard } from '@/components/ds/GlassCard';

interface FirstRunGuideProps {
  /** True once stats have loaded — avoids flashing the guide during the initial fetch. */
  ready: boolean;
  memoryCount: number;
  scanCount: number;
  blockedCount: number;
}

/**
 * First-run guide for a genuinely fresh install — no stored memories, no scans,
 * no blocked operations. Replaces the "silent voids" a brand-new user used to
 * see with a positioning primer (what the dashboard is for vs the CLI) and a
 * short checklist of how to generate data. Data-driven: it disappears the moment
 * there's any activity, so it needs no "dismissed" persistence.
 */
export function FirstRunGuide({ ready, memoryCount, scanCount, blockedCount }: FirstRunGuideProps) {
  if (!ready || memoryCount > 0 || scanCount > 0 || blockedCount > 0) return null;

  return (
    <GlassCard strong className="p-6">
      <div className="flex items-center gap-2">
        <Sparkles size={16} className="text-[var(--sc-cyan)]" />
        <h3 className="text-lg font-semibold text-[var(--sc-text-primary)]">Welcome to ShieldCortex</h3>
      </div>
      <p className="mt-2 max-w-2xl text-sm text-[var(--sc-text-secondary)]">
        Nothing here yet. The dashboard is for <strong className="text-[var(--sc-text-primary)]">visual
        review and bulk decisions</strong>; the <code className="font-mono">shieldcortex</code> CLI and
        the agent hooks are for <strong className="text-[var(--sc-text-primary)]">automation</strong>.
        It fills in as your agents capture memories and the defence pipeline runs.
      </p>

      <div className="mt-5 grid gap-3 sm:grid-cols-3">
        <div className="rounded-xl border border-[var(--sc-border)] bg-[var(--sc-bg-elevated)] p-4">
          <Database size={16} className="text-[var(--sc-cyan)]" />
          <p className="mt-2 text-sm font-medium text-[var(--sc-text-primary)]">Capture memories</p>
          <p className="mt-1 text-xs text-[var(--sc-text-muted)]">
            Captured automatically as you work (Claude Code / OpenClaw hooks), or via the{' '}
            <code className="font-mono">remember</code> MCP tool.
          </p>
        </div>
        <div className="rounded-xl border border-[var(--sc-border)] bg-[var(--sc-bg-elevated)] p-4">
          <Terminal size={16} className="text-[var(--sc-cyan)]" />
          <p className="mt-2 text-sm font-medium text-[var(--sc-text-primary)]">Generate audit data</p>
          <p className="mt-1 text-xs text-[var(--sc-text-muted)]">
            Run <code className="font-mono">shieldcortex scan &lt;file&gt;</code> to push content through
            the defence pipeline and populate the audit log.
          </p>
        </div>
        <div className="rounded-xl border border-[var(--sc-border)] bg-[var(--sc-bg-elevated)] p-4">
          <ScanSearch size={16} className="text-[var(--sc-cyan)]" />
          <p className="mt-2 text-sm font-medium text-[var(--sc-text-primary)]">Scan supply chain</p>
          <p className="mt-1 text-xs text-[var(--sc-text-muted)]">
            Run an X-Ray scan from the X-Ray page, or{' '}
            <code className="font-mono">shieldcortex xray &lt;path&gt;</code> from the CLI.
          </p>
        </div>
      </div>
    </GlassCard>
  );
}
