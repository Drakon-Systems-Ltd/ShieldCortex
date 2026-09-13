'use client';

import type { Severity, RiskLevel } from '@/types/skills';

const SEVERITY_STYLES: Record<string, string> = {
  critical: 'text-[var(--sc-coral)] bg-[var(--sc-coral)]/10',
  high: 'text-[var(--sc-coral)] bg-[var(--sc-coral)]/10',
  medium: 'text-[var(--sc-amber)] bg-[var(--sc-amber)]/10',
  low: 'text-[var(--sc-text-secondary)] bg-[var(--sc-bg-elevated)]/10',
  safe: 'text-[var(--sc-cyan)] bg-[var(--sc-cyan)]/10',
};

export function SeverityBadge({ level }: { level: Severity | RiskLevel }) {
  const style = SEVERITY_STYLES[level] ?? SEVERITY_STYLES.low;
  return (
    <span className={`text-[10px] font-medium px-1.5 py-0.5 rounded ${style}`}>
      {level.toUpperCase()}
    </span>
  );
}
