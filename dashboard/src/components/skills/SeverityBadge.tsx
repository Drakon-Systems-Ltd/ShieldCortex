'use client';

import type { Severity, RiskLevel } from '@/types/skills';

const SEVERITY_STYLES: Record<string, string> = {
  critical: 'text-red-400 bg-red-400/10',
  high: 'text-red-400 bg-red-400/10',
  medium: 'text-yellow-400 bg-yellow-400/10',
  low: 'text-slate-400 bg-slate-400/10',
  safe: 'text-green-400 bg-green-400/10',
};

export function SeverityBadge({ level }: { level: Severity | RiskLevel }) {
  const style = SEVERITY_STYLES[level] ?? SEVERITY_STYLES.low;
  return (
    <span className={`text-[10px] font-medium px-1.5 py-0.5 rounded ${style}`}>
      {level.toUpperCase()}
    </span>
  );
}
