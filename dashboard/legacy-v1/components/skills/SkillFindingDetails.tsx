'use client';

import type { SkillThreatFinding } from '@/types/skills';
import { SeverityBadge } from './SeverityBadge';

export function SkillFindingDetails({ findings }: { findings: SkillThreatFinding[] }) {
  if (findings.length === 0) return null;

  return (
    <div className="mt-2 space-y-1.5 pl-6">
      {findings.map((f, i) => (
        <div key={`${f.pattern}-${i}`} className="flex items-start gap-2">
          <SeverityBadge level={f.severity} />
          <div className="flex-1 min-w-0">
            <span className="text-xs text-[var(--sc-text-primary)]">{f.description}</span>
            {f.matchedText && (
              <div className="mt-0.5 text-[10px] text-[var(--sc-text-muted)] font-mono truncate">
                Match: &quot;{f.matchedText}&quot;
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
