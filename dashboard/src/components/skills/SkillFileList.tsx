'use client';

import { useState } from 'react';
import { CheckCircle2, XCircle, ChevronDown, ChevronRight } from 'lucide-react';
import type { SkillScanFileResult } from '@/types/skills';
import { SeverityBadge } from './SeverityBadge';
import { SkillFindingDetails } from './SkillFindingDetails';

function basename(filePath: string): string {
  const parts = filePath.split(/[/\\]/);
  return parts[parts.length - 1] || filePath;
}

function SkillFileRow({ file }: { file: SkillScanFileResult }) {
  const [expanded, setExpanded] = useState(!file.safe);

  return (
    <div className="bg-slate-800/50 border border-slate-700 rounded-lg overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full px-3 py-2.5 flex items-center gap-3 hover:bg-slate-800/80 transition-colors"
      >
        {file.safe ? (
          <CheckCircle2 size={16} className="text-green-400 shrink-0" />
        ) : (
          <XCircle size={16} className="text-red-400 shrink-0" />
        )}

        <span className="text-xs font-medium text-white truncate flex-1 text-left" title={file.path}>
          {basename(file.path)}
        </span>

        <span className="text-[10px] text-slate-500 shrink-0">{file.format}</span>

        <SeverityBadge level={file.riskLevel} />

        <span className="text-[10px] text-slate-600 shrink-0">{file.scanDurationMs}ms</span>

        {file.findings.length > 0 ? (
          expanded ? (
            <ChevronDown size={14} className="text-slate-500 shrink-0" />
          ) : (
            <ChevronRight size={14} className="text-slate-500 shrink-0" />
          )
        ) : (
          <div className="w-[14px] shrink-0" />
        )}
      </button>

      {expanded && file.findings.length > 0 && (
        <div className="border-t border-slate-700/50 px-3 py-2 bg-slate-900/50">
          <SkillFindingDetails findings={file.findings} />
        </div>
      )}
    </div>
  );
}

export function SkillFileList({ files }: { files: SkillScanFileResult[] }) {
  if (files.length === 0) return null;

  return (
    <div className="space-y-1.5">
      {files.map((file) => (
        <SkillFileRow key={file.path} file={file} />
      ))}
    </div>
  );
}
