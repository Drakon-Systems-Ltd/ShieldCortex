'use client';

import { useState } from 'react';
import { CheckCircle2, XCircle, ChevronDown, ChevronRight, Shield, ShieldCheck, Trash2 } from 'lucide-react';
import type { SkillScanFileResult } from '@/types/skills';
import { SeverityBadge } from './SeverityBadge';
import { SkillFindingDetails } from './SkillFindingDetails';

function basename(filePath: string): string {
  const parts = filePath.split(/[/\\]/);
  return parts[parts.length - 1] || filePath;
}

function shortenPath(p: string): string {
  return p.replace(/^\/Users\/[^/]+/, '~');
}

interface SkillFileRowProps {
  file: SkillScanFileResult;
  cloudConnected: boolean;
  onTrust: (path: string) => void;
  onUntrust: (path: string) => void;
  onRemove: (path: string) => void;
  onCloudUpsell: () => void;
}

function SkillFileRow({ file, cloudConnected, onTrust, onUntrust, onRemove, onCloudUpsell }: SkillFileRowProps) {
  const [expanded, setExpanded] = useState(!file.safe);
  const [confirmRemove, setConfirmRemove] = useState(false);

  return (
    <div className="bg-slate-800/50 border border-slate-700 rounded-lg overflow-hidden">
      <div className="flex items-center">
        <button
          onClick={() => setExpanded(!expanded)}
          className="flex-1 px-3 py-2.5 flex items-center gap-3 hover:bg-slate-800/80 transition-colors min-w-0"
        >
          {file.trusted ? (
            <ShieldCheck size={16} className="text-cyan-400 shrink-0" />
          ) : file.safe ? (
            <CheckCircle2 size={16} className="text-green-400 shrink-0" />
          ) : (
            <XCircle size={16} className="text-red-400 shrink-0" />
          )}

          <div className="flex-1 min-w-0 text-left">
            <span className="text-xs font-medium text-white truncate block">
              {file.skillName || basename(file.path)}
            </span>
            <span className="text-[10px] text-slate-500 truncate block">
              {shortenPath(file.path)}
            </span>
          </div>

          <span className="text-[10px] text-slate-500 shrink-0">{file.format}</span>

          {file.trusted ? (
            <span className="text-[10px] px-1.5 py-0.5 rounded font-medium bg-cyan-400/10 text-cyan-400">TRUSTED</span>
          ) : (
            <SeverityBadge level={file.riskLevel} />
          )}

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

        {/* Action buttons */}
        <div className="flex items-center gap-0.5 pr-2 shrink-0">
          {/* Trust / Untrust */}
          {file.trusted ? (
            <button
              onClick={() => onUntrust(file.path)}
              title="Remove trust"
              className="p-1.5 rounded hover:bg-slate-700 transition-colors text-cyan-400 hover:text-cyan-300"
            >
              <ShieldCheck size={14} />
            </button>
          ) : (
            <button
              onClick={() => onTrust(file.path)}
              title="Mark as trusted"
              className="p-1.5 rounded hover:bg-slate-700 transition-colors text-slate-500 hover:text-cyan-400"
            >
              <Shield size={14} />
            </button>
          )}

          {/* Remove */}
          {!file.safe && !file.trusted && (
            <button
              onClick={() => cloudConnected ? setConfirmRemove(true) : onCloudUpsell()}
              title={cloudConnected ? 'Remove skill file' : 'Connect to Cloud to remove'}
              className={`p-1.5 rounded transition-colors ${
                cloudConnected
                  ? 'hover:bg-red-500/10 text-slate-500 hover:text-red-400'
                  : 'text-slate-600 hover:text-slate-400 cursor-not-allowed'
              }`}
            >
              <Trash2 size={14} />
            </button>
          )}
        </div>
      </div>

      {/* Confirm remove dialog */}
      {confirmRemove && (
        <div className="border-t border-slate-700/50 px-3 py-2.5 bg-red-950/30 flex items-center gap-3">
          <span className="text-xs text-red-300 flex-1">
            Remove <span className="font-medium">{file.skillName || basename(file.path)}</span>? This will delete the file from disk.
          </span>
          <button
            onClick={() => { onRemove(file.path); setConfirmRemove(false); }}
            className="px-3 py-1 text-xs font-medium bg-red-600 hover:bg-red-500 text-white rounded transition-colors"
          >
            Delete
          </button>
          <button
            onClick={() => setConfirmRemove(false)}
            className="px-3 py-1 text-xs text-slate-400 hover:text-white transition-colors"
          >
            Cancel
          </button>
        </div>
      )}

      {expanded && file.findings.length > 0 && (
        <div className="border-t border-slate-700/50 px-3 py-2 bg-slate-900/50">
          <SkillFindingDetails findings={file.findings} />
        </div>
      )}
    </div>
  );
}

interface SkillFileListProps {
  files: SkillScanFileResult[];
  cloudConnected: boolean;
  onTrust: (path: string) => void;
  onUntrust: (path: string) => void;
  onRemove: (path: string) => void;
  onCloudUpsell: () => void;
}

export function SkillFileList({ files, cloudConnected, onTrust, onUntrust, onRemove, onCloudUpsell }: SkillFileListProps) {
  if (files.length === 0) return null;

  return (
    <div className="space-y-1.5">
      {files.map((file) => (
        <SkillFileRow
          key={file.path}
          file={file}
          cloudConnected={cloudConnected}
          onTrust={onTrust}
          onUntrust={onUntrust}
          onRemove={onRemove}
          onCloudUpsell={onCloudUpsell}
        />
      ))}
    </div>
  );
}
