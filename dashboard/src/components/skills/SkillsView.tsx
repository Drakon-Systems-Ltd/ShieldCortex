'use client';

import { useState } from 'react';
import { FileSearch, Loader2, ChevronDown, ChevronRight, Cloud } from 'lucide-react';
import { useSkillScanAll, useSkillScanContent, useSkillTrust, useSkillUntrust, useDeleteSkillFile } from '@/hooks/useSkillScan';
import { useCloudStatus } from '@/hooks/useCloudStatus';
import type { SkillScanAllResponse, SkillScanContentResult } from '@/types/skills';
import { SkillFileList } from './SkillFileList';
import { SeverityBadge } from './SeverityBadge';
import { SkillFindingDetails } from './SkillFindingDetails';

const FORMATS = [
  { value: '', label: 'Auto-detect' },
  { value: 'skill-md', label: 'SKILL.md (Claude Code)' },
  { value: 'hook-md', label: 'HOOK.md (OpenClaw)' },
  { value: 'hook-js', label: 'handler.js (OpenClaw)' },
  { value: 'rules', label: '.cursorrules / .windsurfrules / .clinerules' },
  { value: 'claude-md', label: 'CLAUDE.md' },
  { value: 'copilot-md', label: 'copilot-instructions.md' },
  { value: 'aider-yml', label: '.aider.conf.yml' },
  { value: 'continue-json', label: '.continue/config.json' },
];

export function SkillsView() {
  const scanAll = useSkillScanAll();
  const scanContent = useSkillScanContent();
  const trustMutation = useSkillTrust();
  const untrustMutation = useSkillUntrust();
  const deleteMutation = useDeleteSkillFile();
  const { data: cloudConfig } = useCloudStatus();

  const [scanResult, setScanResult] = useState<SkillScanAllResponse | null>(null);
  const [pasteResult, setPasteResult] = useState<SkillScanContentResult | null>(null);
  const [showPaste, setShowPaste] = useState(false);
  const [pasteContent, setPasteContent] = useState('');
  const [pasteFormat, setPasteFormat] = useState('');
  const [showCloudUpsell, setShowCloudUpsell] = useState(false);

  const cloudConnected = !!(cloudConfig?.enabled && cloudConfig?.apiKeySet);

  const handleScanAll = () => {
    scanAll.mutate(undefined, {
      onSuccess: (data) => setScanResult(data),
    });
  };

  const handleScanContent = () => {
    if (!pasteContent.trim()) return;
    scanContent.mutate(
      { content: pasteContent, format: pasteFormat || undefined },
      { onSuccess: (data) => setPasteResult(data) },
    );
  };

  const handleTrust = (path: string) => {
    trustMutation.mutate(path, {
      onSuccess: () => {
        // Update local state to reflect trust immediately
        if (scanResult) {
          setScanResult({
            ...scanResult,
            files: scanResult.files.map(f =>
              f.path === path ? { ...f, trusted: true } : f
            ),
            threatCount: scanResult.files.filter(f => !f.safe && !f.trusted && f.path !== path).length,
          });
        }
      },
    });
  };

  const handleUntrust = (path: string) => {
    untrustMutation.mutate(path, {
      onSuccess: () => {
        if (scanResult) {
          setScanResult({
            ...scanResult,
            files: scanResult.files.map(f =>
              f.path === path ? { ...f, trusted: false } : f
            ),
            threatCount: scanResult.files.filter(f => {
              const isTrusted = f.path === path ? false : f.trusted;
              return !f.safe && !isTrusted;
            }).length,
          });
        }
      },
    });
  };

  const handleRemove = (path: string) => {
    deleteMutation.mutate(path, {
      onSuccess: () => {
        // Remove from local state
        if (scanResult) {
          const updated = scanResult.files.filter(f => f.path !== path);
          setScanResult({
            ...scanResult,
            files: updated,
            totalScanned: updated.length,
            threatCount: updated.filter(f => !f.safe && !f.trusted).length,
          });
        }
      },
    });
  };

  return (
    <div className="h-full overflow-y-auto p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-lg font-semibold text-white">Skills Scanner</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Scan agent instruction files for hidden threats
          </p>
        </div>
        <button
          onClick={handleScanAll}
          disabled={scanAll.isPending}
          className="flex items-center gap-1.5 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 rounded-lg text-sm font-medium text-white transition-colors"
        >
          {scanAll.isPending ? (
            <Loader2 size={14} className="animate-spin" />
          ) : (
            <FileSearch size={14} />
          )}
          Scan All
        </button>
      </div>

      {/* Cloud upsell banner */}
      {showCloudUpsell && (
        <div className="mb-4 bg-slate-900 border border-cyan-800/50 rounded-xl p-4 flex items-center gap-3">
          <Cloud size={20} className="text-cyan-400 shrink-0" />
          <div className="flex-1">
            <p className="text-sm font-medium text-white">Connect to ShieldCortex Cloud</p>
            <p className="text-xs text-slate-400 mt-0.5">
              Enable one-click skill removal and cloud-powered threat intelligence.
            </p>
          </div>
          <button
            onClick={() => setShowCloudUpsell(false)}
            className="text-xs text-slate-500 hover:text-slate-300 transition-colors"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Scan Results */}
      {scanResult ? (
        <div className="space-y-4">
          {/* Summary bar */}
          <div className="flex items-center gap-3 text-xs text-slate-400">
            <span>
              <span className="text-white font-medium">{scanResult.totalScanned}</span> files scanned
            </span>
            <span className="text-slate-600">&middot;</span>
            {scanResult.threatCount > 0 ? (
              <span>
                <span className="text-red-400 font-medium">{scanResult.threatCount}</span> with threats
              </span>
            ) : (
              <span className="text-green-400">All clean</span>
            )}
            <span className="text-slate-600">&middot;</span>
            <span>
              {new Date(scanResult.scannedAt).toLocaleTimeString()}
            </span>
          </div>

          {/* File list */}
          <SkillFileList
            files={scanResult.files}
            cloudConnected={cloudConnected}
            onTrust={handleTrust}
            onUntrust={handleUntrust}
            onRemove={handleRemove}
            onCloudUpsell={() => setShowCloudUpsell(true)}
          />
        </div>
      ) : !scanAll.isPending ? (
        /* Empty state */
        <div className="flex flex-col items-center justify-center py-16 text-center">
          <FileSearch size={32} className="text-slate-600 mb-3" />
          <p className="text-sm text-slate-400">No skills scanned yet</p>
          <p className="text-xs text-slate-500 mt-1">
            Click &quot;Scan All&quot; to discover and scan agent instruction files
          </p>
        </div>
      ) : (
        <div className="flex items-center justify-center py-16">
          <Loader2 size={24} className="text-cyan-400 animate-spin" />
        </div>
      )}

      {/* Paste & Scan section */}
      <div className="mt-6">
        <button
          onClick={() => setShowPaste(!showPaste)}
          className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-300 transition-colors"
        >
          {showPaste ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
          Paste &amp; Scan
        </button>

        {showPaste && (
          <div className="mt-3 bg-slate-900 border border-slate-800 rounded-xl p-4">
            <textarea
              value={pasteContent}
              onChange={(e) => setPasteContent(e.target.value)}
              placeholder="Paste skill/instruction file content here..."
              className="w-full h-32 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white placeholder:text-slate-500 focus:ring-cyan-500 focus:border-cyan-500 resize-y font-mono"
            />
            <div className="flex items-center gap-3 mt-3">
              <select
                value={pasteFormat}
                onChange={(e) => setPasteFormat(e.target.value)}
                className="bg-slate-800 border border-slate-700 text-white text-xs rounded-lg px-3 py-2 focus:ring-cyan-500 focus:border-cyan-500"
              >
                {FORMATS.map((f) => (
                  <option key={f.value} value={f.value}>{f.label}</option>
                ))}
              </select>
              <button
                onClick={handleScanContent}
                disabled={scanContent.isPending || !pasteContent.trim()}
                className="flex items-center gap-1.5 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 rounded-lg text-xs font-medium text-white transition-colors"
              >
                {scanContent.isPending ? (
                  <Loader2 size={12} className="animate-spin" />
                ) : (
                  <FileSearch size={12} />
                )}
                Scan Content
              </button>
            </div>

            {/* Paste scan result */}
            {pasteResult && (
              <div className="mt-4 bg-slate-800/50 border border-slate-700 rounded-lg p-3">
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-xs font-medium text-white">{pasteResult.skillName}</span>
                  <SeverityBadge level={pasteResult.riskLevel} />
                  <span className="text-[10px] text-slate-500">{pasteResult.scanDurationMs}ms</span>
                </div>
                <p className="text-xs text-slate-400">{pasteResult.summary}</p>
                {pasteResult.findings.length > 0 && (
                  <SkillFindingDetails findings={pasteResult.findings} />
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
