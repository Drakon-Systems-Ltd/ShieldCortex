'use client';

import { useState } from 'react';
import { Search, AlertTriangle, FileSearch } from 'lucide-react';
import { gatedFetch, FeatureLockedError } from '@/lib/auth';
import { PREVIEW_DEEP_SCAN } from '@/lib/pro-previews';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

interface DeepScanResult {
  correlations: Array<{ files: string[]; finding: string; severity: 'critical' | 'high' | 'medium' }>;
  intentBreakdown: Record<string, number>;
  recommendations: string[];
  degraded: boolean;
  degradedReason?: string;
}

function DeepScanForm() {
  const [result, setResult] = useState<DeepScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isLocked, setIsLocked] = useState(false);

  const runScan = async () => {
    setLoading(true);
    setError(null);
    try {
      // Use the skill scanner discover endpoint to find skill files,
      // or for demo just scan with empty files to show the UI
      const response = await gatedFetch(`${API_BASE}/api/skills/deep-scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ files: [] }),
      });
      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.error || 'Deep scan failed');
      }
      setResult(await response.json());
    } catch (err) {
      if (err instanceof FeatureLockedError) {
        setIsLocked(true);
      } else {
        setError((err as Error).message);
      }
    } finally {
      setLoading(false);
    }
  };

  if (isLocked) return <PreviewContent />;

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <FileSearch size={16} className="text-[var(--sc-cyan)]" />
          <h3 className="text-sm font-medium text-[var(--sc-text-primary)]">Deep Skill Scanner</h3>
        </div>
        <button
          onClick={runScan}
          disabled={loading}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-[var(--sc-cyan)] text-[var(--sc-text-primary)] rounded-lg hover:bg-[var(--sc-cyan)] disabled:opacity-50 transition-colors"
        >
          <Search size={12} />
          {loading ? 'Scanning...' : 'Run Deep Scan'}
        </button>
      </div>

      {error && <p className="text-xs text-[var(--sc-coral)]">{error}</p>}

      {result && (
        <div className="space-y-3">
          {result.degraded && (
            <p className="text-[10px] text-[var(--sc-amber)] bg-[var(--sc-amber)]/10 px-2 py-1 rounded">
              {result.degradedReason}
            </p>
          )}

          {result.correlations.length > 0 && (
            <div className="space-y-1">
              <h4 className="text-xs text-[var(--sc-text-secondary)] font-medium">Cross-File Correlations</h4>
              {result.correlations.map((c, i) => (
                <div key={i} className="flex items-start gap-2 px-3 py-2 bg-[var(--sc-bg-elevated)] rounded text-xs">
                  <AlertTriangle size={12} className={
                    c.severity === 'critical' ? 'text-[var(--sc-coral)] mt-0.5' :
                    c.severity === 'high' ? 'text-[var(--sc-coral)] mt-0.5' :
                    'text-[var(--sc-amber)] mt-0.5'
                  } />
                  <div>
                    <p className="text-[var(--sc-text-primary)]">{c.finding}</p>
                    <p className="text-[var(--sc-text-muted)] text-[10px]">Files: {c.files.join(', ')}</p>
                  </div>
                </div>
              ))}
            </div>
          )}

          {Object.keys(result.intentBreakdown).length > 0 && (
            <div>
              <h4 className="text-xs text-[var(--sc-text-secondary)] font-medium mb-1">Intent Breakdown</h4>
              <div className="grid grid-cols-2 gap-1">
                {Object.entries(result.intentBreakdown).map(([key, value]) => (
                  <div key={key} className="flex items-center gap-2 text-xs">
                    <div className="flex-1">
                      <div className="h-1.5 bg-[var(--sc-bg-elevated)] rounded-full overflow-hidden">
                        <div className="h-full bg-[var(--sc-cyan)]/60 rounded-full" style={{ width: `${Math.min(100, value * 5)}%` }} />
                      </div>
                    </div>
                    <span className="text-[var(--sc-text-muted)] text-[10px] w-16 truncate">{key}</span>
                    <span className="text-[var(--sc-text-secondary)] text-[10px] w-4 text-right">{value}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {result.recommendations.length > 0 && (
            <div>
              <h4 className="text-xs text-[var(--sc-text-secondary)] font-medium mb-1">Recommendations</h4>
              <ul className="space-y-1">
                {result.recommendations.map((r, i) => (
                  <li key={i} className="text-xs text-[var(--sc-text-primary)] pl-3 relative before:absolute before:left-0 before:top-1.5 before:w-1.5 before:h-1.5 before:rounded-full before:bg-[var(--sc-cyan)]/40">{r}</li>
                ))}
              </ul>
            </div>
          )}

          {result.correlations.length === 0 && Object.keys(result.intentBreakdown).length === 0 && (
            <p className="text-xs text-[var(--sc-text-muted)] text-center py-2">No files provided for scanning. Upload skill files to analyse.</p>
          )}
        </div>
      )}

      {!result && !loading && (
        <p className="text-xs text-[var(--sc-text-muted)] text-center py-2">Run a deep scan to analyse skill files for cross-file threats and intent patterns.</p>
      )}
    </div>
  );
}

function PreviewContent() {
  const preview = PREVIEW_DEEP_SCAN;
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <FileSearch size={16} className="text-[var(--sc-cyan)]" />
        <h3 className="text-sm font-medium text-[var(--sc-text-primary)]">Deep Skill Scanner</h3>
      </div>

      <div className="space-y-1">
        <h4 className="text-xs text-[var(--sc-text-secondary)] font-medium">Cross-File Correlations</h4>
        {preview.correlations.map((c, i) => (
          <div key={i} className="flex items-start gap-2 px-3 py-2 bg-[var(--sc-bg-elevated)] rounded text-xs">
            <AlertTriangle size={12} className={
              c.severity === 'critical' ? 'text-[var(--sc-coral)] mt-0.5' :
              c.severity === 'high' ? 'text-[var(--sc-coral)] mt-0.5' :
              'text-[var(--sc-amber)] mt-0.5'
            } />
            <div>
              <p className="text-[var(--sc-text-primary)]">{c.finding}</p>
              <p className="text-[var(--sc-text-muted)] text-[10px]">Files: {c.files.join(', ')}</p>
            </div>
          </div>
        ))}
      </div>

      <div>
        <h4 className="text-xs text-[var(--sc-text-secondary)] font-medium mb-1">Intent Breakdown</h4>
        <div className="grid grid-cols-2 gap-1">
          {Object.entries(preview.intentBreakdown).map(([key, value]) => (
            <div key={key} className="flex items-center gap-2 text-xs">
              <div className="flex-1">
                <div className="h-1.5 bg-[var(--sc-bg-elevated)] rounded-full overflow-hidden">
                  <div className="h-full bg-[var(--sc-cyan)]/60 rounded-full" style={{ width: `${value}%` }} />
                </div>
              </div>
              <span className="text-[var(--sc-text-muted)] text-[10px] w-16 truncate">{key}</span>
              <span className="text-[var(--sc-text-secondary)] text-[10px] w-4 text-right">{value}</span>
            </div>
          ))}
        </div>
      </div>

      <div>
        <h4 className="text-xs text-[var(--sc-text-secondary)] font-medium mb-1">Recommendations</h4>
        <ul className="space-y-1">
          {preview.recommendations.map((r, i) => (
            <li key={i} className="text-xs text-[var(--sc-text-primary)] pl-3 relative before:absolute before:left-0 before:top-1.5 before:w-1.5 before:h-1.5 before:rounded-full before:bg-[var(--sc-cyan)]/40">{r}</li>
          ))}
        </ul>
      </div>
    </div>
  );
}

export function DeepScanPanel() {
  return (
    <div className="bg-[var(--sc-bg-surface)] border border-[var(--sc-border)] rounded-xl p-4">
      <DeepScanForm />
    </div>
  );
}
