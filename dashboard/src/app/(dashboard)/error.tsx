'use client';

import { useEffect } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

export default function DashboardError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error('[Dashboard Error]', error);
  }, [error]);

  return (
    <div className="flex h-full items-center justify-center p-8">
      <div className="glass-card max-w-lg p-8 text-center">
        <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-xl bg-[var(--sc-coral)]/10">
          <AlertTriangle size={24} className="text-[var(--sc-coral)]" />
        </div>
        <h2 className="text-xl font-bold text-[var(--sc-text-primary)]">Something went wrong</h2>
        <p className="mt-2 text-sm text-[var(--sc-text-secondary)]">
          {error.message || 'An unexpected error occurred in the dashboard.'}
        </p>
        {error.digest && (
          <p className="mt-1 font-mono text-xs text-[var(--sc-text-muted)]">
            Error ID: {error.digest}
          </p>
        )}
        <div className="mt-6 flex justify-center gap-3">
          <button
            onClick={reset}
            className="inline-flex items-center gap-2 rounded-xl bg-[var(--sc-coral)] px-4 py-2 text-sm font-semibold text-white transition-all hover:-translate-y-0.5 hover:shadow-[0_8px_30px_var(--sc-glow-coral-mid)]"
          >
            <RefreshCw size={14} />
            Try again
          </button>
          <a
            href="/overview"
            className="inline-flex items-center gap-2 rounded-xl border border-[var(--sc-border)] px-4 py-2 text-sm font-medium text-[var(--sc-text-secondary)] transition-colors hover:bg-[var(--sc-surface-interactive)]"
          >
            Go to Overview
          </a>
        </div>
      </div>
    </div>
  );
}
