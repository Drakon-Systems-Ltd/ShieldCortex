'use client';

import { useState, useEffect } from 'react';
import { Cloud, ArrowRight, Loader2, CheckCircle2, X, ExternalLink } from 'lucide-react';
import { authFetch } from '@/lib/auth';
import { useAuditStats } from '@/hooks/useDefence';
import { useDashboardStore } from '@/lib/store';
import { useLicenseStatus } from '@/hooks/useLicense';

type CardState = 'upsell' | 'polling' | 'success' | 'hidden';

export function CloudUpsellCard() {
  const { projectFilter } = useDashboardStore();
  const { data: stats } = useAuditStats('30d', projectFilter || undefined);
  const { data: license } = useLicenseStatus();
  const [state, setState] = useState<CardState>('upsell');
  const [email, setEmail] = useState('');
  const [setupId, setSetupId] = useState<string | null>(null);
  const [error, setError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Check if dismissed (localStorage)
  useEffect(() => {
    const dismissed = localStorage.getItem('shieldcortex_cloud_dismissed');
    if (dismissed) {
      const dismissedDate = new Date(dismissed);
      const daysSince = (Date.now() - dismissedDate.getTime()) / (1000 * 60 * 60 * 24);
      if (daysSince < 30) {
        setState('hidden');
      }
    }
  }, []);

  // Check if cloud is already configured
  useEffect(() => {
    authFetch('http://localhost:3001/api/cloud/config')
      .then(res => res.json())
      .then(data => {
        if (data.enabled && data.apiKeySet) {
          setState('hidden');
        }
      })
      .catch(() => {}); // Ignore errors
  }, []);

  // Poll for setup completion
  useEffect(() => {
    if (state !== 'polling' || !setupId) return;

    const interval = setInterval(async () => {
      try {
        const res = await fetch(`https://api.shieldcortex.ai/v1/auth/setup-status/${setupId}`);
        const data = await res.json();

        if (data.status === 'complete' && data.api_key) {
          // Auto-configure local cloud sync
          await authFetch('http://localhost:3001/api/cloud/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              cloudApiKey: data.api_key,
              cloudEnabled: true,
              cloudBaseUrl: 'https://api.shieldcortex.ai',
            }),
          });
          setState('success');
          clearInterval(interval);

          // Hide after 5 seconds
          setTimeout(() => setState('hidden'), 5000);
        } else if (data.status === 'expired') {
          setError('Setup expired. Please try again.');
          setState('upsell');
          clearInterval(interval);
        }
      } catch {
        // Ignore transient errors, keep polling
      }
    }, 3000);

    return () => clearInterval(interval);
  }, [state, setupId]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || isSubmitting) return;

    setError('');
    setIsSubmitting(true);

    try {
      const res = await fetch('https://api.shieldcortex.ai/v1/auth/cloud-setup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });

      const data = await res.json();

      if (data.setup_id) {
        setSetupId(data.setup_id);
        setState('polling');
      } else {
        setError(data.error || 'Failed to start setup');
      }
    } catch {
      setError('Could not reach ShieldCortex Cloud. Check your connection.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDismiss = () => {
    localStorage.setItem('shieldcortex_cloud_dismissed', new Date().toISOString());
    setState('hidden');
  };

  if (state === 'hidden') return null;

  const blockedCount = stats?.blockedCount ?? 0;
  const totalOps = stats?.totalOperations ?? 0;
  const tier = license?.tier ?? 'free';
  const hasCloudAccess = tier === 'team' || tier === 'enterprise';

  // Free/Pro users: show upgrade prompt instead of cloud setup
  if (!hasCloudAccess && state === 'upsell') {
    return (
      <div className="mt-4 bg-gradient-to-br from-slate-900 via-[var(--sc-bg-surface)] to-violet-950/20 border border-[var(--sc-coral)]/30 rounded-xl p-5 relative">
        <button
          onClick={handleDismiss}
          className="absolute top-3 right-3 text-[var(--sc-text-muted)] hover:text-[var(--sc-text-primary)] transition-colors"
          title="Dismiss for 30 days"
        >
          <X size={16} />
        </button>
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Cloud size={20} className="text-[var(--sc-coral)]" />
            <h3 className="text-sm font-semibold text-[var(--sc-text-primary)]">Cloud Sync</h3>
            <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded text-[var(--sc-coral)] bg-[var(--sc-coral)]/10">Team</span>
          </div>
          <p className="text-sm text-[var(--sc-text-primary)]">
            {blockedCount > 0
              ? `You've blocked ${blockedCount} threats locally. Upgrade to Team to sync across devices and give your team visibility.`
              : 'Sync defence data across devices, share audit logs with your team, and get centralised alerts.'}
          </p>
          <a
            href="https://shieldcortex.ai/pricing"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 px-4 py-2 bg-[var(--sc-coral)] hover:bg-[var(--sc-coral)] rounded-lg text-sm font-medium text-[var(--sc-text-primary)] transition-colors"
          >
            Upgrade to Team
            <ExternalLink size={12} />
          </a>
        </div>
      </div>
    );
  }

  return (
    <div className="mt-4 bg-gradient-to-br from-slate-900 via-[var(--sc-bg-surface)] to-cyan-950/30 border border-[var(--sc-cyan)]/30 rounded-xl p-5 relative">
      {/* Dismiss button */}
      {state === 'upsell' && (
        <button
          onClick={handleDismiss}
          className="absolute top-3 right-3 text-[var(--sc-text-muted)] hover:text-[var(--sc-text-primary)] transition-colors"
          title="Dismiss for 30 days"
        >
          <X size={16} />
        </button>
      )}

      {state === 'upsell' && (
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <Cloud size={20} className="text-[var(--sc-cyan)]" />
            <h3 className="text-sm font-semibold text-[var(--sc-text-primary)]">ShieldCortex Cloud</h3>
          </div>

          <p className="text-sm text-[var(--sc-text-primary)]">
            {blockedCount > 0
              ? `You've blocked ${blockedCount} threats across ${totalOps} scans — your team can't see them yet.`
              : 'Sync your defence data to the cloud for team visibility, audit logs, and alerts.'}
          </p>

          <form onSubmit={handleSubmit} className="flex gap-2">
            <input
              type="email"
              placeholder="Enter your email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              className="flex-1 bg-[var(--sc-bg-elevated)] border border-[var(--sc-border)] rounded-lg px-3 py-2 text-sm text-[var(--sc-text-primary)] placeholder:text-[var(--sc-text-muted)] focus:outline-none focus:ring-1 focus:ring-[var(--sc-cyan)] focus:border-[var(--sc-cyan)]"
            />
            <button
              type="submit"
              disabled={isSubmitting}
              className="flex items-center gap-1.5 px-4 py-2 bg-[var(--sc-cyan)] hover:bg-[var(--sc-cyan-mid)] disabled:opacity-50 rounded-lg text-sm font-medium text-[var(--sc-text-primary)] transition-colors"
            >
              {isSubmitting ? <Loader2 size={14} className="animate-spin" /> : <ArrowRight size={14} />}
              Get Started
            </button>
          </form>

          {error && (
            <p className="text-xs text-[var(--sc-coral)]">{error}</p>
          )}

          <p className="text-[10px] text-[var(--sc-text-muted)]">Your Team licence includes cloud sync. Enter your email to connect.</p>
        </div>
      )}

      {state === 'polling' && (
        <div className="flex items-center gap-3 py-2">
          <Loader2 size={20} className="text-[var(--sc-cyan)] animate-spin" />
          <div>
            <p className="text-sm text-[var(--sc-text-primary)] font-medium">Check your email</p>
            <p className="text-xs text-[var(--sc-text-secondary)]">Click the link in your inbox to complete setup. We&apos;ll auto-configure everything.</p>
          </div>
        </div>
      )}

      {state === 'success' && (
        <div className="flex items-center gap-3 py-2">
          <CheckCircle2 size={20} className="text-[var(--sc-cyan)]" />
          <div>
            <p className="text-sm text-[var(--sc-text-primary)] font-medium">Connected to ShieldCortex Cloud</p>
            <p className="text-xs text-[var(--sc-text-secondary)]">Your defence data will now sync automatically.</p>
          </div>
        </div>
      )}
    </div>
  );
}
