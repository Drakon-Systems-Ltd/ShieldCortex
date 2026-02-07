'use client';

import { useState, useEffect } from 'react';
import { Cloud, ArrowRight, Loader2, CheckCircle2, X } from 'lucide-react';
import { useAuditStats } from '@/hooks/useDefence';
import { useDashboardStore } from '@/lib/store';

type CardState = 'upsell' | 'polling' | 'success' | 'hidden';

export function CloudUpsellCard() {
  const { projectFilter } = useDashboardStore();
  const { data: stats } = useAuditStats('30d', projectFilter || undefined);
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
    fetch('http://localhost:3001/api/cloud/config')
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
          await fetch('http://localhost:3001/api/cloud/config', {
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

  return (
    <div className="mt-4 bg-gradient-to-br from-slate-900 via-slate-900 to-cyan-950/30 border border-cyan-800/30 rounded-xl p-5 relative">
      {/* Dismiss button */}
      {state === 'upsell' && (
        <button
          onClick={handleDismiss}
          className="absolute top-3 right-3 text-slate-500 hover:text-slate-300 transition-colors"
          title="Dismiss for 30 days"
        >
          <X size={16} />
        </button>
      )}

      {state === 'upsell' && (
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <Cloud size={20} className="text-cyan-400" />
            <h3 className="text-sm font-semibold text-white">ShieldCortex Cloud</h3>
          </div>

          <p className="text-sm text-slate-300">
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
              className="flex-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white placeholder:text-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 focus:border-cyan-500"
            />
            <button
              type="submit"
              disabled={isSubmitting}
              className="flex items-center gap-1.5 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 rounded-lg text-sm font-medium text-white transition-colors"
            >
              {isSubmitting ? <Loader2 size={14} className="animate-spin" /> : <ArrowRight size={14} />}
              Get Started
            </button>
          </form>

          {error && (
            <p className="text-xs text-red-400">{error}</p>
          )}

          <p className="text-[10px] text-slate-500">Free tier: 500 scans/month, 7-day retention. No credit card required.</p>
        </div>
      )}

      {state === 'polling' && (
        <div className="flex items-center gap-3 py-2">
          <Loader2 size={20} className="text-cyan-400 animate-spin" />
          <div>
            <p className="text-sm text-white font-medium">Check your email</p>
            <p className="text-xs text-slate-400">Click the link in your inbox to complete setup. We&apos;ll auto-configure everything.</p>
          </div>
        </div>
      )}

      {state === 'success' && (
        <div className="flex items-center gap-3 py-2">
          <CheckCircle2 size={20} className="text-emerald-400" />
          <div>
            <p className="text-sm text-white font-medium">Connected to ShieldCortex Cloud</p>
            <p className="text-xs text-slate-400">Your defence data will now sync automatically.</p>
          </div>
        </div>
      )}
    </div>
  );
}
