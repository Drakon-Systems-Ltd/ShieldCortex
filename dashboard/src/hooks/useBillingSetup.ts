'use client';

// DORMANT billing code — intentionally unreferenced since the Free + Enterprise
// repricing removed the in-dashboard Stripe checkout (LicenseStatusCard no
// longer invokes startCheckout). Kept per the "billing code stays dormant, not
// deleted" policy: the SaaS quick-checkout endpoints remain deployed for
// in-flight sessions and any future manually-arranged checkout.

import { useState, useEffect, useCallback } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { authFetch } from '@/lib/auth';

const SAAS_API = 'https://api.shieldcortex.ai';
const LOCAL_API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

type BillingState = 'idle' | 'submitting' | 'polling' | 'activating' | 'complete' | 'error';

interface UseBillingSetupReturn {
  state: BillingState;
  error: string | null;
  startCheckout: (email: string, plan: 'pro' | 'team' | 'enterprise') => Promise<void>;
  reset: () => void;
}

export function useBillingSetup(): UseBillingSetupReturn {
  const queryClient = useQueryClient();
  const [state, setState] = useState<BillingState>('idle');
  const [error, setError] = useState<string | null>(null);
  const [setupId, setSetupId] = useState<string | null>(null);

  const startCheckout = useCallback(async (email: string, plan: 'pro' | 'team' | 'enterprise') => {
    setState('submitting');
    setError(null);

    try {
      const res = await fetch(`${SAAS_API}/v1/billing/quick-checkout`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, plan }),
      });

      const data = await res.json();

      if (!res.ok || !data.checkout_url || !data.setup_id) {
        throw new Error(data.error || 'Failed to create checkout session');
      }

      setSetupId(data.setup_id);
      window.open(data.checkout_url, '_blank');
      setState('polling');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Checkout failed');
      setState('error');
    }
  }, []);

  // Poll for completion
  useEffect(() => {
    if (state !== 'polling' || !setupId) return;

    const interval = setInterval(async () => {
      try {
        const res = await fetch(`${SAAS_API}/v1/billing/setup-status/${setupId}`);
        const data = await res.json();

        if (data.status === 'complete' && data.license_key) {
          clearInterval(interval);
          setState('activating');

          try {
            const activateRes = await authFetch(`${LOCAL_API}/api/license/activate`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ key: data.license_key }),
            });

            if (!activateRes.ok) throw new Error('Local activation failed');

            queryClient.invalidateQueries({ queryKey: ['license-status'] });
            setState('complete');
          } catch {
            setError('Payment succeeded but local activation failed. Use "I Have a Key" to activate manually.');
            setState('error');
          }
        } else if (data.status === 'expired') {
          clearInterval(interval);
          setError('Setup expired. Please try again.');
          setState('error');
        } else if (data.status === 'complete' && !data.license_key) {
          clearInterval(interval);
          setError('Licence key was already retrieved. Check your dashboard or try again.');
          setState('error');
        }
      } catch {
        // Transient network error — keep polling
      }
    }, 3000);

    // Timeout after 15 minutes
    const timeout = setTimeout(() => {
      clearInterval(interval);
      setError('Checkout timed out. If you completed payment, use "I Have a Key" or contact support.');
      setState('error');
    }, 15 * 60 * 1000);

    return () => {
      clearInterval(interval);
      clearTimeout(timeout);
    };
  }, [state, setupId, queryClient]);

  const reset = useCallback(() => {
    setState('idle');
    setError(null);
    setSetupId(null);
  }, []);

  return { state, error, startCheckout, reset };
}
