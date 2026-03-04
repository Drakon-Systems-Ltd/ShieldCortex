'use client';

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { authFetch } from '@/lib/auth';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

// ── Types ──

export type LicenseTier = 'free' | 'pro' | 'team' | 'enterprise';

export interface LicenseFeature {
  feature: string;
  requiredTier: LicenseTier;
  enabled: boolean;
  description: string;
}

export interface LicenseStatus {
  tier: LicenseTier;
  valid: boolean;
  email: string | null;
  expiresAt: string | null;
  daysUntilExpiry: number | null;
  teamId: number | null;
  features: LicenseFeature[];
}

interface ActivateResponse extends LicenseStatus {
  success: boolean;
  validationStatus: string;
}

interface DeactivateResponse {
  success: boolean;
  tier: LicenseTier;
  features: LicenseFeature[];
}

// ── Fetch Functions ──

async function fetchLicenseStatus(): Promise<LicenseStatus> {
  const res = await authFetch(`${API_BASE}/api/license/status`);
  if (!res.ok) throw new Error('Failed to fetch license status');
  return res.json();
}

async function activateLicenseKey(key: string): Promise<ActivateResponse> {
  const res = await authFetch(`${API_BASE}/api/license/activate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ key }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({ error: 'Activation failed' }));
    throw new Error(data.error || 'Activation failed');
  }
  return res.json();
}

async function deactivateLicenseKey(): Promise<DeactivateResponse> {
  const res = await authFetch(`${API_BASE}/api/license/deactivate`, {
    method: 'POST',
  });
  if (!res.ok) throw new Error('Failed to deactivate license');
  return res.json();
}

// ── Hooks ──

export function useLicenseStatus() {
  return useQuery<LicenseStatus>({
    queryKey: ['license-status'],
    queryFn: fetchLicenseStatus,
    refetchInterval: 60000,
    retry: 2,
  });
}

export function useActivateLicense() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (key: string) => activateLicenseKey(key),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['license-status'] });
    },
  });
}

export function useDeactivateLicense() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: deactivateLicenseKey,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['license-status'] });
    },
  });
}
