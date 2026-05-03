'use client';

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { gatedFetch, readApiError } from '@/lib/auth';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

export interface IntegrationsConfig {
  openclawAutoMemory: boolean;
  proactiveRecall: boolean;
}

export type IntegrationsConfigUpdate = Partial<IntegrationsConfig>;

interface CloudConfigResponse {
  openclawMemory?: { autoMemory?: boolean };
  proactiveRecall?: boolean;
}

export function useIntegrationsConfig() {
  return useQuery<IntegrationsConfig>({
    queryKey: ['integrations-config'],
    queryFn: async () => {
      const res = await gatedFetch(`${API_BASE}/api/cloud/config`);
      if (!res.ok) throw new Error(await readApiError(res, 'Failed to load integration toggles'));
      const data: CloudConfigResponse = await res.json();
      return {
        openclawAutoMemory: Boolean(data.openclawMemory?.autoMemory),
        proactiveRecall: Boolean(data.proactiveRecall),
      };
    },
    refetchOnWindowFocus: true,
  });
}

export function useUpdateIntegrationsConfig() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (update: IntegrationsConfigUpdate) => {
      const res = await gatedFetch(`${API_BASE}/api/cloud/config`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(update),
      });
      if (!res.ok) throw new Error(await readApiError(res, 'Failed to update integration toggle'));
      return res.json();
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['integrations-config'] });
      // Cloud sync diagnostics also reads from /api/cloud/config; keep it in sync.
      qc.invalidateQueries({ queryKey: ['cloud-config'] });
    },
  });
}
