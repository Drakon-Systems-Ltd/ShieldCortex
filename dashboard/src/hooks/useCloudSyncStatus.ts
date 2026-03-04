import { useQuery } from '@tanstack/react-query';
import { authFetch } from '@/lib/auth';

const API_URL = 'http://localhost:3001';

interface CloudSyncStatus {
  enabled: boolean;
  apiKeySet: boolean;
  lastSyncAt: string | null;
  queue: { pending: number; failed: number };
}

export function useCloudSyncStatus() {
  return useQuery<CloudSyncStatus>({
    queryKey: ['cloud-sync-status'],
    queryFn: async () => {
      const res = await authFetch(`${API_URL}/api/cloud/sync-status`);
      if (!res.ok) throw new Error('Failed to fetch sync status');
      return res.json();
    },
    refetchInterval: 10000, // Poll every 10s
  });
}
