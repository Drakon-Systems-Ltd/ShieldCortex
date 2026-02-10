import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { authFetch } from '@/lib/auth';

interface CloudConfig {
  enabled: boolean;
  apiKeySet: boolean;
  baseUrl: string;
}

const API_URL = 'http://localhost:3001';

export function useCloudStatus() {
  return useQuery<CloudConfig>({
    queryKey: ['cloud-config'],
    queryFn: async () => {
      const res = await fetch(`${API_URL}/api/cloud/config`);
      if (!res.ok) throw new Error('Failed to fetch cloud config');
      return res.json();
    },
    refetchInterval: 30000, // Refresh every 30s
  });
}

export function useUpdateCloudConfig() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (config: Partial<{ cloudApiKey: string; cloudEnabled: boolean; cloudBaseUrl: string }>) => {
      const res = await authFetch(`${API_URL}/api/cloud/config`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config),
      });
      if (!res.ok) throw new Error('Failed to update cloud config');
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cloud-config'] });
    },
  });
}
