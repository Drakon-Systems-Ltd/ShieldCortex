import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { authFetch } from '@/lib/auth';

interface CloudConfig {
  enabled: boolean;
  apiKeySet: boolean;
  baseUrl: string;
  syncControls: {
    projectMode: 'all' | 'include' | 'exclude';
    projects: string[];
    contentMode: 'full' | 'metadata';
    excludeSensitive: boolean;
  };
  openclawMemory: {
    autoMemory: boolean;
    dedupe: boolean;
    noveltyThreshold: number;
    maxRecent: number;
  };
}

const API_URL = 'http://localhost:3001';

export function useCloudStatus() {
  return useQuery<CloudConfig>({
    queryKey: ['cloud-config'],
    queryFn: async () => {
      const res = await authFetch(`${API_URL}/api/cloud/config`);
      if (!res.ok) throw new Error('Failed to fetch cloud config');
      return res.json();
    },
    refetchInterval: 30000, // Refresh every 30s
  });
}

export function useUpdateCloudConfig() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (
      config: Partial<{
        cloudApiKey: string;
        cloudEnabled: boolean;
        cloudBaseUrl: string;
        cloudSyncProjectMode: 'all' | 'include' | 'exclude';
        cloudSyncProjects: string[];
        cloudSyncContentMode: 'full' | 'metadata';
        cloudSyncExcludeSensitive: boolean;
        openclawAutoMemory: boolean;
        openclawAutoMemoryDedupe: boolean;
        openclawAutoMemoryNoveltyThreshold: number;
        openclawAutoMemoryMaxRecent: number;
      }>
    ) => {
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
      queryClient.invalidateQueries({ queryKey: ['cloud-sync-status'] });
    },
  });
}

export interface CloudProjectSummary {
  project: string;
  count: number;
}

export function useCloudProjects() {
  return useQuery<{ projects: CloudProjectSummary[] }>({
    queryKey: ['cloud-projects'],
    queryFn: async () => {
      const res = await authFetch(`${API_URL}/api/cloud/projects`);
      if (!res.ok) throw new Error('Failed to fetch cloud projects');
      return res.json();
    },
    staleTime: 30000,
  });
}
