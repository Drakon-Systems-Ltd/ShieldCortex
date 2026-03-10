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

const DEFAULT_SYNC_CONTROLS: CloudConfig['syncControls'] = {
  projectMode: 'all',
  projects: [],
  contentMode: 'full',
  excludeSensitive: false,
};

function normalizeCloudConfig(raw: Partial<CloudConfig> & Record<string, unknown>): CloudConfig {
  const syncControls =
    raw.syncControls && typeof raw.syncControls === 'object'
      ? raw.syncControls as Record<string, unknown>
      : {};
  const openclawMemory =
    raw.openclawMemory && typeof raw.openclawMemory === 'object'
      ? raw.openclawMemory as Record<string, unknown>
      : {};

  return {
    enabled: Boolean(raw.enabled),
    apiKeySet: Boolean(raw.apiKeySet),
    baseUrl: typeof raw.baseUrl === 'string' ? raw.baseUrl : 'https://api.shieldcortex.ai',
    syncControls: {
      projectMode:
        'projectMode' in syncControls &&
        (syncControls.projectMode === 'include' || syncControls.projectMode === 'exclude')
          ? syncControls.projectMode
          : DEFAULT_SYNC_CONTROLS.projectMode,
      projects:
        Array.isArray(syncControls.projects)
          ? syncControls.projects.filter((project): project is string => typeof project === 'string')
          : DEFAULT_SYNC_CONTROLS.projects,
      contentMode:
        'contentMode' in syncControls && syncControls.contentMode === 'metadata'
          ? 'metadata'
          : DEFAULT_SYNC_CONTROLS.contentMode,
      excludeSensitive:
        'excludeSensitive' in syncControls
          ? Boolean(syncControls.excludeSensitive)
          : DEFAULT_SYNC_CONTROLS.excludeSensitive,
    },
    openclawMemory: {
      autoMemory:
        'autoMemory' in openclawMemory
          ? Boolean(openclawMemory.autoMemory)
          : false,
      dedupe:
        'dedupe' in openclawMemory
          ? Boolean(openclawMemory.dedupe)
          : false,
      noveltyThreshold:
        'noveltyThreshold' in openclawMemory && typeof openclawMemory.noveltyThreshold === 'number'
          ? openclawMemory.noveltyThreshold
          : 0.88,
      maxRecent:
        'maxRecent' in openclawMemory && typeof openclawMemory.maxRecent === 'number'
          ? openclawMemory.maxRecent
          : 300,
    },
  };
}

const API_URL = 'http://localhost:3001';

export function useCloudStatus() {
  return useQuery<CloudConfig>({
    queryKey: ['cloud-config'],
    queryFn: async () => {
      const res = await authFetch(`${API_URL}/api/cloud/config`);
      if (!res.ok) throw new Error('Failed to fetch cloud config');
      return normalizeCloudConfig(await res.json());
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
