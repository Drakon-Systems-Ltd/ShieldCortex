import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { authFetch, readApiError } from '@/lib/auth';

const API_URL = 'http://localhost:3001';

export interface CloudSyncStatus {
  enabled: boolean;
  apiKeySet: boolean;
  baseUrl: string;
  featureEnabled: boolean;
  requiredTier: 'free' | 'pro' | 'team' | 'enterprise';
  controls: {
    projectMode: 'all' | 'include' | 'exclude';
    projects: string[];
    contentMode: 'full' | 'metadata';
    excludeSensitive: boolean;
  };
  lastSyncAt: string | null;
  device: { id: string; name: string; platform: string };
  queue: {
    pending: number;
    failed: number;
    synced: number;
    byKind: Record<'audit' | 'quarantine' | 'memory' | 'graph' | 'unknown', {
      pending: number;
      failed: number;
      synced: number;
    }>;
    oldestPendingAt: string | null;
    nextRetryAt: string | null;
    lastError: string | null;
    lastErrorKind: 'audit' | 'quarantine' | 'memory' | 'graph' | 'unknown' | null;
    latestFailureAt: string | null;
  };
}

const DEFAULT_SYNC_CONTROLS: CloudSyncStatus['controls'] = {
  projectMode: 'all',
  projects: [],
  contentMode: 'full',
  excludeSensitive: false,
};

function normalizeCloudSyncStatus(raw: Partial<CloudSyncStatus> & Record<string, unknown>): CloudSyncStatus {
  const controls =
    raw.controls && typeof raw.controls === 'object'
      ? raw.controls as Record<string, unknown>
      : {};
  const queue =
    raw.queue && typeof raw.queue === 'object'
      ? raw.queue as Record<string, unknown>
      : {};
  const byKind = 'byKind' in queue && queue.byKind && typeof queue.byKind === 'object'
    ? queue.byKind as Record<string, { pending?: number; failed?: number; synced?: number }>
    : {};

  const normalizeKind = (key: 'audit' | 'quarantine' | 'memory' | 'graph' | 'unknown') => ({
    pending: Number(byKind[key]?.pending ?? 0),
    failed: Number(byKind[key]?.failed ?? 0),
    synced: Number(byKind[key]?.synced ?? 0),
  });

  return {
    enabled: Boolean(raw.enabled),
    apiKeySet: Boolean(raw.apiKeySet),
    baseUrl: typeof raw.baseUrl === 'string' ? raw.baseUrl : 'https://api.shieldcortex.ai',
    featureEnabled: Boolean(raw.featureEnabled),
    requiredTier:
      raw.requiredTier === 'pro' || raw.requiredTier === 'team' || raw.requiredTier === 'enterprise'
        ? raw.requiredTier
        : 'free',
    controls: {
      projectMode:
        'projectMode' in controls &&
        (controls.projectMode === 'include' || controls.projectMode === 'exclude')
          ? controls.projectMode
          : DEFAULT_SYNC_CONTROLS.projectMode,
      projects:
        Array.isArray(controls.projects)
          ? controls.projects.filter((project): project is string => typeof project === 'string')
          : DEFAULT_SYNC_CONTROLS.projects,
      contentMode:
        'contentMode' in controls && controls.contentMode === 'metadata'
          ? 'metadata'
          : DEFAULT_SYNC_CONTROLS.contentMode,
      excludeSensitive:
        'excludeSensitive' in controls
          ? Boolean(controls.excludeSensitive)
          : DEFAULT_SYNC_CONTROLS.excludeSensitive,
    },
    lastSyncAt: typeof raw.lastSyncAt === 'string' || raw.lastSyncAt === null ? (raw.lastSyncAt ?? null) : null,
    device: {
      id:
        raw.device && typeof raw.device === 'object' && 'id' in raw.device && typeof raw.device.id === 'string'
          ? raw.device.id
          : 'unknown',
      name:
        raw.device && typeof raw.device === 'object' && 'name' in raw.device && typeof raw.device.name === 'string'
          ? raw.device.name
          : 'Unknown device',
      platform:
        raw.device && typeof raw.device === 'object' && 'platform' in raw.device && typeof raw.device.platform === 'string'
          ? raw.device.platform
          : 'unknown',
    },
    queue: {
      pending: Number(queue.pending ?? 0),
      failed: Number(queue.failed ?? 0),
      synced: Number(queue.synced ?? 0),
      byKind: {
        audit: normalizeKind('audit'),
        quarantine: normalizeKind('quarantine'),
        memory: normalizeKind('memory'),
        graph: normalizeKind('graph'),
        unknown: normalizeKind('unknown'),
      },
      oldestPendingAt:
        typeof queue.oldestPendingAt === 'string' || queue.oldestPendingAt === null ? (queue.oldestPendingAt ?? null) : null,
      nextRetryAt:
        typeof queue.nextRetryAt === 'string' || queue.nextRetryAt === null ? (queue.nextRetryAt ?? null) : null,
      lastError:
        typeof queue.lastError === 'string' || queue.lastError === null ? (queue.lastError ?? null) : null,
      lastErrorKind:
        queue.lastErrorKind === 'audit' ||
        queue.lastErrorKind === 'quarantine' ||
        queue.lastErrorKind === 'memory' ||
        queue.lastErrorKind === 'graph' ||
        queue.lastErrorKind === 'unknown'
          ? queue.lastErrorKind
          : null,
      latestFailureAt:
        typeof queue.latestFailureAt === 'string' || queue.latestFailureAt === null ? (queue.latestFailureAt ?? null) : null,
    },
  };
}

export function useCloudSyncStatus() {
  return useQuery<CloudSyncStatus>({
    queryKey: ['cloud-sync-status'],
    queryFn: async () => {
      const res = await authFetch(`${API_URL}/api/cloud/sync-status`);
      if (!res.ok) throw new Error(await readApiError(res, 'Failed to fetch sync status'));
      return normalizeCloudSyncStatus(await res.json());
    },
    refetchInterval: 30000, // Poll every 30s
    staleTime: 15000,
  });
}

export function useClearFailedSync() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const res = await authFetch(`${API_URL}/api/cloud/sync-queue/clear-failed`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      if (!res.ok) throw new Error(await readApiError(res, 'Failed to clear failed items'));
      return res.json() as Promise<{ cleared: number }>;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cloud-sync-status'] });
    },
  });
}
