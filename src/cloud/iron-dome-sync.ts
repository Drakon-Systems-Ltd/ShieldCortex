/**
 * Iron Dome Cloud Sync
 *
 * Pulls custom injection patterns and central policy from ShieldCortex cloud.
 * Non-blocking, with disk cache fallback if cloud is unreachable.
 */

import { getCloudConfig, setCloudIronDomeCache as persistToConfig, getCloudIronDomeCache as readFromConfig } from './config.js';
import { setExternalPatterns } from '../defence/iron-dome/injection-scanner.js';

// ── Types ──

export interface CloudPattern {
  pattern: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface CloudPolicy {
  name: string;
  base_profile: 'school' | 'enterprise' | 'personal' | 'paranoid';
  config_overrides: Record<string, unknown>;
}

export interface CloudIronDomeCache {
  patterns: CloudPattern[];
  policy: CloudPolicy | null;
  patternsUpdatedAt: string | null;
  policyUpdatedAt: string | null;
  lastFetchedAt: string;
}

// ── State ──

let fetchInProgress = false;
let cachedData: CloudIronDomeCache | null = null;

/**
 * Get the cached cloud Iron Dome data (in-memory or from disk).
 */
export function getCloudIronDomeCache(): CloudIronDomeCache | null {
  if (cachedData) return cachedData;

  // Try loading from disk
  try {
    const raw = readFromConfig();
    if (raw) {
      cachedData = raw as unknown as CloudIronDomeCache;
      return cachedData;
    }
  } catch { /* ignore */ }

  return null;
}

/**
 * Fetch custom patterns and policy from ShieldCortex cloud.
 * Non-blocking with 10s timeout. Falls back to disk cache on failure.
 */
export async function refreshCloudIronDome(): Promise<void> {
  const config = getCloudConfig();
  if (!config.cloudEnabled || !config.cloudApiKey) return;
  if (fetchInProgress) return;

  fetchInProgress = true;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10_000);

    const headers = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${config.cloudApiKey}`,
    };

    // Fetch patterns and policy in parallel
    const [patternsRes, policyRes] = await Promise.allSettled([
      fetch(`${config.cloudBaseUrl}/v1/iron-dome/patterns/sync`, {
        headers,
        signal: controller.signal,
      }),
      fetch(`${config.cloudBaseUrl}/v1/iron-dome/policies/sync`, {
        headers,
        signal: controller.signal,
      }),
    ]);

    clearTimeout(timeoutId);

    let patterns: CloudPattern[] = [];
    let patternsUpdatedAt: string | null = null;
    let policy: CloudPolicy | null = null;
    let policyUpdatedAt: string | null = null;

    // Process patterns response
    if (patternsRes.status === 'fulfilled' && patternsRes.value.ok) {
      try {
        const data = await patternsRes.value.json() as {
          patterns: CloudPattern[];
          updated_at: string | null;
        };
        patterns = data.patterns ?? [];
        patternsUpdatedAt = data.updated_at;
      } catch { /* ignore parse errors */ }
    }

    // Process policy response
    if (policyRes.status === 'fulfilled' && policyRes.value.ok) {
      try {
        const data = await policyRes.value.json() as {
          policy: CloudPolicy | null;
          updated_at: string | null;
        };
        policy = data.policy;
        policyUpdatedAt = data.updated_at;
      } catch { /* ignore parse errors */ }
    }

    // Update in-memory cache
    cachedData = {
      patterns,
      policy,
      patternsUpdatedAt,
      policyUpdatedAt,
      lastFetchedAt: new Date().toISOString(),
    };

    // Register external patterns with injection scanner
    if (patterns.length > 0) {
      setExternalPatterns(patterns);
    }

    // Persist to disk with HMAC integrity
    persistToConfig(cachedData as unknown as Record<string, unknown>);

  } catch {
    // Cloud unreachable — fall back to disk cache
    const diskCache = getCloudIronDomeCache();
    if (diskCache && diskCache.patterns.length > 0) {
      setExternalPatterns(diskCache.patterns);
    }
  } finally {
    fetchInProgress = false;
  }
}

/**
 * Apply cached cloud patterns on startup (before first cloud fetch).
 * Called once during initialisation.
 */
export function applyCachedCloudPatterns(): void {
  const cache = getCloudIronDomeCache();
  if (cache && cache.patterns.length > 0) {
    setExternalPatterns(cache.patterns);
  }
}
