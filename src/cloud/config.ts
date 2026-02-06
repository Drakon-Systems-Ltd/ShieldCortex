import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

export interface CloudConfig {
  cloudApiKey: string | null;
  cloudBaseUrl: string;
  cloudEnabled: boolean;
}

const CONFIG_DIR = join(homedir(), '.shieldcortex');
const CONFIG_FILE = join(CONFIG_DIR, 'config.json');
const DEFAULT_BASE_URL = 'https://api.shieldcortex.ai';

// Cache to avoid repeated file reads
let cachedConfig: CloudConfig | null = null;

export function getCloudConfig(): CloudConfig {
  if (cachedConfig) return cachedConfig;

  try {
    if (!existsSync(CONFIG_FILE)) {
      return { cloudApiKey: null, cloudBaseUrl: DEFAULT_BASE_URL, cloudEnabled: false };
    }
    const raw = JSON.parse(readFileSync(CONFIG_FILE, 'utf-8'));
    cachedConfig = {
      cloudApiKey: raw.cloudApiKey ?? null,
      cloudBaseUrl: raw.cloudBaseUrl ?? DEFAULT_BASE_URL,
      cloudEnabled: raw.cloudEnabled ?? false,
    };
    return cachedConfig;
  } catch {
    return { cloudApiKey: null, cloudBaseUrl: DEFAULT_BASE_URL, cloudEnabled: false };
  }
}

export function setCloudConfig(updates: Partial<CloudConfig>): void {
  let existing: Record<string, unknown> = {};
  try {
    if (existsSync(CONFIG_FILE)) {
      existing = JSON.parse(readFileSync(CONFIG_FILE, 'utf-8'));
    }
  } catch {
    // Start fresh if parse fails
  }

  if (updates.cloudApiKey !== undefined) existing.cloudApiKey = updates.cloudApiKey;
  if (updates.cloudBaseUrl !== undefined) existing.cloudBaseUrl = updates.cloudBaseUrl;
  if (updates.cloudEnabled !== undefined) existing.cloudEnabled = updates.cloudEnabled;

  mkdirSync(CONFIG_DIR, { recursive: true });
  writeFileSync(CONFIG_FILE, JSON.stringify(existing, null, 2) + '\n');

  // Invalidate cache
  cachedConfig = null;
}

/** Reset the in-memory cache (useful for testing) */
export function clearCloudConfigCache(): void {
  cachedConfig = null;
}
