import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';
import { homedir, hostname } from 'os';
import { randomUUID } from 'crypto';

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

// ── Trusted Skills ──────────────────────────────────────

export function readRawConfig(): Record<string, unknown> {
  try {
    if (existsSync(CONFIG_FILE)) {
      return JSON.parse(readFileSync(CONFIG_FILE, 'utf-8'));
    }
  } catch { /* ignore */ }
  return {};
}

function writeRawConfig(raw: Record<string, unknown>): void {
  mkdirSync(CONFIG_DIR, { recursive: true });
  writeFileSync(CONFIG_FILE, JSON.stringify(raw, null, 2) + '\n');
  cachedConfig = null;
}

export function getTrustedSkills(): string[] {
  const raw = readRawConfig();
  return Array.isArray(raw.trustedSkills) ? raw.trustedSkills as string[] : [];
}

export function addTrustedSkill(path: string): void {
  const raw = readRawConfig();
  const list = Array.isArray(raw.trustedSkills) ? raw.trustedSkills as string[] : [];
  if (!list.includes(path)) {
    list.push(path);
    raw.trustedSkills = list;
    writeRawConfig(raw);
  }
}

export function removeTrustedSkill(path: string): void {
  const raw = readRawConfig();
  const list = Array.isArray(raw.trustedSkills) ? raw.trustedSkills as string[] : [];
  const idx = list.indexOf(path);
  if (idx !== -1) {
    list.splice(idx, 1);
    raw.trustedSkills = list;
    writeRawConfig(raw);
  }
}

// ── Sync Timestamp ────────────────────────────────────

/**
 * Write lastSyncAt timestamp to config.json on successful cloud sync.
 */
export function updateLastSyncAt(): void {
  const raw = readRawConfig();
  raw.lastSyncAt = new Date().toISOString();
  writeRawConfig(raw);
}

// ── Device Identity ────────────────────────────────────

/**
 * Returns a stable UUID for this machine.
 * Generates and persists on first call; reads from config thereafter.
 */
export function getDeviceId(): string {
  const raw = readRawConfig();
  if (typeof raw.deviceId === 'string' && raw.deviceId) {
    return raw.deviceId;
  }
  const id = randomUUID();
  raw.deviceId = id;
  writeRawConfig(raw);
  return id;
}

/**
 * Returns the OS hostname for this machine.
 * Stores in config on first call; reads from config thereafter.
 */
export function getDeviceName(): string {
  const raw = readRawConfig();
  if (typeof raw.deviceName === 'string' && raw.deviceName) {
    return raw.deviceName;
  }
  const name = hostname();
  raw.deviceName = name;
  writeRawConfig(raw);
  return name;
}
