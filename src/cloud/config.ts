import { readFileSync, writeFileSync, mkdirSync, existsSync, chmodSync } from 'fs';
import { join } from 'path';
import { homedir, hostname } from 'os';
import { randomUUID, randomBytes, createHmac, timingSafeEqual } from 'crypto';

export interface CloudConfig {
  cloudApiKey: string | null;
  cloudBaseUrl: string;
  cloudEnabled: boolean;
}

const CONFIG_DIR = join(homedir(), '.shieldcortex');
const CONFIG_FILE = join(CONFIG_DIR, 'config.json');
const SIG_FILE = join(CONFIG_DIR, '.config-sig');
const INTEGRITY_KEY_FILE = join(CONFIG_DIR, '.integrity-key');
const DEFAULT_BASE_URL = 'https://api.shieldcortex.ai';

// Cache to avoid repeated file reads
let cachedConfig: CloudConfig | null = null;

// ── Config Integrity (HMAC) ──────────────────────────────

let cachedIntegrityKey: string | null = null;
let configTampered = false;

function getIntegrityKey(): string {
  if (cachedIntegrityKey) return cachedIntegrityKey;
  try {
    if (existsSync(INTEGRITY_KEY_FILE)) {
      cachedIntegrityKey = readFileSync(INTEGRITY_KEY_FILE, 'utf-8').trim();
      return cachedIntegrityKey;
    }
  } catch { /* ignore */ }
  // Generate new key on first run
  const key = randomBytes(32).toString('hex');
  mkdirSync(CONFIG_DIR, { recursive: true });
  writeFileSync(INTEGRITY_KEY_FILE, key, { mode: 0o600 });
  try { chmodSync(INTEGRITY_KEY_FILE, 0o600); } catch { /* best-effort */ }
  cachedIntegrityKey = key;
  return key;
}

function signConfig(jsonContent: string): string {
  return createHmac('sha256', getIntegrityKey()).update(jsonContent, 'utf-8').digest('hex');
}

function writeConfigSignature(jsonContent: string): void {
  const sig = signConfig(jsonContent);
  writeFileSync(SIG_FILE, sig, { mode: 0o600 });
  try { chmodSync(SIG_FILE, 0o600); } catch { /* best-effort */ }
}

function verifyConfigIntegrity(jsonContent: string): boolean {
  try {
    if (!existsSync(SIG_FILE)) {
      // First run after upgrade — create signature, don't flag tamper
      writeConfigSignature(jsonContent);
      return true;
    }
    const storedSig = readFileSync(SIG_FILE, 'utf-8').trim();
    const computedSig = signConfig(jsonContent);
    const a = Buffer.from(storedSig, 'utf-8');
    const b = Buffer.from(computedSig, 'utf-8');
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

/** Returns true if config file tampering was detected. */
export function isConfigTampered(): boolean {
  return configTampered;
}

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
  const content = JSON.stringify(existing, null, 2) + '\n';
  writeFileSync(CONFIG_FILE, content);
  writeConfigSignature(content);

  // Invalidate cache
  cachedConfig = null;
  configTampered = false;
}

/** Reset the in-memory cache (useful for testing) */
export function clearCloudConfigCache(): void {
  cachedConfig = null;
}

// ── Trusted Skills ──────────────────────────────────────

export function readRawConfig(): Record<string, unknown> {
  try {
    if (existsSync(CONFIG_FILE)) {
      const content = readFileSync(CONFIG_FILE, 'utf-8');
      const data = JSON.parse(content);

      // Verify HMAC integrity
      if (!verifyConfigIntegrity(content)) {
        configTampered = true;
        console.error('[ShieldCortex] WARNING: Config file integrity check failed — possible tampering detected. Falling back to strict mode.');
        // Force strict mode on tampered config
        data.defenceMode = 'strict';
      }

      return data;
    }
  } catch { /* ignore */ }
  return {};
}

function writeRawConfig(raw: Record<string, unknown>): void {
  mkdirSync(CONFIG_DIR, { recursive: true });
  const content = JSON.stringify(raw, null, 2) + '\n';
  writeFileSync(CONFIG_FILE, content);
  // Sign the config after writing
  writeConfigSignature(content);
  cachedConfig = null;
  // Clear tamper flag on legitimate write
  configTampered = false;
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

// ── Cloud Iron Dome Cache ─────────────────────────────

/**
 * Persist cloud Iron Dome data (patterns + policy) to config.json with HMAC integrity.
 */
export function setCloudIronDomeCache(data: Record<string, unknown>): void {
  const raw = readRawConfig();
  raw.cloudIronDome = data;
  writeRawConfig(raw);
}

/**
 * Read cached cloud Iron Dome data from config.json.
 */
export function getCloudIronDomeCache(): Record<string, unknown> | null {
  const raw = readRawConfig();
  if (raw.cloudIronDome && typeof raw.cloudIronDome === 'object') {
    return raw.cloudIronDome as Record<string, unknown>;
  }
  return null;
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

// ── Defence Mode ──────────────────────────────────────

export type DefenceMode = 'strict' | 'balanced' | 'permissive';

const VALID_MODES: DefenceMode[] = ['strict', 'balanced', 'permissive'];

/**
 * Returns the persisted defence mode, defaulting to 'balanced'.
 */
export function getDefenceMode(): DefenceMode {
  const raw = readRawConfig();
  const mode = raw.defenceMode;
  if (typeof mode === 'string' && VALID_MODES.includes(mode as DefenceMode)) {
    return mode as DefenceMode;
  }
  return 'balanced';
}

/**
 * Persists the defence mode to ~/.shieldcortex/config.json.
 */
export function setDefenceMode(mode: DefenceMode): void {
  if (!VALID_MODES.includes(mode)) {
    throw new Error(`Invalid defence mode: ${mode}. Must be one of: ${VALID_MODES.join(', ')}`);
  }
  const raw = readRawConfig();
  raw.defenceMode = mode;
  writeRawConfig(raw);
}

// ── Verify Config ─────────────────────────────────────

export interface VerifyConfig {
  verifyEnabled: boolean;
  verifyMode: 'advisory' | 'enforce';
  verifyTriggers: Array<'ALLOW' | 'BLOCK' | 'QUARANTINE'>;
  verifyTimeoutMs: number;
}

const DEFAULT_VERIFY_CONFIG: VerifyConfig = {
  verifyEnabled: false,
  verifyMode: 'advisory',
  verifyTriggers: ['QUARANTINE'],
  verifyTimeoutMs: 5000,
};

/**
 * Returns the persisted LLM verification config.
 * Verify requires cloud to be configured (cloudEnabled + cloudApiKey).
 */
export function getVerifyConfig(): VerifyConfig {
  const raw = readRawConfig();
  return {
    verifyEnabled: typeof raw.verifyEnabled === 'boolean' ? raw.verifyEnabled : DEFAULT_VERIFY_CONFIG.verifyEnabled,
    verifyMode: raw.verifyMode === 'enforce' ? 'enforce' : DEFAULT_VERIFY_CONFIG.verifyMode,
    verifyTriggers: Array.isArray(raw.verifyTriggers) ? raw.verifyTriggers as VerifyConfig['verifyTriggers'] : DEFAULT_VERIFY_CONFIG.verifyTriggers,
    verifyTimeoutMs: typeof raw.verifyTimeoutMs === 'number' ? raw.verifyTimeoutMs : DEFAULT_VERIFY_CONFIG.verifyTimeoutMs,
  };
}

/**
 * Persists LLM verification config to ~/.shieldcortex/config.json.
 */
export function setVerifyConfig(updates: Partial<VerifyConfig>): void {
  const raw = readRawConfig();
  if (updates.verifyEnabled !== undefined) raw.verifyEnabled = updates.verifyEnabled;
  if (updates.verifyMode !== undefined) raw.verifyMode = updates.verifyMode;
  if (updates.verifyTriggers !== undefined) raw.verifyTriggers = updates.verifyTriggers;
  if (updates.verifyTimeoutMs !== undefined) raw.verifyTimeoutMs = updates.verifyTimeoutMs;
  writeRawConfig(raw);
}

// ── OpenClaw Memory Config ────────────────────────────

export interface OpenClawMemoryConfig {
  autoMemory: boolean;
  dedupe: boolean;
  noveltyThreshold: number;
  maxRecent: number;
}

const DEFAULT_OPENCLAW_MEMORY_CONFIG: OpenClawMemoryConfig = {
  autoMemory: false,
  dedupe: true,
  noveltyThreshold: 0.88,
  maxRecent: 300,
};

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

/**
 * Returns persisted OpenClaw memory integration config with safe defaults.
 */
export function getOpenClawMemoryConfig(): OpenClawMemoryConfig {
  const raw = readRawConfig();
  const threshold = typeof raw.openclawAutoMemoryNoveltyThreshold === 'number'
    ? clamp(raw.openclawAutoMemoryNoveltyThreshold, 0.6, 0.99)
    : DEFAULT_OPENCLAW_MEMORY_CONFIG.noveltyThreshold;
  const maxRecent = typeof raw.openclawAutoMemoryMaxRecent === 'number'
    ? Math.floor(clamp(raw.openclawAutoMemoryMaxRecent, 50, 1000))
    : DEFAULT_OPENCLAW_MEMORY_CONFIG.maxRecent;

  return {
    autoMemory: raw.openclawAutoMemory === true,
    dedupe: raw.openclawAutoMemoryDedupe !== false,
    noveltyThreshold: threshold,
    maxRecent,
  };
}

/**
 * Persists OpenClaw memory integration config.
 */
export function setOpenClawMemoryConfig(updates: Partial<OpenClawMemoryConfig>): void {
  const raw = readRawConfig();
  if (updates.autoMemory !== undefined) raw.openclawAutoMemory = updates.autoMemory;
  if (updates.dedupe !== undefined) raw.openclawAutoMemoryDedupe = updates.dedupe;
  if (updates.noveltyThreshold !== undefined) {
    raw.openclawAutoMemoryNoveltyThreshold = clamp(updates.noveltyThreshold, 0.6, 0.99);
  }
  if (updates.maxRecent !== undefined) {
    raw.openclawAutoMemoryMaxRecent = Math.floor(clamp(updates.maxRecent, 50, 1000));
  }
  writeRawConfig(raw);
}

/**
 * Returns whether OpenClaw auto-memory extraction is enabled.
 * Default is false (opt-in).
 */
export function getOpenClawAutoMemory(): boolean {
  return getOpenClawMemoryConfig().autoMemory;
}

/**
 * Persists OpenClaw auto-memory extraction preference.
 */
export function setOpenClawAutoMemory(enabled: boolean): void {
  setOpenClawMemoryConfig({ autoMemory: enabled });
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
