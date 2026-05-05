import { readFileSync, writeFileSync, mkdirSync, existsSync, chmodSync } from 'fs';
import { join } from 'path';
import { homedir, hostname } from 'os';
import { randomUUID, randomBytes, createHmac, timingSafeEqual } from 'crypto';

export interface CloudConfig {
  cloudApiKey: string | null;
  cloudBaseUrl: string;
  cloudEnabled: boolean;
}

export interface CloudSyncControls {
  projectMode: 'all' | 'include' | 'exclude';
  projects: string[];
  contentMode: 'full' | 'metadata';
  excludeSensitive: boolean;
}

export interface ReviewCopilotConfig {
  enabled: boolean;
  modelId: string;
  modelCacheDir: string;
  telemetryPath: string;
  inferenceTimeoutMs: number;
  workerHeapMB: number;
}

function getConfigDir(): string {
  const override = process.env.SHIELDCORTEX_CONFIG_DIR?.trim();
  if (override) return override;
  return join(homedir(), '.shieldcortex');
}

function getConfigFile(): string {
  return join(getConfigDir(), 'config.json');
}

function getSigFile(): string {
  return join(getConfigDir(), '.config-sig');
}

function getIntegrityKeyFile(): string {
  return join(getConfigDir(), '.integrity-key');
}

const DEFAULT_BASE_URL = 'https://api.shieldcortex.ai';
const DEFAULT_SYNC_CONTROLS: CloudSyncControls = {
  projectMode: 'all',
  projects: [],
  contentMode: 'full',
  excludeSensitive: false,
};
const DEFAULT_REVIEW_COPILOT_CONFIG: ReviewCopilotConfig = {
  enabled: false,
  modelId: 'onnx-community/Qwen2.5-0.5B-Instruct',
  modelCacheDir: '',
  telemetryPath: '',
  inferenceTimeoutMs: 10000,
  workerHeapMB: 2048,
};

// Cache to avoid repeated file reads
let cachedConfig: CloudConfig | null = null;
let cachedConfigFile: string | null = null;

// ── Config Integrity (HMAC) ──────────────────────────────

let cachedIntegrityKey: string | null = null;
let cachedIntegrityKeyFile: string | null = null;
let configTampered = false;

function getIntegrityKey(): string {
  const integrityKeyFile = getIntegrityKeyFile();
  const configDir = getConfigDir();
  if (cachedIntegrityKey && cachedIntegrityKeyFile === integrityKeyFile) return cachedIntegrityKey;
  try {
    if (existsSync(integrityKeyFile)) {
      cachedIntegrityKey = readFileSync(integrityKeyFile, 'utf-8').trim();
      cachedIntegrityKeyFile = integrityKeyFile;
      return cachedIntegrityKey;
    }
  } catch { /* ignore */ }
  // Generate new key on first run
  const key = randomBytes(32).toString('hex');
  mkdirSync(configDir, { recursive: true });
  writeFileSync(integrityKeyFile, key, { mode: 0o600 });
  try { chmodSync(integrityKeyFile, 0o600); } catch { /* best-effort */ }
  cachedIntegrityKey = key;
  cachedIntegrityKeyFile = integrityKeyFile;
  return key;
}

function signConfig(jsonContent: string): string {
  return createHmac('sha256', getIntegrityKey()).update(jsonContent, 'utf-8').digest('hex');
}

function writeConfigSignature(jsonContent: string): void {
  const sig = signConfig(jsonContent);
  const sigFile = getSigFile();
  writeFileSync(sigFile, sig, { mode: 0o600 });
  try { chmodSync(sigFile, 0o600); } catch { /* best-effort */ }
}

function verifyConfigIntegrity(jsonContent: string): boolean {
  try {
    const sigFile = getSigFile();
    if (!existsSync(sigFile)) {
      // First run after upgrade — create signature, don't flag tamper
      writeConfigSignature(jsonContent);
      return true;
    }
    const storedSig = readFileSync(sigFile, 'utf-8').trim();
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
  const configFile = getConfigFile();
  if (cachedConfig && cachedConfigFile === configFile) return cachedConfig;

  try {
    if (!existsSync(configFile)) {
      return { cloudApiKey: null, cloudBaseUrl: DEFAULT_BASE_URL, cloudEnabled: false };
    }
    const raw = JSON.parse(readFileSync(configFile, 'utf-8'));
    cachedConfig = {
      cloudApiKey: raw.cloudApiKey ?? null,
      cloudBaseUrl: raw.cloudBaseUrl ?? DEFAULT_BASE_URL,
      cloudEnabled: raw.cloudEnabled ?? false,
    };
    cachedConfigFile = configFile;
    return cachedConfig;
  } catch {
    return { cloudApiKey: null, cloudBaseUrl: DEFAULT_BASE_URL, cloudEnabled: false };
  }
}

export function setCloudConfig(updates: Partial<CloudConfig>): void {
  let existing: Record<string, unknown> = {};
  try {
    const configFile = getConfigFile();
    if (existsSync(configFile)) {
      existing = JSON.parse(readFileSync(configFile, 'utf-8'));
    }
  } catch {
    // Start fresh if parse fails
  }

  if (updates.cloudApiKey !== undefined) existing.cloudApiKey = updates.cloudApiKey;
  if (updates.cloudBaseUrl !== undefined) existing.cloudBaseUrl = updates.cloudBaseUrl;
  if (updates.cloudEnabled !== undefined) existing.cloudEnabled = updates.cloudEnabled;

  const configDir = getConfigDir();
  const configFile = getConfigFile();
  mkdirSync(configDir, { recursive: true });
  const content = JSON.stringify(existing, null, 2) + '\n';
  writeFileSync(configFile, content);
  writeConfigSignature(content);

  // Invalidate cache
  cachedConfig = null;
  cachedConfigFile = null;
  configTampered = false;
}

/** Reset the in-memory cache (useful for testing) */
export function clearCloudConfigCache(): void {
  cachedConfig = null;
  cachedConfigFile = null;
}

function normalizeProjectList(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return [...new Set(
    value
      .filter((entry): entry is string => typeof entry === 'string')
      .map((entry) => entry.trim())
      .filter(Boolean),
  )].sort((a, b) => a.localeCompare(b));
}

export function getCloudSyncControls(): CloudSyncControls {
  const raw = readRawConfig();
  const projectMode = raw.cloudSyncProjectMode;
  const contentMode = raw.cloudSyncContentMode;

  return {
    projectMode:
      projectMode === 'include' || projectMode === 'exclude'
        ? projectMode
        : DEFAULT_SYNC_CONTROLS.projectMode,
    projects: normalizeProjectList(raw.cloudSyncProjects),
    contentMode: contentMode === 'metadata' ? 'metadata' : DEFAULT_SYNC_CONTROLS.contentMode,
    excludeSensitive:
      typeof raw.cloudSyncExcludeSensitive === 'boolean'
        ? raw.cloudSyncExcludeSensitive
        : DEFAULT_SYNC_CONTROLS.excludeSensitive,
  };
}

export function setCloudSyncControls(updates: Partial<CloudSyncControls>): void {
  const raw = readRawConfig();
  if (updates.projectMode !== undefined) raw.cloudSyncProjectMode = updates.projectMode;
  if (updates.projects !== undefined) raw.cloudSyncProjects = normalizeProjectList(updates.projects);
  if (updates.contentMode !== undefined) raw.cloudSyncContentMode = updates.contentMode;
  if (updates.excludeSensitive !== undefined) raw.cloudSyncExcludeSensitive = updates.excludeSensitive;
  writeRawConfig(raw);
}

export function shouldSyncProject(project: string | null | undefined, controls: CloudSyncControls = getCloudSyncControls()): boolean {
  const normalized = (project ?? '').trim();
  if (controls.projectMode === 'all') return true;
  const included = controls.projects.includes(normalized);
  return controls.projectMode === 'include' ? included : !included;
}

export function isSensitiveLevel(level: string | null | undefined): boolean {
  if (!level) return false;
  const normalized = level.trim().toUpperCase();
  return normalized.length > 0 && normalized !== 'PUBLIC' && normalized !== 'INTERNAL';
}

// ── Trusted Skills ──────────────────────────────────────

export function readRawConfig(): Record<string, unknown> {
  try {
    const configFile = getConfigFile();
    if (existsSync(configFile)) {
      const content = readFileSync(configFile, 'utf-8');
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
  const configDir = getConfigDir();
  const configFile = getConfigFile();
  mkdirSync(configDir, { recursive: true });
  const content = JSON.stringify(raw, null, 2) + '\n';
  writeFileSync(configFile, content);
  // Sign the config after writing
  writeConfigSignature(content);
  cachedConfig = null;
  cachedConfigFile = null;
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

// ── Review Copilot Config ───────────────────────────────

function readReviewCopilotRaw(): Record<string, unknown> {
  const raw = readRawConfig();
  return raw.reviewCopilot && typeof raw.reviewCopilot === 'object'
    ? raw.reviewCopilot as Record<string, unknown>
    : {};
}

function positiveNumber(value: unknown, fallback: number, min: number, max: number): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(value)));
}

/**
 * Returns local Review Copilot config.
 * Disabled by default regardless of cloud key presence; users must opt in.
 */
export function getReviewCopilotConfig(): ReviewCopilotConfig {
  const raw = readReviewCopilotRaw();
  return {
    enabled: raw.enabled === true,
    modelId: typeof raw.modelId === 'string' && raw.modelId.trim()
      ? raw.modelId.trim()
      : DEFAULT_REVIEW_COPILOT_CONFIG.modelId,
    modelCacheDir: typeof raw.modelCacheDir === 'string' && raw.modelCacheDir.trim()
      ? raw.modelCacheDir.trim()
      : join(getConfigDir(), 'models', 'review-copilot'),
    telemetryPath: typeof raw.telemetryPath === 'string' && raw.telemetryPath.trim()
      ? raw.telemetryPath.trim()
      : join(getConfigDir(), 'review-copilot-telemetry.jsonl'),
    inferenceTimeoutMs: positiveNumber(
      raw.inferenceTimeoutMs,
      DEFAULT_REVIEW_COPILOT_CONFIG.inferenceTimeoutMs,
      1000,
      60000,
    ),
    workerHeapMB: positiveNumber(
      raw.workerHeapMB,
      DEFAULT_REVIEW_COPILOT_CONFIG.workerHeapMB,
      256,
      8192,
    ),
  };
}

/**
 * Persists local Review Copilot config.
 */
export function setReviewCopilotConfig(updates: Partial<ReviewCopilotConfig>): void {
  const raw = readRawConfig();
  const existing = raw.reviewCopilot && typeof raw.reviewCopilot === 'object'
    ? raw.reviewCopilot as Record<string, unknown>
    : {};
  raw.reviewCopilot = {
    ...existing,
    ...updates,
  };
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
  autoMemory: true,
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
 * Default is true (on by default, opt-out with --openclaw-auto-memory false).
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

// ── Proactive Recall ─────────────────────────────────

/**
 * Returns whether proactive memory recall is enabled on prompt submit.
 * Default is false since v4.11.0 — opt-in with --proactive-recall true.
 * Per-turn recall was found to be net-negative for fast agent loops; kept
 * available for interactive sessions that want it.
 */
export function isProactiveRecallEnabled(): boolean {
  const raw = readRawConfig();
  return raw.proactiveRecall === true;
}

/**
 * Persists proactive recall preference to ~/.shieldcortex/config.json.
 */
export function setProactiveRecall(enabled: boolean): void {
  const raw = readRawConfig();
  raw.proactiveRecall = enabled;
  writeRawConfig(raw);
}

/**
 * Restores the v4.10.x defaults for users who preferred the old behaviour.
 * Writes explicit overrides for every default the v4.11.0 release flipped,
 * so the flip is a one-command undo.
 */
export function restore410Defaults(): void {
  const raw = readRawConfig();
  raw.proactiveRecall = true;
  const existingInterceptor = (raw.interceptor && typeof raw.interceptor === 'object')
    ? raw.interceptor as Record<string, unknown>
    : {};
  const existingSeverity = (existingInterceptor.severityActions && typeof existingInterceptor.severityActions === 'object')
    ? existingInterceptor.severityActions as Record<string, string>
    : {};
  raw.interceptor = {
    ...existingInterceptor,
    severityActions: {
      ...existingSeverity,
      low: 'log',
      medium: 'warn',
      high: 'require_approval',
      critical: 'require_approval',
    },
  };
  const existingSessionStart = (raw.sessionStart && typeof raw.sessionStart === 'object')
    ? raw.sessionStart as Record<string, unknown>
    : {};
  raw.sessionStart = {
    ...existingSessionStart,
    preamble: 'minimal',
  };
  writeRawConfig(raw);
}

// ── Auto-Memory Hook Config ───────────────────────────

export interface AutoMemoryEnableConfig {
  enableStop: boolean;
  enableSessionEnd: boolean;
}

/**
 * Returns the resolved on/off state of the opt-in auto-memory hooks.
 *
 * Default is false for both — preserves the OpenClaw-safe default that
 * shipped in v4.13.0. The install flags (`--with-stop-hook` /
 * `--with-session-end`) flip these to true so that wiring the hook in
 * settings.json and enabling the runtime gate are a single user action.
 */
export function getAutoMemoryEnableConfig(): AutoMemoryEnableConfig {
  const raw = readRawConfig();
  const am = raw.autoMemory && typeof raw.autoMemory === 'object'
    ? raw.autoMemory as Record<string, unknown>
    : {};
  return {
    enableStop: am.enableStop === true,
    enableSessionEnd: am.enableSessionEnd === true,
  };
}

/**
 * Persists the on/off state of the opt-in auto-memory hooks.
 *
 * Lives in `autoMemory.enableStop` / `autoMemory.enableSessionEnd` under
 * `~/.shieldcortex/config.json` — the same namespace `auto-memory-config.mjs`
 * reads from at hook fire time. Single source of truth: install flag +
 * runtime gate cannot disagree.
 */
export function setAutoMemoryEnableConfig(updates: Partial<AutoMemoryEnableConfig>): void {
  const raw = readRawConfig();
  const existing = raw.autoMemory && typeof raw.autoMemory === 'object'
    ? raw.autoMemory as Record<string, unknown>
    : {};
  if (updates.enableStop !== undefined) existing.enableStop = updates.enableStop;
  if (updates.enableSessionEnd !== undefined) existing.enableSessionEnd = updates.enableSessionEnd;
  raw.autoMemory = existing;
  writeRawConfig(raw);
}

// ── Tool Response Scan Config ─────────────────────────

export interface ToolResponseScanConfig {
  scanToolResponses: boolean;
  toolResponseMode: 'advisory' | 'enforce';
}

const DEFAULT_TOOL_RESPONSE_SCAN_CONFIG: ToolResponseScanConfig = {
  scanToolResponses: true,
  toolResponseMode: 'advisory',
};

/**
 * Returns tool response scanning config with safe defaults.
 */
export function getToolResponseScanConfig(): ToolResponseScanConfig {
  const raw = readRawConfig();
  return {
    scanToolResponses: raw.scanToolResponses !== false,
    toolResponseMode: raw.toolResponseMode === 'enforce' ? 'enforce' : DEFAULT_TOOL_RESPONSE_SCAN_CONFIG.toolResponseMode,
  };
}

/**
 * Persists tool response scanning config.
 */
export function setToolResponseScanConfig(updates: Partial<ToolResponseScanConfig>): void {
  const raw = readRawConfig();
  if (updates.scanToolResponses !== undefined) raw.scanToolResponses = updates.scanToolResponses;
  if (updates.toolResponseMode !== undefined) raw.toolResponseMode = updates.toolResponseMode;
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
