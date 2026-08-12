import { readFileSync, writeFileSync, mkdirSync, existsSync, chmodSync, statSync, renameSync, rmSync } from 'fs';
import { join } from 'path';
import { homedir, hostname } from 'os';
import { randomUUID, randomBytes, createHmac, timingSafeEqual } from 'crypto';
import type { RankerConfig, RankerEngine, RankerWeights } from '../memory/types.js';

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

export function getConfigDir(): string {
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
// Safety-first defaults: CONFIDENTIAL+ memories are NOT shipped to the cloud
// unless the user explicitly opts in via `--cloud-include-sensitive` or the
// dashboard. Prior to the v4.27 flip, `excludeSensitive` defaulted to false,
// which meant enabling cloud sync silently shipped credential-bearing /
// classified content without per-record consent. `contentMode` stays 'full'
// so the opt-in sync stream remains useful for PUBLIC/INTERNAL records that
// the user did consent to share.
const DEFAULT_SYNC_CONTROLS: CloudSyncControls = {
  projectMode: 'all',
  projects: [],
  contentMode: 'full',
  excludeSensitive: true,
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

// Raw-config cache keyed on (file path, mtimeMs). The defence pipeline reads
// the config on every scan via getDefenceMode() and ~30 other accessors all
// funnel through readRawConfig(); without this each call re-read + re-parsed +
// re-HMAC-verified the file. The mtime key means an external write (any other
// process) is picked up on its next stat, while a hot loop in one process pays
// for the read+parse+verify exactly once per actual file change.
let cachedRawConfig: Record<string, unknown> | null = null;
let cachedRawConfigFile: string | null = null;
let cachedRawConfigMtimeMs: number | null = null;

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

/**
 * The exact byte string the HMAC is computed over for the embedded-`_sig`
 * scheme. Defined once and used by BOTH the write path and the verify path so
 * they can never diverge: the canonical body is the config object with `_sig`
 * stripped, serialised with `JSON.stringify(rest, null, 2)`. Whatever the
 * writer signs, the verifier recomputes over the identical bytes.
 */
function canonicalBodyForSig(obj: Record<string, unknown>): string {
  const rest = { ...obj };
  delete rest._sig;
  return JSON.stringify(rest, null, 2);
}

function constantTimeEqualHex(storedSig: string, computedSig: string): boolean {
  const a = Buffer.from(storedSig, 'utf-8');
  const b = Buffer.from(computedSig, 'utf-8');
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

function writeConfigSignature(jsonContent: string): void {
  const sig = signConfig(jsonContent);
  const sigFile = getSigFile();
  writeFileSync(sigFile, sig, { mode: 0o600 });
  try { chmodSync(sigFile, 0o600); } catch { /* best-effort */ }
}

type IntegrityVerdict = 'valid' | 'self-heal' | 'tampered';

/**
 * Verify a parsed config object's integrity, returning a three-way verdict.
 *
 * Two on-disk formats are supported for backward compatibility:
 *   - **Embedded (new, v4.32+):** the object carries a top-level `_sig` field;
 *     verify it against the HMAC of `canonicalBodyForSig(obj)`.
 *   - **Legacy (pre-v4.32):** no `_sig` field — the signature lives in a
 *     separate `.config-sig` file, computed over the EXACT file bytes
 *     (`rawFileContent`). This is the original scheme; we keep reading it so an
 *     install that hasn't been rewritten yet never false-tampers. The next
 *     write upgrades it to the embedded format.
 *
 * **`'self-heal'`** — an embedded `_sig` is present but does NOT match, AND the
 * legacy whole-file `.config-sig` still validates over the exact bytes on disk.
 * That combination means the file content is provably authentic — only the
 * embedded sig drifted (e.g. it was written by an older version whose canonical
 * form differed, leaving the legacy sig behind). This is NOT tampering: both
 * schemes HMAC with the same secret `.integrity-key` (0600), so an attacker who
 * can't read that key can forge neither, and any edit to the body invalidates
 * BOTH signatures. The caller re-signs silently rather than crying tampering and
 * forcing strict mode. (Observed on a Mac after a cross-version config write.)
 *
 * `rawFileContent` is the literal bytes read from disk (needed for the legacy
 * whole-file signature). On a missing legacy sig file we adopt the current
 * content as trusted (first run after upgrade), matching prior behaviour.
 */
function checkConfigIntegrity(parsed: Record<string, unknown>, rawFileContent: string): IntegrityVerdict {
  try {
    if (typeof parsed._sig === 'string') {
      // Embedded scheme: recompute over the canonical body (object minus _sig).
      const computed = signConfig(canonicalBodyForSig(parsed));
      if (constantTimeEqualHex(parsed._sig, computed)) return 'valid';
      // Embedded sig mismatch — is the file otherwise authentic? If a legacy
      // whole-file sig still validates these exact bytes, the content is intact
      // and only the embedded sig is stale: heal, don't alarm.
      const sigFile = getSigFile();
      if (existsSync(sigFile)) {
        const legacySig = readFileSync(sigFile, 'utf-8').trim();
        if (constantTimeEqualHex(legacySig, signConfig(rawFileContent))) return 'self-heal';
      }
      return 'tampered';
    }
    // Legacy scheme: separate .config-sig file signed over the whole file.
    const sigFile = getSigFile();
    if (!existsSync(sigFile)) {
      // First run after upgrade with no sig yet — adopt as trusted, write a
      // legacy sig so a subsequent read (before the next write upgrades it)
      // still verifies. Matches the prior behaviour to avoid a false tamper.
      writeConfigSignature(rawFileContent);
      return 'valid';
    }
    const storedSig = readFileSync(sigFile, 'utf-8').trim();
    const computedSig = signConfig(rawFileContent);
    return constantTimeEqualHex(storedSig, computedSig) ? 'valid' : 'tampered';
  } catch {
    return 'tampered';
  }
}

/** Returns true if config file tampering was detected. */
export function isConfigTampered(): boolean {
  return configTampered;
}

export function getCloudConfig(): CloudConfig {
  const configFile = getConfigFile();
  if (cachedConfig && cachedConfigFile === configFile) return cachedConfig;

  // Route through the shared, mtime-cached, integrity-verified read so the
  // cloud config reflects the same view (and `_sig` stripping) as every other
  // accessor — no second bespoke parse path that could drift.
  const raw = readRawConfig();
  cachedConfig = {
    cloudApiKey: (raw.cloudApiKey as string | null | undefined) ?? null,
    cloudBaseUrl: (raw.cloudBaseUrl as string | undefined) ?? DEFAULT_BASE_URL,
    cloudEnabled: (raw.cloudEnabled as boolean | undefined) ?? false,
  };
  cachedConfigFile = configFile;
  return cachedConfig;
}

export function setCloudConfig(updates: Partial<CloudConfig>): void {
  // Read-modify-write through mutateRawConfig: preserves every other field
  // (defenceMode, deviceId, sync controls…) and writes atomically with the
  // embedded `_sig`. On a corrupt/unreadable file we do NOT silently start
  // fresh — that would wipe a credential the user is still relying on; the
  // helper throws so the caller surfaces the problem rather than losing data.
  mutateRawConfig((existing) => {
    if (updates.cloudApiKey !== undefined) existing.cloudApiKey = updates.cloudApiKey;
    if (updates.cloudBaseUrl !== undefined) existing.cloudBaseUrl = updates.cloudBaseUrl;
    if (updates.cloudEnabled !== undefined) existing.cloudEnabled = updates.cloudEnabled;
  });

  // Invalidate the derived cloud-config cache (writeRawConfig already cleared
  // the raw cache and tamper flag).
  cachedConfig = null;
  cachedConfigFile = null;
}

/** Reset the in-memory cache (useful for testing) */
export function clearCloudConfigCache(): void {
  cachedConfig = null;
  cachedConfigFile = null;
  invalidateRawConfigCache();
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
  // This is a READER. On a parse failure we must return the in-memory defaults
  // and NOT write — readRawConfigState preserves `parseFailed` so the one-shot
  // migration below never runs against a `{}` derived from a corrupt file
  // (which would persist a near-empty, signed config and wipe cloudApiKey).
  const { data: raw, parseFailed } = readRawConfigState();

  // One-shot v4.27 migration: pre-upgrade configs with cloud sync enabled
  // were silently shipping CONFIDENTIAL+ content because `excludeSensitive`
  // defaulted to false. Detect those configs (cloud on, no explicit setting,
  // no prior migration stamp) and rewrite them to the new safe default. If
  // the user later opts back in via `--cloud-include-sensitive`, that writes
  // `cloudSyncExcludeSensitive: false` explicitly and this branch is skipped.
  // Skip entirely on parseFailed: never write through a reader path.
  if (
    !parseFailed &&
    raw.cloudEnabled === true &&
    typeof raw.cloudSyncExcludeSensitive !== 'boolean' &&
    typeof raw.cloudSyncDefaultsMigratedAt !== 'string'
  ) {
    // Route the migration write through the guarded helper (skip-policy: a
    // reader must never throw). The earlier !parseFailed guard makes the skip
    // path unreachable here, but going through mutateRawConfig keeps the
    // single-source-of-truth invariant: no bare writeRawConfig outside it.
    mutateRawConfig((m) => {
      m.cloudSyncExcludeSensitive = true;
      m.cloudSyncDefaultsMigratedAt = new Date().toISOString();
    }, 'skip');
    raw.cloudSyncExcludeSensitive = true;
  }

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
  mutateRawConfig((raw) => {
    if (updates.projectMode !== undefined) raw.cloudSyncProjectMode = updates.projectMode;
    if (updates.projects !== undefined) raw.cloudSyncProjects = normalizeProjectList(updates.projects);
    if (updates.contentMode !== undefined) raw.cloudSyncContentMode = updates.contentMode;
    if (updates.excludeSensitive !== undefined) raw.cloudSyncExcludeSensitive = updates.excludeSensitive;
  });
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

interface RawConfigState {
  /** Parsed config (or {} if the file is missing/empty), with `_sig` stripped. */
  data: Record<string, unknown>;
  /**
   * True when the file EXISTS but could not be parsed (corrupt / mid-write
   * torn read). Callers that persist (getDeviceId/getDeviceName) MUST NOT write
   * when this is set — overwriting would wipe cloudApiKey and every other
   * setting that the unreadable file still holds.
   */
  parseFailed: boolean;
}

/**
 * Read + verify the raw config, distinguishing "file absent/empty" (safe to
 * write) from "file present but unparseable" (must stay read-only). Backed by
 * an mtime cache so a hot path (per-scan getDefenceMode) doesn't re-read,
 * re-parse and re-HMAC the file on every call.
 */
function readRawConfigState(): RawConfigState {
  const configFile = getConfigFile();

  // mtime cache: if the file is unchanged since the last successful read,
  // return the cached parsed object without touching disk again.
  try {
    const mtimeMs = statSync(configFile).mtimeMs;
    if (
      cachedRawConfig !== null &&
      cachedRawConfigFile === configFile &&
      cachedRawConfigMtimeMs === mtimeMs
    ) {
      // Return a shallow copy so callers can mutate freely without poisoning
      // the cache (accessors push to arrays / set fields before writing back).
      return { data: { ...cachedRawConfig }, parseFailed: false };
    }
  } catch {
    // stat failed (file likely absent) — fall through to the real read.
  }

  try {
    if (existsSync(configFile)) {
      // Capture mtime BEFORE reading the bytes. The cache key must describe the
      // exact bytes we're about to read: if we stat AFTER readFileSync, a
      // concurrent write between read and stat would cache the OLD bytes under
      // the NEW mtime, so a later read at that mtime would serve stale content.
      // Stat-before-read closes that window (a write after this stat bumps the
      // mtime past the cached key, forcing a re-read next time).
      let mtimeMsForCache: number | null = null;
      try { mtimeMsForCache = statSync(configFile).mtimeMs; } catch { /* best-effort */ }

      const content = readFileSync(configFile, 'utf-8');
      // An empty file is treated as "no config yet", not a parse failure.
      if (content.trim().length === 0) {
        return { data: {}, parseFailed: false };
      }

      let data: Record<string, unknown>;
      try {
        data = JSON.parse(content);
      } catch {
        // File exists but is corrupt/torn. Do NOT return {} as writable —
        // signal parseFailed so persisters skip the write and we never clobber
        // a momentarily-unreadable config.
        return { data: {}, parseFailed: true };
      }

      // Verify HMAC integrity (embedded `_sig`, else legacy `.config-sig`).
      const verdict = checkConfigIntegrity(data, content);
      if (verdict === 'tampered') {
        configTampered = true;
        console.error('[ShieldCortex] WARNING: Config file integrity check failed — possible tampering detected. Falling back to strict mode.');
        // Force strict mode on tampered config
        data.defenceMode = 'strict';
      }

      // `_sig` is an integrity artefact, never config data — strip it so it
      // can't leak into CloudConfig or get re-serialised as a normal field.
      delete data._sig;

      if (verdict === 'self-heal') {
        // The bytes are authentic (legacy whole-file sig still validates) — only
        // the embedded `_sig` drifted. Re-sign silently to converge on the
        // embedded-only format and drop the stale legacy sig. This is a one-shot:
        // after the rewrite the embedded sig matches, so subsequent reads return
        // 'valid'. The rewrite changes the file's mtime, so skip the (now stale)
        // cache population below and return the parsed data directly.
        //
        // Deliberately calls writeRawConfig DIRECTLY rather than via
        // mutateRawConfig (the usual sole-writer rule): we're already inside the
        // read, the content is parsed AND cryptographically authenticated (so the
        // {}-wipe-on-parse-fail risk mutateRawConfig guards against cannot apply),
        // and routing back through mutateRawConfig would re-enter readRawConfigState
        // — re-hitting this same 'self-heal' verdict before the write lands and
        // recursing. The direct write is what keeps it one-shot.
        try {
          writeRawConfig({ ...data });
        } catch { /* best-effort: a failed heal just re-checks on the next read */ }
        return { data, parseFailed: false };
      }

      // Populate the mtime cache from the parsed (sig-stripped) object, keyed on
      // the mtime captured BEFORE the read (matches the bytes actually parsed).
      if (mtimeMsForCache !== null) {
        cachedRawConfig = { ...data };
        cachedRawConfigFile = configFile;
        cachedRawConfigMtimeMs = mtimeMsForCache;
      }

      return { data, parseFailed: false };
    }
  } catch { /* ignore — treat as absent */ }
  return { data: {}, parseFailed: false };
}

export function readRawConfig(): Record<string, unknown> {
  return readRawConfigState().data;
}

/**
 * Strict source mode (DefenceConfig.strictSourceMode's config-file wire —
 * previously defined but consumed nowhere). Read from the top-level
 * `strictSourceMode` key, mirroring `defenceMode`. Default false.
 */
export function getStrictSourceMode(): boolean {
  return readRawConfig().strictSourceMode === true;
}

/**
 * Threat-graph trust-modifier mode (docs/design/2026-08-11-threat-graph.md,
 * Loop 2). `threatGraph.trustModifier`: 'off' | 'advisory' | 'enforce'.
 * Default 'advisory' — computed and recorded on the audit row, not applied —
 * so real-world false-positive data accrues before anything changes scan
 * behaviour (#182). Any other value falls back to advisory.
 */
export function getTrustModifierMode(raw?: Record<string, unknown>): 'off' | 'advisory' | 'enforce' {
  const source = raw ?? readRawConfig();
  const block = source.threatGraph;
  if (block && typeof block === 'object' && !Array.isArray(block)) {
    const mode = (block as Record<string, unknown>).trustModifier;
    if (mode === 'off' || mode === 'enforce') return mode;
  }
  return 'advisory';
}

/**
 * Threat-graph feature gate (docs/design/2026-08-11-threat-graph.md).
 * Enabled unless config sets `threatGraph.enabled: false` explicitly.
 * Pass `raw` for tests; production callers omit it and read the live config.
 */
export function isThreatGraphEnabled(raw?: Record<string, unknown>): boolean {
  const source = raw ?? readRawConfig();
  const block = source.threatGraph;
  if (!block || typeof block !== 'object' || Array.isArray(block)) return true;
  return (block as Record<string, unknown>).enabled !== false;
}

function invalidateRawConfigCache(): void {
  cachedRawConfig = null;
  cachedRawConfigFile = null;
  cachedRawConfigMtimeMs = null;
}

/**
 * Atomically persist the raw config with the HMAC embedded as a top-level
 * `_sig` field, computed over `canonicalBodyForSig` (the object WITHOUT
 * `_sig`). Because the signature lives inside the same file and the file is
 * swapped in via `renameSync` (atomic on POSIX), a concurrent reader can never
 * observe a half-written file or a config/signature pair that are out of step
 * — the two torn-read cases the audit found.
 */
function writeRawConfig(raw: Record<string, unknown>): void {
  const configDir = getConfigDir();
  const configFile = getConfigFile();
  mkdirSync(configDir, { recursive: true });

  // Never carry an inbound `_sig` through; we always recompute it.
  const { _sig: _ignored, ...rest } = raw;
  const body = canonicalBodyForSig(rest);
  const sig = signConfig(body);
  const out = JSON.stringify({ ...rest, _sig: sig }, null, 2) + '\n';

  // Write to a unique temp file in the same dir, then atomically rename over
  // the target. The original config survives a failed/partial write — we never
  // truncate it. Same-dir tmp guarantees rename is a same-filesystem move.
  const tmpFile = `${configFile}.tmp-${process.pid}-${randomBytes(6).toString('hex')}`;
  try {
    writeFileSync(tmpFile, out, { mode: 0o600 });
    // On Windows, renameSync over an EXISTING target can throw EPERM if another
    // process has the destination open concurrently. This is non-corrupting:
    // the original config is left intact and the catch below removes the tmp
    // file and rethrows, so a write may FAIL rather than damage the config.
    renameSync(tmpFile, configFile);
  } catch (err) {
    try { if (existsSync(tmpFile)) rmSync(tmpFile, { force: true }); } catch { /* best-effort */ }
    throw err;
  }

  // The embedded `_sig` is now the source of truth. Delete the stale legacy
  // `.config-sig` only after a successful embedded write, only if it exists —
  // this completes the one-way upgrade from the legacy format.
  try {
    const sigFile = getSigFile();
    if (existsSync(sigFile)) rmSync(sigFile, { force: true });
  } catch { /* best-effort */ }

  cachedConfig = null;
  cachedConfigFile = null;
  invalidateRawConfigCache();
  // Clear tamper flag on legitimate write
  configTampered = false;
}

/**
 * The ONLY sanctioned read-modify-write path for config.json.
 *
 * EVERY mutating accessor MUST go through this helper. Do NOT call
 * `writeRawConfig` with a `raw` object obtained from a bare `readRawConfig()`:
 * `readRawConfig()` collapses a parse failure to `{}`, discarding the
 * `parseFailed` flag, so mutating that `{}` and writing it back atomically
 * persists a near-empty, validly-signed config — wiping `cloudApiKey` and every
 * other setting the corrupt file still holds, with no error signal. This helper
 * reads through `readRawConfigState()` (which preserves `parseFailed`) and
 * refuses to write when the on-disk config is unreadable.
 *
 * `onParseFail`:
 *   - `'throw'` (default): surface corruption to user-facing/explicit setters so
 *     the caller sees the problem rather than silently losing credentials.
 *   - `'skip'`: silently no-op for automatic / hot-path writes that must NEVER
 *     throw (background sync, read-with-migration). Returns false so the caller
 *     can tell the write was skipped.
 *
 * Returns true if the mutation was applied and persisted, false if it was
 * skipped because the config was unparseable (`onParseFail: 'skip'`).
 */
function mutateRawConfig(
  fn: (raw: Record<string, unknown>) => void,
  onParseFail: 'throw' | 'skip' = 'throw',
): boolean {
  const { data, parseFailed } = readRawConfigState();
  if (parseFailed) {
    console.error('[ShieldCortex] config.json is unreadable — refusing to overwrite (would wipe settings incl. cloudApiKey). Fix or remove the file.');
    if (onParseFail === 'throw') {
      throw new Error(
        'ShieldCortex config.json is corrupt/unparseable; refusing to overwrite to avoid losing settings. ' +
        'Fix or remove ~/.shieldcortex/config.json and retry.',
      );
    }
    return false;
  }
  fn(data);
  writeRawConfig(data);
  return true;
}

export function getTrustedSkills(): string[] {
  const raw = readRawConfig();
  return Array.isArray(raw.trustedSkills) ? raw.trustedSkills as string[] : [];
}

export function addTrustedSkill(path: string): void {
  // Throw-policy explicit setter: on a corrupt config mutateRawConfig throws
  // (surfacing the corruption) rather than wiping it. The closure is itself a
  // no-op write when the skill is already present, which is acceptable churn on
  // a VALID config and avoids a second bare read just to skip a write — the one
  // case we must not silently swallow is the corrupt one, which the helper
  // handles by throwing.
  mutateRawConfig((raw) => {
    const list = Array.isArray(raw.trustedSkills) ? raw.trustedSkills as string[] : [];
    if (!list.includes(path)) list.push(path);
    raw.trustedSkills = list;
  });
}

export function removeTrustedSkill(path: string): void {
  mutateRawConfig((raw) => {
    const list = Array.isArray(raw.trustedSkills) ? raw.trustedSkills as string[] : [];
    const idx = list.indexOf(path);
    if (idx !== -1) list.splice(idx, 1);
    raw.trustedSkills = list;
  });
}

// ── Reviewed-script allowlist (#189) ──────────────────

function actionGuardBlock(raw: Record<string, unknown>): Record<string, unknown> {
  return raw.actionGuard && typeof raw.actionGuard === 'object' && !Array.isArray(raw.actionGuard)
    ? (raw.actionGuard as Record<string, unknown>)
    : {};
}

/** RAW entries from `actionGuard.reviewedScripts` — shape validation is
 *  normaliseReviewedScripts's job (reviewed-scripts.ts), not this reader's. */
export function getReviewedScriptsRaw(): unknown[] {
  const guard = actionGuardBlock(readRawConfig());
  return Array.isArray(guard.reviewedScripts) ? guard.reviewedScripts : [];
}

/** Replace the allowlist wholesale. Same throw-policy as addTrustedSkill: a
 *  corrupt config surfaces as a throw, never as a silent wipe-and-rewrite. */
export function setReviewedScripts(entries: Array<Record<string, unknown>>): void {
  mutateRawConfig((raw) => {
    const guard = actionGuardBlock(raw);
    guard.reviewedScripts = entries;
    raw.actionGuard = guard;
  });
}

// ── Cloud Iron Dome Cache ─────────────────────────────

/**
 * Persist cloud Iron Dome data (patterns + policy) to config.json with HMAC integrity.
 */
export function setCloudIronDomeCache(data: Record<string, unknown>): void {
  mutateRawConfig((raw) => {
    raw.cloudIronDome = data;
  });
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

// Debounce state for lastSyncAt. The sync queue, graph-sync and memory-sync all
// call updateLastSyncAt() after EVERY successful upload — a busy agent fired a
// full read-modify-write of config.json per record. We keep the latest value in
// memory and only persist at most once per LAST_SYNC_PERSIST_INTERVAL_MS, which
// collapses a burst to a single write while readers still see a fresh value.
const LAST_SYNC_PERSIST_INTERVAL_MS = 60_000;
let pendingLastSyncAt: string | null = null;
let lastSyncPersistedAtMs = 0;

/**
 * Record a successful cloud sync. Always updates the in-memory timestamp;
 * persists to config.json at most once per 60s (time-debounced). Callers
 * (sync.ts / sync-queue.ts / memory-sync.ts) are unchanged — the debounce is
 * internal.
 */
export function updateLastSyncAt(): void {
  const now = Date.now();
  pendingLastSyncAt = new Date(now).toISOString();
  if (now - lastSyncPersistedAtMs < LAST_SYNC_PERSIST_INTERVAL_MS) {
    return; // within the debounce window — memory updated, disk left alone
  }
  persistLastSyncAt(now);
}

function persistLastSyncAt(nowMs: number): void {
  if (pendingLastSyncAt === null) return;
  // Automatic / hot path (fires after cloud uploads): MUST NOT throw. The
  // 'skip' policy makes mutateRawConfig a silent no-op on an unreadable config
  // (returns false) instead of clobbering it. Only stamp the debounce clock
  // when the write actually landed, so a skipped write is retried next call.
  const written = mutateRawConfig((raw) => {
    raw.lastSyncAt = pendingLastSyncAt;
  }, 'skip');
  if (written) lastSyncPersistedAtMs = nowMs;
}

/**
 * Force-persist the latest in-memory lastSyncAt regardless of the debounce
 * window, so the final sync timestamp isn't lost if the process exits inside
 * the debounce window. Safe no-op if nothing is pending.
 *
 * Available for a shutdown path (not currently wired): the existing
 * SIGINT/SIGTERM/exit handlers (src/index.ts, src/api/visualization-server.ts)
 * are MCP-server / dashboard lifecycle concerns and don't obviously own the
 * cloud-sync clock, so wiring is left to whichever shutdown owner adopts it
 * rather than bolted onto an unrelated handler. Losing at most one debounced
 * timestamp on abrupt exit is non-critical (the next sync re-stamps it).
 */
export function flushLastSyncAt(): void {
  persistLastSyncAt(Date.now());
}

/**
 * Returns the most recent sync timestamp, preferring the in-memory value (which
 * may be ahead of disk inside the debounce window) and falling back to the
 * persisted config value.
 */
export function getLastSyncAt(): string | null {
  if (pendingLastSyncAt !== null) return pendingLastSyncAt;
  const raw = readRawConfig();
  return typeof raw.lastSyncAt === 'string' ? raw.lastSyncAt : null;
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
  mutateRawConfig((raw) => {
    raw.defenceMode = mode;
  });
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
  mutateRawConfig((raw) => {
    if (updates.verifyEnabled !== undefined) raw.verifyEnabled = updates.verifyEnabled;
    if (updates.verifyMode !== undefined) raw.verifyMode = updates.verifyMode;
    if (updates.verifyTriggers !== undefined) raw.verifyTriggers = updates.verifyTriggers;
    if (updates.verifyTimeoutMs !== undefined) raw.verifyTimeoutMs = updates.verifyTimeoutMs;
  });
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
  mutateRawConfig((raw) => {
    const existing = raw.reviewCopilot && typeof raw.reviewCopilot === 'object'
      ? raw.reviewCopilot as Record<string, unknown>
      : {};
    raw.reviewCopilot = {
      ...existing,
      ...updates,
    };
  });
}

// ── Ranker Config ─────────────────────────────────────

const DEFAULT_RANKER_CONFIG: RankerConfig = {
  engine: 'rrf',
  rrfK: 60,
  weights: { fts: 0.4, vector: 0.6, graph: 0.3 },
};

const VALID_RANKER_ENGINES: RankerEngine[] = ['rrf', 'legacy'];

function parseEngine(value: unknown): RankerEngine | null {
  if (typeof value !== 'string') return null;
  const normalized = value.trim().toLowerCase();
  return VALID_RANKER_ENGINES.includes(normalized as RankerEngine)
    ? (normalized as RankerEngine)
    : null;
}

function parseWeights(value: unknown): RankerWeights | null {
  if (!value || typeof value !== 'object') return null;
  const v = value as Record<string, unknown>;
  const fts = typeof v.fts === 'number' ? v.fts : null;
  const vector = typeof v.vector === 'number' ? v.vector : null;
  const graph = typeof v.graph === 'number' ? v.graph : null;
  if (fts === null || vector === null || graph === null) return null;
  return { fts, vector, graph };
}

/**
 * Resolved ranker configuration.
 *
 * Resolution order (env wins so it can be flipped per-process without
 * editing config.json):
 *   1. `SHIELDCORTEX_RANKER` env var (`rrf` | `legacy`)
 *   2. `ranker.engine` in `~/.shieldcortex/config.json`
 *   3. Default (`rrf`)
 *
 * `rrfK` and `weights` only come from config.json (no env override) —
 * tuning these is a deliberate config change, not a per-process knob.
 */
export function getRankerConfig(): RankerConfig {
  const raw = readRawConfig();
  const fileRanker = raw.ranker && typeof raw.ranker === 'object'
    ? raw.ranker as Record<string, unknown>
    : null;

  const envEngine = parseEngine(process.env.SHIELDCORTEX_RANKER);
  const fileEngine = fileRanker ? parseEngine(fileRanker.engine) : null;
  const engine = envEngine ?? fileEngine ?? DEFAULT_RANKER_CONFIG.engine;

  const fileK = fileRanker && typeof fileRanker.rrfK === 'number' && fileRanker.rrfK > 0
    ? fileRanker.rrfK
    : null;
  const rrfK = fileK ?? DEFAULT_RANKER_CONFIG.rrfK;

  const fileWeights = fileRanker ? parseWeights(fileRanker.weights) : null;
  const weights = fileWeights ?? DEFAULT_RANKER_CONFIG.weights;

  return { engine, rrfK, weights };
}

/**
 * Persists ranker config to `~/.shieldcortex/config.json`. Only the
 * fields supplied in `updates` are written; other fields are preserved.
 */
export function setRankerConfig(updates: Partial<RankerConfig>): void {
  mutateRawConfig((raw) => {
    const existing = raw.ranker && typeof raw.ranker === 'object'
      ? raw.ranker as Record<string, unknown>
      : {};
    if (updates.engine !== undefined) existing.engine = updates.engine;
    if (updates.rrfK !== undefined) existing.rrfK = updates.rrfK;
    if (updates.weights !== undefined) existing.weights = updates.weights;
    raw.ranker = existing;
  });
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
  mutateRawConfig((raw) => {
    if (updates.autoMemory !== undefined) raw.openclawAutoMemory = updates.autoMemory;
    if (updates.dedupe !== undefined) raw.openclawAutoMemoryDedupe = updates.dedupe;
    if (updates.noveltyThreshold !== undefined) {
      raw.openclawAutoMemoryNoveltyThreshold = clamp(updates.noveltyThreshold, 0.6, 0.99);
    }
    if (updates.maxRecent !== undefined) {
      raw.openclawAutoMemoryMaxRecent = Math.floor(clamp(updates.maxRecent, 50, 1000));
    }
  });
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
  mutateRawConfig((raw) => {
    raw.proactiveRecall = enabled;
  });
}

/**
 * Is the cortex-memory hook's bootstrap self-heal allowed to write? (#108)
 *
 * Default is true — the hook may delete the legacy ~/.clawdbot hook dirs and
 * copy itself into ~/.openclaw/hooks. Set false to downgrade both mutations to
 * warn-only log lines. Mirrors `isSelfHealEnabled` in the hook's runtime.mjs,
 * which reads the same key (the hook can't import this module).
 */
export function isSelfHealEnabled(): boolean {
  const raw = readRawConfig();
  return raw.selfHeal !== false;
}

/**
 * Persists the self-heal preference to ~/.shieldcortex/config.json.
 */
export function setSelfHeal(enabled: boolean): void {
  mutateRawConfig((raw) => {
    raw.selfHeal = enabled;
  });
}

/**
 * Restores the v4.10.x defaults for users who preferred the old behaviour.
 * Writes explicit overrides for every default the v4.11.0 release flipped,
 * so the flip is a one-command undo.
 */
export function restore410Defaults(): void {
  mutateRawConfig((raw) => {
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
  });
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
  mutateRawConfig((raw) => {
    const existing = raw.autoMemory && typeof raw.autoMemory === 'object'
      ? raw.autoMemory as Record<string, unknown>
      : {};
    if (updates.enableStop !== undefined) existing.enableStop = updates.enableStop;
    if (updates.enableSessionEnd !== undefined) existing.enableSessionEnd = updates.enableSessionEnd;
    raw.autoMemory = existing;
  });
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
  mutateRawConfig((raw) => {
    if (updates.scanToolResponses !== undefined) raw.scanToolResponses = updates.scanToolResponses;
    if (updates.toolResponseMode !== undefined) raw.toolResponseMode = updates.toolResponseMode;
  });
}

// ── Revoke-by-source gate ─────────────────────────────

/**
 * revoke-by-source (bulk delete all memories from a source) is a destructive
 * mass-delete primitive. Because a prompt-injection adversary runs AS the agent
 * at the agent's own trust, no in-band (trust) check can distinguish "the human
 * asked" from "an injection asked". So it is gated OFF by default and can only
 * be enabled by an out-of-band human action (editing config / the CLI flag) that
 * a hijacked agent cannot perform.
 */
export function isRevokeBySourceEnabled(): boolean {
  return readRawConfig().allowRevokeBySource === true;
}

export function setRevokeBySourceEnabled(enabled: boolean): void {
  mutateRawConfig((raw) => { raw.allowRevokeBySource = enabled; });
}

// ── Device Identity ────────────────────────────────────

/**
 * Returns a stable UUID for this machine.
 * Generates and persists on first call; reads from config thereafter.
 */
export function getDeviceId(): string {
  const { data: raw, parseFailed } = readRawConfigState();
  if (typeof raw.deviceId === 'string' && raw.deviceId) {
    return raw.deviceId;
  }
  const id = randomUUID();
  if (parseFailed) {
    // The config file exists but is unreadable. Persisting now would write
    // `{ deviceId }` over the corrupt bytes and destroy cloudApiKey and every
    // other setting the file still holds. Return an ephemeral id this run and
    // leave the file untouched — identity persists once the file is readable.
    // (mutateRawConfig('skip') would no-op here too, but we want this specific
    // diagnostic, so we short-circuit before calling it.)
    console.error('[ShieldCortex] config.json unreadable — using an ephemeral device id this run; identity was NOT persisted.');
    return id;
  }
  // Persist through the guarded helper so no bare writeRawConfig exists outside
  // mutateRawConfig; skip-policy keeps this read-then-persist path non-throwing.
  mutateRawConfig((m) => {
    m.deviceId = id;
  }, 'skip');
  return id;
}

/**
 * Returns the OS hostname for this machine.
 * Stores in config on first call; reads from config thereafter.
 */
export function getDeviceName(): string {
  const { data: raw, parseFailed } = readRawConfigState();
  if (typeof raw.deviceName === 'string' && raw.deviceName) {
    return raw.deviceName;
  }
  const name = hostname();
  if (parseFailed) {
    // See getDeviceId — never overwrite an unreadable config.
    console.error('[ShieldCortex] config.json unreadable — using the live hostname this run; device name was NOT persisted.');
    return name;
  }
  mutateRawConfig((m) => {
    m.deviceName = name;
  }, 'skip');
  return name;
}
