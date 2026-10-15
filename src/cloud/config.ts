import { readFileSync, writeFileSync, mkdirSync, existsSync, chmodSync, statSync, renameSync, rmSync } from 'fs';
import { join, resolve } from 'path';
import { homedir, hostname } from 'os';
import { randomUUID, randomBytes, createHash, createHmac, timingSafeEqual } from 'crypto';
import type { RankerConfig, RankerEngine, RankerWeights } from '../memory/types.js';
import { mkdirSecure } from '../setup/state-permissions.js';
import {
  syncOpenClawPluginActionGuard,
  type OpenClawPluginGuardSync,
} from '../setup/openclaw-plugin-guard-sync.js';
import {
  applyPolicyLock,
  applyStrictFailClosedPosture,
  assertPolicyLockAllows,
  policyLockCoverage,
  readPolicyLock,
  PolicyLockRefusal,
  type PolicyLockState,
  type ProtectedPolicyKey,
} from '../defence/iron-dome/policy-lock.js';
import { emitProtectedAudit } from '../defence/iron-dome/protected-root.js';
import { openRecoveryAuditSink, type RecoveryAuditSink } from './recovery-audit.js';

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
// The verdict the cached object was classified with (#647). A cache hit must
// answer with the same verdict as the read that populated it — before this a
// hit reported a tampered file as an ordinary writable one.
let cachedRawConfigIntegrity: ConfigIntegrity | null = null;

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
  mkdirSecure(configDir);
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
function checkConfigIntegrity(parsed: Record<string, unknown>, rawFileContent: string): IntegrityVerdict;
function checkConfigIntegrity(
  parsed: Record<string, unknown>,
  rawFileContent: string,
  opts: { sideEffects: false },
): IntegrityVerdict | 'unsigned';
function checkConfigIntegrity(
  parsed: Record<string, unknown>,
  rawFileContent: string,
  opts: { sideEffects: boolean } = { sideEffects: true },
): IntegrityVerdict | 'unsigned' {
  try {
    // A read-only inspection (doctor, the re-sign preview) must not mint an
    // integrity key: a missing key leaves nothing to verify against, which is
    // reported as tampered exactly as the minting path would conclude.
    const sign = opts.sideEffects
      ? signConfig
      : (() => {
          const key = readIntegrityKeyNoMint();
          return (body: string): string => {
            if (key === null) throw new Error('no integrity key');
            return createHmac('sha256', key).update(body, 'utf-8').digest('hex');
          };
        })();
    if (typeof parsed._sig === 'string') {
      // Embedded scheme: recompute over the canonical body (object minus _sig).
      const computed = sign(canonicalBodyForSig(parsed));
      if (constantTimeEqualHex(parsed._sig, computed)) return 'valid';
      // Embedded sig mismatch — is the file otherwise authentic? If a legacy
      // whole-file sig still validates these exact bytes, the content is intact
      // and only the embedded sig is stale: heal, don't alarm.
      const sigFile = getSigFile();
      if (existsSync(sigFile)) {
        const legacySig = readFileSync(sigFile, 'utf-8').trim();
        if (constantTimeEqualHex(legacySig, sign(rawFileContent))) return 'self-heal';
      }
      return 'tampered';
    }
    // Legacy scheme: separate .config-sig file signed over the whole file.
    const sigFile = getSigFile();
    if (!existsSync(sigFile)) {
      // Read-only inspection: say what the ordinary read WOULD do, don't do it.
      if (!opts.sideEffects) return 'unsigned';
      // First run after upgrade with no sig yet — adopt as trusted, write a
      // legacy sig so a subsequent read (before the next write upgrades it)
      // still verifies. Matches the prior behaviour to avoid a false tamper.
      writeConfigSignature(rawFileContent);
      return 'valid';
    }
    const storedSig = readFileSync(sigFile, 'utf-8').trim();
    const computedSig = sign(rawFileContent);
    return constantTimeEqualHex(storedSig, computedSig) ? 'valid' : 'tampered';
  } catch {
    return 'tampered';
  }
}

/** The integrity key if one exists — never generated (see checkConfigIntegrity). */
function readIntegrityKeyNoMint(): string | null {
  try {
    const key = readFileSync(getIntegrityKeyFile(), 'utf-8').trim();
    return key || null;
  } catch {
    return null;
  }
}

/**
 * What `config.json` is, as the integrity check sees it (#647). Every state is
 * named rather than collapsed: before this, "unreadable" and "non-object JSON"
 * read as absent (and were then overwritten), and a cache hit forgot that the
 * file it had cached was tampered.
 *
 *  - `absent`     no file, or an empty one — safe to create.
 *  - `valid`      a signature verifies (or an unsigned legacy file was adopted).
 *  - `self-heal`  the embedded `_sig` is stale but the legacy whole-file sig
 *                 still authenticates the exact bytes; re-signed on read.
 *  - `malformed`  present but not a JSON object.
 *  - `unreadable` present but could not be read (permissions, a directory, I/O).
 *  - `tampered`   no signature authenticates these bytes.
 */
export type ConfigIntegrity = 'absent' | 'valid' | 'self-heal' | 'malformed' | 'unreadable' | 'tampered';

/**
 * Thrown by an explicit setter asked to write while `config.json` is
 * `tampered` (#647).
 *
 * A write starts from the file's bytes, and on a tampered file those bytes are
 * exactly what the integrity check refused to trust. Writing them back would
 * sign them as valid and end the alarm; writing the strict view back instead
 * would persist the fail-closed posture as if the operator had chosen it,
 * wiping `reviewedScripts`/`autoApprove`. So the write does neither: the file,
 * its pins and its stale signature are left exactly as they are, the strict
 * posture stays in force on every read, and the message points at the
 * deliberate recovery.
 */
export class ConfigIntegrityRefusal extends Error {
  readonly verdict: 'tampered';
  readonly configPath: string;
  constructor(configPath: string) {
    super(
      `Refusing to write ${configPath}: it does not match its integrity signature (verdict: tampered — ` +
      'corruption, a torn write, or a hand edit). The file, its reviewed-script pins and its auto-approve ' +
      'list are left untouched, and the strict fail-closed posture stays in force until the file is ' +
      'recovered. A setting change cannot re-sign it. See `shieldcortex doctor` for the verdict and ' +
      '`shieldcortex config --resign` to review the file and re-sign it deliberately.',
    );
    this.name = 'ConfigIntegrityRefusal';
    this.verdict = 'tampered';
    this.configPath = configPath;
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
  /**
   * Parsed config (or {} if the file is missing/empty/unreadable), with `_sig`
   * stripped. In the UNLOCKED state this is what the file says — including on
   * a `tampered` verdict, where it is the untrusted bytes, never the strict
   * view (#647). The effective reader applies the posture.
   */
  data: Record<string, unknown>;
  /**
   * True when the file EXISTS but could not be parsed or read (corrupt /
   * mid-write torn read / non-object JSON / unreadable). Callers that persist
   * (getDeviceId/getDeviceName) MUST NOT write when this is set — overwriting
   * would wipe cloudApiKey and every other setting that the file still holds.
   */
  parseFailed: boolean;
  /** The integrity verdict these bytes were classified with (#647). */
  integrity: ConfigIntegrity;
}

/**
 * Read + verify the raw config, distinguishing "file absent/empty" (safe to
 * write) from "file present but unparseable" (must stay read-only). Backed by
 * an mtime cache so a hot path (per-scan getDefenceMode) doesn't re-read,
 * re-parse and re-HMAC the file on every call.
 *
 * **Unlocked** (#501): this returns what `config.json` SAYS, with the policy
 * lock not yet applied. {@link readRawConfigState} is the reader every accessor
 * should use; this one exists for {@link mutateRawConfig}, which must write back
 * what the operator configured and never bake a lock-derived value into the file
 * (that would silently turn a temporary OS-owned floor into a permanent local
 * setting, and would survive removing the lock).
 *
 * **Not forced either** (#647): on a `tampered` verdict the data here is still
 * the file's own bytes, with `integrity: 'tampered'`. The strict fail-closed
 * posture is applied by {@link readRawConfigState}, for the same reason the
 * lock is: a value forced on top of the file for READS must never become the
 * file. Before #647 the posture was applied here, so the next incidental write
 * persisted it — `reviewedScripts`/`autoApprove` wiped — and re-signed the
 * result as valid, ending the tamper alarm with nobody having reviewed it.
 */
function readRawConfigStateUnlocked(): RawConfigState {
  const configFile = getConfigFile();

  // mtime cache: if the file is unchanged since the last successful read,
  // return the cached parsed object without touching disk again.
  try {
    const mtimeMs = statSync(configFile).mtimeMs;
    if (
      cachedRawConfig !== null &&
      cachedRawConfigFile === configFile &&
      cachedRawConfigMtimeMs === mtimeMs &&
      cachedRawConfigIntegrity !== null
    ) {
      configTampered = cachedRawConfigIntegrity === 'tampered';
      // Return a shallow copy so callers can mutate freely without poisoning
      // the cache (accessors push to arrays / set fields before writing back).
      return { data: { ...cachedRawConfig }, parseFailed: false, integrity: cachedRawConfigIntegrity };
    }
  } catch {
    // stat failed (file likely absent) — fall through to the real read.
  }

  let present = false;
  try {
    if (existsSync(configFile)) {
      present = true;
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
        configTampered = false;
        return { data: {}, parseFailed: false, integrity: 'absent' };
      }

      let parsed: unknown;
      try {
        parsed = JSON.parse(content);
      } catch {
        // File exists but is corrupt/torn. Do NOT return {} as writable —
        // signal parseFailed so persisters skip the write and we never clobber
        // a momentarily-unreadable config.
        configTampered = false;
        return { data: {}, parseFailed: true, integrity: 'malformed' };
      }
      // `null`, an array or a scalar parses but is not a config. It used to
      // fall into the catch below and read as ABSENT — writable, and so
      // overwritten by the next setter. It is malformed, like a torn write.
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
        configTampered = false;
        return { data: {}, parseFailed: true, integrity: 'malformed' };
      }
      const data = parsed as Record<string, unknown>;

      // Verify HMAC integrity (embedded `_sig`, else legacy `.config-sig`).
      const verdict = checkConfigIntegrity(data, content);
      configTampered = verdict === 'tampered';
      if (verdict === 'tampered') {
        console.error(
          '[ShieldCortex] WARNING: config integrity check failed — the file does not match its signature ' +
          '(corruption, a torn write, or a hand edit). Falling back to the strict fail-closed posture.',
        );
        // #501 forces the WHOLE fail-closed posture on a tampered verdict. #647
        // moved WHERE: it is applied in readRawConfigState, on the way out to
        // readers, so that this state (the one writes start from) keeps the
        // file's own bytes and mutateRawConfig can refuse to sign them.
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
        // recursing. The direct write is what keeps it one-shot. It is never the
        // tampered path (#647): 'self-heal' requires a signature over these bytes.
        try {
          writeRawConfig({ ...data });
        } catch { /* best-effort: a failed heal just re-checks on the next read */ }
        return { data, parseFailed: false, integrity: 'self-heal' };
      }

      // Populate the mtime cache from the parsed (sig-stripped) object, keyed on
      // the mtime captured BEFORE the read (matches the bytes actually parsed),
      // together with the verdict so a cache hit answers the same way.
      if (mtimeMsForCache !== null) {
        cachedRawConfig = { ...data };
        cachedRawConfigFile = configFile;
        cachedRawConfigMtimeMs = mtimeMsForCache;
        cachedRawConfigIntegrity = verdict;
      }

      return { data, parseFailed: false, integrity: verdict };
    }
  } catch {
    // A file that EXISTS but cannot be read (EACCES, EISDIR, EIO) is not an
    // absent one: treating it as absent let the next setter rename a fresh
    // near-empty config over it (#647). Read-only, like a parse failure.
    if (present) {
      configTampered = false;
      return { data: {}, parseFailed: true, integrity: 'unreadable' };
    }
  }
  configTampered = false;
  return { data: {}, parseFailed: false, integrity: 'absent' };
}

/**
 * The raw config as it is actually IN FORCE — `config.json` with the OS-owned
 * policy lock applied on top (#501).
 *
 * Every reader goes through here, which is the whole point: before #501 the
 * security switches were read straight out of a same-UID file, so "what the
 * config says" and "what is enforced" were the same sentence and a one-line
 * edit changed both. Now the lock is the floor and the file may only tighten it.
 *
 * The lock is re-read on every call rather than cached alongside the config
 * mtime. That is four `lstat`s on an unlocked host, and it buys the property
 * that an operator who has just run `protect` is obeyed by the already-running
 * agent instead of at its next restart. A stale security policy is the worse
 * trade.
 */
function readRawConfigState(): RawConfigState {
  const state = readRawConfigStateUnlocked();
  // #501: a tampered verdict forces the WHOLE fail-closed posture, not just
  // `defenceMode`. Before #501, `actionGuard.enabled` was still read straight
  // out of the bytes the integrity check had just called untrustworthy — so
  // the one scenario the check exists to catch was also the scenario in which
  // the guard stayed off. Same posture the policy lock uses for an
  // unverifiable lock, from the same constant, so the two cannot drift.
  // #647: applied HERE, on the effective view only, never to the state a
  // write starts from — same order and same function as before, so every
  // reader sees exactly what it saw before #647.
  const base = state.integrity === 'tampered' ? applyStrictFailClosedPosture(state.data) : state.data;
  const lock = getPolicyLockState();
  const locked = applyPolicyLock(base, lock);
  return locked === state.data ? state : { ...state, data: locked };
}

/**
 * The live policy-lock state. `audit: true` — this is the src-side runtime,
 * where the SQLite audit logger is already available, and an unverifiable lock
 * is exactly the thing that has to leave a forensic trace.
 */
export function getPolicyLockState(): PolicyLockState {
  return readPolicyLock({ audit: true });
}

export function readRawConfig(): Record<string, unknown> {
  return readRawConfigState().data;
}

// ── Integrity inspection and deliberate re-sign (#647) ──

export interface ConfigIntegrityReport {
  /**
   * The verdict, with one more word than {@link ConfigIntegrity}: `unsigned`
   * is a file with no signature at all, which the next ordinary read adopts
   * as trusted (pre-v4.32 compatibility). Inspection reports it instead of
   * adopting it.
   */
  verdict: ConfigIntegrity | 'unsigned';
  path: string;
}

interface ConfigBytes {
  path: string;
  verdict: ConfigIntegrity | 'unsigned';
  bytes: Buffer | null;
  data: Record<string, unknown> | null;
}

function readConfigBytesNoSideEffects(): ConfigBytes {
  const path = getConfigFile();
  if (!existsSync(path)) return { path, verdict: 'absent', bytes: null, data: null };
  let bytes: Buffer;
  try {
    bytes = readFileSync(path);
  } catch {
    return { path, verdict: 'unreadable', bytes: null, data: null };
  }
  const content = bytes.toString('utf-8');
  if (content.trim().length === 0) return { path, verdict: 'absent', bytes, data: null };
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return { path, verdict: 'malformed', bytes, data: null };
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { path, verdict: 'malformed', bytes, data: null };
  }
  const data = parsed as Record<string, unknown>;
  return { path, verdict: checkConfigIntegrity(data, content, { sideEffects: false }), bytes, data };
}

/**
 * The integrity verdict of `config.json` RIGHT NOW, with no side effects at
 * all: no self-heal write, no legacy-signature adoption, no integrity-key mint,
 * no cache update and no change to {@link isConfigTampered}. Doctor reports
 * this, so that what it says cannot depend on which accessor ran first, and so
 * that asking the question never changes the answer.
 */
export function inspectConfigIntegrity(): ConfigIntegrityReport {
  const { path, verdict } = readConfigBytesNoSideEffects();
  return { path, verdict };
}

function sha256Hex(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function isPlainBlock(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

/**
 * The Action Guard keys as the enforcement surfaces resolve them: top-level
 * `actionGuard` over the deprecated `interceptor.actionGuard` gap-fill alias
 * (#209). Values are normalised to strings only so two views can be compared;
 * they never leave this module.
 */
function resolvedGuardKeys(raw: Record<string, unknown>): Record<string, string> {
  const interceptor: Record<string, unknown> = isPlainBlock(raw.interceptor) ? raw.interceptor : {};
  const alias: Record<string, unknown> = isPlainBlock(interceptor.actionGuard) ? interceptor.actionGuard : {};
  const merged: Record<string, unknown> = { ...alias, ...actionGuardBlock(raw) };
  return {
    'actionGuard.enabled': String(merged.enabled === true),
    'actionGuard.enforce': String(merged.enforce !== false),
    'actionGuard.readinessGate': String(merged.readinessGate === true),
    'actionGuard.autoApprove': JSON.stringify(Array.isArray(merged.autoApprove) ? merged.autoApprove : []),
    'actionGuard.broker.enabled': String(isPlainBlock(merged.broker) && merged.broker.enabled === true),
    'actionGuard.reviewedScripts': JSON.stringify(Array.isArray(merged.reviewedScripts) ? merged.reviewedScripts : []),
  };
}

function resolvedDefenceMode(raw: Record<string, unknown>): DefenceMode {
  const mode = raw.defenceMode;
  return typeof mode === 'string' && VALID_MODES.includes(mode as DefenceMode) ? mode as DefenceMode : 'balanced';
}

/**
 * Which effective settings would change if the file's own values replaced the
 * strict fail-closed posture currently forced on top of them — every one of
 * them a loosening, because that posture is the tightest there is — and which
 * of those no authority stronger than the HMAC has granted.
 *
 * The second list is the line #647 does not cross. The Action Guard keys are
 * the ones the guard's own self-protection floor holds (`--action-guard-
 * disable`/`-advisory`/`-enforce-when-ready`) or that `allowlist add` requires
 * an interactive terminal for. A re-sign that made a hand-edited `enabled:
 * false`, auto-approve entry or reviewed-script pin effective would be a new
 * way around those controls, so it is only allowed where a VERIFIED,
 * root-owned policy lock covers the key — that lock, not this command, is then
 * the authority (#501 §8.4: edit, `sudo shieldcortex protect --from-config`,
 * re-sign). `defenceMode` is not in the second list: `shieldcortex config
 * --mode` already sets it with no such hold, so re-signing it grants nothing
 * new, and the policy-lock refusal still applies.
 */
function resignEffects(
  data: Record<string, unknown>,
  lock: PolicyLockState,
): { loosenedKeys: string[]; unauthorisedKeys: string[] } {
  const now = applyPolicyLock(applyStrictFailClosedPosture(data), lock);
  const after = applyPolicyLock(data, lock);
  const nowGuard = resolvedGuardKeys(now);
  const afterGuard = resolvedGuardKeys(after);
  const coverage = lock.status === 'locked' ? policyLockCoverage(lock) : new Map<ProtectedPolicyKey, unknown>();
  const loosenedKeys: string[] = [];
  const unauthorisedKeys: string[] = [];
  for (const key of Object.keys(nowGuard)) {
    if (nowGuard[key] === afterGuard[key]) continue;
    loosenedKeys.push(key);
    if (!coverage.has(key as ProtectedPolicyKey)) unauthorisedKeys.push(key);
  }
  if (resolvedDefenceMode(now) !== resolvedDefenceMode(after)) loosenedKeys.push('defenceMode');
  return { loosenedKeys, unauthorisedKeys };
}

/** The protected keys the file itself declares, for the policy-lock check. */
function declaredProtectedValues(data: Record<string, unknown>): Array<{ key: ProtectedPolicyKey; value: unknown }> {
  const guard = actionGuardBlock(data);
  const memory: Record<string, unknown> = isPlainBlock(data.memory) ? data.memory : {};
  const hostContract: Record<string, unknown> = isPlainBlock(memory.hostContract) ? memory.hostContract : {};
  const inject: Record<string, unknown> = isPlainBlock(memory.inject) ? memory.inject : {};
  const broker: Record<string, unknown> = isPlainBlock(guard.broker) ? guard.broker : {};
  const candidates: Array<{ key: ProtectedPolicyKey; value: unknown }> = [
    { key: 'actionGuard.enabled', value: guard.enabled },
    { key: 'actionGuard.enforce', value: guard.enforce },
    { key: 'actionGuard.autoApprove', value: guard.autoApprove },
    { key: 'actionGuard.broker.enabled', value: broker.enabled },
    { key: 'actionGuard.reviewedScripts', value: guard.reviewedScripts },
    { key: 'defenceMode', value: data.defenceMode },
    { key: 'memory.hostContract.posture', value: hostContract.posture },
    { key: 'memory.inject.mode', value: inject.mode },
  ];
  return candidates.filter((c) => c.value !== undefined);
}

export interface ConfigResignPreview {
  path: string;
  verdict: ConfigIntegrity | 'unsigned';
  /** sha256 of the exact bytes on disk (full hex), or null when there are none. */
  sha256: string | null;
  /** Effective settings that would leave the strict posture. Key names only. */
  loosenedKeys: string[];
  /** The subset no verified policy lock authorises; re-sign is refused while non-empty. */
  unauthorisedKeys: string[];
  lockStatus: PolicyLockState['status'];
  /** The policy lock's refusal of a value the file declares, if any (the re-sign would be refused). */
  lockRefusal: string | null;
}

/**
 * Read-only preview for `shieldcortex config --resign`. Writes nothing, mints
 * nothing, audits nothing. It names keys, never values: config.json can carry
 * `cloudApiKey` and webhook secrets, and a preview is often pasted.
 */
export function previewConfigResign(): ConfigResignPreview {
  const read = readConfigBytesNoSideEffects();
  const lock = readPolicyLock({ audit: false, warn: false });
  const tampered = read.verdict === 'tampered' && read.data !== null;
  const effects = tampered
    ? resignEffects(read.data!, lock)
    : { loosenedKeys: [], unauthorisedKeys: [] };
  // The same check the re-sign makes, asked without auditing: a preview must
  // not say "confirm with this hash" for a write the lock is going to refuse.
  let lockRefusal: string | null = null;
  if (tampered) {
    try {
      assertPolicyLockAllows(lock, declaredProtectedValues(read.data!));
    } catch (err) {
      if (!(err instanceof PolicyLockRefusal)) throw err;
      lockRefusal = err.message;
    }
  }
  return {
    path: read.path,
    verdict: read.verdict,
    sha256: read.bytes ? sha256Hex(read.bytes) : null,
    ...effects,
    lockStatus: lock.status,
    lockRefusal,
  };
}

/**
 * Whether the `config_resigned` row was written. `recorded: false` means the
 * re-sign IS in force but its record is not: the caller must say so, not
 * "recorded".
 */
export type ConfigResignAudit =
  | { recorded: true; rowId: number; location: string }
  | { recorded: false; location: string; error: string };

export interface ConfigResignResult {
  path: string;
  previousVerdict: 'tampered';
  previousSha256: string;
  newSha256: string;
  backupPath: string;
  loosenedKeys: string[];
  audit: ConfigResignAudit;
}

/**
 * The ONE deliberate path that signs a `tampered` config.json (#647).
 *
 * It trusts the file's own bytes — never the strict view forced on top of them
 * — and only the exact bytes the operator previewed: `confirmSha256` must be
 * the FULL sha256 {@link previewConfigResign} printed, and it is checked
 * against bytes read again here, so a file that changed after the preview is
 * refused, not signed. What it will not do:
 *   - sign a file that is not `tampered` (nothing to recover, or not parseable);
 *   - loosen a key the policy lock forbids — the same refusal, audited as
 *     `policy_refused`, that the setters apply;
 *   - make a hand-edited Action Guard loosening effective without a verified
 *     lock covering it (see {@link resignEffects});
 *   - sign anything when the audit log cannot be opened.
 *
 * Order: the checks; then the audit log is opened (refusing, with nothing
 * written, if it cannot be); then the checks again on a fresh read, with no
 * await between them and the write; then the exact previewed bytes are saved
 * to `config.json.bak-resign-<timestamp>` (0600, never overwriting an existing
 * file — and an aborted re-sign if that fails); then the signed write; then
 * the `config_resigned` row naming the previous verdict, both hashes, the
 * backup and the loosened key NAMES — no values. That row can only be written
 * after the file it describes, so if it fails the re-sign has already landed:
 * the result says `audit.recorded: false` and the backup stays as the
 * evidence. Nothing here claims a record it did not make.
 *
 * What this is not: an identity check. A same-uid process can run it, exactly
 * as it can read `.integrity-key` and sign the file itself; the HMAC is a
 * corruption detector (protected-root.ts). This command exists so recovering
 * from that alarm is a reviewed, recorded act instead of a side effect of the
 * next unrelated setting change.
 */
export async function resignTamperedConfig(
  confirmSha256: string,
  opts: { now?: Date } = {},
): Promise<ConfigResignResult> {
  const confirm = confirmSha256.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(confirm)) {
    throw new Error(
      '--confirm needs the full 64-character sha256 that `shieldcortex config --resign` printed for the file you ' +
      'reviewed — a prefix is not accepted. Nothing was written.',
    );
  }
  // Refusals first, so a re-sign that is going to be refused never opens the
  // audit database.
  admitResign(confirm);

  let sink: RecoveryAuditSink;
  try {
    sink = await openRecoveryAuditSink();
  } catch (err) {
    throw new Error(
      `Not re-signing ${getConfigFile()}: the audit log that must record a re-sign could not be opened ` +
      `(${err instanceof Error ? err.message : String(err)}). A re-sign is only done when it can be recorded. ` +
      'Nothing was written.',
    );
  }

  try {
    // Again, on bytes read now: the file may have changed while the audit log
    // was opening. From here to the write there is no await.
    const { read, data, loosenedKeys, previousSha256 } = admitResign(confirm);

    const stamp = (opts.now ?? new Date()).toISOString().replace(/[:.]/g, '-');
    const backupPath = `${read.path}.bak-resign-${stamp}`;
    // The previewed bytes themselves, not a fresh copy of the path: what is
    // backed up is exactly what was reviewed. `wx` never overwrites.
    writeFileSync(backupPath, read.bytes, { mode: 0o600, flag: 'wx' });
    try { chmodSync(backupPath, 0o600); } catch { /* best-effort */ }

    // Direct writeRawConfig, the sanctioned exception to the mutateRawConfig
    // rule (like self-heal): the data is the confirmed bytes, parsed — not a
    // read-modify-write of whatever the file holds by now.
    writeRawConfig(data);
    const newSha256 = sha256Hex(readFileSync(read.path));

    let audit: ConfigResignAudit;
    try {
      const rowId = sink.record({
        outcome: 'config_resigned',
        path: read.path,
        reason: 'tampered',
        detail:
          `config.json re-signed by explicit \`config --resign\`; previous verdict tampered; ` +
          `previous sha256 ${previousSha256}; new sha256 ${newSha256}; backup ${backupPath}; ` +
          `keys leaving the fail-closed posture: ${loosenedKeys.length > 0 ? loosenedKeys.join(', ') : 'none'}`,
      });
      audit = { recorded: true, rowId, location: sink.location };
    } catch (err) {
      audit = { recorded: false, location: sink.location, error: err instanceof Error ? err.message : String(err) };
    }

    return { path: read.path, previousVerdict: 'tampered', previousSha256, newSha256, backupPath, loosenedKeys, audit };
  } finally {
    sink.close();
  }
}

/**
 * Every refusal {@link resignTamperedConfig} makes, on a fresh read. Throws, or
 * returns what the write needs.
 */
function admitResign(confirm: string): {
  read: ConfigBytes & { bytes: Buffer };
  data: Record<string, unknown>;
  loosenedKeys: string[];
  previousSha256: string;
} {
  const read = readConfigBytesNoSideEffects();
  if (!read.bytes || read.verdict !== 'tampered' || !read.data) {
    throw new Error(
      `Not re-signing ${read.path}: its integrity verdict is ${read.verdict}, not tampered. ` +
      (read.verdict === 'malformed' || read.verdict === 'unreadable'
        ? 'A file that cannot be parsed cannot be reviewed or signed — fix it or restore a backup.'
        : 'There is nothing to recover.') +
      ' Nothing was written.',
    );
  }
  const previousSha256 = sha256Hex(read.bytes);
  if (previousSha256 !== confirm) {
    throw new Error(
      `Not re-signing ${read.path}: its sha256 is now ${previousSha256}, not the ${confirm} you confirmed. ` +
      'The file changed after the preview (or the hash was mistyped). Re-run `shieldcortex config --resign` and ' +
      'review it again. Nothing was written.',
    );
  }
  const data = { ...read.data };
  delete data._sig;

  // The lock first, exactly as the setters order it: a locked key is the
  // lock's refusal to make, audited, before anything else is said.
  refuseIfPolicyLockForbids(declaredProtectedValues(data));
  const { loosenedKeys, unauthorisedKeys } = resignEffects(data, getPolicyLockState());
  if (unauthorisedKeys.length > 0) {
    throw new Error(
      `Not re-signing ${read.path}: it would take ${unauthorisedKeys.join(', ')} out of the strict fail-closed ` +
      'posture, and no verified policy lock covers those keys. Changing them is held by the Action Guard ' +
      'self-protection floor or needs an interactive `shieldcortex allowlist add`; a re-sign must not become a ' +
      'way around either. Restore a backup whose signature still verifies, or move config.json aside and ' +
      're-apply these settings with their own commands. Nothing was written.',
    );
  }
  return { read: { ...read, bytes: read.bytes }, data, loosenedKeys, previousSha256 };
}

/**
 * Refuse a signed write that would LOOSEN a key the policy lock covers (#501).
 *
 * The refusal is the whole point of the lock on the write side: without it, a
 * locked host would let `--action-guard-disable` write `enabled: false` into
 * config.json, the lock would silently put it back on every read, and the
 * operator's `config --status` would disagree with the file they just wrote.
 * Saying no — naming the file that is saying it — is the honest behaviour.
 *
 * Throws {@link PolicyLockRefusal}; callers surface `err.message`, which already
 * names the lock path and how to change it. The refusal is audited as
 * `policy_refused` before it is thrown, so a repeated attempt to disable the
 * guard on a locked box leaves a trail even if nobody reads the terminal.
 */
function refuseIfPolicyLockForbids(updates: Array<{ key: ProtectedPolicyKey; value: unknown }>): void {
  if (updates.length === 0) return;
  try {
    assertPolicyLockAllows(getPolicyLockState(), updates);
  } catch (err) {
    if (err instanceof PolicyLockRefusal) {
      emitProtectedAudit({
        outcome: 'policy_refused',
        path: err.lockPath,
        reason: err.key,
        detail: `refused a write of ${JSON.stringify(err.key)} that would loosen the locked value ${JSON.stringify(err.lockedValue)}`,
      });
    }
    throw err;
  }
}

/**
 * Whether this exact raw config is the signed honest-sidecar posture.
 *
 * This is the single trust decision used by both memory-plane doctor rows. It
 * deliberately requires a valid EMBEDDED `_sig`: readRawConfig() may adopt a
 * previously unsigned legacy config by minting `.config-sig`, which is correct
 * compatibility trust for ordinary config reads but is not proof that the
 * signed posture setter created this operator-intent declaration. External
 * legacy signatures therefore never certify the sidecar exemption.
 *
 * #501: on a host that HAS a policy lock, the `_sig` path is not consulted at
 * all — the lock has to declare the posture itself. The HMAC is a corruption
 * detector whose key sits beside the file it signs, so on a locked box it would
 * be the weakest link certifying the strongest claim; and this is the one place
 * a signature has ever gated a security decision, which is precisely the
 * decision the lock exists to take over. A locked host whose lock says nothing
 * about the memory keys therefore answers `false`: silence from the authority
 * is not permission. `protect` writes the whole protected set, so that state
 * only arises from a hand-written partial lock. Unlocked hosts are unchanged.
 */
export function hasTrustedMemorySidecarPosture(
  raw: Record<string, unknown>,
  configPath: string = getConfigFile(),
): boolean {
  try {
    const effectivePath = getConfigFile();
    if (resolve(configPath) !== resolve(effectivePath)) return false;

    const lock = getPolicyLockState();
    if (lock.status === 'locked' || lock.status === 'unverifiable') {
      const coverage = policyLockCoverage(lock);
      return (
        coverage.get('memory.hostContract.posture') === 'mcp_sidecar_no_inject' &&
        coverage.get('memory.inject.mode') === 'off'
      );
    }

    const content = readFileSync(effectivePath, 'utf-8');
    const parsed = JSON.parse(content) as Record<string, unknown>;
    // The caller must be grading the same bytes whose signature is checked.
    if (JSON.stringify(parsed) !== JSON.stringify(raw)) return false;

    // Only a currently valid embedded signature can carry operator intent.
    // `self-heal` means the embedded signature is invalid even if a legacy
    // external signature authenticates the general config bytes, so it is not
    // sufficient here either.
    if (typeof parsed._sig !== 'string' || checkConfigIntegrity(parsed, content) !== 'valid') return false;

    const memory = parsed.memory && typeof parsed.memory === 'object' && !Array.isArray(parsed.memory)
      ? parsed.memory as Record<string, unknown>
      : null;
    if (!memory) return false;
    const hostContract = memory.hostContract && typeof memory.hostContract === 'object'
      && !Array.isArray(memory.hostContract)
      ? memory.hostContract as Record<string, unknown>
      : null;
    const inject = memory.inject && typeof memory.inject === 'object' && !Array.isArray(memory.inject)
      ? memory.inject as Record<string, unknown>
      : null;
    return hostContract?.posture === 'mcp_sidecar_no_inject' && inject?.mode === 'off';
  } catch {
    return false;
  }
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
 * Auto-release gate (docs/design/2026-08-11-threat-graph.md, Loop 3).
 * `threatGraph.autoRelease`: default OFF. When on, a would-be-quarantined item
 * whose every detection is an active allowance for its source and whose
 * content near-duplicates an approved exemplar is admitted instead of held.
 */
export function isAutoReleaseEnabled(raw?: Record<string, unknown>): boolean {
  const source = raw ?? readRawConfig();
  const block = source.threatGraph;
  if (!block || typeof block !== 'object' || Array.isArray(block)) return false;
  return (block as Record<string, unknown>).autoRelease === true;
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
  cachedRawConfigIntegrity = null;
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
  mkdirSecure(configDir);

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
 * reads through `readRawConfigStateUnlocked()` (which preserves `parseFailed`
 * and the integrity verdict) and refuses to write when the on-disk config is
 * unreadable.
 *
 * It also refuses to write a `tampered` config (#647). Every write signs what it
 * writes, so a write on a tampered file can only do one of two wrong things:
 * sign the untrusted bytes as valid (laundering the verdict), or — as it did
 * before #647, when the read it started from was the forced view — persist the
 * strict posture as if the operator had chosen it, wiping `reviewedScripts` and
 * `autoApprove`. It now does neither: the refusal happens before the caller's
 * change runs and before anything touches disk, so the file's bytes, mode,
 * mtime, pins and stale signature all survive. The only path past this gate is
 * the deliberate, previewed, hash-confirmed {@link resignTamperedConfig}.
 *
 * `onParseFail` (the name predates #647; it governs both refusals):
 *   - `'throw'` (default): surface corruption/tampering to user-facing/explicit
 *     setters so the caller sees the problem rather than silently losing
 *     credentials. A tampered config throws {@link ConfigIntegrityRefusal}.
 *   - `'skip'`: silently no-op for automatic / hot-path writes that must NEVER
 *     throw (background sync, read-with-migration). Returns false so the caller
 *     can tell the write was skipped. On a tampered config one stderr line per
 *     process says so, so a background writer that keeps retrying stays quiet.
 *
 * Returns true if the mutation was applied and persisted, false if it was
 * skipped (`onParseFail: 'skip'`).
 */
function mutateRawConfig(
  fn: (raw: Record<string, unknown>) => void,
  onParseFail: 'throw' | 'skip' = 'throw',
): boolean {
  // Deliberately the UNLOCKED read: a write must persist what the operator
  // configured, not the values the policy lock is currently forcing on top of
  // it. Writing the locked view back would freeze an OS-owned floor into the
  // local file, where it would outlive the lock that produced it.
  const { data, parseFailed, integrity } = readRawConfigStateUnlocked();
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
  if (integrity === 'tampered') {
    warnTamperedWriteRefusedOnce();
    if (onParseFail === 'throw') throw new ConfigIntegrityRefusal(getConfigFile());
    return false;
  }
  fn(data);
  writeRawConfig(data);
  return true;
}

let tamperedWriteRefusalWarned = false;

/** One line per process, however often a background writer retries (#647). */
function warnTamperedWriteRefusedOnce(): void {
  if (tamperedWriteRefusalWarned) return;
  tamperedWriteRefusalWarned = true;
  console.error(
    '[ShieldCortex] config.json fails its integrity check — refusing config writes so the file and its ' +
    'pins are not re-signed or overwritten. Run `shieldcortex doctor`; recover with `shieldcortex config --resign`.',
  );
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

// ── Action Guard notify channel (#275) ────────────────

export interface ActionGuardNotifyConfig {
  /** Master switch for the operator-notify transport (#143). Strict-true
   *  semantics on read, mirroring notify-config.ts. */
  enabled: boolean;
  /** Deliver via the native OpenClaw approval card. */
  openclaw: boolean;
  /** Webhook channel target. Absent = no webhook channel configured. */
  webhookUrl?: string;
}

const NOTIFY_WEBHOOK_URL_MAX_LENGTH = 2_048;

/**
 * Validate a webhook URL for the SIGNED setter path. Stricter than the
 * runtime reader (notify-config.ts accepts http: for configs that predate
 * this CLI): a URL being SET today must be https — a denial notification
 * carries operational detail about what a cron just tried to run, and an
 * http target hands that to the network in the clear. Throws with an
 * operator-actionable message; never suggests hand-editing config.json.
 */
export function validateActionGuardNotifyWebhookUrl(url: string): string {
  const trimmed = url.trim();
  if (!trimmed) {
    throw new Error('Invalid webhook URL: empty. Provide an https:// URL, e.g. https://hooks.example.com/shieldcortex.');
  }
  if (trimmed.length > NOTIFY_WEBHOOK_URL_MAX_LENGTH) {
    throw new Error(`Invalid webhook URL: longer than ${NOTIFY_WEBHOOK_URL_MAX_LENGTH} characters.`);
  }
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error(`Invalid webhook URL: "${trimmed}" is not a URL. Provide an https:// URL, e.g. https://hooks.example.com/shieldcortex.`);
  }
  if (parsed.protocol !== 'https:') {
    throw new Error(`Invalid webhook URL: scheme must be https (got ${parsed.protocol.replace(/:$/, '')}). Denial notifications must not travel in cleartext.`);
  }
  return trimmed;
}

/** Strict-true read of `actionGuard.notify`, same discipline as
 *  normaliseNotifyConfig in notify-config.ts (which stays the runtime's
 *  boundary — this reader only serves the CLI/status surface). */
export function getActionGuardNotifyConfig(): ActionGuardNotifyConfig {
  const guard = actionGuardBlock(readRawConfig());
  const notify = guard.notify && typeof guard.notify === 'object' && !Array.isArray(guard.notify)
    ? (guard.notify as Record<string, unknown>)
    : {};
  const cfg: ActionGuardNotifyConfig = {
    enabled: notify.enabled === true,
    openclaw: notify.openclaw === true,
  };
  if (typeof notify.webhookUrl === 'string' && notify.webhookUrl.trim()) {
    cfg.webhookUrl = notify.webhookUrl.trim();
  }
  return cfg;
}

/**
 * The SIGNED write path for `actionGuard.notify` (#275) — what the
 * `shieldcortex config --action-guard-notify-*` flags call. Routed through
 * mutateRawConfig so the `_sig` HMAC is recomputed and the tamper flag
 * clears; the hand-edit this replaces invalidated the signature and forced
 * defenceMode strict. Read-modify-write on the notify block: sub-keys not in
 * `updates` (webhookSecret, timeoutMs, a parked webhookUrl during a disable)
 * survive untouched.
 */
export function setActionGuardNotifyConfig(updates: Partial<ActionGuardNotifyConfig>): void {
  const webhookUrl = updates.webhookUrl !== undefined
    ? validateActionGuardNotifyWebhookUrl(updates.webhookUrl)
    : undefined;
  mutateRawConfig((raw) => {
    const guard = actionGuardBlock(raw);
    const notify = guard.notify && typeof guard.notify === 'object' && !Array.isArray(guard.notify)
      ? (guard.notify as Record<string, unknown>)
      : {};
    if (updates.enabled !== undefined) notify.enabled = updates.enabled;
    if (updates.openclaw !== undefined) notify.openclaw = updates.openclaw;
    if (webhookUrl !== undefined) notify.webhookUrl = webhookUrl;
    guard.notify = notify;
    raw.actionGuard = guard;
  });
}

// ── Action Guard core switches (enable/enforce) ───────

export interface ActionGuardCoreConfig {
  /** Master switch. Default OFF when the key is absent (`enabled === true` only). */
  enabled: boolean;
  /** When true, gate dangerous ops. When false, warn-mode — dangerous ops log
   *  but are not gated (catastrophic may still block). Default ON when absent. */
  enforce: boolean;
  /** #509 enforce-when-ready: with `enforce`, run in shadow mode until this
   *  install meets the readiness conditions. `=== true` only. The Claude
   *  Code hook and the OpenClaw plugin each implement it (per adapter); the
   *  Hermes plugin does not, and ignores it and enforces — the tighter
   *  reading. */
  readinessGate: boolean;
}

/** The four operator-facing postures (#509). */
export type ActionGuardPosture = 'off' | 'watch-only' | 'enforce' | 'enforce-when-ready';

export function actionGuardPosture(core: ActionGuardCoreConfig): ActionGuardPosture {
  if (!core.enabled) return 'off';
  if (!core.enforce) return 'watch-only';
  return core.readinessGate ? 'enforce-when-ready' : 'enforce';
}

/**
 * EFFECTIVE core config, resolved the same way both runtime surfaces and
 * doctor's posture check resolve it (#209): top-level `actionGuard` merged
 * over the deprecated `interceptor.actionGuard` alias (top-level wins per
 * key). Guard is OFF unless `enabled` is explicitly true — default-on
 * minted false cards on ordinary OpenClaw exec bags.
 */
export function getActionGuardCoreConfig(): ActionGuardCoreConfig {
  const raw = readRawConfig();
  const interceptor = raw.interceptor && typeof raw.interceptor === 'object' && !Array.isArray(raw.interceptor)
    ? (raw.interceptor as Record<string, unknown>)
    : {};
  const alias = interceptor.actionGuard && typeof interceptor.actionGuard === 'object' && !Array.isArray(interceptor.actionGuard)
    ? (interceptor.actionGuard as Record<string, unknown>)
    : {};
  const merged = { ...alias, ...actionGuardBlock(raw) };
  return {
    enabled: merged.enabled === true,
    enforce: merged.enforce !== false,
    readinessGate: merged.readinessGate === true,
  };
}

/**
 * The SIGNED write path for `actionGuard.enabled` / `actionGuard.enforce` —
 * what the `shieldcortex config --action-guard-enable|disable|enforce|advisory`
 * flags call. Same discipline as setActionGuardNotifyConfig: routed through
 * mutateRawConfig so the `_sig` HMAC is recomputed, and read-modify-write on
 * the actionGuard block so sibling keys (notify, reviewedScripts, broker,
 * autoApprove) survive untouched. The deprecated `interceptor.actionGuard`
 * alias is deliberately left alone — top-level wins on both surfaces (#209),
 * and migration is `doctor --fix-action-guard`'s job.
 */
export function setActionGuardCoreConfig(updates: Partial<ActionGuardCoreConfig>): OpenClawPluginGuardSync {
  refuseIfPolicyLockForbids([
    ...(updates.enabled !== undefined ? [{ key: 'actionGuard.enabled' as const, value: updates.enabled }] : []),
    ...(updates.enforce !== undefined ? [{ key: 'actionGuard.enforce' as const, value: updates.enforce }] : []),
    // #509: enforce-when-ready runs ADVISORY until proven, so a lock that pins
    // `enforce: true` must refuse it exactly as it refuses `enforce: false`.
    ...(updates.readinessGate === true ? [{ key: 'actionGuard.enforce' as const, value: false }] : []),
  ]);
  mutateRawConfig((raw) => {
    const guard = actionGuardBlock(raw);
    if (updates.enabled !== undefined) guard.enabled = updates.enabled;
    if (updates.enforce !== undefined) guard.enforce = updates.enforce;
    if (updates.readinessGate === true) guard.readinessGate = true;
    else if (updates.readinessGate === false) delete guard.readinessGate;
    raw.actionGuard = guard;
  });
  if (updates.enabled === undefined && updates.enforce === undefined) {
    return { status: 'skipped', reason: 'noop' };
  }
  try {
    return syncOpenClawPluginActionGuard({
      ...(updates.enabled !== undefined ? { enabled: updates.enabled } : {}),
      ...(updates.enforce !== undefined ? { enforce: updates.enforce } : {}),
    });
  } catch {
    return { status: 'skipped', reason: 'unreadable' };
  }
}

/**
 * `doctor --fix-action-guard`'s write path (#209 migration, #275 fix): merge
 * the deprecated `interceptor.actionGuard` alias into the top-level block —
 * top-level wins per key, the alias gap-fills, matching what both runtime
 * surfaces already resolve — remove the alias, and drop an emptied
 * `interceptor` block. Routed through mutateRawConfig so the migrated file is
 * RE-SIGNED: doctor's previous bare fs.writeFileSync carried the stale `_sig`
 * through, and the "fix" itself tripped the integrity check into strict mode.
 * Returns true when an alias was found and migrated.
 */
export function migrateInterceptorActionGuardAlias(): boolean {
  let changed = false;
  mutateRawConfig((raw) => {
    const interceptor = raw.interceptor && typeof raw.interceptor === 'object' && !Array.isArray(raw.interceptor)
      ? (raw.interceptor as Record<string, unknown>)
      : null;
    const alias = interceptor && interceptor.actionGuard && typeof interceptor.actionGuard === 'object' && !Array.isArray(interceptor.actionGuard)
      ? (interceptor.actionGuard as Record<string, unknown>)
      : null;
    if (!interceptor || !alias) return;
    raw.actionGuard = { ...alias, ...actionGuardBlock(raw) };
    delete interceptor.actionGuard;
    if (Object.keys(interceptor).length === 0) delete raw.interceptor;
    changed = true;
  });
  return changed;
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

/**
 * Read the cloud cache for diagnostics without signature adoption, self-heal,
 * cache mutation, policy-lock audit, or any filesystem write. An unreadable or
 * unverifiable existing config is reported to the caller as unavailable.
 */
export function peekCloudIronDomeCache(): Record<string, unknown> | null {
  const configFile = getConfigFile();
  if (!existsSync(configFile)) return null;

  const content = readFileSync(configFile, 'utf-8');
  if (!content.trim()) return null;
  const parsed: unknown = JSON.parse(content);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Config unreadable');
  const raw = parsed as Record<string, unknown>;

  // Verify signatures using only an existing key. An unsigned legacy file is
  // readable, but this peek must not adopt it by creating .config-sig.
  const sigFile = getSigFile();
  if (typeof raw._sig === 'string' || existsSync(sigFile)) {
    const key = readFileSync(getIntegrityKeyFile(), 'utf-8').trim();
    if (!key) throw new Error('Config integrity key unreadable');
    const signed = (body: string) => createHmac('sha256', key).update(body, 'utf-8').digest('hex');
    const embeddedValid = typeof raw._sig === 'string' &&
      constantTimeEqualHex(raw._sig, signed(canonicalBodyForSig(raw)));
    const legacyValid = existsSync(sigFile) &&
      constantTimeEqualHex(readFileSync(sigFile, 'utf-8').trim(), signed(content));
    if (!embeddedValid && !legacyValid) throw new Error('Config integrity check failed');
  }

  return raw.cloudIronDome && typeof raw.cloudIronDome === 'object' && !Array.isArray(raw.cloudIronDome)
    ? raw.cloudIronDome as Record<string, unknown>
    : null;
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
  // #501: `defenceMode` is a FLOOR in the protected key set. A write that goes
  // below it is refused rather than accepted-and-silently-overridden.
  refuseIfPolicyLockForbids([{ key: 'defenceMode', value: mode }]);
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
  // autoMemory is not read: getOpenClawMemoryConfig() uses `openclawAutoMemory === true`,
  // so an unset key is off. Only noveltyThreshold and maxRecent fall back to this object.
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
 * Off when the key is not set. A fresh global, non-CI npm install with no
 * config.json gets one from scripts/postinstall.mjs with the key `true`; an
 * existing config is never changed. Toggle with --openclaw-auto-memory.
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
 * Off when the key is not set (since v4.11.0). A fresh global, non-CI npm
 * install with no config.json gets one from scripts/postinstall.mjs with the
 * key `true`; an existing config is never changed. Toggle with --proactive-recall.
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
 * False for both when nothing is set — the OpenClaw-safe default that
 * shipped in v4.13.0. When `openclawAutoMemory` or `proactiveRecall` is `true`
 * (a fresh global, non-CI install writes both), both resolve true unless set
 * explicitly to false. The install flags (`--with-stop-hook` /
 * `--with-session-end`) flip these to true so that wiring the hook in
 * settings.json and enabling the runtime gate are a single user action.
 */
export function getAutoMemoryEnableConfig(): AutoMemoryEnableConfig {
  const raw = readRawConfig();
  const am = raw.autoMemory && typeof raw.autoMemory === 'object'
    ? raw.autoMemory as Record<string, unknown>
    : {};
  // Memory SOTA: plane flags imply capture gates unless explicitly false.
  const planeOn = raw.openclawAutoMemory === true || raw.proactiveRecall === true;
  return {
    enableStop: am.enableStop === true || (planeOn && am.enableStop !== false),
    enableSessionEnd: am.enableSessionEnd === true || (planeOn && am.enableSessionEnd !== false),
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

// ── Memory inject contract / auto-memory sampling (signed doctor-fix paths) ──

/** The only legal host native-inject contracts (Memory SOTA Track B). Mirrors
 *  NATIVE_INJECT_CONTRACT in scripts/lib/inject-pack.mjs, which stays the
 *  runtime's boundary — normalizeNativeContract there returns null for
 *  anything else (the retired `coexist_dedup` included). */
export const NATIVE_INJECT_CONTRACTS = ['sc_only', 'disable_native_inject'] as const;
export type NativeInjectContract = (typeof NATIVE_INJECT_CONTRACTS)[number];

/**
 * The SIGNED write path for `memory.inject.nativeContract` — what the
 * `shieldcortex config --memory-inject-contract` flag calls. Same discipline
 * as setActionGuardNotifyConfig (#275): routed through mutateRawConfig so the
 * `_sig` HMAC is recomputed — the hand-edit doctor's empty-brain fix used to
 * prescribe invalidated the signature and forced defenceMode strict.
 * Read-modify-write on the inject block: sibling keys (mode, hostId, agentId,
 * budgets) survive untouched. Deliberately does NOT write the legacy aliases
 * `memoryNativeInjectContract` / `memory.nativeInjectContract` — every read
 * surface resolves `memory.inject.nativeContract` first, and minting fresh
 * copies of a deprecated spelling would just create drift.
 */
export function setMemoryInjectContract(value: string): void {
  if (!(NATIVE_INJECT_CONTRACTS as readonly string[]).includes(value)) {
    throw new Error(
      `Invalid native-inject contract "${value}". Legal values: ${NATIVE_INJECT_CONTRACTS.join(', ')}.`,
    );
  }
  mutateRawConfig((raw) => {
    const memory = raw.memory && typeof raw.memory === 'object' && !Array.isArray(raw.memory)
      ? raw.memory as Record<string, unknown>
      : {};
    const inject = memory.inject && typeof memory.inject === 'object' && !Array.isArray(memory.inject)
      ? memory.inject as Record<string, unknown>
      : {};
    inject.nativeContract = value;
    memory.inject = inject;
    raw.memory = memory;
  });
}

/** Host postures a box can declare (#393 T1 / residual lock 9). */
export const MEMORY_HOST_POSTURES = ['mcp_sidecar_no_inject', 'bus_contract'] as const;
export type MemoryHostPosture = (typeof MEMORY_HOST_POSTURES)[number];

/** Host runtimes whose native-memory state doctor knows how to prove (#393). */
export const MEMORY_HOST_RUNTIMES = ['openclaw', 'claude_code', 'hermes'] as const;
export type MemoryHostRuntime = (typeof MEMORY_HOST_RUNTIMES)[number];

/**
 * SIGNED write path for the T1 host posture — `shieldcortex config
 * --memory-host-posture`. Same #275 discipline as setMemoryInjectContract.
 *
 * The two postures are mutually exclusive by construction, so this writes both
 * halves in one signed mutation rather than trusting an operator to keep them
 * consistent (residual lock 9: honest sidecar OR bus contract, never both):
 *
 *  - `mcp_sidecar_no_inject` records the sidecar posture AND forces
 *    `memory.inject.mode = 'off'`. Native host memory keeps the automatic bus;
 *    SC claims nothing. `nativeContract` is left alone so flipping back does not
 *    lose it.
 *  - `bus_contract` clears the posture, leaving the inject contract to govern.
 *    It does NOT turn inject on — that stays an explicit operator act.
 */
export function setMemoryHostPosture(value: string): void {
  if (!(MEMORY_HOST_POSTURES as readonly string[]).includes(value)) {
    throw new Error(
      `Invalid memory host posture "${value}". Legal values: ${MEMORY_HOST_POSTURES.join(', ')}.`,
    );
  }
  // #501: the sidecar-posture PAIR is in the protected key set, and this setter
  // writes both halves (`bus_contract` clears the posture, `mcp_sidecar_no_inject`
  // also forces `inject.mode = 'off'`). Check both against the lock: changing
  // either half away from a locked value is a change the lock forbids.
  refuseIfPolicyLockForbids([
    { key: 'memory.hostContract.posture', value: value === 'bus_contract' ? undefined : value },
    ...(value === 'mcp_sidecar_no_inject' ? [{ key: 'memory.inject.mode' as const, value: 'off' }] : []),
  ]);
  mutateRawConfig((raw) => {
    const memory = raw.memory && typeof raw.memory === 'object' && !Array.isArray(raw.memory)
      ? raw.memory as Record<string, unknown>
      : {};
    const hostContract = memory.hostContract && typeof memory.hostContract === 'object'
      && !Array.isArray(memory.hostContract)
      ? memory.hostContract as Record<string, unknown>
      : {};
    if (value === 'bus_contract') {
      delete hostContract.posture;
      // A stale postureSetAt with no posture reads as "sidecar was set at T"
      // to any forensic pass — the stamp travels with the posture (#393 SOL nit).
      delete hostContract.postureSetAt;
    } else {
      hostContract.posture = value;
      hostContract.postureSetAt = new Date().toISOString();
      const inject = memory.inject && typeof memory.inject === 'object' && !Array.isArray(memory.inject)
        ? memory.inject as Record<string, unknown>
        : {};
      inject.mode = 'off';
      memory.inject = inject;
    }
    memory.hostContract = hostContract;
    raw.memory = memory;
  });
}

/**
 * SIGNED write path for `memory.hostContract.runtimes` — the operator declaring
 * which host runtimes this box is bound to. Declaration only ADDS a runtime to
 * the set doctor must prove: it can never supply the off-proof, so this is safe
 * to accept from config while remaining useless as a green-wash.
 */
export function setMemoryHostRuntimes(values: string[]): void {
  const illegal = values.filter((v) => !(MEMORY_HOST_RUNTIMES as readonly string[]).includes(v));
  if (values.length === 0 || illegal.length > 0) {
    throw new Error(
      `Invalid memory host runtime(s) "${illegal.join(', ') || '(none given)'}". ` +
      `Legal values: ${MEMORY_HOST_RUNTIMES.join(', ')}.`,
    );
  }
  mutateRawConfig((raw) => {
    const memory = raw.memory && typeof raw.memory === 'object' && !Array.isArray(raw.memory)
      ? raw.memory as Record<string, unknown>
      : {};
    const hostContract = memory.hostContract && typeof memory.hostContract === 'object'
      && !Array.isArray(memory.hostContract)
      ? memory.hostContract as Record<string, unknown>
      : {};
    hostContract.runtimes = [...new Set(values)];
    memory.hostContract = hostContract;
    raw.memory = memory;
  });
}

/** Legal memory.plane values (Track A / #348). dual_legacy is deprecated defect mode. */
export const MEMORY_PLANE_VALUES = ['dual_legacy', 'import_only', 'sc_canonical'] as const;
export type MemoryPlaneValue = (typeof MEMORY_PLANE_VALUES)[number];

/**
 * SIGNED write path for `memory.plane` — `shieldcortex config --memory-plane`.
 * Same #275 discipline as setMemoryInjectContract. Also stamps planeSetAt so
 * drift doctor can time-box dual_legacy. Does not mint legacy memoryPlane alias.
 */
export function setMemoryPlane(value: string): void {
  if (!(MEMORY_PLANE_VALUES as readonly string[]).includes(value)) {
    throw new Error(
      `Invalid memory.plane "${value}". Legal values: ${MEMORY_PLANE_VALUES.join(', ')}.`,
    );
  }
  mutateRawConfig((raw) => {
    const memory = raw.memory && typeof raw.memory === 'object' && !Array.isArray(raw.memory)
      ? raw.memory as Record<string, unknown>
      : {};
    memory.plane = value;
    memory.planeSetAt = new Date().toISOString();
    raw.memory = memory;
  });
}

/** Read normalized plane from a raw config object (doctor / tooling). */
export function readMemoryPlane(raw: Record<string, unknown> | null | undefined): {
  plane: MemoryPlaneValue | null;
  planeSetAt: string | null;
  illegal: boolean;
} {
  const mem = (raw?.memory && typeof raw.memory === 'object' && !Array.isArray(raw.memory))
    ? raw.memory as Record<string, unknown>
    : {};
  const p = mem.plane ?? raw?.memoryPlane;
  if (p == null || p === '') {
    return { plane: 'dual_legacy', planeSetAt: typeof mem.planeSetAt === 'string' ? mem.planeSetAt : null, illegal: false };
  }
  if (typeof p === 'string' && (MEMORY_PLANE_VALUES as readonly string[]).includes(p)) {
    return {
      plane: p as MemoryPlaneValue,
      planeSetAt: typeof mem.planeSetAt === 'string' ? mem.planeSetAt : null,
      illegal: false,
    };
  }
  return { plane: null, planeSetAt: null, illegal: true };
}

const AUTO_MEMORY_SAMPLING_MIN = 1;
const AUTO_MEMORY_SAMPLING_MAX = 20;

/**
 * The SIGNED write path for `autoMemory.stopHookSamplingTurns` — what the
 * `shieldcortex config --auto-memory-sampling` flag calls. Same #275
 * discipline as setMemoryInjectContract: doctor's sampling warn used to say
 * "Edit ~/.shieldcortex/config.json", and following it tripped the tamper
 * check into strict mode. Read-modify-write on the autoMemory block so
 * sibling keys (enableStop, enableSessionEnd, stopHookSalienceBypass)
 * survive untouched.
 */
export function setAutoMemorySamplingTurns(n: number): void {
  if (!Number.isInteger(n) || n < AUTO_MEMORY_SAMPLING_MIN || n > AUTO_MEMORY_SAMPLING_MAX) {
    throw new Error(
      `Invalid sampling cadence "${n}". Provide an integer between ${AUTO_MEMORY_SAMPLING_MIN} and ${AUTO_MEMORY_SAMPLING_MAX} (≤ 5 recommended).`,
    );
  }
  mutateRawConfig((raw) => {
    const existing = raw.autoMemory && typeof raw.autoMemory === 'object' && !Array.isArray(raw.autoMemory)
      ? raw.autoMemory as Record<string, unknown>
      : {};
    existing.stopHookSamplingTurns = n;
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
// An id minted but not persisted because config.json is tampered (#647). Kept
// for the process so the sync callers (several per upload) see ONE identity
// rather than a fresh one per call while the write is being refused.
let unpersistedDeviceId: string | null = null;

export function getDeviceId(): string {
  const { data: raw, parseFailed } = readRawConfigState();
  if (typeof raw.deviceId === 'string' && raw.deviceId) {
    return raw.deviceId;
  }
  const id = unpersistedDeviceId ?? randomUUID();
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
  const written = mutateRawConfig((m) => {
    m.deviceId = id;
  }, 'skip');
  unpersistedDeviceId = written ? null : id;
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
