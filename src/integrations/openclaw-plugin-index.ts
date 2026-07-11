import fs from 'fs';
import path from 'path';
import semver from 'semver';

/**
 * Reconciling OpenClaw plugin-install state across its three authoritative
 * layers, and reading the new SQLite install index that OpenClaw 2026.6.1+
 * treats as ground truth.
 *
 * Field incident #74 (aiquant, 2026-07-11): after a disable→enable→restart
 * cycle the realtime interceptor was `enabled:true` in config yet ABSENT from
 * the loaded roster — a security fail-open (protection reports ON while OFF).
 * The root cause was a conflict between the legacy
 * `~/.openclaw/plugins/installs.json` and the shared SQLite
 * `installed_plugin_index`; a toggled plugin re-resolves its install record
 * from the conflicted index and gets silently dropped.
 *
 * This module adds the missing SQLite read + a PURE reconciler that classifies
 * the state and recommends the correct remediation — crucially, routing
 * OpenClaw-tracked plugins through `openclaw plugins update` (not the SC install
 * path, which skips them) and refusing version downgrades.
 */

export const REALTIME_PLUGIN_ID = 'shieldcortex-realtime';

// ── Parsed shapes of the three layers ──────────────────────────────────────

/** One entry from `installed_plugin_index.install_records_json`. */
export interface IndexInstallRecord {
  source?: string;
  version?: string;
  resolvedVersion?: string;
  installPath?: string;
}

/** One entry from `installed_plugin_index.plugins_json` — the LOADED roster. */
export interface IndexPluginEntry {
  pluginId: string;
  enabled?: boolean;
  origin?: string;
  rootDir?: string;
}

/** The latest `installed_plugin_index` row, parsed. */
export interface PluginIndexRow {
  installRecords: Record<string, IndexInstallRecord>;
  plugins: IndexPluginEntry[];
  warning?: string | null;
  generatedAtMs?: number;
}

/** The legacy `installs.json` record for a plugin. */
export interface InstallsJsonRecord {
  version?: string | null;
  installPath?: string | null;
}

export interface ReconcileInput {
  pluginId: string;
  /** The version the package expects to be enforcing (pkg.version). */
  expectedVersion: string;
  /** `~/.openclaw/openclaw.json` → plugins.entries[id].enabled + plugins.allow. */
  config: { enabled: boolean | null; inAllow: boolean };
  /** Legacy installs.json record, or null when absent. */
  installsJson: InstallsJsonRecord | null;
  /** Parsed latest SQLite index row, or null when the index is unreadable. */
  index: PluginIndexRow | null;
  /** Ground-truth version from the plugin's on-disk package.json, or null. */
  onDiskVersion: string | null;
  /** `~/.openclaw/npm/projects/*` dir names matching the plugin. */
  projectDirs?: string[];
}

export type PluginLoadState =
  | 'healthy'
  | 'not-installed'
  | 'enabled-not-loaded'
  | 'version-regressed'
  | 'conflicted-metadata'
  | 'duplicate-install';

export type ReconcileSeverity = 'ok' | 'warn' | 'fail';

export type RecommendedAction =
  | 'none'
  | 'install'
  | 'update-openclaw-tracked'
  | 'reinstall-pinned'
  | 'dedupe-and-reload';

export interface ReconcileVerdict {
  state: PluginLoadState;
  severity: ReconcileSeverity;
  recommendedAction: RecommendedAction;
  enabledInConfig: boolean;
  /** plugins_json roster carries an enabled entry for the plugin. */
  loadedInIndex: boolean;
  /** An npm install record exists in the SQLite index ⇒ OpenClaw-tracked. */
  openClawTracked: boolean;
  /** The index warning string names this plugin (benign on its own). */
  indexWarnsConflict: boolean;
  /** installs.json and the SQLite index disagree on path or version. */
  metadataConflict: boolean;
  indexVersion: string | null;
  installsJsonVersion: string | null;
  onDiskVersion: string | null;
  expectedVersion: string;
  reasons: string[];
}

function coerce(v: string | null | undefined): string | null {
  if (!v || typeof v !== 'string') return null;
  const c = semver.valid(v) ?? semver.valid(semver.coerce(v) ?? '');
  return c ?? null;
}

/**
 * Classify a plugin's install state from the three authoritative layers and
 * recommend the correct remediation. PURE — no disk, no SQLite, no mutation —
 * so the #74 field states can be replayed as fixtures.
 */
export function reconcilePluginState(input: ReconcileInput): ReconcileVerdict {
  const { pluginId, expectedVersion, config } = input;
  const index = input.index ?? null;
  const projectDirs = input.projectDirs ?? [];
  const reasons: string[] = [];

  const indexRecord = index?.installRecords?.[pluginId] ?? null;
  const openClawTracked = Boolean(indexRecord && indexRecord.source === 'npm');

  const enabledInConfig =
    config.enabled === true || (config.enabled == null && config.inAllow === true);

  const loadedInIndex = Boolean(
    index?.plugins?.some((p) => p.pluginId === pluginId && p.enabled === true),
  );

  const installsJsonVersion = input.installsJson?.version ?? null;
  const indexVersion = indexRecord?.version ?? indexRecord?.resolvedVersion ?? null;
  const onDiskVersion = input.onDiskVersion ?? null;

  const installed = Boolean(
    input.installsJson || onDiskVersion || indexRecord || projectDirs.length > 0,
  );

  // The index warning is present even on healthy hosts (it names every plugin
  // whose legacy/SQLite metadata differs), so it is a signal, not a verdict.
  const warning = index?.warning ?? '';
  const indexWarnsConflict =
    typeof warning === 'string' &&
    /conflicting plugin install metadata/i.test(warning) &&
    warning.includes(pluginId);

  // Actionable disagreement between the two install layers.
  const installsPath = input.installsJson?.installPath ?? null;
  const indexPath = indexRecord?.installPath ?? null;
  const pathConflict = Boolean(installsPath && indexPath && installsPath !== indexPath);
  const versionLayerConflict = Boolean(
    installsJsonVersion && indexVersion && installsJsonVersion !== indexVersion,
  );
  const metadataConflict = pathConflict || versionLayerConflict;

  // Effective running version: on-disk is ground truth, else the index record.
  const effective = coerce(onDiskVersion) ?? coerce(indexVersion);
  const expected = coerce(expectedVersion);
  const regressed = Boolean(effective && expected && semver.lt(effective, expected));

  const base = {
    enabledInConfig,
    loadedInIndex,
    openClawTracked,
    indexWarnsConflict,
    metadataConflict,
    indexVersion,
    installsJsonVersion,
    onDiskVersion,
    expectedVersion,
  };

  // ── Priority order: most severe first ────────────────────────────────────

  // 1. Nothing installed anywhere.
  if (!installed) {
    reasons.push('plugin not installed on this host (no config, installs.json, index record, or on-disk build)');
    return { ...base, state: 'not-installed', severity: 'ok', recommendedAction: 'install', reasons };
  }

  // 2. THE #74 silent drop: enabled in config but missing from the loaded roster.
  if (enabledInConfig && !loadedInIndex) {
    reasons.push('enabled:true in config but ABSENT from the loaded roster (plugins_json) — interceptor not loaded, host unprotected while status reports ON');
    if (indexWarnsConflict) reasons.push('index reports conflicting install metadata for this plugin');
    return {
      ...base,
      state: 'enabled-not-loaded',
      severity: 'fail',
      recommendedAction: openClawTracked ? 'update-openclaw-tracked' : 'reinstall-pinned',
      reasons,
    };
  }

  // 3. Version regression (e.g. reinstall regressed 4.47.2 → 4.25.4).
  if (regressed) {
    reasons.push(`running version ${effective} is older than expected ${expected} — refuse downgrade, reinstall pinned`);
    return { ...base, state: 'version-regressed', severity: 'fail', recommendedAction: 'reinstall-pinned', reasons };
  }

  // 4. installs.json ↔ SQLite index disagree (the precondition for a future drop).
  if (metadataConflict) {
    if (pathConflict) reasons.push(`installs.json install path disagrees with the SQLite index (${installsPath} vs ${indexPath})`);
    if (versionLayerConflict) reasons.push(`installs.json version ${installsJsonVersion} disagrees with index version ${indexVersion}`);
    return {
      ...base,
      state: 'conflicted-metadata',
      severity: 'warn',
      recommendedAction: openClawTracked ? 'update-openclaw-tracked' : 'reinstall-pinned',
      reasons,
    };
  }

  // 5. Duplicate project dirs accumulated on disk (authoritative layers agree).
  if (projectDirs.length > 1) {
    reasons.push(`${projectDirs.length} plugin project dirs on disk — prune the stale duplicate so a future toggle cannot re-resolve to it`);
    return { ...base, state: 'duplicate-install', severity: 'warn', recommendedAction: 'dedupe-and-reload', reasons };
  }

  reasons.push('enabled, loaded in roster, versions agree at the expected build');
  return { ...base, state: 'healthy', severity: 'ok', recommendedAction: 'none', reasons };
}

// ── SQLite index reader (best-effort, read-only, never mutates) ─────────────

function openClawSqlitePath(home: string): string {
  return path.join(home, '.openclaw', 'state', 'openclaw.sqlite');
}

function safeParse<T>(json: string | null | undefined, fallback: T): T {
  if (!json || typeof json !== 'string') return fallback;
  try {
    return JSON.parse(json) as T;
  } catch {
    return fallback;
  }
}

/**
 * Read the latest `installed_plugin_index` row from OpenClaw's shared SQLite
 * state and parse the JSON columns we reconcile against. Opens READ-ONLY and
 * best-effort — returns null if the DB, table, or better-sqlite3 is unavailable
 * so callers degrade to the installs.json/on-disk layers rather than throwing.
 *
 * Never opens under a Jest worker: the reconciler analyzer is unit-tested with
 * fixtures; only the on-box repair/self-check path touches the live DB.
 */
export function readPluginInstallIndex(home: string): PluginIndexRow | null {
  if (process.env.JEST_WORKER_ID !== undefined) return null;
  const dbPath = openClawSqlitePath(home);
  if (!fs.existsSync(dbPath)) return null;

  let db: import('better-sqlite3').Database | null = null;
  try {
    // Lazy require so environments without the native binding still load this
    // module (the pure reconciler above must remain usable everywhere).
    const require = createRequireSafe();
    const Database = require('better-sqlite3') as typeof import('better-sqlite3');
    db = new Database(dbPath, { readonly: true, fileMustExist: true });
    const row = db
      .prepare(
        'SELECT install_records_json, plugins_json, warning, generated_at_ms ' +
          'FROM installed_plugin_index ORDER BY generated_at_ms DESC LIMIT 1',
      )
      .get() as
      | { install_records_json: string; plugins_json: string; warning: string | null; generated_at_ms: number }
      | undefined;
    if (!row) return null;
    return {
      installRecords: safeParse<Record<string, IndexInstallRecord>>(row.install_records_json, {}),
      plugins: safeParse<IndexPluginEntry[]>(row.plugins_json, []),
      warning: row.warning ?? null,
      generatedAtMs: row.generated_at_ms,
    };
  } catch {
    return null;
  } finally {
    try {
      db?.close();
    } catch {
      // ignore
    }
  }
}

function createRequireSafe(): NodeRequire {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { createRequire } = require('module') as typeof import('module');
  return createRequire(import.meta.url);
}
