import fs from 'fs';
import path from 'path';
import { createRequire } from 'module';
import semver from 'semver';
import {
  resolveRealtimePluginInstallPath,
  readInstalledRealtimePluginVersion,
  resolveLocalExtensionInstall,
} from './openclaw-plugin-state.js';
import {
  readLatestBootRoster,
  findRegistrationSince,
  findGatewayAttributedRegistrationSince,
} from './openclaw-gateway-roster.js';
import { readRunningGatewayProcess } from './openclaw-gateway-process.js';

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

/**
 * What `~/.openclaw/openclaw.json` says about this plugin — INCLUDING whether
 * we could read the file at all.
 *
 * `readable` is the field this type exists for. Before it, a truncated,
 * permission-denied or half-written openclaw.json was caught by the same
 * `catch` as a file with no entry, and both produced `{ enabled: null, inAllow:
 * false }`. "We could not read the config" then classified identically to "the
 * config says nothing" — so an unreadable file became a confident verdict about
 * a state we had no evidence for, in whichever direction the rules happened to
 * fall. Cannot-read is now its own answer.
 *
 * `present` distinguishes the two readable-absence cases: no file on disk at
 * all (a host that never configured OpenClaw) versus a file that parsed fine
 * and simply has no entry for us (the #222 wipe).
 */
export interface ConfigEnableState {
  enabled: boolean | null;
  inAllow: boolean;
  /** False ⇒ the file exists but could not be read/parsed. Optional so
   *  pre-existing callers and fixtures keep meaning "readable". */
  readable?: boolean;
  /** False ⇒ no openclaw.json on disk. Optional for the same reason. */
  present?: boolean;
}

export interface ReconcileInput {
  pluginId: string;
  /** The version the package expects to be enforcing (pkg.version). */
  expectedVersion: string;
  /**
   * `~/.openclaw/openclaw.json` → plugins.entries[id].enabled + plugins.allow.
   *
   * `readable` distinguishes "the file says this plugin is not registered" from
   * "the file could not be read" — both previously collapsed to
   * `{enabled:null, inAllow:false}`, which would let a corrupt config convict a
   * host as UNPROTECTED (#222). Both flags default to true/present so existing
   * callers and fixtures keep their meaning.
   */
  config: ConfigEnableState;
  /** Legacy installs.json record, or null when absent. */
  installsJson: InstallsJsonRecord | null;
  /** Parsed latest SQLite index row, or null when the index is unreadable. */
  index: PluginIndexRow | null;
  /** Ground-truth version from the plugin's on-disk package.json, or null. */
  onDiskVersion: string | null;
  /**
   * A VALID plugin build found on disk, with its version unread or unreadable
   * (#226).
   *
   * The trusted-local-copy install — `~/.openclaw/extensions/<id>` — has no
   * installs.json record, no SQLite index record and no npm project dir, so
   * before this field the reconciler saw a host with a working, gateway-loaded
   * plugin and concluded nothing was installed. Paired with the enabled config
   * stanza that same installer writes, the verdict was `enabled-not-installed`:
   * a red FAIL saying the box boots unprotected, about a protected box.
   *
   * It is a PATH, not a directory listing: `resolveLocalExtensionInstall`
   * requires both `index.js` and `openclaw.plugin.json` before returning one,
   * so a bare or half-copied directory left behind by an interrupted install
   * does not qualify. Trading the false FAIL for a false PASS would be the
   * worse bug — that is the #222 shape.
   */
  onDiskInstallPath?: string | null;
  /**
   * `~/.openclaw/npm/projects/*` dir names matching the plugin.
   *
   * A DUPLICATE-detection signal, not an installation one (#226). An uninstall
   * routinely leaves one of these behind — `openclaw plugins uninstall` drops
   * the install record and the config stanza and does not always reap the npm
   * project dir — so a directory on its own proves nothing about whether a
   * plugin is installed. See the `installed` computation below.
   */
  projectDirs?: string[];
  /**
   * Plugin ids named on the RUNNING gateway's boot roster line, or null when
   * that line could not be read (#103). This is the only ground truth for what
   * the gateway actually loaded; `index.plugins` merely records what is
   * installed and enabled. Null means "cannot prove", never "healthy".
   */
  liveRoster?: string[] | null;
  /**
   * A plugin registration line was sighted AFTER the boot roster snapshot
   * (#142). The snapshot races registration (169 ms margin observed live), so
   * absence-from-snapshot plus a later sighting is ambiguous — CLI processes
   * write identical lines — and must not convict the host as UNPROTECTED.
   *
   * #216: this flag is ONLY for ambiguous (non-gateway-PID) sightings. A
   * registration whose log PID matches the running gateway is live-load proof
   * and is folded into `liveRoster` / `liveLoadEvidence` instead.
   */
  registrationSeenAfterBoot?: boolean;
  /**
   * #216 — how `loadedInLiveRoster === true` was proven for this gather.
   * - `boot-roster`: named on the current process boot line
   * - `gateway-pid-registration`: post-boot/hot-reload registration attributed
   *   to the running gateway PID (Case #213 / issue #216)
   * - omitted/null: not proven loaded via live evidence
   */
  liveLoadEvidence?: 'boot-roster' | 'gateway-pid-registration' | null;
}

export type PluginLoadState =
  | 'healthy'
  | 'not-installed'
  /** Config says enabled, but there is no package on this host to enable. */
  | 'enabled-not-installed'
  /** #222: installed on disk, but no longer registered in openclaw.json —
   *  the #214 installer wipe. Unprotected, and nobody asked for it. */
  | 'installed-not-enabled'
  /** #222: the operator explicitly set enabled:false. Intentional, not damage. */
  | 'disabled-by-operator'
  | 'enabled-not-loaded'
  /** #222: openclaw.json is on disk but could not be read or parsed, so "not
   *  registered" cannot be distinguished from "cannot tell". Unknown is never a
   *  confident verdict. */
  | 'config-unreadable'
  | 'index-unreadable'
  | 'load-unproven'
  | 'version-regressed'
  | 'conflicted-metadata'
  | 'duplicate-install';

export type ReconcileSeverity = 'ok' | 'warn' | 'fail';

export type RecommendedAction =
  | 'none'
  | 'install'
  | 'update-openclaw-tracked'
  | 'reinstall-pinned'
  | 'dedupe-and-reload'
  /**
   * #222: the package is present and correct; only the openclaw.json
   * registration is missing. Restore the stanza (entry + plugins.allow) — do
   * NOT reinstall. Re-running the installer churns the gateway, does not write
   * the enable flag at all, and (per #214) can wipe the very stanza we are
   * trying to restore.
   */
  | 're-register';

export interface ReconcileVerdict {
  state: PluginLoadState;
  severity: ReconcileSeverity;
  recommendedAction: RecommendedAction;
  enabledInConfig: boolean;
  /**
   * plugins_json carries an enabled entry for the plugin. NOTE: this is the
   * INSTALL index, not the live gateway roster — it says the plugin is
   * installed and enabled, not that the running gateway loaded it (#103).
   */
  loadedInIndex: boolean;
  /**
   * The running gateway's boot roster names the plugin. `null` when that line
   * could not be read — absence of evidence, not evidence of absence.
   */
  loadedInLiveRoster: boolean | null;
  /** The SQLite install index was actually readable (false ⇒ we CANNOT know
   * whether the plugin is loaded — never claim UNPROTECTED off an unreadable index). */
  indexReadable: boolean;
  /** `~/.openclaw/openclaw.json` parsed (false ⇒ every config-derived field
   *  below is absence-of-evidence, not evidence-of-absence). */
  configReadable: boolean;
  /** An openclaw.json exists on disk at all. */
  configPresent: boolean;
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

  // #103: the live gateway roster overrides the install index. Null = unread.
  // #216: gather may also prove load via a gateway-PID-attributed registration
  // (hot-reload / post-boot), which is represented either by promoting the
  // plugin id into `liveRoster` or by `liveLoadEvidence`.
  const liveRoster = input.liveRoster ?? null;
  const loadedInLiveRoster =
    liveRoster == null
      ? input.liveLoadEvidence === 'gateway-pid-registration'
        ? true
        : null
      : liveRoster.includes(pluginId) || input.liveLoadEvidence === 'gateway-pid-registration';

  const installsJsonVersion = input.installsJson?.version ?? null;
  const indexVersion = indexRecord?.version ?? indexRecord?.resolvedVersion ?? null;
  const onDiskVersion = input.onDiskVersion ?? null;

  // What counts as INSTALLED (#226). Four sources, all of them records of an
  // install having been performed and still standing:
  //
  //   - installs.json (the legacy install record)
  //   - an on-disk package.json we could read a version out of
  //   - OpenClaw's own install-index record
  //   - a VALID trusted-local-copy build in ~/.openclaw/extensions (index.js +
  //     openclaw.plugin.json both present — see `onDiskInstallPath`). This is
  //     the fallback install path, and none of the three layers above records
  //     it, so without this the whole install read as absent.
  //
  // `projectDirs` is deliberately NOT one of them. It is an npm project
  // directory under `~/.openclaw/npm/projects`, and a deliberate uninstall
  // routinely leaves an empty one behind: the install record goes, the config
  // stanza goes, the directory stays. Counting it made a cleanly uninstalled
  // host classify as installed-not-enabled and report a red FAIL — "the gateway
  // will boot WITHOUT the interceptor" — about a plugin the operator removed on
  // purpose. It stays in the input because it is real evidence of a DUPLICATE
  // (see the `projectDirs.length > 1` branch below); it is just not evidence of
  // an installation.
  const installed = Boolean(input.installsJson || onDiskVersion || indexRecord || input.onDiskInstallPath);

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

  const indexReadable = index != null;
  // Optional on the input so every pre-existing fixture keeps its meaning: a
  // caller that says nothing about readability is one that read the config.
  const configReadable = config.readable !== false;
  const configPresent = config.present !== false;

  const base = {
    enabledInConfig,
    loadedInIndex,
    loadedInLiveRoster,
    indexReadable,
    configReadable,
    configPresent,
    openClawTracked,
    indexWarnsConflict,
    metadataConflict,
    indexVersion,
    installsJsonVersion,
    onDiskVersion,
    expectedVersion,
  };

  // ── Priority order: most severe first ────────────────────────────────────

  // 0. THE CONFIG ITSELF IS UNREADABLE. Everything below reasons from
  //    `enabledInConfig`, which is derived from a file we just failed to parse.
  //    Collapsing that into "no entry" manufactures a verdict out of a missing
  //    measurement: on a truncated openclaw.json it reads as the #222 wipe
  //    (false red, sends an operator to repair a config that is merely
  //    half-written), and on a host whose file we cannot open it would just as
  //    happily read as healthy. Neither is knowledge. Report the gap.
  if (!configReadable) {
    reasons.push('~/.openclaw/openclaw.json exists but could NOT be read or parsed (truncated, malformed, or permission-denied) — the enable state is INDETERMINATE, not absent; no protection verdict can be drawn from it');
    if (loadedInLiveRoster === true) reasons.push('the RUNNING gateway has the plugin loaded, so the box is protected right now — but what it will load at the next restart depends on this unreadable file');
    else if (loadedInIndex) reasons.push("OpenClaw's install index lists it as enabled — install state, not load state, and it cannot substitute for the config");
    return { ...base, state: 'config-unreadable', severity: 'warn', recommendedAction: 'none', reasons };
  }

  // 1. Nothing installed anywhere.
  if (!installed) {
    // 1a. …but the config asks for it. This is NOT the benign "nothing is
    //     installed so nothing is claimed" case: openclaw.json enables a
    //     security plugin that is not on this host, so the gateway boots
    //     without it while every config-reading surface says it is on. The old
    //     code returned not-installed/ok here and doctor printed
    //     "skipped (realtime plugin not installed)" over exactly that.
    if (enabledInConfig) {
      reasons.push('openclaw.json ENABLES the realtime plugin but no package is installed on this host (no installs.json record, no index record, no on-disk build) — the gateway boots WITHOUT the interceptor while config reports it ON');
      return { ...base, state: 'enabled-not-installed', severity: 'fail', recommendedAction: 'install', reasons };
    }
    reasons.push('plugin not installed on this host (no config, installs.json, index record, or on-disk build)');
    return { ...base, state: 'not-installed', severity: 'ok', recommendedAction: 'install', reasons };
  }

  // 1b. #222 — THE GATING BUG. Every rule below is guarded by
  //     `enabledInConfig`, so when #214's installer wipe deleted the entry AND
  //     removed the id from `plugins.allow`, all of them were skipped and
  //     control fell through to `healthy`/`ok`. The state that leaves a host
  //     unprotected silenced the alarm built to catch it, and doctor printed a
  //     green "plugin loaded" tick over a box with no memory firewall and no
  //     action guard.
  //
  //     The distinction: rule 1 above ("nothing installed anywhere") is
  //     legitimately ok — nothing is installed, so nothing is claimed. THIS is
  //     different: the package is on disk, the operator believes a security
  //     product is running, and the next gateway restart will boot without it.
  //     That is a fail, and it must be evaluated BEFORE any enabledInConfig
  //     gate can skip it.
  //
  //     One case inside it is NOT a fault: an explicit `enabled: false`. That
  //     is a sentence an operator typed. A security check that reports a
  //     human's own decision back to them as a red FAIL is training them to
  //     ignore it — the same "cry wolf" failure #142 fixed on the roster side.
  //     A wiped stanza (no entry at all) still fails: nobody typed that.
  if (!enabledInConfig) {
    // #226: `enabled: false` is ALWAYS the intentional case, with no evidence
    // test in front of it. The first cut gated it on "was this plugin ever
    // running here" (a stale install-index row, or the live roster) and called
    // the answer prior-enablement evidence. It is not evidence of anything of
    // the kind: the index lags config by design and still lists a plugin the
    // operator disabled minutes ago, and the running gateway is *expected* to
    // still have it loaded from the pre-disable config. So the ordinary
    // sequence — edit openclaw.json, run doctor before restarting — hit both
    // branches and reported an operator's deliberate, correct action as a
    // security failure, which is exactly the alarm-fatigue this rule set is
    // trying to avoid. What the disable DID do to the host is still said out
    // loud below; it is simply not called a fault.
    if (config.enabled === false) {
      reasons.push(`installed on disk and explicitly disabled in openclaw.json (plugins.entries.${pluginId}.enabled = false) — an operator wrote that, so it reads as an INTENTIONAL disable, not a fault`);
      reasons.push('the host is running WITHOUT the memory firewall and action guard: that is what disabled means. Set enabled back to true to restore protection — the package is already installed, nothing needs reinstalling');
      if (loadedInLiveRoster === true) reasons.push('the RUNNING gateway still has it loaded from the config as it was before the disable — protection ends at the next restart');
      // `warn`, not `fail`: it is a deliberate state, fully described, and it
      // maps to exit 0 in an ordinary `shieldcortex doctor` run (see
      // doctorExitCode()). A fleet that wants a disabled host to fail its
      // pipeline uses `doctor --strict`, which escalates every ⚠️ to exit 1.
      // Both audiences are served without either overriding the other.
      return { ...base, state: 'disabled-by-operator', severity: 'warn', recommendedAction: 'none', reasons };
    }

    // The #214 wipe shape: no entry at all, and not allow-listed. Nobody typed
    // that, so unlike the branch above it is a fault.
    reasons.push('installed on disk but NOT registered in openclaw.json (no plugins.entries entry and absent from plugins.allow) — the host is UNPROTECTED: the gateway will boot WITHOUT the interceptor, no memory firewall, no action guard');
    if (loadedInIndex) reasons.push('the SQLite install index still lists it as enabled — the index lags a config wipe; config decides what loads at the next restart');
    if (loadedInLiveRoster === true) reasons.push('the RUNNING gateway did load it — from the config as it was BEFORE the wipe; protection ends at the next restart');
    // Repair by RESTORING the registration for the install that is already
    // here. The old routing sent this state to `openclaw plugins update` /
    // `plugins install --force`, which reinstalls a package that is present and
    // correct and does not write the stanza at all — so remediation ran,
    // reported success, and left the config exactly as unprotected as it found
    // it. The package is correct; only the registration is missing (#228).
    return {
      ...base,
      state: 'installed-not-enabled',
      severity: 'fail',
      recommendedAction: 're-register',
      reasons,
    };
  }

  // 2a. #142 guard on rule 2: the boot line is a snapshot and registration
  //     races it. When a registration line postdates the snapshot, absence
  //     from the snapshot cannot convict — but CLI processes write identical
  //     lines, so it cannot acquit either. Report the ambiguity as a warn and
  //     point at the canary, never a confident UNPROTECTED on a maybe.
  if (enabledInConfig && loadedInLiveRoster === false && input.registrationSeenAfterBoot === true) {
    reasons.push('absent from the boot roster snapshot, but a plugin registration was sighted after that snapshot — registration races the boot line and CLI processes write identical lines, so load state is UNPROVEN; the consent-gated live canary is the arbiter');
    return { ...base, state: 'load-unproven', severity: 'warn', recommendedAction: 'none', reasons };
  }

  // 2. THE #103 silent drop: the RUNNING gateway's boot roster does not name
  //    the plugin. This outranks every index-derived signal — on veronica the
  //    plugin was installed, enabled, allow-listed and present in plugins_json
  //    (so the checks below all read "healthy") while the gateway had booted
  //    without it six days earlier. Install state is not load state.
  if (enabledInConfig && loadedInLiveRoster === false) {
    reasons.push('enabled:true in config but ABSENT from the RUNNING gateway boot roster — interceptor not loaded, host unprotected while status reports ON');
    if (loadedInIndex) reasons.push('the SQLite install index lists it as enabled — install state, not load state; the live roster is authoritative');
    return {
      ...base,
      state: 'enabled-not-loaded',
      severity: 'fail',
      recommendedAction: openClawTracked ? 'update-openclaw-tracked' : 'reinstall-pinned',
      reasons,
    };
  }

  // 3. Cannot read the loaded roster (SQLite index unreadable): a broken
  //    better-sqlite3 binding, a locked DB, or a pre-2026.6.1 OpenClaw with no
  //    `installed_plugin_index` table all return a null index. We literally
  //    cannot know whether the plugin is loaded — reporting the #74 fail-open
  //    here would be a FALSE "UNPROTECTED" on a healthy box (the very binding
  //    fault repair pass-1 exists to fix). Classify as a diagnostic gap (warn),
  //    NEVER as a security fail-open. Only reached when enabled + installed but
  //    the index is unreadable; a genuinely uninstalled plugin fell out at (1).
  if (enabledInConfig && !loadedInIndex && index == null && loadedInLiveRoster !== true) {
    reasons.push('cannot read the loaded roster — the SQLite plugin install index is unreadable (broken better-sqlite3 binding, locked DB, or pre-2026.6.1 OpenClaw with no installed_plugin_index table); cannot confirm whether the interceptor is loaded');
    return { ...base, state: 'index-unreadable', severity: 'warn', recommendedAction: 'none', reasons };
  }

  // 4. THE #74 silent drop: enabled in config but missing from a READABLE index.
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

  // 4. Version regression (e.g. reinstall regressed 4.47.2 → 4.25.4).
  if (regressed) {
    reasons.push(`running version ${effective} is older than expected ${expected} — refuse downgrade, reinstall pinned`);
    return { ...base, state: 'version-regressed', severity: 'fail', recommendedAction: 'reinstall-pinned', reasons };
  }

  // 5. installs.json ↔ SQLite index disagree (the precondition for a future drop).
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

  // 6. Duplicate project dirs accumulated on disk (authoritative layers agree).
  if (projectDirs.length > 1) {
    reasons.push(`${projectDirs.length} plugin project dirs on disk — prune the stale duplicate so a future toggle cannot re-resolve to it`);
    return { ...base, state: 'duplicate-install', severity: 'warn', recommendedAction: 'dedupe-and-reload', reasons };
  }

  // Say exactly which evidence we have. Claiming "loaded in roster" off the
  // install index alone is what made #103 a false positive.
  // #216: distinguish boot-snapshot proof from PID-attributed hot-reload proof.
  reasons.push(
    loadedInLiveRoster === true
      ? input.liveLoadEvidence === 'gateway-pid-registration'
        ? 'enabled, registration attributed to the RUNNING gateway PID after boot (hot-reload / post-boot load), versions agree at the expected build'
        : 'enabled, present on the running gateway boot roster, versions agree at the expected build'
      : 'enabled and installed, versions agree at the expected build — but the running gateway boot roster could NOT be read, so the plugin is not proven loaded',
  );
  return { ...base, state: 'healthy', severity: 'ok', recommendedAction: 'none', reasons };
}

// ── Remediation planner (pure) ──────────────────────────────────────────────

export type ReconcileStepKind =
  | 'openclaw-update'
  | 'openclaw-install-pinned'
  | 'openclaw-install'
  | 'prune-duplicate-dirs'
  /** #222/#226: restore a wiped openclaw.json registration WITHOUT reinstalling
   *  — write `plugins.entries[id].enabled = true` (+ `plugins.allow`) back,
   *  merge-preserving. The package on disk is already correct; only the stanza
   *  is missing. */
  | 'restore-registration'
  | 'gateway-reload'
  | 'self-check';

export interface ReconcileStep {
  kind: ReconcileStepKind;
  /** argv passed to the `openclaw` binary, when the step shells out. */
  command?: string[];
  /** Project dir names to remove, for the prune step. */
  dirs?: string[];
  description: string;
}

export interface PlanOptions {
  pluginId: string;
  /** npm package spec, e.g. `@drakon-systems/shieldcortex-realtime`. */
  packageName: string;
  expectedVersion: string;
  /** Stale project dirs to prune (the canonical dir is excluded by the caller). */
  duplicateDirsToPrune?: string[];
}

/**
 * Turn a verdict into an ordered, side-effect-free remediation plan. The
 * executor runs these behind the gateway-safety guards; keeping the routing
 * pure lets us prove — in unit tests — that the three aiquant remediation
 * failures are fixed:
 *
 *  - OpenClaw-tracked plugins are refreshed with `plugins update` (the SC
 *    install path skips them → "source not found").
 *  - a regressed build is reinstalled PINNED to the expected version (a
 *    floating spec re-resolved to 4.25.4).
 *  - every plan ends with a gateway reload + honest-state self-check, so a
 *    "registered but inactive" outcome cannot be reported as success.
 */
export function planReconcileActions(verdict: ReconcileVerdict, opts: PlanOptions): ReconcileStep[] {
  const { packageName, expectedVersion } = opts;
  const steps: ReconcileStep[] = [];
  const prune = opts.duplicateDirsToPrune ?? [];

  const pruneStep = (): void => {
    if (prune.length > 0) {
      steps.push({
        kind: 'prune-duplicate-dirs',
        dirs: prune,
        description: `prune ${prune.length} stale duplicate project dir(s) so a toggle cannot re-resolve to them`,
      });
    }
  };
  const reloadThenVerify = (): void => {
    steps.push({ kind: 'gateway-reload', description: 'reload the OpenClaw gateway so the reconciled plugin loads' });
    steps.push({ kind: 'self-check', description: 'honest-state self-check: roster proof + live enforcement canary (both required)' });
  };

  switch (verdict.recommendedAction) {
    case 'update-openclaw-tracked':
      pruneStep();
      steps.push({
        kind: 'openclaw-update',
        command: ['plugins', 'update', packageName],
        description: 'refresh the OpenClaw-tracked plugin via `openclaw plugins update` (the SC install path skips tracked plugins)',
      });
      reloadThenVerify();
      break;

    case 'reinstall-pinned':
      pruneStep();
      steps.push({
        kind: 'openclaw-install-pinned',
        command: ['plugins', 'install', '--force', `${packageName}@${expectedVersion}`],
        description: `reinstall pinned to ${expectedVersion} (refuse the downgrade a floating spec re-resolved to)`,
      });
      reloadThenVerify();
      break;

    case 'dedupe-and-reload':
      pruneStep();
      steps.push({
        kind: 'openclaw-update',
        command: ['plugins', 'update', packageName],
        description: 'refresh the canonical install after pruning duplicates',
      });
      reloadThenVerify();
      break;

    case 'install':
      steps.push({
        kind: 'openclaw-install',
        command: ['plugins', 'install', `${packageName}@${expectedVersion}`],
        description: `install the plugin pinned to ${expectedVersion}`,
      });
      reloadThenVerify();
      break;

    // #222/#226: the #214 wipe. The package on disk is present and correct — a
    // reinstall would be churn (and on an OpenClaw-tracked plugin can fail
    // outright), and `plugins install --force` does not write the stanza at
    // all, so the old routing "succeeded" while the host stayed unprotected.
    // Restore the registration, then prove it actually loads.
    case 're-register':
      steps.push({
        kind: 'restore-registration',
        description: 'restore the plugin registration in openclaw.json (plugins.allow + plugins.entries[id].enabled = true), preserving every other plugin\'s config — nothing is reinstalled',
      });
      reloadThenVerify();
      break;

    case 'none':
      // Healthy: never churn the install — just verify honestly.
      steps.push({ kind: 'self-check', description: 'verify the healthy state with the honest-state self-check' });
      break;

    default:
      // An unrouted action must not silently plan a no-op and report success —
      // that is the #222 shape one layer down (repair "succeeds" by doing
      // nothing). Verify honestly and let the self-check speak.
      steps.push({
        kind: 'self-check',
        description: `unrouted remediation '${String(verdict.recommendedAction)}' — no automatic fix available; verifying state honestly instead`,
      });
      break;
  }

  return steps;
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
 * Read-only and path-scoped to the supplied `home`, so it is safe to exercise
 * against a temp fixture DB in tests without ever touching live `~/.openclaw`.
 */
export function readPluginInstallIndex(home: string): PluginIndexRow | null {
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
  return createRequire(import.meta.url);
}

// ── Disk gatherer: assemble a ReconcileInput from a host's ~/.openclaw ───────

export interface GatherOptions {
  pluginId?: string;
  expectedVersion: string;
  /** Injectable index reader (defaults to the live SQLite read). */
  readIndex?: (home: string) => PluginIndexRow | null;
  /**
   * Injectable live-roster reader (defaults to reading the gateway's newest
   * `http server listening` boot line). Returns null when it cannot be proven.
   */
  readLiveRoster?: () => string[] | null;
}

/**
 * Read the enable state out of `~/.openclaw/openclaw.json`, keeping the three
 * outcomes apart: parsed, absent, and UNREADABLE.
 *
 * The old body had one `catch` for all of them and returned `{ enabled: null,
 * inAllow: false }` — so a truncated or permission-denied config was reported
 * as a config that simply says nothing, and the reconciler then drew a
 * confident protection verdict from a file it had never read (#222).
 */
export function readConfigEnable(home: string, pluginId: string): ConfigEnableState {
  const configPath = path.join(home, '.openclaw', 'openclaw.json');
  let raw: string;
  try {
    raw = fs.readFileSync(configPath, 'utf-8');
  } catch (err) {
    // ENOENT is a real answer: there is no config, so nothing enables us. Any
    // other read failure (EACCES, EISDIR, I/O) is a missing measurement.
    const code = (err as NodeJS.ErrnoException)?.code;
    if (code === 'ENOENT') return { enabled: null, inAllow: false, readable: true, present: false };
    return { enabled: null, inAllow: false, readable: false, present: true };
  }
  try {
    const cfg = JSON.parse(raw) as {
      plugins?: { entries?: Record<string, { enabled?: unknown }>; allow?: unknown };
    };
    // JSON.parse happily accepts `"x"`, `null` and `7`. A config that is not an
    // object is not a config we have read the plugin stanza out of.
    if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg)) {
      return { enabled: null, inAllow: false, readable: false, present: true };
    }
    const entry = cfg.plugins?.entries?.[pluginId];
    const enabled = entry && typeof entry.enabled === 'boolean' ? entry.enabled : null;
    const allow = Array.isArray(cfg.plugins?.allow) ? (cfg.plugins!.allow as unknown[]) : [];
    const inAllow = allow.some(
      (e) => typeof e === 'string' && (e === pluginId || e.endsWith(`/${pluginId}`) || e.includes(`/${pluginId}/`)),
    );
    return { enabled, inAllow, readable: true, present: true };
  } catch {
    // #222: corrupt/truncated openclaw.json. The file is there, we just cannot
    // know what it says. This used to return the same shape as "registered
    // nowhere", so an unreadable config would have been convicted as
    // UNPROTECTED once that became a fail.
    return { enabled: null, inAllow: false, readable: false, present: true };
  }
}

function readInstallsJsonRecord(home: string, pluginId: string): InstallsJsonRecord | null {
  try {
    const json = JSON.parse(
      fs.readFileSync(path.join(home, '.openclaw', 'plugins', 'installs.json'), 'utf-8'),
    ) as { installRecords?: Record<string, { version?: unknown; installPath?: unknown }> };
    const rec = json.installRecords?.[pluginId];
    if (!rec) return null;
    return {
      version: typeof rec.version === 'string' ? rec.version : null,
      installPath: typeof rec.installPath === 'string' ? rec.installPath : null,
    };
  } catch {
    return null;
  }
}

function scanProjectDirs(home: string, pluginId: string): string[] {
  try {
    return fs
      .readdirSync(path.join(home, '.openclaw', 'npm', 'projects'))
      .filter((d) => d.includes(pluginId));
  } catch {
    return [];
  }
}

/**
 * Read the three authoritative layers off a host's `~/.openclaw` and assemble a
 * {@link ReconcileInput}. Takes `home` explicitly (never `os.homedir()`) so it
 * is fully test-isolable. All reads are best-effort; missing layers degrade to
 * null/empty rather than throwing.
 */
export function gatherReconcileInput(home: string, options: GatherOptions): ReconcileInput {
  const pluginId = options.pluginId ?? REALTIME_PLUGIN_ID;
  const readIndex = options.readIndex ?? ((h: string) => readPluginInstallIndex(h));
  // The default roster read touches the host's real gateway log dir (/tmp/openclaw),
  // which no `home` override can redirect — so it must never fire under Jest, or a
  // test would silently inherit THIS box's roster. Tests inject readLiveRoster.
  // #142/#150: bound the boot line by the RUNNING gateway's process start
  // (from OpenClaw's boot-lifecycle table). A line from a previous process, or
  // one we cannot bound, yields null — "cannot prove", never a stale answer.
  //
  // #216: a post-boot registration attributed to the RUNNING gateway PID is
  // live-load proof (hot-reload after stanza restore). CLI-attributed or
  // anonymous registration lines stay ambiguous (`registrationSeenAfterBoot`).
  let bootAtMs: number | null = null;
  let gatewayPid: number | null = null;
  let processStartedAtMs: number | null = null;
  const readRoster =
    options.readLiveRoster ??
    (() => {
      if (process.env.JEST_WORKER_ID !== undefined) return null;
      const proc = readRunningGatewayProcess(home);
      if (!proc) return null;
      gatewayPid = proc.pid;
      processStartedAtMs = proc.startedAtMs;
      const boot = readLatestBootRoster({ processStartedAtMs: proc.startedAtMs });
      bootAtMs = boot?.atMs ?? null;
      return boot?.plugins ?? null;
    });
  let liveRoster = readRoster();
  let liveLoadEvidence: 'boot-roster' | 'gateway-pid-registration' | null =
    liveRoster != null && liveRoster.includes(pluginId) ? 'boot-roster' : null;
  let registrationSeenAfterBoot = false;

  if (
    process.env.JEST_WORKER_ID === undefined &&
    liveLoadEvidence == null &&
    gatewayPid != null &&
    processStartedAtMs != null
  ) {
    // Prefer the boot snapshot timestamp when we have one (post-snapshot race);
    // otherwise bound by process start so a hot-reload after a missing boot
    // line can still prove load for the CURRENT process.
    const sinceMs = bootAtMs ?? processStartedAtMs;
    const gatewayReg = findGatewayAttributedRegistrationSince(sinceMs, gatewayPid);
    if (gatewayReg) {
      liveLoadEvidence = 'gateway-pid-registration';
      if (liveRoster == null) liveRoster = [pluginId];
      else if (!liveRoster.includes(pluginId)) liveRoster = [...liveRoster, pluginId];
    } else if (liveRoster != null && !liveRoster.includes(pluginId) && bootAtMs != null) {
      // Ambiguous sighting only — CLI/anonymous lines must not convict or acquit.
      registrationSeenAfterBoot = findRegistrationSince(bootAtMs) != null;
    }
  }

  return {
    pluginId,
    expectedVersion: options.expectedVersion,
    config: readConfigEnable(home, pluginId),
    installsJson: readInstallsJsonRecord(home, pluginId),
    index: readIndex(home),
    onDiskVersion: readInstalledRealtimePluginVersion(home),
    // #226: the trusted-local-copy build, only when it is a REAL one (index.js
    // + openclaw.plugin.json). Kept separate from `onDiskVersion` so a valid
    // copy whose manifest version we could not read still counts as installed.
    onDiskInstallPath: resolveLocalExtensionInstall(home),
    projectDirs: scanProjectDirs(home, pluginId),
    liveRoster,
    registrationSeenAfterBoot,
    liveLoadEvidence,
  };
}

/** Extract the `~/.openclaw/npm/projects/<name>` directory name from any path
 * that traverses it, or null when the path does not point into projects/. */
export function projectDirNameFromPath(p: string | null | undefined): string | null {
  if (!p || typeof p !== 'string') return null;
  // Match on the POSIX and platform separators — index paths recorded on the
  // host are POSIX even when this runs on another platform's path module.
  for (const sep of new Set([path.sep, '/'])) {
    const marker = `${sep}.openclaw${sep}npm${sep}projects${sep}`;
    const idx = p.indexOf(marker);
    if (idx === -1) continue;
    const rest = p.slice(idx + marker.length);
    const name = rest.split(sep)[0];
    if (name) return name;
  }
  return null;
}

/** The canonical (non-duplicate) project dir, derived from the resolved install
 * path — used by the reconciler to know which duplicate dirs are prunable. */
export function canonicalProjectDir(home: string): string | null {
  return projectDirNameFromPath(resolveRealtimePluginInstallPath(home));
}

/**
 * The LIVE project dir the AUTHORITATIVE SQLite index resolves into — the dir
 * the loaded gateway is actually running from. Derived from the roster entry's
 * `rootDir` first, then the index install record's `installPath`. This is the
 * dir that must NEVER be pruned (#74 finding 4): `canonicalProjectDir` above
 * resolves via installs.json FIRST, which in a conflicted-metadata state points
 * at the STALE dir — pruning by that would delete the live install. Returns
 * null when the index cannot name a live dir (⇒ caller must refuse to prune).
 */
export function canonicalProjectDirFromIndex(
  index: PluginIndexRow | null,
  pluginId: string,
): string | null {
  if (!index) return null;
  const rosterRootDir = index.plugins?.find((p) => p.pluginId === pluginId)?.rootDir ?? null;
  const fromRoster = projectDirNameFromPath(rosterRootDir);
  if (fromRoster) return fromRoster;
  const recordPath = index.installRecords?.[pluginId]?.installPath ?? null;
  return projectDirNameFromPath(recordPath);
}
