/**
 * ShieldCortex Doctor — Installation health checker.
 * Runs diagnostics and reports issues with actionable fixes.
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import semver from 'semver';
import { execFileSync } from 'child_process';
import { createRequire } from 'module';
import { pathToFileURL } from 'url';
import { REQUIRED_HOOK_NAMES } from '../setup/settings-hooks.js';
import { hookCommandResolves, hookCommandTrust } from '../setup/hook-command-resolution.js';
import {
  resolveRealtimePluginInstallPath,
  readInstalledRealtimePluginVersion,
  readRealtimeProjectManifest,
  findEoverrideRiskPins,
  isRealtimePluginDisabledInConfig,
} from '../integrations/openclaw-plugin-state.js';
import {
  gatherReconcileInput,
  reconcilePluginState,
  REALTIME_PLUGIN_ID,
  type ReconcileVerdict,
} from '../integrations/openclaw-plugin-index.js';
import {
  readConversationAccess,
  describeConversationAccess,
  conversationAccessFix,
} from '../integrations/openclaw-conversation-access.js';
import {
  readOpenClawHostVersion,
  evaluateEnforcementSupport,
  describeEnforcementSupport,
} from '../integrations/openclaw-conversation-capability.js';
import { parseRegistrationsSince, parseLogLinePid } from '../integrations/openclaw-gateway-roster.js';
import { readRunningGatewayProcess } from '../integrations/openclaw-gateway-process.js';
import { resolveSelfInstallDir } from '../setup/native-binding.js';
import {
  evaluateHostContract,
  openClawConfigUsesInclude,
  parseHermesMemoryBlock,
  readInjectModeStrict,
  resolveClaudeCodeEvidence,
  resolveHermesEvidence,
  resolveOpenClawEvidence,
  resolveOpenClawMemorySearchState,
  INJECT_MODES,
  SIDECAR_POSTURE,
  type ArtifactProbe,
  type HermesProfileProbe,
  type HostRuntimeEvidence,
  type HostRuntimeId,
  type OpenClawHookArtifacts,
  type ProbeRead,
} from '../memory/host-contract.js';
import {
  evaluatePlaneDrift,
  type MemoryPlane,
  type NativeSotEvidence,
  type PlaneDriftCounts,
} from '../memory/plane-drift.js';
import { getCanonicalSchema } from '../database/init.js';
import { runMigrations } from '../database/migrations.js';
import { detectStaleDashboard, realDeps } from '../service/dashboard-staleness.js';
import { MCP_LIGHT_TICK_INTERVAL_MS } from '../worker/types.js';
import { DIRECTORY_BUDGET_BYTES } from '../limits.js';
import { gatewayRestartAdvice } from '../setup/gateway-restart-command.js';
import { LIVE_CANARY_COMMAND } from '../setup/openclaw-selfcheck.js';
import {
  CLAUDE_CODE_ENFORCEMENT_FLOOR,
  detectClaudeCode,
  upgradeCommandFor,
  type DetectClaudeCodeDeps,
} from '../integrations/claude-code-version.js';
// #157 (`doctor --ai`): type-only imports, erased at build time — pulling in
// these types costs nothing when `--ai` is never passed. The actual model
// transport (cli-invoker.js) and the explainer (doctor-explainer.js) are
// loaded with a runtime `import()` inside runDoctorAiSection() below, so a
// plain `shieldcortex doctor` never touches either module.
import {
  getConfigDir,
  hasTrustedMemorySidecarPosture,
  readRawConfig,
  migrateInterceptorActionGuardAlias,
} from '../cloud/config.js';
import { validateOpenClawConfig } from '../integrations/openclaw-config-validate.js';
import type { OpenClawConfigVerdict, ValidateDeps } from '../integrations/openclaw-config-validate.js';
import type { ModelInvoker } from '../defence/iron-dome/approval-judge.js';
import type { DoctorExplainerOutcome } from '../defence/iron-dome/doctor-explainer.js';
import {
  formatDoctorReport,
  shouldColorDoctor,
  type DoctorReportStyle,
} from './doctor-report.js';
import {
  correlateCronDenials,
  type CorrelateCronDenialsOptions,
  type CronDenialReport,
} from './cron-denial-audit.js';

const require = createRequire(import.meta.url);
const pkg = require('../../package.json');

// ANSI colour codes
const bold = '\x1b[1m';
const reset = '\x1b[0m';
const green = '\x1b[32m';
const yellow = '\x1b[33m';
const red = '\x1b[31m';
const cyan = '\x1b[36m';
const dim = '\x1b[2m';

export type CheckStatus = 'pass' | 'warn' | 'fail' | 'info';

export interface CheckResult {
  label: string;
  status: CheckStatus;
  message: string;
  fix?: string;
  /**
   * Set when the check did not run because a prerequisite simply does not
   * exist yet on a fresh install. runDoctor() collapses these into a single
   * dim note instead of printing a line per dependent check — the cascade of
   * "skipped (no database)" warnings read as four separate faults on a
   * perfectly healthy first run (#129).
   */
  skipped?: 'db-uninitialised';
  /**
   * Set when this remedy is carried out by an OpenClaw `plugins`/`skills`
   * subcommand. OpenClaw refuses ALL of them — reporting only "Unknown
   * command" — while any config entry dangles, so the advice is a no-op an
   * operator can follow for days without noticing (#221). `applyOpenClawCliGate`
   * strips it, or swaps in `fallbackFix`, when the config does not validate.
   *
   * Declared per site rather than matched from the fix text, deliberately: the
   * `installed-not-enabled` remedy also reads "shieldcortex repair" but routes
   * to a pure JSON write (restore-registration) and keeps working when
   * OpenClaw is blocked — and it is the ONLY remedy for an UNPROTECTED host.
   * No substring can tell those two apart, so a text-matching gate would
   * delete the one piece of advice that still helps.
   */
  needsOpenClawCli?: { subcommand: 'plugins' | 'skills' | 'config'; fallbackFix?: string };
  /**
   * Set by `checkOpenClawConfigValid` when the config is PROVEN invalid, so
   * `applyOpenClawCliGate` keys on the fact rather than on the severity.
   *
   * Keying the gate on `status === 'fail'` would mean any future adjustment to
   * this check's severity silently switches the whole suppression feature off
   * with no test failing — the class of coupling that produced #222 and #103.
   */
  openClawCliBlocked?: true;
}

/** The `OpenClaw config` check's label. */
export const OPENCLAW_CONFIG_LABEL = 'OpenClaw config';

/**
 * Strip remedies that cannot execute (#221).
 *
 * Every OTHER check's severity is deliberately untouched: the host is exactly
 * as broken as it was, so its counts and the exit code must not move. A wrong
 * verdict must never make a blocked host look healthier.
 *
 * The config row itself is the one exception, and only downwards. `doctor`
 * exits 1 on any `fail`, with no `--strict` opt-in — and the enforcement
 * contract above `doctorExitCode` reserves that for states ShieldCortex owns.
 * An invalid OpenClaw config with NOTHING of ours blocked by it (a host using
 * ShieldCortex purely for MCP memory, whose OpenClaw has some third-party
 * plugin's dangling entry) is a real finding but not our failure, so it warns.
 * The moment it actually blocks one of our remedies, it fails.
 *
 * Fail-open. Anything short of a proven-invalid config leaves every fix alone,
 * because a doctor that hides working advice when it could not reach `openclaw`
 * is a worse bug than the one being fixed here.
 */
export function applyOpenClawCliGate(results: CheckResult[]): CheckResult[] {
  // Keyed on the explicit marker, never on severity — see `openClawCliBlocked`.
  if (!results.some(r => r.openClawCliBlocked)) return results;

  // Nothing of ours is actually BROKEN by it: report, do not fail the run.
  //
  // "Has a tag" is not the same as "is a problem". The optional-skill notice is
  // an `info` row that is tagged and is present by DEFAULT on every host not
  // using the OpenClaw skill — so counting tags alone kept the config row at
  // `fail`, and `doctor` exited 1, on hosts with nothing wrong. Only a row that
  // is itself a fault (fail/warn) justifies failing the run; info rows are
  // still annotated below, they just do not vote.
  const blockedFault = results.some(
    r => r.needsOpenClawCli && (r.status === 'fail' || r.status === 'warn'),
  );

  const note = ' [remedy blocked — fix the OpenClaw config first, see "OpenClaw config" above]';
  return results.map((r) => {
    // The config row is the only one whose severity may move, and only down.
    if (r.openClawCliBlocked) {
      return blockedFault
        ? r
        : {
            ...r,
            status: 'warn' as const,
            message: `${r.message}\n      (no ShieldCortex remedy on this host depends on it)`,
          };
    }

    if (!r.needsOpenClawCli) return r;
    // Annotation runs regardless of `blockedFault` — an info row does not vote
    // on severity, but it is still unfollowable advice and must say so.
    //
    // One site carries its remediation in `message` rather than `fix` (the
    // optional-skill notice). A gate that only rewrote `fix` would sail past
    // it and leave it as the single piece of unfollowable advice on the page —
    // the exact class of miss this issue is about. Annotating in place also
    // avoids promoting it into Suggested fixes on healthy hosts.
    if (!r.fix) return { ...r, message: r.message + note };
    const { fallbackFix } = r.needsOpenClawCli;
    return fallbackFix
      ? { ...r, fix: fallbackFix, message: r.message + note }
      : { ...r, message: r.message + note, fix: undefined };
  });
}

/**
 * Uniform "the database hasn't been created yet" result for the checks that
 * need a database to say anything at all. Informational, never a warning:
 * the DB is created lazily on first use, so its absence on a fresh install
 * is the expected state, not a fault.
 */
function skippedNoDatabase(label: string): CheckResult {
  return { label, status: 'info', message: 'skipped — database not created yet', skipped: 'db-uninitialised' };
}

/**
 * How a path actually failed to be readable.
 *
 * `fs.existsSync()` collapses three very different states into one `false`:
 * "not created yet", "there but I'm not allowed to look at it", and "the
 * filesystem returned something else entirely". #131 made doctor treat that
 * `false` as the friendly fresh-install state, so a root-owned
 * `~/.shieldcortex` — the classic artefact of a single `sudo shieldcortex …`
 * run — reported a clean bill of health on a genuinely broken install. A
 * diagnostic going green on the box it exists to diagnose is its worst
 * possible failure mode (#132).
 *
 * probePath() keeps the cases apart. `statSync` is injectable so tests can
 * drive every branch deterministically, including on hosts where the test
 * runner is root and chmod cannot deny it anything.
 */
export type PathProbe =
  | { kind: 'present'; stat: fs.Stats }
  | { kind: 'absent' }
  | { kind: 'denied'; code: string; message: string }
  | { kind: 'error'; code: string; message: string };

export function probePath(
  target: string,
  statSync: (p: string) => fs.Stats = fs.statSync,
): PathProbe {
  try {
    return { kind: 'present', stat: statSync(target) };
  } catch (err: unknown) {
    const code = (err as NodeJS.ErrnoException)?.code ?? 'UNKNOWN';
    const message = err instanceof Error ? err.message : String(err);
    // ENOENT is the only code that means "genuinely not there yet".
    if (code === 'ENOENT') return { kind: 'absent' };
    if (code === 'EACCES' || code === 'EPERM') return { kind: 'denied', code, message };
    return { kind: 'error', code, message };
  }
}

/** True only for "this path is genuinely not there yet" — never for unreadable. */
function isAbsent(target: string): boolean {
  return probePath(target).kind === 'absent';
}

function tildify(target: string): string {
  const home = os.homedir();
  return target.startsWith(home) ? target.replace(home, '~') : target;
}

/**
 * The remedy for the only cause worth naming: ShieldCortex state owned by a
 * different user. Practically always one `sudo shieldcortex …` (or an install
 * script run under sudo) leaving root-owned files behind.
 */
function ownershipFix(): string {
  return (
    'Those paths exist but this user cannot read them — almost always ShieldCortex state owned by ' +
    'another user, typically root, left behind by one `sudo shieldcortex …` run. Restore ownership: ' +
    '`sudo chown -R "$USER" ~/.shieldcortex` (also `~/.claude-memory` on a legacy install), then ' +
    're-run `shieldcortex doctor`.'
  );
}

/**
 * Turn a non-present, non-absent probe into an honest ❌. Never swallows the
 * underlying errno — a code we have no advice for still gets surfaced verbatim
 * rather than being reported as a healthy or fresh install.
 *
 * `opts.fix` overrides the remedy: a string for a path the ownership hint does
 * not fit, `false` for a dependent check whose root cause is already reported
 * (repeating one remedy per affected check reads as several problems).
 */
function unreadableResult(
  label: string,
  target: string,
  probe: Extract<PathProbe, { kind: 'denied' | 'error' }>,
  opts: { fix?: string | false } = {},
): CheckResult {
  const defaultFix = probe.kind === 'denied'
    ? ownershipFix()
    : `Resolve the filesystem error above on ${tildify(target)}, then re-run \`shieldcortex doctor\`.`;
  const fix = opts.fix === undefined ? defaultFix : opts.fix;
  return {
    label,
    status: 'fail',
    message: probe.kind === 'denied'
      ? `permission denied reading ${tildify(target)} (${probe.code})`
      : `cannot read ${tildify(target)} — ${probe.code}: ${probe.message}`,
    ...(fix === false ? {} : { fix }),
  };
}

/**
 * Upgrade a caught filesystem error to a permission ❌ when that is what it is.
 * Returns null for anything else so the caller keeps its own handling.
 */
function permissionFailure(
  label: string,
  target: string,
  err: unknown,
  opts: { fix?: string | false } = {},
): CheckResult | null {
  const code = (err as NodeJS.ErrnoException)?.code;
  if (code === 'EACCES' || code === 'EPERM') {
    const fix = opts.fix === undefined ? ownershipFix() : opts.fix;
    return {
      label,
      status: 'fail',
      message: `permission denied reading ${tildify(target)} (${code})`,
      ...(fix === false ? {} : { fix }),
    };
  }
  return null;
}

/** better-sqlite3 surfaces a denied open as SQLITE_CANTOPEN, not EACCES. */
function looksLikePermissionError(err: unknown, msg: string): boolean {
  const code = (err as NodeJS.ErrnoException)?.code ?? '';
  return (
    code === 'EACCES' ||
    code === 'EPERM' ||
    code === 'SQLITE_CANTOPEN' ||
    code === 'SQLITE_READONLY' ||
    /EACCES|EPERM|permission denied|unable to open database file/i.test(msg)
  );
}

function icon(status: CheckStatus): string {
  switch (status) {
    case 'pass': return `${green}\u2705${reset}`;
    case 'warn': return `${yellow}\u26A0\uFE0F ${reset}`;
    case 'fail': return `${red}\u274C${reset}`;
    case 'info': return `${cyan}\u2139\uFE0F ${reset}`;
  }
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

function getShieldCortexDir(): string {
  return path.join(os.homedir(), '.shieldcortex');
}

// ── Environment detection ────────────────────────────────
interface Environment {
  hasClaude: boolean;
  hasOpenClaw: boolean;
  hasVSCode: boolean;
  hasCodex: boolean;
  isHeadless: boolean;
}

function detectEnvironment(): Environment {
  const home = os.homedir();
  const hasClaude = fs.existsSync(path.join(home, '.claude')) || fs.existsSync(path.join(home, '.claude.json'));
  const hasOpenClaw = fs.existsSync(path.join(home, '.openclaw'));
  const hasCodex = fs.existsSync(path.join(home, '.codex'));

  const platform = process.platform;
  const vscodeDirs = platform === 'darwin'
    ? [path.join(home, 'Library', 'Application Support', 'Code', 'User')]
    : platform === 'win32'
      ? [path.join(process.env.APPDATA ?? path.join(home, 'AppData', 'Roaming'), 'Code', 'User')]
      : [path.join(home, '.config', 'Code', 'User')];
  const hasVSCode = vscodeDirs.some(d => fs.existsSync(d));

  // Headless = no display environment (SSH server, container, etc.)
  const isHeadless = !process.env.DISPLAY && !process.env.WAYLAND_DISPLAY && platform !== 'darwin' && platform !== 'win32';

  return { hasClaude, hasOpenClaw, hasVSCode, hasCodex, isHeadless };
}

function getDbPath(): string {
  const newPath = path.join(getShieldCortexDir(), 'memories.db');
  const legacyPath = path.join(os.homedir(), '.claude-memory', 'memories.db');
  // Probe rather than existsSync: an unreadable DB at the canonical path must
  // still resolve to that path, so the checks report the permission fault
  // against the real install instead of silently falling back to the legacy
  // location (or to "fresh install") (#132).
  if (!isAbsent(newPath)) return newPath;
  if (!isAbsent(legacyPath)) return legacyPath;
  return newPath; // default expected path
}

// ── Check 1: Database health ──────────────────────────────
/**
 * Pure helper for the database health check. Exported so tests can drive it
 * against any path/environment without going through doctor's homedir-derived
 * getDbPath().
 */
export function runDatabaseCheck(dbPath: string, env: Environment = detectEnvironment()): CheckResult {
  const probe = probePath(dbPath);

  if (probe.kind === 'denied' || probe.kind === 'error') {
    // There IS something at this path, we just cannot read it. Never the
    // friendly fresh-install line — that is the #131 regression this closes.
    return unreadableResult('Database', dbPath, probe);
  }

  if (probe.kind === 'absent') {
    // Not a failure. The database is created lazily on the first memory
    // operation, so "no database yet" is the normal state of a fresh install —
    // and doctor is exactly the command a new user runs to check the install
    // worked. Reporting ❌ there told healthy installs they were broken (#129).
    //
    // `quickstart` only configures hooks/MCP — it does NOT touch the DB.
    // The reliable one-shot init paths are: `shieldcortex scan "..."`
    // (works on every install shape) or starting an MCP-bound session
    // (Claude Code) which lazy-inits via the MCP server.
    const fix = env.hasClaude
      ? 'Run `shieldcortex scan "init"` to create the database now, or start a Claude Code session — the MCP server will lazy-init on first memory call'
      : 'Run `shieldcortex scan "init"` to create the database now (OpenClaw-only / headless install)';
    return {
      label: 'Database',
      status: 'info',
      message: 'not initialised yet — created automatically on first use',
      fix,
    };
  }

  try {
    const Database = require('better-sqlite3');
    const db = new Database(dbPath, { readonly: true });
    try {
      const result = db.pragma('integrity_check');
      const integrity = Array.isArray(result) ? result[0]?.integrity_check : result;
      const stat = fs.statSync(dbPath);
      const size = formatBytes(stat.size);

      // Check WAL file
      const walPath = dbPath + '-wal';
      let walInfo = '';
      if (fs.existsSync(walPath)) {
        const walStat = fs.statSync(walPath);
        walInfo = `, WAL ${formatBytes(walStat.size)}`;
      }

      if (integrity === 'ok') {
        return { label: 'Database', status: 'pass', message: `healthy (${size}${walInfo})` };
      } else {
        return {
          label: 'Database',
          status: 'fail',
          message: `corrupt — integrity check returned: ${integrity}`,
          fix: 'Back up and delete `~/.shieldcortex/memories.db`, then restart the MCP server',
        };
      }
    } finally {
      db.close();
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    const isNativeBindingFault = /bindings file|napi|abi|MODULE_VERSION|was compiled against/i.test(msg);
    // A stat'able DB can still be unopenable because the file itself is owned
    // by another user (mode 600 root:root — the other half of the sudo
    // artefact). Telling that user to delete their database is bad advice.
    const fix = isNativeBindingFault
      ? `Native DB engine failed to load. Run \`shieldcortex repair\` (compiles better-sqlite3 from source + re-verifies), or manually: cd "${path.join(resolveSelfInstallDir(), 'node_modules', 'better-sqlite3')}" && npm run build-release`
      : looksLikePermissionError(err, msg)
        ? ownershipFix()
        : 'Back up and delete `~/.shieldcortex/memories.db`, then restart the MCP server';
    return {
      label: 'Database',
      status: 'fail',
      message: `cannot open — ${msg}`,
      fix,
    };
  }
}

async function checkDatabase(): Promise<CheckResult> {
  return runDatabaseCheck(getDbPath());
}

/**
 * Threat-graph projector freshness (docs/design/2026-08-11-threat-graph.md,
 * Phase A). A stalled projector degrades to "no data" silently by design
 * (invariant 4: a missing/stale value must never harm a scan) — this check is
 * what makes a dead projector a finding instead of a silent regression, the
 * #200/#222 lesson that a check that can only report success is not a check.
 *
 * Uses the initialised singleton when present (tests); otherwise opens the
 * DB file read-only like every other doctor check.
 */
/**
 * Attestation coverage (attestation Phase 5) — the rollout observability the
 * plumbing phases need: % of recent defence_audit rows carrying a non-NULL
 * source_attested, with the attested / explicitly-unattested / unplumbed
 * split. Lets an operator WATCH coverage climb after upgrading instead of
 * inferring the writers' state from risk_modifier zeros.
 *
 * The stale-process warn keys on KNOWN-HOOK rows only (adversarially
 * confirmed, PR #322 review): overall-zero coverage is NOT a fault signal,
 * because this same build deliberately ships never-attest writers (REST scan
 * API, langchain guard, universal bridge — pinned NULL forever per the #308
 * mute-lever rule), so a box used exclusively through those surfaces is
 * healthy at 0%. Hook rows are the sharp discriminator: their writers ship in
 * this package and are pinned as attesting, so a busy all-NULL hook window
 * means still-running pre-upgrade processes are writing them — restart.
 */
export async function checkAttestationCoverage(
  opts: { nowMs?: number; windowDays?: number; minRowsForWarn?: number } = {},
): Promise<CheckResult> {
  const label = 'Attestation coverage';
  const windowDays = opts.windowDays ?? 28;
  const minRowsForWarn = opts.minRowsForWarn ?? 50;

  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const Database = require('better-sqlite3');
  let db: any = null;
  let opened = false;
  try {
    const { isDatabaseInitialized, getDatabase } = await import('../database/init.js');
    if (isDatabaseInitialized()) {
      db = getDatabase();
    } else {
      const dbPath = getDbPath();
      const gate = databasePrerequisite(label, dbPath);
      if (gate) return gate;
      db = new Database(dbPath, { readonly: true });
      opened = true;
    }

    const hasCol = (db.prepare('PRAGMA table_info(defence_audit)').all() as Array<{ name: string }>)
      .some((c) => c.name === 'source_attested');
    if (!hasCol) {
      return { label, status: 'info', message: 'source_attested column not present yet (created on next init after upgrade)' };
    }

    const nowMs = opts.nowMs ?? Date.now();
    const since = new Date(nowMs - windowDays * 86_400_000).toISOString();
    const counts = db.prepare(`
      SELECT COUNT(*) AS total,
             SUM(CASE WHEN source_attested = 1 THEN 1 ELSE 0 END) AS attested,
             SUM(CASE WHEN source_attested = 0 THEN 1 ELSE 0 END) AS unattested,
             SUM(CASE WHEN source_attested IS NULL THEN 1 ELSE 0 END) AS unplumbed
      FROM defence_audit WHERE timestamp >= ?
    `).get(since) as { total: number; attested: number | null; unattested: number | null; unplumbed: number | null };

    const total = counts.total;
    if (total === 0) {
      return { label, status: 'info', message: `no audit rows in the last ${windowDays} days — nothing to measure yet` };
    }
    const attested = counts.attested ?? 0;
    const unattested = counts.unattested ?? 0;
    const unplumbed = counts.unplumbed ?? 0;
    const nonNull = attested + unattested;
    const pct = Math.round((nonNull / total) * 100);

    // Stale-process discriminator: only the shipped hook writers (pinned as
    // attesting in this build) can prove staleness. Overall-zero coverage is
    // healthy on a never-attest-only box — see the docblock.
    const hookCounts = db.prepare(`
      SELECT COUNT(*) AS total,
             SUM(CASE WHEN source_attested IS NOT NULL THEN 1 ELSE 0 END) AS nonNull
      FROM defence_audit
      WHERE timestamp >= ?
        AND source_type = 'hook'
        AND source_identifier IN ('session-end-hook', 'pre-compact-hook', 'stop-hook', 'hook', 'recall-defence')
    `).get(since) as { total: number; nonNull: number | null };
    if (hookCounts.total >= minRowsForWarn && (hookCounts.nonNull ?? 0) === 0) {
      return {
        label,
        status: 'warn',
        message: `${hookCounts.total} hook-captured audit rows in the last ${windowDays} days and none carries attestation — ` +
          'these writers attest in the current build, so still-running pre-upgrade processes are writing them',
        fix: 'These writers attest in the current build — still-running pre-upgrade processes are writing them. Run `openclaw gateway restart` and restart MCP / dashboard so they load the current build',
      };
    }

    return {
      label,
      status: 'pass',
      message: `${pct}% of the last ${windowDays} days' ${total} audit rows carry attestation ` +
        `(${attested} attested / ${unattested} explicitly unattested / ${unplumbed} unplumbed)`,
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { label, status: 'warn', message: `could not measure: ${msg}` };
  } finally {
    if (opened && db) {
      try { db.close(); } catch { /* readonly close is best-effort */ }
    }
  }
}

export async function checkThreatGraph(
  opts: { lagWarnThreshold?: number; enabled?: boolean; nowMs?: number; sweepStaleMs?: number } = {},
): Promise<CheckResult> {
  const label = 'Threat graph';
  const lagWarnThreshold = opts.lagWarnThreshold ?? 1000;
  const sweepStaleMs = opts.sweepStaleMs ?? 6 * 60 * 60 * 1000; // 6h default

  // Config gate first: a deliberately disabled projector accrues lag by
  // design and must not WARN forever. `opts.enabled` is a test seam only.
  const { isThreatGraphEnabled } = await import('../cloud/config.js');
  const enabled = opts.enabled ?? isThreatGraphEnabled();
  if (!enabled) {
    return { label, status: 'info', message: 'disabled by config (threatGraph.enabled=false)' };
  }

  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const Database = require('better-sqlite3');
  let db: any = null;
  let opened = false;
  try {
    const { isDatabaseInitialized, getDatabase } = await import('../database/init.js');
    if (isDatabaseInitialized()) {
      db = getDatabase();
    } else {
      const dbPath = getDbPath();
      const gate = databasePrerequisite(label, dbPath);
      if (gate) return gate;
      db = new Database(dbPath, { readonly: true });
      opened = true;
    }

    const hasTable = db.prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'threat_graph_state'"
    ).get();
    if (!hasTable) {
      return {
        label,
        status: 'info',
        message: 'threat-graph tables not present yet (created on next init after upgrade)',
      };
    }

    const state = db.prepare(
      'SELECT last_audit_id, last_rt_cursor, last_run_at, last_error FROM threat_graph_state WHERE id = 1'
    ).get() as { last_audit_id: number; last_rt_cursor: string; last_run_at: string | null; last_error: string | null } | undefined;
    const maxAudit = (db.prepare('SELECT COALESCE(MAX(id), 0) as m FROM defence_audit').get() as { m: number }).m;

    if (state?.last_error) {
      return {
        label,
        status: 'warn',
        message: `last projector run recorded an error: ${state.last_error.slice(0, 200)}`,
        fix: 'shieldcortex threat-graph rebuild',
      };
    }

    const cursor = state?.last_audit_id ?? 0;
    const lag = maxAudit - cursor;

    // Never-ran is not "caught up". A small backlog on a fresh install is a
    // friendly info (the next worker tick handles it); a backlog past the
    // warn threshold with no run ever means no worker is projecting — warn.
    const neverRan = (!state || !state.last_run_at) && cursor === 0;
    if (neverRan && maxAudit > 0 && lag <= lagWarnThreshold) {
      return {
        label,
        status: 'info',
        message: `projector has not run yet (${maxAudit} audit rows waiting) — a worker tick or \`shieldcortex threat-graph rebuild\` will populate the graph`,
      };
    }

    // A non-zero cursor with NO recorded run is the stalled-upgrade shape: an
    // old projector advanced the cursor, then every modern lease run died
    // before it could stamp last_run_at (observed live: the lease_token column
    // was missing on upgraded installs, the acquisition threw outside the
    // recorded path, and this check read "cursor close enough → ✅ caught up"
    // for weeks). Lag CANNOT distinguish "healthy and idle" from "dead and
    // frozen" — only a recorded completion can.
    if (cursor > 0 && !state?.last_run_at) {
      return {
        label,
        status: 'warn',
        message: `cursor is at ${cursor} but no projector run has ever completed on this install — ` +
          'the graph data predates the current projector, which is likely failing before it can record anything',
        fix: 'shieldcortex threat-graph rebuild (and check last_error afterwards)',
      };
    }

    if (lag > lagWarnThreshold) {
      return {
        label,
        status: 'warn',
        message: `projector is ${lag} audit rows behind (cursor ${cursor} of ${maxAudit})` +
          (state?.last_run_at ? `, last ran ${state.last_run_at}` : ', never ran'),
        fix: 'ensure a worker is running (MCP server or dashboard), or: shieldcortex threat-graph rebuild',
      };
    }

    // Idle-sweep freshness: source_risk drives the (advisory/enforce) trust
    // modifier, and a stalled sweep means stale risk feeding it. Warn when the
    // most-recent source_risk.updated_at is older than the budget. Only
    // meaningful once the table has rows.
    const hasRiskTable = db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='source_risk'"
    ).get();
    if (hasRiskTable) {
      const newest = db.prepare('SELECT MAX(updated_at) AS m FROM source_risk').get() as { m: string | null };
      if (newest.m) {
        const nowMs = opts.nowMs ?? Date.now();
        const ageMs = nowMs - Date.parse(newest.m);
        if (ageMs > sweepStaleMs) {
          return {
            label,
            status: 'warn',
            message: `risk sweep is stale — source_risk last refreshed ${newest.m} ` +
              `(${Math.round(ageMs / 3_600_000)}h ago); the trust modifier is reading stale risk`,
            fix: 'ensure a worker is running (MCP server or dashboard), or: shieldcortex threat-graph rebuild',
          };
        }
      }
    }

    // Open relation-channel conflicts (Phase E) are advisory review items, not
    // a projector fault — surface the count in the healthy message so the
    // operator knows there is a review queue without it reading as an error.
    let conflictNote = '';
    try {
      const openConflicts = (db.prepare(
        "SELECT COUNT(*) AS c FROM threat_nodes WHERE kind = 'event' AND key LIKE 'conflict:%'"
      ).get() as { c: number }).c;
      if (openConflicts > 0) {
        conflictNote = `; ${openConflicts} relation-channel conflict(s) awaiting review (shieldcortex threat-graph conflicts)`;
      }
    } catch { /* conflicts are a display extra — never fail the check on them */ }

    return {
      label,
      status: 'pass',
      message: (maxAudit === 0
        ? 'nothing to project yet'
        : `caught up (cursor ${cursor} of ${maxAudit}` +
          `${state?.last_rt_cursor ? `, realtime at ${state.last_rt_cursor}` : ''}` +
          `${state?.last_run_at ? `, last ran ${state.last_run_at}` : ''})`) + conflictNote,
    };
  } catch (e) {
    return {
      label,
      status: 'warn',
      message: `check failed: ${e instanceof Error ? e.message : String(e)}`,
    };
  } finally {
    if (opened && db) {
      try { db.close(); } catch { /* readonly probe */ }
    }
  }
}

/**
 * Gate for the checks that can say nothing without a readable database.
 * Returns the result to return early with, or null to carry on.
 *
 * The three states are deliberately distinct: absent is the friendly
 * fresh-install skip, unreadable is a ❌ that must never be collapsed into it
 * (#132), readable proceeds to the real check.
 */
function databasePrerequisite(label: string, dbPath: string): CheckResult | null {
  const probe = probePath(dbPath);
  if (probe.kind === 'absent') return skippedNoDatabase(label);
  if (probe.kind === 'present') return null;
  // No fix line here on purpose: the Database check already carries the
  // ownership remedy, and repeating it per dependent check turns "Suggested
  // fixes" into four copies of one sentence.
  return unreadableResult(label, dbPath, probe, { fix: false });
}

// ── Check 2: Schema version ──────────────────────────────
/**
 * Diff the live memories table against the canonical schema instead of a
 * hand-maintained column list. The old list froze at three ~v4.0 columns,
 * so v4.47.13 shipped a doctor that said "Schema: up to date" on a DB
 * missing defence_verdict while the write probe failed on it (21 Jul 2026
 * field incident). Deriving the expected set from getCanonicalSchema() —
 * the same source initDatabase() applies to fresh DBs — means a new
 * migration column is covered the day it lands in schema.sql, with no list
 * to forget.
 *
 * Only MISSING columns are drift: live extras (renamed/retired columns on
 * long-lived DBs) are harmless and stay silent.
 */
export function runSchemaDriftCheck(dbPath: string): CheckResult {
  const prerequisite = databasePrerequisite('Schema', dbPath);
  if (prerequisite) return prerequisite;

  try {
    const Database = require('better-sqlite3');

    const reference = new Database(':memory:');
    let expected: string[];
    try {
      reference.exec(getCanonicalSchema());
      expected = (reference.pragma('table_info(memories)') as Array<{ name: string }>)
        .map((c) => c.name);
    } finally {
      reference.close();
    }

    const db = new Database(dbPath, { readonly: true });
    try {
      const columns = db.pragma('table_info(memories)') as Array<{ name: string }>;
      const columnNames = new Set(columns.map((c: { name: string }) => c.name));

      const missing = expected.filter(col => !columnNames.has(col));

      if (missing.length === 0) {
        return { label: 'Schema', status: 'pass', message: 'up to date' };
      } else {
        return {
          label: 'Schema',
          status: 'warn',
          message: `missing columns: ${missing.join(', ')}`,
          fix: 'Restart the MCP server to auto-migrate, or run: shieldcortex install',
        };
      }
    } finally {
      db.close();
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { label: 'Schema', status: 'warn', message: `check failed — ${msg}` };
  }
}

async function checkSchema(): Promise<CheckResult> {
  return runSchemaDriftCheck(getDbPath());
}

// ── Check 3: Memory stats ─────────────────────────────────
/**
 * Pure helper for the memory-count check. Exported so tests can drive it
 * against a temp database instead of the homedir install.
 */
export function runMemoryStatsCheck(dbPath: string): CheckResult {
  const prerequisite = databasePrerequisite('Memories', dbPath);
  if (prerequisite) return prerequisite;

  try {
    const Database = require('better-sqlite3');
    const db = new Database(dbPath, { readonly: true });
    try {
      const total = (db.prepare('SELECT COUNT(*) as count FROM memories').get() as { count: number }).count;
      const stm = (db.prepare("SELECT COUNT(*) as count FROM memories WHERE type = 'short_term'").get() as { count: number }).count;
      const ltm = (db.prepare("SELECT COUNT(*) as count FROM memories WHERE type = 'long_term'").get() as { count: number }).count;

      const STM_LIMIT = 100;
      const LTM_LIMIT = 1000;

      let status: CheckStatus = 'pass';
      let warnings: string[] = [];

      if (stm >= STM_LIMIT * 0.9) {
        status = 'warn';
        warnings.push(`${stm}/${STM_LIMIT} STM — consolidation needed`);
      }
      if (ltm >= LTM_LIMIT * 0.9) {
        status = 'warn';
        warnings.push(`${ltm}/${LTM_LIMIT} LTM — approaching limit`);
      }

      const message = warnings.length > 0
        ? `${total} total (${stm} STM, ${ltm} LTM) — ${warnings.join('; ')}`
        : `${total} total (${stm} STM, ${ltm} LTM)`;

      return { label: 'Memories', status, message };
    } finally {
      db.close();
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { label: 'Memories', status: 'warn', message: `check failed — ${msg}` };
  }
}

async function checkMemoryStats(): Promise<CheckResult> {
  return runMemoryStatsCheck(getDbPath());
}

// ── Check 3b: Write-path smoke test ───────────────────────
/**
 * The honest "is it working?" check.
 *
 * Doctor checks have historically gone green while writes were silently
 * failing (v4.12.4 path-encoding bug, v4.12.5 NOT NULL UUID schema gap).
 * The pattern: schema introspection passed (columns existed) but actual
 * INSERTs threw constraint violations during real workloads.
 *
 * This check does a real round-trip — INSERT a tagged probe memory,
 * SELECT it back, DELETE it. If any step fails, doctor reports the
 * actual error string instead of "all green". The probe is tagged with
 * a unique source identifier so it can never be confused with real data
 * and gets deleted at the end of the check.
 */
/**
 * Pure helper for the write-path round-trip. Exported so tests can
 * exercise it against any database path (in-memory or temp file)
 * without going through doctor's homedir-derived getDbPath().
 */
export function runWritePathProbe(dbPath: string, env: Environment = detectEnvironment()): CheckResult {
  const prerequisite = databasePrerequisite('Write path', dbPath);
  if (prerequisite) return prerequisite;

  let db: any = null;
  const probeUuid = `doctor-probe-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  const probeTitle = '__shieldcortex_doctor_probe__';

  // On an OpenClaw-only / headless box there is no MCP server to "restart" —
  // telling the user to do so is a dead end. The reliable heal is any command
  // that opens the DB through the init/migration path; `shieldcortex repair`
  // does that (and rebuilds a broken engine too). (#116)
  const isOpenClawOnly = env.hasOpenClaw && !env.hasClaude;
  const failFix = isOpenClawOnly
    ? 'Run `shieldcortex repair` — it opens the database through the full init/migration path (and rebuilds the DB engine if that is the fault). This box has no MCP server to restart.'
    : 'This is the smoking gun for a stale schema or migration drift. Run `shieldcortex repair` (opens the DB through the full init/migration path), restart the MCP server (auto-migrates on next open), or re-install: shieldcortex install';

  try {
    const Database = require('better-sqlite3');
    db = new Database(dbPath);

    // Bring the schema current before probing — the same migration path
    // initDatabase() runs on every open (runMigrations → canonical schema).
    // Without this the probe opened the DB raw and INSERTed against whatever
    // was on disk, so a healthy pre-restart DB that is merely missing a
    // freshly-added column (e.g. 4.47.13's defence_verdict) failed here and
    // doctor cried "migration drift" on an install one open away from healthy.
    // Pending migrations apply on the next real init anyway; applying them here
    // makes the probe test the schema the runtime will actually use. (#116)
    runMigrations(db);
    db.exec(getCanonicalSchema());

    // INSERT — exercises NOT NULL columns + CHECK constraints. The schema
    // adds these silently across versions; an INSERT against a stale schema
    // is the exact failure mode v4.12.5 had.
    // P1/WS3: stamp explicit provenance (verdict + low trust + source_kind) so
    // the probe is honestly attributed, not defaulted to trust 1.0 / unverified.
    db.prepare(`
      INSERT INTO memories (uuid, type, category, title, content, salience, source, source_kind, capture_method, trust_score, defence_verdict)
      VALUES (?, 'short_term', 'note', ?, 'doctor probe — safe to delete', 0.01, 'cli:doctor', 'cli', 'doctor-probe', 0.01, 'probe')
    `).run(probeUuid, probeTitle);

    // SELECT — exercises the FTS5 + index path
    const row = db.prepare('SELECT id, title FROM memories WHERE uuid = ?').get(probeUuid) as { id: number; title: string } | undefined;
    if (!row || row.title !== probeTitle) {
      return {
        label: 'Write path',
        status: 'fail',
        message: 'wrote a probe row but could not read it back',
        fix: 'Database may be corrupted. Run `shieldcortex consolidate` then re-run doctor.',
      };
    }

    // DELETE — exercises the cascade triggers (FTS5 cleanup)
    const deleteResult = db.prepare('DELETE FROM memories WHERE uuid = ?').run(probeUuid);
    if (deleteResult.changes !== 1) {
      return {
        label: 'Write path',
        status: 'warn',
        message: `probe row written + read OK but delete affected ${deleteResult.changes} rows (expected 1)`,
        fix: 'Manual cleanup may be needed. Check ~/.shieldcortex/memories.db for orphaned rows.',
      };
    }

    return { label: 'Write path', status: 'pass', message: 'INSERT/SELECT/DELETE round-trip OK' };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    // Best-effort cleanup so we don't leave probe rows behind on a partial failure
    if (db) {
      try { db.prepare('DELETE FROM memories WHERE uuid = ?').run(probeUuid); } catch { /* ignore */ }
    }
    return {
      label: 'Write path',
      status: 'fail',
      message: `round-trip failed — ${msg}`,
      fix: failFix,
    };
  } finally {
    if (db) {
      try { db.close(); } catch { /* ignore */ }
    }
  }
}

async function checkWritePath(): Promise<CheckResult> {
  return runWritePathProbe(getDbPath());
}

// ── Check 4: Hook installation ────────────────────────────
/**
 * Pure helper for the hook-installation check. Exported so tests can point it
 * at a temp settings.json (or a deliberately absent one) without touching the
 * real homedir.
 */
export function runHooksCheck(settingsPath: string, env: Environment = detectEnvironment()): CheckResult {
  const probe = probePath(settingsPath);

  if (probe.kind === 'denied' || probe.kind === 'error') {
    // A settings.json we cannot read is not "not configured yet" — doctor
    // simply cannot tell whether the hooks are wired, and saying so is the
    // only honest answer (#132).
    return unreadableResult('Hooks', settingsPath, probe, {
      fix: `Check ownership and permissions of ${tildify(settingsPath)} — while it is unreadable, doctor cannot tell whether the hooks are wired.`,
    });
  }

  if (probe.kind === 'absent') {
    // No settings.json is not a fault. Either Claude Code isn't on this box at
    // all (OpenClaw-only / headless installs never grow one), or it is and the
    // user hasn't run `shieldcortex install` yet — the exact state of every
    // fresh install. A ⚠️ here told healthy boxes something was wrong (#129).
    return env.hasClaude
      ? {
          label: 'Hooks',
          status: 'info',
          message: 'not configured yet — no ~/.claude/settings.json',
          fix: 'Run `shieldcortex install` to configure hooks',
        }
      : {
          label: 'Hooks',
          status: 'info',
          message: 'not applicable — Claude Code not detected on this host',
        };
  }

  try {
    const settings = JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));
    const hooks = settings.hooks || {};

    // Single source of truth: whatever `shieldcortex install` actually installs.
    // Previously hardcoded a different list which produced false "missing" warnings
    // after SessionEnd was removed from defaults (was crashing OpenClaw agents). [#23]
    const hookNames = [...REQUIRED_HOOK_NAMES];
    let installed = 0;
    const missing: string[] = [];

    // Commands that are configured but do NOT resolve. This is the #146 check:
    // a hook entry existing in settings.json says nothing about whether it runs.
    // Three of four fleet boxes on 31 Jul 2026 had every hook configured and
    // every hook dead, because a bare command name does not resolve in the
    // non-interactive shell a harness spawns hooks in — and this check used to
    // report that state as a clean pass.
    const unresolvable: string[] = [];

    for (const name of hookNames) {
      const hookConfig = hooks[name];
      if (hookConfig) {
        // Check if any hook command references shieldcortex.
        // Settings format: [{ hooks: [{ type, command, timeout }] }]
        const commands: string[] = Array.isArray(hookConfig)
          ? hookConfig.flatMap((entry: { hooks?: Array<{ command?: string }> }) =>
              (Array.isArray(entry?.hooks) ? entry.hooks : [])
                .map(h => h?.command)
                .filter((c): c is string => typeof c === 'string' && c.includes('shieldcortex')),
            )
          : [];
        if (commands.length > 0) {
          installed++;
          if (!commands.every(hookCommandResolves)) unresolvable.push(name);
        } else {
          missing.push(name);
        }
      } else {
        missing.push(name);
      }
    }

    // A configured-but-dead hook is worse than a missing one: the operator
    // believes they are protected. FAIL, not warn.
    if (unresolvable.length > 0) {
      return {
        label: 'Hooks',
        status: 'fail',
        message:
          `${installed}/${hookNames.length} installed but ${unresolvable.length} DO NOT RESOLVE ` +
          `(${unresolvable.join(', ')}) — these hooks never run, so the guard is not enforcing here`,
        fix: 'Run `shieldcortex install` to rewrite them to an absolute path (#146)',
      };
    }

    if (installed === hookNames.length) {
      return { label: 'Hooks', status: 'pass', message: `${installed}/${hookNames.length} installed and resolving` };
    } else {
      return {
        label: 'Hooks',
        status: 'warn',
        message: `${installed}/${hookNames.length} installed — missing: ${missing.join(', ')}`,
        fix: 'Run `shieldcortex install` to configure hooks',
      };
    }
  } catch (err: unknown) {
    // A settings.json that stats but will not open (mode 000) is a permission
    // fault, not an inconclusive check.
    const denied = permissionFailure('Hooks', settingsPath, err, {
      fix: `Check ownership and permissions of ${tildify(settingsPath)} — while it is unreadable, doctor cannot tell whether the hooks are wired.`,
    });
    if (denied) return denied;
    const msg = err instanceof Error ? err.message : String(err);
    return { label: 'Hooks', status: 'warn', message: `check failed — ${msg}` };
  }
}

async function checkHooks(): Promise<CheckResult> {
  return runHooksCheck(path.join(os.homedir(), '.claude', 'settings.json'));
}

// ── Check 4b: Auto-memory hook gates ──────────────────────
/**
 * Surfaces the resolved on/off state of the opt-in Stop and SessionEnd
 * auto-memory hooks. Pre-v4.13.1 these were triple-gated (install flag,
 * runtime config, sampling) with the runtime gate failing silently —
 * users who wired the hook saw zero captures and zero feedback (#41).
 *
 * The check looks at both layers:
 *   - settings.json: is the hook wired so Claude Code will fire it?
 *   - autoMemory.enableStop / enableSessionEnd: will the hook actually run?
 *
 * Both layers must agree for the hook to do work. v4.13.1 onwards, the
 * install flag flips both — if they disagree here, the user edited one
 * side by hand and should re-run setup.
 */
export async function checkAutoMemoryHooks(): Promise<CheckResult[]> {
  const settingsPath = path.join(os.homedir(), '.claude', 'settings.json');
  let wiredStop = false;
  let wiredSessionEnd = false;
  try {
    if (fs.existsSync(settingsPath)) {
      const settings = JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));
      const hooks = settings?.hooks || {};
      const isCortexWired = (entries: unknown): boolean =>
        Array.isArray(entries) && entries.some(
          (entry: { hooks?: Array<{ command?: string }> }) =>
            Array.isArray(entry?.hooks) && entry.hooks.some(
              (h) => typeof h?.command === 'string' && h.command.includes('shieldcortex'),
            ),
        );
      wiredStop = isCortexWired(hooks.Stop);
      wiredSessionEnd = isCortexWired(hooks.SessionEnd);
    }
  } catch { /* fall through — both stay false, user gets a clean info row */ }

  // Lazy-import to avoid pulling cloud/config into doctor's static graph
  // when the user hasn't configured anything yet.
  let gateStop = false;
  let gateSessionEnd = false;
  // Default lowered 10 → 5 in v4.14.0 — keep this fallback in sync with
  // scripts/lib/auto-memory-config.mjs so doctor reports the same value
  // the runtime gate would resolve to when no override is present.
  let samplingTurns = 5;
  try {
    const cfg = await import('../cloud/config.js');
    const enable = cfg.getAutoMemoryEnableConfig();
    gateStop = enable.enableStop;
    gateSessionEnd = enable.enableSessionEnd;
    const raw = cfg.readRawConfig();
    const am = raw.autoMemory && typeof raw.autoMemory === 'object'
      ? raw.autoMemory as Record<string, unknown>
      : {};
    if (typeof am.stopHookSamplingTurns === 'number' && am.stopHookSamplingTurns > 0) {
      samplingTurns = Math.floor(am.stopHookSamplingTurns);
    }
  } catch { /* defaults already set */ }

  const rowFor = (
    label: string,
    wired: boolean,
    gate: boolean,
    flag: string,
    extra?: string,
  ): CheckResult => {
    if (!wired && !gate) {
      return {
        label,
        status: 'info',
        message: 'opt-in (not installed)',
      };
    }
    if (wired && gate) {
      return {
        label,
        status: 'pass',
        message: extra ? `enabled (${extra})` : 'enabled',
      };
    }
    if (wired && !gate) {
      return {
        label,
        status: 'warn',
        message: 'wired in settings.json but runtime gate is off — hook will exit silently every turn',
        fix: `Run \`shieldcortex setup ${flag}\` to flip the gate`,
      };
    }
    // gate && !wired
    return {
      label,
      status: 'warn',
      message: 'runtime gate is on but hook is not wired in settings.json — hook will never fire',
      fix: `Run \`shieldcortex setup ${flag}\` to wire the hook`,
    };
  };

  return [
    rowFor('Auto-memory: Stop hook', wiredStop, gateStop, '--with-stop-hook', `samples turn % ${samplingTurns} == 0`),
    rowFor('Auto-memory: SessionEnd hook', wiredSessionEnd, gateSessionEnd, '--with-session-end'),
  ];
}

// ── Check 5: Process check ────────────────────────────────
// ── Check: OpenClaw Telegram approval buttons (recommendation) ──
// ShieldCortex / Codex approval prompts render as tappable buttons on Telegram
// only when channels.telegram.capabilities.inlineButtons allows the surface;
// otherwise they fall back to "/approve …" text. Advisory only — ShieldCortex
// never rewrites the host's OpenClaw channel config, it just recommends.
export async function checkOpenClawApprovalButtons(
  cfgPath: string = path.join(os.homedir(), '.openclaw', 'openclaw.json'),
): Promise<CheckResult[]> {
  if (!fs.existsSync(cfgPath)) return [];
  let tg: { enabled?: boolean; capabilities?: { inlineButtons?: string } } | undefined;
  try {
    const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
    tg = cfg?.channels?.telegram;
  } catch {
    return []; // best-effort — never break the doctor on an unparseable host config
  }
  if (!tg || tg.enabled === false) return []; // Telegram not configured
  const scope = tg.capabilities?.inlineButtons;
  if (scope === 'all' || scope === 'dm' || scope === 'group') {
    return [{
      label: 'OpenClaw approval buttons',
      status: 'pass',
      message: `Telegram inline approval buttons enabled (inlineButtons: ${scope})`,
    }];
  }
  return [{
    label: 'OpenClaw approval buttons',
    status: 'info',
    message: `Telegram approval prompts fall back to "/approve" text (inlineButtons: ${scope ?? 'unset → allowlist'})`,
    fix: "Make approvals tappable: set channels.telegram.capabilities.inlineButtons to 'all' (or 'dm'/'group' for a tighter surface) via `openclaw config patch`, then restart the gateway.",
    // MEASURED, not assumed: `openclaw config patch` is refused under an
    // invalid config too (exit 1, "OpenClaw config is invalid"). It was
    // initially left untagged on the theory that a *config* subcommand would be
    // the operator's escape hatch — it is not. Hand-editing the file is.
    needsOpenClawCli: {
      subcommand: 'config',
      fallbackFix: "Make approvals tappable: set channels.telegram.capabilities.inlineButtons to 'all' (or 'dm'/'group') by editing ~/.openclaw/openclaw.json directly — `openclaw config patch` is refused while the config is invalid — then restart the gateway.",
    },
  }];
}

async function checkProcesses(): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const env = detectEnvironment();

  // On headless/OpenClaw-only setups, API/Dashboard are optional
  const isOptional = env.isHeadless || (env.hasOpenClaw && !env.hasClaude && !env.hasVSCode);

  // Check API server on port 3001
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2000);
    const response = await fetch('http://localhost:3001/api/health', { signal: controller.signal });
    clearTimeout(timeout);
    if (response.ok) {
      results.push({ label: 'API server', status: 'pass', message: 'running (port 3001)' });
    } else {
      results.push({
        label: 'API server',
        status: 'warn',
        message: `responding but unhealthy (status ${response.status})`,
        fix: 'Restart with `shieldcortex dashboard`',
      });
    }
  } catch {
    if (isOptional) {
      results.push({
        label: 'API server',
        status: 'info',
        message: 'not running (optional on headless/OpenClaw-only setups)',
      });
    } else {
      results.push({
        label: 'API server',
        status: 'warn',
        message: 'not running',
        fix: 'Run `shieldcortex dashboard` to start the API server',
      });
    }
  }

  // Check dashboard on port 3030
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2000);
    const response = await fetch('http://localhost:3030/', { signal: controller.signal });
    clearTimeout(timeout);
    if (response.ok || response.status === 304) {
      results.push({ label: 'Dashboard', status: 'pass', message: 'running (http://localhost:3030)' });
    } else {
      results.push({
        label: 'Dashboard',
        status: 'warn',
        message: `responding but returned status ${response.status}`,
        fix: 'Restart with `shieldcortex dashboard`',
      });
    }
  } catch {
    if (isOptional) {
      results.push({
        label: 'Dashboard',
        status: 'info',
        message: 'not running (optional on headless/OpenClaw-only setups)',
      });
    } else {
      results.push({
        label: 'Dashboard',
        status: 'warn',
        message: 'not running',
        fix: 'Run `shieldcortex dashboard` to start the dashboard',
      });
    }
  }

  return results;
}

// ── Check 6: Disk usage ───────────────────────────────────
/**
 * The 100 MB safety limit applies to the data portion of `~/.shieldcortex/`
 * — DB, state, audit logs, telemetry. The `models/` subtree (local Review
 * Copilot weights, embedding caches) can legitimately reach hundreds of MB
 * for users who opted into local AI inference, and should not trip the same
 * warning as runaway memory growth. v4.14.3 and earlier counted everything
 * under `~/.shieldcortex/`, producing a false `Disk: at limit!` for any
 * user with a local AI model cached.
 */
/**
 * Best-effort read-only peek at what actually fills the live DB (#110):
 * row counts + stored byte totals for the memories and session_events
 * tables. Returns null on ANY failure (missing file, corrupt/locked DB,
 * missing tables, unreadable engine) — the caller then falls back to the
 * generic remedy text, so this can never break the disk check itself.
 */
interface DbRowConsumers {
  memoriesCount: number;
  memoriesBytes: number;
  sessionEventCount: number;
  sessionEventBytes: number;
  auditCount: number;
  auditBytes: number;
}

function readDbRowConsumers(dbPath: string): DbRowConsumers | null {
  if (!fs.existsSync(dbPath)) return null;
  let db: any = null;
  try {
    const Database = require('better-sqlite3');
    db = new Database(dbPath, { readonly: true });
    const mem = db.prepare(
      'SELECT COUNT(*) AS c, COALESCE(SUM(LENGTH(content)), 0) AS b FROM memories',
    ).get() as { c: number; b: number };
    const se = db.prepare(
      'SELECT COUNT(*) AS c, COALESCE(SUM(LENGTH(payload)), 0) AS b FROM session_events',
    ).get() as { c: number; b: number };

    // defence_audit is the OTHER unbounded-growth table (bounded since Phase
    // 8a, but pre-valve DBs can still be audit-dominated). Approximate its
    // stored bytes by summing the text-bearing columns. Guarded separately:
    // a DB without the table (older install, partial fixture) just reports 0
    // rather than nulling out the whole peek.
    let auditCount = 0;
    let auditBytes = 0;
    try {
      const audit = db.prepare(`
        SELECT COUNT(*) AS c, COALESCE(SUM(
          LENGTH(COALESCE(reason, '')) +
          LENGTH(COALESCE(threat_indicators, '')) +
          LENGTH(COALESCE(blocked_patterns, '')) +
          LENGTH(COALESCE(source_type, '')) +
          LENGTH(COALESCE(source_identifier, ''))
        ), 0) AS b FROM defence_audit
      `).get() as { c: number; b: number };
      auditCount = audit.c;
      auditBytes = audit.b;
    } catch { /* table absent — keep zeros */ }

    return {
      memoriesCount: mem.c,
      memoriesBytes: mem.b,
      sessionEventCount: se.c,
      sessionEventBytes: se.b,
      auditCount,
      auditBytes,
    };
  } catch {
    return null;
  } finally {
    if (db) {
      try { db.close(); } catch { /* ignore */ }
    }
  }
}

export async function checkDiskUsage(scDir: string = getShieldCortexDir(), limitBytes: number = DIRECTORY_BUDGET_BYTES): Promise<CheckResult> {
  const dirProbe = probePath(scDir);
  if (dirProbe.kind === 'denied' || dirProbe.kind === 'error') {
    // "Directory not yet created" is a ✅. An unreadable one is not — this is
    // the same false-clean shape as the Database check, on the same directory
    // (#132).
    return unreadableResult('Disk', scDir, dirProbe);
  }
  if (dirProbe.kind === 'absent') {
    return { label: 'Disk', status: 'pass', message: '0 B / 100 MB limit (directory not yet created)' };
  }

  try {
    let dataSize = 0;
    let modelsSize = 0;

    function walkInto(dir: string, bucket: 'data' | 'models'): void {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        try {
          if (entry.isDirectory()) {
            walkInto(fullPath, bucket);
          } else if (entry.isFile()) {
            const size = fs.statSync(fullPath).size;
            if (bucket === 'models') modelsSize += size;
            else dataSize += size;
          }
        } catch {
          // Skip inaccessible files
        }
      }
    }

    const topLevel = fs.readdirSync(scDir, { withFileTypes: true });
    for (const entry of topLevel) {
      const fullPath = path.join(scDir, entry.name);
      try {
        if (entry.isDirectory()) {
          walkInto(fullPath, entry.name === 'models' ? 'models' : 'data');
        } else if (entry.isFile()) {
          dataSize += fs.statSync(fullPath).size;
        }
      } catch {
        // Skip inaccessible top-level entries
      }
    }

    // Bucket the data so the remedy can name the actual consumer rather than always
    // pointing at prune/dedupe — which only touch the live memory table and cannot
    // reclaim backups, session-capture rows, or logs (the real culprits). (4.45.1)
    let backupsSize = 0;
    let liveDbSize = 0;
    let logsSize = 0;
    const BACKUP_RE = /^memories\.db\.(pre-backfill|empty-live|stub|corrupt|recovery-failed|bak)/;
    const LIVE_DB = new Set(['memories.db', 'memories.db-wal', 'memories.db-shm']);
    const LOG_DIRS = new Set(['logs', 'audit', 'recall-log', 'precompact-log', 'quarantine']);
    const sizeOf = (target: string): number => {
      try {
        const st = fs.statSync(target);
        if (st.isFile()) return st.size;
        let total = 0;
        for (const e of fs.readdirSync(target, { withFileTypes: true })) total += sizeOf(path.join(target, e.name));
        return total;
      } catch {
        return 0;
      }
    };
    for (const entry of fs.readdirSync(scDir, { withFileTypes: true })) {
      const fp = path.join(scDir, entry.name);
      if (entry.isFile() && BACKUP_RE.test(entry.name)) backupsSize += sizeOf(fp);
      else if (entry.isFile() && LIVE_DB.has(entry.name)) liveDbSize += sizeOf(fp);
      else if (entry.isDirectory() && LOG_DIRS.has(entry.name)) logsSize += sizeOf(fp);
    }

    // #153: a safety backup does NOT spend the memory-system budget.
    //
    // The budget answers "is the memory system's footprint under control?".
    // A rollback copy taken before a destructive repair, pruned to at most one,
    // is under control by construction — counting it produced a FAILURE an
    // operator could only clear by deleting their own rollback point, caused by
    // an operation this same tool had just recommended (Edith, 1 Aug 2026:
    // 48.9 MB DB + one 48.9 MB copy = 98.8/100, "at limit!").
    //
    // Cached models are already exempted and reported separately for exactly
    // this reason. Backups now follow that precedent: still measured, still
    // shown, no longer able to deadlock the thing that creates them.
    dataSize -= backupsSize;

    const limit = limitBytes; // 100 MB by default; applies to the data portion only
    const limitMb = Math.round(limit / (1024 * 1024));
    const pct = (dataSize / limit) * 100;
    const dataStr = `${formatBytes(dataSize)} / ${limitMb} MB limit`;
    const modelsStr = modelsSize > 0 ? ` + ${formatBytes(modelsSize)} models` : '';
    const backupsStr = backupsSize > 0 ? ` + ${formatBytes(backupsSize)} backups` : '';
    const breakdown = `DB ${formatBytes(liveDbSize)} · backups ${formatBytes(backupsSize)} · logs ${formatBytes(logsSize)}`;

    const remedy = (): string => {
      // NOTE: backups no longer count toward the budget (#153), so they can no
      // longer be the cause of an overage and must not be blamed for one. The
      // old first branch here sent operators to delete their own rollback point
      // — and, when that did not help, to move our files out of our own
      // directory. Both were treating a symptom of the accounting being wrong.
      if (liveDbSize > limit * 0.5) {
        // #110 signature: a big DB whose memories table is tiny — the bulk is
        // session-capture rows. Live incident (Edith, 2026-07-21): 79.6 MB DB,
        // 117 memories, session_events 62.8 MB (79% of the file); both
        // previously suggested fixes (vacuum — 0.0 MB free pages — and
        // memories prune) were no-ops. Best-effort peek inside the DB to name
        // the actual consumer; falls through to the generic remedy when the
        // DB can't be read.
        //
        // Review hardening: only blame session capture when its payload
        // GENUINELY dominates — more than 40% of the live DB file (Edith's
        // signature was 79%) AND more than the defence_audit bytes. A merely
        // "bigger than the memories table" comparison misattributed
        // audit-dominated DBs and recommended a no-op sessions prune.
        const consumers = readDbRowConsumers(path.join(scDir, 'memories.db'));
        if (
          consumers &&
          consumers.sessionEventCount > 0 &&
          consumers.sessionEventBytes > liveDbSize * 0.4 &&
          consumers.sessionEventBytes > consumers.auditBytes
        ) {
          return `The database is ${formatBytes(liveDbSize)} but the memories table holds only ${consumers.memoriesCount} memor${consumers.memoriesCount === 1 ? 'y' : 'ies'} — the bulk is session-capture rows (session_events: ${consumers.sessionEventCount} rows, ${formatBytes(consumers.sessionEventBytes)} of payload), which memories prune/dedupe and vacuum alone can't shrink. Run \`shieldcortex sessions prune --execute\` (deletes events older than 30 days; --days N to adjust), then \`shieldcortex vacuum\` to reclaim the freed pages on disk.`;
        }
        if (consumers && consumers.auditBytes > consumers.sessionEventBytes) {
          // Audit-dominated: the worker's Phase 8a audit retention (90d + row
          // cap) bounds this over time; don't send the user to a sessions
          // prune that would be a no-op.
          return `The database is ${formatBytes(liveDbSize)} — the bulk is defence-audit rows (defence_audit: ${consumers.auditCount} rows, ~${formatBytes(consumers.auditBytes)}), which the background worker's audit retention trims over time (90-day window + row cap). Reclaim free space with \`shieldcortex vacuum\` (compacts the DB in place via the bundled engine — no sqlite3 CLI needed); if it is genuinely the memory table, \`shieldcortex memories prune --execute\`.`;
        }
        return `The database is ${formatBytes(liveDbSize)} — usually session capture + audit rows, which prune/dedupe can't shrink. If it is session capture, \`shieldcortex sessions prune --execute\` deletes events older than 30 days. Reclaim free space with \`shieldcortex vacuum\` (compacts the DB in place via the bundled engine — no sqlite3 CLI needed); if it is genuinely the memory table, \`shieldcortex memories prune --execute\`.`;
      }
      if (logsSize > limit * 0.2) {
        return `${formatBytes(logsSize)} is audit/log files — safe to rotate or clear under ~/.shieldcortex/{logs,audit}/.`;
      }
      return 'Run `shieldcortex memories prune --execute` or `memories dedupe --execute` to trim the live memory table.';
    };

    if (pct >= 95) {
      return {
        label: 'Disk',
        status: 'fail',
        message: `${dataStr}${backupsStr}${modelsStr} — at limit! (${breakdown})`,
        fix: remedy(),
      };
    } else if (pct >= 80) {
      return {
        label: 'Disk',
        status: 'warn',
        message: `${dataStr}${backupsStr}${modelsStr} — approaching limit (${breakdown})`,
        fix: remedy(),
      };
    } else {
      return { label: 'Disk', status: 'pass', message: `${dataStr}${backupsStr}${modelsStr}` };
    }
  } catch (err: unknown) {
    // A directory that stats but cannot be listed (mode 700, another owner) is
    // a permission fault, not an inconclusive check.
    const denied = permissionFailure('Disk', scDir, err);
    if (denied) return denied;
    const msg = err instanceof Error ? err.message : String(err);
    return { label: 'Disk', status: 'warn', message: `check failed — ${msg}` };
  }
}

// ── Check 7: Lock file ───────────────────────────────────
//
// A lock is stale only if its recorded PID is no longer running. Pure mtime age
// is unreliable: a long-running daemon (e.g. `shieldcortex dashboard` started
// at boot) holds the same lock for days, and flagging it stale tells the user
// to delete a file that is still in active use.
export async function checkLockFile(scDir: string = getShieldCortexDir()): Promise<CheckResult> {

  const dirProbe = probePath(scDir);
  if (dirProbe.kind === 'denied' || dirProbe.kind === 'error') {
    return unreadableResult('Lock', scDir, dirProbe, { fix: false });
  }
  if (dirProbe.kind === 'absent') {
    return { label: 'Lock', status: 'pass', message: 'clean' };
  }

  try {
    const lockFiles: string[] = [];

    const entries = fs.readdirSync(scDir);
    for (const entry of entries) {
      if (entry.endsWith('.lock')) {
        lockFiles.push(entry);
      }
    }

    if (lockFiles.length === 0) {
      return { label: 'Lock', status: 'pass', message: 'clean' };
    }

    const stale: string[] = [];
    const active: string[] = [];
    // Fallback only used when the lock file is unparseable or has no PID.
    const oneDayAgo = Date.now() - 24 * 60 * 60 * 1000;

    for (const lockFile of lockFiles) {
      const lockPath = path.join(scDir, lockFile);

      let pid: number | null = null;
      try {
        const parsed = JSON.parse(fs.readFileSync(lockPath, 'utf-8')) as { pid?: unknown };
        if (typeof parsed.pid === 'number' && Number.isFinite(parsed.pid)) {
          pid = parsed.pid;
        }
      } catch {
        // Unparseable lock — fall through to mtime fallback below.
      }

      if (pid !== null) {
        try {
          process.kill(pid, 0);
          active.push(lockFile);
        } catch (err) {
          if ((err as NodeJS.ErrnoException).code === 'ESRCH') {
            stale.push(lockFile);
          } else {
            // EPERM = process exists, owned by another user. Treat as active.
            active.push(lockFile);
          }
        }
      } else {
        const stat = fs.statSync(lockPath);
        if (stat.mtimeMs < oneDayAgo) {
          stale.push(lockFile);
        } else {
          active.push(lockFile);
        }
      }
    }

    if (stale.length > 0) {
      return {
        label: 'Lock',
        status: 'warn',
        message: `stale lock file found: ${stale.join(', ')}`,
        fix: `Remove ${stale.map(f => `\`~/.shieldcortex/${f}\``).join(', ')}`,
      };
    }

    return { label: 'Lock', status: 'pass', message: `clean (${active.length} active lock${active.length !== 1 ? 's' : ''})` };
  } catch (err: unknown) {
    const denied = permissionFailure('Lock', scDir, err, { fix: false });
    if (denied) return denied;
    const msg = err instanceof Error ? err.message : String(err);
    return { label: 'Lock', status: 'warn', message: `check failed — ${msg}` };
  }
}

// ── Check 7.4: OpenClaw config validity (#221) ───────────
/**
 * Runs BEFORE every OpenClaw check, because it is the prerequisite for all of
 * their remedies. An invalid OpenClaw config makes `plugins` and `skills`
 * refuse — reporting "Unknown command", never naming the config — so the seven
 * checks below produce accurate findings with unfollowable advice.
 *
 * Returns rather than throws on every path: the runDoctor catch renders
 * `check crashed — …` with NO fix line, which is the same unactionable outcome
 * this check exists to remove.
 */
export async function checkOpenClawConfigValid(
  home: string = os.homedir(),
  deps: ValidateDeps = {},
): Promise<CheckResult> {
  const label = OPENCLAW_CONFIG_LABEL;
  let verdict: OpenClawConfigVerdict;
  try {
    verdict = validateOpenClawConfig(home, deps);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { label, status: 'info', message: `not checked — ${msg}` };
  }

  switch (verdict.state) {
    case 'valid':
      return { label, status: 'pass', message: 'validates — OpenClaw accepts plugins/skills commands' };
    case 'indeterminate':
      return { label, status: 'info', message: `not checked — ${verdict.reason}` };
    case 'invalid':
      return {
        label,
        status: 'fail',
        openClawCliBlocked: true,
        message:
          'OpenClaw REFUSES every `plugins` and `skills` command until this validates — it reports '
          + 'them as "Unknown command", so remediation looks like it ran and silently did nothing (#221). '
          + `OpenClaw says:\n      ${verdict.detail.join('\n      ')}`,
        fix:
          'Fix the OpenClaw config FIRST — nothing else below can run until it validates: '
          + '`openclaw doctor --fix` (or edit the keys quoted above), confirm with '
          + '`openclaw config validate`, then re-run `shieldcortex doctor`.',
      };
  }
}

// ── Check 7.5: OpenClaw residue (orphans only) ───────────
async function checkOpenClawResidue(): Promise<CheckResult> {
  const env = detectEnvironment();
  if (!env.hasOpenClaw) {
    return { label: 'OpenClaw residue', status: 'info', message: 'skipped (OpenClaw not detected)' };
  }

  try {
    const { scanForOrphans } = await import('../setup/deep-clean.js');
    const report = scanForOrphans();

    if (report.orphanCount === 0) {
      // Legitimate install state is not flagged — a fresh `openclaw install`
      // writes plugin config entries that SHOULD be there, and those are not
      // reported as residue.
      const summary = report.installState.pluginInstalled && report.installState.hookInstalled
        ? 'clean (plugin + hook installed, config aligned)'
        : report.installState.pluginInstalled
          ? 'clean (plugin installed, hook absent but non-orphaned)'
          : report.installState.hookInstalled
            ? 'clean (hook installed, plugin absent but non-orphaned)'
            : 'clean (no ShieldCortex artefacts detected)';
      return { label: 'OpenClaw residue', status: 'pass', message: summary };
    }

    const first = report.paths.slice(0, 3).map((p) => p.description).join('; ');
    const suffix = report.paths.length > 3 ? ` (+${report.paths.length - 3} more)` : '';

    return {
      label: 'OpenClaw residue',
      status: 'warn',
      message: `${report.orphanCount} orphan${report.orphanCount === 1 ? '' : 's'} — ${first}${suffix}`,
      fix: 'Run `shieldcortex uninstall --deep --confirm` to purge, or reinstall with `shieldcortex openclaw install`',
      // Only the reinstall half needs OpenClaw; the purge is pure filesystem.
      needsOpenClawCli: {
        subcommand: 'plugins',
        fallbackFix: 'Run `shieldcortex uninstall --deep --confirm` to purge the residue (pure filesystem — this half still works). Reinstalling needs a valid OpenClaw config first.',
      },
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { label: 'OpenClaw residue', status: 'warn', message: `check failed — ${msg}` };
  }
}

/**
 * Detects a bare/stale `shieldcortex` package sitting in OpenClaw's plugin
 * `node_modules`. Background: the supported OpenClaw plugin is the dedicated
 * package `@drakon-systems/shieldcortex-realtime` (see
 * docs/openclaw-integration.md and src/setup/openclaw.ts — the install runs
 * `openclaw plugins install @drakon-systems/shieldcortex-realtime`). The
 * *main* `shieldcortex` package still carries an `openclaw` key in its
 * package.json, so if a stale/linked/transitive copy lands in
 * `~/.openclaw/npm/node_modules/shieldcortex`, OpenClaw's npm auto-discovery
 * picks it up and tries to load `openclaw.extensions[0]` relative to it.
 *
 * On Jarvis (2026-05-15) such a copy crash-looped the gateway and had to be
 * diagnosed by hand over SSH. The exact crash exception is still under
 * investigation, so this check does NOT claim to identify it — it surfaces
 * the *confirmed-anomalous filesystem state* that preceded it:
 *
 *   - FAIL: bare `shieldcortex` present AND its declared extension entry is
 *     missing on disk (stale/unbuilt — OpenClaw cannot load it).
 *   - WARN: bare `shieldcortex` present with the entry intact (still the
 *     wrong package in the wrong place; the realtime plugin is supported).
 *
 * Cannot false-positive on a healthy install: those carry
 * `@drakon-systems/shieldcortex-realtime`, never bare `shieldcortex`, here.
 *
 * `npmModulesDir` is injectable for tests; defaults to
 * `~/.openclaw/npm/node_modules`.
 */
export async function checkOpenClawPluginPackage(
  npmModulesDir: string = path.join(os.homedir(), '.openclaw', 'npm', 'node_modules'),
): Promise<CheckResult> {
  const label = 'OpenClaw plugin pkg';

  if (!fs.existsSync(npmModulesDir)) {
    return { label, status: 'info', message: 'skipped (OpenClaw plugin dir not present)' };
  }

  const barePkgDir = path.join(npmModulesDir, 'shieldcortex');
  const barePkgJson = path.join(barePkgDir, 'package.json');

  if (!fs.existsSync(barePkgJson)) {
    return {
      label,
      status: 'pass',
      message: 'clean (no misplaced bare `shieldcortex`; realtime plugin is the supported path)',
    };
  }

  // A bare `shieldcortex` here is never the supported state. Decide severity
  // by whether its declared OpenClaw extension entry actually exists.
  let extEntry: string | null = null;
  try {
    const pkg = JSON.parse(fs.readFileSync(barePkgJson, 'utf-8')) as {
      openclaw?: { extensions?: unknown };
    };
    const exts = pkg.openclaw?.extensions;
    if (Array.isArray(exts) && typeof exts[0] === 'string') {
      extEntry = exts[0];
    }
  } catch {
    return {
      label,
      status: 'warn',
      message:
        'bare `shieldcortex` in OpenClaw plugin dir has an unreadable package.json — OpenClaw may mis-discover it',
      fix: `Remove ${barePkgDir.replace(os.homedir(), '~')} — the supported plugin is @drakon-systems/shieldcortex-realtime`,
    };
  }

  if (extEntry) {
    const resolved = path.resolve(barePkgDir, extEntry);
    if (!fs.existsSync(resolved)) {
      return {
        label,
        status: 'fail',
        message:
          `bare \`shieldcortex\` in OpenClaw plugin dir declares extension \`${extEntry}\` ` +
          `but ${resolved.replace(os.homedir(), '~')} is missing — OpenClaw cannot load this ` +
          `plugin. This is the stale state behind the gateway crash-loop incident.`,
        fix:
          `Remove ${barePkgDir.replace(os.homedir(), '~')} then reinstall the supported plugin: ` +
          `\`openclaw plugins install @drakon-systems/shieldcortex-realtime\``,
        needsOpenClawCli: {
          subcommand: 'plugins',
          fallbackFix:
            `Remove ${barePkgDir.replace(os.homedir(), '~')} (pure filesystem — this half still works). ` +
            `Reinstalling the supported plugin needs a valid OpenClaw config first.`,
        },
      };
    }
  }

  // Visibility-first model (v4.21.2+): OpenClaw discovers bare packages via
  // TWO independent vectors — `openclaw.extensions` in package.json AND a
  // root `openclaw.plugin.json`. If EITHER is present, OpenClaw registers
  // the bare copy under `pluginId: shieldcortex-realtime` — same id as the
  // dedicated `@drakon-systems/shieldcortex-realtime` plugin — and emits
  // `duplicate plugin id detected; global plugin will be overridden by
  // global plugin` on every session. v4.21.1 closed the second vector by
  // dropping the root manifest from the bare tarball; v4.20.0 closed the
  // first by dropping `openclaw.extensions`. A v4.21.1+ bare copy has
  // neither vector — it's fully invisible to discovery.
  //
  // INFO when the bare is invisible (no discovery vectors). WARN when any
  // vector is present and OpenClaw will register a duplicate — version
  // alignment doesn't help (both copies share the pluginId regardless).
  const bareVersion = readPkgVersion(barePkgJson);
  const realtimePkgJson = path.join(
    npmModulesDir,
    '@drakon-systems',
    'shieldcortex-realtime',
    'package.json',
  );
  const realtimeVersion = readPkgVersion(realtimePkgJson);
  const realtimePeerRange = readShieldcortexPeerRange(realtimePkgJson);
  const rootManifestPresent = fs.existsSync(path.join(barePkgDir, 'openclaw.plugin.json'));
  const bareDiscoverable = extEntry !== null || rootManifestPresent;

  const inRange =
    bareVersion !== null &&
    realtimePeerRange !== null &&
    semver.satisfies(bareVersion, realtimePeerRange);

  if (!bareDiscoverable) {
    // Post-v4.21.1 architecture: bare exists but has zero discovery vectors.
    // OpenClaw cannot see it; the duplicate-plugin-id warning cannot fire.
    if (realtimeVersion !== null) {
      const rangeNote = realtimePeerRange ? ` (range ${realtimePeerRange})` : '';
      const peerNote = inRange
        ? ''
        : ` — note: bare version does not satisfy realtime's peer range, but ` +
          `realtime imports resolve to this copy so behaviour may differ from intent`;
      return {
        label,
        status: 'info',
        message:
          `bare \`shieldcortex@${bareVersion ?? '?'}\` invisible to OpenClaw discovery ` +
          `(no \`openclaw.extensions\` field, no root \`openclaw.plugin.json\`); ` +
          `peer of @drakon-systems/shieldcortex-realtime@${realtimeVersion}${rangeNote}` +
          peerNote,
      };
    }
    return {
      label,
      status: 'info',
      message:
        `bare \`shieldcortex@${bareVersion ?? '?'}\` invisible to OpenClaw discovery ` +
        `(no \`openclaw.extensions\`, no root manifest); realtime sibling not present — ` +
        `harmless leftover, safe to remove`,
    };
  }

  // bareDiscoverable === true: OpenClaw will pick this up and collide with
  // the dedicated realtime plugin. Always WARN; explain which vector(s).
  const vectors: string[] = [];
  if (extEntry !== null) vectors.push('`openclaw.extensions` declared in package.json');
  if (rootManifestPresent) vectors.push('root `openclaw.plugin.json` present');
  const vectorList = vectors.join(' and ');

  if (realtimeVersion !== null) {
    const rangeNote = realtimePeerRange
      ? `; realtime peer range ${realtimePeerRange}` +
        (inRange ? ' satisfied' : ' NOT satisfied')
      : '';
    return {
      label,
      status: 'warn',
      message:
        `bare \`shieldcortex@${bareVersion ?? '?'}\` is discoverable by OpenClaw ` +
        `(${vectorList}) — will collide with ` +
        `@drakon-systems/shieldcortex-realtime@${realtimeVersion} on every session and ` +
        `emit \`duplicate plugin id detected\`${rangeNote}`,
      fix:
        `Bump the bare copy to v4.21.1 or later — v4.21.1+ ships without any OpenClaw ` +
        `discovery vectors: \`cd ~/.openclaw/npm && npm install shieldcortex@latest && shieldcortex doctor\``,
    };
  }

  // Bare discoverable, no realtime sibling — the original "misplaced bare" case.
  return {
    label,
    status: 'warn',
    message:
      `bare \`shieldcortex@${bareVersion ?? '?'}\` present in OpenClaw plugin dir ` +
      `with active discovery vector (${vectorList}); the supported package is ` +
      `@drakon-systems/shieldcortex-realtime`,
    fix:
      `Remove ${barePkgDir.replace(os.homedir(), '~')} (the dedicated realtime plugin handles ` +
      `OpenClaw integration; the bare main package should not live here)`,
  };
}

/**
 * Detects duplicate `shieldcortex-realtime` plugin installs under
 * `~/.openclaw/extensions/` and `~/.openclaw/hooks/`. OpenClaw's plugin
 * scanner walks both directories and registers every `openclaw.plugin.json`
 * it finds, regardless of `.trash-*` or `*.disabled-*` naming conventions
 * that suggest the directory has been retired. When the canonical npm
 * install at `~/.openclaw/npm/node_modules/@drakon-systems/shieldcortex-realtime/`
 * coexists with any of these legacy locations, OpenClaw emits
 * `duplicate plugin id detected; global plugin will be overridden by global
 * plugin` on every session.
 *
 * Field background (2026-05-27, all fleet boxes after v4.25.1 upgrade):
 *   - edith had `.trash-shieldcortex-realtime.20260527-093144/` in both
 *     extensions/ and hooks/, plus an older `shieldcortex-realtime.disabled-*`
 *     left from a tars-era cleanup. None of them excluded by OpenClaw scan.
 *   - jarvis + case had a live legacy install at
 *     `~/.openclaw/extensions/shieldcortex-realtime/` alongside the newer
 *     npm install — OpenClaw resolved to the npm one but kept warning
 *     about the legacy directory as a duplicate.
 *
 * These weren't created by ShieldCortex's installer (no `.trash-` pattern
 * appears in the codebase) — they appear to come from OpenClaw's own
 * plugin upgrade flow soft-trashing the old install before replacing it.
 * This check surfaces them so operators can clean up; the actual fix is
 * `rm -rf` on each path the check reports.
 */
export async function checkOpenClawDuplicateInstalls(
  openclawDir: string = path.join(os.homedir(), '.openclaw'),
): Promise<CheckResult> {
  const label = 'OpenClaw dup installs';

  if (!fs.existsSync(openclawDir)) {
    return { label, status: 'info', message: 'skipped (OpenClaw not detected)' };
  }

  // The canonical install path post-v4.21.1 is the npm-managed location.
  const canonicalPath = path.join(
    openclawDir,
    'npm',
    'node_modules',
    '@drakon-systems',
    'shieldcortex-realtime',
  );
  const canonicalPresent = fs.existsSync(canonicalPath);

  // Scan extensions/ and hooks/ for ANY directory whose name contains the
  // plugin id — catches `shieldcortex-realtime/` (live legacy),
  // `.trash-shieldcortex-realtime.<ts>/` (OpenClaw upgrade leftover), and
  // `shieldcortex-realtime.disabled-<host>-<ts>/` (manual disable).
  const dupCandidates: string[] = [];
  for (const subdir of ['extensions', 'hooks']) {
    const dir = path.join(openclawDir, subdir);
    if (!fs.existsSync(dir)) continue;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (!entry.name.includes('shieldcortex-realtime')) continue;
      // The manifest must exist for OpenClaw to treat it as a discoverable
      // plugin. If it doesn't, the dir is harmless (no scan hit).
      const manifest = path.join(dir, entry.name, 'openclaw.plugin.json');
      if (fs.existsSync(manifest)) {
        dupCandidates.push(path.join(dir, entry.name));
      }
    }
  }

  if (dupCandidates.length === 0) {
    return {
      label,
      status: 'pass',
      message: 'clean (no duplicate shieldcortex-realtime installs in extensions/ or hooks/)',
    };
  }

  // Format paths for display + fix instructions.
  const home = os.homedir();
  const displayPaths = dupCandidates.map((p) => p.replace(home, '~'));
  const hooksDir = path.join(openclawDir, 'hooks');

  // A duplicate under `~/.openclaw/hooks/<id>/` is the *sticky* case. Field
  // experience (jarvis, 2026-05-27): plain `rm -rf` on the hooks-dir copy
  // doesn't stick — `openclaw plugins update` reads internal hook-pack
  // tracking state (across multiple config keys; `hooks.internal.installs`
  // is one of several) and rebuilds the hook-pack dir at the recorded
  // legacy version. The only reliable purge is a full
  // `openclaw plugins uninstall <id>` + `plugins install <id>@latest`
  // round-trip, which clears every tracking record at once.
  //
  // Duplicates under `~/.openclaw/extensions/` (including `.trash-*` and
  // `*.disabled-*` legacy paths) DON'T have this stickiness — a one-shot
  // `rm -rf` is sufficient.
  const hasHooksDup = dupCandidates.some((p) => p.startsWith(hooksDir + path.sep));
  const rmCmd = dupCandidates.map((p) => `rm -rf ${p.replace(home, '~')}`).join(' && ');

  if (!canonicalPresent) {
    // Legacy install exists but no canonical npm install. The repair
    // command knows how to handle this case too — it'll reinstall via
    // npm + clean the legacy paths in one step.
    return {
      label,
      status: 'warn',
      message:
        `${dupCandidates.length} legacy install location(s) under ~/.openclaw/, no canonical ` +
        `~/.openclaw/npm/.../@drakon-systems/shieldcortex-realtime/: ${displayPaths.join(', ')}`,
      fix:
        `Run \`shieldcortex openclaw repair\` to safely reinstall via the canonical path ` +
        `and clean up the legacy locations (preserves your OpenClaw plugin config).`,
      // `openclaw repair` → repairOpenClawPlugin → `plugins enable` +
      // `plugins install --force`. No filesystem-only half to fall back to.
      needsOpenClawCli: { subcommand: 'plugins' },
    };
  }

  if (hasHooksDup) {
    // Sticky case — `rm -rf` alone reverts on next `plugins update` because
    // OpenClaw's hook-pack tracking re-creates the hooks/ copy at a pinned
    // legacy version. `shieldcortex openclaw repair` runs the full
    // uninstall+reinstall round-trip that clears every tracking record, AND
    // snapshots+restores the customer's plugin config (interceptor settings,
    // cloud API key, allowlist) across the round-trip.
    return {
      label,
      status: 'warn',
      message:
        `${dupCandidates.length} duplicate shieldcortex-realtime install(s) alongside the canonical ` +
        `npm install — OpenClaw emits \`duplicate plugin id detected\` every session: ` +
        displayPaths.join(', ') +
        ` (includes a ~/.openclaw/hooks/ duplicate — sticky)`,
      fix:
        `Run \`shieldcortex openclaw repair\` — it does the safe uninstall+reinstall ` +
        `round-trip needed to clear OpenClaw's sticky hook-pack tracking, while preserving ` +
        `your OpenClaw plugin config. (Plain \`rm -rf\` on the hooks/ copy reverts on the ` +
        `next \`plugins update\`.)`,
      // The worst site to leave unguarded: its own text tells the operator the
      // filesystem escape hatch does NOT work, so a blocked host is left with
      // zero followable action.
      needsOpenClawCli: { subcommand: 'plugins' },
    };
  }

  // Simple case — no hooks-dir copy, just extensions/ leftovers. The repair
  // command handles this too via a plain `rm -rf` path; offer it as the
  // single canonical fix surface for any dup state.
  return {
    label,
    status: 'warn',
    message:
      `${dupCandidates.length} duplicate shieldcortex-realtime install(s) alongside the canonical ` +
      `npm install — OpenClaw emits \`duplicate plugin id detected\` every session: ` +
      displayPaths.join(', '),
    fix:
      `Run \`shieldcortex openclaw repair\` (or remove manually: ${rmCmd}) and restart OpenClaw. ` +
      `The canonical npm install at ~/.openclaw/npm/ is the supported location.`,
    needsOpenClawCli: {
      subcommand: 'plugins',
      // Non-sticky case, so the manual removal genuinely works on its own.
      fallbackFix: `Remove manually: ${rmCmd}, then restart OpenClaw. The canonical npm install at ~/.openclaw/npm/ is the supported location.`,
    },
  };
}

// ── Check: Defence canary (#48) ──────────────────────
/**
 * Defence canary — synthetic probe that proves the firewall layer is alive
 * and catching known-malicious markers. Without this check, the layer runs
 * silently and "no warnings" is indistinguishable from "no protection."
 * Field feedback (edith, jarvis, 2026-05-24) called the layer "unprovable
 * from inside the session." This makes it provable.
 *
 * v4.22.1: calls `detectInstructions()` directly instead of routing through
 * the full `runDefencePipeline()`. The pipeline writes to the events table
 * which requires the DB to be initialised — in the doctor's run order the
 * canary fired before the DB connection was established, leaking a
 * `[Events] Failed to persist event` stack trace to stderr on every cold
 * start. The narrow probe gives the same signal without the side effects:
 * no DB dependency, no audit-log pollution, no event persistence, faster.
 *
 * Safe by construction: the marker `__SHIELDCORTEX_CANARY_PROBE_v1__` is
 * intentionally non-natural (double-underscore + internal version tag) and
 * can never collide with legitimate content. Pattern is registered in
 * src/defence/firewall/instruction-detector.ts under the `defence_canary`
 * group; that's the surface this check probes.
 */
export async function checkDefenceCanary(): Promise<CheckResult> {
  const label = 'Defence canary';
  const canaryPayload =
    'benign-context-prefix __SHIELDCORTEX_CANARY_PROBE_v1__ benign-context-suffix';
  const start = Date.now();
  try {
    const { detectInstructions } = await import('../defence/firewall/instruction-detector.js');
    const result = detectInstructions(canaryPayload);
    const elapsed = Date.now() - start;
    const caught = result.detected && result.patterns.includes('defence_canary');
    if (caught) {
      return {
        label,
        status: 'pass',
        message: `caught (${elapsed}ms, pattern: defence_canary)`,
      };
    }
    return {
      label,
      status: 'fail',
      message:
        `canary payload was NOT caught by the firewall (${elapsed}ms) — instruction ` +
        `detector is not flagging known-malicious markers. This is a positive failure: ` +
        `the layer should always catch this synthetic probe.`,
      fix:
        `Check the \`defence_canary\` pattern group in ` +
        `src/defence/firewall/instruction-detector.ts; rebuild with \`npm run build:ts\`. ` +
        `If the pattern is registered and the canary still slips, the firewall layer is bypassed.`,
    };
  } catch (err) {
    return {
      label,
      status: 'warn',
      message:
        `canary probe could not run (${(err as Error).message}) — firewall layer status unknown`,
    };
  }
}

/**
 * Action Guard check (issue #94). Doctor previously had NO Action Guard check
 * at all — the "Defence canary" above probes the firewall's instruction
 * detector, a different layer entirely. This check:
 *
 *   1. Runs the REAL `evaluateToolCall` against three in-process verdict
 *      probes: a catastrophic shape must block, a dangerous shape must gate,
 *      a benign shape must allow. A wrong verdict is a hard fail — the guard
 *      logic itself is broken on this box's build.
 *   2. Resolves the box's EFFECTIVE guard config (#209): top-level
 *      `actionGuard` governs both surfaces, `interceptor.actionGuard` is a
 *      deprecated per-key gap-fill alias (top-level wins on conflict). Warns
 *      when the effective posture is opted down (naming the exact key that
 *      set it), when the alias is present at all, and when the alias holds
 *      conflicting — and therefore ignored — values.
 *
 * Honest labelling: this is an in-process check of guard logic + config. It
 * does NOT prove the OpenClaw interceptor or the PreToolUse hook is actually
 * wired into a live agent loop — that proof stays with the consent-gated live
 * canary (`SHIELDCORTEX_ALLOW_GATEWAY_CANARY=1` + the openclaw self-check).
 */
export async function checkActionGuard(): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const label = 'Action guard';

  // 1. Verdict probes through the real evaluator.
  try {
    const { evaluateToolCall } = await import('../defence/iron-dome/tool-action-guard.js');
    const nonce = Math.random().toString(36).slice(2, 10);
    const probes: Array<{ name: string; command: string; expect: string }> = [
      // Home-anchored, not /tmp (#170): a /tmp delete is workspace-confined and
      // ALLOWED by design since the target-aware precision pass, so a /tmp
      // probe would report the guard broken for doing its job. `~` can expand
      // anywhere, which the confinement check permanently refuses.
      { name: 'catastrophic→block', command: `rm -rf ~/sc-doctor-${nonce}`, expect: 'block' },
      { name: 'dangerous→approval', command: 'crontab -e', expect: 'require_approval' },
      { name: 'benign→allow', command: 'ls -la', expect: 'allow' },
    ];
    const start = Date.now();
    const wrong: string[] = [];
    for (const p of probes) {
      const v = evaluateToolCall('Bash', { command: p.command });
      if (v.decision !== p.expect) wrong.push(`${p.name} got '${v.decision}'`);
    }
    const elapsed = Date.now() - start;
    if (wrong.length === 0) {
      results.push({
        label,
        status: 'pass',
        message:
          `verdict probes 3/3 (catastrophic→block, dangerous→approval, benign→allow) in ${elapsed}ms — ` +
          `in-process check of guard logic + this box's config; wiring proof needs the consent-gated live canary ` +
          `(${LIVE_CANARY_COMMAND})`,
      });
    } else {
      results.push({
        label,
        status: 'fail',
        message:
          `verdict probes FAILED: ${wrong.join('; ')} — the guard evaluator on this build returns wrong ` +
          `decisions for canonical shapes. This is a positive failure: these probes must always verdict correctly.`,
        fix: 'Rebuild with `npm run build:ts`; if probes still fail, the installed dist is corrupt — run `shieldcortex repair`.',
      });
    }
  } catch (err) {
    results.push({
      label,
      status: 'fail',
      message: `guard evaluator could not load (${(err as Error).message}) — Action Guard status unknown`,
      fix: 'Run `shieldcortex repair` to rebuild the installed dist.',
    });
    return results;
  }

  // 2. Config resolution (#209). Both surfaces now resolve ONE effective
  //    config: top-level `actionGuard` governs, `interceptor.actionGuard` is
  //    a deprecated per-key gap-fill alias, top-level wins on conflict. This
  //    check mirrors that merge (the hook, the plugin and this file are three
  //    build units that cannot share an import — keep them in step by hand),
  //    evaluates posture warnings against the EFFECTIVE config with per-key
  //    provenance, and flags the alias itself so operators migrate off it.
  try {
    // getConfigDir (not getShieldCortexDir): the posture must be judged
    // against the SAME file the `shieldcortex config` setters write and the
    // runtime accessors read — including the SHIELDCORTEX_CONFIG_DIR override.
    const configPath = path.join(getConfigDir(), 'config.json');
    const raw = fs.existsSync(configPath) ? JSON.parse(fs.readFileSync(configPath, 'utf-8')) : {};
    const isBlock = (v: unknown): v is Record<string, unknown> =>
      !!v && typeof v === 'object' && !Array.isArray(v);
    const top = isBlock(raw?.actionGuard) ? (raw.actionGuard as Record<string, unknown>) : null;
    const alias = isBlock(raw?.interceptor?.actionGuard)
      ? (raw.interceptor.actionGuard as Record<string, unknown>)
      : null;
    const merged = { ...(alias ?? {}), ...(top ?? {}) };
    const effective = { enabled: merged.enabled !== false, enforce: merged.enforce !== false };
    // Which key set this value — top-level when it has the key, else the alias.
    const provenance = (k: string) =>
      top && k in top ? `actionGuard.${k}` : `interceptor.actionGuard.${k}`;

    if (!effective.enabled) {
      results.push({
        label: `${label} config`,
        status: 'warn',
        message: `Action Guard is disabled in config (\`${provenance('enabled')}: false\`) — tool calls are not gated on either surface`,
        fix: 'Run `shieldcortex config --action-guard-enable` to restore gating — the CLI writes a signed config; hand-editing config.json invalidates its integrity signature.',
      });
    } else if (!effective.enforce) {
      results.push({
        label: `${label} config`,
        status: 'warn',
        message: `Action Guard runs in warn-mode (\`${provenance('enforce')}: false\`) on both surfaces — dangerous ops log but are not gated (catastrophic still blocks)`,
        fix: 'Run `shieldcortex config --action-guard-enforce` to gate dangerous ops — the CLI writes a signed config; hand-editing config.json invalidates its integrity signature.',
      });
    }

    // #242 Defect B: enforce-on + no notify channel is how unattended denials
    // vanished for eight days while lastRunStatus stayed ok.
    // OpenClaw lastRunStatus is not ours to write (#242 Defect A / #260).
    //
    // NOTE (#354, 30 Aug 2026): this comment used to end "WARN, never fail — a
    // missing webhook is a misconfiguration, not a broken evaluator." That rule
    // is DEAD and must not be restored. It was the reason doctor emitted advice
    // instead of a failure while 312 denials went undelivered on one host over
    // seven days. The distinction that survives is not misconfig-vs-evaluator,
    // it is honest-vs-lying: notify that says `enabled: true` while holding no
    // denial-capable sink claims a delivery path it does not have, and it makes
    // that claim to the operator who is deciding whether the host is safe. That
    // is a failure. Notify that is simply off is not lying, and stays a warning.
    //
    // #354 / #310: `notify.openclaw` is NOT a DNP denial sink. It arms interactive
    // held-approval cards only. Headless denials are `denied_no_prompt_surface`
    // and travel via webhookUrl → denialChannel (or loud DNP digest on that sink).
    // Doctor must not treat openclaw:true alone as "unattended notify configured".
    // #354 P3 (29 Aug 2026): this check used to sit inside
    // `if (effective.enabled && effective.enforce)`. That gate is why clawdbot1
    // went quiet the moment Action Guard was switched off: a disabled host hears
    // only "AG is off" and never that it has no denial-capable sink, so the
    // missing sink is invisible exactly when someone is deciding whether it is
    // safe to switch back on. Measured across three hosts on 29 Aug 2026:
    // 0 denials delivered out of 312 / 89 / 26. Un-gated deliberately.
    {
      const notify = isBlock(merged.notify) ? merged.notify : {};
      const notifyOn = notify.enabled === true;
      const webhook = typeof notify.webhookUrl === 'string' ? notify.webhookUrl.trim() : '';
      const openclaw = notify.openclaw === true;
      // Denial-capable sink for unattended/DNP path = enabled notify + webhook URL.
      const denialSink = notifyOn && webhook.length > 0;
      const armed = effective.enabled && effective.enforce;
      if (!denialSink) {
        const openclawOnly = notifyOn && openclaw && !webhook;
        // FAIL, not WARN, for the armed no-sink that CLAIMS to be configured.
        // The discriminator is `notify.enabled: true` without a webhook — that
        // config asserts a delivery path it does not have, to the one operator
        // who is deciding whether the host is safe. Both shapes measured on
        // 29 Aug 2026 delivered nothing while enforcing:
        //   notify.enabled + openclaw, no webhook  → clawdbot1, 0 of 312
        //   notify.enabled alone,      no webhook  → tars,      0 of 89
        // The second is not the milder case — `notify_not_configured` rows are
        // just a different label on the same zero. Doctor WARNed on both and the
        // outcome did not change, so severity was the defect, not coverage.
        //
        // `notify.enabled` false/absent stays WARN: a host that says notify is
        // off and has it off is not lying, it is under-configured. Same for any
        // host that is disabled or in warn-mode — not currently lying to anyone,
        // but still told, which is the whole point of un-gating.
        const claimsASink = notifyOn && !webhook;
        const status: CheckResult['status'] = armed && claimsASink ? 'fail' : 'warn';
        const prefix = armed
          ? 'Action Guard is enforcing with'
          : effective.enabled
            ? 'Action Guard is in warn-mode and running with'
            : 'Action Guard is disabled and, when re-enabled, would run with';
        results.push({
          label: `${label} notify`,
          status,
          message: openclawOnly
            ? `${prefix} notify.openclaw only — that arms interactive approval cards, ` +
              `not unattended denial delivery. Headless denials (denied_no_prompt_surface / cron) stay local ` +
              `unless actionGuard.notify.webhookUrl is set as the denial-capable sink (#354 / #310).`
            : `${prefix} no denial-capable notify sink (actionGuard.notify.webhookUrl unset` +
              `${notifyOn ? '' : ', notify.enabled is not true'}) — unattended denials stay in the ` +
              `audit log and session-guard index only. The #242 cron incidents were this shape.`,
          fix:
            'Run `shieldcortex config --action-guard-notify-webhook <https-url>` so denied/unattended actions ' +
            'reach a human via a denial-capable webhook sink. `notify.openclaw` is separate (interactive cards ' +
            'for live require_approval holds) and does not replace the webhook for DNP. ' +
            'The CLI writes a signed config — hand-editing config.json invalidates its integrity signature and ' +
            'forces strict mode. OpenClaw lastRunStatus is not ShieldCortex\'s to write.',
        });
      }

      // #143 residual: the broker block is the thing operators most often
      // believe is protecting them. Say what is actually true — present and
      // disabled is the default, and a disabled broker does nothing at all.
      // Neither state removes the need for a notify channel: the broker can
      // harden or hold, but the human path is still the notify path.
      // Broker reporting stays gated on armed, exactly as before this change —
      // un-gating the DENIAL SINK check is the scope; the broker block is not.
      const brokerBlock = armed && isBlock(merged.broker) ? merged.broker : null;
      if (brokerBlock) {
        results.push(
          brokerBlock.enabled === true
            ? {
                label: `${label} broker`,
                status: 'info',
                message:
                  'approval broker is armed (`actionGuard.broker.enabled: true`) — it can harden a gate or hold it, ' +
                  'and only pre-clears reversible on-host actions; catastrophic is never brokered and an unavailable ' +
                  'or timed-out judge holds for a human. The human path is still the notify channel.',
              }
            : {
                label: `${label} broker`,
                status: 'info',
                message:
                  'approval broker is present but disabled (opt-in; `actionGuard.broker.enabled` is not true) — ' +
                  'no judge runs and no gate is brokered. Denials still need a notify channel to reach a human.',
                fix: 'Set `actionGuard.broker.enabled: true` to opt in — the broker never widens a gate, but it is off until you say so.',
              },
        );
      }
    }

    if (alias) {
      const conflicts = top
        ? Object.keys(alias).filter(
            (k) => k in top && JSON.stringify(top[k]) !== JSON.stringify(alias[k]),
          )
        : [];
      if (conflicts.length > 0) {
        results.push({
          label: `${label} config`,
          status: 'warn',
          message:
            `deprecated \`interceptor.actionGuard\` differs from \`actionGuard\` on: ${conflicts.join(', ')} — ` +
            `the top-level value wins on both surfaces (#209), the alias values are ignored`,
          fix: 'Run `shieldcortex doctor --fix-action-guard` to migrate the alias into the top-level block.',
        });
      } else {
        results.push({
          label: `${label} config`,
          status: 'warn',
          message:
            `config uses the deprecated \`interceptor.actionGuard\` alias — it still works (both surfaces honour it), ` +
            `but the single source of truth is the top-level \`actionGuard\` block (#209)`,
          fix: 'Run `shieldcortex doctor --fix-action-guard` to migrate.',
        });
      }
    }
  } catch {
    // Unreadable config resolves to defaults on both runtime surfaces — nothing to warn about here.
  }

  return results;
}

/**
 * `doctor --fix-action-guard` (#209): migrate the deprecated
 * `interceptor.actionGuard` alias into the top-level `actionGuard` block —
 * same merge the runtime surfaces apply (top-level wins per key, alias
 * gap-fills), so the written config is exactly what was already in effect.
 * Backs up config.json first and removes an emptied `interceptor` block.
 */
export function fixActionGuardConfig(): { changed: boolean; backupPath?: string; message: string } {
  const configPath = path.join(getConfigDir(), 'config.json');
  if (!fs.existsSync(configPath)) return { changed: false, message: 'no config file — nothing to migrate' };
  const raw = readRawConfig();
  const isBlock = (v: unknown): v is Record<string, unknown> =>
    !!v && typeof v === 'object' && !Array.isArray(v);
  const alias = isBlock(raw?.interceptor) && isBlock(raw.interceptor.actionGuard)
    ? (raw.interceptor.actionGuard as Record<string, unknown>)
    : null;
  if (!alias) return { changed: false, message: 'no `interceptor.actionGuard` alias in config — nothing to migrate' };

  const backupPath = `${configPath}.bak-fix-209-${new Date().toISOString().replace(/[:.]/g, '-')}`;
  fs.copyFileSync(configPath, backupPath);

  // The write goes through cloud/config's guarded mutate path (#275): the
  // migrated file is re-signed with a fresh `_sig`. The previous bare
  // fs.writeFileSync here carried the stale signature through, so running the
  // fix ITSELF tripped the integrity check and forced strict mode.
  migrateInterceptorActionGuardAlias();
  return {
    changed: true,
    backupPath,
    message: `migrated interceptor.actionGuard into the top-level actionGuard block (backup: ${backupPath})`,
  };
}

// ── Check 8a-bis: Cron denial honesty (#375) ──────────────
/**
 * A guard denial inside a scheduled turn does not fail the turn: OpenClaw
 * records `last_run_status: ok` and the operator sees green while the job has
 * done nothing. Two crons on Edith were dead 2+ weeks with green status.
 *
 * We cannot rewrite OpenClaw's status, so this check says the quiet part out
 * loud — and it is deliberately harder to satisfy than most:
 *
 *   - It WARNs when denials landed inside runs that reported ok.
 *   - It WARNs when it could not look (denial log unreadable, `cron_run_logs`
 *     missing/unreadable). Never `info`, never a pass with a zeroed count: a
 *     "0 silent denials" derived from a table we could not read is the same
 *     green lie in different handwriting.
 *   - It passes only when the sources were readable and nothing was denied.
 *
 * It is never auto-fixed. The remedy is a human reviewing a script and pinning
 * it, which is the one thing `--fix` must not do on anyone's behalf.
 */
export interface CronDenialCheckDeps {
  home?: string;
  openclawDbPath?: string;
  denialsPath?: string;
  now?: number;
  /** Test seam — production uses the real correlation. */
  correlate?: (opts: CorrelateCronDenialsOptions) => CronDenialReport;
}

export const CRON_DENIALS_LABEL = 'Cron denials';

export async function checkCronDenials(deps: CronDenialCheckDeps = {}): Promise<CheckResult> {
  const label = CRON_DENIALS_LABEL;
  let report: CronDenialReport;
  try {
    const correlate = deps.correlate ?? correlateCronDenials;
    report = correlate({
      ...(deps.home ? { home: deps.home } : {}),
      ...(deps.openclawDbPath ? { openclawDbPath: deps.openclawDbPath } : {}),
      ...(deps.denialsPath ? { denialsPath: deps.denialsPath } : {}),
      ...(typeof deps.now === 'number' ? { now: deps.now } : {}),
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    // A correlation that crashed is still a correlation that did not happen.
    return { label, status: 'warn', message: `could not correlate cron denials — ${msg}` };
  }

  const days = Math.max(1, Math.round(report.windowMs / 86_400_000));

  if (report.cannotCorrelate) {
    const seen =
      report.attributedCount > 0
        ? ` — ${report.attributedCount} denial(s) are attributed to scheduled jobs and their run status is unknown`
        : '';
    return {
      label,
      status: 'warn',
      message: `could not correlate cron denials (${report.cannotCorrelate})${seen}`,
    };
  }

  const silentJobs = report.jobs.filter((j) => j.silentCount > 0);
  if (silentJobs.length > 0) {
    // Job names and counts only. No denial surface, no command body — the
    // #284 redaction contract holds on every new surface.
    const perJob = silentJobs
      .map(
        (j) =>
          `${j.name}: ${j.silentCount} of ${j.denialCount} denial(s) inside runs reported ok` +
          (j.enabled ? '' : ' (job disabled)'),
      )
      .join('; ');
    const paths: string[] = [];
    for (const j of silentJobs) for (const p of j.pinnablePaths) if (!paths.includes(p)) paths.push(p);
    const fix =
      paths.length > 0
        ? `Review each script, then pin it: ${paths.map((p) => `\`shieldcortex allowlist add ${p}\``).join(' ')}`
        : 'Open these jobs and check what the guard refused — no script path was discoverable from the job definition.';
    return {
      label,
      status: 'warn',
      message:
        `${silentJobs.length} scheduled job(s) had guard denials in the last ${days} days ` +
        `while their runs reported ok — ${perJob}`,
      fix,
    };
  }

  if (report.unconfirmedCount > 0) {
    return {
      label,
      status: 'warn',
      message:
        `${report.unconfirmedCount} denial(s) could not be matched to a run row ` +
        `(attributed to a scheduled job, no exact session match in the last ${days} days)`,
    };
  }

  const notes: string[] = [];
  if (report.unattributedCount > 0) notes.push(`${report.unattributedCount} not from a scheduled job`);
  if (report.undatedCount > 0) notes.push(`${report.undatedCount} undated row(s) skipped`);
  return {
    label,
    status: 'pass',
    message:
      `no guard denials landed inside scheduled runs in the last ${days} days` +
      (notes.length > 0 ? ` (${notes.join(', ')})` : ''),
  };
}

// ── Check 8b: Claude Code enforcement floor ───────────────
/**
 * The Action Guard's Claude Code surface is only as strong as the harness that
 * honours its verdicts, and that harness is versioned independently of us.
 *
 * On 2026-07-30 a box running Claude Code 2.1.76 was found discarding hook
 * `"ask"` decisions under `bypassPermissions` and executing the command — the
 * audit log recorded the guard firing, the command ran anyway, and this went
 * unnoticed because nobody tracked the harness version. See
 * `claude-code-version.ts` for the mechanism and how the floor was set.
 *
 * A below-floor build is a `fail`, not a warning: on that box the guard's
 * dangerous tier is decorative, and the operator has no other signal that it is.
 */
export async function checkClaudeCodeVersion(
  deps: DetectClaudeCodeDeps = {},
): Promise<CheckResult> {
  const label = 'Claude Code version';

  const install = detectClaudeCode(deps);
  if (!install) {
    return { label, status: 'info', message: 'skipped (Claude Code not detected on PATH)' };
  }

  const where = `${install.channel} channel`;

  if (!install.version) {
    return {
      label,
      status: 'warn',
      message:
        `could not read a version from \`${install.binPath} --version\` ` +
        `(${install.error ?? `output: ${install.rawVersion ?? 'empty'}`}) — ` +
        `cannot confirm this build honours the guard's approval verdicts ` +
        `(floor ${CLAUDE_CODE_ENFORCEMENT_FLOOR})`,
      fix: `Run \`claude --version\` by hand; if it is below ${CLAUDE_CODE_ENFORCEMENT_FLOOR}, upgrade with \`${upgradeCommandFor(install.channel)}\`.`,
    };
  }

  if (semver.lt(install.version, CLAUDE_CODE_ENFORCEMENT_FLOOR)) {
    return {
      label,
      status: 'fail',
      message:
        `${install.version} (${where}) is below the enforcement floor ${CLAUDE_CODE_ENFORCEMENT_FLOOR} — ` +
        `builds this old discard the Action Guard's approval verdicts in promptless modes ` +
        `(e.g. \`--permission-mode bypassPermissions\`) and run the command anyway. ` +
        `The audit log will show the guard firing while nothing was actually stopped.`,
      fix: `Upgrade Claude Code: \`${upgradeCommandFor(install.channel)}\`. Sessions already running keep the old build in memory until they cycle.`,
    };
  }

  return {
    label,
    status: 'pass',
    message: `${install.version} (${where}) — at or above the ${CLAUDE_CODE_ENFORCEMENT_FLOOR} enforcement floor`,
  };
}

/** Read a package's `version` field; returns null on any failure. */
function readPkgVersion(pkgJson: string): string | null {
  try {
    const v = (JSON.parse(fs.readFileSync(pkgJson, 'utf-8')) as { version?: unknown }).version;
    return typeof v === 'string' ? v : null;
  } catch {
    return null;
  }
}

/**
 * Read a package's `peerDependencies.shieldcortex` semver range; returns null
 * if the package.json is unreadable, missing the field, or the value is not a
 * valid semver range. Callers fall back to strict equality when null.
 */
function readShieldcortexPeerRange(pkgJson: string): string | null {
  try {
    const pkg = JSON.parse(fs.readFileSync(pkgJson, 'utf-8')) as {
      peerDependencies?: { shieldcortex?: unknown };
    };
    const range = pkg.peerDependencies?.shieldcortex;
    return typeof range === 'string' && semver.validRange(range) ? range : null;
  } catch {
    return null;
  }
}

// ── Check 9: Auto-memory sampling rate (#44) ──────────────
/**
 * Reports the resolved `autoMemory.stopHookSamplingTurns` and salience-bypass
 * setting. Defaults dropped 10 → 5 (and salience bypass added) in v4.14.0;
 * warn if a user pinned a sparser cadence likely to under-feed LTM.
 *
 * Reads the config file directly rather than importing the .mjs helper so
 * doctor doesn't depend on path layout between dist/ and scripts/.
 */
export async function checkAutoMemorySampling(): Promise<CheckResult> {
  try {
    const configPath = path.join(getShieldCortexDir(), 'config.json');
    let raw: { autoMemory?: { stopHookSamplingTurns?: number; stopHookSalienceBypass?: boolean } } = {};
    if (fs.existsSync(configPath)) {
      try {
        raw = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
      } catch {
        /* fall through to defaults */
      }
    }
    const overrides = raw.autoMemory ?? {};
    const sampling =
      typeof overrides.stopHookSamplingTurns === 'number' &&
      Number.isFinite(overrides.stopHookSamplingTurns) &&
      overrides.stopHookSamplingTurns > 0
        ? Math.floor(overrides.stopHookSamplingTurns)
        : 5; // default in auto-memory-config.mjs as of v4.14.0
    const bypassEnabled =
      typeof overrides.stopHookSalienceBypass === 'boolean' ? overrides.stopHookSalienceBypass : true;
    const bypass = bypassEnabled ? 'on' : 'off';
    if (sampling <= 5) {
      return {
        label: 'Auto-memory sampling',
        status: 'pass',
        message: `every ${sampling} turn(s), salience-bypass ${bypass}`,
      };
    }
    return {
      label: 'Auto-memory sampling',
      status: 'warn',
      message: `every ${sampling} turn(s), salience-bypass ${bypass} — sparser than recommended`,
      fix: 'Run `shieldcortex config --auto-memory-sampling 5` — the CLI writes a signed config; hand-editing config.json invalidates its integrity signature.',
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { label: 'Auto-memory sampling', status: 'info', message: `check skipped — ${msg}` };
  }
}

// ── Check 9b: Memory-capture dist completeness (#137) ─────
/**
 * `scripts/lib/save-memory.mjs` (the single write path for the session-end,
 * pre-compact and stop hooks) routes every captured memory through
 * `loadDefenceModules()`, which dynamically imports three dist/ modules. If
 * ANY of them is missing — a stale checkout, an interrupted install, a
 * partial rebuild — `loadDefenceModules()` returns null, the hook writes a
 * synthetic `defence_audit` row and a stderr line, and returns NORMALLY.
 * Fail-closed there is correct: an unscanned memory must never be stored.
 * This check does not touch that decision. What it fixes is that nothing
 * used to surface the state — hook stderr is usually discarded, and the
 * fallback audit row is otherwise invisible — so EVERY captured memory was
 * silently dropped for as long as the condition held, and the only sign was
 * a user noticing amnesia weeks later (#137).
 *
 * Mirrors loadDefenceModules()'s own resolution EXACTLY: same three files,
 * same distRoot (package root + 'dist' — save-memory.mjs computes this two
 * directories up from scripts/lib/, which is the same package root
 * resolveSelfInstallDir() returns for doctor's own dist/cli/doctor.js).
 */
const MEMORY_CAPTURE_REQUIRED_MODULES: Array<{ rel: string; symbol: string }> = [
  { rel: path.join('defence', 'pipeline.js'), symbol: 'runDefencePipeline' },
  { rel: path.join('database', 'init.js'), symbol: 'initDatabase' },
  { rel: path.join('defence', 'disposition.js'), symbol: 'resolveDisposition' },
];

const MEMORY_CAPTURE_FIX =
  'Run `npm run build:ts` (dev checkout), or on an installed box reinstall + repair: ' +
  '`npm i -g shieldcortex@latest && shieldcortex repair`.';

/**
 * Pure helper for the dist-completeness half. Exported so tests can point it
 * at any temp "package root" instead of the real install.
 */
export async function runMemoryCaptureDistCheck(pkgRoot: string): Promise<CheckResult> {
  const label = 'Memory capture: dist build';
  const distRoot = path.join(pkgRoot, 'dist');

  const missingFiles = MEMORY_CAPTURE_REQUIRED_MODULES.filter(
    (m) => !fs.existsSync(path.join(distRoot, m.rel)),
  );
  if (missingFiles.length > 0) {
    return {
      label,
      status: 'fail',
      message:
        `dist build is missing ${missingFiles.map((m) => m.rel).join(', ')} — the memory-capture ` +
        `hooks (session-end, pre-compact, stop) fail CLOSED on this and silently drop every ` +
        `captured memory while it holds.`,
      fix: MEMORY_CAPTURE_FIX,
    };
  }

  const brokenExports: string[] = [];
  for (const m of MEMORY_CAPTURE_REQUIRED_MODULES) {
    try {
      const mod = await import(pathToFileURL(path.join(distRoot, m.rel)).href);
      if (typeof (mod as Record<string, unknown>)[m.symbol] !== 'function') {
        brokenExports.push(`${m.rel} is missing export ${m.symbol}`);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      brokenExports.push(`${m.rel} failed to import — ${msg}`);
    }
  }

  if (brokenExports.length > 0) {
    return {
      label,
      status: 'fail',
      message: `dist build present but partial/corrupt — ${brokenExports.join('; ')} — memory capture is silently dropping every write.`,
      fix: MEMORY_CAPTURE_FIX,
    };
  }

  return {
    label,
    status: 'pass',
    message: 'defence pipeline modules present (pipeline.js, database/init.js, disposition.js)',
  };
}

/**
 * Pure helper for the "did this already happen" half. Exported so tests can
 * drive it against a temp database. Looks for the synthetic `defence_audit`
 * rows `writeFallbackAudit()` writes when the pipeline is unavailable — these
 * are the only trace a drop leaves. A hit here means real memories were lost
 * even if the dist build has SINCE been fixed (the drops already happened and
 * cannot be recovered — the content was never stored anywhere).
 */
export function runMemoryCaptureDropsCheck(dbPath: string): CheckResult {
  const label = 'Memory capture: recent drops';
  const prerequisite = databasePrerequisite(label, dbPath);
  if (prerequisite) return prerequisite;

  try {
    const Database = require('better-sqlite3');
    const db = new Database(dbPath, { readonly: true });
    try {
      // 24h window: long enough to catch a stale dist build that has been
      // silently dropping captures since the last session, short enough that
      // a FAIL here means "look at this host now" rather than raking up
      // ancient, already-actioned history.
      const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
      const row = db.prepare(
        `SELECT COUNT(*) as count, MAX(timestamp) as latest FROM defence_audit
           WHERE reason LIKE 'defence_pipeline_unavailable%' AND timestamp >= ?`,
      ).get(since) as { count: number; latest: string | null };

      if (row.count > 0) {
        return {
          label,
          status: 'fail',
          message:
            `${row.count} memory capture(s) were DROPPED in the last 24h because the defence ` +
            `pipeline was unavailable at write time (most recent: ${row.latest}). Fail-closed is ` +
            `correct — nothing unscanned was stored — but the content itself is gone.`,
          fix: `${MEMORY_CAPTURE_FIX} Historical drops cannot be recovered; check the "Memory capture: dist build" line above for whether the underlying cause is still live.`,
        };
      }
      return { label, status: 'pass', message: 'no defence_pipeline_unavailable drops in the last 24h' };
    } finally {
      db.close();
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { label, status: 'warn', message: `check failed — ${msg}` };
  }
}


// ── Memory plane: empty-brain / green-wash (Memory SOTA A-min) ──
/**
 * Bound host with auto-memory and/or proactive recall on must not sit on an
 * empty or junk-only store while other activity proves the product is in use.
 * Default window: 7 days (freeze nit).
 */
export async function checkMemoryPlaneEmptyBrain(): Promise<CheckResult> {
  const label = 'Memory plane (empty-brain)';
  const dbPath = getDbPath();
  if (!fs.existsSync(dbPath)) {
    return { label, status: 'info', message: 'no database yet' };
  }

  let openclawAuto = false;
  let proactive = false;
  let injectMode = 'off';
  let injectConfigured = false;
  let nativeContract: string | null = null;
  try {
    const raw = JSON.parse(fs.readFileSync(path.join(getShieldCortexDir(), 'config.json'), 'utf-8')) as Record<string, unknown>;
    openclawAuto = raw.openclawAutoMemory === true;
    proactive = raw.proactiveRecall === true;
    const mem = (raw.memory && typeof raw.memory === 'object') ? raw.memory as Record<string, unknown> : {};
    const inject = (mem.inject && typeof mem.inject === 'object') ? mem.inject as Record<string, unknown> : {};
    injectConfigured = Object.keys(inject).length > 0 || raw.memoryInjectMode != null || raw.memoryNativeInjectContract != null;
    if (typeof inject.mode === 'string') injectMode = inject.mode;
    else if (typeof raw.memoryInjectMode === 'string') injectMode = raw.memoryInjectMode as string;
    else if (injectConfigured) injectMode = 'start';
    const nc = inject.nativeContract ?? raw.memoryNativeInjectContract ?? mem.nativeInjectContract;
    // #381 review: only the two values the runtime accepts count as "set".
    // A junk string (or the rejected coexist_dedup) previously PASSED doctor
    // and then failed at runtime — doctor must not be more lenient than the
    // code it vouches for.
    nativeContract = typeof nc === 'string' && (nc === 'sc_only' || nc === 'disable_native_inject') ? nc : null;
  } catch { /* defaults */ }

  const bound = openclawAuto || proactive || injectMode === 'start' || injectMode === 'both';
  if (!bound) {
    return { label, status: 'info', message: 'auto-memory / proactive recall off — empty store is expected' };
  }

  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const Database = (await import('better-sqlite3')).default;
  let db: InstanceType<typeof Database> | null = null;
  try {
    db = new Database(dbPath, { readonly: true, timeout: 3000, fileMustExist: true });
    const countOf = (sql: string, params: unknown[] = []): number => {
      const row = db!.prepare(sql).get(...params) as { c?: number } | undefined;
      return Number(row?.c ?? 0);
    };
    const admitted = countOf(
      `SELECT COUNT(*) AS c FROM memories
       WHERE COALESCE(status, 'active') NOT IN ('archived', 'suppressed')
         AND COALESCE(sensitivity_level, 'INTERNAL') != 'RESTRICTED'`,
    );
    const total = countOf(`SELECT COUNT(*) AS c FROM memories`);
    let sessionEvents = 0;
    let hookInvocations = 0;
    try {
      sessionEvents = countOf(
        `SELECT COUNT(*) AS c FROM session_events WHERE created_at >= datetime('now', '-7 days')`,
      );
    } catch { /* table may not exist on ancient DBs */ }
    try {
      hookInvocations = countOf(
        `SELECT COUNT(*) AS c FROM hook_invocations WHERE invoked_at >= datetime('now', '-7 days')`,
      );
    } catch { /* optional */ }
    const activity = sessionEvents + hookInvocations;

    if (injectConfigured && injectMode !== 'off' && !nativeContract) {
      return {
        label,
        status: 'fail',
        message: `memory.inject mode=${injectMode} without nativeContract (need sc_only or disable_native_inject)`,
        fix: 'Run `shieldcortex config --memory-inject-contract sc_only` (or `disable_native_inject`) — the CLI writes a signed config; hand-editing config.json invalidates its integrity signature.',
      };
    }

    if (admitted === 0 && activity > 0) {
      return {
        label,
        status: 'fail',
        message: `0 admitted memories with activity in 7d (session_events=${sessionEvents}, hooks=${hookInvocations}, total_rows=${total})`,
        fix: 'Capture path is not filling the store — see docs/design/2026-08-17-memory-sota-empty-brain-rca.md; enable session capture / remember, or turn openclawAutoMemory off until fixed',
      };
    }
    if (admitted === 0 && activity === 0) {
      return {
        label,
        status: 'warn',
        message: '0 memories and no recent activity — plane idle',
      };
    }
    if (total > 0 && admitted === 0) {
      return {
        label,
        status: 'fail',
        message: `green-wash: ${total} row(s) but 0 admitted (quarantine/RESTRICTED/junk only)`,
        fix: 'Review quarantine and sensitivity; admitted durable facts required for a healthy plane',
      };
    }
    return {
      label,
      status: 'pass',
      message: `${admitted} admitted memories (7d activity=${activity})`,
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { label, status: 'warn', message: `check failed — ${msg}` };
  } finally {
    try { db?.close(); } catch { /* ignore */ }
  }
}


// ── Memory plane: dual-plane drift + host contract (Track A / #348) ──

const MEMORY_PLANE_LEGAL = new Set(['dual_legacy', 'import_only', 'sc_canonical']);

export function readMemoryPlaneFromConfig(raw: Record<string, unknown>): {
  plane: string;
  planeSetAt: string | null;
  illegal: boolean;
  injectMode: string;
  /** False when the raw mode is junk the runtime would fail-open to `start` (#393 SOL H5). */
  injectModeLegal: boolean;
  /** False when no mode was written and the emitter default (`start`) applies. */
  injectModeExplicit: boolean;
  nativeContract: string | null;
  openclawAuto: boolean;
  injectConfigured: boolean;
  /** Raw `memory.hostContract.posture` — kept raw so junk fails instead of vanishing. */
  posture: string | null;
  /** Printable description of a present non-string posture (#393 SOL r3 nit). */
  postureIllegal?: string;
  /** Operator-declared bound runtimes. Intent only: adds scrutiny, never proof. */
  declaredRuntimes: HostRuntimeId[];
  /** Unsupported runtimes entries (or a non-array key) — junk fails, never filters (#393 SOL r2 nit). */
  declaredRuntimesIllegal: string[];
} {
  const mem = (raw.memory && typeof raw.memory === 'object' && !Array.isArray(raw.memory))
    ? raw.memory as Record<string, unknown>
    : {};
  const inject = (mem.inject && typeof mem.inject === 'object' && !Array.isArray(mem.inject))
    ? mem.inject as Record<string, unknown>
    : {};
  const pRaw = mem.plane ?? raw.memoryPlane;
  let plane = 'dual_legacy';
  let illegal = false;
  if (pRaw == null || pRaw === '') {
    plane = 'dual_legacy';
  } else if (typeof pRaw === 'string' && MEMORY_PLANE_LEGAL.has(pRaw)) {
    plane = pRaw;
  } else {
    illegal = true;
    plane = String(pRaw);
  }
  const planeSetAt = typeof mem.planeSetAt === 'string' ? mem.planeSetAt : null;
  // #393 SOL H5: mode semantics mirror the runtime emitter
  // (scripts/lib/inject-pack.mjs readInjectConfig) — same key precedence, same
  // normalization — except junk is surfaced as illegal instead of silently
  // kept ('bogus' used to dodge the start-bus delivery requirement while the
  // runtime injected).
  const rawMode = inject.mode != null
    ? inject.mode
    : (raw.memoryInjectMode != null ? raw.memoryInjectMode : undefined);
  const modeReading = readInjectModeStrict(rawMode);
  const injectConfigured = Object.keys(inject).length > 0
    || raw.memoryInjectMode != null
    || raw.memoryNativeInjectContract != null
    // The emitter also reads a contract from memory.nativeInjectContract — a
    // contract alone puts the default-start pack on the bus, so it counts as
    // configured (the old reading called this state "inject off").
    || mem.nativeInjectContract != null;
  const injectMode = modeReading.legal ? (modeReading.mode as string) : modeReading.raw;
  const nc = inject.nativeContract ?? raw.memoryNativeInjectContract ?? mem.nativeInjectContract;
  const nativeContract = typeof nc === 'string'
    && (nc === 'sc_only' || nc === 'disable_native_inject')
    ? nc
    : null;
  const hostContract = (mem.hostContract && typeof mem.hostContract === 'object' && !Array.isArray(mem.hostContract))
    ? mem.hostContract as Record<string, unknown>
    : {};
  // #393 SOL r3 nit: a present non-string posture must FAIL as illegal, like
  // junk runtime declarations — String() coercion is banned here because a
  // one-element array stringifies to its element and could mint the legal
  // sidecar posture out of junk.
  const postureRaw = hostContract.posture;
  const posture = typeof postureRaw === 'string' && postureRaw.trim() !== '' ? postureRaw.trim() : null;
  let postureIllegal: string | undefined;
  if (postureRaw !== undefined && typeof postureRaw !== 'string') {
    try {
      postureIllegal = JSON.stringify(postureRaw) ?? String(postureRaw);
    } catch {
      postureIllegal = String(postureRaw);
    }
  }
  const declaredRuntimes: HostRuntimeId[] = [];
  const declaredRuntimesIllegal: string[] = [];
  if (hostContract.runtimes !== undefined) {
    if (!Array.isArray(hostContract.runtimes)) {
      declaredRuntimesIllegal.push(String(hostContract.runtimes));
    } else {
      for (const r of hostContract.runtimes) {
        if (r === 'openclaw' || r === 'claude_code' || r === 'hermes') declaredRuntimes.push(r);
        else declaredRuntimesIllegal.push(String(r));
      }
    }
  }
  return {
    plane,
    planeSetAt,
    illegal,
    injectMode,
    injectModeLegal: modeReading.legal,
    injectModeExplicit: modeReading.explicit,
    nativeContract,
    openclawAuto: raw.openclawAutoMemory === true,
    injectConfigured,
    posture,
    postureIllegal,
    declaredRuntimes,
    declaredRuntimesIllegal,
  };
}

/**
 * Dual-plane drift (#348 T2 / #394, Opus B3).
 *
 * Distinct from empty-brain: this catches "SC has rows but native is still the
 * brain", and — the #394 residual — "SC has rows the REAL inject gate admits
 * none of", which is a bus that delivers nothing while every row count looks
 * healthy. Doctor gathers evidence here; `src/memory/plane-drift.ts` decides.
 *
 * Three laws this must not break:
 *  - the injectable count uses `isInjectEligible` from
 *    scripts/lib/inject-pack.mjs — the SAME predicate the session-start hook
 *    injects with, not a weaker SQL approximation that grades itself green;
 *  - only artifacts a host actually loads as its agent brain are drift (an
 *    operator scratchpad is not, a project preamble is host-contract's business);
 *  - `requireScope` is deny-by-default CONFIG. Nothing about the data may turn
 *    it off, and an unscoped store must report what it excluded, never PASS.
 */
export async function checkMemoryPlaneDrift(): Promise<CheckResult> {
  const label = 'Memory plane (dual-plane drift)';
  let raw: Record<string, unknown> = {};
  const configPath = path.join(getConfigDir(), 'config.json');
  try {
    raw = JSON.parse(fs.readFileSync(configPath, 'utf-8')) as Record<string, unknown>;
  } catch {
    return { label, status: 'info', message: 'no config yet' };
  }
  const cfg = readMemoryPlaneFromConfig(raw);

  if (cfg.illegal) {
    return {
      label,
      status: 'fail',
      message: `illegal memory.plane value "${cfg.plane}" (need dual_legacy|import_only|sc_canonical)`,
      fix: 'Run `shieldcortex config --memory-plane dual_legacy` (or import_only|sc_canonical) — signed write; do not hand-edit config.json',
    };
  }

  // Illegal inject mode (#393 SOL H5): the runtime would fail-open junk to
  // `start` and inject — doctor fails it here rather than grading around it.
  if (!cfg.injectModeLegal) {
    return {
      label,
      status: 'fail',
      message: `illegal memory.inject.mode "${cfg.injectMode}" (need ${INJECT_MODES.join('|')}) — the runtime emitter would treat this as start`,
      fix: 'Set memory.inject.mode to a legal value (or remove it to accept the default start) — signed write; do not hand-edit config.json',
    };
  }

  // Illegal combo: inject on without legal contract (also empty-brain; keep here for plane law)
  if (cfg.injectConfigured && cfg.injectMode !== 'off' && !cfg.nativeContract) {
    return {
      label,
      status: 'fail',
      message: `plane=${cfg.plane}: inject mode=${cfg.injectMode} without legal nativeContract`,
      fix: 'Run `shieldcortex config --memory-inject-contract sc_only` (or disable_native_inject)',
    };
  }

  const startBusOn = Boolean(cfg.nativeContract)
    && (cfg.injectMode === 'start' || cfg.injectMode === 'both');

  const dbPath = getDbPath();
  const nowMs = Date.now();
  const native = scanNativeAgentSot(os.homedir(), nowMs);

  // The sidecar exemption is intentionally narrower than string equality. The
  // signed setter writes an embedded signature and explicit mode=off; a bare,
  // copied, malformed, or legacy posture blob does not get to suppress drift.
  const sidecarDeclared = cfg.posture === SIDECAR_POSTURE
    && cfg.postureIllegal === undefined;
  const trustedSidecar = sidecarDeclared
    && hasTrustedMemorySidecarPosture(raw, configPath);
  if (sidecarDeclared && !trustedSidecar) {
    return {
      label,
      status: 'fail',
      message:
        `untrusted sidecar posture (${SIDECAR_POSTURE}) — the declaration is not covered by a valid embedded config signature`,
      fix: 'Run `shieldcortex config --memory-host-posture mcp_sidecar_no_inject` so the signed setter records the declaration; a legacy .config-sig is not operator-intent proof',
    };
  }
  if (trustedSidecar) {
    if (cfg.plane === 'import_only' || cfg.plane === 'sc_canonical') {
      return {
        label,
        status: 'fail',
        message: `plane=${cfg.plane} contradicts posture=${SIDECAR_POSTURE} — sidecar leaves native memory authoritative and claims no SC canonicity/import ownership`,
        fix: 'Use plane=dual_legacy for the honest sidecar, or remove sidecar posture and establish a legal automatic start bus',
      };
    }
    return {
      label,
      status: 'pass',
      message:
        `honest sidecar (${SIDECAR_POSTURE}): signed posture, SC inject explicitly off; native memory is expected `
        + `(native_sot_touched_7d=${native.touched7d} native_sot_bytes=${native.bytes} `
        + `native_bus_active=${native.busActive.length > 0}${native.unattestable.length > 0 ? ` native_scan_notes=${native.unattestable.length}` : ''})`,
    };
  }

  // sc_canonical requires a REAL automatic start bus. mode=turn is not one.
  // Keep this after the trusted-sidecar contradiction so signed posture/plane
  // conflicts get the precise diagnosis rather than a generic missing-bus one.
  if (cfg.plane === 'sc_canonical' && !startBusOn) {
    return {
      label,
      status: 'fail',
      message:
        `plane=sc_canonical with SC inject mode=${cfg.injectMode} — canonicity claimed without an automatic start bus`
        + `${cfg.openclawAuto ? ' while openclawAutoMemory is on' : ''}`,
      fix: 'Enable inject with a legal nativeContract, or set plane to dual_legacy / declare the honest sidecar posture',
    };
  }

  if (!fs.existsSync(dbPath)) {
    return {
      label,
      status: 'warn',
      message: `plane=${cfg.plane}: cannot determine drift — no database yet`,
    };
  }

  // The REAL inject law, loaded from the module the hook injects with. A
  // failure to load leaves `injectable` unknown — which surfaces as
  // "cannot determine", never as a passing zero.
  let injectPack: InjectPackModule | null = null;
  try {
    // @ts-expect-error — importing a .mjs hook util that has no .d.ts
    injectPack = await import('../../scripts/lib/inject-pack.mjs') as InjectPackModule;
  } catch {
    injectPack = null;
  }
  const injectCfg = injectPack ? injectPack.readInjectConfig(raw) : null;
  // Deny-by-default when the config reader is unavailable: the gate's absence
  // must never read as the gate being off (Opus B3).
  const scope: DriftScope = {
    hostId: injectCfg?.hostId ?? null,
    agentId: injectCfg?.agentId ?? null,
    requireScope: injectCfg ? injectCfg.requireScope !== false : true,
  };

  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const Database = (await import('better-sqlite3')).default;
  let db: InstanceType<typeof Database> | null = null;
  try {
    db = new Database(dbPath, { readonly: true, timeout: 3000, fileMustExist: true });
    const counts = readPlaneDriftCounts(
      db,
      scope,
      injectPack?.isInjectEligible ?? null,
      injectPack?.selectInjectCandidates ?? null,
    );
    const verdict = evaluatePlaneDrift({
      plane: cfg.plane as MemoryPlane,
      planeSetAt: cfg.planeSetAt,
      // Eligibility only decides delivery when the v2 pack IS the automatic
      // session-start payload: a legal contract plus a start-capable mode.
      injectOn: startBusOn,
      requireScope: scope.requireScope,
      counts,
      native,
      nowMs,
    });
    return {
      label,
      status: verdict.status,
      message: verdict.message,
      ...(verdict.fix ? { fix: verdict.fix } : {}),
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { label, status: 'warn', message: `plane=${cfg.plane}: cannot determine drift — ${msg}` };
  } finally {
    try { db?.close(); } catch { /* ignore */ }
  }
}

/** The two helpers doctor borrows from the runtime inject module. */
interface InjectPackModule {
  isInjectEligible(row: unknown, scope: unknown): boolean;
  selectInjectCandidates(db: unknown, options?: { project?: string | null }): unknown[];
  readInjectConfig(config: Record<string, unknown>): {
    hostId: string | null;
    agentId: string | null;
    requireScope: boolean;
  };
}

interface DriftScope {
  hostId: string | null;
  agentId: string | null;
  requireScope: boolean;
}

/** Structural view of the readonly handle — keeps the counter unit-testable. */
interface DriftDb {
  prepare(sql: string): {
    get(...params: unknown[]): unknown;
    all(...params: unknown[]): unknown[];
  };
}

/**
 * SC-side counts for the drift model. Every count is honest-or-null: a zero
 * that means "could not count" is exactly how absence becomes proof.
 *
 * Doctor runs outside any session, so project-dependent eligibility remains
 * null rather than being presented as an exact positive upper bound.
 */
export function readPlaneDriftCounts(
  db: DriftDb,
  scope: DriftScope,
  isInjectEligible: ((row: unknown, scope: unknown) => boolean) | null,
  selectInjectCandidates: ((db: unknown, options?: { project?: string | null }) => unknown[]) | null = null,
): PlaneDriftCounts {
  const counts: PlaneDriftCounts = {
    durableAdmits7d: null,
    durableRows: null,
    injectable: null,
    unscopedExcluded: null,
    activity7d: null,
  };

  // Activity telemetry: null when NEITHER source exists on this store, so
  // "quiet box" and "no telemetry" stop looking identical.
  let activity: number | null = null;
  for (const sql of [
    `SELECT COUNT(*) AS c FROM session_events WHERE created_at >= datetime('now', '-7 days')`,
    `SELECT COUNT(*) AS c FROM hook_invocations WHERE invoked_at >= datetime('now', '-7 days')`,
  ]) {
    try {
      const row = db.prepare(sql).get() as { c?: number } | undefined;
      activity = (activity ?? 0) + Number(row?.c ?? 0);
    } catch { /* table absent on this store */ }
  }
  counts.activity7d = activity;

  let cols: Set<string>;
  try {
    cols = new Set((db.prepare('PRAGMA table_info(memories)').all() as Array<{ name: string }>).map((c) => c.name));
  } catch {
    cols = new Set();
  }
  // No memories table (or unreadable): every SC count stays unknown.
  if (cols.size === 0) return counts;

  const statusClause = cols.has('status')
    ? `COALESCE(status, 'active') NOT IN ('archived', 'suppressed', 'deleted', 'forgotten')`
    : '1=1';
  const sensClause = cols.has('sensitivity_level')
    ? `COALESCE(sensitivity_level, 'INTERNAL') != 'RESTRICTED'`
    : '1=1';
  const hasScopeCols = cols.has('host_id') && cols.has('agent_id');

  // Scope predicate mirrors isInjectEligible's: both keys present, and equal to
  // the configured value when one is configured. With the gate on and no scope
  // columns, NO row can be in scope — that is the honest answer, not a reason
  // to relax the gate.
  const scopeParams: unknown[] = [];
  let scopeClause = '1=1';
  if (scope.requireScope) {
    if (!hasScopeCols) {
      scopeClause = '1=0';
    } else {
      const parts = [`host_id IS NOT NULL AND host_id != ''`, `agent_id IS NOT NULL AND agent_id != ''`];
      if (scope.hostId != null) {
        parts.push('host_id = ?');
        scopeParams.push(scope.hostId);
      }
      if (scope.agentId != null) {
        parts.push('agent_id = ?');
        scopeParams.push(scope.agentId);
      }
      scopeClause = parts.join(' AND ');
    }
  }

  const countOf = (sql: string, params: unknown[] = []): number | null => {
    try {
      const row = db.prepare(sql).get(...params) as { c?: number } | undefined;
      return Number(row?.c ?? 0);
    } catch {
      return null;
    }
  };

  counts.durableRows = countOf(
    `SELECT COUNT(*) AS c FROM memories WHERE ${statusClause} AND ${sensClause} AND ${scopeClause}`,
    scopeParams,
  );
  counts.durableAdmits7d = cols.has('created_at')
    ? countOf(
      `SELECT COUNT(*) AS c FROM memories
       WHERE ${statusClause} AND ${sensClause} AND ${scopeClause}
         AND created_at >= datetime('now', '-7 days')`,
      scopeParams,
    )
    : null;
  counts.unscopedExcluded = hasScopeCols
    ? countOf(
      `SELECT COUNT(*) AS c FROM memories
       WHERE ${statusClause}
         AND (host_id IS NULL OR host_id = '' OR agent_id IS NULL OR agent_id = '')`,
    )
    // Without the columns every active row is unscoped by construction.
    : countOf(`SELECT COUNT(*) AS c FROM memories WHERE ${statusClause}`);

  if (!isInjectEligible || !selectInjectCandidates) return counts;
  let rows: Array<Record<string, unknown>>;
  try {
    rows = selectInjectCandidates(db) as Array<Record<string, unknown>>;
  } catch {
    return counts;
  }
  // Doctor has no session project. If project changes eligibility for any row
  // in the real top-64 window, an exact result is unknowable; never present an
  // upper-bound positive as PASS.
  if (rows.some((row) => row.project != null && row.project !== ''
    && row.transferable !== true && row.transferable !== 1)) {
    return counts;
  }
  let injectable = 0;
  for (const row of rows) {
    if (isInjectEligible(row, {
      hostId: scope.hostId,
      agentId: scope.agentId,
      requireScope: scope.requireScope,
    })) {
      injectable++;
    }
  }
  counts.injectable = injectable;
  return counts;
}

/**
 * Native agent-SoT scan for #394 drift.
 *
 * FP law — what counts and what deliberately does not:
 *
 *  | Artifact                                        | Drift? | Why |
 *  |---|---|---|
 *  | `<oc workspace>/MEMORY.md`, `memory.md`         | non-empty | OpenClaw bootstraps non-empty content; a zero-byte placeholder is not memory |
 *  | `<oc workspace>/memory/*`                       | yes | the workspace memory store |
 *  | `~/.claude/memory/*`, `~/.claude/projects/<key>/memory/*` | yes | Claude's memory-tool store |
 *  | `~/.hermes/{MEMORY.md,memories/*}`, profile stores | yes | Hermes native store |
 *  | `~/MEMORY.md`, `~/notes/…`, a stray workspace `.md` | **no** | operator scratchpad — no host loads it as a brain |
 *  | `CLAUDE.md` / `AGENTS.md` preambles             | **no** | project instructions, graded by the host-contract check (#393); developers edit them constantly |
 *
 * Every reading distinguishes absent from unreadable: a tree doctor could not
 * probe goes on `unattestable`, and the model turns that into "cannot
 * determine" rather than the silence reading as "native is quiet".
 *
 * Native bus state is only reported when PROVEN on — unknown belongs to the
 * host-contract check, which already caps at unknown and fails there. Drift is
 * not a second host-contract parser.
 */
const NATIVE_SOT_DIR_ENTRY_CAP = 200;
const NATIVE_SOT_DIR_DEPTH_CAP = 8;
const NATIVE_SOT_PROJECT_CAP = 200;

function scanNativeAgentSot(home: string, nowMs: number): NativeSotEvidence {
  const weekAgo = nowMs - 7 * 24 * 60 * 60 * 1000;
  const touched: Array<{ path: string; mtimeMs: number }> = [];
  const unattestable: string[] = [];
  const busActive: string[] = [];
  const seen = new Set<string>();
  const seenDirs = new Set<string>();
  const directoryBudget = { visited: 0, overflowed: false };
  let bytes = 0;

  const considerFile = (target: string): void => {
    if (seen.has(target)) return;
    seen.add(target);
    const probe = probePath(target);
    if (probe.kind === 'absent') return;
    if (probe.kind !== 'present') {
      unattestable.push(
        `${tildify(target)} cannot be read (${probe.code}: ${probe.message}) — native growth there cannot be ruled out`,
      );
      return;
    }
    if (!probe.stat.isFile()) return;
    bytes += probe.stat.size;
    // Match the host load rule: a zero-byte bootstrap contains no memory and
    // therefore cannot prove native SoT growth merely by having a fresh mtime.
    if (probe.stat.size > 0 && probe.stat.mtimeMs >= weekAgo) {
      touched.push({ path: tildify(target), mtimeMs: probe.stat.mtimeMs });
    }
  };

  /** Probe already gathered by a #393 scanner (per-profile Hermes stores). */
  const considerProbe = (probe: ArtifactProbe): void => {
    if (probe.kind === 'absent' || seen.has(probe.path)) return;
    seen.add(probe.path);
    if (probe.kind === 'unreadable') {
      unattestable.push(`${tildify(probe.path)} cannot be read (${probe.detail}) — native growth there cannot be ruled out`);
      return;
    }
    bytes += probe.size;
    if (probe.size > 0 && probe.mtimeMs >= weekAgo) touched.push({ path: tildify(probe.path), mtimeMs: probe.mtimeMs });
  };

  const considerDir = (
    dir: string,
    depth = 0,
    budget: { visited: number; overflowed: boolean } = directoryBudget,
  ): void => {
    if (seenDirs.has(dir)) return;
    seenDirs.add(dir);
    if (depth > NATIVE_SOT_DIR_DEPTH_CAP) {
      unattestable.push(`${tildify(dir)} exceeds native store recursion depth ${NATIVE_SOT_DIR_DEPTH_CAP}`);
      return;
    }
    const probe = probePath(dir);
    if (probe.kind === 'absent') return;
    if (probe.kind !== 'present') {
      unattestable.push(`${tildify(dir)} cannot be inspected (${probe.code}: ${probe.message})`);
      return;
    }
    if (!probe.stat.isDirectory()) {
      considerFile(dir);
      return;
    }
    let names: string[];
    try {
      names = fs.readdirSync(dir);
    } catch (err: unknown) {
      unattestable.push(`${tildify(dir)} cannot be listed (${err instanceof Error ? err.message : String(err)})`);
      return;
    }
    names.sort();
    for (const name of names) {
      if (budget.visited++ >= NATIVE_SOT_DIR_ENTRY_CAP) {
        if (!budget.overflowed) {
          budget.overflowed = true;
          unattestable.push(
            `${tildify(dir)} exceeds ${NATIVE_SOT_DIR_ENTRY_CAP} recursive entries — the native store scan is truncated`,
          );
        }
        return;
      }
      const child = path.join(dir, name);
      const childProbe = probePath(child);
      if (childProbe.kind === 'present' && childProbe.stat.isDirectory()) {
        considerDir(child, depth + 1, budget);
      } else {
        considerFile(child);
      }
    }
  };

  // ── OpenClaw: every workspace the host could resolve, same binding the
  //    host-contract proof grades.
  const binding = resolveOpenClawBinding();
  if (binding.unresolvable) {
    unattestable.push(
      `OpenClaw: ${binding.unresolvable} — doctor will not probe a guessed tree for native memory growth`,
    );
  } else if (binding.stateRoot.root !== null && binding.ocHome !== null) {
    const ws = openClawWorkspacePaths(binding.ocHome, binding.stateRoot.root, binding.config);
    if (!ws.complete) {
      unattestable.push(
        'OpenClaw agent workspaces could not be fully enumerated — a workspace brain outside the scan cannot be ruled out',
      );
    }
    for (const dir of ws.paths) {
      // Both spellings: OpenClaw bootstraps MEMORY.md AND memory.md.
      considerFile(path.join(dir, 'MEMORY.md'));
      considerFile(path.join(dir, 'memory.md'));
      considerDir(path.join(dir, 'memory'));
    }
    // Bus state: only a PROVEN-on switch is drift evidence here. A legacy-bound
    // or unreadable config leaves it unknown, which the host-contract check
    // owns — drift must not grow a second verdict for it.
    if (!binding.legacyConfig) {
      const ms = resolveOpenClawMemorySearchState(binding.config);
      if (ms.state === 'on') busActive.push(`OpenClaw Memory Search is on (${ms.proof.join('; ')})`);
    }
  }

  // ── Claude Code: the memory-tool stores ONLY. CLAUDE.md preambles are
  //    host-contract evidence, not memory growth (the FP law above).
  considerDir(path.join(home, '.claude', 'memory'));
  const projectsDir = path.join(home, '.claude', 'projects');
  const projectsProbe = probePath(projectsDir);
  if (projectsProbe.kind === 'present' && projectsProbe.stat.isDirectory()) {
    let entries: string[] = [];
    try {
      entries = fs.readdirSync(projectsDir);
    } catch (err: unknown) {
      unattestable.push(`${tildify(projectsDir)} cannot be listed (${err instanceof Error ? err.message : String(err)})`);
    }
    if (entries.length > NATIVE_SOT_PROJECT_CAP) {
      unattestable.push(`${tildify(projectsDir)} holds more than ${NATIVE_SOT_PROJECT_CAP} project keys — the scan is truncated`);
    }
    for (const entry of entries.slice(0, NATIVE_SOT_PROJECT_CAP)) {
      considerDir(path.join(projectsDir, entry, 'memory'));
    }
  } else if (projectsProbe.kind === 'denied' || projectsProbe.kind === 'error') {
    unattestable.push(`${tildify(projectsDir)} cannot be inspected (${projectsProbe.code}: ${projectsProbe.message})`);
  }

  // ── Hermes: root store, root MEMORY.md, and every per-profile store.
  considerDir(path.join(home, '.hermes', 'memories'));
  considerFile(path.join(home, '.hermes', 'MEMORY.md'));
  const profileScan = scanHermesProfiles(home);
  for (const probe of profileScan.artifacts) considerProbe(probe);
  for (const profile of profileScan.profiles) {
    considerDir(path.join(home, '.hermes', 'profiles', profile.name, 'memories'));
  }
  if (!profileScan.scanComplete) {
    unattestable.push(
      'Hermes profiles could not be fully enumerated — a per-profile native store outside the scan cannot be ruled out',
    );
  }
  const reportHermesSwitches = (label: string, config: ProbeRead<ReturnType<typeof parseHermesMemoryBlock>>): void => {
    if (config.kind === 'unreadable') {
      unattestable.push(`${label} config.yaml cannot be read (${config.detail}) — native bus state cannot be determined`);
      return;
    }
    if (config.kind === 'absent') {
      unattestable.push(`${label} has no config.yaml — native memory defaults cannot be proven off`);
      return;
    }
    const switches = config.value;
    if (!switches.blockFound) {
      unattestable.push(`${label} config.yaml has no memory block — native memory defaults cannot be proven off`);
      return;
    }
    const on: string[] = [];
    if (switches.memoryEnabled !== false) {
      on.push(`memory_enabled=${switches.memoryEnabled === null ? 'unset (default ON)' : 'true'}`);
    }
    if (switches.userProfileEnabled !== false) {
      on.push(`user_profile_enabled=${switches.userProfileEnabled === null ? 'unset (default ON)' : 'true'}`);
    }
    if (on.length > 0) busActive.push(`${label}: ${on.join(', ')}`);
  };
  const hermesCfg = readTextProbe(path.join(home, '.hermes', 'config.yaml'));
  const hermesNativePresent = probePath(path.join(home, '.hermes', 'memories')).kind !== 'absent'
    || probePath(path.join(home, '.hermes', 'MEMORY.md')).kind !== 'absent';
  if (hermesCfg.kind !== 'absent' || hermesNativePresent || profileScan.profiles.length > 0 || !profileScan.scanComplete) {
    reportHermesSwitches(
      'Hermes root',
      hermesCfg.kind === 'present'
        ? { kind: 'present', value: parseHermesMemoryBlock(hermesCfg.value) }
        : hermesCfg,
    );
  }
  for (const profile of profileScan.profiles) {
    reportHermesSwitches(`Hermes profile ${profile.name}`, profile.config);
  }

  touched.sort((a, b) => b.mtimeMs - a.mtimeMs);
  return {
    touched7d: touched.length > 0,
    touchedPaths: touched.map((t) => t.path),
    bytes,
    unattestable,
    busActive,
  };
}

/**
 * Host contract enforcement proof (#348 T1 / #393).
 *
 * The disk-reading half: gather per-runtime evidence, then let the pure model in
 * `src/memory/host-contract.ts` decide. Every read distinguishes absent from
 * unreadable — the previous version returned PASS ("no paper-contract signals on
 * disk") whenever it found nothing, which is exactly how a Hermes-primary box
 * with a live native MEMORY plane green-washed an `sc_only` paper contract while
 * being handed OpenClaw remediation it could not act on.
 */
function readJsonProbe(target: string): ProbeRead<Record<string, unknown>> {
  const probe = probePath(target);
  if (probe.kind === 'absent') return { kind: 'absent' };
  if (probe.kind === 'denied' || probe.kind === 'error') {
    return { kind: 'unreadable', detail: `${probe.code}: ${probe.message}` };
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(target, 'utf-8')) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return { kind: 'unreadable', detail: 'not a JSON object' };
    }
    return { kind: 'present', value: parsed as Record<string, unknown> };
  } catch (err: unknown) {
    return { kind: 'unreadable', detail: err instanceof Error ? err.message : String(err) };
  }
}

function readTextProbe(target: string): ProbeRead<string> {
  const probe = probePath(target);
  if (probe.kind === 'absent') return { kind: 'absent' };
  if (probe.kind === 'denied' || probe.kind === 'error') {
    return { kind: 'unreadable', detail: `${probe.code}: ${probe.message}` };
  }
  try {
    return { kind: 'present', value: fs.readFileSync(target, 'utf-8') };
  } catch (err: unknown) {
    return { kind: 'unreadable', detail: err instanceof Error ? err.message : String(err) };
  }
}

/** stat-only: doctor proves a native store is live without reading its contents. */
function artifactProbe(target: string): ArtifactProbe {
  const probe = probePath(target);
  if (probe.kind === 'absent') return { kind: 'absent', path: target };
  if (probe.kind === 'denied' || probe.kind === 'error') {
    return { kind: 'unreadable', path: target, detail: `${probe.code}: ${probe.message}` };
  }
  return { kind: 'present', path: target, mtimeMs: probe.stat.mtimeMs, size: probe.stat.isFile() ? probe.stat.size : 1 };
}

/**
 * Claude Code encodes a project's cwd as a directory key under
 * `~/.claude/projects` by replacing every non-alphanumeric character with `-`
 * (`/home/u/my-app` → `-home-u-my-app`). The automatic project instructions
 * live in the REAL project hierarchy — `<root>/CLAUDE.md` and
 * `<root>/.claude/CLAUDE.md` — NOT under the key directory, which holds
 * transcripts and the per-project memory store (#393 SOL r3 B4).
 *
 * The encoding is lossy (`-`, `/`, `.`, `_` all become `-`), so the key is
 * decoded by walking the real filesystem: from `/`, a child matches when
 * encoding its name yields the next chunk of the key. Every existing
 * directory whose full path encodes to the key is a candidate root; ambiguity
 * probes them all (extra probes can only ADD native-ON evidence, never mint a
 * PASS). A walk that cannot finish — unreadable directory, cap hit, a key not
 * shaped like an absolute-path encoding, a matching child it cannot stat — is
 * an attestation gap the caller surfaces as unknown, never as "no preamble".
 * Zero roots from a COMPLETE walk means no such directory exists today, so no
 * session can start there and Claude loads nothing from it.
 *
 * Exported for direct unit testing.
 */
const CLAUDE_KEY_WALK_CAP = 128;
export function decodeClaudeProjectKey(key: string): { roots: string[]; complete: boolean } {
  if (!key.startsWith('-') || key.length < 2) return { roots: [], complete: false };
  const encode = (s: string): string => s.replace(/[^A-Za-z0-9]/g, '-');
  const roots: string[] = [];
  let complete = true;
  let visited = 0;
  const walk = (dir: string, rest: string): void => {
    if (visited++ >= CLAUDE_KEY_WALK_CAP) {
      complete = false;
      return;
    }
    let names: string[];
    try {
      names = fs.readdirSync(dir);
    } catch {
      complete = false;
      return;
    }
    for (const name of names) {
      const enc = encode(name);
      const matchFull = rest === enc;
      const matchPrefix = !matchFull && rest.startsWith(`${enc}-`);
      if (!matchFull && !matchPrefix) continue;
      const child = path.join(dir, name);
      let isDir: boolean;
      try {
        isDir = fs.statSync(child).isDirectory();
      } catch {
        complete = false;
        continue;
      }
      if (!isDir) continue;
      if (matchFull) roots.push(child);
      else walk(child, rest.slice(enc.length + 1));
    }
  };
  walk('/', key.slice(1));
  return { roots, complete };
}

/**
 * Claude Code's native plane is the memory-tool store PLUS the automatic
 * preambles: `~/.claude/memory`, per-project `~/.claude/projects/<key>/memory`
 * directories, `~/.claude/CLAUDE.md`, and — via decodeClaudeProjectKey — the
 * real project roots' CLAUDE.md / .claude/CLAUDE.md AND their ancestors'
 * (#393 SOL r2 B5 + r3 B4 + r4 B1; Claude loads parent-directory preambles
 * for nested sessions, so a clean leaf under a live ancestor is still on the
 * native bus; a preamble loaded into every session is native automatic
 * durable context; the normative host law demands it stop under a bus
 * contract). Doctor cannot
 * enumerate every project on the box — only those Claude has recorded a key
 * for — which stays an accepted attestation limit; what it must never do is
 * scan the WRONG location and call the silence off_proven. Scans are bounded,
 * and BOTH failure shapes surface as scanComplete=false — a directory we
 * cannot list, and a listing that exceeds the cap (#393 SOL H2: a truncated
 * scan used to keep scanComplete=true, so a live store past the slice could
 * vanish from the verdict). "Could not look everywhere" must never read as
 * "nothing there".
 */
const CLAUDE_STORE_FILE_CAP = 50;
const CLAUDE_PROJECT_CAP = 200;
const CLAUDE_ANCESTOR_CAP = 10;
function scanClaudeNativeStores(home: string): { stores: ArtifactProbe[]; scanComplete: boolean } {
  const stores: ArtifactProbe[] = [];
  let scanComplete = true;
  // Preamble probes dedupe across projects (#393 SOL r4 B1): nested projects
  // share ancestors, and every ancestor chain ends at the same $HOME.
  const preambleSeen = new Set<string>();
  const probePreambles = (dir: string): void => {
    for (const p of [path.join(dir, 'CLAUDE.md'), path.join(dir, '.claude', 'CLAUDE.md')]) {
      if (preambleSeen.has(p)) continue;
      preambleSeen.add(p);
      stores.push(artifactProbe(p));
    }
  };
  const collectDir = (dir: string): void => {
    const dirProbe = probePath(dir);
    if (dirProbe.kind === 'absent') return;
    if (dirProbe.kind !== 'present') {
      stores.push({ kind: 'unreadable', path: dir, detail: `${dirProbe.code}: ${dirProbe.message}` });
      return;
    }
    try {
      const names = fs.readdirSync(dir);
      if (names.length > CLAUDE_STORE_FILE_CAP) scanComplete = false;
      for (const name of names.slice(0, CLAUDE_STORE_FILE_CAP)) {
        if (!name.endsWith('.md')) continue;
        stores.push(artifactProbe(path.join(dir, name)));
      }
    } catch (err: unknown) {
      scanComplete = false;
      stores.push({ kind: 'unreadable', path: dir, detail: err instanceof Error ? err.message : String(err) });
    }
  };

  collectDir(path.join(home, '.claude', 'memory'));
  // The global automatic preamble (#393 SOL r2 B5).
  preambleSeen.add(path.join(home, '.claude', 'CLAUDE.md'));
  stores.push(artifactProbe(path.join(home, '.claude', 'CLAUDE.md')));

  const projectsDir = path.join(home, '.claude', 'projects');
  const projectsProbe = probePath(projectsDir);
  if (projectsProbe.kind === 'present') {
    try {
      const entries = fs.readdirSync(projectsDir);
      if (entries.length > CLAUDE_PROJECT_CAP) scanComplete = false;
      for (const entry of entries.slice(0, CLAUDE_PROJECT_CAP)) {
        const keyDir = path.join(projectsDir, entry);
        const keyProbe = probePath(keyDir);
        if (keyProbe.kind === 'absent') continue;
        if (keyProbe.kind !== 'present') {
          scanComplete = false;
          continue;
        }
        // Stray files under projects/ are not keys and hold no store.
        if (!keyProbe.stat.isDirectory()) continue;
        // The per-project memory store genuinely lives under the key dir.
        collectDir(path.join(keyDir, 'memory'));
        // #393 SOL r3 B4: the automatic project preamble does NOT — decode the
        // key back to real project roots and probe there. An undecodable key
        // is an attestation gap surfaced as unreadable evidence, never
        // silence (the old probe read projects/<key>/CLAUDE.md, a location
        // Claude never loads, and its absence green-washed off_proven).
        const decoded = decodeClaudeProjectKey(entry);
        if (!decoded.complete) {
          scanComplete = false;
          stores.push({
            kind: 'unreadable',
            path: keyDir,
            detail: 'project key cannot be fully decoded to a real project root — its automatic CLAUDE.md cannot be attested',
          });
        }
        for (const root of decoded.roots) {
          probePreambles(root);
          // #393 SOL r4 B1: Claude also loads ancestor CLAUDE.md preambles
          // for a session in a nested directory — a clean leaf with a live
          // ancestor preamble used to prove off. Walk parents up to (and
          // including) $HOME — or the filesystem root for projects outside
          // it — bounded; a walk the cap truncates before reaching its
          // terminal is an incomplete scan, never silence.
          let dir = root;
          let depth = 0;
          while (dir !== home) {
            const parent = path.dirname(dir);
            if (parent === dir) break;
            if (depth++ >= CLAUDE_ANCESTOR_CAP) {
              scanComplete = false;
              break;
            }
            dir = parent;
            probePreambles(dir);
          }
        }
      }
    } catch {
      scanComplete = false;
    }
  } else if (projectsProbe.kind === 'denied' || projectsProbe.kind === 'error') {
    scanComplete = false;
  }

  return { stores, scanComplete };
}

/**
 * Hermes profile surface (#393 SOL H6): per-profile config.yaml switches plus
 * per-profile native stores. Bounded by HERMES_PROFILE_CAP; exceeding the cap
 * or failing to list marks the scan incomplete so the evidence model refuses
 * to prove off from a partial look.
 */
const HERMES_PROFILE_CAP = 20;
function scanHermesProfiles(home: string): {
  profiles: HermesProfileProbe[];
  artifacts: ArtifactProbe[];
  scanComplete: boolean;
} {
  const profilesDir = path.join(home, '.hermes', 'profiles');
  const out = { profiles: [] as HermesProfileProbe[], artifacts: [] as ArtifactProbe[], scanComplete: true };
  const probe = probePath(profilesDir);
  if (probe.kind === 'absent') return out;
  if (probe.kind !== 'present') {
    out.scanComplete = false;
    out.artifacts.push({ kind: 'unreadable', path: profilesDir, detail: `${probe.code}: ${probe.message}` });
    return out;
  }
  try {
    const entries = fs.readdirSync(profilesDir);
    if (entries.length > HERMES_PROFILE_CAP) out.scanComplete = false;
    for (const entry of entries.slice(0, HERMES_PROFILE_CAP)) {
      const dir = path.join(profilesDir, entry);
      const dirProbe = probePath(dir);
      if (dirProbe.kind === 'denied' || dirProbe.kind === 'error') {
        out.scanComplete = false;
        out.profiles.push({
          name: entry,
          config: { kind: 'unreadable', detail: `${dirProbe.code}: ${dirProbe.message}` },
        });
        out.artifacts.push({ kind: 'unreadable', path: dir, detail: `${dirProbe.code}: ${dirProbe.message}` });
        continue;
      }
      if (dirProbe.kind !== 'present' || !dirProbe.stat.isDirectory()) continue; // stray file, not a profile
      const text = readTextProbe(path.join(dir, 'config.yaml'));
      if (text.kind === 'unreadable') out.scanComplete = false;
      out.profiles.push({
        name: entry,
        config: text.kind === 'present'
          ? { kind: 'present', value: parseHermesMemoryBlock(text.value) }
          : text,
      });
      const artifact = artifactProbe(path.join(dir, 'memories', 'MEMORY.md'));
      if (artifact.kind === 'unreadable') out.scanComplete = false;
      out.artifacts.push(artifact);
    }
  } catch (err: unknown) {
    out.scanComplete = false;
    out.artifacts.push({ kind: 'unreadable', path: profilesDir, detail: err instanceof Error ? err.message : String(err) });
  }
  return out;
}

/** Mirror of OpenClaw's normalizeAgentId (openclaw/src/routing/session-key.ts):
 * trim, empty => "main", valid ids lowercase, everything else lowercased with
 * invalid runs collapsed to "-", edge dashes stripped, capped at 64 chars. */
const OPENCLAW_DEFAULT_AGENT_ID = 'main';
function normalizeOpenClawAgentId(value: unknown): string {
  const trimmed = typeof value === 'string' ? value.trim() : '';
  if (!trimmed) return OPENCLAW_DEFAULT_AGENT_ID;
  if (/^[a-z0-9][a-z0-9_-]{0,63}$/i.test(trimmed)) return trimmed.toLowerCase();
  return trimmed
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, '-')
    .replace(/^-+/, '')
    .replace(/-+$/, '')
    .slice(0, 64) || OPENCLAW_DEFAULT_AGENT_ID;
}

/**
 * Mirror of OpenClaw's listAgentEntries + resolveDefaultAgentId
 * (openclaw/src/agents/agent-scope.ts). agents.list keeps every truthy
 * `typeof === 'object'` member — ARRAYS INCLUDED (an array's fields read as
 * undefined, so it occupies the `main` id slot with no workspace and no
 * default flag; the old non-array filter could make doctor elect a different
 * default agent than the host, #393 SOL r4 B3). Default id: first entry with
 * a truthy `default`, else the first entry, else `main`.
 */
function openClawAgentEntries(config: ProbeRead<Record<string, unknown>>): {
  entries: Array<Record<string, unknown>>;
  defaultAgentId: string;
} {
  if (config.kind !== 'present') return { entries: [], defaultAgentId: OPENCLAW_DEFAULT_AGENT_ID };
  const agents = config.value.agents;
  const list = agents && typeof agents === 'object' && !Array.isArray(agents)
    ? (agents as Record<string, unknown>).list
    : undefined;
  const rawList = Array.isArray(list) ? list : [];
  const entries = rawList.filter((e): e is Record<string, unknown> => Boolean(e && typeof e === 'object'));
  const flagged = entries.filter((e) => e.default);
  const defaultAgentId = entries.length === 0
    ? OPENCLAW_DEFAULT_AGENT_ID
    : normalizeOpenClawAgentId((flagged[0] ?? entries[0]).id);
  return { entries, defaultAgentId };
}

/**
 * Workspace roots doctor must inspect (#393 SOL H4 + r3 B3), mirroring
 * resolveAgentWorkspaceDir in openclaw/src/agents/agent-scope.ts:
 *
 *  - the stock workspace under the state root (r2 B6) AND the host's true
 *    default-agent workspace — resolveDefaultAgentWorkspaceDir anchors it at
 *    ~/.openclaw/workspace[-<OPENCLAW_PROFILE>] under HOME even when
 *    OPENCLAW_STATE_DIR relocates the state tree;
 *  - every explicit defaults/per-agent workspace value;
 *  - IMPLICIT per-agent workspaces (r3 B3): a configured non-default agent
 *    with no explicit workspace still resolves one at
 *    `<stateDir>/workspace-<normalizedId>` — a live MEMORY.md there used to
 *    vanish from the verdict entirely.
 *
 * Bounded by OPENCLAW_WORKSPACE_CAP (the agents list bounds the implicit set);
 * overflow or an unreadable config marks the enumeration incomplete so the
 * evidence model refuses to prove off. Exported for direct unit testing.
 */
const OPENCLAW_WORKSPACE_CAP = 16;
export function openClawWorkspacePaths(
  home: string,
  stateRoot: string,
  config: ProbeRead<Record<string, unknown>>,
): { paths: string[]; complete: boolean } {
  const paths: string[] = [];
  let complete = true;
  const push = (p: string): void => {
    if (!paths.includes(p)) paths.push(p);
  };
  push(path.join(stateRoot, 'workspace'));
  const profile = process.env.OPENCLAW_PROFILE?.trim();
  push(path.join(
    home,
    '.openclaw',
    profile && profile.toLowerCase() !== 'default' ? `workspace-${profile}` : 'workspace',
  ));
  const asObj = (v: unknown): Record<string, unknown> =>
    v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
  const add = (v: unknown): void => {
    if (typeof v !== 'string' || v.trim() === '') return;
    // Host resolveUserPath semantics (#393 SOL r3 B6): a workspace value
    // doctor cannot resolve (relative, ~user) would otherwise be probed in a
    // guessed tree — mark the enumeration incomplete instead, so the evidence
    // model refuses to prove off past it.
    const resolved = resolveOpenClawUserPath(v, home);
    if ('path' in resolved) push(resolved.path);
    else complete = false;
  };
  if (config.kind === 'present') {
    // #393 SOL r5 B1: $include'd files deep-merge into agents/defaults before
    // the host resolves workspaces — the raw root JSON cannot enumerate them.
    // Raw-visible workspaces still get probed (extra probes only ADD
    // native-ON evidence), but the scan must never claim completeness.
    if (openClawConfigUsesInclude(config.value)) complete = false;
    const agents = asObj(config.value.agents);
    add(asObj(agents.defaults).workspace);
    // resolveDefaultAgentId: first entry marked default (truthy), else the
    // first entry. The default agent's implicit workspace is the home default
    // pushed above, never workspace-<id>.
    const { entries, defaultAgentId } = openClawAgentEntries(config);
    const seen = new Set<string>();
    for (const entry of entries) {
      const id = normalizeOpenClawAgentId(entry.id);
      // Duplicate ids resolve to the FIRST entry (resolveAgentEntry.find).
      if (seen.has(id)) continue;
      seen.add(id);
      const explicit = typeof entry.workspace === 'string' ? entry.workspace.trim() : '';
      if (explicit) {
        add(explicit);
      } else if (id !== defaultAgentId) {
        push(path.join(stateRoot, `workspace-${id}`));
      }
    }
  } else if (config.kind === 'unreadable') {
    // Cannot enumerate configured workspaces at all — never claim we did.
    complete = false;
  }
  if (paths.length > OPENCLAW_WORKSPACE_CAP) {
    paths.length = OPENCLAW_WORKSPACE_CAP;
    complete = false;
  }
  return { paths, complete };
}

/**
 * The ONE workspace OpenClaw's gateway loads internal hooks from — mirror of
 * resolveAgentWorkspaceDir(cfg, resolveDefaultAgentId(cfg)) exactly as server
 * startup calls it (openclaw/src/gateway/server.impl.ts →
 * loadInternalHooks(cfg, defaultWorkspaceDir)): the default agent entry's
 * explicit `workspace`, else `agents.defaults.workspace`, else
 * `<effective home>/.openclaw/workspace[-<OPENCLAW_PROFILE>]`. Configured
 * values resolve with host resolveUserPath semantics (#393 SOL r3 B6) — a
 * value doctor cannot resolve makes the default workspace, and any hook
 * shadowing inside it, unknowable. Exported for direct unit testing.
 */
export function openClawDefaultWorkspace(
  ocHome: string,
  config: ProbeRead<Record<string, unknown>>,
): { path: string } | { unresolvable: string } {
  // #393 SOL r5 B1: the host resolves the default agent and its workspace
  // from the DEEP-MERGED config — an $include can elect a different default
  // agent or redirect its workspace, so the raw root JSON cannot name the one
  // workspace the gateway loads hooks from.
  if (config.kind === 'present' && openClawConfigUsesInclude(config.value)) {
    return { unresolvable: 'openclaw.json uses $include — the merged agents/defaults doctor cannot attest decide the default agent workspace' };
  }
  const obj = (v: unknown): Record<string, unknown> =>
    v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
  const { entries, defaultAgentId } = openClawAgentEntries(config);
  const entry = entries.find((e) => normalizeOpenClawAgentId(e.id) === defaultAgentId);
  const explicit = entry && typeof entry.workspace === 'string' ? entry.workspace.trim() : '';
  if (explicit) return resolveOpenClawUserPath(explicit, ocHome);
  const fallback = config.kind === 'present' ? obj(obj(config.value.agents).defaults).workspace : undefined;
  const fallbackStr = typeof fallback === 'string' ? fallback.trim() : '';
  if (fallbackStr) return resolveOpenClawUserPath(fallbackStr, ocHome);
  const profile = process.env.OPENCLAW_PROFILE?.trim();
  return {
    path: path.join(
      ocHome,
      '.openclaw',
      profile && profile.toLowerCase() !== 'default' ? `workspace-${profile}` : 'workspace',
    ),
  };
}

/**
 * Strict literal frontmatter proof (#393 SOL r5 B2). OpenClaw's frontmatter
 * parser (openclaw/src/markdown/frontmatter.ts) YAML-parses the block —
 * double-quoted scalars DECODE escapes ("\u006eame" → name), quoted keys are
 * trimmed, flow maps restructure the document, and a failed YAML parse falls
 * back to a per-line parser whose extra keys are merged in. Doctor cannot run
 * the host's YAML stack from this repo (drift trap), so a HOOK.md clears only
 * when it is provably inert under BOTH parsers:
 *  - no frontmatter block at all (the hook keeps its dir name), or
 *  - every block line blank, a comment, an indented continuation UNDER a
 *    column-0 entry, or a column-0 `key: value` entry whose key and value are
 *    plain unquoted ASCII (no quotes, escapes, flow/tag/anchor/alias
 *    indicators, block scalars, or other YAML-active punctuation).
 * With every column-0 entry plain there is nothing for YAML to decode at the
 * top level and the line parser reads the same literal values; a folded
 * continuation always joins with whitespace, so no `name` can become
 * cortex-memory without the literal appearing (the caller's literal scan —
 * re-checked here for standalone use). Everything else — quoted keys or
 * values, escapes, flow maps, indented roots, unparseable lines — is an
 * unproven rebrand. Exported for direct unit testing.
 */
export function probeOpenClawHookMdRebrand(
  raw: string,
): { kind: 'clear' } | { kind: 'unproven'; detail: string } {
  // Mirror of the host's extractFrontmatterBlock: normalize newlines, take
  // the block between the leading `---` and the first `\n---` (no block, no
  // frontmatter — parseFrontmatterBlock returns {} and nothing rebrands).
  const normalized = raw.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  if (!normalized.startsWith('---')) return { kind: 'clear' };
  const end = normalized.indexOf('\n---', 3);
  if (end === -1) return { kind: 'clear' };
  const block = normalized.slice(4, end);
  let anchored = false;
  for (const line of block.split('\n')) {
    if (/^[ \t]*$/.test(line)) continue;
    // Comment lines define keys in neither parser.
    if (/^[ \t]*#/.test(line)) continue;
    if (/^[ \t]/.test(line)) {
      // Indented content is nested/continuation — inert for top-level keys —
      // but ONLY once a column-0 entry anchored the root mapping at column 0.
      // An indented FIRST entry re-anchors the whole root map at that indent,
      // and a quoted key there decodes like any other.
      if (anchored) continue;
      return {
        kind: 'unproven',
        detail: 'frontmatter starts with an indented entry — the YAML root mapping is not anchored at column 0, so its keys cannot be evaluated plainly',
      };
    }
    const entry = line.match(/^([A-Za-z0-9_-]+):(?:[ \t]+(.*))?$/);
    if (!entry) {
      return {
        kind: 'unproven',
        detail: 'frontmatter carries a line that is not a plain `key: value` entry — quoted keys, flow maps, and YAML escapes decode under the host parser and could rebrand the hook as cortex-memory',
      };
    }
    anchored = true;
    const value = (entry[2] ?? '').trim();
    if (value !== '' && !/^[A-Za-z0-9][A-Za-z0-9 ._/-]*$/.test(value)) {
      return {
        kind: 'unproven',
        detail: `frontmatter \`${entry[1]}:\` carries a value doctor cannot evaluate plainly — quotes, escapes, and YAML indicators decode under the host parser`,
      };
    }
    if (entry[1] === 'name') {
      if (value === '') {
        return {
          kind: 'unproven',
          detail: 'frontmatter `name:` has no inline value — a nested or folded name cannot be evaluated plainly',
        };
      }
      if (/^cortex-memory$/i.test(value)) {
        return { kind: 'unproven', detail: 'frontmatter names cortex-memory' };
      }
    }
  }
  return { kind: 'clear' };
}

/**
 * Hook-precedence shadow probe (#393 SOL r4 B3). OpenClaw merges hook sources
 * extra < bundled < managed < WORKSPACE (openclaw/src/hooks/workspace.ts
 * loadHookEntries — workspace wins by hook NAME), and the gateway loads from
 * the default agent workspace — so a workspace hook named cortex-memory
 * silently replaces the managed handler no matter how byte-current the
 * managed artifacts are. The name is not bound to the directory: HOOK.md
 * frontmatter `name:` rebrands any dir, and a package.json manifest redirects
 * hook definitions to arbitrary nested dirs. Doctor clears the workspace
 * hooks dir only when every subdir provably CANNOT shadow cortex-memory:
 *  - no package.json manifest (redirection is unprovable without running the
 *    host's loader);
 *  - a dir named cortex-memory only when byte-current with the packaged
 *    source (an identical shadow still delivers the pack);
 *  - any other dir only when its HOOK.md is readable, never mentions
 *    cortex-memory, and passes the strict literal frontmatter proof above
 *    (#393 SOL r5 B2 — the host's YAML parser decodes quoting/escapes a text
 *    scan cannot see); a dir with no HOOK.md and no manifest loads nothing.
 * Anything else — differing content, unreadable evidence, cap overflow — is
 * an unproven shadow: what actually runs is unattested, so wired_proven must
 * not stand. Exported for direct unit testing.
 */
const OPENCLAW_WORKSPACE_HOOK_CAP = 50;
export function probeOpenClawWorkspaceHookShadow(
  workspaceDir: string,
  hookFiles: readonly string[],
  stale: (destDir?: string) => boolean,
  sourceAvailable: boolean,
): { kind: 'none' | 'identical' } | { kind: 'unproven'; detail: string } {
  return probeOpenClawHooksDirClaim(path.join(workspaceDir, 'hooks'), hookFiles, stale, sourceAvailable);
}

/**
 * Who can serve the cortex-memory name out of ONE hooks source dir (#393 SOL
 * r4 B3 + r6 B2). loadHooksFromDir applies the same rules to every source —
 * the default workspace's hooks dir AND the managed <stateRoot>/hooks dir:
 * a package.json manifest redirects hook definitions to nested dirs and
 * SKIPS the root HOOK.md (openclaw/src/hooks/workspace.ts loadHooksFromDir),
 * and frontmatter `name:` rebrands any dir. So even the managed dir can stop
 * serving the byte-current pack (manifest redirect) or serve a rival
 * definition of the name (sibling rebrand) — same-source collisions leave
 * what-runs unattested. Clears only when every subdir provably CANNOT claim
 * cortex-memory away from the packaged set; `identical` = a byte-current
 * cortex-memory dir with no manifest is present. Exported for direct unit
 * testing.
 */
export function probeOpenClawHooksDirClaim(
  hooksDir: string,
  hookFiles: readonly string[],
  stale: (destDir?: string) => boolean,
  sourceAvailable: boolean,
): { kind: 'none' | 'identical' } | { kind: 'unproven'; detail: string } {
  const dirProbe = probePath(hooksDir);
  if (dirProbe.kind === 'absent') return { kind: 'none' };
  if (dirProbe.kind !== 'present') {
    return {
      kind: 'unproven',
      detail: `${hooksDir} is unreadable (${dirProbe.code}) — a hook there could shadow the managed cortex-memory hook by name`,
    };
  }
  // loadHooksFromDir bails on a non-directory, and skips non-directory
  // entries (symlinked dirs included — Dirent.isDirectory() is false for
  // symlinks, so OpenClaw never follows them here).
  if (!dirProbe.stat.isDirectory()) return { kind: 'none' };
  let dirents: fs.Dirent[];
  try {
    dirents = fs.readdirSync(hooksDir, { withFileTypes: true });
  } catch (err: unknown) {
    return {
      kind: 'unproven',
      detail: `${hooksDir} cannot be listed (${err instanceof Error ? err.message : String(err)}) — workspace hook shadowing cannot be ruled out`,
    };
  }
  const subdirs = dirents.filter((d) => d.isDirectory());
  if (subdirs.length > OPENCLAW_WORKSPACE_HOOK_CAP) {
    return {
      kind: 'unproven',
      detail: `${hooksDir} holds more than ${OPENCLAW_WORKSPACE_HOOK_CAP} hook dirs — the shadow scan is incomplete, so workspace hook shadowing cannot be ruled out`,
    };
  }
  let identical = false;
  for (const d of subdirs) {
    const sub = path.join(hooksDir, d.name);
    if (probePath(path.join(sub, 'package.json')).kind !== 'absent') {
      return {
        kind: 'unproven',
        detail: `${sub} carries a package.json manifest — OpenClaw loads redirected hook definitions from manifests, so the handler that runs as cortex-memory cannot be attested`,
      };
    }
    if (d.name === 'cortex-memory') {
      const art = probeOpenClawScHookArtifacts(sub, hookFiles, stale, sourceAvailable);
      if (art === 'complete') {
        identical = true;
        continue;
      }
      return {
        kind: 'unproven',
        detail: `${sub} shadows the managed cortex-memory hook (workspace hooks win by name) and is not byte-current with the packaged source (${art}) — what actually runs cannot be proven to deliver the pack`,
      };
    }
    const hookMd = readTextProbe(path.join(sub, 'HOOK.md'));
    if (hookMd.kind === 'absent') continue;
    if (hookMd.kind === 'unreadable') {
      return {
        kind: 'unproven',
        detail: `${sub}/HOOK.md is unreadable — a frontmatter name could rebrand it as cortex-memory and shadow the managed hook`,
      };
    }
    if (/cortex-memory/i.test(hookMd.value)) {
      return {
        kind: 'unproven',
        detail: `${sub}/HOOK.md mentions cortex-memory — frontmatter \`name:\` rebrands a hook dir, so it may shadow the managed hook`,
      };
    }
    const rebrand = probeOpenClawHookMdRebrand(hookMd.value);
    if (rebrand.kind === 'unproven') {
      return {
        kind: 'unproven',
        detail: `${sub}/HOOK.md ${rebrand.detail} — it could rebrand the dir as cortex-memory and shadow the managed hook`,
      };
    }
  }
  return identical ? { kind: 'identical' } : { kind: 'none' };
}

/**
 * OpenClaw-effective home for expanding `~` in OpenClaw paths — mirror of
 * resolveRawHomeDir (openclaw/src/infra/home-dir.ts): OPENCLAW_HOME (itself
 * `~`-expandable against HOME/USERPROFILE) > HOME > USERPROFILE >
 * os.homedir().
 *
 * #393 SOL r4 B2: a non-`~`, non-absolute OPENCLAW_HOME is returned verbatim
 * by resolveRawHomeDir and then path.resolve()d against the OPENCLAW PROCESS
 * cwd (home-dir.ts resolveEffectiveHomeDir) — doctor resolving it against its
 * OWN cwd probed a decoy tree while OpenClaw ran from another. The same
 * cwd-fallback fires when nothing resolves at all (resolveRequiredHomeDir).
 * Both shapes are unresolvable for doctor: OpenClaw stays bound with buses
 * unknown, never probed against a guessed root.
 */
function openClawEffectiveHome(): { home: string } | { unresolvable: string } {
  const norm = (v: string | undefined): string | undefined => {
    const t = v?.trim();
    return t ? t : undefined;
  };
  const safeHomedir = (): string | undefined => {
    try {
      return norm(os.homedir());
    } catch {
      return undefined;
    }
  };
  const explicit = norm(process.env.OPENCLAW_HOME);
  if (explicit) {
    if (/^~($|[\\/])/.test(explicit)) {
      const fallback = norm(process.env.HOME) ?? norm(process.env.USERPROFILE) ?? safeHomedir();
      if (fallback) return { home: path.resolve(explicit.replace(/^~(?=$|[\\/])/, fallback)) };
      return { unresolvable: `OPENCLAW_HOME="${explicit}" has no HOME/USERPROFILE/homedir to expand ~ against — OpenClaw falls back to its own process cwd, which doctor cannot know` };
    }
    if (!path.isAbsolute(explicit)) {
      return { unresolvable: `OPENCLAW_HOME="${explicit}" is relative (\`~user\` included) — OpenClaw resolves it against its own process cwd, which doctor cannot know` };
    }
    return { home: path.resolve(explicit) };
  }
  const home = norm(process.env.HOME) ?? norm(process.env.USERPROFILE) ?? safeHomedir();
  if (home) return { home: path.resolve(home) };
  return { unresolvable: 'no OPENCLAW_HOME/HOME/USERPROFILE and os.homedir() unavailable — OpenClaw falls back to its own process cwd, which doctor cannot know' };
}

/**
 * Mirror of OpenClaw's resolveUserPath (openclaw/src/utils.ts, #393 SOL r3
 * B6): a leading `~` followed by `/`, `\`, or end-of-string expands against
 * the OpenClaw-effective home; EVERY other shape — `~user/...` included
 * (expandHomePrefix rewrites only the bare `~` prefix) and plain relative
 * paths — goes through path.resolve against the OpenClaw PROCESS cwd. Doctor
 * cannot know that cwd, so those values are unresolvable here: probing a
 * guessed tree could let OpenClaw vanish from the verdict while another
 * runtime carries the box to PASS.
 */
function resolveOpenClawUserPath(
  raw: string,
  home: string | null,
): { path: string } | { unresolvable: string } {
  const trimmed = raw.trim();
  if (/^~($|[\\/])/.test(trimmed)) {
    if (!home) {
      return { unresolvable: 'no home directory to expand ~ against — OpenClaw would fall back to its own process cwd, which doctor cannot know' };
    }
    return { path: path.resolve(trimmed.replace(/^~(?=$|[\\/])/, home)) };
  }
  if (trimmed.startsWith('~')) {
    return { unresolvable: 'OpenClaw does not expand ~user paths — resolveUserPath sends them through path.resolve against its own process cwd, which doctor cannot know' };
  }
  if (path.isAbsolute(trimmed)) return { path: path.resolve(trimmed) };
  return { unresolvable: 'a relative path resolves against the OpenClaw process cwd, which doctor cannot know' };
}

/**
 * OpenClaw state root (#393 SOL r2 B6 + r3 B6): OPENCLAW_STATE_DIR (or legacy
 * CLAWDBOT_STATE_DIR) relocates the whole tree and is resolved with the
 * host's own resolveUserPath semantics — `~` expands against the
 * OpenClaw-effective home; relative and `~user` forms are unresolvable and
 * must cap OpenClaw evidence at unknown rather than silently probing a wrong
 * tree. Default: `<effective home>/.openclaw` (the historical
 * .clawdbot/.moldbot/.moltbot fallback dirs stay unprobed — documented
 * residual). Config, hook, and workspace evidence must all honour the same
 * root — otherwise old complete artifacts under the default root prove
 * delivery for a runtime that actually lives (unwired) somewhere else.
 */
function openClawStateRoot(ocHome: string): { root: string; detail?: undefined } | { root: null; detail: string } {
  const primary = process.env.OPENCLAW_STATE_DIR?.trim();
  const override = primary || process.env.CLAWDBOT_STATE_DIR?.trim();
  if (override) {
    const resolved = resolveOpenClawUserPath(override, ocHome);
    if ('path' in resolved) return { root: resolved.path };
    return {
      root: null,
      detail: `${primary ? 'OPENCLAW_STATE_DIR' : 'CLAWDBOT_STATE_DIR'}="${override}" is unresolvable: ${resolved.unresolvable}`,
    };
  }
  // #393 SOL r7: OpenClaw's resolveStateDir falls back to the historical
  // .clawdbot/.moldbot/.moltbot state dirs when ~/.openclaw is absent
  // (openclaw/src/config/paths.ts resolveStateDir). A doctor that defaults to
  // ~/.openclaw unconditionally probes a tree the host is not using —
  // workspace-<agentId>, hooks/, everything — and can prove native off in the
  // wrong universe. Mirror the fallback: prefer .openclaw when it exists,
  // else the first existing legacy dir (host order). A dir doctor cannot
  // stat is fail-closed: the root is unresolvable, evidence goes unknown.
  const newDir = path.join(ocHome, '.openclaw');
  // OPENCLAW_TEST_FAST=1 makes the host skip the legacy fallback entirely
  // (paths.ts resolveStateDir) — mirror it, or a decoy legacy tree gets
  // attested while the host runs from ~/.openclaw.
  if (process.env.OPENCLAW_TEST_FAST === '1') return { root: newDir };
  const probeDir = (dir: string): 'present' | 'absent' | 'error' => {
    const p = probePath(dir);
    return p.kind === 'present' ? 'present' : p.kind === 'absent' ? 'absent' : 'error';
  };
  const newState = probeDir(newDir);
  if (newState === 'present') return { root: newDir };
  if (newState === 'error') {
    return { root: null, detail: `~/.openclaw exists but cannot be inspected — the state root (and any legacy fallback) cannot be attested` };
  }
  for (const legacyName of OPENCLAW_LEGACY_STATE_DIRNAMES) {
    const legacyDir = path.join(ocHome, legacyName);
    const legacyState = probeDir(legacyDir);
    if (legacyState === 'present') return { root: legacyDir };
    if (legacyState === 'error') {
      return { root: null, detail: `${legacyName} cannot be inspected — OpenClaw's legacy state-dir fallback cannot be ruled out` };
    }
  }
  return { root: newDir };
}

/**
 * Legacy config binding (#393 SOL r6 B1). OpenClaw selects its config from a
 * candidate LIST, not one path (openclaw/src/config/paths.ts
 * resolveDefaultConfigCandidates → resolveConfigPathCandidate): with no
 * explicit config-path override, every candidate dir — the state-dir override
 * when set, then <home>/.openclaw and the historical
 * .clawdbot/.moldbot/.moltbot dirs — is probed for openclaw.json AND the
 * legacy filenames clawdbot.json/moldbot.json/moltbot.json, dir-major, first
 * existing file wins. Doctor fully grades only <stateRoot>/openclaw.json
 * (always candidate #1): when any OTHER candidate is what OpenClaw binds, the
 * runtime is LIVE here with a config doctor does not grade — it must stay
 * bound with config-derived evidence capped at unknown, never vanish from the
 * verdict. A candidate doctor cannot stat counts as existing (fail-closed);
 * OpenClaw's own existsSync would skip it, but doctor cannot prove that from
 * a stat error in its own process. Bounded: ≤20 stats. Exported for direct
 * unit testing.
 */
const OPENCLAW_LEGACY_CONFIG_FILENAMES = ['clawdbot.json', 'moldbot.json', 'moltbot.json'] as const;
const OPENCLAW_LEGACY_STATE_DIRNAMES = ['.clawdbot', '.moldbot', '.moltbot'] as const;
export function openClawBoundConfigCandidate(
  ocHome: string,
  stateRoot: string,
  stateRootIsOverride: boolean,
): { kind: 'graded' } | { kind: 'none' } | { kind: 'ungraded'; path: string } {
  const graded = path.resolve(path.join(stateRoot, 'openclaw.json'));
  const names = ['openclaw.json', ...OPENCLAW_LEGACY_CONFIG_FILENAMES];
  const dirs = stateRootIsOverride ? [stateRoot] : [];
  dirs.push(path.join(ocHome, '.openclaw'), ...OPENCLAW_LEGACY_STATE_DIRNAMES.map((d) => path.join(ocHome, d)));
  for (const dir of dirs) {
    for (const name of names) {
      const candidate = path.join(dir, name);
      if (probePath(candidate).kind === 'absent') continue;
      return path.resolve(candidate) === graded ? { kind: 'graded' } : { kind: 'ungraded', path: candidate };
    }
  }
  return { kind: 'none' };
}

/**
 * Binaries the packaged HOOK.md requires (metadata.openclaw.requires.bins) —
 * #393 SOL r4 B4. Pinned against hooks/openclaw/cortex-memory/HOOK.md by a
 * drift-guard test, so a requirement added to the hook without teaching doctor
 * fails CI instead of silently green-washing.
 */
export const OPENCLAW_HOOK_REQUIRED_BINS = ['npx'] as const;

/**
 * Mirror of OpenClaw's hasBinary (openclaw/src/shared/config-eval.ts): scan
 * each PATH entry for an X_OK candidate, with PATHEXT extensions on Windows.
 * No cache — doctor asks once per run.
 */
function openClawHasBinary(bin: string): boolean {
  const pathEnv = process.env.PATH ?? '';
  const parts = pathEnv.split(path.delimiter).filter(Boolean);
  const rawExt = process.env.PATHEXT;
  const extensions = process.platform === 'win32'
    ? ['', ...(rawExt !== undefined ? rawExt.split(';').map((v) => v.trim()) : ['.EXE', '.CMD', '.BAT', '.COM']).filter(Boolean)]
    : [''];
  for (const part of parts) {
    for (const ext of extensions) {
      try {
        fs.accessSync(path.join(part, bin + ext), fs.constants.X_OK);
        return true;
      } catch {
        // keep scanning
      }
    }
  }
  return false;
}

/**
 * Runtime-eligibility reading for the SC hook (#393 SOL r4 B4): OpenClaw
 * evaluates HOOK.md `requires.bins` the same way at load (shouldIncludeHook →
 * evaluateRuntimeRequires) and silently excludes the hook when a binary is
 * missing. Doctor checks its OWN PATH — the gateway process may run under a
 * different one, so "missing" caps at unknown (registration unattestable)
 * rather than proving not_wired, and "available" stays static attestation.
 * Exported for direct unit testing.
 */
export function openClawRequiredBinsProbe(
  bins: readonly string[] = OPENCLAW_HOOK_REQUIRED_BINS,
): { kind: 'available' } | { kind: 'missing'; detail: string } {
  const missing = bins.filter((bin) => !openClawHasBinary(bin));
  if (missing.length === 0) return { kind: 'available' };
  return {
    kind: 'missing',
    detail: `required binar${missing.length === 1 ? 'y' : 'ies'} ${missing.join(', ')} not resolvable on PATH — ` +
      'OpenClaw excludes hooks whose HOOK.md requires.bins are unavailable, so the installed hook may never register',
  };
}

/**
 * SC hook artifact probe (#393 SOL H1): a bare directory is not wiring. The
 * required file set and byte-currency come from the installer's own
 * authorities (HOOK_FILES / hookFilesStale in src/setup/openclaw.ts) — the
 * same ones `shieldcortex openclaw install` and the installer doctor use.
 *
 * `sourceAvailable=false` (#393 SOL r2 B6): `hookFilesStale` answers `false`
 * when the packaged HOOK_SOURCE is missing — right for the installer ("cannot
 * claim a refresh is needed"), fatal for a proof caller that would read it as
 * byte-current. With no source to compare against, a complete-looking install
 * is `unverifiable`, never `complete`.
 *
 * Exported for direct unit testing of the fail-closed mapping.
 */
export function probeOpenClawScHookArtifacts(
  dir: string,
  hookFiles: readonly string[],
  stale: (destDir?: string) => boolean,
  sourceAvailable: boolean,
): OpenClawHookArtifacts {
  const dirProbe = probePath(dir);
  if (dirProbe.kind === 'absent') return 'absent';
  if (dirProbe.kind !== 'present') return 'unreadable';
  let incomplete = false;
  for (const file of hookFiles) {
    const p = probePath(path.join(dir, file));
    if (p.kind === 'absent') incomplete = true;
    else if (p.kind !== 'present') return 'unreadable';
    else if (p.stat.isFile() && p.stat.size === 0) incomplete = true;
  }
  if (incomplete) return 'incomplete';
  if (!sourceAvailable) return 'unverifiable';
  try {
    return stale(dir) ? 'stale' : 'complete';
  } catch {
    return 'unreadable';
  }
}

/**
 * Where OpenClaw's config actually lives on this box, and what reading it
 * yields — the single resolution of that precedence chain (#393 SOL r3 B6 /
 * r6 B1), shared by the host-contract proof and the #394 plane-drift scan so
 * the two checks can never disagree about which tree they are grading.
 *
 * `unresolvable` set means every OpenClaw reading below is a guess: the caller
 * must cap its evidence at unknown rather than probe a tree the host may not
 * be using.
 */
interface OpenClawBinding {
  /** OpenClaw-effective home, or null when it cannot be resolved. */
  ocHome: string | null;
  stateRoot: { root: string | null; detail?: string };
  /** The config file doctor grades, or null when there is none to grade. */
  configPath: string | null;
  config: ProbeRead<Record<string, unknown>>;
  unresolvable?: string;
  /** Set when OpenClaw binds a config candidate doctor deliberately does not grade. */
  legacyConfig?: string;
}

function resolveOpenClawBinding(): OpenClawBinding {
  const ocHomeRes = openClawEffectiveHome();
  const ocHome = 'home' in ocHomeRes ? ocHomeRes.home : null;
  const stateRoot: { root: string | null; detail?: string } = 'unresolvable' in ocHomeRes
    ? { root: null, detail: ocHomeRes.unresolvable }
    : openClawStateRoot(ocHomeRes.home);
  let unresolvable = stateRoot.detail;
  let configPath: string | null = null;
  let legacyConfig: string | undefined;
  if (!unresolvable) {
    const cfgPrimary = process.env.OPENCLAW_CONFIG_PATH?.trim();
    const cfgOverride = cfgPrimary || process.env.CLAWDBOT_CONFIG_PATH?.trim();
    if (cfgOverride) {
      const resolved = resolveOpenClawUserPath(cfgOverride, ocHome);
      if ('path' in resolved) configPath = resolved.path;
      else {
        unresolvable =
          `${cfgPrimary ? 'OPENCLAW_CONFIG_PATH' : 'CLAWDBOT_CONFIG_PATH'}="${cfgOverride}" is unresolvable: ${resolved.unresolvable}`;
      }
    } else {
      configPath = path.join(stateRoot.root as string, 'openclaw.json');
      // #393 SOL r6 B1: the host binds the FIRST existing candidate across
      // current and legacy filenames/state dirs — a clawdbot-era config is a
      // live OpenClaw whose graded openclaw.json is absent.
      const hasStateOverride = Boolean(
        process.env.OPENCLAW_STATE_DIR?.trim() || process.env.CLAWDBOT_STATE_DIR?.trim(),
      );
      const candidate = openClawBoundConfigCandidate(ocHome as string, stateRoot.root as string, hasStateOverride);
      if (candidate.kind === 'ungraded') legacyConfig = candidate.path;
    }
  }
  const config: ProbeRead<Record<string, unknown>> = configPath === null
    ? { kind: 'absent' }
    : readJsonProbe(configPath);
  return {
    ocHome,
    stateRoot,
    configPath,
    config,
    ...(unresolvable ? { unresolvable } : {}),
    ...(legacyConfig ? { legacyConfig } : {}),
  };
}

export async function checkMemoryHostContract(): Promise<CheckResult> {
  const label = 'Memory plane (host contract)';
  let raw: Record<string, unknown> = {};
  const configPath = path.join(getConfigDir(), 'config.json');
  try {
    raw = JSON.parse(fs.readFileSync(configPath, 'utf-8')) as Record<string, unknown>;
  } catch {
    return { label, status: 'info', message: 'no config yet' };
  }
  const cfg = readMemoryPlaneFromConfig(raw);
  const home = os.homedir();
  const nowMs = Date.now();
  const ctx = { contract: cfg.nativeContract ?? '', plane: cfg.plane, nowMs };
  const declared = (id: HostRuntimeId): boolean => cfg.declaredRuntimes.includes(id);

  // The installer's own authorities for what a wired hook IS (#393 SOL H1).
  // Dynamic import mirrors checkOpenClawHookFreshness — setup/openclaw.js is
  // heavy and only needed here.
  const { HOOK_FILES, hookFilesStale, hookSourceAvailable } = await import('../setup/openclaw.js');

  // #393 SOL r3 B6 + r4 B2: the OpenClaw-effective home and the state-dir /
  // config-path overrides all resolve with the host's own semantics. A value
  // doctor cannot resolve (relative OPENCLAW_HOME, relative or ~user
  // overrides) makes EVERY OpenClaw reading a guess — the probe is marked
  // unresolvable and the evidence model caps OpenClaw at unknown instead of
  // probing a wrong tree it could vanish from.
  const binding = resolveOpenClawBinding();
  const { ocHome, stateRoot, config: ocConfig } = binding;
  const ocUnresolvable = binding.unresolvable;
  const ocLegacyConfig = binding.legacyConfig;
  const ocWorkspaces = stateRoot.root === null || ocHome === null
    ? { paths: [], complete: false }
    : openClawWorkspacePaths(ocHome, stateRoot.root, ocConfig);
  // #393 SOL r4 B3: hook precedence — a hook in the DEFAULT agent workspace
  // overwrites the managed cortex-memory hook by name at gateway load, so the
  // managed artifact proof only stands when that workspace provably carries
  // no shadow (or an identical one).
  const ocDefaultWs = ocHome === null ? null : openClawDefaultWorkspace(ocHome, ocConfig);
  const ocWorkspaceHookShadow = ocDefaultWs === null
    ? {
      kind: 'unproven' as const,
      detail: 'OpenClaw paths are unresolvable — the default agent workspace, and any hook shadowing inside it, cannot be probed',
    }
    : 'unresolvable' in ocDefaultWs
      ? {
        kind: 'unproven' as const,
        detail: `the default agent workspace is unresolvable (${ocDefaultWs.unresolvable}) — a workspace hook there could shadow the managed cortex-memory hook and cannot be ruled out`,
      }
      : probeOpenClawWorkspaceHookShadow(ocDefaultWs.path, HOOK_FILES, hookFilesStale, hookSourceAvailable());
  // #393 SOL r6 B2: the MANAGED hooks dir obeys the same loader rules as a
  // workspace source — a package.json inside cortex-memory redirects the
  // definitions away from the byte-current root set, and a sibling dir can
  // claim the name via manifest or frontmatter.
  const ocManagedHookClaim = stateRoot.root === null
    ? {
      kind: 'unproven' as const,
      detail: 'OpenClaw paths are unresolvable — the managed hooks dir cannot be probed for manifest redirects or name claims',
    }
    : probeOpenClawHooksDirClaim(path.join(stateRoot.root, 'hooks'), HOOK_FILES, hookFilesStale, hookSourceAvailable());
  const runtimes: HostRuntimeEvidence[] = [
    resolveOpenClawEvidence(
      {
        config: ocConfig,
        scHook: stateRoot.root === null
          ? 'unreadable'
          : probeOpenClawScHookArtifacts(
            path.join(stateRoot.root, 'hooks', 'cortex-memory'),
            HOOK_FILES,
            hookFilesStale,
            hookSourceAvailable(),
          ),
        scAutoMemory: cfg.openclawAuto,
        workspaces: ocWorkspaces.paths.map((ws) => ({
          path: ws,
          agentsMd: readTextProbe(path.join(ws, 'AGENTS.md')),
          // Both spellings: OpenClaw bootstraps MEMORY.md AND memory.md
          // (#393 SOL r2 B1). On a case-insensitive filesystem these stat the
          // same file twice, which is harmless duplicate proof, not error.
          memoryFiles: [
            artifactProbe(path.join(ws, 'MEMORY.md')),
            artifactProbe(path.join(ws, 'memory.md')),
          ],
        })),
        workspaceScanComplete: ocWorkspaces.complete,
        declared: declared('openclaw'),
        requiredBins: openClawRequiredBinsProbe(),
        workspaceHookShadow: ocWorkspaceHookShadow,
        managedHookDirClaim: ocManagedHookClaim,
        ...(ocLegacyConfig ? { legacyConfig: ocLegacyConfig } : {}),
        ...(ocUnresolvable ? { pathOverrideUnresolvable: ocUnresolvable } : {}),
      },
      ctx,
    ),
    resolveClaudeCodeEvidence(
      (() => {
        const scan = scanClaudeNativeStores(home);
        return {
          settings: readJsonProbe(path.join(home, '.claude', 'settings.json')),
          nativeStores: scan.stores,
          storeScanComplete: scan.scanComplete,
          // Shape-valid commands must also RESOLVE cleanly (#393 SOL r2 B3).
          commandTrust: hookCommandTrust,
          declared: declared('claude_code'),
        };
      })(),
      ctx,
    ),
    resolveHermesEvidence(
      (() => {
        const text = readTextProbe(path.join(home, '.hermes', 'config.yaml'));
        const profileScan = scanHermesProfiles(home);
        return {
          config: text.kind === 'present'
            ? { kind: 'present' as const, value: parseHermesMemoryBlock(text.value) }
            : text,
          profiles: profileScan.profiles,
          profileScanComplete: profileScan.scanComplete,
          scPluginInstalled: probePath(path.join(home, '.hermes', 'plugins', 'shieldcortex')).kind === 'present',
          nativeArtifacts: [
            artifactProbe(path.join(home, '.hermes', 'memories', 'MEMORY.md')),
            artifactProbe(path.join(home, '.hermes', 'MEMORY.md')),
            ...profileScan.artifacts,
          ],
          declared: declared('hermes'),
        };
      })(),
      ctx,
    ),
  ];

  const verdict = evaluateHostContract({
    plane: cfg.plane,
    injectConfigured: cfg.injectConfigured,
    injectMode: cfg.injectMode,
    injectModeLegal: cfg.injectModeLegal,
    injectModeExplicit: cfg.injectModeExplicit,
    nativeContract: cfg.nativeContract === 'sc_only' || cfg.nativeContract === 'disable_native_inject'
      ? cfg.nativeContract
      : null,
    postureRaw: cfg.posture,
    postureTrusted: hasTrustedMemorySidecarPosture(raw, configPath),
    postureIllegal: cfg.postureIllegal,
    declaredRuntimesIllegal: cfg.declaredRuntimesIllegal,
    runtimes,
    nowMs,
  });

  return {
    label,
    status: verdict.status,
    message: verdict.message,
    ...(verdict.fix ? { fix: verdict.fix } : {}),
  };
}

async function checkMemoryCaptureDist(): Promise<CheckResult[]> {
  const distResult = await runMemoryCaptureDistCheck(resolveSelfInstallDir());
  const dropsResult = runMemoryCaptureDropsCheck(getDbPath());
  return [distResult, dropsResult];
}

// ── Check 10: Brain-worker freshness (#45) ────────────────
/**
 * The MCP server starts a lite-profile brain worker on connect (v4.14.0).
 * Each light tick writes to ~/.shieldcortex/state/worker.json. If the
 * timestamp is missing or older than 30 min, consolidation has likely
 * stalled — STM won't graduate to LTM.
 */
function isPidAlive(pid: number): boolean | null {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err: unknown) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ESRCH') return false; // No such process — definitely dead
    if (code === 'EPERM') return true;  // Process exists but owned by another user
    return null;                         // Unknown — don't make claims
  }
}

function workerRecoveryFix(): string {
  // The right recovery is platform-dependent. On a headless Linux host (most
  // common shape: OpenClaw + bot user, no Claude Code), the durable answer
  // is `service install --headless` plus `loginctl enable-linger`. On macOS
  // and on dev machines running Claude Code, restarting the editor spawns
  // a fresh MCP-bound worker.
  if (process.platform === 'linux') {
    return 'For persistence, run `shieldcortex service install --headless` (recommended on headless hosts) or restart Claude Code';
  }
  return 'Restart Claude Code (spawns a fresh MCP-hosted worker), or run `shieldcortex service install` to start — or restart — the supervised launchd service';
}

// worker.json is last-writer-wins: an MCP-hosted worker dies with its Claude
// Code session and leaves its dead pid in the file until a surviving worker's
// next tick overwrites it — up to MCP_LIGHT_TICK_INTERVAL_MS for mcp-profile
// survivors. Within that window (plus slack) a dead pid is expected churn,
// not a failure.
const WORKER_TAKEOVER_GRACE_MS = MCP_LIGHT_TICK_INTERVAL_MS + 5 * 60 * 1000;

/**
 * "No worker.json" means two different things depending on whether the product
 * has ever run on this box.
 *
 * With no database either, nothing has run yet — the worker starts with the
 * first ShieldCortex session, so its absence is the normal state of a fresh
 * install and a ⚠️ there is the same false alarm as ❌ Database (#129).
 *
 * With a database present, something HAS run and the worker still never
 * recorded a tick — that is a real gap, and still warns.
 */
export function missingWorkerStateResult(databaseExists: boolean): CheckResult {
  if (!databaseExists) {
    return {
      label: 'Brain worker',
      status: 'info',
      message: 'not started yet — starts with your first ShieldCortex session',
      fix: workerRecoveryFix(),
    };
  }
  return {
    label: 'Brain worker',
    status: 'warn',
    message: 'no worker.json — worker has not run yet',
    fix: workerRecoveryFix(),
  };
}

export async function checkBrainWorker(): Promise<CheckResult> {
  if (process.env.SHIELDCORTEX_DISABLE_WORKER === '1') {
    return {
      label: 'Brain worker',
      status: 'info',
      message: 'disabled via SHIELDCORTEX_DISABLE_WORKER=1',
    };
  }
  const statePath = path.join(getShieldCortexDir(), 'state', 'worker.json');
  const stateProbe = probePath(statePath);
  if (stateProbe.kind === 'denied' || stateProbe.kind === 'error') {
    // Unreadable state is not "the worker has not run yet" (#132).
    return unreadableResult('Brain worker', statePath, stateProbe);
  }
  if (stateProbe.kind === 'absent') {
    // isAbsent, not existsSync: an unreadable database means something HAS
    // been installed here, so a missing worker.json is a real gap, not the
    // fresh-install state.
    return missingWorkerStateResult(!isAbsent(getDbPath()));
  }
  try {
    const raw = JSON.parse(fs.readFileSync(statePath, 'utf-8')) as {
      pid?: number;
      profile?: string;
      lastLightTick?: string;
    };
    const last = raw.lastLightTick ? new Date(raw.lastLightTick) : null;
    if (!last || Number.isNaN(last.getTime())) {
      return {
        label: 'Brain worker',
        status: 'warn',
        message: 'worker.json present but lastLightTick missing/invalid',
        fix: workerRecoveryFix(),
      };
    }
    const ageMs = Date.now() - last.getTime();
    const ageMin = Math.round(ageMs / 60000);
    const pid = typeof raw.pid === 'number' ? raw.pid : null;
    const profile = raw.profile ?? '?';

    // Pid liveness changes the meaning of staleness. A stale tick from a
    // *dead* process is a different failure mode than a stale tick from a
    // *running* process — only the first means "the worker crashed and
    // nothing's coming". The fix-hint diverges accordingly.
    const alive = pid != null ? isPidAlive(pid) : null;
    if (pid != null && alive === false) {
      // Grace applies only to mcp-profile hosts: they die with their Claude
      // Code window, so a dead pid inside one takeover window is expected
      // churn. A dead full-profile host (dashboard/api/worker — typically
      // supervised) is a real failure, and a future-dated tick (clock skew)
      // proves nothing — both warn immediately.
      if (profile === 'mcp' && ageMs >= 0 && ageMs <= WORKER_TAKEOVER_GRACE_MS) {
        return {
          label: 'Brain worker',
          status: 'info',
          message: `host pid ${pid} exited (last tick ${ageMin}m ago, profile=${profile}) — expected when a Claude Code session closes; if another ShieldCortex process is running, its worker takes over on its next tick (≤${Math.round(MCP_LIGHT_TICK_INTERVAL_MS / 60000)} min). Re-run doctor to confirm`,
        };
      }
      return {
        label: 'Brain worker',
        status: 'warn',
        message: `process gone (pid ${pid} dead, last tick ${ageMin}m ago, profile=${profile}) and no surviving worker has taken over`,
        fix: workerRecoveryFix(),
      };
    }
    if (ageMs > 30 * 60 * 1000) {
      return {
        label: 'Brain worker',
        status: 'warn',
        message: `last tick ${ageMin}m ago (profile=${profile}, pid=${pid ?? '?'}${alive === true ? ', alive' : ''})`,
        fix: alive === true
          ? 'Worker process alive but ticks stalled — restart Claude Code or `shieldcortex service repair`'
          : workerRecoveryFix(),
      };
    }
    return {
      label: 'Brain worker',
      status: 'pass',
      message: `last tick ${ageMin}m ago (profile=${profile}, pid=${pid ?? '?'})`,
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { label: 'Brain worker', status: 'warn', message: `check failed — ${msg}` };
  }
}

// ── Check 11: Project-key consistency (#42) ───────────────
/**
 * Detects rows tagged with both legacy basename keys and canonical
 * owner-repo keys (the symptom of pre-v4.14.0 stop-hook writes). If any
 * basename collides with a `<something>-<basename>` form already in the
 * DB, point the user at `repair-project-keys`.
 */
export interface ProjectKeyCollision {
  legacy: string;
  /** First canonical candidate — the auto-fix target when unambiguous. */
  canonical: string;
  /** Every canonical key ending in `-<legacy>`; >1 means ambiguous. */
  candidates: string[];
}

export interface ProjectKeyScan {
  keyCount: number;
  collisions: ProjectKeyCollision[];
  /** True when a colliding legacy key has rows outside long_term/episodic. */
  needsStm: boolean;
}

/**
 * Shared collision scanner behind both the doctor check and
 * `doctor --fix-project-keys`. A key is "legacy-looking" when it has no
 * hyphen (a raw cwd basename); it collides when another key ends with
 * `-<legacy>` (the canonical owner-repo form).
 */
export function scanProjectKeyCollisions(dbPath: string = getDbPath()): ProjectKeyScan {
  const Database = require('better-sqlite3');
  const db = new Database(dbPath, { readonly: true });
  try {
    const rows = db
      .prepare("SELECT DISTINCT project FROM memories WHERE project IS NOT NULL AND project != ''")
      .all() as Array<{ project: string }>;
    const keys = rows.map((r) => r.project);
    const collisions: ProjectKeyCollision[] = [];
    for (const candidate of keys) {
      if (candidate.includes('-')) continue;
      const suffix = `-${candidate}`;
      const candidates = keys.filter((k) => k !== candidate && k.endsWith(suffix));
      if (candidates.length > 0) {
        collisions.push({ legacy: candidate, canonical: candidates[0], candidates });
      }
    }
    const stmProbe = db.prepare(
      "SELECT COUNT(*) AS n FROM memories WHERE project = ? AND type NOT IN ('long_term', 'episodic')"
    );
    const needsStm = collisions.some((c) => (stmProbe.get(c.legacy) as { n: number }).n > 0);
    return { keyCount: keys.length, collisions, needsStm };
  } finally {
    db.close();
  }
}

/**
 * Auto-heal for the project-key collision warning: apply the repair doctor
 * already computed, restricted to unambiguous collisions (exactly one
 * canonical candidate). Ambiguous ones are left for a human `--map` call.
 * Delegates to `repairProjectKeys` so backup + JSON rewrite log apply.
 */
export async function fixProjectKeyCollisions(
  opts: { dbPath?: string } = {}
): Promise<{ applied: number; skippedAmbiguous: number; remaining: number; backupPath?: string }> {
  const dbPath = opts.dbPath ?? getDbPath();
  const scan = scanProjectKeyCollisions(dbPath);
  const unambiguous = scan.collisions.filter((c) => c.candidates.length === 1);
  const skippedAmbiguous = scan.collisions.length - unambiguous.length;
  if (unambiguous.length === 0) {
    return { applied: 0, skippedAmbiguous, remaining: scan.collisions.length };
  }
  const map = Object.fromEntries(unambiguous.map((c) => [c.legacy, c.canonical]));
  const { repairProjectKeys } = await import('./migrate-legacy.js');
  const report = await repairProjectKeys({
    dbPath,
    map,
    includeStm: scan.needsStm,
    execute: true,
    noConfirm: true,
  });
  const remaining = scanProjectKeyCollisions(dbPath).collisions.length;
  return { applied: report.applied, skippedAmbiguous, remaining, backupPath: report.backupPath };
}

export async function checkProjectKeyConsistency(): Promise<CheckResult> {
  const dbPath = getDbPath();
  if (!fs.existsSync(dbPath)) {
    return { label: 'Project keys', status: 'info', message: 'skipped (no DB yet)' };
  }
  try {
    const { keyCount, collisions, needsStm } = scanProjectKeyCollisions(dbPath);
    if (collisions.length === 0) {
      return { label: 'Project keys', status: 'pass', message: `${keyCount} distinct, no legacy/canonical collisions` };
    }
    const example = collisions.slice(0, 3).map((c) => `${c.legacy} ↔ ${c.canonical}`).join('; ');
    const more = collisions.length > 3 ? ` (+${collisions.length - 3} more)` : '';
    // Doctor already knows both sides of each collision, so hand the user
    // a runnable command with explicit --map pairs rather than a <root>
    // placeholder. The repair tool defaults to long_term/episodic rows;
    // when a colliding legacy key has rows outside that scope the default
    // repair leaves them behind and this warning survives it — suggest
    // --include-stm in that case.
    const mapFlags = collisions
      .map((c) => {
        const pair = `${c.legacy}=${c.canonical}`;
        return `--map ${/\s/.test(pair) ? `"${pair}"` : pair}`;
      })
      .join(' ');
    return {
      label: 'Project keys',
      status: 'warn',
      message: `${collisions.length} legacy/canonical collision(s): ${example}${more}`,
      fix: `Run \`shieldcortex doctor --fix-project-keys\` to auto-repair, or \`shieldcortex memories repair-project-keys ${mapFlags}${needsStm ? ' --include-stm' : ''}\` (dry-run by default; add --execute to apply)`,
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { label: 'Project keys', status: 'warn', message: `check failed — ${msg}` };
  }
}

// ── Check 12: Hook timeouts (#43) ─────────────────────────
/**
 * Compares each ShieldCortex hook's timeout in ~/.claude/settings.json
 * against the canonical values written by `shieldcortex setup`. Catches
 * the v4.13.x silent-recall failure mode where users on a hand-edited
 * settings.json still ran with `UserPromptSubmit.timeout: 2`.
 */
async function checkHookTimeouts(): Promise<CheckResult> {
  const settingsPath = path.join(os.homedir(), '.claude', 'settings.json');
  if (!fs.existsSync(settingsPath)) {
    return { label: 'Hook timeouts', status: 'info', message: 'skipped (settings.json not found)' };
  }
  try {
    const { CANONICAL_HOOK_TIMEOUTS } = await import('../setup/settings-hooks.js');
    const settings = JSON.parse(fs.readFileSync(settingsPath, 'utf-8')) as {
      hooks?: Record<string, Array<{ hooks?: Array<{ command?: string; timeout?: number }> }>>;
    };
    const hooks = settings.hooks ?? {};
    const drift: string[] = [];
    for (const [name, expected] of Object.entries(CANONICAL_HOOK_TIMEOUTS)) {
      const entries = hooks[name];
      if (!Array.isArray(entries)) continue;
      for (const entry of entries) {
        for (const h of entry.hooks ?? []) {
          if (typeof h.command !== 'string' || !h.command.includes('shieldcortex')) continue;
          if (typeof h.timeout === 'number' && h.timeout < expected) {
            drift.push(`${name}=${h.timeout}s (canonical ${expected}s)`);
          }
        }
      }
    }
    if (drift.length === 0) {
      return { label: 'Hook timeouts', status: 'pass', message: 'all canonical' };
    }
    return {
      label: 'Hook timeouts',
      status: 'warn',
      message: `below canonical: ${drift.join(', ')}`,
      fix: 'Re-run `shieldcortex install` to restore canonical timeouts',
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { label: 'Hook timeouts', status: 'info', message: `check skipped — ${msg}` };
  }
}

// ── Check: OpenClaw managed-pin drift / disabled realtime plugin ─────────────
/**
 * Detects the OpenClaw `EOVERRIDE` trap that silently disables the realtime
 * plugin on `openclaw update` (upstream openclaw/openclaw#91772).
 *
 * OpenClaw pins a plugin's shared deps in its generated project manifest's
 * `dependencies` (managed peers) but NEVER advances them, while it imports its
 * bundled workspace `overrides` afresh each release. When the two drift to
 * different versions for the same package, npm's `assertRootOverrides` throws
 * `EOVERRIDE` and OpenClaw disables the plugin (`enabled:false`) — so threat
 * telemetry silently stops. This surfaces both the pre-failure drift (so it can
 * be healed BEFORE the next update breaks it) and the already-disabled state.
 * The fix is `shieldcortex openclaw repair`.
 */
export async function checkOpenClawManagedPinDrift(
  home: string = os.homedir(),
): Promise<CheckResult> {
  const label = 'OpenClaw plugin pins';

  if (!fs.existsSync(path.join(home, '.openclaw'))) {
    return { label, status: 'info', message: 'skipped (OpenClaw not detected)' };
  }
  const manifest = readRealtimeProjectManifest(home);
  if (!manifest) {
    return { label, status: 'info', message: 'skipped (realtime plugin not installed)' };
  }

  const disabled = isRealtimePluginDisabledInConfig(home);
  const risks = findEoverrideRiskPins(manifest);

  if (disabled) {
    const detail = risks.length
      ? ` (manifest still has a version-drifted pin: ${risks.map((r) => r.name).join(', ')})`
      : '';
    return {
      label,
      status: 'fail',
      message: `realtime plugin is DISABLED in OpenClaw config${detail} — threat telemetry is not flowing`,
      fix: 'Run `shieldcortex openclaw repair` to reconcile the managed pins, reinstall, and re-enable the plugin.',
      needsOpenClawCli: { subcommand: 'plugins' },
    };
  }

  if (risks.length > 0) {
    const list = risks.map((r) => `${r.name} (dep ${r.dependencyVersion} ≠ override ${r.overrideVersion})`).join(', ');
    return {
      label,
      status: 'warn',
      message: `managed-pin drift will EOVERRIDE on the next \`openclaw update\`: ${list}`,
      fix: 'Run `shieldcortex openclaw repair` now to reconcile the pins before an update disables the plugin.',
      needsOpenClawCli: { subcommand: 'plugins' },
    };
  }

  return { label, status: 'pass', message: 'no managed-pin drift; plugin enabled' };
}

// ── Check: OpenClaw hook freshness (Task 6b) ─────────────
/**
 * The cortex-memory hook is installed by FILE COPY into
 * `~/.openclaw/hooks/cortex-memory/` (see src/setup/openclaw.ts). A package
 * update does NOT re-copy it automatically on every install shape — non-global
 * (dependency) installs skip the postinstall auto-refresh, and a documented
 * version-lag (OpenClaw 4.25.x vs a newer global) can leave the installed
 * `handler.ts` / `runtime.mjs` behind the packaged version. A stale hook keeps
 * running the OLD extraction logic, so memory-quality fixes never reach claws.
 *
 * `hookFilesStale()` is the single source of truth (byte-for-byte comparison
 * against the packaged HOOK_SOURCE). Doctor only DETECTS + GUIDES here — it has
 * no auto-repair mode, and re-copying files mid-doctor would be a surprising
 * side effect. The actionable fix is `shieldcortex openclaw install`.
 *
 * `destDir` is injectable for tests; defaults to the standard install dest.
 */
export async function checkOpenClawHookFreshness(
  destDir?: string,
): Promise<CheckResult> {
  const label = 'OpenClaw hook';
  try {
    const { defaultHookDestDir, hookFilesStale } = await import('../setup/openclaw.js');
    const dest = destDir ?? defaultHookDestDir();

    // Only meaningful when a hook copy actually exists on disk. A missing dest
    // dir means the integration simply isn't installed — that's the domain of
    // the OpenClaw residue / dup-installs checks, not a staleness warning.
    if (!fs.existsSync(dest)) {
      return { label, status: 'info', message: 'skipped (cortex-memory hook not installed)' };
    }

    if (hookFilesStale(dest)) {
      return {
        label,
        status: 'warn',
        message: 'cortex-memory hook is out of date (installed copy differs from packaged version)',
        fix: 'Run `shieldcortex openclaw install` to refresh the hook',
        needsOpenClawCli: {
          subcommand: 'plugins',
          // The hook refresh is a file copy that happens BEFORE OpenClaw is
          // invoked at all (copyHookFiles at openclaw.ts:1276, installPlugin at
          // :1320), and `--no-plugins` skips the OpenClaw half outright. So the
          // useful work lands even on a blocked host — withdrawing this outright
          // would leave the operator on a stale memory-capture hook with no
          // action, which is the same withheld-advice failure #221 is about.
          fallbackFix: 'Run `shieldcortex openclaw install --no-plugins` to refresh the hook (a file copy — this half still works). Refreshing the plugin needs a valid OpenClaw config first.',
        },
      };
    }

    return { label, status: 'pass', message: 'cortex-memory hook up to date' };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { label, status: 'info', message: `check skipped — ${msg}` };
  }
}

/**
 * Surfaces the installed OpenClaw realtime plugin's version and WARNs when it
 * lags the running ShieldCortex package.
 *
 * The plugin (`@drakon-systems/shieldcortex-realtime`) ships in lockstep with
 * the main package, but it's managed by OpenClaw's own registry
 * (`~/.openclaw/plugins/installs.json`) — `shieldcortex update` does NOT touch
 * it — so it can silently fall behind (observed: plugin stuck at 4.29.0 while
 * the npm package reached 4.30.1). The other OpenClaw checks confirm the plugin
 * is *present*; none read its *version*.
 *
 * The version is read from the plugin's on-disk package.json (ground truth — the
 * code OpenClaw actually loads), NOT the `installs.json` `version` field, which
 * OpenClaw 2026.6.1 leaves stale after moving plugin state into SQLite. `home` /
 * `expectedVersion` are injectable for tests.
 */
export async function checkOpenClawPluginVersion(
  home: string = os.homedir(),
  expectedVersion: string = pkg.version,
): Promise<CheckResult> {
  const label = 'OpenClaw plugin version';
  const installsJsonPath = path.join(home, '.openclaw', 'plugins', 'installs.json');

  // Present if either the registry lists it or an on-disk install resolves.
  if (!fs.existsSync(installsJsonPath) && !resolveRealtimePluginInstallPath(home)) {
    return { label, status: 'info', message: 'skipped (OpenClaw plugin registry not present)' };
  }

  const installed = readInstalledRealtimePluginVersion(home);
  if (!installed) {
    return { label, status: 'info', message: 'realtime plugin not registered with OpenClaw' };
  }

  // Defensive: if either version isn't valid semver, report presence without a verdict.
  if (!semver.valid(installed) || !semver.valid(expectedVersion)) {
    return { label, status: 'info', message: `realtime plugin v${installed} installed` };
  }

  if (semver.lt(installed, expectedVersion)) {
    return {
      label,
      status: 'warn',
      message: `realtime plugin v${installed} installed, v${expectedVersion} available`,
      fix: 'Run `openclaw plugins install --force @drakon-systems/shieldcortex-realtime@latest` (reliable past a pinned spec), then restart the gateway',
      needsOpenClawCli: { subcommand: 'plugins' },
    };
  }

  if (semver.gt(installed, expectedVersion)) {
    return { label, status: 'info', message: `realtime plugin v${installed} (ahead of local shieldcortex v${expectedVersion})` };
  }

  return { label, status: 'pass', message: `realtime plugin v${installed} (current)` };
}

/**
 * The #74 honest-state check: reconcile the realtime plugin's install metadata
 * across all three authoritative layers (openclaw.json enable flag, legacy
 * installs.json, the SQLite `installed_plugin_index`) and the on-disk build, and
 * FAIL LOUD when it is `enabled:true` but absent from the loaded roster — the
 * security fail-open where protection reports ON while the interceptor is
 * actually unloaded (aiquant, 2026-07-11). Also fails a version regression and
 * warns on installs.json↔index conflict or duplicate install dirs.
 *
 * Unlike every prior surface (`openclaw plugins list`, config, SC status), this
 * reads OpenClaw's own loaded roster, so a silent drop cannot hide. `home` /
 * `expectedVersion` are injectable for tests.
 */
/**
 * #225 phase 1: report whether conversation scanning is actually happening.
 *
 * OpenClaw drops the conversation hooks (`llm_input`/`llm_output`) at
 * registration unless a non-bundled plugin is granted
 * `plugins.entries.<id>.hooks.allowConversationAccess = true`. On this fleet
 * the gateway logged that drop six times in one day while ShieldCortex's own
 * startup line announced both hooks as registered — protection claimed, not
 * held.
 *
 * Two honest outcomes, and neither is a green tick for "protected":
 *  - ungranted → WARN. Nothing is being scanned. Not a `fail`: withholding
 *    conversation access is a legitimate operator choice on a sensitive
 *    surface, and crying damage over a deliberate decision is how a check
 *    earns the right to be ignored.
 *  - granted → INFO, explicitly OBSERVATION ONLY. `llm_input` has no blocking
 *    contract, so a pass tick here would be a fresh false green.
 */
export async function checkOpenClawConversationScanning(
  home: string = os.homedir(),
): Promise<CheckResult> {
  const label = 'Conversation scanning';
  if (!fs.existsSync(path.join(home, '.openclaw'))) {
    return { label, status: 'info', message: 'skipped (OpenClaw not detected)' };
  }

  const state = readConversationAccess(home, REALTIME_PLUGIN_ID);
  // #225 phase 2: the grant and the host's CAPABILITY are independent facts,
  // and an operator needs both. Granting access on a host whose OpenClaw
  // predates before_agent_run buys observation and nothing more — saying so up
  // front is cheaper than discovering it after enabling enforcement.
  const capability = evaluateEnforcementSupport(readOpenClawHostVersion(home));
  const message = `${describeConversationAccess(state, REALTIME_PLUGIN_ID)}; ${describeEnforcementSupport(capability)}`;

  if (!state.readable) {
    return {
      label,
      status: 'warn',
      message,
      fix: 'Check that ~/.openclaw/openclaw.json exists and is valid JSON, then re-run `shieldcortex doctor`.',
    };
  }
  if (!state.granted) {
    return { label, status: 'warn', message, fix: conversationAccessFix(REALTIME_PLUGIN_ID) };
  }
  if (capability.support === 'unsupported') {
    // Granted but incapable: scanning happens, enforcement never can. That is a
    // real ceiling on this host, not a misconfiguration — warn, and name the
    // version that lifts it.
    return {
      label,
      status: 'warn',
      message,
      fix: `Upgrade OpenClaw to ${capability.minVersion} or later if you want conversation enforcement to become possible. Scanning and auditing work as-is.`,
    };
  }
  return { label, status: 'info', message };
}

export async function checkOpenClawPluginLoadState(
  home: string = os.homedir(),
  expectedVersion: string = pkg.version,
): Promise<CheckResult> {
  const label = 'OpenClaw plugin loaded';
  if (!fs.existsSync(path.join(home, '.openclaw'))) {
    return { label, status: 'info', message: 'skipped (OpenClaw not detected)' };
  }

  const verdict = reconcilePluginState(gatherReconcileInput(home, { expectedVersion }));
  const result = renderPluginLoadVerdict(verdict);

  // #226: "loaded" is not "protecting the conversation". A plugin whose
  // conversation-access grant is missing has had its llm_input/llm_output
  // registrations refused by the host. Tool-call gating is live only when the
  // running roster proves the plugin loaded; conversation scanning is absent
  // either way. A green tick that says "loaded" and stops
  // there is read as "protected", so the pass is downgraded — a WARN, matching
  // the severity `checkOpenClawConversationScanning` uses for the same fact
  // (#225/#230): withholding the grant is a legitimate operator choice, not
  // damage. Only the pass is touched; every failing/warning state above owns
  // its own message and must not have this stacked on top of it.
  if (result.status === 'pass') {
    const access = readConversationAccess(home, REALTIME_PLUGIN_ID);
    if (access.readable && !access.granted) {
      const toolCallStatus =
        verdict.loadedInLiveRoster === true
          ? 'tool-call gating is live'
          : 'tool-call gating is NOT separately proven while live-roster evidence is unavailable';
      return {
        ...result,
        status: 'warn',
        message: `${result.message}. NOTE: conversation-hook access is NOT granted, so the gateway refuses this plugin's llm_input/llm_output hooks — ${toolCallStatus}; conversation scanning is NOT live`,
        fix: conversationAccessFix(REALTIME_PLUGIN_ID),
      };
    }
  }
  return result;
}

/**
 * Verdict → operator-facing check result. Split out of
 * `checkOpenClawPluginLoadState` so every state can be asserted directly
 * (#222): the bug there was not the classification but the RENDERING — a
 * `default:` arm that returned `pass`, so any state this function did not
 * explicitly recognise (including a newly added unprotected one) green-ticked.
 * There is no catch-all pass here now; `healthy` is spelled out, and anything
 * unrecognised warns.
 */
export function renderPluginLoadVerdict(verdict: ReconcileVerdict): CheckResult {
  const label = 'OpenClaw plugin loaded';
  const fix = 'Run `shieldcortex repair` to reconcile the plugin install metadata and verify it actually loads.';

  switch (verdict.state) {
    case 'not-installed':
      return { label, status: 'info', message: 'skipped (realtime plugin not installed)' };
    case 'enabled-not-installed':
      // openclaw.json turns on a plugin that is not on this host. Reporting it
      // as "skipped (not installed)" — which is what the old default branch's
      // sibling case did — describes the disk and hides the claim: every
      // config-reading surface says protection is ON, and the gateway boots
      // without an interceptor. Install state and claimed state disagree, and
      // the operator's belief follows the claim.
      return {
        label,
        status: 'fail',
        message:
          'openclaw.json ENABLES the realtime plugin but no package is installed on this host — the gateway boots with NO memory firewall and NO action guard while config reports it ON',
        fix: 'Install the plugin: `openclaw plugins install @drakon-systems/shieldcortex-realtime@latest`, then restart the gateway (or run `shieldcortex repair`, which will do both).',
        // Highest-severity unactionable site: BOTH offered routes spawn the
        // refused subcommand, and the message says the gateway boots with no
        // memory firewall and no action guard.
        needsOpenClawCli: { subcommand: 'plugins' },
      };
    case 'config-unreadable':
      // #11: cannot-read is not absent. A truncated or permission-denied
      // openclaw.json used to collapse into "no entry", which the #222 rule
      // then convicted as an unprotected wipe — a false red pointing an
      // operator at a repair for a config that is merely half-written.
      return {
        label,
        status: 'warn',
        message:
          '~/.openclaw/openclaw.json exists but could NOT be read or parsed — the plugin\'s enable state is INDETERMINATE. Neither protected nor unprotected is proven',
        fix: 'Check the file: `node -e "JSON.parse(require(\'fs\').readFileSync(process.env.HOME+\'/.openclaw/openclaw.json\',\'utf8\'))"` — fix the JSON (or the permissions), then re-run doctor.',
      };
    case 'installed-not-enabled':
      // #222/#228: the #214 installer wipe. The package is on disk and correct;
      // the openclaw.json registration is gone. The old switch had no case for
      // this state at all, so it fell to `default:` and printed the green
      // "realtime plugin loaded (roster-confirmed)" tick — the unprotected
      // state silencing the alarm built to catch it.
      return {
        label,
        status: 'fail',
        message:
          'realtime plugin is installed on disk but NOT REGISTERED in openclaw.json (no entry, absent from plugins.allow) — the host is UNPROTECTED: the gateway will boot WITHOUT the interceptor, no memory firewall, no action guard' +
          (verdict.loadedInLiveRoster === true
            ? '. The RUNNING gateway still has it loaded from the pre-wipe config, so protection ends at the next restart'
            : ''),
        // Not `repair`'s reinstall: the package is already here and correct.
        fix: 'Restore the registration for the EXISTING install: `shieldcortex repair` (writes plugins.allow + plugins.entries["shieldcortex-realtime"].enabled = true and reloads the gateway). Nothing is reinstalled.',
      };
    case 'disabled-by-operator':
      // #12: an explicit `enabled: false` is an operator decision, not an
      // incident. Reporting a human's own deliberate choice back to them as a
      // red FAIL is how the check that catches the real wipe gets ignored. A
      // WIPED stanza (no entry at all) is the case above, and it still fails.
      //
      // WARN IS DELIBERATE, AND SO IS THE EXIT CODE IT PRODUCES.
      //
      // Under `doctorExitCode`, ⚠️ is exit 0 and ❌ is exit 1, so an ordinary
      // `shieldcortex doctor` on a deliberately-disabled host SUCCEEDS while
      // printing this warning. That is the intended contract, not an oversight:
      // an operator who turned the plugin off does not want their scripts to
      // start failing because of it, and the state is fully described here.
      //
      // A fleet that wants "disabled anywhere is a build failure" has a
      // supported route, and it is `--strict`: it escalates every ⚠️ to exit 1,
      // so this line gates CI without changing what a human sees. Escalating the
      // severity itself would take that choice away from both audiences at once
      // — the operator loses a green run they are entitled to, and CI gains
      // nothing it could not already have.
      return {
        label,
        status: 'warn',
        message:
          'realtime plugin is installed but explicitly disabled in openclaw.json (enabled: false) — this host is running WITHOUT the memory firewall and action guard, which is what disabled means. An operator wrote that, so it is reported as a deliberate state rather than a fault' +
          (verdict.loadedInLiveRoster === true
            ? '. The RUNNING gateway still has it loaded from the pre-disable config, so it goes away at the next restart'
            : ''),
        fix: 'If that was not intentional, set plugins.entries["shieldcortex-realtime"].enabled = true in ~/.openclaw/openclaw.json and restart the gateway — the package is already installed, nothing needs reinstalling. To make a disabled host fail a pipeline, run `shieldcortex doctor --strict` (⚠️ becomes exit 1); plain `doctor` exits 0 on a deliberate disable by design.',
      };
    case 'index-unreadable':
      // DIAGNOSTIC-UNAVAILABLE, not a security fail-open: a broken better-sqlite3
      // binding, a locked DB, or a pre-2026.6.1 OpenClaw with no
      // installed_plugin_index table all make the roster unreadable. We CANNOT
      // confirm the plugin is loaded — but reporting "UNPROTECTED" here would be a
      // false alarm on a healthy box whose only fault is the DB engine. Warn and
      // point at repair (whose pass-1 rebuilds the binding), never fail. (#74 finding 2)
      return {
        label,
        status: 'warn',
        message:
          'cannot read OpenClaw\'s plugin roster (SQLite index unreadable — broken better-sqlite3 binding, locked DB, or pre-2026.6.1 OpenClaw) — cannot confirm the realtime plugin is loaded; NOT necessarily unprotected',
        fix,
      };
    case 'load-unproven':
      // #142: the boot roster snapshot races plugin registration, and a
      // registration line was sighted after the snapshot. Neither loaded nor
      // absent can be proven from logs — a confident UNPROTECTED here is the
      // false alarm that trains operators to ignore the check that caught #74.
      return {
        label,
        status: 'warn',
        message:
          'load state UNPROVEN — absent from the boot roster snapshot, but a plugin registration was sighted after it ' +
          '(registration races the snapshot; CLI activity writes identical lines). Neither protected nor unprotected is proven',
        fix: `Prove it live: ${LIVE_CANARY_COMMAND}`,
      };
    case 'enabled-not-loaded':
      return {
        label,
        status: 'fail',
        message:
          'realtime plugin is enabled:true in config but NOT loaded (absent from OpenClaw\'s roster) — the host is UNPROTECTED while status reports ON',
        fix,
        needsOpenClawCli: { subcommand: 'plugins' },
      };
    case 'version-regressed':
      return {
        label,
        status: 'fail',
        message: `realtime plugin regressed to v${verdict.onDiskVersion ?? verdict.indexVersion} (older than expected v${verdict.expectedVersion}) — running stale, refuse the downgrade`,
        fix,
        // The exact line the #221 operator chased for five days.
        needsOpenClawCli: { subcommand: 'plugins' },
      };
    case 'conflicted-metadata':
      return {
        label,
        status: 'warn',
        message: `installs.json and the SQLite index disagree on the realtime plugin — a toggle can silently drop it. ${verdict.reasons[verdict.reasons.length - 1] ?? ''}`.trim(),
        fix,
        needsOpenClawCli: { subcommand: 'plugins' },
      };
    case 'duplicate-install':
      return {
        label,
        status: 'warn',
        message: `${(verdict.onDiskVersion && 'realtime plugin has ') || ''}multiple install dirs on disk — prune the stale duplicate before a toggle re-resolves to it`,
        fix,
        needsOpenClawCli: { subcommand: 'plugins' },
      };
    // EXPLICIT, not `default:`. #222 was a state that fell through to a green
    // tick because no branch claimed it, and a `default: → pass` arm is that
    // hazard rebuilt: the next state added to PluginLoadState would inherit
    // "healthy" silently. Only `healthy` may render a pass here; anything
    // unrecognised lands in the arm below and warns.
    case 'healthy': {
      // #103: "roster-confirmed" is a claim about EVIDENCE, and this arm used to
      // make it unconditionally. `reconcilePluginState` reaches `healthy` both
      // when the running gateway's boot roster names the plugin AND when that
      // roster could not be read at all — it records the difference in
      // `reasons`, which this renderer discards. So on any host where the boot
      // line was unreadable, doctor asserted roster confirmation it did not
      // have: install state described as load state, which is the exact
      // inversion #103 was filed for, rebuilt one layer up.
      //
      // Proven ⇒ pass with an evidence-backed roster claim. Unproven ⇒ pass
      // with an explicit diagnostic gap, matching the reconciler's `ok` verdict
      // without turning installation evidence into a live-load assertion.
      const rosterProven = verdict.loadedInLiveRoster === true;
      const version = verdict.onDiskVersion ?? verdict.expectedVersion;
      if (!rosterProven) {
        // Status stays `pass`: the reconciler classified this `severity: 'ok'`
        // (installed, enabled, versions agree) and nothing is known to be
        // wrong, so escalating here would both contradict the verdict and warn
        // on every host whose gateway log is merely unreadable. What was wrong
        // was the CLAIM, not the status — so the claim is what changes.
        return {
          label,
          status: 'pass',
          message:
            `realtime plugin installed and enabled at v${version} — but the RUNNING gateway's boot roster ` +
            `could not be read, so load is NOT separately proven. Prove it live with: ${LIVE_CANARY_COMMAND}`,
        };
      }
      // Roster-confirmed loaded, but doctor does NOT run the live enforcement
      // canary (that needs gateway consent) — so it must not claim "enforcing"
      // from roster presence alone (#74 attempt #3 was roster-present-but-not-
      // enforcing). Say "loaded (roster-confirmed)"; point at repair's canary. (#74 finding 6)
      //
      // #216: when the reconciler proved load via a gateway-PID-attributed
      // post-boot registration (hot-reload), say so — the boot snapshot alone
      // would have been a false absent.
      //
      // "Loaded" does not mean "scanning conversations" either — that gap is
      // owned by `checkOpenClawPluginLoadState`, which downgrades this tick when
      // the conversation-access grant is missing (#226), and reported in full by
      // `checkOpenClawConversationScanning` (#225/#230). This renderer is pure:
      // it reads the verdict and nothing off disk.
      const hotReload =
        Array.isArray(verdict.reasons) &&
        verdict.reasons.some((r) => /RUNNING gateway PID after boot|hot-reload/i.test(r));
      return {
        label,
        status: 'pass',
        message: hotReload
          ? `realtime plugin loaded (gateway-PID registration after boot / hot-reload, v${version}); enforcement not probed here — prove it live with: ${LIVE_CANARY_COMMAND}`
          : `realtime plugin loaded (roster-confirmed, v${version}); enforcement not probed here — prove it live with: ${LIVE_CANARY_COMMAND}`,
      };
    }
    default: {
      // A state the reconciler produced and this renderer does not know. It is
      // reachable only by adding a PluginLoadState without a case here — which
      // is exactly how #222 happened — so it reports the gap instead of
      // inheriting a green tick. `state` is typed `never` here, so a new state
      // also fails the typecheck before it can ever reach a user.
      const unknown: never = verdict.state;
      return {
        label,
        status: 'warn',
        message: `plugin load state '${String(unknown)}' is not recognised by this version of doctor — cannot confirm the realtime plugin is loaded (this is a doctor gap, not proof of a problem)`,
        fix,
      };
    }
  }
}

/**
 * The #94-class false green: every prior "plugin loaded" surface reads the
 * version on DISK and green-ticks it, so a gateway that registered an older
 * build hours/days ago hides behind a "current" tick (live 21 Jul 2026: box
 * ran v4.47.8 under a "v4.47.13 loaded" green tick). The realtime plugin logs
 * `[shieldcortex] vX.Y.Z registered` on every (re)start, so the most recent
 * such line in the gateway journal is the version actually running. This check
 * reads that line and compares it to the on-disk install:
 *
 *   - running == disk            → PASS (the loaded build matches disk).
 *   - running != disk            → WARN "stale plugin loaded (vX running, vY
 *                                  on disk) — gateway restart needed" (the
 *                                  upgrade is on disk but not yet live).
 *   - journal unreadable / no
 *     registration line found    → INFO "cannot verify running version" — we
 *                                  never emit a green claiming "current" when
 *                                  we could not actually read the running one.
 *
 * The journal reader is injected (see `realRunningPluginVersionDeps`) so the
 * check has no hard dependency on systemd being present or readable.
 */
export interface BoundedJournal {
  text: string;
  /**
   * True when the SOURCE already bounded the text at/after the requested
   * instant (journalctl --since=@epoch). journald's default line format
   * carries no year, so per-line dating is impossible there — bounding at the
   * source is what keeps the #150 guarantee on systemd hosts. False means the
   * text is a raw file read and every line must prove its own freshness.
   */
  preBounded: boolean;
}

export interface RunningPluginVersionDeps {
  /**
   * Returns gateway journal/log text for the window starting at `sinceMs`,
   * or null when it can't be read.
   */
  readGatewayJournal: (sinceMs: number) => BoundedJournal | null;
  /**
   * The RUNNING gateway's process start (ms), or null when it cannot be
   * proven. #150: a Mac reported "v4.14.10 running" off a log line written in
   * May because nothing bounded the log by the life of the process it was
   * being quoted about. No line older than this instant may be called
   * "running".
   */
  readGatewayProcessStartMs: () => number | null;
  /** #214 — running gateway pid, so a CLI registration line is not quoted as the gateway. */
  readGatewayPid?: () => number | null;
  /**
   * #317 — version proven loaded by the live gateway roster (same evidence as
   * "plugin loaded: roster-confirmed"). Used only when the log channel has no
   * fresh `[shieldcortex] … registered` line. A FRESH stale log line still wins
   * (the #94 class).
   */
  readRosterConfirmedVersion?: () => string | null;
}

/**
 * Extract the running realtime-plugin version from a gateway journal by taking
 * the LAST `[shieldcortex] vX.Y.Z registered` line — journald/log output is
 * chronological (oldest → newest), so the final match is the current start's
 * registration. Returns null when no registration line is present.
 */
export function parseRunningPluginVersion(journal: string, gatewayPid?: number | null): string | null {
  // Matches "[shieldcortex] v4.47.8 registered (...)" including semver
  // pre-release/build suffixes. Global so we can walk to the final match.
  const re = /\[shieldcortex\]\s+v(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)\s+registered/g;
  let match: RegExpExecArray | null;
  let last: string | null = null;
  while ((match = re.exec(journal)) !== null) {
    if (gatewayPid != null) {
      const lineStart = journal.lastIndexOf('\n', match.index) + 1;
      const lineEnd = journal.indexOf('\n', match.index);
      const line = journal.slice(lineStart, lineEnd < 0 ? journal.length : lineEnd);
      const pid = parseLogLinePid(line);
      if (pid != null && pid !== gatewayPid) continue;
    }
    last = match[1];
  }
  return last;
}

/**
 * #150: the bounded variant — only registration lines dated at/after `sinceMs`
 * count, and a line that cannot be dated cannot be called fresh. The unbounded
 * parser above remains for callers that genuinely want "newest ever".
 */
export function parseRunningPluginVersionSince(
  journal: string,
  sinceMs: number,
  gatewayPid?: number | null,
): string | null {
  const sightings = parseRegistrationsSince(journal, sinceMs);
  const usable = gatewayPid == null
    ? sightings
    : sightings.filter((s) => s.pid == null || s.pid === gatewayPid);
  return usable.length > 0 ? usable[usable.length - 1].version : null;
}

/**
 * Real journal reader: prefer the user gateway service journal, fall back to
 * OpenClaw's on-disk gateway log. Returns null on ANY failure (no systemd, no
 * perms, no log file) so the check downgrades to "cannot verify" rather than a
 * false green. Follows the execFileSync-with-stderr-swallowed pattern used by
 * the dashboard-staleness probe.
 */
export function realRunningPluginVersionDeps(home: string = os.homedir()): RunningPluginVersionDeps {
  return {
    readGatewayJournal: (sinceMs: number): BoundedJournal | null => {
      // 1. systemd user journal, bounded AT THE SOURCE (#150): journald's
      //    default format has no year, so per-line dating is impossible —
      //    --since makes the whole window provably fresh instead.
      try {
        const out = execFileSync(
          'journalctl',
          ['--user', '-u', 'openclaw-gateway', '--no-pager', '-n', '2000', `--since=@${Math.floor(sinceMs / 1000)}`],
          { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] },
        );
        if (typeof out === 'string' && out.trim().length > 0) return { text: out, preBounded: true };
      } catch {
        // no systemd / unit unknown / no perms — fall through to the log file
      }

      // 2. On-disk gateway log fallback for non-systemd installs.
      const candidates = [
        path.join(home, '.openclaw', 'logs', 'gateway.log'),
        path.join(home, '.openclaw', 'logs', 'openclaw-gateway.log'),
        path.join(home, '.openclaw', 'gateway.log'),
      ];
      for (const file of candidates) {
        try {
          if (fs.existsSync(file)) {
            const text = fs.readFileSync(file, 'utf8');
            if (text.trim().length > 0) return { text, preBounded: false };
          }
        } catch {
          // unreadable — try the next candidate
        }
      }

      // 3. OpenClaw's default log dir (/tmp/openclaw/openclaw-YYYY-MM-DD.log,
      //    ISO-dated JSON lines — the layout every current install writes).
      try {
        const dir = '/tmp/openclaw';
        const logs = fs
          .readdirSync(dir)
          .filter((n) => n.startsWith('openclaw-') && n.endsWith('.log'))
          .sort();
        const parts: string[] = [];
        for (const name of logs.slice(-2)) {
          try {
            parts.push(fs.readFileSync(path.join(dir, name), 'utf8'));
          } catch {
            // skip unreadable file
          }
        }
        const text = parts.join('\n');
        if (text.trim().length > 0) return { text, preBounded: false };
      } catch {
        // no default log dir either
      }

      return null;
    },
    readGatewayProcessStartMs: (): number | null => readRunningGatewayProcess(home)?.startedAtMs ?? null,
    readGatewayPid: (): number | null => readRunningGatewayProcess(home)?.pid ?? null,
    readRosterConfirmedVersion: (): string | null => {
      try {
        const verdict = reconcilePluginState(gatherReconcileInput(home, { expectedVersion: pkg.version }));
        if (verdict.loadedInLiveRoster === true) {
          return readInstalledRealtimePluginVersion(home);
        }
      } catch {
        // roster unreadable — log path stays the only proof
      }
      return null;
    },
  };
}

export async function checkOpenClawRunningPluginVersion(
  home: string = os.homedir(),
  deps: RunningPluginVersionDeps = realRunningPluginVersionDeps(home),
): Promise<CheckResult> {
  const label = 'OpenClaw plugin running version';

  if (!fs.existsSync(path.join(home, '.openclaw'))) {
    return { label, status: 'info', message: 'skipped (OpenClaw not detected)' };
  }

  const diskVersion = readInstalledRealtimePluginVersion(home);
  if (!diskVersion) {
    return { label, status: 'info', message: 'skipped (realtime plugin not installed)' };
  }

  // #150: bound the log by the life of the process it is being quoted about.
  // A Mac reported "v4.14.10 running" off a line written two months earlier —
  // a confident, specific claim from an artifact nothing had touched since
  // May. Without a process-start instant to bound against, the newest line in
  // a log proves nothing about NOW, so the honest answer is unknown.
  const processStartMs = deps.readGatewayProcessStartMs();
  if (processStartMs == null) {
    return {
      label,
      status: 'info',
      message:
        `cannot verify running version (the running gateway's start time could not be established, ` +
        `so no log line can be proven to describe the current process); on-disk v${diskVersion}`,
    };
  }

  const journal = deps.readGatewayJournal(processStartMs);
  if (journal === null) {
    return {
      label,
      status: 'info',
      message:
        `cannot verify running version (gateway journal unreadable — no systemd/journald access, ` +
        `unknown unit, or no gateway log); on-disk v${diskVersion}`,
    };
  }

  const gatewayPid = deps.readGatewayPid?.() ?? null;
  const running = journal.preBounded
    ? parseRunningPluginVersion(journal.text, gatewayPid)
    : parseRunningPluginVersionSince(journal.text, processStartMs, gatewayPid);
  if (!running) {
    const historic = journal.preBounded ? null : parseRunningPluginVersion(journal.text);
    const roster = deps.readRosterConfirmedVersion?.() ?? null;
    if (roster && roster === diskVersion) {
      return {
        label,
        status: 'pass',
        message:
          `running v${roster} matches on-disk v${diskVersion} (roster-confirmed; ` +
          `log line unavailable on this platform)`,
      };
    }
    return {
      label,
      status: 'info',
      message:
        `running version UNKNOWN — no \`[shieldcortex] … registered\` line since the running gateway ` +
        `started (${new Date(processStartMs).toISOString()}); on-disk v${diskVersion}.` +
        (historic ? ` An older line exists (v${historic}) but predates this process and proves nothing about it` : '') +
        (process.platform === 'darwin'
          ? ' On macOS LaunchAgent hosts this is usually a log-channel gap, not an unload — see `openclaw gateway restart` / `launchctl print gui/$(id -u)/ai.openclaw.gateway`'
          : ''),
    };
  }

  if (running === diskVersion) {
    return {
      label,
      status: 'pass',
      message: `running v${running} matches on-disk v${diskVersion} (gateway loaded the current build)`,
    };
  }

  return {
    label,
    status: 'warn',
    message:
      `stale plugin loaded (v${running} running, v${diskVersion} on disk) — the gateway is still ` +
      `enforcing the older build; a gateway restart is needed to pick up the on-disk upgrade`,
    fix:
      'Restart the OpenClaw gateway so it re-registers the on-disk plugin:\n' +
      `  ${gatewayRestartAdvice()}\n` +
      'Until then the live interceptor is the version shown as "running", not the one on disk.',
  };
}

/**
 * #156 — the aiquant silent-skip is a static property of the installed
 * manifest. A 2026.7.x gateway will not load us at boot unless
 * `activation.onStartup === true` or `activation.onCapabilities` lists `hook`.
 */
export function readPluginStartupIntent(home: string = os.homedir()): {
  onStartup: boolean;
  hookCapability: boolean;
  source: string;
} | null {
  const candidates = [
    path.join(home, '.openclaw', 'extensions', 'shieldcortex-realtime', 'openclaw.plugin.json'),
  ];
  // #317 — modern npm-projects layout (same ground-truth path as on-disk version).
  try {
    const install = resolveRealtimePluginInstallPath(home);
    if (install) {
      candidates.push(path.join(install, 'openclaw.plugin.json'));
      candidates.push(path.join(install, 'dist', 'openclaw.plugin.json'));
    }
  } catch {
    // ignore
  }
  for (const file of candidates) {
    try {
      if (!fs.existsSync(file)) continue;
      const raw = JSON.parse(fs.readFileSync(file, 'utf-8')) as { activation?: { onStartup?: unknown; onCapabilities?: unknown } };
      const act = raw.activation && typeof raw.activation === 'object' ? raw.activation : {};
      const caps = Array.isArray(act.onCapabilities) ? act.onCapabilities : [];
      return {
        onStartup: act.onStartup === true,
        hookCapability: caps.includes('hook'),
        source: file,
      };
    } catch {
      continue;
    }
  }
  return null;
}

export async function checkPluginStartupIntent(home: string = os.homedir()): Promise<CheckResult> {
  const label = 'OpenClaw plugin startup intent';
  if (!fs.existsSync(path.join(home, '.openclaw'))) {
    return { label, status: 'info', message: 'skipped (OpenClaw not detected)' };
  }
  const intent = readPluginStartupIntent(home);
  if (!intent) {
    return { label, status: 'info', message: 'skipped (no installed plugin manifest)' };
  }
  if (intent.onStartup && intent.hookCapability) {
    return {
      label,
      status: 'pass',
      message: `installed manifest declares onStartup + hook capability (${intent.source.replace(home, '~')})`,
    };
  }
  return {
    label,
    status: 'fail',
    message:
      `installed plugin manifest will not load at gateway boot ` +
      `(activation.onStartup=${intent.onStartup}, hook capability=${intent.hookCapability}) — ` +
      `this is the aiquant silent-skip`,
    fix:
      'Reinstall the current plugin so the on-disk manifest has `activation.onStartup: true` and `onCapabilities: ["hook"]`: `shieldcortex repair` or `openclaw plugins install @drakon-systems/shieldcortex-realtime`.',
  };
}

/**
 * State permissions (#163).
 *
 * Hardening audit, 1 Aug 2026: on a live default install `memories.db` was 644
 * (world-readable — the whole data asset of a memory-security product) and
 * `audit/` was 775 (group-writable — a forensic trail a non-owner can delete or
 * forge). No code set a mode on either; they inherited the umask.
 *
 * Doctor MEASURES and reports; the correction belongs to install/repair, which
 * the operator invoked deliberately. Reporting a mode we quietly changed behind
 * their back would be its own dishonesty.
 */
/**
 * The installed OpenClaw SKILL must track the CLI version (#179).
 *
 * Found in the field, 1 Aug: a box whose every surface read green was carrying
 * a skill copy 21 releases stale — nothing compared the skill to anything, so
 * the drift was invisible by construction. The skill is the fleet's operating
 * manual for this product; a stale one instructs agents in behaviour the
 * shipped code no longer has.
 *
 * Absent skill is INFO, not a failure — Claude-Code-only installs never want
 * it. Drift is a WARN with the one command that fixes it.
 */
export async function checkOpenClawSkillVersion(
  home: string = os.homedir(),
  cliVersion: string = pkg.version,
): Promise<CheckResult> {
  const label = 'OpenClaw skill version';
  const { findInstalledSkillDirs, readInstalledSkillVersion } = await import('../setup/openclaw.js');
  const dirs = findInstalledSkillDirs(home);
  if (dirs.length === 0) {
    // Remediation lives in `message`, not `fix` — this is the only such site,
    // and it is tagged so the gate annotates it too (#221).
    return {
      label,
      status: 'info',
      message: 'skill not installed (optional) — `shieldcortex openclaw skill install` adds it',
      needsOpenClawCli: { subcommand: 'skills' },
    };
  }
  const v = readInstalledSkillVersion(dirs[0]);
  if (!v) {
    return {
      label, status: 'warn',
      message: `skill present at ${dirs[0]} but its SKILL.md version is unreadable`,
      fix: 'Run shieldcortex openclaw skill install to reinstall a clean copy',
      needsOpenClawCli: { subcommand: 'skills' },
    };
  }
  if (v === cliVersion) {
    return { label, status: 'pass', message: `skill v${v} matches CLI v${cliVersion}` };
  }
  return {
    label, status: 'warn',
    message: `skill v${v} does not match CLI v${cliVersion} — agents are reading stale instructions`,
    fix: 'Run shieldcortex openclaw skill install',
    needsOpenClawCli: { subcommand: 'skills' },
  };
}

export async function checkStatePermissions(stateDir: string = getShieldCortexDir()): Promise<CheckResult> {
  const label = 'State permissions';
  let findings: Array<{ path: string; found: string; required: string }>;
  try {
    const { auditStatePermissions } = await import('../setup/state-permissions.js');
    findings = auditStatePermissions(stateDir);
  } catch (err) {
    return { label, status: 'warn', message: `could not measure — ${err instanceof Error ? err.message : String(err)}` };
  }

  if (findings.length === 0) {
    return { label, status: 'pass', message: 'owner-only (0700 dirs, 0600 files)' };
  }

  const worst = findings.map(f => `${path.basename(f.path)} ${f.found}`).slice(0, 4).join(', ');
  return {
    label,
    status: 'fail',
    message:
      `${findings.length} path(s) readable or writable beyond the owner (${worst}${findings.length > 4 ? ', …' : ''}) — ` +
      `the memory database and the audit trail must be owner-only`,
    // #218: point at `repair` — it now re-hardens the state tree directly
    // (runStatePermissionPass) without rewriting CLAUDE.md/hooks the way a full
    // `install` does. The manual one-liner uses an explicit `audit approvals
    // logs` list rather than a `{…}` brace expansion, because the guard's
    // touch-approval-store rule gates the expanded form (approving our own
    // printed advice would be its own paper cut).
    fix: 'Run `shieldcortex repair` (it re-hardens the state tree), or by hand: chmod 700 ~/.shieldcortex && chmod 700 ~/.shieldcortex/audit ~/.shieldcortex/approvals ~/.shieldcortex/logs && chmod 600 ~/.shieldcortex/memories.db* ~/.shieldcortex/config.json*',
  };
}

// ── Check 8: Model cache ─────────────────────────────────
async function checkModelCache(): Promise<CheckResult> {
  // #383: "directory non-empty" was a green lie for truncated model.onnx.
  // Integrity is size (+ trusted sidecar sha, or live sha). Never pass a
  // corrupt weight; never fail the whole doctor run on a missing optional model.
  try {
    const {
      inspectEmbeddingModelCache,
      formatModelCacheDoctorMessage,
    } = await import('../embeddings/model-cache.js');
    const insp = await inspectEmbeddingModelCache();
    const formatted = formatModelCacheDoctorMessage(insp);
    return {
      label: 'Embeddings',
      status: formatted.status,
      message: formatted.message,
      ...(formatted.fix ? { fix: formatted.fix } : {}),
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { label: 'Embeddings', status: 'warn', message: `check failed — ${msg}` };
  }
}

// ── Main runner ───────────────────────────────────────────
/**
 * Detect a stale dashboard service — the launchd parent serving an OLD build
 * from memory after a global update (it doesn't re-exec on npm install). The
 * postinstall auto-kick handles this on update; this is the safety net + the
 * visible signal when it didn't fire (e.g. updated via a path postinstall skips).
 */
export async function checkDashboardFreshness(): Promise<CheckResult> {
  const label = 'Dashboard freshness';
  try {
    const r = detectStaleDashboard(realDeps());
    if (r.stale) {
      return {
        label,
        status: 'warn',
        message: `dashboard service (pid ${r.pid}) predates the installed build — serving stale code (old theme/assets)`,
        fix: 'launchctl kickstart -k gui/$(id -u)/com.shieldcortex.dashboard',
      };
    }
    if (r.reason === 'process-current') {
      return { label, status: 'pass', message: 'dashboard service is running the current build' };
    }
    if (r.reason === 'not-darwin' || r.reason === 'service-not-loaded' || r.reason === 'service-not-running') {
      return { label, status: 'info', message: 'no managed dashboard service running' };
    }
    // process-start-unknown / install-mtime-unknown — couldn't determine; don't claim "current".
    return { label, status: 'info', message: 'could not determine dashboard build freshness' };
  } catch {
    return { label, status: 'info', message: 'could not probe the dashboard service' };
  }
}

/**
 * Split the report into lines worth printing and the dependent checks that
 * were skipped only because the database has not been created yet.
 *
 * Exported for tests: the first-run contract is that a clean box shows no ❌
 * and no ⚠️, and that the cascade of dependent skips collapses to one note.
 */
export function partitionUninitialisedSkips(
  results: CheckResult[],
): { visible: CheckResult[]; suppressed: CheckResult[] } {
  return {
    visible: results.filter(r => r.skipped !== 'db-uninitialised'),
    suppressed: results.filter(r => r.skipped === 'db-uninitialised'),
  };
}

/**
 * What `shieldcortex doctor` reports back to its caller — and to the shell.
 */
export interface DoctorSummary {
  passed: number;
  warnings: number;
  failures: number;
  infos: number;
  total: number;
  exitCode: number;
  /**
   * Present only when `--ai` was passed (#157). Computed strictly AFTER
   * passed/warnings/failures/exitCode above — those are already final by the
   * time runDoctorAiSection() is ever called and are never revisited, so an
   * AI outcome (however confident) cannot feed back into doctor's own
   * verdicts. See doctor-explainer.ts's file header for the structural half
   * of this guarantee (DoctorExplainerResult has no verdict-shaped field).
   */
  ai?: DoctorExplainerOutcome;
}

/**
 * Render a `DoctorExplainerOutcome` as the lines doctor prints for `--ai`.
 * Pure — no I/O — so the three shapes (nothing to explain / no analysis
 * available / a grounded hypothesis) can be tested without a model or a
 * console. Exported for src/cli/__tests__/doctor-ai-section.test.ts.
 *
 * Every branch that shows a result also shows the disclaimer: this is the
 * operator-facing half of requirement #2 ("explains, never decides") — not
 * just enforced in the types, but said out loud where the operator reads it.
 */
export function formatAiSection(outcome: DoctorExplainerOutcome): string[] {
  const lines: string[] = [];
  lines.push(`\n  ${bold}AI analysis (--ai):${reset}`);

  if (!outcome.attempted) {
    // Requirement #1: the flag alone is not sufficient. Nothing was sent
    // anywhere, no model was billed, and that is the whole point of this line.
    lines.push(`  ${dim}${outcome.reason ?? 'nothing to explain'}${reset}`);
    return lines;
  }

  if (!outcome.result) {
    lines.push(`  ${dim}${outcome.reason ?? 'no AI analysis available'}${reset}`);
    return lines;
  }

  const r = outcome.result;
  lines.push(`  ${yellow}Hypothesis${reset} (${r.confidence} confidence — based on: ${r.citedLabels.join(', ')}):`);
  lines.push(`  ${r.hypothesis}`);
  lines.push(`  ${dim}→ suggested next command:${reset} ${r.suggestedCommand}`);
  lines.push(
    `  ${dim}This is a hypothesis, not a diagnosis — nothing above changed a check's status. ` +
      `Verify before running anything.${reset}`,
  );
  return lines;
}

/**
 * Resolve a judge-model transport and run the explainer over `visible`'s
 * findings, returning both the printable lines and the raw outcome (for
 * DoctorSummary.ai).
 *
 * `deps.invoke` is the test seam: `undefined` (the production default) means
 * "resolve the real, pool-inherited transport" — the same `createCliInvoker`
 * the approval broker's judge uses (#143's cli-invoker.ts), so `doctor --ai`
 * brings no new keys, no new login, no second bill. `null` means "there is
 * definitively no model available" without spawning anything, which is how
 * tests exercise the fail-closed path and how a future "the pool told us it's
 * absent" caller could short-circuit this resolution.
 */
export async function runDoctorAiSection(
  visible: CheckResult[],
  deps: { invoke?: ModelInvoker | null } = {},
): Promise<{ lines: string[]; outcome: DoctorExplainerOutcome }> {
  const { runDoctorAiExplainer } = await import('../defence/iron-dome/doctor-explainer.js');

  let invoke = deps.invoke;
  if (invoke === undefined) {
    try {
      const { createCliInvoker } = await import('../defence/iron-dome/cli-invoker.js');
      invoke = createCliInvoker();
    } catch {
      // No CLI on PATH, or the module could not be loaded — fail closed to
      // "no AI analysis available" rather than throwing doctor's whole run.
      invoke = null;
    }
  }

  const outcome = await runDoctorAiExplainer(visible, invoke ?? null);
  return { lines: formatAiSection(outcome), outcome };
}

/**
 * Exit-code policy.
 *
 * doctor used to always exit 0, so `shieldcortex doctor && …` succeeded on a
 * broken install and CI could not gate on it (#132). A ❌ now means exit 1.
 *
 * Warnings and info stay 0 deliberately: fresh-install states are ℹ️ (#129),
 * and a first run must not fail anyone's pipeline for being a first run.
 * `--strict` opts into escalating ⚠️ as well, for callers that want a
 * zero-tolerance gate.
 *
 * That split is the enforcement contract for every DELIBERATE-but-degraded
 * state — an operator's `enabled: false` being the canonical one (#12/#226).
 * Such a state warns and exits 0 for the human who chose it, and exits 1 under
 * `--strict` for the fleet that has decided it is not acceptable. Neither
 * audience needs the severity itself changed, and changing it would silently
 * override the other one's policy.
 */
export function doctorExitCode(results: CheckResult[], opts: { strict?: boolean } = {}): number {
  if (results.some(r => r.status === 'fail')) return 1;
  if (opts.strict && results.some(r => r.status === 'warn')) return 1;
  return 0;
}

export async function runDoctor(
  args: string[] = [],
  // #157: test seam only. Production's one call site (src/index.ts) never
  // passes a second argument, so `deps.aiInvoke` is `undefined` there and
  // runDoctorAiSection() resolves the real pool-inherited CLI transport.
  deps: { aiInvoke?: ModelInvoker | null } = {},
): Promise<DoctorSummary> {
  // Title is emitted by formatDoctorReport (mobile layout). Keep a single
  // leading blank so piped/cron capture still starts cleanly.
  console.log('');

  const results: CheckResult[] = [];

  // Run checks sequentially (some depend on DB access)
  const checks: Array<() => Promise<CheckResult | CheckResult[]>> = [
    checkDatabase,
    checkSchema,
    checkWritePath, // Smoke test: real INSERT/SELECT/DELETE round-trip — catches silent schema drift
    checkMemoryStats,
    checkHooks,
    checkHookTimeouts,
    checkAutoMemoryHooks,
    checkAutoMemorySampling,
    checkMemoryPlaneEmptyBrain,
    checkMemoryPlaneDrift,
    checkMemoryHostContract,
    checkMemoryCaptureDist,
    checkBrainWorker,
    checkProjectKeyConsistency,
    checkProcesses,
    checkDashboardFreshness,
    checkDiskUsage,
    checkStatePermissions,
    checkLockFile,
    // #221: ahead of every OpenClaw check, so the root cause prints above the
    // symptoms and its fix leads the Suggested-fixes block.
    checkOpenClawConfigValid,
    checkOpenClawResidue,
    checkOpenClawHookFreshness,
    checkOpenClawPluginVersion,
    checkOpenClawSkillVersion,
    checkOpenClawPluginLoadState,
    checkOpenClawConversationScanning,
    checkOpenClawRunningPluginVersion,
    checkPluginStartupIntent,
    checkOpenClawPluginPackage,
    checkOpenClawDuplicateInstalls,
    checkOpenClawManagedPinDrift,
    checkOpenClawApprovalButtons,
    checkDefenceCanary,
    checkActionGuard,
    checkCronDenials,
    checkThreatGraph,
    checkAttestationCoverage,
    checkClaudeCodeVersion,
    checkModelCache,
  ];

  for (const check of checks) {
    try {
      const result = await check();
      if (Array.isArray(result)) {
        results.push(...result);
      } else {
        results.push(result);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      results.push({ label: 'Unknown', status: 'fail', message: `check crashed — ${msg}` });
    }
  }

  // --fix-project-keys: auto-repair the project-key collision warning
  // (unambiguous mappings only; backup + rewrite log via repairProjectKeys),
  // then re-run the check so the printed report reflects the post-fix state.
  if (args.includes('--fix-project-keys')) {
    const idx = results.findIndex((r) => r.label === 'Project keys');
    if (idx !== -1 && results[idx].status === 'warn') {
      try {
        const fix = await fixProjectKeyCollisions();
        const refreshed = await checkProjectKeyConsistency();
        const notes = [`auto-fixed ${fix.applied} row(s)`];
        if (fix.backupPath) notes.push(`backup: ${fix.backupPath}`);
        if (fix.skippedAmbiguous > 0) notes.push(`${fix.skippedAmbiguous} ambiguous mapping(s) skipped — resolve with --map`);
        results[idx] = { ...refreshed, message: `${refreshed.message} — ${notes.join('; ')}` };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        results[idx] = { ...results[idx], message: `${results[idx].message} — auto-fix failed: ${msg}` };
      }
    } else if (idx !== -1) {
      console.log(`  ${dim}--fix-project-keys: nothing to fix (no collision warning).${reset}\n`);
    }
  }

  // --fix-action-guard (#209): migrate the deprecated interceptor.actionGuard
  // alias into the top-level actionGuard block (backup + rewrite via
  // fixActionGuardConfig), then re-run the check so the printed report
  // reflects the post-fix state.
  if (args.includes('--fix-action-guard')) {
    try {
      const fix = fixActionGuardConfig();
      if (fix.changed) {
        const refreshed = await checkActionGuard();
        const start = results.findIndex((r) => r.label.startsWith('Action guard'));
        if (start !== -1) {
          const kept = results.filter((r) => !r.label.startsWith('Action guard'));
          kept.splice(start, 0, ...refreshed);
          results.length = 0;
          results.push(...kept);
        } else {
          results.push(...refreshed);
        }
        console.log(`  ${dim}--fix-action-guard: ${fix.message}${reset}\n`);
      } else {
        console.log(`  ${dim}--fix-action-guard: ${fix.message}.${reset}\n`);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.log(`  ${dim}--fix-action-guard failed: ${msg}${reset}\n`);
    }
  }

  // #221: strip remedies that cannot execute while OpenClaw's config is
  // invalid. Placed here because `results` is final and nothing has yet been
  // printed, filtered, counted or exited on — and it must not disturb any of
  // those. No-op unless the config check actually failed.
  const gated = applyOpenClawCliGate(results);

  // Collapse the dependent "no database yet" checks into one dim note. On a
  // fresh install they added Schema/Write path/Memories lines that all restate
  // the same single fact already reported by the Database line (#129).
  const { visible, suppressed } = partitionUninitialisedSkips(gated);

  // Summary counts stay on the RAW visible set (exit codes / CI gates).
  const passed = visible.filter(r => r.status === 'pass').length;
  const warnings = visible.filter(r => r.status === 'warn').length;
  const failures = visible.filter(r => r.status === 'fail').length;
  const infos = visible.filter(r => r.status === 'info').length;
  const total = visible.length;

  // Mobile/tmux report (render-only). Default collapses passes + duplicate
  // warning themes; --verbose restores the full pass list. Exit codes and
  // check logic are unchanged.
  const verbose = args.includes('--verbose') || args.includes('--debug');
  const style: DoctorReportStyle = { bold, reset, green, yellow, red, cyan, dim };
  const reportLines = formatDoctorReport(visible, {
    verbose,
    version: String(pkg.version ?? ''),
    target: (() => {
      try { return os.hostname(); } catch { return ''; }
    })(),
    color: shouldColorDoctor(),
    style,
    width: Number(process.env.COLUMNS || process.stdout?.columns || 80) || 80,
  });
  for (const line of reportLines) console.log(line);

  if (suppressed.length > 0) {
    console.log(`${dim}(${suppressed.map(r => r.label).join(', ')} checked once the database exists)${reset}`);
  }

  // (The Pro upsell footer that used to render here was removed with the
  // Free + Enterprise repricing \u2014 there is no self-serve tier to nudge
  // towards. `config --upsell-mute/--upsell-unmute` remain accepted no-ops.)

  // \u2500\u2500 doctor --ai (#157) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
  // Opt-in, explanation-only, and deliberately the LAST thing computed:
  // passed/warnings/failures/exitCode above are already final. The AI never
  // sees them as anything but read-only history and cannot feed back into
  // them \u2014 see DoctorSummary.ai's doc comment and doctor-explainer.ts's
  // header for the structural half of "explains, never decides".
  let ai: DoctorExplainerOutcome | undefined;
  if (args.includes('--ai')) {
    const section = await runDoctorAiSection(visible, { invoke: deps.aiInvoke });
    for (const line of section.lines) console.log(line);
    ai = section.outcome;
  }

  // Exit code. Set rather than process.exit() so buffered stdout is flushed
  // in full (doctor's report is long and often piped), and only ever set to
  // a failure \u2014 never reset to 0 over an exit code someone else set.
  const strict = args.includes('--strict');
  const exitCode = doctorExitCode(visible, { strict });
  if (exitCode !== 0) {
    process.exitCode = exitCode;
    const reason = failures > 0
      ? `${failures} failed check${failures !== 1 ? 's' : ''}`
      : `${warnings} warning${warnings !== 1 ? 's' : ''} (--strict)`;
    console.log(`${dim}exit ${exitCode} \u2014 ${reason}${reset}`);
  }

  console.log('');

  return { passed, warnings, failures, infos, total, exitCode, ai };
}
