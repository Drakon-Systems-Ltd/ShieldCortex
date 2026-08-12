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
import { hookCommandResolves } from '../setup/hook-command-resolution.js';
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
import { parseRegistrationsSince } from '../integrations/openclaw-gateway-roster.js';
import { readRunningGatewayProcess } from '../integrations/openclaw-gateway-process.js';
import { resolveSelfInstallDir } from '../setup/native-binding.js';
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
import type { ModelInvoker } from '../defence/iron-dome/approval-judge.js';
import type { DoctorExplainerOutcome } from '../defence/iron-dome/doctor-explainer.js';

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

    return {
      label,
      status: 'pass',
      message: maxAudit === 0
        ? 'nothing to project yet'
        : `caught up (cursor ${cursor} of ${maxAudit}` +
          `${state?.last_rt_cursor ? `, realtime at ${state.last_rt_cursor}` : ''}` +
          `${state?.last_run_at ? `, last ran ${state.last_run_at}` : ''})`,
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
        fix: `Run \`shieldcortex setup ${flag}\` to flip the gate, or set autoMemory.enableStop/enableSessionEnd=true in ~/.shieldcortex/config.json`,
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
    const configPath = path.join(getShieldCortexDir(), 'config.json');
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
        fix: `Remove \`${provenance('enabled')}: false\` from ~/.shieldcortex/config.json to restore gating.`,
      });
    } else if (!effective.enforce) {
      results.push({
        label: `${label} config`,
        status: 'warn',
        message: `Action Guard runs in warn-mode (\`${provenance('enforce')}: false\`) on both surfaces — dangerous ops log but are not gated (catastrophic still blocks)`,
      });
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
  const configPath = path.join(getShieldCortexDir(), 'config.json');
  if (!fs.existsSync(configPath)) return { changed: false, message: 'no config file — nothing to migrate' };
  const raw = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
  const isBlock = (v: unknown): v is Record<string, unknown> =>
    !!v && typeof v === 'object' && !Array.isArray(v);
  const alias = isBlock(raw?.interceptor) && isBlock(raw.interceptor.actionGuard)
    ? (raw.interceptor.actionGuard as Record<string, unknown>)
    : null;
  if (!alias) return { changed: false, message: 'no `interceptor.actionGuard` alias in config — nothing to migrate' };

  const backupPath = `${configPath}.bak-fix-209-${new Date().toISOString().replace(/[:.]/g, '-')}`;
  fs.copyFileSync(configPath, backupPath);

  raw.actionGuard = { ...alias, ...(isBlock(raw.actionGuard) ? raw.actionGuard : {}) };
  delete raw.interceptor.actionGuard;
  if (Object.keys(raw.interceptor).length === 0) delete raw.interceptor;
  fs.writeFileSync(configPath, JSON.stringify(raw, null, 2));
  return {
    changed: true,
    backupPath,
    message: `migrated interceptor.actionGuard into the top-level actionGuard block (backup: ${backupPath})`,
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
async function checkAutoMemorySampling(): Promise<CheckResult> {
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
      fix: 'Edit ~/.shieldcortex/config.json autoMemory.stopHookSamplingTurns (≤ 5 recommended)',
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
    };
  }

  if (risks.length > 0) {
    const list = risks.map((r) => `${r.name} (dep ${r.dependencyVersion} ≠ override ${r.overrideVersion})`).join(', ');
    return {
      label,
      status: 'warn',
      message: `managed-pin drift will EOVERRIDE on the next \`openclaw update\`: ${list}`,
      fix: 'Run `shieldcortex openclaw repair` now to reconcile the pins before an update disables the plugin.',
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
      };
    case 'version-regressed':
      return {
        label,
        status: 'fail',
        message: `realtime plugin regressed to v${verdict.onDiskVersion ?? verdict.indexVersion} (older than expected v${verdict.expectedVersion}) — running stale, refuse the downgrade`,
        fix,
      };
    case 'conflicted-metadata':
      return {
        label,
        status: 'warn',
        message: `installs.json and the SQLite index disagree on the realtime plugin — a toggle can silently drop it. ${verdict.reasons[verdict.reasons.length - 1] ?? ''}`.trim(),
        fix,
      };
    case 'duplicate-install':
      return {
        label,
        status: 'warn',
        message: `${(verdict.onDiskVersion && 'realtime plugin has ') || ''}multiple install dirs on disk — prune the stale duplicate before a toggle re-resolves to it`,
        fix,
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
      // "Loaded" does not mean "scanning conversations" either — that gap is
      // owned by `checkOpenClawPluginLoadState`, which downgrades this tick when
      // the conversation-access grant is missing (#226), and reported in full by
      // `checkOpenClawConversationScanning` (#225/#230). This renderer is pure:
      // it reads the verdict and nothing off disk.
      return {
        label,
        status: 'pass',
        message: `realtime plugin loaded (roster-confirmed, v${version}); enforcement not probed here — prove it live with: ${LIVE_CANARY_COMMAND}`,
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
}

/**
 * Extract the running realtime-plugin version from a gateway journal by taking
 * the LAST `[shieldcortex] vX.Y.Z registered` line — journald/log output is
 * chronological (oldest → newest), so the final match is the current start's
 * registration. Returns null when no registration line is present.
 */
export function parseRunningPluginVersion(journal: string): string | null {
  // Matches "[shieldcortex] v4.47.8 registered (...)" including semver
  // pre-release/build suffixes. Global so we can walk to the final match.
  const re = /\[shieldcortex\]\s+v(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)\s+registered/g;
  let match: RegExpExecArray | null;
  let last: string | null = null;
  while ((match = re.exec(journal)) !== null) {
    last = match[1];
  }
  return last;
}

/**
 * #150: the bounded variant — only registration lines dated at/after `sinceMs`
 * count, and a line that cannot be dated cannot be called fresh. The unbounded
 * parser above remains for callers that genuinely want "newest ever".
 */
export function parseRunningPluginVersionSince(journal: string, sinceMs: number): string | null {
  const sightings = parseRegistrationsSince(journal, sinceMs);
  return sightings.length > 0 ? sightings[sightings.length - 1].version : null;
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

  const running = journal.preBounded
    ? parseRunningPluginVersion(journal.text)
    : parseRunningPluginVersionSince(journal.text, processStartMs);
  if (!running) {
    const historic = journal.preBounded ? null : parseRunningPluginVersion(journal.text);
    return {
      label,
      status: 'info',
      message:
        `running version UNKNOWN — no \`[shieldcortex] … registered\` line since the running gateway ` +
        `started (${new Date(processStartMs).toISOString()}); on-disk v${diskVersion}.` +
        (historic ? ` An older line exists (v${historic}) but predates this process and proves nothing about it` : ''),
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
    return { label, status: 'info', message: 'skill not installed (optional) — `shieldcortex openclaw skill install` adds it' };
  }
  const v = readInstalledSkillVersion(dirs[0]);
  if (!v) {
    return {
      label, status: 'warn',
      message: `skill present at ${dirs[0]} but its SKILL.md version is unreadable`,
      fix: 'Run shieldcortex openclaw skill install to reinstall a clean copy',
    };
  }
  if (v === cliVersion) {
    return { label, status: 'pass', message: `skill v${v} matches CLI v${cliVersion}` };
  }
  return {
    label, status: 'warn',
    message: `skill v${v} does not match CLI v${cliVersion} — agents are reading stale instructions`,
    fix: 'Run shieldcortex openclaw skill install',
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
    fix: 'Run `shieldcortex install` (it hardens on every run), or by hand: chmod 700 ~/.shieldcortex ~/.shieldcortex/{audit,approvals,logs} && chmod 600 ~/.shieldcortex/memories.db* ~/.shieldcortex/config.json*',
  };
}

// ── Check 8: Model cache ─────────────────────────────────
async function checkModelCache(): Promise<CheckResult> {
  const cacheDir = path.join(os.homedir(), '.cache', 'shieldcortex', 'models', 'Xenova', 'all-MiniLM-L6-v2');

  if (!fs.existsSync(cacheDir)) {
    return {
      label: 'Embeddings',
      status: 'info',
      message: 'model not cached — will download on first recall',
    };
  }

  try {
    let totalSize = 0;
    const entries = fs.readdirSync(cacheDir);
    for (const entry of entries) {
      const fullPath = path.join(cacheDir, entry);
      try {
        const stat = fs.statSync(fullPath);
        if (stat.isFile()) totalSize += stat.size;
      } catch {
        // Skip
      }
    }

    return {
      label: 'Embeddings',
      status: 'pass',
      message: `model cached (${formatBytes(totalSize)})`,
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
  console.log(`\n${bold}ShieldCortex Doctor${reset} v${pkg.version}\n`);

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
    checkMemoryCaptureDist,
    checkBrainWorker,
    checkProjectKeyConsistency,
    checkProcesses,
    checkDashboardFreshness,
    checkDiskUsage,
    checkStatePermissions,
    checkLockFile,
    checkOpenClawResidue,
    checkOpenClawHookFreshness,
    checkOpenClawPluginVersion,
    checkOpenClawSkillVersion,
    checkOpenClawPluginLoadState,
    checkOpenClawConversationScanning,
    checkOpenClawRunningPluginVersion,
    checkOpenClawPluginPackage,
    checkOpenClawDuplicateInstalls,
    checkOpenClawManagedPinDrift,
    checkOpenClawApprovalButtons,
    checkDefenceCanary,
    checkActionGuard,
    checkThreatGraph,
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

  // Collapse the dependent "no database yet" checks into one dim note. On a
  // fresh install they added Schema/Write path/Memories lines that all restate
  // the same single fact already reported by the Database line (#129).
  const { visible, suppressed } = partitionUninitialisedSkips(results);

  // Print results
  for (const r of visible) {
    console.log(`  ${icon(r.status)} ${bold}${r.label}:${reset} ${r.message}`);
  }
  if (suppressed.length > 0) {
    console.log(`  ${dim}(${suppressed.map(r => r.label).join(', ')} checked once the database exists)${reset}`);
  }

  // Summary
  const passed = visible.filter(r => r.status === 'pass').length;
  const warnings = visible.filter(r => r.status === 'warn').length;
  const failures = visible.filter(r => r.status === 'fail').length;
  const infos = visible.filter(r => r.status === 'info').length;
  const total = visible.length;

  console.log('');
  const parts: string[] = [];
  parts.push(`${passed}/${total} checks passed`);
  if (warnings > 0) parts.push(`${yellow}${warnings} warning${warnings !== 1 ? 's' : ''}${reset}`);
  if (failures > 0) parts.push(`${red}${failures} failure${failures !== 1 ? 's' : ''}${reset}`);
  if (infos > 0) parts.push(`${infos} info`);
  console.log(`  ${parts.join(', ')}`);

  // Suggested fixes. Deduplicated: one root cause can fail several checks at
  // once (a root-owned ~/.shieldcortex fails Database, Disk and Lock), and
  // printing the same remedy three times reads as three separate problems.
  const fixes = [...new Set(visible.filter(r => r.fix).map(r => r.fix as string))];
  if (fixes.length > 0) {
    console.log(`\n  ${bold}Suggested fixes:${reset}`);
    for (const f of fixes) {
      console.log(`  ${dim}\u2192${reset} ${f}`);
    }
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
    console.log(`  ${dim}exit ${exitCode} \u2014 ${reason}${reset}`);
  }

  console.log('');

  return { passed, warnings, failures, infos, total, exitCode, ai };
}
