/**
 * ShieldCortex Doctor — Installation health checker.
 * Runs diagnostics and reports issues with actionable fixes.
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import semver from 'semver';
import { createRequire } from 'module';
import { REQUIRED_HOOK_NAMES } from '../setup/settings-hooks.js';
import {
  resolveRealtimePluginInstallPath,
  readInstalledRealtimePluginVersion,
  readRealtimeProjectManifest,
  findEoverrideRiskPins,
  isRealtimePluginDisabledInConfig,
} from '../integrations/openclaw-plugin-state.js';
import { resolveSelfInstallDir } from '../setup/native-binding.js';
import { detectStaleDashboard, realDeps } from '../service/dashboard-staleness.js';
import { MCP_LIGHT_TICK_INTERVAL_MS } from '../worker/types.js';

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
  if (fs.existsSync(newPath)) return newPath;
  if (fs.existsSync(legacyPath)) return legacyPath;
  return newPath; // default expected path
}

// ── Check 1: Database health ──────────────────────────────
async function checkDatabase(): Promise<CheckResult> {
  const dbPath = getDbPath();

  if (!fs.existsSync(dbPath)) {
    // The database is created lazily on the first memory operation.
    // `quickstart` only configures hooks/MCP — it does NOT touch the DB.
    // The reliable one-shot init paths are: `shieldcortex scan "..."`
    // (works on every install shape) or starting an MCP-bound session
    // (Claude Code) which lazy-inits via the MCP server.
    const env = detectEnvironment();
    const fix = env.hasClaude
      ? 'Run `shieldcortex scan "init"` to create the database now, or start a Claude Code session — the MCP server will lazy-init on first memory call'
      : 'Run `shieldcortex scan "init"` to create the database now (OpenClaw-only / headless install)';
    return {
      label: 'Database',
      status: 'fail',
      message: 'not found',
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
    return {
      label: 'Database',
      status: 'fail',
      message: `cannot open — ${msg}`,
      fix: /bindings file|napi|abi|MODULE_VERSION|was compiled against/i.test(msg)
        ? `Native DB engine failed to load. Run \`shieldcortex repair\` (compiles better-sqlite3 from source + re-verifies), or manually: cd "${path.join(resolveSelfInstallDir(), 'node_modules', 'better-sqlite3')}" && npm run build-release`
        : 'Back up and delete `~/.shieldcortex/memories.db`, then restart the MCP server',
    };
  }
}

// ── Check 2: Schema version ──────────────────────────────
async function checkSchema(): Promise<CheckResult> {
  const dbPath = getDbPath();
  if (!fs.existsSync(dbPath)) {
    return { label: 'Schema', status: 'warn', message: 'skipped (no database)' };
  }

  try {
    const Database = require('better-sqlite3');
    const db = new Database(dbPath, { readonly: true });
    try {
      const columns = db.pragma('table_info(memories)') as Array<{ name: string }>;
      const columnNames = new Set(columns.map((c: { name: string }) => c.name));

      const required = ['decayed_score', 'graph_extraction_version', 'sensitivity_level'];
      const missing = required.filter(col => !columnNames.has(col));

      if (missing.length === 0) {
        return { label: 'Schema', status: 'pass', message: 'up to date' };
      } else {
        return {
          label: 'Schema',
          status: 'warn',
          message: `missing columns: ${missing.join(', ')}`,
          fix: 'Restart the MCP server to auto-migrate',
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

// ── Check 3: Memory stats ─────────────────────────────────
async function checkMemoryStats(): Promise<CheckResult> {
  const dbPath = getDbPath();
  if (!fs.existsSync(dbPath)) {
    return { label: 'Memories', status: 'warn', message: 'skipped (no database)' };
  }

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
export function runWritePathProbe(dbPath: string): CheckResult {
  if (!fs.existsSync(dbPath)) {
    return { label: 'Write path', status: 'warn', message: 'skipped (no database)' };
  }

  let db: any = null;
  const probeUuid = `doctor-probe-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  const probeTitle = '__shieldcortex_doctor_probe__';

  try {
    const Database = require('better-sqlite3');
    db = new Database(dbPath);

    // INSERT — exercises NOT NULL columns + CHECK constraints. The schema
    // adds these silently across versions; an INSERT against a stale schema
    // is the exact failure mode v4.12.5 had.
    db.prepare(`
      INSERT INTO memories (uuid, type, category, title, content, salience, source, capture_method)
      VALUES (?, 'short_term', 'note', ?, 'doctor probe — safe to delete', 0.01, 'cli:doctor', 'doctor-probe')
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
      fix: 'This is the smoking gun for a stale schema or migration drift. Try restarting the MCP server (auto-migrates), or re-install: shieldcortex install',
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
async function checkHooks(): Promise<CheckResult> {
  const settingsPath = path.join(os.homedir(), '.claude', 'settings.json');

  if (!fs.existsSync(settingsPath)) {
    return {
      label: 'Hooks',
      status: 'warn',
      message: 'settings.json not found',
      fix: 'Run `shieldcortex install` to configure hooks',
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

    for (const name of hookNames) {
      const hookConfig = hooks[name];
      if (hookConfig) {
        // Check if any hook command references shieldcortex.
        // Settings format: [{ hooks: [{ type, command, timeout }] }]
        const hasShieldCortex = Array.isArray(hookConfig) && hookConfig.some(
          (entry: { hooks?: Array<{ command?: string }> }) =>
            Array.isArray(entry?.hooks) && entry.hooks.some(
              (h) => typeof h?.command === 'string' && h.command.includes('shieldcortex'),
            ),
        );
        if (hasShieldCortex) {
          installed++;
        } else {
          missing.push(name);
        }
      } else {
        missing.push(name);
      }
    }

    if (installed === hookNames.length) {
      return { label: 'Hooks', status: 'pass', message: `${installed}/${hookNames.length} installed` };
    } else {
      return {
        label: 'Hooks',
        status: 'warn',
        message: `${installed}/${hookNames.length} installed — missing: ${missing.join(', ')}`,
        fix: 'Run `shieldcortex install` to configure hooks',
      };
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { label: 'Hooks', status: 'warn', message: `check failed — ${msg}` };
  }
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
export async function checkDiskUsage(scDir: string = getShieldCortexDir(), limitBytes: number = 100 * 1024 * 1024): Promise<CheckResult> {
  if (!fs.existsSync(scDir)) {
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

    const limit = limitBytes; // 100 MB by default; applies to the data portion only
    const limitMb = Math.round(limit / (1024 * 1024));
    const pct = (dataSize / limit) * 100;
    const dataStr = `${formatBytes(dataSize)} / ${limitMb} MB limit`;
    const modelsStr = modelsSize > 0 ? ` + ${formatBytes(modelsSize)} models` : '';
    const breakdown = `DB ${formatBytes(liveDbSize)} · backups ${formatBytes(backupsSize)} · logs ${formatBytes(logsSize)}`;

    const remedy = (): string => {
      if (backupsSize >= liveDbSize || backupsSize > limit * 0.15) {
        return `${formatBytes(backupsSize)} is stale DB backups (memories.db.* migration snapshots). Clear them — \`rm ~/.shieldcortex/memories.db.{pre-backfill,empty-live,stub,bak}*\` keeps the live DB; v4.45.1+ also auto-prunes them on start.`;
      }
      if (liveDbSize > limit * 0.5) {
        return `The database is ${formatBytes(liveDbSize)} — usually session capture + audit rows, which prune/dedupe can't shrink. Reclaim free space with \`shieldcortex vacuum\` (compacts the DB in place via the bundled engine — no sqlite3 CLI needed); if it is genuinely the memory table, \`shieldcortex memories prune --execute\`.`;
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
        message: `${dataStr}${modelsStr} — at limit! (${breakdown})`,
        fix: remedy(),
      };
    } else if (pct >= 80) {
      return {
        label: 'Disk',
        status: 'warn',
        message: `${dataStr}${modelsStr} — approaching limit (${breakdown})`,
        fix: remedy(),
      };
    } else {
      return { label: 'Disk', status: 'pass', message: `${dataStr}${modelsStr}` };
    }
  } catch (err: unknown) {
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

  if (!fs.existsSync(scDir)) {
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

export async function checkBrainWorker(): Promise<CheckResult> {
  if (process.env.SHIELDCORTEX_DISABLE_WORKER === '1') {
    return {
      label: 'Brain worker',
      status: 'info',
      message: 'disabled via SHIELDCORTEX_DISABLE_WORKER=1',
    };
  }
  const statePath = path.join(getShieldCortexDir(), 'state', 'worker.json');
  if (!fs.existsSync(statePath)) {
    return {
      label: 'Brain worker',
      status: 'warn',
      message: 'no worker.json — worker has not run yet',
      fix: workerRecoveryFix(),
    };
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

export async function runDoctor(args: string[] = []): Promise<void> {
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
    checkBrainWorker,
    checkProjectKeyConsistency,
    checkProcesses,
    checkDashboardFreshness,
    checkDiskUsage,
    checkLockFile,
    checkOpenClawResidue,
    checkOpenClawHookFreshness,
    checkOpenClawPluginVersion,
    checkOpenClawPluginPackage,
    checkOpenClawDuplicateInstalls,
    checkOpenClawManagedPinDrift,
    checkOpenClawApprovalButtons,
    checkDefenceCanary,
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

  // Print results
  for (const r of results) {
    console.log(`  ${icon(r.status)} ${bold}${r.label}:${reset} ${r.message}`);
  }

  // Summary
  const passed = results.filter(r => r.status === 'pass').length;
  const warnings = results.filter(r => r.status === 'warn').length;
  const failures = results.filter(r => r.status === 'fail').length;
  const infos = results.filter(r => r.status === 'info').length;
  const total = results.length;

  console.log('');
  const parts: string[] = [];
  parts.push(`${passed}/${total} checks passed`);
  if (warnings > 0) parts.push(`${yellow}${warnings} warning${warnings !== 1 ? 's' : ''}${reset}`);
  if (failures > 0) parts.push(`${red}${failures} failure${failures !== 1 ? 's' : ''}${reset}`);
  if (infos > 0) parts.push(`${infos} info`);
  console.log(`  ${parts.join(', ')}`);

  // Suggested fixes
  const fixes = results.filter(r => r.fix);
  if (fixes.length > 0) {
    console.log(`\n  ${bold}Suggested fixes:${reset}`);
    for (const f of fixes) {
      console.log(`  ${dim}\u2192${reset} ${f.fix}`);
    }
  }

  // (The Pro upsell footer that used to render here was removed with the
  // Free + Enterprise repricing \u2014 there is no self-serve tier to nudge
  // towards. `config --upsell-mute/--upsell-unmute` remain accepted no-ops.)

  console.log('');
}
