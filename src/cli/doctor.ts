/**
 * ShieldCortex Doctor — Installation health checker.
 * Runs diagnostics and reports issues with actionable fixes.
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import { createRequire } from 'module';

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

type CheckStatus = 'pass' | 'warn' | 'fail' | 'info';

interface CheckResult {
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
    return {
      label: 'Database',
      status: 'fail',
      message: 'not found',
      fix: 'Start the MCP server or run `shieldcortex setup` to initialise the database',
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
      fix: 'Run `npm rebuild better-sqlite3` if you changed Node versions',
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

      const required = ['decayed_score', 'graph_extraction_version', 'sensitivity'];
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

    const hookNames = ['SessionStart', 'PreCompact', 'SessionEnd'];
    let installed = 0;
    const missing: string[] = [];

    for (const name of hookNames) {
      const hookConfig = hooks[name];
      if (hookConfig) {
        // Check if the hook command/script exists
        const commands: string[] = Array.isArray(hookConfig)
          ? hookConfig.map((h: { command?: string }) => h.command).filter(Boolean)
          : hookConfig.command ? [hookConfig.command] : [];

        const hasShieldCortex = commands.some((cmd: string) => cmd.includes('shieldcortex'));
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

// ── Check 5: Process check ────────────────────────────────
async function checkProcesses(): Promise<CheckResult[]> {
  const results: CheckResult[] = [];

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
    results.push({
      label: 'API server',
      status: 'warn',
      message: 'not running',
      fix: 'Run `shieldcortex dashboard` to start the API server',
    });
  }

  // Check dashboard on port 3030
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2000);
    const response = await fetch('http://localhost:3030/', { signal: controller.signal });
    clearTimeout(timeout);
    if (response.ok || response.status === 304) {
      results.push({ label: 'Dashboard', status: 'pass', message: 'running (port 3030)' });
    } else {
      results.push({
        label: 'Dashboard',
        status: 'warn',
        message: `responding but returned status ${response.status}`,
        fix: 'Restart with `shieldcortex dashboard`',
      });
    }
  } catch {
    results.push({
      label: 'Dashboard',
      status: 'warn',
      message: 'not running',
      fix: 'Run `shieldcortex dashboard` to start the dashboard',
    });
  }

  return results;
}

// ── Check 6: Disk usage ───────────────────────────────────
async function checkDiskUsage(): Promise<CheckResult> {
  const scDir = getShieldCortexDir();

  if (!fs.existsSync(scDir)) {
    return { label: 'Disk', status: 'pass', message: '0 B / 100 MB limit (directory not yet created)' };
  }

  try {
    let totalSize = 0;

    function walkDir(dir: string): void {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        try {
          if (entry.isDirectory()) {
            walkDir(fullPath);
          } else if (entry.isFile()) {
            totalSize += fs.statSync(fullPath).size;
          }
        } catch {
          // Skip inaccessible files
        }
      }
    }

    walkDir(scDir);
    const limit = 100 * 1024 * 1024; // 100 MB
    const pct = (totalSize / limit) * 100;
    const sizeStr = `${formatBytes(totalSize)} / 100 MB limit`;

    if (pct >= 95) {
      return { label: 'Disk', status: 'fail', message: `${sizeStr} — at limit!`, fix: 'Run consolidation or delete old memories' };
    } else if (pct >= 80) {
      return { label: 'Disk', status: 'warn', message: `${sizeStr} — approaching limit`, fix: 'Consider running consolidation to free space' };
    } else {
      return { label: 'Disk', status: 'pass', message: sizeStr };
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { label: 'Disk', status: 'warn', message: `check failed — ${msg}` };
  }
}

// ── Check 7: Lock file ───────────────────────────────────
async function checkLockFile(): Promise<CheckResult> {
  const scDir = getShieldCortexDir();

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

    // Check if lock files are stale (older than 1 hour)
    const stale: string[] = [];
    const active: string[] = [];
    const oneHourAgo = Date.now() - 60 * 60 * 1000;

    for (const lockFile of lockFiles) {
      const lockPath = path.join(scDir, lockFile);
      const stat = fs.statSync(lockPath);
      if (stat.mtimeMs < oneHourAgo) {
        stale.push(lockFile);
      } else {
        active.push(lockFile);
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
export async function runDoctor(): Promise<void> {
  console.log(`\n${bold}ShieldCortex Doctor${reset} v${pkg.version}\n`);

  const results: CheckResult[] = [];

  // Run checks sequentially (some depend on DB access)
  const checks: Array<() => Promise<CheckResult | CheckResult[]>> = [
    checkDatabase,
    checkSchema,
    checkMemoryStats,
    checkHooks,
    checkProcesses,
    checkDiskUsage,
    checkLockFile,
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

  console.log('');
}
