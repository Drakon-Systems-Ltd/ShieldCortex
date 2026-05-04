/**
 * `shieldcortex doctor` — diagnostic checks for Cortex installation health.
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import { createRequire } from 'module';
import { fileURLToPath } from 'url';
import { REQUIRED_HOOK_NAMES } from './settings-hooks.js';

const require = createRequire(import.meta.url);

type Status = 'PASS' | 'WARN' | 'FAIL';

interface CheckResult {
  status: Status;
  message: string;
}

const results: CheckResult[] = [];

function add(status: Status, message: string): void {
  results.push({ status, message });
}

function getDbPath(): { path: string; isLegacy: boolean } | null {
  const newPath = path.join(os.homedir(), '.shieldcortex', 'memories.db');
  const memoryLegacy = path.join(os.homedir(), '.claude-memory', 'memories.db');
  const cortexLegacy = path.join(os.homedir(), '.claude-cortex', 'memories.db');

  if (fs.existsSync(newPath)) return { path: newPath, isLegacy: false };
  if (fs.existsSync(memoryLegacy)) return { path: memoryLegacy, isLegacy: true };
  if (fs.existsSync(cortexLegacy)) return { path: cortexLegacy, isLegacy: true };
  return null;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function checkNode(): void {
  const major = parseInt(process.version.slice(1), 10);
  if (major >= 18) {
    add('PASS', `Node.js ${process.version} (>= 18 required)`);
  } else {
    add('WARN', `Node.js ${process.version} — version 18+ recommended`);
  }
}

function checkDatabase(): void {
  const db = getDbPath();
  if (!db) {
    add('FAIL', 'Database not found at ~/.shieldcortex/memories.db');
    return;
  }

  const label = db.isLegacy ? `${db.path} (legacy)` : '~/.shieldcortex/memories.db';

  try {
    const stat = fs.statSync(db.path);
    const Database = require('better-sqlite3');
    const conn = new Database(db.path, { readonly: true });
    const row = conn.prepare('SELECT COUNT(*) as count FROM memories').get() as { count: number };
    conn.close();
    if (db.isLegacy) {
      add('WARN', `Database: ${label} (${row.count} memories, ${formatBytes(stat.size)}) — DEPRECATED, removed in v5.0.0; run: shieldcortex migrate-legacy`);
    } else {
      add('PASS', `Database: ${label} (${row.count} memories, ${formatBytes(stat.size)})`);
    }
  } catch (err: any) {
    add('FAIL', `Database: ${label} — ${err.message}`);
  }
}

function checkClaudeMd(): void {
  const claudeMdPath = path.join(os.homedir(), '.claude', 'CLAUDE.md');
  if (!fs.existsSync(claudeMdPath)) {
    add('WARN', 'CLAUDE.md not found — run `shieldcortex setup`');
    return;
  }
  const content = fs.readFileSync(claudeMdPath, 'utf-8');
  if (content.includes('# ShieldCortex')) {
    add('PASS', 'CLAUDE.md: Cortex instructions present');
  } else {
    add('WARN', 'CLAUDE.md: Cortex instructions not found — run `shieldcortex setup`');
  }
}

function checkHooks(): void {
  const settingsPath = path.join(os.homedir(), '.claude', 'settings.json');
  if (!fs.existsSync(settingsPath)) {
    add('WARN', 'settings.json not found — hooks not configured');
    return;
  }

  let settings: any;
  try {
    settings = JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));
  } catch {
    add('FAIL', 'settings.json: failed to parse');
    return;
  }

  const hooks = settings?.hooks || {};
  // Canonical source of truth lives in settings-hooks.ts alongside the install logic,
  // so doctor and install stay in lockstep. [#23]
  const expected = REQUIRED_HOOK_NAMES;

  for (const name of expected) {
    const entries = hooks[name];
    const hasCortex = Array.isArray(entries) && entries.some((e: any) =>
      Array.isArray(e?.hooks) && e.hooks.some((h: any) =>
        typeof h?.command === 'string' && h.command.includes('shieldcortex')
      )
    );
    if (hasCortex) {
      add('PASS', `Hook: ${name} configured`);
    } else {
      add('WARN', `Hook: ${name} not configured`);
    }
  }
}

function checkOpenClawHooks(): void {
  const home = os.homedir();

  // Check for legacy .clawdbot hooks (should be migrated)
  // Skip legacy check if .clawdbot is a symlink to .openclaw (common after OpenClaw rename)
  const clawdbotDir = path.join(home, '.clawdbot');
  const isSymlink = fs.existsSync(clawdbotDir) && fs.lstatSync(clawdbotDir).isSymbolicLink();

  const legacyHookDirs = isSymlink ? [] : [
    path.join(home, '.clawdbot', 'hooks', 'cortex-memory'),
    path.join(home, '.clawdbot', 'hooks', 'internal', 'cortex-memory'),
  ];
  const legacyHookDir = legacyHookDirs.find(d => fs.existsSync(d)) || null;
  const preferredHookDir = path.join(home, '.openclaw', 'hooks', 'cortex-memory');
  const legacyOpenClawHookDir = path.join(home, '.openclaw', 'hooks', 'internal', 'cortex-memory');
  const preferredHookExists = fs.existsSync(preferredHookDir);
  const legacyOpenClawHookExists = fs.existsSync(legacyOpenClawHookDir);

  if (legacyHookDir) {
    if (preferredHookExists || legacyOpenClawHookExists) {
      add('WARN', 'OpenClaw hook: found in BOTH ~/.clawdbot/ and ~/.openclaw/ — remove legacy with `shieldcortex migrate`');
    } else {
      add('FAIL', 'OpenClaw hook: only in legacy ~/.clawdbot/hooks/ — run `shieldcortex migrate` to fix');
    }
    return;
  }

  if (legacyOpenClawHookExists && !preferredHookExists) {
    add('WARN', 'OpenClaw hook: only legacy ~/.openclaw/hooks/internal/cortex-memory found — run `shieldcortex openclaw install` to migrate');
    return;
  }

  if (preferredHookExists) {
    // Verify hook files are intact
    const hookMd = path.join(preferredHookDir, 'HOOK.md');
    const handler = path.join(preferredHookDir, 'handler.ts');
    if (fs.existsSync(hookMd) && fs.existsSync(handler)) {
      if (legacyOpenClawHookExists) {
        add('WARN', 'OpenClaw hook: installed in preferred path, but legacy duplicate exists in ~/.openclaw/hooks/internal/ — rerun `shieldcortex openclaw install` to clean up');
      } else {
        add('PASS', `OpenClaw hook: installed at ${preferredHookDir.replace(home, '~')}/`);
      }
    } else {
      add('FAIL', 'OpenClaw hook: directory exists but files missing — reinstall with `openclaw hooks install shieldcortex` or `shieldcortex openclaw install`');
    }
    return;
  }

  // Check if OpenClaw is even installed
  const openclawDir = path.join(home, '.openclaw');
  if (fs.existsSync(openclawDir)) {
    add('WARN', 'OpenClaw detected but cortex-memory hook not installed — run `openclaw hooks install shieldcortex` or `shieldcortex openclaw install`');
  }
  // If no .openclaw dir, user probably isn't using OpenClaw — skip silently
}

function checkMcp(): void {
  // Check project-level .mcp.json
  const projectMcp = path.join(process.cwd(), '.mcp.json');
  // Check user-scope config (where `claude mcp add --scope user` writes)
  const userMcp = path.join(os.homedir(), '.claude.json');

  for (const p of [projectMcp, userMcp]) {
    if (fs.existsSync(p)) {
      try {
        const content = fs.readFileSync(p, 'utf-8');
        if (content.includes('shieldcortex')) {
          add('PASS', `MCP: cortex configured in ${path.basename(p)}`);
          return;
        }
      } catch { /* ignore parse errors */ }
    }
  }
  add('WARN', 'MCP: no cortex entry found in .mcp.json or ~/.claude.json');
}

function checkVersion(): void {
  // Show where this code is running from (helps debug stale version issues)
  const thisFile = fileURLToPath(import.meta.url);
  const thisDir = path.dirname(thisFile);
  const pkgPath = path.resolve(thisDir, '..', '..', 'package.json');

  add('PASS', `Entry point: ${thisFile}`);

  try {
    const raw = fs.readFileSync(pkgPath, 'utf-8');
    const parsed = JSON.parse(raw);
    add('PASS', `package.json: ${pkgPath} → v${parsed.version}`);
  } catch (err: any) {
    add('FAIL', `package.json: ${pkgPath} — ${err.message}`);
  }

  // Check process.argv[1] — the actual script Node is running
  if (process.argv[1] && process.argv[1] !== thisFile) {
    add('WARN', `process.argv[1]: ${process.argv[1]} (differs from import.meta.url)`);
  }
}

export async function handleDoctorCommand(): Promise<void> {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  const pkg = require(path.resolve(__dirname, '..', '..', 'package.json'));

  console.log(`\nShieldCortex Doctor v${pkg.version}\n`);

  checkVersion();
  checkNode();
  checkDatabase();
  checkClaudeMd();
  checkHooks();
  checkOpenClawHooks();
  checkMcp();

  // Print results
  for (const r of results) {
    const tag = r.status === 'PASS' ? '\x1b[32m  PASS\x1b[0m'
      : r.status === 'WARN' ? '\x1b[33m  WARN\x1b[0m'
      : '\x1b[31m  FAIL\x1b[0m';
    console.log(`${tag}  ${r.message}`);
  }

  const passed = results.filter(r => r.status === 'PASS').length;
  const warns = results.filter(r => r.status === 'WARN').length;
  const fails = results.filter(r => r.status === 'FAIL').length;
  console.log(`\n${passed} passed, ${warns} warnings, ${fails} failed\n`);

  process.exit(fails > 0 ? 1 : 0);
}
