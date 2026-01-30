/**
 * `npx claude-cortex doctor` — diagnostic checks for Cortex installation health.
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import { createRequire } from 'module';
import { fileURLToPath } from 'url';

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
  const newPath = path.join(os.homedir(), '.claude-cortex', 'memories.db');
  const legacyPath = path.join(os.homedir(), '.claude-memory', 'memories.db');

  if (fs.existsSync(newPath)) return { path: newPath, isLegacy: false };
  if (fs.existsSync(legacyPath)) return { path: legacyPath, isLegacy: true };
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
    add('FAIL', 'Database not found at ~/.claude-cortex/memories.db');
    return;
  }

  const label = db.isLegacy ? '~/.claude-memory/memories.db (legacy)' : '~/.claude-cortex/memories.db';

  try {
    const stat = fs.statSync(db.path);
    const Database = require('better-sqlite3');
    const conn = new Database(db.path, { readonly: true });
    const row = conn.prepare('SELECT COUNT(*) as count FROM memories').get() as { count: number };
    conn.close();
    add('PASS', `Database: ${label} (${row.count} memories, ${formatBytes(stat.size)})`);
  } catch (err: any) {
    add('FAIL', `Database: ${label} — ${err.message}`);
  }
}

function checkClaudeMd(): void {
  const claudeMdPath = path.join(os.homedir(), '.claude', 'CLAUDE.md');
  if (!fs.existsSync(claudeMdPath)) {
    add('WARN', 'CLAUDE.md not found — run `npx claude-cortex setup`');
    return;
  }
  const content = fs.readFileSync(claudeMdPath, 'utf-8');
  if (content.includes('# Claude Cortex')) {
    add('PASS', 'CLAUDE.md: Cortex instructions present');
  } else {
    add('WARN', 'CLAUDE.md: Cortex instructions not found — run `npx claude-cortex setup`');
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
  const expected = ['PreCompact', 'SessionStart', 'SessionEnd'];

  for (const name of expected) {
    const entries = hooks[name];
    const hasCortex = Array.isArray(entries) && entries.some((e: any) =>
      Array.isArray(e?.hooks) && e.hooks.some((h: any) =>
        typeof h?.command === 'string' && h.command.includes('claude-cortex')
      )
    );
    if (hasCortex) {
      add('PASS', `Hook: ${name} configured`);
    } else {
      add('WARN', `Hook: ${name} not configured`);
    }
  }
}

function checkMcp(): void {
  // Check project-level .mcp.json
  const projectMcp = path.join(process.cwd(), '.mcp.json');
  // Check user-level config
  const userMcp = path.join(os.homedir(), '.claude.json');

  for (const p of [projectMcp, userMcp]) {
    if (fs.existsSync(p)) {
      try {
        const content = fs.readFileSync(p, 'utf-8');
        if (content.includes('claude-cortex')) {
          add('PASS', `MCP: cortex configured in ${path.basename(p)}`);
          return;
        }
      } catch { /* ignore parse errors */ }
    }
  }
  add('WARN', 'MCP: no cortex entry found in .mcp.json or ~/.claude.json');
}

export async function handleDoctorCommand(): Promise<void> {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  const pkg = require(path.resolve(__dirname, '..', '..', 'package.json'));

  console.log(`\nClaude Cortex Doctor v${pkg.version}\n`);

  checkNode();
  checkDatabase();
  checkClaudeMd();
  checkHooks();
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
