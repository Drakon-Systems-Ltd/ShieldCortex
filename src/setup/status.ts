/**
 * Status command - Display ShieldCortex database and system status
 */

import path from 'path';
import os from 'os';
import fs from 'fs';
import { initDatabase, getDatabase } from '../database/init.js';

interface HookActivity {
  hookName: string;
  invocationCount: number;
  lastInvokedAt: string | null;
  memoriesExtracted: number;
}

interface StatusInfo {
  dbPath: string;
  dbSize: string;
  memoriesTotal: number;
  memoriesLongTerm: number;
  memoriesShortTerm: number;
  memoriesEpisodic: number;
  projects: string[];
  lastActivity: string | null;
  quarantined: number;
  threatsBlocked: number;
  hookActivity: HookActivity[];
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatRelativeTime(dateStr: string): string {
  const date = new Date(dateStr);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffMins < 1) return 'just now';
  if (diffMins < 60) return `${diffMins} minute${diffMins === 1 ? '' : 's'} ago`;
  if (diffHours < 24) return `${diffHours} hour${diffHours === 1 ? '' : 's'} ago`;
  if (diffDays < 7) return `${diffDays} day${diffDays === 1 ? '' : 's'} ago`;
  return date.toLocaleDateString();
}

function getStatusInfo(dbPath: string): StatusInfo {
  // Initialize database
  initDatabase(dbPath);
  const db = getDatabase();

  // Get database file size
  let dbSize = '0 B';
  try {
    const stats = fs.statSync(dbPath);
    dbSize = formatBytes(stats.size);
  } catch {
    dbSize = 'unknown';
  }

  // Count memories by type
  const totalRow = db.prepare('SELECT COUNT(*) as count FROM memories').get() as { count: number };
  const longTermRow = db.prepare("SELECT COUNT(*) as count FROM memories WHERE type = 'long_term'").get() as { count: number };
  const shortTermRow = db.prepare("SELECT COUNT(*) as count FROM memories WHERE type = 'short_term'").get() as { count: number };
  const episodicRow = db.prepare("SELECT COUNT(*) as count FROM memories WHERE type = 'episodic'").get() as { count: number };

  // Get unique projects
  const projectRows = db.prepare("SELECT DISTINCT project FROM memories WHERE project IS NOT NULL AND project != ''").all() as { project: string }[];
  const projects = projectRows.map(r => r.project);

  // Get last activity
  const lastRow = db.prepare('SELECT last_accessed FROM memories ORDER BY last_accessed DESC LIMIT 1').get() as { last_accessed: string } | undefined;
  const lastActivity = lastRow ? formatRelativeTime(lastRow.last_accessed) : null;

  // Get defence stats (quarantine table might not exist in older DBs)
  let quarantined = 0;
  let threatsBlocked = 0;
  try {
    const quarantineRow = db.prepare("SELECT COUNT(*) as count FROM quarantine WHERE status = 'pending'").get() as { count: number };
    quarantined = quarantineRow.count;
    const blockedRow = db.prepare("SELECT COUNT(*) as count FROM quarantine WHERE status = 'rejected'").get() as { count: number };
    threatsBlocked = blockedRow.count;
  } catch {
    // Quarantine table doesn't exist - that's fine
  }

  // Per-hook invocation telemetry (last 7 days). Disambiguates the
  // "fires but produces nothing" vs "never fires" failure modes that
  // both showed as "Last activity: never" in older releases.
  const hookActivity: HookActivity[] = [];
  try {
    const rows = db.prepare(`
      SELECT hook_name AS hookName,
             COUNT(*)             AS invocationCount,
             MAX(invoked_at)      AS lastInvokedAt,
             SUM(memories_extracted) AS memoriesExtracted
      FROM hook_invocations
      WHERE invoked_at >= datetime('now', '-7 days')
      GROUP BY hook_name
      ORDER BY hook_name
    `).all() as Array<{ hookName: string; invocationCount: number; lastInvokedAt: string | null; memoriesExtracted: number | null }>;
    for (const r of rows) {
      hookActivity.push({
        hookName: r.hookName,
        invocationCount: r.invocationCount,
        lastInvokedAt: r.lastInvokedAt,
        memoriesExtracted: r.memoriesExtracted ?? 0,
      });
    }
  } catch {
    // hook_invocations table doesn't exist on pre-4.13 installs - leave empty
  }

  return {
    dbPath,
    dbSize,
    memoriesTotal: totalRow.count,
    memoriesLongTerm: longTermRow.count,
    memoriesShortTerm: shortTermRow.count,
    memoriesEpisodic: episodicRow.count,
    projects,
    lastActivity,
    quarantined,
    threatsBlocked,
    hookActivity,
  };
}

const SETTINGS_PATH = path.join(os.homedir(), '.claude', 'settings.json');

function checkHooksConfigured(): boolean {
  try {
    if (!fs.existsSync(SETTINGS_PATH)) return false;
    const settings = JSON.parse(fs.readFileSync(SETTINGS_PATH, 'utf-8'));
    if (!settings.hooks || typeof settings.hooks !== 'object') return false;

    // Check if any hook category has a ShieldCortex hook entry
    for (const category of Object.values(settings.hooks)) {
      if (!Array.isArray(category)) continue;
      for (const entry of category) {
        const hooks = (entry as any)?.hooks;
        if (!Array.isArray(hooks)) continue;
        if (hooks.some((h: any) => typeof h.command === 'string' && h.command.includes('shieldcortex'))) {
          return true;
        }
      }
    }
    return false;
  } catch {
    return false;
  }
}

export async function handleStatusCommand(): Promise<void> {
  // Determine database path
  const dbPath = process.env.CLAUDE_MEMORY_DB || path.join(os.homedir(), '.shieldcortex', 'memories.db');

  // Check if database exists
  if (!fs.existsSync(dbPath)) {
    console.log(`
🧠 ShieldCortex Status
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ⚠️  No database found at: ${dbPath}

  Run 'shieldcortex setup' to get started.
`);
    return;
  }

  try {
    const info = getStatusInfo(dbPath);

    const projectList = info.projects.length > 0 
      ? info.projects.slice(0, 5).join(', ') + (info.projects.length > 5 ? ` (+${info.projects.length - 5} more)` : '')
      : 'none';

    // Check if hooks are configured
    const hooksConfigured = checkHooksConfigured();

    console.log(`
🧠 ShieldCortex Status
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Database:      ${info.dbPath}
  Size:          ${info.dbSize}

  Memories:      ${info.memoriesTotal} total
                 ├─ ${info.memoriesLongTerm} long-term
                 ├─ ${info.memoriesShortTerm} short-term
                 └─ ${info.memoriesEpisodic} episodic
  Projects:      ${info.projects.length} (${projectList})
  Last activity: ${info.lastActivity || 'never'}

  Defence:       ${info.quarantined} quarantined, ${info.threatsBlocked} threats blocked
  Hooks:         ${hooksConfigured ? 'configured' : '⚠️  not configured'}
`);

    if (info.hookActivity.length > 0) {
      console.log('  Hook activity (last 7 days):');
      for (const h of info.hookActivity) {
        const last = h.lastInvokedAt ? formatRelativeTime(h.lastInvokedAt) : 'never';
        const extracted = h.memoriesExtracted > 0
          ? `, extracted ${h.memoriesExtracted} memor${h.memoriesExtracted === 1 ? 'y' : 'ies'}`
          : '';
        console.log(`    ${h.hookName.padEnd(14)} fired ${h.invocationCount}× — last ${last}${extracted}`);
      }
      console.log('');
    }

    if (!hooksConfigured) {
      console.log(`  ⚠️  Claude Code hooks are not set up. Memory won't auto-save or inject context.`);
      console.log(`     Run: shieldcortex install\n`);
    }
  } catch (error) {
    console.error('Failed to get status:', error);
    process.exit(1);
  }
}
