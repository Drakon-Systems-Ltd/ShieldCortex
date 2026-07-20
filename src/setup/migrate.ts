/**
 * Migration from Claude Cortex / Claude Memory to ShieldCortex.
 *
 * Non-destructive: copies database (doesn't move), replaces settings entries.
 * Also cleans up old LaunchAgents and npm packages to prevent conflicts.
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import { execSync } from 'child_process';
import Database from '../database/better-sqlite3-guard.js';

const SETTINGS_PATH = path.join(os.homedir(), '.claude', 'settings.json');
const CLAUDE_MD_PATH = path.join(os.homedir(), '.claude', 'CLAUDE.md');

const NEW_DB_DIR = path.join(os.homedir(), '.shieldcortex');
const LEGACY_DIRS = [
  path.join(os.homedir(), '.claude-cortex'),
  path.join(os.homedir(), '.claude-memory'),
];

const OLD_MARKERS = ['# Claude Cortex', '# Claude Memory'];
const NEW_MARKER = '# ShieldCortex';

const OLD_PATTERNS = ['claude-cortex', 'claude-memory'];

// Old LaunchAgent/service names to clean up
const OLD_LAUNCH_AGENTS = [
  'com.claude-cortex.dashboard.plist',
  'com.claude-memory.dashboard.plist',
];

const OLD_SYSTEMD_SERVICES = [
  'claude-cortex-dashboard.service',
  'claude-memory-dashboard.service',
];

/**
 * Clean up old npm packages that might conflict or auto-start old dashboards.
 */
export function cleanupOldNpmPackages(): { uninstalled: string[] } {
  const uninstalled: string[] = [];

  for (const pkg of OLD_PATTERNS) {
    try {
      // Check if package is installed globally
      const result = execSync(`npm list -g ${pkg} 2>/dev/null`, { encoding: 'utf-8' });
      if (result.includes(pkg)) {
        console.log(`  Uninstalling old package: ${pkg}...`);
        execSync(`npm uninstall -g ${pkg}`, { stdio: 'pipe' });
        uninstalled.push(pkg);
        console.log(`  ✓ Uninstalled ${pkg}`);
      }
    } catch {
      // Package not installed or uninstall failed — ignore
    }
  }

  if (uninstalled.length === 0) {
    console.log('  No old npm packages found to remove.');
  }

  return { uninstalled };
}

/**
 * Clean up old LaunchAgents (macOS) or systemd services (Linux) that would auto-start
 * the deprecated dashboard on reboot.
 */
export function cleanupOldServices(): { removed: string[] } {
  const removed: string[] = [];
  const platform = process.platform;

  if (platform === 'darwin') {
    // macOS: Clean up LaunchAgents
    const launchAgentsDir = path.join(os.homedir(), 'Library', 'LaunchAgents');

    for (const agent of OLD_LAUNCH_AGENTS) {
      const agentPath = path.join(launchAgentsDir, agent);
      if (fs.existsSync(agentPath)) {
        try {
          // Unload first (ignore errors if not loaded)
          try {
            execSync(`launchctl unload "${agentPath}" 2>/dev/null`, { stdio: 'pipe' });
          } catch {
            // May not be loaded — that's fine
          }

          fs.unlinkSync(agentPath);
          removed.push(agent);
          console.log(`  ✓ Removed old LaunchAgent: ${agent}`);
        } catch (err: any) {
          console.error(`  Failed to remove ${agent}: ${err.message}`);
        }
      }
    }
  } else if (platform === 'linux') {
    // Linux: Clean up systemd user services
    const systemdDir = path.join(os.homedir(), '.config', 'systemd', 'user');

    for (const service of OLD_SYSTEMD_SERVICES) {
      const servicePath = path.join(systemdDir, service);
      if (fs.existsSync(servicePath)) {
        try {
          // Disable and stop first
          const serviceName = service.replace('.service', '');
          try {
            execSync(`systemctl --user disable --now ${serviceName} 2>/dev/null`, { stdio: 'pipe' });
          } catch {
            // May not be enabled — that's fine
          }

          fs.unlinkSync(servicePath);
          removed.push(service);
          console.log(`  ✓ Removed old systemd service: ${service}`);
        } catch (err: any) {
          console.error(`  Failed to remove ${service}: ${err.message}`);
        }
      }
    }

    // Reload systemd if we removed anything
    if (removed.length > 0) {
      try {
        execSync('systemctl --user daemon-reload', { stdio: 'pipe' });
      } catch {
        // Ignore reload errors
      }
    }
  }

  if (removed.length === 0) {
    console.log('  No old services found to remove.');
  }

  return { removed };
}

export function migrateSettings(): { mcpSwapped: number; hooksSwapped: number } {
  let mcpSwapped = 0;
  let hooksSwapped = 0;

  if (!fs.existsSync(SETTINGS_PATH)) {
    console.log('  No ~/.claude/settings.json found — skipping.');
    return { mcpSwapped, hooksSwapped };
  }

  let settings: Record<string, any>;
  try {
    settings = JSON.parse(fs.readFileSync(SETTINGS_PATH, 'utf-8'));
  } catch {
    console.error('  Failed to parse settings.json — skipping to avoid corruption.');
    return { mcpSwapped, hooksSwapped };
  }

  // Swap MCP server entries
  if (settings.mcpServers && typeof settings.mcpServers === 'object') {
    for (const oldName of OLD_PATTERNS) {
      if (settings.mcpServers[oldName] && !settings.mcpServers['shieldcortex']) {
        settings.mcpServers['shieldcortex'] = settings.mcpServers[oldName];
        delete settings.mcpServers[oldName];
        mcpSwapped++;
        console.log(`  MCP server: "${oldName}" → "shieldcortex"`);

        // Update args if they reference the old package name
        const entry = settings.mcpServers['shieldcortex'];
        if (Array.isArray(entry.args)) {
          entry.args = entry.args.map((arg: string) => {
            for (const old of OLD_PATTERNS) {
              if (typeof arg === 'string' && arg.includes(old)) {
                return arg.replace(old, 'shieldcortex');
              }
            }
            return arg;
          });
        }
      }
    }
  }

  // Swap hook commands
  if (settings.hooks && typeof settings.hooks === 'object') {
    for (const category of Object.keys(settings.hooks)) {
      const entries = settings.hooks[category];
      if (!Array.isArray(entries)) continue;

      for (const entry of entries) {
        if (!Array.isArray(entry.hooks)) continue;
        for (const hook of entry.hooks) {
          if (typeof hook.command !== 'string') continue;
          for (const old of OLD_PATTERNS) {
            if (hook.command.includes(old)) {
              hook.command = hook.command.replace(new RegExp(old, 'g'), 'shieldcortex');
              hooksSwapped++;
              console.log(`  Hook ${category}: swapped "${old}" → "shieldcortex"`);
            }
          }
        }
      }
    }
  }

  if (mcpSwapped > 0 || hooksSwapped > 0) {
    fs.writeFileSync(SETTINGS_PATH, JSON.stringify(settings, null, 2) + '\n', 'utf-8');
    console.log(`  Settings saved.`);
  } else {
    console.log('  Settings: no old references found (already migrated or fresh install).');
  }

  return { mcpSwapped, hooksSwapped };
}

export function migrateDatabase(): { copied: boolean; merged: boolean; mergedCount?: number; source?: string } {
  const targetDir = NEW_DB_DIR;
  const targetPath = path.join(targetDir, 'memories.db');

  // Find the best legacy source
  let legacyPath: string | null = null;
  for (const legacyDir of LEGACY_DIRS) {
    const candidate = path.join(legacyDir, 'memories.db');
    if (fs.existsSync(candidate)) {
      legacyPath = candidate;
      break;
    }
  }

  if (!legacyPath) {
    console.log('  Database: no legacy database found — nothing to migrate.');
    return { copied: false, merged: false };
  }

  // Fresh install — just copy
  if (!fs.existsSync(targetPath)) {
    fs.mkdirSync(targetDir, { recursive: true });
    fs.copyFileSync(legacyPath, targetPath);
    console.log(`  Database: copied ${legacyPath} → ${targetPath}`);
    console.log(`  (Original preserved at ${legacyPath} for rollback)`);

    for (const suffix of ['-wal', '-shm']) {
      const src = legacyPath + suffix;
      if (fs.existsSync(src)) {
        fs.copyFileSync(src, targetPath + suffix);
      }
    }

    return { copied: true, merged: false, source: legacyPath };
  }

  // Target exists — merge memories that don't already exist
  try {
    const db = new Database(targetPath);
    db.pragma('journal_mode = WAL');
    db.pragma('busy_timeout = 5000');

    const countBefore = (db.prepare('SELECT COUNT(*) as c FROM memories').get() as { c: number }).c;

    db.exec(`ATTACH DATABASE '${legacyPath.replace(/'/g, "''")}' AS old`);

    // Get columns that exist in both tables
    const newCols = db.prepare("PRAGMA table_info(memories)").all().map((r: any) => r.name);
    const oldCols = db.prepare("PRAGMA old.table_info(memories)").all().map((r: any) => r.name);
    const sharedCols = newCols.filter((c: string) => c !== 'id' && oldCols.includes(c));

    // P1/WS3: legacy-DB rows are the user's own prior memories, unscanned by the
    // current pipeline — copy them with an explicit 'legacy' defence_verdict
    // (old DBs predate the column) so every migrated row carries a verdict.
    const colList = sharedCols.join(', ');
    const verdictCol = sharedCols.includes('defence_verdict') ? '' : ', defence_verdict';
    const verdictSel = sharedCols.includes('defence_verdict') ? '' : ", 'legacy'";
    db.exec(`INSERT OR IGNORE INTO memories (${colList}${verdictCol}) SELECT ${colList}${verdictSel} FROM old.memories`);

    db.exec('DETACH old');

    const countAfter = (db.prepare('SELECT COUNT(*) as c FROM memories').get() as { c: number }).c;
    const imported = countAfter - countBefore;

    db.close();

    if (imported > 0) {
      console.log(`  Database: merged ${imported} memories from ${legacyPath}`);
      console.log(`  (Original preserved at ${legacyPath} for rollback)`);
    } else {
      console.log(`  Database: all memories already present — nothing new to import.`);
    }

    return { copied: false, merged: imported > 0, mergedCount: imported, source: legacyPath };
  } catch (err: any) {
    console.error(`  Database merge failed: ${err.message}`);
    console.log(`  You can manually copy ${legacyPath} → ${targetPath} if needed.`);
    return { copied: false, merged: false };
  }
}

export function migrateClaudeMd(): boolean {
  if (!fs.existsSync(CLAUDE_MD_PATH)) {
    console.log('  CLAUDE.md: not found — skipping.');
    return false;
  }

  let content = fs.readFileSync(CLAUDE_MD_PATH, 'utf-8');
  let changed = false;

  for (const oldMarker of OLD_MARKERS) {
    if (content.includes(oldMarker)) {
      content = content.replace(new RegExp(oldMarker.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), NEW_MARKER);
      changed = true;
      console.log(`  CLAUDE.md: replaced "${oldMarker}" → "${NEW_MARKER}"`);
    }
  }

  if (changed) {
    fs.writeFileSync(CLAUDE_MD_PATH, content, 'utf-8');
  } else {
    console.log('  CLAUDE.md: no old markers found.');
  }

  return changed;
}

/**
 * Migrate OpenClaw hooks from legacy ~/.clawdbot/ to ~/.openclaw/.
 * Non-destructive: copies files, then removes legacy directory.
 */
export function migrateOpenClawHooks(): { migrated: boolean; cleanedLegacy: boolean } {
  const home = os.homedir();
  // Check both possible legacy locations (skip if .clawdbot is a symlink to .openclaw)
  const clawdbotDir = path.join(home, '.clawdbot');
  const isSymlink = fs.existsSync(clawdbotDir) && fs.lstatSync(clawdbotDir).isSymbolicLink();
  const legacyCandidates = isSymlink ? [] : [
    path.join(home, '.clawdbot', 'hooks', 'internal', 'cortex-memory'),
    path.join(home, '.clawdbot', 'hooks', 'cortex-memory'),
  ];
  const legacyHookDir = legacyCandidates.find(d => fs.existsSync(d)) || null;

  // Check both possible new locations
  const newCandidates = [
    path.join(home, '.openclaw', 'hooks', 'internal', 'cortex-memory'),
    path.join(home, '.openclaw', 'hooks', 'cortex-memory'),
  ];
  const newHookDir = newCandidates.find(d => fs.existsSync(d)) || path.join(home, '.openclaw', 'hooks', 'internal', 'cortex-memory');

  if (!legacyHookDir) {
    console.log('  No legacy ~/.clawdbot/hooks/cortex-memory/ found — skipping.');
    return { migrated: false, cleanedLegacy: false };
  }

  let migrated = false;
  let cleanedLegacy = false;

  // Copy to new location if not already there
  if (!fs.existsSync(newHookDir)) {
    fs.mkdirSync(newHookDir, { recursive: true });
    for (const file of fs.readdirSync(legacyHookDir)) {
      fs.copyFileSync(
        path.join(legacyHookDir, file),
        path.join(newHookDir, file)
      );
    }
    console.log(`  ✓ Copied hook from ~/.clawdbot/ → ~/.openclaw/`);
    migrated = true;
  } else {
    console.log('  Hook already exists at ~/.openclaw/ — skipping copy.');
  }

  // Clean up legacy hook directory
  try {
    fs.rmSync(legacyHookDir, { recursive: true });
    console.log('  ✓ Removed legacy ~/.clawdbot/hooks/cortex-memory/');
    cleanedLegacy = true;

    // Remove empty parent dirs if possible
    const legacyHooksDir = path.join(home, '.clawdbot', 'hooks');
    if (fs.existsSync(legacyHooksDir) && fs.readdirSync(legacyHooksDir).length === 0) {
      fs.rmdirSync(legacyHooksDir);
    }
    const legacyBaseDir = path.join(home, '.clawdbot');
    if (fs.existsSync(legacyBaseDir) && fs.readdirSync(legacyBaseDir).length === 0) {
      fs.rmdirSync(legacyBaseDir);
    }
  } catch (err: any) {
    console.log(`  Could not remove legacy directory: ${err.message}`);
  }

  return { migrated, cleanedLegacy };
}

export async function handleMigrateCommand(): Promise<void> {
  console.log('Migrating from Claude Cortex → ShieldCortex...\n');

  console.log('[1/6] Settings (MCP server + hooks)');
  const { mcpSwapped, hooksSwapped } = migrateSettings();

  console.log('\n[2/6] Database');
  const { copied, merged, mergedCount, source } = migrateDatabase();

  console.log('\n[3/6] CLAUDE.md');
  const mdChanged = migrateClaudeMd();

  console.log('\n[4/6] OpenClaw hooks (clawdbot → openclaw)');
  const { migrated: hooksMigrated, cleanedLegacy } = migrateOpenClawHooks();

  console.log('\n[5/6] Cleanup old npm packages');
  const { uninstalled } = cleanupOldNpmPackages();

  console.log('\n[6/6] Cleanup old services (LaunchAgents/systemd)');
  const { removed } = cleanupOldServices();

  console.log('\n─────────────────────────────────');
  console.log('Migration complete.');

  const noChanges = mcpSwapped === 0 && hooksSwapped === 0 && !copied && !merged && !mdChanged && !hooksMigrated && !cleanedLegacy && uninstalled.length === 0 && removed.length === 0;

  if (noChanges) {
    console.log('Nothing to migrate — you\'re already on ShieldCortex.');
  } else {
    console.log('\nWhat changed:');
    if (mcpSwapped > 0) console.log(`  ✓ MCP server entry swapped`);
    if (hooksSwapped > 0) console.log(`  ✓ ${hooksSwapped} hook command(s) updated`);
    if (copied) console.log(`  ✓ Database copied (original preserved at ${source})`);
    if (merged) console.log(`  ✓ ${mergedCount} memories merged from ${source}`);
    if (mdChanged) console.log(`  ✓ CLAUDE.md markers updated`);
    if (hooksMigrated) console.log(`  ✓ OpenClaw hook migrated from ~/.clawdbot/ to ~/.openclaw/`);
    if (cleanedLegacy) console.log(`  ✓ Legacy ~/.clawdbot/hooks/ cleaned up`);
    if (uninstalled.length > 0) console.log(`  ✓ Uninstalled old npm packages: ${uninstalled.join(', ')}`);
    if (removed.length > 0) console.log(`  ✓ Removed old services: ${removed.join(', ')}`);
    console.log('\nRestart Claude Code to use the new configuration.');
  }
}
