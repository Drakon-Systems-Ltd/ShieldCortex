/**
 * Migration from Claude Cortex / Claude Memory to ShieldCortex.
 *
 * Non-destructive: copies database (doesn't move), replaces settings entries.
 */

import fs from 'fs';
import path from 'path';
import os from 'os';

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
    const Database = require('better-sqlite3');
    const db = new Database(targetPath);
    db.pragma('journal_mode = WAL');
    db.pragma('busy_timeout = 5000');

    const countBefore = db.prepare('SELECT COUNT(*) as c FROM memories').get().c;

    db.exec(`ATTACH DATABASE '${legacyPath.replace(/'/g, "''")}' AS old`);

    // Get columns that exist in both tables
    const newCols = db.prepare("PRAGMA table_info(memories)").all().map((r: any) => r.name);
    const oldCols = db.prepare("PRAGMA old.table_info(memories)").all().map((r: any) => r.name);
    const sharedCols = newCols.filter((c: string) => c !== 'id' && oldCols.includes(c));

    const colList = sharedCols.join(', ');
    db.exec(`INSERT OR IGNORE INTO memories (${colList}) SELECT ${colList} FROM old.memories`);

    db.exec('DETACH old');

    const countAfter = db.prepare('SELECT COUNT(*) as c FROM memories').get().c;
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

export async function handleMigrateCommand(): Promise<void> {
  console.log('Migrating from Claude Cortex → ShieldCortex...\n');

  console.log('[1/3] Settings (MCP server + hooks)');
  const { mcpSwapped, hooksSwapped } = migrateSettings();

  console.log('\n[2/3] Database');
  const { copied, merged, mergedCount, source } = migrateDatabase();

  console.log('\n[3/3] CLAUDE.md');
  const mdChanged = migrateClaudeMd();

  console.log('\n─────────────────────────────────');
  console.log('Migration complete.');

  if (mcpSwapped === 0 && hooksSwapped === 0 && !copied && !merged && !mdChanged) {
    console.log('Nothing to migrate — you\'re already on ShieldCortex.');
  } else {
    console.log('\nWhat changed:');
    if (mcpSwapped > 0) console.log(`  ✓ MCP server entry swapped`);
    if (hooksSwapped > 0) console.log(`  ✓ ${hooksSwapped} hook command(s) updated`);
    if (copied) console.log(`  ✓ Database copied (original preserved at ${source})`);
    if (merged) console.log(`  ✓ ${mergedCount} memories merged from ${source}`);
    if (mdChanged) console.log(`  ✓ CLAUDE.md markers updated`);
    console.log('\nRestart Claude Code to use the new configuration.');
  }
}
