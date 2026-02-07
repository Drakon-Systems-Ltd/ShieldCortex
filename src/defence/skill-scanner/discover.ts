/**
 * Skill File Discovery
 *
 * Finds agent instruction files across all known locations:
 * Claude Code skills, OpenClaw hooks, Cursor/Windsurf/Cline rules,
 * GitHub Copilot, Aider, Continue, and CLAUDE.md.
 */

import { existsSync, readdirSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

const KNOWN_FILENAMES = [
  'SKILL.md', 'HOOK.md', 'handler.js',
  '.cursorrules', '.windsurfrules', '.clinerules',
  'CLAUDE.md', 'copilot-instructions.md',
  '.aider.conf.yml', 'config.json',
];

/** Add a file to the list if it exists on disk. */
function addIfExists(files: string[], filePath: string): void {
  try {
    if (existsSync(filePath)) files.push(filePath);
  } catch { /* ignore */ }
}

/**
 * Add files matching `patterns` from `dirPath`, scanning recursively
 * up to `maxDepth` levels (for plugin caches with deep nesting).
 */
function addDirFiles(files: string[], dirPath: string, patterns: string[], maxDepth = 6): void {
  function walk(dir: string, depth: number): void {
    if (depth > maxDepth) return;
    try {
      if (!existsSync(dir)) return;
      const entries = readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = join(dir, entry.name);
        if (entry.isFile() && patterns.some(p => entry.name === p || entry.name.endsWith(p))) {
          files.push(fullPath);
        } else if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
          walk(fullPath, depth + 1);
        }
      }
    } catch { /* ignore */ }
  }
  walk(dirPath, 0);
}

/**
 * Discover agent instruction files across all known locations.
 *
 * @param customDir  If provided, scan this directory instead of defaults.
 * @param cwd        Working directory for CWD-relative files (defaults to process.cwd()).
 * @returns Array of absolute file paths.
 */
export function discoverSkillFiles(customDir?: string, cwd?: string): string[] {
  const files: string[] = [];
  const home = homedir();
  const workDir = cwd ?? process.cwd();

  if (customDir) {
    addDirFiles(files, customDir, KNOWN_FILENAMES);
  } else {
    // Claude Code marketplace skills
    addDirFiles(files, join(home, '.claude', 'plugins', 'cache'), ['SKILL.md']);
    // Claude Code custom commands
    addDirFiles(files, join(home, '.claude', 'commands'), ['.md']);
    // OpenClaw hooks
    addDirFiles(files, join(home, '.openclaw', 'hooks'), ['HOOK.md', 'handler.js']);
    // CWD rule files
    addIfExists(files, join(workDir, '.cursorrules'));
    addIfExists(files, join(workDir, '.windsurfrules'));
    addIfExists(files, join(workDir, '.clinerules'));
    addIfExists(files, join(workDir, '.github', 'copilot-instructions.md'));
    addIfExists(files, join(workDir, 'CLAUDE.md'));
    addIfExists(files, join(workDir, '.aider.conf.yml'));
    addIfExists(files, join(workDir, '.continue', 'config.json'));
  }

  return files;
}
