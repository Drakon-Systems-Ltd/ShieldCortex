import fs from 'fs';
import path from 'path';
import os from 'os';
import { getDatabase } from '../database/init.js';

/**
 * Copy the live memories DB to ~/.shieldcortex/backups/ using SQLite's
 * backup() API (consistent snapshot even with the API server holding an
 * open WAL connection). Returns the absolute path of the written file.
 *
 * Used as a safety net before any destructive maintenance op (prune /
 * dedupe). The caller surfaces the path back to the user so they can
 * restore manually if a maintenance run was wrong.
 */
export async function backupMemoriesDb(label: string): Promise<string> {
  const home = os.homedir();
  const backupDir = path.join(home, '.shieldcortex', 'backups');
  if (!fs.existsSync(backupDir)) {
    fs.mkdirSync(backupDir, { recursive: true });
  }

  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const safeLabel = label.replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 32) || 'backup';
  const outPath = path.join(backupDir, `memories.${stamp}.${safeLabel}.db`);

  const db = getDatabase();
  // better-sqlite3's backup() returns a Promise that resolves once the
  // page-by-page copy completes. It honours WAL mode so the snapshot is
  // consistent without locking the API server out.
  await db.backup(outPath);
  return outPath;
}

/**
 * List existing backups newest-first. Caller can show this in the UI so
 * the user knows what restore points exist.
 */
export function listMemoriesBackups(): Array<{ path: string; sizeBytes: number; createdAt: string }> {
  const home = os.homedir();
  const backupDir = path.join(home, '.shieldcortex', 'backups');
  if (!fs.existsSync(backupDir)) return [];

  return fs.readdirSync(backupDir)
    .filter((name) => name.startsWith('memories.') && name.endsWith('.db'))
    .map((name) => {
      const full = path.join(backupDir, name);
      const stat = fs.statSync(full);
      return { path: full, sizeBytes: stat.size, createdAt: stat.mtime.toISOString() };
    })
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}
