/**
 * Memory expiry — auto-delete memories matching user-defined rules.
 * Rules stored in ~/.shieldcortex/config.json under "expiryRules" key.
 */

import { getDatabase } from '../database/init.js';
import { readRawConfig } from '../cloud/config.js';
import { deleteMemory } from './store.js';
import type { MemoryCategory, MemoryType } from './types.js';

export interface ExpiryRule {
  category?: string;      // e.g., 'todo' — only match this category
  type?: string;          // e.g., 'short_term'
  maxAgeDays: number;     // delete if older than this
  tag?: string;           // only match memories with this tag
  protect?: boolean;      // if true, NEVER expire (override for important memories)
}

/**
 * Load expiry rules from ~/.shieldcortex/config.json.
 * Returns an empty array if missing or malformed.
 */
export function loadExpiryRules(): ExpiryRule[] {
  try {
    const raw = readRawConfig();
    if (!Array.isArray(raw.expiryRules)) return [];
    return (raw.expiryRules as ExpiryRule[]).filter(
      (r) => r && typeof r.maxAgeDays === 'number' && r.maxAgeDays > 0
    );
  } catch {
    return [];
  }
}

/**
 * Apply all expiry rules, deleting matching memories that exceed their max age.
 * Memories with salience > 0.8 are always protected regardless of rules.
 * Returns counts of deleted and protected memories.
 */
export function applyExpiryRules(): { deleted: number; protected: number } {
  const rules = loadExpiryRules();
  if (rules.length === 0) return { deleted: 0, protected: 0 };

  let deleted = 0;
  let protectedCount = 0;

  const db = getDatabase();

  // Separate protect rules from expiry rules
  const protectRules = rules.filter((r) => r.protect === true);
  const expiryRules = rules.filter((r) => r.protect !== true);

  for (const rule of expiryRules) {
    const cutoffDate = new Date(Date.now() - rule.maxAgeDays * 24 * 60 * 60 * 1000).toISOString();

    // Build WHERE clause for this rule
    let where = 'WHERE created_at < ?';
    const params: unknown[] = [cutoffDate];

    if (rule.category) {
      where += ' AND category = ?';
      params.push(rule.category);
    }

    if (rule.type) {
      where += ' AND type = ?';
      params.push(rule.type);
    }

    const rows = db.prepare(`SELECT id, salience, category, type, tags FROM memories ${where}`).all(...params) as Array<{
      id: number;
      salience: number;
      category: MemoryCategory;
      type: MemoryType;
      tags: string;
    }>;

    for (const row of rows) {
      // Always protect high-salience memories
      if (row.salience > 0.8) {
        protectedCount++;
        continue;
      }

      // Check if any protect rule applies to this memory
      if (isProtected(row, protectRules)) {
        protectedCount++;
        continue;
      }

      // Check tag filter if specified
      if (rule.tag) {
        try {
          const tags: string[] = JSON.parse(row.tags || '[]');
          if (!tags.includes(rule.tag)) continue;
        } catch {
          continue;
        }
      }

      // Delete the memory
      if (deleteMemory(row.id)) {
        deleted++;
      }
    }
  }

  return { deleted, protected: protectedCount };
}

/**
 * Check if a memory is protected by any protect rule.
 */
function isProtected(
  row: { category: MemoryCategory; type: MemoryType; tags: string },
  protectRules: ExpiryRule[]
): boolean {
  for (const rule of protectRules) {
    let matches = true;

    if (rule.category && row.category !== rule.category) matches = false;
    if (rule.type && row.type !== rule.type) matches = false;

    if (rule.tag && matches) {
      try {
        const tags: string[] = JSON.parse(row.tags || '[]');
        if (!tags.includes(rule.tag)) matches = false;
      } catch {
        matches = false;
      }
    }

    // A protect rule with no category/type/tag protects everything — skip that
    if (matches && (rule.category || rule.type || rule.tag)) {
      return true;
    }
  }

  return false;
}
