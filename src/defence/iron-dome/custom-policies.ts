/**
 * SQLite CRUD for custom Iron Dome policies (Pro feature).
 */

import { getDatabase } from '../../database/init.js';

export interface IronDomePolicy {
  id: number;
  name: string;
  description: string;
  config: string; // JSON
  is_active: number;
  created_at: string;
}

const MAX_POLICIES = 10;

export function listIronDomePolicies(): IronDomePolicy[] {
  const db = getDatabase();
  return db.prepare('SELECT * FROM iron_dome_policies ORDER BY created_at DESC').all() as IronDomePolicy[];
}

export function getIronDomePolicy(id: number): IronDomePolicy | undefined {
  const db = getDatabase();
  return db.prepare('SELECT * FROM iron_dome_policies WHERE id = ?').get(id) as IronDomePolicy | undefined;
}

export function getActiveIronDomePolicy(): IronDomePolicy | undefined {
  const db = getDatabase();
  return db.prepare('SELECT * FROM iron_dome_policies WHERE is_active = 1').get() as IronDomePolicy | undefined;
}

export function createIronDomePolicy(policy: {
  name: string;
  description?: string;
  config: Record<string, unknown>;
}): IronDomePolicy {
  const db = getDatabase();
  const count = (db.prepare('SELECT COUNT(*) as cnt FROM iron_dome_policies').get() as { cnt: number }).cnt;
  if (count >= MAX_POLICIES) {
    throw new Error(`Maximum of ${MAX_POLICIES} custom Iron Dome policies reached.`);
  }

  const configJson = JSON.stringify(policy.config);
  const result = db.prepare(`
    INSERT INTO iron_dome_policies (name, description, config)
    VALUES (?, ?, ?)
  `).run(policy.name, policy.description || '', configJson);

  return getIronDomePolicy(Number(result.lastInsertRowid))!;
}

/**
 * Activate a policy. Deactivates any currently active policy in a transaction
 * to maintain the at-most-one invariant enforced by the partial unique index.
 */
export function activateIronDomePolicy(id: number): IronDomePolicy | undefined {
  const db = getDatabase();
  const policy = getIronDomePolicy(id);
  if (!policy) return undefined;

  const activate = db.transaction(() => {
    // Deactivate current active policy (if any)
    db.prepare('UPDATE iron_dome_policies SET is_active = 0 WHERE is_active = 1').run();
    // Activate the requested policy
    db.prepare('UPDATE iron_dome_policies SET is_active = 1 WHERE id = ?').run(id);
  });
  activate();

  return getIronDomePolicy(id);
}

export function deleteIronDomePolicy(id: number): boolean {
  const db = getDatabase();
  const result = db.prepare('DELETE FROM iron_dome_policies WHERE id = ?').run(id);
  return result.changes > 0;
}

export function updateIronDomePolicy(id: number, updates: Partial<{
  name: string;
  description: string;
  config: Record<string, unknown>;
}>): IronDomePolicy | undefined {
  const db = getDatabase();
  const existing = getIronDomePolicy(id);
  if (!existing) return undefined;

  const fields: string[] = [];
  const values: unknown[] = [];

  if (updates.name !== undefined) {
    fields.push('name = ?');
    values.push(updates.name);
  }
  if (updates.description !== undefined) {
    fields.push('description = ?');
    values.push(updates.description);
  }
  if (updates.config !== undefined) {
    fields.push('config = ?');
    values.push(JSON.stringify(updates.config));
  }

  if (fields.length === 0) return existing;

  values.push(id);
  db.prepare(`UPDATE iron_dome_policies SET ${fields.join(', ')} WHERE id = ?`).run(...values);
  return getIronDomePolicy(id);
}
