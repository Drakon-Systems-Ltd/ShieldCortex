/**
 * SQLite CRUD for custom firewall rules (Pro feature).
 */

import { getDatabase } from '../../database/init.js';

export interface FirewallRule {
  id: number;
  name: string;
  priority: number;
  condition_type: string;
  condition_value: string;
  action: 'block' | 'allow' | 'quarantine';
  enabled: number;
  built_in: number;
  created_at: string;
}

const MAX_RULES = 25;

export function listFirewallRules(opts: { includeBuiltin?: boolean } = {}): FirewallRule[] {
  const includeBuiltin = opts.includeBuiltin ?? true;
  const db = getDatabase();
  const where = includeBuiltin ? '' : 'WHERE built_in = 0';
  return db.prepare(`SELECT * FROM firewall_rules ${where} ORDER BY priority ASC`).all() as FirewallRule[];
}

export function getFirewallRule(id: number): FirewallRule | undefined {
  const db = getDatabase();
  return db.prepare('SELECT * FROM firewall_rules WHERE id = ?').get(id) as FirewallRule | undefined;
}

export function createFirewallRule(rule: {
  name: string;
  priority: number;
  condition_type: string;
  condition_value: string;
  action: 'block' | 'allow' | 'quarantine';
}): FirewallRule {
  const db = getDatabase();
  // The MAX_RULES cap applies only to user-defined rules. Built-in rules
  // (built_in=1) are seeded by the database layer and don't count.
  const count = (db.prepare('SELECT COUNT(*) as cnt FROM firewall_rules WHERE built_in = 0').get() as { cnt: number }).cnt;
  if (count >= MAX_RULES) {
    throw new Error(`Maximum of ${MAX_RULES} custom firewall rules reached.`);
  }

  const result = db.prepare(`
    INSERT INTO firewall_rules (name, priority, condition_type, condition_value, action)
    VALUES (?, ?, ?, ?, ?)
  `).run(rule.name, rule.priority, rule.condition_type, rule.condition_value, rule.action);

  return getFirewallRule(Number(result.lastInsertRowid))!;
}

export function updateFirewallRule(id: number, updates: Partial<{
  name: string;
  priority: number;
  condition_type: string;
  condition_value: string;
  action: 'block' | 'allow' | 'quarantine';
  enabled: number;
}>): FirewallRule | undefined {
  const db = getDatabase();
  const existing = getFirewallRule(id);
  if (!existing) return undefined;

  const fields: string[] = [];
  const values: unknown[] = [];

  for (const [key, value] of Object.entries(updates)) {
    if (value !== undefined) {
      fields.push(`${key} = ?`);
      values.push(value);
    }
  }

  if (fields.length === 0) return existing;

  values.push(id);
  db.prepare(`UPDATE firewall_rules SET ${fields.join(', ')} WHERE id = ?`).run(...values);
  return getFirewallRule(id);
}

export function deleteFirewallRule(id: number): boolean {
  const db = getDatabase();
  const result = db.prepare('DELETE FROM firewall_rules WHERE id = ?').run(id);
  return result.changes > 0;
}

/**
 * Get all enabled rules sorted by priority (used by the defence pipeline).
 */
export function getEnabledFirewallRules(): FirewallRule[] {
  const db = getDatabase();
  return db.prepare('SELECT * FROM firewall_rules WHERE enabled = 1 ORDER BY priority ASC').all() as FirewallRule[];
}
