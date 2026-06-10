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

/**
 * Evaluate a single firewall rule against candidate text(s), honouring the
 * rule's `condition_type`. This is the single source of truth for rule
 * matching — the defence pipeline calls it for every enabled rule.
 *
 * - `keyword`: case-insensitive LITERAL substring match. Regex metacharacters
 *   in the value (`a.b`, `x+y`) are treated literally, not as a pattern.
 * - `domain`: the value is matched as a host/domain. It matches when the value
 *   appears as a hostname (or a suffix of one, so `evil.com` matches
 *   `api.evil.com`) anywhere in the text, including inside a URL.
 * - `regex` (and any unknown type): compiled as a case-insensitive RegExp.
 *   Invalid patterns never match (returns false) rather than throwing.
 *
 * `condition_value` is assumed to have already been vetted by safe-regex2 at
 * creation time for regex rules (see createFirewallRule callers); we still
 * guard compilation here so a malformed stored value can't crash the pipeline.
 */
export function ruleMatches(
  rule: Pick<FirewallRule, 'condition_type' | 'condition_value'>,
  ...texts: Array<string | undefined | null>
): boolean {
  const value = rule.condition_value;
  if (!value) return false;
  const candidates = texts.filter((t): t is string => typeof t === 'string' && t.length > 0);
  if (candidates.length === 0) return false;

  const type = (rule.condition_type || 'regex').toLowerCase();

  if (type === 'keyword') {
    const needle = value.toLowerCase();
    return candidates.some((text) => text.toLowerCase().includes(needle));
  }

  if (type === 'domain') {
    return candidates.some((text) => textContainsDomain(text, value));
  }

  // regex (default): compile case-insensitively; a bad pattern never matches.
  let regex: RegExp;
  try {
    regex = new RegExp(value, 'i');
  } catch {
    return false;
  }
  return candidates.some((text) => regex.test(text));
}

/**
 * True when `domain` appears as a host (or a parent suffix of a host) in the
 * given text. We extract hostname-shaped tokens from the text and compare each
 * against the configured domain with proper label-boundary semantics:
 *   - exact match: `evil.com` matches host `evil.com`
 *   - subdomain match: `evil.com` matches host `api.evil.com`
 *   - NOT a partial-label match: `evil.com` does NOT match `notevil.com`
 */
function textContainsDomain(text: string, domain: string): boolean {
  const target = domain.trim().toLowerCase().replace(/^\.+|\.+$/g, '');
  if (!target) return false;

  // Pull out hostname-shaped tokens (URL hosts, bare hosts, emails-after-@).
  // A host is dot-separated labels of [a-z0-9-], at least two labels long, or
  // the exact target itself.
  const hostRegex = /[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+/gi;
  const matches = text.toLowerCase().match(hostRegex);
  if (!matches) return false;

  return matches.some((host) => host === target || host.endsWith(`.${target}`));
}
