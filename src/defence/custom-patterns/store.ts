/**
 * SQLite CRUD for custom injection patterns (Pro feature).
 */

import { getDatabase } from '../../database/init.js';

export interface CustomPattern {
  id: number;
  name: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  regex: string;
  description: string;
  enabled: number;
  created_at: string;
}

const MAX_PATTERNS = 50;
const MAX_REGEX_LENGTH = 500;

/**
 * Validate regex safety:
 * 1. Length check
 * 2. Compile check
 * 3. ReDoS check via safe-regex2
 */
export function validateRegex(pattern: string): { valid: boolean; error?: string } {
  if (pattern.length > MAX_REGEX_LENGTH) {
    return { valid: false, error: `Pattern exceeds maximum length of ${MAX_REGEX_LENGTH} characters.` };
  }

  // Compile check
  try {
    new RegExp(pattern);
  } catch (e) {
    return { valid: false, error: `Invalid regex: ${(e as Error).message}` };
  }

  // ReDoS check via safe-regex2
  try {
    // Dynamic import fallback — safe-regex2 may not be installed
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const safe = require('safe-regex2');
    if (!safe(pattern)) {
      return { valid: false, error: 'Pattern rejected: potentially vulnerable to ReDoS (catastrophic backtracking).' };
    }
  } catch {
    // Fallback: heuristic check for nested quantifiers
    if (/\(.*[+*].*\)[+*]/.test(pattern) || /\(.*\?\)\{/.test(pattern)) {
      return { valid: false, error: 'Pattern rejected: nested quantifiers detected (ReDoS risk).' };
    }
  }

  return { valid: true };
}

/**
 * Validate flags — only g, i, m allowed.
 */
export function validateFlags(flags?: string): { valid: boolean; error?: string } {
  if (!flags) return { valid: true };
  const allowed = new Set(['g', 'i', 'm']);
  for (const f of flags) {
    if (!allowed.has(f)) {
      return { valid: false, error: `Flag '${f}' is not allowed. Only g, i, m are permitted.` };
    }
  }
  return { valid: true };
}

export function listCustomPatterns(): CustomPattern[] {
  const db = getDatabase();
  return db.prepare('SELECT * FROM custom_patterns ORDER BY created_at DESC').all() as CustomPattern[];
}

export function getCustomPattern(id: number): CustomPattern | undefined {
  const db = getDatabase();
  return db.prepare('SELECT * FROM custom_patterns WHERE id = ?').get(id) as CustomPattern | undefined;
}

export function createCustomPattern(pattern: {
  name: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  regex: string;
  description?: string;
}): CustomPattern {
  const db = getDatabase();
  const count = (db.prepare('SELECT COUNT(*) as cnt FROM custom_patterns').get() as { cnt: number }).cnt;
  if (count >= MAX_PATTERNS) {
    throw new Error(`Maximum of ${MAX_PATTERNS} custom patterns reached.`);
  }

  // Validate regex
  const validation = validateRegex(pattern.regex);
  if (!validation.valid) {
    throw new Error(validation.error);
  }

  const result = db.prepare(`
    INSERT INTO custom_patterns (name, category, severity, regex, description)
    VALUES (?, ?, ?, ?, ?)
  `).run(pattern.name, pattern.category, pattern.severity, pattern.regex, pattern.description || '');

  return getCustomPattern(Number(result.lastInsertRowid))!;
}

export function deleteCustomPattern(id: number): boolean {
  const db = getDatabase();
  const result = db.prepare('DELETE FROM custom_patterns WHERE id = ?').run(id);
  return result.changes > 0;
}

/**
 * Test a pattern against sample text. Returns matches found.
 */
export function testPattern(id: number, text: string): { matches: string[]; count: number } {
  const pattern = getCustomPattern(id);
  if (!pattern) throw new Error('Pattern not found');

  try {
    const regex = new RegExp(pattern.regex, 'gi');
    const matches = text.match(regex) || [];
    return { matches, count: matches.length };
  } catch {
    return { matches: [], count: 0 };
  }
}

/**
 * Get all enabled patterns (used by the defence pipeline).
 */
export function getEnabledCustomPatterns(): CustomPattern[] {
  const db = getDatabase();
  return db.prepare('SELECT * FROM custom_patterns WHERE enabled = 1').all() as CustomPattern[];
}
