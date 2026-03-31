/**
 * Cortex Store — persistent mistake/lesson storage.
 * Uses the same SQLite database as ShieldCortex memory.
 * Pro tier feature.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

// ── Types ────────────────────────────────────────────────

export type MistakeCategory =
  | 'design' | 'code' | 'config' | 'communication'
  | 'judgement' | 'process' | 'data' | 'security';

export type MistakeSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface Mistake {
  id: number;
  timestamp: string;
  category: MistakeCategory;
  severity: MistakeSeverity;
  what: string;
  why: string;
  rule: string;
  tags: string[];
  status: 'active' | 'graduated';
  recurrences: number;
  graduatedAt: string | null;
  agent?: string;          // fleet agent name (e.g. "jarvis", "edith")
  taskContext?: string;     // what task was being performed
}

export interface PreflightMatch {
  score: number;
  mistake: Mistake;
}

export interface ReviewStats {
  total: number;
  active: number;
  graduated: number;
  byCategory: Record<string, number>;
  bySeverity: Record<string, number>;
  repeatOffenders: Mistake[];
  readyToGraduate: Mistake[];
  recentCount: number;     // last 7 days
}

// ── Storage ──────────────────────────────────────────────

function getDataDir(): string {
  const dir = process.env.SHIELDCORTEX_CONFIG_DIR || join(homedir(), '.shieldcortex');
  const cortexDir = join(dir, 'cortex');
  if (!existsSync(cortexDir)) mkdirSync(cortexDir, { recursive: true });
  return cortexDir;
}

function getMistakesFile(): string {
  return join(getDataDir(), 'mistakes.json');
}

export function loadMistakes(): Mistake[] {
  const file = getMistakesFile();
  if (!existsSync(file)) return [];
  try {
    return JSON.parse(readFileSync(file, 'utf-8'));
  } catch {
    return [];
  }
}

export function saveMistakes(mistakes: Mistake[]): void {
  const file = getMistakesFile();
  writeFileSync(file, JSON.stringify(mistakes, null, 2) + '\n', { mode: 0o600 });
}

// ── Capture ──────────────────────────────────────────────

export function capture(opts: {
  category: MistakeCategory;
  severity?: MistakeSeverity;
  what: string;
  why: string;
  rule: string;
  tags?: string[];
  agent?: string;
  taskContext?: string;
}): Mistake {
  const mistakes = loadMistakes();
  const entry: Mistake = {
    id: mistakes.length + 1,
    timestamp: new Date().toISOString(),
    category: opts.category,
    severity: opts.severity || 'medium',
    what: opts.what,
    why: opts.why,
    rule: opts.rule,
    tags: opts.tags || [],
    status: 'active',
    recurrences: 0,
    graduatedAt: null,
    agent: opts.agent,
    taskContext: opts.taskContext,
  };
  mistakes.push(entry);
  saveMistakes(mistakes);
  return entry;
}

// ── Preflight ────────────────────────────────────────────

const CATEGORY_KEYWORDS: Record<string, Set<string>> = {
  design: new Set(['design', 'css', 'html', 'pdf', 'layout', 'font', 'colour', 'color', 'brand', 'logo', 'image', 'slide', 'presentation', 'ui', 'ux', 'flyer', 'banner']),
  code: new Set(['code', 'script', 'python', 'api', 'function', 'bug', 'error', 'import', 'module', 'typescript', 'node', 'build']),
  config: new Set(['config', 'json', 'yaml', 'env', 'setting', 'port', 'path', 'token', 'key', 'dns', 'nginx', 'oauth', 'credential']),
  communication: new Set(['email', 'send', 'reply', 'message', 'slack', 'telegram', 'whatsapp', 'draft', 'notify']),
  judgement: new Set(['decision', 'priority', 'approve', 'confirm', 'check', 'permission', 'authorise', 'authorize']),
  process: new Set(['deploy', 'git', 'push', 'merge', 'test', 'verify', 'backup', 'release', 'publish', 'cron']),
  data: new Set(['data', 'database', 'query', 'xero', 'shopify', 'invoice', 'sync', 'migration', 'import', 'export']),
  security: new Set(['security', 'injection', 'pii', 'firewall', 'scan', 'vulnerability', 'audit', 'breach', 'attack']),
};

export function preflight(taskDescription: string): PreflightMatch[] {
  const mistakes = loadMistakes();
  const task = taskDescription.toLowerCase();
  const taskWords = new Set(task.split(/\s+/));

  const scored: PreflightMatch[] = [];

  for (const m of mistakes) {
    if (m.status !== 'active') continue;

    let score = 0;

    // Category keyword matching
    const catKeywords = CATEGORY_KEYWORDS[m.category];
    if (catKeywords) {
      for (const word of taskWords) {
        if (catKeywords.has(word)) { score += 3; break; }
      }
    }

    // Tag matching
    for (const tag of m.tags) {
      if (task.includes(tag.toLowerCase())) score += 2;
    }

    // Rule/what keyword overlap
    const ruleWords = new Set(
      `${m.rule} ${m.what}`.toLowerCase().split(/\s+/).filter(w => w.length > 3)
    );
    for (const word of taskWords) {
      if (word.length > 3 && ruleWords.has(word)) score += 1;
    }

    // Severity boost
    if (m.severity === 'critical') score += 2;
    else if (m.severity === 'high') score += 1;

    // Recurrence boost
    if (m.recurrences > 0) score += m.recurrences;

    if (score > 0) scored.push({ score, mistake: m });
  }

  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, 10);
}

// ── Review ───────────────────────────────────────────────

export function review(): ReviewStats {
  const mistakes = loadMistakes();
  const active = mistakes.filter(m => m.status === 'active');
  const graduated = mistakes.filter(m => m.status === 'graduated');

  const byCategory: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  for (const m of active) {
    byCategory[m.category] = (byCategory[m.category] || 0) + 1;
    bySeverity[m.severity] = (bySeverity[m.severity] || 0) + 1;
  }

  const thirtyDaysAgo = new Date(Date.now() - 30 * 86400000).toISOString();
  const sevenDaysAgo = new Date(Date.now() - 7 * 86400000).toISOString();

  return {
    total: mistakes.length,
    active: active.length,
    graduated: graduated.length,
    byCategory,
    bySeverity,
    repeatOffenders: active.filter(m => m.recurrences > 0).sort((a, b) => b.recurrences - a.recurrences),
    readyToGraduate: active.filter(m => m.timestamp < thirtyDaysAgo && m.recurrences === 0),
    recentCount: mistakes.filter(m => m.timestamp > sevenDaysAgo).length,
  };
}

// ── Graduate ─────────────────────────────────────────────

export function graduate(): number {
  const mistakes = loadMistakes();
  const thirtyDaysAgo = new Date(Date.now() - 30 * 86400000).toISOString();
  let count = 0;

  for (const m of mistakes) {
    if (m.status === 'active' && m.timestamp < thirtyDaysAgo && m.recurrences === 0) {
      m.status = 'graduated';
      m.graduatedAt = new Date().toISOString();
      count++;
    }
  }

  saveMistakes(mistakes);
  return count;
}

// ── Search ───────────────────────────────────────────────

export function search(query: string): Mistake[] {
  const mistakes = loadMistakes();
  const q = query.toLowerCase();
  return mistakes.filter(m => {
    const text = `${m.what} ${m.why} ${m.rule} ${m.tags.join(' ')}`.toLowerCase();
    return text.includes(q);
  });
}

// ── v4.0.0: Positive Feedback (Confirmations) ───────────────────

export interface Confirmation {
  id: number;
  timestamp: string;
  category: MistakeCategory;
  what: string;
  whyItWorked: string;
  whenToRepeat: string;
  tags: string[];
  agent?: string;
  taskContext?: string;
}

function getConfirmationsFile(): string {
  return join(getDataDir(), 'confirmations.json');
}

export function loadConfirmations(): Confirmation[] {
  const file = getConfirmationsFile();
  if (!existsSync(file)) return [];
  try {
    return JSON.parse(readFileSync(file, 'utf-8'));
  } catch {
    return [];
  }
}

export function saveConfirmations(confirmations: Confirmation[]): void {
  const file = getConfirmationsFile();
  writeFileSync(file, JSON.stringify(confirmations, null, 2) + '\n', { mode: 0o600 });
}

export function captureConfirmation(opts: {
  category: MistakeCategory;
  what: string;
  whyItWorked: string;
  whenToRepeat: string;
  tags?: string[];
  agent?: string;
  taskContext?: string;
}): Confirmation {
  const confirmations = loadConfirmations();
  const entry: Confirmation = {
    id: confirmations.length + 1,
    timestamp: new Date().toISOString(),
    category: opts.category,
    what: opts.what,
    whyItWorked: opts.whyItWorked,
    whenToRepeat: opts.whenToRepeat,
    tags: opts.tags || [],
    agent: opts.agent,
    taskContext: opts.taskContext,
  };
  confirmations.push(entry);
  saveConfirmations(confirmations);
  return entry;
}

export function searchConfirmations(query: string): Confirmation[] {
  const confirmations = loadConfirmations();
  const lower = query.toLowerCase();
  return confirmations.filter(c =>
    c.what.toLowerCase().includes(lower) ||
    c.whyItWorked.toLowerCase().includes(lower) ||
    c.whenToRepeat.toLowerCase().includes(lower) ||
    c.tags.some(t => t.toLowerCase().includes(lower))
  );
}
