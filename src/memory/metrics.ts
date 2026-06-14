/**
 * Memory-quality metrics (Phase 0, measure-first).
 *
 * Read-only instruments that make memory-quality problems QUERYABLE before any
 * model change — so a fix can be validated against the same number, not vibes.
 * Nothing here mutates or deletes; every function is a pure read of the store.
 *
 * The headline instrument is `getSalienceDistribution`: it quantifies the
 * "salience wall" (raw salience saturates at 1.0 for long-lived memories, so it
 * stops discriminating) and the fragment pollution within that wall — the exact
 * shape the edith field report exposed (43/43 long-term at ≥0.99, 81% of them
 * mid-sentence fragments). Re-run it after a change to prove the wall spread and
 * the fragments fell.
 */

import { getDatabase } from '../database/init.js';

type DB = ReturnType<typeof getDatabase>;

/** Salience band boundaries. The top boundary is 0.95 so the final band is the
 * "wall" — the cohort that has ratcheted to (effectively) maximum salience. */
const BAND_EDGES = [0, 0.2, 0.4, 0.6, 0.8, 0.95, 1.0001] as const;
const WALL_THRESHOLD = 0.95;

/** WARN thresholds (roadmap Phase 0): a store is unhealthy when most long-term
 * memories have hit the wall, or when most of the wall is fragments. */
const WALL_LTM_PCT_WARN = 40;
const FRAGMENT_PCT_WARN = 30;

export interface SalienceBand {
  /** Human label, e.g. "0.95–1.00". */
  band: string;
  count: number;
  long_term: number;
  short_term: number;
  episodic: number;
}

export interface SalienceDistribution {
  total: number;
  bands: SalienceBand[];
  /** The salience wall: how saturated long-term memory is. */
  wall: { ltmAtOrAbove095: number; ltmTotal: number; ltmPct: number };
  /** Fragment pollution within the high-salience (≥0.95) cohort. */
  fragments: { atOrAbove095: number; pctOfWall: number };
  /** Human-readable WARN lines when a threshold is breached. */
  warnings: string[];
}

/**
 * Measurement heuristic for "mid-sentence fragment": the content begins on a
 * lowercase function word (sliced before the clause). Intentionally simpler
 * than the ranking-time completeness factor in scripts/lib/salience.mjs — this
 * is a histogram signal, not a recall gate, and "starts lowercase on a function
 * word" captured ~81% of the edith fragment cohort. Kept local (no cross-module
 * coupling into the hot path) and documented as an approximation.
 */
const FRAGMENT_LEAD_WORDS = new Set([
  'and', 'or', 'but', 'nor', 'the', 'a', 'an', 'to', 'of', 'in', 'on', 'at',
  'by', 'for', 'with', 'without', 'from', 'as', 'is', 'are', 'was', 'were',
  'be', 'been', 'that', 'which', 'who', 'whose', 'because', 'so', 'if', 'when',
  'while', 'than', 'then', 'into', 'onto', 'over', 'under', 'via', 'per',
  'about', 'after', 'before', 'between', 'during',
]);

export function looksLikeFragmentContent(content: unknown): boolean {
  if (typeof content !== 'string') return false;
  const t = content.trim();
  if (!t) return false;
  const firstLetter = t.match(/[A-Za-z]/);
  if (!firstLetter || firstLetter[0] < 'a' || firstLetter[0] > 'z') return false; // not a lowercase lead
  // First word carrying letters (skip leading punctuation / em-dashes).
  let first = '';
  for (const w of t.split(/\s+/)) {
    const c = w.toLowerCase().replace(/[^a-z']/g, '');
    if (c) { first = c; break; }
  }
  return FRAGMENT_LEAD_WORDS.has(first);
}

function bandLabel(lo: number, hi: number): string {
  const top = hi > 1 ? 1 : hi;
  return `${lo.toFixed(2)}–${top.toFixed(2)}`;
}

function pct(n: number, d: number): number {
  return d > 0 ? Math.round((n / d) * 100) : 0;
}

/**
 * Compute the salience distribution + wall + fragment metrics for the store.
 *
 * @param db Optional better-sqlite3 handle (defaults to the live DB). Passing a
 *   handle keeps it unit-testable without touching the real store.
 * @param project Optional project filter (NULL-project rows always included).
 */
export function getSalienceDistribution(db: DB = getDatabase(), project?: string): SalienceDistribution {
  const where = project ? 'WHERE (project = ? OR project IS NULL)' : '';
  const args = project ? [project] : [];
  const rows = db
    .prepare(`SELECT type, salience, content FROM memories ${where}`)
    .all(...args) as { type: string; salience: number; content: string }[];

  const bands: SalienceBand[] = [];
  for (let i = 0; i < BAND_EDGES.length - 1; i++) {
    bands.push({ band: bandLabel(BAND_EDGES[i], BAND_EDGES[i + 1]), count: 0, long_term: 0, short_term: 0, episodic: 0 });
  }

  let ltmTotal = 0;
  let ltmAtWall = 0;
  let wallFragments = 0;

  for (const r of rows) {
    const s = typeof r.salience === 'number' ? r.salience : 0;
    let bi = BAND_EDGES.findIndex((edge, i) => i > 0 && s < edge) - 1;
    if (bi < 0) bi = bands.length - 1; // clamp s>=1.0 into the top band
    const band = bands[bi];
    band.count++;
    if (r.type === 'long_term') band.long_term++;
    else if (r.type === 'episodic') band.episodic++;
    else band.short_term++;

    if (r.type === 'long_term') {
      ltmTotal++;
      if (s >= WALL_THRESHOLD) {
        ltmAtWall++;
        if (looksLikeFragmentContent(r.content)) wallFragments++;
      }
    }
  }

  const ltmPct = pct(ltmAtWall, ltmTotal);
  const fragPctOfWall = pct(wallFragments, ltmAtWall);

  const warnings: string[] = [];
  if (ltmPct > WALL_LTM_PCT_WARN) {
    warnings.push(`Salience wall: ${ltmPct}% of long-term memories sit at salience ≥${WALL_THRESHOLD} (raw salience has stopped discriminating).`);
  }
  if (fragPctOfWall > FRAGMENT_PCT_WARN) {
    warnings.push(`Fragment pollution: ${fragPctOfWall}% of the high-salience (≥${WALL_THRESHOLD}) cohort are mid-sentence fragments.`);
  }

  return {
    total: rows.length,
    bands,
    wall: { ltmAtOrAbove095: ltmAtWall, ltmTotal, ltmPct },
    fragments: { atOrAbove095: wallFragments, pctOfWall: fragPctOfWall },
    warnings,
  };
}

export interface HookYield {
  hooks: Array<{ hook: string; fires: number; extracted: number; avgPerFire: number }>;
  totalFires: number;
  totalExtracted: number;
}

/**
 * Aggregate hook_invocations into a fires-vs-extracted yield per hook — the
 * instrument behind EDITH's "pre-compact fired once vs 270 stop-fires" finding.
 * Once the recall hook records an invocation (memories_extracted = injected
 * count), the `prompt-recall` row becomes the cumulative "is the store actually
 * being read into prompts?" signal. Pure read; tolerates a missing table.
 *
 * @param sinceIso Optional ISO-8601 lower bound on `invoked_at` (lexicographic,
 *   safe because telemetry writes ISO-8601 UTC). Omit for all-time.
 */
export function getHookYield(db: DB = getDatabase(), sinceIso?: string): HookYield {
  let rows: { hook_name: string; fires: number; extracted: number }[];
  try {
    const where = sinceIso ? 'WHERE invoked_at >= ?' : '';
    const args = sinceIso ? [sinceIso] : [];
    rows = db
      .prepare(
        `SELECT hook_name, COUNT(*) AS fires, COALESCE(SUM(memories_extracted), 0) AS extracted
         FROM hook_invocations ${where} GROUP BY hook_name`,
      )
      .all(...args) as { hook_name: string; fires: number; extracted: number }[];
  } catch {
    // hook_invocations may not exist on a brand-new store.
    return { hooks: [], totalFires: 0, totalExtracted: 0 };
  }

  const hooks = rows
    .map((r) => ({
      hook: r.hook_name,
      fires: r.fires,
      extracted: r.extracted,
      avgPerFire: r.fires > 0 ? Math.round((r.extracted / r.fires) * 100) / 100 : 0,
    }))
    .sort((a, b) => b.fires - a.fires);

  return {
    hooks,
    totalFires: hooks.reduce((n, h) => n + h.fires, 0),
    totalExtracted: hooks.reduce((n, h) => n + h.extracted, 0),
  };
}
