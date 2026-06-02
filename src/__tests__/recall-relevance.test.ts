import { describe, expect, it } from '@jest/globals';
// @ts-expect-error -- importing a .mjs hook utility
import { filterByRelevance } from '../../scripts/lib/recall-relevance.mjs';

/**
 * Unit tests for the P4 recall relevance gate (B9 design).
 *
 * The per-turn UserPromptSubmit recall hook ran an FTS5 OR-of-terms query and
 * injected up to MAX_RESULTS rows, with the only floor being salience ≥ 0.2.
 * No relevance threshold meant off-topic rows that weakly matched ONE common
 * term got injected ("same 5 every turn, none relevant" — EDITH).
 *
 * The load-bearing discriminator is TERM-COVERAGE: how many distinct query
 * terms a row actually matches. A 1-of-6-terms OR-match is noise; a real match
 * covers multiple terms. A relative BM25 floor is secondary.
 *
 * `filterByRelevance(rows, { queryTerms, relFactor, minTermMatches, maxBm25 })`
 * is PURE — no DB, no env reads. These tests pin its behaviour.
 */
describe('filterByRelevance — term-coverage primary gate', () => {
  const DEFAULT = { relFactor: 0.35, minTermMatches: 2, maxBm25: -0.5 };

  it('drops a high-salience row matching 1 of 6 terms, keeps a row matching 4 of 6', () => {
    const queryTerms = ['migration', 'drizzle', 'schema', 'postgres', 'rollback', 'journal'];
    const rows = [
      {
        id: 'noise',
        title: 'Weekly standup notes',
        content: 'We discussed the migration window briefly and moved on to lunch.',
        salience: 0.95, // high salience must NOT save it
        rank: -3.0,
      },
      {
        id: 'real',
        title: 'Drizzle migration is hand-written',
        content: 'drizzle-kit generate is broken; hand-write the schema SQL plus a journal rollback entry.',
        salience: 0.4,
        rank: -2.5,
      },
    ];

    const { kept, dropped } = filterByRelevance(rows, { ...DEFAULT, queryTerms });

    expect(kept.map((r: any) => r.id)).toContain('real');
    expect(kept.map((r: any) => r.id)).not.toContain('noise');
    const noiseDrop = dropped.find((d: any) => d.row.id === 'noise');
    expect(noiseDrop).toBeDefined();
    expect(noiseDrop.reason).toBe('below_term_coverage');
  });

  it('terse 2-term query: keeps a row matching both, drops a row matching one', () => {
    const queryTerms = ['bcrypt', 'bug'];
    const rows = [
      {
        id: 'both',
        title: 'bcrypt key bug fixed',
        content: 'The dashboard API key bcrypt verification bug was fixed with a self-verify safeguard.',
        salience: 0.5,
        rank: -2.0,
      },
      {
        id: 'one',
        title: 'General bug triage',
        content: 'Triaged a rendering bug in the timeline; unrelated to auth.',
        salience: 0.8,
        rank: -2.1,
      },
    ];

    const { kept, dropped } = filterByRelevance(rows, { ...DEFAULT, queryTerms });

    expect(kept.map((r: any) => r.id)).toEqual(['both']);
    expect(dropped.find((d: any) => d.row.id === 'one')?.reason).toBe('below_term_coverage');
  });

  it('off-topic query: all rows match ≤1 term → kept is empty (weather-query case)', () => {
    const queryTerms = ['what', 'weather', 'today'];
    const rows = [
      {
        id: 'a',
        title: 'Release checklist',
        content: 'Bump version, update CHANGELOG, tag and push so CI publishes to npm today.',
        salience: 0.9,
        rank: -1.0,
      },
      {
        id: 'b',
        title: 'Fly deploy notes',
        content: 'fly deploy ships the Hono API to api.shieldcortex.ai in the lhr region.',
        salience: 0.85,
        rank: -1.1,
      },
    ];

    const { kept, dropped } = filterByRelevance(rows, { ...DEFAULT, queryTerms });

    expect(kept).toHaveLength(0);
    expect(dropped).toHaveLength(2);
    expect(dropped.every((d: any) => d.reason === 'below_term_coverage')).toBe(true);
  });

  it('relative BM25 floor: among term-coverage survivors, a weakly-ranked row is dropped', () => {
    const queryTerms = ['recall', 'relevance', 'gate', 'coverage'];
    // best rank = -10. relFactor 0.35 → floor at -3.5. Anything > -3.5 drops.
    const rows = [
      {
        id: 'strong',
        title: 'Recall relevance gate',
        content: 'The recall gate uses term coverage as the primary relevance discriminator.',
        salience: 0.5,
        rank: -10.0,
      },
      {
        id: 'weak',
        title: 'Coverage and relevance notes',
        content: 'Notes on recall coverage and the relevance gate threshold tuning.',
        salience: 0.5,
        rank: -2.0, // -2.0 > -3.5 → below the relative floor
      },
    ];

    const { kept, dropped } = filterByRelevance(rows, { ...DEFAULT, queryTerms });

    expect(kept.map((r: any) => r.id)).toEqual(['strong']);
    expect(dropped.find((d: any) => d.row.id === 'weak')?.reason).toBe('below_relevance_floor');
  });

  it('rows without a rank (category-boost) are exempt from BM25 floor but still gated on term coverage', () => {
    const queryTerms = ['deploy', 'release', 'publish', 'ship'];
    const rows = [
      {
        id: 'fts-strong',
        title: 'Release process',
        content: 'Bump version, then deploy: publish to npm and ship the tag.',
        salience: 0.5,
        rank: -10.0,
        _source: 'fts',
      },
      {
        id: 'cat-covered',
        title: 'Deploy and release runbook',
        content: 'How to deploy, release, and publish the package and ship to Fly.',
        salience: 0.6,
        _source: 'category-boost', // NO rank field
      },
      {
        id: 'cat-noise',
        title: 'Lunch plans',
        content: 'We will ship out for lunch around noon.',
        salience: 0.99,
        _source: 'category-boost', // NO rank, matches only "ship"
      },
    ];

    const { kept, dropped } = filterByRelevance(rows, { ...DEFAULT, queryTerms });

    // cat-covered matches ≥2 terms and has no rank → survives the BM25 floor.
    expect(kept.map((r: any) => r.id)).toContain('cat-covered');
    expect(kept.map((r: any) => r.id)).toContain('fts-strong');
    // cat-noise matches only "ship" → term-coverage drop.
    expect(kept.map((r: any) => r.id)).not.toContain('cat-noise');
    expect(dropped.find((d: any) => d.row.id === 'cat-noise')?.reason).toBe('below_term_coverage');
  });

  it('matched term detection is case-insensitive and word-ish (not substring)', () => {
    const queryTerms = ['Schema', 'migration'];
    const rows = [
      {
        id: 'real',
        title: 'SCHEMA migration',
        content: 'Hand-written schema MIGRATION journal entry.',
        salience: 0.5,
        rank: -2.0,
      },
      {
        id: 'substring-trap',
        title: 'Schematics overview',
        // "schematics" contains "schema" as a substring but is a different word.
        // "emigration" contains "migration" as a substring. Neither should count.
        content: 'Schematics and emigration are unrelated topics.',
        salience: 0.5,
        rank: -2.1,
      },
    ];

    const { kept } = filterByRelevance(rows, { ...DEFAULT, queryTerms });

    expect(kept.map((r: any) => r.id)).toEqual(['real']);
  });

  it('is pure: does not mutate the input rows array or its elements', () => {
    const queryTerms = ['alpha', 'beta'];
    const rows = [{ id: 'x', title: 'alpha beta', content: 'alpha beta gamma', salience: 0.5, rank: -2.0 }];
    const snapshot = JSON.parse(JSON.stringify(rows));
    filterByRelevance(rows, { ...DEFAULT, queryTerms });
    expect(rows).toEqual(snapshot);
  });
});

describe('shadow-vs-enforce injection contract (B9 item 3)', () => {
  // The pure gate returns { kept, dropped }. The hook chooses what to INJECT
  // based on SHIELDCORTEX_RECALL_ENFORCE:
  //   SHADOW (default / unset): inject the ORIGINAL top-N unchanged.
  //   ENFORCE: inject only `kept`.
  // Either way, `dropped` is recorded in the recall log. These tests pin that
  // selection rule without spawning the hook (which reads the DB + env at
  // module-load). They mirror the exact branch in prompt-recall-hook.mjs.
  const queryTerms = ['drizzle', 'migration', 'rollback'];
  const topN = [
    { id: 'real', title: 'Drizzle migration', content: 'Hand-write the migration rollback journal.', rank: -5.0 },
    { id: 'noise', title: 'Lunch', content: 'We discussed drizzle on the cake at lunch.', rank: -1.0 },
  ];

  function selectInjected(enforce: boolean) {
    const { kept } = filterByRelevance(topN, {
      queryTerms,
      minTermMatches: 2,
      relFactor: 0.35,
      maxBm25: -0.5,
    });
    // This is the exact rule in the hook: `RECALL_ENFORCE ? kept : topN`.
    return enforce ? kept : topN;
  }

  it('SHADOW mode injects the UNCHANGED top-N even though the gate would drop a row', () => {
    const injected = selectInjected(false);
    expect(injected).toBe(topN); // identity — original set, untouched
    expect(injected.map((r) => r.id)).toEqual(['real', 'noise']);
  });

  it('ENFORCE mode injects only the gate survivors', () => {
    const injected = selectInjected(true);
    expect(injected.map((r) => r.id)).toEqual(['real']);
    expect(injected.map((r) => r.id)).not.toContain('noise');
  });

  it('default (env unset) resolves to shadow — enforce flag must be opt-in', () => {
    // The hook reads SHIELDCORTEX_RECALL_ENFORCE via pickBool: unset → false.
    // Asserting the documented default here guards against a future flip that
    // would silently trade recall noise for amnesia before threshold tuning.
    const raw = process.env.SHIELDCORTEX_RECALL_ENFORCE;
    const enforce = raw === '1' || raw === 'true' || raw === 'yes' || raw === 'on';
    expect(enforce).toBe(false);
  });
});
