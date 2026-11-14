/**
 * Phase 1 — command model (shadow mode). Epic line: #519.
 */
import type { FrozenFixture } from './types.js';

export const PHASE1_FIXTURES: FrozenFixture[] = [
  {
    id: '519/tokeniser-growth-repeated-word',
    issue: 519,
    phase: 1,
    class: 'cost',
    status: 'known-gap',
    what: 'one long statement of a repeated package-manager word: scan time must grow linearly with token count',
    // The #519 repro: no guard-package token, no dangerous match; the cost is
    // the tokeniser alone.
    build: (n) => ({ tool: 'Bash', args: { command: 'npm ls ' + 'npm '.repeat(n) + 'other-helper' } }),
    // Stops at 8000: a 16000-token statement is over the command size cap and
    // returns in about 6 ms without reaching the tokeniser.
    sizes: [2000, 4000, 8000],
    effects: ['read'],
    targets: ['cwd'],
    adr: 'LOG',
    expect: { verdict: 'any', maxGrowthPerDoubling: 3 },
    why: '#519 measured 81 / 285 / 1080 ms at 2000 / 4000 / 8000 tokens on d8625b86 (about x4 per doubling). '
      + 'Still quadratic on main 7da096fb: 17 / 59 / 229 ms on the fleet test runner, ratios 3.49 and 3.91; 3.89 to 3.94 for 4000 to 8000 over three more runs (12 Nov 2026). '
      + 'The Phase 1 lexer is single-pass; its acceptance is this growth ratio, not a wall-clock budget.',
  },
];
