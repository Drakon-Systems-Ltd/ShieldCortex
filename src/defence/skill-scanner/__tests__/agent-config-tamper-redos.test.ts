/**
 * ReDoS gate for the agent_config_tamper rows (PR #949 review, blocker 1).
 *
 * Two shapes were measured by the reviewer on the first revision:
 *   ">".repeat(100000)            : >20 s (main: 0.16 s)  - redirect row
 *   "Edit:\n" + " ".repeat(100000): 45 s   (main: 0.20 s) - Markdown verb-colon row
 * Each input is checked per regex and through the full scan. The budgets are
 * wall-clock; a fixed regex finishes in milliseconds, a polynomial one never
 * finishes, so the margin is wide on purpose.
 */

import { describe, it, expect } from '@jest/globals';
import { scanSkillContent } from '../scan-skill.js';
import { detectSkillThreats, skillPatternGroupRows } from '../patterns.js';

const N = 100_000;
const BUDGET_MS = 500;

const ADVERSARIAL: Array<[string, string]> = [
  ['100k ">"', '>'.repeat(N)],
  ['Edit:\\n + 100k spaces', 'Edit:\n' + ' '.repeat(N)],
  ['Edit:\\n + 100k tabs', 'Edit:\n' + '\t'.repeat(N)],
  ['repeated "Edit:\\n  " blocks', 'Edit:\n  '.repeat(N / 16)],
  ['"Edit:\\n" + blank lines', 'Edit:\n' + '\n'.repeat(N)],
  ['Edit: + spaced blank lines', 'Edit:\n' + ' \n'.repeat(N / 2)],
  ['list markers', 'Add:\n' + '- '.repeat(N / 2)],
  ['"> " repeated', '> '.repeat(N / 2)],
  ['">x" repeated', '>x'.repeat(N / 2)],
  ['">" + long path run', '>' + 'a'.repeat(N)],
  ['">" + dotted path run', '>' + '.claude/'.repeat(N / 8)],
  ['tee -a run', 'tee -a '.repeat(N / 7)],
  ['tee + non-space run', 'tee ' + 'x'.repeat(N)],
  ['Add word runs', 'Add '.repeat(N / 8)],
  ['Add + long line', 'Add ' + 'x '.repeat(N / 2)],
  ['install + mcp words', 'install '.repeat(N / 8) + 'mcp server'],
  ['config-file mentions', 'Edit .claude/settings.json '.repeat(N / 26)],
  ['negation runs', "not never n't ".repeat(N / 14)],
  ['underscore var name', 'A_'.repeat(N / 2) + 'BASE_URL'],
  ['long A run', 'A'.repeat(N)],
  ['quote and ws run', 'sandbox' + ' '.repeat(N) + ':'],
  ['CR runs', 'Edit:\r\n'.repeat(N / 7)],
];

// A 100 KB run of one non-space word takes ~18 s through scanSkillContent on
// main as well (a pre-existing stage outside agent_config_tamper; detectSkillThreats
// and every agent_config_tamper row are fast on it). These inputs stay in the
// per-row and detectSkillThreats gates but are excluded from the full-scan gate
// so this suite measures only what PR #949 changed.
const FULL_SCAN_SLOW_ON_MAIN = new Set(['">" + long path run', 'tee + non-space run', 'underscore var name', 'long A run']);

function ms(fn: () => void): number {
  const t = process.hrtime.bigint();
  fn();
  return Number(process.hrtime.bigint() - t) / 1e6;
}

describe('agent_config_tamper ReDoS gate', () => {
  const rows = skillPatternGroupRows('agent_config_tamper');

  it('has rows to test', () => {
    expect(rows.length).toBeGreaterThan(10);
  });

  for (const [label, text] of ADVERSARIAL) {
    it(`every row finishes under ${BUDGET_MS} ms: ${label}`, () => {
      for (const re of rows) {
        const elapsed = ms(() => { re.test(text); });
        expect({ re: re.source.slice(0, 60), ok: elapsed < BUDGET_MS }).toEqual({ re: re.source.slice(0, 60), ok: true });
      }
    });

    it(`detectSkillThreats finishes under ${BUDGET_MS} ms: ${label}`, () => {
      expect(ms(() => { detectSkillThreats(text); })).toBeLessThan(BUDGET_MS);
    });

    const fullScanIt = FULL_SCAN_SLOW_ON_MAIN.has(label) ? it.skip : it;
    fullScanIt(`full scan finishes under ${BUDGET_MS} ms: ${label}`, () => {
      expect(ms(() => { scanSkillContent(text, undefined, 'claude-md', 'CLAUDE.md'); })).toBeLessThan(BUDGET_MS);
    });
  }
});
