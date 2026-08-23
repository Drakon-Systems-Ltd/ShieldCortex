/**
 * Work-lane hint UX for DNP digests / agent deny text.
 */
import { describe, expect, it } from '@jest/globals';
import { formatWorkLaneHintLines, suggestWorkLane } from '../work-lane-hints.js';

describe('suggestWorkLane', () => {
  it('suggests vita gh-ci for egress in vita cwd', () => {
    const h = suggestWorkLane({
      signals: ['external-egress'],
      cwd: '/home/edith/.openclaw/workspace/tmp/vita-mobile-hero',
      reviewedScriptPaths: ['/home/edith/scripts/vita-site/gh-ci.sh'],
    });
    expect(h?.command).toMatch(/gh-ci\.sh status staging/);
    expect(h?.reason).toMatch(/Vita|pinned/i);
  });

  it('suggests jotform pin when relevant', () => {
    const h = suggestWorkLane({
      signals: ['external-egress'],
      cwd: '/home/edith/scripts/jotform',
      reviewedScriptPaths: ['/home/edith/skills/vep-jotform/scripts/jotform.py'],
    });
    expect(h?.command).toMatch(/jotform\.py/);
  });

  it('returns null for unknown local work', () => {
    const h = suggestWorkLane({
      signals: ['file-delete'],
      cwd: '/tmp/scratch',
    });
    expect(h).toBeNull();
  });

  it('format lines are empty without hint', () => {
    expect(formatWorkLaneHintLines(null)).toEqual([]);
  });
});
