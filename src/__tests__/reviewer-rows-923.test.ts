/**
 * #923 r12 — every concrete row a reviewer raised against the Claude
 * transcript floor in r1..r11 (both lanes), judged by the live classifier
 * with enforce on and off. Rows come from support/reviewer-rows-923.ts.
 *   floor    → touch-claude-transcript is present and the call is not allowed
 *   overhold → documented false floor: still floored (pinned so it is visible)
 *   clear    → no touch-claude-transcript
 *   residual → documented residual; only evaluated (must not throw)
 * The effect-backed subset (rows carrying `effect`) runs in
 * claude-transcript-floor-923 via support/transcript-joins-923.ts.
 */
import { describe, expect, it } from '@jest/globals';
import { evaluateToolCall } from '../defence/iron-dome/tool-action-guard.js';
import { reviewerRows } from './support/reviewer-rows-923.js';

const ROWS = reviewerRows('/home/owner', '/tmp/forged/src.jsonl', 's.jsonl');

describe('#923 r12 — reviewer rows r1..r11 are pinned', () => {
  it('covers both lanes and every round with a review file', () => {
    const seen = new Set(ROWS.map(r => `${r.round}-${r.lane}`));
    for (const k of ['4-astra', '4-grok', '5-astra', '6-astra', '9-astra', '9-grok', '10-astra', '10-grok', '11-astra', '11-grok']) {
      expect({ k, seen: seen.has(k) }).toEqual({ k, seen: true });
    }
    expect(new Set(ROWS.map(r => r.id)).size).toBe(ROWS.length);
  });
  for (const enforce of [true, false]) {
    const c = { enabled: true, enforce } as any;
    it.each(ROWS.map(r => [r.id, r] as const))(`%s (enforce=${enforce})`, (_id, row) => {
      const v = evaluateToolCall(row.tool, row.input, c);
      const floored = (v.signals ?? []).includes('touch-claude-transcript');
      if (row.expect === 'floor' || row.expect === 'overhold') {
        expect({ id: row.id, floored, decision: v.decision === 'allow' ? 'allow' : 'held' }).toEqual({ id: row.id, floored: true, decision: 'held' });
      } else if (row.expect === 'clear') {
        expect({ id: row.id, floored }).toEqual({ id: row.id, floored: false });
      }
    });
  }
});
