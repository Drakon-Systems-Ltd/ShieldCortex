/**
 * #648 round 3 (R4) — invisible and look-alike characters never reach a card,
 * and the card module and the OpenClaw plugin use ONE character list.
 *
 * The plugin is compiled with `rootDir: plugins/openclaw` and cannot import
 * from `src/` (TS6059), so "one constant" is enforced the way this repo pins
 * every cross-build constant (conversation-gate-floor-parity-226): both copies
 * are imported here and must be identical, character for character.
 */
import { describe, it, expect } from '@jest/globals';
import {
  CARD_HIDDEN_CHAR_CLASS,
  CARD_LINE_BREAK_CLASS,
  CARD_TAIL_MARKERS,
  WITHHELD_UNUSUAL,
  clipCardLine,
  describeAction,
  formatApprovalCardLines,
  safeTarget,
} from '../approval-card.js';
import * as plugin from '../../../../plugins/openclaw/interceptor.js';

const range = (from: number, to: number) => Array.from({ length: to - from + 1 }, (_v, i) => from + i);
/** Every code point round 3 names (R4), in full. */
const R3_CODE_POINTS = [
  ...range(0x2060, 0x206f),
  0x061c, 0x00ad, 0x180e, 0x3164,
  ...range(0xe0000, 0xe007f),
  ...range(0xfe00, 0xfe0f),
  ...range(0xe0100, 0xe01ef),
  0x201c, 0x201d, 0xff02,
];
const label = (cp: number) => `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`;

describe('#648 r3 R4 — invisible and look-alike characters are withheld or escaped', () => {
  it(`a target carrying any of the ${R3_CODE_POINTS.length} round-3 characters is withheld`, () => {
    const leaked = R3_CODE_POINTS.filter((cp) => safeTarget(`/home/u/notes${String.fromCodePoint(cp)}txt`) !== WITHHELD_UNUSUAL);
    expect(leaked.map(label)).toEqual([]);
  });

  it('the shell WHAT never carries one: the target is withheld instead', () => {
    for (const cp of R3_CODE_POINTS) {
      const c = String.fromCodePoint(cp);
      const line = describeAction({ tool: 'Bash', input: { command: `cat '/home/u/notes${c}txt'` }, signals: [] }).text;
      expect(line.includes(c) ? label(cp) : null).toBeNull();
      expect(line).toContain(WITHHELD_UNUSUAL);
    }
  });

  it('every card line shows them as <U+XXXX>, in the card module and in the plugin', () => {
    for (const cp of R3_CODE_POINTS) {
      const c = String.fromCodePoint(cp);
      const card = { action: `Read a file${c}x`, reason: `r${c}x`, who: `w${c}x` };
      for (const line of formatApprovalCardLines(card, { expiresInMs: 600_000 }).slice(0, 3)) {
        expect(line.includes(c) ? label(cp) : null).toBeNull();
        expect(line).toContain(`<${label(cp)}>`);
      }
      const flat = plugin.flattenPromptField(`a${c}b`);
      expect(flat.includes(c) ? label(cp) : null).toBeNull();
      expect(flat).toBe(`a<${label(cp)}>b`);
    }
  });
});

describe('#648 r3 R4 — one character list and one marker list for both card planes', () => {
  it('the plugin carries the card module\'s character classes exactly', () => {
    expect(plugin.CARD_HIDDEN_CHAR_CLASS).toBe(CARD_HIDDEN_CHAR_CLASS);
    expect(plugin.CARD_LINE_BREAK_CLASS).toBe(CARD_LINE_BREAK_CLASS);
  });

  it('the plugin keeps the same trailing markers when it clips a line', () => {
    expect(plugin.CARD_TAIL_MARKERS.source).toBe(CARD_TAIL_MARKERS.source);
    expect(plugin.CARD_TAIL_MARKERS.flags).toBe(CARD_TAIL_MARKERS.flags);
    const long = `Delete a folder and everything in it: "${'/srv/data/'.repeat(20)}x", as administrator (sudo) (+2 more steps)`;
    expect(plugin.clipCardLine(long, 80)).toBe(clipCardLine(long, 80));
    expect(plugin.clipCardLine(long, 80).endsWith(', as administrator (sudo) (+2 more steps)')).toBe(true);
  });
});
