import { describe, expect, it } from '@jest/globals';
import { detectEncoding } from '../defence/firewall/encoding-detector.js';
import { runDefencePipeline } from '../defence/pipeline.js';
import { DEFAULT_DEFENCE_CONFIG } from '../defence/types.js';

/**
 * Phase 3a hardening — two Unicode-encoding detection bypasses.
 *
 * Bug A: ZERO_WIDTH_PATTERN / RTL_OVERRIDE_PATTERN were module-level `/g`
 *        regexes used only with `.test()`. `.test()` on a `/g` regex advances
 *        `lastIndex`, so the SAME object returns true then false on alternate
 *        calls for identical content — zero-width/RTL smuggling missed on
 *        ~every other scan.
 *
 * Bug B: the sanitiser strips zero-width/bidi BEFORE the firewall runs, so the
 *        encoding detector never sees those bytes and the "zero-width/RTL →
 *        always quarantine" rule never fires — a zero-width-only payload
 *        returned ALLOW end-to-end.
 */

const ZERO_WIDTH = '​'; // zero-width space
const RTL_OVERRIDE = '‮'; // right-to-left override

describe('Bug A: stateful /g regex must not flip-flop across calls', () => {
  it('reports zero_width_chars on repeated calls for identical content', () => {
    // The spec payload carries TWO zero-width chars. With a stale `/g` regex,
    // `.test()` returns true, true, false on calls 1/2/3 (lastIndex walks the
    // two matches then resets) — so the THIRD call is where the bug surfaces.
    const payload = `note${ZERO_WIDTH}${ZERO_WIDTH} end`;

    const first = detectEncoding(payload);
    const second = detectEncoding(payload);
    const third = detectEncoding(payload);

    expect(first.encodingTypes).toContain('zero_width_chars');
    expect(second.encodingTypes).toContain('zero_width_chars');
    expect(third.encodingTypes).toContain('zero_width_chars');
  });

  it('reports rtl_override on BOTH consecutive calls for identical content', () => {
    const payload = `safe${RTL_OVERRIDE}text`;

    const first = detectEncoding(payload);
    const second = detectEncoding(payload);

    expect(first.encodingTypes).toContain('rtl_override');
    expect(second.encodingTypes).toContain('rtl_override');
  });
});

describe('Bug B: sanitiser strips zero-width before firewall — must still block', () => {
  it('quarantines a zero-width-only payload end-to-end (balanced mode)', () => {
    const content = `Meeting notes: roadmap${ZERO_WIDTH}${ZERO_WIDTH} and budget.`;
    const result = runDefencePipeline(content, 'notes', { type: 'user', identifier: 't' });

    expect(result.allowed).toBe(false);
    expect(result.firewall.result).toBe('QUARANTINE');
  });

  it('blocks a zero-width-only payload in strict mode', () => {
    const content = `Meeting notes: roadmap${ZERO_WIDTH}${ZERO_WIDTH} and budget.`;
    const result = runDefencePipeline(content, 'notes', { type: 'user', identifier: 't' }, {
      ...DEFAULT_DEFENCE_CONFIG,
      mode: 'strict',
    });

    expect(result.allowed).toBe(false);
    expect(result.firewall.result).toBe('BLOCK');
  });

  it('does NOT over-trigger on benign content with no encoding tricks', () => {
    const content = 'Meeting notes: roadmap and budget for Q3 planning session.';
    const result = runDefencePipeline(content, 'notes', { type: 'user', identifier: 't' });

    expect(result.allowed).toBe(true);
    expect(result.firewall.result).toBe('ALLOW');
  });
});
