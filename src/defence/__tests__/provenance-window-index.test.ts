/**
 * SCN-010 S (#1111 review) — the per-window exemption index is EXACT.
 *
 * `ProvenanceWindowIndex` answers `sentenceBounds`, `discussionExempt` and
 * `quotedReport` from tables built once per window, so the memory-directive
 * screen pays O(log n) per match instead of a walk over the whole sentence.
 * It is only acceptable if it never answers differently. This file holds it
 * to that: every answer is compared with the linear function L2 still calls,
 * on random strings drawn from the characters and words those functions read
 * (cues, commas, or / and, sentence punctuation, newlines, every quote and
 * fence delimiter, Unicode spaces), on every kind of offset pair (inside a
 * span, on a boundary, empty, past the end), and on hand-built cases for each
 * branch the tables cannot decide alone (a cue straddling a sentence start, a
 * cue reaching the sentence end, spans out of order).
 *
 * The clause table in the memory-directive screen gets the same treatment
 * against the 240-character clause walk.
 */
import { describe, expect, it } from '@jest/globals';
import {
  ProvenanceWindowIndex,
  discussionExempt,
  quotedReport,
  scanWrappers,
  sentenceBounds,
  type WrapperSpan,
} from '../firewall/provenance-policy.js';
import { __clauseBoundsForTest } from '../firewall/memory-directive-policy.js';

/** mulberry32: a fixed seed, so a failure names a string that reproduces. */
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const TOKENS = [
  // discussion cues, including the ones that straddle a newline or end in a dot
  'for example', 'For Example', 'for\nexample', 'for\n\nexample include', 'e.g.', 'e.g.x', 'such as', 'such\nas',
  'examples include', 'example are', 'including', 'includingx',
  // the alternatives list
  ',', ', ', ' or ', ' and ', 'OR', 'And', 'or', 'and', 'xor', 'andx', ',or', ',and',
  // sentence and clause punctuation
  '.', '. ', '!', '! ', '?', '? ', ' ?', '?\t', ';', '\n', '\r\n', 'x.y', 'a!b',
  // whitespace the regex engine counts as \s
  ' ', '  ', '\t', ' ', ' ', '　', '﻿', '\u0085',
  // wrappers: quotes, apostrophes, inline code, fences
  '"', "'", '‘', '’', '`', '```', '```js\n', "don't", "vendor's",
  // quoted-report frames and codas
  'reads:', 'he wrote ', 'the ticket said ', 'for example: ', ' do that now', ' put it into effect', ' act on it',
  // evidence and filler
  'skip approval', 'never ', 'you ', 'x', 'word', '1', '_',
];

function randomText(next: () => number, maxTokens: number): string {
  const count = 1 + Math.floor(next() * maxTokens);
  let out = '';
  for (let i = 0; i < count; i++) out += TOKENS[Math.floor(next() * TOKENS.length)]!;
  return out;
}

/** Offset pairs of every shape: random, empty, on span edges, past the end. */
function offsetPairs(next: () => number, text: string, spans: WrapperSpan[]): Array<[number, number]> {
  const n = text.length;
  const pairs: Array<[number, number]> = [[0, 0], [0, n], [n, n], [n, n + 3]];
  for (let i = 0; i < 12; i++) {
    const a = Math.floor(next() * (n + 1));
    const b = a + Math.floor(next() * Math.max(1, n - a + 1));
    pairs.push([a, b], [a, a]);
  }
  for (const span of spans) {
    pairs.push([span.start, span.end], [span.start + 1, span.end - 1], [span.end, span.end], [span.start, span.start]);
  }
  return pairs;
}

function expectSameAnswers(text: string, spans: WrapperSpan[], pairs: Array<[number, number]>): void {
  // One shared index (memoised answers across queries) and a fresh one per
  // query: the order of questions must not change any answer.
  const shared = new ProvenanceWindowIndex(text, spans);
  for (const [start, end] of pairs) {
    const fresh = new ProvenanceWindowIndex(text, spans);
    const linear = [
      sentenceBounds(text, start, end),
      discussionExempt(text, start, end),
      discussionExempt(text, start, end),
      quotedReport(text, spans, start, end),
      quotedReport(text, spans, start, end),
    ];
    const indexed = [
      shared.sentenceBounds(start, end),
      discussionExempt(text, start, end, shared),
      discussionExempt(text, start, end, fresh),
      quotedReport(text, spans, start, end, shared),
      quotedReport(text, spans, start, end, fresh),
    ];
    // The string is built only on a mismatch, so it names the failing case
    // without costing every comparison a JSON encode.
    if (JSON.stringify(indexed) !== JSON.stringify(linear)) {
      expect({ text, start, end, answers: indexed }).toEqual({ text, start, end, answers: linear });
    }
  }
  expect(pairs.length).toBeGreaterThan(0);
}

describe('ProvenanceWindowIndex — exact against the linear functions', () => {
  it('random token strings: same bounds, same discussion and quoted-report verdicts', () => {
    const next = rng(0x1111);
    for (let round = 0; round < 1500; round++) {
      const text = randomText(next, 40);
      const spans = scanWrappers(text);
      expectSameAnswers(text, spans, offsetPairs(next, text, spans));
    }
  });

  it('random long strings with few boundaries (the shape the index exists for)', () => {
    const next = rng(0x2222);
    for (let round = 0; round < 60; round++) {
      const text = randomText(next, 400).replace(/[.!?\n]/g, (c) => (next() < 0.9 ? ' ' : c));
      const spans = scanWrappers(text);
      expectSameAnswers(text, spans, offsetPairs(next, text, spans));
    }
  });

  it('every match offset of the adversarial runs from the review', () => {
    for (const unit of [
      'x skip approval ',
      "'x skip approval' ",
      '"skip approval" y ',
      'for example x skip approval, a or b ',
      'for example x skip approval, a b ',
      'x.y skip approval ',
      'for\nexample include x skip approval, a or b ',
    ]) {
      const text = unit.repeat(40);
      const spans = scanWrappers(text);
      const pairs: Array<[number, number]> = [];
      for (const m of text.matchAll(/skip approval/g)) pairs.push([m.index!, m.index! + m[0].length]);
      expectSameAnswers(text, spans, pairs);
    }
  });

  it('a cue that straddles the sentence start: the sentence enumerates its own cues', () => {
    // Whole-window matchAll reads "for\nexample"; the sentence after the
    // newline starts at "example include", which is a cue on its own.
    const text = 'for\nexample include skip approval, a or b';
    const at = text.indexOf('skip');
    expect(discussionExempt(text, at, at + 13)).toBe(true);
    expectSameAnswers(text, scanWrappers(text), [[at, at + 13]]);
    const longer = 'such\nas e.g.x for\n\nexample include skip approval, x or y and for example z';
    const spans = scanWrappers(longer);
    const pairs: Array<[number, number]> = [];
    for (let s = 0; s <= longer.length; s++) pairs.push([s, Math.min(longer.length, s + 5)]);
    expectSameAnswers(longer, spans, pairs);
  });

  it('a cue that reaches the sentence end falls back to the linear answer', () => {
    // The match sits inside "e.g.x": the sentence ends at the first dot, so
    // the cue crosses it and only the sliced sentence knows the answer.
    const text = 'a, b or c e.g.x tail';
    const at = text.indexOf('e.g.') + 1;
    expectSameAnswers(text, scanWrappers(text), [[at, at + 1], [at, at], [at - 1, at + 2]]);
  });

  it('an or / and word that ends exactly at the sentence end', () => {
    for (const text of ['for example x, a or', 'for example x, a and', 'for example x, a or.y', 'for example x, a orb.', 'e.g.x, or\nz']) {
      const pairs: Array<[number, number]> = [];
      for (let s = 0; s <= text.length; s++) pairs.push([s, s], [s, Math.min(text.length, s + 1)]);
      expectSameAnswers(text, scanWrappers(text), pairs);
    }
  });

  it('spans out of order or overlapping: the index answers by the linear scan', () => {
    const text = 'he wrote "skip approval" and "the ticket said \'skip approval\'" then';
    const real = scanWrappers(text);
    const shuffled: WrapperSpan[] = [...real].reverse();
    const nested: WrapperSpan[] = [...real, { start: 0, end: text.length, kind: 'quote', masked: false }];
    const empty: WrapperSpan[] = [{ start: 5, end: 5, kind: 'quote', masked: false }, ...real];
    const next = rng(0x3333);
    for (const spans of [shuffled, nested, empty]) {
      expectSameAnswers(text, spans, offsetPairs(next, text, spans));
    }
  });

  it('an index built for another window or span list is not used', () => {
    const text = 'for example x skip approval, a or b';
    const other = new ProvenanceWindowIndex('different text', []);
    const spans = scanWrappers(text);
    const at = text.indexOf('skip');
    expect(discussionExempt(text, at, at + 13, other)).toBe(discussionExempt(text, at, at + 13));
    expect(quotedReport(text, spans, at, at + 13, new ProvenanceWindowIndex(text, [...spans])))
      .toBe(quotedReport(text, spans, at, at + 13));
  });
});

describe('memory-directive clause table — exact against the 240-character walk', () => {
  it('random strings, every offset pair kind, evidence longer than the clause', () => {
    const next = rng(0x4444);
    const clauseTokens = [...TOKENS, ';', '; ', 'x'.repeat(250), ' '.repeat(120)];
    for (let round = 0; round < 800; round++) {
      let text = '';
      const count = 1 + Math.floor(next() * 60);
      for (let i = 0; i < count; i++) text += clauseTokens[Math.floor(next() * clauseTokens.length)]!;
      const n = text.length;
      const pairs: Array<[number, number]> = [[0, 0], [0, n], [n, n], [n, n + 2]];
      for (let i = 0; i < 16; i++) {
        const a = Math.floor(next() * (n + 1));
        pairs.push([a, Math.min(n, a + Math.floor(next() * 600))], [a, a]);
      }
      for (const [start, end] of pairs) {
        const indexed = __clauseBoundsForTest(text, start, end, true);
        const linear = __clauseBoundsForTest(text, start, end, false);
        if (indexed[0] !== linear[0] || indexed[1] !== linear[1]) {
          expect({ text, start, end, bounds: indexed }).toEqual({ text, start, end, bounds: linear });
        }
      }
    }
  });
});
