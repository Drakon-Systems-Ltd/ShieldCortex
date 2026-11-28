/**
 * ADR-002 Phase 1, slice 1A (#1065): the inert command-model lexer.
 *
 * Two groups. "ordinary" uses a fixed neutral vocabulary (placeholder words
 * and plain file names) and one input per unresolved reason. "cost" imports
 * the existing #519 fixture unchanged and asserts the deterministic work
 * counter, never a clock. Neither group calls the live classifier.
 *
 * Not covered here, by design: word-level parity with the production
 * tokeniser (it is private), corpus-verdict parity (slice 1C), and any claim
 * that this lexer fixes #519 (the live classifier does not use it).
 */
import { describe, expect, it } from '@jest/globals';
import { PHASE1_FIXTURES } from '../../__tests__/fixtures/adr002/phase1.js';
import { MAX_SOURCE_LENGTH, lex } from '../lexer.js';
import type { LexedTokens, Token, WordToken } from '../lexer.js';

function tokensOf(source: string): LexedTokens {
  const result = lex(source);
  if (result.kind !== 'tokens') throw new Error(`unresolved (${result.reason}) for: ${source}`);
  return result;
}

const words = (source: string): WordToken[] =>
  tokensOf(source).tokens.filter((t): t is WordToken => t.kind === 'word');

/** `kind` for a blank, the operator name for an operator, `role:raw` for a word. */
const shape = (source: string): string[] =>
  tokensOf(source).tokens.map((t: Token) =>
    t.kind === 'word' ? `${t.role}:${source.slice(t.span.start, t.span.end)}` : t.kind === 'operator' ? t.operator : t.kind);

/** Tokens tile the source, and each word's segments tile the word. */
function expectLossless(source: string): void {
  const { tokens } = tokensOf(source);
  let at = 0;
  for (const t of tokens) {
    expect(t.span.start).toBe(at);
    expect(t.span.end).toBeGreaterThan(t.span.start);
    at = t.span.end;
    if (t.kind !== 'word') continue;
    let inner = t.span.start;
    for (const s of t.segments) {
      expect(s.span.start).toBe(inner);
      inner = s.span.end;
    }
    expect(inner).toBe(t.span.end);
  }
  expect(at).toBe(source.length);
  expect(tokens.map((t) => source.slice(t.span.start, t.span.end)).join('')).toBe(source);
}

const ORDINARY_INPUTS = [
  '',
  'alpha',
  'alpha beta',
  '  alpha\t beta  ',
  "alpha 'one two' beta",
  'alpha "one two" beta',
  "alpha '' \"\" beta",
  'one\\ two',
  'alpha "one \\" two"',
  "al'ph'a\"be\"ta",
  'alpha=beta gamma delta',
  'alpha ; beta && gamma || delta | one & two\nthree',
  'alpha > out.txt',
  'alpha >> out.txt',
  'alpha < in.txt',
  'alpha 2> out.txt beta',
];

describe('command-model lexer (1A) ordinary', () => {
  it.each(ORDINARY_INPUTS)('spans are lossless for %j', (source) => {
    expectLossless(source);
  });

  it('splits words on blanks and gives the first word the command role', () => {
    expect(shape('alpha beta  gamma')).toEqual(['command:alpha', 'blank', 'argument:beta', 'blank', 'argument:gamma']);
    expect(tokensOf('').tokens).toEqual([]);
  });

  it('keeps quote provenance and removes the quoting from the text', () => {
    const [, single, double] = words('alpha \'one two\' "one two"');
    expect(single!.segments).toEqual([{ kind: 'single-quoted', span: { start: 6, end: 15 }, text: 'one two' }]);
    expect(double!.segments).toEqual([{ kind: 'double-quoted', span: { start: 16, end: 25 }, text: 'one two' }]);
  });

  it('keeps empty quotes as words with an empty text', () => {
    const [, single, double] = words("alpha '' \"\"");
    expect(single!.segments).toEqual([{ kind: 'single-quoted', span: { start: 6, end: 8 }, text: '' }]);
    expect(double!.segments).toEqual([{ kind: 'double-quoted', span: { start: 9, end: 11 }, text: '' }]);
  });

  it('joins adjacent segments into one word', () => {
    const [word, ...rest] = words("al'ph'a\"be\"ta");
    expect(rest).toEqual([]);
    expect(word!.segments.map((s) => [s.kind, s.text])).toEqual([
      ['bare', 'al'], ['single-quoted', 'ph'], ['bare', 'a'], ['double-quoted', 'be'], ['bare', 'ta'],
    ]);
  });

  it('treats a backslash before an ordinary character as an escaped segment', () => {
    const [word, ...rest] = words('one\\ two');
    expect(rest).toEqual([]);
    expect(word!.segments.map((s) => [s.kind, s.text])).toEqual([['bare', 'one'], ['escaped', ' '], ['bare', 'two']]);
    expect(words('alpha "one \\" two"')[1]!.segments.map((s) => s.text)).toEqual(['one " two']);
    // Inside single quotes a backslash is an ordinary character.
    expect(words("alpha 'one\\two'")[1]!.segments.map((s) => s.text)).toEqual(['one\\two']);
  });

  it('marks name=value as an assignment only before the command word', () => {
    expect(shape('alpha=beta gamma delta=one')).toEqual([
      'assignment:alpha=beta', 'blank', 'command:gamma', 'blank', 'argument:delta=one',
    ]);
    const [assignment, command, argument] = words('alpha=beta gamma delta=one');
    expect(assignment!.assignmentName).toBe('alpha');
    expect(command!.assignmentName).toBeUndefined();
    expect(argument!.assignmentName).toBeUndefined();
    // A quoted name is not an assignment.
    expect(shape("'alpha'=beta")).toEqual(["command:'alpha'=beta"]);
  });

  it('emits sequencing and pipeline operators and restarts command position after each', () => {
    expect(shape('alpha ; beta && gamma || delta | one & two\nthree')).toEqual([
      'command:alpha', 'blank', 'sequence', 'blank',
      'command:beta', 'blank', 'and', 'blank',
      'command:gamma', 'blank', 'or', 'blank',
      'command:delta', 'blank', 'pipeline', 'blank',
      'command:one', 'blank', 'background', 'blank',
      'command:two', 'newline', 'command:three',
    ]);
    expect(shape('alpha;beta|gamma')).toEqual(['command:alpha', 'sequence', 'command:beta', 'pipeline', 'command:gamma']);
  });

  it('emits redirect operators and gives the next word the redirect-target role', () => {
    expect(shape('alpha > out.txt beta')).toEqual([
      'command:alpha', 'blank', 'redirect-out', 'blank', 'redirect-target:out.txt', 'blank', 'argument:beta',
    ]);
    expect(shape('alpha >> out.txt')).toEqual(['command:alpha', 'blank', 'redirect-append', 'blank', 'redirect-target:out.txt']);
    expect(shape('alpha < in.txt')).toEqual(['command:alpha', 'blank', 'redirect-in', 'blank', 'redirect-target:in.txt']);
    expect(shape('> out.txt alpha')).toEqual(['redirect-out', 'blank', 'redirect-target:out.txt', 'blank', 'command:alpha']);
  });

  it('reads digits written straight before a redirect as its descriptor', () => {
    const { tokens } = tokensOf('alpha 2> out.txt');
    expect(tokens[2]).toEqual({ kind: 'operator', span: { start: 6, end: 8 }, operator: 'redirect-out', fd: 2 });
    // With a blank between them the digits are an ordinary argument.
    expect(shape('alpha 2 > out.txt')).toEqual([
      'command:alpha', 'blank', 'argument:2', 'blank', 'redirect-out', 'blank', 'redirect-target:out.txt',
    ]);
  });

  // One input per unresolved reason, each built from the neutral vocabulary.
  it.each([
    ['unterminated-quote', 'alpha "beta', { start: 6, end: 11 }],
    ['substitution', 'alpha $(beta)', { start: 6, end: 7 }],
    ['heredoc', 'alpha << beta', { start: 6, end: 8 }],
    ['expansion', 'alpha $beta', { start: 6, end: 7 }],
    ['compound-grammar', '( alpha )', { start: 0, end: 1 }],
    ['size-limit', 'alpha '.repeat(Math.ceil(MAX_SOURCE_LENGTH / 6) + 1), null],
  ] as const)('returns unresolved (%s) with a span and no tokens', (reason, source, span) => {
    const result = lex(source);
    expect(result.kind).toBe('unresolved');
    expect(result).toMatchObject({ reason, span: span ?? { start: 0, end: source.length } });
    // No shortened token list is presented as complete.
    expect(Object.keys(result).sort()).toEqual(['kind', 'reason', 'span', 'work']);
  });

  it('counts work deterministically and within the stated linear bound', () => {
    // 10 code units, plus 3 tokens and 2 segments.
    expect(tokensOf('alpha beta').work).toBe(15);
    for (const source of ORDINARY_INPUTS) {
      const first = tokensOf(source).work;
      expect(tokensOf(source).work).toBe(first);
      expect(first).toBeLessThanOrEqual(3 * source.length);
      expect(first).toBeGreaterThanOrEqual(source.length);
    }
    // Doubling a small neutral input doubles the count exactly.
    expect(tokensOf('alpha '.repeat(100)).work).toBe(2 * tokensOf('alpha '.repeat(50)).work);
  });
});

describe('command-model lexer (1A) cost on the #519 fixture', () => {
  const fixture = PHASE1_FIXTURES.find((f) => f.id === '519/tokeniser-growth-repeated-word')!;
  const commandAt = (n: number): string => fixture.build!(n).args.command as string;

  it('uses the existing fixture unchanged, at its own sizes', () => {
    expect(fixture.sizes).toEqual([2000, 4000, 8000]);
    expect(fixture.status).toBe('known-gap');
    expect(fixture.expect!.maxGrowthPerDoubling).toBe(3);
  });

  it('resolves every size, losslessly, within work <= 3 * length, with the same count twice', () => {
    for (const n of fixture.sizes!) {
      const source = commandAt(n);
      const first = tokensOf(source);
      expect(first.tokens.filter((t) => t.kind === 'word')).toHaveLength(n + 3);
      expect(first.tokens.map((t) => source.slice(t.span.start, t.span.end)).join('')).toBe(source);
      expect(first.work).toBeLessThanOrEqual(3 * source.length);
      expect(tokensOf(source).work).toBe(first.work);
    }
  });

  it('grows by at most 2.2 per doubling: 2000 to 4000 and 4000 to 8000', () => {
    const [a, b, c] = fixture.sizes!.map((n) => tokensOf(commandAt(n)).work);
    // eslint-disable-next-line no-console
    console.log(`[command-model-1A] ${JSON.stringify({ sizes: fixture.sizes, work: [a, b, c], ratios: [b! / a!, c! / b!] })}`);
    expect(b! / a!).toBeLessThanOrEqual(2.2);
    expect(c! / b!).toBeLessThanOrEqual(2.2);
    expect(b! / a!).toBeGreaterThan(1);
    expect(c! / b!).toBeGreaterThan(1);
  });
});
