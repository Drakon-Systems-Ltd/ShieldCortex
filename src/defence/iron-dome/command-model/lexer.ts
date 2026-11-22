/**
 * ADR-002 Phase 1, slice 1A (#1065): one-pass lexer for a bounded
 * POSIX-shell subset.
 *
 * INERT. Nothing outside this folder imports it, it is not a package export,
 * and the live classifier does not use it. It evaluates nothing, resolves no
 * variable, and makes no decision.
 *
 * It lexes: ordinary words, blanks, newlines, single and double quotes, a
 * backslash before an ordinary character, `name=value` before the command
 * word, the operators `;` `&&` `||` `&` `|`, and the redirects `<` `>` `>>`
 * with optional descriptor digits. Everything else returns `unresolved` with
 * a reason and a span (see `UnresolvedReason` in `ast.ts`). An unresolved
 * result carries no tokens, so a shortened list is never presented as
 * complete. A token list is lexically complete; it is not a syntax check
 * (there is no parser in 1A).
 *
 * LOSSLESS. The tokens tile the source: joining `source.slice(span)` over the
 * tokens in order gives back the input exactly. Segment spans tile each word.
 *
 * COST. `work` is a deterministic counter, not a clock: one per code unit
 * consumed, plus one per event emitted (each token and each segment). The
 * cursor only moves forward, through `step`, and every code unit is consumed
 * once; lookahead reads at most one unit ahead and consumes nothing. A token and a segment
 * each cover at least one code unit, so
 *
 *     work <= 3 * source.length
 */
import type { Segment, Span, Unresolved, UnresolvedReason, WordRole } from './ast.js';

/** Longer sources return `unresolved` (`size-limit`) before any lexing. */
export const MAX_SOURCE_LENGTH = 65536;

export type OperatorKind =
  | 'sequence' | 'and' | 'or' | 'background' | 'pipeline' | 'newline'
  | 'redirect-in' | 'redirect-out' | 'redirect-append';

export interface BlankToken { kind: 'blank'; span: Span }

export interface WordToken {
  kind: 'word';
  span: Span;
  role: WordRole;
  segments: Segment[];
  /** Set when `role` is `assignment`: the name before the first `=`. */
  assignmentName?: string;
}

export interface OperatorToken {
  kind: 'operator';
  span: Span;
  operator: OperatorKind;
  /** Explicit descriptor number on a redirect, as in `2>`. */
  fd?: number;
}

export type Token = BlankToken | WordToken | OperatorToken;

export interface LexedTokens { kind: 'tokens'; tokens: Token[]; work: number }
export interface LexUnresolved extends Unresolved { work: number }

export type LexResult = LexedTokens | LexUnresolved;

/** Reserved words. As a bare word in command position they start grammar 1A does not lex. */
const RESERVED: ReadonlySet<string> = new Set([
  '!', 'case', 'coproc', 'do', 'done', 'elif', 'else', 'esac', 'fi', 'for',
  'function', 'if', 'in', 'select', 'then', 'time', 'until', 'while',
]);

/** Unquoted characters that start a construct 1A does not lex. */
const BARE_UNRESOLVED: ReadonlyMap<string, UnresolvedReason> = new Map<string, UnresolvedReason>([
  ['$', 'expansion'], ['*', 'expansion'], ['?', 'expansion'], ['[', 'expansion'], ['~', 'expansion'],
  ['`', 'substitution'],
  ['(', 'compound-grammar'], [')', 'compound-grammar'], ['{', 'compound-grammar'], ['}', 'compound-grammar'],
]);

const isBlank = (c: string | undefined): boolean => c === ' ' || c === '\t';
const isWordEnd = (c: string): boolean =>
  c === ' ' || c === '\t' || c === '\n' || c === ';' || c === '&' || c === '|' || c === '<' || c === '>';
const isDigit = (c: string): boolean => c >= '0' && c <= '9';
const isNameChar = (c: string, first: boolean): boolean =>
  (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c === '_' || (!first && isDigit(c));

export function lex(source: string): LexResult {
  const n = source.length;
  let work = 0;
  const unresolved = (reason: UnresolvedReason, start: number, end = start + 1): LexUnresolved =>
    ({ kind: 'unresolved', reason, span: { start, end: Math.min(end, n) }, work });
  if (n > MAX_SOURCE_LENGTH) return unresolved('size-limit', 0, n);

  const tokens: Token[] = [];
  let i = 0;
  let prefix = true; // the next word may be an assignment or the command word
  let target = false; // the next word is a redirect target
  /** The only place the cursor moves: every code unit consumed is counted once. */
  const step = (units = 1): void => {
    i += units;
    work += units;
  };

  const operator = (start: number, kind: OperatorKind, length: number, fd?: number): void => {
    step(length);
    work++;
    const token: OperatorToken = { kind: 'operator', span: { start, end: i }, operator: kind };
    if (fd !== undefined) token.fd = fd;
    tokens.push(token);
    target = kind === 'redirect-in' || kind === 'redirect-out' || kind === 'redirect-append';
    if (!target) prefix = true; // any other operator starts a new statement
  };

  /** `i` is on `<` or `>`. `start` differs from `i` when descriptor digits came first. */
  const redirect = (start: number, fd?: number): LexUnresolved | null => {
    const next = source[i + 1];
    if (next === '(') return unresolved('substitution', i, i + 2);
    if (source[i] === '<') {
      if (next === '<') return unresolved('heredoc', i, i + 2);
      if (next === '&' || next === '>') return unresolved('compound-grammar', i, i + 2);
      operator(start, 'redirect-in', 1, fd);
    } else if (next === '&' || next === '|') {
      return unresolved('compound-grammar', i, i + 2);
    } else if (next === '>') {
      operator(start, 'redirect-append', 2, fd);
    } else {
      operator(start, 'redirect-out', 1, fd);
    }
    return null;
  };

  while (i < n) {
    const c = source[i]!;
    const start = i;

    if (isBlank(c)) {
      while (isBlank(source[i])) step();
      tokens.push({ kind: 'blank', span: { start, end: i } });
      work++;
      continue;
    }
    if (c === '\n') {
      operator(start, 'newline', 1);
      continue;
    }
    if (c === ';') {
      if (source[i + 1] === ';') return unresolved('compound-grammar', i, i + 2);
      operator(start, 'sequence', 1);
      continue;
    }
    if (c === '&') {
      if (source[i + 1] === '>') return unresolved('compound-grammar', i, i + 2);
      if (source[i + 1] === '&') operator(start, 'and', 2);
      else operator(start, 'background', 1);
      continue;
    }
    if (c === '|') {
      if (source[i + 1] === '&') return unresolved('compound-grammar', i, i + 2);
      if (source[i + 1] === '|') operator(start, 'or', 2);
      else operator(start, 'pipeline', 1);
      continue;
    }
    if (c === '<' || c === '>') {
      const stopped = redirect(start);
      if (stopped) return stopped;
      continue;
    }

    // A word: bare runs, escapes and quotes, up to the next blank or operator.
    const segments: Segment[] = [];
    let bareStart = -1;
    let digitsOnly = true; // the word so far is unquoted digits
    let nameOpen = prefix && !target; // the word may still be `name=value`
    let assignmentName: string | undefined;
    const emit = (kind: Segment['kind'], from: number, text: string): void => {
      segments.push({ kind, span: { start: from, end: i }, text });
      work++;
    };
    const flushBare = (): void => {
      if (bareStart >= 0) emit('bare', bareStart, source.slice(bareStart, i));
      bareStart = -1;
    };

    while (i < n) {
      const d = source[i]!;
      if (isWordEnd(d)) break;

      if (d === "'" || d === '"' || d === '\\') {
        flushBare();
        digitsOnly = false;
        nameOpen = false;
      }
      if (d === "'") {
        const open = i;
        step();
        while (i < n && source[i] !== "'") step();
        if (i >= n) return unresolved('unterminated-quote', open, n);
        step();
        emit('single-quoted', open, source.slice(open + 1, i - 1));
        continue;
      }
      if (d === '"') {
        const open = i;
        const parts: string[] = [];
        step();
        let run = i;
        while (i < n && source[i] !== '"') {
          const q = source[i]!;
          if (q === '$') return unresolved(source[i + 1] === '(' ? 'substitution' : 'expansion', i);
          if (q === '`') return unresolved('substitution', i);
          const e = source[i + 1];
          if (q === '\\' && (e === undefined || e === '\n')) return unresolved('unterminated-quote', i, i + 2);
          if (q === '\\' && (e === '"' || e === '\\' || e === '$' || e === '`')) {
            parts.push(source.slice(run, i), e);
            step(2);
            run = i;
            continue;
          }
          step();
        }
        if (i >= n) return unresolved('unterminated-quote', open, n);
        parts.push(source.slice(run, i));
        step();
        emit('double-quoted', open, parts.join(''));
        continue;
      }
      if (d === '\\') {
        const e = source[i + 1];
        if (e === undefined || e === '\n') return unresolved('unterminated-quote', i, i + 2);
        const escaped = String.fromCodePoint(source.codePointAt(i + 1)!);
        const open = i;
        step(1 + escaped.length);
        emit('escaped', open, escaped);
        continue;
      }

      const reason = BARE_UNRESOLVED.get(d);
      if (reason) return unresolved(d === '$' && source[i + 1] === '(' ? 'substitution' : reason, i);
      if (d === '#' && i === start) return unresolved('compound-grammar', i);

      if (nameOpen) {
        if (d === '=' && i > start) {
          assignmentName = source.slice(start, i);
          nameOpen = false;
        } else if (d === '+' && source[i + 1] === '=' && i > start) {
          return unresolved('compound-grammar', start, i + 2);
        } else if (!isNameChar(d, i === start)) {
          nameOpen = false;
        }
      }
      if (!isDigit(d)) digitsOnly = false;
      if (bareStart < 0) bareStart = i;
      step();
    }
    flushBare();

    // Digits written straight before a redirect are its descriptor, not a word.
    if (digitsOnly && (source[i] === '<' || source[i] === '>')) {
      const stopped = redirect(start, Number(source.slice(start, i)));
      if (stopped) return stopped;
      continue;
    }

    const role: WordRole = target ? 'redirect-target'
      : assignmentName !== undefined ? 'assignment'
        : prefix ? 'command' : 'argument';
    if (role === 'command' && segments.length === 1 && segments[0]!.kind === 'bare' && RESERVED.has(segments[0]!.text)) {
      return unresolved('compound-grammar', start, i);
    }
    if (target) target = false;
    else if (role === 'command') prefix = false;

    const word: WordToken = { kind: 'word', span: { start, end: i }, role, segments };
    if (assignmentName !== undefined) word.assignmentName = assignmentName;
    tokens.push(word);
    work++;
  }

  return { kind: 'tokens', tokens, work };
}
