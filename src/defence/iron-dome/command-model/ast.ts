/**
 * ADR-002 Phase 1, slice 1A (#1065): the command model's tree shape.
 *
 * TYPES ONLY, AND INERT. Nothing outside this folder imports it, it is not a
 * package export, and the live classifier does not use it. It describes a
 * deliberately bounded POSIX-shell subset: simple statements made of ordinary
 * words, quote segments, assignments and redirects, joined by sequencing and
 * pipeline operators.
 *
 * Slice 1A ships the lexer only (`lexer.ts`). No parser builds a `Program`
 * yet, so the tree types below are a declared shape, not produced values.
 * There is no normalise step, no decision, no severity and no effect mapping
 * anywhere in this folder.
 *
 * A role is syntactic. It says where a word sits in a statement. It is never
 * a statement that running the command is safe.
 */

/** Half-open range of UTF-16 code-unit offsets into the source text. */
export interface Span {
  start: number;
  end: number;
}

/** How a piece of a word was written. Provenance is kept, never guessed. */
export type SegmentKind = 'bare' | 'escaped' | 'single-quoted' | 'double-quoted';

export interface Segment {
  kind: SegmentKind;
  /** The raw source range, including quote marks or the backslash. */
  span: Span;
  /** The value with its quoting removed. Raw text is `source.slice(span)`. */
  text: string;
}

/** Where a word sits in its statement. */
export type WordRole = 'command' | 'argument' | 'assignment' | 'redirect-target';

export interface Word {
  role: WordRole;
  span: Span;
  segments: Segment[];
  /** Set on an `assignment` word: the name before the first `=`. */
  assignmentName?: string;
}

export type RedirectOperator = '<' | '>' | '>>';

export interface Redirect {
  operator: RedirectOperator;
  /** The operator's own range, with the descriptor digits when present. */
  span: Span;
  /** Explicit descriptor number, as in `2>`. Absent when none was written. */
  fd?: number;
  target: Word;
}

/** A child command written inside a word. Not parsed by slice 1A. */
export interface Substitution {
  kind: 'command' | 'backtick' | 'process';
  span: Span;
  body: Program | Unresolved;
}

/**
 * `shell` and `other` are assigned only from an unambiguous, supported
 * interpreter context. Body text never decides the language.
 */
export type HeredocLanguage = 'shell' | 'other' | 'unknown';

/** A here-document. Not parsed by slice 1A. */
export interface Heredoc {
  delimiter: string;
  /** A quoted delimiter means the body is taken literally. */
  quotedDelimiter: boolean;
  span: Span;
  body: Span;
  language: HeredocLanguage;
}

/** What follows a statement. */
export type StatementJoin = 'sequence' | 'and' | 'or' | 'background' | 'pipeline' | 'newline' | 'end';

export interface Statement {
  span: Span;
  /** `name=value` words before the command word. */
  assignments: Word[];
  /** The command word first, then its arguments. Empty for a bare assignment. */
  words: Word[];
  redirects: Redirect[];
  substitutions: Substitution[];
  heredocs: Heredoc[];
  next: StatementJoin;
}

export interface Program {
  kind: 'program';
  span: Span;
  statements: Statement[];
}

/**
 * Why the model stopped. Each reason names a family, listed here in full so a
 * reader knows what slice 1A folds into it.
 *
 * - `unterminated-quote`: a quote with no closing mark, or a backslash with
 *   no ordinary character after it (end of input, or a newline: a line
 *   continuation is not joined in 1A).
 * - `substitution`: a command, backtick or process substitution.
 * - `heredoc`: a here-document or here-string operator.
 * - `expansion`: a parameter or arithmetic expansion, a pathname pattern
 *   character or a tilde.
 * - `compound-grammar`: any grammar outside simple statements. Grouping,
 *   braces, a reserved word in command position, a comment, `;;`, a
 *   descriptor-duplicating or other unsupported redirect form, `name+=value`.
 * - `size-limit`: the source is longer than the lexer's stated limit.
 */
export type UnresolvedReason =
  | 'unterminated-quote'
  | 'substitution'
  | 'heredoc'
  | 'expansion'
  | 'compound-grammar'
  | 'size-limit';

/**
 * The model could not describe the input. It carries no partial tree: a
 * caller gets the whole answer or this, never a shortened result presented
 * as complete.
 */
export interface Unresolved {
  kind: 'unresolved';
  reason: UnresolvedReason;
  /** Where the unsupported construct starts (or the whole input, for size). */
  span: Span;
}

export type ParseResult = Program | Unresolved;
