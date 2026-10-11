/**
 * #713 — the allow-list behind the heredoc data-read relief (#661 follow-up).
 *
 * #686 masked a whole-command interpreter heredoc whose body had no
 * `SHELL_OUT_SINK` match; #712 withdrew that because "no sink found" is a
 * deny-list of code loaders and no such list across five languages could be
 * shown complete. This module inverts the test: a body earns the mask only
 * when EVERY top-level statement in it is positively recognised as inert or as
 * a data read from a literal path. Anything this file does not recognise —
 * a loader, an evaluator, a deserialiser, a dispatch trick, a block, a
 * spelling it has never seen — leaves the body scanned exactly as in 5.5.0.
 * Unknown is unsafe.
 *
 * Three invariants hold on every recognised read (design of record, #713):
 *
 *   I1  the path is ONE plain string literal — no concatenation, variable,
 *       call, escape, interpolation, pipe (`|cmd`) or `scheme://` wrapper;
 *   I2  the read is OUTERMOST: the whole statement, the right-hand side of one
 *       simple assignment, or the sole argument of a printer. It may be
 *       followed by allow-listed pure methods (`.read()`, `.length`) and may be
 *       wrapped by an allow-listed data parser (`json.load`), nothing else;
 *   I3  every identifier is an exact ASCII spelling from the tables below — no
 *       `\u` escapes, no aliases, no receivers the tables do not name.
 *
 * Statements that are not reads may only be pure expressions over literals and
 * variables this body bound from a recognised statement, using the pure
 * functions and methods listed per language (`len`, `re.findall`,
 * `.startswith`, `JSON.parse`, …). An identifier the body did not bind and the
 * table does not list is unrecognised, which is what makes `f = open; f(x)`,
 * `k = Kernel; k.load(…)` and every unlisted loader fall out without being
 * named here.
 *
 * Everything is a single forward pass: the splitter is a hand-written lexer
 * (no regex gaps), the parser is recursive descent whose recursion is bounded
 * by `MAX_NEST` bracket levels and `MAX_CHAIN` postfix steps, and any
 * exception is treated as "unrecognised".
 */
import type { ScriptLang } from './tool-action-guard.js';

type DataLang = Exclude<ScriptLang, 'sh'>;

/** One lexical token of a heredoc body. `str` carries the literal's contents. */
export interface DataReadToken {
  k: 'id' | 'var' | 'str' | 'num' | 'rl' | 'p';
  v: string;
  /** `str` only: no backslash escape inside the literal. */
  plain?: boolean;
}

/** Bracket nesting deeper than this is unrecognised (bounds parser recursion). */
const MAX_NEST = 32;
/** Postfix steps (`.x`, `(…)`, `[…]`) on one operand beyond this are unrecognised. */
const MAX_CHAIN = 32;

const CLOSER: Record<string, string> = { '(': ')', '[': ']', '{': '}' };
const PUNCT3 = new Set(['===', '!==']);
const PUNCT2 = new Set(['==', '!=', '<=', '>=', '&&', '||', '**', '//', '::', '??', '+=', '-=', '?.', '->', '=>']);
const PUNCT1 = new Set(['(', ')', '[', ']', '{', '}', ',', '.', ';', ':', '=', '+', '-', '*', '/', '%', '<', '>', '!', '?', '&', '|', '^', '~']);

/**
 * Words that introduce a block or compound statement (design §3). As the FIRST
 * token of a statement they make the whole body unrecognised. A block can hide
 * a loader in a branch, and this splitter does not model blocks.
 */
const BLOCK_START: Record<DataLang, ReadonlySet<string>> = {
  python: new Set(['def', 'class', 'if', 'elif', 'else', 'for', 'while', 'with', 'try', 'except', 'finally', 'async', 'match', 'case']),
  node: new Set(['function', 'class', 'if', 'else', 'for', 'while', 'do', 'try', 'switch', 'async', 'with']),
  ruby: new Set(['def', 'class', 'module', 'if', 'unless', 'else', 'while', 'until', 'for', 'case', 'begin', 'do']),
  perl: new Set(['sub', 'if', 'unless', 'else', 'elsif', 'for', 'foreach', 'while', 'until', 'do', 'eval', 'BEGIN', 'END', 'package']),
  php: new Set(['function', 'fn', 'class', 'if', 'else', 'elseif', 'for', 'foreach', 'while', 'do', 'switch', 'match', 'try']),
};
/** Words that open a body ANYWHERE in a statement (lambdas, blocks, generators). */
const BLOCK_ANYWHERE: Record<DataLang, ReadonlySet<string>> = {
  python: new Set(['def', 'class', 'lambda', 'for', 'while', 'yield', 'await', 'async']),
  node: new Set(['function', 'class', 'async', 'await', 'yield']),
  ruby: new Set(['do', 'begin', 'end', 'lambda', 'proc', 'then', 'def', 'class', 'module']),
  perl: new Set(['sub', 'do', 'eval']),
  php: new Set(['function', 'fn', 'class']),
};

/** Inside a comment: printable ASCII, a tab, or the CR of a CRLF. LF is the caller's. */
function commentByteOk(body: string, at: number): boolean {
  const code = body.charCodeAt(at);
  if (code === 0x0d) return body[at + 1] === '\n';
  return code === 0x09 || (code >= 0x20 && code <= 0x7e);
}

/**
 * Split a heredoc body into top-level statements, fail-closed (#713, design §3).
 *
 * Deliberately NOT `splitCommandStatements`: that one breaks on `(` because
 * shell does, which is how `open('/tmp/x/table.md')` became a path in command
 * position (#661). This one lexes the body as the interpreter's own language —
 * string literals, comments, `()[]{}` depth — and splits only on a depth-0
 * newline (Python, Node, Ruby; a backslash-newline continues the line in
 * Python and Ruby) or a depth-0 `;`. Perl and PHP end statements with `;`
 * only, so a depth-0 newline inside an unfinished statement is unrecognised.
 *
 * Returns null — the whole body is unrecognised — when a quote or bracket is
 * still open at the end, when a nested `<<`, backtick, `$(` or `${` appears
 * anywhere (this splitter does not model re-entry), when an interpolating
 * string could run code (Ruby `#{`, Perl/PHP `$`/`@` in double quotes), when a
 * byte outside a literal is not ASCII code (identifier escapes, I3), or when a
 * statement opens a block (design §3: Python trailing `:`, `def`/`class`/
 * `function`/`sub`/`if`/`for`/`while`/lambda, Ruby `do`/`begin`, a `{` opening
 * a statement).
 */
export function splitDataReadStatements(body: string, lang: DataLang): DataReadToken[][] | null {
  if (body.includes('<<') || body.includes('`') || body.includes('$(') || body.includes('${')) return null;
  if (lang === 'ruby' && (body.includes('#{') || body.includes('#@') || body.includes('#$'))) return null;
  if (lang === 'python') {
    // Python honours a source-encoding cookie (`# coding: utf_7`) on line 1 or
    // 2, and the guard may have blanked that comment before this view, leaving
    // only trailing whitespace. Refuse rather than read bytes Python decodes
    // differently.
    const nl1 = body.indexOf('\n');
    const nl2 = nl1 < 0 ? -1 : body.indexOf('\n', nl1 + 1);
    const line1 = body.slice(0, nl1 < 0 ? body.length : nl1);
    const line2 = nl1 < 0 ? '' : body.slice(nl1 + 1, nl2 < 0 ? body.length : nl2);
    if (/[ \t\r]$/.test(line1) || /[ \t\r]$/.test(line2)) return null;
  }
  let i = 0;
  let end = body.length;
  if (lang === 'php') {
    // The program must open with `<?php` (text before it is output, and a
    // second `<?` re-enters code) and may close with `?>` only at the very end.
    let s = 0;
    while (s < end && (body[s] === ' ' || body[s] === '\t' || body[s] === '\n' || body[s] === '\r')) s++;
    if (!body.startsWith('<?php', s) || !/[ \t\r\n]/.test(body[s + 5] ?? '')) return null;
    i = s + 5;
    if (body.indexOf('<?', i) >= 0) return null;
    const close = body.indexOf('?>', i);
    if (close >= 0) {
      if (body.slice(close + 2).trim() !== '') return null;
      end = close;
    }
  }
  const nlEnds = lang === 'python' || lang === 'node' || lang === 'ruby';
  const stmts: DataReadToken[][] = [];
  const stack: string[] = [];
  let cur: DataReadToken[] = [];
  const flush = (): void => {
    if (cur.length) stmts.push(cur);
    cur = [];
  };
  const identAt = (at: number): number => {
    let j = at;
    while (j < end && /[A-Za-z0-9_]/.test(body[j])) j++;
    return j;
  };

  while (i < end) {
    const c = body[i];
    if (c === '\n') {
      if (stack.length === 0) {
        if (nlEnds) flush();
        else if (cur.length) return null;            // Perl/PHP: a statement ends at `;` only
      }
      i++;
      continue;
    }
    if (c === '\r') {
      if (body[i + 1] !== '\n') return null;        // a lone CR is a line break to Python
      i++;
      continue;
    }
    if (c === ' ' || c === '\t') { i++; continue; }
    if (c === '\\') {
      const next = body[i + 1] === '\r' ? body[i + 2] : body[i + 1];
      if ((lang === 'python' || lang === 'ruby') && next === '\n') {
        i += body[i + 1] === '\r' ? 3 : 2;           // line continuation: same statement
        continue;
      }
      return null;                                   // I3: no escape outside a literal
    }
    if ((c === '#' && lang !== 'node') || (c === '/' && body[i + 1] === '/' && (lang === 'node' || lang === 'php'))) {
      if (lang === 'php' && c === '#' && body[i + 1] === '[') return null;   // PHP 8 attribute
      // The comment ends at LF here. ECMAScript also ends it at a lone CR,
      // U+2028 and U+2029; PHP and Python at a lone CR. Any such byte, any other
      // control byte or any non-ASCII byte inside the comment is unrecognised,
      // so code after it is never hidden as comment text.
      let stop = i;
      while (stop < end && body[stop] !== '\n') {
        if (!commentByteOk(body, stop)) return null;
        stop++;
      }
      // A source-encoding cookie re-decodes the body the interpreter runs.
      if (/coding[:=]/.test(body.slice(i, stop))) return null;
      i = stop;
      continue;
    }
    if (c === '/' && body[i + 1] === '*' && (lang === 'node' || lang === 'php')) {
      const close = body.indexOf('*/', i + 2);
      if (close < 0 || close + 2 > end) return null;
      for (let j = i + 2; j < close; j++) if (body[j] !== '\n' && !commentByteOk(body, j)) return null;
      i = close + 2;
      continue;
    }
    if (c === '"' || c === "'") {
      const q = lang === 'python' && body.startsWith(c + c + c, i) ? c + c + c : c;
      let j = i + q.length;
      let escaped = false;
      for (;;) {
        if (j >= end) return null;                   // unclosed quote
        const d = body[j];
        // No literal spans a line, not even by a backslash-newline. The guard
        // blanks shell `#` comments before detection (`stripComments`), so a
        // `#` inside a literal may already be cut from this view; a literal
        // that could continue onto the next line would then close somewhere
        // the interpreter's does not.
        if (d === '\n' || (d === '\\' && (body[j + 1] === '\n' || body[j + 1] === '\r'))) return null;
        if (d === '\\') { escaped = true; j += 2; continue; }
        if (body.startsWith(q, j)) break;
        j++;
      }
      const inner = body.slice(i + q.length, j);
      if (c === '"' && lang === 'php' && inner.includes('$')) return null;
      // Perl interpolates `$x`, `@x` and `@{[ code ]}`; only the errno `$!` is let through.
      if (c === '"' && lang === 'perl' && /@|\$(?!!)|\$![[{]/.test(inner)) return null;
      cur.push({ k: 'str', v: inner, plain: !escaped });
      i = j + q.length;
      continue;
    }
    if (c >= '0' && c <= '9') {
      let j = i;
      while (j < end && body[j] >= '0' && body[j] <= '9') j++;
      if (body[j] === '.' && body[j + 1] >= '0' && body[j + 1] <= '9') {
        j++;
        while (j < end && body[j] >= '0' && body[j] <= '9') j++;
      }
      cur.push({ k: 'num', v: body.slice(i, j) });
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      const j = identAt(i);
      cur.push({ k: 'id', v: body.slice(i, j) });
      i = j;
      continue;
    }
    if ((c === '$' && (lang === 'perl' || lang === 'php')) || (c === '@' && lang === 'perl')) {
      if (c === '$' && lang === 'perl' && body[i + 1] === '!') {
        cur.push({ k: 'var', v: '$!' });
        i += 2;
        continue;
      }
      if (!/[A-Za-z_]/.test(body[i + 1] ?? '')) return null;   // `$$x`, `$#a`, `@$r`, …
      const j = identAt(i + 1);
      cur.push({ k: 'var', v: body.slice(i, j) });
      i = j;
      continue;
    }
    if (c === '<' && lang === 'perl') {
      const m = /<(\$?[A-Za-z_][A-Za-z0-9_]*)>/y;
      m.lastIndex = i;
      const r = m.exec(body);
      if (r && i + r[0].length <= end) {
        cur.push({ k: 'rl', v: r[1] });
        i += r[0].length;
        continue;
      }
    }
    const p3 = body.slice(i, i + 3);
    const p2 = body.slice(i, i + 2);
    const p = PUNCT3.has(p3) ? p3 : PUNCT2.has(p2) ? p2 : PUNCT1.has(c) ? c : null;
    if (p === null) return null;                     // non-ASCII, `@`, `$`, … outside a literal
    if (p === '/' || p === '//') {
      // A regex literal and a division share `/` in Node, Ruby and Perl; refuse
      // rather than guess. Python and PHP have no regex literal.
      if (lang !== 'python' && lang !== 'php') return null;
      if (p === '//' && lang !== 'python') return null;
    }
    if (p === '(' || p === '[' || p === '{') {
      if (stack.length >= MAX_NEST) return null;
      stack.push(CLOSER[p]);
    } else if (p === ')' || p === ']' || p === '}') {
      if (stack.pop() !== p) return null;            // unbalanced
    } else if (p === ';' && stack.length === 0) {
      flush();
      i += 1;
      continue;
    }
    cur.push({ k: 'p', v: p });
    i += p.length;
  }
  if (stack.length) return null;                     // unclosed bracket
  flush();

  for (const s of stmts) {
    const first = s[0];
    if (first.k === 'p' && first.v === '{') return null;
    if (first.k === 'id' && BLOCK_START[lang].has(first.v)) return null;
    if (lang === 'python' && s[s.length - 1].k === 'p' && s[s.length - 1].v === ':') return null;
    for (const t of s) if (t.k === 'id' && BLOCK_ANYWHERE[lang].has(t.v)) return null;
  }
  return stmts;
}

// ── Expression trees ─────────────────────────────────────────────────────────

type Expr =
  | { t: 'num' }
  | { t: 'str'; v: string; plain: boolean }
  | { t: 'id'; name: string }
  | { t: 'rl'; name: string }
  | { t: 'mem'; obj: Expr; name: string }
  | { t: 'call'; fn: Expr; args: Expr[]; kw: Array<{ name: string; value: Expr }> }
  | { t: 'idx'; obj: Expr; idx: Expr }
  | { t: 'seq'; items: Expr[] }
  | { t: 'ops'; items: Expr[] };

/** The allow set for one language (design §4). Every name is an exact spelling. */
interface DataReadProfile {
  literals: ReadonlySet<string>;
  /** Binary/ternary operator tokens (punctuation or words). */
  binOps: ReadonlySet<string>;
  prefixOps: ReadonlySet<string>;
  /** `.` is member access (false in Perl/PHP, where it concatenates). */
  dotMember: boolean;
  /** Printers, called with parentheses. */
  printers: ReadonlySet<string>;
  /** Printers that also take a paren-less argument list (`puts x`, `echo $a, "\n"`). */
  bareArgPrinters: ReadonlySet<string>;
  /** Pure functions, by dotted name. */
  pureFns: ReadonlySet<string>;
  /** Pure methods callable on a pure value or on a recognised read. */
  pureMethods: ReadonlySet<string>;
  /** Members readable without a call (Node `.length`; every pure method in Ruby). */
  pureProps: ReadonlySet<string>;
  /** Data parsers whose sole argument may be a recognised read (`json.load(open(…))`). */
  consumers: ReadonlySet<string>;
  /** What may index a value: any pure expression, or a literal only. */
  index: 'any' | 'literal' | 'number';
  /** Keyword-argument names allowed (Python), always with a literal value. */
  kwargs: ReadonlySet<string>;
  /** Keyword arguments whose literal must be one of these plain strings (codec names, error handlers). */
  kwStrings: Readonly<Record<string, ReadonlySet<string>>>;
}

const set = (...xs: string[]): ReadonlySet<string> => new Set(xs);
const PY_SECOND_WORD = set('in', 'not');
const RUBY_METHODS = set('read', 'readlines', 'close', 'length', 'size', 'strip', 'chomp', 'lines', 'split', 'count', 'upcase', 'downcase', 'to_s', 'to_i', 'first', 'last', 'join');

const PROFILES: Record<DataLang, DataReadProfile> = {
  python: {
    literals: set('True', 'False', 'None'),
    binOps: set('+', '-', '*', '/', '//', '%', '**', '==', '!=', '<', '>', '<=', '>=', '&', '|', '^', 'and', 'or', 'not', 'in', 'is', 'if', 'else'),
    prefixOps: set('-', '+', '~', 'not'),
    dotMember: true,
    printers: set('print'),
    bareArgPrinters: set(),
    pureFns: set('len', 'str', 'int', 'float', 'bool', 'list', 'tuple', 'sorted', 'min', 'max', 'sum', 'abs', 'round', 'repr', 'enumerate', 'zip', 'any', 'all',
      're.findall', 're.search', 're.match', 're.fullmatch', 're.split', 're.escape',
      'json.loads', 'json.load', 'json.dumps', 'yaml.safe_load', 'csv.reader', 'csv.DictReader'),
    pureMethods: set('read', 'readlines', 'close', 'strip', 'lstrip', 'rstrip', 'split', 'splitlines', 'startswith', 'endswith', 'lower', 'upper', 'count', 'find', 'replace', 'join', 'keys', 'values', 'items', 'get', 'decode'),
    pureProps: set(),
    consumers: set('json.load', 'json.loads', 'yaml.safe_load', 'csv.reader', 'csv.DictReader'),
    index: 'any',
    kwargs: set('sep', 'end', 'flush', 'encoding', 'errors', 'newline', 'indent', 'sort_keys', 'ensure_ascii'),
    // A codec or error-handler name is looked up through the codec registry,
    // which a third-party package can extend; only stdlib spellings are inert.
    kwStrings: {
      encoding: set('utf-8', 'utf8', 'UTF-8', 'ascii', 'latin-1', 'latin1'),
      errors: set('strict', 'replace', 'ignore'),
    },
  },
  node: {
    literals: set('true', 'false', 'null', 'undefined'),
    binOps: set('+', '-', '*', '%', '==', '===', '!=', '!==', '<', '>', '<=', '>=', '&&', '||', '??', '?', ':'),
    prefixOps: set('-', '+', '!'),
    dotMember: true,
    printers: set('console.log', 'console.error'),
    bareArgPrinters: set(),
    pureFns: set('JSON.parse', 'JSON.stringify', 'String', 'Number', 'parseInt', 'Object.keys', 'Array.isArray'),
    pureMethods: set('toString', 'trim', 'split', 'includes', 'startsWith', 'endsWith', 'toLowerCase', 'toUpperCase', 'slice', 'indexOf', 'join'),
    pureProps: set('length'),
    consumers: set('JSON.parse'),
    index: 'number',
    kwargs: set(),
    kwStrings: {},
  },
  ruby: {
    literals: set('true', 'false', 'nil'),
    binOps: set('+', '-', '*', '%', '**', '==', '!=', '<', '>', '<=', '>=', '&&', '||', '?', ':', 'and', 'or'),
    prefixOps: set('-', '!', 'not'),
    dotMember: true,
    printers: set('puts', 'print', 'p'),
    bareArgPrinters: set('puts', 'print', 'p'),
    pureFns: set(),
    pureMethods: RUBY_METHODS,
    pureProps: RUBY_METHODS,
    consumers: set(),
    index: 'literal',
    kwargs: set(),
    kwStrings: {},
  },
  perl: {
    literals: set('undef', '$!'),
    binOps: set('.', '+', '-', '*', '%', '**', '==', '!=', '<', '>', '<=', '>=', '&&', '||', '?', ':', 'eq', 'ne', 'lt', 'gt', 'le', 'ge', 'cmp', 'x', 'and', 'or'),
    prefixOps: set('-', '!', 'not'),
    dotMember: false,
    printers: set('print', 'say'),
    bareArgPrinters: set('print', 'say'),
    pureFns: set('length', 'scalar', 'join', 'lc', 'uc', 'close', 'chomp', 'readline'),
    pureMethods: set(),
    pureProps: set(),
    consumers: set(),
    index: 'literal',
    kwargs: set(),
    kwStrings: {},
  },
  php: {
    literals: set('true', 'false', 'null'),
    binOps: set('.', '+', '-', '*', '/', '%', '==', '===', '!=', '!==', '<', '>', '<=', '>=', '&&', '||', '?', ':', '??', 'and', 'or'),
    prefixOps: set('-', '!'),
    dotMember: false,
    printers: set('echo', 'print', 'print_r', 'var_dump'),
    bareArgPrinters: set('echo', 'print'),
    pureFns: set('strlen', 'count', 'trim', 'strtolower', 'strtoupper', 'substr_count', 'explode', 'implode', 'json_decode', 'json_encode', 'intval', 'str_contains', 'fread', 'fgets', 'fclose', 'feof'),
    pureMethods: set(),
    pureProps: set(),
    consumers: set('json_decode'),
    index: 'literal',
    kwargs: set(),
    kwStrings: {},
  },
};

/** Names a body may never bind: every listed name, the read entry points, and keywords. */
const RESERVED: Record<DataLang, ReadonlySet<string>> = (() => {
  const extra: Record<DataLang, string[]> = {
    python: ['open', 'Path', 'pathlib', 'json', 're', 'csv', 'io', 'yaml', 'import', 'from', 'as', 'del', 'global', 'nonlocal', 'exec', 'eval', 'compile'],
    node: ['require', 'module', 'exports', 'process', 'globalThis', 'global', 'eval', 'Function', 'const', 'let', 'var', 'new', 'this', 'typeof', 'import'],
    ruby: ['File', 'IO', 'Kernel', 'self', 'load', 'require', 'eval', 'send', 'method'],
    perl: ['my', 'our', 'local', 'open', 'read_file', 'use', 'require', 'die'],
    php: ['file_get_contents', 'readfile', 'fopen', 'include', 'require', 'eval'],
  };
  const out = {} as Record<DataLang, ReadonlySet<string>>;
  for (const lang of Object.keys(PROFILES) as DataLang[]) {
    const p = PROFILES[lang];
    const names = new Set<string>(extra[lang]);
    for (const s of [p.literals, p.printers, p.bareArgPrinters, p.pureFns, p.consumers, p.binOps, p.prefixOps, BLOCK_START[lang], BLOCK_ANYWHERE[lang]]) {
      for (const n of s) names.add(n.split('.')[0]);
    }
    out[lang] = names;
  }
  return out;
})();

/** A binding target: a plain lower-case-initial name (Perl/PHP: with its sigil), not reserved. */
function bindableName(tok: DataReadToken | undefined, lang: DataLang): string | null {
  if (!tok) return null;
  const sigil = lang === 'perl' || lang === 'php';
  if (sigil ? tok.k !== 'var' : tok.k !== 'id') return null;
  const bare = sigil ? tok.v.slice(1) : tok.v;
  if (!/^[a-z][A-Za-z0-9_]*$/.test(bare)) return null;   // no `_x`/`__x`, no constants or specials
  if (RESERVED[lang].has(tok.v) || RESERVED[lang].has(bare)) return null;
  return tok.v;
}

class DataReadParser {
  private pos = 0;
  constructor(private readonly toks: DataReadToken[], private readonly prof: DataReadProfile, private readonly lang: DataLang) {}

  at(): number { return this.pos; }
  done(): boolean { return this.pos >= this.toks.length; }
  peek(o = 0): DataReadToken | undefined { return this.toks[this.pos + o]; }
  isP(v: string, o = 0): boolean {
    const t = this.toks[this.pos + o];
    return !!t && t.k === 'p' && t.v === v;
  }
  eatP(v: string): boolean {
    if (!this.isP(v)) return false;
    this.pos++;
    return true;
  }

  private isOp(t: DataReadToken | undefined, ops: ReadonlySet<string>): boolean {
    return !!t && (t.k === 'p' || t.k === 'id') && ops.has(t.v);
  }

  /** A flat chain of operands and operators. Operator precedence is irrelevant: every operand must be pure. */
  expr(): Expr | null {
    const items: Expr[] = [];
    let wrapped = false;
    for (;;) {
      while (this.isOp(this.peek(), this.prof.prefixOps)) { this.pos++; wrapped = true; }
      const x = this.postfix();
      if (!x) return null;
      items.push(x);
      if (!this.isOp(this.peek(), this.prof.binOps)) break;
      this.pos++;
      // Python's two-word operators: `not in`, `is not`.
      if (this.lang === 'python' && this.isOp(this.peek(), PY_SECOND_WORD)) this.pos++;
      wrapped = true;
    }
    return items.length === 1 && !wrapped ? items[0] : { t: 'ops', items };
  }

  /** Comma-separated expressions up to (not including) `close`, or to the end when `close` is null. */
  list(close: string | null, allowKw: boolean): { args: Expr[]; kw: Array<{ name: string; value: Expr }> } | null {
    const args: Expr[] = [];
    const kw: Array<{ name: string; value: Expr }> = [];
    const atEnd = (): boolean => (close === null ? this.done() : this.isP(close));
    if (atEnd()) return { args, kw };
    for (;;) {
      const t = this.peek();
      if (allowKw && t?.k === 'id' && this.isP('=', 1)) {
        this.pos += 2;
        const value = this.expr();
        if (!value) return null;
        kw.push({ name: t.v, value });
      } else {
        if (kw.length) return null;                  // positional after keyword
        const e = this.expr();
        if (!e) return null;
        args.push(e);
      }
      if (atEnd()) return { args, kw };
      if (!this.eatP(',')) return null;
      if (atEnd()) return close === null ? null : { args, kw };   // trailing comma inside brackets only
    }
  }

  postfix(): Expr | null {
    let x = this.primary();
    if (!x) return null;
    for (let steps = 0; ; steps++) {
      if (steps > MAX_CHAIN) return null;
      if (this.prof.dotMember && this.isP('.')) {
        const name = this.peek(1);
        if (!name || name.k !== 'id') return null;
        this.pos += 2;
        x = { t: 'mem', obj: x, name: name.v };
        continue;
      }
      if (this.isP('(')) {
        this.pos++;
        const l = this.list(')', this.prof.kwargs.size > 0);
        if (!l || !this.eatP(')')) return null;
        x = { t: 'call', fn: x, args: l.args, kw: l.kw };
        continue;
      }
      if (this.isP('[')) {
        this.pos++;
        const idx = this.expr();
        if (!idx || !this.eatP(']')) return null;
        x = { t: 'idx', obj: x, idx };
        continue;
      }
      return x;
    }
  }

  primary(): Expr | null {
    const t = this.peek();
    if (!t) return null;
    if (t.k === 'p') {
      if (t.v !== '(' && t.v !== '[') return null;   // `{`, `::`, `->`, … are not recognised
      this.pos++;
      const close = t.v === '(' ? ')' : ']';
      const l = this.list(close, false);
      if (!l || !this.eatP(close)) return null;
      return { t: 'seq', items: l.args };
    }
    this.pos++;
    if (t.k === 'str') return { t: 'str', v: t.v, plain: !!t.plain };
    if (t.k === 'num') return { t: 'num' };
    if (t.k === 'rl') return { t: 'rl', name: t.v };
    return { t: 'id', name: t.v };
  }
}

interface Ctx {
  lang: DataLang;
  prof: DataReadProfile;
  /** Names this body bound from a recognised statement. `fs` = Node's fs module, used only to read. */
  vars: Map<string, 'data' | 'fs'>;
}

/** `a.b.c` for a chain of bare identifiers, else null. */
function dotted(e: Expr): string | null {
  const parts: string[] = [];
  let x = e;
  while (x.t === 'mem') {
    parts.push(x.name);
    x = x.obj;
  }
  if (x.t !== 'id') return null;
  parts.push(x.name);
  return parts.reverse().join('.');
}

/** I1: one plain string literal naming a file — no escape, pipe, control byte or `scheme://`. */
function isPathLiteral(e: Expr | undefined): boolean {
  return !!e && e.t === 'str' && e.plain && e.v.length > 0 && !/[|\\\x00-\x1f]/.test(e.v) && !e.v.includes('://');
}

function isLiteral(e: Expr, cx: Ctx): boolean {
  return e.t === 'num' || e.t === 'str' || (e.t === 'id' && cx.prof.literals.has(e.name));
}

function kwOk(kw: Array<{ name: string; value: Expr }>, cx: Ctx): boolean {
  return kw.every(k => {
    if (!cx.prof.kwargs.has(k.name) || !isLiteral(k.value, cx)) return false;
    const allowed = Object.prototype.hasOwnProperty.call(cx.prof.kwStrings, k.name) ? cx.prof.kwStrings[k.name] : undefined;
    return allowed === undefined || (k.value.t === 'str' && k.value.plain && allowed.has(k.value.v));
  });
}

function indexOk(idx: Expr, cx: Ctx): boolean {
  if (cx.prof.index === 'any') return isPure(idx, cx);
  if (cx.prof.index === 'number') return idx.t === 'num';
  return idx.t === 'num' || idx.t === 'str';
}

/** A function name from the allow set that the body has not rebound. */
function listedFn(fn: Expr, names: ReadonlySet<string>, cx: Ctx): string | null {
  const name = dotted(fn);
  if (name === null || !names.has(name) || cx.vars.has(name.split('.')[0])) return null;
  return name;
}

/** Inert: literals, bound data variables, and allow-listed pure calls over them. Never a read (I2). */
function isPure(e: Expr, cx: Ctx): boolean {
  switch (e.t) {
    case 'num':
    case 'str':
      return true;
    case 'id':
      return cx.prof.literals.has(e.name) || cx.vars.get(e.name) === 'data';
    case 'rl':
      return false;
    case 'seq':
    case 'ops':
      return e.items.every(x => isPure(x, cx));
    case 'idx':
      return indexOk(e.idx, cx) && isPure(e.obj, cx);
    case 'mem':
      return cx.prof.pureProps.has(e.name) && isPure(e.obj, cx);
    case 'call':
      if (!kwOk(e.kw, cx) || !e.args.every(a => isPure(a, cx))) return false;
      if (listedFn(e.fn, cx.prof.pureFns, cx) !== null) return true;
      return e.fn.t === 'mem' && cx.prof.pureMethods.has(e.fn.name) && isPure(e.fn.obj, cx);
  }
}

/** A recognised data read (design §4), optionally followed by pure methods/members/indexing. */
function isRead(e: Expr, cx: Ctx): boolean {
  let x = e;
  for (;;) {
    if (readBase(x, cx)) return true;
    if (x.t === 'call' && x.fn.t === 'mem' && cx.prof.pureMethods.has(x.fn.name) && kwOk(x.kw, cx) && x.args.every(a => isPure(a, cx))) {
      x = x.fn.obj;
      continue;
    }
    if (x.t === 'mem' && cx.prof.pureProps.has(x.name)) { x = x.obj; continue; }
    if (x.t === 'idx' && indexOk(x.idx, cx)) { x = x.obj; continue; }
    return false;
  }
}

/** Node: the `fs` module, by a bound name or `require('fs' | 'node:fs')` written in place. */
function isFsModule(e: Expr, cx: Ctx): boolean {
  if (e.t === 'id') return cx.vars.get(e.name) === 'fs';
  return e.t === 'call' && e.fn.t === 'id' && e.fn.name === 'require' && !cx.vars.has('require') && e.kw.length === 0
    && e.args.length === 1 && e.args[0].t === 'str' && e.args[0].plain && (e.args[0].v === 'fs' || e.args[0].v === 'node:fs');
}

function readBase(e: Expr, cx: Ctx): boolean {
  if (e.t === 'rl') return cx.lang === 'perl' && cx.vars.has(e.name);
  if (e.t !== 'call') return false;
  const { fn, args } = e;
  // Data parser wrapped round a read: json.load(open('x')), JSON.parse(fs.readFileSync('x')).
  // Extra arguments are literals only (`json_decode(…, true)`), never a reviver or hook.
  if (listedFn(fn, cx.prof.consumers, cx) !== null && args.length >= 1 && e.kw.length === 0
    && isRead(args[0], cx) && args.slice(1).every(a => isLiteral(a, cx))) return true;
  const name = dotted(fn);
  const bound = name !== null && cx.vars.has(name.split('.')[0]);
  switch (cx.lang) {
    case 'python':
      if (name === 'open' && !bound) {
        const mode = args[1];
        return isPathLiteral(args[0]) && args.length <= 2 && kwOk(e.kw, cx)
          && (mode === undefined || (mode.t === 'str' && /^(?:r|rb|rt)$/.test(mode.v)));
      }
      // pathlib.Path('x').read_text() / Path('x').read_bytes()
      if (fn.t === 'mem' && (fn.name === 'read_text' || fn.name === 'read_bytes') && args.length === 0 && kwOk(e.kw, cx)) {
        const p = fn.obj;
        if (p.t !== 'call' || p.args.length !== 1 || p.kw.length || !isPathLiteral(p.args[0])) return false;
        const ctor = dotted(p.fn);
        return (ctor === 'Path' || ctor === 'pathlib.Path') && !cx.vars.has(ctor.split('.')[0]);
      }
      return false;
    case 'ruby':
      return !bound && args.length === 1 && e.kw.length === 0 && isPathLiteral(args[0])
        && (name === 'File.read' || name === 'File.readlines' || name === 'IO.read' || name === 'File.open');
    case 'perl':
      return name === 'read_file' && !bound && args.length === 1 && isPathLiteral(args[0]);
    case 'php':
      if (bound) return false;
      if ((name === 'file_get_contents' || name === 'readfile') && args.length === 1) return isPathLiteral(args[0]);
      return name === 'fopen' && args.length === 2 && isPathLiteral(args[0]) && args[1].t === 'str' && (args[1].v === 'r' || args[1].v === 'rb');
    case 'node': {
      // fs.readFileSync('x'[, 'utf8']) / fs.promises.readFile('x'[, 'utf8'])
      if (fn.t !== 'mem' || e.kw.length || !isPathLiteral(args[0]) || args.length > 2) return false;
      if (args.length === 2 && args[1].t !== 'str') return false;
      if (fn.name === 'readFileSync') return isFsModule(fn.obj, cx);
      return fn.name === 'readFile' && fn.obj.t === 'mem' && fn.obj.name === 'promises' && isFsModule(fn.obj.obj, cx);
    }
  }
}

/** A printer call whose arguments are all pure, or whose sole argument is a recognised read (I2). */
function printerArgsOk(args: Expr[], kw: Array<{ name: string; value: Expr }>, cx: Ctx): boolean {
  if (!kwOk(kw, cx)) return false;
  if (args.length === 1 && isRead(args[0], cx)) return true;
  return args.every(a => isPure(a, cx));
}

const PY_IMPORTS = set('re', 'json', 'csv', 'io', 'yaml', 'pathlib');

const isId = (t: DataReadToken | undefined, v: string): boolean => !!t && t.k === 'id' && t.v === v;
const isP = (t: DataReadToken | undefined, v: string): boolean => !!t && t.k === 'p' && t.v === v;

/** Language-specific statement forms that are not expressions: imports, `use`, Perl `open`. */
function specialStatement(s: DataReadToken[], cx: Ctx): boolean | null {
  if (cx.lang === 'python') {
    if (isId(s[0], 'import')) {
      // import re, json — listed modules only, no `as`, no dotted submodules
      for (let i = 1; i < s.length; i += 2) {
        if (s[i].k !== 'id' || !PY_IMPORTS.has(s[i].v)) return false;
        if (i + 1 < s.length && !isP(s[i + 1], ',')) return false;
      }
      return s.length >= 2 && s.length % 2 === 0;
    }
    if (isId(s[0], 'from')) {
      return s.length === 4 && isId(s[1], 'pathlib') && isId(s[2], 'import') && isId(s[3], 'Path');
    }
    return null;
  }
  if (cx.lang === 'perl') {
    if (isId(s[0], 'use')) {
      if (s.length === 2) return isId(s[1], 'strict') || isId(s[1], 'warnings');
      return s.length === 4 && isId(s[1], 'File') && isP(s[2], '::') && isId(s[3], 'Slurp');
    }
    if (isId(s[0], 'open')) return perlOpen(s, cx);
    return null;
  }
  return null;
}

/**
 * Perl three-argument read open, the only `open` recognised:
 *   open(my $fh, '<', 'lit') [or die …];   open(FH, '<:encoding(UTF-8)', 'lit') || die(…);
 * The mode is one of a closed set: `<`, `<:raw`, `<:utf8`, `<:encoding(UTF-8)`,
 * `<:encoding(utf8)`, `<:encoding(utf-8)`. Any other layer is unrecognised
 * (`<:via(Evil)` loads `PerlIO::via::Evil`). Two-argument open
 * (`open(F, "cmd|")`) and any pipe mode are unrecognised.
 */
const PERL_READ_MODES = set('<', '<:raw', '<:utf8', '<:encoding(UTF-8)', '<:encoding(utf8)', '<:encoding(utf-8)');

function perlOpen(s: DataReadToken[], cx: Ctx): boolean {
  let i = 1;
  if (!isP(s[i++], '(')) return false;
  if (isId(s[i], 'my')) i++;
  const fh = s[i++];
  let name: string | null = null;
  if (fh?.k === 'var' && fh.v.startsWith('$')) name = bindableName(fh, 'perl');
  else if (fh?.k === 'id' && /^[A-Z][A-Z0-9_]*$/.test(fh.v) && !['STDIN', 'STDOUT', 'STDERR', 'ARGV', 'DATA'].includes(fh.v)) name = fh.v;
  if (name === null) return false;
  if (!isP(s[i++], ',')) return false;
  const mode = s[i++];
  if (mode?.k !== 'str' || !mode.plain || !PERL_READ_MODES.has(mode.v)) return false;
  if (!isP(s[i++], ',')) return false;
  const path = s[i++];
  if (!path || path.k !== 'str' || !isPathLiteral({ t: 'str', v: path.v, plain: !!path.plain })) return false;
  if (!isP(s[i++], ')')) return false;
  if (i < s.length) {
    // `or die …` / `|| die …` with pure arguments (literals and `$!`).
    if (!(isId(s[i], 'or') || isP(s[i], '||')) || !isId(s[i + 1], 'die')) return false;
    const p = new DataReadParser(s.slice(i + 2), cx.prof, cx.lang);
    let args: Expr[];
    if (p.isP('(')) {
      const e = p.postfix();
      if (!e || e.t !== 'seq' || !p.done()) return false;
      args = e.items;
    } else {
      const l = p.list(null, false);
      if (!l || !p.done()) return false;
      args = l.args;
    }
    if (!args.every(a => isPure(a, cx))) return false;
  }
  cx.vars.set(name, 'data');
  return true;
}

/** Split `NAME = rhs` (with the language's declaration keyword), else null. */
function assignment(s: DataReadToken[], cx: Ctx): { name: string; rhs: DataReadToken[] } | null {
  let i = 0;
  if (cx.lang === 'node' && (isId(s[0], 'const') || isId(s[0], 'let') || isId(s[0], 'var'))) i = 1;
  if (cx.lang === 'perl' && isId(s[0], 'my')) i = 1;
  if (!isP(s[i + 1], '=')) return null;
  const tok = s[i];
  if (cx.lang === 'perl' && tok?.k === 'var' && tok.v.startsWith('@')) {
    // `my @lines = <$fh>;` binds an array
    const name = bindableName({ k: 'var', v: '$' + tok.v.slice(1) }, 'perl') === null ? null : tok.v;
    return name === null ? null : { name, rhs: s.slice(i + 2) };
  }
  const name = bindableName(tok, cx.lang);
  return name === null ? null : { name, rhs: s.slice(i + 2) };
}

function statementIsDataRead(s: DataReadToken[], cx: Ctx): boolean {
  const special = specialStatement(s, cx);
  if (special !== null) return special;

  const asg = assignment(s, cx);
  if (asg) {
    if (asg.rhs.length === 0) return false;
    const p = new DataReadParser(asg.rhs, cx.prof, cx.lang);
    const e = p.expr();
    if (!e || !p.done()) return false;
    if (cx.lang === 'node' && isFsModule(e, cx) && e.t === 'call') {
      cx.vars.set(asg.name, 'fs');
      return true;
    }
    if (!isPure(e, cx) && !isRead(e, cx)) return false;
    cx.vars.set(asg.name, 'data');
    return true;
  }

  // Node: a statement must open with a word or a literal. One that opens with
  // `(`, `[`, `+`, `-`, `.`, … continues the previous line (no ASI there).
  if (cx.lang === 'node' && s[0].k === 'p') return false;

  // Paren-less printer: `puts x`, `print $n, "\n"`, `echo strlen($t);`
  const head = s[0];
  if (head.k === 'id' && cx.prof.bareArgPrinters.has(head.v) && !cx.vars.has(head.v) && !isP(s[1], '(')) {
    const p = new DataReadParser(s.slice(1), cx.prof, cx.lang);
    const l = p.list(null, false);
    return !!l && p.done() && printerArgsOk(l.args, l.kw, cx);
  }

  const p = new DataReadParser(s, cx.prof, cx.lang);
  const e = p.expr();
  if (!e || !p.done()) return false;
  if (e.t === 'call' && listedFn(e.fn, cx.prof.printers, cx) !== null) return printerArgsOk(e.args, e.kw, cx);
  return isPure(e, cx) || isRead(e, cx);
}

/**
 * True only when every top-level statement of `body` is inert or a recognised
 * data read in `lang` (#713). Unrecognised — including any internal failure —
 * is false, which keeps the 5.5.0 scan.
 */
export function bodyIsAllDataRead(body: string, lang: ScriptLang): boolean {
  if (lang === 'sh') return false;
  try {
    const stmts = splitDataReadStatements(body, lang);
    if (stmts === null) return false;
    const cx: Ctx = { lang, prof: PROFILES[lang], vars: new Map() };
    for (const s of stmts) if (!statementIsDataRead(s, cx)) return false;
    return true;
  } catch {
    return false;
  }
}
