/**
 * #923 r7: the ONE shell-word tokenizer and lexical path normaliser shared by
 * both Action Guard planes — the live guard (src/defence/iron-dome/
 * tool-action-guard.ts imports this file) and the pre-tool hook's dist-outage
 * fallback (scripts/pre-tool-hook.mjs imports it). There is no second copy to
 * drift: a word is a word, and a path collapses the same way, on both planes.
 *
 * Why it exists: rounds r5/r6 split command text with ad-hoc character
 * classes that ignored shell escapes, and the normaliser turned every
 * backslash into `/`. `cp src ~/.claude/x\ y/../projects/p/s.jsonl` writes the
 * transcript (`x\ y` is ONE directory name, `x y`), but the split saw
 * `.claude/x\` and `y/../projects/…`, and the `..` collapse never saw the
 * directory the shell writes. The fix is structural: tokenise the way the
 * shell does, unescape, and only then collapse `.`/`..` on each whole word.
 *
 * Scope — POSIX-ish word splitting, as bash parses a command line:
 *   - outside quotes, `\c` is the literal `c`; `\<newline>` is a line
 *     continuation (removed); a trailing lone `\` is a literal backslash;
 *   - single quotes are literal to the next `'`;
 *   - double quotes keep everything literal except `\` before `$`, backtick,
 *     `"`, `\` or newline (the newline pair is removed);
 *   - bash's ANSI-C `$'…'` is decoded and `$"…"` is read as `"…"`;
 *   - words end at unquoted blanks (space, tab) and operators
 *     (`; & | < > ( )`, newline, backtick).
 * NOT modelled by `shellTokens` / `shellWords` (callers must not assume
 * them): parameter / command / arithmetic expansion, globbing, brace
 * expansion, aliases, `#` comments (a `#` is kept as a literal word
 * character, which only ever adds words). r10: `expansionWords` marks where
 * those expansions sit inside a word, and `claudeWordExpands` is the shared
 * refusal of a `.claude` path the shell would compute (see below).
 *
 * Plain ESM, no dependencies: it must load when dist/ is missing.
 */

/** Operators, longest first so `&&` wins over `&`. */
const OPS = ['<<<', '&>>', ';;&', '&&', '||', '|&', ';;', ';&', '>>', '>|', '>&', '<<', '<&', '<>', '&>', ';', '&', '|', '<', '>', '(', ')', '\n', '`'];
const OP_START = new Set(OPS.map((o) => o[0]));
const BLANK = new Set([' ', '\t']);

const ANSI_SIMPLE = { a: '\x07', b: '\b', e: '\x1b', E: '\x1b', f: '\f', n: '\n', r: '\r', t: '\t', v: '\v', '\\': '\\', "'": "'", '"': '"', '?': '?' };
const OCTAL_RE = /^[0-7]{1,3}/;
const HEX2_RE = /^[0-9a-fA-F]{1,2}/;
const HEX4_RE = /^[0-9a-fA-F]{1,4}/;
const HEX8_RE = /^[0-9a-fA-F]{1,8}/;

/**
 * Decode bash ANSI-C quoting starting just after `$'`. Returns the decoded
 * text and the index after the closing quote, or `end: -1` when unterminated.
 */
function decodeAnsiC(s, start) {
  let out = '';
  let i = start;
  while (i < s.length) {
    const c = s[i];
    if (c === "'") return { text: nulCut(out), end: i + 1 };
    if (c !== '\\' || i + 1 >= s.length) { out += c; i++; continue; }
    const n = s[i + 1];
    if (Object.prototype.hasOwnProperty.call(ANSI_SIMPLE, n)) { out += ANSI_SIMPLE[n]; i += 2; continue; }
    const oct = s.slice(i + 1, i + 4).match(OCTAL_RE);
    if (oct) { out += String.fromCharCode(parseInt(oct[0], 8) & 0xff); i += 1 + oct[0].length; continue; }
    if (n === 'x') {
      const hex = s.slice(i + 2, i + 4).match(HEX2_RE);
      if (hex) { out += String.fromCharCode(parseInt(hex[0], 16)); i += 2 + hex[0].length; continue; }
    }
    if (n === 'u' || n === 'U') {
      const hex = s.slice(i + 2, i + 10).match(n === 'u' ? HEX4_RE : HEX8_RE);
      if (hex) {
        const cp = parseInt(hex[0], 16);
        out += cp <= 0x10ffff ? String.fromCodePoint(cp) : '';
        i += 2 + hex[0].length; continue;
      }
    }
    if (n === 'c' && i + 2 < s.length) { out += String.fromCharCode(s.charCodeAt(i + 2) & 0x1f); i += 3; continue; }
    out += c + n; i += 2;
  }
  return { text: nulCut(out), end: -1 };
}

/**
 * r11: bash drops everything after a NUL in a `$'…'` string (a C string
 * ends there): `$'.claude\0junk'/projects/…` is `.claude/projects/…`.
 */
function nulCut(t) {
  const z = t.indexOf('\u0000');
  return z < 0 ? t : t.slice(0, z);
}

/**
 * Tokenise `text` into words and operators.
 *
 * Each word is `{ type: 'word', value, bare }`: `value` is the word after
 * quote removal and unescaping; `bare` is only the characters that appeared
 * unquoted AND unescaped (so a caller can refuse a word whose live syntax —
 * `$`, `{`, `#` … — it does not model). Each operator is `{ type: 'op', value }`.
 * `complete` is false when a quote is left open; the open quote then runs to
 * the end of the text (so scanning still sees its contents).
 */
export function shellTokens(text) {
  const s = String(text ?? '');
  const tokens = [];
  let complete = true;
  let cur = '';
  let bare = '';
  let inWord = false;
  const flush = () => {
    if (inWord) tokens.push({ type: 'word', value: cur, bare });
    cur = ''; bare = ''; inWord = false;
  };
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (c === '\\') {
      if (i + 1 >= s.length) { cur += '\\'; inWord = true; i++; continue; }
      if (s[i + 1] === '\n') { i += 2; continue; }
      cur += s[i + 1]; inWord = true; i += 2; continue;
    }
    if (c === "'") {
      const j = s.indexOf("'", i + 1);
      inWord = true;
      if (j < 0) { cur += s.slice(i + 1); complete = false; i = s.length; continue; }
      cur += s.slice(i + 1, j); i = j + 1; continue;
    }
    if (c === '$' && s[i + 1] === "'") {
      const { text: t, end } = decodeAnsiC(s, i + 2);
      cur += t; bare += '$'; inWord = true;
      if (end < 0) { complete = false; i = s.length; } else i = end;
      continue;
    }
    if (c === '"' || (c === '$' && s[i + 1] === '"')) {
      if (c === '$') { bare += '$'; i++; }
      inWord = true;
      let j = i + 1;
      let closed = false;
      while (j < s.length) {
        const d = s[j];
        if (d === '"') { closed = true; break; }
        if (d === '\\' && j + 1 < s.length) {
          const n = s[j + 1];
          if (n === '\n') { j += 2; continue; }
          if (n === '$' || n === '`' || n === '"' || n === '\\') { cur += n; j += 2; continue; }
          cur += '\\'; j++; continue;
        }
        cur += d; j++;
      }
      if (!closed) { complete = false; i = s.length; } else i = j + 1;
      continue;
    }
    if (BLANK.has(c)) { flush(); i++; continue; }
    if (OP_START.has(c)) {
      flush();
      const op = OPS.find((o) => s.startsWith(o, i));
      tokens.push({ type: 'op', value: op });
      i += op.length;
      continue;
    }
    cur += c; bare += c; inWord = true; i++;
  }
  flush();
  return { tokens, complete };
}

/** A word that may itself be shell text (`bash -c '…'`, `"$(…)"`). */
const NESTED_SHELL_TEXT_RE = /[\s'"\\`$();&|<>]/;
const NESTED_DEPTH = 3;

/**
 * Every word of `text` as the shell would pass it to a command, unescaped.
 * A word that itself looks like shell text (it holds blanks, quotes, escapes
 * or operators — `bash -c 'cp a b'`, `"$(cp a b)"`) is also tokenised again,
 * up to three levels: that only ever ADDS candidate words, so a nested
 * command's operand is scanned as the nested shell would split it.
 */
export function shellWords(text, depth = 0) {
  const out = [];
  for (const t of shellTokens(text).tokens) {
    if (t.type !== 'word') continue;
    out.push(t.value);
    if (depth < NESTED_DEPTH && t.value !== text && NESTED_SHELL_TEXT_RE.test(t.value)) {
      out.push(...shellWords(t.value, depth + 1));
    }
  }
  return out;
}

/**
 * `p` with `.` and empty segments dropped and `..` collapsed, purely
 * lexically, on `/` only. `<home>/.claude/./projects/p/s.jsonl`,
 * `.claude//projects` and `.claude/x/../projects` all name the same file.
 * A backslash is an ordinary filename character on Linux and macOS
 * (`.claude/x\y/..` collapses `x\y`), never a separator: Windows-style paths
 * are not in scope. Callers pass ONE path or ONE already-unescaped shell word;
 * a symlink or a target reached after an earlier `cd` is not resolved.
 */
export function lexicalPathNormalise(p) {
  const s = String(p ?? '');
  const abs = s.startsWith('/');
  const out = [];
  for (const seg of s.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') {
      if (out.length > 0 && out[out.length - 1] !== '..') out.pop();
      else if (!abs) out.push('..');
      continue;
    }
    out.push(seg);
  }
  return (abs ? '/' : '') + out.join('/');
}

// ── #923 r10: words that the shell EXPANDS before the command sees them ─────
//
// `shellTokens` deliberately does not model expansion, so a word it returns is
// the text as typed. Bash runs `$((1))`, `$(printf 1)`, `` `printf 1` ``,
// `${v:-1y}`, `$v`, `<(…)`, globs and `{a,b}` BEFORE `cp` sees its operand:
// `.claude/x$((1))y/../projects/p/s.jsonl` writes `.claude/x1y/../projects/…`,
// the transcript, while the typed word never matches a path regex. The guard
// does not evaluate the shell; it refuses instead. `expansionWords` returns
// every word with each live expansion replaced by EXPANSION_MARK, and
// `claudeWordExpands` is true when any word carries a mark AFTER a literal
// `.claude`: the closed-set refusal both planes apply (no expansion is run).

/** Stand-in for text the shell computes; never valid in a command. */
export const EXPANSION_MARK = '\u0000';
const PARAM_START_RE = /[A-Za-z_0-9@*#?$!-]/;
const PARAM_NAME_RE = /^[A-Za-z_][A-Za-z_0-9]*|^[0-9@*#?$!-]/;

/** Index just past the `close` that balances the opener at `start - 1`. */
function skipBalanced(s, start, open, close) {
  let depth = 1;
  let i = start;
  while (i < s.length) {
    const c = s[i];
    if (c === '\\') { i += 2; continue; }
    if (c === "'") { const j = s.indexOf("'", i + 1); i = j < 0 ? s.length : j + 1; continue; }
    if (c === '"') {
      let j = i + 1;
      while (j < s.length && s[j] !== '"') j += s[j] === '\\' ? 2 : 1;
      i = j + 1; continue;
    }
    if (c === '`') { i = skipBacktick(s, i + 1); continue; }
    if (c === open) depth++;
    else if (c === close && --depth === 0) return i + 1;
    i++;
  }
  return s.length;
}

/** Index just past the backtick closing a substitution opened before `start`. */
function skipBacktick(s, start) {
  let i = start;
  while (i < s.length) {
    if (s[i] === '\\') { i += 2; continue; }
    if (s[i] === '`') return i + 1;
    i++;
  }
  return s.length;
}

/**
 * The live expansion at `s[i]` (`$…`, backtick, or mid-word `<(`/`>(`), or
 * null. Returns its end index and the shell text it runs (`body`), so callers
 * can scan that text as a command in its own right.
 */
function expansionAt(s, i, inDouble) {
  const c = s[i];
  if (c === '`') {
    const end = skipBacktick(s, i + 1);
    return { end, type: 'cmd', body: s.slice(i + 1, Math.max(i + 1, end - 1)) };
  }
  if ((c === '<' || c === '>') && !inDouble && s[i + 1] === '(') {
    const end = skipBalanced(s, i + 2, '(', ')');
    return { end, type: 'proc', body: s.slice(i + 2, Math.max(i + 2, end - 1)) };
  }
  if (c !== '$') return null;
  const n = s[i + 1];
  if (n === '(') {
    const end = skipBalanced(s, i + 2, '(', ')');
    return { end, type: s[i + 2] === '(' ? 'arith' : 'cmd', body: s.slice(i + 2, Math.max(i + 2, end - 1)) };
  }
  if (n === '{') {
    const end = skipBalanced(s, i + 2, '{', '}');
    return { end, type: 'brace-param', body: s.slice(i + 2, Math.max(i + 2, end - 1)) };
  }
  if (n !== undefined && PARAM_START_RE.test(n)) {
    const m = s.slice(i + 1).match(PARAM_NAME_RE);
    const len = m ? m[0].length : 1;
    return { end: i + 1 + len, type: 'param', name: s.slice(i + 1, i + 1 + len), body: '' };
  }
  return null;
}


/**
 * r11: the glob bracket expression `[…]` opening at `s[i]`, or null when the
 * `[` is literal (no closing `]` among plain unquoted characters). Only plain
 * contents are accepted, so the marked `value` is the same as it was in r10.
 */
function classAt(s, i) {
  let j = i + 1;
  let neg = false;
  if (s[j] === '!' || s[j] === '^') { neg = true; j++; }
  const from = j;
  if (s[j] === ']') j++;
  while (j < s.length && s[j] !== ']') {
    if (/[\s'"\\`$*?[{/;&|<>()]/.test(s[j])) return null;
    j++;
  }
  if (j >= s.length || j === from) return null;
  return { end: j + 1, neg, set: s.slice(from, j) };
}

/** Split `t` at every top-level `|` (extglob alternatives). */
function splitAlternatives(t) {
  const out = [];
  let depth = 0;
  let cur = '';
  for (const ch of t) {
    if (ch === '(') depth++;
    else if (ch === ')') depth--;
    if (ch === '|' && depth === 0) { out.push(cur); cur = ''; continue; }
    cur += ch;
  }
  out.push(cur);
  return out;
}

/**
 * Tokenise `text` into words and operators for the expansion scans. Each word
 * is `{ type: 'word', value, expands, parts, lit }`:
 *   - `value` is the word with quotes removed and escapes honoured, every live
 *     expansion (and unquoted glob / brace syntax) replaced by EXPANSION_MARK;
 *   - `parts` (r11) is the SAME word as the shell assembles it: literal text
 *     runs (`lit`), unquoted glob items (`star`, `one`, `class`, extglob
 *     `ext`), brace syntax (`bo`, `comma`, `bc`), and each expansion (`exp`,
 *     with its `type` and `body`), in order, so the pieces can be JOINED;
 *   - `lit` is the word's text with quotes removed, expansions verbatim.
 * `nested` is every command-substitution body and every word that itself
 * looks like shell text, for the callers' rescans.
 */
function parseExpansionText(text) {
  const s = String(text ?? '');
  const seq = [];
  const nested = [];
  let cur = '';
  let lit = '';
  let expands = false;
  let inWord = false;
  let parts = [];
  const addLit = (t) => {
    if (!t) return;
    const last = parts[parts.length - 1];
    if (last && last.k === 'lit') last.t += t;
    else parts.push({ k: 'lit', t });
  };
  const flush = () => {
    if (inWord) {
      seq.push({ type: 'word', value: cur, expands, parts, lit });
      if (lit !== s && NESTED_SHELL_TEXT_RE.test(lit)) nested.push(lit);
    }
    cur = ''; lit = ''; expands = false; inWord = false; parts = [];
  };
  const mark = (e, from, quoted) => {
    cur += EXPANSION_MARK; lit += s.slice(from, e.end); expands = true; inWord = true;
    parts.push({ k: 'exp', type: e.type, name: e.name, body: e.body, quoted });
    if (e.body) nested.push(e.body);
    return e.end;
  };
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (c === '\\') {
      if (i + 1 >= s.length) { cur += '\\'; lit += '\\'; addLit('\\'); inWord = true; i++; continue; }
      if (s[i + 1] === '\n') { i += 2; continue; }
      cur += s[i + 1]; lit += s[i + 1]; addLit(s[i + 1]); inWord = true; i += 2; continue;
    }
    if (c === "'") {
      const j = s.indexOf("'", i + 1);
      const t = j < 0 ? s.slice(i + 1) : s.slice(i + 1, j);
      cur += t; lit += t; addLit(t); inWord = true; i = j < 0 ? s.length : j + 1; continue;
    }
    if (c === '$' && s[i + 1] === "'") {
      const { text: t, end } = decodeAnsiC(s, i + 2);
      cur += t; lit += t; addLit(t); inWord = true; i = end < 0 ? s.length : end; continue;
    }
    if (c === '"' || (c === '$' && s[i + 1] === '"')) {
      let j = c === '$' ? i + 2 : i + 1;
      inWord = true;
      while (j < s.length && s[j] !== '"') {
        const d = s[j];
        if (d === '\\' && j + 1 < s.length) {
          const n = s[j + 1];
          if (n === '\n') { j += 2; continue; }
          if (n === '$' || n === '`' || n === '"' || n === '\\') { cur += n; lit += n; addLit(n); j += 2; continue; }
          cur += '\\'; lit += '\\'; addLit('\\'); j++; continue;
        }
        const e = expansionAt(s, j, true);
        if (e) { j = mark(e, j, true); continue; }
        cur += d; lit += d; addLit(d); j++;
      }
      i = j + 1;
      continue;
    }
    const e = expansionAt(s, i, false);
    if (e && (c !== '<' && c !== '>' ? true : inWord)) { i = mark(e, i, false); continue; }
    // r11: extglob `@(…)`, `+(…)`, `!(…)`, `?(…)`, `*(…)` is one glob item
    // (bash -O extglob); without extglob it is a syntax error, never a write.
    if ('?*+@!'.includes(c) && s[i + 1] === '(') {
      const end = skipBalanced(s, i + 2, '(', ')');
      const body = s.slice(i + 2, Math.max(i + 2, end - 1));
      cur += EXPANSION_MARK; lit += s.slice(i, end); expands = true; inWord = true;
      parts.push({ k: 'ext', op: c, alts: splitAlternatives(body) });
      i = end; continue;
    }
    if (BLANK.has(c)) { flush(); i++; continue; }
    if (OP_START.has(c)) {
      flush();
      const op = OPS.find((o) => s.startsWith(o, i));
      seq.push({ type: 'op', value: op });
      i += op.length;
      continue;
    }
    if (c === '[') {
      const cls = classAt(s, i);
      cur += EXPANSION_MARK; expands = true; inWord = true;
      if (cls) {
        cur += s.slice(i + 1, cls.end); lit += s.slice(i, cls.end);
        parts.push({ k: 'class', neg: cls.neg, set: cls.set });
        i = cls.end; continue;
      }
      lit += c; addLit(c); i++; continue;
    }
    if (c === '*' || c === '?' || c === '{') {
      cur += EXPANSION_MARK; lit += c; expands = true; inWord = true;
      parts.push({ k: c === '*' ? 'star' : c === '?' ? 'one' : 'bo' });
      i++; continue;
    }
    if (c === '}' || c === ',') {
      cur += c; lit += c; inWord = true;
      parts.push({ k: c === '}' ? 'bc' : 'comma' });
      i++; continue;
    }
    cur += c; lit += c; addLit(c); inWord = true; i++;
  }
  flush();
  return { seq, nested };
}

/**
 * Every word of `text` as `{ value, expands }`: `value` is the word with
 * quotes removed and escapes honoured (as `shellTokens` gives it), except that
 * each live expansion — `$name`, `${…}`, `$(…)`, `$((…))`, backticks,
 * mid-word `<(…)`/`>(…)`, and unquoted glob (`* ? [`, extglob) or brace (`{`)
 * characters — is replaced by EXPANSION_MARK; `expands` is true when it has
 * one. Unlike `shellTokens`, an expansion stays INSIDE its word
 * (`x$(printf 1)y` is one word). The body of every command substitution, and
 * any word that itself looks like shell text (`bash -c '…'`), is scanned
 * again (up to three levels), so a nested command's words are included.
 */
export function expansionWords(text, depth = 0) {
  const { seq, nested } = parseExpansionText(text);
  const out = seq.filter((t) => t.type === 'word').map((w) => ({ value: w.value, expands: w.expands }));
  if (depth < NESTED_DEPTH) {
    for (const t of nested) out.push(...expansionWords(t, depth + 1));
  }
  return out;
}

/** r11: per-call memo of parses, so one body is tokenised once per scan. */
let parseMemo = null;
function parseCached(text) {
  if (!parseMemo) return parseExpansionText(text);
  let hit = parseMemo.get(text);
  if (!hit) { hit = parseExpansionText(text); parseMemo.set(text, hit); }
  return hit;
}

/** Every parsed level of `text`: the text itself, then each nested rescan. */
function parsedLevels(text, depth = 0, out = [], seen = new Set()) {
  // An identical nested text judges identically (assignments are collected
  // across the whole scan), so each distinct text is one level.
  if (seen.has(text)) return out;
  seen.add(text);
  const level = parseCached(text);
  out.push(level);
  if (depth < NESTED_DEPTH) for (const t of level.nested) parsedLevels(t, depth + 1, out, seen);
  return out;
}

/** A transcript tail below `.claude`: `projects/…/*.jsonl` or `…/subagents`. */
const TRANSCRIPT_TAIL_RE = /(?:^|\/)projects\/+(?:[^\s;&|<>'"`]*?\/)?(?:subagents(?=$|\/)|[^\/]*\.jsonl\b)/i;

/**
 * r11: the guard's CLAUDE_TRANSCRIPT_PATH_RE (tool-action-guard.ts), equal
 * source held by shell-words-923.test.ts. The JOINED candidate of a word is
 * judged by the very regex a literal path is.
 */
export const CLAUDE_TRANSCRIPT_NAMED_RE = /\.claude[\\/]+projects[\\/]+(?:[^\s;&|<>'"`]*?[\\/])?(?:subagents(?=$|[\\/\s;&|<>'"`)])|[^\s;&|<>'"`\\/]*\.jsonl\b)/i;

/**
 * True when the directory directly above a literal transcript tail
 * (`projects/…/*.jsonl`) is one the shell computes: `.c[l]aude/projects/…`,
 * `${D}aude/projects/…`, `.cla$(…)/projects/…`, `$C/projects/…`, or a `..`
 * that climbs out of an expansion. That directory may be `.claude` once
 * expanded, so the typed text cannot say the word is not a transcript.
 */
function computedTranscriptParent(value) {
  for (const s of [value, lexicalPathNormalise(value)]) {
    const m = TRANSCRIPT_TAIL_RE.exec(s);
    if (!m) continue;
    const before = s.slice(0, m.index);
    const parent = before.split('/').pop() ?? '';
    if (parent.includes(EXPANSION_MARK)) return true;
    if (parent === '..' && before.includes(EXPANSION_MARK)) return true;
    // `$(…)/../projects/…`: the collapse popped the expansion itself.
    if (s !== value && !before.includes(EXPANSION_MARK)
      && value.slice(0, value.search(/(?:^|\/)projects\//i) + 1).includes(EXPANSION_MARK)) return true;
  }
  return false;
}

/**
 * A computed path ending in a transcript leaf (`$C/p/s.jsonl`, `$C/subagents`).
 * Judged only in a command that also names `.claude` literally, where `$C` may
 * have been assigned it (`C=~/.claude/projects; cp s $C/p/s.jsonl`).
 */
const COMPUTED_TRANSCRIPT_LEAF_RE = /\u0000.*(?:\.jsonl\b|(?:^|\/)subagents(?=$|\/))/i;

// ── #923 r11: JOIN the pieces ───────────────────────────────────────────────
//
// r10 judged each piece of a word on its own: the marked word, and the body
// of every expansion as an unrelated word. The shell joins them before `cp`
// runs: `/h/.cla${u:-ude/projects/p/s.jsonl}`, `/h/.cla$(printf %s ude/…)`,
// `A=/h/.cla; B=ude/projects/p/s.jsonl; cp s $A$B` and `/h/.cl[a]ude/
// proj[e]cts/p/s.jsonl` all write the transcript while no single piece names
// it. r11 rebuilds the word the way the shell assembles it, WITHOUT running
// anything: brace alternatives are expanded; each expansion is replaced in
// turn by every value the command itself spells for it (an assignment —
// `NAME=`, `export`/`local`/`declare`, `NAME+=`, `printf -v`, `read <<<`,
// `for NAME in` — a `${v:-word}` word, what an `echo`/`printf` body prints,
// the body text itself, or empty); and the cross-product of those pieces is
// judged by the transcript regex (glob items by a segment matcher that knows
// `*`/`?`/`[…]`/extglob, including that they never match a leading `.`). When
// a word carries a parameter or command expansion and the command anywhere
// holds both a `.claude`-ish fragment (`.cla`, `claude`, `ude/`) and a
// `projects`/`.jsonl`/`subagents` fragment, the word is refused outright: the
// value may be assembled where the guard cannot follow (`printf -v`, `read`,
// a loop), and over-denying a closed set is the accepted cost.

/** Glob items inside a candidate (plain strings are literal text). */
const STAR = { g: 'star' };
const ONE = { g: 'one' };
const CAND_CAP = 256;
const BRACE_CAP = 64;
const BUDGET = 4096;
/**
 * Total candidate pieces one scan may build. Past it the scan stops and the
 * closed-set rule decides (refused when the command holds the `.claude`-ish
 * and `projects`/`.jsonl` fragments): pathological padding cannot make the
 * guard slow, and cannot make it pass a command it could not finish judging.
 */
const WORK_BUDGET = 20000;
/** Charge `n` units of work; true once the scan is over budget. */
function spend(ctx, n = 1) {
  ctx.work += n;
  if (ctx.work > WORK_BUDGET) ctx.overflow = true;
  return ctx.overflow;
}
const CLAUDEISH_RE = /\.cla|claude|ude\//i;
const PROJECTISH_RE = /projects|\.jsonl|subagents/i;
const ASSIGN_RE = /^([A-Za-z_][A-Za-z0-9_]*)(\+?)=/;

/** Decode `\…` escapes as `printf`'s format, `%b` and `echo -e` do. */
function decodeEscapes(t) {
  return decodeAnsiC(`${String(t).replace(/'/g, "\\'")}'`, 0).text;
}

/** A word's parts as plain text when it has no expansion or glob, else null. */
function partsText(parts) {
  let t = '';
  for (const p of parts) {
    if (p.k === 'lit') t += p.t;
    else if (p.k === 'bc') t += '}';
    else if (p.k === 'comma') t += ',';
    else return null;
  }
  return t;
}

/** Concatenate two candidates (arrays of strings and glob items). */
function cat(a, b) {
  const out = a.slice();
  for (const x of b) {
    if (typeof x === 'string' && typeof out[out.length - 1] === 'string') out[out.length - 1] += x;
    else out.push(x);
  }
  return out;
}

/** Cross-product of candidate lists, `sep` between, capped. */
function product(lists, sep, ctx) {
  let acc = [[]];
  lists.forEach((opts, n) => {
    const next = [];
    for (const a of acc) {
      for (const o of opts) {
        if (next.length >= CAND_CAP) { ctx.overflow = true; break; }
        if (spend(ctx)) break;
        next.push(cat(n > 0 && sep ? cat(a, [sep]) : a, o));
      }
    }
    acc = next;
  });
  return acc;
}

/** `{a..e}` / `{1..3}` sequence alternatives, or null. */
function sequenceAlternatives(inner) {
  const t = partsText(inner);
  const m = t === null ? null : /^(-?\d+|[A-Za-z])\.\.(-?\d+|[A-Za-z])(?:\.\.(-?\d+))?$/.exec(t);
  if (!m) return null;
  const num = /^-?\d+$/.test(m[1]) && /^-?\d+$/.test(m[2]);
  if (!num && (/\d/.test(m[1]) || /\d/.test(m[2]))) return null;
  const a = num ? Number(m[1]) : m[1].charCodeAt(0);
  const b = num ? Number(m[2]) : m[2].charCodeAt(0);
  const step = Math.max(1, Math.abs(Number(m[3] ?? 1)));
  const out = [];
  for (let v = a; (a <= b ? v <= b : v >= b) && out.length < BRACE_CAP; v += a <= b ? step : -step) {
    out.push([{ k: 'lit', t: num ? String(v) : String.fromCharCode(v) }]);
  }
  return out;
}

/** Brace expansion of a word's parts (bash does it first): every variant. */
function braceExpand(parts, ctx, budget = { n: 0 }) {
  for (let i = 0; i < parts.length; i++) {
    if (parts[i].k !== 'bo') continue;
    let depth = 0;
    let close = -1;
    const commas = [];
    for (let j = i + 1; j < parts.length; j++) {
      const k = parts[j].k;
      if (k === 'bo') depth++;
      else if (k === 'bc') { if (depth === 0) { close = j; break; } depth--; }
      else if (k === 'comma' && depth === 0) commas.push(j);
    }
    if (close < 0) continue;
    const inner = parts.slice(i + 1, close);
    let alts = null;
    if (commas.length > 0) {
      alts = [];
      let from = i + 1;
      for (const c of [...commas, close]) { alts.push(parts.slice(from, c)); from = c + 1; }
    } else alts = sequenceAlternatives(inner);
    if (!alts) continue;
    const out = [];
    for (const alt of alts) {
      for (const v of braceExpand([...parts.slice(0, i), ...alt, ...parts.slice(close + 1)], ctx, budget)) {
        if (++budget.n > BRACE_CAP) { ctx.overflow = true; return out; }
        out.push(v);
      }
    }
    return out;
  }
  // Unmatched braces are literal text.
  return [parts.map((p) => (p.k === 'bo' ? { k: 'lit', t: '{' } : p.k === 'bc' ? { k: 'lit', t: '}' } : p.k === 'comma' ? { k: 'lit', t: ',' } : p))];
}

/** Every value the command itself spells for a word (its parts). */
function wordCandidates(parts, ctx, depth) {
  if (spend(ctx, parts.length)) return [[]];
  const out = [];
  for (const variant of braceExpand(parts, ctx)) {
    const lists = variant.map((p) => partCandidates(p, ctx, depth));
    for (const c of product(lists, '', ctx)) {
      if (out.length >= CAND_CAP) { ctx.overflow = true; break; }
      out.push(c);
    }
  }
  return out;
}

/** Candidates of a text that is ONE word in its context (`${v:-a b}`). */
function textCandidates(text, ctx, depth) {
  const words = parseCached(text).seq.filter((t) => t.type === 'word');
  if (words.length === 0) return [[]];
  return product(words.map((w) => wordCandidates(w.parts, ctx, depth + 1)), ' ', ctx);
}

function partCandidates(p, ctx, depth) {
  switch (p.k) {
    case 'lit': return [[p.t]];
    case 'star': return [[STAR]];
    case 'one': return [[ONE]];
    case 'class': return [[{ g: 'class', neg: p.neg, set: p.set }]];
    case 'ext':
      if (p.op === '!') return [[STAR]];
      return [...p.alts.flatMap((a) => textCandidates(a, ctx, depth)), ...(p.op === '?' || p.op === '*' ? [[]] : [])];
    case 'exp': return expansionCandidates(p, ctx, depth);
    default: return [[]];
  }
}

/** Values a parameter takes in this command, plus unset (empty). */
function nameCandidates(name, ctx, depth) {
  const key = `${name}\u0000${depth}`;
  if (ctx.names.has(key)) return ctx.names.get(key);
  const out = [[]];
  const all = ctx.assign.get(name);
  if (!all || depth >= NESTED_DEPTH || ctx.overflow) return out;
  // The first and last few assignments: a padded run of `A=…` cannot fan out.
  const vals = all.length > 16 ? [...all.slice(0, 8), ...all.slice(-8)] : all;
  const base = [];
  const appends = [];
  for (const v of vals) {
    const cands = v.printf ? printfCandidates(v.printf, v.args, ctx, depth + 1) : wordCandidates(v.parts, ctx, depth + 1);
    const into = v.append ? appends : base;
    for (const c of cands) if (into.length < CAND_CAP) into.push(c);
  }
  for (const b of base) if (out.length < CAND_CAP) out.push(b);
  for (const a of appends) for (const b of [[], ...base]) if (out.length < CAND_CAP && !spend(ctx)) out.push(cat(b, a));
  ctx.names.set(key, out);
  return out;
}

/** Every choice of one candidate per argument (each list trimmed), capped. */
function choices(lists, cap = 32) {
  let acc = [[]];
  for (const opts of lists) {
    const next = [];
    for (const a of acc) for (const o of opts.slice(0, 4)) if (next.length < cap) next.push([...a, o]);
    acc = next;
  }
  return acc;
}

/** What `printf FMT ARGS…` prints, for each candidate of each word. */
function printfCandidates(fmtParts, argParts, ctx, depth) {
  const fmts = wordCandidates(fmtParts, ctx, depth).filter((c) => c.every((x) => typeof x === 'string'));
  const args = argParts.map((a) => wordCandidates(a, ctx, depth));
  const out = [];
  for (const f of fmts.slice(0, 4)) {
    for (const argv of choices(args)) out.push(...formatPrintf(decodeEscapes(f.join('')), argv));
  }
  return out.length ? out : [[]];
}

/** Apply a printf format to one choice of arguments (`%s`/`%b`, reused). */
function formatPrintf(fmt, argv) {
  const pieces = fmt.split(/(%[-#0 +']*[0-9]*(?:\.[0-9]*)?[a-zA-Z%])/);
  const convs = pieces.filter((x, n) => n % 2 === 1 && x !== '%%').length;
  let out = [];
  let k = 0;
  do {
    pieces.forEach((x, n) => {
      if (n % 2 === 0) { out = cat(out, [x]); return; }
      if (x === '%%') { out = cat(out, ['%']); return; }
      const a = argv[k++] ?? [];
      out = cat(out, x.endsWith('b') && a.every((y) => typeof y === 'string') ? [decodeEscapes(a.join(''))] : a);
    });
  } while (convs > 0 && k < argv.length);
  // Also the plain join of the arguments (`printf %s a b` is `ab`).
  return [out, argv.reduce((acc, a) => cat(acc, a), [])];
}

/** What a command substitution prints: `echo`/`printf` modelled, else its words. */
function commandOutputCandidates(body, ctx, depth) {
  const out = [[], [body]];
  if (depth >= NESTED_DEPTH) return out;
  for (const stmt of statements(parseCached(body).seq).slice(0, 4)) {
    const words = stmt.words;
    if (words.length === 0) continue;
    const head = partsText(words[0].parts) ?? '';
    let args = words.slice(1);
    if (head === 'echo') {
      let esc = false;
      while (args.length && /^-[neE]+$/.test(partsText(args[0].parts) ?? '')) { esc = esc || /e/.test(partsText(args[0].parts)); args = args.slice(1); }
      for (const c of product(args.map((w) => wordCandidates(w.parts, ctx, depth + 1).slice(0, 8)), ' ', ctx)) {
        out.push(c, ...(esc && c.every((x) => typeof x === 'string') ? [[decodeEscapes(c.join(''))]] : []));
      }
      continue;
    }
    if (head === 'printf' && args.length && partsText(args[0].parts) !== '-v') {
      out.push(...printfCandidates(args[0].parts, args.slice(1).map((w) => w.parts), ctx, depth + 1));
      continue;
    }
    for (const w of words) out.push(...wordCandidates(w.parts, ctx, depth + 1).slice(0, 8));
    out.push(...product(args.map((w) => wordCandidates(w.parts, ctx, depth + 1).slice(0, 8)), '', ctx));
  }
  return out.slice(0, CAND_CAP);
}

/** `${…}`: the parameter's values, plus its `:-`/`:=`/`:+`/`:?` word. */
function braceParamCandidates(body, ctx, depth) {
  const m = /^([#!]?)([A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-])(.*)$/s.exec(body);
  const out = [[], [body]];
  if (!m) return out;
  out.push(...nameCandidates(m[2], ctx, depth));
  const op = /^(:?[-=+?])(.*)$/s.exec(m[3]);
  if (op) out.push(...textCandidates(op[2], ctx, depth));
  else {
    // `${v/pat/rep}`, `${v#pre}`, `${v:1:2}`…: the pieces it could leave.
    const rep = /^\/\/?[^/]*\/(.*)$/s.exec(m[3]);
    if (rep) out.push(...textCandidates(rep[1], ctx, depth));
  }
  return out.slice(0, CAND_CAP);
}

function expansionCandidates(p, ctx, depth) {
  if (depth >= NESTED_DEPTH || ctx.overflow) return [[]];
  switch (p.type) {
    case 'arith': return [['1']];
    case 'proc': return [['/dev/fd/63']];
    case 'param': return nameCandidates(p.name, ctx, depth);
    case 'brace-param': return braceParamCandidates(p.body, ctx, depth);
    case 'cmd': return commandOutputCandidates(p.body, ctx, depth);
    default: return [[]];
  }
}

/** Statements of a token sequence: `{ words, redirects }` split at separators. */
function statements(seq) {
  const out = [];
  let words = [];
  let herestrings = [];
  let redirect = null;
  const end = () => { if (words.length || herestrings.length) out.push({ words, herestrings }); words = []; herestrings = []; };
  for (const t of seq) {
    if (t.type === 'op') {
      if (/^(?:<<<|<<|>>|>\||>&|<&|<>|&>>|&>|<|>)$/.test(t.value)) { redirect = t.value; continue; }
      end(); redirect = null; continue;
    }
    if (redirect) { if (redirect === '<<<') herestrings.push(t); redirect = null; continue; }
    words.push(t);
  }
  end();
  return out;
}

/** Same-command assignments: every way the command itself sets a NAME. */
function collectAssignments(levels) {
  const assign = new Map();
  const add = (name, v) => { if (!assign.has(name)) assign.set(name, []); assign.get(name).push(v); };
  for (const { seq } of levels) {
    for (const { words, herestrings } of statements(seq)) {
      for (const w of words) {
        const first = w.parts[0];
        const m = first && first.k === 'lit' ? ASSIGN_RE.exec(first.t) : null;
        if (!m) continue;
        const rest = first.t.slice(m[0].length);
        add(m[1], { append: m[2] === '+', parts: [...(rest ? [{ k: 'lit', t: rest }] : []), ...w.parts.slice(1)] });
      }
      const texts = words.map((w) => partsText(w.parts));
      const head = texts.findIndex((t) => t !== null && !ASSIGN_RE.test(t));
      if (head < 0) continue;
      const cmd = texts[head];
      if (cmd === 'printf') {
        for (let n = head + 1; n < words.length; n++) {
          const t = texts[n];
          const v = t === '-v' ? texts[n + 1] : t && t.startsWith('-v') ? t.slice(2) : null;
          if (v && /^[A-Za-z_]\w*$/.test(v)) {
            const at = t === '-v' ? n + 2 : n + 1;
            if (words[at]) add(v, { printf: words[at].parts, args: words.slice(at + 1).map((x) => x.parts) });
            break;
          }
        }
      }
      if (cmd === 'read') {
        const names = texts.slice(head + 1).filter((t) => t && /^[A-Za-z_]\w*$/.test(t));
        for (const name of names) for (const h of herestrings) add(name, { parts: h.parts });
      }
      if (cmd === 'for' && texts[head + 2] === 'in' && /^[A-Za-z_]\w*$/.test(texts[head + 1] ?? '')) {
        for (const w of words.slice(head + 3)) if (partsText(w.parts) !== 'do') add(texts[head + 1], { parts: w.parts });
      }
    }
  }
  return assign;
}

// ── the glob matcher: can this glob candidate expand to a transcript? ──────

function classSource(it) {
  if (/\[:/.test(it.set)) return '[^/]';
  const body = it.set.replace(/[\\\]\[^]/g, (ch) => `\\${ch}`);
  return `[${it.neg ? '^/' : ''}${body}]`;
}

function itemSource(it) {
  if (typeof it === 'string') return it.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
  if (it.g === 'star') return '[^/]*';
  if (it.g === 'one') return '[^/]';
  return classSource(it);
}

function segmentRegex(seg) {
  try { return new RegExp(`^${seg.map(itemSource).join('')}$`, 'i'); } catch { return /^[^/]*$/; }
}

/** Glob items never match a leading `.` (no dotglob); a class may, over-approximated. */
function leadingDotOk(seg, dotglob) {
  const first = seg[0];
  if (first === undefined) return false;
  if (typeof first === 'string') return first[0] === '.';
  return dotglob || first.g === 'class';
}

function segmentMatches(seg, name, dotglob) {
  if (name.startsWith('.') && !leadingDotOk(seg, dotglob)) return false;
  return segmentRegex(seg).test(name);
}

/** One item accepts the character `ch`. */
function itemAccepts(it, ch) {
  if (typeof it === 'string') return it.toLowerCase() === ch.toLowerCase();
  if (it.g === 'one') return true;
  try { return new RegExp(`^${classSource(it)}$`, 'i').test(ch); } catch { return true; }
}

/** The segment may name a file whose name holds `.jsonl` at a word boundary. */
function segmentMayBeJsonl(seg) {
  if (seg.some((it) => typeof it !== 'string' && it.g === 'star')) return true;
  const chars = seg.flatMap((it) => (typeof it === 'string' ? [...it] : [it]));
  const want = '.jsonl';
  for (let k = 0; k + want.length <= chars.length; k++) {
    if (![...want].every((ch, m) => itemAccepts(chars[k + m], ch))) continue;
    const next = chars[k + want.length];
    if (next === undefined || ['.', '-', '~', '#', ' '].some((ch) => itemAccepts(next, ch))) return true;
  }
  return false;
}

/** True when a candidate holding glob items may expand to a transcript path. */
function globMayNameTranscript(items, dotglob) {
  const segs = [[]];
  for (const it of items) {
    if (typeof it !== 'string') { segs[segs.length - 1].push(it); continue; }
    const pieces = it.split('/');
    pieces.forEach((piece, n) => {
      if (n > 0) segs.push([]);
      if (piece) segs[segs.length - 1].push(piece);
    });
  }
  const norm = [];
  for (const seg of segs) {
    const text = seg.every((x) => typeof x === 'string') ? seg.join('') : null;
    if (text === '' || text === '.') continue;
    if (text === '..') { norm.pop(); continue; }
    norm.push(seg);
  }
  for (let i = 0; i + 2 < norm.length; i++) {
    if (!segmentMatches(norm[i], '.claude', dotglob) || !segmentMatches(norm[i + 1], 'projects', dotglob)) continue;
    if (norm.slice(i + 2).some((seg) => segmentMayBeJsonl(seg) || segmentMatches(seg, 'subagents', dotglob))) return true;
  }
  return false;
}

/** The transcript named-check on ONE joined candidate. */
function candidateNamesTranscript(items, dotglob) {
  if (items.every((x) => typeof x === 'string')) {
    const t = items.join('');
    return CLAUDE_TRANSCRIPT_NAMED_RE.test(t) || CLAUDE_TRANSCRIPT_NAMED_RE.test(lexicalPathNormalise(t));
  }
  return globMayNameTranscript(items, dotglob);
}

/** A parameter or command expansion: its value may come from anywhere. */
const isValueExpansion = (p) => p.k === 'exp' && p.type !== 'arith';

/**
 * The word's expansions all sit BEFORE a literal `.claude` that is followed
 * only by literal text without `..`: the regex on the typed text judges that
 * tail exactly (`$HOME/.claude/settings.json`), so no join is needed.
 */
function literalClaudeTail(parts) {
  let last = -1;
  parts.forEach((p, n) => { if (p.k !== 'lit') last = n; });
  const tail = parts.slice(last + 1);
  const t = tail.map((p) => p.t).join('');
  return /\.claude/i.test(t) && !/(?:^|\/)\.\.(?:\/|$)/.test(t);
}

/** Commands that copy a source INTO a directory operand (`cp s dir/`, `-t dir`). */
const INTO_DIR_COMMANDS = new Set(['cp', 'mv', 'install', 'ln']);

/**
 * r11 sweep: `cp src <home>/.claude/projects/p/` and `cp -t <dir> src` write
 * `<dir>/<basename of src>`: the file the shell-level write names is
 * COMPOSED by the command from two operands. Every (destination, source)
 * candidate pair is joined as `dest/basename(src)` and judged like any other
 * joined word. `budget` is shared with the caller.
 */
function intoDirectoryMayNameTranscript(levels, ctx, dotglob, budget) {
  for (const { seq } of levels) {
    for (const { words } of statements(seq)) {
      const texts = words.map((w) => partsText(w.parts));
      const at = texts.findIndex((t) => t !== null && INTO_DIR_COMMANDS.has(t));
      if (at < 0) continue;
      let dest = null;
      const operands = [];
      for (let n = at + 1; n < words.length; n++) {
        const t = texts[n];
        if (t === '--target-directory' || (t && /^-[A-Za-z]*t$/.test(t))) { dest = words[n + 1] ?? null; n++; continue; }
        if (t && t.startsWith('--target-directory=')) { dest = { parts: [{ k: 'lit', t: t.slice(19) }] }; continue; }
        if (t && /^-[A-Za-z]*t./.test(t) && !t.startsWith('--')) { dest = { parts: [{ k: 'lit', t: t.slice(t.indexOf('t') + 1) }] }; continue; }
        if (t && t.startsWith('-')) continue;
        operands.push(words[n]);
      }
      const explicit = Boolean(dest);
      if (!dest) { if (operands.length < 2) continue; dest = operands.pop(); }
      // Only a DIRECTORY destination composes a new name: `-t dir`, `dir/`,
      // or a last segment without a dot (Claude Code's project directories
      // encode `.` as `-`). `cp s …/memory/MEMORY.md` names its own file.
      const dests = wordCandidates(dest.parts, ctx, 0).filter((d) => {
        if (explicit) return true;
        const last = d[d.length - 1];
        if (typeof last !== 'string') return false;
        return last.endsWith('/') || !last.split('/').pop().includes('.');
      });
      for (const src of operands) {
        for (const sc of wordCandidates(src.parts, ctx, 0).slice(0, 16)) {
          const last = sc[sc.length - 1];
          const base = typeof last === 'string' ? [last.split('/').pop()] : [last];
          for (const d of dests) {
            if (++budget.n > BUDGET) { ctx.overflow = true; return false; }
            if (candidateNamesTranscript(cat(d, ['/', ...base]), dotglob)) return true;
          }
        }
      }
    }
  }
  return false;
}

/**
 * #923 r11: true when some word of `text` — at any nesting level — JOINED as
 * the shell joins it (literal parts + every value the command spells for each
 * expansion, brace alternatives, glob items) may name a Claude transcript, or
 * when a word carries a parameter/command expansion in a command that holds
 * both a `.claude`-ish and a `projects`/`.jsonl` fragment anywhere.
 */
export function claudeJoinedWordMayBeTranscript(text) {
  parseMemo = new Map();
  try {
    return joinedScan(String(text ?? ''));
  } catch {
    // A scan that cannot finish cannot clear the command: closed set.
    return true;
  } finally {
    parseMemo = null;
  }
}

function joinedScan(raw) {
  const levels = parsedLevels(raw);
  const ctx = { assign: collectAssignments(levels), overflow: false, work: 0, names: new Map() };
  const dotglob = /dotglob|GLOBIGNORE/.test(raw);
  const words = levels.flatMap((l) => l.seq.filter((t) => t.type === 'word'));
  const evidenceText = [raw, ...words.map((w) => w.value.split(EXPANSION_MARK).join(''))].join('\n');
  const evidence = CLAUDEISH_RE.test(evidenceText) && PROJECTISH_RE.test(evidenceText);
  const budget = { n: 0 };
  const judged = new Set();
  for (const w of words) {
    if (w.parts.every((p) => p.k === 'lit')) continue;
    const key = JSON.stringify(w.parts);
    if (judged.has(key)) continue;
    judged.add(key);
    if (evidence && w.parts.some(isValueExpansion) && !literalClaudeTail(w.parts)) return true;
    const cands = wordCandidates(w.parts, ctx, 0);
    budget.n += cands.length;
    if (cands.some((c) => candidateNamesTranscript(c, dotglob))) return true;
    if (budget.n > BUDGET) { ctx.overflow = true; break; }
  }
  if (!ctx.overflow && intoDirectoryMayNameTranscript(levels, ctx, dotglob, budget)) return true;
  return ctx.overflow && evidence;
}

/**
 * True when some word of `text` (at any nesting level `expansionWords`
 * reaches) is a path the shell computes and that may be a Claude transcript
 * once expanded:
 *   - a live expansion AFTER a literal `.claude` (`.claude/x$((1))y/../…`,
 *     `.claude/$P/p/s.jsonl`, `.claude/proj*`), or
 *   - a computed directory directly above a literal `projects/…/*.jsonl`
 *     tail (`.c[l]aude/projects/…`, `${D}aude/projects/…`), or
 *   - in a command that names `.claude` literally anywhere, a computed path
 *     ending in a transcript leaf (`C=~/.claude/projects; cp s $C/p/s.jsonl`),
 *   - r11: the word JOINED (`claudeJoinedWordMayBeTranscript`) names it.
 * The shell computes that part of the path, so no lexical match can say it is
 * not a transcript; both Action Guard planes floor it as one. An expansion
 * only BEFORE a literal `.claude` tail (`$HOME/.claude/settings.json`) is
 * judged by the path regex. Over-deny, accepted: `$OUT/projects/x/a.jsonl`
 * beside any `claude` mention. Residual, documented: a value the command does
 * not spell — a variable set by an earlier call or the environment, `$(cat f)`
 * reading the path from a file — when the command holds no `.claude`-ish and
 * `projects`/`.jsonl` fragment; the guard does not evaluate the shell (the
 * class of a custom CLAUDE_CONFIG_DIR or a `cd`).
 */
export function claudeWordExpands(text) {
  const words = expansionWords(text);
  const namesClaude = words.some((w) => /\.claude/i.test(w.value));
  const piecewise = words.some((w) => {
    if (!w.expands) return false;
    const at = w.value.toLowerCase().indexOf('.claude');
    if (at >= 0 && w.value.indexOf(EXPANSION_MARK, at) > at) return true;
    if (computedTranscriptParent(w.value)) return true;
    return namesClaude && COMPUTED_TRANSCRIPT_LEAF_RE.test(w.value);
  });
  return piecewise || claudeJoinedWordMayBeTranscript(text);
}
