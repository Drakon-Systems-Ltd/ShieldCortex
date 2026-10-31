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
    if (c === "'") return { text: out, end: i + 1 };
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
  return { text: out, end: -1 };
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
    return { end, body: s.slice(i + 1, Math.max(i + 1, end - 1)) };
  }
  if ((c === '<' || c === '>') && !inDouble && s[i + 1] === '(') {
    const end = skipBalanced(s, i + 2, '(', ')');
    return { end, body: s.slice(i + 2, Math.max(i + 2, end - 1)) };
  }
  if (c !== '$') return null;
  const n = s[i + 1];
  if (n === '(') {
    const end = skipBalanced(s, i + 2, '(', ')');
    return { end, body: s.slice(i + 2, Math.max(i + 2, end - 1)) };
  }
  if (n === '{') {
    const end = skipBalanced(s, i + 2, '{', '}');
    return { end, body: s.slice(i + 2, Math.max(i + 2, end - 1)) };
  }
  if (n !== undefined && PARAM_START_RE.test(n)) {
    const m = s.slice(i + 1).match(PARAM_NAME_RE);
    return { end: i + 1 + (m ? m[0].length : 1), body: '' };
  }
  return null;
}

/**
 * Every word of `text` as `{ value, expands }`: `value` is the word with
 * quotes removed and escapes honoured (as `shellTokens` gives it), except that
 * each live expansion — `$name`, `${…}`, `$(…)`, `$((…))`, backticks,
 * mid-word `<(…)`/`>(…)`, and unquoted glob (`* ? [`) or brace (`{`)
 * characters — is replaced by EXPANSION_MARK; `expands` is true when it has
 * one. Unlike `shellTokens`, an expansion stays INSIDE its word
 * (`x$(printf 1)y` is one word). The body of every command substitution, and
 * any word that itself looks like shell text (`bash -c '…'`), is scanned
 * again (up to three levels), so a nested command's words are included.
 */
export function expansionWords(text, depth = 0) {
  const s = String(text ?? '');
  const out = [];
  const nested = [];
  let cur = '';
  let lit = '';
  let expands = false;
  let inWord = false;
  const flush = () => {
    if (inWord) {
      out.push({ value: cur, expands });
      if (lit !== s && NESTED_SHELL_TEXT_RE.test(lit)) nested.push(lit);
    }
    cur = ''; lit = ''; expands = false; inWord = false;
  };
  const mark = (e, from) => {
    cur += EXPANSION_MARK; lit += s.slice(from, e.end); expands = true; inWord = true;
    if (e.body) nested.push(e.body);
    return e.end;
  };
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (c === '\\') {
      if (i + 1 >= s.length) { cur += '\\'; lit += '\\'; inWord = true; i++; continue; }
      if (s[i + 1] === '\n') { i += 2; continue; }
      cur += s[i + 1]; lit += s[i + 1]; inWord = true; i += 2; continue;
    }
    if (c === "'") {
      const j = s.indexOf("'", i + 1);
      const t = j < 0 ? s.slice(i + 1) : s.slice(i + 1, j);
      cur += t; lit += t; inWord = true; i = j < 0 ? s.length : j + 1; continue;
    }
    if (c === '$' && s[i + 1] === "'") {
      const { text: t, end } = decodeAnsiC(s, i + 2);
      cur += t; lit += t; inWord = true; i = end < 0 ? s.length : end; continue;
    }
    if (c === '"' || (c === '$' && s[i + 1] === '"')) {
      let j = c === '$' ? i + 2 : i + 1;
      inWord = true;
      while (j < s.length && s[j] !== '"') {
        const d = s[j];
        if (d === '\\' && j + 1 < s.length) {
          const n = s[j + 1];
          if (n === '\n') { j += 2; continue; }
          if (n === '$' || n === '`' || n === '"' || n === '\\') { cur += n; lit += n; j += 2; continue; }
          cur += '\\'; lit += '\\'; j++; continue;
        }
        const e = expansionAt(s, j, true);
        if (e) { j = mark(e, j); continue; }
        cur += d; lit += d; j++;
      }
      i = j + 1;
      continue;
    }
    const e = expansionAt(s, i, false);
    if (e && (c !== '<' && c !== '>' ? true : inWord)) { i = mark(e, i); continue; }
    if (BLANK.has(c)) { flush(); i++; continue; }
    if (OP_START.has(c)) {
      flush();
      const op = OPS.find((o) => s.startsWith(o, i));
      i += op.length;
      continue;
    }
    if (c === '*' || c === '?' || c === '[' || c === '{') {
      cur += EXPANSION_MARK; lit += c; expands = true; inWord = true; i++; continue;
    }
    cur += c; lit += c; inWord = true; i++;
  }
  flush();
  if (depth < NESTED_DEPTH) {
    for (const t of nested) out.push(...expansionWords(t, depth + 1));
  }
  return out;
}

/** A transcript tail below `.claude`: `projects/…/*.jsonl` or `…/subagents`. */
const TRANSCRIPT_TAIL_RE = /(?:^|\/)projects\/+(?:[^\s;&|<>'"`]*?\/)?(?:subagents(?=$|\/)|[^\/]*\.jsonl\b)/i;

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

/**
 * True when some word of `text` (at any nesting level `expansionWords`
 * reaches) is a path the shell computes and that may be a Claude transcript
 * once expanded:
 *   - a live expansion AFTER a literal `.claude` (`.claude/x$((1))y/../…`,
 *     `.claude/$P/p/s.jsonl`, `.claude/proj*`), or
 *   - a computed directory directly above a literal `projects/…/*.jsonl`
 *     tail (`.c[l]aude/projects/…`, `${D}aude/projects/…`), or
 *   - in a command that names `.claude` literally anywhere, a computed path
 *     ending in a transcript leaf (`C=~/.claude/projects; cp s $C/p/s.jsonl`).
 * The shell computes that part of the path, so no lexical match can say it is
 * not a transcript; both Action Guard planes floor it as one. An expansion
 * only BEFORE `.claude` (`$HOME/.claude/…`) leaves the rest literal and is
 * judged by the path regex. Over-deny, accepted: `$OUT/projects/x/a.jsonl`.
 * Residual, documented: a value the command does not spell — a variable set
 * by an earlier call or the environment, `$(cat f)` reading the path from a
 * file — carries no literal `.claude` and no literal tail; the guard does not
 * evaluate the shell (the class of a custom CLAUDE_CONFIG_DIR or a `cd`).
 */
export function claudeWordExpands(text) {
  const words = expansionWords(text);
  const namesClaude = words.some((w) => /\.claude/i.test(w.value));
  return words.some((w) => {
    if (!w.expands) return false;
    const at = w.value.toLowerCase().indexOf('.claude');
    if (at >= 0 && w.value.indexOf(EXPANSION_MARK, at) > at) return true;
    if (computedTranscriptParent(w.value)) return true;
    return namesClaude && COMPUTED_TRANSCRIPT_LEAF_RE.test(w.value);
  });
}
