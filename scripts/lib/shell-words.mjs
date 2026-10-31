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
 * NOT modelled (callers must not assume them): parameter / command /
 * arithmetic expansion, globbing, brace expansion, aliases, `#` comments
 * (a `#` is kept as a literal word character, which only ever adds words).
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
