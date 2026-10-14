/** #588: shell words, redirects and statement boundaries. One pass; no gap regex. */
const STARTUP = /(?:^|\/)(?:\.(?:bashrc|zshrc|zprofile|zshenv|zlogin|zlogout|profile|bash_profile|bash_login|bash_logout)|\.config\/fish\/config\.fish)$/i;
type Word = { value: string; kind: 'word' | 'redirect' | 'boundary' };

function words(text: string): Word[] {
  const out: Word[] = [];
  let value = '', quote = '';
  const flush = () => { if (value) { out.push({ value, kind: 'word' }); value = ''; } };
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (c === '\\' && quote !== '\x27') {
      if (text[i + 1] === '\n') { i++; continue; }
      if (i + 1 < text.length) { value += text[++i]!; continue; }
    }
    if (quote) { if (c === quote) quote = ''; else value += c; continue; }
    if (c === '#' && !value) { while (i + 1 < text.length && text[i + 1] !== '\n' && text[i + 1] !== '\r') i++; continue; }
    if (c === '\x27' || c === '\x22') { quote = c; continue; }
    if (c === ' ' || c === '\t' || c === '\r') { flush(); continue; }
    if (c === '\n' || c === ';' || c === '|' || c === '&' || c === '(' || c === ')') {
      flush(); out.push({ value: c, kind: 'boundary' }); continue;
    }
    if (c === '>') {
      flush(); let op = '>';
      if (text[i + 1] === '>' || text[i + 1] === '|') op += text[++i];
      out.push({ value: op, kind: 'redirect' }); continue;
    }
    value += c;
  }
  flush();
  return out;
}

// Only cat's heredoc is classified as inert data. Unknown readers stay fail closed.
function stripCatHeredocs(text: string): string {
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const m = /^\s*cat\s+<<-?\s*(['\x22]?)([A-Za-z_][A-Za-z_0-9]*)\1(?:\s|$)/.exec(lines[i]!);
    if (!m) continue;
    const end = m[2]!;
    let j = i + 1;
    while (j < lines.length && !new RegExp('^\\s*' + end + '(?:\\s|$)').test(lines[j]!)) j++;
    if (j < lines.length && !/\|\s*(?:sh|bash|zsh|dash|ksh)\b/.test(lines[i]!) && !/\|\s*(?:sh|bash|zsh|dash|ksh)\b/.test(lines[j]!)) {
      for (let k = i + 1; k < j; k++) lines[k] = '';
    }
    i = j;
  }
  return lines.join('\n');
}

function unwrap(command: string[]): { verb: string; args: string[] } {
  let i = 0;
  while (i < command.length) {
    const w = command[i]!, v = w.replace(/^.*\//, '').toLowerCase();
    if (/^[A-Za-z_][A-Za-z_0-9]*=/.test(w)) { i++; continue; }
    if (!/^(?:sudo|doas|env|command|exec|nohup|nice|timeout|stdbuf|time|builtin|xargs)$/.test(v)) break;
    i++;
    while (i < command.length) {
      const a = command[i]!;
      if (v === 'env' && /^[A-Za-z_][A-Za-z_0-9]*=/.test(a)) { i++; continue; }
      if (a === '--') { i++; break; }
      if (!a.startsWith('-')) break;
      i++;
      if ((v === 'sudo' || v === 'doas') && /^(?:-u|-g|-C|-p)$/.test(a)
          || v === 'env' && /^(?:-u|--unset)$/.test(a)
          || v === 'exec' && a === '-a'
          || v === 'xargs' && /^(?:-n|-P|-I|-L|-s|-E)$/.test(a)
          || v === 'nice' && a === '-n'
          || v === 'timeout' && /^(?:-s|--signal|-k|--kill-after)$/.test(a)
          || v === 'stdbuf' && /^(?:-i|-o|-e)$/.test(a)) i++;
    }
    if (v === 'timeout' && i < command.length) i++;
  }
  return { verb: command[i]?.replace(/^.*\//, '').toLowerCase() ?? '', args: command.slice(i + 1) };
}

export function shellStartupWrite(text: string, nested = false): boolean {
  text = stripCatHeredocs(text);
  // Substitutions are disjoint; only the outer call extracts them.
  if (!nested) {
    let quote = '';
    for (let i = 0; i < text.length; i++) {
      const c = text[i]!;
      if (c === '\\') { i++; continue; }
      if (c === '\x27' && quote !== '\x22') { quote = quote ? '' : '\x27'; continue; }
      if (c === '\x22' && quote !== '\x27') { quote = quote ? '' : '\x22'; continue; }
      if (quote === '\x27') continue;
      if (c === '#' && (i === 0 || /[\s;|&()]/.test(text[i - 1]!))) {
        while (i + 1 < text.length && text[i + 1] !== '\n' && text[i + 1] !== '\r') i++;
        continue;
      }
      if (c !== '\x60' && !(c === '$' && text[i + 1] === '(')) continue;
      const backtick = c === '\x60', start = i + (backtick ? 1 : 2);
      let depth = 1, innerQuote = '', end = start;
      for (; end < text.length; end++) {
        const d = text[end]!;
        if (d === '\\') { end++; continue; }
        if (backtick) { if (d === '\x60') break; continue; }
        if (d === '\x27' || d === '\x22') { if (!innerQuote) innerQuote = d; else if (innerQuote === d) innerQuote = ''; continue; }
        if (innerQuote === '\x27') continue;
        if (d === '(') depth++;
        else if (d === ')' && --depth === 0) break;
      }
      if (end < text.length) {
        if (shellStartupWrite(text.slice(start, end), true)) return true;
        i = end;
      } else break;
    }
  }
  const tokens = words(text);
  let stmt: string[] = [];
  const check = (): boolean => {
    if (!stmt.length) return false;
    const { verb, args } = unwrap(stmt);
    if (verb === 'tee' && args.some(a => !a.startsWith('-') && STARTUP.test(a))) return true;
    if (verb === 'sed' && args.some(a => /^-(?:[a-zA-Z]*i(?:\.|$)|-in-place(?:=|$))/.test(a)) && args.some(a => STARTUP.test(a))) return true;
    if ((verb === 'cp' || verb === 'mv' || verb === 'install') && STARTUP.test(args.at(-1) ?? '')) return true;
    if (!nested && verb === 'eval' && args.length && shellStartupWrite(args.join(' '), true)) return true;
    if (!nested && /^(?:sh|bash|zsh|dash|ksh)$/.test(verb)) {
      const at = args.findIndex(a => /^-[a-zA-Z]*c[a-zA-Z]*$/.test(a));
      if (at >= 0 && args[at + 1] && shellStartupWrite(args[at + 1] === '--' ? args[at + 2] ?? '' : args[at + 1]!, true)) return true;
    }
    return false;
  };
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i]!;
    if (t.kind === 'redirect' && STARTUP.test(tokens[i + 1]?.value ?? '') && tokens[i + 1]?.kind === 'word') return true;
    if (t.kind === 'boundary') { if (check()) return true; stmt = []; }
    else if (t.kind === 'word') stmt.push(t.value);
  }
  return check();
}

const SINK = /^(?:system|execSync|exec|spawnSync|spawn|run|Popen|call|check_call|check_output|popen|getoutput|getstatusoutput|shell_exec|passthru|proc_open)$/;
const NO_TAG = new Set(['return', 'typeof', 'await', 'yield', 'delete', 'void', 'in', 'of', 'instanceof', 'new', 'case', 'throw', 'else', 'do']);

/** Lex written interpreter source. String bytes are offered only at shell sinks. */
export function sourceStartupWrite(text: string, lang: string): boolean {
  if (lang === 'sh') return shellStartupWrite(text);
  const frames: Array<{ kind: 'code' | 'template'; tagged?: boolean; body?: string; brace?: number }> = [{ kind: 'code', brace: 0 }];
  const calls: boolean[] = [];
  let activeSinks = 0;
  let previous = '';
  let word = '';
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    const frame = frames[frames.length - 1]!;
    if (frame.kind === 'template') {
      if (c === '\\') { frame.body += c + (text[++i] ?? ''); continue; }
      if (c === '\x60') {
        if (frame.tagged && shellStartupWrite(frame.body ?? '')) return true;
        frames.pop(); previous = 'literal'; continue;
      }
      if (c === '$' && text[i + 1] === '{') { frames.push({ kind: 'code', brace: 0 }); i++; continue; }
      frame.body += c; continue;
    }
    if ((lang === 'node' || lang === 'php') && c === '/' && text[i + 1] === '/') { while (i + 1 < text.length && !/[\n\r\u2028\u2029]/.test(text[i + 1]!)) i++; continue; }
    if ((lang === 'node' || lang === 'php') && c === '/' && text[i + 1] === '*') { const end = text.indexOf('*/', i + 2); if (end < 0) break; i = end + 1; continue; }
    // `#` line comments in Ruby, Perl and PHP. A comment must never open a
    // quote (`# don't` would swallow the next sink). Perl's `$#array` is not
    // a comment.
    if ((lang === 'ruby' || lang === 'perl' || lang === 'php') && c === '#' && !(lang === 'perl' && text[i - 1] === '$')) {
      while (i + 1 < text.length && text[i + 1] !== '\n' && text[i + 1] !== '\r') i++;
      continue;
    }
    if (lang === 'node' && c === '/' && text[i + 1] !== '=' && previous !== 'identifier' && previous !== 'literal' && previous !== ')' && previous !== ']') {
      let inClass = false;
      for (i++; i < text.length; i++) {
        const d = text[i]!;
        if (d === '\\') { i++; continue; }
        if (d === '[') inClass = true;
        else if (d === ']') inClass = false;
        else if (d === '/' && !inClass) break;
        else if (/[\n\r\u2028\u2029]/.test(d)) break;
      }
      previous = 'literal'; continue;
    }
    if (lang === 'python' && c === '#') { while (i + 1 < text.length && text[i + 1] !== '\n' && text[i + 1] !== '\r') i++; continue; }
    if ((lang === 'ruby' || lang === 'perl' || lang === 'php') && c === '\x60') {
      let value = '';
      for (i++; i < text.length && text[i] !== '\x60'; i++) { if (text[i] === '\\') value += text[i++] ?? ''; value += text[i] ?? ''; }
      if (shellStartupWrite(value)) return true;
      previous = 'literal'; continue;
    }
    // Ruby `%x` and Perl `qx` take any punctuation delimiter; bracket pairs nest.
    if ((lang === 'ruby' && c === '%' && text[i + 1] === 'x' || lang === 'perl' && c === 'q' && text[i + 1] === 'x' && !/[A-Za-z_\d$]/.test(text[i - 1] ?? ''))
        && /[^\sA-Za-z\d_]/.test(text[i + 2] ?? 'a')) {
      const open = text[i + 2]!;
      const close = ({ '{': '}', '(': ')', '[': ']', '<': '>' } as Record<string, string>)[open] ?? open;
      let depth = 1, value = '';
      for (i += 3; i < text.length && depth; i++) {
        const d = text[i]!;
        if (d === '\\') { value += d + (text[++i] ?? ''); continue; }
        if (d === close && --depth === 0) break;
        if (d === open && open !== close) depth++;
        value += d;
      }
      if (shellStartupWrite(value)) return true;
      previous = 'literal'; continue;
    }
    if (c === '\x27' || c === '\x22') {
      let value = '';
      for (i++; i < text.length; i++) {
        const d = text[i]!;
        if (d === '\\') { value += d + (text[++i] ?? ''); continue; }
        if (d === c) break;
        value += d;
      }
      if (activeSinks > 0 && shellStartupWrite(value)) return true;
      previous = 'literal'; continue;
    }
    if (lang === 'node' && c === '\x60') {
      const tagged = previous === '$' || (previous === 'identifier' && !NO_TAG.has(word)) || previous === ')' || previous === ']';
      frames.push({ kind: 'template', tagged: tagged || activeSinks > 0, body: '' }); continue;
    }
    if (/[A-Za-z_$\d]/.test(c)) {
      const start = i;
      while (i + 1 < text.length && /[A-Za-z_$\d]/.test(text[i + 1]!)) i++;
      word = text.slice(start, i + 1); previous = lang === 'node' && NO_TAG.has(word) ? word : 'identifier'; continue;
    }
    if (/\s/.test(c)) continue;
    if (c === '(') {
      const sink = previous === 'identifier' && SINK.test(word);
      calls.push(sink);
      if (sink) activeSinks++;
      previous = '('; continue;
    }
    if (c === ')') { if (calls.pop()) activeSinks--; previous = ')'; continue; }
    if (c === '{') { frame.brace = (frame.brace ?? 0) + 1; previous = '{'; continue; }
    if (c === '}' && frames.length > 1 && frame.brace === 0) { frames.pop(); previous = 'literal'; continue; }
    if (c === '}') frame.brace = Math.max(0, (frame.brace ?? 0) - 1);
    previous = c;
  }
  return false;
}
