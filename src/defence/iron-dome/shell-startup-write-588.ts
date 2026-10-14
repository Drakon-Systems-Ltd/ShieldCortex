/** #588: shell words, redirects and statement boundaries. One pass; no gap regex. */
const STARTUP = /(?:^|\/)(?:\.(?:bashrc|zshrc|zprofile|zshenv|zlogin|zlogout|profile|bash_profile|bash_login|bash_logout)|\.config\/fish\/config\.fish)$/i;
const MAX_STARTUP_NESTING = 8;
const NESTED_STARTUP_MENTION = /\.(?:bashrc|zshrc|zprofile|zshenv|zlogin|zlogout|profile|bash_profile|bash_login|bash_logout)|\.config\/fish\/config\.fish/i;
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
    const m = /^\s*cat\s+<<-?\s*(?:([\x27\x22])([A-Za-z_][A-Za-z_0-9]*)\1|\\([A-Za-z_][A-Za-z_0-9]*)|([A-Za-z_][A-Za-z_0-9]*))(?:\s|$)/.exec(lines[i]!);
    if (!m) continue;
    const end = m[2] ?? m[3] ?? m[4]!;
    let j = i + 1;
    while (j < lines.length && lines[j]!.trim() !== end) j++;
    const tail = lines[i]!.slice(m[0].length);
    const reader = /^\s*\|\s*([^|;&<>\\`$]+?)\s*$/.exec(tail)?.[1] ?? '';
    const consumer = reader ? unwrap(words(reader).filter(w => w.kind === 'word').map(w => w.value)).verb : '';
    // A continued opener, dangling pipe, redirection, or substitution can run the body.
    const safe = /^\s*$/.test(tail) || !!reader && /^(?:cat|head|tail|grep|rg|wc|sort|uniq|cut|tr|jq|column|nl|fold|fmt)$/.test(consumer);
    if (j < lines.length && (m[2] || m[3]) && safe) {
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

export function shellStartupWrite(text: string, nested = false, depth = 0): boolean {
  if (depth >= MAX_STARTUP_NESTING && NESTED_STARTUP_MENTION.test(text)) return true;
  text = stripCatHeredocs(text);
  // Each nested substitution is scanned once; cap nesting, never byte distance.
  if (depth < MAX_STARTUP_NESTING) {
    let quote = '';
    for (let i = 0; i < text.length; i++) {
      const c = text[i]!;
      if (c === '\\') { i++; continue; }
      if (c === '\x27' && quote !== '\x22') { quote = quote ? '' : '\x27'; continue; }
      if (c === '\x22' && quote !== '\x27') { quote = quote ? '' : '\x22'; continue; }
      if (quote === '\x27') continue;
      if (!quote && c === '#' && (i === 0 || /[\s;|&()]/.test(text[i - 1]!))) {
        while (i + 1 < text.length && text[i + 1] !== '\n' && text[i + 1] !== '\r') i++;
        continue;
      }
      if (c !== '\x60' && !(c === '$' && text[i + 1] === '(')) continue;
      const backtick = c === '\x60', start = i + (backtick ? 1 : 2);
      let parenDepth = 1, innerQuote = '', end = start;
      for (; end < text.length; end++) {
        const d = text[end]!;
        if (d === '\\') { end++; continue; }
        if (backtick) { if (d === '\x60') break; continue; }
        if (d === '\x27' || d === '\x22') { if (!innerQuote) innerQuote = d; else if (innerQuote === d) innerQuote = ''; continue; }
        if (innerQuote === '\x27') continue;
        if (d === '(') parenDepth++;
        else if (d === ')' && --parenDepth === 0) break;
      }
      if (end < text.length) {
        if (shellStartupWrite(text.slice(start, end), true, depth + 1)) return true;
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

function decodeLiteral(value: string, raw: boolean, lang: string, quote = '\x22'): string {
  if (raw) return value;
  if (lang === 'php' && quote === '\x27') return value.replace(/\\([\\\x27])/g, '$1');
  // An unknown Python Unicode name may conceal any character in a write target.
  if (lang === 'python' && /\\N\{/.test(value) && /\.(?:bash|zsh|profile|config\/fish\/config)/i.test(value) && /(?:>>?|tee|sed|cp|mv|install)/.test(value))
    return value + '\necho x >> ~/.bashrc';
  return value.replace(/\\(?:\r?\n|u\{([0-9a-fA-F]{1,6})\}|U([0-9a-fA-F]{8})|u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|([0-7]{1,3})|N\{([^}]+)\}|([ntr\\\x22\x27\x60]))/g,
    (all, brace: string, big: string, unicode: string, hex: string, octal: string, named: string, simple: string) => {
      if (brace || big || unicode || hex) {
        const code = parseInt(brace || big || unicode || hex, 16);
        return code <= 0x10ffff ? String.fromCodePoint(code) : all;
      }
      if (octal) return String.fromCharCode(parseInt(octal, 8));
      if (named) return named === 'LATIN SMALL LETTER C' ? 'c' : all;
      if (!simple) return '';
      if (simple === 'n') return '\n';
      if (simple === 't') return '\t';
      if (simple === 'r') return '\r';
      return simple;
    });
}

type SourceCall = { name: string; arg: number; bracket: number; values: string[][]; shellFlag: boolean; shellKey: boolean; shellEquals: boolean; shellNegation: boolean };
function callStartupWrite(call: SourceCall, lang: string): boolean {
  const first = call.values[0] ?? [];
  const second = call.values[1] ?? [];
  const name = call.name;
  const shell = /^(?:sh|bash|dash|zsh|ksh|mksh|ash|fish|busybox)$/.test(first[0]?.replace(/^.*\//, '') ?? '');
  if (lang === 'node') {
    if (/^(?:spawn|spawnSync|execFile|execFileSync)$/.test(name))
      return call.shellFlag ? shellStartupWrite([first[0] ?? '', ...second].join(' '))
        : shell && second[0] === '-c' && second[1] !== undefined && shellStartupWrite(second[1]);
    return /^(?:exec|execSync)$/.test(name) && first[0] !== undefined && shellStartupWrite(first[0]);
  }
  if (lang === 'python') {
    if (/^(?:run|Popen|call|check_call|check_output)$/.test(name))
      return call.shellFlag && first.length === 1 && shellStartupWrite(first[0]!)
        || shell && first[1] === '-c' && first[2] !== undefined && shellStartupWrite(first[2]);
    return /^(?:system|popen|getoutput|getstatusoutput|spawn)$/.test(name) && first[0] !== undefined && shellStartupWrite(first[0]);
  }
  return SINK.test(name) && first[0] !== undefined && shellStartupWrite(first[0]);
}

/** Lex written interpreter source. String bytes are offered only at shell sinks. */
export function sourceStartupWrite(text: string, lang: string): boolean {
  if (lang === 'sh') return shellStartupWrite(text);
  const frames: Array<{ kind: 'code' | 'template'; tagged?: boolean; raw?: boolean; body?: string; brace?: number }> = [{ kind: 'code', brace: 0 }];
  const calls: Array<SourceCall | null> = [];
  let previous = '';
  let word = '';
  let shellTag = false;
  let rawTag = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    const frame = frames[frames.length - 1]!;
    if (frame.kind === 'template') {
      if (c === '\\') { frame.body += c + (text[++i] ?? ''); continue; }
      if (c === '\x60') {
        if (frame.tagged && shellStartupWrite(decodeLiteral(frame.body ?? '', frame.raw ?? false, lang))) return true;
        const call = calls.at(-1);
        if (call) (call.values[call.arg] ??= []).push(decodeLiteral(frame.body ?? '', frame.raw ?? false, lang));
        frames.pop(); previous = 'literal'; continue;
      }
      if (c === '$' && text[i + 1] === '{') { frame.body += ' opaque '; frames.push({ kind: 'code', brace: 0 }); i++; continue; }
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
      const triple = lang === 'python' && text[i + 1] === c && text[i + 2] === c;
      let value = '';
      for (i += triple ? 3 : 1; i < text.length; i++) {
        const d = text[i]!;
        if (d === '\\') { value += d + (text[++i] ?? ''); continue; }
        if (d === c && (!triple || text[i + 1] === c && text[i + 2] === c)) { if (triple) i += 2; break; }
        value += d;
      }
      const call = calls.at(-1);
      if (call) {
        let keyEnd = i + 1;
        if (lang === 'node' && value === 'shell') while (keyEnd < text.length && /\s/.test(text[keyEnd]!)) keyEnd++;
        if (lang === 'node' && value === 'shell' && text[keyEnd] === ':') call.shellKey = true;
        else (call.values[call.arg] ??= []).push(decodeLiteral(value, lang === 'python' && /^[rubf]*r[rubf]*$/i.test(word), lang, c));
      }
      previous = 'literal'; continue;
    }
    if (lang === 'node' && c === '\x60') {
      const tagged = previous === 'identifier' && (word === '$' || word === '$$' || word === 'execa' || shellTag);
      frames.push({ kind: 'template', tagged, raw: rawTag, body: '' }); continue;
    }
    if (/[A-Za-z_$\d]/.test(c)) {
      const start = i;
      while (i + 1 < text.length && /[A-Za-z_$\d]/.test(text[i + 1]!)) i++;
      const memberShell = previous === '.' && word === '$' && text.slice(start, i + 1) === 'sync';
      rawTag = previous === '.' && word === 'String' && text.slice(start, i + 1) === 'raw';
      word = text.slice(start, i + 1);
      shellTag = memberShell;
      const call = calls.at(-1);
      if (call) {
        if (call.shellEquals) {
          const literal = word.toLowerCase();
          call.shellFlag = literal === 'true' || literal === '1' || literal !== 'false' && literal !== '0' && !call.shellNegation;
          if (call.shellNegation) call.shellFlag = literal === 'false' || literal === '0';
          call.shellEquals = false; call.shellNegation = false;
        }
        call.shellKey = word === 'shell';
        if (word !== 'shell' && word !== 'True' && word !== 'true') call.shellEquals = false;
      }
      previous = 'identifier'; continue;
    }
    if (/\s/.test(c)) continue;
    if (c === '(') {
      const sink = previous === 'identifier' && (SINK.test(word) || /^(?:execFile|execFileSync)$/.test(word));
      calls.push(sink ? { name: word, arg: 0, bracket: 0, values: [], shellFlag: false, shellKey: false, shellEquals: false, shellNegation: false } : null);
      previous = '('; continue;
    }
    if (c === ')') { const call = calls.pop(); if (call && callStartupWrite(call, lang)) return true; previous = ')'; continue; }
    const call = calls.at(-1);
    if (call) {
      if (c === '[') call.bracket++;
      else if (c === ']') call.bracket = Math.max(0, call.bracket - 1);
      else if (c === ',' && call.bracket === 0) { call.arg++; call.shellKey = false; call.shellEquals = false; }
      else if ((c === '=' || c === ':') && call.shellKey) { call.shellEquals = true; call.shellFlag = true; call.shellKey = false; }
      else if (c === '!' && call.shellEquals) call.shellNegation = !call.shellNegation;
    }
    if (c === '{') { frame.brace = (frame.brace ?? 0) + 1; previous = '{'; continue; }
    if (c === '}' && frames.length > 1 && frame.brace === 0) { frames.pop(); previous = 'literal'; continue; }
    if (c === '}') frame.brace = Math.max(0, (frame.brace ?? 0) - 1);
    previous = c;
  }
  return false;
}
