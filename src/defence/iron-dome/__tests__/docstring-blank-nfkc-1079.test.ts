/**
 * #1079 follow-up — the docstring blanker's readback gate judges the names
 * Python reads, not the bytes on disk.
 *
 * Python folds every identifier to NFKC (PEP 3131), so `_＿doc＿_` IS
 * `__doc__`, and a fullwidth or mathematical-bold `getattr`/`globals` IS the
 * builtin. A PEP 263 coding declaration changes the text Python parses
 * altogether (`+AF8AXw-` is `__` under utf-7). The gate's patterns are ASCII
 * and the resolver reads UTF-8, so before this fix every shape in the
 * "held" tables below had its docstring blanked and was ALLOWED unpinned,
 * where v5.20.0 (no blanking) holds it on `touch-guard-config`.
 *
 * Invariants: a docstring that the remaining code can read back keeps its scan
 * surface whatever the spelling; a mixed spelling of an allowed dunder
 * (`__name__`, `__main__`, `__init__`) is judged exactly as its ASCII form.
 *
 * Every probe below was run on CPython 3.14 (Unicode 16.0): each held shape
 * that Python accepts prints the docstring. The reviewer's original spelling
 * (U+FF3F as the FIRST character) is a SyntaxError there, since U+FF3F is not
 * XID_Start, but the guard is not a parser and holds it anyway.
 */
import { spawnSync } from 'node:child_process';
import { evaluateToolCall } from '../tool-action-guard.js';

const FLOOR = ['touch-approval-store', 'touch-decisions-ledger', 'touch-guard-config', 'disable-action-guard'];
const SHELL_OUT = ['os', 'system'].join('.');
const WRITE = `echo '{"x":"1"}' > ~/.shieldcortex/config.json`;
const DOC = `"""${WRITE}"""\n`;

const cp = (n: number) => String.fromCodePoint(n);
/** ASCII a-z → FULLWIDTH LATIN SMALL LETTER a-z (U+FF41..U+FF5A). */
const fw = (s: string) => [...s].map((c) => cp(c.codePointAt(0)! + 0xfee0)).join('');
/** ASCII a-z → MATHEMATICAL BOLD SMALL a-z (U+1D41A..). */
const bold = (s: string) => [...s].map((c) => cp(0x1d41a + c.codePointAt(0)! - 0x61)).join('');
/** Every code point whose NFKC form is `_` (CPython 3.14 / Unicode 16.0 sweep). */
const LOW_LINES: Array<[string, string]> = [
  ['U+FE33 vertical low line', cp(0xfe33)],
  ['U+FE34 vertical wavy low line', cp(0xfe34)],
  ['U+FE4D dashed low line', cp(0xfe4d)],
  ['U+FE4E centreline low line', cp(0xfe4e)],
  ['U+FE4F wavy low line', cp(0xfe4f)],
  ['U+FF3F fullwidth low line', cp(0xff3f)],
];
const FF = cp(0xff3f);

const floorOf = (v: { signals?: string[] }): string[] => (v.signals ?? []).filter((s) => FLOOR.includes(s));
const run = (src: string) =>
  evaluateToolCall('Bash', { command: 'python3 /ws/n.py' }, undefined, { resolveScriptSource: (p: string) => (p === '/ws/n.py' ? src : null) });
const held = (src: string) => {
  const v = run(src);
  expect(v.decision).not.toBe('allow');
  expect(v.signals).toContain('touch-guard-config');
};
const allowed = (src: string) => {
  const v = run(src);
  expect(floorOf(v)).toEqual([]);
  expect(v.decision).toBe('allow');
};

describe('#1079 NFKC — a dunder spelled with a compatibility low line is still `__doc__`', () => {
  test('control: the ASCII form is held', () => {
    held(`${DOC}import os\n${SHELL_OUT}(__doc__)\n`);
  });

  test('the reported spelling (U+FF3F doc U+FF3F U+FF3F) is held, exactly as the ASCII form', () => {
    const ascii = run(`${DOC}import os\n${SHELL_OUT}(__doc__)\n`);
    const v = run(`${DOC}import os\n${SHELL_OUT}(${FF}doc${FF}${FF})\n`);
    expect(v.decision).toBe(ascii.decision);
    expect(floorOf(v)).toEqual(floorOf(ascii));
    expect(v.signals).toContain('touch-guard-config');
  });

  describe.each(LOW_LINES)('%s', (_label, c) => {
    test.each([
      ['module __doc__, no two ASCII underscores adjacent', `${DOC}import os\n${SHELL_OUT}(_${c}doc${c}_)\n`],
      ['module __doc__, mixed with one ASCII pair', `${DOC}import os\n${SHELL_OUT}(_${c}doc__)\n`],
      ['module __doc__, the low line closing', `${DOC}import os\n${SHELL_OUT}(_${c}doc_${c})\n`],
      ['function __doc__', `import os\ndef f():\n    """${WRITE}"""\n${SHELL_OUT}(f._${c}doc${c}_)\n`],
      ['__file__ read back from disk', `${DOC}import os\n${SHELL_OUT}(open(_${c}file${c}_).read().split('"' * 3)[1])\n`],
    ])('%s', (_l, src) => held(src));
  });
});

describe('#1079 NFKC — a dynamic lookup spelled in compatibility letters is still the builtin', () => {
  const name = `'_' '_doc_' '_'`;              // implicit concatenation: no `__` in the bytes
  test.each([
    ['fullwidth globals()', `${DOC}import os\n${SHELL_OUT}(${fw('globals')}()[${name}])\n`],
    ['mathematical bold globals()', `${DOC}import os\n${SHELL_OUT}(${bold('globals')}()[${name}])\n`],
    ['fullwidth vars()', `${DOC}import os\n${SHELL_OUT}(${fw('vars')}()[${name}])\n`],
    ['one fullwidth letter in getattr', `import os\ndef f():\n    """${WRITE}"""\n${SHELL_OUT}(${fw('g')}etattr(f, ${name}))\n`],
    ['fullwidth getattr', `import os\ndef f():\n    """${WRITE}"""\n${SHELL_OUT}(${fw('getattr')}(f, ${name}))\n`],
    ['fullwidth sys.argv', `${DOC}import os, sys\n${SHELL_OUT}(open(sys.${fw('argv')}[0]).read().split('"' * 3)[1])\n`],
    ['fullwidth module name in a from-import', `${DOC}import os, sys\nfrom ${fw('inspect')} import getdoc\n${SHELL_OUT}(getdoc(sys.${fw('modules')}[__name__]))\n`],
  ])('%s', (_label, src) => held(src));
});

describe('#1079 — a source Python decodes differently from the resolver keeps its docstrings', () => {
  test.each([
    ['utf-7 cookie (`+AF8AXw-` is `__`)', `# coding: utf-7\n${DOC}import os\n${SHELL_OUT}(+AF8AXw-doc+AF8AXw-)\n`],
    ['vim-style utf-7 cookie on line 2', `#!/usr/bin/env python3\n# vim: set fileencoding=utf-7 :\n${DOC}import os\n${SHELL_OUT}(+AF8AXw-doc+AF8AXw-)\n`],
    // `${IFS…}` may span lines; the IFS rewrite would turn this whole cookie into a space.
    ['utf-7 cookie inside an IFS-shaped span', `# \${IFS\n# coding: utf-7 }\n${DOC}import os\n${SHELL_OUT}(+AF8AXw-doc+AF8AXw-)\n`],
    // Byte 0xAA is `ª` (NFKC `a`) under latin-1; the UTF-8 resolver yields U+FFFD.
    ['latin-1 cookie (`globªls` is `globals`)', `# -*- coding: latin-1 -*-\n${DOC}import os\n${SHELL_OUT}(glob${cp(0xfffd)}ls()['_' '_doc_' '_'])\n`],
  ])('%s', (_label, src) => held(src));

  test('control: a utf-8 declaration is the default and still relieves the docstring', () => {
    for (const cookie of ['# -*- coding: utf-8 -*-', '# coding=UTF_8', '# -*- coding: utf-8-unix -*-', '# vim: set fileencoding=utf8 :']) {
      allowed(`#!/usr/bin/env python3\n${cookie}\n"""Lease helper.\n\nNever touches ~/.shieldcortex/config.json.\n"""\nimport subprocess\nsubprocess.run(["git", "status"])\n`);
    }
  });
});

/**
 * Review r1 B2: a declaration is what CPython's tokenizer takes for one. Every
 * row below was checked on CPython 3.14 (compile of the bytes, and running the
 * file). The "allowed" rows are read as UTF-8 by Python, and origin/main
 * (no declaration check) allows each of them. Every "held" row is read under
 * the foreign codec by the tokenizer that runs the file, unless noted.
 */
describe('#1079 r1 — only a PEP 263 declaration names the codec, and UTF-8 aliases are UTF-8', () => {
  const HELPER = `"""Lease helper.\n\nNever touches ~/.shieldcortex/config.json.\n"""\nimport subprocess\nsubprocess.run(["git", "status"])\n`;
  const prose = (l1: string, l2 = 'Never touches ~/.shieldcortex/config.json.') =>
    `"""${l1}\n${l2}\n"""\nimport subprocess\nsubprocess.run(["git", "status"])\n`;

  test.each([
    ['docstring line 1 "encoding: json"', prose('encoding: json')],
    ['docstring line 1 "Decoding: json"', prose('Decoding: json')],
    ['docstring line 1 "encoding=base64"', prose('encoding=base64')],
    ['docstring line 1 "Transcoding: utf-16"', prose('Transcoding: utf-16')],
    ['docstring line 2 "Output encoding: json"', prose('Lease helper.', 'Output encoding: json; never touches ~/.shieldcortex/config.json.')],
    ['shebang, then a docstring "encoding: json"', `#!/usr/bin/env python3\n${prose('encoding: json. Never touches ~/.shieldcortex/config.json.', '')}`],
    ['line 1 code holding "decoding: base64"', `MODE = "decoding: base64"\n${HELPER}`],
    ['a latin-1 comment on line 2 after a code line', `import subprocess\n# -*- coding: latin-1 -*-\n${HELPER}`],
    ['a latin-1 comment on line 3', `#!/usr/bin/env python3\n\n# -*- coding: latin-1 -*-\n${HELPER}`],
    ['"coding" then a tab before the colon', `# coding\t: utf-7\n${HELPER}`],
    ['a utf-8 declaration on line 1 wins over a utf-7 one on line 2', `# coding: utf-8\n# coding: utf-7\n${HELPER}`],
  ])('not a foreign declaration: %s', (_label, src) => allowed(src));

  test.each([
    'u8', 'utf', 'UTF8', 'Utf8', 'utf_8', 'utf--8', 'utf-8-sig', 'utf-8-unix', 'cp65001', 'utf8_ucs4',
    'ascii', 'us-ascii', 'US_ASCII', '646', 'ansi_x3.4_1968', 'ansi_x3.4.1968',
  ])('`# coding: %s` reads the file as UTF-8 does: relieved', (name) => {
    allowed(`#!/usr/bin/env python3\n# -*- coding: ${name} -*-\n${HELPER}`);
  });

  test('a BOM before a utf-8 declaration relieves', () => {
    allowed(`\uFEFF# -*- coding: utf-8 -*-\n${HELPER}`);
  });

  const ATTACK = `${DOC}import os\n${SHELL_OUT}(+AF8AXw-doc+AF8AXw-)\n`;
  test.each([
    ['utf-7 after a `\\r`-only shebang line', `#!/usr/bin/env python3\r# coding: utf-7\n${ATTACK}`],
    ['utf-7 after a blank `\\r` line (tokenize.detect_encoding misses it; the running tokenizer does not)', `\r# coding: utf-7\n${ATTACK}`],
    ['utf-7 on line 2 of a CRLF file', `#!/usr/bin/env python3\r\n# coding: utf-7\r\n${ATTACK}`],
    ['utf-7 on line 2 after an empty declaration on line 1', `# coding: \n# coding: utf-7\n${ATTACK}`],
    ['utf-7 after a form-feed indent', ` \f# coding: utf-7\n${ATTACK}`],
    ['utf-7 spelled UTF_7', `# coding=UTF_7\n${ATTACK}`],
    ['utf-7 after U+2028 in the comment', `# \u2028 coding: utf-7\n${ATTACK}`],
    ['utf-7 behind a BOM (a SyntaxError, so never run; kept scanned anyway)', `\uFEFF# coding: utf-7\n${ATTACK}`],
    // Line 3 for the running tokenizer, line 1 for tokenize.detect_encoding. Both readings count.
    ['utf-7 after two `\\r`', `#!/x\r\r# coding: utf-7\n${ATTACK}`],
    ['latin-1 on line 2 under a vim modeline spelling', `#!/usr/bin/env python3\n# vim: set fileencoding=latin-1 :\n${DOC}import os\n${SHELL_OUT}(glob${cp(0xfffd)}ls()['_' '_doc_' '_'])\n`],
  ])('a foreign declaration keeps the docstring: %s', (_label, src) => held(src));

  // 200 KiB keeps the file under the 256 KiB fold cap (a larger file is opaque, never blanked).
  test('the declaration scan stays linear on a 200 KiB first line', () => {
    const t0 = performance.now();
    allowed(`# coding: utf-8 ${'x'.repeat(200 * 1024)}\n${HELPER}`);
    held(`# ${'x'.repeat(200 * 1024)} coding: utf-7\n${ATTACK}`);
    expect(performance.now() - t0).toBeLessThan(5_000);
  });
});

describe('#1079 NFKC — mixed spellings of the allowed dunders behave as the ASCII forms', () => {
  const helper = (guard: string, extra = '') => [
    '"""Lease helper.',
    '',
    'Never touches ~/.shieldcortex/config.json or ~/.shieldcortex/approvals/.',
    '"""',
    'import argparse, subprocess, sys',
    extra,
    'def main():',
    '    ap = argparse.ArgumentParser(description="Lease helper.")',
    '    ap.add_argument("scope", help="lease scope")',
    '    args = ap.parse_args()',
    '    subprocess.run(["git", "status"])',
    '    return 0',
    '',
    `if ${guard}:`,
    '    sys.exit(main())',
    '',
  ].join('\n');
  const ASCII_GUARD = '__name__ == "__main__"';

  test('control: the ASCII helper is relieved', () => {
    allowed(helper(ASCII_GUARD));
  });

  test.each([
    ...LOW_LINES.map(([label, c]) => [`__name__ via ${label}`, `_${c}name${c}_ == "__main__"`] as [string, string]),
    ['__name__ with one ASCII pair', `__name${FF}_ == "__main__"`],
    ['__name__ in mathematical bold', `_${FF}${bold('name')}${FF}_ == "__main__"`],
    ['"__main__" with a fullwidth low line', `__name__ == "_${FF}main${FF}_"`],
  ])('%s is relieved, as the ASCII helper is', (_label, guard) => {
    allowed(helper(guard));
  });

  test('a mixed `__init__` in a class is relieved, as the ASCII form is', () => {
    const cls = (init: string) => `class Lease:\n    def ${init}(self, scope):\n        self.scope = scope\n`;
    allowed(helper(ASCII_GUARD, cls('__init__')));
    allowed(helper(ASCII_GUARD, cls(`_${FF}init${FF}_`)));
  });

  test.each([
    ['import __main__', (m: string) => `import ${m}\n`],
    ['__main__.__doc__ handed to a shell', (m: string) => `import ${m}, os\n${SHELL_OUT}(${m}.__doc__)\n`],
  ])('%s: the mixed spelling gets the ASCII decision', (_label, body) => {
    const ascii = run(`${DOC}${body('__main__')}`);
    const mixed = run(`${DOC}${body(`_${FF}main${FF}_`)}`);
    expect(ascii.signals).toContain('touch-guard-config');
    expect(mixed.decision).toBe(ascii.decision);
    expect(floorOf(mixed)).toEqual(floorOf(ascii));
  });

  test('non-ASCII prose in the remaining code does not cost the relief', () => {
    allowed(helper(ASCII_GUARD, 'DONE = "完成！ ✓ — ﬁnished"\n'));
  });
});

/**
 * Review r1 B1: NFKC/NFKD reorder each run of combining marks by combining
 * class, which is quadratic in the run on adversarial input (U+0315 x n, then
 * U+0300 x n, in an ordinary string literal: 32.5 s for one 256 KiB script
 * before this fix, 44 ms on origin/main). A run of more than 30 code points
 * that decompose to marks only now refuses the relief before anything is
 * normalized: the docstring keeps its scan surface, as on any other doubt.
 */
describe('#1079 r1 — a long run of combining marks refuses the relief instead of being normalized', () => {
  const withLiteral = (text: string) =>
    `"""Lease helper.\n\nNever touches ~/.shieldcortex/config.json.\n"""\nimport subprocess\nLABEL = "${text}"\nsubprocess.run(["git", "status"])\n`;

  /**
   * Combining class from this runtime's own normalizer, for a code point that
   * NFD leaves alone: U+0345 (class 240) before it is reordered when its class
   * is 1..239, and it before U+0334 (class 1) when its class is 2..240. A
   * starter (class 0) blocks both.
   */
  const nonStarter = (y: string) =>
    ('\u0345' + y).normalize('NFD') !== '\u0345' + y || (y + '\u0334').normalize('NFD') !== y + '\u0334';

  test('the combining-class probe reads known classes', () => {
    expect(['\u0300', '\u0315', '\u0316', '\u0334', '\u0345', '\u3099', '\u05B0'].map(nonStarter)).toEqual(Array(7).fill(true));
    expect(['a', '_', '\u0903', '\u093E', '\uFF9E', '\u00E9'.normalize('NFD')[0], '\u4E00'].map(nonStarter)).toEqual(Array(7).fill(false));
  });

  test('every code point that NFKD turns into combining marks only counts toward the bound (full sweep)', () => {
    const marksOnly: number[] = [];
    let maxMarks = 0;          // marks one such code point becomes
    let maxTrailing = 0;       // marks after the last starter of any other code point
    let maxLeading = 0;        // marks before the first starter of any other code point
    for (let n = 0x80; n <= 0x10ffff; n++) {
      if (n >= 0xd800 && n <= 0xdfff) continue;
      const parts = [...cp(n).normalize('NFKD')];
      const flags = parts.map(nonStarter);
      if (flags.every(Boolean)) { marksOnly.push(n); maxMarks = Math.max(maxMarks, parts.length); continue; }
      maxTrailing = Math.max(maxTrailing, flags.length - 1 - flags.lastIndexOf(false));
      maxLeading = Math.max(maxLeading, flags.indexOf(false));
    }
    // The bound's arithmetic (tool-action-guard.ts, pyDocGateViews): 3 + 2 x 30 = 63.
    expect(marksOnly.length).toBeGreaterThan(900);
    expect(maxMarks).toBeLessThanOrEqual(2);
    expect(maxTrailing).toBeLessThanOrEqual(3);
    expect(maxLeading).toBe(0);
    const notCounted: string[] = [];
    const overRefused: string[] = [];
    for (const n of marksOnly) {
      const at31 = run(withLiteral(`a${cp(n).repeat(31)}`));
      if (!at31.signals?.includes('touch-guard-config')) notCounted.push(n.toString(16));
      const at30 = run(withLiteral(`a${cp(n).repeat(30)}`));
      if (floorOf(at30).length > 0) overRefused.push(n.toString(16));
    }
    expect(notCounted).toEqual([]);
    expect(overRefused).toEqual([]);
  }, 60_000);

  test.each([
    ['31 x U+0301', `a${'\u0301'.repeat(31)}`],
    ['16 x U+0315, then 15 x U+0300 (the review shape, small)', `a${'\u0315'.repeat(16)}${'\u0300'.repeat(15)}`],
    ['(U+0315 U+FF9E) x 16: U+FF9E is the mark U+3099 once decomposed', `a${'\u0315\uFF9E'.repeat(16)}`],
    ['(U+0F73) x 31: each is two marks once decomposed', `a${'\u0F73'.repeat(31)}`],
  ])('held: %s', (_label, text) => held(withLiteral(text)));

  test.each([
    ['30 x U+0301 (the bound)', `a${'\u0301'.repeat(30)}`],
    ['15 x U+0315, 15 x U+0300, then a starter, twice', `a${'\u0315'.repeat(15)}${'\u0300'.repeat(15)}b${'\u0315'.repeat(15)}${'\u0300'.repeat(15)}`],
    ['Vietnamese', 'Tiếng Việt: Nguyễn Thị Hồng, Hồ Chí Minh'],
    ['Vietnamese, decomposed', 'Tiếng Việt: Nguyễn Thị Hồng, Hồ Chí Minh'.normalize('NFD')],
    ['Hebrew with points and cantillation', 'בְּרֵאשִׁ֖ית בָּרָ֣א אֱלֹהִ֑ים'],
    ['Arabic with harakat', 'بِسْمِ ٱللَّٰهِ ٱلرَّحْمَٰنِ'],
    ['Devanagari conjuncts', 'क्षत्रिय संस्कृतम् द्ध्र्य'],
    ['Tibetan stacks', 'བསྒྲུབས་ཧཱུྃ་བསྐྱེད'],
    ['Thai tone marks', 'ภาษาไทย ผู้ใหญ่ น้ำ'],
    ['emoji keycap and ZWJ sequences', '1\uFE0F\u20E3 \u{1F469}\u200D\u{1F4BB} \u{1F44B}\u{1F3FD}'],
  ])('relieved: %s in a string literal', (_label, text) => allowed(withLiteral(text)));

  /**
   * The full evaluator at 256 KiB, in a child bounded at 20 s. Before this fix
   * the first shape alone took 32.5 s here; each shape now takes well under a
   * second. The "allow" rows are the worst inputs under the bound, which ARE
   * normalized: the longest decomposed run it admits (63 marks), in falling
   * class order.
   */
  test('256 KiB adversarial mark runs: the full evaluator stays linear (bounded child)', () => {
    const GUARD = new URL('../../../../dist/defence/iron-dome/tool-action-guard.js', import.meta.url).href;
    const PREFIX = `"""Lease helper. Never touches ~/.shieldcortex/config.json."""\nimport os\n${SHELL_OUT}("ls")\n`;
    const r15 = (s: string) => s.repeat(15);
    // [label, unit A, unit B (a second run of equal count), place, expected]
    const SHAPES: Array<[string, string, string, 'string' | 'ident', 'held' | 'allow']> = [
      ['U+0315 x n then U+0300 x n, in a string literal (the review shape)', '\u0315', '\u0300', 'string', 'held'],
      ['U+0315 x n then U+0300 x n, in an identifier', '\u0315', '\u0300', 'ident', 'held'],
      ['U+0301 x n then U+0316 x n', '\u0301', '\u0316', 'string', 'held'],
      ['(U+0315 U+0301 U+0316) x n', '\u0315\u0301\u0316', '', 'string', 'held'],
      ['(U+0315 U+FF9E) x n', '\u0315\uFF9E', '', 'string', 'held'],
      ['(15 x U+0315, 15 x U+0300, a) x n', `${r15('\u0315')}${r15('\u0300')}a`, '', 'string', 'allow'],
      ['(15 x U+0315, 15 x U+FF9E, a) x n', `${r15('\u0315')}${r15('\uFF9E')}a`, '', 'string', 'allow'],
      ['(U+1D164, 15 x U+0345, 15 x U+0334) x n', `\u{1D164}${r15('\u0345')}${r15('\u0334')}`, '', 'string', 'allow'],
      ['(U+1D164, 30 x U+0F73) x n', `\u{1D164}${'\u0F73'.repeat(30)}`, '', 'string', 'allow'],
    ];
    const child = spawnSync(process.execPath, ['--input-type=module', '-e', `
      const { evaluateToolCall } = await import(${JSON.stringify(GUARD)});
      const [prefix, shapes] = JSON.parse(process.argv[1]);
      const enc = new TextEncoder();
      const bytes = (s) => enc.encode(s).length;
      const out = [];
      for (const [label, a, b, place] of shapes) {
        const [open, close] = place === 'ident' ? ['a', ' = 1\\n'] : ['X = "a', '"\\n'];
        const budget = 256 * 1024 - bytes(prefix + open + close);
        const n = Math.floor(budget / (bytes(a) + bytes(b)));
        let body = a.repeat(n) + b.repeat(n);
        const pad = 'a'.repeat(budget - bytes(body));
        body = place === 'ident' ? pad + body : body + pad;
        const src = prefix + open + body + close;
        const t0 = performance.now();
        const v = evaluateToolCall('Bash', { command: 'python3 /ws/n.py' }, undefined, { resolveScriptSource: (p) => (p === '/ws/n.py' ? src : null) });
        out.push({ label, bytes: bytes(src), decision: v.decision, held: (v.signals ?? []).includes('touch-guard-config'), ms: Math.round(performance.now() - t0) });
      }
      process.stdout.write(JSON.stringify(out));
    `, JSON.stringify([PREFIX, SHAPES.map(([label, a, b, place]) => [label, a, b, place])])], {
      encoding: 'utf8', timeout: 20_000, killSignal: 'SIGKILL', maxBuffer: 1 << 20,
    });
    expect(child.error).toBeUndefined();
    expect(child.stderr).toBe('');
    expect(child.status).toBe(0);
    const rows = JSON.parse(child.stdout) as Array<{ label: string; bytes: number; decision: string; held: boolean }>;
    expect(rows.map((r) => [r.label, r.bytes, r.held ? 'held' : r.decision])).toEqual(
      SHAPES.map(([label, , , , want]) => [label, 256 * 1024, want]),
    );
  }, 60_000);
});
