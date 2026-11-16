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
