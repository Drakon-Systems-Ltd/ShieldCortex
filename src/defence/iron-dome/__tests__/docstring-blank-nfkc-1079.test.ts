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

/**
 * Review r2 (B2-r1): the declaration window is Python's physical lines.
 * compile() of the bytes, `python3 file.py` and `python3 - <file.py` all split
 * lines at `\r\n`, `\r` and `\n` alike before they look for a declaration, so
 * a cookie on physical line 3 is a comment and the file runs as UTF-8: the
 * text the gate already judges. `tokenize.detect_encoding` splits at `\n` only
 * and takes `#!x\r\r# coding: X` for line 1's declaration; nothing that runs
 * the file reads it that way. Each row was run on CPython 3.14.9 both ways
 * (compile of the bytes, and the file): every "relieved" row runs as UTF-8 and
 * origin/main allows it; every "held" row prints the docstring under the codec.
 */
describe('#1079 r2 — a declaration on physical line 3 is a comment, however lines 1 and 2 end', () => {
  const HELPER = `"""Lease helper. Never touches ~/.shieldcortex/config.json."""\nimport subprocess\nsubprocess.run(["git", "status"])\n`;
  const CODECS = ['utf-7', 'latin-1', 'cp1252', 'unicode_escape', 'raw_unicode_escape'];
  const LINE3: Array<[string, (codec: string) => string]> = [
    ['shebang, CR, CR; the cookie LF-ended', (c) => `#!/usr/bin/env python3\r\r# coding: ${c}\n`],
    ['shebang, CR, CR; the cookie CR-ended', (c) => `#!/usr/bin/env python3\r\r# coding: ${c}\r`],
    ['shebang, CR, CR; the cookie CRLF-ended', (c) => `#!/usr/bin/env python3\r\r# coding: ${c}\r\n`],
    ['shebang, CR, CRLF; the cookie LF-ended', (c) => `#!/usr/bin/env python3\r\r\n# coding: ${c}\n`],
    ['shebang, CR, CRLF; the cookie CR-ended', (c) => `#!/usr/bin/env python3\r\r\n# coding: ${c}\r`],
    ['shebang, CR, CRLF; the cookie CRLF-ended', (c) => `#!/usr/bin/env python3\r\r\n# coding: ${c}\r\n`],
    ['a CR inside the line-2 comment', (c) => `#!x\n# a\r# coding: ${c}\n`],
    ['two CR-ended comment lines', (c) => `# a\r# b\r# coding: ${c}\n`],
    ['two blank CR lines', (c) => `\r\r# coding: ${c}\n`],
    ['shebang, LF, then a blank CR line', (c) => `#!x\n\r# coding: ${c}\n`],
  ];

  test("the reviewer's two files, byte for byte, are relieved", () => {
    allowed(`#!/usr/bin/env python3\r\r# coding: latin-1\n${HELPER}`);
    allowed(`#!x\n# a\r# coding: latin-1\n${HELPER}`);
  });

  // Review r3 (B-CR): the same two files with the cookie line and the body
  // CR- or CRLF-ended too. CPython 3.14.9 runs each as UTF-8, and `__doc__`
  // is the helper text, exactly as for the LF body above.
  test.each([['CR', '\r'], ['CRLF', '\r\n']])("the reviewer's two files with a %s-ended body are relieved, as the LF body is", (_n, eol) => {
    const body = HELPER.replace(/\n/g, eol);
    allowed(`#!/usr/bin/env python3\r\r# coding: latin-1${eol}${body}`);
    allowed(`#!x\n# a\r# coding: latin-1${eol}${body}`);
  });

  describe.each(LINE3)('%s', (_label, head) => {
    test.each(CODECS)('`# coding: %s` on line 3 is relieved, as its LF spelling is', (codec) => {
      const src = `${head(codec)}${HELPER}`;
      allowed(src);
      allowed(src.replace(/\r\n?/g, '\n'));
      allowed(`${head(codec)}${HELPER.replace(/\n/g, '\r')}`);       // review r3: the body CR-ended
      allowed(`${head(codec)}${HELPER.replace(/\n/g, '\r\n')}`);     // and CRLF-ended
    });
  });

  test('a line-3 cookie opens no door: the UTF-8 text Python runs is the text the gate reads', () => {
    held(`#!/x\r\r# coding: utf-7\n${DOC}import os\n${SHELL_OUT}(__doc__)\n`);
    held(`#!x\n# a\r# coding: latin-1\n${DOC}import os\n${SHELL_OUT}(_${FF}doc${FF}_)\n`);
  });

  // A declaration on line 1 or 2 is still honoured under every line ending.
  const UTF7_ATTACK = `${DOC}import os\n${SHELL_OUT}(+AF8AXw-doc+AF8AXw-)\n`;
  const LATIN1_ATTACK = `${DOC}import os\n${SHELL_OUT}(glob${cp(0xfffd)}ls()['_' '_doc_' '_'])\n`;
  const ENDS: Array<[string, string]> = [['LF', '\n'], ['CR', '\r'], ['CRLF', '\r\n']];
  test.each(ENDS)('a declaration on line 1, %s-ended, keeps the docstring (utf-7, latin-1)', (_n, t) => {
    held(`# coding: utf-7${t}${UTF7_ATTACK}`);
    held(`# -*- coding: latin-1 -*-${t}${LATIN1_ATTACK}`);
  });
  test.each(ENDS.flatMap(([n1, t1]) => ENDS.map(([n2, t2]) => [n1, n2, t1, t2] as [string, string, string, string])))(
    'a declaration on line 2 after a %s-ended shebang, itself %s-ended, keeps the docstring (utf-7, latin-1)',
    (_n1, _n2, t1, t2) => {
      held(`#!/usr/bin/env python3${t1}# coding: utf-7${t2}${UTF7_ATTACK}`);
      held(`#!/usr/bin/env python3${t1}# -*- coding: latin-1 -*-${t2}${LATIN1_ATTACK}`);
    },
  );
  test('a declaration on line 2 behind a CR inside a line-1 comment keeps the docstring', () => {
    held(`# harmless\r# coding: utf-7\n${UTF7_ATTACK}`);
    held(`# harmless\r# -*- coding: latin-1 -*-\n${LATIN1_ATTACK}`);
  });
});

/**
 * Review r3 (B-CR): the walk that finds the docstrings reads the same physical
 * lines the declaration window does. Python splits the WHOLE file at `\r\n`,
 * `\r` and `\n` alike, so a CR-ended helper is the program its LF spelling is:
 * a CR ends a line, a comment and a standalone docstring; `\` then `\r` or
 * `\r\n` is one continuation. The readback gate reads those lines too: its
 * import check took everything up to the next LF for one `import` statement,
 * so in a CR-only file the first import hid every later one.
 *
 * Every row below was run on CPython 3.14.9, as the file, in all three
 * spellings: each "relieved" row runs and its docstring is the helper text;
 * each "held" row hands the docstring (or the literal) to the sink.
 */
describe('#1079 r3 — CR and CRLF end a line in the docstring walk, as LF does', () => {
  const EOLS: Array<[string, string]> = [['LF', '\n'], ['CR', '\r'], ['CRLF', '\r\n']];
  const spell = (src: string, eol: string) => src.replace(/\n/g, eol);
  const HELPER = `"""Lease helper.\n\nNever touches ~/.shieldcortex/config.json.\n"""\nimport subprocess\nsubprocess.run(["git", "status"])\n`;
  const LINE = `"""Lease helper. Never touches ~/.shieldcortex/config.json."""\nimport subprocess\nsubprocess.run(["git", "status"])\n`;
  const FN_DOC = `    """Never touches ~/.shieldcortex/config.json."""\n`;
  const fn = (before = '') => `import subprocess\ndef main():\n${before}${FN_DOC}    subprocess.run(["git", "status"])\nmain()\n`;
  const CLICK = `@click.command()\ndef main():\n    """${WRITE}"""\n${SHELL_OUT}(main.help)\n`;

  describe.each(EOLS)('%s-ended', (_n, eol) => {
    test.each([
      ['the helper', HELPER],
      ['the one-line helper', LINE],
      ['a function docstring', fn()],
      ['a docstring on the line after a mid-line comment (the walk ends that comment)', `import subprocess  # git only\n"""Never touches ~/.shieldcortex/config.json."""\nsubprocess.run(["git", "status"])\n`],
      ['a utf-8 declaration behind a BOM (that comment is not blanked; the walk ends it)', `﻿# -*- coding: utf-8 -*-\n${HELPER}`],
      ['a backslash-newline inside a one-line string', `${LINE}LABEL = "lease \\\nhelper"\n`],
      ['a backslash continuation before the module docstring (Grok r2 NIT)', `\\\n${HELPER}`],
      ['a backslash continuation before a function docstring', fn('    \\\n')],
    ])('relieved: %s', (_l, src) => allowed(spell(src, eol)));

    test.each([
      ['module __doc__', `${DOC}import os\n${SHELL_OUT}(__doc__)\n`],
      ['function __doc__', `import os\ndef f():\n    """${WRITE}"""\n${SHELL_OUT}(f.__doc__)\n`],
      ['a compatibility-low-line __doc__', `${DOC}import os\n${SHELL_OUT}(_${FF}doc${FF}_)\n`],
      ['a globals() lookup', `${DOC}import os\n${SHELL_OUT}(globals()['_' '_doc_' '_'])\n`],
      ['a readback after a mid-line comment', `${DOC}import os  # the sink\n${SHELL_OUT}(__doc__)\n`],
      ['a utf-7 declaration on line 1', `# coding: utf-7\n${DOC}import os\n${SHELL_OUT}(+AF8AXw-doc+AF8AXw-)\n`],
      ['click hands the docstring back as `main.help` (only the import tells)', `import os\nimport click\n${CLICK}`],
      ['the same, the first import a from-import', `from os import path\nimport click\nimport os\n${CLICK}`],
      // Grok r3 B-CONT: Python deletes `\` and the break after it and reads one
      // statement, so each of these is `import os as os, click`.
      ['click in an aliased import on one line (the control for the next four)', `import os as os, click\n${CLICK}`],
      ['click after a continuation: `import os \\`, then `as os, click`', `import os \\\nas os, click\n${CLICK}`],
      ['click after a continuation: `import os \\`, then `, click`', `import os \\\n, click\n${CLICK}`],
      ['click after two continuations: `import os \\`, `as os, \\`, `click`', `import os \\\nas os, \\\nclick\n${CLICK}`],
      ['click after a comma and a continuation: `import os,\\`, then `click`', `import os,\\\nclick\n${CLICK}`],
      ['the literal is an operand across a continuation', `X = \\\n"""${WRITE}"""\nimport os\n${SHELL_OUT}(X)\n`],
    ])('held: %s', (_l, src) => held(spell(src, eol)));
  });

  /**
   * The paths this round opens, at the fold cap, in a child bounded at 20 s.
   * The walk, its comment skip and continuations, and the import check each
   * move forward only, so every shape takes a fraction of a second (70 to
   * 250 ms each here). Not this check: an LF-ended file of thousands of
   * docstrings is slow for an older reason, the command-position scans over
   * the blanked lines, and is as slow on origin/main.
   */
  test('256 KiB CR- and CRLF-ended shapes: the walk and the import check stay linear (bounded child)', () => {
    const GUARD = new URL('../../../../dist/defence/iron-dome/tool-action-guard.js', import.meta.url).href;
    const KIB = 256 * 1024;
    // [label, head, unit repeated to fill 256 KiB, tail, expected]
    const SHAPES: Array<[string, string, string, string, 'held' | 'allow']> = [
      ['CR: short code lines after the helper', spell(LINE, '\r'), 'x = 1\r', '', 'allow'],
      ['CR: one long mid-line comment before the docstring', 'import subprocess  # ', 'a', spell(`\n${LINE}`, '\r'), 'allow'],
      ['CR: leading continuations', '', '\\\r', spell(LINE, '\r'), 'allow'],
      ['CR: a standalone docstring on every line', 'import subprocess\r', '"""Never touches ~/.shieldcortex/config.json."""\r', 'subprocess.run(["git", "status"])\r', 'allow'],
      ['CR: a backslash-newline in every one-line string', spell(LINE, '\r'), 'L = "lease \\\rhelper"\r', '', 'allow'],
      ['CR: one import per line', spell(LINE, '\r'), 'import os\r', '', 'allow'],
      ['CR: a readback after the short code lines', spell(`${DOC}import os\n`, '\r'), 'x = 1\r', `${SHELL_OUT}(__doc__)\r`, 'held'],
      ['CRLF: leading continuations', '', '\\\r\n', spell(LINE, '\r\n'), 'allow'],
      ['CRLF: a backslash-newline in every one-line string', spell(LINE, '\r\n'), 'L = "lease \\\r\nhelper"\r\n', '', 'allow'],
    ];
    const child = spawnSync(process.execPath, ['--input-type=module', '-e', `
      const { evaluateToolCall } = await import(${JSON.stringify(GUARD)});
      const [kib, shapes] = JSON.parse(process.argv[1]);
      const enc = new TextEncoder();
      const bytes = (s) => enc.encode(s).length;
      const out = [];
      for (const [label, head, unit, tail] of shapes) {
        const src = head + unit.repeat(Math.floor((kib - bytes(head) - bytes(tail)) / bytes(unit))) + tail;
        const t0 = performance.now();
        const v = evaluateToolCall('Bash', { command: 'python3 /ws/n.py' }, undefined, { resolveScriptSource: (p) => (p === '/ws/n.py' ? src : null) });
        out.push({ label, bytes: bytes(src), decision: v.decision, held: (v.signals ?? []).includes('touch-guard-config'), ms: Math.round(performance.now() - t0) });
      }
      process.stdout.write(JSON.stringify(out));
    `, JSON.stringify([KIB, SHAPES.map(([label, head, unit, tail]) => [label, head, unit, tail])])], {
      encoding: 'utf8', timeout: 20_000, killSignal: 'SIGKILL', maxBuffer: 1 << 20,
    });
    expect(child.error).toBeUndefined();
    expect(child.stderr).toBe('');
    expect(child.status).toBe(0);
    const rows = JSON.parse(child.stdout) as Array<{ label: string; bytes: number; decision: string; held: boolean }>;
    expect(rows.map((r) => [r.label, r.bytes > KIB - 64 && r.bytes <= KIB, r.held ? 'held' : r.decision])).toEqual(
      SHAPES.map(([label, , , , want]) => [label, true, want]),
    );
  }, 60_000);
});

/** [label, head, unit repeated to fill the size, tail, expected] */
type SizeShape = [string, string, string, string, 'held' | 'allow'];

/**
 * Each shape at 16 KiB and at 256 KiB, in a child bounded at 20 s; the
 * fastest of three runs at each size. The join is one forward pass and every
 * term after it moves forward only, so 16x the input costs about 16x (a
 * quadratic step would cost about 256x). The bound is 64x, with a 4 ms floor
 * on the small run so that timer noise there cannot fail it.
 */
function expectNearLinear(SHAPES: SizeShape[]): void {
  const GUARD = new URL('../../../../dist/defence/iron-dome/tool-action-guard.js', import.meta.url).href;
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', `
    const { evaluateToolCall } = await import(${JSON.stringify(GUARD)});
    const [sizes, shapes] = JSON.parse(process.argv[1]);
    const enc = new TextEncoder();
    const bytes = (s) => enc.encode(s).length;
    const fill = (kib, head, unit, tail) => head + unit.repeat(Math.floor((kib - bytes(head) - bytes(tail)) / bytes(unit))) + tail;
    const judge = (src) => evaluateToolCall('Bash', { command: 'python3 /ws/n.py' }, undefined, { resolveScriptSource: (p) => (p === '/ws/n.py' ? src : null) });
    const out = [];
    for (const [label, head, unit, tail] of shapes) {
      const row = { label };
      for (const [name, kib] of sizes) {
        const src = fill(kib, head, unit, tail);
        judge(src);
        let best = Infinity;
        let v;
        for (let r = 0; r < 3; r++) {
          const t0 = performance.now();
          v = judge(src);
          best = Math.min(best, performance.now() - t0);
        }
        row[name] = { bytes: bytes(src), ms: best, verdict: (v.signals ?? []).includes('touch-guard-config') ? 'held' : v.decision };
      }
      out.push(row);
    }
    process.stdout.write(JSON.stringify(out));
  `, JSON.stringify([[['small', 16 * 1024], ['large', 256 * 1024]], SHAPES.map(([label, head, unit, tail]) => [label, head, unit, tail])])], {
    encoding: 'utf8', timeout: 20_000, killSignal: 'SIGKILL', maxBuffer: 1 << 20,
  });
  expect(child.error).toBeUndefined();
  expect(child.stderr).toBe('');
  expect(child.status).toBe(0);
  type Run = { bytes: number; ms: number; verdict: string };
  const rows = JSON.parse(child.stdout) as Array<{ label: string; small: Run; large: Run }>;
  expect(rows.map((r) => [r.label, r.small.verdict, r.large.verdict, r.large.bytes > 256 * 1024 - 64, r.large.bytes <= 256 * 1024])).toEqual(
    SHAPES.map(([label, , , , want]) => [label, want, want, true, true]),
  );
  for (const r of rows) expect([r.label, r.large.ms / Math.max(r.small.ms, 4) < 64]).toEqual([r.label, true]);
}

/**
 * Grok r3 B-CONT and NIT 1: the gate reads Python's logical lines. A backslash
 * before a physical break is an explicit line join (Python deletes both and a
 * token never spans it), and a form feed between tokens is whitespace, so each
 * separates tokens as a space does. Before this every held row below but the
 * one-line controls was allowed, though its one-line spelling is held; and
 * three relieved rows (a continuation right after the name, before `import` in
 * a from-import, after a comma) were held, though their one-line spellings are
 * relieved. On CPython 3.14.9 (sinks stubbed) each held row hands the
 * docstring back, to stdout or to the sink, and each relieved row runs with
 * `__doc__` the helper text.
 */
describe('#1079 r4 — a backslash continuation and a form feed separate tokens, as Python reads them', () => {
  const EOLS: Array<[string, string]> = [['LF', '\n'], ['CR', '\r'], ['CRLF', '\r\n']];
  const spell = (src: string, eol: string) => src.replace(/\n/g, eol);
  const LINE = `"""Lease helper. Never touches ~/.shieldcortex/config.json."""\n`;
  const RUN = `subprocess.run(["git", "status"])\n`;
  const MAIN = `def main():\n    """${WRITE}"""\n`;
  /** `help(main)` renders the docstring to `sys.stdout`; `W.write` hands it to the sink. */
  const CAPTURE = (gap: string) => [
    'import os, sys',
    'class W:',
    `    def write(self, s): ${SHELL_OUT}(s)`,
    '    def flush(self): pass',
    '    def isatty(self): return False',
    `${MAIN}w = W()`,
    `sys.stdout${gap}=${gap}w`,
    `help${gap}(main)`,
    '',
  ].join('\n');

  describe.each(EOLS)('%s-ended', (_n, eol) => {
    test.each([
      ['builtin help() on one line (the control for the next row)', `import os\n${MAIN}help(main)\n`],
      ['builtin help() across a continuation', `import os\n${MAIN}help \\\n(main)\n`],
      ['help() into a captured stdout on one line (the control for the next two rows)', CAPTURE(' ')],
      ['help() into a captured stdout, each step across a continuation', CAPTURE(' \\\n')],
      ['help() into a captured stdout, the tokens separated by form feeds', CAPTURE('\f')],
      ['builtin help() after a form feed', `import os\n${MAIN}help\f(main)\n`],
    ])('held: %s', (_l, src) => held(spell(src, eol)));

    test.each([
      ['an aliased import continued after a space (Grok r3: must stay allowed)', `${LINE}import subprocess \\\nas sp\nsp.run(["git", "status"])\n`],
      ['an aliased import continued right after the name', `${LINE}import subprocess\\\nas sp\nsp.run(["git", "status"])\n`],
      ['a from-import continued before `import` (Grok r3 NIT 1)', `${LINE}import subprocess\nfrom os.path \\\nimport join\n${RUN}`],
      ['an import list continued after a comma', `${LINE}import subprocess, \\\n    json\n${RUN}`],
      ['an argparse `help=` keyword on a continued line', `${LINE}import argparse, subprocess\nap = argparse.ArgumentParser()\nap.add_argument("--dry-run", \\\n    help="print only", action="store_true")\n${RUN}`],
      ['a form-feed page break between two functions', `${LINE}import subprocess\ndef a():\n    return 1\n\f\ndef b():\n    ${RUN}b()\n`],
      ['a form feed between tokens', `${LINE}import subprocess\nx =\f1\n${RUN}`],
    ])('relieved: %s', (_l, src) => allowed(spell(src, eol)));
  });

  test('continuation-heavy CR and CRLF input: 16 KiB vs 256 KiB stays near-linear (bounded child)', () => {
    const CR = (s: string) => spell(s, '\r');
    const CRLF = (s: string) => spell(s, '\r\n');
    const CLICK = `@click.command()\n${MAIN}${SHELL_OUT}(main.help)\n`;
    expectNearLinear([
      ['CR: a continued aliased import per line', CR(LINE), 'import os \\\ras os, \\\rsys\r', '', 'allow'],
      ['CRLF: a continued from-import per line', CRLF(LINE), 'from os.path \\\r\nimport join\r\n', '', 'allow'],
      ['CR: one logical import line of continuations', `${CR(LINE)}import os`, ' \\\r', ', sys\r', 'allow'],
      ['CRLF: one logical import line of continuations', `${CRLF(LINE)}import os`, ' \\\r\n', ', sys\r\n', 'allow'],
      ['CR: click after a logical line of continuations', `${CR(DOC)}import os`, ' \\\r', `, click\r${CR(CLICK)}`, 'held'],
      ['CRLF: help( after a logical line of continuations', `${CRLF(`import os\n${MAIN}`)}help`, ' \\\r\n', '(main)\r\n', 'held'],
      ['CR: a form feed between tokens on every line', CR(LINE), 'x =\f1\r', '', 'allow'],
    ]);
  }, 60_000);
});

/**
 * Review r4 of #1096 (Astra and Grok B-COMMENT): a backslash joins two
 * physical lines only where Python reads it as code. In a comment it is
 * comment text, and the comment still ends at the break; in a string it is
 * part of the literal. The r4 join rewrote every `\` and break, so
 * `import os # \` then `import click` read as one import of `os` (allowed,
 * though origin/main holds it and Python imports click), and a comment
 * ending in `\` pulled the next statement into a safe import's capture or
 * made `help (` out of `# help \` and `(42))` (held, though Python calls
 * nothing). A form feed in a comment or a string is no token separator
 * either: rewritten, `# from<FF>os<FF>import (` read as a from-import whose
 * parenthesised list swallowed the next line's `import click`.
 *
 * `<J>` marks the break right after the backslash, so the mixed rows end it
 * differently from the rest of the file. On CPython 3.14.9 (sinks stubbed)
 * each held row hands the docstring to the sink, and each relieved row runs
 * with nothing handed back.
 */
describe('#1079 r5 — a backslash or a form feed in a comment or a string joins nothing', () => {
  const J = '<J>';
  const ENDINGS: Array<[string, string, string]> = [
    ['LF', '\n', '\n'], ['CR', '\r', '\r'], ['CRLF', '\r\n', '\r\n'],
    ['LF, the join CRLF', '\n', '\r\n'], ['LF, the join CR', '\n', '\r'],
    ['CRLF, the join LF', '\r\n', '\n'], ['CR, the join LF', '\r', '\n'],
  ];
  const spell = (src: string, eol: string, join = eol) => src.replace(/\n/g, eol).split(J).join(join);
  const MAIN = `def main():\n    """${WRITE}"""\n`;
  const CLICK = `@click.command()\n${MAIN}${SHELL_OUT}(main.help)\n`;
  const LINE = `"""Lease helper. Never touches ~/.shieldcortex/config.json."""\n`;
  const RUN = `subprocess.run(["git", "status"])\n`;
  const HELPER = `def helper():\n    ${LINE}    return 0\nimport subprocess\n`;

  describe.each(ENDINGS)('%s-ended', (_n, eol, join) => {
    test.each([
      ['`import os # \\`, then `import click`', `import os # \\${J}import click\n${CLICK}`],
      ['the same, no space before the backslash', `import os #\\${J}import click\n${CLICK}`],
      ['the same, a tab before the comment', `import os\t# \\${J}import click\n${CLICK}`],
      ['the same, after an import list', `import os, sys # \\${J}import click\n${CLICK}`],
      ['`from os import path # \\`, then `import click`', `from os import path # \\${J}import click\nimport os\n${CLICK}`],
      ['`from os.path import join # \\`, then `import click`', `from os.path import join # \\${J}import click\nimport os\n${CLICK}`],
      ['`from os import path # \\`, then `from click import command`', `from os import path # \\${J}from click import command\nimport os\n@command()\n${MAIN}${SHELL_OUT}(main.help)\n`],
      ['a `#` in a string is no comment, so the continuation after it joins', `x = "foo#bar"; import os \\${J}, click\n${CLICK}`],
      ['help() on the line after a comment ending in a backslash', `import os\n${MAIN}x = 1 # \\${J}help(main)\n`],
    ])('held: %s', (_l, src) => held(spell(src, eol, join)));

    test.each([
      ['`( # help \\`, then `(42))`: no call (Astra)', `${HELPER}x = ( # help \\${J}(42))\n${RUN}`],
      ['the same with `dir`', `${HELPER}x = ( # dir \\${J}(42))\n${RUN}`],
      ['the same with `compile`', `${HELPER}x = ( # compile \\${J}(42))\n${RUN}`],
      ['`# see help\\`, then a parenthesised string: no call (Grok)', `${LINE}import subprocess  # see help\\${J}("docs")\n${RUN}`],
      ['a Windows path ending the comment after a safe import (Grok)', `${LINE}import subprocess  # C:\\${J}${RUN}`],
      ['the same after a continued import (Grok)', `${LINE}import \\\n    subprocess  # C:\\${J}${RUN}`],
    ])('relieved: %s', (_l, src) => allowed(spell(src, eol, join)));
  });

  describe.each(ENDINGS.slice(0, 3))('%s-ended, a form feed', (_n, eol) => {
    test.each([
      ['in a comment: `# from<FF>os<FF>import (` swallows no import', `import os  # from\fos\fimport (\nimport click\nprint()\n${CLICK}`],
      ['in a string: the same words swallow no import', `import os\nx = "from\fos\fimport ("\nimport click\ny = ")"\n${CLICK}`],
      ['in an f-string replacement field, which is code: `help<FF>(main)` is a call', `import os\n${MAIN}x = f"{help\f(main)}"\n`],
    ])('held: %s', (_l, src) => held(spell(src, eol)));

    test.each([
      ['in a string: `help<FF>(` is no call (Grok r4 NIT 1)', `${LINE}import subprocess\nLABEL = "help\f(me)"\n${RUN}`],
      ['in a comment: `help<FF>(` is no call', `${LINE}import subprocess  # see help\f(docs)\n${RUN}`],
    ])('relieved: %s', (_l, src) => allowed(spell(src, eol)));
  });

  test('comment-backslash and comment-form-feed input: 16 KiB vs 256 KiB stays near-linear (bounded child)', () => {
    expectNearLinear([
      ['CRLF: a safe import, its comment ending in a backslash, per line', spell(LINE, '\r\n'), 'import os # C:\\\r\n', '', 'allow'],
      ['LF: imports whose comments end in a backslash, then click', 'import os\n', 'import os # \\\n', `import click\n${CLICK}`, 'held'],
      ['CR: `( # help \\`, then `(42))`, per line', spell(`${LINE}import subprocess\n`, '\r'), 'x = ( # help \\\r(42))\r', '', 'allow'],
      ['LF: `help<FF>(` in a comment per line', `${LINE}import subprocess\n`, 'x = 1  # see help\f(docs)\n', '', 'allow'],
      ['CRLF: a `#` in a string, then a continued import per line', spell(LINE, '\r\n'), 'x = "a#b"; import os \\\r\n, sys\r\n', '', 'allow'],
    ]);
  }, 60_000);
});

/**
 * Review r5 of #1096 (Astra B-FORMAT-LITERAL): in an f- or t-string
 * replacement field, a `:` outside any bracket of the expression ends the
 * expression, and the format spec after it is literal text that Python hands
 * to `format()` as it stands. Only a nested `{…}` in the spec is code again.
 * `:=` there is a spec starting `=` (PEP 572), not a walrus. The r5 walk read
 * every form feed in the field as a token gap, so
 * `f"{when:from<FF>os<FF>import (}"` became a from-import whose parenthesised
 * list swallowed the next line's `import click` (allowed, though origin/main
 * holds it), and `f"{when:help<FF>(}"` became a help call (held, though
 * origin/main relieves it and Python calls nothing).
 *
 * On CPython 3.14.9 (real Click, sinks stubbed) each held row imports click
 * and hands the docstring to the sink; each relieved row runs, calls no
 * help() and hands nothing back; each expression row calls help(main).
 */
describe('#1079 r6 — a form feed in an f- or t-string format spec is literal text', () => {
  const J = '<J>';
  const ENDINGS: Array<[string, string, string]> = [
    ['LF', '\n', '\n'], ['CR', '\r', '\r'], ['CRLF', '\r\n', '\r\n'],
    ['LF, the join CRLF', '\n', '\r\n'], ['LF, the join CR', '\n', '\r'],
    ['CRLF, the join LF', '\r\n', '\n'], ['CR, the join LF', '\r', '\n'],
  ];
  const spell = (src: string, eol: string, join = eol) => src.replace(/\n/g, eol).split(J).join(join);
  const MAIN = `def main():\n    """${WRITE}"""\n`;
  const CLICK = `@click.command()\n${MAIN}${SHELL_OUT}(main.help)\n`;
  const LINE = `"""Lease helper. Never touches ~/.shieldcortex/config.json."""\n`;
  const RUN = `subprocess.run(["git", "status"])\n`;
  const WHEN = 'datetime.datetime(2026, 1, 1)';
  const SWALLOW = 'from\fos\fimport (';
  /** `<J>` is the break after the stamp, so the mixed rows end it differently from the rest of the file. */
  const UNSAFE = (stamp: string) => `import os, datetime\nFMT = "%Y"\nstamp = ${stamp}${J}import click\n${CLICK}`;
  const BENIGN = (stamp: string) => `${LINE}import datetime, subprocess\nFMT = "%Y"\nstamp = ${stamp}${J}${RUN}`;
  const CALL = (stamp: string) => `import os, datetime\n${MAIN}x = ${stamp}${J}`;

  describe.each(ENDINGS)('%s-ended', (_n, eol, join) => {
    test.each([
      ['an f-string spec `from<FF>os<FF>import (` swallows no import (Astra)', UNSAFE(`f"{${WHEN}:${SWALLOW}}"`)],
      ['the same in a t-string', UNSAFE(`t"{${WHEN}:${SWALLOW}}"`)],
      ['the same in a triple-quoted f-string, the spec across a line break', UNSAFE(`f"""{${WHEN}:${SWALLOW}\nmore literal text\n}"""`)],
      ['the same in a raw f-string', UNSAFE(`rf"{${WHEN}:${SWALLOW}}"`)],
      ['a spec that starts `:=`', UNSAFE(`f"{${WHEN}:=${SWALLOW}}"`)],
      ['spec text after a nested field', UNSAFE(`f"{${WHEN}:{FMT}${SWALLOW}}"`)],
      ['a spec after a slice colon in the expression', UNSAFE(`f"{[${WHEN}][0:1][0]:${SWALLOW}}"`)],
      ['a spec after a dict colon in the expression', UNSAFE(`f"{ {0: ${WHEN}}[0]:${SWALLOW}}"`)],
    ])('held: %s', (_l, src) => held(spell(src, eol, join)));

    test.each([
      ['an f-string date spec `help<FF>(` is no call (Astra)', BENIGN(`f"{${WHEN}:help\f(}"`)],
      ['the same in a t-string', BENIGN(`t"{${WHEN}:help\f(}"`)],
      ['a date spec `sys.stdout<FF>=x` captures no stdout (Astra)', BENIGN(`f"{${WHEN}:sys.stdout\f=x}"`)],
      ['a triple-quoted f-string date spec across a line break', BENIGN(`f"""{${WHEN}:%Y\f%m\nhelp\f(\n}"""`)],
      ['a date spec that starts `:=`', BENIGN(`f"{${WHEN}:=help\f(}"`)],
      ['date spec text after a nested field', BENIGN(`f"{${WHEN}:{FMT}help\f(}"`)],
      ['a date spec after a slice colon in the expression', BENIGN(`f"{[${WHEN}][0:1][0]:help\f(}"`)],
      ['a date spec after a dict colon in the expression', BENIGN(`f"{ {0: ${WHEN}}[0]:help\f(}"`)],
      ['a date spec with form-feed page breaks', BENIGN(`f"{${WHEN}:%Y\f%m\f%d}"`)],
    ])('relieved: %s', (_l, src) => allowed(spell(src, eol, join)));

    test.each([
      ['a nested field in a spec is code: `{help<FF>(main)}`', CALL(`f"{${WHEN}:{help\f(main)}}"`)],
      ['the same in a t-string', CALL(`t"{${WHEN}:{help\f(main)}}"`)],
      ['a nested field after spec text', CALL(`f"{${WHEN}:%Y{help\f(main)}}"`)],
      ['a field after a spec has ended', CALL(`f"{${WHEN}:%Y}{help\f(main)}"`)],
      ['a slice colon begins no spec', CALL(`f"{[0, 1][0:1] and help\f(main)}"`)],
      ['a dict colon begins no spec', CALL(`f"{ {1: 2}[1] and help\f(main)}"`)],
      ['a lambda colon in parentheses begins no spec', CALL(`f"{(lambda: 0)() or help\f(main)}"`)],
    ])('held, the expression is code: %s', (_l, src) => held(spell(src, eol, join)));
  });

  test('format-spec input: 16 KiB vs 256 KiB stays near-linear (bounded child)', () => {
    expectNearLinear([
      ['LF: a date spec with form feeds per line', `${LINE}import datetime\n`, `x = f"{${WHEN}:%Y\f%m\f%d}"\n`, '', 'allow'],
      ['CRLF: nested fields in a date spec per line', spell(`${LINE}import datetime\nFMT = "%Y"\n`, '\r\n'), `x = f"{${WHEN}:{FMT}\f{FMT}}"\r\n`, '', 'allow'],
      ['CR: a swallowing spec per line, then click', 'import os, datetime\r', `x = f"{${WHEN}:${SWALLOW}}"\r`, `import click\r${spell(CLICK, '\r')}`, 'held'],
      ['LF: one spec of form feeds', `${LINE}import datetime\nx = f"{${WHEN}:`, '%Y\f', '}"\n', 'allow'],
      ['LF: one spec of nested fields', `${LINE}import datetime\nFMT = "%Y"\nx = f"{${WHEN}:`, '{FMT}\f', '}"\n', 'allow'],
      ['LF: one expression of brackets before the spec', `${LINE}import datetime\nx = f"{`, '(1) and ', `${WHEN}:help\f(}"\n`, 'allow'],
    ]);
  }, 60_000);
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
