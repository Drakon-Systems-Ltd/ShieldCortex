import { describe, it, expect } from '@jest/globals';
import { evaluateToolCall, detectScriptInvocations } from '../tool-action-guard.js';

/**
 * #661 follow-up — v5.6.0 release review (GPT-6 Astra B1, Grok).
 *
 * #686 masked a quoted whole-command interpreter heredoc whenever its body had
 * no `SHELL_OUT_SINK` match. The sink knows process starters, not code
 * LOADERS, so a body like
 *
 *     import runpy
 *     runpy.run_path('/tmp/fixture.py')
 *
 * was blanked as data-only and the file it executes was never offered to the
 * resolver. 5.5.0 offered it and scanned its contents. Same for Ruby `load`,
 * Perl `do`, PHP `include` and the rest of the loaders below.
 *
 * A body that loads or evaluates code now keeps its text, so the loaded path
 * reaches the resolver as on 5.5.0. The data-read relief #661 was for is
 * unchanged. Fixtures are BENIGN: discovery (the resolver being asked for the
 * path) is the evidence, not a block on a destructive payload.
 *
 * Each loaded path sits where invocation discovery reads a clean token (after
 * an open paren, without a trailing `, arg`). `f('/x', y)` yields `/x,` on
 * every plane and every version — a pre-existing tokeniser shape, not this fix.
 */
const BENIGN = 'print("benign fixture")\n';

/** Every path the guard asks its resolver for while evaluating `command`. */
function asked(command: string): string[] {
  const seen: string[] = [];
  evaluateToolCall('Bash', { command }, undefined, {
    resolveScriptSource: (p: string) => { seen.push(p); return BENIGN; },
  });
  return seen;
}

const heredoc = (interp: string, body: string): string => `${interp} <<'EOF'\n${body}\nEOF`;

/** [interpreter, body, the file the body loads]. */
const LOADERS: Record<string, [string, string, string]> = {
  // Python
  'python runpy.run_path': ['python3 -', "import runpy\nrunpy.run_path('/tmp/fx/a.py')", '/tmp/fx/a.py'],
  'python runpy after sys.path.insert': ['python3 -', "import sys, runpy\nsys.path.insert(0, '/tmp/fx')\nrunpy.run_path('/tmp/fx/b.py')", '/tmp/fx/b.py'],
  'python importlib.import_module': ['python3 -', "import importlib\nimportlib.import_module('m')\nopen('/tmp/fx/c.py')", '/tmp/fx/c.py'],
  'python importlib.util.spec_from_file_location': ['python3 -', "import importlib.util as u\ns = u.spec_from_file_location('m',\n'/tmp/fx/d.py')", '/tmp/fx/d.py'],
  'python SourceFileLoader': ['python3 -', "from importlib.machinery import SourceFileLoader\nSourceFileLoader('m',\n'/tmp/fx/e.py').load_module()", '/tmp/fx/e.py'],
  'python imp.load_source': ['python3 -', "import imp\nimp.load_source('m',\n'/tmp/fx/f.py')", '/tmp/fx/f.py'],
  'python __import__': ['python3 -', "m = __import__('m')\nopen('/tmp/fx/g.py')", '/tmp/fx/g.py'],
  'python execfile': ['python2 -', "execfile('/tmp/fx/h.py')", '/tmp/fx/h.py'],
  'python compile': ['python3 -', "src = open('/tmp/fx/i.py').read()\ncode = compile(src, 'i', 'exec')", '/tmp/fx/i.py'],
  'python eval of a file': ['python3 -', "eval(open('/tmp/fx/j.py').read())", '/tmp/fx/j.py'],
  'python 2 exec statement': ['python2 -', "exec open('/tmp/fx/k.py').read()", '/tmp/fx/k.py'],
  'python os.posix_spawn': ['python3 -', "import os\nos.posix_spawn(\n'/tmp/fx/l.sh'\n, ['l'], {})", '/tmp/fx/l.sh'],
  'python os.posix_spawnp': ['python3 -', "import os\nos.posix_spawnp(\n'/tmp/fx/m.sh'\n, ['m'], {})", '/tmp/fx/m.sh'],
  'python ctypes.CDLL': ['python3 -', "import ctypes\nctypes.CDLL('/tmp/fx/n.so')", '/tmp/fx/n.so'],
  // Ruby
  'ruby load': ['ruby -', "load('/tmp/fx/a.rb')", '/tmp/fx/a.rb'],
  'ruby Kernel.load': ['ruby -', "Kernel.load('/tmp/fx/b.rb')", '/tmp/fx/b.rb'],
  'ruby require': ['ruby -', "require('/tmp/fx/c.rb')", '/tmp/fx/c.rb'],
  'ruby require_relative': ['ruby -', "require_relative('/tmp/fx/d.rb')", '/tmp/fx/d.rb'],
  'ruby eval': ['ruby -', "eval(File.read('/tmp/fx/e.rb'))", '/tmp/fx/e.rb'],
  'ruby instance_eval': ['ruby -', "Object.new.instance_eval(File.read('/tmp/fx/f.rb'))", '/tmp/fx/f.rb'],
  'ruby class_eval': ['ruby -', "String.class_eval(File.read('/tmp/fx/g.rb'))", '/tmp/fx/g.rb'],
  'ruby module_eval': ['ruby -', "Kernel.module_eval(File.read('/tmp/fx/h.rb'))", '/tmp/fx/h.rb'],
  'ruby binding': ['ruby -', "binding.local_variable_get(:x)\nFile.read('/tmp/fx/i.rb')", '/tmp/fx/i.rb'],
  // Perl
  'perl do FILE': ['perl -', "do('/tmp/fx/a.pl');", '/tmp/fx/a.pl'],
  'perl require': ['perl -', "require('/tmp/fx/b.pl');", '/tmp/fx/b.pl'],
  'perl string eval': ['perl -', "my $src = read_file(\n'/tmp/fx/c.pl');\neval $src;", '/tmp/fx/c.pl'],
  'perl use lib': ['perl -', "use lib '/tmp/fx';\nuse Fixture;\nprint(\n'/tmp/fx/d.pl');", '/tmp/fx/d.pl'],
  // PHP
  'php include': ['php', "<?php include('/tmp/fx/a.php'); ?>", '/tmp/fx/a.php'],
  'php include_once': ['php', "<?php include_once('/tmp/fx/b.php'); ?>", '/tmp/fx/b.php'],
  'php require': ['php', "<?php require('/tmp/fx/c.php'); ?>", '/tmp/fx/c.php'],
  'php require_once': ['php', "<?php require_once('/tmp/fx/d.php'); ?>", '/tmp/fx/d.php'],
  'php eval': ['php', "<?php eval(file_get_contents('/tmp/fx/e.php')); ?>", '/tmp/fx/e.php'],
  'php assert with a string': ['php', "<?php assert('true'); readfile('/tmp/fx/f.php'); ?>", '/tmp/fx/f.php'],
  'php create_function': ['php', "<?php $f = create_function('', file_get_contents('/tmp/fx/g.php')); ?>", '/tmp/fx/g.php'],
  // Node
  'node require of a path': ['node -', "require('/tmp/fx/a.js')", '/tmp/fx/a.js'],
  'node dynamic import()': ['node -', "import('/tmp/fx/b.mjs')", '/tmp/fx/b.mjs'],
  'node import … from a path': ['node --input-type=module -', "import x from '/tmp/fx/c.mjs'\nconsole.log(\n'/tmp/fx/c.mjs')", '/tmp/fx/c.mjs'],
  'node vm.runInThisContext': ['node -', "const vm = require('vm')\nvm.runInThisContext(require('fs').readFileSync(\n'/tmp/fx/d.js'))", '/tmp/fx/d.js'],
  'node vm.Script': ['node -', "const vm = require('vm')\nnew vm.Script(require('fs').readFileSync(\n'/tmp/fx/e.js'))", '/tmp/fx/e.js'],
  'node new Function': ['node -', "new Function(require('fs').readFileSync(\n'/tmp/fx/f.js'))()", '/tmp/fx/f.js'],
  'node Function()': ['node -', "Function(require('fs').readFileSync(\n'/tmp/fx/g.js'))()", '/tmp/fx/g.js'],
  'node eval': ['node -', "eval(require('fs').readFileSync(\n'/tmp/fx/h.js'))", '/tmp/fx/h.js'],
  'node child_process by concatenation': ['node -', "const cp = require('child_' + 'process')\ncp.execFileSync(\n'/tmp/fx/i.sh')", '/tmp/fx/i.sh'],
  'node _process fragment': ['node -', "const n = 'child' + '_process'\nrequire(n).spawnSync(\n'/tmp/fx/j.sh')", '/tmp/fx/j.sh'],
  'node process.binding': ['node -', "process.binding('spawn_sync')\nconsole.log(\n'/tmp/fx/k.sh')", '/tmp/fx/k.sh'],
  'node module.createRequire': ['node -', "const { createRequire } = require('module')\ncreateRequire(__filename)(\n'/tmp/fx/l.js')", '/tmp/fx/l.js'],
};

describe('#661 follow-up — a heredoc that LOADS code is never masked as data', () => {
  it.each(Object.entries(LOADERS))('%s: the loaded file is offered to the resolver', (_name, [interp, body, path]) => {
    const cmd = heredoc(interp, body);
    expect([cmd, asked(cmd)]).toEqual([cmd, expect.arrayContaining([path])]);
  });

  it("Astra's four reproductions, verbatim", () => {
    const rows: Array<[string, string]> = [
      ["python3 - <<'EOF'\nimport runpy\nrunpy.run_path('/tmp/review-fixture.py')\nEOF", '/tmp/review-fixture.py'],
      ["ruby - <<'EOF'\nload('/tmp/review-fixture.rb')\nEOF", '/tmp/review-fixture.rb'],
      ["perl - <<'EOF'\ndo('/tmp/review-fixture.pl');\nEOF", '/tmp/review-fixture.pl'],
      ["php <<'EOF'\n<?php include('/tmp/review-fixture.php'); ?>\nEOF", '/tmp/review-fixture.php'],
    ];
    for (const [cmd, path] of rows) {
      expect([cmd, detectScriptInvocations(cmd).map(s => s.path)]).toEqual([cmd, expect.arrayContaining([path])]);
      expect([cmd, asked(cmd)]).toEqual([cmd, expect.arrayContaining([path])]);
    }
  });
});

describe('#661 follow-up — controls', () => {
  it('exec(open(...).read()) is still discovered (sink path, unchanged)', () => {
    const cmd = heredoc('python3 -', "exec(open('/tmp/fx/z.py').read())");
    expect(asked(cmd)).toContain('/tmp/fx/z.py');
  });

  it('a data-read-only body is still masked: nothing folded, nothing asked', () => {
    for (const cmd of [
      heredoc('python3 -', "import re, json\ntext = open('/tmp/x/table.md').read()\nrows = json.loads(text) if text.startswith('[') else []\nprint(len(re.findall('x', text)), len(rows))"),
      heredoc('node -', "const t = require('fs').readFileSync('/tmp/x/table.md', 'utf8')\nconsole.log(t.length)"),
      heredoc('node -', "const fs = require('node:fs')\nconsole.log(fs.readFileSync('/tmp/x/table.md', 'utf8').length)"),
      heredoc('perl -', "open(F, '/tmp/x/table.md'); print scalar(<F>);"),
      heredoc('ruby -', "puts File.read('/tmp/x/table.md').length"),
    ]) {
      expect([cmd, detectScriptInvocations(cmd)]).toEqual([cmd, []]);
      expect([cmd, asked(cmd)]).toEqual([cmd, []]);
    }
  });

  it('a Node bare-module require is exempt only for a plain name, not a path or an expression', () => {
    expect(asked(heredoc('node -', "require('./x/fixture.js')"))).toContain('./x/fixture.js');
    expect(asked(heredoc('node -', "const p = '/tmp/fx/q.js'\nrequire(p)\nconsole.log(\n'/tmp/fx/q.js')"))).toContain('/tmp/fx/q.js');
  });
});
