import { describe, it, expect } from '@jest/globals';
import { evaluateToolCall, detectScriptInvocations } from '../tool-action-guard.js';

/**
 * #661 follow-up — v5.6.0 release review (GPT-6 Astra, Grok), PR #712.
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
 * Two review rounds each found loader spellings a code-loader deny-list
 * missed (Perl `do` + newline, Ruby receiver aliases and paren-less `send`,
 * PHP `EVAL`, Node identifier escapes, `pickle`). A deny-list across five
 * languages cannot be shown complete, so the heredoc relief is WITHDRAWN for
 * 5.6.0: a whole-command interpreter heredoc is scanned and folded exactly as
 * in 5.5.0. It may return only as an allow-list design (mask a body made
 * solely of recognised data-read idioms); these rows are its required
 * negative tests. Fixtures are BENIGN: discovery (the resolver being asked
 * for the path) is the evidence, not a block on a destructive payload.
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

describe('#661 follow-up — a heredoc that LOADS code keeps the loaded file discoverable', () => {
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

  it('a data-read-only body is scanned as in 5.5.0: the heredoc relief is withdrawn pending an allow-list design', () => {
    for (const cmd of [
      heredoc('python3 -', "import re, json\ntext = open('/tmp/x/table.md').read()\nrows = json.loads(text) if text.startswith('[') else []\nprint(len(re.findall('x', text)), len(rows))"),
      heredoc('ruby -', "puts File.read('/tmp/x/table.md').length"),
    ]) {
      expect([cmd, detectScriptInvocations(cmd).map(s => s.path)]).toEqual([cmd, expect.arrayContaining(['/tmp/x/table.md'])]);
      expect([cmd, asked(cmd)]).toEqual([cmd, expect.arrayContaining(['/tmp/x/table.md'])]);
    }
  });

  it('a Node data-read body that loads fs by bare name is scanned in full', () => {
    for (const cmd of [
      heredoc('node -', "const t = require('fs').readFileSync(\n'/tmp/x/table.md')\nconsole.log(t.length)"),
      heredoc('node -', "const fs = require('node:fs')\nconsole.log(fs.readFileSync(\n'/tmp/x/table.md').length)"),
      heredoc('node --input-type=module -', "import fs from 'node:fs'\nconsole.log(fs.readFileSync(\n'/tmp/x/table.md').length)"),
    ]) {
      expect([cmd, asked(cmd)]).toEqual([cmd, expect.arrayContaining(['/tmp/x/table.md'])]);
    }
  });

  it('a Node require of a path or a variable is scanned in full', () => {
    expect(asked(heredoc('node -', "require('./x/fixture.js')"))).toContain('./x/fixture.js');
    expect(asked(heredoc('node -', "const p = '/tmp/fx/q.js'\nrequire(p)\nconsole.log(\n'/tmp/fx/q.js')"))).toContain('/tmp/fx/q.js');
  });
});

/**
 * PR #712 round 1 (GPT-6 Astra and Grok reviews): spellings the first
 * deny-list missed, so the body was masked and a file 5.5.0 offered was not.
 * Each row is a reviewer reproduction; each failed at d23026ca.
 */
const REVIEW_R1: Record<string, [string, string, string]> = {
  // Astra B1 — the Node bare-module exemption swallowed expressions and aliases
  "astra: require('fs' && path)": ['node -', "require('fs' && ('/tmp/fx/a.js'))", '/tmp/fx/a.js'],
  "astra: import('fs' && path)": ['node -', "import('fs' && ('/tmp/fx/a.mjs'))", '/tmp/fx/a.mjs'],
  'astra: split child-process name, then spawn': ['node -', "const cp = require('chi' + 'ld_process')\ncp.spawn('/tmp/fx/a.sh')", '/tmp/fx/a.sh'],
  'astra: aliased vm compileFunction': ['node -', "const { compileFunction: f } = require('vm')\nf(require('fs').readFileSync('/tmp/fx/a.js').toString())()", '/tmp/fx/a.js'],
  'astra: module receiver _load': ['node -', "const m = require('module')\nm._load('/tmp/fx/a.js')", '/tmp/fx/a.js'],
  // Astra B2 — Ruby, Perl and PHP spellings
  'astra: ruby load of a local variable': ['ruby -', "p = File.expand_path('/tmp/fx/a.rb')\nload p", '/tmp/fx/a.rb'],
  'astra: ruby self.load': ['ruby -', "self.load('/tmp/fx/a.rb')", '/tmp/fx/a.rb'],
  'astra: perl do +(…)': ['perl -', "do +('/tmp/fx/a.pl');", '/tmp/fx/a.pl'],
  'astra: php INCLUDE in upper case': ['php', "<?php INCLUDE('/tmp/fx/a.php'); ?>", '/tmp/fx/a.php'],
  'astra: php include with comment trivia': ['php', "<?php include/**/('/tmp/fx/a.php'); ?>", '/tmp/fx/a.php'],
  // Grok B1 — concatenation, vm, split child-process name
  "grok: require('fs' + path)": ['node -', "require('fs' + \n'/tmp/fx/concat.js')", '/tmp/fx/concat.js'],
  "grok: import('node:fs' + path)": ['node -', "import('node:fs' + \n'/tmp/fx/nconcat.js')", '/tmp/fx/nconcat.js'],
  "grok: new (require('vm').Script)": ['node -', "new (require('vm').Script)(require('fs').readFileSync(\n'/tmp/fx/vms.js'))", '/tmp/fx/vms.js'],
  'grok: destructured vm Script': ['node -', "const { Script } = require('vm')\nnew Script(require('fs').readFileSync(\n'/tmp/fx/vmd.js'))", '/tmp/fx/vmd.js'],
  "grok: require('vm').compileFunction": ['node -', "require('vm').compileFunction(require('fs').readFileSync(\n'/tmp/fx/vmc.js'))", '/tmp/fx/vmc.js'],
  "grok: import { Script } from 'vm'": ['node --input-type=module -', "import { Script } from 'vm'\nimport fs from 'fs'\nnew Script(fs.readFileSync(\n'/tmp/fx/vmi.js'))", '/tmp/fx/vmi.js'],
  'grok: split child-process name, then fork': ['node -', "require('chi' + 'ld_process').fork(\n'/tmp/fx/fork.js')", '/tmp/fx/fork.js'],
  'grok: split child-process name, then spawn': ['node -', "require('chi' + 'ld_process').spawn(\n'/tmp/fx/spawn2.sh')", '/tmp/fx/spawn2.sh'],
  // Grok B2 — imported posix_spawn, Ruby load/send/autoload, PHP include expression
  'grok: from os import posix_spawn': ['python3 -', "from os import posix_spawn\nposix_spawn(\n'/tmp/fx/spawn.sh'\n, ['spawn'], {})", '/tmp/fx/spawn.sh'],
  'grok: from os import posix_spawnp': ['python3 -', "from os import posix_spawnp\nposix_spawnp(\n'/tmp/fx/spawnp.sh'\n, ['spawnp'], {})", '/tmp/fx/spawnp.sh'],
  'grok: ruby load File.expand_path(…)': ['ruby -', "load File.expand_path('/tmp/fx/expand.rb')", '/tmp/fx/expand.rb'],
  "grok: ruby Kernel.send('load', …)": ['ruby -', "Kernel.send('load',\n'/tmp/fx/sendstr.rb')", '/tmp/fx/sendstr.rb'],
  'grok: ruby autoload': ['ruby -', "autoload :Foo,\n'/tmp/fx/auto.rb'", '/tmp/fx/auto.rb'],
  'grok: php include __DIR__ . path': ['php', "<?php include __DIR__ . \n'/tmp/fx/incdir.php'; ?>", '/tmp/fx/incdir.php'],
  // Same class as grok's send row: the other dynamic-dispatch spellings
  "ruby public_send('load', …)": ['ruby -', "Kernel.public_send('load',\n'/tmp/fx/psend.rb')", '/tmp/fx/psend.rb'],
  "ruby __send__('load', …)": ['ruby -', "Kernel.__send__('load',\n'/tmp/fx/usend.rb')", '/tmp/fx/usend.rb'],
};

describe('#661 follow-up — PR #712 round-1 review reproductions keep the loaded file discoverable', () => {
  it.each(Object.entries(REVIEW_R1))('%s: the loaded file is offered to the resolver', (_name, [interp, body, path]) => {
    const cmd = heredoc(interp, body);
    expect([cmd, asked(cmd)]).toEqual([cmd, expect.arrayContaining([path])]);
  });

  it('a Python json.load data read is scanned as in 5.5.0: the heredoc relief is withdrawn pending an allow-list design', () => {
    const cmd = heredoc('python3 -', "import json\nrows = json.load(open('/tmp/x/table.json'))\nprint(len(rows))");
    expect([cmd, asked(cmd)]).toEqual([cmd, expect.arrayContaining(['/tmp/x/table.json'])]);
  });
});

/**
 * PR #712 round 2 (GPT-6 Astra): spellings the second deny-list still missed
 * at 3e5a9baa, each discovered by 5.5.0. They are why the relief was
 * withdrawn rather than patched again.
 */
const REVIEW_R2: Record<string, [string, string, string]> = {
  // B1 — Perl `do` with its operand on the next line
  'B1 perl do, newline, (path)': ['perl -', "do\n('/tmp/fx/a.pl');", '/tmp/fx/a.pl'],
  'B1 perl do, newline, $variable': ['perl -', "my $f = ('/tmp/fx/a.pl');\ndo\n$f;", '/tmp/fx/a.pl'],
  "B1 perl do, newline, 'path'": ['perl -', "do\n'/tmp/fx/a.pl';", '/tmp/fx/a.pl'],
  // B2 — Ruby receiver aliases, parenthesised receivers, dynamic dispatch
  'B2 ruby Kernel alias .load': ['ruby -', "k = Kernel\nk.load('/tmp/fx/a.rb')", '/tmp/fx/a.rb'],
  'B2 ruby (Kernel).load': ['ruby -', "(Kernel).load('/tmp/fx/a.rb')", '/tmp/fx/a.rb'],
  'B2 ruby (self).load': ['ruby -', "(self).load('/tmp/fx/a.rb')", '/tmp/fx/a.rb'],
  "B2 ruby method('load').call": ['ruby -', "method('load').call('/tmp/fx/a.rb')", '/tmp/fx/a.rb'],
  "B2 ruby Kernel.send 'load' without parens": ['ruby -', "Kernel.send 'load',\n'/tmp/fx/a.rb'", '/tmp/fx/a.rb'],
  // B3 — PHP evaluation is case-insensitive
  'B3 php EVAL': ['php', "<?php EVAL(file_get_contents('/tmp/fx/a.php')); ?>", '/tmp/fx/a.php'],
  'B3 php Eval': ['php', "<?php Eval(file_get_contents('/tmp/fx/a.php')); ?>", '/tmp/fx/a.php'],
  // B4 — Node identifier escapes spell require
  'B4 node req\\u0075ire': ['node -', "req\\u0075ire('/tmp/fx/a.js')", '/tmp/fx/a.js'],
  'B4 node req\\u{75}ire': ['node -', "req\\u{75}ire('/tmp/fx/a.js')", '/tmp/fx/a.js'],
  // B5 — pickle deserialisation can call code
  'B5 python pickle.load': ['python3 -', "import pickle\npickle.load(open(\n'/tmp/fx/a.pkl'\n, 'rb'))", '/tmp/fx/a.pkl'],
};

describe('#661 follow-up — PR #712 round-2 review reproductions keep the loaded file discoverable', () => {
  it.each(Object.entries(REVIEW_R2))('%s: the loaded file is offered to the resolver', (_name, [interp, body, path]) => {
    const cmd = heredoc(interp, body);
    expect([cmd, asked(cmd)]).toEqual([cmd, expect.arrayContaining([path])]);
  });
});
