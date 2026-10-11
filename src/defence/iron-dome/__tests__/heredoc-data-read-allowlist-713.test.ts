import { describe, it, expect } from '@jest/globals';
import { evaluateToolCall, detectScriptInvocations } from '../tool-action-guard.js';
import { bodyIsAllDataRead, splitDataReadStatements } from '../heredoc-data-read.js';

/**
 * #713 — the heredoc data-read relief returns as an ALLOW-LIST (#661 follow-up).
 *
 * #686 masked a whole-command interpreter heredoc whose body had no shell-out
 * sink; #712 withdrew that for 5.6.0 because "no loader found" is a deny-list
 * and two review rounds kept finding loaders it missed. The relief is back
 * only for bodies in which EVERY top-level statement is inert or a recognised
 * data read from a literal path (design of record on #713: I1 literal path,
 * I2 read is outermost, I3 literal identifiers; fail-closed splitter). Any
 * unrecognised statement keeps the 5.5.0 scan.
 *
 * "Masked" is observed the way the #712 tests observe discovery: the paths the
 * guard asks its resolver for. The UNMASKED (5.5.0-behaviour) scan of the same
 * command is taken by putting a no-op statement before it: `true⏎<cmd>` is not
 * the whole-command shape, so the gate never matches and the heredoc is
 * scanned and folded exactly as main does. A control below pins that this
 * baseline really is unmasked.
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

/** The same command scanned with the relief out of reach (5.5.0 behaviour). */
const unmasked = (command: string): string[] => asked(`true\n${command}`);

const heredoc = (interp: string, body: string): string => `${interp} <<'EOF'\n${body}\nEOF`;

/** [interpreter, body, the data file it reads]. Each one is masked. */
const DATA_READS: Record<string, [string, string, string]> = {
  // Python
  'python open().read() assigned, len printed': ['python3 -', "text = open('/tmp/x/table.md').read()\nprint(len(text))", '/tmp/x/table.md'],
  'python #661 live shape': ['python3 -', "import re, json\ntext = open('/tmp/x/table.md').read()\nrows = json.loads(text) if text.startswith('[') else []\nprint(len(re.findall('x', text)), len(rows))", '/tmp/x/table.md'],
  'python json.load(open())': ['python3 -', "import json\nrows = json.load(open('/tmp/x/table.json'))\nprint(len(rows))", '/tmp/x/table.json'],
  'python json.loads(open().read())': ['python3 -', "import json\nrows = json.loads(open('/tmp/x/table.json').read())\nprint(rows['k'])", '/tmp/x/table.json'],
  'python yaml.safe_load(open())': ['python3 -', "import yaml\ncfg = yaml.safe_load(open('/tmp/x/c.yaml'))\nprint(cfg)", '/tmp/x/c.yaml'],
  'python pathlib read_text': ['python3 -', "import pathlib\nprint(pathlib.Path('/tmp/x/table.md').read_text())", '/tmp/x/table.md'],
  'python Path read_bytes': ['python3 -', "from pathlib import Path\nb = Path('/tmp/x/blob.bin').read_bytes()\nprint(len(b))", '/tmp/x/blob.bin'],
  'python readlines, mode and encoding': ['python3 -', "lines = open('/tmp/x/log.txt', 'r', encoding='utf-8').readlines()\nprint(len(lines), lines[0].strip())", '/tmp/x/log.txt'],
  'python print of a read, statements on one line': ['python3 -', "import json; print(open('/tmp/x/table.md').read())", '/tmp/x/table.md'],
  'python csv reader over a bound file': ['python3 -', "import csv\nf = open('/tmp/x/t.csv')\nrows = csv.reader(f)\nprint(list(rows))\nf.close()", '/tmp/x/t.csv'],
  'python comments, docstring, blank lines': ['python3 -', "'''Count table rows.'''\n\n# read the table\ntext = open('/tmp/x/table.md').read()  # data only\nprint(text.count('|'))", '/tmp/x/table.md'],
  // Ruby
  'ruby puts File.read().length': ['ruby -', "puts File.read('/tmp/x/table.md').length", '/tmp/x/table.md'],
  'ruby File.readlines assigned': ['ruby -', "lines = File.readlines('/tmp/x/table.md')\nputs lines.size", '/tmp/x/table.md'],
  'ruby IO.read': ['ruby -', "t = IO.read('/tmp/x/table.md')\np t.strip", '/tmp/x/table.md'],
  'ruby File.open().read': ['ruby -', "t = File.open('/tmp/x/table.md').read\nputs(t.lines.count)", '/tmp/x/table.md'],
  // Perl
  'perl three-argument open and readline': ['perl -', "use strict;\nuse warnings;\nopen(my $fh, '<', '/tmp/x/table.md') or die \"cannot open: $!\";\nmy @lines = <$fh>;\nclose($fh);\nprint scalar(@lines), \"\\n\";", '/tmp/x/table.md'],
  'perl read_file': ['perl -', "use File::Slurp;\nmy $t = read_file('/tmp/x/table.md');\nprint length($t), \"\\n\";", '/tmp/x/table.md'],
  // PHP
  'php file_get_contents': ['php', "<?php\n$t = file_get_contents('/tmp/x/table.md');\necho strlen($t), \"\\n\";\n?>", '/tmp/x/table.md'],
  'php readfile': ['php', "<?php readfile('/tmp/x/table.md'); ?>", '/tmp/x/table.md'],
  'php fopen and fgets': ['php', "<?php\n$f = fopen('/tmp/x/table.md', 'r');\necho fgets($f);\nfclose($f);", '/tmp/x/table.md'],
  'php json_decode(file_get_contents())': ['php', "<?php\n$rows = json_decode(file_get_contents('/tmp/x/table.json'), true);\necho count($rows);", '/tmp/x/table.json'],
  // Node
  "node require('fs').readFileSync": ['node -', "const t = require('fs').readFileSync(\n'/tmp/x/table.md')\nconsole.log(t.length)", '/tmp/x/table.md'],
  "node fs bound from require('node:fs')": ['node -', "const fs = require('node:fs')\nconsole.log(fs.readFileSync(\n'/tmp/x/table.md').length)", '/tmp/x/table.md'],
  'node JSON.parse(fs.readFileSync(…, enc))': ['node -', "'use strict'\nconst fs = require('fs')\nconst rows = JSON.parse(fs.readFileSync('/tmp/x/table.json', 'utf8'))\nconsole.log(rows.length)", '/tmp/x/table.json'],
  'node fs.promises.readFile': ['node -', "const fs = require('fs');\nfs.promises.readFile('/tmp/x/table.md');", '/tmp/x/table.md'],
};

describe('#713 — a body made only of literal-path data reads is masked', () => {
  it.each(Object.entries(DATA_READS))('%s: the data file is not offered to the resolver', (_name, [interp, body, path]) => {
    const cmd = heredoc(interp, body);
    expect([cmd, asked(cmd)]).toEqual([cmd, expect.not.arrayContaining([path])]);
    expect([cmd, detectScriptInvocations(cmd).map(s => s.path)]).toEqual([cmd, expect.not.arrayContaining([path])]);
  });

  it('the baseline is the unmasked 5.5.0 scan: it still offers the data file the mask hides', () => {
    // Rows whose path the 5.5.0 tokeniser reads as a clean token. (Perl's
    // `open(my $fh, '<', '/x')` and a few others never offered it on any version.)
    for (const name of ['python #661 live shape', 'python json.load(open())', 'ruby puts File.read().length', "node require('fs').readFileSync", 'php file_get_contents']) {
      const [interp, body, path] = DATA_READS[name];
      const cmd = heredoc(interp, body);
      expect([name, unmasked(cmd)]).toEqual([name, expect.arrayContaining([path])]);
      expect([name, asked(cmd)]).toEqual([name, expect.not.arrayContaining([path])]);
    }
  });

  it('the mask is length-preserving and only blanks the body', () => {
    const cmd = heredoc('python3 -', "text = open('/tmp/x/table.md').read()\nprint(len(text))");
    // The intro line is still scanned: a path on it is still found.
    const withArgv = cmd.replace("python3 -", 'cd /tmp/x && python3 -');
    expect(asked(withArgv)).not.toContain('/tmp/x/table.md');
    expect(bodyIsAllDataRead("text = open('/tmp/x/table.md').read()\nprint(len(text))", 'python')).toBe(true);
  });

  it('a double-quoted delimiter, an absolute system interpreter and a locale variable keep the relief', () => {
    const body = "print(open('/tmp/x/table.md').read())";
    for (const cmd of [
      `python3 - <<"EOF"\n${body}\nEOF`,
      `/usr/bin/python3.12 - <<'EOF'\n${body}\nEOF`,
      `cd /tmp/x && LC_ALL=C timeout 30 python3 -I - <<'EOF'\n${body}\nEOF`,
    ]) expect([cmd, asked(cmd)]).toEqual([cmd, expect.not.arrayContaining(['/tmp/x/table.md'])]);
  });
});

/**
 * Design §7 — the bypass classes an allow-list invites. Every row has a
 * recognised-looking read in it and must still be scanned: the resolver is
 * asked for the path, and for at least everything the unmasked scan asks for.
 */
const NEAR_MISSES: Record<string, [string, string, string]> = {
  // outer-consumer wrapping (I2)
  'eval(open(x).read())': ['python3 -', "eval(open('/tmp/fx/a.py').read())", '/tmp/fx/a.py'],
  'exec(open(x).read())': ['python3 -', "exec(open('/tmp/fx/a.py').read())", '/tmp/fx/a.py'],
  'a read consumed by an unlisted call': ['python3 -', "run(open('/tmp/fx/a.py').read())", '/tmp/fx/a.py'],
  'len() of a read is not outermost': ['python3 -', "n = len(open(\n'/tmp/fx/a.py').read())", '/tmp/fx/a.py'],
  'vm.runInThisContext(fs.readFileSync(x))': ['node -', "const vm = require('vm')\nconst fs = require('fs')\nvm.runInThisContext(fs.readFileSync(\n'/tmp/fx/a.js'))", '/tmp/fx/a.js'],
  'new Function(fs.readFileSync(x))': ['node -', "const fs = require('fs')\nnew Function(fs.readFileSync(\n'/tmp/fx/a.js'))()", '/tmp/fx/a.js'],
  'Function(fs.readFileSync(x)) without new': ['node -', "const fs = require('fs')\nconst f = Function(fs.readFileSync(\n'/tmp/fx/a.js'))", '/tmp/fx/a.js'],
  'ruby eval(File.read(x))': ['ruby -', "eval(File.read('/tmp/fx/a.rb'))", '/tmp/fx/a.rb'],
  'php eval(file_get_contents(x))': ['php', "<?php eval(file_get_contents('/tmp/fx/a.php')); ?>", '/tmp/fx/a.php'],
  // unsafe deserialisers
  'pickle.load': ['python3 -', "import pickle\nd = pickle.load(open(\n'/tmp/fx/a.pkl'))", '/tmp/fx/a.pkl'],
  'marshal.load': ['python3 -', "import marshal\nd = marshal.load(open(\n'/tmp/fx/a.bin'))", '/tmp/fx/a.bin'],
  'yaml.load (not safe_load)': ['python3 -', "import yaml\nd = yaml.load(open(\n'/tmp/fx/a.yaml'))", '/tmp/fx/a.yaml'],
  'ruby Marshal.load': ['ruby -', "d = Marshal.load(File.read('/tmp/fx/a.bin'))", '/tmp/fx/a.bin'],
  'php unserialize': ['php', "<?php $d = unserialize(file_get_contents('/tmp/fx/a.ser')); ?>", '/tmp/fx/a.ser'],
  // computed / concatenated path (I1)
  "python open('a' + b)": ['python3 -', "b = 'c/x'\nt = open('/et' + b).read()\nprint(\n'/tmp/fx/a.py')", '/tmp/fx/a.py'],
  "python open('/et' + 'c/x')": ['python3 -', "t = open('/et' + 'c/x').read()\nprint(\n'/tmp/fx/a.py')", '/tmp/fx/a.py'],
  'python open(variable)': ['python3 -', "p = '/tmp/x/t.md'\nt = open(p).read()\nprint(\n'/tmp/fx/a.py')", '/tmp/fx/a.py'],
  'ruby File.read(variable)': ['ruby -', "p = '/tmp/x/t.md'\nt = File.read(p)\nputs(\n'/tmp/fx/a.rb')", '/tmp/fx/a.rb'],
  "php include __DIR__ . '…'": ['php', "<?php include __DIR__ . \n'/tmp/fx/a.php'; ?>", '/tmp/fx/a.php'],
  'php file_get_contents(__DIR__ . …)': ['php', "<?php $t = file_get_contents(__DIR__ .\n'/tmp/fx/a.php'); ?>", '/tmp/fx/a.php'],
  'ruby pipe path': ['ruby -', "t = IO.read('|sh /tmp/fx/a.sh')\nputs(\n'/tmp/fx/a.sh')", '/tmp/fx/a.sh'],
  'php stream wrapper': ['php', "<?php $t = file_get_contents('phar:///tmp/fx/a.phar');\necho(\n'/tmp/fx/a.php'); ?>", '/tmp/fx/a.php'],
  // a sink beside a read
  'subprocess.run(open(x).read(), shell=True)': ['python3 -', "import subprocess\nsubprocess.run(open('/tmp/fx/a.sh').read(), shell=True)", '/tmp/fx/a.sh'],
  // dynamic dispatch / aliasing (I3)
  "ruby method('read').call": ['ruby -', "t = method('read').call(\n'/tmp/fx/a.rb')", '/tmp/fx/a.rb'],
  'ruby send(:read, …)': ['ruby -', "t = File.send(:read,\n'/tmp/fx/a.rb')", '/tmp/fx/a.rb'],
  'python f = open; f(x)': ['python3 -', "f = open\nt = f(\n'/tmp/fx/a.py').read()", '/tmp/fx/a.py'],
  'python getattr dispatch': ['python3 -', "t = getattr(__builtins__, 'open')(\n'/tmp/fx/a.py').read()", '/tmp/fx/a.py'],
  'node fs alias via destructuring': ['node -', "const { readFileSync } = require('fs')\nconst t = readFileSync(\n'/tmp/fx/a.js')", '/tmp/fx/a.js'],
  'node require of a non-fs module': ['node -', "const m = require('module')\nconst t = m.readFileSync(\n'/tmp/fx/a.js')", '/tmp/fx/a.js'],
  // multi-statement smuggling
  "open('x').read(); require('y') on one line": ['python3 -', "open('/tmp/x/table.md').read(); require('/tmp/fx/a.py')", '/tmp/fx/a.py'],
  "node read; require('y') on one line": ['node -', "const fs = require('fs'); fs.readFileSync('/tmp/x/t.md'); require('/tmp/fx/a.js')", '/tmp/fx/a.js'],
  'read then a loader on the next line': ['python3 -', "t = open('/tmp/x/table.md').read()\nimport runpy\nrunpy.run_path('/tmp/fx/a.py')", '/tmp/fx/a.py'],
  'loader then a read': ['ruby -', "load('/tmp/fx/a.rb')\nputs File.read('/tmp/x/table.md')", '/tmp/fx/a.rb'],
  // nested heredoc / substitution in the body (splitter fails closed)
  'nested heredoc': ['python3 -', "t = open('/tmp/x/table.md').read()\nx = 1 << 2\nprint(\n'/tmp/fx/a.py')", '/tmp/fx/a.py'],
  'backtick in the body': ['python3 -', "t = open('/tmp/x/table.md').read()\nprint('`x`')\nprint(\n'/tmp/fx/a.py')", '/tmp/fx/a.py'],
  '$( in the body': ['python3 -', "t = open('/tmp/x/table.md').read()\nprint('$(x)')\nprint(\n'/tmp/fx/a.py')", '/tmp/fx/a.py'],
  '${ in the body': ['python3 -', "t = open('/tmp/x/table.md').read()\nprint('${x}')\nprint(\n'/tmp/fx/a.py')", '/tmp/fx/a.py'],
  'ruby #{} interpolation': ['ruby -', "t = File.read('/tmp/x/table.md')\nputs \"#{load('/tmp/fx/a.rb')}\"", '/tmp/fx/a.rb'],
  'perl @{[ ]} interpolation': ['perl -', "my $t = read_file('/tmp/x/table.md');\nprint \"@{[ do('/tmp/fx/a.pl') ]}\";", '/tmp/fx/a.pl'],
  'python f-string': ['python3 -', "t = open('/tmp/x/table.md').read()\nprint(f\"{__import__('runpy').run_path('/tmp/fx/a.py')}\")", '/tmp/fx/a.py'],
  // block / compound forms
  'python if True:': ['python3 -', "if True:\n    t = open(\n'/tmp/fx/a.py').read()", '/tmp/fx/a.py'],
  'python for loop': ['python3 -', "for p in ['/tmp/x/t.md']:\n    print(\n'/tmp/fx/a.py')", '/tmp/fx/a.py'],
  'python with block': ['python3 -', "with open('/tmp/x/t.md') as f:\n    print(\n'/tmp/fx/a.py')", '/tmp/fx/a.py'],
  'python def': ['python3 -', "def f():\n    return open(\n'/tmp/fx/a.py').read()", '/tmp/fx/a.py'],
  'python lambda': ['python3 -', "f = lambda: open(\n'/tmp/fx/a.py').read()", '/tmp/fx/a.py'],
  'python comprehension': ['python3 -', "x = [open(p).read() for p in ['/tmp/x/t.md']]\nprint(\n'/tmp/fx/a.py')", '/tmp/fx/a.py'],
  'ruby do block': ['ruby -', "File.open('/tmp/x/t.md') do |f|\n  puts(\n'/tmp/fx/a.rb')\nend", '/tmp/fx/a.rb'],
  'ruby brace block': ['ruby -', "File.readlines('/tmp/x/t.md').each { |l| puts l }\nputs(\n'/tmp/fx/a.rb')", '/tmp/fx/a.rb'],
  'node arrow function': ['node -', "const fs = require('fs')\nconst f = () => fs.readFileSync(\n'/tmp/fx/a.js')", '/tmp/fx/a.js'],
  'node statement opening with {': ['node -', "{ console.log(\n'/tmp/fx/a.js') }", '/tmp/fx/a.js'],
  'perl do block slurp': ['perl -', "open(my $fh, '<', '/tmp/x/t.md');\nmy $t = do { local $/; <$fh> };\nprint(\n'/tmp/fx/a.pl');", '/tmp/fx/a.pl'],
  'php function': ['php', "<?php function f() { return file_get_contents(\n'/tmp/fx/a.php'); } ?>", '/tmp/fx/a.php'],
  // unclosed quote / bracket
  'unclosed bracket': ['python3 -', "t = open('/tmp/x/table.md').read()\nprint(\n'/tmp/fx/a.py'", '/tmp/fx/a.py'],
  'unclosed quote': ['python3 -', "t = open('/tmp/x/table.md').read()\nprint(\n'/tmp/fx/a.py')\nx = '", '/tmp/fx/a.py'],
  // escaped identifiers (I3)
  'node \\u escape in readFileSync': ['node -', "const fs = require('fs')\nfs.readFile\\u0053ync(\n'/tmp/fx/a.js')", '/tmp/fx/a.js'],
  "node \\u escape in require('fs')": ['node -', "const fs = require('\\u0066s')\nfs.readFileSync(\n'/tmp/fx/a.js')", '/tmp/fx/a.js'],
  'python non-ASCII identifier': ['python3 -', "ｅｖａｌ(open(\n'/tmp/fx/a.py').read())", '/tmp/fx/a.py'],
  'python coding cookie': ['python3 -', "# -*- coding: utf-7 -*-\nt = open('/tmp/x/t.md').read()\nprint(\n'/tmp/fx/a.py')", '/tmp/fx/a.py'],
  'python coding cookie on line 2': ['python3 -', "print(1)\n# coding: utf_7\nprint('+AAo-import runpy')\nprint(\n'/tmp/fx/a.py')", '/tmp/fx/a.py'],
  // The guard blanks shell `#` comments before detection, so a `#` inside a
  // literal can be cut from its view; a literal that could span lines would
  // then close where the interpreter's does not.
  'python triple-quoted literal around a stripped #': ['python3 -', 'x = """ #"""\nimport runpy; runpy.run_path(\n\'/tmp/fx/a.py\')\ny = """\n"""', '/tmp/fx/a.py'],
  'ruby multi-line literal around a stripped #': ['ruby -', 'x = \' #\'\nload(\n"/tmp/fx/a.rb")\ny = \'\n\'', '/tmp/fx/a.rb'],
  'python backslash-newline inside a literal': ['python3 -', "x = 'a\\\nb'\nprint(\n'/tmp/fx/a.py')", '/tmp/fx/a.py'],
  // a write is not a read
  "python open(x, 'w')": ['python3 -', "f = open('/tmp/x/t.md', 'w')\nprint(\n'/tmp/fx/a.py')", '/tmp/fx/a.py'],
  "perl two-argument open (pipe)": ['perl -', "open(F, 'sh /tmp/fx/a.sh|');\nprint(\n'/tmp/fx/a.sh');", '/tmp/fx/a.sh'],
  'perl newline mid-statement': ['perl -', "my $t =\nread_file('/tmp/x/t.md');\ndo\n('/tmp/fx/a.pl');", '/tmp/fx/a.pl'],
};

describe('#713 — design §7 near misses keep discovery', () => {
  it.each(Object.entries(NEAR_MISSES))('%s: scanned, path offered, nothing less than the unmasked scan', (_name, [interp, body, path]) => {
    const cmd = heredoc(interp, body);
    const got = asked(cmd);
    expect([cmd, got]).toEqual([cmd, expect.arrayContaining([path, ...unmasked(cmd)])]);
  });
});

describe('#713 — the classifier refuses what it cannot segment', () => {
  it('fail-closed splitter cases are unrecognised', () => {
    const rows: Array<[string, 'python' | 'node' | 'ruby' | 'perl' | 'php']> = [
      ["print('x'", 'python'],
      ["print('x')\n)", 'python'],
      ["x = '''open", 'python'],
      ["if True: print('x')", 'python'],
      ["print('a')\nwhile 1: pass", 'python'],
      ["x = 1 \\\n+ 2\nprint(x) \\", 'python'],
      ["print('a') \\ print('b')", 'python'],
      ["@decorator\nprint('x')", 'python'],
      ["print('x')\r", 'python'],
      ['print(1)\nx = `id`', 'python'],
      ["x = <<A\nA", 'ruby'],
      ["begin\nputs 1\nend", 'ruby'],
      ['p = File.read("/tmp/x/t.md")\nputs "#{p}"', 'ruby'],
      ['print "$x\\n";', 'perl'],
      ['print 1\n;', 'perl'],
      ['$t = file_get_contents("/tmp/$x");', 'php'],
      ["echo 1; ?> <?php echo 2;", 'php'],
      ["<?php echo 1; ?> text", 'php'],
      ["echo 1;", 'php'],
      ['const a = 1\n(console.log(a))', 'node'],
      ["console.log(1)\n/x/.test('a')", 'node'],
      ['#!/usr/bin/env node\nconsole.log(1)', 'node'],
      ['console.log(${x})', 'node'],
    ];
    for (const [body, lang] of rows) expect([body, bodyIsAllDataRead(body, lang)]).toEqual([body, false]);
  });

  it('splits only on depth-0 newlines and semicolons', () => {
    const s = splitDataReadStatements("a = open('/x;y').read(); print(len(\na))\n\n# c ; d\nprint('e\\'f')", 'python');
    expect(s?.map(t => t.map(x => x.v).join(' '))).toEqual([
      'a = open ( /x;y ) . read ( )',
      'print ( len ( a ) )',
      "print ( e\\'f )",
    ]);
  });

  it('a body that is unrecognised in one statement is unrecognised as a whole', () => {
    expect(bodyIsAllDataRead("t = open('/tmp/x/t.md').read()\nprint(len(t))", 'python')).toBe(true);
    expect(bodyIsAllDataRead("t = open('/tmp/x/t.md').read()\nprint(len(t))\nos.remove('/tmp/x/t.md')", 'python')).toBe(false);
    expect(bodyIsAllDataRead("t = open('/tmp/x/t.md').read()\nprint(len(t))", 'sh')).toBe(false);
  });
});

/**
 * Probes from the #686 and #712 reviews: the interpreter that reads the body
 * is not the one the intro line seems to name, or the heredoc is not the whole
 * command. The body is a data read the relief WOULD mask, so any of these
 * reaching the mask would be a hole. Every one keeps the unmasked scan.
 */
const READ_BODY = "print(open('/tmp/fx/a.sh').read())";
const DECOYS: Record<string, string> = {
  'bash -s python3 <<EOF': `bash -s python3 <<'EOF'\n${READ_BODY}\nEOF`,
  'node -v; cat <<EOF | ash': `node -v; cat <<'EOF' | ash\n${READ_BODY}\nEOF`,
  'python3 - <<EOF | sh': `python3 - <<'EOF' | sh\n${READ_BODY}\nEOF`,
  'eval "$(cat <<EOF': `python3 -V; eval "$(cat <<'EOF'\n${READ_BODY}\nEOF\n)"`,
  'python3 -W, newline, bash <<EOF': `python3 -W\nbash <<'EOF'\n${READ_BODY}\nEOF`,
  'python3 shadowed by a function': `python3() { bash; }\npython3 - <<'EOF'\n${READ_BODY}\nEOF`,
  'python3 shadowed by an alias': `alias python3=bash\npython3 - <<'EOF'\n${READ_BODY}\nEOF`,
  '/tmp/python3': `/tmp/python3 - <<'EOF'\n${READ_BODY}\nEOF`,
  './python3': `./python3 - <<'EOF'\n${READ_BODY}\nEOF`,
  'PATH=/tmp/b python3': `PATH=/tmp/b python3 - <<'EOF'\n${READ_BODY}\nEOF`,
  'PYTHONPATH=/tmp/b python3': `PYTHONPATH=/tmp/b python3 - <<'EOF'\n${READ_BODY}\nEOF`,
  'NODE_OPTIONS before node': `NODE_OPTIONS=--require=/tmp/fx/a.js node - <<'EOF'\nconsole.log(require('fs').readFileSync('/tmp/fx/a.sh'))\nEOF`,
  'unquoted delimiter': `python3 - <<EOF\n${READ_BODY}\nEOF`,
  'sudo python3': `sudo python3 - <<'EOF'\n${READ_BODY}\nEOF`,
  'followed by a statement': `python3 - <<'EOF'\n${READ_BODY}\nEOF\nsh /tmp/fx/a.sh`,
  'closer look-alike line': `python3 - <<'EOF'\n${READ_BODY}\nEOF #\nsh /tmp/fx/a.sh\nEOF`,
  'output captured to a file that runs': `python3 - <<'EOF' > /tmp/fx/g.sh\n${READ_BODY}\nEOF\nsh /tmp/fx/g.sh`,
  'bash heredoc': `bash <<'EOF'\n${READ_BODY}\nEOF`,
};

describe('#713 — decoy interpreters and non-whole commands keep the unmasked scan', () => {
  it.each(Object.entries(DECOYS))('%s', (_name, cmd) => {
    const base = unmasked(cmd);
    expect([cmd, asked(cmd)]).toEqual([cmd, expect.arrayContaining(base)]);
    // Where 5.5.0 offered the body's path, it is still offered.
    if (base.includes('/tmp/fx/a.sh')) expect(asked(cmd)).toContain('/tmp/fx/a.sh');
  });

  it('the decoy rows do reach the path on 5.5.0 (the probe is not vacuous)', () => {
    const reaching = Object.values(DECOYS).filter(cmd => unmasked(cmd).includes('/tmp/fx/a.sh'));
    expect(reaching.length).toBeGreaterThanOrEqual(10);
  });
});

/**
 * Differential probe (#712's acceptance check, restated for #713, design §6.3):
 * on the loader / attack corpus, the guard must ask the resolver for at least
 * everything the unmasked 5.5.0-behaviour scan asks for. The corpus is the
 * three #712 tables (copied verbatim from guard-fold-code-loaders.test.ts),
 * the §7 near misses above, and every loader row re-run with a recognised
 * data read before it and after it — the "mostly data, one loader" shape an
 * allow-list has to refuse. The benign DATA_READS rows are deliberately NOT in
 * this invariant: asking for less than 5.5.0 there is the relief.
 */
const PROBE_LOADERS: Record<string, [string, string, string]> = {
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
const PROBE_REVIEW_R1: Record<string, [string, string, string]> = {
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
const PROBE_REVIEW_R2: Record<string, [string, string, string]> = {
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

/** A recognised data read in each language, to surround a loader with. */
const BENIGN_READ: Record<string, string> = {
  python: "t = open('/tmp/x/table.md').read()",
  ruby: "t = File.read('/tmp/x/table.md')",
  perl: "my $t = read_file('/tmp/x/table.md');",
  php: "$t = file_get_contents('/tmp/x/table.md');",
  node: "const t = require('fs').readFileSync('/tmp/x/table.md')",
};
const langOf = (interp: string): string => /^python/.test(interp) ? 'python' : interp.split(' ')[0];

function withBenignRead(interp: string, body: string, where: 'before' | 'after'): string {
  const read = BENIGN_READ[langOf(interp)];
  if (langOf(interp) === 'php') {
    return where === 'before' ? body.replace('<?php ', `<?php ${read}\n`) : body.replace(/ \?>$/, `\n${read} ?>`);
  }
  return where === 'before' ? `${read}\n${body}` : `${body}\n${read}`;
}

const LOADER_ROWS: Array<[string, [string, string, string]]> = [
  ...Object.entries(PROBE_LOADERS),
  ...Object.entries(PROBE_REVIEW_R1),
  ...Object.entries(PROBE_REVIEW_R2),
];
const PROBE_CORPUS: Array<[string, string, string]> = [
  ...LOADER_ROWS.map(([n, [i, b, p]]): [string, string, string] => [n, heredoc(i, b), p]),
  ...LOADER_ROWS.map(([n, [i, b, p]]): [string, string, string] => [`${n} + read before`, heredoc(i, withBenignRead(i, b, 'before')), p]),
  ...LOADER_ROWS.map(([n, [i, b, p]]): [string, string, string] => [`${n} + read after`, heredoc(i, withBenignRead(i, b, 'after')), p]),
  ...Object.entries(NEAR_MISSES).map(([n, [i, b, p]]): [string, string, string] => [`near miss: ${n}`, heredoc(i, b), p]),
];

describe('#713 — differential probe: the loader/attack corpus requests at least what the unmasked scan requests', () => {
  it('covers at least the 165 bodies of the #712 probe', () => {
    expect(PROBE_CORPUS.length).toBeGreaterThanOrEqual(165);
  });

  it.each(PROBE_CORPUS)('%s', (_name, cmd, path) => {
    const base = unmasked(cmd);
    const got = asked(cmd);
    expect([cmd, got]).toEqual([cmd, expect.arrayContaining(base)]);
    expect([cmd, got]).toEqual([cmd, expect.arrayContaining([path])]);
  });
});

/**
 * Performance (design §3, #86 budget style). The splitter is one forward lexer
 * pass and the idiom matcher a bounded-depth parser, so a body costs linear
 * time however it is shaped. Each row runs through `detectScriptInvocations`,
 * the entry point that applies the mask, at FALLBACK_SCAN_CAP (4096) and at 25x
 * that, with a long body the relief accepts next to each long body it refuses.
 */
const TIME_BUDGET_MS = 300;
const FALLBACK_SCAN_CAP = 4096;

function timedDetect(cmd: string): { paths: string[]; ms: number } {
  const t0 = performance.now();
  const paths = detectScriptInvocations(cmd).map(s => s.path);
  return { paths, ms: performance.now() - t0 };
}

const fill = (unit: string, size: number): string => unit.repeat(Math.ceil(size / unit.length));

describe('#713 — the splitter and idiom matchers are linear', () => {
  for (const size of [FALLBACK_SCAN_CAP, FALLBACK_SCAN_CAP * 25]) {
    describe(`${size}-char bodies`, () => {
      const longRead = fill("t = open('/tmp/x/table.md').read()\nprint(len(t), t.count('|'))\n", size);

      it('long data-read body (python): masked, in budget', () => {
        const r = timedDetect(heredoc('python3 -', longRead));
        expect(r.paths).not.toContain('/tmp/x/table.md');
        expect(r.ms).toBeLessThan(TIME_BUDGET_MS);
      });

      it('long data-read body with one loader at the end: scanned, in budget', () => {
        const r = timedDetect(heredoc('python3 -', `${longRead}import runpy\nrunpy.run_path('/tmp/fx/a.py')`));
        expect(r.paths).toContain('/tmp/fx/a.py');
        expect(r.ms).toBeLessThan(TIME_BUDGET_MS);
      });

      it('long data-read body (node, php, ruby, perl): masked, in budget', () => {
        const rows: Array<[string, string]> = [
          ['node -', fill("const t = require('fs').readFileSync('/tmp/x/table.md', 'utf8')\nconsole.log(t.length, t.split('|').length)\n", size)],
          ['php', `<?php\n${fill("$t = file_get_contents('/tmp/x/table.md');\necho strlen($t), \"\\n\";\n", size)}?>`],
          ['ruby -', fill("t = File.read('/tmp/x/table.md')\nputs t.lines.count\n", size)],
          ['perl -', fill("my $t = read_file('/tmp/x/table.md');\nprint length($t), \"\\n\";\n", size)],
        ];
        for (const [interp, body] of rows) {
          const r = timedDetect(heredoc(interp, body));
          expect([interp, r.paths]).toEqual([interp, expect.not.arrayContaining(['/tmp/x/table.md'])]);
          expect(r.ms).toBeLessThan(TIME_BUDGET_MS);
        }
      });

      it('one unclosed-bracket line: refused, in budget', () => {
        const r = timedDetect(heredoc('python3 -', `print(${fill("t, '/tmp/x/a', ", size)}`));
        expect(r.ms).toBeLessThan(TIME_BUDGET_MS);
        expect(bodyIsAllDataRead(`print(${fill("t, '/tmp/x/a', ", size)}`, 'python')).toBe(false);
      });

      it('bracket nesting, an unclosed quote, a long method chain and a long operator chain: in budget', () => {
        const bodies = [
          '('.repeat(size),
          '['.repeat(size / 2) + ']'.repeat(size / 2),
          `x = '${'a'.repeat(size)}`,
          `x = """${'a\n'.repeat(size / 2)}`,
          `t = open('/tmp/x/t.md').read()${'.strip()'.repeat(size / 8)}`,
          `t = 'a'${" + 'a'".repeat(size / 6)}\nprint(t)`,
          `print(${'len('.repeat(size / 4)}`,
          `x = ${'-'.repeat(size)}1`,
          `${'#'.repeat(size)}\nprint(1)`,
        ];
        for (const body of bodies) {
          const t0 = performance.now();
          bodyIsAllDataRead(body, 'python');
          detectScriptInvocations(heredoc('python3 -', body));
          expect(performance.now() - t0).toBeLessThan(TIME_BUDGET_MS);
        }
      });

      it('long blank-line body: in budget', () => {
        const r = timedDetect(heredoc('python3 -', '\n'.repeat(size)));
        expect(r.ms).toBeLessThan(TIME_BUDGET_MS);
      });
    });
  }

  it('"\\n".repeat(1e5) and a 1e5-char unclosed-bracket line: in budget, with a long positive alongside', () => {
    for (const [body, masked] of [
      ['\n'.repeat(1e5), true],
      [`print(${'x, '.repeat(33_334)}`, false],
      [fill("print(open('/tmp/x/table.md').read())\n", 1e5), true],
    ] as Array<[string, boolean]>) {
      const t0 = performance.now();
      expect(bodyIsAllDataRead(body, 'python')).toBe(masked);
      detectScriptInvocations(heredoc('python3 -', body));
      expect(performance.now() - t0).toBeLessThan(TIME_BUDGET_MS);
    }
  });

  it('through evaluateToolCall at FALLBACK_SCAN_CAP: masked and scanned bodies both in budget', () => {
    const longRead = fill("t = open('/tmp/x/table.md').read()\nprint(len(t))\n", FALLBACK_SCAN_CAP);
    for (const [body, path, offered] of [
      [longRead, '/tmp/x/table.md', false],
      [`${longRead}import runpy\nrunpy.run_path('/tmp/fx/a.py')`, '/tmp/fx/a.py', true],
    ] as Array<[string, string, boolean]>) {
      const t0 = performance.now();
      const got = asked(heredoc('python3 -', body));
      expect(performance.now() - t0).toBeLessThan(TIME_BUDGET_MS);
      expect(got.includes(path)).toBe(offered);
    }
  });
});
