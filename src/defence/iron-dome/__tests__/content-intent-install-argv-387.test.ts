import { performance } from 'node:perf_hooks';
import { evaluateToolCall } from '../tool-action-guard.js';

const cfg = { enabled: true, enforce: true } as any;
const npm = 'n' + 'pm';
const install = 'in' + 'stall';
const global = '-' + 'g';
const nl = String.fromCharCode(10);
const cr = String.fromCharCode(13);
const ls = String.fromCharCode(0x2028);

function write(ext: string, content: string) {
  return evaluateToolCall('Write', { file_path: `/tmp/run.${ext}`, content }, cfg);
}

function bestOf(n: number, fn: () => void): number {
  let best = Infinity;
  for (let k = 0; k < n; k++) {
    const start = performance.now();
    fn();
    best = Math.min(best, performance.now() - start);
  }
  return best;
}

const argvList = `["${npm}", "${install}", "${global}", "x"]`;

const gated: Array<[string, string, string]> = [
  ['p1 subprocess.run', 'py', `import subprocess${nl}subprocess.run(["${npm}", "${install}", "${global}", "leftpad"])`],
  ['p2 spawn', 'js', `require("child_process").spawn("${npm}", ["${install}", "${global}", "leftpad"])`],
  ['check_output list', 'py', `import subprocess${nl}subprocess.check_output(['${npm}', '${install}', '${global}', 'x'])`],
  ['Popen list', 'py', `import subprocess${nl}subprocess.Popen(["${npm}", "${install}", "${global}", "x"])`],
  ['execFileSync flag first', 'js', `require("child_process").execFileSync("${npm}", ["${global}", "${install}", "x"])`],
  ['location split', 'py', `import subprocess${nl}subprocess.run(["${npm}", "${install}", "--location", "global", "x"])`],
  ['yarn global add', 'js', `require("child_process").spawn("yarn", ["global", "add", "x"])`],
  ['npx wrapper', 'js', `require("child_process").spawn("npx", ["${npm}", "${install}", "${global}", "x"])`],
  // Original #387 matrix rows: closed on main before this change, pinned here.
  ['exec string flag first', 'js', `child_process.exec("${npm} ${global} ${install} x")`],
  ['check_output string', 'py', `import subprocess${nl}subprocess.check_output("${npm} ${install} ${global} x", shell=True)`],
  ['os.system variable', 'py', `import os${nl}cmd = "${npm} ${install} ${global} x"${nl}os.system(cmd)`],
  ['npx shell', 'sh', `#!/bin/sh${nl}npx ${npm} ${install} ${global} x`],
  ['corepack shell', 'sh', `#!/bin/sh${nl}corepack ${npm} ${install} ${global} x`],
  // A lexer that tracked comments/strings before the sink would desync on
  // these and hide the call. The reader does no such tracking.
  ['JS private field before sink', 'js', `class A { #x = 1; go() { this.#x; require("child_process").spawn("${npm}", ["${install}", "${global}", "x"]); } }`],
  ['Python floor division before sink', 'py', `import subprocess${nl}n = 7 // 2; subprocess.run(${argvList})`],
  ['JS quote regex literal before sink', 'js', `const q = /'/; require("child_process").spawnSync("${npm}", ["${install}", "${global}", "x"])`],
  ['sink after a long data list', 'py', `import subprocess${nl}DATA = [${'"a", '.repeat(5000)}"b"]${nl}subprocess.run(${argvList})`],
  ['opaque package', 'py', `subprocess.run(["${npm}", "${install}", "${global}", pkg])`],
  ['spawn opaque package', 'js', `spawn("${npm}", ["${install}", "${global}", pkg])`],
  ['tuple', 'py', `subprocess.run(("${npm}", "${install}", "${global}", "x"))`],
  ['args keyword', 'py', `subprocess.run(args=["${npm}", "${install}", "${global}", "x"])`],
  ['path command', 'py', `subprocess.run(["/usr/bin/${npm}", "${install}", "${global}", "x"])`],
  ['Windows shim command', 'py', `subprocess.run(["${npm}.cmd", "${install}", "${global}", "x"])`],
  ['global true', 'py', `subprocess.run(["${npm}", "${install}", "--global=true", "x"])`],
  ['global one', 'py', `subprocess.run(["${npm}", "${install}", "--global=1", "x"])`],
  ['short global true', 'py', `subprocess.run(["${npm}", "${install}", "-g=true", "x"])`],
  ['short global one', 'py', `subprocess.run(["${npm}", "${install}", "-g=1", "x"])`],
  ['nested opaque element', 'py', `subprocess.run(["${npm}", "${install}", f(x, ")"), "${global}", "x"])`],
  ['Windows path wrapper', 'js', `spawn("C:\\\\x\\\\npx.exe", ["${npm}.cmd", "${install}", "${global}", "x"])`],
  ['opaque subcommand', 'py', `subprocess.run(["${npm}", cmd, "${global}", "x"])`],
  ['flag value before subcommand', 'py', `subprocess.run(["${npm}", "--prefix", "/opt", "${install}", "${global}", "x"])`],
  ['truncated after visible install', 'py', `subprocess.run(["${npm}", "${install}", "${global}", "${'x'.repeat(9000)}"])`],
  ['lone CR ends comment', 'py', `# x${cr}subprocess.run(${argvList})`],
  ['U+2028 ends comment', 'py', `# x${ls}subprocess.run(${argvList})`],
  ['printed pipe executes text', 'sh', `echo 'subprocess.run(${argvList})' | python3`],
  ['shadowed print', 'py', `print = exec${nl}print('subprocess.run(${argvList})')`],
  ['printed concatenation', 'py', `print("x" + subprocess.run(${argvList}))`],
  ['printed interpolation', 'py', `print(f"{subprocess.run(${argvList})}")`],
  ['hash without space', 'py', `#subprocess.run(${argvList})`],
  // Shell echo/printf get no printed-example relief: their output is
  // routinely fed back into an interpreter.
  ['shell echo example', 'sh', `echo 'subprocess.run(${argvList})'`],
  ['echo inside multi-line command substitution', 'sh', `python3 -c "$(${nl}echo 'import subprocess; subprocess.run(${argvList})'${nl})"`],
  // `//usr/bin/python3` is a path a shell runs, not a comment.
  ['double-slash path command', 'sh', `//usr/bin/python3 -c 'import subprocess; subprocess.run(${argvList})'`],
  ['print parameter shadow', 'py', `def f(print):${nl}    print('subprocess.run(${argvList})')${nl}f(exec)`],
  ['console shadowed by with', 'js', `with ({ console: { log: eval } }) {${nl}console.log("spawn('${npm}', ['${install}', '${global}', 'x'])")${nl}}`],
  ['stdout redirected into a child', 'py', `import sys, subprocess${nl}sys.stdout = subprocess.Popen(["python3"], stdin=subprocess.PIPE, text=True).stdin${nl}print('subprocess.run(${argvList})')`],
  ['opaque element after a value flag', 'py', `subprocess.run(["${npm}", "--verbose", cmd, "${global}", "x"])`],
];

describe('written global installs through argv lists (#387)', () => {
  it.each(gated)('gates %s', (_name, ext, content) => {
    const verdict = write(ext, content);
    expect(verdict.signals ?? []).toContain('install-package-global');
    expect(verdict.severity).toBe('dangerous');
  });

  it.each([
    ['local npm list', 'py', `import subprocess${nl}subprocess.run(["${npm}", "${install}", "leftpad"])`],
    ['gcc debug and npm comment', 'py', `import subprocess${nl}# remember: ${npm} ${install} later${nl}subprocess.run(["gcc", "${global}", "main.c"])`],
    ['stored list, no sink', 'py', `ARGS = ${argvList}${nl}print(ARGS)`],
    ['unrelated spawn and note', 'js', `spawn("ls", ["${global}"]); const note = "${npm} ${install}";`],
    ['global flag on a different call', 'py', `import subprocess${nl}subprocess.run(["${npm}", "${install}", "x"])${nl}subprocess.run(["gcc", "${global}", "m.c"])`],
    ['commented sink', 'py', `# subprocess.run(${argvList})`],
    ['printed sink text', 'py', `print('subprocess.run(${argvList})')`],
    ['JS comment', 'js', `// spawn("${npm}", ["${install}", "${global}", "x"])`],
    ['indented comment', 'py', `    # subprocess.run(${argvList})`],
    ['console printed example', 'js', `console.log("spawn('${npm}', ['${install}', '${global}', 'x'])")`],
    ['help topic', 'py', `subprocess.run(["${npm}", "help", "${install}", "${global}"])`],
    ['read-only ls operand', 'py', `subprocess.run(["${npm}", "ls", "${global}", "in"])`],
    ['read-only view operand', 'py', `subprocess.run(["${npm}", "view", "${global}", "i"])`],
    ['opaque package without global', 'py', `subprocess.run(["${npm}", "${install}", pkg])`],
  ])('allows %s', (_name, ext, content) => {
    expect(write(ext, content).signals ?? []).not.toContain('install-package-global');
  });

  it.each([
    ['unfinished list of npm words', 'import subprocess' + nl + 'subprocess.run([' + `"${npm}", `.repeat(20000)],
    ['quote run', 'import subprocess' + nl + 'subprocess.run([' + '"'.repeat(100000)],
    ['nested sinks inside list strings', 'import subprocess' + nl + 'subprocess.run([' + '"subprocess.run([", '.repeat(5000)],
    ['spawn command then nested', 'spawn("x", [' + '"spawn(\\"x\\", [", '.repeat(5000)],
    ['unquoted-element flood', 'subprocess.run([' + 'a, '.repeat(30000) + ' '.repeat(10000)],
    ['nested-bracket flood', 'subprocess.run([' + 'f('.repeat(30000) + ' '.repeat(40000)],
    ['comment sink flood', '# subprocess.run(['.repeat(6000)],
    ['printed sink flood', 'print("spawn('.repeat(9000)],
    ['single-line sink flood after spaces', ' '.repeat(50000) + 'spawn('.repeat(30000)],
  ])('scans 100 KB adversarial argv (%s) in under 300 ms', (_name, content) => {
    expect(content.length).toBeGreaterThan(90_000);
    expect(bestOf(3, () => write('py', content))).toBeLessThan(300);
  });
});
