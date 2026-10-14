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
  ['vars computed print rebound', 'py', `vars()["pr" + "int"] = eval${nl}print('subprocess.run(${argvList})')`],
  ['locals computed print rebound', 'py', `locals()["pr" + "int"] = eval${nl}print('subprocess.run(${argvList})')`],
  ['exec computed print rebound', 'py', `exec("pr" + "int = eval")${nl}print('subprocess.run(${argvList})')`],
  ['builtins computed print rebound', 'py', `import sys${nl}sys.modules["built" + "ins"].__dict__["pr" + "int"] = eval${nl}print('subprocess.run(${argvList})')`],
  ['globalThis computed console rebound', 'js', `globalThis["con" + "sole"] = { log: eval }${nl}console.log("spawn('${npm}', ['${install}', '${global}', 'x'])")`],
  ['globalThis computed log rebound', 'js', `const k = "log"; globalThis["con" + "sole"][k] = eval${nl}console.log("spawn('${npm}', ['${install}', '${global}', 'x'])")`],
  ['printed concatenation', 'py', `print("x" + subprocess.run(${argvList}))`],
  ['printed interpolation', 'py', `print(f"{subprocess.run(${argvList})}")`],
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
  ['triple double quote', 'py', `s = """\n# """; subprocess.run(${argvList})`],
  ['triple single quote', 'py', `s = '''\nprint("'''; subprocess.run(${argvList}); t = '''")\n'''`],
  ['JS template literal', 'js', `const s = \`\n// \`; spawn("${npm}", ["${install}", "${global}", "x"]);`],
  ['JS block comment', 'js', `/*\nconsole.log("*/ spawn('${npm}', ['${install}', '${global}', 'x']); /*")\n*/`],
  ['form feed before Python hash', 'py', `x = "\u000c# "; subprocess.run(${argvList})`],
  ['line separator before Python hash', 'py', `x = "\u2028# "; subprocess.run(${argvList})`],
  ['line separator before JS slash', 'js', `const x = "\u2028// "; spawn("${npm}", ["${install}", "${global}", "x"]);`],
  ['vertical tab before JS slash', 'js', `const x = "\u000b// "; spawn("${npm}", ["${install}", "${global}", "x"]);`],
  ['next line before Python hash', 'py', `x = "\u0085# "; subprocess.run(${argvList})`],
  ['shell unterminated quote line', 'sh', `x="\n# "; python3 -c 'import subprocess; subprocess.run(${argvList})'`],
  ['Python continuation floor division', 'py', `y = (a\n     // 2); subprocess.run(${argvList})`],
  ['JS private field line', 'js', `#x; spawn("${npm}", ["${install}", "${global}", "x"])`],
  ['redefined print direct call', 'py', `def print(s):\n    exec(s)\nprint('subprocess.run(${argvList})')`],
  ['redefined print beyond first window', 'py', `print('subprocess.run(${argvList})')\n${'# pad\n'.repeat(10000)}def print(s):\n    exec(s)`],
  ['nested JS sink', 'js', `spawn("ls", [f(spawn("${npm}", ["${install}", "${global}", "x"]))])`],
  ['nested Python sink', 'py', `subprocess.run(["echo", str(subprocess.run(${argvList}))])`],
  ['outer Python install after nested sink', 'py', `subprocess.run(["${npm}", "${install}", str(subprocess.run(["ls"])), "${global}", "x"])`],
  ['outer JS install after nested sink', 'js', `spawn("${npm}", ["${install}", f(spawn("ls", [])), "${global}", "x"])`],
  ['outer install after quoted sink spelling', 'py', `subprocess.run(["${npm}", "${install}", "see subprocess.run(", "${global}", "x"])`],
  ['outer JS install after quoted sink spelling', 'js', `spawn("${npm}", ["${install}", "see spawn(", "${global}", "x"])`],
  ['env wrapper', 'py', `subprocess.run(["env", "${npm}", "${install}", "${global}", "x"])`],
  ['env options and assignment', 'py', `subprocess.run(["env", "-u", "OLD", "-C", "/tmp", "A=1", "${npm}", "${install}", "${global}", "x"])`],
  ['env opaque assignment', 'py', `subprocess.run(["env", assignment, "${npm}", "${install}", "${global}", "x"])`],
  ['command wrapper', 'py', `subprocess.run(["command", "${npm}", "${install}", "${global}", "x"])`],
  ['nohup wrapper', 'py', `subprocess.run(["nohup", "${npm}", "${install}", "${global}", "x"])`],
  ['time wrapper', 'py', `subprocess.run(["time", "${npm}", "${install}", "${global}", "x"])`],
  ['nice wrapper', 'py', `subprocess.run(["nice", "-n", "5", "${npm}", "${install}", "${global}", "x"])`],
  ['repeated wrappers before corepack', 'py', `subprocess.run(["env", "A=1", "nice", "-5", "corepack", "${npm}", "${install}", "${global}", "x"])`],
  ['unknown script language', 'rb', `# subprocess.run(${argvList})`],
  // Printed examples gate because print and console can be rebound to eval.
  ['printed sink text', 'py', `print('subprocess.run(${argvList})')`],
  ['printed sink with trailing comment', 'py', `print('subprocess.run(${argvList})')  # example`],
  ['console printed example', 'js', `console.log("spawn('${npm}', ['${install}', '${global}', 'x'])")`],
  ['Python frame globals rebound', 'py', `fr.f_globals.update({"pr"+"int": fr.f_builtins["ev"+"al"]})${nl}print('subprocess.run(${argvList})')`],
  ['Python function globals rebound', 'py', `f.__globals__.update({"pr"+"int": f.__globals__["ev"+"al"]})${nl}print('subprocess.run(${argvList})')`],
  ['JS sloppy global console rebound', 'js', `const g = (function(){return this})();${nl}g["con"+"sole"].log = g["ev"+"al"];${nl}console.log("spawn('${npm}', ['${install}', '${global}', 'x'])")`],
  ['JS Object.assign console rebound', 'js', `const g = (function(){return this})();${nl}Object.assign(g["con"+"sole"], {log: g["ev"+"al"]});${nl}console.log("spawn('${npm}', ['${install}', '${global}', 'x'])")`],
  ['real sink after apostrophe comment', 'py', `# don't${nl}subprocess.run(${argvList})`],
  ['real sink after trailing comment', 'py', `x = 1 # c${nl}subprocess.run(${argvList})`],
  ['shell hash inside multiline quote', 'sh', `python3 -c '${nl}# x${nl}import subprocess; subprocess.run(${argvList})${nl}'`],
  ['shell midword hash', 'sh', `echo a#b subprocess.run(${argvList})`],
  // Shell relief is off with a here-document (its body may be another
  // language, where a leading # is code) or an ANSI-C $'...' quote.
  ['shell heredoc JS private field', 'sh', `node <<'EOF'${nl}class A {${nl}#x = require("child_process").spawnSync("${npm}", ["${install}", "${global}", "x"])${nl}}${nl}new A()${nl}EOF`],
  ['shell ANSI-C quote before hash line', 'sh', `node -e $'class A {\\'${nl}#x = require("child_process").spawnSync("${npm}", ["${install}", "${global}", "x"])${nl}}'`],
  ['budget exhausted with yarn global add', 'py', 'spawn("ls", ['.repeat(7500) + nl + `subprocess.run(["yarn", "global", "add", "x"])`],
  ['budget exhausted with separate --location', 'py', 'spawn("ls", ['.repeat(7500) + nl + `subprocess.run(["${npm}", "${install}", "--location", "global", "x"])`],
];

describe('written global installs through argv lists (#387)', () => {
  it.each(gated)('gates %s', (_name, ext, content) => {
    const verdict = write(ext, content);
    expect(verdict.decision).toBe('require_approval');
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
    ['hash without space', 'py', `#subprocess.run(${argvList})`],
    ['quoted comment before sink', 'py', `# "note" subprocess.run(${argvList})`],
    ['quote between two commented sinks', 'py', `# subprocess.run(${argvList}); "note" subprocess.run(${argvList})`],
    ['apostrophe in commented sink', 'py', `# don't run: subprocess.run(${argvList})`],
    ['apostrophe on another comment line', 'py', `# it's fine${nl}# subprocess.run(${argvList})`],
    ['JS apostrophe in commented sink', 'js', `// it's fine: spawn("${npm}", ["${install}", "${global}", "x"])`],
    ['trailing apostrophe comment before commented sink', 'py', `x = 1  # don't${nl}# subprocess.run(${argvList})`],
    ['lone CR before commented sink', 'py', `x = 1${cr}# subprocess.run(${argvList})`],
    ['JS comment', 'js', `// spawn("${npm}", ["${install}", "${global}", "x"])`],
    ['indented comment', 'py', `    # subprocess.run(${argvList})`],
    ['nested noninstall outer argv', 'py', `subprocess.run(["echo", str(subprocess.run(["ls"])), "${global}"])`],
    ['shell whole comment line with apostrophe', 'sh', `# don't: subprocess.run(${argvList})`],
    ['nested flood without a package manager', 'py', 'spawn("ls", ['.repeat(7500)],
    ['help topic', 'py', `subprocess.run(["${npm}", "help", "${install}", "${global}"])`],
    ['read-only ls operand', 'py', `subprocess.run(["${npm}", "ls", "${global}", "in"])`],
    ['read-only view operand', 'py', `subprocess.run(["${npm}", "view", "${global}", "i"])`],
    ['opaque package without global', 'py', `subprocess.run(["${npm}", "${install}", pkg])`],
    ['known prefix consumes install', 'py', `subprocess.run(["${npm}", "--prefix", "${install}", "ls", "${global}"])`],
    ['known registry consumes install', 'py', `subprocess.run(["${npm}", "--registry", "${install}", "ls", "${global}"])`],
    ['known location consumes non-global install', 'py', `subprocess.run(["${npm}", "--location", "${install}", "ls", "${global}"])`],
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
    ['nested spawn flood', 'spawn("ls", ['.repeat(7500) + ' '.repeat(30000)],
    ['quoted Python sink spelling flood', 'subprocess.run(["echo", "subprocess.run('.repeat(2800)],
  ])('scans 100 KB adversarial argv (%s) in under 300 ms', (_name, content) => {
    expect(content.length).toBeGreaterThan(90_000);
    expect(bestOf(3, () => write('py', content))).toBeLessThan(300);
  });

  it.each([
    ['nested spawn expressions', 'js', 'spawn("ls", [' + 'spawn(f('.repeat(12500)],
    ['unfinished Python argv calls', 'py', 'subprocess.run([x, '.repeat(5500)],
    ['Python comment lines', 'py', '# subprocess.run(["npm",\n'.repeat(3700)],
    ['newline flood and final sink', 'py', '"\n'.repeat(50000) + `subprocess.run(${argvList})`],
  ])('scans 100 KB whole-file argv (%s) in under 300 ms', (_name, ext, content) => {
    expect(content.length).toBeGreaterThan(90_000);
    expect(bestOf(5, () => write(ext, content))).toBeLessThan(300);
  });
});
