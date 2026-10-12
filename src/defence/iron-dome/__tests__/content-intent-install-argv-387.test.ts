import { performance } from 'node:perf_hooks';
import { evaluateToolCall } from '../tool-action-guard.js';

const cfg = { enabled: true, enforce: true } as any;
const npm = 'n' + 'pm';
const install = 'in' + 'stall';
const global = '-' + 'g';
const nl = String.fromCharCode(10);

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
  // Fail closed: a commented-out or printed call that would run a global
  // install still asks. Telling these from live code needs a real lexer per
  // language, and getting that wrong hides live calls (rows above).
  ['commented sink (fails closed)', 'py', `# subprocess.run(${argvList})`],
  ['printed sink text (fails closed)', 'py', `print('subprocess.run(${argvList})')`],
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
  ])('allows %s', (_name, ext, content) => {
    expect(write(ext, content).signals ?? []).not.toContain('install-package-global');
  });

  it.each([
    ['unfinished list of npm words', 'import subprocess' + nl + 'subprocess.run([' + `"${npm}", `.repeat(20000)],
    ['quote run', 'import subprocess' + nl + 'subprocess.run([' + '"'.repeat(100000)],
    ['nested sinks inside list strings', 'import subprocess' + nl + 'subprocess.run([' + '"subprocess.run([", '.repeat(5000)],
    ['sink run', 'subprocess.run('.repeat(7000)],
    ['spawn command then nested', 'spawn("x", [' + '"spawn(\\"x\\", [", '.repeat(5000)],
  ])('scans 100 KB adversarial argv (%s) in under 300 ms', (_name, content) => {
    expect(content.length).toBeGreaterThan(90_000);
    expect(bestOf(3, () => write('py', content))).toBeLessThan(300);
  });
});
