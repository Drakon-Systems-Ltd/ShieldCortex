import { describe, it, expect } from '@jest/globals';
import { performance } from 'node:perf_hooks';
import { evaluateToolCall } from '../tool-action-guard.js';
import { shellStartupWrite, sourceStartupWrite } from '../shell-startup-write-588.js';

const rc = '.bash' + 'rc';
const target = `~/${rc}`;
const write = (path: string, content: string) => evaluateToolCall('Write', { file_path: path, content });
const shell = (command: string) => evaluateToolCall('Bash', { command });

describe('#588 startup writes in authored content', () => {
  it.each([
    ['/repo/install.sh', `#!/bin/sh\necho x >> ${target}\n`],
    ['/repo/install', `#!/bin/sh\necho x >> ${target}\n`],
    ['/repo/install.sh', `sh -c 'echo x >> ${target}'\n`],
    ['/repo/install.sh', `echo x | tee /tmp/a\\b ${target}\n`],
    ['/repo/install.sh', `echo x > '/home/u/${rc}'\n`],
    ['/repo/install.sh', `sed -Ei 's/a/b/' ${target}\n`],
    ['/repo/install.sh', `echo "$(echo x >> ${target})"\n`],
    ['/repo/install.sh', 'echo "`echo x >> ' + target + '`"\n'],
    ['/repo/help.py', `import os\nos.system("echo x >> ${target}")\n`],
    ['/repo/help.py', `import subprocess\nsubprocess.run("echo x >> ${target}", shell=True)\n`],
    ['/repo/app.mjs', `execSync("echo x >> ${target}");\n`],
    ['/repo/app.mjs', 'execSync(`echo x >> ' + target + '`);\n'],
    ['/repo/app.mjs', `exec("echo x >> ${target}");\n`],
    ['/repo/app.mjs', `spawnSync('sh', ['-c', 'echo x >> ${target}']);\n`],
    ['/repo/app.mjs', '$`echo x >> ' + target + '`;\n'],
    ['/repo/app.mjs', '$\n`echo x >> ' + target + '`;\n'],
    ['/repo/app.mjs', '$/* c */`echo x >> ' + target + '`;\n'],
    ['/repo/help.py', `import os\nx = 1 // 2; os.system("echo x >> ${target}")`],
    ['/repo/app.mjs', `const r = /'/; execSync("echo x >> ${target}"); const s = /'/;`],
    ['/repo/app.mjs', `// x\rexecSync("echo x >> ${target}")`],
    ['/repo/app.mjs', `// x\u2028execSync("echo x >> ${target}")`],
    ['/repo/app.mjs', `// x\u2029execSync("echo x >> ${target}")`],
    ['/repo/help.py', `# x\ros.system("echo x >> ${target}")`],
    ['/repo/install.sh', 'x=\x60echo x >> ' + target + '\x60'],
    ['/repo/install.sh', `echo "$(f() { echo x >> ${target}; }; f)"`],
    ['/repo/install.sh', `# don't\necho x >> ${target}\n# it's`],
    ['/repo/install.sh', `echo x | sudo tee -a ${target}`],
    ['/repo/install.sh', `echo x | sudo -u root tee -a ${target}`],
    ['/repo/install.sh', `echo x | env tee -a ${target}`],
    ...['doas', 'command', 'exec', 'nohup', 'nice -n 1', 'timeout 5', 'stdbuf -oL', 'time', 'builtin', 'xargs', 'env -u OLD', 'A=1 env B=2'].map(prefix => ['/repo/install.sh', `echo x | ${prefix} tee -a ${target}`]),
    ['/repo/install.sh', `eval "echo x >> ${target}"`],
    ['/repo/install.sh', `eval 'echo x >> ${target}'`],
    ['/repo/install.sh', `bash -lc 'echo x >> ${target}'`],
    ['/repo/install.sh', `bash -c -- 'echo x >> ${target}'`],
    ['/repo/install.sh', `bash <<EOF\necho x >> ${target}\nEOF`],
    ['/repo/install.sh', `sh -s <<'EOF'\necho x >> ${target}\nEOF`],
    ['/repo/install.sh', `cat <<'EOF' | sh\necho x >> ${target}\nEOF`],
    ['/repo/install.sh', `cat <<'EOF'\necho x >> ${target}\nEOF | sh`],
    ['/repo/help.py', `os.popen("echo x >> ${target}")`],
    ['/repo/help.py', `subprocess.getoutput("echo x >> ${target}")`],
    ['/repo/help.py', `subprocess.getstatusoutput("echo x >> ${target}")`],
    ['/repo/help.py', `commands.getoutput("echo x >> ${target}")`],
    ['/repo/help.py', `pty.spawn("echo x >> ${target}")`],
    ['/repo/install.rb', '\x60echo x >> ' + target + '\x60'],
    ['/repo/install.rb', `%x{echo x >> ${target}}`],
    ['/repo/install.rb', `%x(echo x >> ${target})`],
    ['/repo/install.pl', '\x60echo x >> ' + target + '\x60'],
    ['/repo/install.pl', `qx{echo x >> ${target}}`],
    ['/repo/install.pl', `qx(echo x >> ${target})`],
    ...['shell_exec', 'system', 'passthru', 'exec', 'popen', 'proc_open'].map(sink => ['/repo/install.php', `${sink}("echo x >> ${target}");`]),
    ['/repo/install.php', '\x60echo x >> ' + target + '\x60'],
    // A `#` / `//` comment holding an apostrophe must not open a quote that
    // swallows the real sink on the next line.
    ['/repo/install.rb', `# don't\nsystem("echo x >> ${target}")\n# it's`],
    ['/repo/install.pl', `# don't\nsystem("echo x >> ${target}");\n# it's`],
    ['/repo/install.php', `<?php\n// don't\nshell_exec("echo x >> ${target}");\n// it's`],
    ['/repo/install.php', `<?php\n# don't\nshell_exec("echo x >> ${target}");\n# it's`],
    // Perl `$#array` is not a comment.
    ['/repo/install.pl', `my $n = $#a; system("echo x >> ${target}");`],
    // Any punctuation delimiter for %x / qx.
    ['/repo/install.rb', `%x[echo x >> ${target}]`],
    ['/repo/install.rb', `%x|echo x >> ${target}|`],
    ['/repo/install.pl', `qx!echo x >> ${target}!`],
    ['/repo/install.pl', `qx[echo x >> ${target}]`],
  ])('gates %s: %s', (path, content) => {
    const v = write(path, content);
    expect(v.signals).toContain('modify-shell-startup');
    expect(v.decision).toBe('require_approval');
  });

  it.each([
    ['/repo/app.mjs', `console.log("echo x >> ${target}");`],
    ['/repo/help.py', `HINT = "echo x >> ${target}"\nprint(HINT)`],
    ['/repo/app.mjs', 'function help() { return `hint: echo x >> ' + target + '`; }'],
    ['/repo/app.mjs', 'const hint = `echo x >> ' + target + '`;'],
    ['/repo/app.mjs', 'const hint = `outer ${"echo x >> ' + target + '"}`;'],
    ['/repo/app.mjs', 'const hint = `outer ${`inner ${"echo x >> ' + target + '"}`}`;'],
    ['/repo/install.sh', `# echo x >> ${target}`],
    ['/repo/install.sh', `cat <<'EOF'\necho x >> ${target}\nEOF`],
  ])('allows a mention in %s: %s', (path, content) => {
    const v = write(path, content);
    expect(v.signals).not.toContain('modify-shell-startup');
  });

  it.each(['return', 'typeof', 'await', 'yield', 'delete', 'void', 'in', 'of', 'instanceof', 'new', 'case', 'throw', 'else', 'do'])(
    'does not mistake the %s keyword for a template tag', (keyword) => {
      const v = write('/repo/app.mjs', keyword + ' `hint: echo x >> ' + target + '`;');
      expect(v.signals).not.toContain('modify-shell-startup');
    },
  );

  it('recognises escaped tee operands and continued lines on the exec surface', () => {
    for (const command of [
      `echo x | tee /tmp/a\\b ${target}`,
      `echo x | tee -a \\\n ${target}`,
    ]) expect(shell(command).signals).toContain('modify-shell-startup');
  });

  it('checks edited script text as well as new writes', () => {
    const v = evaluateToolCall('Edit', { file_path: '/repo/install.sh', old_string: 'old', new_string: `echo x >> ${target}\n` });
    expect(v.signals).toContain('modify-shell-startup');
  });

  it('keeps the startup lexers linear on blank lines', () => {
    const content = 'x' + '\n'.repeat(99_999);
    for (const scan of [() => shellStartupWrite(content), () => sourceStartupWrite(content, 'node')]) {
      const start = performance.now();
      expect(scan()).toBe(false);
      expect(performance.now() - start).toBeLessThan(300);
    }
  });

  it.each([
    ['ruby', '%x{'.repeat(33_000)], ['ruby', '%x|'.repeat(33_000)], ['ruby', '#'.repeat(100_000)],
    ['perl', 'qx('.repeat(33_000)], ['perl', '$#'.repeat(50_000)], ['perl', 'qx/'.repeat(33_000)],
    ['php', '//'.repeat(50_000)], ['php', '/*'.repeat(50_000)], ['php', "#'".repeat(50_000)],
  ])('keeps the %s lexer linear on 100 KB of delimiters', (lang, content) => {
    const start = performance.now();
    sourceStartupWrite(content, lang);
    expect(performance.now() - start).toBeLessThan(300);
  });

  it.each([
    ['/repo/install.rb', `# system("echo x >> ${target}")\nputs "ok"`],
    ['/repo/install.php', `<?php\n// shell_exec("echo x >> ${target}");\necho "ok";`],
    ['/repo/install.pl', `# system("echo x >> ${target}");\nprint "ok";`],
  ])('allows a commented-out sink in %s', (path, content) => {
    expect(write(path, content).signals).not.toContain('modify-shell-startup');
  });

  it.each(['\\'.repeat(100_000), '\x60'.repeat(100_000), '${'.repeat(50_000), '\x22'.repeat(100_000), 'const x = \x60' + '\\'.repeat(99_990), '/'.repeat(1e5), "#" + "'".repeat(1e5), '/['.repeat(5e4), '$('.repeat(5e4), '('.repeat(1e5), 'eval '.repeat(2e4), 'sudo '.repeat(2e4)])(
    'scans a 100 KB adversarial write in under 300 ms', (content) => {
      const start = performance.now();
      write('/repo/app.mjs', content);
      expect(performance.now() - start).toBeLessThan(300);
    },
  );
});
