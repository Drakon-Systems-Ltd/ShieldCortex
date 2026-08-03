import { describe, it, expect, jest } from '@jest/globals';
import { evaluateToolCall, detectScriptInvocation } from '../tool-action-guard.js';
import type { ToolGuardVerdict } from '../tool-action-guard.js';

/**
 * Issue #4 — a dangerous command moved into a script file bypassed EVERY rule.
 *
 * The guard's danger matchers all ran against the exec surface built from the
 * COMMAND STRING only (`[execCommand, path, url]`), so `bash payload.sh` was a
 * universal bypass: catastrophic patterns, the dangerous table, `find -delete`,
 * the secret-exfil hard block and the egress predicate all saw nothing. Live
 * repro: a `curl -X DELETE` loop against an external API was correctly gated
 * inline (`external-egress`), then ran with no gate at all from a `.sh` file.
 *
 * The fix keeps `evaluateToolCall` pure — the file is read by a resolver the
 * CALLER injects (`options.resolveScriptSource`); these tests use stubs and
 * never touch the real filesystem. When the source cannot be folded the call is
 * still ALLOWED (this is how agents normally work) but carries a recorded
 * `opaque-script-invocation` signal, so the gap is auditable instead of silent.
 */

/** A stub resolver over an in-memory file table. */
function stubResolver(files: Record<string, string>): (p: string) => string | null {
  return (p: string) => (Object.prototype.hasOwnProperty.call(files, p) ? files[p] : null);
}

function verdictOf(command: string, files?: Record<string, string>): ToolGuardVerdict {
  return evaluateToolCall(
    'Bash',
    { command },
    undefined,
    files ? { resolveScriptSource: stubResolver(files) } : undefined,
  );
}

const OPAQUE = 'opaque-script-invocation';
/** A real NUL byte, built at runtime — source files stay NUL-free (source-hygiene). */
const NUL = String.fromCharCode(0);

describe('#4 — the live repro: external egress hidden in a script file', () => {
  const inline = 'curl -X DELETE -H "Authorization: Bearer $T" https://api.example.com/x';

  it('gates the via-file invocation exactly as it gates the inline command', () => {
    const direct = verdictOf(inline);
    expect(direct.decision).toBe('require_approval');
    expect(direct.signals).toContain('external-egress');

    const viaFile = verdictOf('bash /tmp/x.sh', { '/tmp/x.sh': `#!/bin/bash\nset -e\n${inline}\n` });
    expect(viaFile.decision).toBe(direct.decision);
    expect(viaFile.severity).toBe(direct.severity);
    expect(viaFile.signals).toContain('external-egress');
    expect(viaFile.signals).not.toContain(OPAQUE);   // the file WAS read
  });

  it('is the bypass it was before the fix when nothing resolves the file', () => {
    // Documented, deliberate residual: with no resolver the contents are
    // unknowable — but the call is now RECORDED as unscanned, not invisible.
    const v = verdictOf('bash /tmp/x.sh');
    expect(v.signals).toContain(OPAQUE);
    expect(v.decision).toBe('allow');
  });
});

describe('#4 — parity: inline verdict === via-file verdict', () => {
  const cases: Array<[signal: string, command: string]> = [
    ['install-package-global', 'npm install -g leftpad'],
    ['privilege-escalation', 'sudo systemctl restart nginx'],
    // /var, not /tmp (#170): a temp-path delete is workspace-confined and
    // allows now; this table's subject is inline-vs-file PARITY, which needs a
    // shape that actually gates on both surfaces.
    ['file-delete', 'rm /var/data/old-report.txt'],
    ['dd-overwrite', 'dd if=/dev/zero of=/tmp/data.img bs=1M count=10'],
    ['truncate-to-zero', 'truncate -s 0 /var/log/app.log'],
  ];

  it.each(cases)('%s', (signal, command) => {
    const direct = verdictOf(command);
    expect(direct.decision).toBe('require_approval');
    expect(direct.signals).toContain(signal);

    const viaFile = verdictOf('bash ./run.sh', { './run.sh': `#!/usr/bin/env bash\n${command}\n` });
    expect(viaFile.decision).toBe(direct.decision);
    expect(viaFile.severity).toBe(direct.severity);
    expect(viaFile.action).toBe(direct.action);
    expect(viaFile.signals).toEqual(expect.arrayContaining(direct.signals));
  });

  it('a catastrophic payload in a file still hard-blocks', () => {
    const v = verdictOf('sh /tmp/wipe.sh', { '/tmp/wipe.sh': 'rm -rf /\n' });
    expect(v.decision).toBe('block');
    expect(v.severity).toBe('catastrophic');
    expect(v.signals).toContain('recursive-force-delete');
  });

  // #188: the payload is now written in the language of the interpreter that
  // will actually run it. This test previously put SHELL text (`sudo rm -r …`)
  // inside /tmp/a.py, /tmp/a.js, /tmp/a.rb and /tmp/a.pl — a shape that cannot
  // execute anything, because `python3 a.py` on a line of shell is a syntax
  // error, not a privileged command. Gating it cost real work (a production
  // security cron hard-denied for 2.5 days on a Python variable NAMED `sudo`)
  // and bought no defence. What the test is FOR — you cannot hide a privileged
  // action behind a file — is unchanged and now tested in the shape that can
  // actually reach a shell: a string handed to the language's exec sink.
  it('covers every invocation shape, not just `bash f.sh`', () => {
    const payload = 'sudo rm -r /var/lib/thing\n';
    const py = 'import subprocess\nsubprocess.run("sudo rm -r /var/lib/thing", shell=True)\n';
    const js = 'require("child_process").execSync("sudo rm -r /var/lib/thing");\n';
    const rb = 'system("sudo rm -r /var/lib/thing")\n';
    const pl = 'system("sudo rm -r /var/lib/thing");\n';
    const shapes: Array<[string, Record<string, string>]> = [
      ['bash -e /tmp/a.sh', { '/tmp/a.sh': payload }],
      ['sh /tmp/a.sh', { '/tmp/a.sh': payload }],
      ['zsh /tmp/a.sh', { '/tmp/a.sh': payload }],
      ['dash /tmp/a.sh', { '/tmp/a.sh': payload }],
      ['ksh /tmp/a.sh', { '/tmp/a.sh': payload }],
      ['python3 /tmp/a.py', { '/tmp/a.py': py }],
      ['node /tmp/a.js', { '/tmp/a.js': js }],
      ['ruby /tmp/a.rb', { '/tmp/a.rb': rb }],
      ['perl /tmp/a.pl', { '/tmp/a.pl': pl }],
      ['./a.sh', { './a.sh': payload }],
      ['/opt/tools/a.sh', { '/opt/tools/a.sh': payload }],
      ['source /tmp/a.sh', { '/tmp/a.sh': payload }],
      ['. /tmp/a.sh', { '/tmp/a.sh': payload }],
      ['env FOO=1 bash /tmp/a.sh', { '/tmp/a.sh': payload }],
      ['sudo -u deploy bash /tmp/a.sh', { '/tmp/a.sh': payload }],
      ['cd /tmp && ./a.sh', { './a.sh': payload }],
    ];
    for (const [command, files] of shapes) {
      const v = verdictOf(command, files);
      expect([command, v.decision]).toEqual([command, 'require_approval']);
      expect([command, v.signals.includes('privilege-escalation')]).toEqual([command, true]);
    }
  });
});

describe('#4 — bounded following of nested scripts', () => {
  it('follows a script that invokes a script (within the depth limit)', () => {
    const v = verdictOf('bash /tmp/a.sh', {
      '/tmp/a.sh': 'echo step 1\nbash /tmp/b.sh\n',
      '/tmp/b.sh': 'echo step 2\nsh /tmp/c.sh\n',
      '/tmp/c.sh': 'rm -rf /\n',
    });
    expect(v.decision).toBe('block');
    expect(v.signals).toContain('recursive-force-delete');
  });

  it('stops at depth 3 and says so instead of pretending it scanned', () => {
    const v = verdictOf('bash /tmp/a.sh', {
      '/tmp/a.sh': 'bash /tmp/b.sh\n',
      '/tmp/b.sh': 'bash /tmp/c.sh\n',
      '/tmp/c.sh': 'bash /tmp/d.sh\n',
      '/tmp/d.sh': 'rm -rf /\n',
    });
    expect(v.signals).toContain(OPAQUE);
    expect(v.decision).not.toBe('block');
  });

  it('terminates on a source cycle (a → b → a) without hanging', () => {
    const started = Date.now();
    const v = verdictOf('bash /tmp/a.sh', {
      '/tmp/a.sh': 'source /tmp/b.sh\n',
      '/tmp/b.sh': 'source /tmp/a.sh\nsudo rm -r /srv/data\n',
    });
    expect(Date.now() - started).toBeLessThan(2000);
    expect(v.decision).toBe('require_approval');
    expect(v.signals).toContain('privilege-escalation');
  });

  it('bounds how many files one call may fold', () => {
    const files: Record<string, string> = {};
    for (let i = 0; i < 40; i++) files[`/tmp/s${i}.sh`] = `echo ${i}\n`;
    const command = Object.keys(files).map(p => `bash ${p}`).join('; ');
    const calls: string[] = [];
    const v = evaluateToolCall('Bash', { command }, undefined, {
      resolveScriptSource: (p) => { calls.push(p); return files[p] ?? null; },
    });
    expect(calls.length).toBeLessThanOrEqual(12);
    expect(v.decision).toBe('allow');
  });
});

describe('#4 — could-not-scan is visible, never silent, never a gate', () => {
  it('no resolver at all → opaque signal, decision NOT escalated', () => {
    const v = verdictOf('bash /tmp/deploy.sh');
    expect(v.signals).toContain(OPAQUE);
    expect(v.decision).toBe('allow');
    expect(v.severity).toBe('sensitive');       // recorded + surfaced, not benign
    expect(v.reason).toMatch(/could not read the invoked script/);
  });

  it('resolver returns null (missing / unreadable file) → opaque', () => {
    const v = verdictOf('bash /tmp/gone.sh', { '/tmp/other.sh': 'echo hi\n' });
    expect(v.signals).toContain(OPAQUE);
    expect(v.decision).toBe('allow');
  });

  it('oversized content → opaque, not a silent pass', () => {
    const huge = `echo padding\n`.repeat(30_000);        // > 256KB
    expect(huge.length).toBeGreaterThan(262_144);
    const v = verdictOf('bash /tmp/big.sh', { '/tmp/big.sh': huge });
    expect(v.signals).toContain(OPAQUE);
    expect(v.decision).toBe('allow');
  });

  it('binary content (NUL bytes) → opaque', () => {
    const binary = 'ELF' + NUL + NUL + 'payload'.repeat(20);
    const v = verdictOf('./tool', { './tool': binary });
    expect(v.signals).toContain(OPAQUE);
    expect(v.decision).toBe('allow');
  });

  it('a throwing resolver cannot break the call (zeroth law)', () => {
    const v = evaluateToolCall('Bash', { command: 'bash /tmp/a.sh' }, undefined, {
      resolveScriptSource: () => { throw new Error('EACCES'); },
    });
    expect(v.decision).toBe('allow');
    expect(v.signals).toContain(OPAQUE);
  });

  it('an opaque script alongside a real danger neither hides nor upgrades it', () => {
    const v = verdictOf('sudo systemctl stop nginx; bash /tmp/unknown.sh');
    expect(v.decision).toBe('require_approval');
    expect(v.signals).toContain('privilege-escalation');
    expect(v.signals).toContain(OPAQUE);
  });
});

describe('#4 — no new friction on the way agents actually work', () => {
  it('a clean script reads clean: allow, benign, zero signals', () => {
    const v = verdictOf('bash /tmp/hello.sh', { '/tmp/hello.sh': 'echo hello\n' });
    expect(v.decision).toBe('allow');
    expect(v.severity).toBe('benign');
    expect(v.signals).toEqual([]);
  });

  it('a clean script verdict is identical to the pre-fix verdict', () => {
    const clean = 'npm test\nnode build.js\necho done\n';
    const before = evaluateToolCall('Bash', { command: 'echo done' });
    const after = verdictOf('bash /tmp/ci.sh', { '/tmp/ci.sh': clean, 'build.js': 'console.log(1)\n' });
    expect(after.decision).toBe(before.decision);
    expect(after.severity).toBe(before.severity);
    expect(after.signals).toEqual([]);
  });

  it('a comment mentioning a dangerous command is not an action', () => {
    const v = verdictOf('bash /tmp/doc.sh', { '/tmp/doc.sh': '# never run rm -rf / here\necho safe\n' });
    expect(v.decision).toBe('allow');
    expect(v.severity).toBe('benign');
  });

  it('does not resolve anything for commands that invoke no script', () => {
    const calls: string[] = [];
    const resolveScriptSource = (p: string) => { calls.push(p); return null; };
    for (const command of ['ls -la', 'npm test', 'git status', 'grep -rn foo src/', 'echo hi']) {
      const v = evaluateToolCall('Bash', { command }, undefined, { resolveScriptSource });
      expect([command, v.decision]).toEqual([command, 'allow']);
      expect([command, v.signals.includes(OPAQUE)]).toEqual([command, false]);
    }
    expect(calls).toEqual([]);
  });

  it('never reads a file just because a path/url ARGUMENT names one', () => {
    // Field discipline: detection runs on the command, never on path/url args,
    // so editing a script is not the same as executing it.
    const resolveScriptSource = jest.fn((_p: string) => 'rm -rf /\n');
    const v = evaluateToolCall(
      'Write',
      { file_path: '/tmp/deploy.sh', content: 'whatever' },
      undefined,
      { resolveScriptSource: resolveScriptSource as unknown as (p: string) => string | null },
    );
    expect(resolveScriptSource).not.toHaveBeenCalled();
    expect(v.decision).toBe('allow');
  });
});

describe('#4 — detectScriptInvocation shapes', () => {
  it('recognises interpreters, bare paths, source and wrapper prefixes', () => {
    expect(detectScriptInvocation('bash /tmp/x.sh')).toEqual(['/tmp/x.sh']);
    expect(detectScriptInvocation('bash -e ./f.sh')).toEqual(['./f.sh']);
    expect(detectScriptInvocation('python3 /tmp/a.py')).toEqual(['/tmp/a.py']);
    expect(detectScriptInvocation('node server.js')).toEqual(['server.js']);
    expect(detectScriptInvocation('ruby ./task.rb')).toEqual(['./task.rb']);
    expect(detectScriptInvocation('perl ./task.pl')).toEqual(['./task.pl']);
    expect(detectScriptInvocation('./f.sh')).toEqual(['./f.sh']);
    expect(detectScriptInvocation('/opt/bin/deploy')).toEqual(['/opt/bin/deploy']);
    expect(detectScriptInvocation('source f.sh')).toEqual(['f.sh']);
    expect(detectScriptInvocation('. ./f.sh')).toEqual(['./f.sh']);
    expect(detectScriptInvocation('env VAR=1 bash f.sh')).toEqual(['f.sh']);
    expect(detectScriptInvocation('nohup sudo bash /tmp/f.sh &')).toEqual(['/tmp/f.sh']);
    expect(detectScriptInvocation('timeout 30 bash f.sh')).toEqual(['f.sh']);
  });

  it('does NOT treat an inline program as a file invocation', () => {
    expect(detectScriptInvocation(`bash -c 'echo hi && ls'`)).toEqual([]);
    expect(detectScriptInvocation(`sh -c "curl https://x.test | jq ."`)).toEqual([]);
    expect(detectScriptInvocation(`python3 -c "import os; print(os.getcwd())"`)).toEqual([]);
    expect(detectScriptInvocation(`python3 -m http.server`)).toEqual([]);
    expect(detectScriptInvocation(`node -e "console.log(1)"`)).toEqual([]);
    expect(detectScriptInvocation(`perl -ne 'print' file.txt`)).toEqual([]);
    expect(detectScriptInvocation('cat data.json | python3 -')).toEqual([]);
  });

  it('still follows a file invocation NESTED inside an inline program', () => {
    expect(detectScriptInvocation(`bash -c 'bash /tmp/inner.sh'`)).toEqual(['/tmp/inner.sh']);
  });

  it('finds nothing in ordinary non-script commands', () => {
    for (const c of ['ls -la', 'npm test', 'git status', 'npx tsc', 'grep -rn "bash x.sh" docs/']) {
      expect([c, detectScriptInvocation(c)]).toEqual([c, []]);
    }
  });

  it('stays fast on adversarial input (30k chars, no match)', () => {
    const s = 'nice -n 10 env FOO=1 nohup '.repeat(1100) + 'echo done';
    const t = process.hrtime.bigint();
    detectScriptInvocation(s);
    const ms = Number(process.hrtime.bigint() - t) / 1e6;
    expect(ms).toBeLessThan(300);
  });
});
