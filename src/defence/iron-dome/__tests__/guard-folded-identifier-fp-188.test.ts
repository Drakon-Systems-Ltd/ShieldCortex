/**
 * Failing-first spec for #188 — a shell verb in interpreter CODE position is an
 * identifier, not a command.
 *
 * Found in production: Friday's daily security cron was hard-denied for 2.5
 * days (every run from 2026-08-01 16:28Z; sentry.log has no entry after
 * 06:01:27 that day). No privileged command ever ran. The whole invocation was
 * killed on two matches inside the script's own source:
 *
 *   sudo = ["michael", "admin"]   # macOS admin group = sudo equivalent
 *                                   → privilege-escalation, matched "sudo"
 *
 * #165 already drew this line for string literals and comments, but only for
 * files with NO shell-out sink. A security-monitoring script calls
 * `subprocess.run` by definition, and one sink anywhere in the file re-armed
 * every shell rule against every token in it — and bare code (an assignment
 * target) never got even that relief, falling straight through to 'executed'.
 *
 * The boundary this pins: the ONLY route from interpreter source to a shell is
 * a string handed to an exec sink. Those still gate, in every language.
 */
import { describe, it, expect } from '@jest/globals';
import { evaluateToolCall } from '../tool-action-guard.js';

const stub = (files: Record<string, string>) => (p: string) => files[p] ?? null;
const verdictOf = (command: string, files: Record<string, string>) =>
  evaluateToolCall('Bash', { command }, undefined, { resolveScriptSource: stub(files) });

// The reported script, reduced to the two shapes that denied it.
const SENTRY = `import json, subprocess, os

# macOS admin group = sudo equivalent
sudo = ["michael", "admin"]

def check_firewall():
    return subprocess.run(["socketfilterfw", "--getglobalstate"], capture_output=True).stdout

print(json.dumps({"fw": check_firewall(), "admins": sudo}))
`;

describe('#188 — shell vocabulary in interpreter code position', () => {
  // NOTE on what these assert: the demotion changes the VERDICT, not the
  // signal list. The match is still named (see 'surfaced, not dropped' below),
  // so asserting the signal is absent would be asserting the wrong thing —
  // and would pass just as well if the guard had stopped scanning altogether.
  it('the reported cron is no longer denied', () => {
    const v = verdictOf('python3 scripts/security-sentry.py', {
      'scripts/security-sentry.py': SENTRY,
    });
    expect(v.decision).toBe('allow');
    expect(v.severity).toBe('sensitive');
  });

  it('a variable named `sudo` in a file that shells out elsewhere is not a sudo call', () => {
    const v = verdictOf('python3 /tmp/a.py', {
      '/tmp/a.py': 'import subprocess\nsudo = ["a"]\nsubprocess.run(["ls"])\n',
    });
    expect(v.decision).toBe('allow');
    expect(v.severity).toBe('sensitive');
  });

  it('the demoted signal is surfaced, not silently dropped', () => {
    // A dangerous verb that IS demoted still names itself at the sensitive tier,
    // so a reviewer can see what the folded source said.
    const v = verdictOf('python3 /tmp/a.py', {
      '/tmp/a.py': 'import subprocess\niptables = 1\nsubprocess.run(["ls"])\n',
    });
    expect(v.decision).toBe('allow');
    expect(v.severity).toBe('sensitive');
    expect(v.signals).toContain('modify-network-firewall');
  });

  // ── the boundary: a string handed to an exec sink is still a command ──

  it('subprocess with shell=True still gates', () => {
    const v = verdictOf('python3 /tmp/a.py', {
      '/tmp/a.py': 'import subprocess\nsubprocess.run("sudo systemctl stop nginx", shell=True)\n',
    });
    expect(v.decision).toBe('require_approval');
    expect(v.signals).toContain('privilege-escalation');
  });

  it('os.system still gates', () => {
    const v = verdictOf('python3 /tmp/a.py', {
      '/tmp/a.py': 'import os\nos.system("sudo apt-get install -y age")\n',
    });
    expect(v.decision).toBe('require_approval');
  });

  it('child_process.execSync still gates', () => {
    const v = verdictOf('node /tmp/a.js', {
      '/tmp/a.js': 'require("child_process").execSync("sudo systemctl stop nginx");\n',
    });
    expect(v.decision).toBe('require_approval');
    expect(v.signals).toContain('privilege-escalation');
  });

  it('a folded .sh file is shell and is untouched by this relief', () => {
    const v = verdictOf('bash /tmp/a.sh', { '/tmp/a.sh': 'sudo systemctl stop nginx\n' });
    expect(v.decision).toBe('require_approval');
    expect(v.signals).toContain('privilege-escalation');
  });

  it('catastrophic content in folded source is NOT relieved', () => {
    const v = verdictOf('python3 /tmp/a.py', {
      '/tmp/a.py': 'import subprocess\nsubprocess.run("rm -rf /", shell=True)\n',
    });
    expect(v.decision).toBe('block');
    expect(v.severity).toBe('catastrophic');
  });

  // This half of the reported denial is NOT relieved here, and the reported cron
  // is still denied by it — see #189. The exec-sink argument does not transfer to
  // a path: the route from Python to ~/.ssh/id_rsa is a file API, not a shell.
  it('a path-target rule still fires on folded source — naming the path is the access', () => {
    const v = verdictOf('python3 /tmp/a.py', {
      '/tmp/a.py': 'import os\nprint(os.stat("/Users/michael/.ssh/id_rsa").st_mode)\n',
    });
    expect(v.signals).toContain('touch-sensitive-path');
  });
});
