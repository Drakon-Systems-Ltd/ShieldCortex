/**
 * #1077 — self-protection false positives that hard-denied routine headless
 * work under Watch only (advisory), where the self-protection floor is the
 * only thing that still holds a call.
 *
 * Invariant: the floor signals (touch-approval-store, touch-decisions-ledger,
 * touch-guard-config, disable-action-guard) fire on this host's REAL guard
 * paths when a call can actually act on them — not on prose in a script's
 * source, not on a read of a file on another host, not on a stderr redirect
 * to /dev/null. A script pinned with `shieldcortex allowlist add` is neither
 * opaque nor driving the floor through its own source.
 *
 * Every must-not-fire case ships with a must-still-fire control.
 */
import { evaluateToolCall } from '../tool-action-guard.js';

const FLOOR = ['touch-approval-store', 'touch-decisions-ledger', 'touch-guard-config', 'disable-action-guard'];
const SHELL_OUT = ['os', 'system'].join('.');

const floorOf = (v: { signals?: string[] }): string[] => (v.signals ?? []).filter((s) => FLOOR.includes(s));
const bash = (command: string, files?: Record<string, string>, reviewed?: (p: string, s: string) => boolean) =>
  evaluateToolCall('Bash', { command }, undefined, files
    ? { resolveScriptSource: (p: string) => files[p] ?? null, ...(reviewed ? { isReviewedScript: reviewed } : {}) }
    : undefined);

describe('#1077 case 3 — listing the approval store with stderr discarded', () => {
  test.each([
    'ls -la ~/.shieldcortex/approvals/ 2>/dev/null',
    'ls -la ~/.shieldcortex/approvals/ &>/dev/null',
    "ls -la ~/.shieldcortex/approvals/ 2>/dev/null || echo 'no approvals dir'",
    'ls -la ~/.shieldcortex/approvals/ 2> /dev/null | head -20',
    'cat ~/.shieldcortex/config.json 2>/dev/null',
    'grep -n enforce ~/.shieldcortex/config.json 2>/dev/null',
  ])('runs with no floor signal: %s', (command) => {
    const v = bash(command);
    expect(floorOf(v)).toEqual([]);
    expect(v.decision).toBe('allow');
  });

  test.each([
    ['echo x > ~/.shieldcortex/approvals/approvals.json', 'touch-approval-store'],
    ['ls ~/.shieldcortex/approvals > /tmp/listing.txt', 'touch-approval-store'],
    ['ls ~/.shieldcortex/approvals 2>/dev/null > /tmp/listing.txt', 'touch-approval-store'],
    ['cat /dev/null > ~/.shieldcortex/config.json', 'touch-guard-config'],
    ['echo {} >/dev/null/../../home/u/.shieldcortex/config.json', 'touch-guard-config'],
    ['echo {} > "/dev/null" ; echo {} > ~/.shieldcortex/config.json', 'touch-guard-config'],
    ['rm ~/.shieldcortex/approvals/approvals.json 2>/dev/null', 'touch-approval-store'],
  ])('control — a real write is still held: %s', (command, signal) => {
    const v = bash(command);
    expect(v.decision).not.toBe('allow');
    expect(v.signals).toContain(signal);
  });
});

describe('#1077 case 2 — reading a config file on another host over ssh', () => {
  test.each([
    "ssh pi@vps2 'cat ~/.openclaw/openclaw.json'",
    `ssh vps2 "jq '.channels.telegram' ~/.openclaw/openclaw.json"`,
    "ssh -o ConnectTimeout=5 -p 2222 vps2 'jq .channels.telegram ~/.openclaw/openclaw.json' | jq .",
    "ssh -q -T vps2 'grep -A20 telegram ~/.openclaw/openclaw.json' 2>/dev/null",
    "ssh vps2 'cat ~/.shieldcortex/config.json'",
    "ssh vps2 'ls -la ~/.shieldcortex/approvals/'",
  ])('runs with no floor signal: %s', (command) => {
    const v = bash(command);
    expect(floorOf(v)).toEqual([]);
    expect(v.decision).toBe('allow');
  });

  test.each([
    // A remote WRITE keeps the gate: the guard cannot prove the host is not this one.
    "ssh vps2 'echo {} > ~/.openclaw/openclaw.json'",
    `ssh localhost "sed -i 's/a/b/' ~/.openclaw/openclaw.json"`,
    "ssh vps2 'cat ~/.openclaw/openclaw.json; rm -f ~/.openclaw/openclaw.json'",
    // Options that run a local command or write a local file are not unwrapped.
    "ssh -o ProxyCommand='sh -c x' vps2 'cat ~/.openclaw/openclaw.json'",
    "ssh -E ~/.openclaw/openclaw.json vps2 'cat /etc/hostname'",
    "ssh -F /tmp/cfg vps2 'cat ~/.openclaw/openclaw.json'",
    // The local side of the pipeline is still judged as written.
    "ssh vps2 'cat ~/.openclaw/openclaw.json' > ~/.openclaw/openclaw.json",
    "ssh vps2 'cat ~/.shieldcortex/config.json' | tee ~/.shieldcortex/config.json",
    // Expansion and interpreters stay fail-closed, remote or local.
    `ssh vps2 "cat $(echo ~/.openclaw/openclaw.json)"`,
    `ssh vps2 'python3 -c "print(open(\\"/home/u/.openclaw/openclaw.json\\").read())"'`,
    'sudo ssh vps2 cat ~/.openclaw/openclaw.json',
  ])('control — still held: %s', (command) => {
    const v = bash(command);
    expect(v.decision).not.toBe('allow');
    expect(floorOf(v).length).toBeGreaterThan(0);
  });
});

describe('#1077 case 1 — a workspace script that mentions guard concepts', () => {
  const LEASE = '/ws/scripts/action_lease.py';
  const leaseSource = (docExtra: string, body = '') => [
    '#!/usr/bin/env python3',
    '"""Workspace action lease: a cooperative lock for risky operations.',
    '',
    'Usage:',
    '    python3 scripts/action_lease.py acquire <scope> --reason "why"',
    '    python3 scripts/action_lease.py release <scope>',
    docExtra,
    '"""',
    'import argparse, json, os, subprocess, sys, time',
    'from pathlib import Path',
    '',
    'LEASE_DIR = Path.home() / ".openclaw" / "workspace" / ".leases"',
    '',
    'def _git_head():',
    '    out = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True)',
    '    return out.stdout.strip()',
    '',
    'def _path(scope):',
    '    return LEASE_DIR / f"{scope}.json"',
    body,
    'def main():',
    '    ap = argparse.ArgumentParser(description=__doc__)',
    '    ap.add_argument("cmd")',
    '    ap.add_argument("scope")',
    '    ap.add_argument("--reason")',
    '    args = ap.parse_args()',
    '    print(args.cmd, args.scope, _git_head())',
    '',
    'if __name__ == "__main__":',
    '    sys.exit(main())',
  ].join('\n');

  const DOC_MENTION = 'It never stops a service and never touches ~/.shieldcortex/config.json\nor ~/.shieldcortex/approvals/ -- guard state is the owner\'s alone.';
  const command = `python3 ${LEASE} acquire plugin-update --reason "owner-approved plugin update"`;

  test('a docstring mention of guard paths in a sink-bearing script is not access', () => {
    const v = bash(command, { [LEASE]: leaseSource(DOC_MENTION) });
    expect(floorOf(v)).toEqual([]);
    expect(v.decision).toBe('allow');
  });

  test('the `Path.home() / "x"` operator and docstring usage lines do not make the fold opaque', () => {
    // Before #1077 the `/` after `)` read as a command-position path `/`, and
    // the usage line's `scripts/action_lease.py` (relative, wrong cwd) as an
    // unreadable child: both reported opaque-script-invocation.
    const v = bash(command, { [LEASE]: leaseSource('') });
    expect(v.signals).not.toContain('opaque-script-invocation');
    expect(v.decision).toBe('allow');
  });

  test('pinned (reviewed): not opaque, no floor, review recorded', () => {
    const src = leaseSource(DOC_MENTION, 'SCOPES = {"guard": "edits to ~/.shieldcortex/config.json (owner only)"}\n');
    const v = bash(`python3 ${LEASE} release plugin-update`, { [LEASE]: src }, (p, s) => p === LEASE && s === src);
    expect(v.signals ?? []).not.toContain('opaque-script-invocation');
    expect(floorOf(v)).toEqual([]);
    expect(v.reviewedScripts).toEqual([LEASE]);
    expect(v.decision).toBe('allow');
  });

  // RESIDUAL (not relieved by #1077): a non-docstring string literal that names
  // a guard path is still held, even in prose, because a sink-free script can
  // still split such a string and open() the path. The owner's route for a
  // reviewed script of this shape is the pin, asserted here.
  test('a sink-free script with prose naming guard paths: held unpinned, relieved when pinned', () => {
    const src = [
      'import json, sys',
      'SCOPES = {',
      '    "plugin-update": "openclaw plugins update; may rewrite ~/.openclaw/openclaw.json",',
      '    "guard": "edits to ~/.shieldcortex/config.json (owner only)",',
      '    "gateway": "cd ~/.shieldcortex and read approvals before a restart",',
      '}',
      'print(json.dumps(SCOPES.get(sys.argv[1], "")))',
    ].join('\n');
    const P = '/ws/scripts/scopes.py';
    expect(floorOf(bash(`python3 ${P} guard`, { [P]: src })).length).toBeGreaterThan(0);
    const v = bash(`python3 ${P} guard`, { [P]: src }, (p, s2) => p === P && s2 === src);
    expect(floorOf(v)).toEqual([]);
    expect(v.reviewedScripts).toEqual([P]);
    expect(v.decision).toBe('allow');
  });

  describe('controls — real access from a script is still held', () => {
    test.each([
      ['open() on a path value', 'import os\nopen(os.path.expanduser("~/.shieldcortex/config.json"), "w").write("{}")\n', 'touch-guard-config'],
      ['sink-free path value, read', 'import json\nprint(json.load(open("/home/u/.openclaw/openclaw.json")))\n', 'disable-action-guard'],
      ['command string bound to a variable, then run', 'import subprocess\ncmd = "echo {} > ~/.shieldcortex/config.json"\nsubprocess.run(cmd, shell=True)\n', 'touch-guard-config'],
      ['sink argument', 'import subprocess\nsubprocess.run("rm -f ~/.shieldcortex/approvals/approvals.json", shell=True)\n', 'touch-approval-store'],
      ['sink-bearing file, non-docstring literal (fail-closed)', 'import subprocess\nHELP = "edits to ~/.shieldcortex/config.json"\nsubprocess.run(["git", "status"])\n', 'touch-guard-config'],
      ['docstring handed to a shell via __doc__', `"""echo {} > ~/.shieldcortex/config.json"""\nimport os\n${SHELL_OUT}(__doc__)\n`, 'touch-guard-config'],
    ])('%s', (_label, src, signal) => {
      const v = bash('python3 /ws/x.py', { '/ws/x.py': src });
      expect(v.decision).not.toBe('allow');
      expect(v.signals).toContain(signal);
    });

    test('a folded shell script is shell: a write in it is held', () => {
      const v = bash('sh /ws/x.sh', { '/ws/x.sh': "#!/bin/sh\necho '{}' > ~/.shieldcortex/config.json\n" });
      expect(v.signals).toContain('touch-guard-config');
      expect(v.decision).not.toBe('allow');
    });

    test('an inline program the agent typed is never relieved (folded:false)', () => {
      const v = bash(`python3 -c '"""never touches ~/.shieldcortex/config.json"""'`);
      expect(v.signals).toContain('touch-guard-config');
    });

    test('a docstring is relieved for the floor; the same docstring handed to a shell via __doc__ is not', () => {
      const relieved = bash('python3 /ws/a.py', { '/ws/a.py': '"""Helper. To inspect by hand:\n    cd ~/.shieldcortex && rm approvals/stale.json\n"""\nimport subprocess\nsubprocess.run(["git", "status"])\n' });
      expect(floorOf(relieved)).toEqual([]);
      const held = bash('python3 /ws/b.py', { '/ws/b.py': '"""Helper.\n    cd ~/.shieldcortex && rm approvals/stale.json\n"""\nimport subprocess\nsubprocess.run(__doc__, shell=True)\n' });
      expect(floorOf(held).length).toBeGreaterThan(0);
    });

    test('the command line itself is always scanned — pinning relieves the file, never the invocation', () => {
      const src = leaseSource('');
      const v = bash(`python3 ${LEASE} release x; echo {} > ~/.shieldcortex/config.json`, { [LEASE]: src }, (p, s) => p === LEASE && s === src);
      expect(v.signals).toContain('touch-guard-config');
    });

    test('a real unreadable script is still reported opaque', () => {
      expect(bash('python3 /ws/missing.py', {}).signals).toContain('opaque-script-invocation');
      expect(bash('./deploy.sh', {}).signals).toContain('opaque-script-invocation');
    });
  });
});
