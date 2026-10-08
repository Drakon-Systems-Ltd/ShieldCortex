/**
 * #648 round 3 (R2) — git host truthfulness: the card never names a host the
 * command may not reach.
 *
 * Each test builds its own repository and its own HOME (global git config),
 * and passes an empty system-config list, so nothing on the box that runs the
 * suite can change the answer.
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describeAction } from '../approval-card.js';
import { evaluateToolCall } from '../tool-action-guard.js';

let root = '';
let repo = '';
let home = '';
const saved: Record<string, string | undefined> = {};

function repoConfig(text: string): void {
  writeFileSync(join(repo, '.git', 'config'), text);
}

const ORIGIN = '[remote "origin"]\n\turl = git@github.com:acme/app.git\n';
const NO_CWD = Symbol('no working directory');
const git = (command: string, cwd: string | typeof NO_CWD = repo, signals: string[] = ['external-egress']) =>
  describeAction({ tool: 'Bash', input: { command }, signals, cwd: cwd === NO_CWD ? undefined : cwd, gitSystemConfig: [] }).text;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'sc-648-r3-git-'));
  repo = join(root, 'repo');
  home = join(root, 'home');
  mkdirSync(join(repo, '.git'), { recursive: true });
  mkdirSync(home, { recursive: true });
  for (const k of ['HOME', 'XDG_CONFIG_HOME', 'GIT_CONFIG_GLOBAL']) saved[k] = process.env[k];
  process.env.HOME = home;
  delete process.env.XDG_CONFIG_HOME;
  delete process.env.GIT_CONFIG_GLOBAL;
});

afterEach(() => {
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  rmSync(root, { recursive: true, force: true });
});

describe('#648 r3 R2 — a push names the pushurl host, read first', () => {
  it('pushurl pointing elsewhere: the push names where it really goes', () => {
    repoConfig(`${ORIGIN}\tpushurl = git@push.example.net:acme/app.git\n`);
    expect(git('git push')).toBe('Send data to push.example.net (git push)');
    expect(git('git push --force origin main')).toBe('Force-push to push.example.net (branch "main") (git push --force)');
    // A fetch still reads `url`.
    expect(git('git fetch origin')).toBe('Send data to github.com (git fetch)');
  });

  it('without a pushurl, the push names the url host', () => {
    repoConfig(ORIGIN);
    expect(git('git push origin main')).toBe('Send data to github.com (git push)');
  });

  it('several push targets on different hosts: no host is claimed', () => {
    repoConfig(`${ORIGIN}\turl = git@gitlab.example.org:acme/app.git\n`);
    expect(git('git push origin main')).toBe('Send data to the "origin" remote (git push)');
    repoConfig(`${ORIGIN}\tpushurl = git@a.example.net:x.git\n\tpushurl = git@b.example.net:x.git\n`);
    expect(git('git push origin main')).toBe('Send data to the "origin" remote (git push)');
  });

  it('keys and section names are read the way git reads them', () => {
    repoConfig('[remote "origin"]\n\tURL = "git@github.com:acme/app.git" ; comment\n\tPushUrl = git@push.example.net:acme/app.git # comment\n');
    expect(git('git push')).toBe('Send data to push.example.net (git push)');
  });
});

describe('#648 r3 R2 — the host is dropped whenever the config may rewrite it', () => {
  it.each([
    ['insteadOf in the repository config', `${ORIGIN}[url "git@evil.example.net:"]\n\tinsteadOf = git@github.com:\n`],
    ['pushInsteadOf in the repository config', `${ORIGIN}[url "git@evil.example.net:"]\n\tpushInsteadOf = git@github.com:\n`],
    ['an include', `${ORIGIN}[include]\n\tpath = /tmp/elsewhere\n`],
    ['an includeIf', `${ORIGIN}[includeIf "gitdir:~/"]\n\tpath = /tmp/elsewhere\n`],
    ['a value continued on the next line', `${ORIGIN}[core]\n\tpager = less \\\n\t-R\n`],
  ])('%s', (_label, config) => {
    repoConfig(config);
    expect(git('git push origin main')).toBe('Send data to the "origin" remote (git push)');
    expect(git('git fetch origin')).toBe('Send data to the "origin" remote (git fetch)');
  });

  it('insteadOf in the GLOBAL config (~/.gitconfig and ~/.config/git/config)', () => {
    repoConfig(ORIGIN);
    writeFileSync(join(home, '.gitconfig'), '[url "https://mirror.example.net/"]\n\tinsteadOf = git@github.com:\n');
    expect(git('git push origin main')).toBe('Send data to the "origin" remote (git push)');
    rmSync(join(home, '.gitconfig'));
    mkdirSync(join(home, '.config', 'git'), { recursive: true });
    writeFileSync(join(home, '.config', 'git', 'config'), '[url "https://mirror.example.net/"]\n\tpushInsteadOf = git@github.com:\n');
    expect(git('git push origin main')).toBe('Send data to the "origin" remote (git push)');
  });

  it('insteadOf in the SYSTEM config', () => {
    repoConfig(ORIGIN);
    const system = join(root, 'gitconfig');
    writeFileSync(system, '[url "https://mirror.example.net/"]\n\tinsteadOf = git@github.com:\n');
    expect(describeAction({ tool: 'Bash', input: { command: 'git push' }, signals: [], cwd: repo, gitSystemConfig: [system] }).text)
      .toBe('Send data to the "origin" remote (git push)');
  });

  it('git config pointed elsewhere by the environment', () => {
    repoConfig(ORIGIN);
    process.env.GIT_CONFIG_GLOBAL = join(root, 'other');
    expect(git('git push origin main')).toBe('Send data to the "origin" remote (git push)');
  });

  it('-C, --git-dir, GIT_DIR and an earlier cd move the repository', () => {
    repoConfig(ORIGIN);
    for (const command of [
      'git -C /tmp/x push --force origin main',
      'git --git-dir=/tmp/x/.git push --force origin main',
      'GIT_DIR=/tmp/x/.git git push --force origin main',
      'cd /tmp/x && git push --force origin main',
      'env -C /tmp/x git push --force origin main',
    ]) {
      expect(git(command, repo, evaluateToolCall('Bash', { command }).signals))
        .toMatch(/^Force-push to the "origin" remote \(branch "main"\) \(git push --force\)/);
    }
    // With no remote named, the moved repository's default is unknown too.
    expect(git('git -C /tmp/x push --force')).toBe('Force-push to a remote server (git push --force)');
  });

  it('a redirected default remote (pushDefault, branch.*.pushRemote) is not followed', () => {
    repoConfig(`${ORIGIN}[remote]\n\tpushDefault = fork\n[remote "fork"]\n\turl = git@fork.example.net:me/app.git\n`);
    expect(git('git push')).toBe('Send data to a remote server (git push)');
    expect(git('git push origin')).toBe('Send data to github.com (git push)');
    repoConfig(`${ORIGIN}[branch "main"]\n\tpushRemote = fork\n`);
    expect(git('git push')).toBe('Send data to a remote server (git push)');
  });

  it('a URL typed on the command line is named only when the repository config was read', () => {
    repoConfig(ORIGIN);
    expect(git('git push https://gitlab.example.org/acme/app.git main')).toBe('Send data to gitlab.example.org (git push)');
    expect(git('git push https://gitlab.example.org/acme/app.git main', NO_CWD)).toBe('Send data to a remote server (git push)');
  });

  it('git clone: global insteadOf drops the host', () => {
    expect(git('git clone https://github.com/acme/app.git', NO_CWD)).toBe('Send data to github.com (git clone)');
    writeFileSync(join(home, '.gitconfig'), '[url "https://mirror.example.net/"]\n\tinsteadOf = https://github.com/\n');
    expect(git('git clone https://github.com/acme/app.git', NO_CWD)).toBe('Send data to a remote server (git clone)');
  });
});
