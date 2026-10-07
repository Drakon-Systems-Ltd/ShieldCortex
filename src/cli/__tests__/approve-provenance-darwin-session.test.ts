/**
 * macOS: `ps -o sess=` is a kernel pointer that prints 0 on current releases,
 * so the #502 session-leader lookup found no leader and refused every human on
 * a Mac (Terminal.app and SSH alike). The leader now comes from BSD ps STAT's
 * `s` flag on our controlling tty, and every way that discovery can fail
 * refuses rather than degrading.
 *
 * These drive the real Darwin reader (makeDarwinProcReader) over a fake `ps`,
 * so the parsing, the tty lookup and its failure modes are all under test.
 */
import { describe, expect, it } from '@jest/globals';

import {
  darwinSessionLeaderFromPs,
  makeDarwinProcReader,
  operatorProvenance,
  type PsRunner,
} from '../approve-provenance.js';

interface FakeProc { ppid: number; tty: string; comm: string; stat: string }

/** A fake `/bin/ps` that answers the two shapes the reader asks. */
function fakePs(procs: Record<number, FakeProc>, opts: { failTty?: boolean } = {}): PsRunner & { calls: string[][] } {
  const calls: string[][] = [];
  const run = ((args: string[]) => {
    calls.push(args);
    if (args[0] === '-t') {
      if (opts.failTty) throw new Error('ps exited 1');
      const rows = Object.entries(procs).filter(([, p]) => p.tty === args[1]);
      if (rows.length === 0) throw new Error('ps exited 1'); // macOS ps exits 1 on no match
      return rows.map(([pid, p]) => `${pid} ${p.stat}`).join('\n') + '\n';
    }
    const pid = Number(args[args.indexOf('-p') + 1]);
    const p = procs[pid];
    if (!p) throw new Error('ps exited 1');
    return `${p.ppid} ${p.tty} ${p.comm}\n`;
  }) as PsRunner & { calls: string[][] };
  run.calls = calls;
  return run;
}

function verdict(procs: Record<number, FakeProc>, leaf: number, opts?: { failTty?: boolean }) {
  const ps = fakePs(procs, opts);
  const v = operatorProvenance({ pid: leaf, env: {}, platform: 'darwin', proc: makeDarwinProcReader(ps) });
  return { v, ps };
}

const LAUNCHD: FakeProc = { ppid: 0, tty: '??', comm: '/sbin/launchd', stat: 'Ss' };

const TERMINAL_APP: Record<number, FakeProc> = {
  1: LAUNCHD,
  500: { ppid: 1, tty: '??', comm: '/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal', stat: 'S' },
  600: { ppid: 500, tty: 'ttys000', comm: 'login', stat: 'Ss' },
  601: { ppid: 600, tty: 'ttys000', comm: '-zsh', stat: 'S' },
  700: { ppid: 601, tty: 'ttys000', comm: 'node', stat: 'S+' },
};

const SSH: Record<number, FakeProc> = {
  1: LAUNCHD,
  390: { ppid: 1, tty: '??', comm: 'sshd-session: michael [priv]', stat: 'Ss' },
  400: { ppid: 390, tty: '??', comm: 'sshd-session: michael@ttys001', stat: 'S' },
  401: { ppid: 400, tty: 'ttys001', comm: '-zsh', stat: 'Ss' },
  450: { ppid: 401, tty: 'ttys001', comm: 'node', stat: 'S+' },
};

describe('darwinSessionLeaderFromPs', () => {
  it('Terminal.app tty: login is the leader, the shell is not', () => {
    expect(darwinSessionLeaderFromPs('98863 Ss\n98864 S+\n12001 R+\n')).toBe(98863);
  });
  it('SSH tty: the login shell is the leader', () => {
    expect(darwinSessionLeaderFromPs('  23067 Ss+\n  24000 R+\n')).toBe(23067);
  });
  it('no leader on the tty → 0', () => {
    expect(darwinSessionLeaderFromPs('100 S+\n101 R+\n')).toBe(0);
  });
  it('two leaders on one tty is ambiguous → 0', () => {
    expect(darwinSessionLeaderFromPs('100 Ss\n200 Ss+\n')).toBe(0);
  });
  it('ignores blank, header and malformed lines', () => {
    expect(darwinSessionLeaderFromPs('\n  \nPID STAT\n300 Ss\ngarbage\n')).toBe(300);
  });
});

describe('macOS — humans pass', () => {
  it('Terminal.app (launchd → Terminal → login → -zsh → node)', () => {
    expect(verdict(TERMINAL_APP, 700).v).toMatchObject({ ok: true, reason: null });
  });
  it('SSH, e.g. a phone client (sshd-session → -zsh → node)', () => {
    expect(verdict(SSH, 450).v).toMatchObject({ ok: true, reason: null });
  });
  it('a multiplexer pane (tmux server → zsh) is an accepted residual', () => {
    const procs: Record<number, FakeProc> = {
      1: LAUNCHD,
      300: { ppid: 1, tty: '??', comm: 'tmux', stat: 'Ss' },
      301: { ppid: 300, tty: 'ttys004', comm: '-zsh', stat: 'Ss' },
      302: { ppid: 301, tty: 'ttys004', comm: 'node', stat: 'S+' },
    };
    expect(verdict(procs, 302).v.ok).toBe(true);
  });
});

describe('macOS — discovery failures refuse', () => {
  it('the tty → leader query failing leaves sid 0 and refuses (never the env-only degrade)', () => {
    const { v } = verdict(SSH, 450, { failTty: true });
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('no-session-leader');
  });
  it('two leaders on our tty refuses', () => {
    const procs = { ...SSH, 460: { ppid: 1, tty: 'ttys001', comm: 'zsh', stat: 'Ss' } };
    expect(verdict(procs, 450).v.reason).toBe('no-session-leader');
  });
  it('our own process unreadable refuses', () => {
    const { v } = verdict(SSH, 9999);
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('process-tree-unreadable');
  });
  it('a hole mid-ancestry refuses instead of ending the walk clean', () => {
    const procs = { ...SSH };
    delete (procs as Record<number, FakeProc>)[401];
    const { v } = verdict(procs, 450);
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('process-tree-unreadable');
  });
  it('the leader lookup runs once per tty, not once per ancestor', () => {
    const { ps } = verdict(TERMINAL_APP, 700);
    expect(ps.calls.filter((a) => a[0] === '-t')).toHaveLength(1);
  });
  it('uses no PATH lookup: the default runner is /bin/ps (source contract)', async () => {
    const { readFileSync } = await import('node:fs');
    const src = readFileSync(new URL('../approve-provenance.ts', import.meta.url), 'utf8');
    expect(src).toMatch(/execFileSync\('\/bin\/ps'/);
    expect(src).not.toMatch(/execFileSync\('ps'/);
  });
});

describe('macOS — manufactured terminals refuse', () => {
  it('fresh pty, shell as leader, launcher gone (launchd → -zsh → node)', () => {
    const procs: Record<number, FakeProc> = {
      1: LAUNCHD,
      801: { ppid: 1, tty: 'ttys009', comm: '-zsh', stat: 'Ss+' },
      802: { ppid: 801, tty: 'ttys009', comm: 'node', stat: 'S+' },
    };
    const { v } = verdict(procs, 802);
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('orphaned-shell-leader');
  });
  it('the same with a non-shell leader name still refuses', () => {
    const procs: Record<number, FakeProc> = {
      1: LAUNCHD,
      801: { ppid: 1, tty: 'ttys009', comm: 'Terminal', stat: 'Ss+' },
      802: { ppid: 801, tty: 'ttys009', comm: 'node', stat: 'S+' },
    };
    expect(verdict(procs, 802).v.reason).toBe('orphaned-shell-leader');
  });
  it('python pty.spawn leading the tty, no agent ancestor visible', () => {
    const procs: Record<number, FakeProc> = {
      1: LAUNCHD,
      500: { ppid: 1, tty: '??', comm: 'some-supervisor', stat: 'S' },
      810: { ppid: 500, tty: 'ttys010', comm: 'python3', stat: 'Ss' },
      811: { ppid: 810, tty: 'ttys010', comm: 'zsh', stat: 'S' },
      812: { ppid: 811, tty: 'ttys010', comm: 'node', stat: 'S+' },
    };
    expect(verdict(procs, 812).v.reason).toBe('pty-interpreter-leader');
  });
  it('script(1) as leader parent, no agent ancestor visible', () => {
    const procs: Record<number, FakeProc> = {
      1: LAUNCHD,
      500: { ppid: 1, tty: '??', comm: 'some-supervisor', stat: 'S' },
      820: { ppid: 500, tty: '??', comm: 'script', stat: 'S' },
      821: { ppid: 820, tty: 'ttys011', comm: 'sh', stat: 'Ss' },
      822: { ppid: 821, tty: 'ttys011', comm: 'node', stat: 'S+' },
    };
    expect(verdict(procs, 822).v.reason).toBe('pty-tool-session-leader');
  });
  it('no controlling terminal still refuses before any lookup', () => {
    const procs: Record<number, FakeProc> = {
      1: LAUNCHD,
      830: { ppid: 1, tty: '??', comm: 'node', stat: 'S' },
    };
    expect(verdict(procs, 830).v.reason).toBe('no-controlling-terminal');
  });
  it('an agent ancestor above a real Terminal session still refuses', () => {
    const procs = { ...TERMINAL_APP, 500: { ...TERMINAL_APP[500], ppid: 450 }, 450: { ppid: 1, tty: '??', comm: 'claude', stat: 'S' } };
    expect(verdict(procs, 700).v.reason).toBe('agent-ancestor');
  });
});
