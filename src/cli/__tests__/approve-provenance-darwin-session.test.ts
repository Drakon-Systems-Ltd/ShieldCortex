/**
 * macOS `ps` reports SESS as 0 for every process, so the #502 session-leader
 * lookup found no leader and refused every human on a Mac (Terminal.app and
 * SSH alike). The leader now comes from BSD ps STAT's `s` flag on our tty.
 */
import { describe, expect, it } from '@jest/globals';

import {
  darwinSessionLeaderFromPs,
  defaultProvenanceSeam,
  operatorProvenance,
  type ProcInfo,
  type ProvenanceSeam,
} from '../approve-provenance.js';

type Row = [pid: number, ppid: number, sid: number, comm: string, tty?: number];

function seam(rows: Row[], leafPid: number): ProvenanceSeam {
  const map = new Map<number, ProcInfo>(rows.map(([pid, ppid, sid, comm, tty]) => [pid, { pid, ppid, sid, comm, tty: tty ?? 1 }]));
  return { pid: leafPid, env: {}, platform: 'darwin', proc: (pid) => map.get(pid) ?? null };
}

const LAUNCHD: Row = [1, 0, 1, 'launchd', 0];

describe('darwinSessionLeaderFromPs', () => {
  it('Terminal.app tty: login is the leader, the shell is not', () => {
    expect(darwinSessionLeaderFromPs('98863 Ss\n98864 S+\n12001 R+\n')).toBe(98863);
  });

  it('SSH tty: the login shell is the leader', () => {
    expect(darwinSessionLeaderFromPs('  23067 Ss+\n  24000 R+\n')).toBe(23067);
  });

  it('no leader on the tty fails closed', () => {
    expect(darwinSessionLeaderFromPs('100 S+\n101 R+\n')).toBe(0);
  });

  it('two leaders on one tty is ambiguous and fails closed', () => {
    expect(darwinSessionLeaderFromPs('100 Ss\n200 Ss+\n')).toBe(0);
  });

  it('ignores blank and malformed lines', () => {
    expect(darwinSessionLeaderFromPs('\n  \nPID STAT\n300 Ss\n')).toBe(300);
  });
});

describe('macOS session shapes with the recovered leader', () => {
  it('Terminal.app: launchd → Terminal → login (leader) → zsh → node passes', () => {
    const s = seam([LAUNCHD, [500, 1, 0, 'Terminal', 0], [600, 500, 600, 'login'],
      [601, 600, 600, '-zsh'], [700, 601, 600, 'node']], 700);
    expect(operatorProvenance(s)).toMatchObject({ ok: true, reason: null });
  });

  it('SSH (e.g. a phone client): sshd-session → zsh (leader) → node passes', () => {
    const s = seam([LAUNCHD, [400, 1, 0, 'sshd-session', 0], [401, 400, 401, '-zsh'],
      [450, 401, 401, 'node']], 450);
    expect(operatorProvenance(s)).toMatchObject({ ok: true, reason: null });
  });

  it('an agent ancestor above a real login session still refuses', () => {
    const s = seam([LAUNCHD, [300, 1, 0, 'claude', 0], [301, 300, 0, 'zsh', 0], [500, 301, 0, 'Terminal', 0],
      [600, 500, 600, 'login'], [601, 600, 600, '-zsh'], [700, 601, 600, 'node']], 700);
    expect(operatorProvenance(s).reason).toBe('agent-ancestor');
  });

  it('python pty.spawn leading a fresh tty still refuses', () => {
    const s = seam([LAUNCHD, [300, 1, 0, 'claude', 0], [310, 300, 310, 'python3'], [320, 310, 310, 'zsh'],
      [330, 320, 310, 'node']], 330);
    expect(operatorProvenance(s).ok).toBe(false);
  });

  it('an unresolved leader (sid 0) still refuses as no-session-leader', () => {
    const s = seam([LAUNCHD, [400, 1, 0, 'sshd-session', 0], [401, 400, 0, '-zsh'], [450, 401, 0, 'node']], 450);
    expect(operatorProvenance(s).reason).toBe('no-session-leader');
  });
});

const onDarwin = process.platform === 'darwin' ? it : it.skip;

describe('live macOS ps', () => {
  onDarwin('readProcDarwin never reports a nonzero SESS from ps, so the tty lookup is what supplies sid', () => {
    const self = defaultProvenanceSeam().proc(process.pid);
    expect(self).not.toBeNull();
    // Under jest there is usually no controlling tty; when there is, the sid
    // must be a live leader rather than the 0 ps prints.
    if (self && self.tty === 1) expect(self.sid).toBeGreaterThan(0);
  });
});
