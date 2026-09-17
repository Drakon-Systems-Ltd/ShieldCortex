/**
 * #502 — `shieldcortex approve` must refuse when the "terminal" was
 * manufactured by an agent's tool call, and must NOT refuse a real human.
 *
 * Synthetic process trees. The live reproducers (script(1), python pty.spawn,
 * setsid -f variants) were run by hand against dist and are recorded in the
 * PR. Each MUST-REFUSE shape here was ok:true on 5.0.5's isTTY-only gate.
 */
import { describe, expect, it } from '@jest/globals';

import {
  operatorProvenance,
  describeProvenanceRefusal,
  type ProcInfo,
  type ProvenanceSeam,
} from '../approve-provenance.js';
import { runApprove } from '../approve.js';

type Row = [pid: number, ppid: number, sid: number, comm: string, tty?: number];

function seam(rows: Row[], leafPid: number, env: NodeJS.ProcessEnv = {}): ProvenanceSeam {
  // tty defaults to 1 (has a controlling terminal); 0 models a detached child.
  const map = new Map<number, ProcInfo>(rows.map(([pid, ppid, sid, comm, tty]) => [pid, { pid, ppid, sid, comm, tty: tty ?? 1 }]));
  return { pid: leafPid, env, platform: 'linux', proc: (pid) => map.get(pid) ?? null };
}

const INIT: Row = [1, 0, 1, 'systemd'];

describe('#502 operator provenance — must REFUSE', () => {
  it('agent environment marker, even with a perfect ancestry', () => {
    const s = seam([INIT, [100, 1, 100, 'sshd'], [200, 100, 200, 'bash'], [300, 200, 200, 'node']], 300, { HERMES_SESSION_ID: 'x' });
    const v = operatorProvenance(s);
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('agent-environment');
  });

  it.each([
    ['CLAUDECODE', { CLAUDECODE: '1' }],
    ['CLAUDE_CODE_ prefix', { CLAUDE_CODE_ENTRYPOINT: 'cli' }],
    ['OPENCLAW_ prefix', { OPENCLAW_SESSION: 'a' }],
    ['CODEX_SANDBOX', { CODEX_SANDBOX: 'seatbelt' }],
  ])('env marker %s refuses', (_l, env) => {
    const s = seam([INIT, [100, 1, 100, 'sshd'], [200, 100, 200, 'bash'], [300, 200, 200, 'node']], 300, env);
    expect(operatorProvenance(s).reason).toBe('agent-environment');
  });

  it('the issue reproducer: script -qec under an agent shell (env -i, so ancestry decides)', () => {
    const s = seam([INIT, [10, 1, 10, 'hermes'], [11, 10, 10, 'bash'], [12, 11, 10, 'bash'],
      [13, 12, 10, 'script'], [14, 13, 14, 'sh'], [15, 14, 14, 'node']], 15);
    const v = operatorProvenance(s);
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('agent-ancestor');
    expect(v.chain).toEqual(['node', 'sh', 'script', 'bash', 'bash', 'hermes']);
  });

  it.each(['claude', 'openclaw', 'clawdbot', 'codex', 'aider', 'hermes'])('agent ancestor %s refuses', (agent) => {
    const s = seam([INIT, [10, 1, 10, agent], [11, 10, 10, 'bash'], [12, 11, 12, 'bash'], [13, 12, 12, 'node']], 13);
    expect(operatorProvenance(s).reason).toBe('agent-ancestor');
  });

  it('setsid -f + script: orphaned to init, leader is the shell, parent is the pty tool', () => {
    const s = seam([INIT, [20, 1, 20, 'script'], [21, 20, 21, 'sh'], [22, 21, 21, 'node']], 22);
    const v = operatorProvenance(s);
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('pty-tool-session-leader');
  });

  it.each(['script', 'expect', 'unbuffer', 'socat'])('%s as session leader itself refuses', (tool) => {
    const s = seam([INIT, [20, 1, 20, tool], [22, 20, 20, 'node']], 22);
    expect(operatorProvenance(s).reason).toBe('pty-tool-session-leader');
  });

  it('setsid -f + python pty.spawn: leader is bash, parent is a bare interpreter', () => {
    const s = seam([INIT, [30, 1, 30, 'python3'], [31, 30, 31, 'bash'], [32, 31, 31, 'node']], 32);
    const v = operatorProvenance(s);
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('pty-interpreter-parent');
  });

  it.each(['node', 'python3.12', 'python', 'perl', 'ruby'])('interpreter %s as leader parent refuses', (interp) => {
    const s = seam([INIT, [30, 1, 30, interp], [31, 30, 31, 'bash'], [32, 31, 31, 'node']], 32);
    expect(operatorProvenance(s).reason).toBe('pty-interpreter-parent');
  });

  it('GPT-6 r1: pty allocated with script, THEN setsid -f a child that keeps the fds and outlives its launcher', () => {
    // Live on the TARS box: isTTY true, chain node → systemd, every ancestry
    // check passed. The tell is tty_nr === 0 — fds without a controlling tty.
    const s = seam([INIT, [50, 1, 50, 'node', 0]], 50);
    const v = operatorProvenance(s);
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('no-controlling-terminal');
  });

  it('no-controlling-terminal is checked BEFORE ancestry, so a clean tree does not rescue it', () => {
    const s = seam([INIT, [100, 1, 100, 'sshd'], [101, 100, 101, 'bash'], [102, 101, 101, 'node', 0]], 102);
    expect(operatorProvenance(s).reason).toBe('no-controlling-terminal');
  });

  it('GPT-6 r2: daemonise, openpty, TIOCSCTTY, keep interpreter as session leader', () => {
    // Live: node → python3 → systemd, isTTY true, tty_nr nonzero.
    const s = seam([INIT, [60, 1, 60, 'python3'], [61, 60, 60, 'node']], 61);
    const v = operatorProvenance(s);
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('pty-interpreter-leader');
  });

  it.each(['python3', 'node', 'perl', 'ruby'])('interpreter %s as session leader refuses', (interp) => {
    const s = seam([INIT, [60, 1, 60, interp], [61, 60, 60, 'node']], 61);
    expect(operatorProvenance(s).reason).toBe('pty-interpreter-leader');
  });

  it('GPT-6 r3: leader is python OUTSIDE the parent chain (leaf double-forked, adopted by init, keeps python sid)', () => {
    // Live: leader python pid=214294 sid=214294; leaf pid=214296 ppid=1 sid=214294.
    // Old walk picked systemd's session; self.sid finds python.
    const s = seam([INIT, [70, 1, 70, 'python3'], [71, 1, 70, 'node']], 71);
    const v = operatorProvenance(s);
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('pty-interpreter-leader');
  });

  it('leader outside the chain that is a pty tool still refuses', () => {
    const s = seam([INIT, [70, 1, 70, 'script'], [71, 1, 70, 'node']], 71);
    expect(operatorProvenance(s).reason).toBe('pty-tool-session-leader');
  });

  it('leader outside the chain that is an agent refuses', () => {
    const s = seam([INIT, [70, 1, 70, 'hermes'], [71, 1, 70, 'node']], 71);
    expect(operatorProvenance(s).reason).toBe('agent-ancestor');
  });

  it('GPT-6 r4: recovered leader is a shell whose PARENT is an agent (orphaned leaf keeps bash sid)', () => {
    // systemd ← agent(sid 10) ← bash(sid 20, leader) ; leaf node parent=1 sid=20
    const s = seam([INIT, [10, 1, 10, 'hermes'], [20, 10, 20, 'bash'], [30, 1, 20, 'node']], 30);
    const v = operatorProvenance(s);
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('agent-ancestor');
  });

  it('GPT-6 r4: agent is two hops above the recovered leader', () => {
    const s = seam([INIT, [10, 1, 10, 'claude'], [15, 10, 10, 'bash'], [20, 15, 20, 'bash'], [30, 1, 20, 'node']], 30);
    expect(operatorProvenance(s).reason).toBe('agent-ancestor');
  });

  it('a dead session leader refuses (no session leader)', () => {
    // sid points at a pid that no longer exists.
    const s = seam([INIT, [41, 1, 99, 'node']], 41);
    expect(operatorProvenance(s).reason).toBe('no-session-leader');
  });
});

describe('#502 operator provenance — must ALLOW (a human at a real terminal)', () => {
  it.each([
    ['ssh: sshd to bash', [[100, 1, 100, 'sshd'], [101, 100, 101, 'bash'], [102, 101, 101, 'node']] as Row[], 102],
    ['ssh: sshd-session to zsh', [[100, 1, 100, 'sshd-session'], [101, 100, 101, 'zsh'], [102, 101, 101, 'node']] as Row[], 102],
    ['tmux: tmux server to bash', [[100, 1, 100, 'tmux: server'], [101, 100, 101, 'bash'], [102, 101, 101, 'node']] as Row[], 102],
    ['screen to bash', [[100, 1, 100, 'screen'], [101, 100, 101, 'bash'], [102, 101, 101, 'node']] as Row[], 102],
    ['Terminal.app: login to zsh', [[100, 1, 100, 'login'], [101, 100, 101, 'zsh'], [102, 101, 101, 'node']] as Row[], 102],
    ['gnome-terminal-server to bash', [[100, 1, 100, 'gnome-terminal-server'], [101, 100, 101, 'bash'], [102, 101, 101, 'node']] as Row[], 102],
    ['VS Code integrated terminal: code to bash (NOT the agent)', [[100, 1, 100, 'code'], [101, 100, 101, 'bash'], [102, 101, 101, 'node']] as Row[], 102],
    ['agetty to login to bash (console)', [[100, 1, 100, 'agetty'], [101, 100, 101, 'login'], [102, 101, 102, 'bash'], [103, 102, 102, 'node']] as Row[], 103],
    ['nested: human bash to bash to node', [[100, 1, 100, 'sshd'], [101, 100, 101, 'bash'], [102, 101, 101, 'bash'], [103, 102, 101, 'node']] as Row[], 103],
  ])('%s', (_label, rows, leaf) => {
    const v = operatorProvenance(seam([INIT, ...rows], leaf));
    expect(v.ok).toBe(true);
    expect(v.reason).toBeNull();
  });

  it('WSL / console login: bash whose parent is init is allowed (indistinguishable from GPT-6 r2 exec-bash; refusing it cards every WSL user)', () => {
    const s = seam([INIT, [101, 1, 101, 'bash'], [102, 101, 101, 'node']], 102);
    expect(operatorProvenance(s).ok).toBe(true);
  });

  it('an unknown session-leader parent is allowed (unknown is not bad; false refusals teach uninstall)', () => {
    const s = seam([INIT, [100, 1, 100, 'some-new-terminal'], [101, 100, 101, 'fish'], [102, 101, 101, 'node']], 102);
    expect(operatorProvenance(s).ok).toBe(true);
  });

  it('unreadable process tree degrades to env-only and says so', () => {
    const s: ProvenanceSeam = { pid: 1, env: {}, platform: 'win32', proc: () => null };
    const v = operatorProvenance(s);
    expect(v.ok).toBe(true);
    expect(v.detail).toMatch(/environment check only/);
  });
});

describe('#502 wiring — runApprove refuses on provenance even with TTYs', () => {
  const refused = () => ({ ok: false, reason: 'agent-ancestor' as const, detail: 'x', chain: ['node', 'script', 'claude'] });
  const passed = () => ({ ok: true, reason: null, detail: 'ok', chain: ['node', 'bash', 'sshd'] });

  it('<hash> path: TTY true + provenance refused to exit 1, no grant, names the ancestry', () => {
    const errs: string[] = [];
    const code = runApprove(['deadbeef'], {
      home: '/nonexistent-home-502', interactive: true, provenance: refused,
      log: () => {}, error: (m) => errs.push(m),
    });
    expect(code).toBe(1);
    expect(errs.join('\n')).toMatch(/terminal the agent did not open/);
    expect(errs.join('\n')).toMatch(/node ← script ← claude/);
    expect(errs.join('\n')).not.toMatch(/No pending approval/);
  });

  it('--denial path: TTY true + provenance refused to exit 1 before any store lookup', () => {
    const errs: string[] = [];
    const code = runApprove(['--denial', 'act-0000000000000000'], {
      home: '/nonexistent-home-502', interactive: true, provenance: refused,
      log: () => {}, error: (m) => errs.push(m), confirm: () => true,
    });
    expect(code).toBe(1);
    expect(errs.join('\n')).toMatch(/terminal the agent did not open/);
    expect(errs.join('\n')).not.toMatch(/No headless denial matches/);
  });

  it('provenance passed then reaches the store as before (no-such-hash is the expected next error)', () => {
    const errs: string[] = [];
    const code = runApprove(['deadbeef'], {
      home: '/nonexistent-home-502', interactive: true, provenance: passed,
      log: () => {}, error: (m) => errs.push(m),
    });
    expect(code).toBe(1);
    expect(errs.join('\n')).toMatch(/No pending approval matches/);
  });

  it('listing never consults provenance', () => {
    let called = 0;
    const code = runApprove([], { home: '/nonexistent-home-502', interactive: false, provenance: () => { called += 1; return refused(); }, log: () => {}, error: () => {} });
    expect(code).toBe(0);
    expect(called).toBe(0);
  });

  it('refusal copy points the human at a terminal they open themselves', () => {
    const lines = describeProvenanceRefusal(refused());
    expect(lines.join('\n')).toMatch(/ssh, Terminal\.app, tmux/);
  });
});
