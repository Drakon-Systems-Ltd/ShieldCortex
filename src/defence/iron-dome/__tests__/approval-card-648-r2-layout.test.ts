/**
 * #648 round 2 — the length caps never hide what matters (S5 the WHY count,
 * S6 the WHAT tail) — plus the round's wording nits.
 *
 * Destructive fixtures are assembled at runtime (the guard's own
 * write-content scan).
 */
import { describe, it, expect } from '@jest/globals';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describeAction as describeActionFull, describeSignal, describeSignals, formatApprovalCardLines } from '../approval-card.js';
import { evaluateToolCall } from '../tool-action-guard.js';

/** Line 1's text; round 3 added a confidence flag beside it. */
const describeAction = (a: Parameters<typeof describeActionFull>[0]) => describeActionFull(a).text;

const RM_RF = ['r', 'm', ' -', 'r', 'f'].join('');
const KILL_ALL = ['kill', '-9', '-1'].join(' ');

const bash = (command: string, signals: string[] = evaluateToolCall('Bash', { command }).signals) =>
  describeAction({ tool: 'Bash', input: { command }, signals });

describe('#648 r2 S5 — the WHY line always keeps the count of further reasons', () => {
  it('"(+N more reasons)" is always shown; the phrase is shortened instead', () => {
    expect(describeSignals(['privilege-escalation', 'stop-process-or-service', 'external-egress']))
      .toBe('runs with administrator (root) rights (+2 more reasons)');
    const long = describeSignals(['openclaw-process-unknown-action', 'external-egress']);
    expect(long.endsWith(' (+1 more reason)')).toBe(true);
    expect(long.length).toBeLessThanOrEqual(59);
    expect(long.startsWith('asks a running command')).toBe(true);
  });

  it('the count survives the card layout', () => {
    const reason = describeSignals(['openclaw-process-unknown-action', 'external-egress', 'privilege-escalation']);
    const [, why] = formatApprovalCardLines({ action: 'x', reason, who: 'w' }, { expiresInMs: 600_000 });
    expect(why).toMatch(/\(\+2 more reasons\)$/);
  });
});

describe('#648 r2 S6 — clipping keeps the head and the tail, and the markers always survive', () => {
  const deep = `/srv/${'a'.repeat(30)}/${'b'.repeat(30)}/final.txt`;

  it('the WHAT line is clipped in the middle, keeping sudo and the step count', () => {
    const action = bash(`cd /tmp && sudo ${RM_RF} ${deep} && echo ok`);
    expect(action).toContain(', as administrator (sudo)');
    expect(action).toContain('(+2 more steps)');
    const who = 'w'.repeat(70);
    const reason = 'r'.repeat(58);
    // Long WHY and WHO leave the action 80 of the 256 characters.
    const [what] = formatApprovalCardLines({ action, reason, who }, { expiresInMs: 600_000 });
    expect(action.length).toBeGreaterThan(80);
    expect(what.length).toBeLessThanOrEqual(80);
    expect(what.startsWith('Delete a folder')).toBe(true);
    expect(what).toContain(', as administrator (sudo)');
    expect(what.endsWith('(+2 more steps)')).toBe(true);
    expect(what).toContain('…');
  });

  it('a long target keeps its tail (the file name) when the line is clipped', () => {
    const [what] = formatApprovalCardLines({ action: `Read a file: "${deep}"`, reason: 'r', who: 'w' }, { expiresInMs: 600_000, budget: 120 });
    expect(what).toContain('final.txt"');
    expect(what.startsWith('Read a file')).toBe(true);
  });
});

describe('#648 r2 NITs — wording that says only what is known', () => {
  it('kill -9 -1 stops ALL your programs', () => {
    expect(bash(KILL_ALL, ['stop-process-or-service'])).toBe('Stop ALL your programs');
    expect(bash(['kill', '-s', 'KILL', '-1'].join(' '), ['stop-process-or-service'])).toBe('Stop ALL your programs');
    expect(bash(['kill', '--', '-1'].join(' '), ['stop-process-or-service'])).toBe('Stop ALL your programs');
  });

  it('"it started" is claimed only when ancestry proves it; otherwise "a running program"', () => {
    const proc = mkdtempSync(join(tmpdir(), 'sc-648-r2-proc-'));
    try {
      const stat = (pid: number, comm: string, ppid: number) => `${pid} (${comm}) S ${ppid} ${Array(17).fill('0').join(' ')} ${(1000 - 240) * 100} 0 0\n`;
      writeFileSync(join(proc, 'uptime'), '1000.00 4000.00\n');
      mkdirSync(join(proc, '4242'));
      writeFileSync(join(proc, '4242', 'stat'), stat(4242, 'node', 999));
      writeFileSync(join(proc, '4242', 'comm'), 'node\n');
      symlinkSync('/tmp/relay', join(proc, '4242', 'cwd'));
      const input = { tool: 'Bash', input: { command: 'kill 4242' }, signals: ['stop-process-or-service'], procRoot: proc };
      expect(describeAction({ ...input })).toMatch(/^Stop a running program \(node/);
      expect(describeAction({ ...input, agentPid: 31337 })).toMatch(/^Stop a running program \(node/);
      expect(describeAction({ ...input, agentPid: 999 })).toMatch(/^Stop a program it started 4 minutes ago/);
    } finally {
      rmSync(proc, { recursive: true, force: true });
    }
  });

  it("the OpenClaw process tool's kill does not claim the agent started it", () => {
    expect(describeAction({ tool: 'process', input: { action: 'kill', sessionId: 's' }, signals: [] })).not.toMatch(/it started/);
  });

  it('force-push and history phrases say only what their rules catch', () => {
    for (const id of ['git-force-push', 'force-push', 'force-push-invocation']) {
      expect(describeSignal(id)).toBe('pushes to a remote branch (may overwrite history)');
    }
    expect(describeSignal('wipe-history-or-logs')).toBe('touches shell history or log files');
  });

  it('readiness phrases complete "stopped because it …"', () => {
    for (const id of ['readiness-demoted', 'readiness-promoted', 'readiness-started']) {
      expect(describeSignal(id)).toMatch(/^is the first call since ShieldCortex /);
    }
  });

  it('curl -d@file and -XPOST read as an upload', () => {
    expect(bash('curl -d@report.json https://collector.example.net/in', [])).toBe('Send data to collector.example.net (curl)');
    expect(bash('curl -XPOST https://collector.example.net/in', [])).toBe('Send data to collector.example.net (curl)');
    expect(bash('curl --request=PUT https://collector.example.net/in', [])).toBe('Send data to collector.example.net (curl)');
    expect(bash('curl https://collector.example.net/in', [])).toBe('Download from collector.example.net (curl)');
  });
});
