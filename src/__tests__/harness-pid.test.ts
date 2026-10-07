import { describe, expect, it } from '@jest/globals';
// The hook imports this published .mjs file directly; keep the tests on the same module.
// @ts-ignore no declaration is emitted for scripts outside the TS build
import { resolveHarnessPid } from '../../scripts/lib/harness-pid.mjs';

type Ancestor = { ppid: number; argv: string[] };
const walk = (rows: Record<number, Ancestor | null>, hops = 8) =>
  resolveHarnessPid(40, (pid: number) => rows[pid] ?? null, hops);

describe('#553 harness pid ancestor walk', () => {
  it('skips a shell invoked with -c and stops at the harness', () => {
    expect(walk({
      40: { ppid: 30, argv: ['/bin/dash', '-c', 'node dist/index.js hook pre-tool'] },
      30: { ppid: 20, argv: ['/usr/bin/claude', 'session'] },
    })).toBe(30);
  });

  it('skips the ShieldCortex launcher and shell but stops at another node process', () => {
    expect(walk({
      40: { ppid: 30, argv: ['/usr/bin/node', '/app/dist/index.js', 'hook', 'pre-tool'] },
      30: { ppid: 20, argv: ['/bin/sh', '-c', 'shieldcortex hook pre-tool'] },
      20: { ppid: 10, argv: ['/usr/bin/node', '/app/harness.mjs'] },
    })).toBe(20);
  });

  it('bounds the walk and returns the parent when the process table is unreadable', () => {
    const rows = {
      40: { ppid: 30, argv: ['/bin/bash', '-lc', 'command'] },
      30: { ppid: 20, argv: ['/bin/ash', '-c', 'command'] },
    };
    expect(walk(rows, 1)).toBe(30);
    expect(walk({ 40: null })).toBe(40);
    expect(resolveHarnessPid(1, () => null)).toBe(process.pid);
  });
});
