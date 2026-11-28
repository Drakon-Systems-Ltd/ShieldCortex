/**
 * #1179 (item 3): the launch tripwire in support/openclaw-host-isolation.ts
 * mocked only the bare `child_process` specifier, while product code doctor
 * reaches imports `node:child_process`. Both forms must hand out the
 * tripwire's fakes.
 *
 * Jest 30 maps the prefixed specifier onto the bare one's mock, so the
 * identity checks below already held before the fix; what the fix adds is
 * the explicit registration of both, so the tripwire does not depend on that
 * resolver behaviour. The first test pins the registration list.
 *
 * Nothing here calls a launcher: the checks are by identity, so a missing
 * mock fails the test without spawning anything.
 */
import { describe, expect, it } from '@jest/globals';
import { TRIPWIRED_SPECIFIERS, installLaunchTripwire } from './support/openclaw-host-isolation.js';

const tripwire = installLaunchTripwire();
const bare = (await import('child_process')) as unknown as Record<string, unknown> & { default: Record<string, unknown> };
const prefixed = (await import('node:child_process')) as unknown as Record<string, unknown> & { default: Record<string, unknown> };

describe('#1179: the launch tripwire covers both child_process specifiers', () => {
  const names = Object.keys(tripwire.launchers) as (keyof typeof tripwire.launchers)[];

  it('mocks both specifiers explicitly', () => {
    expect([...TRIPWIRED_SPECIFIERS]).toEqual(['child_process', 'node:child_process']);
  });

  it('covers every launcher the support module lists', () => {
    expect([...names].sort()).toEqual(['exec', 'execFile', 'execFileSync', 'execSync', 'fork', 'spawn', 'spawnSync']);
  });

  it.each([
    ['child_process', bare],
    ['node:child_process', prefixed],
  ])('%s: named and default exports are the tripwire fakes', (_specifier, mod) => {
    for (const name of names) {
      expect({ name, named: mod[name] === tripwire.launchers[name] }).toEqual({ name, named: true });
      expect({ name, viaDefault: mod.default[name] === tripwire.launchers[name] }).toEqual({ name, viaDefault: true });
    }
  });

  it('the rest of the real module is kept under both specifiers', () => {
    // A non-launcher export the code under test may still need.
    expect(typeof bare.ChildProcess).toBe('function');
    expect(prefixed.ChildProcess).toBe(bare.ChildProcess);
  });
});
