/**
 * #577 round 3, blocker 1 — the reported invocation, at the real entry point.
 *
 *   shieldcortex audit --deps-path node_modules help
 *
 * printed audit's usage and exited 0, but ran the `npm ls -g` staleness preamble
 * on the way there: the whole-argv gate in `src/index.ts` counted `node_modules`
 * as the verb and answered "not a help request", while audit's own gate skipped
 * the value and found `help`. npm's update-notifier reaches the registry and
 * writes `~/.npm/_logs` from that probe, so the operator's one chance to READ
 * what a command does spawned a process and touched their HOME.
 *
 * A unit test cannot see this: the preamble is in `main()`, not in any handler.
 * So this drives the built `dist/index.js` in a child process with HOME at an
 * empty temp directory and a fake `npm` first on PATH (see
 * entry-point-harness-577.ts). No marker, nothing under HOME, usage on stdout.
 */
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import fs from 'node:fs';
import { cliEntry, makeEntryPointSandbox, type EntryPointSandbox } from './entry-point-harness-577.js';

let sandbox: EntryPointSandbox;

beforeEach(() => { sandbox = makeEntryPointSandbox('sc577-help-entry-'); });
afterEach(() => { sandbox.cleanup(); });

describe('#577 — a command-aware help request costs nothing at the entry point', () => {
  it('has the built CLI to drive', () => {
    expect(fs.existsSync(cliEntry)).toBe(true);
  });

  it('`audit --deps-path node_modules help` prints usage, spawns no npm, writes nothing under HOME', () => {
    const r = sandbox.run(['audit', '--deps-path', 'node_modules', 'help']);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('Usage: shieldcortex audit');
    expect(r.stdout).toContain('--deps-path <path>');
    expect(sandbox.npmRan()).toBe(false);
    // The audit itself never ran either: its first act is
    // initDatabase(~/.shieldcortex/memories.db), so an empty HOME is the proof.
    expect(sandbox.underHome()).toEqual([]);
  });

  it('the same shape for the other value-flag commands is equally free', () => {
    // One per registry row that has a value flag, so a future divergence in any
    // of them fails here and not only for audit.
    const cases: Array<[string[], string]> = [
      [['audit', '--deps-path', 'node_modules', 'help'], 'Usage: shieldcortex audit'],
      [['allowlist', '--glob', '/tmp/x.sh', 'help'], 'Usage: shieldcortex allowlist'],
      [['sessions', '--days', '30', 'help'], 'Usage: shieldcortex sessions'],
      [['memories', '--project', 'acme', 'help'], 'Usage: shieldcortex memories'],
      [['openclaw', '--agent', 'main', 'help'], 'Usage: shieldcortex openclaw'],
    ];
    for (const [argv, usage] of cases) {
      const r = sandbox.run(argv);
      expect({ argv, status: r.status }).toEqual({ argv, status: 0 });
      expect({ argv, usage: r.stdout.includes(usage) }).toEqual({ argv, usage: true });
      expect({ argv, npm: sandbox.npmRan() }).toEqual({ argv, npm: false });
      expect({ argv, under: sandbox.underHome() }).toEqual({ argv, under: [] });
    }
  });

  it('a bare `audit help` is still free, and `audit --deps-path help` is still a real path', () => {
    const help = sandbox.run(['audit', 'help']);
    expect(help.status).toBe(0);
    expect(help.stdout).toContain('Usage: shieldcortex audit');
    expect(sandbox.npmRan()).toBe(false);
    expect(sandbox.underHome()).toEqual([]);
  });

  it('`allowlist --note -- reviewed help`: the gate reads the argv the handler reads (-- stripped)', () => {
    // allowlist drops every bare `--` before parsing, so to the handler this is
    // `--note reviewed help` → the help verb. The global gate must agree, or the
    // npm staleness preamble runs before usage is printed (round-3 review).
    const r = sandbox.run(['allowlist', '--note', '--', 'reviewed', 'help']);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('Usage: shieldcortex allowlist');
    expect(sandbox.npmRan()).toBe(false);
    expect(sandbox.underHome()).toEqual([]);
  });
});
