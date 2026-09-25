/**
 * #573 blocker 8 — `logs` costs nothing until it has been asked something valid.
 *
 * `logs` joined #577's help detection but not its strict preflight, so its
 * arguments were only checked inside the handler — after `main()`'s
 * `checkVersionStaleness()` had already shelled out to `npm ls -g` and let
 * npm's update-notifier write `~/.npm/_logs`. Measured by the reviewer against
 * the built CLI with a fresh isolated home:
 *
 *   - `logs prune --execute --exectue` exited 1 without pruning, but left an
 *     npm debug log and update-notifier state behind;
 *   - `logs prune` — a DRY RUN, which promises to change nothing — did the
 *     same;
 *   - `update --bogus` exited 2 with no files created, which is the
 *     convention `logs` was supposed to be following.
 *
 * Two fixes, tested here. `logs` is registered in the shared strict preflight,
 * so a bad argument is rejected before any subprocess. And the `logs` dispatch
 * now sits AHEAD of the staleness preamble and the stats banner in `main()`,
 * for the same reason `hook` does: this is the command an operator reaches for
 * when the disk budget is full, and spending bytes of their HOME on an npm
 * registry probe is precisely backwards.
 *
 * The harness is #577's own: HOME at an empty temp directory, every inherited
 * SHIELDCORTEX_* variable dropped, and a fake `npm` first on PATH that leaves a
 * marker OUTSIDE home if it is ever run — so "npm never ran" and "HOME is
 * untouched" stay independent assertions.
 */
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import fs from 'node:fs';
import path from 'node:path';
import { makeEntryPointSandbox, type EntryPointSandbox } from './entry-point-harness-577.js';

let sandbox: EntryPointSandbox;
const runCli = (args: string[]) => sandbox.run(args);

beforeEach(() => { sandbox = makeEntryPointSandbox('sc573-logs-entry-'); });
afterEach(() => { sandbox.cleanup(); });

describe('#573 blocker 8 — a rejected `logs` argument costs nothing', () => {
  it('`logs prune --execute --exectue` exits 2 and leaves HOME byte-identical', () => {
    const r = runCli(['logs', 'prune', '--execute', '--exectue']);

    // The `update --bogus` convention, exactly: exit 2, usage on stderr.
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('Unknown argument: --exectue');
    expect(r.stderr).toContain('Usage: shieldcortex logs');
    expect(r.stdout).toBe('');
    // No npm debug log, no update-notifier state, nothing at all.
    expect(sandbox.npmRan()).toBe(false);
    expect(sandbox.underHome()).toEqual([]);
  });

  it('`logs` with no subcommand is the same usage error, just as cheaply', () => {
    const r = runCli(['logs']);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('Usage: shieldcortex logs');
    expect(sandbox.npmRan()).toBe(false);
    expect(sandbox.underHome()).toEqual([]);
  });

  it('`logs prune --execute --help` prints usage and changes nothing', () => {
    const r = runCli(['logs', 'prune', '--execute', '--help']);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('Usage: shieldcortex logs');
    expect(r.stdout).not.toContain('[DRY RUN]');
    expect(sandbox.npmRan()).toBe(false);
    expect(sandbox.underHome()).toEqual([]);
  });
});

describe('#573 blocker 8 — a dry run does not spawn the mutating preamble', () => {
  it('`logs prune` writes nothing under HOME and runs no subprocess', () => {
    // A preview that promises to change nothing must actually change nothing.
    // There is no ~/.shieldcortex/logs in this home, so the pass finds no
    // plane and reports it — and that is the whole of what it does.
    const r = runCli(['logs', 'prune']);

    expect(r.status).toBe(0);
    expect(r.stdout).toContain('[DRY RUN]');
    expect(sandbox.npmRan()).toBe(false);
    expect(sandbox.underHome()).toEqual([]);
  });

  it('`logs prune --execute` touches only the logs directory it was pointed at', () => {
    // Seed 25 records for one database plus an audit file, then prune for real:
    // the only change under HOME is inside ~/.shieldcortex/logs.
    const logs = path.join(sandbox.home, '.shieldcortex', 'logs');
    const audit = path.join(sandbox.home, '.shieldcortex', 'audit');
    fs.mkdirSync(logs, { recursive: true });
    fs.mkdirSync(audit, { recursive: true });
    fs.writeFileSync(path.join(audit, 'realtime-2026-01-01.jsonl'), '{"e":1}\n');
    const auditBefore = fs.readFileSync(path.join(audit, 'realtime-2026-01-01.jsonl'));
    for (let i = 0; i < 25; i++) {
      const p = path.join(logs, `project-key-repair-2026-01-01T00-00-${String(i).padStart(2, '0')}-000Z.json`);
      fs.writeFileSync(p, '{}');
      const when = new Date(1_700_000_000_000 + i * 1000);
      fs.utimesSync(p, when, when);
    }

    const r = runCli(['logs', 'prune', '--execute']);

    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/Deleted: 5\b/);
    expect(fs.readdirSync(logs)).toHaveLength(20);
    expect(sandbox.npmRan()).toBe(false);
    // The realtime audit plane is byte-for-byte what it was (#579 owns it).
    expect(fs.readdirSync(audit)).toEqual(['realtime-2026-01-01.jsonl']);
    expect(fs.readFileSync(path.join(audit, 'realtime-2026-01-01.jsonl'))).toEqual(auditBefore);
    // And nothing outside ~/.shieldcortex was created — no ~/.npm, no
    // update-notifier state, no config file written on the way past.
    expect(sandbox.underHome().filter((p) => !p.startsWith('.shieldcortex'))).toEqual([]);
  });
});

/**
 * The preflight registration itself, unit-tested.
 *
 * The entry-point assertions above cannot see it: `logs` is dispatched ahead of
 * the staleness preamble now, so removing it from `STRICT_COMMANDS` leaves
 * every one of them green — the handler's own gate reaches the same verdict a
 * few lines later and nothing spawns npm either way. That redundancy is the
 * point (the registration is the backstop if the dispatch ever moves back
 * down), but a backstop nothing tests is a backstop that rots. So this asks
 * the preflight directly.
 */
describe('#573 blocker 8 — `logs` is registered in the shared strict preflight', () => {
  const said: string[] = [];
  const deps = {
    log: (m: string) => { said.push(m); },
    error: (m: string) => { said.push(m); },
  };
  beforeEach(() => { said.length = 0; });

  it('rejects an unknown argument with exit 2 and usage', async () => {
    const { preflightStrictArgs } = await import('../strict-args-preflight.js');
    expect(await preflightStrictArgs(['logs', 'prune', '--execute', '--exectue'], deps)).toBe(2);
    expect(said.join('\n')).toContain('Unknown argument: --exectue');
    expect(said.join('\n')).toContain('Usage: shieldcortex logs');
  });

  it('answers a help request with exit 0 and usage', async () => {
    const { preflightStrictArgs } = await import('../strict-args-preflight.js');
    expect(await preflightStrictArgs(['logs', 'prune', '--help'], deps)).toBe(0);
    expect(said.join('\n')).toContain('Usage: shieldcortex logs');
  });

  it('lets a valid command line through to the dispatcher', async () => {
    const { preflightStrictArgs } = await import('../strict-args-preflight.js');
    for (const argv of [['logs', 'prune'], ['logs', 'prune', '--execute']]) {
      expect(await preflightStrictArgs(argv, deps)).toBeNull();
    }
    expect(said).toEqual([]);
  });

  it('rejects a command line whose SHAPE is wrong, not just its vocabulary', async () => {
    // Round-2 blocker 5. Both of these are made entirely of tokens the
    // allow-list knows, and both used to reach the handler — `logs prune prune
    // --execute` deleted records and exited 0. The preflight is where that has
    // to be caught: it is what runs before `main()` spawns anything.
    const { preflightStrictArgs } = await import('../strict-args-preflight.js');
    expect(await preflightStrictArgs(['logs', 'prune', 'prune', '--execute'], deps)).toBe(2);
    expect(said.join('\n')).toContain('takes at most --execute');
    said.length = 0;
    expect(await preflightStrictArgs(['logs'], deps)).toBe(2);
    expect(said.join('\n')).toContain('Usage: shieldcortex logs');
  });
});
