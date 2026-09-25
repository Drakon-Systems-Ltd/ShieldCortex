/**
 * #577 (round-2 nit) — an invalid argument must cost NOTHING, end to end.
 *
 * Round 1 gated `update` inside `handleUpdateCommand`, which is correct but
 * late: `main()` opens with `checkVersionStaleness()`, which shells out to
 * `npm ls -g`. npm's own update-notifier then reaches the registry and writes
 * `~/.npm/_logs` — so `shieldcortex update --bogus` spawned a child process and
 * left files under the operator's HOME on its way to exit 2. The handler-level
 * test could not see that, because the preamble is not in the handler.
 *
 * So this drives the real entry point: the BUILT `dist/index.js`, in a child
 * process, with HOME at an empty temp directory and a fake `npm` first on PATH
 * that leaves a marker if it is ever executed. The assertions are the whole
 * claim — exit 2, no marker, and not one byte written under HOME.
 */
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import fs from 'node:fs';
import { cliEntry, makeEntryPointSandbox, type EntryPointSandbox } from './entry-point-harness-577.js';

let sandbox: EntryPointSandbox;
const runCli = (args: string[]) => sandbox.run(args);
const walk = () => sandbox.underHome();

beforeEach(() => { sandbox = makeEntryPointSandbox(); });
afterEach(() => { sandbox.cleanup(); });

describe('#577 — `shieldcortex update --bogus` at the real entry point', () => {
  it('has the built CLI to drive', () => {
    expect(fs.existsSync(cliEntry)).toBe(true);
  });

  it('exits 2, spawns no npm, and writes nothing under HOME', () => {
    const r = runCli(['update', '--bogus']);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('Unknown argument: --bogus');
    expect(r.stderr).toContain('Usage: shieldcortex update');
    expect(r.stdout).toBe('');
    expect(sandbox.npmRan()).toBe(false);
    expect(walk()).toEqual([]);
  });

  it('`update --help` is free too — exit 0, usage on stdout, HOME untouched', () => {
    const r = runCli(['update', '--help']);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('Usage: shieldcortex update');
    expect(r.stdout).toContain('--allow-conversation-access');
    expect(sandbox.npmRan()).toBe(false);
    expect(walk()).toEqual([]);
  });

  it('`update --allow-conversation-access --help` prints usage, not an argument error', () => {
    const r = runCli(['update', '--allow-conversation-access', '--help']);
    expect(r.status).toBe(0);
    expect(r.stderr).toBe('');
    expect(r.stdout).toContain('Usage: shieldcortex update');
    expect(walk()).toEqual([]);
  });

  it('the other strict commands reject a bad argument just as cheaply', () => {
    for (const cmd of ['repair', 'migrate', 'uninstall', 'vacuum']) {
      const r = runCli([cmd, '--bogus']);
      expect({ cmd, status: r.status }).toEqual({ cmd, status: 2 });
      expect(r.stderr).toContain('Unknown argument: --bogus');
      expect(sandbox.npmRan()).toBe(false);
      expect({ cmd, under: walk() }).toEqual({ cmd, under: [] });
    }
  });
});
