import * as realFs from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

/**
 * #1105 r2 B-dir — the boot env is read through the `~/.openclaw` that was
 * checked, never one swapped in between the check and the open, and nothing
 * is read on a platform without O_NOFOLLOW / O_DIRECTORY / O_NONBLOCK.
 *
 * `fs` is replaced for the module under test only (the #339 fixed-root
 * pattern): the wrapper swaps `~/.openclaw` for a link to another private
 * directory at the exact moment the module opens the boot env, hides
 * `/proc/self/fd` to force the path-plus-recheck route, or withholds an open
 * flag. Nothing in the module knows a test is running.
 */

const seam = {
  /** Run once, immediately before the module opens `gateway.systemd.env`. */
  beforeBootEnvOpen: null as null | (() => void),
  /** Pretend this kernel has no `/proc/self/fd`. */
  noProcFd: false,
  /** Open flags to withhold from `fs.constants`. */
  withhold: [] as string[],
  /** Every path the module opened the boot env by. */
  bootEnvOpens: [] as string[],
};

const wrapped: typeof realFs = {
  ...realFs,
  openSync: ((p: realFs.PathLike, ...rest: unknown[]) => {
    if (typeof p === 'string' && p.endsWith('gateway.systemd.env')) {
      seam.bootEnvOpens.push(p);
      const run = seam.beforeBootEnvOpen;
      seam.beforeBootEnvOpen = null;
      run?.();
    }
    return (realFs.openSync as (...a: unknown[]) => number)(p, ...rest);
  }) as typeof realFs.openSync,
  statSync: ((p: realFs.PathLike, ...rest: unknown[]) => {
    if (seam.noProcFd && typeof p === 'string' && p.startsWith('/proc/self/fd/')) {
      throw Object.assign(new Error(`ENOENT: no such file or directory, stat '${p}'`), { code: 'ENOENT' });
    }
    return (realFs.statSync as (...a: unknown[]) => unknown)(p, ...rest);
  }) as typeof realFs.statSync,
};
Object.defineProperty(wrapped, 'constants', {
  enumerable: true,
  get: () => {
    const c: Record<string, number | undefined> = { ...realFs.constants };
    for (const k of seam.withhold) delete c[k];
    return c;
  },
});
jest.unstable_mockModule('fs', () => ({ ...wrapped, default: wrapped }));

const { resolveGatewayBootCredentials } = await import('../integrations/openclaw-gateway-boot-env.js');

const TOKEN = 'checked-directory-token';
const SWAPPED = 'swapped-in-directory-token';

let home: string;
let saved: Record<string, string | undefined>;
const ENV_KEYS = ['OPENCLAW_GATEWAY_TOKEN', 'OPENCLAW_GATEWAY_PASSWORD', 'NODE_DEBUG', 'NODE_DEBUG_NATIVE'];

/** A private OpenClaw state dir: local gateway, a 0600 boot env holding `token`. */
function stateDir(dir: string, token: string) {
  realFs.mkdirSync(dir, { recursive: true });
  realFs.chmodSync(dir, 0o700);
  realFs.writeFileSync(join(dir, 'openclaw.json'), JSON.stringify({ gateway: { mode: 'local' } }));
  realFs.writeFileSync(join(dir, 'gateway.systemd.env'), `OPENCLAW_GATEWAY_TOKEN=${token}\n`);
  realFs.chmodSync(join(dir, 'gateway.systemd.env'), 0o600);
}

/** Replace `~/.openclaw` with a link to another private dir the user owns, with a different token. */
function swapInLink() {
  const other = join(home, 'other-openclaw');
  stateDir(other, SWAPPED);
  realFs.renameSync(join(home, '.openclaw'), join(home, 'checked-openclaw'));
  realFs.symlinkSync(other, join(home, '.openclaw'));
}

const resolve = () => resolveGatewayBootCredentials({ home, refusedPath: 'gateway.auth.token', env: process.env });

beforeEach(() => {
  home = realFs.mkdtempSync(join(tmpdir(), 'sc-1105-fs-'));
  stateDir(join(home, '.openclaw'), TOKEN);
  seam.beforeBootEnvOpen = null;
  seam.noProcFd = false;
  seam.withhold = [];
  seam.bootEnvOpens = [];
  saved = {};
  for (const k of ENV_KEYS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
});

afterEach(() => {
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
  realFs.rmSync(home, { recursive: true, force: true });
});

const hasProcFd = realFs.existsSync('/proc/self/fd');

describe('#1105 r2 B-dir — bound to the directory that was checked', () => {
  it('control: the checked directory, unswapped, is read', () => {
    expect(resolve()).toEqual({ used: true, env: { OPENCLAW_GATEWAY_TOKEN: TOKEN }, keys: ['OPENCLAW_GATEWAY_TOKEN'] });
  });

  (hasProcFd ? it : it.skip)('where the kernel has /proc/self/fd, the boot env is opened through the directory\'s descriptor', () => {
    expect(resolve()).toMatchObject({ used: true });
    expect(seam.bootEnvOpens).toHaveLength(1);
    expect(seam.bootEnvOpens[0]).toMatch(/^\/proc\/self\/fd\/\d+\/gateway\.systemd\.env$/);
  });

  it.each([
    ['through /proc/self/fd', false],
    ['by path, re-checked after the open (no /proc/self/fd)', true],
  ])('~/.openclaw swapped for a link to another private dir between the check and the open: refused (%s)', (_label, noProcFd) => {
    seam.noProcFd = noProcFd;
    seam.beforeBootEnvOpen = swapInLink;
    const r = resolve();
    expect(seam.bootEnvOpens).toHaveLength(1);
    if (noProcFd) expect(seam.bootEnvOpens[0]).toBe(join(home, '.openclaw', 'gateway.systemd.env'));
    else if (hasProcFd) expect(seam.bootEnvOpens[0]).toMatch(/^\/proc\/self\/fd\/\d+\//);
    // The swap happened: ~/.openclaw is now a link to the other directory.
    expect(realFs.lstatSync(join(home, '.openclaw')).isSymbolicLink()).toBe(true);
    expect(r).toEqual({ used: false, reason: '~/.openclaw changed while it was being read' });
    expect(JSON.stringify(r)).not.toContain(SWAPPED);
    expect(JSON.stringify(r)).not.toContain(TOKEN);
  });

  it('control: without /proc/self/fd and no swap, the path route still reads the checked directory', () => {
    seam.noProcFd = true;
    expect(resolve()).toMatchObject({ used: true, env: { OPENCLAW_GATEWAY_TOKEN: TOKEN } });
  });
});

describe('#1105 r2 B-dir — no O_NOFOLLOW / O_DIRECTORY / O_NONBLOCK, nothing read', () => {
  it.each(['O_NOFOLLOW', 'O_DIRECTORY', 'O_NONBLOCK'])('%s missing: refused, never opened with a 0 flag', (flag) => {
    seam.withhold = [flag];
    expect(resolve()).toEqual({
      used: false,
      reason: '~/.openclaw/gateway.systemd.env cannot be opened without following links on this platform',
    });
    expect(seam.bootEnvOpens).toEqual([]);
  });
});
