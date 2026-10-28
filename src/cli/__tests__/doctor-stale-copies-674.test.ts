import { execFileSync } from 'node:child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { checkStaleShieldCortexCopies, scanStaleShieldCortexCopies } from '../doctor.js';

/**
 * #674 part 2 — a ShieldCortex copy at 5.2.1 or older that opens the shared
 * database runs a start-up `project` backfill that does not skip chained audit
 * rows. The doctor row reads each copy's package.json from the fixed install
 * roots and warns; it never runs a copy and never writes.
 *
 * Every case builds a throwaway home (realpath'd, so macOS /var → /private/var
 * symlinks cannot change the displayed paths) and passes it explicitly. The
 * absolute global prefixes (/usr/lib/node_modules, …) are replaced by fixture
 * dirs through `systemPackageDirs`, so the real host is never read.
 */
let home: string;
let sys: string;

beforeEach(() => {
  home = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-stale-copies-home-')));
  sys = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-stale-copies-sys-')));
});

afterEach(() => {
  for (const dir of [home, sys]) {
    // Restore modes a permission case may have removed, then clean up.
    try { fs.chmodSync(path.join(dir, '.npm', '_npx'), 0o755); } catch { /* not created */ }
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

/** Write a package dir with the given package.json contents (null = none). */
function makeCopy(dir: string, pkgJson: Record<string, unknown> | string | null): string {
  fs.mkdirSync(dir, { recursive: true });
  if (pkgJson !== null) {
    fs.writeFileSync(
      path.join(dir, 'package.json'),
      typeof pkgJson === 'string' ? pkgJson : JSON.stringify(pkgJson),
    );
  }
  return dir;
}

const sc = (version: string) => ({ name: 'shieldcortex', version });
const npxCopy = (hash: string) => path.join(home, '.npm', '_npx', hash, 'node_modules', 'shieldcortex');
const run = () => checkStaleShieldCortexCopies(home, { systemPackageDirs: [path.join(sys, 'shieldcortex')] });

/** Every path under `root` with its size and mtime — a write anywhere changes it. */
function snapshot(root: string): string[] {
  const out: string[] = [];
  const walk = (dir: string) => {
    for (const name of fs.readdirSync(dir).sort()) {
      const p = path.join(dir, name);
      const st = fs.lstatSync(p);
      out.push(`${path.relative(root, p)} ${st.mode} ${st.size} ${st.mtimeMs}`);
      if (st.isDirectory()) walk(p);
    }
  };
  walk(root);
  return out;
}

describe('checkStaleShieldCortexCopies (#674)', () => {
  it('passes quietly when no copy exists in any install root', async () => {
    const r = await run();
    expect(r.status).toBe('pass');
    expect(r.message).toMatch(/no ShieldCortex copies in the checked install roots/);
    expect(r.fix).toBeUndefined();
  });

  it('warns on a 5.2.1 copy in the npx cache, naming the home-relative path, version and remedy', async () => {
    makeCopy(npxCopy('abc123'), sc('5.2.1'));
    const r = await run();
    expect(r.status).toBe('warn');
    expect(r.message).toContain('~/.npm/_npx/abc123/node_modules/shieldcortex (v5.2.1 ≤ 5.2.1)');
    expect(r.message).toMatch(/chained audit rows/);
    expect(r.message).toMatch(/ledger verify/);
    expect(r.message).not.toMatch(/Action Guard/i);
    expect(r.fix).toContain('rm -rf ~/.npm/_npx/abc123');
  });

  it('finds stale copies in global, nvm and OpenClaw roots too', async () => {
    makeCopy(path.join(sys, 'shieldcortex'), sc('4.5.0'));
    makeCopy(path.join(home, '.npm-global', 'lib', 'node_modules', 'shieldcortex'), sc('5.0.0'));
    makeCopy(path.join(home, '.nvm', 'versions', 'node', 'v20.1.0', 'lib', 'node_modules', 'shieldcortex'), sc('4.44.0'));
    makeCopy(path.join(home, '.openclaw', 'npm', 'node_modules', 'shieldcortex'), sc('5.1.0'));
    makeCopy(path.join(home, '.openclaw', 'npm', 'projects', 'shieldcortex-realtime-x', 'node_modules', 'shieldcortex'), sc('5.2.0'));
    const scan = scanStaleShieldCortexCopies(home, { systemPackageDirs: [path.join(sys, 'shieldcortex')] });
    expect(scan.copies.map((c) => c.state)).toEqual(['stale', 'stale', 'stale', 'stale', 'stale']);
    const r = await run();
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/^5 ShieldCortex copy/);
    expect(r.fix).toContain('npm install -g shieldcortex@latest');
    expect(r.fix).toContain('~/.openclaw/npm/node_modules/shieldcortex: remove it');
  });

  it.each(['5.3.0', '5.2.2', '5.2.2-beta.1', '6.0.0'])('does not warn on a %s copy', async (version) => {
    makeCopy(npxCopy('newer'), sc(version));
    const r = await run();
    expect(r.status).toBe('pass');
    expect(r.message).toMatch(/1 ShieldCortex copy\(ies\) found in the checked install roots, all newer than 5\.2\.1/);
  });

  it.each(['5.2.1-beta.1', '5.2.1-rc.0', '5.2.0'])('treats %s as stale (≤ 5.2.1 by semver)', async (version) => {
    makeCopy(npxCopy('pre'), sc(version));
    const r = await run();
    expect(r.status).toBe('warn');
    expect(r.message).toContain(`(v${version} ≤ 5.2.1)`);
  });

  it.each<[string, Record<string, unknown> | string | null, RegExp]>([
    ['missing package.json', null, /no package\.json/],
    ['invalid JSON', '{ not json', /not valid JSON/],
    ['no version field', { name: 'shieldcortex' }, /no valid semver version/],
    ['non-semver version', sc('latest'), /no valid semver version/],
  ])('reports %s as version unknown, never stale', async (_label, pkgJson, reason) => {
    makeCopy(npxCopy('odd'), pkgJson);
    const r = await run();
    expect(r.status).toBe('info');
    expect(r.message).toMatch(/version unknown: ~\/\.npm\/_npx\/odd\/node_modules\/shieldcortex/);
    expect(r.message).toMatch(reason);
    expect(r.message).not.toMatch(/≤ 5\.2\.1/);
  });

  it('reports an unreadable package.json (a directory) as version unknown', async () => {
    const dir = makeCopy(npxCopy('dirpkg'), null);
    fs.mkdirSync(path.join(dir, 'package.json'));
    const r = await run();
    expect(r.status).toBe('info');
    // POSIX opens the directory and rejects it by type; Windows fails the open.
    expect(r.message).toMatch(/package\.json (is not a regular file|unreadable \(EISDIR\))/);
  });

  // #905 — a named pipe with no writer must not block the scan.
  (process.platform === 'win32' ? it.skip : it)('reports a FIFO package.json as not a regular file instead of waiting on it (POSIX only: mkfifo)', async () => {
    const dir = makeCopy(npxCopy('fifo'), null);
    execFileSync('mkfifo', [path.join(dir, 'package.json')]);
    const scan = scanStaleShieldCortexCopies(home, { systemPackageDirs: [path.join(sys, 'shieldcortex')] });
    expect(scan.copies).toEqual([
      { dir, kind: 'npx', state: 'unknown', reason: 'package.json is not a regular file' },
    ]);
    const r = await run();
    expect(r.status).toBe('info');
    expect(r.message).toMatch(/version unknown: ~\/\.npm\/_npx\/fifo\/node_modules\/shieldcortex \(package\.json is not a regular file\)/);
  });

  it('reports a package.json larger than 64 KiB as version unknown without parsing it', async () => {
    const dir = makeCopy(npxCopy('big'), JSON.stringify({ ...sc('5.2.1'), pad: 'x'.repeat(64 * 1024) }));
    const scan = scanStaleShieldCortexCopies(home, { systemPackageDirs: [path.join(sys, 'shieldcortex')] });
    expect(scan.copies).toEqual([
      { dir, kind: 'npx', state: 'unknown', reason: 'package.json is larger than 64 KiB' },
    ]);
  });

  it('still reads a regular package.json at the 64 KiB limit', async () => {
    const base = JSON.stringify({ ...sc('5.2.1'), pad: '' });
    const body = JSON.stringify({ ...sc('5.2.1'), pad: 'x'.repeat(64 * 1024 - base.length) });
    expect(Buffer.byteLength(body)).toBe(64 * 1024);
    const dir = makeCopy(npxCopy('edge'), body);
    const scan = scanStaleShieldCortexCopies(home, { systemPackageDirs: [path.join(sys, 'shieldcortex')] });
    expect(scan.copies).toEqual([{ dir, kind: 'npx', state: 'stale', version: '5.2.1' }]);
  });

  it('still warns on a stale copy when another copy is version unknown', async () => {
    makeCopy(npxCopy('a'), sc('5.2.1'));
    makeCopy(npxCopy('b'), null);
    const r = await run();
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/^1 ShieldCortex copy/);
    expect(r.message).toMatch(/version unknown: ~\/\.npm\/_npx\/b/);
  });

  it('ignores a directory named shieldcortex that declares a different package', async () => {
    makeCopy(npxCopy('other'), { name: 'not-shieldcortex', version: '1.0.0' });
    const r = await run();
    expect(r.status).toBe('pass');
    expect(r.message).toMatch(/no ShieldCortex copies in the checked install roots/);
  });

  it('counts one copy reached through a symlink once', async () => {
    const real = makeCopy(path.join(sys, 'shieldcortex'), sc('5.2.1'));
    fs.mkdirSync(path.join(home, '.npm-global', 'lib', 'node_modules'), { recursive: true });
    fs.symlinkSync(real, path.join(home, '.npm-global', 'lib', 'node_modules', 'shieldcortex'));
    const r = await run();
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/^1 ShieldCortex copy/);
  });

  const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
  (isRoot ? it.skip : it)('says "could not inspect" for an unlistable root instead of crashing', async () => {
    const npx = path.join(home, '.npm', '_npx');
    fs.mkdirSync(npx, { recursive: true });
    fs.chmodSync(npx, 0o000);
    const r = await run();
    expect(r.status).toBe('info');
    expect(r.message).toMatch(/could not inspect: ~\/\.npm\/_npx \(EACCES\)/);
    expect(r.fix).toMatch(/permission to list/);
  });

  it('writes nothing to the scanned home or the system roots', async () => {
    makeCopy(npxCopy('abc'), sc('5.2.1'));
    makeCopy(npxCopy('def'), null);
    makeCopy(path.join(sys, 'shieldcortex'), sc('5.3.0'));
    makeCopy(path.join(home, '.openclaw', 'extensions', 'shieldcortex-realtime', 'node_modules', 'shieldcortex'), sc('4.0.0'));
    const before = [snapshot(home), snapshot(sys)];
    const r = await run();
    expect(r.status).toBe('warn');
    expect([snapshot(home), snapshot(sys)]).toEqual(before);
  });
});
