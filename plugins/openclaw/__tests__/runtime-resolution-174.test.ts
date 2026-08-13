import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, realpathSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { __collectRuntimeCandidatesForTest } from '../index.js';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

/**
 * #174 — the realtime plugin could not find `cortex-memory/runtime.mjs` on a
 * host where ShieldCortex is installed under `~/.local`, so the interceptor
 * never initialised and that host silently lost the realtime surface.
 *
 * Mechanism: candidate 1 was `new URL("../../hooks/…", import.meta.url)`, added
 * with NO existsSync guard — every other candidate is screened. On an installed
 * layout the plugin lives at
 * `…/node_modules/@drakon-systems/shieldcortex-realtime/dist/index.js`, so
 * `../../` lands on the SCOPE directory and the path becomes
 * `…/node_modules/@drakon-systems/hooks/openclaw/cortex-memory/runtime.mjs`,
 * which does not exist. Being unguarded it was the ONLY entry in the list, so
 * its ERR_MODULE_NOT_FOUND became the operator-visible message — the exact
 * string the issue reports.
 *
 * The fixes pinned here:
 *   1. Ask Node (`shieldcortex/package.json` via createRequire) — works on ANY
 *      layout, including this one, and is what actually closes the report.
 *   2. Candidate 1 is now SCREENED, so an absent relative path stops polluting
 *      the list. It is kept, not deleted: in the source tree it genuinely
 *      resolves.
 *   3. `~/.local` prefixes added to the bin/global sweeps.
 *   4. `SHIELDCORTEX_RUNTIME_PATH` escape hatch, so the NEXT unusual prefix
 *      does not need a code change (this list was the only "known install
 *      roots" copy without one).
 */

const RUNTIME_REL = join('hooks', 'openclaw', 'cortex-memory', 'runtime.mjs');

/**
 * Lay down a package root that really contains the runtime file.
 *
 * `exports` mirrors the SHAPE of the real package's map — `./package.json` is
 * declared, `hooks/**` is not — because that asymmetry is precisely what the
 * fix depends on. A fixture without an `exports` field would resolve any
 * subpath and would therefore pass no matter which specifier the
 * implementation picked.
 */
function makePackage(root: string, withExports = false): string {
  mkdirSync(join(root, 'hooks', 'openclaw', 'cortex-memory'), { recursive: true });
  writeFileSync(join(root, RUNTIME_REL), 'export function createOpenClawRuntime() { return {}; }');
  writeFileSync(join(root, 'package.json'), JSON.stringify({
    name: 'shieldcortex',
    version: '0.0.0',
    main: 'index.js',
    ...(withExports ? { exports: { '.': './index.js', './package.json': './package.json' } } : {}),
  }));
  return root;
}

/** The real installed shape: plugin under its scope, package as a peer sibling. */
function makeInstalledPlugin(home: string): string {
  const dist = join(home, 'node_modules', '@drakon-systems', 'shieldcortex-realtime', 'dist');
  mkdirSync(dist, { recursive: true });
  writeFileSync(join(dist, 'index.js'), '');
  return pathToFileURL(join(dist, 'index.js')).href;
}

let home: string;
const origEnv = { ...process.env };

beforeEach(() => {
  // realpath, because on macOS tmpdir() is /var/… (a symlink to /private/var/…)
  // and Node's resolver answers with the REAL path. Without this, a candidate
  // found by peer resolution would not string-match one built from `home`.
  home = realpathSync(mkdtempSync(join(tmpdir(), 'sc-174-home-')));
  delete process.env.SHIELDCORTEX_RUNTIME_PATH;
  delete process.env.SHIELDCORTEX_CONFIG_DIR;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  process.env = { ...origEnv };
});

describe('#174 — the reported failure no longer poisons the candidate list', () => {
  it('an installed layout whose ../../ path does not exist contributes NOTHING', () => {
    // Simulate the real shape: plugin at <x>/node_modules/@drakon-systems/
    // shieldcortex-realtime/dist/index.js, with no hooks/ two levels up.
    const from = makeInstalledPlugin(home);

    const candidates = __collectRuntimeCandidatesForTest(home, from);

    // The old bug: this bogus scoped path WAS the list, and its
    // ERR_MODULE_NOT_FOUND was the message the operator saw.
    expect(candidates.some(c => c.includes(join('@drakon-systems', 'hooks')))).toBe(false);
  });

  /**
   * THE DISCRIMINATING TEST for the headline fix.
   *
   * The package sits at `<home>/node_modules/shieldcortex` — a genuine peer
   * sibling, which is the layout the reporting host actually had. No other
   * strategy can reach it: `addAncestorCandidates` only probes
   * `<ancestor>/hooks/…` for the plugin's six ancestors (dist,
   * shieldcortex-realtime, @drakon-systems, node_modules, home, home/..), and
   * the global sweep only probes hardcoded prefixes. The ONLY way this goes
   * green is if `addResolvedPeerCandidate` ran and Node's resolver answered.
   *
   * Deleting strategy 1 from `collectRuntimeCandidates` must turn this RED.
   * That property is the entire point. The version of this test that shipped
   * in the first pass laid the package under `~/.local`, where the global
   * sweep found it anyway — so the whole suite passed with the fix removed.
   */
  it("finds a peer sibling that ONLY Node's resolver can reach", () => {
    const from = makeInstalledPlugin(home);
    makePackage(join(home, 'node_modules', 'shieldcortex'), true);

    const candidates = __collectRuntimeCandidatesForTest(home, from);

    expect(candidates).toContain(
      pathToFileURL(join(home, 'node_modules', 'shieldcortex', RUNTIME_REL)).href,
    );
    // Guard against a stray resolution to a real package further up the
    // filesystem: every candidate must live inside this test's sandbox.
    expect(candidates.every(c => c.startsWith(pathToFileURL(home).href))).toBe(true);
  });

  it('the ~/.local global sweep also covers an `npm --prefix ~/.local` install', () => {
    // A SEPARATE strategy from the one above, and now named for what it tests.
    makePackage(join(home, '.local', 'lib', 'node_modules', 'shieldcortex'));

    const candidates = __collectRuntimeCandidatesForTest(home, makeInstalledPlugin(home));

    expect(candidates).toContain(
      pathToFileURL(join(home, '.local', 'lib', 'node_modules', 'shieldcortex', RUNTIME_REL)).href,
    );
  });
});

/**
 * Why the implementation resolves `shieldcortex/package.json` and not the
 * runtime file directly — and the contract that choice rests on.
 *
 * `hooks/openclaw/**` ships (it is in `files`) but is NOT in `exports`, so
 * asking Node for it throws ERR_PACKAGE_PATH_NOT_EXPORTED. `./package.json` is
 * the one subpath that is declared. If that entry is ever trimmed from the real
 * package, strategy 1 dies silently on every host and every fixture-based test
 * above still passes — which is the exact failure mode this file already had.
 */
describe('#174 — the exports contract the peer resolution rests on', () => {
  it('the runtime path is NOT resolvable directly, but package.json is', () => {
    const root = makePackage(join(home, 'node_modules', 'shieldcortex'), true);
    const req = createRequire(join(home, 'node_modules', '@drakon-systems', 'x', 'index.js'));

    expect(() => req.resolve('shieldcortex/hooks/openclaw/cortex-memory/runtime.mjs')).toThrow();
    expect(req.resolve('shieldcortex/package.json')).toBe(join(root, 'package.json'));
  });

  it('the REAL package still declares "./package.json" in exports', () => {
    const real = JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf-8'));

    expect(real.name).toBe('shieldcortex');
    expect(real.exports['./package.json']).toBe('./package.json');
    // And the runtime still ships, or there would be nothing to resolve to.
    expect(real.files).toContain('hooks/openclaw');
  });
});

describe('#174 — the escape hatch', () => {
  it('SHIELDCORTEX_RUNTIME_PATH accepts a package root', () => {
    const root = makePackage(join(home, 'weird', 'prefix', 'shieldcortex'));
    process.env.SHIELDCORTEX_RUNTIME_PATH = root;
    const candidates = __collectRuntimeCandidatesForTest(home);
    expect(candidates.some(c => c.includes(join('weird', 'prefix')))).toBe(true);
  });

  it('SHIELDCORTEX_RUNTIME_PATH accepts the runtime.mjs itself', () => {
    const root = makePackage(join(home, 'direct'));
    process.env.SHIELDCORTEX_RUNTIME_PATH = join(root, RUNTIME_REL);
    const candidates = __collectRuntimeCandidatesForTest(home);
    expect(candidates[0]).toBe(pathToFileURL(join(root, RUNTIME_REL)).href);
  });

  it('a bogus override is screened, not blindly trusted', () => {
    process.env.SHIELDCORTEX_RUNTIME_PATH = join(home, 'does', 'not', 'exist');
    const candidates = __collectRuntimeCandidatesForTest(home);
    expect(candidates.some(c => c.includes('does/not/exist'))).toBe(false);
  });
});

describe('#174 — config override honours SHIELDCORTEX_CONFIG_DIR', () => {
  it('reads installRoot from the relocated config dir, not a hardcoded ~/.shieldcortex', () => {
    // Reading homedir() directly made this strategy permanently blind on a host
    // that relocates its config — the same isolation hole the rest of the
    // product already closed.
    const pkg = makePackage(join(home, 'pkg'));
    const cfgDir = join(home, 'relocated-config');
    mkdirSync(cfgDir, { recursive: true });
    writeFileSync(join(cfgDir, 'config.json'), JSON.stringify({ installRoot: pkg }));
    process.env.SHIELDCORTEX_CONFIG_DIR = cfgDir;

    const candidates = __collectRuntimeCandidatesForTest(home);
    expect(candidates.some(c => c.includes(join('pkg', 'hooks')))).toBe(true);
  });
});

describe('#174 — every candidate is screened', () => {
  it('returns an empty list when nothing exists anywhere', () => {
    // Which is what makes the "none found" error message (naming the escape
    // hatch) reachable instead of `Tried: . Last error: unknown error`.
    const nm = join(home, 'node_modules', '@drakon-systems', 'shieldcortex-realtime', 'dist');
    mkdirSync(nm, { recursive: true });
    const candidates = __collectRuntimeCandidatesForTest(home, pathToFileURL(join(nm, 'index.js')).href);
    expect(candidates).toEqual([]);
  });

  it('every returned candidate is a file: URL ending in runtime.mjs', () => {
    makePackage(join(home, '.local', 'lib', 'node_modules', 'shieldcortex'));
    for (const c of __collectRuntimeCandidatesForTest(home)) {
      expect(c.startsWith('file://')).toBe(true);
      expect(c.endsWith('runtime.mjs')).toBe(true);
    }
  });
});
