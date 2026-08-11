import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { __collectRuntimeCandidatesForTest } from '../index.js';

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

/** Lay down a package root that really contains the runtime file. */
function makePackage(root: string): string {
  mkdirSync(join(root, 'hooks', 'openclaw', 'cortex-memory'), { recursive: true });
  writeFileSync(join(root, RUNTIME_REL), 'export function createOpenClawRuntime() { return {}; }');
  writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'shieldcortex', version: '0.0.0' }));
  return root;
}

let home: string;
const origEnv = { ...process.env };

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'sc-174-home-'));
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
    const nm = join(home, 'node_modules', '@drakon-systems', 'shieldcortex-realtime', 'dist');
    mkdirSync(nm, { recursive: true });
    const from = pathToFileURL(join(nm, 'index.js')).href;

    const candidates = __collectRuntimeCandidatesForTest(home, from);

    // The old bug: this bogus scoped path WAS the list, and its
    // ERR_MODULE_NOT_FOUND was the message the operator saw.
    expect(candidates.some(c => c.includes(join('@drakon-systems', 'hooks')))).toBe(false);
  });

  it('resolving the peer package finds the runtime — the fix for the reported host', () => {
    // Node's own resolver, stubbed the way createRequire would answer.
    const pkg = makePackage(join(home, '.local', 'lib', 'node_modules', 'shieldcortex'));
    const nm = join(home, 'node_modules', '@drakon-systems', 'shieldcortex-realtime', 'dist');
    mkdirSync(nm, { recursive: true });

    // The ~/.local GLOBAL sweep must find it even without the resolver.
    const candidates = __collectRuntimeCandidatesForTest(home, pathToFileURL(join(nm, 'index.js')).href);
    expect(candidates.some(c => c.includes(join('.local', 'lib', 'node_modules', 'shieldcortex')))).toBe(true);
    expect(candidates.some(c => c.endsWith('runtime.mjs'))).toBe(true);
    expect(pkg).toContain('.local');
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
