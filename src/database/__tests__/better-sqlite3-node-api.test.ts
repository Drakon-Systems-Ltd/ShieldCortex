/**
 * Regression guard for the Node 24 worker crash-loop.
 *
 * better-sqlite3 <= 12 subclassed the RAW `node::ObjectWrap` from
 * `node_object_wrap.h`. Node 24 changed that header: the constructor now calls
 * `AddEnvironmentCleanupHook` and the destructor calls
 *
 *     RemoveEnvironmentCleanupHook(v8::Isolate::GetCurrent(), CleanupHook, this)
 *
 * and `node::RemoveEnvironmentCleanupHook` does `CHECK_NOT_NULL(env)`. A
 * `Statement` is destroyed from a V8 GC weak callback, where there may be no
 * current Environment — so a garbage-collected prepared statement aborts the
 * whole process:
 *
 *     Assertion failed: (env) != nullptr
 *     node::RemoveEnvironmentCleanupHook <- Statement::~Statement()
 *
 * That crash-looped `shieldcortex --mode worker` on a Node 24 host, ~10s in,
 * the moment BrainWorker's predictive consolidation churned prepared
 * statements. better-sqlite3 13 fixed it by moving to Node-API
 * (`Napi::ObjectWrap`), which touches no `node::` C++ symbol at all.
 *
 * Nothing in ShieldCortex's JS can prevent this — `db.close()` does not destroy
 * the C++ wrapper, GC does. So the dependency floor IS the fix, and this test
 * is what holds it: a resolution back to 12.x would reintroduce a crash that
 * only shows up on a Node 24 host under GC pressure.
 *
 * Two known-false-green traps this test closes:
 *
 * 1. `better-sqlite3/lib/binding` is NOT in the package's `exports` map (only
 *    `.`, the per-platform loader shims, and `./package.json` are), so
 *    `require('better-sqlite3/lib/binding')` throws ERR_PACKAGE_PATH_NOT_EXPORTED
 *    under Node's package-exports enforcement, the `catch` swallowed it, and
 *    the byte-scan below silently skipped itself on every real install —
 *    always exiting via the "no binding on disk" early return. The floor
 *    version assertions still held, but the actual Node-API/ObjectWrap-symbol
 *    check never ran. Fixed by resolving the package root via
 *    `require.resolve('better-sqlite3/package.json')` (which IS exported) and
 *    reading `lib/binding.js` as an absolute filesystem path — never as a bare
 *    deep-import specifier subject to the exports map.
 * 2. A prepared statement that is merely constructed and immediately dropped
 *    may never actually run its GC weak-callback destructor path inside a
 *    single Jest process. The original abort only reproduces under real
 *    memory pressure (`--expose-gc` + a forced collection) in a *separate*
 *    process, because the crash is a process abort (SIGABRT), not a
 *    catchable JS exception — if it happened in the Jest worker itself it
 *    would take the whole suite down uninformatively. This file spawns a
 *    bounded, argv-only (no shell) child process under the *current* Node
 *    binary with `--expose-gc`, which prepares many statements, forces a
 *    collection, and must print a positive sentinel to prove it ran the real
 *    code path (not just failed to start).
 */
import { describe, it, expect } from '@jest/globals';
import { readFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const require = createRequire(import.meta.url);
const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

function major(version: string): number {
  return Number(version.split('.')[0]);
}

/**
 * Resolve the better-sqlite3 package root the same way Node's module
 * resolver does — through the package's own `exports` map, via the one
 * subpath it actually publishes (`./package.json`) — rather than assuming a
 * `node_modules/better-sqlite3` layout that npm workspaces/hoisting can
 * change out from under a hardcoded relative path.
 */
function resolvePackageRoot(): string {
  const pkgJsonPath = require.resolve('better-sqlite3/package.json');
  return dirname(pkgJsonPath);
}

/**
 * Resolve the absolute path to the shipped `lib/binding.js` resolver module.
 * This is deliberately NOT `require('better-sqlite3/lib/binding')`: that bare
 * specifier is not present in the package's `exports` map, so under Node's
 * package-exports enforcement it throws ERR_PACKAGE_PATH_NOT_EXPORTED — which
 * a naive try/catch silently swallows, making the whole downstream check a
 * no-op that always looks green. Loading it as an absolute filesystem path
 * bypasses the exports map entirely (Node only enforces exports for
 * specifier-based resolution) and fails loudly if the file is truly missing.
 */
function resolveBindingModulePath(pkgRoot: string): string {
  const bindingJs = join(pkgRoot, 'lib', 'binding.js');
  if (!existsSync(bindingJs)) {
    throw new Error(
      `better-sqlite3 lib/binding.js not found at ${bindingJs} — cannot verify the ` +
        'Node-API regression guard. This must fail closed, not skip, because a ' +
        'missing resolver is itself evidence the installed package is not what ' +
        'this guard expects.',
    );
  }
  return bindingJs;
}

describe('better-sqlite3 must be Node-API based (Node 24 worker crash-loop)', () => {
  it('admits Node 22.14+ LTS and 24+, but excludes pre-Node-API-10 runtimes', () => {
    const semver = require('semver') as typeof import('semver');
    const rootPkg = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf-8'));
    const pluginPkg = JSON.parse(
      readFileSync(join(repoRoot, 'plugins', 'openclaw', 'package.json'), 'utf-8'),
    );
    const range: string = rootPkg.engines.node;

    expect(pluginPkg.engines.node).toBe(range);
    expect(semver.satisfies('22.14.0', range)).toBe(true);
    expect(semver.satisfies('22.99.0', range)).toBe(true);
    expect(semver.satisfies('24.0.0', range)).toBe(true);
    expect(semver.satisfies('26.1.0', range)).toBe(true);
    expect(semver.satisfies('22.13.1', range)).toBe(false);
    expect(semver.satisfies('23.5.0', range)).toBe(false);
  });

  it('declares a >=13 floor in package.json (whole range excludes <13)', () => {
    const semver = require('semver') as typeof import('semver');
    const pkg = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf-8'));
    const range: string = pkg.dependencies['better-sqlite3'];

    // Validate the WHOLE declared range, not just its textual floor: a range
    // string can be crafted (e.g. via a caret on a 0.x, an OR-range, or a
    // loose `*`) whose printed "floor" looks >=13 while the range still
    // matches a 12.x or earlier version. `semver.subset` proves the declared
    // range is entirely contained within ">=13.0.0", i.e. it truly cannot
    // resolve anything below 13.
    expect(semver.validRange(range)).not.toBeNull();
    expect(semver.subset(range, '>=13.0.0')).toBe(true);
    expect(semver.intersects(range, '<13.0.0')).toBe(false);
  });

  it('has an installed version >=13', () => {
    const pkgRoot = resolvePackageRoot();
    const installed: string = JSON.parse(
      readFileSync(join(pkgRoot, 'package.json'), 'utf-8'),
    ).version;
    expect(major(installed)).toBeGreaterThanOrEqual(13);
  });

  it('resolves a native binding that links no node::ObjectWrap cleanup hooks', () => {
    const pkgRoot = resolvePackageRoot();
    const bindingModulePath = resolveBindingModulePath(pkgRoot);

    // Absolute-path require — never a bare `better-sqlite3/lib/binding`
    // specifier, which is not in the package's exports map and throws
    // ERR_PACKAGE_PATH_NOT_EXPORTED under Node's exports enforcement.
    const { getPrebuildPath } = require(bindingModulePath) as {
      getPrebuildPath(): string | null;
    };

    // Same order `getBinding()` uses: the shipped prebuilt first, then Debug,
    // then Release. Inspecting Release before Debug would check a binary the
    // runtime does not load when both source-build outputs exist.
    const candidates = [
      getPrebuildPath(),
      join(pkgRoot, 'build', 'Debug', 'better_sqlite3.node'),
      join(pkgRoot, 'build', 'Release', 'better_sqlite3.node'),
    ];
    const bindingPath = candidates.find((p): p is string => typeof p === 'string' && existsSync(p));

    // Fail closed: an installed package with no loadable binding at all is
    // exactly the silent-no-op failure mode this guard exists to catch, not
    // a reason to skip the assertion.
    if (!bindingPath) {
      throw new Error(
        `No better-sqlite3 native binding found under ${pkgRoot} ` +
          '(checked getPrebuildPath(), build/Debug and build/Release). ' +
          'A dependency-less checkout must not silently pass this guard — run ' +
          '`npm install` before testing.',
      );
    }

    // Dynamic symbol names live as plain ASCII in the binary on every platform
    // we ship, so this needs no nm/objdump and works on Linux, macOS and Windows.
    const bytes = readFileSync(bindingPath).toString('latin1');
    expect(bytes).not.toContain('RemoveEnvironmentCleanupHook');
    expect(bytes).not.toContain('AddEnvironmentCleanupHook');
    // Positive control: it really is a Node-API addon, not just a stripped one.
    expect(bytes).toContain('napi_');
  });

  it('mirrors better-sqlite3 13 loader precedence for source-build fallbacks', () => {
    const pkgRoot = resolvePackageRoot();
    const source = readFileSync(resolveBindingModulePath(pkgRoot), 'utf-8');
    const debugAt = source.indexOf("'build', 'Debug', 'better_sqlite3.node'");
    const releaseAt = source.indexOf("'build', 'Release', 'better_sqlite3.node'");
    expect(debugAt).toBeGreaterThanOrEqual(0);
    expect(releaseAt).toBeGreaterThan(debugAt);
  });

  it(
    'survives GC of many prepared statements under --expose-gc in a fresh process ' +
      '(the actual Node 24 crash path)',
    () => {
      // The original abort is a process-level SIGABRT triggered from inside a
      // V8 GC weak callback — it cannot be caught as a JS exception, and
      // reproducing it reliably needs real memory pressure plus a forced
      // collection. Both require a separate process: running this inline in
      // the Jest worker would either not trigger it deterministically, or
      // would take the whole test worker down without a clear failure
      // message if it did.
      //
      // Spawned with execFileSync (argv array, no shell) against the CURRENT
      // node binary (`process.execPath`), so this runs under whatever Node
      // version the test itself is running under — matching the CI matrix
      // leg (22.14.0 floor, 24) rather than a hardcoded interpreter path.
      const pkgRoot = resolvePackageRoot();
      const script = `
        const Database = require(${JSON.stringify(pkgRoot)});
        const db = new Database(':memory:');
        db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)');
        const ITER = 20000;
        for (let i = 0; i < ITER; i++) {
          const stmt = db.prepare('INSERT INTO t (v) VALUES (?)');
          stmt.run('row-' + i);
          // Drop the reference immediately so the statement is only
          // reachable via better-sqlite3's internal bookkeeping and becomes
          // GC-collectible, matching the real BrainWorker churn pattern.
        }
        if (typeof global.gc !== 'function') {
          throw new Error('global.gc unavailable — subprocess must run with --expose-gc');
        }
        global.gc();
        global.gc();
        db.close();
        // Positive sentinel: proves this code path actually executed and the
        // process did not silently abort before reaching here.
        process.stdout.write('BETTER_SQLITE3_GC_SURVIVED:' + ITER);
      `;

      const output = execFileSync(
        process.execPath,
        ['--expose-gc', '-e', script],
        {
          cwd: repoRoot,
          encoding: 'utf-8',
          timeout: 60_000,
          windowsHide: true,
        },
      );

      expect(output).toContain('BETTER_SQLITE3_GC_SURVIVED:20000');
    },
    70_000,
  );
});
