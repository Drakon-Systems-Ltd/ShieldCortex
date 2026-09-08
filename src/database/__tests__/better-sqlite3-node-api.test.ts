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
 */
import { describe, it, expect } from '@jest/globals';
import { readFileSync, existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const require = createRequire(import.meta.url);
const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

function major(version: string): number {
  return Number(version.split('.')[0]);
}

describe('better-sqlite3 must be Node-API based (Node 24 worker crash-loop)', () => {
  it('declares a >=13 floor in package.json', () => {
    const pkg = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf-8'));
    const range: string = pkg.dependencies['better-sqlite3'];
    // Any range that can resolve a 12.x is a range that can resurrect the abort.
    const floor = range.replace(/^[\^~>=]+/, '');
    expect(major(floor)).toBeGreaterThanOrEqual(13);
  });

  it('has an installed version >=13', () => {
    const installed: string = require('better-sqlite3/package.json').version;
    expect(major(installed)).toBeGreaterThanOrEqual(13);
  });

  it('resolves a native binding that links no node::ObjectWrap cleanup hooks', () => {
    // better-sqlite3 13 exposes its own resolver; fall back to the node-gyp
    // location for a locally compiled build (`shieldcortex repair`).
    let bindingPath: string | null = null;
    try {
      bindingPath = (require('better-sqlite3/lib/binding') as {
        getPrebuildPath(): string | null;
      }).getPrebuildPath();
    } catch {
      bindingPath = null;
    }
    if (!bindingPath) {
      const built = join(repoRoot, 'node_modules', 'better-sqlite3', 'build', 'Release', 'better_sqlite3.node');
      bindingPath = existsSync(built) ? built : null;
    }
    if (!bindingPath) {
      // No binding on disk to inspect (e.g. a dependency-less checkout). The
      // two version assertions above still hold the floor.
      return;
    }

    // Dynamic symbol names live as plain ASCII in the binary on every platform
    // we ship, so this needs no nm/objdump and works on Linux, macOS and Windows.
    const bytes = readFileSync(bindingPath).toString('latin1');
    expect(bytes).not.toContain('RemoveEnvironmentCleanupHook');
    expect(bytes).not.toContain('AddEnvironmentCleanupHook');
    // Positive control: it really is a Node-API addon, not just a stripped one.
    expect(bytes).toContain('napi_');
  });
});
