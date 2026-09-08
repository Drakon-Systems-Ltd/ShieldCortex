/**
 * Self-healing for the better-sqlite3 native binding.
 *
 * better-sqlite3 ships prebuilt binaries for common platform/ABI combos; when
 * none matches (e.g. a newer Node than the prebuilds, or arm64 with no prebuilt)
 * it must compile from source, which needs a C/C++ toolchain. If that hasn't
 * happened the binding is missing and every DB operation fails with
 * "Could not locate the bindings file".
 *
 * The trap (observed on an arm64 fleet box): `npm rebuild better-sqlite3` only
 * works when run IN THE PACKAGE'S INSTALL DIR. Run from anywhere else (e.g. the
 * user's home dir) it matches nothing and reports "rebuilt dependencies
 * successfully" — a no-op. So this module resolves the install dir from the
 * running code's own location and rebuilds there.
 *
 * The second trap (proven on clawdbot1): even in the right dir, `npm rebuild
 * better-sqlite3` — AND `npm rebuild … --build-from-source` — can report "rebuilt
 * dependencies successfully" while the binary never built. On 12.x that was
 * prebuild-install exiting 0 without building; on 13.x npm's implicit node-gyp
 * rebuild is a deliberate no-op whenever the package already carries a prebuilt
 * for the host. Either way, when a plain rebuild doesn't heal, we escalate to
 * better-sqlite3's own `npm run build-release` (= `node-gyp rebuild --release
 * --force_build=1`) IN its package dir, which actually compiles — surfacing the
 * real build error (almost always a missing C/C++ toolchain) if it can't.
 *
 * The third trap, new in 13.x: `lib/binding.js` resolves `prebuilds/` BEFORE
 * `build/Release/`, so a from-source build is invisible while an unloadable
 * prebuilt is still sitting there. {@link shelvePrebuild} moves it aside for the
 * duration of a forced build, and puts it back if that build fails.
 *
 * Used by: `shieldcortex update` (verify+heal step), `shieldcortex repair`,
 * `shieldcortex doctor` (correct remediation text), and the postinstall guidance.
 */

import path from 'path';
import { spawn } from 'child_process';
import { existsSync, renameSync } from 'fs';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);

export interface VerifyResult {
  ok: boolean;
  error?: string;
}

export type EnsureStatus = 'ok' | 'healed' | 'failed';

export interface EnsureResult {
  status: EnsureStatus;
  /** Underlying load error, when the binding could not be loaded. */
  error?: string;
  /** Captured rebuild output, when a rebuild was attempted. */
  rebuildOutput?: string;
  /** Full copy-paste remediation, present when status is 'failed'. */
  remediation?: string;
}

/** Injection seam so the heal orchestration is testable without a real failure. */
export interface BindingDeps {
  verify: () => VerifyResult;
  rebuild: (dir: string, opts?: { fromSource?: boolean }) => Promise<{ ok: boolean; output: string }>;
  installDir: () => string;
}

/**
 * The package's own install root — the directory whose `package.json` is this
 * package, and which contains `node_modules/better-sqlite3`. Derived from the
 * running module's location, NOT `npm root -g` (which points at the wrong tree
 * when the package was installed under a custom prefix or via a registry shim).
 *
 * From `dist/setup/native-binding.js` → `../../` is the package root.
 */
export function resolveSelfInstallDir(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  return path.resolve(here, '..', '..');
}

/**
 * Smoke-test the native binding: load it, open an in-memory DB, run a probe.
 * Synchronous (the load is sync) and never throws — returns a verdict.
 */
export function verifyNativeBinding(): VerifyResult {
  try {
    const Database = require('better-sqlite3');
    const db = new Database(':memory:');
    db.exec('CREATE TABLE _sc_probe(x)');
    db.close();
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

/**
 * The command used to (re)build the binding — split out so the choice is
 * unit-testable without actually spawning npm.
 *
 * - normal: `npm rebuild better-sqlite3` in the install dir. Fast, and places a
 *   matching prebuilt when one exists for this platform/ABI.
 * - fromSource: `npm run build-release` IN the better-sqlite3 dir — its own script
 *   (`node-gyp rebuild --release`). This is the ONLY reliable force-compile:
 *   `npm rebuild … --build-from-source` still goes through prebuild-install, which
 *   on a platform with no matching prebuilt exits 0 WITHOUT building and reports
 *   "rebuilt dependencies successfully" (proven on arm64 Node 22). build-release
 *   bypasses prebuild-install entirely and invokes node-gyp directly.
 */
export function nativeRebuildCommand(
  installDir: string,
  fromSource = false,
): { cmd: string; args: string[]; cwd: string } {
  if (fromSource) {
    return {
      cmd: 'npm',
      args: ['run', 'build-release'],
      cwd: path.join(installDir, 'node_modules', 'better-sqlite3'),
    };
  }
  return { cmd: 'npm', args: ['rebuild', 'better-sqlite3', '--no-audit', '--no-fund'], cwd: installDir };
}

/**
 * Run the binding (re)build. Async (the compile can take tens of seconds) so
 * callers can keep a spinner alive. Never throws.
 *
 * With `{ fromSource: true }` it forces a real compile via better-sqlite3's
 * `build-release` (node-gyp) — bypassing prebuild-install's silent no-op — and
 * captures the build output so a failed compile surfaces its real error rather
 * than npm's misleading "rebuilt dependencies successfully".
 */
export function rebuildNativeBinding(
  installDir: string,
  opts: { fromSource?: boolean } = {},
): Promise<{ ok: boolean; output: string }> {
  const fromSource = opts.fromSource ?? false;
  const { cmd, args, cwd } = nativeRebuildCommand(installDir, fromSource);
  const shadowing = fromSource ? shelvePrebuild(installDir) : null;
  return new Promise((resolve) => {
    let output = '';
    let settled = false;
    const finish = (ok: boolean) => {
      if (settled) return;
      settled = true;
      // A failed source build must not leave the install with NO binding at
      // all: put the shelved prebuilt back, since it is still the best
      // available binary.
      if (shadowing && !ok) restorePrebuild(shadowing);
      resolve({ ok, output });
    };

    let child;
    try {
      child = spawn(cmd, args, {
        cwd,
        stdio: ['ignore', 'pipe', 'pipe'],
        shell: false,
      });
    } catch (err) {
      return resolve({ ok: false, output: err instanceof Error ? err.message : String(err) });
    }

    const timer = setTimeout(() => {
      try { child.kill('SIGTERM'); } catch { /* already dead */ }
      output += '\n[timed out after 180s]';
      finish(false);
    }, 180_000);
    timer.unref();

    child.stdout?.setEncoding('utf-8');
    child.stderr?.setEncoding('utf-8');
    child.stdout?.on('data', (c: string) => { output += c; });
    child.stderr?.on('data', (c: string) => { output += c; });
    child.on('error', (err) => { clearTimeout(timer); output += String(err?.message ?? err); finish(false); });
    child.on('close', (code) => { clearTimeout(timer); finish(code === 0); });
  });
}

interface ShelvedPrebuild {
  from: string;
  to: string;
}

/**
 * Move better-sqlite3 13's shipped prebuilt binary aside before a from-source
 * compile, and remember where it went.
 *
 * Why this is needed: 13.x resolves its binding as
 * `prebuilds/<platform>-<arch>.node` FIRST and only falls back to the node-gyp
 * output in `build/Release/`. So on a box where the shipped prebuilt exists but
 * cannot load (unsupported glibc, a truncated download, a hardened mount),
 * `npm run build-release` would compile a perfectly good binary that nothing
 * ever loads — the exact silent no-op this module exists to prevent, one layer
 * down. Shelving the prebuilt makes the fresh build the resolved binding.
 *
 * Best-effort by design: on 12.x (no `lib/binding`, no `prebuilds/`) and on any
 * fs error this returns null and the build proceeds unchanged.
 */
function shelvePrebuild(installDir: string): ShelvedPrebuild | null {
  try {
    const pkgDir = path.join(installDir, 'node_modules', 'better-sqlite3');
    const { getPrebuildPath } = require(path.join(pkgDir, 'lib', 'binding.js')) as {
      getPrebuildPath(): string | null;
    };
    const from = getPrebuildPath();
    if (!from || !existsSync(from)) return null;
    const to = `${from}.shelved-for-source-build`;
    renameSync(from, to);
    return { from, to };
  } catch {
    return null;
  }
}

/** Undo {@link shelvePrebuild} when the source build did not produce a binding. */
function restorePrebuild(shelved: ShelvedPrebuild): void {
  try {
    if (existsSync(shelved.to) && !existsSync(shelved.from)) renameSync(shelved.to, shelved.from);
  } catch {
    // Best-effort: the source build's own output is the remediation path now.
  }
}

/**
 * Platform-aware build-toolchain hint.
 *
 * Always emitted in the failed-remediation path: by the time we're generating
 * remediation, BOTH a plain rebuild and a forced source build have failed to
 * heal the binding, and on Linux/macOS the overwhelmingly common cause is a
 * missing C/C++ toolchain. The old version gated this on recognising error text
 * in the rebuild output — which silently suppressed the hint in exactly the
 * worst case (a rebuild that reported success but never built the binary),
 * leaving the user with no idea they needed to install a compiler.
 */
function toolchainHint(): string {
  if (process.platform === 'darwin') {
    return 'If it fails for lack of a compiler: xcode-select --install';
  }
  if (process.platform === 'win32') {
    return 'If it fails for lack of a compiler: install the "Desktop development with C++" workload (Visual Studio Build Tools).';
  }
  return 'If it fails for lack of a compiler: sudo apt-get install -y python3 make g++  (Debian/Ubuntu; or your distro\'s build-essential).';
}

/**
 * The correct copy-paste remediation. Two things users (and a naive
 * `npm rebuild`) get wrong, both leading to a silent no-op:
 *   1. running the rebuild outside the package's install dir, and
 *   2. using `npm rebuild`/`--build-from-source`, which goes through
 *      prebuild-install and exits 0 without building when no prebuilt matches.
 * The reliable command is better-sqlite3's own `build-release` (node-gyp) run in
 * its package dir, which compiles from source directly.
 */
export function nativeBindingRemediation(installDir: string): string {
  const pkgDir = path.join(installDir, 'node_modules', 'better-sqlite3');
  return [
    `cd "${pkgDir}" && npm run build-release`,
    toolchainHint(),
    'Then restart Claude Code / the OpenClaw gateway so processes reload the binding.',
  ].join('\n');
}

/**
 * Verify the binding; if it fails, rebuild in the install dir and re-verify.
 * - 'ok'     — loaded first try (no rebuild).
 * - 'healed' — rebuilt and now loads.
 * - 'failed' — still broken after a rebuild; `remediation` carries the fix.
 *
 * Two rebuild attempts when needed: first a plain `npm rebuild` (fast, uses a
 * matching prebuilt if one exists), then — only if that didn't heal it — a
 * forced `npm run build-release` (node-gyp) source compile. The forced build is
 * what actually produces the binary when no prebuilt matches AND surfaces the
 * real error if it can't (and `rebuildOutput` in the failed result carries IT,
 * not the earlier misleading "rebuilt dependencies successfully").
 */
export async function ensureNativeBinding(deps: Partial<BindingDeps> = {}): Promise<EnsureResult> {
  const verify = deps.verify ?? verifyNativeBinding;
  const rebuild = deps.rebuild ?? rebuildNativeBinding;
  const installDir = deps.installDir ?? resolveSelfInstallDir;

  const first = verify();
  if (first.ok) return { status: 'ok' };

  const dir = installDir();

  // Attempt 1: a plain rebuild (matches a prebuilt for this platform/ABI if any).
  const normal = await rebuild(dir);
  const afterNormal = verify();
  if (afterNormal.ok) return { status: 'healed', rebuildOutput: normal.output };

  // Attempt 2: force a source compile. A plain rebuild can report success while
  // never producing the binary; this forces the build and captures the real
  // error so the failed remediation is honest about what went wrong.
  const sourceBuild = await rebuild(dir, { fromSource: true });
  const afterSource = verify();
  if (afterSource.ok) return { status: 'healed', rebuildOutput: sourceBuild.output };

  return {
    status: 'failed',
    error: afterSource.error ?? afterNormal.error ?? first.error,
    rebuildOutput: sourceBuild.output,
    remediation: nativeBindingRemediation(dir),
  };
}
