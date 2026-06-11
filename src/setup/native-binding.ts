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
 * The second trap (observed on clawdbot1): even in the right dir, a plain
 * `npm rebuild` can report "rebuilt dependencies successfully" while the binary
 * never built — no matching prebuilt, and the source build silently no-op'd or
 * its failure was swallowed. So when a plain rebuild doesn't heal, we escalate
 * to `--build-from-source --foreground-scripts`, which forces a real compile and
 * streams the build output — surfacing the ACTUAL error (almost always a missing
 * C/C++ toolchain) instead of a misleading success.
 *
 * Used by: `shieldcortex update` (verify+heal step), `shieldcortex repair`,
 * `shieldcortex doctor` (correct remediation text), and the postinstall guidance.
 */

import path from 'path';
import { spawn } from 'child_process';
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
 * Run `npm rebuild better-sqlite3` in the install dir. Async (the rebuild can
 * take tens of seconds) so callers can keep a spinner alive. Never throws.
 *
 * With `{ fromSource: true }` it forces a real compile (`--build-from-source`)
 * and streams the build-script output (`--foreground-scripts`) so a failed
 * compile surfaces its real error rather than npm's misleading
 * "rebuilt dependencies successfully".
 */
export function rebuildNativeBinding(
  installDir: string,
  opts: { fromSource?: boolean } = {},
): Promise<{ ok: boolean; output: string }> {
  return new Promise((resolve) => {
    let output = '';
    let settled = false;
    const finish = (ok: boolean) => { if (!settled) { settled = true; resolve({ ok, output }); } };

    const args = ['rebuild', 'better-sqlite3', '--no-audit', '--no-fund'];
    if (opts.fromSource) args.push('--build-from-source', '--foreground-scripts');

    let child;
    try {
      child = spawn('npm', args, {
        cwd: installDir,
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
 * The correct copy-paste remediation — the install-dir `cd` is the bit users
 * miss (a bare `npm rebuild better-sqlite3` from $HOME is a silent no-op).
 *
 * Uses `--build-from-source` because by the time we surface this, a plain
 * rebuild has already failed to heal: forcing a source compile is both what
 * actually produces the binary (when no prebuilt matches this Node/arch) and
 * what reveals the real error if it can't.
 */
export function nativeBindingRemediation(installDir: string): string {
  return [
    `cd "${installDir}" && npm rebuild better-sqlite3 --build-from-source`,
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
 * forced `--build-from-source` compile. The forced build is what surfaces the
 * real error (and `rebuildOutput` in the failed result carries IT, not the
 * earlier misleading "rebuilt dependencies successfully").
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
