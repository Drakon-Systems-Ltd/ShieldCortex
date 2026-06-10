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
  rebuild: (dir: string) => Promise<{ ok: boolean; output: string }>;
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
 */
export function rebuildNativeBinding(installDir: string): Promise<{ ok: boolean; output: string }> {
  return new Promise((resolve) => {
    let output = '';
    let settled = false;
    const finish = (ok: boolean) => { if (!settled) { settled = true; resolve({ ok, output }); } };

    let child;
    try {
      child = spawn('npm', ['rebuild', 'better-sqlite3', '--no-audit', '--no-fund'], {
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
 * Platform-aware build-toolchain hint, tailored by error text when available.
 */
function toolchainHint(rebuildOutput?: string): string {
  const out = (rebuildOutput ?? '').toLowerCase();
  const needsToolchain = !rebuildOutput || /gyp|python|make|g\+\+|cc1plus|no such file|command not found/.test(out);
  if (!needsToolchain) return '';
  if (process.platform === 'darwin') {
    return 'If the rebuild fails for lack of a compiler: xcode-select --install';
  }
  if (process.platform === 'win32') {
    return 'If the rebuild fails for lack of a compiler: install the "Desktop development with C++" workload (Visual Studio Build Tools).';
  }
  return 'If the rebuild fails for lack of a compiler: sudo apt-get install -y python3 make g++  (or your distro\'s build-essential).';
}

/**
 * The correct copy-paste remediation — the install-dir `cd` is the bit users
 * miss (a bare `npm rebuild better-sqlite3` from $HOME is a silent no-op).
 */
export function nativeBindingRemediation(installDir: string, rebuildOutput?: string): string {
  const lines = [
    `cd "${installDir}" && npm rebuild better-sqlite3`,
  ];
  const hint = toolchainHint(rebuildOutput);
  if (hint) lines.push(hint);
  lines.push('Then restart Claude Code / the OpenClaw gateway so processes reload the binding.');
  return lines.join('\n');
}

/**
 * Verify the binding; if it fails, rebuild in the install dir and re-verify.
 * - 'ok'     — loaded first try (no rebuild).
 * - 'healed' — rebuilt and now loads.
 * - 'failed' — still broken after a rebuild; `remediation` carries the fix.
 */
export async function ensureNativeBinding(deps: Partial<BindingDeps> = {}): Promise<EnsureResult> {
  const verify = deps.verify ?? verifyNativeBinding;
  const rebuild = deps.rebuild ?? rebuildNativeBinding;
  const installDir = deps.installDir ?? resolveSelfInstallDir;

  const first = verify();
  if (first.ok) return { status: 'ok' };

  const dir = installDir();
  const rebuilt = await rebuild(dir);
  const after = verify();
  if (after.ok) return { status: 'healed', rebuildOutput: rebuilt.output };

  return {
    status: 'failed',
    error: after.error ?? first.error,
    rebuildOutput: rebuilt.output,
    remediation: nativeBindingRemediation(dir, rebuilt.output),
  };
}
