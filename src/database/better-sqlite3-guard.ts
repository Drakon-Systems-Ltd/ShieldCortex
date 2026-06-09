/**
 * Guarded loader for the better-sqlite3 native module.
 *
 * better-sqlite3 ships prebuilt binaries per Node ABI. On a Node version
 * newer than the installed better-sqlite3's prebuilds (and with no C++
 * toolchain to compile from source), the native load fails — historically
 * with a bare `libc++abi: terminating ... Napi::Error` crash-loop and zero
 * guidance. This module is the single place better-sqlite3 is loaded at
 * runtime: it turns that failure into one actionable message and a clean
 * exit instead of an opaque abort.
 */

import { createRequire } from 'module';
import type DatabaseConstructor from 'better-sqlite3';

const require = createRequire(import.meta.url);

/**
 * Build the user-facing message for a native-load failure. Pure and
 * side-effect free so it can be unit-tested without breaking the binding.
 */
export function formatNativeLoadError(
  err: unknown,
  nodeVersion: string,
  abi: string,
): string {
  const detail = err instanceof Error ? err.message : String(err);
  return [
    'ShieldCortex could not load its database engine (better-sqlite3).',
    '',
    `Node ${nodeVersion} (ABI ${abi}) has no matching prebuilt binary and`,
    'the module was not compiled locally.',
    '',
    'Fix one of these:',
    '  • Rebuild the native module:   npm rebuild better-sqlite3',
    '    (requires a C/C++ toolchain — Xcode CLT / build-essential)',
    '  • Or run ShieldCortex on a supported Node LTS (20.x or 22.x),',
    '    which ship prebuilt binaries — no compiler needed.',
    '',
    `Underlying error: ${detail}`,
  ].join('\n');
}

/**
 * Signatures of a NATIVE-MODULE load failure (missing / ABI-mismatched / wrong-
 * arch better-sqlite3 binding, or the module not being installed). These throw
 * from `new Database()` — better-sqlite3 resolves its binding lazily at
 * construction, not at require() — and must be distinguished from genuine SQLite
 * FILE corruption: a load failure is an install problem, and treating it as
 * corruption (renaming the live DB to .corrupt.*) is data loss.
 */
const NATIVE_LOAD_SIGNATURES: RegExp[] = [
  /could not locate the bindings file/i,
  /better_sqlite3\.node/i,
  /NODE_MODULE_VERSION/i,
  /compiled against a different node/i,
  /invalid ELF header/i,
  /wrong ELF class/i,
  /dlopen\(/i,
  /symbol not found/i,
  /specified module could not be found/i,
  /cannot find module ['"]better-sqlite3/i,
];

/**
 * True when an error from opening the database is a better-sqlite3 native-module
 * load failure (environmental), as opposed to genuine file corruption. Pure +
 * exported so the init path can route it away from destructive recovery.
 */
export function isNativeModuleLoadError(error: unknown): boolean {
  const msg = error instanceof Error ? error.message : String(error ?? '');
  return NATIVE_LOAD_SIGNATURES.some((re) => re.test(msg));
}

function loadBetterSqlite3(): typeof DatabaseConstructor {
  try {
    return require('better-sqlite3') as typeof DatabaseConstructor;
  } catch (err) {
    const message = formatNativeLoadError(
      err,
      process.version,
      String(process.versions.modules),
    );
    // Clean, single-message fatal exit — never the bare libc++abi crash-loop.
    console.error(`\n${message}\n`);
    process.exit(1);
  }
}

const BetterSqlite3: typeof DatabaseConstructor = loadBetterSqlite3();

export type { DatabaseConstructor };
export default BetterSqlite3;
