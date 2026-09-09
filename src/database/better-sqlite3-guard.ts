/**
 * Guarded loader for the better-sqlite3 native module.
 *
 * better-sqlite3 13 ships Node-API prebuilt binaries per PLATFORM (not per
 * Node ABI), so a Node upgrade no longer strands the binding — that was the
 * 12.x failure mode, where a Node version newer than the installed prebuilds
 * (and with no C++ toolchain to compile from source) failed to load with a
 * bare `libc++abi: terminating ... Napi::Error` crash-loop and zero guidance.
 * An unsupported platform, a stripped install or a half-finished local build
 * can still fail. This module is the single place better-sqlite3 is REQUIRED
 * at runtime: it turns a failure to require the package into one actionable,
 * catchable error instead of an opaque abort.
 *
 * WHERE THE FAILURES ACTUALLY SURFACE in v13 — measured, not assumed, because
 * the two are routinely conflated:
 *
 *  • REQUIRING the package resolves JAVASCRIPT ONLY. `lib/index.js` is
 *    `require('./database')(require('./binding').getBinding, true)`, which
 *    hands `getBinding` over as a FUNCTION; no `.node` file is opened. So the
 *    `require` below can only fail when the PACKAGE itself is unusable — not
 *    installed, stripped by a pruning install, or a corrupt entry file. That
 *    is the failure `getBetterSqlite3()` wraps in `NativeModuleLoadError`.
 *
 *  • The BINDING is loaded at DATABASE CONSTRUCTION. `prebuilds/<platform>-
 *    <arch>.node` is dlopen'd inside `new Database(...)`, so an unloadable or
 *    Node-API-incompatible prebuild throws from the CONSTRUCTOR and never from
 *    the require here. Callers that open a database classify that error with
 *    `isNativeModuleLoadError` / `isPackagedPrebuildLoadError` (see
 *    `database/init.ts`), which is what keeps a binding fault from being
 *    mistaken for file corruption.
 *
 * It must NEVER call `process.exit()`: this module is reachable from the
 * library entry (`shieldcortex` → `initDatabase`), so a host app that merely
 * imports the package must not be terminated. The load failure is thrown as a
 * typed `NativeModuleLoadError`; a CLI/server entry point can catch it and
 * decide to exit, but the module itself stays a well-behaved library.
 *
 * It must ALSO never require the package at MODULE EVALUATION. `dist/index.js`
 * is simultaneously the `bin` entry and the package `main`, and it re-exports
 * the library surface (`export * from './lib.js'` → `initDatabase` → this
 * module), so a module-scope `require('better-sqlite3')` here threw before
 * `main()` could dispatch whenever the package was unrequirable — taking
 * `shieldcortex repair`, `doctor`, `--help` and the MCP startup self-heal down
 * with it, i.e. every command that exists to fix a broken install. The require
 * is therefore lazy and memoised behind `getBetterSqlite3()`: opening a
 * database still fails loudly with the same typed error, but importing this
 * module costs nothing.
 *
 * The classifiers and the message formatter deliberately live in the
 * side-effect-free `./native-load-classify.js`, re-exported below for existing
 * callers. Anything that only needs to classify or explain a failure should
 * import THAT module directly and never reach this one.
 */

import { createRequire } from 'module';
import type DatabaseConstructor from 'better-sqlite3';
import {
  NativeModuleLoadError,
  formatNativeLoadError,
} from './native-load-classify.js';

const require = createRequire(import.meta.url);

export {
  NativeModuleLoadError,
  formatNativeLoadError,
  isNativeModuleLoadError,
  isPackagedPrebuildLoadError,
} from './native-load-classify.js';

/** Memoised constructor — populated on first successful require, never reset. */
let cachedConstructor: typeof DatabaseConstructor | undefined;

/**
 * Resolve the better-sqlite3 constructor, requiring the package on first call
 * and reusing it thereafter.
 *
 * Lazy on purpose (see the module header): callers get the same typed
 * `NativeModuleLoadError` they always did, but only when they actually try to
 * open a database — never merely because something on the CLI startup path
 * imported this file. Note that a successful return does NOT mean the native
 * binding loads: v13 defers that to `new Database(...)`.
 */
export function getBetterSqlite3(): typeof DatabaseConstructor {
  if (cachedConstructor) return cachedConstructor;
  try {
    cachedConstructor = require('better-sqlite3') as typeof DatabaseConstructor;
    return cachedConstructor;
  } catch (err) {
    const message = formatNativeLoadError(
      err,
      process.version,
      String(process.versions.modules),
    );
    // THROW, never exit: this module is imported by the library entry, so it
    // must not kill a host app. The message carries the remediation guidance;
    // an entry point (CLI/server) may catch this and exit if it wants to.
    throw new NativeModuleLoadError(message, err);
  }
}

export type { DatabaseConstructor };
