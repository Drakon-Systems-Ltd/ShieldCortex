/**
 * Guarded loader for the better-sqlite3 native module.
 *
 * better-sqlite3 13 ships Node-API prebuilt binaries per PLATFORM (not per
 * Node ABI), so a Node upgrade no longer strands the binding — that was the
 * 12.x failure mode, where a Node version newer than the installed prebuilds
 * (and with no C++ toolchain to compile from source) failed to load with a
 * bare `libc++abi: terminating ... Napi::Error` crash-loop and zero guidance.
 * An unsupported platform, a stripped install or a half-finished local build
 * can still fail. This module is the single place better-sqlite3 is loaded at
 * runtime: it turns that failure into one actionable, catchable error
 * instead of an opaque abort.
 *
 * It must NEVER call `process.exit()`: this module is reachable from the
 * library entry (`shieldcortex` → `initDatabase`), so a host app that merely
 * imports the package must not be terminated. The load failure is thrown as a
 * typed `NativeModuleLoadError`; a CLI/server entry point can catch it and
 * decide to exit, but the module itself stays a well-behaved library.
 *
 * It must ALSO never load the addon at MODULE EVALUATION. `dist/index.js` is
 * simultaneously the `bin` entry and the package `main`, and it re-exports the
 * library surface (`export * from './lib.js'` → `initDatabase` → this module),
 * so a module-scope `require('better-sqlite3')` here threw before `main()`
 * could dispatch — taking `shieldcortex repair`, `doctor`, `--help` and the
 * MCP startup self-heal down with it, i.e. every command that exists to fix a
 * broken binding. The load is therefore lazy and memoised behind
 * `getBetterSqlite3()`: the first `new Database(...)` still fails loudly with
 * the same typed error, but importing the module costs nothing.
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

/** Memoised addon handle — populated on first successful load, never reset. */
let cachedConstructor: typeof DatabaseConstructor | undefined;

/**
 * Resolve the better-sqlite3 constructor, loading the native addon on first
 * call and reusing it thereafter.
 *
 * Lazy on purpose (see the module header): callers get the same typed
 * `NativeModuleLoadError` they always did, but only when they actually try to
 * open a database — never merely because something on the CLI startup path
 * imported this file.
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
    // must not kill a host app. The message carries the rebuild guidance; an
    // entry point (CLI/server) may catch this and exit if it wants to.
    throw new NativeModuleLoadError(message, err);
  }
}

export type { DatabaseConstructor };
