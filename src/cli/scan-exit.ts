/**
 * `shieldcortex scan` process exit contract (#449).
 *
 * 0/1 are verdicts. 2 is the caller. 3 is the scanner.
 * Collapsing 2 and 3 made a dead tool look like a catch (or a typo),
 * which is how a Node 26 better-sqlite3 ABI death scored as a 100% catch rate.
 */

// Classification/formatting only — imported from the side-effect-free
// classifier module, NEVER from `better-sqlite3-guard.js`. `src/index.ts`
// imports this file statically, so any path from here to the loader would
// put the native addon on the CLI's startup graph again.
import {
  NativeModuleLoadError,
  formatNativeLoadError,
  isNativeModuleLoadError,
} from '../database/native-load-classify.js';

export const SCAN_EXIT = Object.freeze({
  ALLOW: 0,
  CAUGHT: 1,
  USAGE: 2,
  TOOL_FAILURE: 3,
} as const);

export type ScanExitCode = (typeof SCAN_EXIT)[keyof typeof SCAN_EXIT];

export const SCAN_USAGE_LINES = [
  'Usage: shieldcortex scan "text to analyse"',
  '  Runs the defence pipeline (firewall + trust + sensitivity).',
  '  No MCP server or ML model required — works on ARM64.',
  '  Exit codes: 0=allow 1=caught 2=usage 3=tool-failure (control absent).',
] as const;

export function scanVerdictExit(allowed: boolean): typeof SCAN_EXIT.ALLOW | typeof SCAN_EXIT.CAUGHT {
  return allowed ? SCAN_EXIT.ALLOW : SCAN_EXIT.CAUGHT;
}

/** Non-scan CLI failures stay 1. Scan uncaught/init failures are 3. */
export function cliCatchExit(command: string | undefined): number {
  return command === 'scan' ? SCAN_EXIT.TOOL_FAILURE : 1;
}

const NATIVE_BINDING_HEADER =
  'Scan tool failure (native binding): control is absent until the scanner binary matches this Node.';

export function formatScanToolFailure(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err);
  // Already diagnosed upstream (the guard, or initDatabase): print its message
  // verbatim. formatNativeLoadError is NOT idempotent — its own generic
  // diagnosis says "this Node build predates the Node-API version it
  // requires", which isPackagedPrebuildLoadError matches, so a second pass
  // over a rendered message both nests a duplicate header and rewrites a
  // repairable missing/source-only failure as a packaged-prebuild one,
  // headlining "a source build cannot help" above the only fix that works.
  // The class travels with the typed error; never re-derive it from prose.
  if (err instanceof NativeModuleLoadError) {
    return `${NATIVE_BINDING_HEADER}\n${msg}`;
  }
  if (isNativeModuleLoadError(err)) {
    return (
      `${NATIVE_BINDING_HEADER}\n` +
      formatNativeLoadError(err, process.version, process.versions.modules ?? 'unknown')
    );
  }
  return `Scan tool failure: ${msg}`;
}

export function installScanToolFailureHandlers(exit: (code: number) => void = (code) => process.exit(code)): void {
  const fail = (err: unknown) => {
    console.error(formatScanToolFailure(err));
    exit(SCAN_EXIT.TOOL_FAILURE);
  };
  process.on('uncaughtException', fail);
  process.on('unhandledRejection', fail);
}
