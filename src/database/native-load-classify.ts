/**
 * Native-binding load CLASSIFICATION and MESSAGE FORMATTING — pure, and
 * deliberately free of any module-evaluation side effect.
 *
 * This module exists so the recovery surfaces (`shieldcortex repair`,
 * `doctor`, the MCP startup self-heal, the `scan` exit contract) can classify
 * and explain a better-sqlite3 load failure WITHOUT importing the loader that
 * fails. `better-sqlite3-guard.ts` is the one place that actually resolves the
 * native addon; anything that only needs to answer "is this a native-binding
 * fault, and what should the user do about it?" imports THIS module instead.
 *
 * The rule this enforces: a module on the CLI's startup path must never be
 * able to detonate on a broken binding before command dispatch. If the
 * classifiers lived next to the loader, every consumer of a predicate would
 * drag the loader in with it — which is exactly how a binding fault used to
 * kill `shieldcortex repair`, the command that exists to fix it.
 *
 * Nothing here touches the filesystem, the process, or a native module. It is
 * string classification and string building only.
 */

/**
 * Thrown when the better-sqlite3 native binding cannot be loaded (missing /
 * ABI-mismatched / wrong-arch prebuild, or the module is not installed).
 *
 * Carries the actionable, formatted guidance in `.message` so a caller can
 * print it verbatim. Typed so entry points can distinguish an environmental
 * install problem from a genuine runtime error and exit cleanly if they choose.
 */
export class NativeModuleLoadError extends Error {
  /** The original error raised by `require('better-sqlite3')`. */
  readonly cause: unknown;

  constructor(message: string, cause: unknown) {
    super(message);
    this.name = 'NativeModuleLoadError';
    this.cause = cause;
  }
}

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
  const packagedPrebuild = isPackagedPrebuildLoadError(err);
  const lines = [
    'ShieldCortex could not load its database engine (better-sqlite3).',
    '',
    `Node ${nodeVersion} (module ABI ${abi}) could not load the better-sqlite3 binding.`,
  ];
  // The diagnosis has to match the class. "the module was not compiled
  // locally" is simply wrong for a packaged-prebuild failure: a prebuilt
  // binary IS present, it just cannot be loaded on this runtime, and nothing
  // the user compiles will be used instead of it.
  if (packagedPrebuild) {
    lines.push(
      'The packaged Node-API native binding cannot be loaded here: the shipped',
      'prebuilt binary is unusable on this platform, or this Node build predates',
      'the Node-API version it requires.',
    );
  } else {
    lines.push(
      'The shipped Node-API prebuilt binary is missing for this platform, this',
      'Node build predates the Node-API version it requires, or the module was',
      'not compiled locally.',
    );
  }
  lines.push(
    '',
    'Fix one of these:',
    '  • Use Node ^22.14.0 || >=24.0.0, then reinstall ShieldCortex so npm restores the',
    '    matching Node-API prebuilt binary — no compiler needed.',
  );
  if (packagedPrebuild) {
    lines.push(
      '  • If the error persists after reinstalling on a supported Node, report',
      '    that platform failure; a source build cannot safely override the packaged prebuild',
      '    in this release.',
    );
  } else {
    lines.push(
      '  • For a missing/source-only binding, run `shieldcortex repair` or',
      '    compile in the better-sqlite3 package dir with `npm run build-release`',
      '    (requires Xcode CLT / build-essential; a plain `npm rebuild` can',
      '    silently no-op).',
    );
  }
  lines.push('', `Underlying error: ${detail}`);
  return lines.join('\n');
}

/**
 * Signatures of a NATIVE-MODULE load failure (missing / ABI-mismatched / wrong-
 * arch better-sqlite3 binding, incompatible Node-API version, or the module
 * not being installed). These throw from `new Database()` — better-sqlite3
 * resolves its binding lazily at construction, not at require() — and must be
 * distinguished from genuine SQLite FILE corruption: a load failure is an
 * install problem, and treating it as corruption (renaming the live DB to
 * .corrupt.*) is data loss.
 *
 * better-sqlite3 13 ships Node-API prebuilds named `prebuilds/<platform>-
 * <arch>.node` (e.g. `prebuilds/linux-x64.node`, `prebuilds/darwin-arm64.node`)
 * instead of the 12.x `build/Release/better_sqlite3.node` layout, so the
 * filename signatures below cover both. A prebuild can also be a truncated /
 * corrupted download (`invalid ELF header`, `not a valid Win32 application`,
 * `is not a Mach-O`, a bad file magic) or unreadable (`EACCES`) without ever
 * touching the live database file — those still belong here. Node-API
 * incompatibility (a Node build too old for the addon's required Node-API
 * version — see https://github.com/WiseLibs/better-sqlite3/issues/1514, fixed
 * floor is Node 22.14.0) surfaces as "N-API version" / "Node-API version" /
 * "napi_version" wording, not an ABI number, and must route the same way.
 */
// v13 Node-API prebuild layout: prebuilds/<platform>-<arch>(.node), e.g.
// "prebuilds/linux-x64.node", "prebuilds\\win32-arm64.node". Extracted as a
// named pattern (rather than inlined only in NATIVE_LOAD_SIGNATURES) so
// isPackagedPrebuildLoadError below can reuse the exact same contract instead
// of duplicating it.
const PREBUILD_PATH_PATTERN = /prebuilds[\\/][a-z0-9_]+-[a-z0-9_]+\.node\b/i;

// Node-API version incompatibility (better-sqlite3 13 requires Node-API 10,
// true floor Node >=22.14.0 — an older/odd Node build lacks the requested
// Node-API version). Distinct wording from the legacy ABI/NODE_MODULE_VERSION
// mismatch below but the same "wrong Node for this prebuild" failure mode.
// Extracted as a named list so isPackagedPrebuildLoadError below reuses the
// exact same patterns instead of duplicating the broad message logic.
const NODE_API_INCOMPATIBILITY_PATTERNS: RegExp[] = [
  /this node(?:\.js)? instance does not support/i,
  /does not support builds for (?:node|n)-?api version/i,
  /\b(?:node|n)-?api version\b.{0,80}\b(?:not supported|unsupported|requires?|too (?:old|low)|only supports?)/i,
  /\brequires? (?:node|n)-?api version\b/i,
  /napi_module_register/i,
];

const NATIVE_LOAD_SIGNATURES: RegExp[] = [
  /could not locate the bindings file/i,
  /better_sqlite3\.node/i,
  PREBUILD_PATH_PATTERN,
  /NODE_MODULE_VERSION/i,
  /compiled against a different node/i,
  ...NODE_API_INCOMPATIBILITY_PATTERNS,
  /invalid ELF header/i,
  /wrong ELF class/i,
  // glibc/musl prebuild mismatch (a glibc-linked prebuild run on musl/Alpine,
  // or vice versa) — Node reports it as a shared-library resolution failure,
  // not a corruption message.
  /GLIBC_[\d.]+/i,
  /version `GLIBC/i,
  /ld-linux[^\s]*\.so/i,
  // Truncated/corrupted native binary downloads — file-format errors on the
  // .node addon itself, not on a SQLite database file.
  /is not a valid win32 application/i,
  /not a valid (?:win32|mach-?o) (?:application|file)/i,
  /is not a mach-?o/i,
  /dlopen\(/i,
  /symbol not found/i,
  /specified module could not be found/i,
  /cannot find module ['"]better-sqlite3/i,
  // Permission-denied reading/loading the addon itself (EACCES/EPERM naming a
  // .node file, in either message order — Node's own EACCES wording puts the
  // code first, "invalid ELF header"-style wrappers put the path first).
  // Gated on the .node extension so a permissions error on the SQLite
  // database file (a plain .db/.sqlite path) is never misclassified.
  /(?:EACCES|EPERM)\b[\s\S]{0,200}\.node\b(?![\\/])/i,
  /\.node\b(?![\\/])[\s\S]{0,200}(?:EACCES|EPERM|permission denied)/i,
];

/**
 * Evidence that a message is talking about a NATIVE ADDON at all — a `.node`
 * file, better-sqlite3 itself, or the v13 prebuilds directory.
 *
 * Required alongside the generic signatures below, which are real native-load
 * wordings but are not self-identifying: `file too short` is a plain
 * truncated-file error and `error while loading shared libraries` is emitted by
 * the dynamic loader for any ELF binary (including `node` itself failing on
 * libnode.so). Ungated, either could classify an unrelated
 * database-path failure as a native-binding fault and route a genuinely
 * recoverable condition away from recovery.
 */
const NATIVE_ADDON_CONTEXT = /(?:\.node\b(?![\\/])|better[_-]sqlite3|prebuilds[\\/])/i;

/**
 * Native-load wordings that are only meaningful WITH native-addon context.
 * Matched conjunctively with NATIVE_ADDON_CONTEXT — never on their own.
 */
const CONTEXTUAL_NATIVE_LOAD_SIGNATURES: RegExp[] = [
  /file too short/i,
  /error while loading shared libraries/i,
];

/**
 * True when an error from opening the database is a better-sqlite3 native-module
 * load failure (environmental), as opposed to genuine file corruption. Pure +
 * exported so the init path can route it away from destructive recovery.
 */
export function isNativeModuleLoadError(error: unknown): boolean {
  const msg = error instanceof Error ? error.message : String(error ?? '');
  if (NATIVE_LOAD_SIGNATURES.some((re) => re.test(msg))) return true;
  return (
    NATIVE_ADDON_CONTEXT.test(msg) &&
    CONTEXTUAL_NATIVE_LOAD_SIGNATURES.some((re) => re.test(msg))
  );
}

/**
 * Narrow predicate, true only for the subset of native-load failures that a
 * local rebuild cannot safely heal in this release: an unloadable PACKAGED
 * prebuild (the error names a `prebuilds/<platform>-<arch>.node` file) or a
 * Node-API version the running Node build does not support. Both mean the
 * shipped binary itself is the problem — reinstalling on a supported Node is
 * the fix, not `npm run build-release`: the package resolver gives the shipped
 * prebuild priority over local source-build output.
 *
 * Deliberately narrower than isNativeModuleLoadError: a merely missing /
 * source-only binding (e.g. "Could not locate the bindings file" with no
 * prebuilds/*.node in the message) stays false here — ensureNativeBinding can
 * still heal that case by rebuilding.
 */
export function isPackagedPrebuildLoadError(error: unknown): boolean {
  const msg = error instanceof Error ? error.message : String(error ?? '');
  return PREBUILD_PATH_PATTERN.test(msg) || NODE_API_INCOMPATIBILITY_PATTERNS.some((re) => re.test(msg));
}
