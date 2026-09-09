import { describe, it, expect } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  formatNativeLoadError,
  NativeModuleLoadError,
  isNativeModuleLoadError,
  isPackagedPrebuildLoadError,
} from '../better-sqlite3-guard.js';

const GUARD_SRC = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  'better-sqlite3-guard.ts',
);

const INIT_SRC = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  'init.ts',
);

describe('formatNativeLoadError', () => {
  const nodeVersion = 'v25.8.0';
  const abi = '141';

  it('reports the detected Node version and ABI', () => {
    const msg = formatNativeLoadError(
      new Error("The module was compiled against NODE_MODULE_VERSION 127. This version requires 141."),
      nodeVersion,
      abi,
    );
    expect(msg).toContain('v25.8.0');
    expect(msg).toContain('141');
    expect(msg).toContain('better-sqlite3');
  });

  it('gives the reliable source-compile remediation (build-release / repair, not the no-op npm rebuild)', () => {
    const msg = formatNativeLoadError(new Error('ERR_DLOPEN_FAILED'), nodeVersion, abi);
    expect(msg).toContain('npm run build-release');
    expect(msg).toContain('shieldcortex repair');
    // Must NOT suggest the bare `npm rebuild better-sqlite3`, which goes through
    // prebuild-install and silently no-ops when no prebuilt matches this Node/arch.
    expect(msg).not.toContain('npm rebuild better-sqlite3');
  });

  it('points users at the supported Node-API floor', () => {
    const msg = formatNativeLoadError(new Error('Cannot find module better_sqlite3.node'), nodeVersion, abi);
    expect(msg).toContain('Node ^22.14.0 || >=24.0.0');
  });

  it('does not claim source repair can override an unloadable v13 prebuild', () => {
    const msg = formatNativeLoadError(
      new Error('/app/node_modules/better-sqlite3/prebuilds/linux-arm64.node: file too short'),
      nodeVersion,
      abi,
    );
    expect(msg).toContain('reinstall ShieldCortex');
    expect(msg).toContain('cannot safely override the packaged prebuild');
    expect(msg).not.toContain('shieldcortex repair');
    expect(msg).not.toContain('npm run build-release');
  });

  it('preserves the underlying error text for debugging', () => {
    const msg = formatNativeLoadError(new Error('totally-unique-native-error-xyz'), nodeVersion, abi);
    expect(msg).toContain('totally-unique-native-error-xyz');
  });

  it('is a single actionable block, not a stack dump', () => {
    const msg = formatNativeLoadError(new Error('boom'), nodeVersion, abi);
    expect(msg).toContain('ShieldCortex');
    expect(msg.split('\n').length).toBeLessThan(20);
  });
});

describe('isNativeModuleLoadError — better-sqlite3 13 (Node-API) prebuild failures', () => {
  // v13 replaced the 12.x build/Release/better_sqlite3.node layout with
  // per-platform Node-API prebuilds at prebuilds/<platform>-<arch>.node. A
  // failure to load one of these must still be classified as a native-module
  // load error, not routed into init.ts's corrupt-DB recovery.
  it('matches a truncated/corrupted v13 prebuild (bad file magic)', () => {
    expect(isNativeModuleLoadError(new Error(
      "Error: /app/node_modules/better-sqlite3/prebuilds/linux-x64.node: invalid ELF header",
    ))).toBe(true);
    expect(isNativeModuleLoadError(new Error(
      "\\\\?\\C:\\app\\node_modules\\better-sqlite3\\prebuilds\\win32-x64.node is not a valid Win32 application",
    ))).toBe(true);
    expect(isNativeModuleLoadError(new Error(
      'dlopen(/app/node_modules/better-sqlite3/prebuilds/darwin-arm64.node, 0x0001): tried: (is not a Mach-O)',
    ))).toBe(true);
    expect(isNativeModuleLoadError(new Error(
      'The specified procedure could not be found.\r\nC:\\app\\node_modules\\better-sqlite3\\prebuilds\\win32-x64.node',
    ))).toBe(true);
  });

  it('matches a glibc/musl mismatch on a v13 prebuild', () => {
    expect(isNativeModuleLoadError(new Error(
      "/app/node_modules/better-sqlite3/prebuilds/linux-x64.node: /lib/x86_64-linux-gnu/libm.so.6: version `GLIBC_2.35' not found (required by prebuilds/linux-x64.node)",
    ))).toBe(true);
    expect(isNativeModuleLoadError(new Error(
      'Error loading shared library ld-linux-x86-64.so.2: No such file or directory (needed by prebuilds/linuxmusl-x64.node)',
    ))).toBe(true);
  });

  it('matches EACCES / permission-denied on a v13 prebuild file', () => {
    expect(isNativeModuleLoadError(new Error(
      "EACCES: permission denied, open '/app/node_modules/better-sqlite3/prebuilds/linux-arm64.node'",
    ))).toBe(true);
  });

  it('matches Node-API version incompatibility (Node older than the addon needs, e.g. pre-22.14.0)', () => {
    // node-pre-gyp / node-gyp-build style wording.
    expect(isNativeModuleLoadError(new Error(
      'This Node instance does not support builds for N-API version 10',
    ))).toBe(true);
    expect(isNativeModuleLoadError(new Error(
      'better-sqlite3 requires N-API version 10, but this Node.js build only supports up to version 8',
    ))).toBe(true);
    expect(isNativeModuleLoadError(new Error(
      "The module 'better-sqlite3' requires Node-API version 10, but this version of Node.js only supports version 9 add-ons.",
    ))).toBe(true);
    // Native-side registration failure surfaced when the runtime cannot
    // satisfy the addon's requested Node-API version.
    expect(isNativeModuleLoadError(new Error(
      'napi_module_register(): Assertion failed',
    ))).toBe(true);
  });

  it('does NOT match genuine SQLite/database-file errors, even ones mentioning permissions or paths', () => {
    // These must stay routed to init.ts's corruption-recovery path — a
    // .node-load signature must never fire on a database file error.
    expect(isNativeModuleLoadError(new Error('database disk image is malformed'))).toBe(false);
    expect(isNativeModuleLoadError(new Error('file is not a database'))).toBe(false);
    expect(isNativeModuleLoadError(new Error('file is encrypted or is not a database'))).toBe(false);
    expect(isNativeModuleLoadError(new Error('database is locked'))).toBe(false);
    // Permission denied on the DB FILE (not a .node addon) is a real,
    // recoverable file-corruption-adjacent condition, not an install problem.
    expect(isNativeModuleLoadError(new Error(
      "EACCES: permission denied, open '/home/user/.shieldcortex/memories.db'",
    ))).toBe(false);
    expect(isNativeModuleLoadError(new Error(
      "EACCES: permission denied, open '/home/user/.node/memories.db'",
    ))).toBe(false);
    expect(isNativeModuleLoadError(new Error('SQLITE_CORRUPT: database disk image is malformed'))).toBe(false);
    expect(isNativeModuleLoadError(new Error('unable to open database file'))).toBe(false);
  });
});

describe('classifier/formatter contract consumed by init.ts', () => {
  // This does NOT reimplement or mock a second classifier — it exercises the
  // exact exported functions init.ts imports (isNativeModuleLoadError,
  // formatNativeLoadError) and pins the property that makes the routing safe:
  // every error classified as native-load produces guidance that is purely
  // install-oriented (build/repair/Node-version), and never suggests the
  // destructive corrupt-DB recovery (backup/rename/"Creating fresh database").
  const NATIVE_LOAD_CORPUS = [
    'Could not locate the bindings file',
    "Cannot find module 'better-sqlite3'",
    'The module was compiled against NODE_MODULE_VERSION 115. This version requires NODE_MODULE_VERSION 127.',
    '/app/node_modules/better-sqlite3/prebuilds/linux-x64.node: invalid ELF header',
    "EACCES: permission denied, open '/app/node_modules/better-sqlite3/prebuilds/linux-arm64.node'",
    'This Node instance does not support builds for N-API version 10',
  ];

  const CORRUPTION_CORPUS = [
    'database disk image is malformed',
    'file is not a database',
    'file is encrypted or is not a database',
    'database is locked',
  ];

  it('every native-load corpus entry is classified true and formats install-only guidance', () => {
    for (const text of NATIVE_LOAD_CORPUS) {
      const err = new Error(text);
      expect(isNativeModuleLoadError(err)).toBe(true);

      const message = formatNativeLoadError(err, process.version, String(process.versions.modules));
      // Actionable install guidance is present...
      expect(message).toContain('better-sqlite3');
      // ...and the destructive corruption-recovery vocabulary from init.ts's
      // OTHER branch never appears in the native-load message, so a caller
      // reading only this message cannot confuse the two recovery paths.
      expect(message.toLowerCase()).not.toContain('corrupt');
      expect(message.toLowerCase()).not.toContain('backing up');
      expect(message.toLowerCase()).not.toContain('creating fresh database');
    }
  });

  it('every corruption corpus entry is classified false (recovery path, never treated as native-load)', () => {
    for (const text of CORRUPTION_CORPUS) {
      expect(isNativeModuleLoadError(new Error(text))).toBe(false);
    }
  });
});

describe('isPackagedPrebuildLoadError — narrow predicate for the unhealable class', () => {
  // This predicate is deliberately NARROWER than isNativeModuleLoadError: it
  // must fire only for the two failure modes that a local rebuild cannot fix
  // in this release (an unloadable packaged prebuild, or a Node-API version
  // the running Node build does not support) — never for a merely missing /
  // source-only binding, which ensureNativeBinding can still heal by rebuilding.
  it('matches an error naming a v13 prebuilds/<platform>-<arch>.node file', () => {
    expect(isPackagedPrebuildLoadError(new Error(
      '/app/node_modules/better-sqlite3/prebuilds/linux-x64.node: invalid ELF header',
    ))).toBe(true);
  });

  it('matches a v13 Windows prebuild load failure', () => {
    expect(isPackagedPrebuildLoadError(new Error(
      '\\\\?\\C:\\app\\node_modules\\better-sqlite3\\prebuilds\\win32-x64.node is not a valid Win32 application',
    ))).toBe(true);
  });

  it('matches the exact real-world Node-API version incompatibility wording', () => {
    expect(isPackagedPrebuildLoadError(new Error(
      "The module 'better-sqlite3' requires Node-API version 10, but this version of Node.js only supports version 9 add-ons.",
    ))).toBe(true);
  });

  it('does NOT match a generic missing-bindings-file error (missing/source-only class, still healable by rebuild)', () => {
    expect(isPackagedPrebuildLoadError(new Error('Could not locate the bindings file'))).toBe(false);
  });

  it('does NOT match database corruption', () => {
    expect(isPackagedPrebuildLoadError(new Error('database disk image is malformed'))).toBe(false);
  });

  it('does NOT match a permission error on the database file itself (only on a .node addon)', () => {
    expect(isPackagedPrebuildLoadError(new Error(
      "EACCES: permission denied, open '/home/user/.shieldcortex/memories.db'",
    ))).toBe(false);
  });
});

describe('init.ts native-load branch renders the central formatter (no stale hardcoded paragraph)', () => {
  it('calls formatNativeLoadError instead of hand-rolling its own remediation text', () => {
    const src = readFileSync(INIT_SRC, 'utf-8');
    expect(src).toContain('formatNativeLoadError');
    // The old hardcoded paragraph named a fixed global-install path that is
    // wrong for local/npx installs and drifted out of sync with the guard's
    // own remediation text.
    expect(src).not.toContain('$(npm root -g)/shieldcortex/node_modules/better-sqlite3');
  });

  it('explicitly tells the caller the database path was untouched', () => {
    const src = readFileSync(INIT_SRC, 'utf-8');
    expect(src).toMatch(/untouched/i);
  });
});

describe('native-load failure must never terminate the host process (C1)', () => {
  it('has NO process.exit CALL in the guard source — a library must not terminate its host', () => {
    const src = readFileSync(GUARD_SRC, 'utf-8');
    // Strip comments so a doc-reference to `process.exit()` (explaining why we
    // must never call it) doesn't trip the check — we only forbid real calls.
    const code = src
      .replace(/\/\*[\s\S]*?\*\//g, '') // block comments
      .replace(/\/\/.*$/gm, '');         // line comments
    // The guard is reachable from the library entry (initDatabase); a
    // process.exit here would kill any app that merely imports the package.
    expect(code).not.toMatch(/process\s*\.\s*exit\s*\(/);
  });

  it('throws a typed NativeModuleLoadError carrying the actionable guidance', () => {
    const cause = new Error('Cannot find module better_sqlite3.node');
    const message = formatNativeLoadError(cause, process.version, String(process.versions.modules));
    const err = new NativeModuleLoadError(message, cause);

    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('NativeModuleLoadError');
    expect(err.cause).toBe(cause);
    // Keeps the helpful (reliable) compile remediation in the thrown error.
    expect(err.message).toContain('npm run build-release');
    expect(err.message).toContain('better-sqlite3');
    // A binding-load error is recognised as native (routes away from the
    // destructive corrupt-DB recovery in init.ts).
    expect(isNativeModuleLoadError(cause)).toBe(true);
  });
});
