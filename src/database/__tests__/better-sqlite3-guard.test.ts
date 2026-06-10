import { describe, it, expect } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  formatNativeLoadError,
  NativeModuleLoadError,
  isNativeModuleLoadError,
} from '../better-sqlite3-guard.js';

const GUARD_SRC = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  'better-sqlite3-guard.ts',
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

  it('gives the exact rebuild remediation command', () => {
    const msg = formatNativeLoadError(new Error('ERR_DLOPEN_FAILED'), nodeVersion, abi);
    expect(msg).toContain('npm rebuild better-sqlite3');
  });

  it('points users at a supported Node LTS when on bleeding-edge Node', () => {
    const msg = formatNativeLoadError(new Error('Cannot find module better_sqlite3.node'), nodeVersion, abi);
    expect(msg.toLowerCase()).toContain('node');
    // Must name a concrete supported line, not just say "use LTS"
    expect(msg).toMatch(/\b(20|22)\b/);
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

describe('native-load failure must never kill the host (C1)', () => {
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
    // Keeps the helpful rebuild remediation in the thrown error.
    expect(err.message).toContain('npm rebuild better-sqlite3');
    expect(err.message).toContain('better-sqlite3');
    // A binding-load error is recognised as native (routes away from the
    // destructive corrupt-DB recovery in init.ts).
    expect(isNativeModuleLoadError(cause)).toBe(true);
  });
});
