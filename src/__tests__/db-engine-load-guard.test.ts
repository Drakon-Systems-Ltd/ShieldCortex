import { describe, expect, it } from '@jest/globals';
import { isNativeModuleLoadError } from '../database/better-sqlite3-guard.js';

/**
 * Regression (2026-06-09, Jarvis / clawdbot1, arm64): after `shieldcortex
 * update` the better-sqlite3 native binding was missing for the box's Node/arch.
 * `new Database(path)` threw "Could not locate the bindings file" — and the DB
 * init path CAUGHT that and treated it as FILE CORRUPTION, renaming the live
 * `memories.db` to `.corrupt.<ts>` (data moved aside) before crashing.
 *
 * A native-module load failure is an INSTALL problem, not corruption. This pins
 * the discriminator that keeps the init path from ever renaming a healthy DB on
 * a binding error.
 */
describe('isNativeModuleLoadError — distinguishes engine-load failure from file corruption', () => {
  it('matches the exact error Jarvis hit (missing better-sqlite3 binding)', () => {
    const msg =
      'Could not locate the bindings file. Tried:\n' +
      ' → /home/ubuntu/.npm-global/lib/node_modules/shieldcortex/node_modules/better-sqlite3/build/better_sqlite3.node\n' +
      ' → /home/ubuntu/.npm-global/lib/node_modules/shieldcortex/node_modules/better-sqlite3/lib/binding/node-v127-linux-arm64/better_sqlite3.node';
    expect(isNativeModuleLoadError(new Error(msg))).toBe(true);
  });

  it('matches ABI / arch / load-time native failures', () => {
    expect(isNativeModuleLoadError(new Error(
      'The module was compiled against a different Node.js version using NODE_MODULE_VERSION 115. This version requires NODE_MODULE_VERSION 127.',
    ))).toBe(true);
    expect(isNativeModuleLoadError(new Error('/path/better_sqlite3.node: invalid ELF header'))).toBe(true);
    expect(isNativeModuleLoadError(new Error("Cannot find module 'better-sqlite3'"))).toBe(true);
    expect(isNativeModuleLoadError(new Error('dlopen(better_sqlite3.node): symbol not found'))).toBe(true);
  });

  it('does NOT match genuine database CORRUPTION (those must still trigger recovery)', () => {
    expect(isNativeModuleLoadError(new Error('database disk image is malformed'))).toBe(false);
    expect(isNativeModuleLoadError(new Error('file is not a database'))).toBe(false);
    expect(isNativeModuleLoadError(new Error('file is encrypted or is not a database'))).toBe(false);
    expect(isNativeModuleLoadError(new Error('database is locked'))).toBe(false);
  });

  it('is defensive about non-Error inputs', () => {
    expect(isNativeModuleLoadError(undefined)).toBe(false);
    expect(isNativeModuleLoadError('Could not locate the bindings file')).toBe(true);
  });
});
