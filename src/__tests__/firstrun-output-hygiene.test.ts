import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

import { debugLog, isDebugLoggingEnabled } from '../debug-log.js';
import { closeDatabase, initDatabase } from '../database/init.js';

/**
 * First-run output hygiene (#129).
 *
 * A clean-box `remember` / `scan` printed three lines that belong to us, not
 * to the user:
 *
 *   [database] Startup runtime=installed db=/root/.shieldcortex/memories.db …
 *   [shieldcortex] pre-backfill snapshot saved: …/memories.db.pre-backfill-…
 *   dtype not specified for "model". Using the default dtype (fp32) …
 *
 * Internal startup state, an internal restore-point path, and a dependency
 * warning. All three now stay out of user output on a healthy install;
 * `--verbose` / `SHIELDCORTEX_DEBUG` restores the first two.
 */
describe('debug gate', () => {
  it('is off by default', () => {
    expect(isDebugLoggingEnabled({}, ['node', 'shieldcortex', 'remember', 'hello'])).toBe(false);
  });

  it.each(['1', 'true', 'yes', 'on', 'anything-truthy'])('is on for SHIELDCORTEX_DEBUG=%s', (value) => {
    expect(isDebugLoggingEnabled({ SHIELDCORTEX_DEBUG: value }, ['node', 'shieldcortex'])).toBe(true);
  });

  it.each(['0', 'false', 'no', 'off', ''])('stays off for SHIELDCORTEX_DEBUG=%s', (value) => {
    expect(isDebugLoggingEnabled({ SHIELDCORTEX_DEBUG: value }, ['node', 'shieldcortex'])).toBe(false);
  });

  it.each(['--verbose', '--debug'])('is on for %s on the command line', (flag) => {
    expect(isDebugLoggingEnabled({}, ['node', 'shieldcortex', 'scan', 'x', flag])).toBe(true);
  });

  it('lets --verbose win over an inherited SHIELDCORTEX_DEBUG=0', () => {
    expect(isDebugLoggingEnabled({ SHIELDCORTEX_DEBUG: '0' }, ['node', 'shieldcortex', '--verbose'])).toBe(true);
  });

  it('writes to stderr only when enabled', () => {
    const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
    const previous = process.env.SHIELDCORTEX_DEBUG;
    try {
      delete process.env.SHIELDCORTEX_DEBUG;
      debugLog('internal detail');
      expect(spy).not.toHaveBeenCalled();

      process.env.SHIELDCORTEX_DEBUG = '1';
      debugLog('internal detail');
      expect(spy).toHaveBeenCalledWith('internal detail');
    } finally {
      if (previous === undefined) delete process.env.SHIELDCORTEX_DEBUG;
      else process.env.SHIELDCORTEX_DEBUG = previous;
      spy.mockRestore();
    }
  });
});

describe('database startup diagnostics stay out of user output', () => {
  let tmpDir: string;
  let dbPath: string;
  let previousDebug: string | undefined;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-quiet-startup-'));
    dbPath = path.join(tmpDir, 'memories.db');
    previousDebug = process.env.SHIELDCORTEX_DEBUG;
    delete process.env.SHIELDCORTEX_DEBUG;
    closeDatabase();
  });

  afterEach(() => {
    closeDatabase();
    if (previousDebug === undefined) delete process.env.SHIELDCORTEX_DEBUG;
    else process.env.SHIELDCORTEX_DEBUG = previousDebug;
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  function captureStderrDuringInit(): string {
    const lines: string[] = [];
    const spy = jest.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
      lines.push(args.map(String).join(' '));
    });
    try {
      initDatabase(dbPath);
    } finally {
      spy.mockRestore();
      closeDatabase();
    }
    return lines.join('\n');
  }

  it('does not print the [database] Startup line by default', () => {
    expect(captureStderrDuringInit()).not.toMatch(/\[database\] Startup/);
  });

  it('prints it again under SHIELDCORTEX_DEBUG', () => {
    process.env.SHIELDCORTEX_DEBUG = '1';
    expect(captureStderrDuringInit()).toMatch(/\[database\] Startup runtime=/);
  });

  it('never leaks an internal restore-point path by default', () => {
    // First init creates the file; a second init is what can take the
    // pre-backfill snapshot of an existing database.
    captureStderrDuringInit();
    const output = captureStderrDuringInit();
    expect(output).not.toMatch(/pre-backfill snapshot saved/);
    expect(output).not.toMatch(/\.pre-backfill-/);
  });
});

describe('embedding model load does not warn about dtype', () => {
  const thisFile = fileURLToPath(import.meta.url);
  const repoRoot = path.resolve(path.dirname(thisFile), '..', '..');

  it.each([
    ['src/embeddings/worker.ts'],
    ['src/defence/judge/worker.ts'],
  ])('%s pins an explicit dtype on its transformers pipeline', (relPath) => {
    const source = fs.readFileSync(path.join(repoRoot, relPath), 'utf-8');
    // transformers.js prints `dtype not specified for "model" …` to the
    // console whenever a pipeline is constructed without one. Inspect the
    // options block of every pipeline construction in the file.
    const callSites = [...source.matchAll(/\bpipeline(?:Fn)?\(/g)];
    expect(callSites.length).toBeGreaterThan(0);
    for (const site of callSites) {
      const optionsBlock = source.slice(site.index!, site.index! + 400);
      expect(optionsBlock).toMatch(/dtype:\s*'[a-z0-9]+'/);
    }
  });
});
