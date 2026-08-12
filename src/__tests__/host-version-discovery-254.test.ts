import { describe, expect, it, beforeEach, afterEach } from '@jest/globals';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { readOpenClawHostVersion } from '../integrations/openclaw-conversation-capability.js';

/**
 * #254 — the capability probe searched ONE install layout.
 *
 * `readOpenClawHostVersion` only looked under `~/.openclaw/tools/<node>/lib/
 * node_modules/openclaw`, which is the MANAGED runtime layout. A plain global
 * `npm i -g openclaw` puts it somewhere on PATH instead (`~/.npm-global`,
 * `/usr/local`, nvm, volta). On those hosts `readdirSync` threw, the function
 * returned null, and doctor reported "enforcement support UNKNOWN — could not
 * read the installed OpenClaw version" on every run, forever — while the
 * version sat plainly readable next to the binary.
 *
 * That is a false UNKNOWN: the probe is capable of a confident verdict and
 * declines to give one. These tests pin BOTH layouts, and pin that a genuinely
 * absent install still yields null rather than a guess.
 */

let tmp: string;

function makeInstall(dir: string, version: string): void {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'openclaw', version }));
}

/** A global npm install: bin/openclaw symlinked at ../lib/node_modules/openclaw. */
function makeGlobalInstall(prefix: string, version: string): string {
  const pkgDir = path.join(prefix, 'lib', 'node_modules', 'openclaw');
  makeInstall(pkgDir, version);
  fs.writeFileSync(path.join(pkgDir, 'openclaw.mjs'), '#!/usr/bin/env node\n');
  const binDir = path.join(prefix, 'bin');
  fs.mkdirSync(binDir, { recursive: true });
  fs.symlinkSync(path.join(pkgDir, 'openclaw.mjs'), path.join(binDir, 'openclaw'));
  return binDir;
}

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-254-'));
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe('#254 — host version discovery across install layouts', () => {
  it('still reads the managed runtime layout', () => {
    const home = path.join(tmp, 'home');
    makeInstall(
      path.join(home, '.openclaw', 'tools', 'node-v24.15.0', 'lib', 'node_modules', 'openclaw'),
      '2026.6.1',
    );
    expect(readOpenClawHostVersion(home, '')).toBe('2026.6.1');
  });

  it('reads a global npm install found on PATH — the #254 regression', () => {
    const home = path.join(tmp, 'home');
    fs.mkdirSync(home, { recursive: true });
    // No ~/.openclaw/tools at all: this is the shape that returned null.
    const binDir = makeGlobalInstall(path.join(tmp, 'npm-global'), '2026.7.1-2');
    expect(readOpenClawHostVersion(home, binDir)).toBe('2026.7.1-2');
  });

  it('prefers the highest version when both layouts are present', () => {
    const home = path.join(tmp, 'home');
    makeInstall(
      path.join(home, '.openclaw', 'tools', 'node-v24.15.0', 'lib', 'node_modules', 'openclaw'),
      '2026.5.12',
    );
    const binDir = makeGlobalInstall(path.join(tmp, 'npm-global'), '2026.7.1');
    expect(readOpenClawHostVersion(home, binDir)).toBe('2026.7.1');
  });

  it('a stale global install does not beat a newer managed one', () => {
    const home = path.join(tmp, 'home');
    makeInstall(
      path.join(home, '.openclaw', 'tools', 'node-v24.15.0', 'lib', 'node_modules', 'openclaw'),
      '2026.7.1',
    );
    const binDir = makeGlobalInstall(path.join(tmp, 'npm-global'), '2026.4.23');
    expect(readOpenClawHostVersion(home, binDir)).toBe('2026.7.1');
  });

  it('returns null when there is genuinely no install — never a guess', () => {
    const home = path.join(tmp, 'home');
    fs.mkdirSync(home, { recursive: true });
    expect(readOpenClawHostVersion(home, path.join(tmp, 'empty-bin'))).toBeNull();
  });

  it('ignores a same-named binary that is not openclaw', () => {
    const home = path.join(tmp, 'home');
    fs.mkdirSync(home, { recursive: true });
    const prefix = path.join(tmp, 'impostor');
    const pkgDir = path.join(prefix, 'lib', 'node_modules', 'something-else');
    fs.mkdirSync(pkgDir, { recursive: true });
    fs.writeFileSync(
      path.join(pkgDir, 'package.json'),
      JSON.stringify({ name: 'something-else', version: '9999.1.1' }),
    );
    fs.writeFileSync(path.join(pkgDir, 'openclaw.mjs'), '');
    const binDir = path.join(prefix, 'bin');
    fs.mkdirSync(binDir, { recursive: true });
    fs.symlinkSync(path.join(pkgDir, 'openclaw.mjs'), path.join(binDir, 'openclaw'));
    expect(readOpenClawHostVersion(home, binDir)).toBeNull();
  });

  it('survives an unreadable PATH entry without throwing', () => {
    const home = path.join(tmp, 'home');
    fs.mkdirSync(home, { recursive: true });
    const binDir = makeGlobalInstall(path.join(tmp, 'npm-global'), '2026.7.1');
    const bogus = path.join(tmp, 'does-not-exist');
    expect(readOpenClawHostVersion(home, `${bogus}${path.delimiter}${binDir}`)).toBe('2026.7.1');
  });
});
