/**
 * #630 — `shieldcortex config` help must describe the auto-memory and
 * proactive-recall defaults as they actually are:
 *
 *   - the config readers treat a key that is not set as OFF (`=== true`);
 *   - a fresh global, non-CI npm install with no ~/.shieldcortex/config.json
 *     gets one written by postinstall with both keys set to `true`;
 *   - an existing config.json is never overwritten.
 *
 * The old help said "(default: off)" for both, which is false for a fresh
 * global install. Source contract only: the help strings are read out of
 * src/cloud/cli.ts and the claims are pinned to scripts/postinstall.mjs and
 * src/cloud/config.ts. Nothing here runs postinstall, setup or a config
 * writer, and nothing reads or writes the real home directory.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { describe, expect, it } from '@jest/globals';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');

const read = (...rel: string[]): string => fs.readFileSync(path.join(REPO_ROOT, ...rel), 'utf8');

/** The `config` usage text, rebuilt from its console.log string literals. */
function configHelpLines(): string[] {
  const src = read('src', 'cloud', 'cli.ts');
  const start = src.indexOf("console.log('Usage: shieldcortex config [options]')");
  expect(start).toBeGreaterThan(-1);
  const end = src.indexOf("console.log('LLM Verification:')", start);
  expect(end).toBeGreaterThan(start);
  const lines: string[] = [];
  const re = /console\.log\('((?:[^'\\]|\\.)*)'\)/g;
  for (const m of src.slice(start, end).matchAll(re)) lines.push(m[1].replace(/\\'/g, "'"));
  return lines;
}

/** Body of a top-level `function name()` / `if (...) {` block, by brace matching. */
function blockAfter(src: string, marker: string): string {
  const at = src.indexOf(marker);
  expect(at).toBeGreaterThan(-1);
  const open = src.indexOf('{', at);
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}' && --depth === 0) return src.slice(open, i + 1);
  }
  throw new Error(`unbalanced block after ${marker}`);
}

describe('#630 config help — auto-memory / proactive-recall defaults', () => {
  const help = configHelpLines();
  const text = help.join('\n');
  const flagLine = (flag: string) => {
    const line = help.find((l) => l.trimStart().startsWith(flag));
    expect(line).toBeDefined();
    return line as string;
  };

  it('no longer claims an unqualified "default: off" for either flag', () => {
    for (const flag of ['--openclaw-auto-memory', '--proactive-recall']) {
      expect(flagLine(flag)).not.toMatch(/default:\s*off/i);
    }
  });

  it('states the unset-key fallback as off for both flags', () => {
    expect(flagLine('--openclaw-auto-memory')).toMatch(/off when unset/);
    expect(flagLine('--proactive-recall')).toMatch(/off when unset/);
  });

  it('states that a fresh global, non-CI install with no config.json writes both as true', () => {
    expect(text).toMatch(/fresh global npm install \(not CI\)/);
    expect(text).toContain('~/.shieldcortex/config.json');
    expect(text).toMatch(/writes both as true/);
  });

  it('states that an existing config is kept, and does not imply existing configs default to true', () => {
    expect(text).toMatch(/existing config\.json is never changed/);
    expect(text).toMatch(/upgrade keeps your current values/);
    expect(text).toMatch(/a key it does not set stays off/);
  });
});

describe('#630 — the help claims match the shipped behaviour', () => {
  it('postinstall writes both keys as true, only when config.json is absent', () => {
    const post = read('scripts', 'postinstall.mjs');
    const writer = blockAfter(post, 'function writeFreshInstallDefaults()');
    expect(writer).toMatch(/if \(existsSync\(configFile\)\) return false;/);
    expect(writer).toMatch(/openclawAutoMemory:\s*true/);
    expect(writer).toMatch(/proactiveRecall:\s*true/);
  });

  it('postinstall calls that writer only for a global, non-CI install', () => {
    const post = read('scripts', 'postinstall.mjs');
    expect(post).toMatch(/const isGlobal = process\.env\.npm_config_global === 'true';/);
    expect(post).toMatch(/const isCI = process\.env\.CI === 'true'/);
    const main = blockAfter(post, 'if (isGlobal && !isCI)');
    expect(main).toContain('writeFreshInstallDefaults()');
    // Exactly one call site, so there is no other path that writes these defaults.
    expect(post.match(/writeFreshInstallDefaults\(\)/g)).toHaveLength(2); // definition + call
  });

  it('the config readers treat an unset key as off', () => {
    const cfg = read('src', 'cloud', 'config.ts');
    expect(cfg).toContain('autoMemory: raw.openclawAutoMemory === true,');
    expect(blockAfter(cfg, 'export function isProactiveRecallEnabled()')).toContain(
      'return raw.proactiveRecall === true;',
    );
  });
});
