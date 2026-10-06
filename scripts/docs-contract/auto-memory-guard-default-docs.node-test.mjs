/**
 * Docs/comment contract: auto-memory, proactive-recall and Action Guard
 * defaults, as described in the OpenClaw docs, the plugin README, the OpenClaw
 * quickstart and the comments in src/cloud/config.ts.
 *
 * What the shipped source does (pinned by the first describe block):
 *   - the readers treat an unset `openclawAutoMemory` / `proactiveRecall` as
 *     OFF (`=== true`);
 *   - a fresh global, non-CI npm install with no ~/.shieldcortex/config.json
 *     gets one written by postinstall with both keys `true`; an existing file
 *     is never changed;
 *   - that write sets only those two keys, so it never turns on the Action
 *     Guard, which is off unless `actionGuard.enabled` is exactly `true`.
 *
 * Text only: files are read and matched. Nothing here runs postinstall, setup,
 * doctor, a hook or a config writer, and nothing touches the home directory.
 * Dependency-free (node:test) and NOT part of the Jest suite — run directly:
 *
 *   node --test scripts/docs-contract/auto-memory-guard-default-docs.node-test.mjs
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const read = (...rel) => fs.readFileSync(path.join(REPO_ROOT, ...rel), 'utf8');

/** Body of the block opened by the first `{` after `marker`, by brace matching. */
function blockAfter(src, marker) {
  const at = src.indexOf(marker);
  assert.ok(at > -1, `marker not found: ${marker}`);
  const open = src.indexOf('{', at);
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}' && --depth === 0) return src.slice(open, i + 1);
  }
  throw new Error(`unbalanced block after ${marker}`);
}

/** Text from `start` up to (not including) `end`. */
function between(src, start, end) {
  const a = src.indexOf(start);
  assert.ok(a > -1, `start not found: ${start}`);
  const b = src.indexOf(end, a + start.length);
  assert.ok(b > a, `end not found after start: ${end}`);
  return src.slice(a, b);
}

/** The JSDoc comment immediately preceding `export function name(`. */
function jsdocBefore(src, decl) {
  const at = src.indexOf(decl);
  assert.ok(at > -1, `declaration not found: ${decl}`);
  const open = src.lastIndexOf('/**', at);
  const close = src.indexOf('*/', open);
  assert.ok(open > -1 && close < at, `no JSDoc directly before ${decl}`);
  assert.equal(src.slice(close + 2, at).trim(), '', `JSDoc is not adjacent to ${decl}`);
  return src.slice(open, close + 2);
}

// Collapses whitespace and JSDoc/line-comment prefixes, so wrapping does not matter.
const oneLine = (s) => s.replace(/\n\s*(?:\*(?!\/)|\/\/)?/g, ' ').replace(/\s+/g, ' ');

describe('source facts the docs describe', () => {
  it('postinstall writes exactly openclawAutoMemory/proactiveRecall true, only when config.json is absent', () => {
    const post = read('scripts', 'postinstall.mjs');
    const writer = blockAfter(post, 'function writeFreshInstallDefaults()');
    assert.match(writer, /if \(existsSync\(configFile\)\) return false;/);
    const defaults = blockAfter(writer, 'const defaults =');
    assert.match(defaults, /openclawAutoMemory:\s*true/);
    assert.match(defaults, /proactiveRecall:\s*true/);
    // Only those two keys: the memory defaults cannot switch the guard on.
    assert.equal(defaults.match(/^\s*\w+:/gm).length, 2);
    assert.doesNotMatch(defaults, /actionGuard|interceptor/);
    // A failed write is swallowed (returns false), so the install carries on.
    assert.match(writer, /\} catch \{\s*return false;\s*\}/);
  });

  it('postinstall calls the writer only on a global, non-CI install', () => {
    const post = read('scripts', 'postinstall.mjs');
    assert.match(post, /const isGlobal = process\.env\.npm_config_global === 'true';/);
    assert.match(post, /const isCI = process\.env\.CI === 'true' \|\| process\.env\.CONTINUOUS_INTEGRATION === 'true';/);
    assert.ok(blockAfter(post, 'if (isGlobal && !isCI)').includes('writeFreshInstallDefaults()'));
    assert.equal(post.match(/writeFreshInstallDefaults\(\)/g).length, 2); // definition + one call
  });

  it('config readers treat unset auto-memory / proactive-recall / guard as off', () => {
    const cfg = read('src', 'cloud', 'config.ts');
    assert.ok(cfg.includes('autoMemory: raw.openclawAutoMemory === true,'));
    assert.ok(blockAfter(cfg, 'export function isProactiveRecallEnabled()').includes('return raw.proactiveRecall === true;'));
    assert.ok(cfg.includes('const planeOn = raw.openclawAutoMemory === true || raw.proactiveRecall === true;'));
    assert.match(blockAfter(cfg, 'export function getActionGuardCoreConfig()'), /enabled:\s*merged\.enabled === true/);
  });

  it('the OpenClaw plugin reads auto-memory strictly and ships the guard disabled', () => {
    const idx = read('plugins', 'openclaw', 'index.ts');
    assert.ok(blockAfter(idx, 'function isAutoMemoryEnabled(').includes('return config.openclawAutoMemory === true;'));
    const icpt = read('plugins', 'openclaw', 'interceptor.ts');
    assert.match(blockAfter(blockAfter(icpt, 'const DEFAULT_CONFIG: InterceptorConfig ='), 'actionGuard:'), /enabled:\s*false/);
    assert.ok(blockAfter(icpt, 'async function runActionGuard(').includes('if (!actionGuardCfg.enabled) return;'));
  });
});

describe('docs/openclaw-integration.md', () => {
  const doc = read('docs', 'openclaw-integration.md');
  const intro = oneLine(between(doc, '# OpenClaw Integration', '## Install'));
  const defaults = between(doc, '## Default behavior (safe complement mode)', '## Enable optional auto-memory');
  const enabledByDefault = between(defaults, 'Enabled by default:', '\nOff unless');

  it('intro says the Action Guard is off unless enabled, not "on"', () => {
    assert.doesNotMatch(intro, /Action Guard is on/);
    assert.match(intro, /Action Guard is \*\*off\*\* unless you enable it/);
    assert.match(intro, /shieldcortex config --action-guard-enable/);
  });

  it('intro qualifies "off by default" for auto-memory with the fresh-install write', () => {
    assert.doesNotMatch(intro, /opt-in \(off by default\)/);
    assert.match(intro, /off when the key is not set/);
    assert.match(intro, /fresh global, non-CI npm install/);
  });

  it('the guard is not listed under "Enabled by default"', () => {
    assert.doesNotMatch(enabledByDefault, /Action Guard/);
    assert.match(oneLine(defaults), /Off unless `actionGuard\.enabled` is `true`:/);
    assert.match(oneLine(defaults), /fresh-install defaults below do not turn it on/);
  });

  it('keeps the #630/#641 wording and adds that hooks still need installing', () => {
    const d = oneLine(defaults);
    assert.match(d, /When the key is not set, both stay off\./);
    assert.match(d, /An existing config file is never changed/);
    assert.match(d, /does not install the OpenClaw hook or plugin/);
  });

  it('install-time seed bullet is scoped to a global, non-CI install, not "only --ignore-scripts"', () => {
    const section = between(doc, '## Install-time refresh (postinstall)', '\nTo update the package without');
    // The seed bullet is the last one in the section.
    const at = section.indexOf('Also separately from OpenClaw');
    assert.ok(at > -1, 'seed bullet not found');
    const seed = oneLine(section.slice(at));
    assert.doesNotMatch(seed, /only `--ignore-scripts` avoids it/);
    assert.match(seed, /global, non-CI install/);
    assert.match(seed, /`CI=true` or `CONTINUOUS_INTEGRATION=true`/);
    assert.match(seed, /An existing config file is never overwritten/);
    // Success-qualified: a failed non-atomic write cannot promise that nothing was written.
    assert.match(seed, /when that write succeeds, `openclawAutoMemory: true` and `proactiveRecall: true` are saved/);
    assert.match(seed, /If the write fails, the two defaults are not saved and the install continues without them\./);
    assert.doesNotMatch(seed, /nothing is written|keys stay unset|so both stay off/);
    assert.match(seed, /still happens with `SHIELDCORTEX_SKIP_AUTO_OPENCLAW=1` and inside Docker/);
    assert.match(seed, /`--ignore-scripts`/);
    assert.match(seed, /does not install the OpenClaw hook or plugin and does not turn on the Action Guard/);
    assert.match(oneLine(section), /when `CI=true` or `CONTINUOUS_INTEGRATION=true`, or inside Docker/);
  });
});

describe('plugins/openclaw/README.md', () => {
  const readme = read('plugins', 'openclaw', 'README.md');
  const row = (hook) => {
    const line = readme.split('\n').find((l) => l.startsWith(`| \`${hook}\` |`));
    assert.ok(line, `no table row for ${hook}`);
    return line;
  };
  const autoMemory = oneLine(between(readme, '## Auto-memory', '## Cloud forwarding'));

  it('before_tool_call row says the guard is off unless enabled before claiming "always blocked"', () => {
    const r = row('before_tool_call');
    assert.match(r, /off unless `actionGuard\.enabled` is `true`/);
    assert.ok(r.indexOf('off unless') < r.indexOf('always blocked'), 'qualification must precede the blocking claim');
  });

  it('llm_output row is gated on openclawAutoMemory', () => {
    assert.match(row('llm_output'), /When `openclawAutoMemory` is `true`/);
  });

  it('Auto-memory section distinguishes unset fallback from fresh-install default', () => {
    assert.match(autoMemory, /when the key is not set it is off/);
    assert.match(autoMemory, /fresh global, non-CI npm install/);
    assert.match(autoMemory, /existing config file is never changed/);
    assert.match(autoMemory, /do not install the plugin or hook, and they do not turn on the Action Guard/);
  });
});

describe('docs/quickstarts/openclaw.md', () => {
  const qs = oneLine(read('docs', 'quickstarts', 'openclaw.md'));

  it('says a fresh global install turns auto-memory on, existing config kept', () => {
    assert.match(qs, /fresh global, non-CI `npm install -g`/);
    assert.match(qs, /auto-memory is on until you turn it off/);
    assert.match(qs, /existing config is kept as it was/);
  });

  it('says the Action Guard stays off until enabled', () => {
    assert.match(qs, /Action Guard stays off until you enable it/);
  });
});

describe('src/cloud/config.ts comments match the readers', () => {
  const cfg = read('src', 'cloud', 'config.ts');

  it('getOpenClawAutoMemory no longer claims on-by-default', () => {
    const doc = oneLine(jsdocBefore(cfg, 'export function getOpenClawAutoMemory('));
    assert.doesNotMatch(doc, /Default is true/);
    assert.match(doc, /Off when the key is not set/);
    assert.match(doc, /fresh global, non-CI npm install/);
  });

  it('isProactiveRecallEnabled qualifies the v4.11.0 opt-in with the fresh-install write', () => {
    const doc = oneLine(jsdocBefore(cfg, 'export function isProactiveRecallEnabled('));
    assert.doesNotMatch(doc, /Default is false since v4\.11\.0 — opt-in/);
    assert.match(doc, /Off when the key is not set/);
    assert.match(doc, /fresh global, non-CI npm install/);
  });

  it('getAutoMemoryEnableConfig names the plane-flag implication', () => {
    const doc = oneLine(jsdocBefore(cfg, 'export function getAutoMemoryEnableConfig('));
    assert.doesNotMatch(doc, /Default is false for both —/);
    assert.match(doc, /`openclawAutoMemory` or `proactiveRecall` is `true`/);
  });

  it('DEFAULT_OPENCLAW_MEMORY_CONFIG.autoMemory is marked as not consulted', () => {
    const at = cfg.indexOf('const DEFAULT_OPENCLAW_MEMORY_CONFIG');
    assert.match(oneLine(cfg.slice(at, cfg.indexOf('};', at))), /not read: getOpenClawMemoryConfig\(\) uses `openclawAutoMemory === true`/);
  });
});
