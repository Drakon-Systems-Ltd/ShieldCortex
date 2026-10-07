/**
 * Docs/comment contract: per-consumer memory defaults and wiring prerequisites,
 * as described in the cortex-memory hook (source and ClawHub-bundled copies),
 * the `shieldcortex update` 4.11 boundary notice and the root README.
 *
 * What the shipped source does (pinned by the first describe block):
 *   - every consumer treats an unset `openclawAutoMemory` / `proactiveRecall`
 *     as OFF (`=== true`), including when config.json is missing;
 *   - postinstall seeds both `true` only on a fresh global, non-CI install,
 *     and it wires no Claude Code hook — `setup` / `install` add the
 *     UserPromptSubmit hook that does prompt-time recall;
 *   - the 4.11 notice prints only after `update` installs a new package over
 *     a pre-4.11.0 version, so it is migration context, not today's default.
 *
 * Text only: files are read and matched. Nothing here runs postinstall, setup,
 * update, doctor, a hook or a config writer, and nothing touches the home
 * directory. Dependency-free (node:test) and NOT part of the Jest suite:
 *
 *   node --test scripts/docs-contract/memory-default-hook-update-copy.node-test.mjs
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

const oneLine = (s) => s.replace(/\s+/g, ' ');

const HOOK_DIRS = [
  ['hooks', 'openclaw', 'cortex-memory'],
  ['skills', 'shieldcortex', 'bundled', 'cortex-memory-hook'],
];

describe('source facts the copy describes', () => {
  for (const dir of HOOK_DIRS) {
    it(`${dir.join('/')}: auto-memory and proactive recall read strictly as === true`, () => {
      assert.ok(blockAfter(read(...dir, 'runtime.mjs'), 'function isOpenClawAutoMemoryEnabled(config)')
        .includes('return config?.openclawAutoMemory === true;'));
      assert.ok(blockAfter(read(...dir, 'handler.ts'), 'async function isProactiveRecallEnabled()')
        .includes('return config?.proactiveRecall === true;'));
    });
  }

  it('Claude Code prompt recall: missing config is {} and anything but true exits before recall', () => {
    const hook = read('scripts', 'prompt-recall-hook.mjs');
    assert.match(blockAfter(hook, 'function loadConfig()'), /return \{\};/);
    assert.match(hook, /if \(config\.proactiveRecall !== true\) \{[\s\S]{0,200}process\.exit\(0\);/);
  });

  it('the UserPromptSubmit recall hook is added by setupHooks (setup / install), not by postinstall', () => {
    const hooks = read('src', 'setup', 'settings-hooks.ts');
    assert.match(blockAfter(hooks, 'UserPromptSubmit:'), /shieldcortex hook prompt-recall/);
    assert.ok(read('src', 'setup', 'claude-md.ts').includes('setupHooks(options);'));
    const index = read('src', 'index.ts');
    assert.ok(index.includes("process.argv[2] === 'setup' || process.argv[2] === 'install'"));
    assert.ok(read('src', 'setup', 'host-table.ts').includes('await setupClaudeMd({});'));
    // postinstall seeds config but never touches Claude Code settings or hooks.
    const post = read('scripts', 'postinstall.mjs');
    assert.doesNotMatch(post, /setupHooks|settings-hooks|setupClaudeMd|claude-md|settings\.json/);
    assert.ok(blockAfter(post, 'if (isGlobal && !isCI)').includes('writeFreshInstallDefaults()'));
  });

  it('the 4.11 notice prints only after a package update from a pre-4.11.0 version', () => {
    const upd = read('src', 'cli', 'update.ts');
    const fn = blockAfter(upd, 'function maybePrint411Notice(');
    assert.match(fn, /if \(!mainUpdated \|\| !\/\^\\d\+\\\.\\d\+\\\.\\d\+\/\.test\(currentVersion\)\) return;/);
    assert.match(fn, /if \(!\(maj < 4 \|\| \(maj === 4 && min < 11\)\)\) return;/);
    assert.match(upd, /maybePrint411Notice\(fromVersion, mainUpdated\);/);
  });
});

for (const dir of HOOK_DIRS) {
  const where = dir.join('/');

  describe(`${where}/HOOK.md Auto-Memory`, () => {
    const section = oneLine(between(read(...dir, 'HOOK.md'), '## Auto-Memory', '## Requirements'));

    it('does not claim an unqualified on-by-default', () => {
      assert.doesNotMatch(section, /enabled by default/i);
    });

    it('distinguishes the unset fallback, the fresh-install write and existing configs', () => {
      assert.match(section, /only when `openclawAutoMemory` is `true`/);
      assert.match(section, /When the key is not set, or the file is missing, it is off\./);
      assert.match(section, /fresh global, non-CI `npm install -g shieldcortex`/);
      assert.match(section, /when that write succeeds/);
      assert.match(section, /Local and CI installs, and installs run with `--ignore-scripts`, do not write it/);
      assert.match(section, /An existing config file is never changed/);
    });

    it('names the hook-install prerequisite instead of implying it is automatic', () => {
      assert.match(section, /The config file does not install this hook/);
      assert.match(section, /`shieldcortex openclaw install`/);
      assert.match(section, /`shieldcortex setup`, which asks before wiring/);
    });
  });

  describe(`${where}/handler.ts proactive-recall comment`, () => {
    const fn = blockAfter(read(...dir, 'handler.ts'), 'async function isProactiveRecallEnabled()');

    it('separates the reader fallback from the fresh-install seed', () => {
      assert.doesNotMatch(fn, /Default: false since v4\.11\.0 \(opt-in\)/);
      assert.match(fn, /Unset or false → off \(opt-in since v4\.11\.0\)/);
      assert.match(fn, /fresh global, non-CI npm install/);
      assert.match(fn, /existing config is never changed/);
    });
  });
}

describe('src/cli/update.ts 4.11 boundary notice', () => {
  const fn = blockAfter(read('src', 'cli', 'update.ts'), 'function maybePrint411Notice(');

  it('keeps the migration header but drops the blanket "now OFF by default" claim', () => {
    assert.ok(fn.includes("'v4.11.0 default behaviour changes'"));
    assert.doesNotMatch(fn, /Proactive recall on prompt submit is now OFF by default/);
  });

  it('states the actual gate and that an existing config is kept', () => {
    assert.ok(fn.includes('Proactive recall on prompt submit became opt-in in 4.11: it runs only when'));
    assert.ok(fn.includes('config.json has proactiveRecall: true. An existing config is kept as it is.'));
  });
});

describe('README.md prompt-time recall', () => {
  const readme = read('README.md');
  const line = readme.split('\n').find((l) => l.startsWith('Local UI: **Overview'));

  it('names the hook prerequisite and the config gate', () => {
    assert.ok(line, 'Local UI paragraph not found');
    assert.doesNotMatch(line, /Prompt-time recall into Claude Code is on for a fresh global, non-CI install:/);
    assert.match(line, /needs two things: the Claude Code `UserPromptSubmit` hook/);
    assert.match(line, /`shieldcortex setup` adds once you agree to wire Claude Code \(or `shieldcortex install`\)/);
    assert.match(line, /and `proactiveRecall: true` in `~\/\.shieldcortex\/config\.json`/);
  });

  it('distinguishes fresh global, local/CI, existing and unset configs', () => {
    assert.match(line, /A fresh global, non-CI `npm install -g` with no config file writes one with `proactiveRecall: true`/);
    assert.match(line, /local and CI installs do not/);
    assert.match(line, /an existing config is never changed/);
    assert.match(line, /when the key is not set, recall is off/);
    assert.match(line, /The npm install wires no hook\./);
  });
});
