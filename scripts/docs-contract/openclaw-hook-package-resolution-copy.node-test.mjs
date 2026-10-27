/**
 * Docs/source/runtime contract (#946): what SKILL.md says the npm-shipped
 * cortex-memory hook runs, checked against the hook's runtime.
 *
 * hooks/openclaw/cortex-memory/runtime.mjs starts mcporter as
 * `npx mcporter call --stdio <server> …` and, with no configured `binaryPath`
 * and no `shieldcortex` on PATH, uses `npx -y shieldcortex` as `<server>`. Both
 * can make npm fetch a package from the registry. The v5.15.1 SKILL.md said the
 * hook "never downloads or installs a package" and "stays inert"; this contract
 * pins the corrected copy and fails if the old promise comes back.
 *
 * The runtime check spawns a child node process with PATH holding only a fake
 * `npx` that records its argv and exits; nothing reaches npm, a registry or a
 * provider, and the config path points into a temp dir, never the home
 * directory. Dependency-free (node:test) and NOT part of the Jest suite:
 *
 *   node --test scripts/docs-contract/openclaw-hook-package-resolution-copy.node-test.mjs
 */

import { afterEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const read = (...rel) => fs.readFileSync(path.join(REPO_ROOT, ...rel), 'utf8');
const RUNTIME = path.join(REPO_ROOT, 'hooks', 'openclaw', 'cortex-memory', 'runtime.mjs');

const oneLine = (s) => s.replace(/\s+/g, ' ');

/** The SKILL.md bullet that starts with `**Subprocess execution`. */
function subprocessBullet(md) {
  const line = md.split('\n').find((l) => l.startsWith('- **Subprocess execution'));
  assert.ok(line, 'SKILL.md has no "Subprocess execution" bullet');
  return oneLine(line);
}

const scratch = [];
afterEach(() => {
  for (const d of scratch.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});

describe('runtime.mjs source facts the copy describes', () => {
  const src = read('hooks', 'openclaw', 'cortex-memory', 'runtime.mjs');

  it('mcporter is always started through npx, with no --yes/--no', () => {
    assert.match(src, /const cmdArgs = \["mcporter", "call", "--stdio", serverCmd, tool, "--args", JSON\.stringify\(args\)\];/);
    assert.match(src, /execFile\("npx", cmdArgs, \{/);
    assert.doesNotMatch(src, /"--yes"|"--no"/);
  });

  it('server resolution order is binaryPath, then `which shieldcortex`, then npx -y shieldcortex', () => {
    const a = src.indexOf('if (config?.binaryPath) {');
    const b = src.indexOf('execFileSync("which", ["shieldcortex"]');
    const c = src.indexOf('resolvedServerCmd = "npx -y shieldcortex";');
    assert.ok(a > -1 && b > a && c > b, `order: binaryPath ${a}, which ${b}, npx ${c}`);
  });
});

describe('runtime behaviour with nothing installed (fake npx, no network)', () => {
  it('calls npx mcporter with `npx -y shieldcortex` as the server', { skip: process.platform === 'win32' }, () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc946-'));
    scratch.push(dir);
    const bin = path.join(dir, 'bin');
    fs.mkdirSync(bin);
    const argvLog = path.join(dir, 'npx-argv');
    // Only this fake npx is on PATH: no `which`, no shieldcortex, no mcporter.
    fs.writeFileSync(path.join(bin, 'npx'), `#!/bin/sh\nfor a in "$@"; do printf '%s\\n' "$a"; done > "${argvLog}"\nprintf 'ok\\n'\n`, { mode: 0o755 });

    const script = `
      const { createOpenClawRuntime } = await import(${JSON.stringify(pathToFileURL(RUNTIME).href)});
      const rt = createOpenClawRuntime({ configPath: ${JSON.stringify(path.join(dir, 'absent', 'config.json'))} });
      const out = await rt.callCortex('remember', { title: 't' });
      process.stdout.write('RESULT ' + JSON.stringify({ server: await rt.resolveServerCmd(), out }) + '\\n');
    `;
    const r = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
      encoding: 'utf8',
      env: { PATH: bin, HOME: dir },
      timeout: 20000,
    });
    assert.equal(r.status, 0, `${r.stdout}\n${r.stderr}`);
    // The runtime logs its resolution ("Falling back to npx -y shieldcortex") to stdout too.
    assert.match(r.stdout, /Falling back to npx -y shieldcortex/);
    const result = r.stdout.split('\n').find((l) => l.startsWith('RESULT '));
    assert.ok(result, r.stdout);
    assert.deepEqual(JSON.parse(result.slice('RESULT '.length)), { server: 'npx -y shieldcortex', out: 'ok' });
    assert.deepEqual(fs.readFileSync(argvLog, 'utf8').trimEnd().split('\n'), [
      'mcporter', 'call', '--stdio', 'npx -y shieldcortex', 'remember', '--args', '{"title":"t"}',
    ]);
  });
});

describe('skills/shieldcortex/SKILL.md subprocess disclosure', () => {
  const md = read('skills', 'shieldcortex', 'SKILL.md');
  const bullet = subprocessBullet(md);

  it('no longer promises local binaries only / no downloads / inert when absent', () => {
    assert.doesNotMatch(oneLine(md), /never downloads or installs a package/);
    assert.doesNotMatch(bullet, /only runs binaries it finds on `PATH`/);
    assert.doesNotMatch(bullet, /stays inert/);
  });

  it('discloses npx mcporter and its conditional registry fetch', () => {
    assert.match(bullet, /\*\*Subprocess execution and package resolution\.\*\*/);
    assert.match(bullet, /always starts `mcporter` through `npx` \(`npx mcporter call --stdio <server> …`\) without `--yes` or `--no`/);
    assert.match(bullet, /otherwise npm can download `mcporter` from the npm registry and run it/);
  });

  it('discloses the server resolution order and the npx -y shieldcortex fallback', () => {
    assert.match(bullet, /uses the configured `binaryPath` \(from `~\/\.shieldcortex\/config\.json`, or `\$SHIELDCORTEX_CONFIG_DIR\/config\.json` when set\) only if that path is accessible, else a `shieldcortex` found on `PATH`, else `npx -y shieldcortex`/);
    assert.doesNotMatch(bullet, /when that file exists/);
    assert.match(bullet, /which can download the `shieldcortex` package from the npm registry and run it/);
    assert.match(bullet, /`npm install -g shieldcortex mcporter`/);
  });
});
