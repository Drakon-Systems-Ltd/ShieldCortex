#!/usr/bin/env node
// scripts/clawhub-sync.mjs
//
// Publish the ShieldCortex skill to ClawHub at the current package.json version.
//
// Why this exists: ClawHub sync lived ONLY in .github/workflows/publish.yml, which
// fires on tag push in CI. But 4.x releases are published MANUALLY from a dev
// machine (npm tokens rotate, so CI auto-publish isn't used) — so that CI step
// never runs, and the documented "ClawHub auto-sync" silently doesn't happen for
// the actual release path. This script makes the manual flow self-sufficient:
// after `npm publish`, run `npm run release:clawhub`.
//
// Idempotent: no-ops if ClawHub is already at this version. Auth: if CLAWHUB_TOKEN
// is set it logs in (headless/CI); otherwise it assumes `clawhub login` was already
// run locally. Mirrors the publish.yml clawhub publish command exactly.

import { readFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const version = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version;
const skillDir = join(root, 'skills', 'shieldcortex');

// Resolve the clawhub binary. `npm i -g clawhub` installs to npm's global prefix
// (e.g. ~/.npm-global/bin), which is NOT always first on PATH: a stale root-owned
// system package (/usr/bin/clawhub) shadowed it, and that old client (0.6.x) trips
// ClawHub's server-side MIT-0 publish gate. Prefer the npm-global binary — the one
// `npm i -g clawhub@latest` actually updates — and fall back to PATH if absent.
function resolveClawhubBin() {
  try {
    const prefix = execFileSync('npm', ['prefix', '-g'], { encoding: 'utf8' }).trim();
    const cand = join(prefix, 'bin', 'clawhub');
    if (existsSync(cand)) return cand;
  } catch { /* npm not on PATH — fall back below */ }
  return 'clawhub';
}

const CLAWHUB_BIN = resolveClawhubBin();

function clawhub(args, { capture = false } = {}) {
  return execFileSync(CLAWHUB_BIN, args, { stdio: capture ? 'pipe' : 'inherit', encoding: 'utf8' });
}

function clawhubCliVersion() {
  try {
    return execFileSync(CLAWHUB_BIN, ['-V'], { encoding: 'utf8' }).trim().match(/[0-9]+\.[0-9]+\.[0-9]+/)?.[0] || '?';
  } catch {
    return '?';
  }
}

function clawhubVersion() {
  try {
    const out = clawhub(['inspect', 'shieldcortex'], { capture: true });
    return (out.match(/[0-9]+\.[0-9]+\.[0-9]+/) || [''])[0];
  } catch {
    return '';
  }
}

if (process.env.CLAWHUB_TOKEN) {
  clawhub(['login', '--token', process.env.CLAWHUB_TOKEN, '--no-browser']);
}

const cliVersion = clawhubCliVersion();
console.log(`[clawhub-sync] using clawhub ${cliVersion} (${CLAWHUB_BIN})`);
if (/^0\.(?:[0-9]|1[0-9]|2[0-2])\./.test(cliVersion)) {
  console.warn(
    `[clawhub-sync] ⚠️ clawhub ${cliVersion} predates 0.23 and trips the MIT-0 publish gate. ` +
    `Run \`npm i -g clawhub@latest\` (and ensure its bin dir is on PATH).`,
  );
}

const current = clawhubVersion();
console.log(`[clawhub-sync] ClawHub: '${current || 'none'}'  package: '${version}'`);

if (current === version) {
  console.log(`[clawhub-sync] ✅ Already synced at ${version} — nothing to do.`);
  process.exit(0);
}

console.log(`[clawhub-sync] Publishing skill to ClawHub @ ${version}…`);
clawhub([
  'publish', skillDir,
  '--slug', 'shieldcortex',
  '--name', 'ShieldCortex',
  '--version', version,
  '--changelog', `Sync from manual npm publish v${version}`,
]);

// Loud, non-fatal verification — a ClawHub hiccup (e.g. the MIT-0 web gate) should
// be visible, not silently masked.
const after = clawhubVersion();
if (after === version) {
  console.log(`[clawhub-sync] ✅ ClawHub synced at ${version}`);
} else {
  console.warn(
    `[clawhub-sync] ⚠️ ClawHub is at '${after}', expected '${version}'. If blocked by the ` +
    `MIT-0 web gate, publish manually at https://clawhub.ai/skills/publish (drop skills/shieldcortex, ` +
    `tick MIT-0, set version ${version}).`,
  );
  process.exitCode = 1;
}
