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

import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const version = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version;
const skillDir = join(root, 'skills', 'shieldcortex');

function clawhub(args, { capture = false } = {}) {
  return execFileSync('clawhub', args, { stdio: capture ? 'pipe' : 'inherit', encoding: 'utf8' });
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
