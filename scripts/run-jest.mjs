#!/usr/bin/env node

import { spawn, spawnSync } from 'child_process';
import { existsSync, readdirSync, statSync } from 'fs';
import path from 'path';

const jestBin = path.join(process.cwd(), 'node_modules', 'jest', 'bin', 'jest.js');
const localStorageFile = path.join(process.cwd(), '.jest-localstorage');

// ── The build pre-step (#501) ───────────────────────────────────────────────
//
// Several suites drive the BUILT artefacts rather than the TypeScript sources —
// the two #501 policy-lock suites, the hook-package fixture, the native
// import-graph gate, the guard precision planes. They used to differ on what to
// do about a stale build: most asserted and failed with "run `npm run build:ts`
// first", but `built-artefact-freshness.ts` briefly ran the build itself, from
// inside a Jest worker. `build:ts` starts with `rm -rf dist`, Jest runs workers
// in parallel, and the result was that an ordinary `npm test` after any edit
// deleted `dist/` out from under every sibling worker — reproducibly failing 45
// tests in `embed-shutdown-noise`, a suite with nothing to do with the change.
//
// So the build happens HERE: once, serially, before a single worker exists.
// The suites keep their assertions, which is what makes a bare `jest`
// invocation (no build) fail with an honest message instead of a mystery.
const SOURCE_DIRS = ['src', 'plugins/openclaw'];
const BUILT_ENTRIES = ['dist/index.js', 'plugins/openclaw/dist/index.js'];
const SOURCE_EXT = /\.(?:ts|mts|cts)$/;

function newestSourceMtime(dir, acc = { ms: -Infinity }) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return acc;
  }
  for (const e of entries) {
    if (e.name === 'node_modules' || e.name === 'dist' || e.name.startsWith('.')) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      newestSourceMtime(full, acc);
      continue;
    }
    if (!SOURCE_EXT.test(e.name)) continue;
    try {
      const ms = statSync(full).mtimeMs;
      if (ms > acc.ms) acc.ms = ms;
    } catch { /* raced with an editor — ignore */ }
  }
  return acc;
}

function buildIsStale(cwd) {
  for (const rel of BUILT_ENTRIES) {
    if (!existsSync(path.join(cwd, rel))) return `${rel} is missing`;
  }
  const newest = SOURCE_DIRS.reduce(
    (ms, d) => Math.max(ms, newestSourceMtime(path.join(cwd, d)).ms),
    -Infinity,
  );
  if (newest === -Infinity) return null;
  for (const rel of BUILT_ENTRIES) {
    if (statSync(path.join(cwd, rel)).mtimeMs < newest) return `${rel} is older than the sources`;
  }
  return null;
}

function ensureBuiltArtefacts(cwd) {
  // Opt-out for a fast inner loop on suites that touch no built artefact, and
  // for CI pipelines that have already built in an earlier step.
  if (process.env.SHIELDCORTEX_SKIP_TEST_BUILD === '1') return true;
  const stale = buildIsStale(cwd);
  if (!stale) return true;
  process.stderr.write(`[run-jest] ${stale} — running \`npm run build:ts\` before starting Jest workers.\n`);
  const built = spawnSync('npm', ['run', 'build:ts'], { cwd, stdio: 'inherit' });
  if (built.status !== 0) {
    process.stderr.write('[run-jest] build failed — not starting Jest against a broken dist.\n');
    return false;
  }
  return true;
}

if (!ensureBuiltArtefacts(process.cwd())) process.exit(1);

function sanitizeNodeOptions(value) {
  if (!value) return undefined;

  const cleaned = value
    .replace(/(?:^|\s)--localstorage-file(?:=\S+)?(?=\s|$)/g, ' ')
    .replace(/(?:^|\s)--disable-warning(?:=\S+)?(?=\s|$)/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  return cleaned || undefined;
}

function appendNodeOption(existing, option) {
  return existing ? `${existing} ${option}` : option;
}

const env = { ...process.env, SHIELDCORTEX_SKIP_EMBEDDINGS: '1' };
delete env.ELECTRON_RUN_AS_NODE;

const combinedNodeOptions = [env.NODE_OPTIONS, env.npm_config_node_options]
  .filter(Boolean)
  .join(' ')
  .trim();

let sanitizedNodeOptions = sanitizeNodeOptions(combinedNodeOptions);

if (process.allowedNodeEnvironmentFlags.has('--localstorage-file')) {
  sanitizedNodeOptions = appendNodeOption(
    sanitizedNodeOptions,
    `--localstorage-file=${JSON.stringify(localStorageFile)}`,
  );
}

if (process.allowedNodeEnvironmentFlags.has('--disable-warning')) {
  sanitizedNodeOptions = appendNodeOption(sanitizedNodeOptions, '--disable-warning=ExperimentalWarning');
}

if (sanitizedNodeOptions) {
  env.NODE_OPTIONS = sanitizedNodeOptions;
} else {
  delete env.NODE_OPTIONS;
}
delete env.npm_config_node_options;

const child = spawn(
  process.execPath,
  ['--experimental-vm-modules', jestBin, ...process.argv.slice(2)],
  {
    stdio: 'inherit',
    env,
  },
);

child.on('exit', (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 1);
});
