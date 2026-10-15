#!/usr/bin/env node
// scripts/clawhub-sync.mjs
//
// Publish the ShieldCortex skill to ClawHub at the current package.json version,
// and/or verify that ClawHub actually serves it.
//
//   node scripts/clawhub-sync.mjs                    publish if needed, then verify
//   node scripts/clawhub-sync.mjs --check            READ-ONLY verify, never publishes
//   node scripts/clawhub-sync.mjs --check --wait 30  poll up to 30 min for promotion
//
// Exit codes (issue #200 — a check that cannot fail is a decoration):
//   0  ClawHub serves this version
//   2  version uploaded but not promoted (moderation queue), or submitted and
//      reported by the CLI as pending security scans — no republish needed
//   1  version absent from ClawHub — the publish did not land
//   3  ClawHub state could not be read — nothing proven either way
//
// Why --check is read-only: the old script published whenever it found drift, so
// any "verify" loop could republish. A verification path must not mutate the
// thing it verifies.
//
// Auth: if CLAWHUB_TOKEN is set it logs in (headless/CI); otherwise it assumes
// `clawhub login` was already run locally.

import { readFileSync, existsSync } from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { readLatestVersion, readVersionList, reportsPendingSubmission, diagnose, describeState, exitCodeFor } from './lib/clawhub-state.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const version = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version;
const skillDir = join(root, 'skills', 'shieldcortex');

const argv = process.argv.slice(2);
const CHECK_ONLY = argv.includes('--check');
const waitIdx = argv.indexOf('--wait');
// Measured: 4.47.36 promoted ~26 min after upload, so a 10-minute bound would
// false-fail a healthy release. Default generously; override for a fast check.
const WAIT_MINUTES = waitIdx >= 0 ? Number(argv[waitIdx + 1] ?? 30) : 0;
const POLL_INTERVAL_MS = 30_000;

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

/**
 * Run `clawhub publish`, echo its output, and return that output so the caller
 * can read the submission result. Inherited stdio used to discard it — the line
 * saying the upload was pending security scans never reached the verdict.
 */
function clawhubPublish(args) {
  const res = spawnSync(CLAWHUB_BIN, args, { stdio: ['inherit', 'pipe', 'pipe'], encoding: 'utf8' });
  if (res.stdout) process.stdout.write(res.stdout);
  if (res.stderr) process.stderr.write(res.stderr);
  if (res.error || res.status !== 0) {
    // Code/status only: the error object carries argv, which is not needed here.
    const why = res.error ? res.error.code ?? 'spawn error' : `exit ${res.status ?? res.signal}`;
    console.error(`[clawhub-sync] ❌ clawhub publish failed (${why}).`);
    process.exit(1);
  }
  return `${res.stdout ?? ''}\n${res.stderr ?? ''}`;
}

function clawhubCliVersion() {
  try {
    return execFileSync(CLAWHUB_BIN, ['-V'], { encoding: 'utf8' }).trim().match(/[0-9]+\.[0-9]+\.[0-9]+/)?.[0] || '?';
  } catch {
    return '?';
  }
}

/** One structured read of ClawHub state. Never mutates. */
function fetchState() {
  try {
    const out = clawhub(['inspect', 'shieldcortex', '--versions', '--limit', '50', '--json'], { capture: true });
    const json = JSON.parse(out);
    return { latest: readLatestVersion(json), versions: readVersionList(json) };
  } catch (err) {
    // A read failure is NOT evidence of a good state — report it as such rather
    // than letting an empty read look like "absent" for the wrong reason.
    console.warn(`[clawhub-sync] ⚠️ could not read ClawHub state: ${err?.message ?? err}`);
    return { latest: '', versions: [], readFailed: true };
  }
}

function sleep(ms) {
  // Synchronous sleep keeps this script dependency-free and linear.
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
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

let { latest, versions, readFailed } = fetchState();
let submitted = false;
console.log(`[clawhub-sync] ClawHub: '${latest || 'none'}'  package: '${version}'${CHECK_ONLY ? '  (read-only check)' : ''}`);

// Publish only when asked to AND only when the version is genuinely missing.
// A 'pending' version already exists server-side; republishing it just burns a
// version number for an "already exists" error. An unreadable state proves
// nothing is missing, so it does not publish either.
if (!CHECK_ONLY) {
  const state = diagnose({ latest, versions, readFailed, target: version });
  if (state === 'unknown') {
    console.error(`[clawhub-sync] ${describeState({ state, latest, target: version })}`);
    process.exit(exitCodeFor(state));
  }
  if (state === 'synced') {
    console.log(`[clawhub-sync] ✅ Already synced at ${version} — nothing to do.`);
    process.exit(0);
  }
  if (state === 'pending') {
    console.log(`[clawhub-sync] ${version} is already uploaded and awaiting promotion — not republishing.`);
  } else {
    console.log(`[clawhub-sync] Publishing skill to ClawHub @ ${version}…`);
    const output = clawhubPublish([
      'publish', skillDir,
      '--slug', 'shieldcortex',
      '--name', 'ShieldCortex',
      '--version', version,
      '--changelog', `Sync from npm publish v${version}`,
    ]);
    submitted = reportsPendingSubmission(output, version);
    if (submitted) {
      console.log(`[clawhub-sync] CLI reports ${version} submitted, pending security scans — not public until ClawHub serves it.`);
    }
  }
}

// Verify — polling if asked. Exits as soon as ClawHub serves the version.
const deadline = Date.now() + WAIT_MINUTES * 60_000;
const startedAt = Date.now();
let state = diagnose({ latest, versions, readFailed, submitted, target: version });

while (state !== 'synced' && Date.now() < deadline) {
  sleep(POLL_INTERVAL_MS);
  ({ latest, versions, readFailed } = fetchState());
  state = diagnose({ latest, versions, readFailed, submitted, target: version });
  if (state !== 'synced') {
    const waitedMin = Math.round((Date.now() - startedAt) / 60_000);
    console.log(`[clawhub-sync] …still '${latest || 'none'}' (${state}) after ${waitedMin}m`);
  }
}

const message = describeState({ state, latest, target: version, waitedMs: Date.now() - startedAt, submitted });
if (state === 'synced') {
  console.log(`[clawhub-sync] ${message}`);
} else {
  console.error(`[clawhub-sync] ${message}`);
}
process.exit(exitCodeFor(state));
