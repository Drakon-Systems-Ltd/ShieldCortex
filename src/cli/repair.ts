/**
 * `shieldcortex repair` — fix a broken install in place.
 *
 * Today it heals the better-sqlite3 native binding (the #1 post-update breakage
 * on arm64 / newer-than-prebuilt Node): verify → rebuild in the install dir →
 * re-verify, then print the exact remediation if it still can't load.
 */

import { ensureNativeBinding } from '../setup/native-binding.js';

const isTTY = Boolean(process.stdout.isTTY);
const c = (code: string, s: string) => (isTTY ? `\x1b[${code}m${s}\x1b[0m` : s);

export async function runRepair(): Promise<void> {
  process.stdout.write(`\n  ${c('35', '◆')} ${c('1', 'ShieldCortex repair')}\n\n`);
  process.stdout.write(`  ${c('90', 'Checking the native database engine (better-sqlite3)…')}\n`);

  const r = await ensureNativeBinding();

  if (r.status === 'ok') {
    process.stdout.write(`  ${c('32', '✓')}  Database engine: healthy (no rebuild needed)\n\n`);
    return;
  }
  if (r.status === 'healed') {
    process.stdout.write(`  ${c('32', '✓')}  Database engine: rebuilt and verified\n`);
    process.stdout.write(`  ${c('90', 'Restart Claude Code / the OpenClaw gateway so running processes reload it.')}\n\n`);
    return;
  }

  // failed
  process.stdout.write(`  ${c('31', '✗')}  Database engine: still cannot load after a rebuild\n`);
  if (r.error) process.stdout.write(`     ${c('90', r.error.split('\n')[0])}\n`);

  // Surface the REAL build error, not just the load failure. `rebuildOutput` is
  // from the forced `--build-from-source` attempt, so it carries the actual
  // compiler/node-gyp output (e.g. "g++: command not found") — the bit that
  // tells the user WHY, instead of npm's misleading "rebuilt successfully".
  const buildTail = (r.rebuildOutput ?? '').trim();
  if (buildTail) {
    const lines = buildTail.split('\n').slice(-12);
    process.stdout.write(`\n  ${c('90', 'Build output (last lines):')}\n`);
    for (const line of lines) process.stdout.write(`     ${c('90', line)}\n`);
  }

  process.stdout.write(`\n  ${c('1', 'Fix it manually:')}\n`);
  for (const line of (r.remediation ?? '').split('\n')) {
    process.stdout.write(`     ${c('33', line)}\n`);
  }
  process.stdout.write('\n');
  process.exitCode = 1;
}
