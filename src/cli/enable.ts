/**
 * `shieldcortex enable|disable [feature] [options]` (#275).
 *
 * The command `doctor` could not previously point at. With no feature named it
 * prints the whole registry and each toggle's current state, so "what can I turn
 * on, and what is on right now?" is one command rather than a config-file
 * archaeology session.
 *
 * Writes go through the signing config writer (see toggles.ts) — an operator
 * should never have to hand-edit `config.json`, because that trips the integrity
 * check and silently forces strict mode.
 */

import { applyToggle, listToggles, type ToggleOptions } from './toggles.js';

function pad(s: string, n: number): string {
  return s.length >= n ? s : s + ' '.repeat(n - s.length);
}

function printRegistry(): void {
  const rows = listToggles();
  const width = Math.max(...rows.map((r) => r.id.length));
  console.log('\nShieldCortex features\n');
  for (const r of rows) {
    const mark = r.state === 'on' ? '●' : r.state === 'off' ? '○' : '?';
    console.log(`  ${mark} ${pad(r.id, width)}  ${pad(r.state, 7)} ${r.summary}`);
    if (r.detail) console.log(`    ${' '.repeat(width)}          ${r.detail}`);
  }
  console.log('\n  ● on   ○ off   ? unknown\n');
  console.log('  shieldcortex enable <feature>     shieldcortex disable <feature>\n');
  console.log('  Options: --openclaw | --webhook <url> [--secret <key>]   (notify)');
  console.log('           --warn-only                                     (action-guard)\n');
  console.log('  Settings live in ~/.shieldcortex/config.json — do not edit it by hand;');
  console.log('  these commands re-sign it, a manual edit reads back as tampering.\n');
}

/** `--flag value` / `--flag` parsing, deliberately tiny — no dependency. */
function parseOptions(args: string[]): ToggleOptions {
  const opts: ToggleOptions = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--openclaw') opts.openclaw = true;
    else if (a === '--no-openclaw') opts.openclaw = false;
    else if (a === '--warn-only') opts.warnOnly = true;
    else if (a === '--webhook') opts.webhookUrl = args[++i];
    else if (a === '--secret') opts.webhookSecret = args[++i];
  }
  return opts;
}

export function handleToggleCommand(argv: string[], on: boolean): void {
  const verb = on ? 'enable' : 'disable';
  const feature = argv.find((a) => !a.startsWith('--'));

  if (!feature) {
    printRegistry();
    return;
  }

  const result = applyToggle(feature, on, parseOptions(argv));
  if (!result.ok) {
    console.error(`✗ ${result.message}`);
    console.error(`\n  Run \`shieldcortex ${verb}\` with no arguments to see every feature and its state.`);
    process.exitCode = 1;
    return;
  }

  console.log(`✓ ${result.message}`);
  for (const note of result.notes) console.log(`  → ${note}`);

  const after = listToggles().find((t) => t.id === feature);
  if (after) console.log(`  now: ${after.state}${after.detail ? ` (${after.detail})` : ''}`);
}
