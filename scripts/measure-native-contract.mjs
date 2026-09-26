#!/usr/bin/env node
/**
 * ADR-002 §5C (#594) — print one measurement-record revision for the
 * `openclaw.sessions_spawn` contract, read from an OpenClaw install's shipped
 * `dist` schema and its `package.json` version string.
 *
 *   node scripts/measure-native-contract.mjs --root <openclaw install root>
 *   node scripts/measure-native-contract.mjs --root <root> --check
 *
 * `--check` exits 1 unless the record in
 * `scripts/native-contracts/openclaw-sessions-spawn.json` already carries a
 * revision for exactly this host version with exactly these fields — the
 * "re-measure, do not hand-widen" gate for the next host schema move.
 *
 * Node core only. Reads files; never executes host code, never spawns.
 */

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { measureInstalledHost } from './lib/native-contract-measure.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const RECORD_PATH = path.join(HERE, 'native-contracts', 'openclaw-sessions-spawn.json');

function usage(msg) {
  if (msg) process.stderr.write(`${msg}\n`);
  process.stderr.write('usage: measure-native-contract.mjs --root <openclaw install root> [--check]\n');
  process.exit(2);
}

function main(argv) {
  let root = null;
  let check = false;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--root') root = argv[++i];
    else if (argv[i] === '--check') check = true;
    else usage(`unknown argument ${argv[i]}`);
  }
  if (!root) usage('--root is required');
  const revision = measureInstalledHost(path.resolve(root));
  if (!check) {
    process.stdout.write(`${JSON.stringify(revision, null, 2)}\n`);
    return 0;
  }
  const record = JSON.parse(readFileSync(RECORD_PATH, 'utf8'));
  const match = (record.revisions ?? []).find((r) => r.hostVersion === revision.hostVersion);
  if (!match) {
    process.stderr.write(`no recorded revision for host ${revision.hostVersion}; measured fields: ${revision.fields.join(', ')}\n`);
    return 1;
  }
  const a = JSON.stringify([...match.fields].sort());
  const b = JSON.stringify(revision.fields);
  if (a !== b) {
    process.stderr.write(`recorded revision ${revision.hostVersion} differs from the install\n  recorded: ${a}\n  measured: ${b}\n`);
    return 1;
  }
  process.stdout.write(`record matches host ${revision.hostVersion}: ${revision.fields.length} declared fields\n`);
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    process.exit(main(process.argv.slice(2)));
  } catch (err) {
    process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  }
}
