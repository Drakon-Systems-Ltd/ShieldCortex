#!/usr/bin/env node
/**
 * Guard for the CI step "Docs contracts (node:test)" (#847).
 *
 * That step runs `node --test scripts/docs-contract/*.node-test.mjs`. A contract
 * file renamed away from the `*.node-test.mjs` pattern, or a new one added with
 * another suffix, would silently stop running while CI stayed green. This check
 * runs first and fails the step unless:
 *
 *   - every entry in scripts/docs-contract/ other than manifest.txt is named
 *     `<lowercase-name>.node-test.mjs`, and
 *   - the set of those files equals the list in scripts/docs-contract/manifest.txt
 *     (one file name per line; blank lines and `#` comments ignored; no
 *     duplicates).
 *
 * So the glob the step runs is exactly the manifest. Adding a contract means
 * adding its name to the manifest in the same change.
 *
 * Dependency-free. Usage: node scripts/check-docs-contracts.mjs [dir]
 * Exit 0 when the directory matches the manifest, 1 otherwise (each problem is
 * printed as a GitHub `::error::` line).
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const MANIFEST_NAME = 'manifest.txt';
export const CONTRACT_NAME = /^[a-z0-9][a-z0-9-]*\.node-test\.mjs$/;

/**
 * @param {string} dir the docs-contract directory
 * @returns {{ errors: string[], files: string[] }} problems found, and the
 *   contract files present (sorted)
 */
export function checkDocsContracts(dir) {
  const errors = [];
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (err) {
    return { errors: [`cannot read ${dir}: ${err.code ?? err.message}`], files: [] };
  }

  const files = [];
  for (const e of entries) {
    if (e.name === MANIFEST_NAME) continue;
    if (!e.isFile() || !CONTRACT_NAME.test(e.name)) {
      errors.push(`${e.name}: not a docs contract file name (expected <lowercase-name>.node-test.mjs); CI would not run it`);
      continue;
    }
    files.push(e.name);
  }
  files.sort();

  let manifestText;
  try {
    manifestText = fs.readFileSync(path.join(dir, MANIFEST_NAME), 'utf8');
  } catch (err) {
    errors.push(`${MANIFEST_NAME}: cannot read (${err.code ?? err.message})`);
    return { errors, files };
  }

  const listed = new Set();
  manifestText.split(/\r?\n/).forEach((raw, i) => {
    const line = raw.trim();
    if (line === '' || line.startsWith('#')) return;
    if (!CONTRACT_NAME.test(line)) {
      errors.push(`${MANIFEST_NAME}:${i + 1}: "${line}" is not a docs contract file name`);
      return;
    }
    if (listed.has(line)) {
      errors.push(`${MANIFEST_NAME}:${i + 1}: "${line}" is listed twice`);
      return;
    }
    listed.add(line);
  });

  for (const name of listed) {
    if (!files.includes(name)) errors.push(`${name}: listed in ${MANIFEST_NAME} but not present; CI would not run it`);
  }
  for (const name of files) {
    if (!listed.has(name)) errors.push(`${name}: present but not listed in ${MANIFEST_NAME}`);
  }
  if (listed.size === 0) errors.push(`${MANIFEST_NAME}: lists no contract files`);

  return { errors, files };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const dir = process.argv[2] ?? path.join(here, 'docs-contract');
  const { errors, files } = checkDocsContracts(dir);
  if (errors.length > 0) {
    for (const e of errors) console.log(`::error::docs-contract: ${e}`);
    process.exit(1);
  }
  console.log(`docs contracts: ${files.length} files match ${MANIFEST_NAME}`);
}
