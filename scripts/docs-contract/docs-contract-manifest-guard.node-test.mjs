/**
 * Self-check for scripts/check-docs-contracts.mjs (#847): the guard in front of
 * the CI "Docs contracts (node:test)" step must pass on this directory and fire
 * when a contract file drops out of the `*.node-test.mjs` glob.
 *
 * The negative cases run against throwaway copies of this directory in the OS
 * temp dir; nothing here writes to the repository. Dependency-free (node:test)
 * and NOT part of the Jest suite — run directly:
 *
 *   node --test scripts/docs-contract/docs-contract-manifest-guard.node-test.mjs
 */

import { afterEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { MANIFEST_NAME, checkDocsContracts } from '../check-docs-contracts.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const checker = path.join(here, '..', 'check-docs-contracts.mjs');

const scratch = [];
afterEach(() => {
  for (const d of scratch.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});

/** A copy of this directory's manifest and contract files in a fresh temp dir. */
function copyOfHere() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc847-contracts-'));
  scratch.push(dir);
  for (const name of fs.readdirSync(here)) fs.copyFileSync(path.join(here, name), path.join(dir, name));
  return dir;
}

function runChecker(dir) {
  const r = spawnSync(process.execPath, [checker, dir], { encoding: 'utf8' });
  return { status: r.status, out: `${r.stdout ?? ''}${r.stderr ?? ''}` };
}

describe('docs-contract manifest guard (#847)', () => {
  it('passes on this directory, and the manifest lists this self-check', () => {
    const { errors, files } = checkDocsContracts(here);
    assert.deepEqual(errors, []);
    assert.ok(files.includes(path.basename(fileURLToPath(import.meta.url))));
    assert.ok(files.length >= 6);
    const r = runChecker(here);
    assert.equal(r.status, 0, r.out);
    assert.match(r.out, new RegExp(`docs contracts: ${files.length} files match ${MANIFEST_NAME}`));
  });

  it('fails when a listed contract is renamed out of the glob', () => {
    const dir = copyOfHere();
    const victim = 'setup-target-wiring-copy.node-test.mjs';
    fs.renameSync(path.join(dir, victim), path.join(dir, 'setup-target-wiring-copy.test.mjs'));
    const { errors } = checkDocsContracts(dir);
    assert.ok(errors.some((e) => e.startsWith('setup-target-wiring-copy.test.mjs: not a docs contract file name')), errors.join('\n'));
    assert.ok(errors.some((e) => e.startsWith(`${victim}: listed in ${MANIFEST_NAME} but not present`)), errors.join('\n'));
    const r = runChecker(dir);
    assert.equal(r.status, 1, r.out);
    assert.match(r.out, /::error::docs-contract: /);
  });

  it('fails when a contract is deleted, even with no stray file left behind', () => {
    const dir = copyOfHere();
    fs.rmSync(path.join(dir, 'openclaw-hook-event-copy.node-test.mjs'));
    const { errors } = checkDocsContracts(dir);
    assert.deepEqual(errors, [`openclaw-hook-event-copy.node-test.mjs: listed in ${MANIFEST_NAME} but not present; CI would not run it`]);
    assert.equal(runChecker(dir).status, 1);
  });

  it('fails when a new contract is added without a manifest entry', () => {
    const dir = copyOfHere();
    fs.writeFileSync(path.join(dir, 'new-copy.node-test.mjs'), '');
    const { errors } = checkDocsContracts(dir);
    assert.deepEqual(errors, [`new-copy.node-test.mjs: present but not listed in ${MANIFEST_NAME}`]);
  });

  it('fails on a duplicate or malformed manifest line, and on a missing manifest', () => {
    const dir = copyOfHere();
    fs.appendFileSync(path.join(dir, MANIFEST_NAME), 'cloud-cli-watch-only-copy.node-test.mjs\nnot-a-contract.mjs\n');
    const { errors } = checkDocsContracts(dir);
    assert.ok(errors.some((e) => /"cloud-cli-watch-only-copy\.node-test\.mjs" is listed twice/.test(e)), errors.join('\n'));
    assert.ok(errors.some((e) => /"not-a-contract\.mjs" is not a docs contract file name/.test(e)), errors.join('\n'));

    const bare = copyOfHere();
    fs.rmSync(path.join(bare, MANIFEST_NAME));
    assert.ok(checkDocsContracts(bare).errors.some((e) => e.startsWith(`${MANIFEST_NAME}: cannot read`)));
    assert.equal(runChecker(bare).status, 1);
  });
});
