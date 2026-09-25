import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeAll, beforeEach, describe, expect, it } from '@jest/globals';
import { requireFreshBuiltArtefacts } from '../../__tests__/built-artefact-freshness.js';

/**
 * #574 / #576 round 4 blocker 4 — the window a SIGKILL lands in.
 *
 * Replacing an installed directory is two `rename(2)` calls, and between them
 * the host has NO installed copy. Everything this code says about that state —
 * the backup it left, the installer that puts the packaged set back — was said
 * by RETURNING it, through a catch and a rollback the caller then reports. A
 * terminated process reaches none of that. The operator was left with an empty
 * `plugins/` directory, a `backups/` entry they had no reason to look in, and
 * nothing on screen; and since round 4 the next refresh deliberately SKIPS an
 * absent integration, so no later run tells them either.
 *
 * So the notice is written to fd 2 with `fs.writeSync` BEFORE the first rename.
 * That is the only report that survives `SIGKILL`, and this suite is the only
 * way to prove it does: the reviewer's attempted probe could not be run under
 * Jest (a worker that kills itself takes the run with it), so the kill happens
 * in a SPAWNED node child driving the BUILT `stageAndPublish`, and the parent
 * reads the child's captured stderr after it dies.
 *
 * Drives `dist/`, so it asserts the build is current rather than building one
 * (see `built-artefact-freshness.ts` — building from a worker deletes `dist/`
 * out from under every sibling worker).
 */
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const SOURCE = path.join(repoRoot, 'src', 'setup', 'host-swap.ts');
const ARTEFACT = path.join(repoRoot, 'dist', 'setup', 'host-swap.js');
const STAMP = '2026-09-24T12-34-56-789Z';

/**
 * The child: publish a packaged copy over an installed one, and die the
 * instant the first rename returns — the target moved away, the new set not
 * yet in place. `process.kill(self, SIGKILL)` is not catchable and does not
 * return, so nothing after it runs and no exit handler fires.
 */
const CHILD = `
import fs from 'fs';
import path from 'path';
import { pathToFileURL } from 'url';

const [, , artefact, root, reinstall] = process.argv;
const { stageAndPublish } = await import(pathToFileURL(artefact).href);

const target = path.join(root, 'plugins', 'shieldcortex');
fs.mkdirSync(target, { recursive: true });
fs.writeFileSync(path.join(target, 'plugin.yaml'), 'installed\\n');

let renames = 0;
const realRename = fs.renameSync;
fs.renameSync = (from, to) => {
  const done = realRename(from, to);
  renames += 1;
  if (renames === 1) process.kill(process.pid, 'SIGKILL');
  return done;
};

stageAndPublish({
  bound: root,
  target,
  stagingParent: root,
  backupsRoot: path.join(root, 'backups'),
  stamp: '${STAMP}',
  stagingPrefix: '.shieldcortex-staging',
  backupPrefix: 'shieldcortex',
  stage: (dir) => {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'plugin.yaml'), 'packaged\\n');
  },
  verify: () => null,
  reinstallCommand: reinstall,
});
process.stdout.write('SURVIVED\\n');
`;

let root: string;
let probe: string;

beforeAll(() => {
  requireFreshBuiltArtefacts({ repoRoot, sources: [SOURCE], artefacts: [ARTEFACT] });
});

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-kill-swap-'));
  probe = path.join(root, 'kill-probe.mjs');
  fs.writeFileSync(probe, CHILD);
});

afterEach(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

describe('a process killed between the two renames has already said where the copy went', () => {
  for (const command of ['shieldcortex hermes install', 'shieldcortex openclaw install']) {
    const reinstall = `run \`${command}\``;
    it(`names the backup and \`${command}\` on stderr before the target moves`, () => {
      const child = spawnSync(process.execPath, [probe, ARTEFACT, root, reinstall], {
        encoding: 'utf-8',
        timeout: 60_000,
      });

      // It really was killed, in the window, and nothing after the rename ran.
      expect(child.signal).toBe('SIGKILL');
      expect(child.status).toBeNull();
      expect(child.stdout).not.toContain('SURVIVED');

      const target = path.join(root, 'plugins', 'shieldcortex');
      const backup = path.join(root, 'backups', `shieldcortex-preupdate-${STAMP}`, 'shieldcortex');
      // The host state a power cut leaves: no installed copy, the previous one
      // in `backups/`. Nothing will repair this, so the line below is the
      // operator's only pointer at it.
      expect(fs.existsSync(target)).toBe(false);
      expect(fs.readFileSync(path.join(backup, 'plugin.yaml'), 'utf-8')).toBe('installed\n');

      // The three facts the notice has to carry, on the one stream that
      // survived: what moved, exactly where it is, and what puts it back.
      expect(child.stderr).toContain(target);
      expect(child.stderr).toContain(backup);
      expect(child.stderr).toContain(command);
    });
  }
});
