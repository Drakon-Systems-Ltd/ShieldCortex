/**
 * #654 B11 test fixture. Tests load it with `node --import <this file>?…` into
 * a spawned, unchanged scripts/stop-hook.mjs; nothing in the shipped hook
 * refers to it. It wraps node:fs so that the `read`-th readSync on the
 * `open`-th open of the file whose basename is `name` throws EIO: a mid-stream
 * failure in one pass (the hook opens each realtime candidate once per pass,
 * receipts first), driven without any switch in production code.
 *
 * Parameters come from this module's own URL query, never the environment.
 */
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { basename } from 'node:path';

const params = new URL(import.meta.url).searchParams;
const name = params.get('name');
const open = Number(params.get('open'));
const failOnRead = Number(params.get('read'));
if (!name || !(open > 0) || !(failOnRead > 0)) {
  throw new Error('audit-read-fault preload: name, open and read are required');
}

const realOpenSync = fs.openSync;
const realReadSync = fs.readSync;
const realCloseSync = fs.closeSync;
const armed = new Map();
let opens = 0;

fs.openSync = function openSync(path, ...rest) {
  const fd = realOpenSync.call(fs, path, ...rest);
  if (typeof path === 'string' && basename(path) === name) {
    opens += 1;
    if (opens === open) armed.set(fd, 0);
  }
  return fd;
};

fs.readSync = function readSync(fd, ...rest) {
  if (armed.has(fd)) {
    const reads = armed.get(fd) + 1;
    armed.set(fd, reads);
    if (reads === failOnRead) throw Object.assign(new Error('fixture: EIO mid-stream'), { code: 'EIO' });
  }
  return realReadSync.call(fs, fd, ...rest);
};

fs.closeSync = function closeSync(fd) {
  armed.delete(fd);
  return realCloseSync.call(fs, fd);
};

// The hook binds `import { openSync, readSync, closeSync } from 'fs'`; this
// pushes the wrappers into those live ESM bindings before it is loaded.
syncBuiltinESMExports();
