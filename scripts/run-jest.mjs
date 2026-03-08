#!/usr/bin/env node

import { spawn } from 'child_process';
import path from 'path';

const jestBin = path.join(process.cwd(), 'node_modules', 'jest', 'bin', 'jest.js');

function sanitizeNodeOptions(value) {
  if (!value) return undefined;

  const cleaned = value
    .replace(/(?:^|\s)--localstorage-file(?:=\S+)?(?=\s|$)/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  return cleaned || undefined;
}

const env = { ...process.env, SHIELDCORTEX_SKIP_EMBEDDINGS: '1' };
delete env.ELECTRON_RUN_AS_NODE;

const sanitizedNodeOptions = sanitizeNodeOptions(env.NODE_OPTIONS);
if (sanitizedNodeOptions) {
  env.NODE_OPTIONS = sanitizedNodeOptions;
} else {
  delete env.NODE_OPTIONS;
}

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
