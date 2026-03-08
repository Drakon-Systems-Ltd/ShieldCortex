#!/usr/bin/env node

import { spawn } from 'child_process';
import path from 'path';

const jestBin = path.join(process.cwd(), 'node_modules', 'jest', 'bin', 'jest.js');
const localStorageFile = path.join(process.cwd(), '.jest-localstorage');

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
