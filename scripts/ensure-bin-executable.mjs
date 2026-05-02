#!/usr/bin/env node

import { chmodSync, existsSync, statSync } from 'fs';
import { join } from 'path';

const entrypoint = join(process.cwd(), 'dist', 'index.js');

if (!existsSync(entrypoint)) {
  console.error('[ensure-bin-executable] Missing dist/index.js. Run npm run build:ts first.');
  process.exit(1);
}

const currentMode = statSync(entrypoint).mode;
const executableMode = currentMode | 0o755;

chmodSync(entrypoint, executableMode);

