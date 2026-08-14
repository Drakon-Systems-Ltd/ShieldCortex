#!/usr/bin/env node
/**
 * Action Guard precision gate (#182) plus optional three-plane parity.
 *
 *   npm run guard:precision           — core evaluateToolCall corpus
 *   npm run guard:precision -- --planes
 *       — same corpus, plus Claude hook / OpenClaw interceptor / Hermes
 *         REST must return the same decision + signal set. Drift fails.
 */
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const planes = process.argv.slice(2).includes('--planes');
const files = ['src/__tests__/guard-precision-corpus.test.ts'];
if (planes) files.push('src/__tests__/guard-precision-planes.test.ts');

const child = spawn(process.execPath, ['scripts/run-jest.mjs', ...files], {
  cwd: repo,
  stdio: 'inherit',
});
child.on('exit', (code) => process.exit(code ?? 1));
child.on('error', (err) => {
  console.error(err);
  process.exit(1);
});
