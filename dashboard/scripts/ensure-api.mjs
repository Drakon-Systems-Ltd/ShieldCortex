#!/usr/bin/env node
/**
 * Ensures the API server is running before starting the dashboard.
 * Automatically spawns the API if it's not reachable.
 */

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = join(__dirname, '..', '..');

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';
const HEALTH_ENDPOINT = `${API_URL}/api/health`;
const MAX_WAIT_MS = 10000;
const POLL_INTERVAL_MS = 500;

async function checkApiHealth() {
  try {
    const response = await fetch(HEALTH_ENDPOINT, {
      signal: AbortSignal.timeout(2000)
    });
    return response.ok;
  } catch {
    return false;
  }
}

async function waitForApi(timeoutMs) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (await checkApiHealth()) {
      return true;
    }
    await new Promise(r => setTimeout(r, POLL_INTERVAL_MS));
  }
  return false;
}

async function main() {
  console.log('[Dashboard] Checking if API server is running...');

  if (await checkApiHealth()) {
    console.log('[Dashboard] API server is already running ✓');
    process.exit(0);
  }

  console.log('[Dashboard] API server not detected, starting it...');

  // Spawn API server in background (fully detached)
  // Using 'ignore' for all stdio to prevent SIGPIPE when parent exits
  const apiProcess = spawn('npm', ['run', 'dev:api'], {
    cwd: rootDir,
    detached: true,
    stdio: 'ignore',
    shell: true,
  });

  // Fully detach - allow parent to exit without killing child
  apiProcess.unref();

  // Wait for API to be ready
  console.log('[Dashboard] Waiting for API server to be ready...');
  const ready = await waitForApi(MAX_WAIT_MS);

  if (ready) {
    console.log('[Dashboard] API server is ready ✓');
    process.exit(0);
  } else {
    console.error('[Dashboard] API server failed to start within timeout');
    process.exit(1);
  }
}

main();
