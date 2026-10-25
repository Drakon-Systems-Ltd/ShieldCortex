/**
 * Session-start launcher for the agent configuration watch (#916).
 *
 * Spawns dist/audit/agent-config-watch-runner.js fully detached (own process
 * group, stdio ignored, unref'd) so session start never waits on it. Opt out
 * with `sessionStart.agentConfigWatch: false` in ~/.shieldcortex/config.json.
 * Fails open: a missing build or a spawn error is swallowed (zeroth law —
 * ShieldCortex must never break the host agent).
 */

import { existsSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export function agentConfigWatchEnabled(config) {
  const ss = config && typeof config === 'object' ? config.sessionStart : undefined;
  return !(ss && typeof ss === 'object' && ss.agentConfigWatch === false);
}

/**
 * @param {object} config parsed ~/.shieldcortex/config.json
 * @param {{distRoot?: string, spawnImpl?: typeof spawn}} [opts] test seams
 * @returns {boolean} true when a background check was launched
 */
export function maybeSpawnAgentConfigWatch(config, opts = {}) {
  try {
    if (!agentConfigWatchEnabled(config)) return false;
    const here = dirname(fileURLToPath(import.meta.url));
    const distRoot = opts.distRoot ?? resolve(here, '..', '..', 'dist');
    const runner = resolve(distRoot, 'audit', 'agent-config-watch-runner.js');
    if (!existsSync(runner)) return false;
    const child = (opts.spawnImpl ?? spawn)(process.execPath, [runner], {
      detached: true,
      stdio: 'ignore',
      env: process.env,
    });
    child.on?.('error', () => {});
    child.unref?.();
    return true;
  } catch {
    return false;
  }
}
