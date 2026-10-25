/**
 * Own-write rebaseline for the agent configuration watch (#916).
 *
 * ShieldCortex's installer/update/doctor rewrite their own hook entries in
 * watched files. Wrapping that write here records the new baseline so it does
 * not alert. Fail-safe in both directions: it never throws into the writer, and
 * it only advances the baseline when the file matched the baseline BEFORE the
 * write, so a foreign edit that landed earlier still alerts at the next check.
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  agentConfigWatchEnabled,
  loadAgentConfigState,
  saveAgentConfigState,
  snapshotFile,
  specForPath,
  type FileSnapshot,
} from './agent-config-watch.js';

function readConfig(home: string): unknown {
  try { return JSON.parse(fs.readFileSync(path.join(home, '.shieldcortex', 'config.json'), 'utf-8')); } catch { return {}; }
}

export function withOwnConfigWrite(filePath: string, write: () => void, home: string = os.homedir()): void {
  let pre: FileSnapshot | undefined;
  let state: ReturnType<typeof loadAgentConfigState> | undefined;
  let spec: ReturnType<typeof specForPath>;
  try {
    if (agentConfigWatchEnabled(readConfig(home))) {
      state = loadAgentConfigState(home);
      spec = specForPath(filePath, home, state.roots);
      if (spec && state.initialised) pre = snapshotFile(filePath, spec);
    }
  } catch { pre = undefined; }

  write(); // a failing write propagates exactly as before

  try {
    if (!state || !spec || !pre) return;
    const key = path.resolve(filePath);
    const fresh = loadAgentConfigState(home);
    const baseline = fresh.files[key];
    if (baseline === undefined) return; // not baselined yet: the next run baselines silently
    if (JSON.stringify(baseline) !== JSON.stringify(pre)) return; // foreign drift: leave it to alert
    fresh.files[key] = snapshotFile(filePath, spec);
    saveAgentConfigState(home, fresh);
  } catch { /* never break the installer */ }
}
