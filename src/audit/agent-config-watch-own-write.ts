/**
 * Own-write rebaseline for the agent configuration watch (#916).
 *
 * ShieldCortex's installer/update/doctor rewrite their own hook entries in
 * watched files. Wrapping that write here records the new baseline so it does
 * not alert. Fail-safe in both directions: it never throws into the writer, and
 * it only advances the baseline when the file matched the baseline BEFORE the
 * write, so a foreign edit that landed earlier still alerts at the next check.
 *
 * The write callback returns the exact text it wrote, and the new baseline is
 * derived from those bytes (#928 round 1), not from re-reading the file: a
 * same-user writer that races in after our write is not recorded as ours, it
 * alerts at the next check. A callback that returns nothing advances nothing.
 *
 * `home` defaults to `agentConfigWatchHome()`, the same home the runner and the
 * doctor check use, so the rebaseline always lands in the state file the check
 * reads. Callers must not derive it from OPENCLAW_HOME or similar.
 */

import fs from 'fs';
import path from 'path';
import {
  agentConfigWatchEnabled,
  agentConfigWatchHome,
  loadAgentConfigStateChecked,
  sameSnapshot,
  saveAgentConfigState,
  sectionVersionsFor,
  snapshotContent,
  snapshotFile,
  watchedEntryForPath,
  type FileSnapshot,
} from './agent-config-watch.js';

function readConfig(home: string): unknown {
  try { return JSON.parse(fs.readFileSync(path.join(home, '.shieldcortex', 'config.json'), 'utf-8')); } catch { return {}; }
}

export function withOwnConfigWrite(filePath: string, write: () => string, home: string = agentConfigWatchHome()): void {
  let pre: FileSnapshot | undefined;
  let entry: ReturnType<typeof watchedEntryForPath>;
  try {
    if (agentConfigWatchEnabled(readConfig(home))) {
      const loaded = loadAgentConfigStateChecked(home);
      // An untrusted baseline is left for the check to report, never re-signed here.
      if (loaded.integrity === 'ok' && loaded.state.initialised) {
        entry = watchedEntryForPath(filePath, home, loaded.state.roots);
        if (entry) pre = snapshotFile(filePath, entry.spec);
      }
    }
  } catch { pre = undefined; }

  const written = write(); // a failing write propagates exactly as before

  try {
    if (!entry || !pre || typeof written !== 'string') return;
    const fresh = loadAgentConfigStateChecked(home);
    if (fresh.integrity !== 'ok') return;
    const baseline = fresh.state.files[entry.file];
    if (baseline === undefined) return; // not baselined yet: the next run baselines silently
    // Same semantic equality as the check: a harmless key reorder is not drift.
    if (!sameSnapshot(baseline, pre)) return; // foreign drift: leave it to alert
    fresh.state.files[entry.file] = snapshotContent(written, entry.spec);
    fresh.state.sectionVersions = { ...(fresh.state.sectionVersions ?? {}), [entry.file]: sectionVersionsFor(entry.spec) };
    saveAgentConfigState(home, fresh.state);
  } catch { /* never break the installer */ }
}
