import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import {
  checkOpenClawRunningPluginVersion,
  parseRunningPluginVersion,
} from '../doctor.js';

/**
 * The #94-class false green: doctor's "plugin loaded" surfaces read the version
 * on DISK and green-tick it, even when the RUNNING gateway registered an older
 * build hours/days ago (live 21 Jul 2026: box ran v4.47.8 under a "v4.47.13
 * loaded" green tick). The gateway logs `[shieldcortex] vX.Y.Z registered` every
 * time it (re)starts, so the most recent such line in its journal is the version
 * actually running. This check compares running-vs-disk and refuses to claim
 * "current" when they differ or when the journal can't be read.
 *
 * The journal reader is injected so these tests never touch systemd/journald.
 */
const PLUGIN_ID = '@drakon-systems/shieldcortex-realtime';
const PKG_SUBPATH = path.join('node_modules', '@drakon-systems', 'shieldcortex-realtime');

let home: string;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-doctor-running-'));
});
afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

/** Install the realtime plugin on disk at the given version. */
function installOnDisk(diskVersion: string): void {
  const oc = path.join(home, '.openclaw');
  fs.mkdirSync(path.join(oc, 'plugins'), { recursive: true });
  const pkgDir = path.join(oc, 'npm', 'projects', 'drakon-systems-shieldcortex-realtime-abc', PKG_SUBPATH);
  fs.mkdirSync(pkgDir, { recursive: true });
  fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify({ version: diskVersion }));
  fs.writeFileSync(
    path.join(oc, 'plugins', 'installs.json'),
    JSON.stringify({ installRecords: { [PLUGIN_ID]: { version: diskVersion, installPath: pkgDir } } }),
  );
}

/** A journal transcript ending with the given registered version(s), oldest → newest. */
function journalWith(...registeredVersions: string[]): string {
  const lines = [
    'Jul 21 09:00:01 host openclaw-gateway[123]: starting gateway',
    ...registeredVersions.map(
      (v, i) =>
        `Jul 21 09:0${i}:05 host openclaw-gateway[123]: [shieldcortex] v${v} registered (llm_input + llm_output + before_tool_call + /shieldcortex-status)`,
    ),
  ];
  return lines.join('\n') + '\n';
}

describe('parseRunningPluginVersion', () => {
  it('returns the most recent registered version (last wins)', () => {
    expect(parseRunningPluginVersion(journalWith('4.47.8', '4.47.13'))).toBe('4.47.13');
  });

  it('returns null when no registration line is present', () => {
    expect(parseRunningPluginVersion('Jul 21 09:00:01 host openclaw-gateway[123]: starting gateway\n')).toBeNull();
  });

  it('parses a single registration', () => {
    expect(parseRunningPluginVersion(journalWith('4.47.8'))).toBe('4.47.8');
  });
});

describe('checkOpenClawRunningPluginVersion', () => {
  it('skips (info) when OpenClaw is not present', async () => {
    const r = await checkOpenClawRunningPluginVersion(home, { readGatewayJournal: () => ({ text: journalWith('4.47.13'), preBounded: true }), readGatewayProcessStartMs: () => 1_700_000_000_000 });
    expect(r.status).toBe('info');
    expect(r.message).toMatch(/not detected|skipped/i);
  });

  it('passes when the running version matches the on-disk version', async () => {
    installOnDisk('4.47.13');
    const r = await checkOpenClawRunningPluginVersion(home, { readGatewayJournal: () => ({ text: journalWith('4.47.8', '4.47.13'), preBounded: true }), readGatewayProcessStartMs: () => 1_700_000_000_000 });
    expect(r.status).toBe('pass');
    expect(r.message).toMatch(/4\.47\.13/);
  });

  it('warns when the running version is stale (older than on disk) — gateway restart needed', async () => {
    installOnDisk('4.47.13');
    // Gateway registered v4.47.8 at last start; disk was upgraded to v4.47.13 but
    // the gateway was never restarted — the live incident signature.
    const r = await checkOpenClawRunningPluginVersion(home, { readGatewayJournal: () => ({ text: journalWith('4.47.8'), preBounded: true }), readGatewayProcessStartMs: () => 1_700_000_000_000 });
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/stale/i);
    expect(r.message).toMatch(/4\.47\.8 running/i);
    expect(r.message).toMatch(/4\.47\.13 on disk/i);
    expect(r.fix).toMatch(/restart/i);
  });

  it('reports info (never a green "current") when the gateway journal is unreadable', async () => {
    installOnDisk('4.47.13');
    const r = await checkOpenClawRunningPluginVersion(home, { readGatewayJournal: () => null, readGatewayProcessStartMs: () => 1_700_000_000_000 });
    expect(r.status).toBe('info');
    expect(r.message).toMatch(/cannot verify running version/i);
    expect(r.status).not.toBe('pass');
  });

  it('reports info when the journal is readable but holds no registration line', async () => {
    installOnDisk('4.47.13');
    const r = await checkOpenClawRunningPluginVersion(home, {
      readGatewayJournal: () => ({ text: 'Jul 21 09:00:01 host openclaw-gateway[123]: starting gateway\n', preBounded: true }),
      readGatewayProcessStartMs: () => 1_700_000_000_000,
    });
    expect(r.status).toBe('info');
    expect(r.message).toMatch(/running version UNKNOWN/i);
  });

  it('skips (info) when OpenClaw is present but the realtime plugin is not installed', async () => {
    fs.mkdirSync(path.join(home, '.openclaw'), { recursive: true });
    const r = await checkOpenClawRunningPluginVersion(home, { readGatewayJournal: () => ({ text: journalWith('4.47.13'), preBounded: true }), readGatewayProcessStartMs: () => 1_700_000_000_000 });
    expect(r.status).toBe('info');
    expect(r.message).toMatch(/not installed|skipped/i);
  });
});
