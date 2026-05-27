import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { checkOpenClawDuplicateInstalls } from '../cli/doctor.js';

/**
 * Regression guard for the post-v4.25.1 duplicate-plugin-id incident.
 *
 * Field observation (2026-05-27, all fleet boxes): OpenClaw's plugin
 * scanner walks `~/.openclaw/extensions/` and `~/.openclaw/hooks/` and
 * registers every `openclaw.plugin.json` it finds — including ones in
 * `.trash-<id>.<ts>/` directories left by OpenClaw's own upgrade flow
 * and `<id>.disabled-<host>-<ts>/` directories from manual disables.
 * Every duplicate fires `duplicate plugin id detected; global plugin
 * will be overridden by global plugin` on every session.
 *
 * The fix is purely `rm -rf` on each offending path. This check surfaces
 * the paths so operators don't need to SSH in and find them by hand.
 */
describe('doctor — OpenClaw duplicate installs', () => {
  let openclawDir: string;

  beforeEach(() => {
    openclawDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-ocdup-'));
  });

  afterEach(() => {
    fs.rmSync(openclawDir, { recursive: true, force: true });
  });

  function writeManifest(relDir: string): string {
    const dir = path.join(openclawDir, relDir);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'openclaw.plugin.json'),
      JSON.stringify({ id: 'shieldcortex-realtime', version: '4.x' }),
      'utf-8',
    );
    return dir;
  }

  function writeCanonical(): string {
    return writeManifest('npm/node_modules/@drakon-systems/shieldcortex-realtime');
  }

  it('skips when ~/.openclaw does not exist', async () => {
    const r = await checkOpenClawDuplicateInstalls(path.join(openclawDir, 'nope'));
    expect(r.status).toBe('info');
    expect(r.message).toMatch(/skipped/i);
  });

  it('passes on a clean install: canonical present, nothing in extensions/ or hooks/', async () => {
    writeCanonical();
    const r = await checkOpenClawDuplicateInstalls(openclawDir);
    expect(r.status).toBe('pass');
    expect(r.message).toMatch(/clean/);
  });

  it('flags `.trash-shieldcortex-realtime.<ts>/` leftovers in extensions/', async () => {
    writeCanonical();
    writeManifest('extensions/.trash-shieldcortex-realtime.20260527-093144');
    const r = await checkOpenClawDuplicateInstalls(openclawDir);
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/duplicate/i);
    expect(r.message).toMatch(/\.trash-shieldcortex-realtime/);
    expect(r.fix).toMatch(/rm -rf/);
  });

  it('flags `.trash-shieldcortex-realtime.<ts>/` in hooks/ (edith pattern)', async () => {
    writeCanonical();
    writeManifest('hooks/.trash-shieldcortex-realtime.20260527-092053');
    const r = await checkOpenClawDuplicateInstalls(openclawDir);
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/hooks\/\.trash-shieldcortex-realtime/);
  });

  it('flags a live legacy install at extensions/shieldcortex-realtime/ (jarvis + case pattern)', async () => {
    writeCanonical();
    writeManifest('extensions/shieldcortex-realtime');
    const r = await checkOpenClawDuplicateInstalls(openclawDir);
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/duplicate/i);
    expect(r.message).toMatch(/extensions\/shieldcortex-realtime/);
  });

  it('flags `*.disabled-<host>-<ts>/` directories (manual disable leftovers)', async () => {
    writeCanonical();
    writeManifest('extensions/shieldcortex-realtime.disabled-tars-20260526T104503Z');
    const r = await checkOpenClawDuplicateInstalls(openclawDir);
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/disabled-tars/);
  });

  it('reports ALL duplicate locations in the same run (not just the first)', async () => {
    writeCanonical();
    writeManifest('extensions/.trash-shieldcortex-realtime.20260527-093144');
    writeManifest('hooks/.trash-shieldcortex-realtime.20260527-092053');
    writeManifest('extensions/shieldcortex-realtime.disabled-tars-20260526T104503Z');
    const r = await checkOpenClawDuplicateInstalls(openclawDir);
    expect(r.status).toBe('warn');
    // All three paths should be in the fix string
    expect(r.fix).toMatch(/\.trash-shieldcortex-realtime\.20260527-093144/);
    expect(r.fix).toMatch(/\.trash-shieldcortex-realtime\.20260527-092053/);
    expect(r.fix).toMatch(/disabled-tars/);
  });

  it('directory matching the name pattern but missing openclaw.plugin.json is not flagged', async () => {
    writeCanonical();
    const orphan = path.join(openclawDir, 'extensions', '.trash-shieldcortex-realtime.20260527-000000');
    fs.mkdirSync(orphan, { recursive: true });
    // No openclaw.plugin.json written — OpenClaw scanner would skip it too.
    const r = await checkOpenClawDuplicateInstalls(openclawDir);
    expect(r.status).toBe('pass');
  });

  it('legacy install with no canonical npm install: still warn but with different fix advice', async () => {
    writeManifest('extensions/shieldcortex-realtime'); // pre-v4.21 install
    // No canonical npm install written
    const r = await checkOpenClawDuplicateInstalls(openclawDir);
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/legacy install location/);
    expect(r.fix).toMatch(/openclaw plugins install/);
  });

  it('non-shieldcortex directories are not flagged (other plugins are not our concern)', async () => {
    writeCanonical();
    // Other plugin's install — should be invisible to our scan
    const dir = path.join(openclawDir, 'extensions', 'some-other-plugin');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'openclaw.plugin.json'),
      JSON.stringify({ id: 'some-other-plugin', version: '1.0.0' }),
      'utf-8',
    );
    const r = await checkOpenClawDuplicateInstalls(openclawDir);
    expect(r.status).toBe('pass');
  });
});
