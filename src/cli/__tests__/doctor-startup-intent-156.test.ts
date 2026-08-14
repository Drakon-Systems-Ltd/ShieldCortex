import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { checkPluginStartupIntent, readPluginStartupIntent } from '../doctor.js';

/**
 * #156 — doctor/repair must statically see the aiquant silent-skip.
 *
 * A 2026.7.x gateway loads a plugin at boot only if the installed manifest
 * says `activation.onStartup === true` or lists `hook` in
 * `activation.onCapabilities`. A pre-fix copy on disk with onStartup:false
 * is silently absent from every boot while doctor can still look green.
 */

let home: string;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-156-intent-'));
});
afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

function writeManifest(activation: Record<string, unknown>): string {
  const dir = path.join(home, '.openclaw', 'extensions', 'shieldcortex-realtime');
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, 'openclaw.plugin.json');
  fs.writeFileSync(file, JSON.stringify({ id: 'shieldcortex-realtime', activation }, null, 2));
  return file;
}

describe('#156 readPluginStartupIntent', () => {
  it('reads onStartup and hook capability from the installed manifest', () => {
    writeManifest({ onStartup: true, onCapabilities: ['hook'] });
    const intent = readPluginStartupIntent(home);
    expect(intent).toEqual({
      onStartup: true,
      hookCapability: true,
      source: expect.stringContaining('openclaw.plugin.json'),
    });
  });

  it('returns null when no installed manifest exists', () => {
    expect(readPluginStartupIntent(home)).toBeNull();
  });
});

describe('#156 doctor startup-intent check', () => {
  it('fails a pre-fix manifest that declares onStartup:false and no hook capability', async () => {
    writeManifest({ onStartup: false, hooks: ['llm_input'] });
    const r = await checkPluginStartupIntent(home);
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/onStartup/i);
    expect(r.fix).toMatch(/reinstall|repair/i);
  });

  it('passes the current manifest shape', async () => {
    writeManifest({ onStartup: true, onCapabilities: ['hook'], hooks: ['llm_input'] });
    const r = await checkPluginStartupIntent(home);
    expect(r.status).toBe('pass');
  });

  it('is informational when no plugin is installed', async () => {
    const r = await checkPluginStartupIntent(home);
    expect(r.status).toBe('info');
  });
});
