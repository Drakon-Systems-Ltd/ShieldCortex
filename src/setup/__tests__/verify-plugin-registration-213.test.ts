import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { verifyPluginRegistration } from '../openclaw.js';

/**
 * Issue #213 — the 4.47.32 installer left a box silently unprotected.
 *
 * Field origin (Case's aiquant box, 8 Aug 2026): `shieldcortex install` ran,
 * the native `openclaw plugins install` path exited 0, and afterwards the
 * `shieldcortex-realtime` stanza was GONE from openclaw.json (`plugins.allow`
 * and `plugins.entries` both). Nothing verified the on-disk config after the
 * native path — and the #74 honest-state self-check proves the RUNNING
 * gateway's roster, which still held the pre-install plugin, so it passed.
 * The wipe only bit at the next gateway restart: 7 plugins, no shieldcortex,
 * while the CLI had reported installed.
 *
 * The invariant this file pins: an installer must never reduce the protection
 * state it found. `verifyPluginRegistration` re-reads openclaw.json after any
 * install path, restores the stanza when it is missing or disabled (via
 * trustLocalPlugin — merge-preserving, never a whole-file clobber), and
 * reports honestly when it cannot.
 */

let tempHome: string;

beforeEach(() => {
  tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-213-'));
});

afterEach(() => {
  fs.rmSync(tempHome, { recursive: true, force: true });
});

const configPath = () => path.join(tempHome, '.openclaw', 'openclaw.json');

function writeConfig(cfg: Record<string, unknown>): void {
  fs.mkdirSync(path.dirname(configPath()), { recursive: true });
  fs.writeFileSync(configPath(), JSON.stringify(cfg, null, 2) + '\n');
}

const FULL_STANZA = {
  plugins: {
    allow: ['codex', 'shieldcortex-realtime'],
    entries: {
      codex: { enabled: true, config: { appServer: { networkProxy: 'http://127.0.0.1:9' } } },
      'shieldcortex-realtime': { enabled: true },
    },
  },
};

describe('verifyPluginRegistration (#213)', () => {
  it('reports registered and leaves a correct config byte-for-byte untouched', () => {
    writeConfig(FULL_STANZA);
    const before = fs.readFileSync(configPath(), 'utf-8');
    const result = verifyPluginRegistration(tempHome);
    expect(result.registered).toBe(true);
    expect(result.restored).toBe(false);
    expect(fs.readFileSync(configPath(), 'utf-8')).toBe(before);
  });

  it('restores a wiped stanza (the Case shape: both allow and entries gone)', () => {
    writeConfig({
      plugins: {
        allow: ['codex'],
        entries: { codex: { enabled: true } },
      },
    });
    const result = verifyPluginRegistration(tempHome);
    expect(result.restored).toBe(true);
    expect(result.registered).toBe(true);
    const after = JSON.parse(fs.readFileSync(configPath(), 'utf-8'));
    expect(after.plugins.allow).toContain('shieldcortex-realtime');
    expect(after.plugins.entries['shieldcortex-realtime']).toEqual({ enabled: true });
    // Other plugins survive the restore untouched.
    expect(after.plugins.allow).toContain('codex');
    expect(after.plugins.entries.codex).toEqual({ enabled: true });
  });

  it('re-enables a disabled entry while preserving its other keys', () => {
    writeConfig({
      plugins: {
        allow: ['shieldcortex-realtime'],
        entries: {
          'shieldcortex-realtime': { enabled: false, config: { cloudEnabled: true } },
        },
      },
    });
    const result = verifyPluginRegistration(tempHome);
    expect(result.restored).toBe(true);
    expect(result.registered).toBe(true);
    const after = JSON.parse(fs.readFileSync(configPath(), 'utf-8'));
    expect(after.plugins.entries['shieldcortex-realtime']).toEqual({
      enabled: true,
      config: { cloudEnabled: true },
    });
  });

  it('creates the registration when no config file exists at all', () => {
    const result = verifyPluginRegistration(tempHome);
    expect(result.registered).toBe(true);
    expect(result.restored).toBe(true);
    const after = JSON.parse(fs.readFileSync(configPath(), 'utf-8'));
    expect(after.plugins.allow).toContain('shieldcortex-realtime');
  });

  it('reports honestly when the restore itself is impossible', () => {
    // `.openclaw` exists as a FILE, so the config path can never be written.
    fs.writeFileSync(path.join(tempHome, '.openclaw'), 'not a directory');
    const result = verifyPluginRegistration(tempHome);
    expect(result.registered).toBe(false);
    expect(result.detail).toMatch(/restore|write|fail/i);
  });
});
