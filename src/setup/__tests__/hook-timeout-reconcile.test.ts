import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

/**
 * Doctor's "Hook timeouts" check (introduced in v4.14.0 alongside the #43
 * recall-timeout bump) tells users to "Re-run `shieldcortex install` to
 * restore canonical timeouts" when an existing settings.json has a too-low
 * timeout (e.g. pre-#43 hand-edited UserPromptSubmit at 2 s). Without
 * timeout reconciliation in setupHooks, that suggested fix was a lie —
 * install only added missing hooks. v4.14.2 fixes it: setupHooks now
 * bumps timeouts on existing shieldcortex hook entries to canonical.
 */
describe('setupHooks reconciles existing hook timeouts to canonical', () => {
  let tmpHome: string;
  let tmpScDir: string;
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-timeout-home-'));
    tmpScDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-timeout-scdir-'));
    originalEnv = { ...process.env };
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    process.env.SHIELDCORTEX_CONFIG_DIR = tmpScDir;
    jest.resetModules();
    jest.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    process.env = originalEnv;
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch { /* ignore */ }
    try { fs.rmSync(tmpScDir, { recursive: true, force: true }); } catch { /* ignore */ }
    jest.restoreAllMocks();
  });

  function settingsPath() {
    return path.join(tmpHome, '.claude', 'settings.json');
  }

  function readSettings(): Record<string, unknown> {
    return JSON.parse(fs.readFileSync(settingsPath(), 'utf-8'));
  }

  function writeSettings(s: Record<string, unknown>) {
    fs.mkdirSync(path.dirname(settingsPath()), { recursive: true });
    fs.writeFileSync(settingsPath(), JSON.stringify(s, null, 2), 'utf-8');
  }

  function userPromptSubmitTimeout(): number | undefined {
    const settings = readSettings() as {
      hooks?: { UserPromptSubmit?: Array<{ hooks?: Array<{ command?: string; timeout?: number }> }> };
    };
    const entry = settings.hooks?.UserPromptSubmit?.[0];
    return entry?.hooks?.[0]?.timeout;
  }

  it('bumps UserPromptSubmit timeout 2 → 5 when an existing shieldcortex entry has the legacy value', async () => {
    writeSettings({
      hooks: {
        UserPromptSubmit: [{
          hooks: [{ type: 'command', command: 'shieldcortex hook prompt-recall', timeout: 2 }],
        }],
        PreCompact: [{
          hooks: [{ type: 'command', command: 'shieldcortex hook pre-compact', timeout: 10 }],
        }],
        SessionStart: [{
          hooks: [{ type: 'command', command: 'shieldcortex hook session-start', timeout: 5 }],
        }],
      },
    });

    jest.spyOn(os, 'homedir').mockReturnValue(tmpHome);
    const { setupHooks } = await import('../settings-hooks.js');
    setupHooks();

    expect(userPromptSubmitTimeout()).toBe(5);
  });

  it('leaves canonical timeouts untouched (idempotent)', async () => {
    writeSettings({
      hooks: {
        UserPromptSubmit: [{
          hooks: [{ type: 'command', command: 'shieldcortex hook prompt-recall', timeout: 5 }],
        }],
        PreCompact: [{
          hooks: [{ type: 'command', command: 'shieldcortex hook pre-compact', timeout: 10 }],
        }],
        SessionStart: [{
          hooks: [{ type: 'command', command: 'shieldcortex hook session-start', timeout: 5 }],
        }],
      },
    });

    jest.spyOn(os, 'homedir').mockReturnValue(tmpHome);
    const { setupHooks } = await import('../settings-hooks.js');
    setupHooks();

    expect(userPromptSubmitTimeout()).toBe(5);
  });

  it('does not touch non-shieldcortex hook entries even when their timeout is below ours', async () => {
    writeSettings({
      hooks: {
        UserPromptSubmit: [
          { hooks: [{ type: 'command', command: 'some-other-tool foo', timeout: 1 }] },
        ],
      },
    });

    jest.spyOn(os, 'homedir').mockReturnValue(tmpHome);
    const { setupHooks } = await import('../settings-hooks.js');
    setupHooks();

    const settings = readSettings() as {
      hooks?: { UserPromptSubmit?: Array<{ hooks?: Array<{ command?: string; timeout?: number }> }> };
    };
    const otherEntry = settings.hooks?.UserPromptSubmit?.find((e) =>
      e.hooks?.some((h) => h.command === 'some-other-tool foo'),
    );
    expect(otherEntry?.hooks?.[0]?.timeout).toBe(1);
  });

  it('preserves a higher-than-canonical user override (only bumps below canonical)', async () => {
    writeSettings({
      hooks: {
        UserPromptSubmit: [{
          hooks: [{ type: 'command', command: 'shieldcortex hook prompt-recall', timeout: 30 }],
        }],
      },
    });

    jest.spyOn(os, 'homedir').mockReturnValue(tmpHome);
    const { setupHooks } = await import('../settings-hooks.js');
    setupHooks();

    expect(userPromptSubmitTimeout()).toBe(30);
  });
});
