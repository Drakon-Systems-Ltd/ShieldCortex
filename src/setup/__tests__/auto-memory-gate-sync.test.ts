import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

/**
 * v4.13.0 shipped a triple-gated auto-memory pipeline where the
 * `--with-stop-hook` / `--with-session-end` install flags wired the hook
 * in settings.json but did NOT flip the runtime gate
 * (autoMemory.enableStop / enableSessionEnd, default false). Result was
 * silent-amnesia: hook fires every turn, bails immediately with no log,
 * user sees zero captures. (#41)
 *
 * v4.13.1 collapses install flag and runtime gate into a single user
 * action — passing the install flag flips the runtime gate too. These
 * tests pin that contract so the silent-amnesia regression cannot reland.
 */
describe('setupHooks aligns autoMemory enable gate with install flags (#41)', () => {
  let tmpHome: string;
  let tmpScDir: string;
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hooks-home-'));
    tmpScDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hooks-scdir-'));
    originalEnv = { ...process.env };
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome; // Windows fallback
    process.env.SHIELDCORTEX_CONFIG_DIR = tmpScDir;
    // os.homedir() caches via libuv — only re-import target module after env is set.
    jest.resetModules();
  });

  afterEach(() => {
    process.env = originalEnv;
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch { /* ignore */ }
    try { fs.rmSync(tmpScDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  function readScConfig(): Record<string, unknown> {
    const file = path.join(tmpScDir, 'config.json');
    if (!fs.existsSync(file)) return {};
    return JSON.parse(fs.readFileSync(file, 'utf-8'));
  }

  it('--with-stop-hook flips autoMemory.enableStop=true so the runtime gate matches the wiring', async () => {
    jest.spyOn(os, 'homedir').mockReturnValue(tmpHome);
    const { setupHooks } = await import('../settings-hooks.js');
    setupHooks({ stopHook: true });
    const cfg = readScConfig();
    expect((cfg.autoMemory as { enableStop?: boolean })?.enableStop).toBe(true);
  });

  it('--with-session-end flips autoMemory.enableSessionEnd=true', async () => {
    jest.spyOn(os, 'homedir').mockReturnValue(tmpHome);
    const { setupHooks } = await import('../settings-hooks.js');
    setupHooks({ sessionEnd: true });
    const cfg = readScConfig();
    expect((cfg.autoMemory as { enableSessionEnd?: boolean })?.enableSessionEnd).toBe(true);
  });

  it('explicit stopHook:false flips autoMemory.enableStop=false (re-running setup without the flag disables the gate too)', async () => {
    jest.spyOn(os, 'homedir').mockReturnValue(tmpHome);
    // Pre-seed gate as on, simulating a prior --with-stop-hook install
    const seed = path.join(tmpScDir, 'config.json');
    fs.writeFileSync(seed, JSON.stringify({ autoMemory: { enableStop: true } }, null, 2) + '\n');
    const { setupHooks } = await import('../settings-hooks.js');
    setupHooks({ stopHook: false });
    const cfg = readScConfig();
    expect((cfg.autoMemory as { enableStop?: boolean })?.enableStop).toBe(false);
  });

  it('calling setupHooks() with no opt-in fields leaves autoMemory untouched (no churn for default installs)', async () => {
    jest.spyOn(os, 'homedir').mockReturnValue(tmpHome);
    const { setupHooks } = await import('../settings-hooks.js');
    setupHooks();
    const cfg = readScConfig();
    expect(cfg.autoMemory).toBeUndefined();
  });

  it('runtime config-loader honours SHIELDCORTEX_CONFIG_DIR — gate read at hook fire matches what setupHooks wrote', async () => {
    jest.spyOn(os, 'homedir').mockReturnValue(tmpHome);
    const { setupHooks } = await import('../settings-hooks.js');
    setupHooks({ stopHook: true, sessionEnd: true });

    // The .mjs hook script reads via getAutoMemoryConfig — must resolve to
    // the same temp dir or tests can't isolate from the real ~/.shieldcortex.
    const { getAutoMemoryConfig } = await import('../../../scripts/lib/auto-memory-config.mjs');
    const liveConfig = getAutoMemoryConfig();
    expect(liveConfig.enableStop).toBe(true);
    expect(liveConfig.enableSessionEnd).toBe(true);
  });

  // Regression (2026-06-02): setup printed "Hook: SessionEnd (removed …)" but
  // left it wired on disk. The removal mutated `settings` but wasn't counted
  // toward `changed`, so a removal-only run (every other hook already
  // configured) took the "all already configured" branch and never wrote the
  // file. Doctor then warned "wired in settings.json but runtime gate is off".
  it('persists SessionEnd removal even when no other hook changes (removal-only write)', async () => {
    jest.spyOn(os, 'homedir').mockReturnValue(tmpHome);

    // Seed every always-installed hook as already configured (so `added` stays
    // 0) plus a stale ShieldCortex SessionEnd entry. Timeouts are high so the
    // timeout reconciler counts nothing either — the exact shape that skipped
    // the write.
    const claudeDir = path.join(tmpHome, '.claude');
    fs.mkdirSync(claudeDir, { recursive: true });
    const settingsPath = path.join(claudeDir, 'settings.json');
    const cmd = (c: string) => ({ hooks: [{ type: 'command', command: c, timeout: 60 }] });
    fs.writeFileSync(settingsPath, JSON.stringify({
      hooks: {
        PreCompact: [cmd('shieldcortex hook pre-compact')],
        SessionStart: [cmd('shieldcortex hook session-start')],
        UserPromptSubmit: [cmd('shieldcortex hook prompt-recall')],
        SessionEnd: [cmd('shieldcortex hook session-end')],
      },
    }, null, 2) + '\n');

    const { setupHooks } = await import('../settings-hooks.js');
    setupHooks(); // no opt-in → the stale SessionEnd must be removed AND written

    const after = JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));
    expect(after.hooks.SessionEnd).toBeUndefined();
    // Removal-only: the other hooks must survive untouched (no collateral write).
    expect(after.hooks.PreCompact).toBeDefined();
    expect(after.hooks.SessionStart).toBeDefined();
    expect(after.hooks.UserPromptSubmit).toBeDefined();
  });
});
