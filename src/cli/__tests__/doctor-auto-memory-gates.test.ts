import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

/**
 * Doctor must surface the resolved Stop/SessionEnd gate state — pre-v4.13.1
 * a hook could be wired in settings.json with the runtime gate (silently)
 * off, and doctor reported all-green while the user got zero captures (#41).
 */
describe('doctor surfaces auto-memory hook gate state (#41)', () => {
  let tmpHome: string;
  let tmpScDir: string;
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-doc-home-'));
    tmpScDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-doc-scdir-'));
    originalEnv = { ...process.env };
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    process.env.SHIELDCORTEX_CONFIG_DIR = tmpScDir;
    jest.resetModules();
  });

  afterEach(() => {
    process.env = originalEnv;
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch { /* ignore */ }
    try { fs.rmSync(tmpScDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  function writeSettings(stop: boolean, sessionEnd: boolean): void {
    const dir = path.join(tmpHome, '.claude');
    fs.mkdirSync(dir, { recursive: true });
    const hooks: Record<string, unknown> = {};
    if (stop) {
      hooks.Stop = [{ hooks: [{ type: 'command', command: 'shieldcortex hook stop', timeout: 10 }] }];
    }
    if (sessionEnd) {
      hooks.SessionEnd = [{ hooks: [{ type: 'command', command: 'shieldcortex hook session-end', timeout: 10 }] }];
    }
    fs.writeFileSync(path.join(dir, 'settings.json'), JSON.stringify({ hooks }, null, 2));
  }

  function writeGate(enableStop: boolean, enableSessionEnd: boolean): void {
    const cfg = { autoMemory: { enableStop, enableSessionEnd } };
    fs.writeFileSync(path.join(tmpScDir, 'config.json'), JSON.stringify(cfg, null, 2) + '\n');
  }

  async function runChecks() {
    jest.spyOn(os, 'homedir').mockReturnValue(tmpHome);
    const mod = await import('../doctor.js');
    return mod.checkAutoMemoryHooks();
  }

  it('Stop hook wired but gate off → warn with the silent-amnesia hint', async () => {
    writeSettings(true, false);
    writeGate(false, false);
    const results = await runChecks();
    const stop = results.find(r => r.label === 'Auto-memory: Stop hook');
    expect(stop?.status).toBe('warn');
    expect(stop?.message).toMatch(/runtime gate is off/i);
  });

  it('Stop hook wired AND gate on → pass', async () => {
    writeSettings(true, false);
    writeGate(true, false);
    const results = await runChecks();
    const stop = results.find(r => r.label === 'Auto-memory: Stop hook');
    expect(stop?.status).toBe('pass');
    expect(stop?.message).toMatch(/enabled/i);
  });

  it('Neither wired nor gated → info "opt-in (not installed)"', async () => {
    writeSettings(false, false);
    // No config file at all.
    const results = await runChecks();
    const stop = results.find(r => r.label === 'Auto-memory: Stop hook');
    const sessionEnd = results.find(r => r.label === 'Auto-memory: SessionEnd hook');
    expect(stop?.status).toBe('info');
    expect(sessionEnd?.status).toBe('info');
  });

  it('Gate on but hook NOT wired → warn (the inverse mismatch)', async () => {
    writeSettings(false, true);
    writeGate(true, false);
    const results = await runChecks();
    const stop = results.find(r => r.label === 'Auto-memory: Stop hook');
    expect(stop?.status).toBe('warn');
    expect(stop?.message).toMatch(/not wired/i);
  });

  it('wired-but-gate-off warn fix prescribes `shieldcortex setup`, never a config.json hand-edit', async () => {
    writeSettings(true, false);
    writeGate(false, false);
    const results = await runChecks();
    const stop = results.find(r => r.label === 'Auto-memory: Stop hook');
    expect(stop?.status).toBe('warn');
    expect(stop?.fix).toMatch(/shieldcortex setup/);
    // The old fix carried an "or set autoMemory.enableStop/… in
    // ~/.shieldcortex/config.json" clause — following it invalidated the
    // `_sig` HMAC and forced defenceMode strict (#275 class).
    expect(stop?.fix).not.toMatch(/config\.json/i);
    expect(stop?.fix).not.toMatch(/enableStop|enableSessionEnd/);
  });

  it('sampling warn fix prescribes the signed --auto-memory-sampling flag, not an Edit of config.json', async () => {
    // checkAutoMemorySampling reads ~/.shieldcortex/config.json off homedir
    // (not SHIELDCORTEX_CONFIG_DIR) — seed a sparser-than-recommended cadence.
    const scDir = path.join(tmpHome, '.shieldcortex');
    fs.mkdirSync(scDir, { recursive: true });
    fs.writeFileSync(
      path.join(scDir, 'config.json'),
      JSON.stringify({ autoMemory: { stopHookSamplingTurns: 12 } }, null, 2) + '\n',
    );
    jest.spyOn(os, 'homedir').mockReturnValue(tmpHome);
    const mod = await import('../doctor.js');
    const r = await mod.checkAutoMemorySampling();
    expect(r.status).toBe('warn');
    const fix = r.fix ?? '';
    expect(fix).toMatch(/shieldcortex config --auto-memory-sampling/);
    expect(fix).not.toMatch(/(^|\.\s)(Edit|Add|Set)\b/);
  });
});
