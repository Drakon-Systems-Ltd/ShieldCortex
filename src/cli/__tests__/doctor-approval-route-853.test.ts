import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

/**
 * #853 ruling (issuecomment-6313152247 §3): under enforce, headless approvable
 * calls with no card route run as ADVISORY, and doctor must say "approvals
 * have no route" in red. With a route, a hook timeout too short to hold is a
 * warning (those calls are denied, not held).
 */
describe('doctor: approval route (#853)', () => {
  let tmpHome: string;
  let tmpScDir: string;
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-doc853-home-'));
    tmpScDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-doc853-scdir-'));
    originalEnv = { ...process.env };
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    process.env.SHIELDCORTEX_CONFIG_DIR = tmpScDir;
    delete process.env.CLAUDE_PROJECT_DIR;
    jest.resetModules();
  });

  afterEach(() => {
    process.env = originalEnv;
    jest.restoreAllMocks();
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch { /* ignore */ }
    try { fs.rmSync(tmpScDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  function writeGuard(actionGuard: Record<string, unknown>): void {
    fs.writeFileSync(path.join(tmpScDir, 'config.json'), JSON.stringify({ actionGuard }, null, 2) + '\n');
  }

  function writePreToolTimeout(timeout: number): void {
    const dir = path.join(tmpHome, '.claude');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'settings.json'), JSON.stringify({
      hooks: { PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: '/usr/bin/shieldcortex hook pre-tool', timeout }] }] },
    }));
  }

  async function check() {
    jest.spyOn(os, 'homedir').mockReturnValue(tmpHome);
    const mod = await import('../doctor.js');
    return mod.checkApprovalRoute();
  }

  it('enforce with no card route is a FAIL: "approvals have no route"', async () => {
    writeGuard({ enabled: true, enforce: true, notify: { enabled: true, webhookUrl: 'https://example.invalid/h' } });
    const r = await check();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/approvals have no route/);
    expect(r.message).toMatch(/ADVISORY/);
  });

  it('notify off entirely is also no route', async () => {
    writeGuard({ enabled: true, enforce: true });
    expect((await check()).status).toBe('fail');
  });

  it('a card route with a hold-sized timeout passes', async () => {
    writeGuard({ enabled: true, enforce: true, notify: { enabled: true, openclaw: true } });
    writePreToolTimeout(135);
    const r = await check();
    expect(r.status).toBe('pass');
    expect(r.message).toMatch(/held up to 120s/);
  });

  it('a card route with the old 10 s timeout warns that holds are impossible', async () => {
    writeGuard({ enabled: true, enforce: true, notify: { enabled: true, openclaw: true } });
    writePreToolTimeout(10);
    const r = await check();
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/too short to hold/);
    expect(r.fix).toMatch(/135s/);
  });

  it('advisory posture and guard-off are informational, not red', async () => {
    writeGuard({ enabled: true, enforce: false });
    expect((await check()).status).toBe('info');
    jest.resetModules();
    writeGuard({ enabled: false });
    expect((await check()).status).toBe('info');
  });
});
