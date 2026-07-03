import { spawn } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * PreToolUse action-guard wiring (P1/WS1 carry-over to Claude Code).
 *
 * Locks two contracts:
 *  1. `setupHooks()` installs a PreToolUse entry with a wildcard matcher and
 *     the `shieldcortex hook pre-tool` command — so `shieldcortex install` /
 *     `update` wire the guard by default (enforce-by-default carry-over).
 *  2. The `shieldcortex hook pre-tool` CLI path dispatches to the script —
 *     drift between BUILT_IN_HOOKS and settings-hooks is the #23 failure class.
 */

describe('action-guard hook install (PreToolUse)', () => {
  let tmpHome: string;
  let tmpScDir: string;
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-ag-home-'));
    tmpScDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-ag-scdir-'));
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

  function readSettings(): Record<string, any> {
    return JSON.parse(fs.readFileSync(path.join(tmpHome, '.claude', 'settings.json'), 'utf-8'));
  }

  it('setupHooks installs PreToolUse with a wildcard matcher and the pre-tool command', async () => {
    // jest virtualizes process.env, so a HOME swap is invisible to the native
    // os.homedir() — the spy is the repo's established redirection seam (see
    // hook-timeout-reconcile.test.ts). Without it this test writes to the REAL
    // ~/.claude/settings.json.
    jest.spyOn(os, 'homedir').mockReturnValue(tmpHome);
    const { setupHooks } = await import('../settings-hooks.js');
    setupHooks();

    const settings = readSettings();
    const entries = settings.hooks?.PreToolUse;
    expect(Array.isArray(entries)).toBe(true);
    const entry = entries[0];
    expect(entry.matcher).toBe('*');
    expect(entry.hooks?.[0]?.command).toBe('shieldcortex hook pre-tool');
    expect(entry.hooks?.[0]?.timeout).toBe(10);
  });

  it('setupHooks does not duplicate an existing PreToolUse entry', async () => {
    jest.spyOn(os, 'homedir').mockReturnValue(tmpHome);
    const { setupHooks } = await import('../settings-hooks.js');
    setupHooks();
    setupHooks();

    const entries = readSettings().hooks?.PreToolUse;
    const cortexEntries = entries.filter((e: any) =>
      e.hooks?.some((h: any) => typeof h.command === 'string' && h.command.includes('shieldcortex')),
    );
    expect(cortexEntries.length).toBe(1);
  });

  it('the hook CLI dispatches pre-tool to the guard script', async () => {
    const cliPath = path.resolve(__dirname, '..', '..', '..', 'dist', 'index.js');
    // dist is built before tests in CI; guard the local invariant explicitly so
    // a missing build fails loudly instead of green-skipping the dispatch check.
    expect(fs.existsSync(cliPath)).toBe(true);

    const result = await new Promise<{ stdout: string; code: number }>((resolve, reject) => {
      const child = spawn(process.execPath, [cliPath, 'hook', 'pre-tool'], {
        stdio: ['pipe', 'pipe', 'pipe'],
        env: { ...process.env },
      });
      let stdout = '';
      child.stdout.on('data', (c) => { stdout += c.toString(); });
      child.on('error', reject);
      child.on('close', (code) => resolve({ stdout, code: code ?? 0 }));
      child.stdin.write(JSON.stringify({
        session_id: 't', cwd: '/tmp', hook_event_name: 'PreToolUse',
        tool_name: 'Bash', tool_input: { command: 'rm -rf /' },
      }));
      child.stdin.end();
    });

    expect(result.code).toBe(0);
    const parsed = JSON.parse(result.stdout);
    expect(parsed.hookSpecificOutput?.permissionDecision).toBe('deny');
  });
});
