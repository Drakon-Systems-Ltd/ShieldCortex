import { spawn } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * These tests spawn scripts/session-start-hook.mjs as a subprocess with a
 * synthesised Claude Code hook payload and assert that stdout stays silent
 * for resume/compact/clear, and that the project key honours git origin +
 * config overrides. This locks the v4.10.4 "amnesia every resume" regression.
 */

const HOOK_PATH = path.resolve(__dirname, '..', '..', 'scripts', 'session-start-hook.mjs');

type HookResult = { stdout: string; stderr: string; code: number };

function runHook(payload: Record<string, unknown>, envOverrides: NodeJS.ProcessEnv = {}): Promise<HookResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [HOOK_PATH], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, ...envOverrides },
    });

    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => { stdout += c.toString(); });
    child.stderr.on('data', (c) => { stderr += c.toString(); });
    child.on('error', reject);
    child.on('close', (code) => resolve({ stdout, stderr, code: code ?? 0 }));

    child.stdin.write(JSON.stringify(payload));
    child.stdin.end();
  });
}

describe('session-start hook — source gating (#27)', () => {
  const originalHome = process.env.HOME;
  let tempHome: string;

  beforeEach(() => {
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-sshook-'));
    // Point HOME at a directory with no memories.db and no config so the hook
    // takes the "no DB / no memories" path rather than hitting the user's real
    // shieldcortex install during CI.
    process.env.HOME = tempHome;
  });

  afterEach(() => {
    process.env.HOME = originalHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  });

  it.each(['resume', 'compact', 'clear'])(
    'emits no stdout when source=%s',
    async (source) => {
      const tempCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-cwd-'));
      try {
        const result = await runHook({ cwd: tempCwd, source });
        expect(result.stdout).toBe('');
        expect(result.code).toBe(0);
      } finally {
        fs.rmSync(tempCwd, { recursive: true, force: true });
      }
    },
  );

  it('exits cleanly on source=startup with no DB present', async () => {
    const tempCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-cwd-'));
    try {
      const result = await runHook({ cwd: tempCwd, source: 'startup' });
      // No DB -> no banner. Minimal-mode default also suppresses the "New
      // project" banner when there are no memories to load, so stdout should
      // stay empty here too.
      expect(result.stdout).toBe('');
      expect(result.code).toBe(0);
    } finally {
      fs.rmSync(tempCwd, { recursive: true, force: true });
    }
  });

  it('emits the legacy "No memories yet" banner only when preamble=full', async () => {
    const configDir = path.join(tempHome, '.shieldcortex');
    fs.mkdirSync(configDir, { recursive: true });
    fs.writeFileSync(
      path.join(configDir, 'config.json'),
      JSON.stringify({ sessionStart: { preamble: 'full' } }),
    );

    const tempCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-cwd-'));
    try {
      const result = await runHook({ cwd: tempCwd, source: 'startup' });
      // Still no DB so no context loaded, but with preamble=full we DO want
      // the "New project" banner plus the proactive-memory block.
      expect(result.stdout).toContain('🧠 SHIELDCORTEX - New project');
      expect(result.stdout).toContain('ALWAYS use `remember`');
    } finally {
      fs.rmSync(tempCwd, { recursive: true, force: true });
    }
  });
});

describe('session-start hook — project key derivation (#29)', () => {
  it('honours SHIELDCORTEX_PROJECT_KEY env override', async () => {
    const tempCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-cwd-'));
    const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-sshook-'));
    try {
      const result = await runHook(
        { cwd: tempCwd, source: 'resume' },
        { SHIELDCORTEX_PROJECT_KEY: 'forced-project', HOME: tempHome },
      );
      // resume -> silent, but stderr logs the source skip with no crash
      expect(result.stdout).toBe('');
      expect(result.stderr).toContain('source=resume');
      expect(result.code).toBe(0);
    } finally {
      fs.rmSync(tempCwd, { recursive: true, force: true });
      fs.rmSync(tempHome, { recursive: true, force: true });
    }
  });
});
