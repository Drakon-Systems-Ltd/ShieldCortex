import { spawn } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { PACK_HEADER } from '../../scripts/lib/inject-pack.mjs';

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

/**
 * #393 T1 bus law at the emitter. Two acceptance clauses live here:
 * contract off must not produce a pack that claims canonicity, and an
 * inject mode of off must put nothing at all on the automatic bus (the honest
 * sidecar posture) — the legacy formatter used to fire regardless.
 */
describe('session-start hook — T1 bus law (#393)', () => {
  let tempHome: string;
  let tempCwd: string;
  const originalHome = process.env.HOME;

  function seedMemory(): void {
    const scDir = path.join(tempHome, '.shieldcortex');
    fs.mkdirSync(scDir, { recursive: true });
    const db = new Database(path.join(scDir, 'memories.db'));
    db.exec(`
      CREATE TABLE memories (
        id INTEGER PRIMARY KEY, title TEXT, content TEXT, category TEXT, type TEXT,
        salience REAL, tags TEXT, created_at TEXT, pinned INTEGER, access_count INTEGER,
        last_accessed TEXT, trust_score REAL, sensitivity_level TEXT, metadata TEXT,
        reviewed_at TEXT, downvote_count INTEGER, project TEXT, status TEXT,
        source TEXT, defence_verdict TEXT, content_form TEXT
      );
    `);
    db.prepare(`
      INSERT INTO memories (title, content, category, type, salience, created_at, pinned,
                            access_count, trust_score, sensitivity_level, downvote_count,
                            project, status, source, defence_verdict, content_form)
      VALUES ('deploy key rotated', 'the CI deploy key was rotated on 2026-08-20', 'architecture',
              'long_term', 0.9, datetime('now'), 0, 0, 0.9, 'INTERNAL', 0, NULL, 'active',
              'agent', 'allow', 'fact')
    `).run();
    db.close();
  }

  function writeConfig(cfg: Record<string, unknown>): void {
    const scDir = path.join(tempHome, '.shieldcortex');
    fs.mkdirSync(scDir, { recursive: true });
    fs.writeFileSync(path.join(scDir, 'config.json'), JSON.stringify(cfg));
  }

  beforeEach(() => {
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-t1-home-'));
    tempCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-t1-cwd-'));
    process.env.HOME = tempHome;
    seedMemory();
  });

  afterEach(() => {
    process.env.HOME = originalHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
    fs.rmSync(tempCwd, { recursive: true, force: true });
  });

  it('claims no canonicity when no native contract is set', async () => {
    writeConfig({ memory: { plane: 'dual_legacy', inject: { mode: 'start' } } });
    const result = await runHook({ cwd: tempCwd, source: 'startup' }, { HOME: tempHome });
    expect(result.stdout).toContain('deploy key rotated');
    expect(result.stdout).toContain(PACK_HEADER.SIDECAR);
    // The old contract-off output headed itself as the project's context.
    expect(result.stdout).not.toContain('# Project Context:');
    expect(result.stdout).not.toContain(PACK_HEADER.BUS);
  });

  it('emits the bus-plane pack only when a contract is in force', async () => {
    writeConfig({
      memory: {
        plane: 'dual_legacy',
        inject: { mode: 'start', nativeContract: 'sc_only', hostId: 'h', agentId: 'a', requireScope: false },
      },
    });
    const result = await runHook({ cwd: tempCwd, source: 'startup' }, { HOME: tempHome });
    expect(result.stdout).toContain(PACK_HEADER.BUS);
    expect(result.stdout).not.toContain(PACK_HEADER.SIDECAR);
  });

  it('puts nothing on the automatic bus when inject mode is off (honest sidecar)', async () => {
    writeConfig({
      memory: {
        plane: 'dual_legacy',
        hostContract: { posture: 'mcp_sidecar_no_inject' },
        inject: { mode: 'off', nativeContract: 'sc_only' },
      },
    });
    const result = await runHook({ cwd: tempCwd, source: 'startup' }, { HOME: tempHome });
    expect(result.stdout).toBe('');
    expect(result.stderr).toContain('inject mode=off');
  });

  it('puts nothing on the start bus when inject mode is turn-only', async () => {
    writeConfig({ memory: { plane: 'dual_legacy', inject: { mode: 'turn', nativeContract: 'sc_only' } } });
    const result = await runHook({ cwd: tempCwd, source: 'startup' }, { HOME: tempHome });
    expect(result.stdout).toBe('');
  });
});
