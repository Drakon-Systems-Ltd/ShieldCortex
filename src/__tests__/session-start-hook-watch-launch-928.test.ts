/**
 * #928 round 2: the agent-config watch guards USER-level files, so session
 * start must launch it even when no project key can be derived (generic cwd
 * such as OpenClaw's ~/.openclaw/workspace). The project-scoped MCP tool check
 * stays behind the project-key gate.
 *
 * Drives the real hook and its real launchers in a synthetic tree: the hook
 * and scripts/lib are copied verbatim, `dist/audit/*-runner.js` are stub
 * runners that only record their argv, and better-sqlite3 is an inert stub
 * (HOME is synthetic and has no memories.db, so it is never constructed).
 */
import { spawn } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCRIPTS = path.resolve(__dirname, '..', '..', 'scripts');

const STUB_RUNNER = `import fs from 'node:fs';
import path from 'node:path';
fs.writeFileSync(path.join(process.env.SC_928R2_RECORD_DIR, path.basename(process.argv[1]) + '.json'), JSON.stringify(process.argv.slice(2)));
`;

let root: string;
let home: string;
let records: string;

function buildTree(): void {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-928r2-hook-'));
  home = path.join(root, 'home');
  records = path.join(root, 'records');
  fs.mkdirSync(home);
  fs.mkdirSync(records);
  fs.mkdirSync(path.join(root, 'scripts'));
  fs.copyFileSync(path.join(SCRIPTS, 'session-start-hook.mjs'), path.join(root, 'scripts', 'session-start-hook.mjs'));
  fs.cpSync(path.join(SCRIPTS, 'lib'), path.join(root, 'scripts', 'lib'), { recursive: true });
  fs.mkdirSync(path.join(root, 'dist', 'audit'), { recursive: true });
  for (const r of ['agent-config-watch-runner.js', 'mcp-tools-autocheck-runner.js']) {
    fs.writeFileSync(path.join(root, 'dist', 'audit', r), STUB_RUNNER);
  }
  fs.writeFileSync(path.join(root, 'dist', 'package.json'), '{"type":"module"}');
  const sqlite = path.join(root, 'node_modules', 'better-sqlite3');
  fs.mkdirSync(sqlite, { recursive: true });
  fs.writeFileSync(path.join(sqlite, 'package.json'), '{"name":"better-sqlite3","main":"index.js"}');
  fs.writeFileSync(path.join(sqlite, 'index.js'), 'module.exports = function Database() { throw new Error("stub: no database in this test"); };');
}

function writeConfig(cfg: unknown): void {
  fs.mkdirSync(path.join(home, '.shieldcortex'), { recursive: true });
  fs.writeFileSync(path.join(home, '.shieldcortex', 'config.json'), JSON.stringify(cfg));
}

function workspaceDir(): string {
  // Generic basename: deriveProjectKey refuses it and returns null.
  const dir = path.join(root, 'cwds', 'openclaw-home', 'workspace');
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function runHook(payload: Record<string, unknown>, env: NodeJS.ProcessEnv = {}): Promise<{ code: number | null; stdout: string }> {
  const childEnv: NodeJS.ProcessEnv = {
    PATH: process.env.PATH,
    HOME: home,
    TMPDIR: path.join(root, 'tmp'),
    CLAUDE_MEMORY_DB: path.join(home, 'no-such.db'),
    SC_928R2_RECORD_DIR: records,
    ...env,
  };
  fs.mkdirSync(childEnv.TMPDIR as string, { recursive: true });
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(root, 'scripts', 'session-start-hook.mjs')], {
      // A process cwd that is NOT the payload cwd: the payload must win.
      cwd: root,
      env: childEnv,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    child.stdout.on('data', (c) => { stdout += c.toString(); });
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stdout }));
    child.stdin.end(JSON.stringify(payload));
  });
}

const recordPath = (runner: string) => path.join(records, `${runner}.json`);

async function waitFor(file: string, ms = 8000): Promise<string[] | null> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (fs.existsSync(file)) {
      try { return JSON.parse(fs.readFileSync(file, 'utf-8')); } catch { /* mid-write */ }
    }
    await new Promise((r) => setTimeout(r, 50));
  }
  return null;
}

const WATCH = 'agent-config-watch-runner.js';
const TOOLS = 'mcp-tools-autocheck-runner.js';

beforeEach(() => buildTree());
afterEach(() => fs.rmSync(root, { recursive: true, force: true }));

describe('session-start hook launches the agent-config watch before the project-key gate (#928 r2)', () => {
  it('generic workspace with no project key: watch launched with the payload cwd, tool check not', async () => {
    const cwd = workspaceDir();
    const r = await runHook({ source: 'startup', cwd });
    expect(r.code).toBe(0);
    expect(r.stdout).toBe('');
    expect(await waitFor(recordPath(WATCH))).toEqual(['--project-root', cwd]);
    // The MCP tool check is project-scoped and stays behind the null-key exit.
    await new Promise((res) => setTimeout(res, 750));
    expect(fs.existsSync(recordPath(TOOLS))).toBe(false);
  }, 20000);

  it('generic workspace with sessionStart.agentConfigWatch=false: nothing launched', async () => {
    writeConfig({ sessionStart: { agentConfigWatch: false } });
    const r = await runHook({ source: 'startup', cwd: workspaceDir() });
    expect(r.code).toBe(0);
    await new Promise((res) => setTimeout(res, 1500));
    expect(fs.readdirSync(records)).toEqual([]);
  }, 20000);

  it('keyed project with the watch opted out: tool check launched, watch not', async () => {
    writeConfig({ sessionStart: { agentConfigWatch: false } });
    const r = await runHook({ source: 'startup', cwd: workspaceDir() }, { SHIELDCORTEX_PROJECT_KEY: 'synthetic-928' });
    expect(r.code).toBe(0);
    expect(await waitFor(recordPath(TOOLS))).toEqual([]);
    await new Promise((res) => setTimeout(res, 750));
    expect(fs.existsSync(recordPath(WATCH))).toBe(false);
  }, 20000);

  it('keyed project: both launched, watch gets the payload cwd', async () => {
    const cwd = workspaceDir();
    const r = await runHook({ source: 'startup', cwd }, { SHIELDCORTEX_PROJECT_KEY: 'synthetic-928' });
    expect(r.code).toBe(0);
    expect(await waitFor(recordPath(WATCH))).toEqual(['--project-root', cwd]);
    expect(await waitFor(recordPath(TOOLS))).toEqual([]);
  }, 20000);

  it.each(['resume', 'compact', 'clear'])('source=%s still exits before launching anything', async (source) => {
    const r = await runHook({ source, cwd: workspaceDir() }, { SHIELDCORTEX_PROJECT_KEY: 'synthetic-928' });
    expect(r.code).toBe(0);
    expect(r.stdout).toBe('');
    await new Promise((res) => setTimeout(res, 1000));
    expect(fs.readdirSync(records)).toEqual([]);
  }, 20000);
});
