import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { afterEach, beforeAll, beforeEach, describe, expect, it } from '@jest/globals';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const HELPER_PATH = path.resolve(__dirname, '..', '..', 'scripts', 'lib', 'project-key.mjs');
const HELPER_URL = pathToFileURL(HELPER_PATH).href;

type Helper = {
  deriveProjectKey(cwd: string): string | null;
};
let helper: Helper;

/**
 * Tests the project-key helper by importing the .mjs module directly.
 * The helper drives banner scoping, recall scoping, and pre-compact writes,
 * so an incorrect key silently silos memories across sibling repos (#29).
 */

describe('deriveProjectKey', () => {
  let tempRoot: string;
  let tempHome: string;
  const originalHome = process.env.HOME;
  const originalKey = process.env.SHIELDCORTEX_PROJECT_KEY;

  beforeEach(() => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-pk-root-'));
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-pk-home-'));
    process.env.HOME = tempHome;
    delete process.env.SHIELDCORTEX_PROJECT_KEY;
  });

  afterEach(() => {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
    process.env.HOME = originalHome;
    if (originalKey === undefined) delete process.env.SHIELDCORTEX_PROJECT_KEY;
    else process.env.SHIELDCORTEX_PROJECT_KEY = originalKey;
  });

  it('prefers the env override', async () => {
    process.env.SHIELDCORTEX_PROJECT_KEY = 'override-project';
    expect(helper.deriveProjectKey(tempRoot)).toBe('override-project');
  });

  it('prefers config.projectKey over cwd basename', async () => {
    fs.mkdirSync(path.join(tempHome, '.shieldcortex'), { recursive: true });
    fs.writeFileSync(
      path.join(tempHome, '.shieldcortex', 'config.json'),
      JSON.stringify({ projectKey: 'pinned-project' }),
    );
    expect(helper.deriveProjectKey(tempRoot)).toBe('pinned-project');
  });

  it('resolves alias for a cwd basename', async () => {
    fs.mkdirSync(path.join(tempHome, '.shieldcortex'), { recursive: true });
    fs.writeFileSync(
      path.join(tempHome, '.shieldcortex', 'config.json'),
      JSON.stringify({ projectAliases: { workspace: 'drakon-agent-platform' } }),
    );
    const cwd = path.join(tempRoot, 'workspace');
    fs.mkdirSync(cwd, { recursive: true });
    expect(helper.deriveProjectKey(cwd)).toBe('drakon-agent-platform');
  });

  it('derives owner-repo from git origin when .git/config is present', async () => {
    const cwd = path.join(tempRoot, 'nested', 'workspace');
    fs.mkdirSync(cwd, { recursive: true });
    const gitDir = path.join(tempRoot, 'nested', '.git');
    fs.mkdirSync(gitDir, { recursive: true });
    fs.writeFileSync(
      path.join(gitDir, 'config'),
      `[remote "origin"]\n\turl = git@github.com:Drakon-Systems-Ltd/ShieldCortex.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n`,
    );
    expect(helper.deriveProjectKey(cwd)).toBe('Drakon-Systems-Ltd-ShieldCortex');
  });

  it('handles https remote URLs', async () => {
    const cwd = path.join(tempRoot, 'repo');
    fs.mkdirSync(cwd, { recursive: true });
    const gitDir = path.join(cwd, '.git');
    fs.mkdirSync(gitDir, { recursive: true });
    fs.writeFileSync(
      path.join(gitDir, 'config'),
      `[remote "origin"]\n\turl = https://github.com/acme/widgets.git\n`,
    );
    expect(helper.deriveProjectKey(cwd)).toBe('acme-widgets');
  });

  it('falls back to cwd basename when no git remote is present', async () => {
    const cwd = path.join(tempRoot, 'solo-repo');
    fs.mkdirSync(cwd, { recursive: true });
    expect(helper.deriveProjectKey(cwd)).toBe('solo-repo');
  });


  it('refuses generic basename workspace without alias (OpenClaw home cwd)', async () => {
    const cwd = path.join(tempRoot, 'workspace');
    fs.mkdirSync(cwd, { recursive: true });
    expect(helper.deriveProjectKey(cwd)).toBeNull();
  });

  it('skips known noise directory segments when using cwd basename', async () => {
    // A bare cwd pointing at myrepo/src should resolve to 'myrepo', not 'src'.
    const cwd = path.join(tempRoot, 'myrepo', 'src');
    fs.mkdirSync(cwd, { recursive: true });
    expect(helper.deriveProjectKey(cwd)).toBe('myrepo');
  });
});

// Load the helper once via dynamic import so ts-jest's ESM loader resolves it.
// Per-test HOME swaps are honoured because loadConfig() re-reads homedir() on
// every call.
beforeAll(async () => {
  const mod = await import(HELPER_URL);
  helper = mod as Helper;
});
