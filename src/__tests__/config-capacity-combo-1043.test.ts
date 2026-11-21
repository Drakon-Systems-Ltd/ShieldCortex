/**
 * #1043 round 2: a capacity flag combined with another mutating flag used to
 * half-apply. Against a signed config whose `memory` entry is not an object,
 *
 *   shieldcortex config --auto-memory-sampling 4 --memory-cap ltm=2000
 *
 * wrote and re-signed the sampling cadence, THEN refused the malformed memory
 * block with "Nothing was changed". The capacity flags now run alone: any
 * other option alongside them is refused before anything is read or written.
 *
 * Driven through the BUILT CLI (dist/index.js) under a temp HOME and
 * SHIELDCORTEX_CONFIG_DIR, as cli-help-gate-767.test.ts does.
 */
import { spawnSync } from 'node:child_process';
import { createHmac } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeAll, beforeEach, describe, expect, it } from '@jest/globals';
import { requireFreshBuiltArtefacts } from './built-artefact-freshness.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const DIST_ENTRY = path.join(repoRoot, 'dist', 'index.js');

let home: string;
let configDir: string;

function writeSignedConfig(obj: unknown): void {
  const key = 'a'.repeat(64);
  fs.writeFileSync(path.join(configDir, '.integrity-key'), key, { mode: 0o600 });
  const body = JSON.stringify(obj, null, 2) + '\n';
  fs.writeFileSync(path.join(configDir, 'config.json'), body);
  fs.writeFileSync(path.join(configDir, '.config-sig'), createHmac('sha256', key).update(body, 'utf-8').digest('hex'), { mode: 0o600 });
}

/** Every entry in the config dir: name, bytes and mtime. */
function snapshot(): Array<[string, string, number]> {
  return fs.readdirSync(configDir).sort().map((name) => {
    const p = path.join(configDir, name);
    return [name, fs.readFileSync(p, 'utf-8'), fs.lstatSync(p).mtimeMs];
  });
}

function runCli(args: string[]): { status: number | null; out: string } {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    SHIELDCORTEX_CONFIG_DIR: configDir,
    NO_COLOR: '1',
  };
  delete env.CLAUDE_MEMORY_DB;
  delete env.SHIELDCORTEX_AUDIT_DIR;
  const r = spawnSync(process.execPath, [DIST_ENTRY, 'config', ...args], {
    env, cwd: home, encoding: 'utf8', input: '', timeout: 30_000,
  });
  return { status: r.status, out: `${r.stdout ?? ''}${r.stderr ?? ''}` };
}

beforeAll(() => {
  requireFreshBuiltArtefacts({
    repoRoot,
    sources: ['src/index.ts', 'src/cloud/cli.ts', 'src/cloud/config.ts'].map((p) => path.join(repoRoot, p)),
    artefacts: ['dist/index.js', 'dist/cloud/cli.js', 'dist/cloud/config.js'].map((p) => path.join(repoRoot, p)),
  });
});

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1043-combo-'));
  configDir = path.join(home, '.shieldcortex');
  fs.mkdirSync(configDir, { recursive: true });
});

afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

describe('#1043 capacity flags never half-apply alongside another setter (built CLI)', () => {
  it.each([
    ['a malformed memory block', { memory: null, autoMemory: { stopHookSamplingTurns: 2 } }],
    ['a well-formed config', { memory: {}, autoMemory: { stopHookSamplingTurns: 2 } }],
  ])('--auto-memory-sampling 4 --memory-cap ltm=2000 on %s: refused, config bytes unchanged', (_name, cfg) => {
    writeSignedConfig(cfg);
    const before = snapshot();
    const r = runCli(['--auto-memory-sampling', '4', '--memory-cap', 'ltm=2000']);
    expect(r.status).toBe(1);
    expect(r.out).toMatch(/cannot be combined with other options \(found --auto-memory-sampling\)\. Nothing was changed/);
    expect(r.out).not.toMatch(/sampling set to/);
    expect(snapshot()).toEqual(before);
  });

  it('a flag after the capacity flag is refused the same way', () => {
    writeSignedConfig({ memory: {} });
    const before = snapshot();
    const r = runCli(['--disk-budget', '1GB', '--mode', 'strict']);
    expect(r.status).toBe(1);
    expect(r.out).toMatch(/found --mode/);
    expect(snapshot()).toEqual(before);
  });

  it('the two capacity flags together still write one signed change', () => {
    writeSignedConfig({ memory: {} });
    const r = runCli(['--memory-cap', 'ltm=2000', '--disk-budget', '1GB']);
    expect(r.status).toBe(0);
    const raw = JSON.parse(fs.readFileSync(path.join(configDir, 'config.json'), 'utf-8'));
    expect(raw.memory).toEqual({ maxLongTermMemories: 2000 });
    expect(raw.storage).toEqual({ diskBudgetBytes: 1_000_000_000 });
  });
});
