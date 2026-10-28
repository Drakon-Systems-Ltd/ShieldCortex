import { describe, expect, it } from '@jest/globals';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * #931: ClawHub's static scan flags a skill bundle that shells out to a package
 * runner or a shell (`suspicious.dangerous_exec`) and holds the release in
 * manual review. This is a cheap mirror of that rule over skills/shieldcortex,
 * so the finding cannot come back unnoticed.
 */
const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const bundleRoot = join(repoRoot, 'skills', 'shieldcortex');
const SPAWNERS = 'execFile|execFileSync|spawn|spawnSync|fork';
const RUNNERS = '(?:npx|npm|pnpm|yarn|sh|bash|zsh|dash|cmd|cmd\\.exe|powershell|pwsh)(?:\\.cmd)?';

export function findDangerousExec(source: string): string[] {
  const hits: string[] = [];
  const spawnRunner = new RegExp(`\\b(?:${SPAWNERS})\\s*\\(\\s*(['"\`])${RUNNERS}\\1`, 'g');
  for (const m of source.matchAll(spawnRunner)) hits.push(m[0]);
  // exec/execSync always go through a shell.
  if (/child_process/.test(source)) {
    for (const m of source.matchAll(/\b(?:exec|execSync)\s*\(/g)) hits.push(m[0]);
  }
  for (const m of source.matchAll(/\bshell\s*:\s*true\b/g)) hits.push(m[0]);
  return hits;
}

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const full = join(dir, name);
    return statSync(full).isDirectory() ? walk(full) : [full];
  });
}

/**
 * The ClawHub upload set is the whole of skills/shieldcortex (scripts/clawhub-sync.mjs
 * publishes that directory). ClawHub's `suspicious.dangerous_exec` finding fired on a
 * plain `execFile(mcporterBin, ...)`, so the bundle must hold no process-spawning API
 * at all, in any file type: the hook and plugin ship via npm, not via the skill.
 */
const ANY_EXEC = /child_process|\bexecFile(?:Sync)?\b|\bspawn(?:Sync)?\s*\(|\bexec(?:Sync)?\s*\(|\bfork\s*\(/;

export function findAnyExec(text: string): string[] {
  return [...text.matchAll(new RegExp(ANY_EXEC.source, 'g'))].map((m) => m[0]);
}

describe('#931: the ClawHub skill bundle does not shell out to npx/npm/sh', () => {
  it('the rule fires on the pattern ClawHub reported (positive control)', () => {
    const pre931 = 'import { execFile } from "node:child_process";\nexecFile("npx", cmdArgs, {}, cb);';
    expect(findDangerousExec(pre931)).toHaveLength(1);
    expect(findDangerousExec('execFile("sh", ["-c", x])')).toHaveLength(1);
    expect(findDangerousExec('import cp from "child_process"; cp.execSync(cmd)')).toHaveLength(1);
    expect(findDangerousExec('execFile(mcporterBin, cmdArgs, {})')).toEqual([]);
  });

  it('the npm-shipped hook (not part of the skill bundle) still uses npx, so the rule is not vacuous', () => {
    const shipped = readFileSync(join(repoRoot, 'hooks', 'openclaw', 'cortex-memory', 'runtime.mjs'), 'utf8');
    expect(findDangerousExec(shipped).length).toBeGreaterThan(0);
  });
});

describe('ClawHub upload set contains no process-spawning API at all (v5.14.0 held in review)', () => {
  const uploadSet = walk(bundleRoot);

  it('the upload set is the instructions only: SKILL.md and no bundled/ executables', () => {
    expect(uploadSet.map((f) => relative(bundleRoot, f))).toEqual(['SKILL.md']);
    expect(existsSync(join(bundleRoot, 'bundled'))).toBe(false);
  });

  it.each(uploadSet.map((f) => [relative(repoRoot, f), f]))('%s has no child_process/execFile/spawn(/exec(', (_label, file) => {
    expect(findAnyExec(readFileSync(file as string, 'utf8'))).toEqual([]);
  });

  it('the rule fires on the line ClawHub reported (positive control)', () => {
    expect(findAnyExec('execFile(mcporterBin, cmdArgs, {')).toHaveLength(1);
    expect(findAnyExec('spawn("x")')).toHaveLength(1);
    expect(findAnyExec('exec(cmd)')).toHaveLength(1);
    expect(findAnyExec("from 'node:child_process'")).toHaveLength(1);
    expect(findAnyExec('plain prose about executing a process')).toEqual([]);
  });

  it('the hook and plugin still ship via npm (not dropped, only moved off the skill)', () => {
    expect(existsSync(join(repoRoot, 'hooks', 'openclaw', 'cortex-memory', 'runtime.mjs'))).toBe(true);
    expect(existsSync(join(repoRoot, 'plugins', 'openclaw', 'openclaw.plugin.json'))).toBe(true);
    const pkg = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf8'));
    expect(pkg.files).toContain('hooks/openclaw');
  });
});
