import { describe, expect, it } from '@jest/globals';
import { readdirSync, readFileSync, statSync } from 'node:fs';
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
const SOURCE = /\.(?:[cm]?js|ts|tsx)$/;
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

describe('#931: the ClawHub skill bundle does not shell out to npx/npm/sh', () => {
  const files = walk(bundleRoot).filter((f) => SOURCE.test(f));

  it('scans a non-empty bundle', () => {
    expect(files.length).toBeGreaterThan(0);
  });

  it.each(files.map((f) => [relative(repoRoot, f), f]))('%s has no dangerous exec', (_label, file) => {
    expect(findDangerousExec(readFileSync(file as string, 'utf8'))).toEqual([]);
  });

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
