/**
 * Drive the REAL CLI entry point, cheaply and safely (#577).
 *
 * Not a test file (no `.test.ts`, so Jest's testMatch skips it): the harness two
 * entry-point suites share. Both have the same claim to prove — that a help
 * request or a rejected argument costs nothing — and that claim is only credible
 * against the built `dist/index.js` in a child process, because the things it
 * denies (a spawned `npm`, a file under HOME) happen in `main()`'s preamble and
 * not in any handler a unit test can call.
 *
 * So: HOME at an empty temp directory, every inherited SHIELDCORTEX_* variable
 * dropped, and a fake `npm` first on PATH that leaves a marker OUTSIDE HOME if
 * it is ever executed — which keeps "npm never ran" and "HOME is untouched"
 * independent assertions rather than one.
 */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
export const cliEntry = path.join(repoRoot, 'dist', 'index.js');

export interface EntryPointSandbox {
  /** Temp root; the npm marker lives here, outside HOME. */
  tmp: string;
  /** The child's HOME — must stay empty. */
  home: string;
  /** The fake npm's marker file; its existence means a child process ran. */
  marker: string;
  /** True when the fake npm was executed. */
  npmRan(): boolean;
  /** Every path under HOME, relative — the proof that nothing was written. */
  underHome(): string[];
  run(args: string[]): { status: number | null; stdout: string; stderr: string };
  cleanup(): void;
}

function walk(dir: string, base = dir): string[] {
  const out: string[] = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, e.name);
    out.push(path.relative(base, full));
    if (e.isDirectory()) out.push(...walk(full, base));
  }
  return out;
}

export function makeEntryPointSandbox(prefix = 'sc577-entry-'): EntryPointSandbox {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const home = path.join(tmp, 'home');
  const binDir = path.join(tmp, 'bin');
  const marker = path.join(tmp, 'npm-was-executed');
  fs.mkdirSync(home);
  fs.mkdirSync(binDir);
  fs.writeFileSync(
    path.join(binDir, 'npm'),
    `#!/bin/sh\necho "$@" >> ${JSON.stringify(marker)}\nmkdir -p "$HOME/.npm/_logs"\ntouch "$HOME/.npm/_logs/debug.log"\nexit 0\n`,
    { mode: 0o755 },
  );

  return {
    tmp,
    home,
    marker,
    npmRan: () => fs.existsSync(marker),
    underHome: () => walk(home),
    run(args: string[]) {
      const env: Record<string, string> = {};
      for (const [k, v] of Object.entries(process.env)) {
        if (v === undefined) continue;
        if (k.startsWith('SHIELDCORTEX_') || k === 'CLAUDE_MEMORY_DB') continue;
        env[k] = v;
      }
      env.HOME = home;
      env.USERPROFILE = home;
      env.npm_config_cache = path.join(home, '.npm');
      env.PATH = `${binDir}${path.delimiter}${env.PATH ?? ''}`;
      const r = spawnSync(process.execPath, [cliEntry, ...args], {
        env,
        encoding: 'utf-8',
        timeout: 60_000,
      });
      return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
    },
    cleanup() {
      fs.rmSync(tmp, { recursive: true, force: true });
    },
  };
}
