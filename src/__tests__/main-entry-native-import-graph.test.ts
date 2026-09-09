import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync, appendFileSync } from 'fs';
import os from 'os';
import path from 'path';
import { spawnSync } from 'child_process';
import { fileURLToPath } from 'url';
import { afterAll, beforeAll, describe, expect, it } from '@jest/globals';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');
const DIST = path.join(REPO_ROOT, 'dist');

/**
 * `dist/index.js` is BOTH the `bin` entry and the package `main`, and it ends
 * with `export * from './lib.js'` — which statically re-exports `initDatabase`
 * and therefore evaluates `dist/database/better-sqlite3-guard.js` before
 * `main()` runs. While that guard loaded better-sqlite3 at module evaluation,
 * an unloadable binding killed the process before command dispatch: `--help`,
 * `doctor`, `repair` and the MCP startup self-heal — every command that exists
 * to FIX a broken binding — exited 1 with no dispatch at all. CI never sees it
 * because better-sqlite3 always loads there.
 *
 * `src/__tests__/scan-only-entry.test.ts` already pins the equivalent
 * invariant for the `shieldcortex/scan` entry. This file pins it for the main
 * entry and the recovery modules, in two independent ways:
 *
 *  1. STRUCTURALLY — the compiled recovery modules must have no STATIC import
 *     path to the guard at all (that is the edge a10cc0f added and this branch
 *     removed).
 *  2. BEHAVIOURALLY — the actual built artefact, run against a better-sqlite3
 *     that throws on load, must still dispatch. A positive control in the same
 *     sandbox reproduces the pre-fix module-evaluation load and asserts the
 *     harness catches it, so this can never degrade into a green no-op.
 *
 * Every child process below is spawned with `spawnSync(process.execPath, [...])`
 * — an argv array, never a shell string — so no sandbox path is interpolated
 * into a command line.
 */

// ── Static import-graph walk ───────────────────────────────────────────────

/**
 * Collect STATIC import/export-from specifiers only.
 *
 * Deliberately narrower than the walker in scan-only-entry.test.ts, which also
 * follows `import()` calls: the property under test here is what ESM evaluates
 * BEFORE the entry module's own body runs, and a dynamic import is by
 * definition not part of that. Counting dynamic edges would flag every lazily
 * dispatched CLI command and make the assertion meaningless.
 */
function collectStaticSpecifiers(src: string): string[] {
  const withoutComments = src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1');
  const specs: string[] = [];
  const STATIC = /(?:^|\n)\s*(?:import|export)[\s\S]*?from\s*['"]([^'"]+)['"]/g;
  const BARE_IMPORT = /(?:^|\n)\s*import\s*['"]([^'"]+)['"]/g;
  for (const re of [STATIC, BARE_IMPORT]) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(withoutComments)) !== null) specs.push(m[1]);
  }
  return specs;
}

function isLocal(spec: string): boolean {
  return spec.startsWith('./') || spec.startsWith('../');
}

function resolveLocal(from: string, spec: string): string {
  const resolved = path.resolve(path.dirname(from), spec);
  for (const candidate of [resolved, `${resolved}.js`, path.join(resolved, 'index.js')]) {
    if (existsSync(candidate)) return candidate;
  }
  return resolved.endsWith('.js') ? resolved : `${resolved}.js`;
}

/** Every local file reachable from `entryFile` through STATIC edges only. */
function staticGraph(entryFile: string): Set<string> {
  const visited = new Set<string>();
  const queue = [entryFile];
  while (queue.length) {
    const file = queue.pop()!;
    if (visited.has(file)) continue;
    visited.add(file);
    if (!existsSync(file)) {
      throw new Error(`Static import graph references a missing file: ${file}`);
    }
    for (const spec of collectStaticSpecifiers(readFileSync(file, 'utf8'))) {
      if (isLocal(spec)) queue.push(resolveLocal(file, spec));
    }
  }
  return visited;
}

function requireDist(): void {
  if (!existsSync(path.join(DIST, 'index.js'))) {
    throw new Error('dist/index.js missing — run `npm run build:ts` before this test');
  }
}

// ── Built-artefact sandbox ─────────────────────────────────────────────────

const THROWING_STUB_MESSAGE =
  '/app/node_modules/better-sqlite3/prebuilds/linux-x64.node: invalid ELF header';

/**
 * A self-contained copy of the built package whose `better-sqlite3` throws on
 * load, exactly as an unloadable packaged prebuild does.
 *
 * The stub is planted at `<sandbox>/dist/node_modules/better-sqlite3`, which
 * Node's resolver checks BEFORE `<sandbox>/node_modules` (a symlink to the
 * real install) for any require originating under `<sandbox>/dist`. So every
 * other dependency resolves normally and only better-sqlite3 is poisoned —
 * and the real `node_modules` is never modified.
 */
function makeSandbox(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'sc-native-entry-'));
  cpSync(DIST, path.join(dir, 'dist'), { recursive: true });
  cpSync(path.join(REPO_ROOT, 'package.json'), path.join(dir, 'package.json'));
  // dist/memory/consolidate.js and the hook entries import `../scripts/lib/*.mjs`
  // as real sibling files, so the sandbox needs them alongside dist.
  cpSync(path.join(REPO_ROOT, 'scripts'), path.join(dir, 'scripts'), { recursive: true });
  symlinkSync(path.join(REPO_ROOT, 'node_modules'), path.join(dir, 'node_modules'), 'dir');

  const stubDir = path.join(dir, 'dist', 'node_modules', 'better-sqlite3');
  mkdirSync(stubDir, { recursive: true });
  writeFileSync(
    path.join(stubDir, 'package.json'),
    JSON.stringify({ name: 'better-sqlite3', version: '13.0.3', main: 'index.js' }),
  );
  writeFileSync(
    path.join(stubDir, 'index.js'),
    `throw new Error(${JSON.stringify(THROWING_STUB_MESSAGE)});\n`,
  );
  return dir;
}

/**
 * Re-introduce the pre-fix defect INSIDE a sandbox: a module-evaluation-time
 * load in the guard, throwing the same typed error the old
 * `const BetterSqlite3 = loadBetterSqlite3()` did. This is the positive
 * control — the assertions below must fail against it.
 */
function reproducePreFixEagerLoad(sandbox: string): void {
  appendFileSync(
    path.join(sandbox, 'dist', 'database', 'better-sqlite3-guard.js'),
    [
      '',
      '// [test control] reproduction of the pre-fix module-evaluation load.',
      'const __preFixEager = (() => {',
      "  try { return require('better-sqlite3'); }",
      '  catch (err) {',
      '    throw new NativeModuleLoadError(',
      '      formatNativeLoadError(err, process.version, String(process.versions.modules)),',
      '      err,',
      '    );',
      '  }',
      '})();',
      'export default __preFixEager;',
      '',
    ].join('\n'),
  );
}

/** argv-array spawn (never a shell string) of the CURRENT node binary. */
function runNode(args: string[], cwd: string) {
  return spawnSync(process.execPath, args, {
    cwd,
    encoding: 'utf-8',
    timeout: 90_000,
    windowsHide: true,
  });
}

describe('main entry must dispatch with an unloadable native binding', () => {
  describe('import-graph edge safety (compiled dist, static edges only)', () => {
    // These four are the recovery surface. `dist/cli/doctor.js` is deliberately
    // NOT here: it genuinely opens the database (via database/init.js) and so
    // legitimately reaches the guard — which is now inert at module evaluation.
    const RECOVERY_ENTRIES = [
      'cli/scan-exit.js',
      'setup/native-binding.js',
      'cli/repair.js',
      'setup/mcp-self-heal.js',
    ];

    it('dist is built (run npm run build:ts first)', () => {
      requireDist();
      expect(existsSync(path.join(DIST, 'database', 'better-sqlite3-guard.js'))).toBe(true);
    });

    for (const entry of RECOVERY_ENTRIES) {
      it(`dist/${entry} has no static import path to better-sqlite3-guard.js`, () => {
        requireDist();
        const graph = staticGraph(path.join(DIST, entry));
        const guard = path.join(DIST, 'database', 'better-sqlite3-guard.js');
        expect([...graph].filter((f) => f === guard)).toEqual([]);
      });
    }

    it('`src/index.ts` reaches scan-exit statically, which is why that edge matters', () => {
      // Pins the premise: if this ever became a dynamic import the structural
      // assertion above would silently stop protecting anything.
      const indexSrc = readFileSync(path.join(REPO_ROOT, 'src', 'index.ts'), 'utf8');
      expect(indexSrc).toMatch(/^import \{[^}]*\} from '\.\/cli\/scan-exit\.js';$/m);
    });
  });

  describe('built artefact against a better-sqlite3 that throws on load', () => {
    let sandbox: string;
    let control: string;

    beforeAll(() => {
      requireDist();
      sandbox = makeSandbox();
      control = makeSandbox();
      reproducePreFixEagerLoad(control);
    }, 120_000);

    afterAll(() => {
      for (const dir of [sandbox, control]) {
        if (dir) rmSync(dir, { recursive: true, force: true });
      }
    });

    it('the stub really is unloadable (sanity check on the harness itself)', () => {
      const probe = runNode(
        ['-e', "try { require('better-sqlite3'); console.log('LOADED'); } catch (e) { console.log('THREW:' + e.message); }"],
        path.join(sandbox, 'dist'),
      );
      expect(probe.stdout).toContain('THREW:');
      expect(probe.stdout).toContain('invalid ELF header');
    }, 120_000);

    it('`--help` still dispatches (exit 0, usage printed)', () => {
      const r = runNode([path.join(sandbox, 'dist', 'index.js'), '--help'], sandbox);
      expect(r.stderr ?? '').not.toContain('NativeModuleLoadError');
      expect(r.stdout).toContain('USAGE');
      expect(r.status).toBe(0);
    }, 120_000);

    it('the recovery modules load without touching the native addon', () => {
      const script = [
        `await import(${JSON.stringify(path.join(sandbox, 'dist', 'cli', 'repair.js'))});`,
        `await import(${JSON.stringify(path.join(sandbox, 'dist', 'setup', 'mcp-self-heal.js'))});`,
        `process.stdout.write('RECOVERY_MODULES_LOADED');`,
      ].join('\n');
      const r = runNode(['--input-type=module', '-e', script], sandbox);
      expect(r.stderr ?? '').not.toContain('invalid ELF header');
      expect(r.stdout).toContain('RECOVERY_MODULES_LOADED');
      expect(r.status).toBe(0);
    }, 120_000);

    it('opening a database still fails loudly with the typed error (the load is deferred, not swallowed)', () => {
      const script = [
        `const { getBetterSqlite3 } = await import(${JSON.stringify(path.join(sandbox, 'dist', 'database', 'better-sqlite3-guard.js'))});`,
        `try { getBetterSqlite3(); process.stdout.write('NO_THROW'); }`,
        `catch (err) { process.stdout.write(err.name + '|' + String(err.message).includes('invalid ELF header')); }`,
      ].join('\n');
      const r = runNode(['--input-type=module', '-e', script], sandbox);
      expect(r.stdout).toBe('NativeModuleLoadError|true');
    }, 120_000);

    it('CONTROL: reproducing the pre-fix eager load makes `--help` fail before dispatch', () => {
      const r = runNode([path.join(control, 'dist', 'index.js'), '--help'], control);
      expect(r.stdout ?? '').not.toContain('USAGE');
      expect(r.stderr ?? '').toContain('NativeModuleLoadError');
      expect(r.status).not.toBe(0);
    }, 120_000);

    it('CONTROL: the pre-fix guard detonates on mere import, while the fixed one does not', () => {
      const importGuard = (root: string) =>
        runNode(
          [
            '--input-type=module',
            '-e',
            [
              `await import(${JSON.stringify(path.join(root, 'dist', 'database', 'better-sqlite3-guard.js'))});`,
              `process.stdout.write('GUARD_IMPORTED');`,
            ].join('\n'),
          ],
          root,
        );

      const broken = importGuard(control);
      expect(broken.stdout ?? '').not.toContain('GUARD_IMPORTED');
      expect(broken.stderr ?? '').toContain('NativeModuleLoadError');

      const fixed = importGuard(sandbox);
      expect(fixed.stdout).toContain('GUARD_IMPORTED');
      expect(fixed.status).toBe(0);
    }, 120_000);
  });
});
