import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync, appendFileSync } from 'fs';
import os from 'os';
import path from 'path';
import { spawnSync } from 'child_process';
import { fileURLToPath } from 'url';
import { afterAll, beforeAll, describe, expect, it } from '@jest/globals';
import {
  isNativeModuleLoadError,
  isPackagedPrebuildLoadError,
} from '../database/native-load-classify.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');
const DIST = path.join(REPO_ROOT, 'dist');

/**
 * `dist/index.js` is BOTH the `bin` entry and the package `main`, and it ends
 * with `export * from './lib.js'` — which statically re-exports `initDatabase`
 * and therefore evaluates `dist/database/better-sqlite3-guard.js` before
 * `main()` runs. While that guard required better-sqlite3 at module
 * evaluation, an unrequirable package killed the process before command
 * dispatch: `--help`, `doctor`, `repair` and the MCP startup self-heal — every
 * command that exists to FIX a broken install — exited 1 with no dispatch at
 * all. CI never sees it because better-sqlite3 always installs cleanly there.
 *
 * better-sqlite3 13 has TWO distinct failure shapes and they are NOT
 * interchangeable. Conflating them is how the defect got mis-described in the
 * first place, so this file pins each one separately:
 *
 *  • REQUIRE-time — `require('better-sqlite3')` itself throws. v13's
 *    `lib/index.js` is `require('./database')(require('./binding').getBinding,
 *    true)`: `getBinding` is handed over as a FUNCTION, so requiring the
 *    package resolves JavaScript only and opens no `.node` file. This call
 *    therefore only fails when the PACKAGE cannot be required at all — not
 *    installed, stripped by a pruning install, or a corrupt entry file. THIS
 *    is the shape that used to kill dispatch, and the shape the lazy guard
 *    fixes.
 *
 *  • CONSTRUCTION-time — `require` succeeds and returns a constructor; the
 *    `prebuilds/<platform>-<arch>.node` binary is dlopen'd inside
 *    `new Database(...)`. An unloadable or Node-API-incompatible prebuild
 *    throws from the CONSTRUCTOR. It never blocked dispatch, before the fix or
 *    after it — but it must still reach the caller as the classified
 *    install-failure, never as "your database is corrupt".
 *
 * `src/__tests__/scan-only-entry.test.ts` already pins the equivalent
 * import-graph invariant for the `shieldcortex/scan` entry. This file pins the
 * main entry and the recovery modules, in two independent ways:
 *
 *  1. STRUCTURALLY — the compiled recovery modules must have no STATIC import
 *     path to the guard at all (that is the edge a10cc0f added and this branch
 *     removed).
 *  2. BEHAVIOURALLY — the actual built artefact, run against each broken
 *     better-sqlite3, must still dispatch. A positive control in the same
 *     sandbox reproduces the pre-fix module-evaluation require and asserts the
 *     harness catches it, so this can never degrade into a green no-op.
 *
 * Every child process below is spawned with `spawnSync(process.execPath, [...])`
 * — an argv array, never a shell string — so no sandbox path is interpolated
 * into a command line, and every sandbox is a fresh mkdtemp directory that is
 * removed afterwards. No live config, database or install is touched.
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

// ── The two failure shapes ─────────────────────────────────────────────────

type FailureShape = 'require' | 'construct' | 'syntax' | 'missing-internal';

/**
 * REQUIRE-time failure: the package entry cannot be required at all. Modelled
 * with the MODULE_NOT_FOUND shape Node raises for the commonest cause (the
 * package missing, e.g. after a pruning install), which
 * `native-load-classify.ts` already catalogues as a native-load signature.
 * This is deliberately NOT a prebuild error — requiring v13 never opens a
 * `.node` file, so no prebuild fault can surface here.
 */
const REQUIRE_FAILURE_MESSAGE = "Cannot find module 'better-sqlite3'";

/**
 * CONSTRUCTION-time failure: the packaged Node-API prebuild is present but
 * unusable on this runtime. Shaped like the real error for THIS box — the
 * `prebuilds/<platform>-<arch>.node` path v13 resolves plus Node's own
 * Node-API-version wording — so `isPackagedPrebuildLoadError` sees exactly
 * what it would see in production.
 */
const CONSTRUCT_FAILURE_MESSAGE =
  `The module '/app/node_modules/better-sqlite3/prebuilds/${process.platform}-${process.arch}.node' `
  + 'requires Node-API version 10, but this version of Node.js only supports version 9 add-ons.';

/**
 * The two PACKAGE-LOAD shapes whose thrown error says nothing about a native
 * addon at all — the entry file is broken JavaScript, or it requires an
 * internal file a pruning install removed.
 *
 * Both are require-time failures like `require` above, but `Cannot find module
 * 'better-sqlite3'` is a catalogued native-load signature and these are not:
 * `isNativeModuleLoadError` returns FALSE for "Unexpected end of input" and for
 * "Cannot find module './lib/index.js'". Anything that classifies a load
 * failure by reading its message therefore cannot see them — which is why the
 * doctor split below has to be structural (a separately guarded load stage,
 * classified by the loader's TYPE) rather than one more regex.
 */
const SYNTAX_FAILURE_DETAIL = 'Unexpected end of input';
const MISSING_INTERNAL_FAILURE_DETAIL = "Cannot find module './lib/index.js'";

const STUB_SOURCE: Record<FailureShape, string> = {
  // A REAL JavaScript SyntaxError raised by the parser at require time — the
  // entry file truncated mid-object, as a half-written install or a torn npm
  // cache entry leaves it. Deliberately not an Error whose *message* is
  // stage-managed: the point is that the parser, not the test, decides what
  // this failure looks like.
  syntax: [
    "'use strict';",
    '// Truncated mid-object: requiring this file is a parse error.',
    'module.exports = {',
    '',
  ].join('\n'),
  // The package entry is intact but an internal file it requires is gone.
  'missing-internal': [
    "'use strict';",
    '// The entry resolves, its own dependency does not (pruned/partial install).',
    "module.exports = require('./lib/index.js');",
    '',
  ].join('\n'),
  require: [
    "'use strict';",
    '// The package cannot be required at all (missing / stripped / corrupt entry).',
    `const err = new Error(${JSON.stringify(REQUIRE_FAILURE_MESSAGE)});`,
    "err.code = 'MODULE_NOT_FOUND';",
    'throw err;',
    '',
  ].join('\n'),
  construct: [
    "'use strict';",
    '// Requiring resolves JavaScript only — exactly as better-sqlite3 13 does.',
    "// The prebuild is dlopen'd inside the constructor, so that is what fails.",
    'function Database() {',
    `  throw new Error(${JSON.stringify(CONSTRUCT_FAILURE_MESSAGE)});`,
    '}',
    'module.exports = Database;',
    'module.exports.SqliteError = class SqliteError extends Error {};',
    '',
  ].join('\n'),
};

// ── Built-artefact sandbox ─────────────────────────────────────────────────

/**
 * A self-contained copy of the built package whose `better-sqlite3` fails in
 * the requested shape.
 *
 * The stub is planted at `<sandbox>/dist/node_modules/better-sqlite3`, which
 * Node's resolver checks BEFORE `<sandbox>/node_modules` (a symlink to the
 * real install) for any require originating under `<sandbox>/dist`. So every
 * other dependency resolves normally and only better-sqlite3 is poisoned —
 * and the real `node_modules` is never modified.
 */
function makeSandbox(shape: FailureShape): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), `sc-native-entry-${shape}-`));
  cpSync(DIST, path.join(dir, 'dist'), { recursive: true });
  cpSync(path.join(REPO_ROOT, 'package.json'), path.join(dir, 'package.json'));
  // dist/memory/consolidate.js and the hook entries import `../scripts/lib/*.mjs`
  // as real sibling files, so the sandbox needs them alongside dist.
  cpSync(path.join(REPO_ROOT, 'scripts'), path.join(dir, 'scripts'), { recursive: true });
  symlinkSync(path.join(REPO_ROOT, 'node_modules'), path.join(dir, 'node_modules'), 'dir');
  plantStub(dir, shape);
  return dir;
}

/**
 * (Re)write the poisoned better-sqlite3 in an existing sandbox. Split out of
 * makeSandbox so a describe that exercises several REQUIRE-time shapes pays
 * for one 6 MB dist copy instead of one per shape — every child process is
 * spawned fresh, so re-planting between spawns is the whole of the setup.
 */
function plantStub(sandbox: string, shape: FailureShape): void {
  const stubDir = path.join(sandbox, 'dist', 'node_modules', 'better-sqlite3');
  mkdirSync(stubDir, { recursive: true });
  writeFileSync(
    path.join(stubDir, 'package.json'),
    JSON.stringify({ name: 'better-sqlite3', version: '13.0.3', main: 'index.js' }),
  );
  writeFileSync(path.join(stubDir, 'index.js'), STUB_SOURCE[shape]);
}

/**
 * Re-introduce the pre-fix defect INSIDE a sandbox: a module-evaluation-time
 * require in the guard, throwing the same typed error the old
 * `const BetterSqlite3 = loadBetterSqlite3()` did. This is the positive
 * control — the require-shape assertions below must fail against it.
 */
function reproducePreFixEagerLoad(sandbox: string): void {
  appendFileSync(
    path.join(sandbox, 'dist', 'database', 'better-sqlite3-guard.js'),
    [
      '',
      '// [test control] reproduction of the pre-fix module-evaluation require.',
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

/**
 * argv-array spawn (never a shell string) of the CURRENT node binary.
 *
 * `env`, when given, is MERGED over the inherited environment — the CLI cases
 * below need HOME / CLAUDE_MEMORY_DB pointed inside the sandbox so no live
 * config or database is read or written.
 */
function runNode(args: string[], cwd: string, env?: NodeJS.ProcessEnv) {
  return spawnSync(process.execPath, args, {
    cwd,
    encoding: 'utf-8',
    timeout: 90_000,
    windowsHide: true,
    ...(env ? { env: { ...process.env, ...env } } : {}),
  });
}

/** Run an ESM snippet in a child of the given sandbox. */
function runModule(source: string, cwd: string) {
  return runNode(['--input-type=module', '-e', source], cwd);
}

const distPath = (root: string, ...rest: string[]) => path.join(root, 'dist', ...rest);

const occurrences = (text: string, needle: string): number => text.split(needle).length - 1;

/**
 * The COMPLETE user-facing output for a REQUIRE-time (missing / source-only)
 * failure, asserted as one whole rather than per-layer.
 *
 * The formatter is not self-idempotent: its generic diagnosis says "this Node
 * build predates the Node-API version it requires", which is itself a
 * packaged-prebuild signature. So formatting an already-formatted message a
 * second time both NESTS a duplicate header and FLIPS the class, headlining
 * "a source build cannot safely override the packaged prebuild" above the one
 * remedy that actually works. Counting occurrences across the whole output is
 * what catches that — a `toContain` on the correct guidance passes happily
 * while the contradiction sits two layers above it.
 */
function expectMissingSourceOnlyGuidance(text: string): void {
  expect(occurrences(text, 'ShieldCortex could not load its database engine')).toBe(1);
  expect(occurrences(text, 'For a missing/source-only binding, run `shieldcortex repair`')).toBe(1);
  expect(text).not.toContain('The packaged Node-API native binding cannot be loaded here');
  expect(text).not.toContain('a source build cannot safely override the packaged prebuild');
}

describe('main entry must dispatch with a broken better-sqlite3', () => {
  describe('the two failure shapes are genuinely different faults', () => {
    it('the require-time stub is NOT a packaged-prebuild failure', () => {
      const err = new Error(REQUIRE_FAILURE_MESSAGE);
      expect(isNativeModuleLoadError(err)).toBe(true);
      expect(isPackagedPrebuildLoadError(err)).toBe(false);
    });

    it('the construction-time stub IS a packaged-prebuild failure', () => {
      const err = new Error(CONSTRUCT_FAILURE_MESSAGE);
      expect(isNativeModuleLoadError(err)).toBe(true);
      expect(isPackagedPrebuildLoadError(err)).toBe(true);
    });

    // The control for the doctor split below: these two are genuine
    // package-load failures that the MESSAGE classifier cannot see. Any fix
    // that routed them by inspecting error text would leave them exactly where
    // they were — in the "must be file corruption, then" branch.
    it('a corrupt entry / missing internal module is invisible to the message classifier', () => {
      const syntaxErr = new SyntaxError(SYNTAX_FAILURE_DETAIL);
      expect(isNativeModuleLoadError(syntaxErr)).toBe(false);
      expect(isPackagedPrebuildLoadError(syntaxErr)).toBe(false);

      const missingInternal = new Error(
        `${MISSING_INTERNAL_FAILURE_DETAIL}\nRequire stack:\n- /app/node_modules/better-sqlite3/index.js`,
      );
      expect(isNativeModuleLoadError(missingInternal)).toBe(false);
      expect(isPackagedPrebuildLoadError(missingInternal)).toBe(false);
    });
  });

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

  describe('REQUIRE-time failure: better-sqlite3 cannot be required at all', () => {
    let sandbox: string;
    let control: string;

    const LIVE_DB_CONTENT = 'require-shape-live-database-bytes-that-must-survive';

    /** A fresh directory holding a pre-existing "live" DB, one per test. */
    const liveDbDir = (name: string): string => {
      const dir = path.join(sandbox, `dbstate-${name}`);
      mkdirSync(dir, { recursive: true });
      writeFileSync(path.join(dir, 'memories.db'), LIVE_DB_CONTENT);
      return dir;
    };

    beforeAll(() => {
      requireDist();
      sandbox = makeSandbox('require');
      control = makeSandbox('require');
      reproducePreFixEagerLoad(control);
    }, 180_000);

    afterAll(() => {
      for (const dir of [sandbox, control]) {
        if (dir) rmSync(dir, { recursive: true, force: true });
      }
    });

    it('the stub really is unrequirable (sanity check on the harness itself)', () => {
      const probe = runNode(
        ['-e', "try { require('better-sqlite3'); console.log('LOADED'); } catch (e) { console.log('THREW:' + e.message); }"],
        distPath(sandbox),
      );
      expect(probe.stdout).toContain('THREW:');
      expect(probe.stdout).toContain(REQUIRE_FAILURE_MESSAGE);
    }, 120_000);

    it('`--help` still dispatches (exit 0, usage printed)', () => {
      const r = runNode([distPath(sandbox, 'index.js'), '--help'], sandbox);
      expect(r.stderr ?? '').not.toContain('NativeModuleLoadError');
      expect(r.stdout).toContain('USAGE');
      expect(r.status).toBe(0);
    }, 120_000);

    it('the recovery modules load without touching better-sqlite3', () => {
      const r = runModule(
        [
          `await import(${JSON.stringify(distPath(sandbox, 'cli', 'repair.js'))});`,
          `await import(${JSON.stringify(distPath(sandbox, 'setup', 'mcp-self-heal.js'))});`,
          `process.stdout.write('RECOVERY_MODULES_LOADED');`,
        ].join('\n'),
        sandbox,
      );
      expect(r.stderr ?? '').not.toContain(REQUIRE_FAILURE_MESSAGE);
      expect(r.stdout).toContain('RECOVERY_MODULES_LOADED');
      expect(r.status).toBe(0);
    }, 120_000);

    it('asking for the constructor still fails loudly with the typed error (deferred, not swallowed)', () => {
      const r = runModule(
        [
          `const { getBetterSqlite3 } = await import(${JSON.stringify(distPath(sandbox, 'database', 'better-sqlite3-guard.js'))});`,
          `try { getBetterSqlite3(); process.stdout.write('NO_THROW'); }`,
          `catch (err) { process.stdout.write(err.name + '|' + String(err.message).includes(${JSON.stringify(REQUIRE_FAILURE_MESSAGE)})); }`,
        ].join('\n'),
        sandbox,
      );
      expect(r.stdout).toBe('NativeModuleLoadError|true');
    }, 120_000);

    it('a real initDatabase keeps the missing/source-only class and never touches the DB file', () => {
      // The construction-shape sibling below has always driven initDatabase.
      // The require shape reaches this catch for the FIRST time now that the
      // guard is lazy, carrying an already-formatted NativeModuleLoadError —
      // which is precisely the input that used to be re-formatted into the
      // wrong class.
      const dbDir = liveDbDir('init');
      const dbPath = path.join(dbDir, 'memories.db');
      const resultPath = path.join(dbDir, 'init-result.json');
      const r = runModule(
        [
          `const { writeFileSync } = await import('fs');`,
          `const { initDatabase } = await import(${JSON.stringify(distPath(sandbox, 'database', 'init.js'))});`,
          `let out;`,
          `try { initDatabase(${JSON.stringify(dbPath)}); out = { threw: false, name: '', message: '' }; }`,
          `catch (err) { out = { threw: true, name: err && err.name, message: String(err && err.message) }; }`,
          `writeFileSync(${JSON.stringify(resultPath)}, JSON.stringify(out));`,
        ].join('\n'),
        sandbox,
      );
      expect(r.status).toBe(0);
      const out = JSON.parse(readFileSync(resultPath, 'utf8'));
      expect(out.threw).toBe(true);
      // The typed class must survive the wrap: it is what lets the next
      // consumer render the failure without re-deriving a class from prose.
      expect(out.name).toBe('NativeModuleLoadError');
      expectMissingSourceOnlyGuidance(out.message);
      expect(out.message).toContain('NOT database corruption');
      expect(out.message).toContain(REQUIRE_FAILURE_MESSAGE);
      expect(readFileSync(dbPath, 'utf8')).toBe(LIVE_DB_CONTENT);
      expect(readdirSync(dbDir).filter((name) => name.includes('.corrupt.'))).toEqual([]);
    }, 120_000);

    it('the real `scan` CLI exits 3 with one header and the same unflipped guidance', () => {
      const dbDir = liveDbDir('scan');
      const dbPath = path.join(dbDir, 'memories.db');
      const r = runNode([distPath(sandbox, 'index.js'), 'scan', 'hello world'], sandbox, {
        HOME: sandbox,
        CLAUDE_MEMORY_DB: dbPath,
        SHIELDCORTEX_AUDIT_DIR: path.join(sandbox, 'audit'),
      });
      expect(r.status).toBe(3);
      const output = `${r.stdout ?? ''}\n${r.stderr ?? ''}`;
      expect(occurrences(output, 'Scan tool failure (native binding)')).toBe(1);
      expectMissingSourceOnlyGuidance(output);
      expect(output).toContain('NOT database corruption');
      expect(output).not.toContain('ShieldCortex Scan Result');
      expect(readFileSync(dbPath, 'utf8')).toBe(LIVE_DB_CONTENT);
      expect(readdirSync(dbDir).filter((name) => name.includes('.corrupt.'))).toEqual([]);
    }, 120_000);

    it('CONTROL: reproducing the pre-fix eager require makes `--help` fail before dispatch', () => {
      const r = runNode([distPath(control, 'index.js'), '--help'], control);
      expect(r.stdout ?? '').not.toContain('USAGE');
      expect(r.stderr ?? '').toContain('NativeModuleLoadError');
      expect(r.status).not.toBe(0);
    }, 120_000);

    it('CONTROL: the pre-fix guard detonates on mere import, while the fixed one does not', () => {
      const importGuard = (root: string) =>
        runModule(
          [
            `await import(${JSON.stringify(distPath(root, 'database', 'better-sqlite3-guard.js'))});`,
            `process.stdout.write('GUARD_IMPORTED');`,
          ].join('\n'),
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

  describe('CONSTRUCTION-time failure: the packaged prebuild is unloadable', () => {
    let sandbox: string;
    let dbDir: string;

    const LIVE_DB_CONTENT = 'live-database-bytes-that-must-survive';

    beforeAll(() => {
      requireDist();
      sandbox = makeSandbox('construct');
      dbDir = path.join(sandbox, 'dbstate');
      mkdirSync(dbDir, { recursive: true });
      writeFileSync(path.join(dbDir, 'memories.db'), LIVE_DB_CONTENT);
    }, 180_000);

    afterAll(() => {
      if (sandbox) rmSync(sandbox, { recursive: true, force: true });
    });

    it('requiring the package SUCCEEDS — only construction throws (harness sanity)', () => {
      const probe = runNode(
        [
          '-e',
          "const B = require('better-sqlite3');"
          + " process.stdout.write('REQUIRED:' + typeof B + '|');"
          + " try { new B('/tmp/never-created.db'); process.stdout.write('NO_THROW'); }"
          + ' catch (e) { process.stdout.write(e.message); }',
        ],
        distPath(sandbox),
      );
      expect(probe.stdout).toContain('REQUIRED:function|');
      expect(probe.stdout).toContain(CONSTRUCT_FAILURE_MESSAGE);
      expect(probe.status).toBe(0);
    }, 120_000);

    it('`--help` still dispatches (exit 0, usage printed)', () => {
      const r = runNode([distPath(sandbox, 'index.js'), '--help'], sandbox);
      expect(r.stderr ?? '').not.toContain('NativeModuleLoadError');
      expect(r.stdout).toContain('USAGE');
      expect(r.status).toBe(0);
    }, 120_000);

    it('the guard hands back the constructor without throwing, and the throw is classified at construction', () => {
      const resultPath = path.join(dbDir, 'ctor-probe.json');
      const r = runModule(
        [
          `const { writeFileSync } = await import('fs');`,
          `const { getBetterSqlite3 } = await import(${JSON.stringify(distPath(sandbox, 'database', 'better-sqlite3-guard.js'))});`,
          `const classify = await import(${JSON.stringify(distPath(sandbox, 'database', 'native-load-classify.js'))});`,
          `const out = { guardThrew: false, ctorType: '', constructThrew: false, message: '', native: false, packaged: false };`,
          `let Ctor;`,
          `try { Ctor = getBetterSqlite3(); out.ctorType = typeof Ctor; }`,
          `catch (err) { out.guardThrew = true; out.message = String(err.message); }`,
          `if (Ctor) {`,
          `  try { new Ctor(${JSON.stringify(path.join(dbDir, 'probe.db'))}); }`,
          `  catch (err) {`,
          `    out.constructThrew = true;`,
          `    out.message = String(err.message);`,
          `    out.native = classify.isNativeModuleLoadError(err);`,
          `    out.packaged = classify.isPackagedPrebuildLoadError(err);`,
          `  }`,
          `}`,
          `writeFileSync(${JSON.stringify(resultPath)}, JSON.stringify(out));`,
        ].join('\n'),
        sandbox,
      );
      expect(r.status).toBe(0);
      const out = JSON.parse(readFileSync(resultPath, 'utf8'));
      expect(out.guardThrew).toBe(false);
      expect(out.ctorType).toBe('function');
      expect(out.constructThrew).toBe(true);
      expect(out.message).toContain(CONSTRUCT_FAILURE_MESSAGE);
      expect(out.native).toBe(true);
      expect(out.packaged).toBe(true);
    }, 120_000);

    it('a real DB-open path reports the classified install failure and never touches the file', () => {
      const dbPath = path.join(dbDir, 'memories.db');
      const resultPath = path.join(dbDir, 'init-result.json');
      const r = runModule(
        [
          `const { writeFileSync } = await import('fs');`,
          `const { initDatabase } = await import(${JSON.stringify(distPath(sandbox, 'database', 'init.js'))});`,
          `let out;`,
          `try { initDatabase(${JSON.stringify(dbPath)}); out = { threw: false, message: '' }; }`,
          `catch (err) { out = { threw: true, message: String(err.message) }; }`,
          `writeFileSync(${JSON.stringify(resultPath)}, JSON.stringify(out));`,
        ].join('\n'),
        sandbox,
      );
      expect(r.status).toBe(0);
      const out = JSON.parse(readFileSync(resultPath, 'utf8'));
      expect(out.threw).toBe(true);
      // Class-aware remediation, not the generic "not compiled locally" text.
      expect(out.message).toContain('The packaged Node-API native binding cannot be loaded here');
      expect(out.message).toContain('NOT database corruption');
      expect(out.message).toContain(CONSTRUCT_FAILURE_MESSAGE);
      // The data-loss regression this routing exists to prevent: a binding
      // fault must never be mistaken for corruption and moved aside.
      expect(readFileSync(dbPath, 'utf8')).toBe(LIVE_DB_CONTENT);
      expect(readdirSync(dbDir).filter((name) => name.includes('.corrupt.'))).toEqual([]);
    }, 120_000);
  });

  /**
   * PACKAGE-LOAD failure inside `doctor` (#465).
   *
   * `runDatabaseCheck` required better-sqlite3 inside the SAME try that opened
   * the database, so a failure to load the PACKAGE landed in a catch whose
   * final else is "then it must be a broken file": doctor answered a corrupt
   * entry file with `Back up and delete ~/.shieldcortex/memories.db` — for a
   * database it had never opened — and `doctor --ai` uploaded that instruction
   * to a model as the evidence to reason from.
   *
   * The shapes here are the ones no message classifier can catch (see the
   * control above), so they pin the STRUCTURE: the load stage is separately
   * guarded and routed by the loader's type, not by what its error says.
   */
  describe('PACKAGE-LOAD failure: doctor must not read it as a corrupt database', () => {
    let sandbox: string;

    const LIVE_DB_CONTENT = 'doctor-live-database-bytes-that-must-survive';
    /** The pre-fix advice. It must appear nowhere — not on screen, not in the
     *  prompt `--ai` sends. */
    const DELETE_ADVICE = 'Back up and delete';

    interface DoctorProbe {
      check: { label: string; status: string; message: string; fix?: string };
      aiPrompt: string;
      aiAttempted: boolean;
    }

    beforeAll(() => {
      requireDist();
      sandbox = makeSandbox('syntax');
    }, 180_000);

    afterAll(() => {
      if (sandbox) rmSync(sandbox, { recursive: true, force: true });
    });

    /** A fresh directory holding a pre-existing "live" DB, one per case. */
    const liveDbDir = (name: string): string => {
      const dir = path.join(sandbox, `dbstate-${name}`);
      mkdirSync(dir, { recursive: true });
      writeFileSync(path.join(dir, 'memories.db'), LIVE_DB_CONTENT);
      return dir;
    };

    /**
     * Drive the BUILT doctor end to end for one shape: the `Database`
     * CheckResult an operator sees, and the exact prompt `--ai` would hand a
     * model, captured through runDoctorAiSection's own invoker seam. Both come
     * from the same run, because they are the same defect seen twice.
     */
    const probeDoctor = (shape: FailureShape, name: string): { probe: DoctorProbe; dbDir: string } => {
      plantStub(sandbox, shape);
      const dbDir = liveDbDir(name);
      const dbPath = path.join(dbDir, 'memories.db');
      const resultPath = path.join(dbDir, 'doctor-probe.json');
      const r = runModule(
        [
          `const { writeFileSync } = await import('fs');`,
          `const doctor = await import(${JSON.stringify(distPath(sandbox, 'cli', 'doctor.js'))});`,
          // Explicit environment: the check must not depend on what happens to
          // exist in the sandbox's HOME.
          `const env = { hasClaude: false, hasOpenClaw: false, hasVSCode: false, hasCodex: false, isHeadless: true };`,
          `const check = doctor.runDatabaseCheck(${JSON.stringify(dbPath)}, env);`,
          `let aiPrompt = '';`,
          `const ai = await doctor.runDoctorAiSection([check], {`,
          `  invoke: async (_system, user) => { aiPrompt = user; return ''; },`,
          `});`,
          `writeFileSync(${JSON.stringify(resultPath)}, JSON.stringify({ check, aiPrompt, aiAttempted: ai.outcome.attempted }));`,
        ].join('\n'),
        sandbox,
      );
      expect(r.stderr ?? '').not.toContain('SyntaxError');
      expect(r.status).toBe(0);
      return { probe: JSON.parse(readFileSync(resultPath, 'utf8')) as DoctorProbe, dbDir };
    };

    it('the corrupt entry really is a parser-raised SyntaxError (harness sanity)', () => {
      plantStub(sandbox, 'syntax');
      const r = runNode(
        [
          '-e',
          "try { require('better-sqlite3'); console.log('LOADED'); }"
          + " catch (e) { console.log('THREW|' + e.name + '|' + e.message); }",
        ],
        distPath(sandbox),
      );
      expect(r.stdout.trim()).toBe(`THREW|SyntaxError|${SYNTAX_FAILURE_DETAIL}`);
    }, 120_000);

    for (const [shape, detail] of [
      ['syntax', SYNTAX_FAILURE_DETAIL],
      ['missing-internal', MISSING_INTERNAL_FAILURE_DETAIL],
    ] as const) {
      it(`[${shape}] the Database row advises reinstalling the engine, never deleting the database`, () => {
        const { probe, dbDir } = probeDoctor(shape, shape);
        const { check } = probe;

        expect(check.label).toBe('Database');
        expect(check.status).toBe('fail');

        // The whole row, message and fix together: the advice must not survive
        // anywhere on it.
        const row = `${check.message}\n${check.fix ?? ''}`;
        expect(row).not.toContain(DELETE_ADVICE);
        expect(row).not.toContain('memories.db`, then restart the MCP server');

        // Says what actually broke, and says what did NOT.
        expect(check.message).toContain('NOT database corruption');
        expect(check.message).toContain(detail);

        // The guard's already-formatted guidance, carried through intact: one
        // header, the missing/source-only class kept, no second formatting
        // pass flipping it to the unfixable packaged-prebuild copy.
        expectMissingSourceOnlyGuidance(check.message);

        // Installation recovery, from the one remediation authority.
        expect(check.fix).toContain('npm run build-release');
        expect(check.fix).toContain('node_modules/better-sqlite3');

        // The data-loss regression itself: doctor never opened the file, so
        // the bytes are untouched and nothing was moved aside.
        expect(readFileSync(path.join(dbDir, 'memories.db'), 'utf8')).toBe(LIVE_DB_CONTENT);
        expect(readdirSync(dbDir).filter((n) => n.includes('.corrupt.'))).toEqual([]);
      }, 120_000);

      it(`[${shape}] the prompt \`--ai\` uploads carries the same advice, not the deletion`, () => {
        const { probe } = probeDoctor(shape, `${shape}-ai`);

        // A failing check exists, so the explainer really did run — otherwise
        // "no deletion advice in the prompt" would be true of an empty string.
        expect(probe.aiAttempted).toBe(true);
        expect(probe.aiPrompt).toContain('[FAIL] Database:');

        expect(probe.aiPrompt).not.toContain(DELETE_ADVICE);
        expect(probe.aiPrompt).toContain('NOT database corruption');
        expect(probe.aiPrompt).toContain('npm run build-release');
      }, 120_000);
    }
  });
});
