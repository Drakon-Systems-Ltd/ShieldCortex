import { execFileSync, spawnSync } from 'child_process';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'fs';
import os from 'os';
import path from 'path';

const dist = path.join(process.cwd(), 'dist');
const CHECK = path.join(process.cwd(), 'scripts', 'check-no-bare-require.mjs');

// Build-output guard. Skips if dist is absent (pure-source CI), runs when dist exists.
(existsSync(dist) ? describe : describe.skip)('dist has no ESM-unsafe require()', () => {
  it('passes the static guard', () => {
    execFileSync('node', [CHECK], { stdio: 'pipe' });
  });
});

// The guard itself, on fixture dist trees: it reads real call expressions, so a
// require() named in a comment is not a call even after a regex literal holding a
// quote (the tokenizer it replaced lost step there, #1005 CI), and a real call is
// still caught.
describe('check-no-bare-require reads calls, not text', () => {
  let root: string;
  beforeEach(() => { root = mkdtempSync(path.join(os.tmpdir(), 'sc-no-bare-require-')); });
  afterEach(() => { rmSync(root, { recursive: true, force: true }); });

  function check(files: Record<string, string>): { status: number | null; out: string } {
    for (const [name, body] of Object.entries(files)) {
      const file = path.join(root, name);
      mkdirSync(path.dirname(file), { recursive: true });
      writeFileSync(file, body);
    }
    const r = spawnSync('node', [CHECK, root], { encoding: 'utf8' });
    return { status: r.status, out: `${r.stdout}${r.stderr}` };
  }

  it('does not flag a require() mentioned in a comment after a regex literal holding a quote', () => {
    const r = check({
      'a.js': [
        "const QUOTE_RE = /'/;",
        '/**',
        " * `.execSync` on a `require('child_process')` result.",
        ' */',
        'export const x = QUOTE_RE.test("a");',
        '',
      ].join('\n'),
    });
    expect(r.out).toContain('OK');
    expect(r.status).toBe(0);
  });

  it('does not flag require() inside a string', () => {
    const r = check({ 'a.js': "export const hint = \"call require('x') from CommonJS\";\n" });
    expect(r.status).toBe(0);
  });

  it('flags a bare require() call in a file with no createRequire shim', () => {
    const r = check({ 'sub/b.js': "const QUOTE_RE = /'/;\nexport const cp = require('child_process');\n" });
    expect(r.status).toBe(1);
    expect(r.out).toContain(`${path.relative(process.cwd(), path.join(root, 'sub', 'b.js'))}:2 — bare require() with no createRequire shim`);
  });

  it('allows a builtin require() behind a createRequire shim', () => {
    const r = check({
      'c.js': "import { createRequire } from 'module';\nconst require = createRequire(import.meta.url);\nexport const cp = require('child_process');\n",
    });
    expect(r.status).toBe(0);
  });

  it('flags a relative non-.json require() even behind a shim', () => {
    const r = check({
      'd.js': "import { createRequire } from 'module';\nconst require = createRequire(import.meta.url);\nexport const m = require('./x.js');\nexport const j = require('./x.json');\n",
    });
    expect(r.status).toBe(1);
    expect(r.out).toContain("d.js:3 — require('./x.js')");
    expect(r.out).not.toContain('d.js:4');
  });

  it('does not count a property call named require', () => {
    const r = check({ 'e.js': "export const v = loader.require('./x.js');\n" });
    expect(r.status).toBe(0);
  });
});
