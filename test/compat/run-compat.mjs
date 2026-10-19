#!/usr/bin/env node
// 5.x public-API compatibility gate for the #718 sensitivity tier.
//
//   node test/compat/run-compat.mjs [--package <dir-or-tgz>]
//
// 1. Walker self-test: a synthetic package hides 'PERSONAL' / internal names
//    behind Array, Promise, generic constraints/defaults, a renamed re-export
//    and `export *`. Every control must be reported, or the gate fails.
// 2. Builds an isolated consumer dir (tmp) holding only package.json and the
//    package's dist/**/*.d.ts under node_modules/shieldcortex, then compiles
//    the 5.6.0 consumer and the new-consumer fixture through the `exports`
//    map (NodeNext, no paths, no baseUrl, no src).
// 3. Walks every `exports` entry with a types target and fails if an internal
//    name is exported or the literal type 'PERSONAL' is reachable from any
//    exported declaration.
//
// Default package source is the repo root after `build:ts`.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, '..', '..');
const require = createRequire(path.join(repo, 'package.json'));
const ts = require('typescript');

const INTERNAL = new Set([
  'SensitivityTier', 'PreciseSensitivityClassification', 'PreciseDefencePipelineResult', 'PreciseSkillScanResult',
  'classifySensitivityPrecise', 'runDefencePipelinePrecise', 'redactForDisplayTier', 'projectSensitivityTier',
  'toPublicSensitivity', 'toPublicPipelineResult', 'toPublicSkillScanResult', 'scanSkillPrecise',
  'scanSkillContentPrecise', 'syncToCloudInternal',
]);
const MAX_DEPTH = 40;

function copyDts(srcRoot, destRoot) {
  fs.mkdirSync(destRoot, { recursive: true });
  fs.copyFileSync(path.join(srcRoot, 'package.json'), path.join(destRoot, 'package.json'));
  const walk = (rel) => {
    for (const ent of fs.readdirSync(path.join(srcRoot, rel), { withFileTypes: true })) {
      const r = path.join(rel, ent.name);
      if (ent.isDirectory()) walk(r);
      else if (ent.name.endsWith('.d.ts')) {
        fs.mkdirSync(path.join(destRoot, rel), { recursive: true });
        fs.copyFileSync(path.join(srcRoot, r), path.join(destRoot, r));
      }
    }
  };
  walk('dist');
}

function resolvePackage(arg, tmp) {
  if (!arg) return repo;
  if (fs.statSync(arg).isDirectory()) return path.resolve(arg);
  const out = path.join(tmp, 'tgz');
  fs.mkdirSync(out);
  execFileSync('tar', ['-xzf', path.resolve(arg), '-C', out]);
  return path.join(out, 'package');
}

const compilerOptions = {
  strict: true, noEmit: true, skipLibCheck: true, types: [],
  module: ts.ModuleKind.NodeNext, moduleResolution: ts.ModuleResolutionKind.NodeNext, target: ts.ScriptTarget.ES2022,
};

/** Returns a list of leak descriptions (empty = clean). */
function walkExports(consumerDir) {
  const pkg = JSON.parse(fs.readFileSync(path.join(consumerDir, 'node_modules/shieldcortex/package.json'), 'utf8'));
  const specs = Object.entries(pkg.exports)
    .filter(([, v]) => v && typeof v === 'object' && v.types)
    .map(([k]) => (k === '.' ? 'shieldcortex' : `shieldcortex/${k.slice(2)}`));
  const probe = path.join(consumerDir, '__walk_probe.ts');
  fs.writeFileSync(probe, specs.map((s, i) => `import * as m${i} from '${s}';\nexport { m${i} };`).join('\n'));
  const program = ts.createProgram([probe], compilerOptions);
  const checker = program.getTypeChecker();
  const sf = program.getSourceFile(probe);
  const leaks = [];
  const isLib = (sym) => (sym?.declarations ?? []).some((d) => program.isSourceFileDefaultLibrary(d.getSourceFile()));
  for (const stmt of sf.statements) {
    if (!ts.isImportDeclaration(stmt)) continue;
    const spec = stmt.moduleSpecifier.text;
    const modSym = checker.getSymbolAtLocation(stmt.moduleSpecifier);
    if (!modSym) { leaks.push(`${spec}: UNRESOLVED`); continue; }
    const exps = checker.getExportsOfModule(modSym);
    const file = path.relative(consumerDir, modSym.declarations?.[0]?.getSourceFile().fileName ?? '?');
    console.log(`  ${spec} -> ${file}: ${exps.length} exports`);
    const seen = new Set();
    const visitSignature = (s, trail, depth) => {
      for (const tp of s.typeParameters ?? []) {
        visit(tp.getConstraint?.() ?? checker.getBaseConstraintOfType(tp), `${trail}<${tp.symbol?.name} extends>`, depth + 1);
        visit(tp.getDefault?.(), `${trail}<${tp.symbol?.name} =>`, depth + 1);
      }
      for (const p of s.parameters) visit(checker.getTypeOfSymbol(p), `${trail}(${p.name})`, depth + 1);
      visit(checker.getReturnTypeOfSignature(s), `${trail}()`, depth + 1);
    };
    const visit = (t, trail, depth = 0) => {
      if (!t || seen.has(t)) return;
      if (depth > MAX_DEPTH) { leaks.push(`${trail}: INCOMPLETE (depth > ${MAX_DEPTH})`); return; }
      seen.add(t);
      const alias = t.aliasSymbol?.name;
      if (alias && INTERNAL.has(alias)) leaks.push(`${trail} via alias ${alias}`);
      const sym = t.getSymbol?.();
      if (sym && INTERNAL.has(sym.name)) leaks.push(`${trail} via ${sym.name}`);
      if (t.isStringLiteral?.() && t.value === 'PERSONAL') leaks.push(`${trail} reaches literal "PERSONAL"`);
      if (t.isUnionOrIntersection?.()) t.types.forEach((u) => visit(u, trail, depth + 1));
      // Type arguments first, so Array<…> / Promise<…> / Map<…> from the default
      // lib cannot hide a package-supplied type (grok N1, astra N1).
      (t.aliasTypeArguments ?? []).forEach((a) => visit(a, `${trail}<>`, depth + 1));
      if (t.flags & ts.TypeFlags.Object) (checker.getTypeArguments?.(t) ?? []).forEach((a) => visit(a, `${trail}<>`, depth + 1));
      if (t.flags & ts.TypeFlags.TypeParameter) {
        visit(checker.getBaseConstraintOfType(t), `${trail} extends`, depth + 1);
        visit(t.getDefault?.(), `${trail} =`, depth + 1);
      }
      if (t.flags & ts.TypeFlags.Conditional || t.flags & ts.TypeFlags.Index || t.flags & ts.TypeFlags.IndexedAccess) {
        visit(checker.getBaseConstraintOfType(t), `${trail} constraint`, depth + 1);
      }
      if (isLib(sym) && !t.aliasSymbol) return; // lib members themselves are not package surface
      if (t.flags & ts.TypeFlags.Object) {
        for (const p of checker.getPropertiesOfType(t)) {
          const d = p.valueDeclaration ?? p.declarations?.[0];
          visit(d ? checker.getTypeOfSymbolAtLocation(p, d) : checker.getTypeOfSymbol(p), `${trail}.${p.name}`, depth + 1);
        }
        for (const kind of [ts.SignatureKind.Call, ts.SignatureKind.Construct]) {
          for (const s of checker.getSignaturesOfType(t, kind)) visitSignature(s, trail, depth);
        }
        for (const ii of checker.getIndexInfosOfType(t)) visit(ii.type, `${trail}[]`, depth + 1);
      }
    };
    for (const e of exps) {
      if (INTERNAL.has(e.name)) leaks.push(`${spec}: exports internal name ${e.name}`);
      const target = e.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(e) : e;
      if (target !== e && INTERNAL.has(target.name)) leaks.push(`${spec}: ${e.name} re-exports internal ${target.name}`);
      const decl = target.declarations?.[0];
      if (!decl) continue;
      const trail = `${spec}:${e.name}`;
      if (target.flags & (ts.SymbolFlags.TypeAlias | ts.SymbolFlags.Interface | ts.SymbolFlags.Class | ts.SymbolFlags.Enum)) {
        const declared = checker.getDeclaredTypeOfSymbol(target);
        visit(declared, trail);
        for (const tp of declared.typeParameters ?? declared.aliasTypeArguments ?? []) visit(tp, `${trail}<>`, 1);
        for (const d of target.declarations ?? []) {
          for (const tpd of d.typeParameters ?? []) visit(checker.getTypeAtLocation(tpd), `${trail}<${tpd.name.text}>`, 1);
        }
      }
      if (target.flags & ts.SymbolFlags.Value) visit(checker.getTypeOfSymbolAtLocation(target, decl), trail);
    }
  }
  fs.unlinkSync(probe);
  return leaks;
}

function walkerSelfTest() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-compat-selftest-'));
  const pkgDir = path.join(tmp, 'node_modules/shieldcortex');
  fs.mkdirSync(path.join(pkgDir, 'dist'), { recursive: true });
  fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify({
    name: 'shieldcortex', type: 'module',
    exports: Object.fromEntries(['array', 'promise', 'generic', 'gdefault', 'alias', 'star', 'renamed', 'name']
      .map((n) => [`./${n}`, { types: `./dist/${n}.d.ts`, import: `./dist/${n}.js` }])),
  }));
  const files = {
    'hidden.d.ts': "export interface Hidden { level: 'PUBLIC' | 'PERSONAL'; }\nexport declare function classifySensitivityPrecise(): Hidden;\n",
    'array.d.ts': "import type { Hidden } from './hidden.js';\nexport declare function f(): Hidden[];\n",
    'promise.d.ts': "import type { Hidden } from './hidden.js';\nexport declare function f(): Promise<Hidden>;\n",
    'generic.d.ts': "export declare function f<T extends 'PERSONAL'>(x: string): string;\n",
    'gdefault.d.ts': "export interface Box<T = 'PERSONAL'> { ok: true }\n",
    'alias.d.ts': "export type Wrapped = Map<string, ReadonlyArray<'PERSONAL'>>;\n",
    'star.d.ts': "export * from './hidden.js';\n",
    'renamed.d.ts': "export { classifySensitivityPrecise as classify } from './hidden.js';\n",
    'name.d.ts': 'export declare function syncToCloudInternal(): void;\n',
  };
  for (const [n, body] of Object.entries(files)) fs.writeFileSync(path.join(pkgDir, 'dist', n), body);
  const leaks = walkExports(tmp);
  const missed = ['array', 'promise', 'generic', 'gdefault', 'alias', 'star', 'renamed', 'name']
    .filter((n) => !leaks.some((l) => l.startsWith(`shieldcortex/${n}`)));
  fs.rmSync(tmp, { recursive: true, force: true });
  return missed;
}

const argv = process.argv.slice(2);
const pkgArg = argv[argv.indexOf('--package') + 1] && argv.includes('--package') ? argv[argv.indexOf('--package') + 1] : null;
let failed = false;

console.log('walker self-test (mutation controls):');
const missed = walkerSelfTest();
if (missed.length) { console.log(`  FAIL: walker missed controls: ${missed.join(', ')}`); failed = true; }
else console.log('  PASS: every control reported');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-compat-'));
try {
  const source = resolvePackage(pkgArg, tmp);
  if (!fs.existsSync(path.join(source, 'dist', 'index.d.ts'))) {
    console.error(`run-compat: ${source}/dist/index.d.ts missing — run build:ts first`);
    process.exit(2);
  }
  const consumer = path.join(tmp, 'consumer');
  copyDts(source, path.join(consumer, 'node_modules/shieldcortex'));
  const fixtures = ['sensitivity-5.6-consumer.ts', 'sensitivity-new-consumer.ts'];
  for (const f of fixtures) fs.copyFileSync(path.join(here, f), path.join(consumer, f));

  console.log(`fixtures against ${pkgArg ?? 'repo build'}:`);
  const program = ts.createProgram(fixtures.map((f) => path.join(consumer, f)), compilerOptions);
  const pkgFiles = program.getSourceFiles().map((s) => s.fileName).filter((f) => f.includes('/node_modules/shieldcortex/'));
  const stray = pkgFiles.filter((f) => !f.startsWith(path.join(consumer, 'node_modules/shieldcortex/dist/')));
  console.log(`  ${pkgFiles.length} shieldcortex declaration files, all under node_modules/shieldcortex/dist: ${stray.length === 0}`);
  if (stray.length || pkgFiles.length === 0) failed = true;
  const diags = ts.getPreEmitDiagnostics(program);
  for (const d of diags) {
    const where = d.file ? `${path.basename(d.file.fileName)}:${d.file.getLineAndCharacterOfPosition(d.start).line + 1}` : '';
    console.log(`  TS${d.code} ${where} ${ts.flattenDiagnosticMessageText(d.messageText, ' ')}`);
  }
  console.log(`  ${diags.length === 0 ? 'PASS' : `FAIL (${diags.length} diagnostics)`}`);
  if (diags.length) failed = true;

  console.log('public declaration walk (every exports entry with types):');
  const leaks = walkExports(consumer);
  for (const l of leaks) console.log(`  LEAK ${l}`);
  console.log(`  ${leaks.length === 0 ? 'PASS' : `FAIL (${leaks.length})`}`);
  if (leaks.length) failed = true;
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
console.log(failed ? 'run-compat: FAIL' : 'run-compat: PASS');
process.exit(failed ? 1 : 0);
