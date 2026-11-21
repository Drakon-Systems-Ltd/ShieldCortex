#!/usr/bin/env node
// Fails if any compiled ESM file calls require() in a way that breaks under
// real Node ESM. Two distinct failure modes are caught:
//
//  (a) A file with NO createRequire shim calls require() at all. Under real
//      Node ESM that bare require() throws ReferenceError, which a surrounding
//      catch silently swallows — disabling whatever the require() fed.
//
//  (b) A file (even one WITH a createRequire shim) require()s a RELATIVE module
//      whose specifier is not a .json file. createRequire().require('./x.js')
//      only resolves an internal ESM module on Node >=22 (the require(esm)
//      feature); on Node 20 it throws ERR_REQUIRE_ESM, again swallowed by a
//      catch. Internal ESM modules must be `import`ed, not require()d. Bare
//      package requires (require('safe-regex2')), Node builtins
//      (require('child_process')), and .json requires stay allowed.
//
// The Jest suite cannot catch either: ts-jest's ESM preset shims require(), so
// bare/relative require() "works" in tests but throws under real Node ESM.
//
// Each file is parsed with the TypeScript parser (a devDependency, already
// needed to build dist) and only real call expressions count, so a require()
// named in a comment, a string or a regex literal is never flagged. The
// earlier regex tokenizer could not tell a regex literal from a quote: a `'`
// or a backtick inside /…/ started a "string" it never closed where the code
// did, the rest of the file drifted in and out of step, and a doc comment
// that mentions require('child_process') was read as code (#1005 CI,
// dist/defence/iron-dome/tool-action-guard.js:1683, a file with no require()).
//
// Usage: node scripts/check-no-bare-require.mjs [distDir]   (default ./dist)
import { readdirSync, readFileSync, statSync } from 'fs';
import path from 'path';
import ts from 'typescript';

const DIST = path.resolve(process.argv[2] ?? path.join(process.cwd(), 'dist'));
const offenders = [];

function isRelativeNonJson(spec) {
  if (spec === undefined) return false;
  if (!(spec.startsWith('./') || spec.startsWith('../'))) return false;
  return !spec.endsWith('.json');
}

/** Every `require(…)` call (callee the bare identifier, not `x.require`) and
 *  whether the file calls `createRequire(…)` / `module.createRequire(…)`. */
function scanCalls(file, text) {
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  const requires = [];
  let hasShim = false;
  const visit = (node) => {
    if (ts.isCallExpression(node)) {
      const callee = node.expression;
      if (ts.isIdentifier(callee) && callee.text === 'require') {
        const arg = node.arguments[0];
        const spec = arg && (ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg)) ? arg.text : undefined;
        requires.push({ spec, line: sf.getLineAndCharacterOfPosition(callee.getStart(sf)).line + 1 });
      }
      if ((ts.isIdentifier(callee) && callee.text === 'createRequire')
        || (ts.isPropertyAccessExpression(callee) && callee.name.text === 'createRequire')) {
        hasShim = true;
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return { requires, hasShim };
}

function walk(dir) {
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) { walk(full); continue; }
    if (!full.endsWith('.js')) continue;
    const { requires, hasShim } = scanCalls(full, readFileSync(full, 'utf8'));
    for (const { spec, line } of requires) {
      const relativeNonJson = isRelativeNonJson(spec);
      // Offender if: (a) no shim (any require is a bare-require risk), OR
      //             (b) it require()s a relative non-.json (internal ESM).
      if (!hasShim || relativeNonJson) {
        const why = relativeNonJson
          ? `require('${spec}') — relative ESM module must be imported, not require()d (Node 20 ERR_REQUIRE_ESM)`
          : `bare require() with no createRequire shim`;
        offenders.push(`${path.relative(process.cwd(), full)}:${line} — ${why}`);
      }
    }
  }
}

walk(DIST);
if (offenders.length) {
  console.error('require() in ESM dist that breaks under real Node ESM:');
  for (const o of offenders) console.error('  ' + o);
  process.exit(1);
}
console.log('OK: no ESM-unsafe require() in dist.');
