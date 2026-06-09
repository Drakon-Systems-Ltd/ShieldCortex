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
import { readdirSync, readFileSync, statSync } from 'fs';
import path from 'path';

const DIST = path.join(process.cwd(), 'dist');
const offenders = [];

// Matches a require( call that is NOT a property access (foo.require / .require)
// and NOT the createRequire( factory itself. Captures the leading boundary char
// so we can compute the line, plus (optionally) a string-literal argument.
const REQUIRE_CALL = /(^|[^.\w])require\s*\(\s*(['"])([^'"]*)\2\s*\)|(^|[^.\w])require\s*\(/g;

function isRelativeNonJson(spec) {
  if (spec === undefined) return false;
  if (!(spec.startsWith('./') || spec.startsWith('../'))) return false;
  return !spec.endsWith('.json');
}

function walk(dir) {
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) { walk(full); continue; }
    if (!full.endsWith('.js')) continue;
    const src = readFileSync(full, 'utf8');
    const hasShim = /createRequire\s*\(/.test(src);

    REQUIRE_CALL.lastIndex = 0;
    let m;
    while ((m = REQUIRE_CALL.exec(src)) !== null) {
      // Group 3 is the string literal arg when the require had a literal arg.
      const spec = m[3];
      const relativeNonJson = isRelativeNonJson(spec);

      // Offender if: (a) no shim (any require is a bare-require risk), OR
      //             (b) it require()s a relative non-.json (internal ESM).
      if (!hasShim || relativeNonJson) {
        const index = m.index;
        const line = src.slice(0, index).split('\n').length;
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
console.log('OK: no fragile require() in dist.');
