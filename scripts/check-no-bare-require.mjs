#!/usr/bin/env node
// Fails if any compiled ESM file calls require() without a createRequire shim.
// The Jest suite cannot catch this: ts-jest's ESM preset shims require(), so
// bare require() "works" in tests but throws ReferenceError under real Node ESM.
import { readdirSync, readFileSync, statSync } from 'fs';
import path from 'path';

const DIST = path.join(process.cwd(), 'dist');
const offenders = [];

function walk(dir) {
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) { walk(full); continue; }
    if (!full.endsWith('.js')) continue;
    const src = readFileSync(full, 'utf8');
    const definesCreateRequire = /createRequire\s*\(/.test(src);
    if (definesCreateRequire) continue;           // file has its own require shim — fine
    // match a require( call that is NOT a property access (e.g. foo.require) and not part of a word
    const m = src.match(/(^|[^.\w])require\s*\(/m);
    if (m) {
      const line = src.slice(0, m.index).split('\n').length;
      offenders.push(`${path.relative(process.cwd(), full)}:${line}`);
    }
  }
}

walk(DIST);
if (offenders.length) {
  console.error('Bare require() in ESM dist (will throw at runtime, swallowed by catch):');
  for (const o of offenders) console.error('  ' + o);
  process.exit(1);
}
console.log('OK: no bare require() in dist.');
