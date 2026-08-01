// shieldcortex is published ESM-only (package.json "type": "module") — there
// is no CommonJS build, and there deliberately never will be a fake one:
// pointing the "require" condition at the compiled ESM output would just
// swap one runtime error (this one) for a worse one (ERR_REQUIRE_ESM, or a
// silent wrong-module load on Node 22+'s experimental require(esm)).
//
// Before this file existed, `require('shieldcortex')` (or any subpath) fell
// through Node's default `exports` resolution — no "require" condition, no
// "default" — and Node raised a bare ERR_PACKAGE_PATH_NOT_EXPORTED that names
// neither shieldcortex nor the real cause. That cost a fleet agent real
// diagnostic time: it root-caused an unrelated plugin failure to this exact
// string and stood down waiting on a rebuild that would never have helped
// (issue #134).
//
// This file is wired as the "require" condition on every `exports` entry in
// package.json, so a CJS `require()` call resolves HERE — a real, loadable
// CommonJS module (the .cjs extension makes Node treat it as CJS regardless
// of the package's "type": "module") — and fails with a message that says
// exactly what's wrong and how to fix it, instead of Node's opaque default.
'use strict';

throw new Error(
  '[shieldcortex] This package is ESM-only — there is no CommonJS build, by ' +
    'design (see README.md "ESM only"). `require("shieldcortex")` (or any ' +
    'shieldcortex/* subpath) cannot work and never silently will. Fix your ' +
    'importing code instead: use a dynamic import — ' +
    '`const shieldcortex = await import("shieldcortex")` — or convert the ' +
    'consuming file/package to ESM (add "type": "module" to its ' +
    'package.json, or use a .mjs extension). ' +
    'https://github.com/Drakon-Systems-Ltd/ShieldCortex#esm-only',
);
