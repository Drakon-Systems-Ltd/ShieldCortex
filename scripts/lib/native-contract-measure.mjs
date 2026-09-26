/**
 * ADR-002 §5C — measure a host's DECLARED native tool contract from the schema
 * it ships, so the reviewed contract in `src/defence/iron-dome/tool-input-schema.ts`
 * is tracked PER HOST VERSION against a recorded version string rather than
 * hand-widened once more (#594; the widening series was #436, #445 and the
 * 13-of-28 round).
 *
 * What is measured: the top-level property names of the object literal an
 * OpenClaw `createSessionsSpawnToolSchema` builds — including every
 * capability-gated block (`...params.swarmEnabled ? { … } : {}`) and every
 * spread of a named object in the same file (`...VISIBLE_SESSIONS_SPAWN_SCHEMA`).
 * A gated block is still a DECLARED field: the host accepts it when the flag
 * is on, and the reviewed contract is "every capability flag on".
 *
 * What is NOT measured: types, descriptions, nesting. The reviewed contract
 * only needs the name set; a name the guard does not read is dropped and
 * reported, never judged (see the drift split in `tool-input-schema.ts`).
 *
 * Node core only; no product import. The parser is a bounded brace walker over
 * the shipped bundle text — it does not execute host code.
 */

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import path from 'node:path';

const IDENT = /^[A-Za-z_$][\w$]*$/;

/** Where the bundle declares the schema builder, and which object it returns. */
export const SESSIONS_SPAWN_ANCHORS = Object.freeze({
  fn: 'function createSessionsSpawnToolSchema(',
  object: 'const schema = {',
  distGlob: /^sessions-spawn-tool-.*\.mjs$/,
});

/**
 * Skip a JS string, template or comment starting at `i`. Returns the index just
 * past it, or `i` when nothing skippable starts there.
 */
function skipOpaque(src, i) {
  const c = src[i];
  const n = src[i + 1];
  if (c === '/' && n === '/') {
    const e = src.indexOf('\n', i);
    return e === -1 ? src.length : e;
  }
  if (c === '/' && n === '*') {
    const e = src.indexOf('*/', i + 2);
    return e === -1 ? src.length : e + 2;
  }
  if (c === '"' || c === "'" || c === '`') {
    let j = i + 1;
    while (j < src.length) {
      if (src[j] === '\\') { j += 2; continue; }
      if (src[j] === c) return j + 1;
      // A template literal can nest `${ … }`: skip the expression as a
      // balanced block (its own strings and braces included), then carry on
      // inside the template.
      if (c === '`' && src[j] === '$' && src[j + 1] === '{') {
        const e = matchBrace(src, j + 1);
        if (e === -1) return src.length;
        j = e + 1;
        continue;
      }
      j++;
    }
    return src.length;
  }
  return i;
}

/** Index of the `}` matching the `{` at `open`, honouring strings and comments. -1 when unbalanced. */
function matchBrace(src, open) {
  let depth = 0;
  let i = open;
  while (i < src.length) {
    const skipped = skipOpaque(src, i);
    if (skipped !== i) { i = skipped; continue; }
    const c = src[i];
    if (c === '{' || c === '(' || c === '[') depth++;
    else if (c === '}' || c === ')' || c === ']') {
      depth--;
      if (depth === 0) return i;
    }
    i++;
  }
  return -1;
}

/**
 * Does the spread expression that ended at `i` END the property there? A spread
 * is only a bare named spread (or a gated block) when the next significant
 * character is the property separator or the end of the literal body. Anything
 * else — `...X && { … }`, `...X.member`, `...X ?? Y`, `...X ? {…} : {…} || Z` —
 * is an expression this walker does not evaluate, and its declared set is NOT
 * the named object's; it must be refused, never counted as the bare spread.
 * Returns the index of the terminator (`,` or body end), or -1.
 */
function spreadTerminator(body, i) {
  let j = i;
  while (j < body.length) {
    const skipped = skipOpaque(body, j);
    if (skipped !== j) { j = skipped; continue; }
    if (/\s/.test(body[j])) { j++; continue; }
    return body[j] === ',' ? j : -1;
  }
  return j;
}

/** Advance from `i` to the next top-level `,` in `body` (or its end), skipping nested brackets. */
function skipToPropertyEnd(body, i) {
  let j = i;
  while (j < body.length) {
    const skipped = skipOpaque(body, j);
    if (skipped !== j) { j = skipped; continue; }
    const c = body[j];
    if (c === ',') return j;
    if (c === '{' || c === '(' || c === '[') {
      const e = matchBrace(body, j);
      if (e === -1) throw new Error('unbalanced value');
      j = e + 1;
      continue;
    }
    j++;
  }
  return j;
}

/**
 * Declared top-level keys of the object literal whose `{` sits at `open`.
 *
 * Returns `{ keys, unresolved }`: `keys` in declaration order, de-duplicated;
 * `unresolved` lists any spread the walker could not resolve to an object
 * literal in the same source (a measurement with an unresolved spread is
 * INCOMPLETE and must not be recorded as the host's declared set).
 */
export function declaredTopLevelKeys(src, open, seen = new Set()) {
  if (src[open] !== '{') throw new Error(`declaredTopLevelKeys: no object literal at ${open}`);
  const close = matchBrace(src, open);
  if (close === -1) throw new Error('declaredTopLevelKeys: unbalanced object literal');
  const keys = [];
  const unresolved = [];
  const push = (k) => { if (!keys.includes(k)) keys.push(k); };
  const body = src.slice(open + 1, close);

  let i = 0;
  let atPropertyStart = true;
  while (i < body.length) {
    const skipped = skipOpaque(body, i);
    if (skipped !== i) { i = skipped; continue; }
    const c = body[i];
    if (/\s/.test(c)) { i++; continue; }
    if (c === ',') { atPropertyStart = true; i++; continue; }

    if (atPropertyStart) {
      // `...expr ? { … } : { … }` — a capability-gated block. Both branches are
      // declared fields (one is usually `{}`).
      // `...IDENT` — a named object in the same file, resolved recursively.
      if (body.startsWith('...', i)) {
        const rest = body.slice(i + 3);
        const cond = rest.match(/^\s*((?:[\w$]|\.|\?\.)+(?:\([^)]*\))?)\s*\?\s*\{/);
        if (cond) {
          const branchOpen = i + 3 + cond[0].length - 1;
          const branchClose = matchBrace(body, branchOpen);
          if (branchClose === -1) throw new Error('unbalanced gated block');
          const inner = declaredTopLevelKeys(body, branchOpen, seen);
          // the alternative branch
          const after = body.slice(branchClose + 1);
          const alt = after.match(/^\s*:\s*\{/);
          if (!alt) throw new Error('gated block without an alternative branch');
          const altOpen = branchClose + 1 + alt[0].length - 1;
          const altClose = matchBrace(body, altOpen);
          if (altClose === -1) throw new Error('unbalanced alternative branch');
          const innerAlt = declaredTopLevelKeys(body, altOpen, seen);
          const gatedEnd = spreadTerminator(body, altClose + 1);
          if (gatedEnd === -1) {
            // `...c ? {…} : {…} <more>` — the block is an operand of a wider
            // expression; its branches are not simply the declared fields.
            unresolved.push(body.slice(i, skipToPropertyEnd(body, altClose + 1)).replace(/\s+/g, ' ').slice(0, 60).trim());
            i = skipToPropertyEnd(body, altClose + 1);
            atPropertyStart = false;
            continue;
          }
          inner.keys.forEach(push);
          unresolved.push(...inner.unresolved);
          innerAlt.keys.forEach(push);
          unresolved.push(...innerAlt.unresolved);
          i = gatedEnd;
          atPropertyStart = false;
          continue;
        }
        const named = rest.match(/^\s*([A-Za-z_$][\w$]*)/);
        if (named) {
          const name = named[1];
          const afterName = i + 3 + named[0].length;
          const end = spreadTerminator(body, afterName);
          if (end === -1) {
            // `...NAME <more>` — `&& {…}`, `.member`, `?? …`, `(…)`: the IDENT
            // is only the prefix of an expression whose value this walker does
            // not compute. Refuse it; do NOT count NAME's own fields.
            const propEnd = skipToPropertyEnd(body, afterName);
            unresolved.push(body.slice(i, propEnd).replace(/\s+/g, ' ').slice(0, 60).trim());
            i = propEnd;
            atPropertyStart = false;
            continue;
          }
          if (seen.has(name)) throw new Error(`cyclic spread of ${name}`);
          const decl = src.indexOf(`const ${name} = {`);
          if (decl === -1) {
            unresolved.push(name);
          } else {
            const nextSeen = new Set(seen); nextSeen.add(name);
            const inner = declaredTopLevelKeys(src, decl + `const ${name} = `.length, nextSeen);
            inner.keys.forEach(push);
            unresolved.push(...inner.unresolved);
          }
          i = end;
          atPropertyStart = false;
          continue;
        }
        unresolved.push(rest.slice(0, 40).trim());
        i += 3;
        atPropertyStart = false;
        continue;
      }
      const prop = body.slice(i).match(/^([A-Za-z_$][\w$]*)\s*:/);
      if (prop && IDENT.test(prop[1])) {
        push(prop[1]);
        i += prop[0].length;
        atPropertyStart = false;
        // Skip the value: walk to the next top-level comma.
        continue;
      }
      const quoted = body.slice(i).match(/^(["'])([^"'\\]+)\1\s*:/);
      if (quoted) {
        push(quoted[2]);
        i += quoted[0].length;
        atPropertyStart = false;
        continue;
      }
      // Anything else at a property start (a computed key, a method) is a shape
      // this walker does not claim to read.
      unresolved.push(body.slice(i, i + 40).trim());
      atPropertyStart = false;
      i++;
      continue;
    }

    // Inside a value: skip nested brackets wholesale, otherwise advance.
    if (c === '{' || c === '(' || c === '[') {
      const e = matchBrace(body, i);
      if (e === -1) throw new Error('unbalanced value');
      i = e + 1;
      continue;
    }
    i++;
  }
  return { keys, unresolved };
}

/**
 * Measure the `sessions_spawn` schema in one bundle's source text.
 * Returns `{ fields, unresolved }` with `fields` sorted for a stable record.
 */
export function measureSessionsSpawnSource(src) {
  const fn = src.indexOf(SESSIONS_SPAWN_ANCHORS.fn);
  if (fn === -1) throw new Error(`anchor not found: ${SESSIONS_SPAWN_ANCHORS.fn}`);
  const obj = src.indexOf(SESSIONS_SPAWN_ANCHORS.object, fn);
  if (obj === -1) throw new Error(`anchor not found after builder: ${SESSIONS_SPAWN_ANCHORS.object}`);
  const open = obj + SESSIONS_SPAWN_ANCHORS.object.length - 1;
  const { keys, unresolved } = declaredTopLevelKeys(src, open);
  return { fields: [...keys].sort(), unresolved };
}

/** Locate the host's version and its spawn-tool bundle under an OpenClaw install root. */
export function locateSessionsSpawnBundle(root) {
  const pkgPath = path.join(root, 'package.json');
  if (!existsSync(pkgPath)) throw new Error(`no package.json under ${root}`);
  const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
  if (pkg?.name !== 'openclaw') throw new Error(`${pkgPath} is not the openclaw package (name=${String(pkg?.name)})`);
  const dist = path.join(root, 'dist');
  const candidates = existsSync(dist) ? readdirSync(dist).filter((f) => SESSIONS_SPAWN_ANCHORS.distGlob.test(f)).sort() : [];
  if (candidates.length !== 1) {
    throw new Error(`expected exactly one sessions-spawn bundle under ${dist}, found ${candidates.length}`);
  }
  return { hostVersion: String(pkg.version), bundle: path.join(dist, candidates[0]), bundleName: `dist/${candidates[0]}` };
}

/**
 * Measure an installed host. The returned object is one REVISION entry of the
 * measurement record (`scripts/native-contracts/openclaw-sessions-spawn.json`).
 */
export function measureInstalledHost(root, { today = new Date() } = {}) {
  const { hostVersion, bundle, bundleName } = locateSessionsSpawnBundle(root);
  const src = readFileSync(bundle, 'utf8');
  const { fields, unresolved } = measureSessionsSpawnSource(src);
  if (unresolved.length > 0) {
    throw new Error(`measurement incomplete — unresolved spread(s): ${unresolved.join(', ')}`);
  }
  return {
    hostVersion,
    fields,
    evidence: { kind: 'dist-schema', file: bundleName, script: 'scripts/measure-native-contract.mjs' },
    measuredOn: today.toISOString().slice(0, 10),
  };
}
