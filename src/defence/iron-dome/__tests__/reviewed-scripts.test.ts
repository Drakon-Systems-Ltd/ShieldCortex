/**
 * Unit spec for reviewed-scripts.ts (#189) — the fs-backed half of the
 * allowlist: entry shape validation (hostile-input rules) and the
 * path-canonicalising, content-hashing predicate handed to the guard core.
 */
import { mkdtempSync, writeFileSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  createReviewedScriptCheck,
  hashScriptSource,
  normaliseReviewedScripts,
} from '../reviewed-scripts.js';

describe('normaliseReviewedScripts — hostile-input shape validation', () => {
  const good = { path: '/abs/script.py', sha256: 'a'.repeat(64) };

  test('non-arrays and junk yield an empty list, never a throw', () => {
    for (const junk of [null, undefined, 42, 'x', {}, { path: 1 }]) {
      expect(normaliseReviewedScripts(junk)).toEqual([]);
    }
  });

  test('a malformed field drops the WHOLE entry — no half-matching', () => {
    expect(normaliseReviewedScripts([
      { ...good, path: 'relative/path.py' },          // not absolute
      { ...good, sha256: 'A'.repeat(63) },             // wrong length
      { ...good, sha256: 'g'.repeat(64) },             // not hex
      { path: '/abs/x.py' },                           // missing hash
      { ...good, path: '/x/' + 'p'.repeat(1100) },     // over length cap
      good,                                            // the one survivor
    ])).toEqual([good]);
  });

  test('sha256 is case-normalised; note and addedAt survive only when sane', () => {
    const [e] = normaliseReviewedScripts([
      { path: '/abs/a.py', sha256: 'A'.repeat(64), note: '  reviewed  ', addedAt: 123 },
    ]);
    expect(e.sha256).toBe('a'.repeat(64));
    expect(e.note).toBe('reviewed');
    expect(e.addedAt).toBe(123);
  });

  test('entry count is capped at 200', () => {
    const many = Array.from({ length: 300 }, (_, i) => ({ path: `/abs/${i}.py`, sha256: 'a'.repeat(64) }));
    expect(normaliseReviewedScripts(many)).toHaveLength(200);
  });
});

describe('createReviewedScriptCheck — canonical path + exact content', () => {
  let dir: string;
  let scriptPath: string;
  const SOURCE = '#!/bin/sh\nls -la ~/.ssh\n';

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'sc-189-'));
    scriptPath = join(dir, 'sentry.sh');
    writeFileSync(scriptPath, SOURCE);
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  const entryFor = (p: string, src: string) => [{ path: p, sha256: hashScriptSource(src) }];

  test('matches the pinned file with identical content', () => {
    const check = createReviewedScriptCheck(entryFor(scriptPath, SOURCE));
    expect(check(scriptPath, SOURCE)).toBe(true);
  });

  test('a relative invocation resolves against cwd and still matches', () => {
    const check = createReviewedScriptCheck(entryFor(scriptPath, SOURCE), dir);
    expect(check('./sentry.sh', SOURCE)).toBe(true);
  });

  test('content drift fails: the hash is of the bytes being scanned, not the pin-time file', () => {
    const check = createReviewedScriptCheck(entryFor(scriptPath, SOURCE));
    expect(check(scriptPath, SOURCE + '# edited')).toBe(false);
  });

  test('a DIFFERENT file with identical content does not match — path is part of the pin', () => {
    const copy = join(dir, 'copy.sh');
    writeFileSync(copy, SOURCE);
    const check = createReviewedScriptCheck(entryFor(scriptPath, SOURCE));
    expect(check(copy, SOURCE)).toBe(false);
  });

  test('a symlink to the pinned file matches — canonicalisation on both sides', () => {
    const link = join(dir, 'link.sh');
    symlinkSync(scriptPath, link);
    const check = createReviewedScriptCheck(entryFor(scriptPath, SOURCE));
    expect(check(link, SOURCE)).toBe(true);
  });

  test('a pin whose file no longer exists matches nothing (dead entry, not a wildcard)', () => {
    const gone = join(dir, 'gone.sh');
    const check = createReviewedScriptCheck(entryFor(gone, SOURCE));
    expect(check(gone, SOURCE)).toBe(false);
  });

  test('never throws on garbage inputs', () => {
    const check = createReviewedScriptCheck(entryFor(scriptPath, SOURCE));
    expect(check('', SOURCE)).toBe(false);
    expect(check(scriptPath, undefined as unknown as string)).toBe(false);
    expect(check('/proc/self/environ', SOURCE)).toBe(false);
  });

  test('empty or invalid entry list yields the constant-false predicate', () => {
    expect(createReviewedScriptCheck([])(scriptPath, SOURCE)).toBe(false);
    expect(createReviewedScriptCheck([{ path: 'rel.py', sha256: 'zz' } as never])(scriptPath, SOURCE)).toBe(false);
  });
});
