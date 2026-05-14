/**
 * Tests for the portable glob walker. Has to behave correctly on Node 18
 * — that's the minimum engine declared in package.json and the reason
 * we don't use fs.promises.glob (Node 22+).
 */
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { expandGlob, isGlobPattern } from '../sessions/glob.js';

let root: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'sc-glob-'));
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

function touch(...parts: string[]): string {
  const p = join(root, ...parts);
  mkdirSync(join(p, '..'), { recursive: true });
  writeFileSync(p, '');
  return p;
}

describe('isGlobPattern', () => {
  it('detects *, ?, and []', () => {
    expect(isGlobPattern('foo/*.jsonl')).toBe(true);
    expect(isGlobPattern('foo/?.jsonl')).toBe(true);
    expect(isGlobPattern('foo/[ab].jsonl')).toBe(true);
  });

  it('returns false for literal paths', () => {
    expect(isGlobPattern('/abs/path/file.jsonl')).toBe(false);
    expect(isGlobPattern('relative/file.jsonl')).toBe(false);
    expect(isGlobPattern('')).toBe(false);
  });
});

describe('expandGlob', () => {
  it('returns the literal path when pattern has no wildcards', () => {
    expect(expandGlob('/abs/file.jsonl')).toEqual(['/abs/file.jsonl']);
  });

  it('matches a single-segment wildcard', () => {
    touch('a.jsonl');
    touch('b.jsonl');
    touch('skip.txt');
    const result = expandGlob(join(root, '*.jsonl'));
    expect(result.sort()).toEqual([join(root, 'a.jsonl'), join(root, 'b.jsonl')]);
  });

  it('matches `?` for a single character', () => {
    touch('a.jsonl');
    touch('ab.jsonl');
    const result = expandGlob(join(root, '?.jsonl'));
    expect(result).toEqual([join(root, 'a.jsonl')]);
  });

  it('matches `[ab]` character class', () => {
    touch('a.jsonl');
    touch('b.jsonl');
    touch('c.jsonl');
    const result = expandGlob(join(root, '[ab].jsonl'));
    expect(result.sort()).toEqual([join(root, 'a.jsonl'), join(root, 'b.jsonl')]);
  });

  it('recurses with `**`', () => {
    touch('top.jsonl');
    touch('sub', 'mid.jsonl');
    touch('sub', 'deep', 'bottom.jsonl');
    touch('sub', 'deep', 'ignore.txt');
    const result = expandGlob(join(root, '**', '*.jsonl'));
    expect(result.sort()).toEqual(
      [
        join(root, 'sub', 'deep', 'bottom.jsonl'),
        join(root, 'sub', 'mid.jsonl'),
        join(root, 'top.jsonl'),
      ].sort(),
    );
  });

  it('returns empty array when nothing matches', () => {
    touch('a.txt');
    expect(expandGlob(join(root, '*.jsonl'))).toEqual([]);
  });

  it('skips unreadable directories without throwing', () => {
    expect(expandGlob(join(root, 'no-such-subdir', '*.jsonl'))).toEqual([]);
  });

  it('respects maxMatches', () => {
    for (let i = 0; i < 20; i++) touch(`f${i}.jsonl`);
    const result = expandGlob(join(root, '*.jsonl'), { maxMatches: 5 });
    expect(result.length).toBeLessThanOrEqual(5);
  });

  it('skips directories at the leaf — only returns files', () => {
    mkdirSync(join(root, 'dir.jsonl'), { recursive: true });
    touch('real.jsonl');
    const result = expandGlob(join(root, '*.jsonl'));
    expect(result).toEqual([join(root, 'real.jsonl')]);
  });
});
