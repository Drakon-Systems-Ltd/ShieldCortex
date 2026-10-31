/**
 * #923 r7 — the ONE shell-word tokenizer and path normaliser
 * (scripts/lib/shell-words.mjs) that both Action Guard planes use.
 *
 * 1. It splits words the way bash does. A seeded fuzz corpus of escape- and
 *    quote-heavy operands is compared against bash's own argv (`printf
 *    '%s\0'`, which only prints; nothing is expanded or executed — the
 *    alphabet holds no `$`, backtick, glob, brace, `~` or operator).
 * 2. It is shared, not copied: the live guard (source and dist) and the
 *    pre-tool hook import the same file, and neither defines its own
 *    tokenizer or backslash-mapping normaliser any more. So the two planes
 *    cannot drift; the claude-transcript-floor-923 suite asserts identical
 *    live and outage verdicts on top of this.
 */
import { describe, expect, it } from '@jest/globals';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { lexicalPathNormalise, shellTokens, shellWords } from '../../scripts/lib/shell-words.mjs';
import { lexicalPathNormalise as guardNormalise, claudeTranscriptNamed } from '../defence/iron-dome/tool-action-guard.js';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const words = (s: string) => shellTokens(s).tokens.filter(t => t.type === 'word').map(t => t.value);

/** bash's argv for `printf '%s\0' <text>`, or null when bash rejects the text. */
function bashWords(text: string): string[] | null {
  const r = spawnSync('bash', ['--noprofile', '--norc', '-c', `printf '%s\\0' ${text}`], { encoding: 'utf8', timeout: 10_000 });
  if (r.status !== 0) return null;
  return r.stdout.split('\0').slice(0, -1);
}

/** Small deterministic PRNG (mulberry32), so a failure is reproducible. */
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const PIECES = ['a', 'x', '.claude', '/', '/', '.', '..', ' ', '\t', ',', '=', '-', '\\ ', '\\(', '\\)', '\\,', '\\=', '\\\\', '\\\'', '\\"', '\\;', '\\a',
  "'a b'", "'a\\b'", '"a b"', '"a\\b"', '"a\\"b"', '"a\\\\b"', '"(x)"', "''", '""', '\\\n', "$'a\\x20b'", "$'\\101\\n'"];

function fuzzCase(next: () => number): string {
  let s = 'w';
  const n = 2 + Math.floor(next() * 12);
  for (let i = 0; i < n; i++) s += PIECES[Math.floor(next() * PIECES.length)];
  return s;
}

describe('#923 r7 — shellTokens splits words as bash does', () => {
  const bash = spawnSync('bash', ['--version'], { encoding: 'utf8' });
  const itBash = bash.status === 0 ? it : it.skip;

  const HAND: string[] = [
    String.raw`/h/.claude/x\ y/../projects/p/s.jsonl`,
    String.raw`/h/.claude/x\(y\)/../projects/p/s.jsonl`,
    String.raw`/h/.claude/x\,y/../projects/p/s.jsonl a\=b`,
    String.raw`"/h/.claude/x y/../p" 'a\b' "a\b\"c\\d"`,
    String.raw`a\'b "x'y" 'x"y'`,
    'a\\\nb c',
    String.raw`$'a\x20b\nc\101'`,
    String.raw`x\\y \\ \#z`,
    'tab\tsep  multi',
    String.raw`.claude/"projects"/p/s.jsonl`,
    String.raw`a\ \ b`,
  ];

  itBash.each(HAND)('hand case %j', (text) => {
    expect(words(text)).toEqual(bashWords(text));
  });

  itBash('a seeded fuzz corpus of 300 operands matches bash word for word', () => {
    const next = rng(923);
    let compared = 0;
    const mismatches: Array<{ text: string; bash: string[]; ours: string[] }> = [];
    for (let i = 0; i < 300; i++) {
      const text = fuzzCase(next);
      const expected = bashWords(text);
      if (expected === null) continue;
      compared++;
      const ours = words(text);
      if (JSON.stringify(ours) !== JSON.stringify(expected)) mismatches.push({ text, bash: expected, ours });
    }
    expect(mismatches).toEqual([]);
    expect(compared).toBeGreaterThan(250);
  });

  it('operators end words and are reported; quoted operators are not', () => {
    const t = shellTokens(`cat a;b|c&&d "e;f" 'g|h' i\\;j`).tokens;
    expect(t.map(x => `${x.type}:${x.value}`)).toEqual([
      'word:cat', 'word:a', 'op:;', 'word:b', 'op:|', 'word:c', 'op:&&', 'word:d', 'word:e;f', 'word:g|h', 'word:i;j',
    ]);
  });

  it('an unterminated quote is incomplete but its text is still a word', () => {
    const r = shellTokens(`cp x "/h/.claude/a b/../projects/p/s.jsonl`);
    expect(r.complete).toBe(false);
    expect(r.tokens.at(-1)).toMatchObject({ type: 'word', value: '/h/.claude/a b/../projects/p/s.jsonl' });
  });

  it('bare records only unquoted, unescaped characters', () => {
    const [w] = shellTokens(String.raw`a\$"{b}"'#'c!`).tokens;
    expect(w).toMatchObject({ type: 'word', value: 'a${b}#c!', bare: 'ac!' });
  });

  it('a nested shell word is tokenised again (bash -c, "$(…)")', () => {
    expect(shellWords(String.raw`bash -c 'cp a /h/x\ y/../z'`)).toContain('/h/x y/../z');
    expect(shellWords(String.raw`echo "$(cp a /h/x\ y/../z)"`)).toContain('/h/x y/../z');
  });
});

describe('#923 r7 — lexicalPathNormalise collapses on / only', () => {
  it.each<[string, string]>([
    ['/h/.claude/./projects/p/s.jsonl', '/h/.claude/projects/p/s.jsonl'],
    ['/h/.claude//projects//p/s.jsonl', '/h/.claude/projects/p/s.jsonl'],
    ['/h/.claude/x y/../projects/p/s.jsonl', '/h/.claude/projects/p/s.jsonl'],
    ['/h/.claude/x\\y/../projects/p/s.jsonl', '/h/.claude/projects/p/s.jsonl'],
    ['/h/.claude/x\\/../projects', '/h/.claude/projects'],
    ['a\\b', 'a\\b'],
    ['../x/../y', '../y'],
    ['/../x', '/x'],
  ])('%j -> %j', (input, expected) => {
    expect(lexicalPathNormalise(input)).toBe(expected);
    expect(guardNormalise(input)).toBe(expected);
  });

  it('the r6 Astra B1 escaped alias names the transcript; the bare fragments do not', () => {
    expect(claudeTranscriptNamed(String.raw`sudo cp /h/src.jsonl /h/.claude/x\ y/../projects/p/session.jsonl`)).toBe(true);
    expect(claudeTranscriptNamed(String.raw`cat /h/.claude/x\ y/../notes.txt`)).toBe(false);
  });
});

describe('#923 r7 — both planes import the one module (no copy to drift)', () => {
  const hook = readFileSync(join(repoRoot, 'scripts', 'pre-tool-hook.mjs'), 'utf8');
  const guard = readFileSync(join(repoRoot, 'src', 'defence', 'iron-dome', 'tool-action-guard.ts'), 'utf8');

  it('the pre-tool hook imports scripts/lib/shell-words.mjs and defines no tokenizer of its own', () => {
    expect(hook).toMatch(/from '\.\/lib\/shell-words\.mjs'/);
    expect(hook).not.toMatch(/function fallbackShellWords\b/);
    expect(hook).not.toMatch(/function fallbackLexicalPathNormalise\b/);
  });

  it('the live guard imports the same file and defines no tokenizer of its own', () => {
    expect(guard).toMatch(/from '\.\.\/\.\.\/\.\.\/scripts\/lib\/shell-words\.mjs'/);
    expect(guard).not.toMatch(/^function shellWords\b/m);
    // The guard's normaliser is the shared one, so no backslash-to-slash
    // mapping survives in it; the hook has none at all. (isShellStartupWritePath
    // and isMemoryWritePath keep theirs: basename detectors that only ever
    // match MORE paths, and never collapse `..`.)
    expect(guard).toMatch(/export function lexicalPathNormalise\(p: string\): string \{\n {2}return sharedLexicalPathNormalise\(p\);\n\}/);
    expect(hook).not.toMatch(/replace\(\/\\\\\/g, '\/'\)/);
  });

  it('the built guard resolves the import to the shipped scripts/lib file', () => {
    const distGuard = join(repoRoot, 'dist', 'defence', 'iron-dome', 'tool-action-guard.js');
    let built = '';
    try { built = readFileSync(distGuard, 'utf8'); } catch { /* no build: covered by the source check above */ }
    if (built) {
      expect(built).toMatch(/from '\.\.\/\.\.\/\.\.\/scripts\/lib\/shell-words\.mjs'/);
      expect(resolve(dirname(distGuard), '../../../scripts/lib/shell-words.mjs')).toBe(join(repoRoot, 'scripts', 'lib', 'shell-words.mjs'));
    }
  });
});
